package platform

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"path/filepath"
	"time"
)

type retryState struct {
	targets           []control.Profile
	full              bool
	attempt, failures int
	next              time.Time
}

func (r *Runtime) armRetry(request control.Request) {
	r.retry = retryState{}
	if request.Profile.Reliability == nil || !request.Profile.Reliability.AutoReconnect {
		return
	}
	r.retry.targets = append(r.retry.targets, *request.Profile)
	if request.Profile.Reliability.UseFallbacks {
		r.retry.targets = append(r.retry.targets, request.Fallbacks...)
	}
	r.retry.full = request.FullDevice
	r.retry.next = time.Now().Add(20 * time.Second)
}

func (r *Runtime) cancelRetry() {
	r.retryMu.Lock()
	defer r.retryMu.Unlock()
	if r.retryCancel != nil {
		r.retryCancel()
	}
}
func (r *Runtime) retryContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	r.retryMu.Lock()
	r.retryCancel = cancel
	r.retryMu.Unlock()
	return ctx, func() { cancel(); r.retryMu.Lock(); r.retryCancel = nil; r.retryMu.Unlock() }
}

// Called with the operation mutex held. No timer ever removes traffic policy.
func (r *Runtime) maintainConnection() {
	r.maintainConnectionWith(retryEffects{time.Now, r.connectionHealth, r.disconnectMode, r.start, r.activateStatistics})
}

type retryEffects struct {
	now        func() time.Time
	health     func(context.Context) error
	disconnect func(context.Context, bool) error
	start      func(context.Context, control.Request) error
	activate   func()
}

func (r *Runtime) maintainConnectionWith(effects retryEffects) {
	if len(r.retry.targets) == 0 || effects.now().Before(r.retry.next) {
		return
	}
	ctx, cancel := r.retryContext()
	defer cancel()
	if !r.transportFailed && !r.retrying && r.session != nil {
		probeCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err := effects.health(probeCtx)
		done()
		r.retry.next = effects.now().Add(20 * time.Second)
		if err == nil {
			r.retry.failures = 0
			return
		}
		if ctx.Err() != nil {
			return
		}
		r.retry.failures++
		if r.retry.failures < 2 {
			return
		}
	}
	if r.retry.attempt >= 9 {
		r.retry.targets = nil
		r.retrying = false
		r.transportFailed = true
		r.publish("Серверы недоступны · попытки остановлены; защита сохранена")
		return
	}
	r.retrying = true
	r.retry.attempt++
	r.publish("Переподключение · попытка " + itoa(r.retry.attempt) + " из 9")
	retain := r.lock.needed()
	if err := effects.disconnect(ctx, retain); err != nil {
		r.retry.targets = nil
		r.retrying = false
		r.transportFailed = true
		r.publish("")
		return
	}
	// First retry keeps the selected server; following retries visit its backups.
	index := (r.retry.attempt - 1) % len(r.retry.targets)
	target := r.retry.targets[index]
	request := control.Request{Version: 1, Command: "start", Profile: &target, FullDevice: r.retry.full}
	err := ctx.Err()
	if err == nil {
		err = effects.start(ctx, request)
		if err == nil {
			err = ctx.Err()
		}
	}
	if err == nil {
		probeCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err = effects.health(probeCtx)
		done()
		if err == nil {
			err = ctx.Err()
		}
	}
	if err == nil {
		effects.activate()
		r.retrying = false
		r.transportFailed = false
		r.retry.failures = 0
		r.retry.attempt = 0
		// Resume from the working backup instead of constantly preferring a dead node.
		r.retry.targets[0], r.retry.targets[index] = r.retry.targets[index], r.retry.targets[0]
		r.retry.next = effects.now().Add(20 * time.Second)
		r.publish("Подключение восстановлено: " + target.Name)
		return
	}
	// An engine that started but failed its end-to-end check must not be exposed
	// as connected. Leave the deny rules installed while disposing its transport.
	cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
	cleanupErr := effects.disconnect(cleanup, retain)
	done()
	r.transportFailed = true
	if cleanupErr != nil {
		r.retry.targets = nil
		r.retrying = false
	}
	r.retry.next = effects.now().Add(time.Duration(r.retry.attempt*3) * time.Second)
	r.publish("Ожидается следующая попытка переподключения")
}

func (r *Runtime) checkProfile(ctx context.Context, p *control.Profile) (*string, error) {
	return r.checkProfileWithProbe(ctx, p, httpsCheck)
}

func (r *Runtime) checkProfileWithProbe(ctx context.Context, p *control.Profile, httpsProbe func(context.Context, int) error) (*string, error) {
	return r.checkProfileWithProbeDirectory(ctx, p, httpsProbe, privateDirectory)
}

func (r *Runtime) checkProfileWithProbeDirectory(ctx context.Context, p *control.Profile, httpsProbe func(context.Context, int) error, prepareDirectory func(string) error) (*string, error) {
	if p == nil || httpsProbe == nil || prepareDirectory == nil {
		return nil, protocol.ErrConfiguration
	}
	if r.session != nil || r.recovery() {
		return nil, errors.New("connection must be idle for group checks")
	}
	started := time.Now()
	result := control.ProfileCheck{NetworkTest: p.Protocol >= 2}
	policyValidated := !protocol.NetworkOptionsEmpty(p.Network)
	localProfile := *p
	if p.Transport != nil {
		options := *p.Transport
		localProfile.Transport = &options
	}
	if p.Reliability != nil {
		options := *p.Reliability
		localProfile.Reliability = &options
	}
	if policyValidated {
		plan, err := protocol.CompileWithNetwork(p.Source, p.Protocol, true, 18001, 18002, "unused", p.Transport, p.Network)
		if err != nil || plan.Proxy == "" {
			result.NetworkTest = false
			result.Message = "Invalid DNS or routing configuration; no network check was started."
			result.Milliseconds = time.Since(started).Milliseconds()
			data, _ := json.Marshal(result)
			text := string(data)
			return &text, nil
		}
		if p.Protocol < 2 {
			if err = validateEmbeddedSharedNative([]byte(plan.Proxy)); err != nil {
				result.NetworkTest = false
				result.Message = "Shared native DNS and routing configuration validation failed; no network check was started."
				result.Milliseconds = time.Since(started).Milliseconds()
				data, _ := json.Marshal(result)
				text := string(data)
				return &text, nil
			}
		}
		localProfile.Network = nil
	}
	if p.Protocol < 2 {
		var err error
		if !policyValidated {
			_, err = protocol.CompileWithNetwork(p.Source, p.Protocol, false, 18001, 18002, "unused", p.Transport, p.Network)
		}
		result.Success = err == nil
		result.Message = "Configuration validated; native WG/AWG connectivity is checked during connection."
		if policyValidated {
			result.Message = "Native source and shared DNS/routing configuration validated only; no native engine, OS adapter or network probe was started."
		}
		if err != nil {
			result.Message = "Invalid configuration."
		}
	} else {
		root, err := os.MkdirTemp(r.root, "profile-check-")
		if err != nil {
			return nil, err
		}
		cleaned := false
		defer func() {
			if cleaned {
				_ = os.RemoveAll(root)
			}
		}()
		if err = prepareDirectory(filepath.Join(root, "runtime")); err != nil {
			cleaned = true
			return nil, err
		}
		probe := &Runtime{directory: r.directory, root: root, lock: trafficLock{owner: "OneTunnel.ProfileCheck", root: root}, forceSecureBootstrap: policyValidated || r.forceSecureBootstrap, update: func(control.State) {}}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if probe.disconnect(cleanup) == nil {
				cleaned = true
			}
		}()
		deadline, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		err = probe.start(deadline, control.Request{Version: 1, Command: "start", Profile: &localProfile})
		if err == nil {
			probeStarted := time.Now()
			err = httpsProbe(deadline, probe.snapshot().LocalPort)
			if err == nil {
				latency := time.Since(probeStarted).Milliseconds()
				result.HTTPSLatencyMilliseconds = &latency
			}
		}
		result.Success = err == nil
		cleanup, finish := context.WithTimeout(context.Background(), 15*time.Second)
		cleanupErr := probe.disconnect(cleanup)
		finish()
		if cleanupErr != nil {
			return nil, errors.New("profile check cleanup failed")
		}
		cleaned = true
		result.Message = "The server HTTPS check failed."
		if result.Success {
			result.Message = "Server HTTPS check succeeded."
		}
		if policyValidated {
			result.Message += " Saved DNS and routing policy was validated as configuration only and was not applied. Infrastructure endpoint bootstrap remained encrypted."
		}
	}
	result.Milliseconds = time.Since(started).Milliseconds()
	data, _ := json.Marshal(result)
	text := string(data)
	return &text, nil
}

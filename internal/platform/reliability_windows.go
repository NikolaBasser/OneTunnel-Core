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
	if len(r.retry.targets) == 0 || time.Now().Before(r.retry.next) {
		return
	}
	ctx, cancel := r.retryContext()
	defer cancel()
	if !r.transportFailed && !r.retrying && r.session != nil {
		probeCtx, done := context.WithTimeout(ctx, 5*time.Second)
		port := r.snapshot().LocalPort
		err := httpsCheck(probeCtx, port)
		done()
		r.retry.next = time.Now().Add(20 * time.Second)
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
	if err := r.disconnectMode(ctx, retain); err != nil {
		r.retry.targets = nil
		r.retrying = false
		r.transportFailed = true
		return
	}
	// First retry keeps the selected server; following retries visit its backups.
	index := (r.retry.attempt - 1) % len(r.retry.targets)
	target := r.retry.targets[index]
	request := control.Request{Version: 1, Command: "start", Profile: &target, FullDevice: r.retry.full}
	err := r.start(ctx, request)
	if err == nil {
		probeCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err = httpsCheck(probeCtx, r.snapshot().LocalPort)
		done()
	}
	if err == nil {
		r.activateStatistics()
		r.retrying = false
		r.transportFailed = false
		r.retry.failures = 0
		r.retry.attempt = 0
		// Resume from the working backup instead of constantly preferring a dead node.
		r.retry.targets[0], r.retry.targets[index] = r.retry.targets[index], r.retry.targets[0]
		r.retry.next = time.Now().Add(20 * time.Second)
		r.publish("Подключение восстановлено: " + target.Name)
		return
	}
	// An engine that started but failed its end-to-end check must not be exposed
	// as connected. Leave the deny rules installed while disposing its transport.
	cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
	cleanupErr := r.disconnectMode(cleanup, retain)
	done()
	r.transportFailed = true
	if cleanupErr != nil {
		r.retry.targets = nil
		r.retrying = false
	}
	r.retry.next = time.Now().Add(time.Duration(r.retry.attempt*3) * time.Second)
	r.publish("Ожидается следующая попытка переподключения")
}

func (r *Runtime) checkProfile(ctx context.Context, p *control.Profile) (*string, error) {
	if p == nil {
		return nil, protocol.ErrConfiguration
	}
	if r.session != nil || r.recovery() {
		return nil, errors.New("connection must be idle for group checks")
	}
	started := time.Now()
	result := control.ProfileCheck{NetworkTest: p.Protocol >= 2}
	if !protocol.NetworkOptionsEmpty(p.Network) {
		plan, err := protocol.CompileWithNetwork(p.Source, p.Protocol, true, 18001, 18002, "unused", p.Transport, p.Network)
		result.Success = err == nil && plan.Proxy != ""
		result.NetworkTest = false
		result.Message = "Конфигурация DNS и маршрутизации проверена; сетевой тест не выполнялся"
		if !result.Success {
			result.Message = "Некорректная конфигурация DNS или маршрутизации"
		}
	} else if p.Protocol < 2 {
		_, err := protocol.CompileWithNetwork(p.Source, p.Protocol, false, 18001, 18002, "unused", p.Transport, p.Network)
		result.Success = err == nil
		result.Message = "Конфигурация проверена; сетевой тест WG/AWG выполняется при подключении"
		if err != nil {
			result.Message = "Некорректная конфигурация"
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
		if err = privateDirectory(filepath.Join(root, "runtime")); err != nil {
			return nil, err
		}
		probe := &Runtime{directory: r.directory, root: root, lock: trafficLock{owner: "OneTunnel.ProfileCheck", root: root}, update: func(control.State) {}}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if probe.disconnect(cleanup) == nil {
				cleaned = true
			}
		}()
		deadline, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		err = probe.start(deadline, control.Request{Version: 1, Command: "start", Profile: p})
		if err == nil {
			err = httpsCheck(deadline, probe.snapshot().LocalPort)
		}
		result.Success = err == nil
		cleanup, finish := context.WithTimeout(context.Background(), 15*time.Second)
		cleanupErr := probe.disconnect(cleanup)
		finish()
		if cleanupErr != nil {
			return nil, errors.New("profile check cleanup failed")
		}
		cleaned = true
		result.Message = "Нет доступа через сервер"
		if result.Success {
			result.Message = "HTTPS через сервер работает"
		}
	}
	result.Milliseconds = time.Since(started).Milliseconds()
	data, _ := json.Marshal(result)
	text := string(data)
	return &text, nil
}

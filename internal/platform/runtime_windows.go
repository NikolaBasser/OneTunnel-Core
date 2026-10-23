package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Session is compatible with 0.6–0.8, including .NET UTC ticks. Paths read
// from disk are never executable inputs: recovery derives them afresh.
type Session struct {
	Kind           string
	Engine         string
	ConfigPath     string
	TunnelName     string
	Pid            int
	Started        int64
	XrayPid        int
	XrayStarted    int64
	FullDevice     bool
	EmbeddedNative bool
}
type child struct {
	cmd     *exec.Cmd
	done    chan struct{}
	started int64
}
type Runtime struct {
	bootstrapIPs       map[string]string
	retry              retryState
	retrying           bool
	retryMu            sync.Mutex
	retryCancel        context.CancelFunc
	directory, root    string
	lock               trafficLock
	operations         sync.Mutex
	stateMu            sync.Mutex
	state              control.State
	session            *Session
	transportFailed    bool
	engine, xray       *child
	embeddedXray       interface{ Close() error }
	embeddedProxy      interface{ Close() error }
	embeddedNative     nativeEngine
	statisticsProvider interface {
		Statistics(time.Time) *control.ConnectionStatistics
	}
	statisticsNative interface {
		Counters() (uint64, uint64, error)
	}
	statisticsAccumulator *control.StatisticsAccumulator
	statisticsSessionID   string
	job                   windows.Handle
	update                func(control.State)
	dead                  atomic.Bool
	stop                  chan struct{}
	monitorDone           chan struct{}
}

func NewRuntime(directory, owner string, update func(control.State), _ func()) (*Runtime, error) {
	programData, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return nil, e
	}
	root := filepath.Join(programData, "OneTunnel", "Service", owner)
	// The installer seals all ancestors. Verify them again before writing secrets.
	for _, p := range []string{filepath.Join(programData, "OneTunnel"), filepath.Join(programData, "OneTunnel", "Service"), root} {
		if e = privateDirectory(p); e != nil {
			return nil, e
		}
	}
	if e = privateDirectory(filepath.Join(root, "runtime")); e != nil {
		return nil, e
	}
	r := &Runtime{directory: directory, root: root, lock: trafficLock{owner, root}, update: update, stop: make(chan struct{}), monitorDone: make(chan struct{})}
	r.state.Status = "Отключено"
	r.publish("")
	go r.monitor()
	return r, nil
}
func privateDirectory(path string) error {
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("reparse runtime forbidden")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	attributes, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if e != nil {
		return e
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse runtime forbidden")
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func itoa(n int) string { return strconv.Itoa(n) }
func atomicJSON(path string, value any) error {
	data, e := json.Marshal(value)
	if e != nil {
		return e
	}
	defer clear(data)
	file, e := os.OpenFile(path+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = file.Write(data); e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(path+".new"), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (r *Runtime) journal() string { return filepath.Join(r.root, "session.json") }
func exists(path string) bool      { _, e := os.Stat(path); return e == nil || !os.IsNotExist(e) }
func (r *Runtime) recovery() bool  { return exists(r.journal()) || r.lock.needed() }
func (r *Runtime) snapshot() control.State {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	return r.state
}
func (r *Runtime) publish(status string) {
	r.sampleStatistics(time.Now())
	r.stateMu.Lock()
	r.state.Active = r.session != nil && !r.transportFailed
	r.state.NeedsRecovery = r.transportFailed || (r.session == nil && r.recovery())
	r.state.TrafficLocked = r.lock.needed()
	r.state.Reconnecting = r.retrying
	r.state.ReconnectAttempt = r.retry.attempt
	if status != "" {
		r.state.Status = status
	}
	if r.state.NeedsRecovery && !r.state.Reconnecting {
		if r.state.TrafficLocked {
			r.state.Status = "Требуется восстановление · прямой трафик заблокирован"
		} else {
			r.state.Status = "Требуется очистка предыдущего подключения"
		}
	}
	state := r.state
	r.stateMu.Unlock()
	r.update(state)
}

func (r *Runtime) sampleStatistics(now time.Time) {
	if r.statisticsProvider != nil {
		r.setStatistics(r.statisticsProvider.Statistics(now))
	} else if r.statisticsNative != nil && r.statisticsAccumulator != nil {
		if uploaded, downloaded, err := r.statisticsNative.Counters(); err == nil {
			r.statisticsAccumulator.UpdateAbsolute(uploaded, downloaded)
			r.setStatistics(r.statisticsAccumulator.Snapshot(now, r.statisticsSessionID))
		} else {
			r.statisticsAccumulator.ResetRateBaseline()
			r.setStatistics(nil)
		}
	}
}

func (r *Runtime) setStatistics(value *control.ConnectionStatistics) {
	r.stateMu.Lock()
	r.state.Statistics = value
	r.stateMu.Unlock()
}

func (r *Runtime) activateStatistics() {
	r.statisticsProvider = nil
	r.statisticsNative = nil
	r.statisticsAccumulator = nil
	r.statisticsSessionID = ""
	if provider, ok := r.embeddedProxy.(interface {
		Statistics(time.Time) *control.ConnectionStatistics
	}); ok {
		r.statisticsProvider = provider
	} else if counters, ok := r.embeddedNative.(interface {
		Counters() (uint64, uint64, error)
	}); ok {
		stats, id, err := control.NewStatisticsAccumulator(time.Now(), "native-transport")
		if err == nil {
			r.statisticsNative, r.statisticsAccumulator, r.statisticsSessionID = counters, stats, id
		}
	}
	r.stateMu.Lock()
	r.state.Statistics = nil
	r.stateMu.Unlock()
}
func (r *Runtime) Alive() bool { return !r.dead.Load() }
func (r *Runtime) Call(ctx context.Context, request control.Request) (control.BackendResult, error) {
	if request.Command == "stop" || request.Command == "recover" {
		r.cancelRetry()
	}
	r.operations.Lock()
	defer r.operations.Unlock()
	if !r.Alive() {
		return control.BackendResult{}, errors.New("runtime unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	var e error
	var result *string
	switch request.Command {
	case "hello", "status":
		r.poll()
	case "start":
		r.bootstrapIPs = map[string]string{}
		e = r.start(ctx, request)
		if e == nil {
			r.activateStatistics()
			r.armRetry(request)
		}
	case "check-profile":
		result, e = r.checkProfile(ctx, request.Profile)
	case "stop":
		r.retry = retryState{}
		r.retrying = false
		e = r.disconnect(ctx)
	case "recover":
		r.retry = retryState{}
		r.retrying = false
		e = r.recover(ctx)
	case "probe":
		var text string
		text, e = r.probe(ctx)
		if e == nil {
			result = &text
		}
	default:
		e = errors.New("unknown runtime command")
	}
	r.publish("")
	var code *string
	if e != nil {
		value := "operation_failed"
		switch {
		case errors.Is(e, protocol.ErrTransportUpgrade):
			value = "transport_upgrade_required"
		case errors.Is(e, protocol.ErrConfiguration):
			value = "invalid_configuration"
		case errors.Is(e, context.DeadlineExceeded):
			value = "network_timeout"
		default:
			var ne net.Error
			if errors.As(e, &ne) {
				if ne.Timeout() {
					value = "network_timeout"
				} else {
					value = "network_error"
				}
			}
		}
		code = &value
	}
	var errorInfo *control.ErrorInfo
	if e != nil {
		stage := failureStage(e, "engine")
		if errors.Is(e, protocol.ErrConfiguration) || errors.Is(e, protocol.ErrTransportUpgrade) {
			stage = "configuration"
		} else if stage != "bootstrap" && (request.Command == "check-profile" || request.Command == "probe") {
			stage = "probe"
		}
		errorInfo = control.ClassifyError(stage, e)
	}
	return control.BackendResult{State: r.snapshot(), Result: result, Error: code, ErrorInfo: errorInfo}, nil
}
func (r *Runtime) monitor() {
	defer close(r.monitorDone)
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-timer.C:
			if r.operations.TryLock() {
				r.poll()
				r.maintainConnection()
				r.publish("")
				r.operations.Unlock()
			}
		}
	}
}
func (r *Runtime) poll() {
	if r.session == nil {
		return
	}
	failed := false
	if r.session.Kind == "proxy" {
		failed = childExited(r.engine) || childExited(r.xray) || embeddedExited(r.embeddedXray) || embeddedExited(r.embeddedProxy)
		if !failed && r.session.FullDevice && fullDeviceEmbeddingEnabled() {
			v4, e4 := routeInterface("1.1.1.1")
			v6, e6 := routeInterface("2606:4700:4700::1111")
			failed = e4 != nil || e6 != nil || v4 != "OneTunnel" || v6 != "OneTunnel"
		}
	} else if r.session.EmbeddedNative {
		failed = nativeExited(r.embeddedNative)
		if !failed && r.session.FullDevice {
			name, e := routeInterface("1.1.1.1")
			failed = e != nil || name != r.session.TunnelName
		}
	} else {
		running, _ := nativeServiceState(nativeServiceName(r.session))
		failed = !running
	}
	if failed {
		if !r.transportFailed && len(r.retry.targets) > 0 {
			r.retry.next = time.Now().Add(time.Second)
		}
		r.transportFailed = true
		if r.lock.needed() {
			r.publish("Соединение оборвано · прямой трафик заблокирован")
		} else {
			r.publish("Движок остановился · нажми «Отключить» для очистки")
		}
	}
}
func embeddedExited(engine interface{ Close() error }) bool {
	observable, ok := engine.(interface{ Done() <-chan struct{} })
	if !ok {
		return false
	}
	select {
	case <-observable.Done():
		return true
	default:
		return false
	}
}

func childExited(c *child) bool {
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}
func (r *Runtime) Close() {
	r.cancelRetry()
	if r.dead.Swap(true) {
		return
	}
	close(r.stop)
	<-r.monitorDone
	r.operations.Lock()
	defer r.operations.Unlock()
	// Service shutdown releases in-process sockets, just as closing the job
	// releases child engines. Keep the journal and WFP state for recovery.
	r.publish("")
	if r.embeddedNative != nil {
		_ = r.embeddedNative.Close()
		r.embeddedNative = nil
	}
	if r.embeddedProxy != nil {
		_ = r.embeddedProxy.Close()
		r.embeddedProxy = nil
	}
	if r.embeddedXray != nil {
		_ = r.embeddedXray.Close()
		r.embeddedXray = nil
	}
	if r.job != 0 {
		windows.CloseHandle(r.job)
		r.job = 0
	}
}
func (r *Runtime) enginePath(kind int) string {
	file := "sing-box.exe"
	if kind == 0 || kind == 1 {
		file = "amneziawg.exe"
	}
	return filepath.Join(r.directory, "engines", file)
}
func (r *Runtime) xrayPath() string { return filepath.Join(r.directory, "engines", "xray.exe") }
func newEngineJob() (windows.Handle, error) {
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return 0, e
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if e != nil {
		windows.CloseHandle(job)
		return 0, e
	}
	return job, nil
}
func command(ctx context.Context, path string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, path, args...)
	c.Dir = filepath.Dir(path)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}
func runEngine(ctx context.Context, path string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	c := command(ctx, path, args...)
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	return c.Run()
}
func processTicks(pid int) (int64, error) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if e != nil {
		return 0, e
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); e != nil {
		return 0, e
	}
	return (int64(created.HighDateTime)<<32 | int64(created.LowDateTime)) + 504911232000000000, nil
}
func (r *Runtime) launch(path string, args []string, inspect func(string)) (*child, error) {
	c := command(context.Background(), path, args...)
	output, e := c.StdoutPipe()
	if e != nil {
		return nil, e
	}
	stderr, e := c.StderrPipe()
	if e != nil {
		output.Close()
		return nil, e
	}
	// Logs are consumed for readiness only and are never written to disk/API.
	consume := func(reader io.ReadCloser) {
		defer reader.Close()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			if inspect != nil {
				inspect(scanner.Text())
			}
		}
	}
	if e = c.Start(); e != nil {
		output.Close()
		stderr.Close()
		return nil, e
	}
	h, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if e == nil {
		e = windows.AssignProcessToJobObject(r.job, h)
		windows.CloseHandle(h)
	}
	if e != nil {
		c.Process.Kill()
		c.Wait()
		output.Close()
		stderr.Close()
		return nil, e
	}
	ticks, e := processTicks(c.Process.Pid)
	if e != nil {
		c.Process.Kill()
		c.Wait()
		return nil, e
	}
	child := &child{cmd: c, done: make(chan struct{}), started: ticks}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); consume(output) }()
	go func() { defer readers.Done(); consume(stderr) }()
	go func() { readers.Wait(); c.Wait(); close(child.done) }()
	return child, nil
}
func waitPort(ctx context.Context, c *child, port int) error {
	for i := 0; i < 40; i++ {
		if childExited(c) {
			return errors.New("engine exited during startup")
		}
		dialer := net.Dialer{Timeout: 150 * time.Millisecond}
		connection, e := dialer.DialContext(ctx, "tcp4", "127.0.0.1:"+itoa(port))
		if e == nil {
			connection.Close()
			return nil
		}
		if e = delay(ctx, 100*time.Millisecond); e != nil {
			return e
		}
	}
	return errors.New("engine port not ready")
}
func delay(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func writeConfig(path string, c jsonObject) error {
	data, e := json.Marshal(c)
	if e != nil {
		return e
	}
	defer clear(data)
	return os.WriteFile(path, data, 0600)
}
func (r *Runtime) save() error { return atomicJSON(r.journal(), r.session) }
func (r *Runtime) start(ctx context.Context, request control.Request) (err error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	if r.session != nil || r.recovery() && !(r.retrying && r.lock.needed() && !exists(r.journal())) {
		return errors.New("recovery required")
	}
	if r.bootstrapIPs == nil {
		r.bootstrapIPs = map[string]string{}
	}
	secureBootstrap := r.retrying && r.lock.needed()
	forceSecureBootstrap := false
	if request.Profile != nil && !protocol.NetworkOptionsEmpty(request.Profile.Network) {
		secureBootstrap = true
		forceSecureBootstrap = true
	}
	ctx = context.WithValue(ctx, bootstrapKey{}, &bootstrapResolver{cache: r.bootstrapIPs, secure: secureBootstrap, forceSecure: forceSecureBootstrap, attempt: r.retry.attempt})
	if request.Profile == nil {
		return protocol.ErrConfiguration
	}
	p := request.Profile
	if err = protocol.CheckEngineCompatibility(p.Source, p.Protocol); err != nil {
		return err
	}
	local, bridge := 0, 0
	if p.Protocol >= 2 {
		local, err = freePort()
		if err != nil {
			return err
		}
		for i := 0; i < 40; i++ {
			bridge, err = freePort()
			if err != nil {
				return err
			}
			if bridge != local {
				break
			}
		}
		if bridge == local {
			return errors.New("port allocation failed")
		}
	}
	xrayIdentity, err := r.xrayIdentity(request.FullDevice)
	if err != nil {
		return err
	}
	plan, err := protocol.CompileWithNetwork(p.Source, p.Protocol, request.FullDevice, local, bridge, xrayIdentity, p.Transport, p.Network)
	if err != nil {
		return err
	}
	engine := r.enginePath(p.Protocol)
	if (p.Protocol < 2 && !embeddedAWGEnabled()) || (p.Protocol >= 2 && !embeddedSingBoxAllowed(request.FullDevice, plan.AccurateTime)) {
		if _, err = os.Stat(engine); err != nil {
			return err
		}
	}
	if plan.NeedsXray && !embeddedXrayAllowed(request.FullDevice) {
		if _, err = os.Stat(r.xrayPath()); err != nil {
			return err
		}
	}
	native := p.Protocol < 2
	tunnel := "OneTunnel" + strings.ReplaceAll(strings.ToLower(p.ID), "-", "")[:12]
	extension := ".json"
	kind := "proxy"
	if native {
		extension = ".conf"
		kind = "AmneziaWG"
	}
	path := filepath.Join(r.root, "runtime", tunnel+extension)
	r.stateMu.Lock()
	r.state.WholeDevice = request.FullDevice || native
	r.state.FullDeviceMode = request.FullDevice
	r.state.ClockSynchronized = false
	r.state.LocalPort = local
	id := p.ID
	r.state.ProfileID = &id
	r.stateMu.Unlock()
	r.session = &Session{Kind: kind, Engine: engine, ConfigPath: path, TunnelName: tunnel, FullDevice: request.FullDevice}
	r.session.EmbeddedNative = native && embeddedAWGEnabled()
	r.transportFailed = false
	if err = r.save(); err != nil {
		r.session = nil
		return err
	}
	r.publish("Запуск…")
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if e := r.disconnectMode(cleanup, r.retrying); e != nil {
				r.publish("Ошибка · требуется восстановление")
			}
		}
	}()
	if native {
		plan.NativeSource, err = pinNativeEndpoints(ctx, plan.NativeSource)
		if err != nil {
			return err
		}
		if err = os.WriteFile(path, []byte(plan.NativeSource), 0600); err != nil {
			return err
		}
		if embeddedAWGEnabled() {
			r.embeddedNative, err = startEmbeddedAWG(ctx, plan.NativeSource, p.Protocol, false, tunnel)
			if err != nil {
				return err
			}
		} else {
			if err = runEngine(ctx, engine, "/installtunnelservice", path); err != nil {
				return err
			}
			ready := false
			for i := 0; i < 30; i++ {
				ready, _ = nativeServiceState(nativeServiceName(r.session))
				if ready {
					break
				}
				if err = delay(ctx, 250*time.Millisecond); err != nil {
					return err
				}
			}
			if !ready {
				return errors.New("native tunnel service not running")
			}
		}
		if request.FullDevice {
			ready := false
			for i := 0; i < 120; i++ {
				name, _ := routeInterface("1.1.1.1")
				if name == tunnel {
					ready = true
					break
				}
				running := !nativeExited(r.embeddedNative)
				if !embeddedAWGEnabled() {
					running, _ = nativeServiceState(nativeServiceName(r.session))
				}
				if !running {
					break
				}
				if err = delay(ctx, 250*time.Millisecond); err != nil {
					return err
				}
			}
			if !ready {
				return errors.New("native full route unavailable")
			}
		}
		r.publish("Туннель запущен · handshake ещё не проверен")
	} else {
		r.job, err = newEngineJob()
		if err != nil {
			return err
		}
		if plan.NeedsXray {
			c, e := decodeConfig(plan.Xray)
			if e != nil {
				return e
			}
			if request.FullDevice {
				if err = prepareXray(ctx, c); err != nil {
					return err
				}
			}
			xrayConfig := path + ".xray.json"
			if err = writeConfig(xrayConfig, c); err != nil {
				return err
			}
			if embeddedXrayAllowed(request.FullDevice) {
				data, marshalErr := json.Marshal(c)
				if marshalErr != nil {
					return marshalErr
				}
				r.embeddedXray, err = startEmbeddedXray(data)
				clear(data)
				if err != nil {
					return err
				}
			} else {
				if err = runEngine(ctx, r.xrayPath(), "run", "-test", "-config", xrayConfig); err != nil {
					return err
				}
				r.xray, err = r.launch(r.xrayPath(), []string{"run", "-config", xrayConfig}, nil)
				if err != nil {
					return err
				}
				r.session.XrayPid = r.xray.cmd.Process.Pid
				r.session.XrayStarted = r.xray.started
			}
			if err = r.save(); err != nil {
				return err
			}
			if err = waitPort(ctx, r.xray, *plan.BridgePort); err != nil {
				return err
			}
		}
		c, e := decodeConfig(plan.Proxy)
		if e != nil {
			return e
		}
		synchronize := false
		if plan.AccurateTime {
			r.publish("Проверка времени для Shadowsocks 2022…")
			var server string
			synchronize, server, err = discoverClock(ctx)
			if err != nil {
				return stageError{stage: "bootstrap", err: err}
			}
			if synchronize {
				clock, e := decodeConfig(plan.Clock)
				if e != nil {
					return e
				}
				clock["server"] = server
				c["ntp"] = clock
				jObject(c["log"])["level"] = "info"
			}
		}
		if request.FullDevice {
			jObject(c["log"])["level"] = "info"
			if !plan.NeedsXray {
				out := first(c["outbounds"])
				out["server"], err = resolveEndpoint(ctx, jString(out["server"]))
				if err != nil {
					return err
				}
			}
		}
		if err = writeConfig(path, c); err != nil {
			return err
		}
		ready := make(chan struct{})
		clockReady := make(chan struct{})
		if embeddedSingBoxAllowed(request.FullDevice, plan.AccurateTime) {
			data, marshalErr := json.Marshal(c)
			if marshalErr != nil {
				return marshalErr
			}
			r.embeddedProxy, err = startEmbeddedSingBox(data, request.FullDevice)
			clear(data)
			if err != nil {
				return err
			}
			if synchronize {
				clock, ok := r.embeddedProxy.(interface{ ClockSynchronized() bool })
				if !ok || !clock.ClockSynchronized() {
					return errors.New("embedded clock not ready")
				}
				close(clockReady)
			}
			close(ready)
		} else {
			if err = runEngine(ctx, engine, "check", "-c", path); err != nil {
				return err
			}
			var readyOnce, clockOnce sync.Once
			r.engine, err = r.launch(engine, []string{"run", "-c", path}, func(line string) {
				line = strings.ToLower(line)
				if strings.Contains(line, "sing-box started") {
					readyOnce.Do(func() { close(ready) })
				}
				if synchronize && strings.Contains(line, "ntp") && strings.Contains(line, "updated time") {
					clockOnce.Do(func() { close(clockReady) })
				}
			})
			if err != nil {
				return err
			}
			r.session.Pid = r.engine.cmd.Process.Pid
			r.session.Started = r.engine.started
		}
		if err = r.save(); err != nil {
			return err
		}
		if err = waitPort(ctx, r.engine, local); err != nil {
			return err
		}
		if request.FullDevice {
			var engineDone <-chan struct{}
			if r.engine != nil {
				engineDone = r.engine.done
			}
			timer := time.NewTimer(30 * time.Second)
			defer timer.Stop()
			select {
			case <-ready:
			case <-engineDone:
				return errors.New("TUN engine exited")
			case <-timer.C:
				return errors.New("TUN readiness timeout")
			case <-ctx.Done():
				return ctx.Err()
			}
			v4, e4 := routeInterface("1.1.1.1")
			v6, e6 := routeInterface("2606:4700:4700::1111")
			if e4 != nil || e6 != nil || v4 != "OneTunnel" || v6 != "OneTunnel" {
				return errors.New("TUN IPv4/IPv6 routes not ready")
			}
		}
		if synchronize {
			var engineDone <-chan struct{}
			if r.engine != nil {
				engineDone = r.engine.done
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-clockReady:
				r.stateMu.Lock()
				r.state.ClockSynchronized = true
				r.stateMu.Unlock()
			case <-timer.C:
				return errors.New("internal NTP not ready")
			case <-engineDone:
				return errors.New("engine exited before clock ready")
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		r.publish("Прокси запущен · трафик ещё не проверен")
	}
	if request.FullDevice {
		r.publish("Включение блокировки прямого трафика…")
		name := "OneTunnel"
		if native {
			name = tunnel
		}
		paths, e := r.transportProcesses(p.Protocol, request.FullDevice, plan.NeedsXray)
		if e != nil {
			return e
		}
		if r.retrying && r.lock.needed() {
			err = r.lock.replace(name, paths)
		} else {
			err = r.lock.enable(name, paths)
		}
		if err != nil {
			return err
		}
		dnsFlush.Call()
		r.publish("Всё устройство · kill switch включён")
	}
	return nil
}
func nativeServiceName(s *Session) string {
	prefix := "AmneziaWGTunnel$"
	if s.Kind == "WireGuard" {
		prefix = "WireGuardTunnel$"
	}
	return prefix + s.TunnelName
}
func nativeServiceState(name string) (running, exists bool) {
	manager, e := mgr.Connect()
	if e != nil {
		return false, true
	}
	defer manager.Disconnect()
	service, e := manager.OpenService(name)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return false, false
	}
	if e != nil {
		return false, true
	}
	defer service.Close()
	status, e := service.Query()
	return e == nil && status.State == svc.Running, true
}
func stopChild(ctx context.Context, c *child, pid int, started int64, path string) error {
	if c != nil {
		if !childExited(c) {
			if e := c.cmd.Process.Kill(); e != nil && !errors.Is(e, os.ErrProcessDone) {
				return e
			}
		}
		select {
		case <-c.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return errors.New("engine shutdown timeout")
		}
	}
	if pid == 0 {
		return nil
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if e == windows.ERROR_INVALID_PARAMETER {
		return nil
	}
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	// A terminated process can remain addressable while another handle is
	// open. QueryFullProcessImageName then fails, which used to abort recovery
	// before the persistent traffic lock was removed.
	status, e := windows.WaitForSingleObject(h, 0)
	if e != nil {
		return e
	}
	if status == windows.WAIT_OBJECT_0 {
		return nil
	}
	var created, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); e != nil {
		return e
	}
	ticks := (int64(created.HighDateTime)<<32 | int64(created.LowDateTime)) + 504911232000000000
	if ticks != started {
		return nil
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	if e = windows.QueryFullProcessImageName(h, 0, &buffer[0], &length); e != nil {
		if status, waitErr := windows.WaitForSingleObject(h, 0); waitErr == nil && status == windows.WAIT_OBJECT_0 {
			return nil
		}
		return e
	}
	if !strings.EqualFold(windows.UTF16ToString(buffer[:length]), path) {
		return nil
	}
	if e = windows.TerminateProcess(h, 1); e != nil {
		if status, waitErr := windows.WaitForSingleObject(h, 0); waitErr == nil && status == windows.WAIT_OBJECT_0 {
			return nil
		}
		return e
	}
	result, e := windows.WaitForSingleObject(h, 10000)
	if e != nil {
		return e
	}
	if result != windows.WAIT_OBJECT_0 {
		return errors.New("owned engine did not stop")
	}
	return nil
}
func (r *Runtime) disconnect(ctx context.Context) error { return r.disconnectMode(ctx, false) }
func (r *Runtime) disconnectMode(ctx context.Context, retainLock bool) error {
	flush := r.lock.needed()
	if r.session != nil {
		s := r.session
		flush = flush || s.FullDevice
		r.publish("Отключение…")
		if s.Kind == "proxy" {
			if r.embeddedProxy != nil {
				if e := r.embeddedProxy.Close(); e != nil {
					return errors.New("embedded sing-box shutdown failed")
				}
				r.embeddedProxy = nil
			}
			if e := stopChild(ctx, r.engine, s.Pid, s.Started, s.Engine); e != nil {
				return e
			}
			r.engine = nil
			if r.embeddedXray != nil {
				if e := r.embeddedXray.Close(); e != nil {
					return errors.New("embedded Xray shutdown failed")
				}
				r.embeddedXray = nil
			}
			if e := stopChild(ctx, r.xray, s.XrayPid, s.XrayStarted, r.xrayPath()); e != nil {
				return e
			}
			r.xray = nil
			if r.job != 0 {
				windows.CloseHandle(r.job)
				r.job = 0
			}
		} else if s.EmbeddedNative {
			if r.embeddedNative != nil {
				if e := r.embeddedNative.Close(); e != nil {
					return e
				}
				r.embeddedNative = nil
			}
		} else {
			_, exists := nativeServiceState(nativeServiceName(s))
			if exists {
				var e error
				if s.Kind == "WireGuard" {
					e = removeLegacyWireGuardService(ctx, s.TunnelName)
				} else {
					e = runEngine(ctx, s.Engine, "/uninstalltunnelservice", s.TunnelName)
				}
				if e != nil {
					return e
				}
				for i := 0; i < 30; i++ {
					_, exists = nativeServiceState(nativeServiceName(s))
					if !exists {
						break
					}
					if e := delay(ctx, 200*time.Millisecond); e != nil {
						return e
					}
				}
				if exists {
					return errors.New("native tunnel service still exists")
				}
			}
		}
		for _, path := range []string{s.ConfigPath, s.ConfigPath + ".xray.json"} {
			if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		if !retainLock {
			if e := r.lock.remove(false); e != nil {
				return e
			}
		}
		r.session = nil
		r.statisticsProvider = nil
		r.statisticsNative = nil
		r.statisticsAccumulator = nil
		r.statisticsSessionID = ""
	}
	if !retainLock {
		if e := r.lock.remove(false); e != nil {
			return e
		}
	}
	if flush {
		dnsFlush.Call()
	}
	if e := os.Remove(r.journal()); e != nil && !os.IsNotExist(e) {
		return e
	}
	r.transportFailed = false
	r.stateMu.Lock()
	r.state.LocalPort = 0
	if !retainLock {
		r.state.ProfileID = nil
	}
	if !retainLock {
		r.state.WholeDevice = false
		r.state.FullDeviceMode = false
	}
	r.state.ClockSynchronized = false
	r.stateMu.Unlock()
	r.publish("Отключено")
	return nil
}

var tunnelNamePattern = regexp.MustCompile(`^OneTunnel[0-9a-f]{12}$`)

func (r *Runtime) recover(ctx context.Context) error {
	if r.session == nil && exists(r.journal()) {
		file, e := os.Open(r.journal())
		if e != nil {
			return e
		}
		var s Session
		decoder := json.NewDecoder(io.LimitReader(file, 65537))
		if e = decoder.Decode(&s); e != nil {
			file.Close()
			return e
		}
		if decoder.Decode(new(any)) != io.EOF {
			file.Close()
			return errors.New("invalid recovery journal tail")
		}
		if e = file.Close(); e != nil {
			return e
		}
		if !tunnelNamePattern.MatchString(s.TunnelName) || (s.Kind != "proxy" && s.Kind != "WireGuard" && s.Kind != "AmneziaWG") {
			return errors.New("invalid recovery journal")
		}
		kind := 2
		extension := ".json"
		if s.Kind != "proxy" {
			kind = 0
			extension = ".conf"
			if s.Kind == "WireGuard" {
				kind = 1
			}
		}
		s.Engine = r.enginePath(kind)
		s.ConfigPath = filepath.Join(r.root, "runtime", s.TunnelName+extension)
		r.session = &s
	}
	if e := r.disconnect(ctx); e != nil {
		return e
	}
	if e := r.lock.remove(true); e != nil {
		return e
	}
	files, e := os.ReadDir(filepath.Join(r.root, "runtime"))
	if e != nil {
		return e
	}
	for _, file := range files {
		if file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected runtime entry")
		}
		if e = os.Remove(filepath.Join(r.root, "runtime", file.Name())); e != nil {
			return e
		}
	}
	return nil
}
func (r *Runtime) probe(ctx context.Context) (string, error) {
	if r.session == nil {
		return "", errors.New("no active connection")
	}
	s := r.snapshot()
	port := s.LocalPort
	if s.WholeDevice {
		if s.FullDeviceMode {
			v4, e := routeInterface("1.1.1.1")
			if e != nil || !strings.HasPrefix(v4, "OneTunnel") {
				return "", errors.New("full IPv4 route missing")
			}
			if r.session.Kind == "proxy" {
				v6, e := routeInterface("2606:4700:4700::1111")
				if e != nil || !strings.HasPrefix(v6, "OneTunnel") {
					return "", errors.New("full IPv6 route missing")
				}
			}
		}
		if s.FullDeviceMode && r.session.Kind == "proxy" && (r.embeddedProxy != nil || r.embeddedXray != nil) {
			// This service is an explicit WFP transport exception. A direct HTTP
			// request here would test the exception, not the user's tunnel.
			if e := httpsCheck(ctx, port); e != nil {
				return "", e
			}
			return "Маршруты IPv4/IPv6 направлены в TUN; HTTPS через локальный прокси работает. Проверка отсутствия утечек DNS и IPv6 требует отдельного захвата трафика.", nil
		}
		if s.FullDeviceMode && r.embeddedNative != nil {
			if e := httpsCheckOnInterface(ctx, r.session.TunnelName); e != nil {
				return "", e
			}
			return "HTTPS через интерфейс AmneziaWG/WireGuard работает. Отсутствие утечек DNS и IPv6 требует отдельного захвата трафика.", nil
		}
		if e := httpsCheck(ctx, 0); e != nil {
			return "", e
		}
		return fmt.Sprintf("Системный HTTPS и разрешение имени работают. IPv4: %s. IPv6: %s. Отсутствие утечек DNS требует отдельного захвата трафика; этот тест его не подтверждает.", familyCheck(ctx, false), familyCheck(ctx, true)), nil
	}
	if e := httpsCheck(ctx, port); e != nil {
		return "", e
	}
	return "HTTPS-запрос через локальный прокси выполнен. Это подтверждает работу выбранного сервера; маршруты TUN и DNS требуют отдельной проверки.", nil
}

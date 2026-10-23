package embeddedawg

import (
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type Engine struct {
	instance *device.Device
	once     sync.Once
}

// NewDevice starts reading TUN before IpcSet applies S4. The first read can
// therefore retain the old packet offset. Return an empty read after config
// is committed so the upstream loop reloads its padding before reading data.
type configuredTUN struct {
	tun.Device
	ready               chan struct{}
	first               atomic.Bool
	openOnce, closeOnce sync.Once
	closeErr            error
}

func (t *configuredTUN) configured() { t.openOnce.Do(func() { close(t.ready) }) }
func (t *configuredTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if !t.first.Swap(true) {
		<-t.ready
		return 0, nil
	}
	return t.Device.Read(buffers, sizes, offset)
}
func (t *configuredTUN) Close() error {
	t.configured()
	t.closeOnce.Do(func() { t.closeErr = t.Device.Close() })
	return t.closeErr
}

// Start takes ownership of the TUN and bind, including on failure. It does not
// configure Windows addresses, DNS, routes, or firewall policy.
func Start(p *Plan, adapter tun.Device, bind conn.Bind) (*Engine, error) {
	data, err := p.UAPI()
	if err != nil {
		adapter.Close()
		bind.Close()
		return nil, err
	}
	defer clear(data)
	configured := &configuredTUN{Device: adapter, ready: make(chan struct{})}
	instance := device.NewDevice(configured, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err = instance.IpcSet(string(data)); err != nil {
		instance.Close()
		return nil, errors.New("embedded AWG configuration rejected")
	}
	configured.configured()
	if err = instance.Up(); err != nil {
		instance.Close()
		return nil, errors.New("embedded AWG startup failed")
	}
	return &Engine{instance: instance}, nil
}
func (e *Engine) Close() error {
	if e != nil {
		e.once.Do(e.instance.Close)
	}
	return nil
}
func (e *Engine) Done() <-chan struct{} { return e.instance.Wait() }

type Status struct {
	ListenPort            uint16
	Received, Transmitted uint64
	HandshakeUnix         int64
}

// Only counters leave the library boundary; UAPI private keys are never logged.
func (e *Engine) Status() (Status, error) {
	text, err := e.instance.IpcGet()
	if err != nil {
		return Status{}, errors.New("AWG status unavailable")
	}
	var status Status
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			v, _ := strconv.ParseUint(value, 10, 16)
			status.ListenPort = uint16(v)
		case "rx_bytes":
			v, _ := strconv.ParseUint(value, 10, 64)
			status.Received += v
		case "tx_bytes":
			v, _ := strconv.ParseUint(value, 10, 64)
			status.Transmitted += v
		case "last_handshake_time_sec":
			v, _ := strconv.ParseInt(value, 10, 64)
			if v > status.HandshakeUnix {
				status.HandshakeUnix = v
			}
		}
	}
	return status, nil
}

func (e *Engine) Counters() (uploaded, downloaded uint64, err error) {
	status, err := e.Status()
	if err != nil {
		return 0, 0, err
	}
	return status.Transmitted, status.Received, nil
}

// Package embeddedsingbox provides a limited engine registry. TUN is available
// only with the explicit experimental embeddedtun build tag. System DNS APIs,
// API services and WireGuard endpoints are not registered here.
package embeddedsingbox

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
)

type Engine struct {
	instance   *box.Box
	cancel     context.CancelFunc
	once       sync.Once
	err        error
	clock      *privateClock
	done       chan struct{}
	statistics *control.StatisticsAccumulator
	sessionID  string
	native     NativeTransport
	nativeDNS  nativeDNSExchanger
}

type nativeDNSExchanger interface {
	Exchange(context.Context, *mDNS.Msg, adapter.DNSQueryOptions) (*mDNS.Msg, error)
}

func Start(data []byte, wholeDevice bool) (*Engine, error) {
	if _, err := checkNativePlaceholder(data, false); err != nil {
		return nil, err
	}
	return start(data, wholeDevice, nil)
}

// StartWithNativeTransport starts a generated shared-TUN plan with one injected
// native transport. The transport is owned by the returned Engine.
func StartWithNativeTransport(data []byte, wholeDevice bool, transport NativeTransport) (*Engine, error) {
	if !wholeDevice || transport == nil {
		if transport != nil {
			_ = transport.Close()
		}
		return nil, errors.New("native transport requires full-device mode and a transport")
	}
	if _, err := checkNativePlaceholder(data, true); err != nil {
		_ = transport.Close()
		return nil, err
	}
	engine, err := start(data, wholeDevice, transport)
	if err != nil {
		_ = transport.Close()
	}
	return engine, err
}

func start(data []byte, wholeDevice bool, native NativeTransport) (*Engine, error) {
	in, out := inbound.NewRegistry(), outbound.NewRegistry()
	registerTun(in)
	mixed.RegisterInbound(in)
	http.RegisterInbound(in)
	trojan.RegisterInbound(in)
	tuic.RegisterInbound(in)
	anytls.RegisterInbound(in)
	naive.RegisterInbound(in)
	socks.RegisterInbound(in)
	shadowsocks.RegisterInbound(in)
	hysteria2.RegisterInbound(in)
	direct.RegisterOutbound(out)
	http.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	tuic.RegisterOutbound(out)
	anytls.RegisterOutbound(out)
	registerNaive(out)
	socks.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	if native != nil {
		registerNativeOutbound(out, native)
	}
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsRegistry)
	transport.RegisterTCP(dnsRegistry)
	transport.RegisterHTTPS(dnsRegistry)
	transport.RegisterTLS(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	ctx, cancel := context.WithCancel(box.Context(context.Background(), in, out, endpoint.NewRegistry(), dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry()))
	ctx = service.ContextWithDefaultRegistry(ctx)
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, data); err != nil {
		cancel()
		return nil, errors.New("invalid embedded sing-box configuration")
	}
	for _, out := range options.Outbounds {
		if out.Type == "naive" {
			if err := loadNaive(); err != nil {
				cancel()
				return nil, err
			}
		}
	}
	// The current embedding boundary must never accept privileged network changes.
	if len(options.Endpoints) > 0 || len(options.Services) > 0 || len(options.NetworkNamespaces) > 0 || options.Experimental != nil || (options.NTP != nil && options.NTP.WriteToSystem) {
		cancel()
		return nil, errors.New("unsupported embedded sing-box feature")
	}
	clock, err := startClock(ctx, options.NTP)
	if err != nil {
		cancel()
		return nil, err
	}
	options.NTP = nil
	if clock != nil {
		ctx = service.ExtendContext(ctx)
		service.MustRegister[ntp.TimeService](ctx, clock)
	}
	options.Log = &option.LogOptions{Disabled: true}
	scope := "proxy-payload"
	if wholeDevice {
		scope = "proxy-payload-and-packets"
	}
	statistics, sessionID, err := control.NewStatisticsAccumulator(time.Now(), scope)
	if err != nil {
		statistics, sessionID = nil, ""
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, errors.New("embedded sing-box initialization failed")
	}
	if statistics != nil {
		instance.Router().AppendTracker(newIngressTracker(statistics, wholeDevice))
	}
	var nativeDNS nativeDNSExchanger
	if native != nil {
		nativeDNS = service.FromContext[adapter.DNSRouter](ctx)
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return nil, errors.New("embedded sing-box startup failed")
	}
	statistics.MarkStarted(time.Now())
	if clock != nil {
		go clock.run(ctx)
	}
	return &Engine{instance: instance, cancel: cancel, clock: clock, done: make(chan struct{}), statistics: statistics, sessionID: sessionID, native: native, nativeDNS: nativeDNS}, nil
}

// NativeHealth checks the configured policy DNS path through sing-box. It is
// only available for a shared native transport and never falls back to a
// public endpoint or an operating-system resolver.
func (e *Engine) NativeHealth(ctx context.Context) error {
	if e == nil || e.native == nil {
		return errors.New("native health check is unavailable")
	}
	if ctx == nil {
		return errors.New("native health check context is required")
	}
	if e.nativeDNS == nil {
		return errors.New("native policy DNS router is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	query := new(mDNS.Msg)
	query.SetQuestion(".", mDNS.TypeNS)
	response, err := e.nativeDNS.Exchange(checkCtx, query, adapter.DNSQueryOptions{
		DisableCache:           true,
		DisableOptimisticCache: true,
	})
	if err != nil {
		return errors.New("native policy DNS check failed")
	}
	if response == nil || !response.Response || response.Id != query.Id || len(response.Question) != 1 || response.Question[0].Name != "." || response.Question[0].Qtype != mDNS.TypeNS || response.Question[0].Qclass != mDNS.ClassINET {
		return errors.New("native policy DNS check returned an invalid response")
	}
	return nil
}

// Validate constructs and closes an instance without starting listeners, TUN,
// clocks or routing. It is used for network-free full-device plan checks.
func Validate(data []byte) error {
	if _, err := checkNativePlaceholder(data, false); err != nil {
		return err
	}
	return validate(data, nil)
}

// ValidateWithNativeTransport validates a generated shared-TUN native plan
// without starting listeners, clocks, routing or the supplied transport.
func ValidateWithNativeTransport(data []byte, wholeDevice bool) error {
	if !wholeDevice {
		return errors.New("native transport requires full-device mode")
	}
	if _, err := checkNativePlaceholder(data, true); err != nil {
		return err
	}
	return validate(data, validationNativeTransport{})
}

func validate(data []byte, native NativeTransport) error {
	in, out := inbound.NewRegistry(), outbound.NewRegistry()
	registerTun(in)
	mixed.RegisterInbound(in)
	http.RegisterInbound(in)
	trojan.RegisterInbound(in)
	tuic.RegisterInbound(in)
	anytls.RegisterInbound(in)
	naive.RegisterInbound(in)
	socks.RegisterInbound(in)
	direct.RegisterOutbound(out)
	http.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	tuic.RegisterOutbound(out)
	anytls.RegisterOutbound(out)
	registerNaive(out)
	socks.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	if native != nil {
		registerNativeOutbound(out, native)
	}
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterHTTPS(dnsRegistry)
	transport.RegisterTLS(dnsRegistry)
	transport.RegisterUDP(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	ctx, cancel := context.WithCancel(box.Context(context.Background(), in, out, endpoint.NewRegistry(), dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry()))
	defer cancel()
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, data); err != nil {
		return errors.New("invalid embedded validation configuration")
	}
	if options.NTP != nil || len(options.Services) > 0 || len(options.Endpoints) > 0 || options.Experimental != nil {
		return errors.New("unsupported validation feature")
	}
	for _, out := range options.Outbounds {
		if out.Type == "naive" {
			if err := loadNaive(); err != nil {
				return err
			}
		}
	}
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return errors.New("embedded configuration validation failed")
	}
	return instance.Close()
}

func (e *Engine) ClockSynchronized() bool { return e != nil && e.clock != nil }

func (e *Engine) Statistics(now time.Time) *control.ConnectionStatistics {
	if e == nil || e.statistics == nil {
		return nil
	}
	return e.statistics.Snapshot(now, e.sessionID)
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() {
		e.err = e.instance.Close()
		e.cancel()
		if e.native != nil {
			e.err = errors.Join(e.err, e.native.Close())
		}
		close(e.done)
	})
	return e.err
}

func (e *Engine) Done() <-chan struct{} { return e.done }

// NativeDone reports loss of the injected transport independently of the
// shared sing-box engine lifecycle.
func (e *Engine) NativeDone() <-chan struct{} {
	if e == nil || e.native == nil {
		return nil
	}
	return e.native.Done()
}

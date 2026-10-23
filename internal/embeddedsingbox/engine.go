// Package embeddedsingbox provides a limited engine registry. TUN is available
// only with the explicit experimental embeddedtun build tag. System DNS APIs,
// API services and WireGuard endpoints are not registered here.
package embeddedsingbox

import (
	"context"
	"errors"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"sync"

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
	instance *box.Box
	cancel   context.CancelFunc
	once     sync.Once
	err      error
	clock    *privateClock
	done     chan struct{}
}

func Start(data []byte) (*Engine, error) {
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
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsRegistry)
	transport.RegisterTCP(dnsRegistry)
	transport.RegisterHTTPS(dnsRegistry)
	transport.RegisterTLS(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	ctx, cancel := context.WithCancel(box.Context(context.Background(), in, out, endpoint.NewRegistry(), dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry()))
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
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, errors.New("embedded sing-box initialization failed")
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return nil, errors.New("embedded sing-box startup failed")
	}
	if clock != nil {
		go clock.run(ctx)
	}
	return &Engine{instance: instance, cancel: cancel, clock: clock, done: make(chan struct{})}, nil
}

// Validate constructs and closes an instance without starting listeners, TUN,
// clocks or routing. It is used for network-free full-device plan checks.
func Validate(data []byte) error {
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

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() { e.err = e.instance.Close(); e.cancel(); close(e.done) })
	return e.err
}

func (e *Engine) Done() <-chan struct{} { return e.done }

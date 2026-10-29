//go:build windows && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/balancer"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type balanceLazy struct {
	mu     sync.Mutex
	build  func(context.Context) (balancer.Transport, error)
	active balancer.Transport
	done   chan struct{}
	closed bool
}

func (l *balanceLazy) get(ctx context.Context) (balancer.Transport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	if l.active != nil {
		select {
		case <-l.active.Done():
			_ = l.active.Close()
			l.active = nil
		default:
			return l.active, nil
		}
	}
	var e error
	l.active, e = l.build(ctx)
	return l.active, e
}
func (l *balanceLazy) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	t, e := l.get(ctx)
	if e != nil {
		return nil, e
	}
	return t.DialContext(ctx, n, a)
}
func (l *balanceLazy) ListenPacketTo(ctx context.Context, a string) (net.PacketConn, error) {
	t, e := l.get(ctx)
	if e != nil {
		return nil, e
	}
	return t.ListenPacketTo(ctx, a)
}
func (l *balanceLazy) Done() <-chan struct{} { return l.done }
func (l *balanceLazy) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active != nil {
		_ = l.active.Close()
		l.active = nil
	}
}
func (l *balanceLazy) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	if l.active != nil {
		return l.active.Close()
	}
	return nil
}

type balanceProxy struct {
	*embeddedsingbox.Engine
	xray     interface{ Close() error }
	once     sync.Once
	err      error
	done     chan struct{}
	doneOnce sync.Once
}

func (t *balanceProxy) Done() <-chan struct{} { return t.done }

func (t *balanceProxy) Close() error {
	t.once.Do(func() {
		t.err = t.Engine.Close()
		if t.xray != nil {
			t.err = errors.Join(t.err, t.xray.Close())
		}
		t.doneOnce.Do(func() { close(t.done) })
	})
	return t.err
}

func (r *Runtime) buildBalanceNode(ctx context.Context, p control.Profile) (balancer.Transport, error) {
	ctx = context.WithValue(ctx, bootstrapKey{}, &bootstrapResolver{cache: map[string]string{}, secure: true, forceSecure: true, secureLookup: r.secureQualityBootstrap})
	if p.Protocol < 2 {
		plan, e := embeddedawg.Parse(p.Source, p.Protocol, false)
		if e != nil {
			return nil, e
		}
		if e = resolveNativePlanEndpoints(ctx, plan); e != nil {
			return nil, e
		}
		plan.UseEphemeralListenPort()
		return startNativeUserspaceTransportWithRoute(plan, r.qualityInterface)
	}
	local, e := freePort()
	if e != nil {
		return nil, e
	}
	bridge, e := freePort()
	if e != nil || bridge == local {
		return nil, errors.New("pool port allocation failed")
	}
	plan, e := protocol.CompileWithOptions(p.Source, p.Protocol, false, local, bridge, "", p.Transport)
	if e != nil {
		return nil, e
	}
	var xray interface{ Close() error }
	success := false
	defer func() {
		if !success && xray != nil {
			_ = xray.Close()
		}
	}()
	if plan.NeedsXray {
		x, e := decodeConfig(plan.Xray)
		if e != nil {
			return nil, e
		}
		if e = prepareXrayWithBinding(ctx, x, func(stream jsonObject, address string) error {
			ip := net.ParseIP(address)
			if ip != nil && ip.IsLoopback() {
				return nil
			}
			name, e := r.qualityInterface(address)
			if e != nil {
				return e
			}
			sock := jObject(stream["sockopt"])
			sock["interface"] = name
			stream["sockopt"] = sock
			return nil
		}); e != nil {
			return nil, e
		}
		data, e := json.Marshal(x)
		if e != nil {
			return nil, e
		}
		xray, e = startEmbeddedXray(data)
		clear(data)
		if e != nil {
			return nil, e
		}
		if e = waitPort(ctx, nil, bridge); e != nil {
			return nil, e
		}
	}
	config, e := decodeConfig(plan.Proxy)
	if e != nil {
		return nil, e
	}
	if e = prepareQualityConfig(config, r.qualityInterface); e != nil {
		return nil, e
	}
	for _, raw := range jArray(config["outbounds"]) {
		out := jObject(raw)
		host := jString(out["server"])
		if host == "" {
			continue
		}
		address, e := resolveEndpoint(ctx, host)
		if e != nil {
			return nil, e
		}
		out["server"] = address
		if !net.ParseIP(address).IsLoopback() && jString(out["detour"]) == "" {
			name, e := r.qualityInterface(address)
			if e != nil {
				return nil, e
			}
			out["bind_interface"] = name
		}
	}
	if plan.AccurateTime {
		syncClock, server, e := discoverClock(ctx)
		if e != nil {
			return nil, e
		}
		if syncClock {
			clock, e := decodeConfig(plan.Clock)
			if e != nil {
				return nil, e
			}
			clock["server"] = server
			config["ntp"] = clock
		}
	}
	data, e := json.Marshal(config)
	if e != nil {
		return nil, e
	}
	engine, e := embeddedsingbox.Start(data, false)
	clear(data)
	if e != nil {
		return nil, e
	}
	success = true
	result := &balanceProxy{Engine: engine, xray: xray, done: make(chan struct{})}
	var xrayDone <-chan struct{}
	if child, ok := xray.(interface{ Done() <-chan struct{} }); ok {
		xrayDone = child.Done()
	}
	go func() {
		select {
		case <-engine.Done():
		case <-xrayDone:
		}
		result.doneOnce.Do(func() { close(result.done) })
	}()
	return result, nil
}

func (r *Runtime) startBalanceRouter(ctx context.Context, b *control.Balance, data []byte, full bool) (interface{ Close() error }, error) {
	return r.startBalanceRouterWithProbe(ctx, b, data, full, r.balanceProbeIP)
}
func (r *Runtime) startBalanceRouterWithProbe(ctx context.Context, b *control.Balance, data []byte, full bool, probeIP string) (interface{ Close() error }, error) {
	var probeMu sync.Mutex
	probeAddress := func(ctx context.Context) (string, error) {
		probeMu.Lock()
		defer probeMu.Unlock()
		if probeIP != "" {
			return probeIP, nil
		}
		ip, err := r.secureQualityBootstrap(ctx, "www.gstatic.com")
		if err == nil {
			probeIP = ip
		}
		return ip, err
	}
	nodes := []balancer.Node{}
	nativePlans := []*embeddedawg.Plan{}
	for _, member := range b.Members {
		p := member
		if full && p.Protocol < 2 {
			var err error
			p.Source, err = protocol.FullNativeRoutingSource(p.Source, p.Protocol)
			if err != nil {
				if b.Automatic {
					continue
				}
				return nil, err
			}
		}
		covers := func(network, address string) bool {
			_, e := netip.ParseAddrPort(address)
			return e == nil && (network == "tcp" || network == "udp" && p.Protocol != protocol.HTTP && p.Protocol != protocol.Naive)
		}
		if p.Protocol < 2 {
			plan, e := embeddedawg.Parse(p.Source, p.Protocol, false)
			if e != nil {
				if b.Automatic {
					continue
				}
				return nil, e
			}
			duplicate := false
			for _, existing := range nativePlans {
				if plan.SamePeer(existing) {
					if b.Automatic {
						duplicate = true
						break
					}
					return nil, errors.New("pool cannot run duplicate WG/AWG peer identities")
				}
			}
			if duplicate {
				continue
			}
			nativePlans = append(nativePlans, plan)
			covers = func(network, address string) bool {
				target, e := netip.ParseAddrPort(address)
				if e != nil {
					return false
				}
				family := false
				for _, a := range plan.Addresses {
					family = family || a.Addr().Is4() == target.Addr().Is4()
				}
				if !family {
					return false
				}
				for _, route := range plan.Routes {
					if route.Contains(target.Addr()) {
						return true
					}
				}
				return false
			}
		}
		lazy := &balanceLazy{done: make(chan struct{}), build: func(ctx context.Context) (balancer.Transport, error) { return r.buildBalanceNode(ctx, p) }}
		node := balancer.Node{ID: p.ID, Transport: lazy, Covers: covers}
		node.Probe = func(ctx context.Context) (time.Duration, error) {
			if !covers("tcp", "1.1.1.1:443") {
				return 0, balancer.ErrProbeNotCovered
			}
			ip, e := probeAddress(ctx)
			if e != nil {
				return 0, e
			}
			address := net.JoinHostPort(ip, "443")
			if !covers("tcp", address) {
				return 0, balancer.ErrProbeNotCovered
			}
			if _, e = lazy.get(ctx); e != nil {
				return 0, e
			}
			tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: "www.gstatic.com", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return lazy.DialContext(ctx, "tcp", address) }}
			defer tr.CloseIdleConnections()
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/generate_204", nil)
			start := time.Now()
			resp, e := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("pool probe redirected") }}).Do(req)
			if e != nil {
				return 0, e
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			if resp.StatusCode != 204 {
				return 0, errors.New("pool probe rejected")
			}
			return time.Since(start), nil
		}
		nodes = append(nodes, node)
	}
	if b.Automatic {
		// Discovery closes each temporary engine before releasing its worker;
		// only the final pool keeps engines alive.
		probes := append([]balancer.Node(nil), nodes...)
		for i := range probes {
			probe := probes[i].Probe
			lazy := probes[i].Transport.(*balanceLazy)
			probes[i].Probe = func(ctx context.Context) (time.Duration, error) { defer lazy.reset(); return probe(ctx) }
		}
		selected, err := balancer.Select(ctx, probes, 20*time.Second, time.Duration(b.MaxRTT)*time.Millisecond)
		if err != nil {
			for _, node := range nodes {
				_ = node.Transport.Close()
			}
			return nil, err
		}
		keep := map[string]bool{}
		for _, node := range selected {
			keep[node.ID] = true
		}
		retained := []balancer.Node{}
		// Select returns quality order; preserve it for best mode and ties.
		for _, node := range selected {
			for _, original := range nodes {
				if node.ID == original.ID {
					retained = append(retained, original)
					break
				}
			}
		}
		for _, node := range nodes {
			if !keep[node.ID] {
				_ = node.Transport.Close()
			}
		}
		nodes = retained
	}
	pool, e := balancer.New(nodes, b.Mode, min(b.Best, len(nodes)), time.Duration(b.Interval)*time.Second, time.Duration(b.MaxRTT)*time.Millisecond)
	if e != nil {
		return nil, e
	}
	if e = pool.WaitReady(ctx); e != nil {
		_ = pool.Close()
		return nil, e
	}
	return embeddedsingbox.StartWithPoolTransport(data, full, pool)
}

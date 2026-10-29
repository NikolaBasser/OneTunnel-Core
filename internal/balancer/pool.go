package balancer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var ErrNoServer = errors.New("no eligible pool server; direct fallback is disabled")
var ErrProbeNotCovered = errors.New("probe destination not covered")

type Transport interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenPacketTo(context.Context, string) (net.PacketConn, error)
	Close() error
	Done() <-chan struct{}
}
type Node struct {
	ID        string
	Transport Transport
	Covers    func(string, string) bool
	Probe     func(context.Context) (time.Duration, error)
}
type sample struct {
	latency time.Duration
	ok      bool
}
type entry struct {
	Node
	samples []sample
	blocked time.Time
	ready   bool
}
type Pool struct {
	mu       sync.Mutex
	nodes    []*entry
	mode     string
	best     int
	maxRTT   time.Duration
	interval time.Duration
	cursor   uint64
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	first    chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	flows    map[interface{ Close() error }]struct{}
	closed   bool
	closeErr error
}

func New(nodes []Node, mode string, best int, interval, maxRTT time.Duration) (*Pool, error) {
	if len(nodes) < 2 || len(nodes) > 8 || (mode != "best" && mode != "balanced") || best < 1 || best > len(nodes) || interval <= 0 || maxRTT <= 0 {
		return nil, errors.New("invalid pool")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{mode: mode, best: best, interval: interval, maxRTT: maxRTT, ctx: ctx, cancel: cancel, done: make(chan struct{}), first: make(chan struct{}), flows: map[interface{ Close() error }]struct{}{}}
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.ID == "" || seen[n.ID] || n.Transport == nil || n.Covers == nil || n.Probe == nil {
			cancel()
			return nil, errors.New("invalid pool node")
		}
		seen[n.ID] = true
		p.nodes = append(p.nodes, &entry{Node: n})
	}
	p.wg.Add(1)
	go p.run()
	return p, nil
}
func (p *Pool) Done() <-chan struct{} { return p.done }
func (p *Pool) Summary() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	verified, unknown := 0, 0
	for _, n := range p.nodes {
		if !n.ready || time.Now().Before(n.blocked) {
			continue
		}
		if len(n.samples) == 0 {
			unknown++
			continue
		}
		last := n.samples[len(n.samples)-1]
		if last.ok && last.latency <= p.maxRTT {
			verified++
		}
	}
	return fmt.Sprintf("Общий пул: проверка проходит у %d/%d; без общей пробы — %d", verified, len(p.nodes), unknown)
}
func (p *Pool) record(e *entry, d time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if errors.Is(err, ErrProbeNotCovered) {
		e.ready = true
		if !e.blocked.IsZero() && !time.Now().Before(e.blocked) {
			e.samples = nil
			e.blocked = time.Time{}
		}
		return
	}
	e.samples = append(e.samples, sample{d, err == nil})
	if len(e.samples) > 5 {
		e.samples = e.samples[len(e.samples)-5:]
	}
	if err != nil {
		e.blocked = time.Now().Add(p.interval)
	} else {
		e.ready = true
		e.blocked = time.Time{}
	}
}
func (p *Pool) run() {
	defer p.wg.Done()
	p.probe()
	close(p.first)
	timer := time.NewTicker(p.interval)
	defer timer.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
			p.probe()
		}
	}
}
func (p *Pool) probe() {
	var wg sync.WaitGroup
	for _, e := range p.nodes {
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(p.ctx, 8*time.Second)
			defer cancel()
			d, err := e.Probe(ctx)
			p.record(e, d, err)
		}(e)
	}
	wg.Wait()
}
func (p *Pool) candidates(network, address string) []*entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	now := time.Now()
	result := []*entry{}
	for _, e := range p.nodes {
		select {
		case <-e.Transport.Done():
			continue
		default:
		}
		if !e.ready || now.Before(e.blocked) || !e.Covers(network, address) {
			continue
		}
		result = append(result, e)
	}
	score := func(e *entry) time.Duration {
		if len(e.samples) == 0 {
			return p.maxRTT
		}
		var lat []time.Duration
		fail := 0
		for _, s := range e.samples {
			if s.ok {
				lat = append(lat, s.latency)
			} else {
				fail++
			}
		}
		if len(lat) == 0 {
			return p.maxRTT * 10
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return lat[len(lat)/2] + (lat[len(lat)-1]-lat[0])/2 + time.Duration(fail)*time.Second
	}
	sort.SliceStable(result, func(i, j int) bool { return score(result[i]) < score(result[j]) })
	filtered := result[:0]
	for _, e := range result {
		if score(e) <= p.maxRTT {
			filtered = append(filtered, e)
		}
	}
	result = filtered
	limit := min(p.best, len(result))
	primary, reserve := result[:limit], result[limit:]
	if p.mode == "balanced" && len(primary) > 1 {
		offset := int(p.cursor % uint64(len(primary)))
		p.cursor++
		primary = append(append([]*entry{}, primary[offset:]...), primary[:offset]...)
	}
	return append(append([]*entry(nil), primary...), reserve...)
}
func (p *Pool) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	for _, e := range p.candidates(network, address) {
		attempt, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(8*time.Second, cancel)
		c, err := e.Transport.DialContext(attempt, network, address)
		timer.Stop()
		if err == nil && attempt.Err() != nil {
			c.Close()
			err = attempt.Err()
		}
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			p.record(e, 0, err)
			continue
		}
		wrapped := &flowConn{Conn: c, p: p, cancel: cancel}
		if !p.track(wrapped) {
			wrapped.Close()
			return nil, net.ErrClosed
		}
		return wrapped, nil
	}
	return nil, ErrNoServer
}
func (p *Pool) ListenPacketTo(ctx context.Context, address string) (net.PacketConn, error) {
	for _, e := range p.candidates("udp", address) {
		c, err := e.Transport.ListenPacketTo(ctx, address)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			p.record(e, 0, err)
			continue
		}
		wrapped := &flowPacket{PacketConn: c, p: p, covers: e.Covers}
		if !p.track(wrapped) {
			c.Close()
			return nil, net.ErrClosed
		}
		return wrapped, nil
	}
	return nil, ErrNoServer
}
func (p *Pool) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("pool requires UDP destination")
}
func (p *Pool) track(c interface{ Close() error }) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.flows[c] = struct{}{}
	return true
}
func (p *Pool) untrack(c interface{ Close() error }) { p.mu.Lock(); delete(p.flows, c); p.mu.Unlock() }
func (p *Pool) Close() error {
	p.once.Do(func() {
		p.cancel()
		p.mu.Lock()
		p.closed = true
		flows := []interface{ Close() error }{}
		for c := range p.flows {
			flows = append(flows, c)
		}
		p.mu.Unlock()
		for _, c := range flows {
			p.closeErr = errors.Join(p.closeErr, c.Close())
		}
		for _, n := range p.nodes {
			p.closeErr = errors.Join(p.closeErr, n.Transport.Close())
		}
		p.wg.Wait()
		close(p.done)
	})
	return p.closeErr
}

type flowConn struct {
	net.Conn
	p      *Pool
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (c *flowConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.cancel(); c.p.untrack(c) })
	return c.err
}

type flowPacket struct {
	net.PacketConn
	p      *Pool
	covers func(string, string) bool
	once   sync.Once
	err    error
}

func (c *flowPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	if a == nil || !c.covers("udp", a.String()) {
		return 0, errors.New("UDP destination outside selected member coverage")
	}
	return c.PacketConn.WriteTo(b, a)
}
func (c *flowPacket) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close(); c.p.untrack(c) })
	return c.err
}

func (p *Pool) WaitReady(ctx context.Context) error {
	select {
	case <-p.first:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

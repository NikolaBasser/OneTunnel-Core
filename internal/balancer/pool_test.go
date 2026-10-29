package balancer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeTransport struct {
	id   string
	mu   sync.Mutex
	fail bool
	done chan struct{}
}

func (f *fakeTransport) Done() <-chan struct{} { return f.done }
func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return nil
}
func (f *fakeTransport) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	f.mu.Lock()
	bad := f.fail
	f.mu.Unlock()
	if bad {
		return nil, errors.New("offline")
	}
	client, server := net.Pipe()
	context.AfterFunc(ctx, func() { client.Close() })
	go func() { defer server.Close(); _, _ = io.WriteString(server, f.id); _, _ = io.Copy(server, server) }()
	return client, nil
}
func (f *fakeTransport) ListenPacketTo(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("no UDP fixture")
}
func TestPoolDistributionAffinityFailureAndClose(t *testing.T) {
	a := &fakeTransport{id: "a", done: make(chan struct{})}
	b := &fakeTransport{id: "b", done: make(chan struct{})}
	node := func(f *fakeTransport) Node {
		return Node{ID: f.id, Transport: f, Covers: func(n, a string) bool { return a == "192.0.2.1:443" }, Probe: func(context.Context) (time.Duration, error) { return 10 * time.Millisecond, nil }}
	}
	p, e := New([]Node{node(a), node(b)}, "balanced", 2, time.Hour, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if e = p.WaitReady(ctx); e != nil {
		t.Fatal(e)
	}
	first, e := p.DialContext(ctx, "tcp", "192.0.2.1:443")
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	buf := make([]byte, 1)
	io.ReadFull(first, buf)
	if string(buf) != "a" {
		t.Fatal("first node")
	}
	next, e := p.DialContext(ctx, "tcp", "192.0.2.1:443")
	if e != nil {
		t.Fatal(e)
	}
	io.ReadFull(next, buf)
	if string(buf) != "b" {
		t.Fatal("distribution")
	}
	next.Close()
	if _, e = p.DialContext(ctx, "tcp", "198.51.100.1:443"); !errors.Is(e, ErrNoServer) {
		t.Fatal("coverage bypass")
	}
	a.mu.Lock()
	a.fail = true
	a.mu.Unlock()
	flow, e := p.DialContext(ctx, "tcp", "192.0.2.1:443")
	if e != nil {
		t.Fatal("failed node not retried", e)
	}
	io.ReadFull(flow, buf)
	if string(buf) != "b" {
		t.Fatal("failover")
	}
	flow.Close()
	// A dialing timeout must not become an established native flow's lifetime.
	time.Sleep(8100 * time.Millisecond)
	go first.Write([]byte("x"))
	if _, e = io.ReadFull(first, buf); e != nil || string(buf) != "x" {
		t.Fatal("established flow expired or migrated", e)
	}
	b.mu.Lock()
	b.fail = true
	b.mu.Unlock()
	if _, e = p.DialContext(ctx, "tcp", "192.0.2.1:443"); !errors.Is(e, ErrNoServer) {
		t.Fatal("all-down did not fail closed", e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = p.DialContext(ctx, "tcp", "192.0.2.1:443"); !errors.Is(e, ErrNoServer) {
		t.Fatal("dial after close")
	}
}
func TestPoolQualityAndRecovery(t *testing.T) {
	a := &fakeTransport{id: "a", done: make(chan struct{})}
	b := &fakeTransport{id: "b", done: make(chan struct{})}
	var mu sync.Mutex
	bad := true
	nodes := []Node{}
	for _, f := range []*fakeTransport{a, b} {
		f := f
		nodes = append(nodes, Node{ID: f.id, Transport: f, Covers: func(string, string) bool { return true }, Probe: func(context.Context) (time.Duration, error) {
			mu.Lock()
			defer mu.Unlock()
			if f == a {
				if bad {
					return 0, errors.New("failed check")
				}
				return time.Millisecond, nil
			}
			return 15 * time.Millisecond, nil
		}})
	}
	p, e := New(nodes, "best", 2, 20*time.Millisecond, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.WaitReady(ctx)
	c, _ := p.DialContext(ctx, "tcp", "192.0.2.1:443")
	buf := make([]byte, 1)
	io.ReadFull(c, buf)
	c.Close()
	if string(buf) != "b" {
		t.Fatal("unhealthy selected")
	}
	mu.Lock()
	bad = false
	mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for {
		c, e = p.DialContext(ctx, "tcp", "192.0.2.1:443")
		if e != nil {
			t.Fatal(e)
		}
		io.ReadFull(c, buf)
		c.Close()
		if string(buf) == "a" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recovered server not selected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPoolUsesHealthyReserveBeyondDistributionLimit(t *testing.T) {
	nodes := []Node{}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeTransport{id: id, done: make(chan struct{}), fail: id != "c"}
		nodes = append(nodes, Node{ID: id, Transport: f, Covers: func(string, string) bool { return true }, Probe: func(context.Context) (time.Duration, error) { return time.Millisecond, nil }})
	}
	p, e := New(nodes, "best", 1, time.Hour, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.WaitReady(ctx)
	c, e := p.DialContext(ctx, "tcp", "192.0.2.1:443")
	if e != nil {
		t.Fatal("reserve omitted", e)
	}
	defer c.Close()
	b := make([]byte, 1)
	io.ReadFull(c, b)
	if string(b) != "c" {
		t.Fatal("healthy reserve not used")
	}
}

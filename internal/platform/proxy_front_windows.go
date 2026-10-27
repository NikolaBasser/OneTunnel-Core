package platform

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// A connection owns this loopback port until explicit stop or terminal failure.
// It forwards only to the configured engine; there is no direct fallback.
type proxyFront struct {
	listener net.Listener
	mu       sync.Mutex
	backend  int
	closed   bool
	flows    map[net.Conn]bool
	wg       sync.WaitGroup
}

func newProxyFront() (*proxyFront, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &proxyFront{listener: l, flows: map[net.Conn]bool{}}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			if f.closed || f.backend == 0 || len(f.flows) >= 256 {
				f.mu.Unlock()
				_ = c.Close()
				continue
			}
			backend := f.backend
			f.flows[c] = true
			f.wg.Add(1)
			f.mu.Unlock()
			go f.forward(c, backend)
		}
	}()
	return f, nil
}

func (f *proxyFront) port() int { return f.listener.Addr().(*net.TCPAddr).Port }
func (f *proxyFront) setBackend(port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.backend == port {
		return
	}
	f.backend = port
	for c := range f.flows {
		_ = c.Close()
	}
}
func (f *proxyFront) forward(c net.Conn, port int) {
	defer f.wg.Done()
	defer func() { _ = c.Close(); f.mu.Lock(); delete(f.flows, c); f.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return
	}
	defer b.Close()
	f.mu.Lock()
	if f.closed || f.backend != port {
		f.mu.Unlock()
		return
	}
	f.flows[b] = true
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.flows, b); f.mu.Unlock() }()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(b, c); _ = b.Close(); close(done) }()
	_, _ = io.Copy(c, b)
	_ = c.Close()
	<-done
}
func (f *proxyFront) close() {
	f.mu.Lock()
	f.closed = true
	f.backend = 0
	_ = f.listener.Close()
	for c := range f.flows {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (r *Runtime) activateConnection() {
	if r.front != nil {
		r.front.setBackend(r.backendPort)
	}
	r.activateStatistics()
}
func (r *Runtime) closeFront() {
	if r.front != nil {
		r.front.close()
		r.front = nil
	}
	r.stateMu.Lock()
	r.state.ProxyListenerStable = false
	r.stateMu.Unlock()
}

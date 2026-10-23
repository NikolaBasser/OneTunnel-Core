package embeddedawg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// Transport sends literal-IP TCP and UDP traffic through an embedded AWG peer.
type Transport struct {
	engine *Engine
	stack  *netstack.Net
	addrs  map[bool]bool
	local  map[bool]netip.Addr
	routes []netip.Prefix

	mu        sync.Mutex
	closed    bool
	flows     map[ioCloser]struct{}
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

type ioCloser interface{ Close() error }

// StartTransport takes ownership of plan's bind, including on failure. pin is
// called after the UDP sockets are opened and before the AWG device can send.
func StartTransport(plan *Plan, bind conn.Bind, pin func(conn.Bind) error) (_ *Transport, err error) {
	if bind == nil {
		return nil, errors.New("AWG bind is required")
	}
	if plan == nil {
		_ = bind.Close()
		return nil, errors.New("AWG plan is required")
	}
	if pin == nil {
		_ = bind.Close()
		return nil, errors.New("AWG physical interface binding is required")
	}
	if plan.MTU < 576 || plan.MTU > 65535 {
		_ = bind.Close()
		return nil, errors.New("AWG transport MTU is invalid")
	}
	endpoint, err := netip.ParseAddrPort(plan.Endpoint())
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().Zone() != "" {
		_ = bind.Close()
		return nil, errors.New("AWG endpoint must be a resolved literal IP")
	}
	addresses := make([]netip.Addr, 0, len(plan.Addresses))
	families := map[bool]bool{}
	local := map[bool]netip.Addr{}
	for _, prefix := range plan.Addresses {
		addr := prefix.Addr()
		if !addr.IsValid() || addr.IsUnspecified() || addr.Is4In6() || addr.Zone() != "" {
			_ = bind.Close()
			return nil, errors.New("AWG transport requires valid literal interface addresses")
		}
		if addr.Is6() && plan.MTU < 1280 {
			_ = bind.Close()
			return nil, errors.New("AWG transport MTU is too small for IPv6")
		}
		addresses = append(addresses, addr)
		families[addr.Is6()] = true
		if !local[addr.Is6()].IsValid() {
			local[addr.Is6()] = addr
		}
	}
	if len(addresses) == 0 {
		_ = bind.Close()
		return nil, errors.New("AWG transport requires an interface address")
	}
	device, stack, err := netstack.CreateNetTUN(addresses, nil, plan.MTU)
	if err != nil {
		_ = bind.Close()
		return nil, fmt.Errorf("create AWG userspace network: %w", err)
	}
	physicalBind := &pinningBind{Bind: bind, pin: pin}
	engine, err := Start(plan, device, physicalBind)
	if err != nil {
		return nil, err
	}
	return &Transport{engine: engine, stack: stack, addrs: families, local: local, routes: append([]netip.Prefix(nil), plan.Routes...), flows: make(map[ioCloser]struct{}), closeDone: make(chan struct{})}, nil
}

type pinningBind struct {
	conn.Bind
	pin    func(conn.Bind) error
	mu     sync.Mutex
	opened bool
}

func (b *pinningBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.opened {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.opened = true
	b.mu.Unlock()
	fns, actualPort, err := b.Bind.Open(port)
	if err == nil {
		err = b.pin(b.Bind)
	}
	if err != nil {
		_ = b.Close()
		return nil, 0, err
	}
	return fns, actualPort, nil
}

func (b *pinningBind) Close() error {
	b.mu.Lock()
	b.opened = false
	b.mu.Unlock()
	return b.Bind.Close()
}

func (t *Transport) covers(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Is4In6() || addr.Zone() != "" || !t.addrs[addr.Is6()] {
		return false
	}
	for _, route := range t.routes {
		if route.Addr().Is6() == addr.Is6() && route.Contains(addr) {
			return true
		}
	}
	return false
}

func (t *Transport) register(flow ioCloser) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.flows[flow] = struct{}{}
	return true
}

func (t *Transport) unregister(flow ioCloser) {
	t.mu.Lock()
	delete(t.flows, flow)
	t.mu.Unlock()
}

func (t *Transport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("AWG dial context is required")
	}
	isTCP := network == "tcp" || network == "tcp4" || network == "tcp6"
	isUDP := network == "udp" || network == "udp4" || network == "udp6"
	if !isTCP && !isUDP {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	addr, err := parseLiteralAddrPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: stringAddr(address), Err: err}
	}
	if (network == "tcp4" || network == "udp4") && addr.Addr().Is6() || (network == "tcp6" || network == "udp6") && addr.Addr().Is4() || !t.covers(addr.Addr()) {
		return nil, errors.New("AWG destination is outside the configured peer routes or address families")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var conn net.Conn
	if isTCP {
		conn, err = t.stack.DialContextTCPAddrPort(ctx, addr)
	} else {
		conn, err = t.stack.DialUDPAddrPort(netip.AddrPort{}, addr)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	flow := &trackedConn{Conn: conn, owner: t}
	if !t.register(flow) {
		_ = flow.Close()
		return nil, net.ErrClosed
	}
	return flow, nil
}

func parseLiteralAddrPort(address string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.Is4In6() {
		return netip.AddrPort{}, errors.New("destination must be a literal IP address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("destination port is invalid")
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

type stringAddr string

func (a stringAddr) Network() string { return "ip" }
func (a stringAddr) String() string  { return string(a) }

func (t *Transport) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("AWG packet context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, &net.OpError{Op: "listen", Net: network, Err: net.UnknownNetworkError(network)}
	}
	local, err := parseLocalAddrPort(address)
	if err != nil {
		return nil, err
	}
	families := make([]bool, 0, 2)
	if local.IsValid() {
		is6 := local.Addr().Is6()
		if network == "udp4" && is6 || network == "udp6" && !is6 || !t.addrs[is6] {
			return nil, errors.New("AWG local address family is unavailable")
		}
		families = append(families, is6)
	} else {
		if network != "udp6" && t.addrs[false] {
			families = append(families, false)
		}
		if network != "udp4" && t.addrs[true] {
			families = append(families, true)
		}
	}
	if network == "udp4" && (len(families) == 0 || families[0]) || network == "udp6" && (len(families) == 0 || !families[0]) {
		return nil, errors.New("AWG local address family is unavailable")
	}
	if len(families) == 0 {
		return nil, errors.New("AWG transport has no supported UDP address family")
	}
	result := &packetConn{owner: t, conns: make(map[bool]net.PacketConn), packets: make(chan packetResult, 2), done: make(chan struct{}), readWake: make(chan struct{}, 1)}
	for _, is6 := range families {
		bindAddr := netip.AddrPortFrom(t.local[is6], 0)
		if local.IsValid() && !local.Addr().IsUnspecified() {
			bindAddr = local
		} else if local.IsValid() {
			bindAddr = netip.AddrPortFrom(t.local[is6], local.Port())
		}
		udp, err := t.stack.ListenUDPAddrPort(bindAddr)
		if err != nil {
			result.close()
			return nil, err
		}
		result.conns[is6] = udp
		if result.localAddr == nil {
			result.localAddr = udp.LocalAddr()
		}
		result.readers.Add(1)
		go result.readLoop(udp)
	}
	if !t.register(result) {
		result.close()
		return nil, net.ErrClosed
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = result.Close() })
	result.mu.Lock()
	if result.closed {
		result.mu.Unlock()
		stopCancel()
	} else {
		result.stopCancel = stopCancel
		result.mu.Unlock()
	}
	return result, nil
}

func parseLocalAddrPort(address string) (netip.AddrPort, error) {
	if address == "" {
		return netip.AddrPort{}, nil
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.AddrPort{}, errors.New("AWG local port is invalid")
	}
	if host == "" {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)), nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return netip.AddrPort{}, errors.New("AWG local address must be a literal IP")
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

type packetResult struct {
	data   []byte
	buffer []byte
	addr   net.Addr
	err    error
}

var packetBuffers = sync.Pool{New: func() any { return make([]byte, 65535) }}

type packetConn struct {
	owner      *Transport
	conns      map[bool]net.PacketConn
	packets    chan packetResult
	done       chan struct{}
	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	stopCancel func() bool
	readDead   time.Time
	readWake   chan struct{}
	localAddr  net.Addr
	readers    sync.WaitGroup
}

func (p *packetConn) readLoop(c net.PacketConn) {
	defer p.readers.Done()
	for {
		buf := packetBuffers.Get().([]byte)
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			packetBuffers.Put(buf)
			select {
			case p.packets <- packetResult{err: err}:
			case <-p.done:
				return
			}
			if p.isClosed() {
				return
			}
			continue
		}
		select {
		case p.packets <- packetResult{data: buf[:n], buffer: buf, addr: addr}:
		case <-p.done:
			packetBuffers.Put(buf)
			return
		}
	}
}

func (p *packetConn) isClosed() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.closed }

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := p.readDead
		p.mu.Unlock()
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, timeoutError{}
			}
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
		select {
		case packet := <-p.packets:
			if timer != nil {
				timer.Stop()
			}
			if packet.buffer != nil {
				defer packetBuffers.Put(packet.buffer)
			}
			if packet.err != nil {
				return 0, nil, packet.err
			}
			n := copy(b, packet.data)
			return n, packet.addr, nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-p.readWake:
			if timer != nil {
				timer.Stop()
			}
		case <-timerC:
			return 0, nil, timeoutError{}
		}
	}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return 0, errors.New("AWG UDP destination must be a literal IP address")
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if ok {
		ip = ip.Unmap()
	}
	if !ok || ip.IsUnspecified() || ip.Zone() != "" || udpAddr.Port < 1 || udpAddr.Port > 65535 {
		return 0, errors.New("AWG UDP destination must be a literal IP address and valid port")
	}
	if !p.owner.covers(ip) {
		return 0, errors.New("AWG UDP destination is outside the configured peer routes or address families")
	}
	conn := p.conns[ip.Is6()]
	if conn == nil {
		return 0, errors.New("AWG UDP destination family is unavailable")
	}
	return conn.WriteTo(b, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: udpAddr.Port})
}

func (p *packetConn) Close() error { return p.close() }
func (p *packetConn) close() error {
	var first error
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.done)
		stopCancel := p.stopCancel
		p.mu.Unlock()
		if stopCancel != nil {
			stopCancel()
		}
		for _, c := range p.conns {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
		p.readers.Wait()
		for {
			select {
			case packet := <-p.packets:
				if packet.buffer != nil {
					packetBuffers.Put(packet.buffer)
				}
			default:
				p.owner.unregister(p)
				return
			}
		}
	})
	return first
}

func (p *packetConn) LocalAddr() net.Addr {
	return p.localAddr
}

func (p *packetConn) SetDeadline(deadline time.Time) error {
	if err := p.SetReadDeadline(deadline); err != nil {
		return err
	}
	return p.SetWriteDeadline(deadline)
}
func (p *packetConn) SetReadDeadline(deadline time.Time) error {
	p.mu.Lock()
	p.readDead = deadline
	p.mu.Unlock()
	select {
	case p.readWake <- struct{}{}:
	default:
	}
	return nil
}
func (p *packetConn) SetWriteDeadline(deadline time.Time) error {
	for _, c := range p.conns {
		if err := c.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type trackedConn struct {
	net.Conn
	owner *Transport
	once  sync.Once
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.owner.unregister(c) })
	return err
}

func (t *Transport) Close() error {
	if t == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		flows := make([]ioCloser, 0, len(t.flows))
		for flow := range t.flows {
			flows = append(flows, flow)
		}
		t.mu.Unlock()
		for _, flow := range flows {
			_ = flow.Close()
		}
		t.closeErr = t.engine.Close()
		close(t.closeDone)
	})
	<-t.closeDone
	return t.closeErr
}

func (t *Transport) Done() <-chan struct{} { return t.engine.Done() }
func (t *Transport) Counters() (uploaded, downloaded uint64, err error) {
	return t.engine.Counters()
}

var _ net.PacketConn = (*packetConn)(nil)

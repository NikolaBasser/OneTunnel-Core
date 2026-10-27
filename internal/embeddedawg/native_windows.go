package embeddedawg

import (
	"context"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	singtun "github.com/sagernet/sing-tun"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

type Native struct {
	core   *Engine
	luid   winipcfg.LUID
	routes []net.IPNet
	once   sync.Once
	err    error
}

// Share sing-tun's Wintun loader with the embedded sing-box engine. Loading a
// second Wintun DLL in the same process conflicts on its private namespace.
type sharedTUN struct {
	device singtun.WinTun
	events chan tun.Event
	mtu    int
	once   sync.Once
	err    error
}

func (t *sharedTUN) File() *os.File           { return nil }
func (t *sharedTUN) Name() (string, error)    { return t.device.Name() }
func (t *sharedTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *sharedTUN) Events() <-chan tun.Event { return t.events }
func (t *sharedTUN) BatchSize() int           { return 1 }
func (t *sharedTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.device.Read(buffers[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (t *sharedTUN) Write(buffers [][]byte, offset int) (int, error) {
	for i, packet := range buffers {
		if _, err := t.device.Write(packet[offset:]); err != nil {
			return i, err
		}
	}
	return len(buffers), nil
}
func (t *sharedTUN) Close() error {
	t.once.Do(func() { t.err = t.device.Close(); close(t.events) })
	return t.err
}

func splitRoutes(routes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range routes {
		route = route.Masked()
		if route.Bits() != 0 {
			out = append(out, route)
			continue
		}
		if route.Addr().Is4() {
			out = append(out, netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"))
		} else {
			out = append(out, netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"))
		}
	}
	return out
}
func ipNet(prefix netip.Prefix) net.IPNet {
	return net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}
func gateway(route net.IPNet) net.IP {
	if route.IP.To4() != nil {
		return net.IPv4zero
	}
	return net.IPv6zero
}

// StartNative configures only a newly created adapter. Endpoint sockets are
// pinned before adding routes; ordinary WG uses this same AWG implementation.
func StartNative(ctx context.Context, p *Plan, name string, uplinkIndex uint32) (native *Native, err error) {
	if uplinkIndex == 0 {
		return nil, errors.New("AWG uplink unavailable")
	}
	adapters, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, adapter := range adapters {
		if adapter.Name == name {
			return nil, errors.New("existing AWG adapter requires recovery")
		}
	}
	adapter, err := singtun.New(singtun.Options{Name: name, MTU: uint32(p.MTU), DNSMode: singtun.DNSModeDisabled, EXP_ExternalConfiguration: true})
	if err != nil {
		return nil, fmt.Errorf("embedded AWG adapter creation failed: %w", err)
	}
	luidProvider, ok := adapter.(interface{ LUID() uint64 })
	if !ok {
		adapter.Close()
		return nil, errors.New("embedded AWG adapter identity unavailable")
	}
	bind := conn.NewDefaultBind()
	core, err := Start(p, &sharedTUN{device: adapter, events: make(chan tun.Event), mtu: p.MTU}, bind)
	if err != nil {
		return nil, err
	}
	native = &Native{core: core, luid: winipcfg.LUID(luidProvider.LUID())}
	owner := native
	defer func() {
		if err != nil {
			owner.Close()
		}
	}()
	binder, ok := bind.(interface {
		BindSocketToInterface4(uint32, bool) error
		BindSocketToInterface6(uint32, bool) error
	})
	if !ok {
		return nil, errors.New("AWG interface binding unavailable")
	}
	if err = binder.BindSocketToInterface4(uplinkIndex, false); err != nil {
		return nil, errors.New("AWG IPv4 uplink binding failed")
	}
	if err = binder.BindSocketToInterface6(uplinkIndex, false); err != nil {
		return nil, errors.New("AWG IPv6 uplink binding failed")
	}
	addresses := make([]net.IPNet, 0, len(p.Addresses))
	for _, address := range p.Addresses {
		addresses = append(addresses, ipNet(address))
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, rowErr := native.luid.IPInterface(family)
		if rowErr != nil {
			err = errors.New("AWG interface settings unavailable")
			return nil, err
		}
		row.NLMTU = uint32(p.MTU)
		row.UseAutomaticMetric = false
		row.Metric = 0
		row.DadTransmits = 0
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		row.ManagedAddressConfigurationSupported = false
		row.OtherStatefulConfigurationSupported = false
		if err = row.Set(); err != nil {
			return nil, errors.New("AWG interface settings failed")
		}
		if err = native.luid.SetDNS(family, p.DNS, p.SearchDomains); err != nil {
			return nil, errors.New("AWG DNS settings failed")
		}
	}
	if err = native.luid.SetIPAddresses(addresses); err != nil {
		return nil, errors.New("AWG addresses could not be configured")
	}
	for _, route := range splitRoutes(p.Routes) {
		destination := ipNet(route)
		if err = native.luid.AddRoute(destination, gateway(destination), 0); err != nil {
			return nil, errors.New("AWG route installation failed")
		}
		native.routes = append(native.routes, destination)
	}
	readyContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		ready := true
		for _, address := range p.Addresses {
			row, e := native.luid.IPAddress(net.IP(address.Addr().AsSlice()))
			if e != nil || row.DadState != winipcfg.DadStatePreferred {
				ready = false
				break
			}
		}
		if ready {
			break
		}
		select {
		case <-readyContext.Done():
			err = errors.New("AWG addresses not ready")
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return native, nil
}
func (n *Native) Done() <-chan struct{} { return n.core.Done() }
func (n *Native) Counters() (uploaded, downloaded uint64, err error) {
	return n.core.Counters()
}
func (n *Native) Close() error {
	if n == nil {
		return nil
	}
	n.once.Do(func() {
		for _, route := range n.routes {
			_ = n.luid.DeleteRoute(route, gateway(route))
		}
		n.err = n.core.Close()
	})
	return n.err
}

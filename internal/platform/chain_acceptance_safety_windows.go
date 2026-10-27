//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"net"
	"os"
	"strings"
)

// Loopback-only controlled hops. Only the exit can dial the public HTTPS targets;
// the entry separately permits the configured encrypted DNS resolver.
type ChainAcceptanceFixture struct {
	hops      [3]*acceptanceGateway
	addresses [3]string
}

func NewChainAcceptanceFixture(physical string) (f *ChainAcceptanceFixture, err error) {
	host, _ := os.Hostname()
	if !strings.EqualFold(host, "WIN-67BE833BA6F") || physical != "Ethernet" {
		return nil, errors.New("dedicated VM interface required")
	}
	f = &ChainAcceptanceFixture{}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	dialer, err := interfaceDialer(physical)
	if err != nil {
		return nil, err
	}
	for i := range f.hops {
		f.hops[i], err = newAcceptanceGateway()
		if err != nil {
			return nil, err
		}
		f.addresses[i] = f.hops[i].address
		g := f.hops[i]
		g.mu.Lock()
		g.destinations = map[string]int{}
		g.dialConnect = func(ctx context.Context, address string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(address)
			if e != nil {
				return nil, e
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
			}
			if net.ParseIP(host) == nil {
				host, e = secureBootstrapLookupWithDial(ctx, host, dialer.DialContext)
				if e != nil {
					return nil, e
				}
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		}
		g.mu.Unlock()
	}
	for i, g := range f.hops {
		index := i
		g.mu.Lock()
		g.allowConnect = func(address string) bool {
			if index < 2 {
				return address == f.addresses[index+1] || index == 0 && address == "1.1.1.1:443"
			}
			if acceptanceConnectTarget(address) {
				return true
			}
			host, port, e := net.SplitHostPort(address)
			ip := net.ParseIP(host)
			return e == nil && port == "443" && ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
		}
		g.mu.Unlock()
	}
	return f, nil
}
func (f *ChainAcceptanceFixture) Close() {
	for _, g := range f.hops {
		if g != nil {
			g.stop()
		}
	}
}
func (f *ChainAcceptanceFixture) SetOnline(hop int, online bool) error {
	if hop < 0 || hop >= len(f.hops) {
		return errors.New("invalid hop")
	}
	if online {
		return f.hops[hop].start()
	}
	f.hops[hop].stop()
	return nil
}
func (f *ChainAcceptanceFixture) Counts() [3]int {
	var counts [3]int
	for i, g := range f.hops {
		g.mu.Lock()
		if i < 2 {
			counts[i] = g.destinations[f.addresses[i+1]]
		} else {
			counts[i] = g.connections
		}
		g.mu.Unlock()
	}
	return counts
}
func (f *ChainAcceptanceFixture) Profile() control.Profile {
	rules := []protocol.NetworkRule{}
	for _, domain := range []string{"example.com", "www.gstatic.com", "captive.apple.com"} {
		rules = append(rules, protocol.NetworkRule{Kind: "domain", Value: domain, Action: "proxy", Outbound: "exit"})
	}
	return control.Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "Controlled three-hop chain", Group: "Chain acceptance", Protocol: 6, Source: "http://" + f.addresses[0], Network: &protocol.NetworkOptions{Targets: []protocol.PolicyTarget{{Name: "middle", Protocol: 6, Source: "http://" + f.addresses[1], Via: "@primary"}, {Name: "exit", Protocol: 6, Source: "http://" + f.addresses[2], Via: "middle"}}, Rules: rules}}
}

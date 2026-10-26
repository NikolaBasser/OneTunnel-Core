package embeddedawg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ProbeDNSAddress never expands imported peer routes or resolves a DNS hostname.
func (p *Plan) ProbeDNSAddress() (netip.Addr, bool) {
	for _, ip := range p.DNS {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		family := false
		for _, local := range p.Addresses {
			if local.Addr().Is6() == addr.Is6() {
				family = true
				break
			}
		}
		if !family {
			continue
		}
		for _, route := range p.Routes {
			if route.Contains(addr) {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

// UseEphemeralListenPort affects this parsed plan only, never the imported source.
func (p *Plan) UseEphemeralListenPort() { delete(p.values, "ilistenport") }

// ProbeDNS measures a single DNS exchange, which may include the initial handshake.
func (t *Transport) ProbeDNS(ctx context.Context, address netip.Addr) (time.Duration, error) {
	if ctx == nil {
		return 0, errors.New("DNS probe context required")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var token [2]byte
	if _, err := rand.Read(token[:]); err != nil {
		return 0, errors.New("DNS probe token unavailable")
	}
	// A root SOA answer stays small without EDNS; root NS often truncates at 512 bytes.
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(token[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	data, err := query.Pack()
	if err != nil {
		return 0, errors.New("DNS probe encoding failed")
	}
	c, err := t.DialContext(ctx, "udp", netip.AddrPortFrom(address, 53).String())
	if err != nil {
		return 0, errors.New("DNS probe transport unavailable")
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return 0, errors.New("DNS probe deadline unavailable")
	}
	started := time.Now()
	if _, err = c.Write(data); err != nil {
		return 0, errors.New("DNS probe write failed")
	}
	body := make([]byte, 65535)
	n, err := c.Read(body)
	if err != nil || ctx.Err() != nil {
		return 0, errors.New("DNS probe response unavailable")
	}
	var response dnsmessage.Message
	if response.Unpack(body[:n]) != nil || !response.Response || response.OpCode != 0 || response.Truncated || response.RCode != dnsmessage.RCodeSuccess || response.ID != query.ID || len(response.Questions) != 1 || response.Questions[0] != question {
		return 0, errors.New("DNS probe response rejected")
	}
	return time.Since(started), nil
}

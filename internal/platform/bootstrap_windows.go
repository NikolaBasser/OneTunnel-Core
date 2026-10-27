package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type bootstrapKey struct{}
type bootstrapResolver struct {
	cache        map[string]string
	secure       bool
	forceSecure  bool
	attempt      int
	secureLookup func(context.Context, string) (string, error)
	systemLookup func(context.Context, string) ([]net.IPAddr, error)
}

func (b *bootstrapResolver) lookup(ctx context.Context, host string) (string, error) {
	cached := b.cache[host]
	if b.secure {
		ip := net.ParseIP(cached)
		// Preserve internal names locally; never send them to a public resolver.
		localEndpoint := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !strings.Contains(host, ".") || strings.HasSuffix(host, ".local")
		if cached != "" && (localEndpoint || !b.forceSecure && b.attempt <= 1) {
			return cached, nil
		}
		lookup := b.secureLookup
		if lookup == nil {
			lookup = secureBootstrapLookup
		}
		resolved, err := lookup(ctx, host)
		if err == nil {
			b.cache[host] = resolved
			return resolved, nil
		}
		if cached != "" && !b.forceSecure {
			return cached, nil
		}
		return "", err
	}
	lookup := b.systemLookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			b.cache[host] = ip.IP.String()
			return ip.IP.String(), nil
		}
	}
	if len(ips) > 0 {
		b.cache[host] = ips[0].IP.String()
		return ips[0].IP.String(), nil
	}
	return "", errors.New("no endpoint address")
}

func secureBootstrapLookup(ctx context.Context, host string) (string, error) {
	return secureBootstrapLookupWithDial(ctx, host, nil)
}

func secureBootstrapLookupWithDial(ctx context.Context, host string, dial func(context.Context, string, string) (net.Conn, error)) (string, error) {
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || !strings.Contains(ascii, ".") || strings.HasSuffix(ascii, ".local") {
		return "", errors.New("private endpoint DNS unavailable")
	}
	for _, resolver := range []struct{ address, name string }{{"1.1.1.1", "cloudflare-dns.com"}, {"8.8.8.8", "dns.google"}} {
		transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{ServerName: resolver.name, MinVersion: tls.VersionTLS12}}
		for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
			address, err := bootstrapQuery(deadline, &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, "https://"+resolver.address+"/dns-query", ascii, kind)
			cancel()
			if err == nil {
				transport.CloseIdleConnections()
				return address, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		transport.CloseIdleConnections()
	}
	return "", errors.New("secure endpoint DNS unavailable")
}

func bootstrapQuery(ctx context.Context, client *http.Client, endpoint, host string, kind dnsmessage.Type) (string, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return "", err
	}
	var token [2]byte
	if _, err = rand.Read(token[:]); err != nil {
		return "", err
	}
	id := binary.BigEndian.Uint16(token[:])
	question := dnsmessage.Question{Name: name, Type: kind, Class: dnsmessage.ClassINET}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	data, err := query.Pack()
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("DNS response rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return "", errors.New("invalid DNS response")
	}
	var answer dnsmessage.Message
	if answer.Unpack(body) != nil || !answer.Response || answer.ID != id || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 || answer.Questions[0] != question {
		return "", errors.New("DNS response mismatch")
	}
	for _, record := range answer.Answers {
		switch value := record.Body.(type) {
		case *dnsmessage.AResource:
			if kind == dnsmessage.TypeA {
				return net.IP(value.A[:]).String(), nil
			}
		case *dnsmessage.AAAAResource:
			if kind == dnsmessage.TypeAAAA {
				return net.IP(value.AAAA[:]).String(), nil
			}
		}
	}
	return "", errors.New("no endpoint address")
}

func pinNativeEndpoints(ctx context.Context, source string) (string, error) {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Endpoint") {
			continue
		}
		host, port, err := net.SplitHostPort(strings.TrimSpace(parts[1]))
		if err != nil {
			return "", err
		}
		address, err := resolveEndpoint(ctx, host)
		if err != nil {
			return "", err
		}
		lines[i] = "Endpoint = " + net.JoinHostPort(address, port)
	}
	return strings.Join(lines, "\n"), nil
}

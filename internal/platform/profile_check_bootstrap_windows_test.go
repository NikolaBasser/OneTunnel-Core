package platform

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDetachedPolicyProbeBootstrapKeepsEncryptedClockResolution(t *testing.T) {
	secure, system, dials := 0, 0, 0
	inherited := &bootstrapResolver{secureLookup: func(context.Context, string) (string, error) {
		secure++
		return "", errors.New("encrypted resolver unavailable")
	}, systemLookup: func(context.Context, string) ([]net.IPAddr, error) { system++; return nil, nil }}
	runtime := &Runtime{forceSecureBootstrap: true, bootstrapIPs: map[string]string{"www.cloudflare.com": "203.0.113.2"}}
	ctx := runtime.bootstrapContext(context.WithValue(context.Background(), bootstrapKey{}, inherited), nil)
	resolver := ctx.Value(bootstrapKey{}).(*bootstrapResolver)
	if !resolver.forceSecure || !resolver.secure {
		t.Fatal("detached policy lost encrypted bootstrap")
	}
	_, err := resolveAndDialClockEndpoint(ctx, "tcp", "www.cloudflare.com:443", resolveEndpoint, func(context.Context, string, string) (net.Conn, error) { dials++; return nil, nil })
	if err == nil || secure != 1 || system != 0 || dials != 0 {
		t.Fatalf("clock bootstrap failed open: %v secure=%d system=%d dial=%d", err, secure, system, dials)
	}
}

func TestDetachedXrayProbeResolvesPrimaryAndDownloadWithoutInterfaceBinding(t *testing.T) {
	calls := map[string]int{}
	ctx := context.WithValue(context.Background(), bootstrapKey{}, &bootstrapResolver{cache: map[string]string{}, secure: true, forceSecure: true, secureLookup: func(_ context.Context, host string) (string, error) { calls[host]++; return "203.0.113.4", nil }, systemLookup: func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("Xray probe used OS resolver")
		return nil, nil
	}})
	download := jsonObject{"address": "download.invalid", "tlsSettings": jsonObject{}, "xhttpSettings": jsonObject{}}
	stream := jsonObject{"tlsSettings": jsonObject{}, "xhttpSettings": jsonObject{"extra": jsonObject{"downloadSettings": download}}}
	peer := jsonObject{"address": "primary.invalid"}
	config := jsonObject{"outbounds": []any{jsonObject{"protocol": "vless", "settings": jsonObject{"vnext": []any{peer}}, "streamSettings": stream}}}
	bound := 0
	if err := prepareXrayWithBinding(ctx, config, func(jsonObject, string) error { bound++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls["primary.invalid"] != 1 || calls["download.invalid"] != 1 || bound != 2 || jString(peer["address"]) != "203.0.113.4" || jString(jObject(stream["tlsSettings"])["serverName"]) != "primary.invalid" || jString(jObject(download["tlsSettings"])["serverName"]) != "download.invalid" {
		t.Fatal("encrypted endpoint preparation lost TLS identity or skipped a hostname")
	}
}

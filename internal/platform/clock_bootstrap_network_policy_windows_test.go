package platform

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestPolicyClockProbeResolvesEncryptedAndFailsBeforeDial(t *testing.T) {
	secureCalls, systemCalls, dialCalls := 0, 0, 0
	resolver := &bootstrapResolver{cache: map[string]string{}, secure: true, forceSecure: true,
		secureLookup: func(_ context.Context, host string) (string, error) {
			secureCalls++
			if host != "www.cloudflare.com" {
				t.Fatalf("unexpected clock hostname: %s", host)
			}
			return "203.0.113.42", nil
		},
		systemLookup: func(context.Context, string) ([]net.IPAddr, error) {
			systemCalls++
			return nil, errors.New("system DNS called")
		},
	}
	ctx := context.WithValue(context.Background(), bootstrapKey{}, resolver)
	conn, err := resolveAndDialClockEndpoint(ctx, "tcp", "www.cloudflare.com:443", resolveEndpoint, func(_ context.Context, network, address string) (net.Conn, error) {
		dialCalls++
		if network != "tcp" || address != "203.0.113.42:443" {
			t.Fatalf("unexpected dial target %s %s", network, address)
		}
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if secureCalls != 1 || systemCalls != 0 || dialCalls != 1 {
		t.Fatalf("secure=%d system=%d dial=%d", secureCalls, systemCalls, dialCalls)
	}

	resolver.secureLookup = func(context.Context, string) (string, error) {
		secureCalls++
		return "", errors.New("encrypted bootstrap failed")
	}
	_, err = resolveAndDialClockEndpoint(ctx, "tcp", "www.cloudflare.com:443", resolveEndpoint, func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, nil
	})
	if err == nil || secureCalls != 2 || systemCalls != 0 || dialCalls != 1 {
		t.Fatalf("failed bootstrap did not fail closed: err=%v secure=%d system=%d dial=%d", err, secureCalls, systemCalls, dialCalls)
	}
}

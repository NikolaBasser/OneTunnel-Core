package platform

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestSecurePolicyBootstrapNeverFallsBackToSystemDNS(t *testing.T) {
	systemCalled := false
	secureCalled := false
	resolver := &bootstrapResolver{
		cache: map[string]string{"proxy.example": "203.0.113.1"}, secure: true, forceSecure: true, attempt: 1,
		systemLookup: func(context.Context, string) ([]net.IPAddr, error) {
			systemCalled = true
			return nil, errors.New("system DNS must not run")
		},
		secureLookup: func(context.Context, string) (string, error) {
			secureCalled = true
			return "", errors.New("encrypted bootstrap failed")
		},
	}
	if address, err := resolver.lookup(context.Background(), "proxy.example"); err == nil || address != "" {
		t.Fatal("failed encrypted bootstrap used fallback", address, err)
	}
	if !secureCalled || systemCalled || resolver.cache["proxy.example"] != "203.0.113.1" {
		t.Fatalf("resolver path secure=%v system=%v", secureCalled, systemCalled)
	}
}

//go:build windows && embeddedawg

package platform

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestNativeGroupNoTargetSkipsBootstrapAndUsesEncryptedBootstrapOnly(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	source := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.77.0.1/32\nDNS = 10.77.0.3\nListenPort = 51820\n[Peer]\nPublicKey = " + key + "\nEndpoint = peer.example:51820\nAllowedIPs = 10.77.0.2/32\n"
	secureCalls := 0
	resolver := &bootstrapResolver{secureLookup: func(context.Context, string) (string, error) {
		secureCalls++
		return "", errors.New("synthetic encrypted failure")
	}}
	ctx := context.WithValue(context.Background(), bootstrapKey{}, resolver)
	network, latency, err := nativeGroupDNSProbe(ctx, source, 1)
	if err != nil || network || latency != nil || secureCalls != 0 {
		t.Fatal("unsafe target performed network work")
	}
	source = strings.ReplaceAll(source, "DNS = 10.77.0.3", "DNS = 10.77.0.2")
	network, latency, err = nativeGroupDNSProbe(ctx, source, 1)
	if err == nil || !network || latency != nil || secureCalls != 1 {
		t.Fatal("encrypted bootstrap did not fail closed")
	}
}

package profiles

import (
	"reflect"
	"testing"

	"onetunnel/core/internal/control"
	"onetunnel/core/internal/protocol"
)

func TestBundleBoundaryPreservesEncryptedSettings(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	document, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	const native = "[Interface]\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\nEndpoint = proxy.example:51820\nAllowedIPs = 10.9.0.1/32"
	sources := []string{
		native + "\n", native,
		vless, "socks5://user:synthetic@proxy.example:1080", "hy2://synthetic@proxy.example:443", "ss://aes-128-gcm:synthetic@proxy.example:443",
		"https://user:synthetic@proxy.example:443", "trojan://synthetic@proxy.example:443",
		"tuic://11111111-1111-4111-8111-111111111111:synthetic@proxy.example:443", "anytls://synthetic@proxy.example:443", "naive+https://user:synthetic@proxy.example:443",
	}
	for kind, source := range sources {
		p, err := Parse("Synthetic profile", source, &kind)
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		p.Group = "synthetic group"
		p.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
		if kind == 2 {
			p.Transport = &protocol.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
		}
		document.Profiles = append(document.Profiles, p)
	}
	document.CollapsedGroups = []string{"synthetic group"}
	document.SubscriptionSources = map[string]string{"synthetic group": "https://subscription.example/synthetic"}
	if err := store.Save(document); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || !reflect.DeepEqual(loaded, document) {
		t.Fatalf("encrypted profile/settings round trip changed across bundle boundary: %v", err)
	}
}

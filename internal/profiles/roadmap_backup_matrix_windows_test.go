package profiles

import (
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPortableBackupRoundTripsEveryProtocol(t *testing.T) {
	data, err := os.ReadFile("../protocol/testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Kind   int
		Source string
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	sources := map[int]string{}
	for _, f := range corpus {
		if f.Kind <= 5 && sources[f.Kind] == "" {
			sources[f.Kind] = f.Source
		}
	}
	for _, link := range []string{"http://user:password@127.0.0.1:8080", "trojan://secret@127.0.0.1:443?sni=example.com", "tuic://11111111-1111-4111-8111-111111111111:secret@127.0.0.1:443", "anytls://secret@127.0.0.1:443?sni=example.com", "naive+https://user:secret@127.0.0.1:443"} {
		sources[protocol.LinkKind(link)] = link
	}
	if len(sources) != protocol.MaxKind+1 {
		t.Fatalf("fixture coverage:%d", len(sources))
	}
	profiles := make([]Profile, 0, len(sources))
	for kind := 0; kind <= protocol.MaxKind; kind++ {
		p, parseErr := Parse("Synthetic portable", sources[kind], &kind)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		p.ID = fmtTrayID(kind)
		p.Group = "Manual"
		if kind >= 2 {
			p.Network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "tls", ServerIP: "1.1.1.1", ServerName: "one.one.one.one"}, Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "192.0.2.0/24", Action: "reject"}}, Resolvers: []protocol.DNSOptions{{Transport: "https", ServerIP: "8.8.8.8", ServerName: "dns.google"}}, DNSRules: []protocol.DNSRule{{Kind: "domain", Value: "synthetic.example", ResolverIndex: 0}}, AllowLAN: true}
		}
		profiles = append(profiles, p)
	}
	source := managementStore(t, Document{Profiles: profiles, FavoriteIDs: []string{profiles[0].ID, profiles[2].ID}, CollapsedGroups: []string{"Manual"}})
	original, err := source.Load()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "portable-all.otbackup")
	exporting := &Application{Store: source}
	if _, err = exporting.exportBackup(path, "Synthetic-transfer-password"); err != nil {
		t.Fatal(err)
	}
	target := managementStore(t, Document{})
	restoring := &Application{Store: target}
	view, err := restoring.previewBackupRestore(path, "Synthetic-transfer-password")
	if err != nil {
		t.Fatal(err)
	}
	result, err := restoring.applyBackupRestore(view.Token, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Profiles, original.Profiles) || !reflect.DeepEqual(result.FavoriteIDs, original.FavoriteIDs) || !reflect.DeepEqual(result.CollapsedGroups, original.CollapsedGroups) {
		t.Fatal("portable transfer lost protocol payload, options or metadata")
	}
	if source.Root == target.Root {
		t.Fatal("test must restore into a different encrypted store")
	}
}

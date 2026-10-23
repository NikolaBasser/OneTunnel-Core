//go:build windows && amd64 && embeddedtun && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"encoding/json"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFullDevicePolicyMatrixWithoutNetworkChanges(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	libraryPath := filepath.Join(filepath.Dir(executable), "libcronet.dll")
	if _, err = os.Stat(libraryPath); os.IsNotExist(err) {
		module, lookupErr := exec.Command("go", "list", "-mod=readonly", "-m", "-f", "{{.Dir}}", "github.com/sagernet/cronet-go/lib/windows_amd64").Output()
		if lookupErr != nil {
			t.Fatal("locate pinned Naive dependency:", lookupErr)
		}
		library, readErr := os.ReadFile(filepath.Join(strings.TrimSpace(string(module)), "libcronet.dll"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(libraryPath, library, 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if !tunSupported() {
		t.Skip("embeddedtun production tag required")
	}
	var corpus []struct {
		Kind   int
		Source string
	}
	data, err := os.ReadFile("../protocol/testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	sources := map[int]string{}
	for _, f := range corpus {
		if f.Kind >= 2 && f.Kind <= 5 && sources[f.Kind] == "" {
			sources[f.Kind] = f.Source
		}
	}
	for _, link := range []string{"http://user:password@127.0.0.1:8080", "trojan://secret@127.0.0.1:443?sni=example.com", "tuic://11111111-1111-4111-8111-111111111111:secret@127.0.0.1:443", "anytls://secret@127.0.0.1:443?sni=example.com", "naive+https://user:secret@127.0.0.1:443"} {
		sources[protocol.LinkKind(link)] = link
	}
	if len(sources) != 9 {
		t.Fatalf("protocol fixture coverage: %d", len(sources))
	}
	for kind, source := range sources {
		for _, dnsMode := range []string{"https", "tls"} {
			t.Run(strconv.Itoa(kind)+"/"+dnsMode, func(t *testing.T) {
				policy := &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: dnsMode, ServerIP: "1.1.1.1", ServerName: "dns.example"}, Rules: []protocol.NetworkRule{{Kind: "domain-suffix", Value: "example.com", Action: "proxy"}, {Kind: "cidr", Value: "192.0.2.0/24", Action: "direct"}, {Kind: "process", Value: `C:\Synthetic\blocked.exe`, Action: "reject"}}}
				plan, err := protocol.CompileWithNetwork(source, kind, true, 18111, 18112, `C:\Program Files\OneTunnel\OneTunnel.Service.exe`, nil, policy)
				if err != nil {
					t.Fatal(err)
				}
				if err = Validate([]byte(plan.Proxy)); err != nil {
					t.Fatalf("generated full-device engine plan rejected: %v", err)
				}
			})
		}
	}
}

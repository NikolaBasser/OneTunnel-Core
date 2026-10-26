package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func TestGroupHTTPSLatencyMeasuresProbeOnlyAndKeepsPolicyDetached(t *testing.T) {
	if !embeddedSingBoxAllowed(false, false) {
		t.Skip("loopback fixture requires embedded sing-box production build tag")
	}
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			runtime := &Runtime{root: t.TempDir(), directory: t.TempDir()}
			policy := &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "tls", ServerIP: "203.0.113.53", ServerName: "resolver.invalid"}, Rules: []protocol.NetworkRule{{Kind: "cidr", Value: "192.0.2.0/24", Action: "reject"}}}
			original := protocol.CloneNetworkOptions(policy)
			profile := &control.Profile{ID: "11111111-1111-4111-8111-111111111111", Name: "synthetic", Group: "manual", Protocol: 3, Source: "socks5://proxy.invalid:9", Network: policy}
			probeCalls := 0
			secureCalls := 0
			ctx := context.WithValue(context.Background(), bootstrapKey{}, &bootstrapResolver{secureLookup: func(context.Context, string) (string, error) { secureCalls++; return "127.0.0.1", nil }, systemLookup: func(context.Context, string) ([]net.IPAddr, error) {
				t.Fatal("policy probe used OS DNS")
				return nil, nil
			}})
			text, err := runtime.checkProfileWithProbeDirectory(ctx, profile, func(ctx context.Context, port int) error {
				probeCalls++
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
				if err != nil {
					t.Fatalf("engine was not ready before measurement: %v", err)
				}
				_ = conn.Close()
				time.Sleep(25 * time.Millisecond)
				if fail {
					return errors.New("synthetic probe failed")
				}
				return nil
			}, func(path string) error { return os.MkdirAll(path, 0700) })
			if err != nil || text == nil {
				t.Fatalf("check %v", err)
			}
			var check control.ProfileCheck
			if err := json.Unmarshal([]byte(*text), &check); err != nil {
				t.Fatal(err)
			}
			if probeCalls != 1 || secureCalls != 1 || !check.NetworkTest || check.Success == fail || !reflect.DeepEqual(profile.Network, original) {
				t.Fatalf("probe/policy semantics: %+v", check)
			}
			if fail {
				if check.HTTPSLatencyMilliseconds != nil {
					t.Fatal("failed probe fabricated latency")
				}
			} else {
				if check.HTTPSLatencyMilliseconds == nil || *check.HTTPSLatencyMilliseconds < 20 || check.Milliseconds < *check.HTTPSLatencyMilliseconds {
					t.Fatalf("invalid probe-only interval: %+v", check)
				}
			}
			if !strings.Contains(check.Message, "configuration only") || runtime.session != nil {
				t.Fatal("saved policy was not explicitly kept configuration-only")
			}
			files, err := os.ReadDir(runtime.root)
			if err != nil || len(files) != 0 {
				t.Fatalf("temporary engine state not cleaned: %v %v", files, err)
			}
		})
	}
}

func TestNativeGroupCheckNeverFabricatesHTTPSLatency(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	profile := &control.Profile{Protocol: 1, Source: "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n"}
	runtime := &Runtime{root: t.TempDir()}
	text, err := runtime.checkProfileWithProbe(context.Background(), profile, func(context.Context, int) error {
		t.Fatal("native configuration check invoked network probe")
		return nil
	})
	if err != nil || text == nil {
		t.Fatal(err)
	}
	var check control.ProfileCheck
	if json.Unmarshal([]byte(*text), &check) != nil || check.NetworkTest || check.HTTPSLatencyMilliseconds != nil {
		t.Fatal("native check returned network latency")
	}
}

func TestGroupCheckDirectoryFailureRemovesUnstartedRuntime(t *testing.T) {
	runtime := &Runtime{root: t.TempDir()}
	_, err := runtime.checkProfileWithProbeDirectory(context.Background(), &control.Profile{Protocol: 3, Source: "socks5://127.0.0.1:9"}, func(context.Context, int) error {
		t.Fatal("probe started after directory failure")
		return nil
	}, func(string) error { return errors.New("synthetic directory failure") })
	if err == nil {
		t.Fatal("directory failure was ignored")
	}
	entries, readErr := os.ReadDir(runtime.root)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("unstarted runtime left behind: %v %v", entries, readErr)
	}
}

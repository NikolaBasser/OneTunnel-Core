package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type sharedNativeHealthFixture struct {
	engineDone, nativeDone chan struct{}
	closes                 int
}

func (f *sharedNativeHealthFixture) Close() error                { f.closes++; return nil }
func (f *sharedNativeHealthFixture) Done() <-chan struct{}       { return f.engineDone }
func (f *sharedNativeHealthFixture) NativeDone() <-chan struct{} { return f.nativeDone }
func TestSharedNativeComponentFailureMarksTransportFailedWithoutUnlock(t *testing.T) {
	for _, component := range []string{"native", "router"} {
		t.Run(component, func(t *testing.T) {
			fixture := &sharedNativeHealthFixture{engineDone: make(chan struct{}), nativeDone: make(chan struct{})}
			if sharedNativeExited(fixture) || embeddedExited(fixture) {
				t.Fatal("live component failed")
			}
			if component == "native" {
				close(fixture.nativeDone)
			} else {
				close(fixture.engineDone)
			}
			runtime := &Runtime{root: t.TempDir(), session: &Session{Kind: "proxy"}, embeddedProxy: fixture, update: func(control.State) {}}
			runtime.poll()
			if !runtime.transportFailed || fixture.closes != 0 {
				t.Fatal("component failure was ignored or transport closed outside disconnect")
			}
		})
	}
	if sharedNativeExited(nil) {
		t.Fatal("legacy absent native component was marked failed")
	}
}
func TestSharedNativeUplinkRejectsUnpinnedAndTunnelBeforeLookup(t *testing.T) {
	for _, endpoint := range []string{"peer.invalid:51820", "bad"} {
		if _, err := sharedNativePhysicalInterface(endpoint, func(string) (string, error) { t.Fatal("unresolved endpoint reached OS route query"); return "", nil }, nil); err == nil {
			t.Fatal("accepted unresolved endpoint")
		}
	}
	for _, name := range []string{"", "OneTunnel", "onetunnel012345abcdef"} {
		if _, err := sharedNativePhysicalInterface("192.0.2.1:51820", func(string) (string, error) { return name, nil }, func(string) (*net.Interface, error) { t.Fatal("tunnel reached lookup"); return nil, nil }); err == nil {
			t.Fatal("accepted tunnel uplink")
		}
	}
	expected := errors.New("route unavailable")
	if _, err := sharedNativePhysicalInterface("[2001:db8::1]:51820", func(string) (string, error) { return "", expected }, nil); !errors.Is(err, expected) {
		t.Fatal(err)
	}
	adapter, err := sharedNativePhysicalInterface("192.0.2.1:51820", func(ip string) (string, error) {
		if ip != "192.0.2.1" {
			t.Fatal(ip)
		}
		return "Ethernet", nil
	}, func(name string) (*net.Interface, error) { return &net.Interface{Name: name, Index: 7}, nil })
	if err != nil || adapter.Index != 7 {
		t.Fatal(adapter, err)
	}
}
func TestSharedNativeCanceledBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Both compiled and disabled implementations must refuse without opening sockets.
	if _, err := startEmbeddedSharedNative(ctx, "invalid", 1, nil); err == nil {
		t.Fatal("started canceled/invalid transport")
	}
}

func TestNativePolicyGroupCheckRemainsConfigurationOnly(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	source := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = peer.invalid:51820\nAllowedIPs = 0.0.0.0/0\n"
	for _, kind := range []int{0, 1} {
		profile := &control.Profile{Protocol: kind, Source: source, Network: &protocol.NetworkOptions{AllowLAN: true}}
		runtime := &Runtime{root: t.TempDir()}
		text, err := runtime.checkProfileWithProbeDirectory(context.Background(), profile, func(context.Context, int) error { t.Fatal("native group check performed HTTPS"); return nil }, func(string) error { t.Fatal("native group check prepared runtime"); return nil })
		if err != nil || text == nil {
			t.Fatal(text, err)
		}
		var result control.ProfileCheck
		if err = json.Unmarshal([]byte(*text), &result); err != nil {
			t.Fatal(err)
		}
		if result.Success != sharedNativeAvailable() || result.NetworkTest || result.HTTPSLatencyMilliseconds != nil {
			t.Fatalf("native configuration verdict: %+v", result)
		}
		entries, err := os.ReadDir(runtime.root)
		if err != nil || len(entries) != 0 || runtime.session != nil || runtime.embeddedProxy != nil || runtime.embeddedNative != nil {
			t.Fatal("configuration check acquired runtime resources")
		}
	}
}

func TestSharedNativeUsesDistinctFamilyIndices(t *testing.T) {
	name, err := windows.UTF16PtrFromString("Ethernet")
	if err != nil {
		t.Fatal(err)
	}
	adapter := &windows.IpAdapterAddresses{FriendlyName: name, IfIndex: 7, Ipv6IfIndex: 11}
	four, six, err := sharedNativeAdapterIndices("Ethernet", []*windows.IpAdapterAddresses{adapter})
	if err != nil || four != 7 || six != 11 {
		t.Fatal(four, six, err)
	}
	adapter.Ipv6IfIndex = 0
	if _, _, err = sharedNativeAdapterIndices("Ethernet", []*windows.IpAdapterAddresses{adapter}); err == nil {
		t.Fatal("zero index could unbind family")
	}
	if _, _, err = sharedNativeAdapterIndices("missing", []*windows.IpAdapterAddresses{adapter}); err == nil {
		t.Fatal("missing adapter accepted")
	}
}

type nativeHealthFixture struct {
	sharedNativeHealthFixture
	calls   int
	failure error
}

func (f *nativeHealthFixture) NativeHealth(context.Context) error { f.calls++; return f.failure }
func TestSharedNativeHealthUsesConfiguredDNSInsteadOfPublicHTTPS(t *testing.T) {
	expected := errors.New("encrypted resolver unavailable")
	fixture := &nativeHealthFixture{sharedNativeHealthFixture: sharedNativeHealthFixture{nativeDone: make(chan struct{})}}
	runtime := &Runtime{embeddedProxy: fixture}
	noHTTPS := func(context.Context, int) error { t.Fatal("shared native health attempted public HTTPS"); return nil }
	if err := runtime.connectionHealthWithHTTPS(context.Background(), noHTTPS); err != nil || fixture.calls != 1 {
		t.Fatal(fixture.calls, err)
	}
	fixture.failure = expected
	if err := runtime.connectionHealthWithHTTPS(context.Background(), noHTTPS); !errors.Is(err, expected) || fixture.calls != 2 {
		t.Fatal(fixture.calls, err)
	}
	runtime.embeddedProxy = &sharedNativeHealthFixture{nativeDone: make(chan struct{})}
	if err := runtime.connectionHealthWithHTTPS(context.Background(), noHTTPS); err == nil {
		t.Fatal("missing native health silently fell back")
	}
}
func TestLegacyNativeAndProxyHealthKeepHTTPS(t *testing.T) {
	for _, shared := range []bool{false, true} {
		fixture := &nativeHealthFixture{}
		runtime := &Runtime{}
		if shared {
			runtime.embeddedProxy = fixture
		} else {
			runtime.embeddedNative = &sharedNativeHealthFixture{}
		}
		runtime.state.LocalPort = 1234
		calls := 0
		expected := errors.New("original HTTPS result")
		err := runtime.connectionHealthWithHTTPS(context.Background(), func(_ context.Context, port int) error {
			calls++
			if port != 1234 {
				t.Fatal(port)
			}
			return expected
		})
		if !errors.Is(err, expected) || calls != 1 || fixture.calls != 0 {
			t.Fatal(calls, fixture.calls, err)
		}
	}
}

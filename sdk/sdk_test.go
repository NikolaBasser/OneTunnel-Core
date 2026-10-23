package sdk_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/sdk"
)

const native = "[Interface]\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\nEndpoint = proxy.example:51820\nAllowedIPs = 10.9.0.1/32"
const vless = "vless://11111111-1111-4111-8111-111111111111@proxy.example:443?security=tls&sni=proxy.example"

func TestImportAndCompileEveryProfileKind(t *testing.T) {
	sources := []string{native, native, vless, "socks5://user:synthetic@proxy.example:1080", "hy2://synthetic@proxy.example:443", "ss://aes-128-gcm:synthetic@proxy.example:443", "https://user:synthetic@proxy.example:443", "trojan://synthetic@proxy.example:443", "tuic://11111111-1111-4111-8111-111111111111:synthetic@proxy.example:443", "anytls://synthetic@proxy.example:443", "naive+https://user:synthetic@proxy.example:443"}
	for kind, source := range sources {
		p, err := sdk.Parse("Synthetic profile", source, &kind)
		if err != nil || p.Protocol != kind || sdk.Validate(p) != nil {
			t.Fatalf("kind %d import: %v", kind, err)
		}
		plan, err := sdk.CompileLocal(p, 18734, 18735)
		if err != nil {
			t.Fatalf("kind %d compile: %v", kind, err)
		}
		if kind < 2 && plan.NativeSource == "" || kind >= 2 && plan.Proxy == "" {
			t.Fatalf("kind %d has no configuration", kind)
		}
		if strings.Contains(plan.Proxy, `"type":"tun"`) || strings.Contains(plan.Proxy, "xray.exe") {
			t.Fatal("local plan acquired a Windows full-device dependency")
		}
	}
}

func TestSubscriptionMergeKeepsOptionsAndRejectsInvalidInput(t *testing.T) {
	batch, err := sdk.ParseSubscription(vless + "\nsocks5://proxy.example:1080")
	if err != nil || len(batch.Profiles) != 2 {
		t.Fatal("subscription", err)
	}
	p := batch.Profiles[0]
	p.Group = "synthetic group"
	p.Transport = &sdk.TransportOptions{Fragment: true, FragmentLength: "100-200", FragmentInterval: "10-20", NoiseLength: "50-150", NoiseDelay: "10-20", MuxConcurrency: 8}
	p.Reliability = &sdk.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	p.Network = &sdk.NetworkOptions{Rules: []sdk.NetworkRule{{Kind: "domain", Value: "example.com", Action: "proxy"}}}
	if _, err := sdk.CompileLocal(p, 18734, 18735); err == nil {
		t.Fatal("local SDK silently ignored full-device network preferences")
	}
	network := p.Network
	p.Network = nil
	plan, err := sdk.CompileLocal(p, 18734, 18735)
	if err != nil || !strings.Contains(plan.Xray, "fragment") {
		t.Fatal("transport options", err)
	}
	fresh, err := sdk.Parse(p.Name, p.Source, &p.Protocol)
	if err != nil {
		t.Fatal(err)
	}
	p.Network = network
	merged, err := sdk.Merge([]sdk.Profile{p}, []sdk.Profile{fresh}, p.Group)
	if err != nil || len(merged.Profiles) != 1 || !reflect.DeepEqual(merged.Profiles[0].Transport, p.Transport) || !reflect.DeepEqual(merged.Profiles[0].Reliability, p.Reliability) || !reflect.DeepEqual(merged.Profiles[0].Network, p.Network) || merged.Profiles[0].ID != p.ID {
		t.Fatal("merge changed profile options", err)
	}
	if _, err := sdk.Parse("invalid", "not a profile", nil); err == nil {
		t.Fatal("invalid import accepted")
	}
	if _, err := sdk.ParseSubscription("not a subscription"); err == nil {
		t.Fatal("invalid subscription accepted")
	}
	if _, err := sdk.CompileLocal(sdk.Profile{}, 18734, 18735); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestCapabilitiesDoNotAdvertiseUnimplementedRuntime(t *testing.T) {
	for _, target := range [][2]string{{"windows", "amd64"}, {"windows", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"android", "amd64"}, {"android", "arm64"}, {"ios", "arm64"}} {
		c, err := sdk.CapabilitiesFor(target[0], target[1])
		implemented := target == [2]string{"windows", "amd64"}
		if err != nil || !c.PortableAPI || c.RuntimeAvailable != implemented || c.SystemProtection != implemented || c.OS != target[0] || c.Architecture != target[1] {
			t.Fatalf("incorrect support claim for %v: %+v %v", target, c, err)
		}
	}
	for _, target := range [][2]string{{"", ""}, {"unknown", "arm64"}, {"ios", "amd64"}, {"linux", "386"}, {"Windows", "amd64"}} {
		if _, err := sdk.CapabilitiesFor(target[0], target[1]); !errors.Is(err, sdk.ErrUnsupportedTarget) {
			t.Fatalf("unknown target accepted: %v", target)
		}
	}
}

type hostAdapter struct {
	state  sdk.State
	update func(sdk.State)
	closed bool
}

func (a *hostAdapter) Alive() bool { return !a.closed }
func (a *hostAdapter) Close()      { a.closed = true }
func (a *hostAdapter) Call(_ context.Context, r sdk.Request) (sdk.BackendResult, error) {
	switch r.Command {
	case "start":
		a.state = sdk.State{Active: true, Status: "synthetic connection"}
	case "stop", "recover":
		a.state = sdk.State{}
	}
	a.update(a.state)
	return sdk.BackendResult{State: a.state}, nil
}

func TestControllerRequiresAdapterAndPreservesLifecycle(t *testing.T) {
	if _, err := sdk.NewController(nil); !errors.Is(err, sdk.ErrAdapterRequired) {
		t.Fatal("missing host adapter accepted")
	}
	if _, err := sdk.NewController(func(func(sdk.State), func()) (sdk.Backend, error) {
		return nil, nil
	}); !errors.Is(err, sdk.ErrAdapterRequired) {
		t.Fatal("factory without a backend accepted")
	}
	factoryError := errors.New("synthetic adapter initialization failure")
	if _, err := sdk.NewController(func(func(sdk.State), func()) (sdk.Backend, error) {
		return nil, factoryError
	}); !errors.Is(err, factoryError) {
		t.Fatal("factory error was not preserved")
	}
	var adapter *hostAdapter
	controller, err := sdk.NewController(func(update func(sdk.State), _ func()) (sdk.Backend, error) {
		adapter = &hostAdapter{update: update}
		return adapter, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	profile, err := sdk.Parse("Synthetic", "socks5://proxy.example:1080", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := controller.Dispatch(context.Background(), sdk.Request{Version: sdk.APIVersion, Command: "start", Profile: &profile})
	if started.Error != nil || !started.State.Active || started.State.ProfileID == nil || *started.State.ProfileID != profile.ID {
		t.Fatal("adapter session did not start", started.Error)
	}
	stopped := controller.Dispatch(context.Background(), sdk.Request{Version: sdk.APIVersion, Command: "stop"})
	if stopped.Error != nil || stopped.State.Active || stopped.State.ProfileID != nil {
		t.Fatal("adapter session did not stop", stopped.Error)
	}
	controller.Close()
	if !adapter.closed {
		t.Fatal("host adapter was not closed")
	}
}

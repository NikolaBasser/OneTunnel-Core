package profiles

import (
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"reflect"
	"strings"
	"testing"
)

func globalTransportFixture() TransportInput {
	return TransportInput{Fragment: true, FragmentLength: "64", FragmentInterval: "0", Noise: true, NoiseLength: "53", NoiseDelay: "0", Mux: true, MuxConcurrency: "4", MuxProtocol: "yamux", MuxMaxConnections: "2", MuxMinStreams: "1", MuxPadding: true, XUDPConcurrency: "2", UDP443Policy: "reject"}
}

func TestGlobalTransportProtocolMatrix(t *testing.T) {
	prefs := UserPreferences{Transport: globalTransportFixture()}
	for _, tc := range []struct {
		name, source         string
		kind                 int
		fragment, noise, mux bool
	}{
		{"vless-tls", vless, 2, true, false, true},
		{"vision", vless + "&flow=xtls-rprx-vision", 2, true, false, false},
		{"kcp", "vless://6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a@127.0.0.1:443?type=kcp", 2, false, true, false},
		{"hysteria2", "hy2://fixture@127.0.0.1:443?sni=localhost", 4, false, true, false},
		{"shadowsocks", "ss://chacha20-ietf-poly1305:fixture@127.0.0.1:18080", 5, false, false, true},
		{"trojan", "trojan://fixture@127.0.0.1:443?sni=localhost", protocol.Trojan, false, false, true},
		{"socks", "socks5://127.0.0.1:1080", 3, false, false, false},
		{"wg", "native", 1, false, false, false}, {"awg", "native", 0, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{Protocol: tc.kind, Source: tc.source}
			before := p
			got, skipped, e := globalTransportProfile(p, prefs)
			if e != nil || got.Source != before.Source || got.Transport.Fragment != tc.fragment || got.Transport.Noise != tc.noise || got.Transport.Mux != tc.mux {
				t.Fatal(got, e)
			}
			if len(skipped) != 3-boolInt(tc.fragment)-boolInt(tc.noise)-boolInt(tc.mux) {
				t.Fatal("missing skipped-option notice", skipped)
			}
			if tc.mux && tc.kind == 2 && got.Transport.MuxProtocol != "" {
				t.Fatal("sing options leaked into Xray")
			}
			if tc.mux && tc.kind == 5 && (got.Transport.MuxProtocol != "yamux" || got.Transport.XUDPConcurrency != 0) {
				t.Fatal("wrong mux engine selection")
			}
			if tc.kind >= 2 {
				if _, e := protocol.CompileWithOptions(got.Source, got.Protocol, false, 18001, 18002, "", got.Transport); e != nil {
					t.Fatal("effective profile cannot compile", e)
				}
			}
		})
	}
	legacy := Profile{Transport: &protocol.TransportOptions{Mux: true}}
	untouched, _, _ := globalTransportProfile(legacy, UserPreferences{})
	if !reflect.DeepEqual(legacy, untouched) {
		t.Fatal("legacy profile changed before explicit global save")
	}
	off := prefs
	off.Transport.Fragment = false
	off.Transport.Noise = false
	off.Transport.Mux = false
	got, _, e := globalTransportProfile(legacy, off)
	if e != nil || got.Transport.Mux || !legacy.Transport.Mux {
		t.Fatal("global off did not override runtime-only", e)
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestGlobalTransportSaveAndStartFallbacks(t *testing.T) {
	a, _, _, _, _ := automationFixture(t)
	prefs := UserPreferences{Transport: globalTransportFixture()}
	saveAutomation(t, a, prefs)
	d, e := a.Store.Load()
	if e != nil || d.UserSettings.Transport != prefs.Transport {
		t.Fatal(e)
	}
	primary := d.Profiles[0]
	primary.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	secondary := primary
	secondary.ID = "22222222-2222-4222-8222-222222222222"
	secondary.Source = strings.Replace(vless, ":443?", ":444?", 1)
	secondary.Name = "Fallback"
	d.Profiles = []Profile{primary, secondary}
	if e = a.Store.Save(d); e != nil {
		t.Fatal(e)
	}
	before := storeBytes(t, a.Store)
	a.ServiceCall = func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Command != "start" || r.Profile == nil || !r.Profile.Transport.Fragment || !r.Profile.Transport.Mux || len(r.Fallbacks) != 1 || !r.Fallbacks[0].Transport.Fragment || !r.Fallbacks[0].Transport.Mux {
			t.Fatal("global settings absent from service start/fallbacks", r)
		}
		return control.Response{Version: control.Version, Instance: "global-test", Revision: 1, State: control.State{Active: true}}, 1, nil
	}
	reply := a.desktopCall(context.Background(), "start", &primary, false)
	if reply.Response.Error != nil || !strings.Contains(reply.Message, "шумы UDP") {
		t.Fatal("unsupported options were silent", reply)
	}
	if !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
		t.Fatal("starting with globals rewrote profiles")
	}
	bad := prefs
	bad.Transport.FragmentLength = "0"
	a.desktopState.Response.State = control.State{}
	view, _ := a.userSettingsView()
	if _, e = a.saveUserSettings(view.Token, &bad); e == nil || !reflect.DeepEqual(before, storeBytes(t, a.Store)) {
		t.Fatal("invalid global values altered storage")
	}
}

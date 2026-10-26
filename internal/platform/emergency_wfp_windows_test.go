package platform

import (
	"golang.org/x/sys/windows"
	"testing"
	"unsafe"
)

func TestEmergencyWFPLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("utility supports 64-bit Windows")
	}
	if unsafe.Sizeof(wFilter{}) != 200 || unsafe.Offsetof(wFilter{}.Provider) != 40 || unsafe.Offsetof(wFilter{}.Layer) != 64 || unsafe.Offsetof(wFilter{}.Action) != 128 || unsafe.Offsetof(wFilter{}.ID) != 176 || unsafe.Sizeof(wProvider{}) != 64 || unsafe.Sizeof(wSublayer{}) != 72 {
		t.Fatal("WFP ABI mismatch")
	}
}

func TestEmergencyProviderRequiresExactMetadata(t *testing.T) {
	data := make([]byte, 32)
	valid := wProvider{Display: wDisplayName("OneTunnel kill switch"), Flags: 1, Data: wBlob{Size: 32, Data: &data[0]}}
	if !emergencyProviderMatches(&valid) {
		t.Fatal("valid provider rejected")
	}
	for _, mutate := range []func(*wProvider){func(p *wProvider) { p.Display = wDisplayName("Another VPN") }, func(p *wProvider) { p.Display = wDisplayName("OneTunnel kill switch extra") }, func(p *wProvider) { p.Flags = 0 }, func(p *wProvider) { p.Data.Size = 31 }, func(p *wProvider) { p.Data.Data = nil }} {
		candidate := valid
		mutate(&candidate)
		if emergencyProviderMatches(&candidate) {
			t.Fatal("foreign or malformed provider accepted")
		}
	}
	if emergencyProviderMatches(nil) {
		t.Fatal("nil accepted")
	}
}

func TestEmergencyFilterRequiresRelatedSublayerAndKnownShape(t *testing.T) {
	sub := wGuid("11111111-1111-4111-8111-111111111111")
	valid := wFilter{Display: wDisplayName("OneTunnel · block direct traffic"), Flags: 1, Layer: wLayers[0], Sublayer: sub, Action: wAction{Type: 0x1001}, Weight: wValue{Type: 1}}
	if !emergencyFilterMatches(&valid, []windows.GUID{sub}) {
		t.Fatal("valid filter rejected")
	}
	for _, mutate := range []func(*wFilter){func(f *wFilter) { f.Display = wDisplayName("Windows Firewall") }, func(f *wFilter) { f.Layer = windows.GUID{} }, func(f *wFilter) { f.Sublayer = windows.GUID{} }, func(f *wFilter) { f.Action.Type = 0x1003 }, func(f *wFilter) { f.Flags = 0 }} {
		candidate := valid
		mutate(&candidate)
		if emergencyFilterMatches(&candidate, []windows.GUID{sub}) {
			t.Fatal("foreign or malformed filter accepted")
		}
	}
	if emergencyFilterMatches(&valid, nil) || emergencyFilterMatches(nil, nil) {
		t.Fatal("missing relationship accepted")
	}
}

func TestEmergencySelectionValidatesWholeSetBeforeDeletion(t *testing.T) {
	a := wGuid("11111111-1111-4111-8111-111111111111")
	b := wGuid("22222222-2222-4222-8222-222222222222")
	objects := []recoveryObjects{{provider: a, view: EmergencyWFPProvider{Recoverable: true}}, {provider: b, view: EmergencyWFPProvider{Recoverable: false, Reason: "foreign shape"}}}
	if selected, err := selectEmergencyProviders(objects, nil); err == nil || len(selected) != 0 {
		t.Fatal("partial unsafe set accepted")
	}
	if selected, err := selectEmergencyProviders(objects, &a); err != nil || len(selected) != 1 || selected[0].provider != a {
		t.Fatal("exact selection changed other provider")
	}
	foreign := windows.GUID{}
	if _, err := selectEmergencyProviders(objects, &foreign); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestEmergencyKnownTestProviderGUID(t *testing.T) {
	lock := trafficLock{owner: "OneTunnel-Test-412bc58265d84cddbfcf68e95d556301"}
	if lock.key("provider").String() != "{D6E3D9D9-3BA8-55E5-532F-4C821DB7929D}" {
		t.Fatal("historical key derivation changed")
	}
}

func TestEmergencyExpectedFingerprintRequiresExactProvider(t *testing.T) {
	var fingerprint [32]byte
	fingerprint[0] = 42
	provider := wProvider{Display: wDisplayName("OneTunnel kill switch"), Flags: 1, Data: wBlob{Size: 32, Data: &fingerprint[0]}}
	if !emergencyProviderFingerprintMatches(&provider, fingerprint) {
		t.Fatal("expected owner rejected")
	}
	other := fingerprint
	other[31] = 1
	if emergencyProviderFingerprintMatches(&provider, other) || emergencyProviderFingerprintMatches(nil, fingerprint) {
		t.Fatal("unexpected owner accepted")
	}
	provider.Display = wDisplayName("Another provider")
	if emergencyProviderFingerprintMatches(&provider, fingerprint) {
		t.Fatal("foreign metadata accepted")
	}
}

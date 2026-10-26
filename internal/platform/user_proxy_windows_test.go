//go:build windows

package platform

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

type fakeUserRegistry struct {
	values        map[string]RawRegistryValue
	failWrite     string
	writeFailures map[string]int
	events        []string
}

func TestWatchdogRetriesSharedLockUntilCleanupCanProceed(t *testing.T) {
	busyCount := 2
	waits := 0
	unlock, err := retryUserAutomationLock(func() (func(), error) {
		if busyCount > 0 {
			busyCount--
			return nil, errUserAutomationBusy
		}
		return func() {}, nil
	}, func(d time.Duration) {
		if d != 5*time.Second {
			t.Fatalf("unexpected retry wait %s", d)
		}
		waits++
	}, 4)
	if err != nil || unlock == nil || waits != 2 {
		t.Fatalf("lock=%v waits=%d err=%v", unlock != nil, waits, err)
	}
}

func TestWatchdogLockRetryStopsOnNonContentionError(t *testing.T) {
	failure := errors.New("mutex setup failed")
	waits := 0
	_, err := retryUserAutomationLock(func() (func(), error) { return nil, failure }, func(time.Duration) { waits++ }, 3)
	if !errors.Is(err, failure) || waits != 0 {
		t.Fatalf("err=%v waits=%d", err, waits)
	}
}

func fakeValueKey(key, name string) string { return key + "/" + name }
func (f *fakeUserRegistry) Read(key, name string) (RawRegistryValue, error) {
	return cloneRaw(f.values[fakeValueKey(key, name)]), nil
}
func (f *fakeUserRegistry) Write(key, name string, v RawRegistryValue) error {
	f.events = append(f.events, name)
	if f.writeFailures[name] > 0 {
		f.writeFailures[name]--
		return errors.New("transient write failure")
	}
	if f.failWrite == name {
		return errors.New("write failed")
	}
	f.values[fakeValueKey(key, name)] = cloneRaw(v)
	return nil
}
func (f *fakeUserRegistry) Delete(key, name string) error {
	delete(f.values, fakeValueKey(key, name))
	return nil
}
func cloneRaw(v RawRegistryValue) RawRegistryValue { v.Data = append([]byte(nil), v.Data...); return v }

func TestRestoreOwnedPreservesTypedMissingAndRawBaseline(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{
		fakeValueKey(userProxyRegistryKey, "ProxyEnable"): {Exists: true, Type: registry.DWORD, Data: []byte{0, 0, 0, 0}},
		fakeValueKey(userProxyRegistryKey, "ProxyServer"): {Exists: true, Type: registry.EXPAND_SZ, Data: []byte{0x41, 0, 0, 0}},
	}}
	j := proxyJournal{Baseline: map[string]RawRegistryValue{
		"ProxyEnable": {Exists: false}, "ProxyServer": {Exists: true, Type: registry.EXPAND_SZ, Data: []byte{0x41, 0, 0, 0}},
	}, Applied: map[string]RawRegistryValue{
		"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}, "ProxyServer": {Exists: true, Type: registry.SZ, Data: []byte{0x42, 0, 0, 0}},
	}}
	reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")] = cloneRaw(j.Applied["ProxyEnable"])
	reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")] = cloneRaw(j.Applied["ProxyServer"])
	conflict, err := restoreOwned(reg, j)
	if err != nil || conflict {
		t.Fatalf("restore conflict=%v err=%v", conflict, err)
	}
	if got := reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")]; got.Exists {
		t.Fatalf("absent baseline was not restored: %#v", got)
	}
	if got := reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")]; !sameRegistryValue(got, j.Baseline["ProxyServer"]) {
		t.Fatalf("raw typed baseline changed: %#v", got)
	}
}

func TestRestoreOwnedLeavesExternalEditAndRestoresOtherValues(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{
		fakeValueKey(userProxyRegistryKey, "ProxyEnable"): {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}},
		fakeValueKey(userProxyRegistryKey, "ProxyServer"): {Exists: true, Type: registry.SZ, Data: []byte{0x58, 0, 0, 0}},
	}}
	j := proxyJournal{Baseline: map[string]RawRegistryValue{"ProxyEnable": {Exists: false}, "ProxyServer": {Exists: true, Type: registry.SZ, Data: []byte{0x41, 0, 0, 0}}}, Applied: map[string]RawRegistryValue{
		"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}, "ProxyServer": {Exists: true, Type: registry.SZ, Data: []byte{0x42, 0, 0, 0}},
	}}
	conflict, err := restoreOwned(reg, j)
	if err != nil || !conflict {
		t.Fatalf("want external conflict, got conflict=%v err=%v", conflict, err)
	}
	if reg.values[fakeValueKey(userProxyRegistryKey, "ProxyEnable")].Exists {
		t.Fatal("owned ProxyEnable was not restored")
	}
	if got := reg.values[fakeValueKey(userProxyRegistryKey, "ProxyServer")]; got.Data[0] != 0x58 {
		t.Fatalf("external edit overwritten: %#v", got)
	}
}

func TestRestoreOwnedDoesNotTreatUnappliedBaselineAsExternalChange(t *testing.T) {
	baseline := RawRegistryValue{Exists: true, Type: registry.SZ, Data: []byte{0x41, 0, 0, 0}}
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{fakeValueKey(userProxyRegistryKey, "ProxyServer"): baseline}}
	j := proxyJournal{Baseline: map[string]RawRegistryValue{"ProxyServer": baseline}, Applied: map[string]RawRegistryValue{"ProxyServer": {Exists: true, Type: registry.SZ, Data: []byte{0x42, 0, 0, 0}}}}
	conflict, err := restoreOwned(reg, j)
	if err != nil || conflict {
		t.Fatalf("unchanged baseline considered conflict: %v %v", conflict, err)
	}
}

func TestProxyActivationRejectsPACAndUnknownAutoDetectValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]RawRegistryValue
	}{
		{"PAC", map[string]RawRegistryValue{"AutoConfigURL": {Exists: true, Type: registry.SZ, Data: registryStringBytes("https://pac.example/proxy.pac")}}},
		{"unknown PAC type", map[string]RawRegistryValue{"AutoConfigURL": {Exists: true, Type: registry.BINARY, Data: []byte{1}}}},
		{"automatic detection", map[string]RawRegistryValue{"AutoDetect": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}}}},
		{"malformed detection", map[string]RawRegistryValue{"AutoDetect": {Exists: true, Type: registry.DWORD, Data: []byte{0}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
			for key, value := range tc.values {
				reg.values[fakeValueKey(userProxyRegistryKey, key)] = value
			}
			if err := checkProxyAutoconfiguration(reg, func() (uint32, error) { return 0, nil }); err == nil {
				t.Fatal("conflicting or unknown proxy mode was accepted")
			}
		})
	}
}

func TestProxyActivationChecksAuthoritativeWinINETFlags(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	for _, flags := range []uint32{winINETProxyAutoURL, winINETProxyAutoDetect, winINETProxyAutoURL | winINETProxyAutoDetect} {
		if err := checkProxyAutoconfiguration(reg, func() (uint32, error) { return flags, nil }); err == nil {
			t.Errorf("accepted active WinINET auto flags %#x", flags)
		}
	}
	queryErr := errors.New("option query failed")
	if err := checkProxyAutoconfiguration(reg, func() (uint32, error) { return 0, queryErr }); !errors.Is(err, queryErr) {
		t.Fatalf("query error was not propagated: %v", err)
	}
	if err := checkProxyAutoconfiguration(reg, func() (uint32, error) { return 0, nil }); err != nil {
		t.Fatalf("explicit direct/manual settings should be accepted: %v", err)
	}
}

//go:build windows

package platform

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestOwnedStartupDoesNotReplaceUnrelatedRunValue(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{fakeValueKey(userProxyRunKey, userProxyRunValue): {Exists: true, Type: registry.SZ, Data: registryStringBytes(`C:\Other\app.exe`)}}}
	if err := enableOwnedStartup(reg, `"C:\OneTunnel\OneTunnel.exe" --startup`, ""); err == nil {
		t.Fatal("unrelated entry was replaced")
	}
	if got := decodeRegistryString(reg.values[fakeValueKey(userProxyRunKey, userProxyRunValue)]); got != `C:\Other\app.exe` {
		t.Fatalf("existing command changed: %q", got)
	}
}

func TestOwnedStartupIdempotenceRequiresSavedOwner(t *testing.T) {
	command := `"C:\OneTunnel\OneTunnel.exe" --startup`
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{fakeValueKey(userProxyRunKey, userProxyRunValue): {Exists: true, Type: registry.SZ, Data: registryStringBytes(command)}}}
	if err := enableOwnedStartup(reg, command, ""); err == nil {
		t.Fatal("existing identical value was adopted without saved ownership")
	}
	if err := enableOwnedStartup(reg, command, command); err != nil {
		t.Fatalf("saved owned value should be idempotent: %v", err)
	}
}

func TestOwnedStartupDisableRequiresExactCommand(t *testing.T) {
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{fakeValueKey(userProxyRunKey, userProxyRunValue): {Exists: true, Type: registry.SZ, Data: registryStringBytes(`"C:\OneTunnel\OneTunnel.exe" --startup`)}}}
	startup := UserStartup{Registry: reg}
	conflict, err := startup.Disable(`"C:\Other\OneTunnel.exe" --startup`)
	if err != nil || !conflict {
		t.Fatalf("expected ownership conflict, got %v %v", conflict, err)
	}
	if _, ok := reg.values[fakeValueKey(userProxyRunKey, userProxyRunValue)]; !ok {
		t.Fatal("conflicting startup value was deleted")
	}
	conflict, err = startup.Disable(`"C:\OneTunnel\OneTunnel.exe" --startup`)
	if err != nil || conflict {
		t.Fatalf("owned value should delete cleanly, got %v %v", conflict, err)
	}
	if _, ok := reg.values[fakeValueKey(userProxyRunKey, userProxyRunValue)]; ok {
		t.Fatal("owned startup value remains")
	}
}

func TestValidateStableExecutableRejectsTempAndNonAppPaths(t *testing.T) {
	if _, err := validateStableUserExecutable(`C:\Temp\OneTunnel.exe`); err == nil {
		t.Fatal("temporary path accepted")
	}
	if _, err := validateStableUserExecutable(`C:\OneTunnel\profiles.exe`); err == nil {
		t.Fatal("wrong executable accepted")
	}
}

func TestStartupCommandUsesWindowsArgumentQuoting(t *testing.T) {
	got := windows.EscapeArg(`C:\Apps\OneTunnel QA\OneTunnel.exe`) + " --startup"
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, " --startup") {
		t.Fatalf("unexpected startup command: %s", got)
	}
}

func TestStartupStatusRequiresExactOwnedTypedValue(t *testing.T) {
	command := `"C:\OneTunnel\OneTunnel.exe" --startup`
	key := fakeValueKey(userProxyRunKey, userProxyRunValue)
	reg := &fakeUserRegistry{values: map[string]RawRegistryValue{}}
	startup := UserStartup{Registry: reg}
	if enabled, err := startup.Status(command); err != nil || enabled {
		t.Fatalf("missing Run value: enabled=%v err=%v", enabled, err)
	}
	reg.values[key] = RawRegistryValue{Exists: true, Type: registry.EXPAND_SZ, Data: registryStringBytes(command)}
	if enabled, err := startup.Status(command); err != nil || enabled {
		t.Fatalf("wrong registry type: enabled=%v err=%v", enabled, err)
	}
	reg.values[key] = RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes(command + " ")}
	if enabled, err := startup.Status(command); err != nil || enabled {
		t.Fatalf("different command: enabled=%v err=%v", enabled, err)
	}
	reg.values[key] = RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes(command)}
	if enabled, err := startup.Status(command); err != nil || !enabled {
		t.Fatalf("exact owned command: enabled=%v err=%v", enabled, err)
	}
}

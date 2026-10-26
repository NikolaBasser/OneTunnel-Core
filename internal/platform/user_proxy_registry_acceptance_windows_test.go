//go:build windows

package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

const userProxyTestRegistryRoot = `Software\OneTunnel.Tests`

var userProxyTestValues = map[string]bool{
	"ProxyEnable": true, "ProxyServer": true, "AutoConfigURL": true, "AutoDetect": true,
}

// isolatedProxyRegistry maps the one production key used by UserProxy to an
// exclusively-created test leaf. It rejects every other key or value name.
type isolatedProxyRegistry struct {
	leaf        string
	writeCount  int
	failWriteAt int
}

func newIsolatedProxyRegistry(t *testing.T) *isolatedProxyRegistry {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal("could not create isolated registry name")
	}
	leaf := userProxyTestRegistryRoot + `\UserProxy-` + hex.EncodeToString(nonce)
	key, existed, err := registry.CreateKey(registry.CURRENT_USER, leaf, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal("could not create isolated registry leaf")
	}
	if err = key.Close(); err != nil {
		t.Fatal("could not close isolated registry leaf")
	}
	if existed {
		t.Fatal("isolated registry leaf unexpectedly existed")
	}
	r := &isolatedProxyRegistry{leaf: leaf}
	t.Cleanup(func() {
		prefix := userProxyTestRegistryRoot + `\UserProxy-`
		if r.leaf != leaf || !strings.HasPrefix(leaf, prefix) || strings.Contains(strings.TrimPrefix(leaf, prefix), `\`) {
			t.Errorf("refusing to clean an unexpected registry path")
			return
		}
		for name := range userProxyTestValues {
			if err := (windowsUserRegistry{}).Delete(r.leaf, name); err != nil {
				t.Errorf("could not remove an isolated test value")
				return
			}
		}
		verifyKey, verifyErr := registry.OpenKey(registry.CURRENT_USER, r.leaf, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if verifyErr != nil {
			t.Errorf("could not inspect isolated registry leaf")
			return
		}
		info, statErr := verifyKey.Stat()
		_ = verifyKey.Close()
		if statErr != nil || info.ValueCount != 0 || info.SubKeyCount != 0 {
			t.Errorf("isolated registry leaf contains unexpected values or subkeys")
			return
		}
		if err := registry.DeleteKey(registry.CURRENT_USER, r.leaf); err != nil && err != registry.ErrNotExist {
			t.Errorf("could not remove isolated registry leaf")
			return
		}
		key, err := registry.OpenKey(registry.CURRENT_USER, r.leaf, registry.QUERY_VALUE)
		if err != registry.ErrNotExist {
			if err == nil {
				_ = key.Close()
			}
			t.Errorf("isolated registry leaf remains after cleanup")
		}
	})
	return r
}

func (r *isolatedProxyRegistry) mapKey(key, name string) (string, error) {
	if key != userProxyRegistryKey || !userProxyTestValues[name] {
		return "", errors.New("registry access outside isolated proxy test mapping")
	}
	return r.leaf, nil
}

func (r *isolatedProxyRegistry) Read(key, name string) (RawRegistryValue, error) {
	leaf, err := r.mapKey(key, name)
	if err != nil {
		return RawRegistryValue{}, err
	}
	return (windowsUserRegistry{}).Read(leaf, name)
}

func (r *isolatedProxyRegistry) Write(key, name string, value RawRegistryValue) error {
	leaf, err := r.mapKey(key, name)
	if err != nil || name != "ProxyEnable" && name != "ProxyServer" {
		return errors.New("registry write outside isolated proxy test mapping")
	}
	r.writeCount++
	if r.failWriteAt != 0 && r.writeCount == r.failWriteAt {
		r.failWriteAt = 0
		return errors.New("injected one-shot registry write failure")
	}
	return (windowsUserRegistry{}).Write(leaf, name, value)
}

func (r *isolatedProxyRegistry) Delete(key, name string) error {
	leaf, err := r.mapKey(key, name)
	if err != nil || name != "ProxyEnable" && name != "ProxyServer" {
		return errors.New("registry delete outside isolated proxy test mapping")
	}
	return (windowsUserRegistry{}).Delete(leaf, name)
}

func TestUserProxyRegistryAcceptanceIsolated(t *testing.T) {
	actualBefore := actualProxyRawSnapshot(t)
	t.Cleanup(func() {
		actualAfter := actualProxyRawSnapshot(t)
		for name, before := range actualBefore {
			if !sameRegistryValue(before, actualAfter[name]) {
				t.Errorf("actual Internet Settings proxy baseline changed")
				return
			}
		}
	})
	t.Run("missing baseline values restore to missing", func(t *testing.T) {
		runProxyRegistryLease(t, nil)
	})
	t.Run("typed raw baseline round trips", func(t *testing.T) {
		baseline := map[string]RawRegistryValue{
			"ProxyEnable": {Exists: true, Type: registry.BINARY, Data: []byte{0, 0xff, 0x7a}},
			"ProxyServer": {Exists: true, Type: registry.EXPAND_SZ, Data: []byte{0x41, 0, 0xff}},
		}
		runProxyRegistryLease(t, baseline)
	})
	t.Run("valid DWORD and string baseline round trips", func(t *testing.T) {
		baseline := map[string]RawRegistryValue{
			"ProxyEnable": {Exists: true, Type: registry.DWORD, Data: []byte{1, 0, 0, 0}},
			"ProxyServer": {Exists: true, Type: registry.EXPAND_SZ, Data: registryStringBytes("http=proxy.test:8080;https=proxy.test:8080")},
		}
		runProxyRegistryLease(t, baseline)
	})
	t.Run("foreign edit is preserved and reported", func(t *testing.T) {
		r := newIsolatedProxyRegistry(t)
		p := newAcceptanceProxy(t, r)
		lease := enableAcceptanceLease(t, p)
		foreign := RawRegistryValue{Exists: true, Type: registry.BINARY, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
		if err := (windowsUserRegistry{}).Write(r.leaf, "ProxyServer", foreign); err != nil {
			t.Fatal("could not install synthetic foreign edit")
		}
		conflict, err := p.Disable(lease)
		if err != nil || !conflict {
			t.Fatalf("foreign edit was not reported as a conflict: conflict=%v err=%v", conflict, err)
		}
		assertIsolatedBaseline(t, r, map[string]RawRegistryValue{"ProxyServer": foreign})
		assertJournalAbsent(t, p)
		assertNotificationCount(t, p, 2)
	})
	t.Run("second write failure rolls back first write", func(t *testing.T) {
		r := newIsolatedProxyRegistry(t)
		r.failWriteAt = 2
		p := newAcceptanceProxy(t, r)
		if _, err := p.Enable(startAcceptanceListener(t)); err == nil {
			t.Fatal("second write failure was ignored")
		}
		assertIsolatedBaseline(t, r, map[string]RawRegistryValue{})
		assertJournalAbsent(t, p)
		assertNotificationCount(t, p, 1)
	})
	t.Run("real listener loss restores lease", func(t *testing.T) {
		r := newIsolatedProxyRegistry(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("could not open loopback listener")
		}
		t.Cleanup(func() { _ = listener.Close() })
		address := listener.Addr().String()
		p := newAcceptanceProxy(t, r)
		lease := enableAcceptanceLeaseAt(t, p, address)
		if owns, err := p.Owns(lease); err != nil || !owns {
			t.Fatalf("durable lease ownership check failed: owns=%v err=%v", owns, err)
		}
		if err = listener.Close(); err != nil {
			t.Fatal("could not close loopback listener")
		}
		deadline := time.Now().Add(2 * time.Second)
		monitorStarted := time.Now()
		probeCount := 0
		failed, err := monitorProxyLeaseOwnerAndListener(func(interval time.Duration) (bool, error) {
			if time.Now().Add(interval).After(deadline) {
				return false, errors.New("listener monitor exceeded its bounded test deadline")
			}
			time.Sleep(interval)
			return false, nil
		}, func() (bool, error) { return p.Owns(lease) }, func(address string, timeout time.Duration) error {
			probeCount++
			return probeLoopbackListener(address, timeout)
		}, address, 10*time.Millisecond, 3)
		if err != nil || !failed || probeCount != 3 || time.Since(monitorStarted) > 2*time.Second {
			t.Fatalf("listener-loss monitor did not stop after consecutive failures: failed=%v err=%v", failed, err)
		}
		if err = restoreProxyLeaseAfterWatchEnd(p.UserProxy, lease, p.readJournal, p.userAutomationLock, nil); err != nil {
			t.Fatalf("production restore after listener loss failed: %v", err)
		}
		assertIsolatedBaseline(t, r, map[string]RawRegistryValue{})
		assertJournalAbsent(t, p)
		assertNotificationCount(t, p, 2)
	})
}

func runProxyRegistryLease(t *testing.T, baseline map[string]RawRegistryValue) {
	t.Helper()
	r := newIsolatedProxyRegistry(t)
	for name, value := range baseline {
		if err := (windowsUserRegistry{}).Write(r.leaf, name, value); err != nil {
			t.Fatal("could not write synthetic baseline")
		}
	}
	p := newAcceptanceProxy(t, r)
	lease := enableAcceptanceLease(t, p)
	if owns, err := p.Owns(lease); err != nil || !owns {
		t.Fatalf("journal ownership check failed: owns=%v err=%v", owns, err)
	}
	conflict, err := p.Disable(lease)
	if err != nil || conflict {
		t.Fatalf("lease did not disable cleanly: conflict=%v err=%v", conflict, err)
	}
	assertIsolatedBaseline(t, r, baseline)
	assertJournalAbsent(t, p)
	assertNotificationCount(t, p, 2)
}

type acceptanceUserProxy struct {
	*UserProxy
	notifyCalls int
}

func newAcceptanceProxy(t *testing.T, r *isolatedProxyRegistry) *acceptanceUserProxy {
	t.Helper()
	p := &acceptanceUserProxy{UserProxy: &UserProxy{registry: r, journalPath: filepath.Join(t.TempDir(), "user-proxy.dpapi"), queryProxyFlags: func() (uint32, error) { return 0, nil }}}
	p.notify = func() error { p.notifyCalls++; return nil }
	p.armWatchdog = func(lease string, pid uint32, created uint64, path string) error {
		if path != p.journalPath {
			return errors.New("watchdog received an unexpected journal path")
		}
		journal, err := p.readJournal()
		if err != nil {
			return err
		}
		if journal.LeaseID != lease || journal.OwnerPID != pid || journal.OwnerCreated != created {
			return errors.New("watchdog acknowledgement did not match durable journal")
		}
		return nil
	}
	return p
}

func enableAcceptanceLease(t *testing.T, p *acceptanceUserProxy) string {
	t.Helper()
	return enableAcceptanceLeaseAt(t, p, startAcceptanceListener(t))
}

func enableAcceptanceLeaseAt(t *testing.T, p *acceptanceUserProxy, address string) string {
	t.Helper()
	lease, err := p.Enable(address)
	if err != nil {
		t.Fatalf("could not enable isolated proxy lease: %v", err)
	}
	return lease
}

func startAcceptanceListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("could not open loopback listener")
	}
	address := listener.Addr().String()
	t.Cleanup(func() { _ = listener.Close() })
	return address
}

func actualProxyRawSnapshot(t *testing.T) map[string]RawRegistryValue {
	t.Helper()
	result := make(map[string]RawRegistryValue, 5)
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"} {
		value, err := (windowsUserRegistry{}).Read(userProxyRegistryKey, name)
		if err != nil {
			t.Fatal("could not read actual Internet Settings proxy baseline")
		}
		result[name] = value
	}
	return result
}

func assertIsolatedBaseline(t *testing.T, r *isolatedProxyRegistry, baseline map[string]RawRegistryValue) {
	t.Helper()
	for _, name := range []string{"ProxyEnable", "ProxyServer"} {
		got, err := (windowsUserRegistry{}).Read(r.leaf, name)
		if err != nil || !sameRegistryValue(got, baseline[name]) {
			t.Fatalf("isolated proxy value %s did not match its expected baseline (err=%v)", name, err)
		}
	}
}

func assertJournalAbsent(t *testing.T, p *acceptanceUserProxy) {
	t.Helper()
	if _, err := os.Stat(p.journalPath); !os.IsNotExist(err) {
		t.Fatal("proxy journal remains after lease restoration")
	}
}

func assertNotificationCount(t *testing.T, p *acceptanceUserProxy, want int) {
	t.Helper()
	if p.notifyCalls != want {
		t.Fatalf("WinINET no-op notification count=%d, want %d", p.notifyCalls, want)
	}
}

func TestIsolatedProxyRegistryRejectsUnmappedAccess(t *testing.T) {
	r := newIsolatedProxyRegistry(t)
	if _, err := r.Read(userProxyRegistryKey+`\..`, "ProxyEnable"); err == nil {
		t.Fatal("unmapped registry key was accepted")
	}
	if _, err := r.Read(userProxyRegistryKey, "UnexpectedValue"); err == nil {
		t.Fatal("unrecognized registry value was accepted")
	}
	if err := r.Write(userProxyRegistryKey, "AutoDetect", RawRegistryValue{}); err == nil {
		t.Fatal("write to a non-owned registry value was accepted")
	}
}

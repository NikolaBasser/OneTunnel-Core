package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
)

func TestWFPSessionBoundsWaitWithoutDynamicLifetime(t *testing.T) {
	h, err := openWFPWith(func(name string, args ...uintptr) error {
		if name != "FwpmEngineOpen0" || len(args) != 5 || args[3] == 0 {
			t.Fatal("explicit WFP session missing")
		}
		session := (*wSession)(unsafe.Pointer(args[3]))
		if session.TransactionWaitMS != 5000 || session.Flags != 0 {
			t.Fatalf("unbounded wait or dynamic filter lifetime: %+v", session)
		}
		*(*windows.Handle)(unsafe.Pointer(args[4])) = 123
		return nil
	})
	if err != nil || h != 123 {
		t.Fatalf("open result: %v %v", h, err)
	}
	want := errors.New("synthetic WFP open failure")
	if _, err := openWFPWith(func(string, ...uintptr) error { return want }); !errors.Is(err, want) {
		t.Fatalf("WFP error lost: %v", err)
	}
}

func TestTrafficLockRemovalReconcilesOwnerWithoutMarker(t *testing.T) {
	lock := trafficLock{owner: "test-owner", root: `C:\synthetic\runtime`}
	var data [32]byte
	owner := lock.ownerHash()
	copy(data[:], owner[:])
	provider := wProvider{Data: wBlob{Size: uint32(len(data)), Data: &data[0]}}
	var calls []string
	var removedMarker string
	call := func(name string, args ...uintptr) error {
		calls = append(calls, name)
		return nil
	}
	open := func() (windows.Handle, error) { return 1, nil }
	lookup := func(windows.Handle, *windows.GUID) (*wProvider, error) { return &provider, nil }
	remove := func(path string) error {
		removedMarker = path
		return nil
	}
	if err := lock.removeWith(call, open, remove, lookup, func(*wProvider) {}); err != nil {
		t.Fatal(err)
	}
	if removedMarker != lock.marker() {
		t.Fatalf("marker cleanup did not run: got %q", removedMarker)
	}
	if strings.Count(strings.Join(calls, "\n"), "FwpmFilterDeleteByKey0") != 256 {
		t.Fatalf("did not reconcile derived filter keys: %v", calls)
	}
	if !containsCall(calls, "FwpmSubLayerDeleteByKey0") || !containsCall(calls, "FwpmProviderDeleteByKey0") || !containsCall(calls, "FwpmTransactionCommit0") {
		t.Fatalf("owner objects were not transactionally removed: %v", calls)
	}
	keep(&provider)
	keep(&data)
}

func TestTrafficLockRemovalRefusesDifferentRootFingerprint(t *testing.T) {
	lock := trafficLock{owner: "test-owner", root: `C:\synthetic\runtime`}
	var data [32]byte
	owner := lock.ownerHash()
	copy(data[:], owner[:])
	data[0] ^= 0xff
	provider := wProvider{Data: wBlob{Size: uint32(len(data)), Data: &data[0]}}
	var calls []string
	call := func(name string, args ...uintptr) error {
		calls = append(calls, name)
		return nil
	}
	lookup := func(windows.Handle, *windows.GUID) (*wProvider, error) { return &provider, nil }
	err := lock.removeWith(call, func() (windows.Handle, error) { return 1, nil }, func(string) error {
		t.Fatal("marker must remain when owner validation fails")
		return nil
	}, lookup, func(*wProvider) {})
	if err == nil || !strings.Contains(err.Error(), "another runtime") {
		t.Fatalf("expected ownership rejection, got %v", err)
	}
	if containsCall(calls, "FwpmTransactionBegin0") || containsCall(calls, "FwpmProviderDeleteByKey0") {
		t.Fatalf("different owner was mutated: %v", calls)
	}
	keep(&provider)
	keep(&data)
}

func TestTrafficLockRemovalHandlesAbsentProviderWithoutMarker(t *testing.T) {
	lock := trafficLock{owner: "test-owner", root: `C:\synthetic\runtime`}
	lookedUp, cleanedMarker := false, false
	call := func(string, ...uintptr) error { return nil }
	lookup := func(windows.Handle, *windows.GUID) (*wProvider, error) {
		lookedUp = true
		return nil, windows.Errno(0x80320005)
	}
	err := lock.removeWith(call, func() (windows.Handle, error) { return 1, nil }, func(path string) error {
		cleanedMarker = path == lock.marker()
		return os.ErrNotExist
	}, lookup, func(*wProvider) {})
	if err != nil || !lookedUp || !cleanedMarker {
		t.Fatalf("absent marker/provider reconciliation failed: err=%v lookup=%v cleanup=%v", err, lookedUp, cleanedMarker)
	}
}

func TestTrafficLockRemovalPropagatesWFPFailureWithoutMarker(t *testing.T) {
	lock := trafficLock{owner: "test-owner", root: `C:\synthetic\runtime`}
	want := errors.New("synthetic WFP unavailable")
	got := lock.removeWith(func(string, ...uintptr) error { return nil }, func() (windows.Handle, error) { return 1, nil }, func(string) error {
		t.Fatal("marker must remain when WFP reconciliation fails")
		return nil
	}, func(windows.Handle, *windows.GUID) (*wProvider, error) { return nil, want }, func(*wProvider) {})
	if !errors.Is(got, want) {
		t.Fatalf("expected WFP error, got %v", got)
	}
}

func TestStopRefusesInvalidJournalWithoutRemovingRecoveryData(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, "session.json")
	contents := []byte("{corrupt synthetic journal")
	if err := os.WriteFile(journal, contents, 0600); err != nil {
		t.Fatal(err)
	}
	r := newRuntimeAtRoot("C:/synthetic", "test-owner", root, func(control.State) {})
	defer r.Close()
	response, err := r.Call(context.Background(), control.Request{Version: control.Version, Command: "stop"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil {
		t.Fatal("stop unexpectedly succeeded with an invalid journal")
	}
	after, err := os.ReadFile(journal)
	if err != nil || string(after) != string(contents) {
		t.Fatalf("invalid recovery journal was altered: err=%v data=%q", err, after)
	}
}

func containsCall(calls []string, target string) bool {
	for _, call := range calls {
		if call == target {
			return true
		}
	}
	return false
}

//go:build windows

package platform

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestNetworkManagerCOMVTableSlotsMatchIDispatchLayout(t *testing.T) {
	// Microsoft netlistmgr.h declares the manager, network, connection, and
	// enumerator interfaces as IDispatch-derived; derived methods start at 7.
	want := map[string]uintptr{
		"INetworkListManager.GetNetworks": 7,
		"INetwork.GetNetworkConnections":  13,
		"INetwork.GetCategory":            18,
		"INetworkConnection.GetAdapterId": 12,
		"IEnumNetworks.Next":              8,
		"IEnumNetworkConnections.Next":    8,
	}
	got := map[string]uintptr{
		"INetworkListManager.GetNetworks": nlmGetNetworksSlot,
		"INetwork.GetNetworkConnections":  networkGetConnectionsSlot,
		"INetwork.GetCategory":            networkGetCategorySlot,
		"INetworkConnection.GetAdapterId": networkConnectionGetAdapterSlot,
		"IEnumNetworks.Next":              nlmEnumeratorNextSlot,
		"IEnumNetworkConnections.Next":    nlmEnumeratorNextSlot,
	}
	for name, slot := range want {
		if got[name] != slot {
			t.Errorf("%s vtable slot=%d, want %d", name, got[name], slot)
		}
	}
}

func TestNLMCOMCallsDispatchExpectedSlotsAndArguments(t *testing.T) {
	type callRecord struct {
		actualSlot uintptr
		arguments  []uintptr
	}
	for _, test := range []struct {
		name      string
		slot      uintptr
		arguments []uintptr
		callback  func(func(uintptr, ...uintptr)) uintptr
	}{
		{"GetNetworks", nlmGetNetworksSlot, []uintptr{1, 0xabc}, func(record func(uintptr, ...uintptr)) uintptr {
			return syscall.NewCallback(func(this, flags, out uintptr) uintptr { record(nlmGetNetworksSlot, this, flags, out); return 0 })
		}},
		{"GetNetworkConnections", networkGetConnectionsSlot, []uintptr{0xdef}, func(record func(uintptr, ...uintptr)) uintptr {
			return syscall.NewCallback(func(this, out uintptr) uintptr { record(networkGetConnectionsSlot, this, out); return 0 })
		}},
		{"GetCategory", networkGetCategorySlot, []uintptr{0x123}, func(record func(uintptr, ...uintptr)) uintptr {
			return syscall.NewCallback(func(this, out uintptr) uintptr { record(networkGetCategorySlot, this, out); return 0 })
		}},
		{"GetAdapterId", networkConnectionGetAdapterSlot, []uintptr{0x456}, func(record func(uintptr, ...uintptr)) uintptr {
			return syscall.NewCallback(func(this, out uintptr) uintptr { record(networkConnectionGetAdapterSlot, this, out); return 0 })
		}},
		{"Next", nlmEnumeratorNextSlot, []uintptr{1, 0x789, 0x987}, func(record func(uintptr, ...uintptr)) uintptr {
			return syscall.NewCallback(func(this, count, items, fetched uintptr) uintptr {
				record(nlmEnumeratorNextSlot, this, count, items, fetched)
				return 0
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var record callRecord
			const entries = 21
			noop := syscall.NewCallback(func(this, a, b, c uintptr) uintptr { return 0 })
			vtable := make([]uintptr, entries)
			for i := range vtable {
				vtable[i] = noop
			}
			vtable[test.slot] = test.callback(func(slot uintptr, args ...uintptr) {
				record.actualSlot = slot
				record.arguments = append([]uintptr(nil), args...)
			})
			object := &userCOMInterface{vtable: &vtable[0]}
			if _, err := comCall(object, test.slot, test.arguments...); err != nil {
				t.Fatal(err)
			}
			want := append([]uintptr{uintptr(unsafe.Pointer(object))}, test.arguments...)
			if record.actualSlot != test.slot || len(record.arguments) != len(want) {
				t.Fatalf("slot=%d arguments=%v, want slot=%d arguments=%v", record.actualSlot, record.arguments, test.slot, want)
			}
			for i := range want {
				if record.arguments[i] != want[i] {
					t.Fatalf("argument[%d]=%#x, want %#x", i, record.arguments[i], want[i])
				}
			}
		})
	}
}

func TestClassifyPhysicalNetworkRequiresEveryKnownPhysicalNetworkTrusted(t *testing.T) {
	for _, test := range []struct {
		name       string
		categories []int
		physical   int
		want       UserNetworkCategory
	}{
		{"no networks", nil, 0, UserNetworkPublic},
		{"unknown", nil, 1, UserNetworkPublic},
		{"private", []int{nlmPrivate}, 1, UserNetworkTrusted},
		{"domain", []int{nlmDomainAuthenticated}, 1, UserNetworkTrusted},
		{"public among trusted", []int{nlmPrivate, nlmPublic}, 2, UserNetworkPublic},
		{"unknown category", []int{99}, 1, UserNetworkPublic},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyPhysicalNetwork(test.categories, test.physical); got != test.want {
				t.Fatalf("got %s want %s", got, test.want)
			}
		})
	}
}

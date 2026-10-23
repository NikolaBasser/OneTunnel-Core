//go:build windows

package platform

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type UserNetworkCategory string

const (
	UserNetworkTrusted UserNetworkCategory = "trusted"
	UserNetworkPublic  UserNetworkCategory = "public"
)
const (
	nlmPublic              = 0
	nlmPrivate             = 1
	nlmDomainAuthenticated = 2
)

// Slot numbers follow the Microsoft netlistmgr.h declarations. These NLM
// interfaces inherit IDispatch (7 base slots); the two enumerators do too.
const (
	nlmGetNetworksSlot              = 7
	networkGetConnectionsSlot       = 13
	networkGetCategorySlot          = 18
	networkConnectionGetAdapterSlot = 12
	nlmEnumeratorNextSlot           = 8
)

var oneTunnelAdapterName = regexp.MustCompile(`(?i)^onetunnel[0-9a-f]{12}$`)

type userNetworkAdapter struct {
	name          string
	interfaceType uint32
}

// userCOMInterface is the common ABI prefix for the NLM interfaces.
type userCOMInterface struct {
	vtable *uintptr
}

// ClassifyPhysicalNetwork is deliberately conservative: any missing category or
// unrecognized physical adapter makes the result public.
func ClassifyPhysicalNetwork(categories []int, physicalCount int) UserNetworkCategory {
	if physicalCount == 0 || len(categories) == 0 {
		return UserNetworkPublic
	}
	for _, category := range categories {
		if category != nlmPrivate && category != nlmDomainAuthenticated {
			return UserNetworkPublic
		}
	}
	return UserNetworkTrusted
}

// CurrentUserPhysicalNetworkCategory reads Windows NLM and excludes OneTunnel's
// own generated TUN adapter names. Any API failure is classified as public.
func CurrentUserPhysicalNetworkCategory() UserNetworkCategory {
	category, err := currentUserPhysicalNetworkCategory()
	if err != nil {
		return UserNetworkPublic
	}
	return category
}

func currentUserPhysicalNetworkCategory() (UserNetworkCategory, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, 0); err != nil && err != syscall.Errno(1) {
		return UserNetworkPublic, err
	}
	defer windows.CoUninitialize()
	adapters, err := windowsAdapterNames()
	if err != nil {
		return UserNetworkPublic, err
	}
	clsid, err := windows.GUIDFromString("{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")
	if err != nil {
		return UserNetworkPublic, err
	}
	iid, err := windows.GUIDFromString("{DCB00000-570F-4A9B-8D69-199FDBA5723B}")
	if err != nil {
		return UserNetworkPublic, err
	}
	manager, err := coCreate(&clsid, &iid)
	if err != nil {
		return UserNetworkPublic, err
	}
	defer comRelease(manager)
	var enum *userCOMInterface
	_, err = comCall(manager, nlmGetNetworksSlot, 1, uintptr(unsafe.Pointer(&enum)))
	if err != nil {
		return UserNetworkPublic, err
	}
	if enum == nil {
		return UserNetworkPublic, errors.New("NLM returned no network enumerator")
	}
	defer comRelease(enum)
	categories := []int{}
	physical := 0
	for {
		network, ok, e := comNext(enum)
		if e != nil {
			return UserNetworkPublic, e
		}
		if !ok {
			break
		}
		var connections *userCOMInterface
		_, e = comCall(network, networkGetConnectionsSlot, uintptr(unsafe.Pointer(&connections)))
		if e != nil {
			comRelease(network)
			return UserNetworkPublic, e
		}
		var cat uint32
		_, e = comCall(network, networkGetCategorySlot, uintptr(unsafe.Pointer(&cat)))
		if e != nil {
			comRelease(connections)
			comRelease(network)
			return UserNetworkPublic, e
		}
		for {
			connection, has, e := comNext(connections)
			if e != nil {
				comRelease(connections)
				comRelease(network)
				return UserNetworkPublic, e
			}
			if !has {
				break
			}
			var adapter windows.GUID
			_, e = comCall(connection, networkConnectionGetAdapterSlot, uintptr(unsafe.Pointer(&adapter)))
			comRelease(connection)
			if e != nil {
				comRelease(connections)
				comRelease(network)
				return UserNetworkPublic, e
			}
			physicalAdapter, known := adapters[networkGUIDKey(adapter.String())]
			if !known {
				comRelease(connections)
				comRelease(network)
				return UserNetworkPublic, errors.New("NLM adapter identity is unclassified")
			}
			if oneTunnelAdapterName.MatchString(physicalAdapter.name) {
				continue
			}
			if physicalAdapter.name == "" || (physicalAdapter.interfaceType != 6 && physicalAdapter.interfaceType != 71) {
				comRelease(connections)
				comRelease(network)
				return UserNetworkPublic, errors.New("connected adapter is not a recognized physical Ethernet or Wi-Fi interface")
			}
			physical++
			categories = append(categories, int(cat))
		}
		comRelease(connections)
		comRelease(network)
	}
	if physical == 0 {
		return UserNetworkPublic, errors.New("no physical connected network was classified")
	}
	return ClassifyPhysicalNetwork(categories, physical), nil
}

func windowsAdapterNames() (map[string]userNetworkAdapter, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, nil, &size)
	if err != nil && err != syscall.ERROR_BUFFER_OVERFLOW {
		return nil, err
	}
	buf := make([]byte, size+windows.MAX_ADAPTER_ADDRESS_LENGTH+64)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, first, &size); err != nil {
		return nil, err
	}
	result := map[string]userNetworkAdapter{}
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.AdapterName == nil {
			continue
		}
		adapterID := windows.BytePtrToString(adapter.AdapterName)
		name := windows.UTF16PtrToString(adapter.FriendlyName)
		result[networkGUIDKey(adapterID)] = userNetworkAdapter{name: name, interfaceType: adapter.IfType}
	}
	return result, nil
}
func networkGUIDKey(guid string) string {
	return strings.NewReplacer("{", "", "}", "", "-", "").Replace(strings.ToLower(guid))
}

func coCreate(clsid, iid *windows.GUID) (*userCOMInterface, error) {
	proc := windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")
	var object *userCOMInterface
	hr, _, _ := proc.Call(uintptr(unsafe.Pointer(clsid)), 0, 1, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&object)))
	if int32(hr) < 0 {
		return nil, fmt.Errorf("Network List Manager unavailable: HRESULT 0x%08x", uint32(hr))
	}
	return object, nil
}
func comCall(object *userCOMInterface, index uintptr, args ...uintptr) (uintptr, error) {
	if object == nil {
		return 0, errors.New("invalid COM interface")
	}
	proc := *(*uintptr)(unsafe.Add(unsafe.Pointer(object.vtable), index*unsafe.Sizeof(uintptr(0))))
	params := append([]uintptr{uintptr(unsafe.Pointer(object))}, args...)
	hr, _, _ := syscall.SyscallN(proc, params...)
	if int32(hr) < 0 {
		return 0, fmt.Errorf("Network List Manager call failed: HRESULT 0x%08x", uint32(hr))
	}
	return hr, nil
}
func comNext(enumerator *userCOMInterface) (*userCOMInterface, bool, error) {
	var item *userCOMInterface
	var fetched uint32
	_, err := comCall(enumerator, nlmEnumeratorNextSlot, 1, uintptr(unsafe.Pointer(&item)), uintptr(unsafe.Pointer(&fetched)))
	if err != nil {
		return nil, false, err
	}
	if fetched == 0 {
		return nil, false, nil
	}
	if item == nil {
		return nil, false, errors.New("NLM returned an empty item")
	}
	return item, true, nil
}
func comRelease(object *userCOMInterface) {
	if object != nil {
		_, _ = comCall(object, 2)
	}
}

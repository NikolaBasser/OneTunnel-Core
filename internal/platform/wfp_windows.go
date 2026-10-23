package platform

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These native layouts and key byte order match the former C# implementation.
// Persistent filters deliberately outlive every process and service handle.
type wDisplay struct{ Name, Description *uint16 }
type wBlob struct {
	Size uint32
	Data *byte
}
type wValue struct {
	Type uint32
	_    uint32
	Data uintptr
}
type wCondition struct {
	Field windows.GUID
	Match uint32
	_     uint32
	Value wValue
}
type wAction struct {
	Type    uint32
	Callout windows.GUID
}
type wProvider struct {
	Key     windows.GUID
	Display wDisplay
	Flags   uint32
	Data    wBlob
	Service *uint16
}
type wSublayer struct {
	Key      windows.GUID
	Display  wDisplay
	Flags    uint32
	Provider *windows.GUID
	Data     wBlob
	Weight   uint16
}
type wFilter struct {
	Key             windows.GUID
	Display         wDisplay
	Flags           uint32
	Provider        *windows.GUID
	Data            wBlob
	Layer, Sublayer windows.GUID
	Weight          wValue
	Count           uint32
	Conditions      *wCondition
	Action          wAction
	_               uint32
	Context         windows.GUID
	Reserved        uintptr
	ID              uint64
	EffectiveWeight wValue
}
type trafficLock struct{ owner, root string }

var wfp = windows.NewLazySystemDLL("fwpuclnt.dll")

func keep(v any) { runtime.KeepAlive(v) }

//go:uintptrescapes
func wCall(name string, args ...uintptr) error {
	r, _, _ := wfp.NewProc(name).Call(args...)
	if r != 0 {
		return windows.Errno(uint32(r))
	}
	return nil
}
func wIgnored(e error, code uint32) bool { return e == nil || e == windows.Errno(code) }
func wGuid(s string) windows.GUID {
	g, e := windows.GUIDFromString("{" + s + "}")
	if e != nil {
		panic("invalid internal WFP GUID")
	}
	return g
}

var wLayers = []windows.GUID{wGuid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), wGuid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), wGuid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), wGuid("a3b42c97-9f04-4672-b87e-cee9c483257f")}
var wApp = wGuid("d78e1e87-8644-4ea5-9437-d809ecefc971")
var wInterface = wGuid("4cd62a49-59c3-4969-b7f3-bda5d32890a4")
var wFlags = wGuid("632ce23b-5167-435c-86d7-e903684aa80c")
var wProtocol = wGuid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7")
var wLocalPort = wGuid("0c1ba1af-5765-453f-af22-a8f791ac775b")
var wRemotePort = wGuid("c35a604d-d22b-4e1a-91b4-68f674ee674b")
var wRemoteAddress = wGuid("b235ae9a-1d64-49b8-a44c-5ff3d9095045")

func (t trafficLock) key(name string) windows.GUID {
	h := sha256.Sum256([]byte("OneTunnel.WFP.v1/" + t.owner + "/" + name))
	return windows.GUID{Data1: binary.LittleEndian.Uint32(h[:4]), Data2: binary.LittleEndian.Uint16(h[4:6]), Data3: binary.LittleEndian.Uint16(h[6:8]), Data4: [8]byte(h[8:16])}
}
func (t trafficLock) ownerHash() [32]byte {
	return sha256.Sum256([]byte(strings.ToUpper(strings.TrimRight(filepath.Clean(t.root), `\`))))
}
func (t trafficLock) marker() string { return filepath.Join(t.root, "kill-switch.json") }
func (t trafficLock) needed() bool   { _, e := os.Stat(t.marker()); return e == nil || !os.IsNotExist(e) }
func openWFP() (windows.Handle, error) {
	var h windows.Handle
	e := wCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&h)))
	return h, e
}
func wDisplayName(name string) wDisplay {
	p, _ := windows.UTF16PtrFromString(name)
	return wDisplay{Name: p}
}

//go:uintptrescapes
func condition(field windows.GUID, kind uint32, value uintptr, match uint32) wCondition {
	return wCondition{Field: field, Match: match, Value: wValue{Type: kind, Data: value}}
}
func (t trafficLock) enable(interfaceName string, enginePaths []string) error {
	return t.configure(interfaceName, enginePaths, false)
}
func (t trafficLock) replace(interfaceName string, enginePaths []string) error {
	return t.configure(interfaceName, enginePaths, true)
}
func (t trafficLock) configure(interfaceName string, enginePaths []string, replace bool) error {
	if unsafe.Sizeof(wFilter{}) != 200 {
		return errors.New("unsupported WFP layout")
	}
	h, e := openWFP()
	if e != nil {
		return e
	}
	defer wCall("FwpmEngineClose0", uintptr(h))
	providerKey := t.key("provider")
	subKey := t.key("sublayer")
	var existingProvider *wProvider
	e = wCall("FwpmProviderGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&providerKey)), uintptr(unsafe.Pointer(&existingProvider)))
	if e == nil {
		owner := t.ownerHash()
		matches := existingProvider.Data.Size == 32 && existingProvider.Data.Data != nil
		if matches {
			for i, v := range unsafe.Slice(existingProvider.Data.Data, 32) {
				if v != owner[i] {
					matches = false
					break
				}
			}
		}
		wCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&existingProvider)))
		if !replace || !matches {
			return errors.New("existing traffic protection requires recovery")
		}
	} else if replace || !wIgnored(e, 0x80320005) {
		return errors.New("traffic protection replacement unavailable")
	}
	list, buffer, e := adapters()
	if e != nil {
		return e
	}
	defer keep(buffer)
	var luid uint64
	present := false
	for _, a := range list {
		if windows.UTF16PtrToString(a.FriendlyName) == interfaceName && a.OperStatus == windows.IfOperStatusUp {
			guid, e := windows.GUIDFromString(windows.BytePtrToString(a.AdapterName))
			if e != nil {
				return e
			}
			r, _, _ := guidToLuid.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&luid)))
			if r != 0 {
				return windows.Errno(r)
			}
			present = true
			break
		}
	}
	if !present {
		return errors.New("tunnel interface not ready")
	}
	if e = atomicJSON(t.marker(), map[string]any{"version": 1, "scope": "whole-device"}); e != nil {
		return e
	}
	if e = wCall("FwpmTransactionBegin0", uintptr(h), 0); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			wCall("FwpmTransactionAbort0", uintptr(h))
			if !replace {
				os.Remove(t.marker())
			}
		}
	}()
	if replace {
		// The old deny policy remains active until the entire replacement commits.
		for i := 0; i < 256; i++ {
			key := t.key(fmt.Sprintf("filter/%d", i))
			if e = wCall("FwpmFilterDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&key))); !wIgnored(e, 0x80320003) {
				return e
			}
		}
		if e = wCall("FwpmSubLayerDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&subKey))); e != nil {
			return e
		}
		if e = wCall("FwpmProviderDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&providerKey))); e != nil {
			return e
		}
	}
	owner := t.ownerHash()
	provider := wProvider{Key: providerKey, Display: wDisplayName("OneTunnel kill switch"), Flags: 1, Data: wBlob{Size: 32, Data: &owner[0]}}
	if e = wCall("FwpmProviderAdd0", uintptr(h), uintptr(unsafe.Pointer(&provider)), 0); e != nil {
		return e
	}
	keep(provider)
	keep(owner)
	sub := wSublayer{Key: subKey, Display: wDisplayName("OneTunnel persistent traffic lock"), Flags: 1, Provider: &providerKey, Weight: 0xfffe}
	if e = wCall("FwpmSubLayerAdd0", uintptr(h), uintptr(unsafe.Pointer(&sub)), 0); e != nil {
		return e
	}
	keep(sub)
	slot := 0
	rule := func(layer windows.GUID, label string, weight byte, permit bool, conditions ...wCondition) error {
		if slot >= 256 {
			return errors.New("too many protection filters")
		}
		action := uint32(0x1001)
		if permit {
			action = 0x1002
		}
		f := wFilter{Key: t.key(fmt.Sprintf("filter/%d", slot)), Display: wDisplayName("OneTunnel · " + label), Flags: 1, Provider: &providerKey, Layer: layer, Sublayer: subKey, Weight: wValue{Type: 1, Data: uintptr(weight)}, Count: uint32(len(conditions)), Action: wAction{Type: action}}
		slot++
		if len(conditions) > 0 {
			f.Conditions = &conditions[0]
		}
		var id uint64
		e := wCall("FwpmFilterAdd0", uintptr(h), uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
		keep(f)
		keep(conditions)
		return e
	}
	for _, layer := range wLayers {
		if e = rule(layer, "block direct traffic", 0, false); e != nil {
			return e
		}
		if e = rule(layer, "tunnel interface", 12, true, condition(wInterface, 4, uintptr(unsafe.Pointer(&luid)), 0)); e != nil {
			return e
		}
		keep(luid)
		if e = rule(layer, "loopback", 13, true, condition(wFlags, 3, 1, 6)); e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, path := range enginePaths {
			if seen[strings.ToLower(path)] {
				continue
			}
			seen[strings.ToLower(path)] = true
			p, _ := windows.UTF16PtrFromString(path)
			var app uintptr
			if e = wCall("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&app))); e != nil {
				return e
			}
			keep(p)
			e = rule(layer, "transport engine", 14, true, condition(wApp, 12, app, 0))
			wCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&app)))
			if e != nil {
				return e
			}
		}
	}
	// Match the previous limited bypass: DHCP and IPv6 neighbor discovery only.
	dhcp := map[uint32]bool{0xffffffff: true}
	for _, a := range list {
		if ip := a.Dhcpv4Server.IP().To4(); ip != nil {
			dhcp[binary.BigEndian.Uint32(ip)] = true
		}
	}
	for address := range dhcp {
		for _, layer := range []windows.GUID{wLayers[0], wLayers[2]} {
			if e = rule(layer, "DHCPv4", 12, true, condition(wProtocol, 1, 17, 0), condition(wLocalPort, 2, 68, 0), condition(wRemotePort, 2, 67, 0), condition(wRemoteAddress, 3, uintptr(address), 0)); e != nil {
				return e
			}
		}
	}
	v6 := net.ParseIP("ff02::1:2").To16()
	if e = rule(wLayers[1], "DHCPv6", 12, true, condition(wProtocol, 1, 17, 0), condition(wLocalPort, 2, 546, 0), condition(wRemotePort, 2, 547, 0), condition(wRemoteAddress, 11, uintptr(unsafe.Pointer(&v6[0])), 0)); e != nil {
		return e
	}
	keep(v6)
	for _, kind := range []uintptr{133, 134, 135, 136} {
		for _, layer := range []windows.GUID{wLayers[1], wLayers[3]} {
			if e = rule(layer, "IPv6 neighbor discovery", 12, true, condition(wProtocol, 1, 58, 0), condition(wLocalPort, 2, kind, 0)); e != nil {
				return e
			}
		}
	}
	e = wCall("FwpmTransactionCommit0", uintptr(h))
	committed = e == nil
	return e
}
func (t trafficLock) remove(force bool) error {
	if !t.needed() && !force {
		return nil
	}
	h, e := openWFP()
	if e != nil {
		return e
	}
	defer wCall("FwpmEngineClose0", uintptr(h))
	key := t.key("provider")
	var pointer unsafe.Pointer
	e = wCall("FwpmProviderGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
	if e == nil {
		provider := (*wProvider)(pointer)
		owner := t.ownerHash()
		matches := provider.Data.Size == 32 && provider.Data.Data != nil
		if matches {
			data := unsafe.Slice(provider.Data.Data, 32)
			for i := range owner {
				if data[i] != owner[i] {
					matches = false
					break
				}
			}
		}
		wCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&pointer)))
		if !matches {
			return errors.New("traffic protection belongs to another runtime")
		}
		if e = wCall("FwpmTransactionBegin0", uintptr(h), 0); e != nil {
			return e
		}
		committed := false
		defer func() {
			if !committed {
				wCall("FwpmTransactionAbort0", uintptr(h))
			}
		}()
		for i := 0; i < 256; i++ {
			k := t.key(fmt.Sprintf("filter/%d", i))
			e = wCall("FwpmFilterDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&k)))
			if !wIgnored(e, 0x80320003) {
				return e
			}
		}
		sub := t.key("sublayer")
		if e = wCall("FwpmSubLayerDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&sub))); !wIgnored(e, 0x80320007) {
			return e
		}
		if e = wCall("FwpmProviderDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&key))); e != nil {
			return e
		}
		if e = wCall("FwpmTransactionCommit0", uintptr(h)); e != nil {
			return e
		}
		committed = true
	} else if !wIgnored(e, 0x80320005) {
		return e
	}
	e = os.Remove(t.marker())
	if os.IsNotExist(e) {
		return nil
	}
	return e
}

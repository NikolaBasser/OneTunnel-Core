package platform

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Emergency recovery intentionally does not construct Runtime or read profiles,
// journals, executable paths, or owner-root markers.
type EmergencyWFPProvider struct {
	GUID            string
	Name            string
	Filters         int
	Sublayers       int
	Recoverable     bool
	Reason          string
	RootFingerprint string
}

type recoveryObjects struct {
	view      EmergencyWFPProvider
	provider  windows.GUID
	filters   []windows.GUID
	sublayers []windows.GUID
}

func emergencyEnum(h windows.Handle, kind string, visit func(unsafe.Pointer) error) error {
	var enumeration windows.Handle
	if err := wCall("Fwpm"+kind+"CreateEnumHandle0", uintptr(h), 0, uintptr(unsafe.Pointer(&enumeration))); err != nil {
		return err
	}
	defer wCall("Fwpm"+kind+"DestroyEnumHandle0", uintptr(h), uintptr(enumeration))
	for {
		var entries **byte
		var count uint32
		if err := wCall("Fwpm"+kind+"Enum0", uintptr(h), uintptr(enumeration), 128, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count))); err != nil {
			return err
		}
		if count > 128 || count > 0 && entries == nil {
			if entries != nil {
				_ = wCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&entries)))
			}
			return errors.New("invalid WFP enumeration")
		}
		var visitErr error
		if count > 0 {
			for _, entry := range unsafe.Slice(entries, int(count)) {
				if entry == nil {
					visitErr = errors.New("invalid WFP object")
					break
				}
				if visitErr = visit(unsafe.Pointer(entry)); visitErr != nil {
					break
				}
			}
		}
		if entries != nil {
			_ = wCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&entries)))
		}
		if visitErr != nil {
			return visitErr
		}
		if count < 128 {
			return nil
		}
	}
}

func emergencyObjects(h windows.Handle) ([]recoveryObjects, error) {
	if unsafe.Sizeof(wFilter{}) != 200 || unsafe.Sizeof(wProvider{}) != 64 || unsafe.Sizeof(wSublayer{}) != 72 {
		return nil, errors.New("unsupported WFP layout; use Windows x64 or ARM64")
	}
	var objects []recoveryObjects
	err := emergencyEnum(h, "Provider", func(pointer unsafe.Pointer) error {
		p := (*wProvider)(pointer)
		name := windows.UTF16PtrToString(p.Display.Name)
		if name != "OneTunnel kill switch" {
			return nil
		}
		ok := emergencyProviderMatches(p)
		reason := ""
		if !ok {
			reason = "provider metadata does not match OneTunnel"
		}
		objects = append(objects, recoveryObjects{provider: p.Key, view: EmergencyWFPProvider{GUID: p.Key.String(), Name: name, Recoverable: ok, Reason: reason}})
		if p.Data.Size == 32 && p.Data.Data != nil {
			objects[len(objects)-1].view.RootFingerprint = hex.EncodeToString(unsafe.Slice(p.Data.Data, 32))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enumerate providers: %w", err)
	}
	byKey := make(map[windows.GUID]int, len(objects))
	for i := range objects {
		byKey[objects[i].provider] = i
	}
	if err = emergencyEnum(h, "SubLayer", func(pointer unsafe.Pointer) error {
		s := (*wSublayer)(pointer)
		if s.Provider == nil {
			return nil
		}
		i, ok := byKey[*s.Provider]
		if !ok {
			return nil
		}
		objects[i].sublayers = append(objects[i].sublayers, s.Key)
		if windows.UTF16PtrToString(s.Display.Name) != "OneTunnel persistent traffic lock" || s.Weight != 0xfffe || s.Flags&1 == 0 {
			objects[i].view.Recoverable = false
			objects[i].view.Reason = "unexpected sublayer owned by provider"
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("enumerate sublayers: %w", err)
	}
	for i := range objects {
		if len(objects[i].sublayers) > 1 {
			objects[i].view.Recoverable = false
			objects[i].view.Reason = "multiple sublayers do not match the OneTunnel object layout"
		}
	}
	if err = emergencyEnum(h, "Filter", func(pointer unsafe.Pointer) error {
		f := (*wFilter)(pointer)
		if f.Provider == nil {
			return nil
		}
		i, ok := byKey[*f.Provider]
		if !ok {
			return nil
		}
		objects[i].filters = append(objects[i].filters, f.Key)
		if !emergencyFilterMatches(f, objects[i].sublayers) {
			objects[i].view.Recoverable = false
			objects[i].view.Reason = "unexpected filter owned by provider"
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("enumerate filters: %w", err)
	}
	for i := range objects {
		objects[i].view.Filters = len(objects[i].filters)
		objects[i].view.Sublayers = len(objects[i].sublayers)
	}
	return objects, nil
}

func emergencyProviderMatches(p *wProvider) bool {
	return p != nil && windows.UTF16PtrToString(p.Display.Name) == "OneTunnel kill switch" && p.Flags&1 != 0 && p.Data.Size == 32 && p.Data.Data != nil
}

func emergencyFilterMatches(f *wFilter, sublayers []windows.GUID) bool {
	if f == nil {
		return false
	}
	layerOK, sublayerOK := false, false
	for _, layer := range wLayers {
		layerOK = layerOK || f.Layer == layer
	}
	for _, sublayer := range sublayers {
		sublayerOK = sublayerOK || f.Sublayer == sublayer
	}
	name := strings.TrimPrefix(windows.UTF16PtrToString(f.Display.Name), "OneTunnel · ")
	count, weight, action := uint32(0), uintptr(0), uint32(0x1002)
	switch name {
	case "block direct traffic":
		action = 0x1001
	case "tunnel interface":
		count, weight = 1, 12
	case "loopback":
		count, weight = 1, 13
	case "transport engine":
		count, weight = 1, 14
	case "DHCPv4", "DHCPv6":
		count, weight = 4, 12
	case "IPv6 neighbor discovery":
		count, weight = 2, 12
	default:
		return false
	}
	return windows.UTF16PtrToString(f.Display.Name) == "OneTunnel · "+name && layerOK && sublayerOK && f.Flags&1 != 0 && f.Action.Type == action && f.Count == count && f.Weight.Type == 1 && f.Weight.Data == weight
}

func EmergencyWFPInventory() ([]EmergencyWFPProvider, error) {
	h, err := openWFP()
	if err != nil {
		return nil, err
	}
	defer wCall("FwpmEngineClose0", uintptr(h))
	objects, err := emergencyObjects(h)
	if err != nil {
		return nil, err
	}
	views := make([]EmergencyWFPProvider, 0, len(objects))
	for _, object := range objects {
		views = append(views, object.view)
	}
	return views, nil
}

// RecoverEmergencyWFPProvider deletes only a freshly validated provider and its
// related filters/sublayers, atomically. Foreign objects are never reset.
func RecoverEmergencyWFPProvider(guid string) error {
	key, err := windows.GUIDFromString(guid)
	if err != nil {
		return errors.New("invalid provider GUID")
	}
	return recoverEmergencyWFP(&key)
}

func RecoverAllEmergencyWFP() error { return recoverEmergencyWFP(nil) }

func selectEmergencyProviders(objects []recoveryObjects, key *windows.GUID) ([]recoveryObjects, error) {
	var selected []recoveryObjects
	for _, object := range objects {
		if key != nil && object.provider != *key {
			continue
		}
		if !object.view.Recoverable {
			return nil, errors.New(object.view.Reason)
		}
		selected = append(selected, object)
	}
	if key != nil && len(selected) == 0 {
		return nil, errors.New("provider is absent or is not OneTunnel")
	}
	return selected, nil
}

func recoverEmergencyWFP(key *windows.GUID) error {
	return recoverEmergencyWFPExpected(key, nil)
}

func recoverEmergencyWFPExpected(key *windows.GUID, expected *[32]byte) error {
	h, err := openWFP()
	if err != nil {
		return err
	}
	defer wCall("FwpmEngineClose0", uintptr(h))
	if err = wCall("FwpmTransactionBegin0", uintptr(h), 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = wCall("FwpmTransactionAbort0", uintptr(h))
		}
	}()
	if expected != nil {
		if key == nil {
			return errors.New("expected recovery requires one provider")
		}
		provider, lookupErr := lookupTrafficProvider(h, key)
		if lookupErr == windows.Errno(0x80320005) {
			return nil
		}
		if lookupErr != nil {
			return lookupErr
		}
		matches := emergencyProviderFingerprintMatches(provider, *expected)
		freeTrafficProvider(provider)
		if !matches {
			return errors.New("provider does not match the expected recovery owner")
		}
	}
	objects, err := emergencyObjects(h)
	if err != nil {
		return err
	}
	selected, err := selectEmergencyProviders(objects, key)
	if err != nil {
		return err
	}
	for _, object := range selected {
		for _, filter := range object.filters {
			if err = wCall("FwpmFilterDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&filter))); err != nil {
				return err
			}
		}
		for _, sublayer := range object.sublayers {
			if err = wCall("FwpmSubLayerDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&sublayer))); err != nil {
				return err
			}
		}
		providerKey := object.provider
		if err = wCall("FwpmProviderDeleteByKey0", uintptr(h), uintptr(unsafe.Pointer(&providerKey))); err != nil {
			return err
		}
	}
	if err = wCall("FwpmTransactionCommit0", uintptr(h)); err != nil {
		return err
	}
	committed = true
	return nil
}

func emergencyProviderFingerprintMatches(provider *wProvider, expected [32]byte) bool {
	if !emergencyProviderMatches(provider) {
		return false
	}
	for i, value := range unsafe.Slice(provider.Data.Data, 32) {
		if value != expected[i] {
			return false
		}
	}
	return true
}

//go:build windows && onetunnel_safety_test

package platform

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateAcceptancePermitCanary creates only loopback permits, never deny rules.
// It is a harmless persistent-object recovery drill, not a kill-switch test.
func CreateAcceptancePermitCanary(owner, root string) error {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	if err = validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		return err
	}
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
	provider, sublayer, filters := acceptancePermitObjects(trafficLock{owner: owner, root: root})
	if err = wCall("FwpmProviderAdd0", uintptr(h), uintptr(unsafe.Pointer(&provider)), 0); err != nil {
		return err
	}
	if err = wCall("FwpmSubLayerAdd0", uintptr(h), uintptr(unsafe.Pointer(&sublayer)), 0); err != nil {
		return err
	}
	for i := range filters {
		var id uint64
		if err = wCall("FwpmFilterAdd0", uintptr(h), uintptr(unsafe.Pointer(&filters[i])), 0, uintptr(unsafe.Pointer(&id))); err != nil {
			return err
		}
	}
	keep(provider)
	keep(sublayer)
	keep(filters)
	err = wCall("FwpmTransactionCommit0", uintptr(h))
	committed = err == nil
	return err
}

func acceptancePermitObjects(lock trafficLock) (wProvider, wSublayer, []wFilter) {
	providerKey, sublayerKey := lock.key("provider"), lock.key("sublayer")
	fingerprint := lock.ownerHash()
	provider := wProvider{Key: providerKey, Display: wDisplayName("OneTunnel kill switch"), Flags: 1, Data: wBlob{Size: 32, Data: &fingerprint[0]}}
	sublayer := wSublayer{Key: sublayerKey, Display: wDisplayName("OneTunnel persistent traffic lock"), Flags: 1, Provider: &providerKey, Weight: 0xfffe}
	filters := make([]wFilter, len(wLayers))
	for i, layer := range wLayers {
		loopback := &wCondition{Field: wFlags, Match: 6, Value: wValue{Type: 3, Data: 1}}
		filters[i] = wFilter{Key: lock.key(fmt.Sprintf("filter/%d", i)), Display: wDisplayName("OneTunnel · loopback"), Flags: 1, Provider: &providerKey, Layer: layer, Sublayer: sublayerKey, Weight: wValue{Type: 1, Data: 13}, Count: 1, Conditions: loopback, Action: wAction{Type: 0x1002}}
	}
	return provider, sublayer, filters
}

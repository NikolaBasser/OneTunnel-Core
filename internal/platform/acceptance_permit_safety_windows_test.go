//go:build windows && onetunnel_safety_test

package platform

import (
	"strings"
	"testing"
)

func TestAcceptanceCanaryContainsOnlyScopedLoopbackPermits(t *testing.T) {
	lock := trafficLock{owner: "OneTunnel-Test-11111111111111111111111111111111", root: `C:\synthetic\runtime`}
	provider, sublayer, filters := acceptancePermitObjects(lock)
	if provider.Key != lock.key("provider") || sublayer.Key != lock.key("sublayer") || !emergencyProviderFingerprintMatches(&provider, lock.ownerHash()) || len(filters) != 4 {
		t.Fatal("canary owner mismatch")
	}
	for i, filter := range filters {
		if filter.Action.Type != 0x1002 || filter.Layer != wLayers[i] || filter.Count != 1 || filter.Conditions == nil || filter.Conditions.Field != wFlags || filter.Conditions.Match != 6 || filter.Conditions.Value.Type != 3 || filter.Conditions.Value.Data != 1 || filter.Provider == nil || *filter.Provider != provider.Key || filter.Sublayer != sublayer.Key {
			t.Fatal("canary can affect non-loopback traffic or belongs to another owner")
		}
	}
}

func TestAcceptanceExpectedRecoveryRejectsMalformedScopeBeforeWFP(t *testing.T) {
	for _, entry := range [][2]string{{"invalid", strings.Repeat("0", 64)}, {"{11111111-1111-4111-8111-111111111111}", "invalid"}, {"{11111111-1111-4111-8111-111111111111}", strings.Repeat("0", 62)}} {
		if RecoverEmergencyWFPProviderExpected(entry[0], entry[1]) == nil {
			t.Fatal("malformed scope accepted")
		}
	}
}

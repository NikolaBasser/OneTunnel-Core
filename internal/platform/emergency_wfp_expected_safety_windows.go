//go:build windows && onetunnel_safety_test

package platform

import (
	"encoding/hex"
	"errors"

	"golang.org/x/sys/windows"
)

// RecoverEmergencyWFPProviderExpected is available only to explicit safety builds.
// Ownership is checked inside the deletion transaction; absent keys are harmless.
func RecoverEmergencyWFPProviderExpected(guid, expectedFingerprint string) error {
	key, err := windows.GUIDFromString(guid)
	if err != nil {
		return errors.New("invalid recovery provider GUID")
	}
	bytes, err := hex.DecodeString(expectedFingerprint)
	if err != nil || len(bytes) != 32 {
		return errors.New("invalid recovery provider fingerprint")
	}
	var expected [32]byte
	copy(expected[:], bytes)
	return recoverEmergencyWFPExpected(&key, &expected)
}

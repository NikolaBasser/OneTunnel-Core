package platform

import (
	"strings"
	"testing"
)

func TestPipeOwnerValidationAndRestrictedAccess(t *testing.T) {
	if _, err := PipeSecurity("S-1-5-21-1-2-3-1001)(A;;GA;;;WD)"); err == nil {
		t.Fatal("SDDL injection accepted")
	}
	descriptor, err := PipeSecurity("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(descriptor, "(D;;GA;;;NU)") || !strings.Contains(descriptor, "0x12019b") || strings.Contains(descriptor, ";;;WD)") {
		t.Fatal("unrestricted control pipe")
	}
}

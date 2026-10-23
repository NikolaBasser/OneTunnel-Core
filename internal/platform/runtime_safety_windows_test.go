//go:build windows && onetunnel_safety_test

package platform

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestSafetyRuntimeIdentityIsRestrictedToFreshTestSibling(t *testing.T) {
	programData := `C:\ProgramData`
	id := "0123456789abcdef0123456789abcdef"
	owner := "OneTunnel-Test-" + id
	root := filepath.Join(programData, "OneTunnel-Phase4Runtime-"+id)
	if err := validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ owner, root string }{
		{"OneTunnel-Service", root},
		{"OneTunnel-Test-../../installed", root},
		{owner, filepath.Join(programData, "OneTunnel", "Service", owner)},
		{owner, filepath.Join(programData, "OneTunnel-Phase4Runtime-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
	} {
		if err := validateSafetyTestRuntimeIdentity(programData, tc.owner, tc.root); err == nil {
			t.Fatalf("accepted owner %q at root %q", tc.owner, tc.root)
		}
	}
}

func TestSafetyRuntimeReopenRequiresExactOwnerMarker(t *testing.T) {
	owner := "OneTunnel-Test-0123456789abcdef0123456789abcdef"
	root := filepath.Join(`C:\ProgramData`, "OneTunnel-Phase4Runtime-0123456789abcdef0123456789abcdef")
	marker, err := json.Marshal(safetyOwnerMarker{Version: 1, Owner: owner, Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSafetyOwnerMarker(marker, owner, root); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(`{"version":1,"owner":"OneTunnel-Service","root":"C:\\ProgramData\\OneTunnel-Phase4Runtime-0123456789abcdef0123456789abcdef"}`),
		[]byte(`{"version":1,"owner":"OneTunnel-Test-0123456789abcdef0123456789abcdef","root":"C:\\ProgramData\\OneTunnel\\Service\\OneTunnel-Test-0123456789abcdef0123456789abcdef"}`),
		append(append([]byte(nil), marker...), []byte(` {}`)...),
	} {
		if err := validateSafetyOwnerMarker(data, owner, root); err == nil {
			t.Fatalf("accepted unsafe owner marker %s", data)
		}
	}
}

func TestSafetyRuntimeAcceptsOnlyExactProtectedPrivateDACL(t *testing.T) {
	for _, sddl := range []string{
		"O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)",
	} {
		if !hasPrivateRuntimeDACL(sddl) {
			t.Fatalf("rejected expected protected DACL %q", sddl)
		}
	}
	for _, sddl := range []string{
		"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)",
		"D:AR(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
	} {
		if hasPrivateRuntimeDACL(sddl) {
			t.Fatalf("accepted unexpected protected DACL %q", sddl)
		}
	}
}

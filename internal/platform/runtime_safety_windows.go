//go:build windows && onetunnel_safety_test

package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
)

var safetyOwnerID = regexp.MustCompile(`^OneTunnel-Test-([0-9a-f]{32})$`)

type safetyOwnerMarker struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	Root    string `json:"root"`
}

// NewSafetyTestRuntime is available only in explicitly tagged test builds. It
// isolates Runtime state under a fresh ProgramData sibling and never seals the
// installed OneTunnel directory ancestors.
func NewSafetyTestRuntime(directory, owner, root string, update func(control.State)) (*Runtime, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, err
	}
	if err = validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		return nil, err
	}
	if _, err = os.Lstat(root); !os.IsNotExist(err) {
		return nil, errors.New("safety runtime root already exists")
	}
	if err = privateDirectory(root); err != nil {
		return nil, err
	}
	if err = writeSafetyOwnerMarker(root, owner); err != nil {
		return nil, err
	}
	if err = privateDirectory(filepath.Join(root, "runtime")); err != nil {
		return nil, err
	}
	return newRuntimeAtRoot(directory, owner, root, update), nil
}

// OpenSafetyTestRuntime only reopens an isolated root bearing the exact marker
// written by NewSafetyTestRuntime. It never repairs an existing root ACL.
func OpenSafetyTestRuntime(directory, owner, root string, update func(control.State)) (*Runtime, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, err
	}
	if err = validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		return nil, err
	}
	if err = verifySafetyTestRoot(root, owner); err != nil {
		return nil, err
	}
	runtimePath := filepath.Join(root, "runtime")
	if _, err = os.Lstat(runtimePath); os.IsNotExist(err) {
		if err = privateDirectory(runtimePath); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, errors.New("safety runtime directory unavailable")
	}
	if err = verifySafetyDirectory(runtimePath); err != nil {
		return nil, err
	}
	return newRuntimeAtRoot(directory, owner, root, update), nil
}

func validateSafetyTestRuntimeIdentity(programData, owner, root string) error {
	match := safetyOwnerID.FindStringSubmatch(owner)
	if len(match) != 2 {
		return errors.New("invalid safety runtime owner")
	}
	expected := filepath.Join(programData, "OneTunnel-Phase4Runtime-"+match[1])
	actual, err := filepath.Abs(filepath.Clean(root))
	if err != nil || !strings.EqualFold(actual, filepath.Clean(expected)) {
		return errors.New("invalid safety runtime root")
	}
	return nil
}

func writeSafetyOwnerMarker(root, owner string) error {
	marker := safetyOwnerMarker{Version: 1, Owner: owner, Root: filepath.Clean(root)}
	file, err := os.OpenFile(filepath.Join(root, "safety-owner.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("safety owner marker creation failed")
	}
	if err = json.NewEncoder(file).Encode(marker); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func verifySafetyTestRoot(root, owner string) error {
	if err := verifySafetyDirectory(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) < 1 || len(entries) > 2 {
		return errors.New("unexpected safety runtime root contents")
	}
	var foundMarker bool
	for _, entry := range entries {
		switch entry.Name() {
		case "safety-owner.json":
			foundMarker = true
		case "runtime":
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("safety runtime path is not a directory")
			}
		default:
			return errors.New("unexpected safety runtime root contents")
		}
	}
	if !foundMarker {
		return errors.New("safety owner marker missing")
	}
	markerPath := filepath.Join(root, "safety-owner.json")
	info, err := os.Lstat(markerPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("safety owner marker unavailable")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(markerPath))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("safety owner marker is reparse")
	}
	data, err := os.ReadFile(markerPath)
	if err != nil || len(data) > 4096 {
		return errors.New("safety owner marker invalid")
	}
	if err = validateSafetyOwnerMarker(data, owner, root); err != nil {
		return err
	}
	return nil
}

func validateSafetyOwnerMarker(data []byte, owner, root string) error {
	var marker safetyOwnerMarker
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || decoder.Decode(new(any)) != io.EOF ||
		marker.Version != 1 || marker.Owner != owner || !strings.EqualFold(filepath.Clean(marker.Root), filepath.Clean(root)) {
		return errors.New("safety owner marker identity mismatch")
	}
	return nil
}

func verifySafetyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("safety runtime directory unavailable")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("safety runtime directory is reparse")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !hasPrivateRuntimeDACL(sd.String()) {
		return errors.New("safety runtime directory ACL mismatch")
	}
	return nil
}

func hasPrivateRuntimeDACL(sddl string) bool {
	index := strings.Index(sddl, "D:")
	if index < 0 {
		return false
	}
	dacl := sddl[index+2:]
	if strings.HasPrefix(dacl, "P") {
		dacl = dacl[1:]
	} else {
		return false
	}
	if strings.HasPrefix(dacl, "AI") {
		dacl = dacl[2:]
	}
	return dacl == "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" || dacl == "(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
}

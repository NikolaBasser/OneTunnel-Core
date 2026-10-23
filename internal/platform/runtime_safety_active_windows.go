//go:build windows && onetunnel_safety_test

package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
)

// OpenSafetyActiveRuntime only recovers the synthetic embedded proxy case. The
// idle canary's stricter factory remains unchanged.
func OpenSafetyActiveRuntime(directory, owner, root string, update func(control.State)) (*Runtime, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, err
	}
	if err = validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		return nil, err
	}
	if err = verifySafetyDirectory(root); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	foundMarker, foundRuntime := false, false
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if entry.Name() == "runtime" {
			if err = verifySafetyDirectory(path); err != nil {
				return nil, err
			}
			foundRuntime = true
			continue
		}
		if entry.Name() != "safety-owner.json" && entry.Name() != "session.json" && entry.Name() != "kill-switch.json" && entry.Name() != "session.json.new" && entry.Name() != "kill-switch.json.new" {
			return nil, errors.New("unexpected active safety root entry")
		}
		data, readErr := readActiveSafetyFile(path, 65536)
		if readErr != nil {
			return nil, readErr
		}
		switch entry.Name() {
		case "safety-owner.json":
			err = validateSafetyOwnerMarker(data, owner, root)
			foundMarker = true
		case "session.json":
			err = validateActiveSafetySession(data, root, directory)
		case "kill-switch.json":
			var marker struct {
				Version int    `json:"version"`
				Scope   string `json:"scope"`
			}
			err = decodeActiveSafetyJSON(data, &marker)
			if err == nil && (marker.Version != 1 || marker.Scope != "whole-device") {
				err = errors.New("invalid active safety lock marker")
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if !foundMarker || !foundRuntime {
		return nil, errors.New("missing active safety owner/runtime")
	}
	return newRuntimeAtRoot(directory, owner, root, update), nil
}
func readActiveSafetyFile(path string, limit int64) ([]byte, error) {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("active safety file is unavailable or reparse")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid active safety file")
	}
	return os.ReadFile(path)
}
func decodeActiveSafetyJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid active safety JSON tail")
	}
	return nil
}
func validateActiveSafetySession(data []byte, root, directory string) error {
	var session Session
	if err := decodeActiveSafetyJSON(data, &session); err != nil {
		return err
	}
	if session.Kind != "proxy" || !session.FullDevice || session.EmbeddedNative || session.Pid != 0 || session.Started != 0 || session.XrayPid != 0 || session.XrayStarted != 0 || !tunnelNamePattern.MatchString(session.TunnelName) {
		return errors.New("session is not a synthetic embedded proxy")
	}
	expectedConfig := filepath.Join(root, "runtime", session.TunnelName+".json")
	if !strings.EqualFold(filepath.Clean(session.ConfigPath), expectedConfig) || !strings.EqualFold(filepath.Clean(session.Engine), filepath.Join(directory, "engines", "sing-box.exe")) {
		return errors.New("active safety session paths mismatch")
	}
	return nil
}

// ReleaseSafetyActiveLock is an emergency fallback after the harness has
// independently confirmed its exact embedded worker has terminated. It never
// reads executable paths from a journal or touches any other owner's filters.
func ReleaseSafetyActiveLock(owner, root string) error {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	if err = validateSafetyTestRuntimeIdentity(programData, owner, root); err != nil {
		return err
	}
	if err = verifySafetyDirectory(root); err != nil {
		return err
	}
	data, err := readActiveSafetyFile(filepath.Join(root, "safety-owner.json"), 4096)
	if err != nil {
		return err
	}
	if err = validateSafetyOwnerMarker(data, owner, root); err != nil {
		return err
	}
	return (trafficLock{owner: owner, root: root}).remove(true)
}

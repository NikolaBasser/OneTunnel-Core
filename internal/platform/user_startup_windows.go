//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// UserStartup writes only the named current-user Run value and never replaces a different owner.
type UserStartup struct{ Registry UserRegistry }

func (s UserStartup) Enable(executable, ownedCommand string) (string, error) {
	command, err := s.ProposedCommand(executable)
	if err != nil {
		return "", err
	}
	reg := s.Registry
	if reg == nil {
		reg = windowsUserRegistry{}
	}
	if err = enableOwnedStartup(reg, command, ownedCommand); err != nil {
		return "", err
	}
	return command, nil
}

// ProposedCommand returns the exact current-user Run value Enable would write.
func (s UserStartup) ProposedCommand(executable string) (string, error) {
	path, err := validateStableUserExecutable(executable)
	if err != nil {
		return "", err
	}
	return windows.EscapeArg(path) + " --startup", nil
}

// Status reports whether the current Run value exactly matches the recorded owner.
func (s UserStartup) Status(ownedCommand string) (bool, error) {
	if strings.TrimSpace(ownedCommand) == "" {
		return false, nil
	}
	reg := s.Registry
	if reg == nil {
		reg = windowsUserRegistry{}
	}
	current, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil {
		return false, err
	}
	return current.Exists && current.Type == registry.SZ && decodeRegistryString(current) == ownedCommand, nil
}

func enableOwnedStartup(reg UserRegistry, command, ownedCommand string) error {
	current, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil {
		return err
	}
	if current.Exists {
		if ownedCommand == command && current.Type == registry.SZ && decodeRegistryString(current) == command {
			return nil
		}
		return errors.New("an unrelated startup entry already uses the OneTunnel value")
	}
	if err = reg.Write(userProxyRunKey, userProxyRunValue, RawRegistryValue{Exists: true, Type: registry.SZ, Data: registryStringBytes(command)}); err != nil {
		return err
	}
	return nil
}

func (s UserStartup) Disable(ownedCommand string) (bool, error) {
	if strings.TrimSpace(ownedCommand) == "" {
		return false, errors.New("owned startup command is required")
	}
	reg := s.Registry
	if reg == nil {
		reg = windowsUserRegistry{}
	}
	current, err := reg.Read(userProxyRunKey, userProxyRunValue)
	if err != nil {
		return false, err
	}
	if !current.Exists {
		return false, nil
	}
	if current.Type != registry.SZ || decodeRegistryString(current) != ownedCommand {
		return true, nil
	}
	return false, reg.Delete(userProxyRunKey, userProxyRunValue)
}

func validateStableUserExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), "OneTunnel.exe") {
		return "", errors.New("startup executable must be the installed OneTunnel.exe")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(abs, `\\`) {
		return "", errors.New("startup executable must be on a local drive")
	}
	temp, err := filepath.Abs(os.TempDir())
	if err == nil && (strings.EqualFold(abs, temp) || strings.HasPrefix(strings.ToLower(abs), strings.ToLower(temp+string(os.PathSeparator)))) {
		return "", errors.New("temporary installations cannot be registered for startup")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("startup executable is missing or reparse-backed")
	}
	if err = rejectReparsePath(abs); err != nil {
		return "", errors.New("startup path contains a reparse point")
	}
	for dir := filepath.Dir(abs); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		st, e := os.Lstat(dir)
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("startup path contains a reparse point")
		}
	}
	return abs, nil
}

package platform

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/control"
	"path/filepath"
)

func LegacyUserRecovery(ctx context.Context, root, directory string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator token required")
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	owner := user.User.Sid.String()
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return e
	}
	serviceRoot := filepath.Join(data, "OneTunnel", "Service", owner)
	if exists(filepath.Join(serviceRoot, "session.json")) || exists(filepath.Join(serviceRoot, "kill-switch.json")) {
		return errors.New("recover the current service connection first")
	}
	// Caller supplies only its own user-store root, never an RPC from the service.
	r := &Runtime{root: root, directory: directory, lock: trafficLock{owner: owner, root: root}, update: func(control.State) {}}
	if !r.recovery() {
		return nil
	}
	return r.recover(ctx)
}

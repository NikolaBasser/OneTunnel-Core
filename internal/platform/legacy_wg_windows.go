package platform

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"time"
)

// Older releases used WireGuard's service namespace. Recovery must not depend
// on the removed WireGuard executable, nor call AWG's different uninstaller.
func removeLegacyWireGuardService(ctx context.Context, tunnel string) error {
	if !tunnelNamePattern.MatchString(tunnel) {
		return errors.New("invalid owned tunnel")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("WireGuardTunnel$" + tunnel)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		if _, err = service.Control(svc.Stop); err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
			return err
		}
		for i := 0; i < 50; i++ {
			status, err = service.Query()
			if err != nil {
				return err
			}
			if status.State == svc.Stopped {
				break
			}
			if err = delay(ctx, 200*time.Millisecond); err != nil {
				return err
			}
		}
		if status.State != svc.Stopped {
			return errors.New("legacy tunnel did not stop")
		}
	}
	return service.Delete()
}

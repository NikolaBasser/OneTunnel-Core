package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/buildinfo"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type service struct{ owner, directory string }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("OneTunnel Go core %s; control API %d; revision %s; dirty %s; embedded Windows runtime\n", buildinfo.Version, control.Version, buildinfo.Revision, buildinfo.Dirty)
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	directory := filepath.Dir(executable)
	data, err := os.ReadFile(filepath.Join(directory, "service-owner.json"))
	if err != nil {
		os.Exit(2)
	}
	var config struct {
		OwnerSID string `json:"OwnerSid"`
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil {
		os.Exit(2)
	}
	if _, err := platform.PipeSecurity(config.OwnerSID); err != nil {
		os.Exit(2)
	}
	// The independent test watchdog uses this only after stopping the public
	// service. Recovery never takes caller-supplied paths or changes other VPNs.
	if len(os.Args) == 2 && os.Args[1] == "--recover-network" {
		manager, e := mgr.Connect()
		if e != nil {
			os.Exit(2)
		}
		defer manager.Disconnect()
		installed, e := manager.OpenService(control.ServiceName)
		if e != nil {
			os.Exit(2)
		}
		status, e := installed.Query()
		installed.Close()
		if e != nil || status.State != svc.Stopped {
			os.Exit(2)
		}
		r, e := platform.NewRuntime(directory, config.OwnerSID, func(control.State) {}, func() {})
		if e != nil {
			os.Exit(1)
		}
		defer r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		response, e := r.Call(ctx, control.Request{Version: control.Version, Command: "recover"})
		if e != nil || response.Error != nil || response.State.NeedsRecovery || response.State.TrafficLocked {
			os.Exit(1)
		}
		fmt.Println("Owned network session recovered")
		return
	}
	if err := svc.Run(control.ServiceName, &service{config.OwnerSID, directory}); err != nil {
		os.Exit(1)
	}
}
func (s *service) Execute(args []string, changes <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	manager, err := control.NewManager(func(update func(control.State), fail func()) (control.Backend, error) {
		return platform.NewRuntime(s.directory, s.owner, update, fail)
	})
	if err != nil {
		return false, 1066
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- platform.Serve(ctx, s.owner, manager) }()
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- running
	for {
		select {
		case request := <-changes:
			switch request.Cmd {
			case svc.Interrogate:
				status <- running
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 420000, CheckPoint: 1}
				err := stopServiceGracefully(cancel, done, func() error {
					return stopRuntimeForSCM(manager)
				}, func(checkpoint uint32) {
					status <- svc.Status{State: svc.StopPending, WaitHint: 420000, CheckPoint: checkpoint}
				})
				if err != nil {
					return false, 1066
				}
				return false, 0
			}
		case <-done:
			return false, 1066
		}
	}
}

func stopServiceGracefully(cancel func(), pipeDone <-chan error, recoverOwned func() error, progress func(uint32)) error {
	cancel()
	drainErr, checkpoint := waitForPipeDrain(pipeDone, progress, 1)
	recoveryErr, _ := waitWithProgress(recoverOwned, progress, checkpoint)
	if drainErr != nil && recoveryErr != nil {
		return fmt.Errorf("control pipe shutdown failed: %v; graceful recovery failed: %w", drainErr, recoveryErr)
	}
	if drainErr != nil {
		return fmt.Errorf("control pipe shutdown failed: %w", drainErr)
	}
	return recoveryErr
}

func waitForPipeDrain(pipeDone <-chan error, progress func(uint32), checkpoint uint32) (error, uint32) {
	return waitWithProgress(func() error { return <-pipeDone }, progress, checkpoint)
}

func waitWithProgress(action func() error, progress func(uint32), checkpoint uint32) (error, uint32) {
	done := make(chan error, 1)
	go func() { done <- action() }()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err, checkpoint
		case <-ticker.C:
			checkpoint++
			if progress != nil {
				progress(checkpoint)
			}
		}
	}
}

func stopRuntimeForSCM(manager *control.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	response := manager.Dispatch(ctx, control.Request{Version: control.Version, Command: "recover"})
	if response.Error != nil {
		return fmt.Errorf("graceful recovery failed: %s", *response.Error)
	}
	if response.State.Active || response.State.TrafficLocked || response.State.NeedsRecovery {
		return errors.New("graceful recovery left traffic protection or recovery active")
	}
	return nil
}

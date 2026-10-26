package main

import (
	"context"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

type shutdownTestBackend struct {
	state   control.State
	stopErr bool
	calls   []string
	update  func(control.State)
	alive   bool
}

func (b *shutdownTestBackend) Alive() bool { return b.alive }
func (b *shutdownTestBackend) Close()      { b.alive = false }
func (b *shutdownTestBackend) Call(_ context.Context, r control.Request) (control.BackendResult, error) {
	b.calls = append(b.calls, r.Command)
	if r.Command == "recover" {
		if b.stopErr {
			b.state = control.State{Active: true, TrafficLocked: true, NeedsRecovery: true, Status: "recovery required"}
			b.update(b.state)
			message := "operation_failed"
			return control.BackendResult{State: b.state, Error: &message}, nil
		}
		b.state = control.State{Status: "disconnected"}
	}
	b.update(b.state)
	return control.BackendResult{State: b.state}, nil
}

func newShutdownTestManager(t *testing.T, failStop bool) (*control.Manager, *shutdownTestBackend) {
	t.Helper()
	var backend *shutdownTestBackend
	manager, err := control.NewManager(func(update func(control.State), fail func()) (control.Backend, error) {
		backend = &shutdownTestBackend{state: control.State{Active: true, TrafficLocked: true, Status: "connected"}, stopErr: failStop, update: update, alive: true}
		return backend, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	return manager, backend
}

func TestSCMShutdownRunsRecoveryBeforeReturning(t *testing.T) {
	manager, backend := newShutdownTestManager(t, false)
	if err := stopRuntimeForSCM(manager); err != nil {
		t.Fatal(err)
	}
	if len(backend.calls) != 2 || backend.calls[0] != "hello" || backend.calls[1] != "recover" {
		t.Fatalf("unexpected backend calls: %v", backend.calls)
	}
	if state := manager.Dispatch(context.Background(), control.Request{Version: control.Version, Command: "status"}).State; state.Active || state.TrafficLocked || state.NeedsRecovery {
		t.Fatalf("shutdown returned before protection was cleared: %+v", state)
	}
}

func TestSCMShutdownFailureDoesNotReportGracefulCompletion(t *testing.T) {
	manager, backend := newShutdownTestManager(t, true)
	err := stopRuntimeForSCM(manager)
	if err == nil || err.Error() == "" {
		t.Fatalf("expected a recovery error, got %v", err)
	}
	if len(backend.calls) != 2 || backend.calls[1] != "recover" {
		t.Fatalf("recovery was not attempted: %v", backend.calls)
	}
	state := manager.Dispatch(context.Background(), control.Request{Version: control.Version, Command: "status"}).State
	if !state.Active || !state.TrafficLocked || !state.NeedsRecovery {
		t.Fatalf("failed recovery did not preserve protective state: %+v", state)
	}
}

func TestSCMShutdownDrainsPipeBeforeRecovery(t *testing.T) {
	canceled := make(chan struct{})
	pipeDone := make(chan error)
	pipeReturned := make(chan struct{})
	go func() {
		<-canceled
		pipeDone <- nil
		close(pipeReturned)
	}()
	err := stopServiceGracefully(func() { close(canceled) }, pipeDone, func() error {
		<-pipeReturned
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
}

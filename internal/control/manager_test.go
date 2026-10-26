package control

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	state        State
	alive        atomic.Bool
	update       func(State)
	fail         func()
	startEntered chan struct{}
	release      chan struct{}
	starts       atomic.Int32
	mu           sync.Mutex
}

func (b *fakeBackend) Alive() bool { return b.alive.Load() }
func (b *fakeBackend) Close() {
	if b.alive.Swap(false) {
		b.fail()
	}
}
func (b *fakeBackend) Call(ctx context.Context, r Request) (BackendResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch r.Command {
	case "start":
		b.starts.Add(1)
		if b.startEntered != nil {
			close(b.startEntered)
			<-b.release
		}
		b.state = State{Active: true, TrafficLocked: r.FullDevice, WholeDevice: r.FullDevice, FullDeviceMode: r.FullDevice, Status: "connected"}
	case "stop", "recover":
		b.state = State{Status: "Отключено"}
	}
	b.update(b.state)
	return BackendResult{State: b.state}, nil
}
func fakeManager(t *testing.T) (*Manager, *[]*fakeBackend) {
	t.Helper()
	all := []*fakeBackend{}
	m, err := NewManager(func(update func(State), fail func()) (Backend, error) {
		b := &fakeBackend{update: update, fail: fail}
		b.alive.Store(true)
		if len(all) > 0 {
			b.state = State{NeedsRecovery: true, TrafficLocked: true}
		}
		all = append(all, b)
		return b, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, &all
}
func start() Request {
	return Request{Version: 1, Command: "start", Profile: testProfile(), FullDevice: true}
}

func TestCanceledRequestNeverStartsBackend(t *testing.T) {
	m, all := fakeManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 128; i++ {
		response := m.Dispatch(ctx, start())
		if response.Error == nil || *response.Error != "operation_timeout" {
			t.Fatalf("canceled request was accepted: %+v", response)
		}
	}
	if (*all)[0].starts.Load() != 0 {
		t.Fatal("canceled requests reached backend")
	}
}
func command(s string) Request { return Request{Version: 1, Command: s} }
func TestManagerSessionIdentityAndDuplicateStart(t *testing.T) {
	m, all := fakeManager(t)
	reply := m.Dispatch(context.Background(), start())
	if reply.Error != nil || !reply.State.Active || reply.State.ProfileID == nil || *reply.State.ProfileID != testProfile().ID {
		t.Fatal("session not owned by Go")
	}
	duplicate := m.Dispatch(context.Background(), start())
	if duplicate.Error == nil || *duplicate.Error != "recovery_required" || (*all)[0].starts.Load() != 1 {
		t.Fatal("duplicate start reached adapter")
	}
	stop := m.Dispatch(context.Background(), command("stop"))
	if stop.State.Active || stop.State.ProfileID != nil {
		t.Fatal("stop kept active identity")
	}
}
func TestStatusResponsiveAndAcceptedRequestSurvivesClientCancellation(t *testing.T) {
	m, all := fakeManager(t)
	b := (*all)[0]
	b.startEntered = make(chan struct{})
	b.release = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Response, 1)
	go func() { done <- m.Dispatch(ctx, start()) }()
	<-b.startEntered
	cancel()
	status := make(chan Response, 1)
	go func() { status <- m.Dispatch(context.Background(), command("status")) }()
	select {
	case r := <-status:
		if r.Instance == "" {
			t.Fatal("missing service identity")
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind startup")
	}
	close(b.release)
	if r := <-done; r.Error != nil || !r.State.Active {
		t.Fatal("accepted operation canceled with GUI")
	}
}
func TestAdapterFailureRequiresExplicitRecovery(t *testing.T) {
	m, all := fakeManager(t)
	m.Dispatch(context.Background(), start())
	old := (*all)[0]
	old.Close()
	old.update(State{Active: true, Status: "stale event"})
	failed := m.Dispatch(context.Background(), command("status"))
	if failed.State.Active || !failed.State.TrafficLocked || !failed.State.NeedsRecovery {
		t.Fatal("failure lost protection state")
	}
	refused := m.Dispatch(context.Background(), start())
	if refused.Error == nil || len(*all) != 1 {
		t.Fatal("silently restarted failed adapter")
	}
	recovered := m.Dispatch(context.Background(), command("recover"))
	if recovered.Error != nil || recovered.State.NeedsRecovery || recovered.State.TrafficLocked || len(*all) != 2 {
		t.Fatal("explicit recovery failed")
	}
	old.update(State{Active: true, TrafficLocked: true})
	if m.snapshot().Active {
		t.Fatal("old generation modified current state")
	}
}
func TestFactoryFailureDoesNotPanic(t *testing.T) {
	if _, err := NewManager(func(func(State), func()) (Backend, error) { return nil, errors.New("offline") }); err == nil {
		t.Fatal("missing adapter accepted")
	}
}

package platform

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

type retryFixture struct {
	r         *Runtime
	now       time.Time
	effects   retryEffects
	starts    []string
	retained  []bool
	activated int
}

func newRetryFixture(t *testing.T) *retryFixture {
	t.Helper()
	f := &retryFixture{now: time.Unix(1000, 0)}
	f.r = &Runtime{root: t.TempDir(), update: func(control.State) {}}
	f.r.lock = trafficLock{owner: "synthetic-retry", root: f.r.root}
	if err := os.WriteFile(f.r.lock.marker(), []byte("synthetic marker; never applied"), 0600); err != nil {
		t.Fatal(err)
	}
	f.r.retry = retryState{targets: []control.Profile{{Name: "primary"}, {Name: "backup"}}, full: true, next: f.now}
	f.r.transportFailed = true
	f.effects = retryEffects{
		now:    func() time.Time { return f.now },
		health: func(context.Context) error { return nil },
		disconnect: func(_ context.Context, retain bool) error {
			f.retained = append(f.retained, retain)
			f.r.session = nil
			return nil
		},
		start: func(_ context.Context, request control.Request) error {
			f.starts = append(f.starts, request.Profile.Name)
			f.r.session = &Session{}
			return nil
		},
		activate: func() { f.activated++ },
	}
	t.Cleanup(func() {
		if !f.r.lock.needed() {
			t.Error("retry removed retained protection marker")
		}
	})
	return f
}

func TestRetryStateHealthyAndDebounced(t *testing.T) {
	f := newRetryFixture(t)
	f.r.session, f.r.transportFailed = &Session{}, false
	checks := 0
	f.effects.health = func(context.Context) error { checks++; return nil }
	f.r.retry.next = f.now.Add(time.Second)
	f.r.maintainConnectionWith(f.effects)
	if checks != 0 {
		t.Fatal("health check ran before deadline")
	}
	f.now = f.r.retry.next
	f.r.maintainConnectionWith(f.effects)
	if checks != 1 || len(f.starts) != 0 || !f.r.retry.next.Equal(f.now.Add(20*time.Second)) {
		t.Fatal("healthy session restarted or wrong health deadline")
	}
}

func TestRetryStateTwoHealthFailures(t *testing.T) {
	f := newRetryFixture(t)
	f.r.session, f.r.transportFailed = &Session{}, false
	checks := 0
	f.effects.health = func(context.Context) error {
		checks++
		if checks <= 2 {
			return errors.New("outage")
		}
		return nil
	}
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 0 || f.r.retry.failures != 1 {
		t.Fatal("single failure restarted session")
	}
	f.now = f.r.retry.next
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 1 || f.starts[0] != "primary" || f.r.retrying || f.r.transportFailed || f.activated != 1 {
		t.Fatal("second failure did not reconnect primary")
	}
}

func TestRetryStateFallbackAndPromotion(t *testing.T) {
	f := newRetryFixture(t)
	f.effects.start = func(_ context.Context, request control.Request) error {
		if request.Version != 1 || request.Command != "start" || !request.FullDevice {
			t.Fatal("retry lost its original full-device request")
		}
		f.starts = append(f.starts, request.Profile.Name)
		if request.Profile.Name == "primary" {
			return errors.New("unavailable")
		}
		f.r.session = &Session{}
		return nil
	}
	f.r.maintainConnectionWith(f.effects)
	if f.r.retry.attempt != 1 || !f.r.retrying || !f.r.transportFailed || !f.r.retry.next.Equal(f.now.Add(3*time.Second)) {
		t.Fatal("failed primary did not enter bounded backoff")
	}
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 1 {
		t.Fatal("retry ignored backoff")
	}
	f.now = f.r.retry.next
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 2 || f.starts[1] != "backup" || f.r.retry.targets[0].Name != "backup" || f.r.retry.attempt != 0 || f.r.retrying || f.r.transportFailed || f.activated != 1 {
		t.Fatal("working fallback was not activated and promoted")
	}
	for _, retained := range f.retained {
		if !retained {
			t.Fatal("retry requested removal of traffic lock")
		}
	}
}

func TestRetryStateExhaustionRetainsProtection(t *testing.T) {
	f := newRetryFixture(t)
	f.effects.start = func(_ context.Context, request control.Request) error {
		f.starts = append(f.starts, request.Profile.Name)
		return errors.New("unavailable")
	}
	for i := 0; i < 10; i++ {
		f.now = f.r.retry.next
		f.r.maintainConnectionWith(f.effects)
	}
	if len(f.starts) != 9 || len(f.r.retry.targets) != 0 || f.r.retrying || !f.r.transportFailed || f.activated != 0 {
		t.Fatal("retry budget did not stop fail closed")
	}
	if state := f.r.snapshot(); !state.TrafficLocked || state.Active || state.Reconnecting {
		t.Fatalf("invalid exhausted state: %+v", state)
	}
}

func TestRetryStateCleanupFailuresStopFurtherStarts(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			f := newRetryFixture(t)
			calls := 0
			f.effects.disconnect = func(_ context.Context, retain bool) error {
				calls++
				f.retained = append(f.retained, retain)
				if calls == failAt {
					return errors.New("cleanup failed")
				}
				return nil
			}
			f.effects.health = func(context.Context) error { return errors.New("probe failed") }
			f.r.maintainConnectionWith(f.effects)
			if len(f.r.retry.targets) != 0 || f.r.retrying || !f.r.transportFailed || len(f.starts) != failAt-1 || f.activated != 0 {
				t.Fatal("cleanup failure allowed a new start or connected state")
			}
			if state := f.r.snapshot(); state.Active || state.Reconnecting || !state.NeedsRecovery || !state.TrafficLocked {
				t.Fatalf("cleanup failure did not publish fail-closed recovery state: %+v", state)
			}
			f.now = f.r.retry.next
			f.r.maintainConnectionWith(f.effects)
			if calls != failAt {
				t.Fatal("cleanup failure was retried automatically")
			}
		})
	}
}

func TestRetryStateManualCancellationReachesTransport(t *testing.T) {
	f := newRetryFixture(t)
	entered, finished := make(chan struct{}), make(chan struct{})
	f.effects.start = func(ctx context.Context, _ control.Request) error { close(entered); <-ctx.Done(); return ctx.Err() }
	go func() { f.r.maintainConnectionWith(f.effects); close(finished) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retry did not start")
	}
	f.r.cancelRetry()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("manual cancellation did not stop retry")
	}
	// Call(stop/recover) clears the retry queue under the operation mutex after cancellation.
	f.r.retry = retryState{}
	f.r.retrying = false
	f.r.maintainConnectionWith(f.effects)
	if f.activated != 0 || f.r.session != nil {
		t.Fatal("cancelled retry was activated")
	}
}

func TestRetryStateCancellationWinsOverSuccessfulEffects(t *testing.T) {
	for _, boundary := range []string{"disconnect", "start", "health"} {
		t.Run(boundary, func(t *testing.T) {
			f := newRetryFixture(t)
			cleanups, checks := 0, 0
			f.r.update = func(state control.State) {
				if state.Active {
					t.Error("cancelled reconnect published connected")
				}
			}
			f.effects.disconnect = func(ctx context.Context, retain bool) error {
				cleanups++
				if !retain {
					t.Error("cancelled reconnect dropped traffic lock")
				}
				if cleanups == 1 && boundary == "disconnect" {
					f.r.cancelRetry()
				}
				if cleanups == 2 && ctx.Err() != nil {
					t.Error("cleanup reused cancelled operation context")
				}
				f.r.session = nil
				return nil
			}
			f.effects.start = func(_ context.Context, request control.Request) error {
				f.starts = append(f.starts, request.Profile.Name)
				f.r.session = &Session{}
				if boundary == "start" {
					f.r.cancelRetry()
				}
				return nil
			}
			f.effects.health = func(context.Context) error {
				checks++
				if boundary == "health" {
					f.r.cancelRetry()
				}
				return nil
			}
			f.r.maintainConnectionWith(f.effects)
			if f.activated != 0 || f.r.session != nil || !f.r.transportFailed || cleanups != 2 {
				t.Fatal("cancelled successful effect was promoted or transport was not disposed")
			}
			if boundary == "disconnect" && len(f.starts) != 0 {
				t.Fatal("start invoked after cancellation during disconnect")
			}
			if boundary != "health" && checks != 0 {
				t.Fatal("health invoked after known cancellation")
			}
			if f.r.retry.attempt != 1 || f.r.retry.targets[0].Name != "primary" {
				t.Fatal("cancelled reconnect reset retry budget or promoted fallback")
			}
		})
	}
}

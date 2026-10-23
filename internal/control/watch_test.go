package control

import (
	"context"
	"testing"
	"time"
)

func TestWatchDeliversChangesWithoutChangingLegacyReplies(t *testing.T) {
	m, _ := fakeManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan Response, 8)
	done := make(chan error, 1)
	go func() { done <- m.Watch(ctx, func(r Response) error { changes <- r; return nil }) }()
	var first Response
	select {
	case first = <-changes:
	case <-time.After(time.Second):
		t.Fatal("missing initial state")
	}
	normal := m.Dispatch(ctx, Request{Version: 1, Command: "status"})
	if normal.Revision != 0 {
		t.Fatal("legacy API-v1 reply schema changed")
	}
	m.mu.Lock()
	m.state.Status = "changed"
	m.notifyLocked()
	m.mu.Unlock()
	select {
	case next := <-changes:
		if next.Revision <= first.Revision || next.State.Status != "changed" {
			t.Fatal("missing ordered update")
		}
	case <-time.After(time.Second):
		t.Fatal("update not delivered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch ignored cancellation")
	}
}

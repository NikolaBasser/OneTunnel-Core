package profiles

import (
	"context"
	"encoding/json"
	"onetunnel/core/internal/control"
	"strings"
	"testing"
)

func TestReliabilityPersistMergeAndGroupCheck(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse("fixture", "socks5://127.0.0.1:1080", nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Group = "fixture group"
	p.Reliability = &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: true}
	doc.Profiles = []Profile{p}
	if err = store.Save(doc); err != nil {
		t.Fatal(err)
	}
	doc, err = store.Load()
	if err != nil || !doc.Profiles[0].Reliability.UseFallbacks {
		t.Fatal("policy lost", err)
	}
	fresh := p
	fresh.ID = "22222222-2222-4222-8222-222222222222"
	fresh.Reliability = nil
	merged, err := Merge(doc.Profiles, []Profile{fresh}, p.Group)
	if err != nil || !merged.Profiles[0].Reliability.AutoReconnect {
		t.Fatal("refresh lost policy", err)
	}
	called := 0
	a := &Application{Store: store, ServiceCall: func(_ context.Context, r control.Request) (control.Response, int64, error) {
		reply := control.Response{Version: 1, Instance: "fixture"}
		if r.Command == "check-profile" {
			called++
			if r.FullDevice {
				t.Fatal("group check requested TUN")
			}
			b, _ := json.Marshal(control.ProfileCheck{Success: true, NetworkTest: true, Milliseconds: 12, Message: "HTTPS works"})
			text := string(b)
			reply.Result = &text
		}
		return reply, 0, nil
	}}
	result, err := a.checkGroup(context.Background(), p.Group)
	if err != nil || called != 1 || len(result.Rows) != 1 || !result.Rows[0].Success {
		t.Fatal("group check failed", err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "socks5://") || strings.Contains(string(data), "Source") {
		t.Fatal("group check exposed credentials")
	}
	a.desktopContext = DesktopContext{StorageReady: true, SelectedID: p.ID}
	a.desktopState.Available = true
	a.desktopState.Response.State = control.State{Reconnecting: true, TrafficLocked: true, NeedsRecovery: true}
	projected := a.projectDesktop(a.desktopState, Environment{})
	if !projected.Actions.CanDisconnect || projected.Actions.CanConnect || projected.Actions.CanProbe || projected.Actions.CanCheckGroup {
		t.Fatal("reconnect action policy unsafe")
	}
}

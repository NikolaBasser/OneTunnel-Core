package profiles

import (
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"reflect"
	"testing"
)

func TestDesktopBrowsingDuringConnection(t *testing.T) {
	p := managementProfile(t, "11111111-1111-4111-8111-111111111111", "View", "Group")
	store := managementStore(t, Document{Profiles: []Profile{p}})
	app := &Application{Store: store, ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("view action contacted service")
		return control.Response{}, 0, nil
	}}
	for _, state := range []control.State{{Active: true}, {Reconnecting: true}, {TrafficLocked: true}, {NeedsRecovery: true}} {
		for _, busy := range []bool{false, true} {
			app.desktopContext = DesktopContext{StorageReady: true, SelectedID: p.ID, Busy: busy}
			app.desktopState.Response.State = state
			got := app.projectDesktop(app.desktopState, Environment{}).Actions
			if !got.CanSelect || got.CanSave || got.CanDelete || got.CanConnect {
				t.Fatalf("browse/write separation lost busy=%v state=%+v actions=%+v", busy, state, got)
			}
			before, _ := store.Load()
			if _, e := app.setGroupExpanded("Group", false); e != nil {
				t.Fatal(e)
			}
			after, _ := store.Load()
			if !reflect.DeepEqual(before.Profiles, after.Profiles) || !reflect.DeepEqual(app.desktopState.Response.State, state) {
				t.Fatal("collapse changed profiles or session")
			}
			if _, e := app.setAllGroupsExpanded(true); e != nil {
				t.Fatal(e)
			}
		}
	}
	app.desktopContext.StorageReady = false
	if app.projectDesktop(app.desktopState, Environment{}).Actions.CanSelect {
		t.Fatal("unreadable store enabled selection")
	}
}

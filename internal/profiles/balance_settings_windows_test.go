package profiles

import (
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"strings"
	"testing"
)

func TestBalanceSettingsSnapshotAcrossGroups(t *testing.T) {
	first := managementProfile(t, "11111111-1111-4111-8111-111111111111", "One", "Subscription A")
	second := managementProfile(t, "22222222-2222-4222-8222-222222222222", "Two", "Manual")
	third := managementProfile(t, "33333333-3333-4333-8333-333333333333", "Three", "Subscription B")
	settings := BalanceInput{true, "balanced", first.ID + "," + second.ID + "," + third.ID, 2, 30, 1500, true}
	doc := Document{Profiles: []Profile{first, second, third}, UserSettings: &UserPreferences{Balance: settings}}
	b, e := settings.snapshot(doc)
	if e != nil || len(b.Members) != 3 {
		t.Fatal(e)
	}
	if code := control.Validate(control.Request{Version: 1, Command: "start", Profile: &first, Balance: b}); code != "" {
		t.Fatal(code)
	}
	store := managementStore(t, doc)
	app := &Application{Store: store, ServiceCall: func(_ context.Context, r control.Request) (control.Response, int64, error) {
		if r.Balance == nil || len(r.Balance.Members) != 3 || r.Profile.Reliability == nil || !r.Profile.Reliability.AutoReconnect || len(r.Fallbacks) != 0 {
			t.Fatal("pool not applied to start")
		}
		return control.Response{Version: 1}, 0, nil
	}}
	_ = app.desktopCall(context.Background(), "start", &first, false)
	settings.ProfileIDs = first.ID + "," + first.ID
	if _, e = settings.snapshot(doc); e == nil {
		t.Fatal("duplicate accepted")
	}
	settings.ProfileIDs = strings.Repeat(first.ID+",", 9)
	if _, e = settings.snapshot(doc); e == nil {
		t.Fatal("unbounded pool")
	}
	doc.Profiles = []Profile{first}
	saved := normalizeStoredUserPreferences(doc.UserSettings, doc)
	if saved.Balance.Enabled {
		t.Fatal("deleted member silently selected another server")
	}
	settings.Manual = false
	doc.Profiles = []Profile{first, second, third}
	pool, err := settings.snapshot(doc)
	if err != nil || !pool.Automatic || len(pool.Members) != 3 || pool.Best != 8 {
		t.Fatalf("automatic library snapshot: %+v %v", pool, err)
	}
	doc.Profiles = append(doc.Profiles, managementProfile(t, "44444444-4444-4444-8444-444444444444", "New subscription", "C"))
	pool, err = settings.snapshot(doc)
	if err != nil || len(pool.Members) != 4 {
		t.Fatal("automatic snapshot did not include new library member", err)
	}
}

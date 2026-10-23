package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func resultToolsStore(t *testing.T) (*Store, Document) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := fixture(t, "Alpha", vless), fixture(t, "Beta", vless), fixture(t, "Gamma", vless)
	a.ID, b.ID, c.ID = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	a.Group, b.Group, c.Group = "G", "G", "G"
	doc.Profiles = []Profile{a, b, c}
	doc.FavoriteIDs = []string{a.ID}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	doc, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return store, doc
}

func resultToolsBatch(store *Store, rows []GroupCheckRow) *completedGroupResults {
	return &completedGroupResults{
		result:   GroupCheckResult{Group: "G", CheckedAt: "2026-10-23T00:00:00Z", Rows: append([]GroupCheckRow(nil), rows...)},
		revision: store.revision, token: "batch-token",
	}
}

func TestGroupResultsSortFilterFastestAndNoWrites(t *testing.T) {
	store, doc := resultToolsStore(t)
	rows := []GroupCheckRow{
		{ID: "11111111-1111-4111-8111-111111111111", Name: "Alpha", Success: true, NetworkTest: true, Milliseconds: 20, Message: "synthetic result"},
		{ID: "22222222-2222-4222-8222-222222222222", Name: "Beta", Success: true, NetworkTest: true, Milliseconds: 0},
		{ID: "33333333-3333-4333-8333-333333333333", Name: "Gamma", Success: true, NetworkTest: true, Milliseconds: 0},
		{ID: "id-d", Name: "Delta", Success: false, NetworkTest: true, Milliseconds: -1},
		{ID: "id-e", Name: "Epsilon", Success: true, NetworkTest: false, Milliseconds: 7},
		{ID: "id-f", Name: "Zeta", Success: false, NetworkTest: false, Milliseconds: 0},
	}
	app := &Application{Store: store, groupResults: resultToolsBatch(store, rows)}
	before, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil {
		t.Fatal(err)
	}
	assertIDs := func(mode, filter string, want []string) {
		t.Helper()
		got, err := app.groupResultsView(mode, filter)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, len(got.Rows))
		for i, row := range got.Rows {
			ids[i] = row.ID
		}
		if !reflect.DeepEqual(ids, want) {
			t.Fatalf("%s/%s: got %v, want %v", mode, filter, ids, want)
		}
	}
	assertIDs("stored", "all", []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "id-d", "id-e", "id-f"})
	assertIDs("duration", "all", []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111", "id-d", "id-e", "id-f"})
	assertIDs("duration", "reachable", []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111"})
	assertIDs("stored", "failed", []string{"id-d", "id-f"})
	assertIDs("stored", "config-only", []string{"id-e", "id-f"})
	view, err := app.groupResultsView("stored", "all")
	if err != nil || !view.HasResults || view.Stale || !view.CanSelectFastest {
		t.Fatalf("unexpected view %+v: %v", view, err)
	}
	if view.Rows[0].TimingLabel != "20 ms check duration" || view.Rows[4].TimingLabel != "Configuration only · no network check" {
		t.Fatalf("bad timing labels: %+v", view.Rows)
	}
	view.Rows[0].Name = "mutated return"
	if app.groupResults.result.Rows[0].Name != "Alpha" {
		t.Fatal("view aliases the cached row slice")
	}
	selected, err := app.groupResultsFastest("batch-token")
	if err != nil || selected != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("fastest = %q, %v", selected, err)
	}
	if _, err := app.groupResultsView("unexpected", "all"); err == nil {
		t.Fatal("accepted invalid sort")
	}
	if _, err := app.groupResultsView("stored", "unexpected"); err == nil {
		t.Fatal("accepted invalid filter")
	}
	app.groupResults = resultToolsBatch(store, []GroupCheckRow{{ID: "id-d", Success: false, NetworkTest: true}, {ID: "id-e", Success: true, NetworkTest: false}})
	noCandidates, err := app.groupResultsView("stored", "all")
	if err != nil || !noCandidates.HasResults || noCandidates.CanSelectFastest {
		t.Fatalf("ineligible-only batch enabled fastest: %+v, %v", noCandidates, err)
	}
	after, err := os.ReadFile(filepath.Join(store.Root, "profiles.bin"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("result tools wrote profile storage", err)
	}
	if !reflect.DeepEqual(doc.FavoriteIDs, []string{"11111111-1111-4111-8111-111111111111"}) {
		t.Fatal("fixture favorite changed")
	}
}

func TestGroupResultsStaleSupersededRetainedAndMissingID(t *testing.T) {
	store, doc := resultToolsStore(t)
	app := &Application{Store: store, groupResults: resultToolsBatch(store, []GroupCheckRow{{ID: "11111111-1111-4111-8111-111111111111", Name: "Alpha", Success: true, NetworkTest: true, Milliseconds: 2}})}
	app.groupResults.token = "old-token"
	// Replacing a completed batch under the same revision still supersedes its token.
	app.groupResults = resultToolsBatch(store, []GroupCheckRow{{ID: "11111111-1111-4111-8111-111111111111", Success: true, NetworkTest: true}})
	if _, err := app.groupResultsFastest("old-token"); err == nil {
		t.Fatal("accepted a superseded token")
	}
	app.groupResults.token = "batch-token"
	app.desktopState.Response.State.Active = true
	view, err := app.groupResultsView("stored", "all")
	if err != nil || view.CanSelectFastest {
		t.Fatalf("active state enabled fastest: %+v, %v", view, err)
	}
	if _, err := app.groupResultsFastest("batch-token"); err == nil {
		t.Fatal("selected while retained active state")
	}
	app.desktopState.Response.State = control.State{}
	missing := resultToolsBatch(store, []GroupCheckRow{{ID: "deleted-id", Success: true, NetworkTest: true}})
	app.groupResults = missing
	if _, err := app.groupResultsFastest(missing.token); err == nil {
		t.Fatal("selected missing profile id")
	}
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	view, err = app.groupResultsView("stored", "all")
	if err != nil || !view.Stale || view.CanSelectFastest {
		t.Fatalf("store change not marked stale: %+v, %v", view, err)
	}
	if _, err := app.groupResultsFastest(missing.token); err == nil {
		t.Fatal("selected stale results")
	}
}

func TestGroupCheckCacheLifecycleAndViewDoesNotCallService(t *testing.T) {
	store, _ := resultToolsStore(t)
	checks, unexpected := 0, 0
	app := &Application{Store: store, ServiceCall: func(_ context.Context, request control.Request) (control.Response, int64, error) {
		switch request.Command {
		case "status":
			return control.Response{Version: control.Version, Instance: "result-tools-fixture"}, 1, nil
		case "check-profile":
			checks++
			payload, _ := json.Marshal(control.ProfileCheck{Success: true, NetworkTest: true, Milliseconds: 4, Message: "synthetic secret message"})
			value := string(payload)
			return control.Response{Version: control.Version, Instance: "result-tools-fixture", Result: &value}, 1, nil
		default:
			unexpected++
			return control.Response{}, 0, errors.New("unexpected command")
		}
	}}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.check", Group: "G"}); err != nil {
		t.Fatal(err)
	}
	if checks != 3 || app.groupResults == nil {
		t.Fatalf("check did not publish full batch: checks=%d cache=%v", checks, app.groupResults)
	}
	beforeCalls := checks + unexpected
	viewAny, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.results.view", Sort: "duration", Filter: "all"})
	if err != nil {
		t.Fatal(err)
	}
	view := viewAny.(GroupResultsView)
	if !view.HasResults || len(view.Rows) != 3 || !view.CanSelectFastest {
		t.Fatalf("unexpected wire view: %+v", view)
	}
	if selected, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.results.fastest", Token: view.Token}); err != nil || selected != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("fastest = %#v, %v", selected, err)
	}
	if checks+unexpected != beforeCalls {
		t.Fatal("view/selection made a service call")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.results.clear"}); err != nil {
		t.Fatal(err)
	}
	cleared, err := app.groupResultsView("stored", "all")
	if err != nil || cleared.HasResults || cleared.CanSelectFastest || len(cleared.Rows) != 0 {
		t.Fatalf("clear left results: %+v, %v", cleared, err)
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.check", Group: "G"}); err != nil {
		t.Fatal(err)
	}
	app.ServiceCall = func(_ context.Context, request control.Request) (control.Response, int64, error) {
		if request.Command == "status" {
			return control.Response{Version: control.Version, Instance: "result-tools-fixture"}, 1, nil
		}
		return control.Response{}, 0, errors.New("synthetic interruption")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.check", Group: "G"}); err == nil {
		t.Fatal("expected interrupted batch")
	}
	if app.groupResults != nil {
		t.Fatal("failed batch retained previous completed results")
	}
	ctx, cancel := context.WithCancel(context.Background())
	app.ServiceCall = func(_ context.Context, request control.Request) (control.Response, int64, error) {
		if request.Command == "status" {
			return control.Response{Version: control.Version, Instance: "result-tools-fixture"}, 1, nil
		}
		cancel() // Cancellation immediately after the final successful reply is still incomplete.
		payload, _ := json.Marshal(control.ProfileCheck{Success: true, NetworkTest: true, Milliseconds: 1})
		value := string(payload)
		return control.Response{Version: control.Version, Instance: "result-tools-fixture", Result: &value}, 1, nil
	}
	if _, err := app.Handle(ctx, Request{Version: 1, Command: "group.check", Group: "G"}); err == nil || app.groupResults != nil {
		t.Fatal("cancellation after final row published a completed result")
	}
}

func TestGroupResultsRunHostWireDTOIsMetadataOnlyAndEmptyOnRestart(t *testing.T) {
	const secret = "RESULT-TOOLS-PRIVATE-SENTINEL"
	store, doc := resultToolsStore(t)
	privateProfile := fixture(t, "Alpha", "socks5://"+secret+"@example.invalid:1080")
	privateProfile.ID, privateProfile.Group = doc.Profiles[0].ID, "G"
	doc.Profiles[0] = privateProfile
	sourceSecret := privateProfile.Source
	if err := store.Save(doc); err != nil {
		t.Fatal(err)
	}
	app := &Application{Store: store, ServiceCall: func(_ context.Context, request control.Request) (control.Response, int64, error) {
		if request.Command == "status" {
			return control.Response{Version: control.Version, Instance: "wire-fixture"}, 1, nil
		}
		payload, _ := json.Marshal(control.ProfileCheck{Success: true, NetworkTest: true, Milliseconds: 3})
		value := string(payload)
		return control.Response{Version: control.Version, Instance: "wire-fixture", Result: &value}, 1, nil
	}}
	var input bytes.Buffer
	for _, request := range []Request{{Version: 1, Command: "group.check", Group: "G"}, {Version: 1, Command: "group.results.view", Sort: "stored", Filter: "all"}} {
		data, _ := json.Marshal(request)
		var header [4]byte
		binary.LittleEndian.PutUint32(header[:], uint32(len(data)))
		input.Write(header[:])
		input.Write(data)
	}
	var output bytes.Buffer
	if err := RunHost(context.Background(), &input, &output, app); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Version int
		Value   any
		Error   *string
	}
	reader := bytes.NewReader(output.Bytes())
	for i := 0; i < 2; i++ {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, binary.LittleEndian.Uint32(header[:]))
		if _, err := io.ReadFull(reader, payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &reply); err != nil {
			t.Fatal(err)
		}
		if i == 1 && (reply.Error != nil || reply.Value == nil) {
			t.Fatalf("invalid view frame: %+v", reply)
		}
		if i == 1 {
			view := reply.Value.(map[string]any)
			assertJSONKeys(t, view, "Group", "CheckedAt", "Rows", "HasResults", "Stale", "CanSelectFastest", "Token", "Message")
			row := view["Rows"].([]any)[0].(map[string]any)
			assertJSONKeys(t, row, "ID", "Name", "Message", "Success", "NetworkTest", "Milliseconds", "TimingLabel")
		}
	}
	wire := output.String()
	if strings.Contains(wire, secret) || strings.Contains(wire, sourceSecret) || strings.Contains(wire, "Source") || strings.Contains(wire, "Subscription") {
		t.Fatal("wire DTO exposed private profile data")
	}
	newHost := &Application{Store: store, ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
		t.Fatal("empty result view called service")
		return control.Response{}, 0, nil
	}}
	view, err := newHost.groupResultsView("stored", "all")
	if err != nil || view.HasResults || len(view.Rows) != 0 {
		t.Fatalf("new host restored volatile results: %+v %v", view, err)
	}
	report, err := newHost.diagnosticsReport()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(report, secret) || strings.Contains(report, "synthetic result") {
		t.Fatal("diagnostics included profile credentials or volatile check results")
	}
}

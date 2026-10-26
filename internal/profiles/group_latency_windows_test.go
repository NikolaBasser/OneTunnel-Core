package profiles

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestGroupHTTPSLatencyProjectionIsOptionalDetachedAndKeepsDurationSort(t *testing.T) {
	store, doc := resultToolsStore(t)
	latency := int64(5)
	app := &Application{Store: store, groupResults: resultToolsBatch(store, []GroupCheckRow{
		{ID: doc.Profiles[0].ID, Success: true, NetworkTest: true, Milliseconds: 100, HTTPSLatencyMilliseconds: &latency},
		{ID: doc.Profiles[1].ID, Success: true, NetworkTest: true, Milliseconds: 20},
		{ID: doc.Profiles[2].ID, Success: false, NetworkTest: true, Milliseconds: 30, HTTPSLatencyMilliseconds: &latency},
	})}
	view, err := app.groupResultsView("duration", "all")
	if err != nil {
		t.Fatal(err)
	}
	if view.Rows[0].ID != doc.Profiles[1].ID || strings.Contains(view.Rows[0].TimingLabel, "HTTPS latency") {
		t.Fatal("latency changed duration sort or old-service row fabricated latency")
	}
	if view.Rows[1].HTTPSLatencyMilliseconds == nil || !strings.Contains(view.Rows[1].TimingLabel, "5 ms HTTPS latency (not ICMP RTT)") {
		t.Fatal("measured latency not formatted by Go")
	}
	*view.Rows[1].HTTPSLatencyMilliseconds = 999
	if *app.groupResults.result.Rows[0].HTTPSLatencyMilliseconds != 5 {
		t.Fatal("projection latency pointer aliases cached result")
	}
	if view.Rows[2].HTTPSLatencyMilliseconds != nil {
		t.Fatal("failed row exposed latency")
	}
}

func TestGroupCheckAcceptsOldServiceAndDropsInvalidLatency(t *testing.T) {
	store, doc := resultToolsStore(t)
	count := 0
	app := &Application{Store: store, ServiceCall: func(_ context.Context, r control.Request) (control.Response, int64, error) {
		response := control.Response{Version: 1, Instance: "latency-test", Revision: uint64(count + 1)}
		if r.Command == "status" {
			return response, 1, nil
		}
		if r.Command != "check-profile" {
			t.Fatalf("unexpected command %s", r.Command)
		}
		count++
		text := `{"Success":true,"NetworkTest":true,"Milliseconds":20,"Message":"old service"}`
		if count == 2 {
			text = `{"Success":true,"NetworkTest":true,"Milliseconds":30,"HTTPSLatencyMilliseconds":7}`
		}
		if count == 3 {
			text = `{"Success":false,"NetworkTest":true,"Milliseconds":40,"HTTPSLatencyMilliseconds":4}`
		}
		response.Result = &text
		return response, 1, nil
	}}
	result, err := app.checkGroup(context.Background(), doc.Profiles[0].Group)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows[0].HTTPSLatencyMilliseconds != nil || result.Rows[1].HTTPSLatencyMilliseconds == nil || *result.Rows[1].HTTPSLatencyMilliseconds != 7 || result.Rows[2].HTTPSLatencyMilliseconds != nil {
		t.Fatal("optional/failed service latency handling")
	}
	*result.Rows[1].HTTPSLatencyMilliseconds = 999
	if *app.groupResults.result.Rows[1].HTTPSLatencyMilliseconds != 7 {
		t.Fatal("returned batch aliases cache latency")
	}
	encoded, err := json.Marshal(result.Rows[0])
	if err != nil || strings.Contains(string(encoded), "HTTPSLatencyMilliseconds") {
		t.Fatal("missing latency was serialized as fabricated zero")
	}
}

func TestGroupDNSLatencyIsDetachedReachableButNotFastestCandidate(t *testing.T) {
	store, doc := resultToolsStore(t)
	latency := int64(9)
	app := &Application{Store: store, groupResults: resultToolsBatch(store, []GroupCheckRow{
		{ID: doc.Profiles[0].ID, Success: true, NetworkTest: true, Milliseconds: 10, DNSLatencyMilliseconds: &latency},
		{ID: doc.Profiles[1].ID, Success: true, NetworkTest: true, Milliseconds: 20},
		{ID: doc.Profiles[2].ID, Success: false, NetworkTest: true, Milliseconds: 30, DNSLatencyMilliseconds: &latency},
	})}
	view, err := app.groupResultsView("duration", "reachable")
	if err != nil || len(view.Rows) != 2 || view.Rows[0].ID != doc.Profiles[0].ID {
		t.Fatalf("DNS reachability or duration order lost: %+v, %v", view, err)
	}
	if view.Rows[0].HTTPSLatencyMilliseconds != nil || view.Rows[0].DNSLatencyMilliseconds == nil || !strings.Contains(view.Rows[0].TimingLabel, "9 ms DNS exchange latency (may include initial handshake; not public internet access)") {
		t.Fatalf("DNS probe misrepresented: %+v", view.Rows[0])
	}
	*view.Rows[0].DNSLatencyMilliseconds = 999
	if *app.groupResults.result.Rows[0].DNSLatencyMilliseconds != 9 {
		t.Fatal("DNS pointer aliases cache")
	}
	selected, err := app.groupResultsFastest("batch-token")
	if err != nil || selected != doc.Profiles[1].ID {
		t.Fatalf("DNS-only candidate selected: %q, %v", selected, err)
	}
	all, err := app.groupResultsView("stored", "all")
	if err != nil || all.Rows[2].DNSLatencyMilliseconds != nil {
		t.Fatal("failed DNS row exposed latency", err)
	}
	app.groupResults = resultToolsBatch(store, []GroupCheckRow{{ID: doc.Profiles[0].ID, Success: true, NetworkTest: true, Milliseconds: 1, DNSLatencyMilliseconds: &latency}})
	onlyDNS, err := app.groupResultsView("stored", "all")
	if err != nil || onlyDNS.CanSelectFastest {
		t.Fatal("DNS-only batch enabled fastest selection", err)
	}
	if _, err := app.groupResultsFastest("batch-token"); err == nil {
		t.Fatal("DNS-only batch selected a general network candidate")
	}
}

func TestGroupCheckDNSLatencyOptionalAndInvalidValuesDiscarded(t *testing.T) {
	store, doc := resultToolsStore(t)
	count := 0
	responses := []string{
		`{"Success":true,"NetworkTest":true,"Milliseconds":20,"DNSLatencyMilliseconds":7}`,
		`{"Success":true,"NetworkTest":false,"Milliseconds":30,"DNSLatencyMilliseconds":8}`,
		`{"Success":true,"NetworkTest":true,"Milliseconds":40,"DNSLatencyMilliseconds":-1}`,
	}
	app := &Application{Store: store, ServiceCall: func(_ context.Context, request control.Request) (control.Response, int64, error) {
		response := control.Response{Version: 1, Instance: "dns-latency-fixture", Revision: uint64(count + 1)}
		if request.Command == "status" {
			return response, 1, nil
		}
		if request.Command != "check-profile" {
			t.Fatalf("unexpected command %s", request.Command)
		}
		response.Result = &responses[count]
		count++
		return response, 1, nil
	}}
	result, err := app.checkGroup(context.Background(), doc.Profiles[0].Group)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rows[0].DNSLatencyMilliseconds == nil || *result.Rows[0].DNSLatencyMilliseconds != 7 || result.Rows[1].DNSLatencyMilliseconds != nil || result.Rows[2].DNSLatencyMilliseconds != nil {
		t.Fatalf("DNS latency handling: %+v", result)
	}
	*result.Rows[0].DNSLatencyMilliseconds = 999
	if *app.groupResults.result.Rows[0].DNSLatencyMilliseconds != 7 {
		t.Fatal("returned DNS latency aliases cache")
	}
	encoded, err := json.Marshal(result.Rows[1])
	if err != nil || strings.Contains(string(encoded), "DNSLatencyMilliseconds") {
		t.Fatal("absent DNS latency serialized as fabricated value", err)
	}
}

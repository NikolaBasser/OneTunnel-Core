package profiles

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestGroupQualityBoundsExpiryFingerprintAndDetachedSummary(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	app := &Application{}
	row := GroupCheckRow{ID: "a", qualityKey: [32]byte{1}, Success: true, NetworkTest: true}
	for _, latency := range []int64{900, 800, 70, 10, 60, 20, 50, 30, 40, 80} {
		row.HTTPSLatencyMilliseconds = &latency
		app.recordGroupQuality(row, now)
	}
	view := app.groupQualitySummary(row, now)
	if view == nil || view.Samples != 8 || view.Successful != 8 || *view.MedianHTTPSMilliseconds != 45 || *view.MinimumHTTPSMilliseconds != 10 || *view.MaximumHTTPSMilliseconds != 80 {
		t.Fatalf("wrong bounded metrics: %+v", view)
	}
	*view.MedianHTTPSMilliseconds = 999
	if *app.groupQualitySummary(row, now).MedianHTTPSMilliseconds != 45 {
		t.Fatal("returned metric aliases history")
	}
	row.Success = false
	row.HTTPSLatencyMilliseconds = nil
	app.recordGroupQuality(row, now)
	view = app.groupQualitySummary(row, now)
	if view.Samples != 8 || view.Successful != 7 || view.TimingSamples != 7 {
		t.Fatal("failed check omitted from denominator or fabricated timing")
	}
	if app.groupQualitySummary(row, now.Add(groupQualityWindow)) != nil || app.groupQualitySummary(row, now.Add(-time.Second)) != nil {
		t.Fatal("expired or future measurements retained")
	}
	row.qualityKey = [32]byte{2}
	if app.groupQualitySummary(row, now) != nil {
		t.Fatal("changed profile inherited old quality")
	}
	app.recordGroupQuality(row, now)
	if app.groupQualitySummary(row, now).Samples != 1 {
		t.Fatal("changed fingerprint did not reset history")
	}
	for i := 0; i < 300; i++ {
		row.ID = fmt.Sprint(i)
		app.recordGroupQuality(row, now)
	}
	if len(app.groupQuality) != groupQualityProfiles {
		t.Fatal("profile history is unbounded")
	}
}

func TestGroupQualityExcludesUnmeasuredAndNativeChecks(t *testing.T) {
	app := &Application{}
	zero, negative := int64(0), int64(-1)
	for _, row := range []GroupCheckRow{
		{ID: "config", qualityKey: [32]byte{1}, Success: true, HTTPSLatencyMilliseconds: &zero},
		{ID: "missing", qualityKey: [32]byte{1}, Success: true, NetworkTest: true},
		{ID: "negative", qualityKey: [32]byte{1}, Success: true, NetworkTest: true, HTTPSLatencyMilliseconds: &negative},
		{ID: "dns", qualityKey: [32]byte{1}, Success: true, NetworkTest: true, DNSLatencyMilliseconds: &zero},
		{ID: "native", NetworkTest: true, Success: false},
	} {
		app.recordGroupQuality(row, time.Now())
	}
	if len(app.groupQuality) != 0 || groupQualityKey(Profile{Protocol: 0}) != ([32]byte{}) || groupQualityKey(Profile{Protocol: 1}) != ([32]byte{}) {
		t.Fatal("unmeasured or native checks entered HTTPS history")
	}
}

func TestGroupQualityCompletedBatchesAccumulateAndClear(t *testing.T) {
	store, doc := resultToolsStore(t)
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	app := &Application{Store: store, Now: func() time.Time { return now }}
	app.ServiceCall = func(_ context.Context, request control.Request) (control.Response, int64, error) {
		response := control.Response{Version: 1, Instance: "quality-test", Revision: 1}
		if request.Command == "check-profile" {
			result := `{"Success":true,"NetworkTest":true,"Milliseconds":100,"HTTPSLatencyMilliseconds":12}`
			response.Result = &result
		}
		return response, 1, nil
	}
	for range 3 {
		if _, err := app.checkGroup(context.Background(), "G"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	view, err := app.groupResultsView("stored", "all")
	if err != nil || len(view.Rows) != 3 || view.Rows[0].Quality == nil || view.Rows[0].Quality.Samples != 3 || !strings.Contains(view.Rows[0].TimingLabel, "3/3 successful") {
		t.Fatalf("history not visible in existing UI projection: %+v %v", view, err)
	}
	changed := doc.Profiles[0]
	changed.Source += "#changed"
	if groupQualityKey(changed) == groupQualityKey(doc.Profiles[0]) {
		t.Fatal("source changes do not invalidate quality")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := app.checkGroup(ctx, "G"); err == nil {
		t.Fatal("cancelled batch accepted")
	}
	if len(app.groupQuality[doc.Profiles[0].ID].samples) != 3 {
		t.Fatal("cancelled batch changed history")
	}
	previousCall := app.ServiceCall
	changedDuringCheck := false
	app.ServiceCall = func(ctx context.Context, request control.Request) (control.Response, int64, error) {
		if request.Command == "check-profile" && !changedDuringCheck {
			changedDuringCheck = true
			doc.Profiles[0].Name = "Changed during check"
			if err := store.Save(doc); err != nil {
				t.Fatal(err)
			}
		}
		return previousCall(ctx, request)
	}
	if _, err := app.checkGroup(context.Background(), "G"); err != nil {
		t.Fatal(err)
	}
	if len(app.groupQuality[doc.Profiles[0].ID].samples) != 3 {
		t.Fatal("stale batch changed history")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.results.clear"}); err != nil {
		t.Fatal(err)
	}
	if len(app.groupQuality[doc.Profiles[0].ID].samples) != 3 {
		t.Fatal("discarding an incomplete result cleared completed history")
	}
	if _, err := app.Handle(context.Background(), Request{Version: 1, Command: "group.results.clear", ClearQuality: true}); err != nil {
		t.Fatal(err)
	}
	if len(app.groupQuality) != 0 {
		t.Fatal("explicit clear retained history")
	}
	encoded, _ := json.Marshal(GroupCheckRow{qualityKey: [32]byte{1}, qualityAt: now})
	if strings.Contains(string(encoded), "qualityKey") || strings.Contains(string(encoded), "qualityAt") {
		t.Fatal("internal fingerprint leaked into response")
	}
}

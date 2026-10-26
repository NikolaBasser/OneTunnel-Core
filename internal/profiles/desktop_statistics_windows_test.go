//go:build windows

package profiles

import (
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestDesktopStatisticsProjectionKeepsUnknownsExplicit(t *testing.T) {
	state := control.State{Active: true, Status: "connected", Statistics: &control.ConnectionStatistics{
		SchemaVersion: 1, SessionID: "opaque", ElapsedMilliseconds: 3_723_000,
		UploadedBytes: ptrU64(2048), Scope: "proxy-payload-and-packets",
	}}
	app := &Application{}
	got := app.projectDesktop(DesktopReply{Available: true, Response: control.Response{State: state}}, Environment{})
	if !got.Display.ShowStatistics || got.Display.Uploaded != "2 KiB" || got.Display.Downloaded != "—" || got.Display.UploadRate != "—" || got.Display.Elapsed != "01:02:03" || got.Display.StatisticsScopeHint == "" {
		t.Fatalf("unexpected projection: %+v", got.Display)
	}
	state.Statistics.SchemaVersion = 99
	got = app.projectDesktop(DesktopReply{Available: true, Response: control.Response{State: state}}, Environment{})
	if got.Display.ShowStatistics {
		t.Fatalf("unsupported schema was projected: %+v", got.Display)
	}
}

func TestDesktopFailureDiagnosticUsesOnlyAllowlistedMetadata(t *testing.T) {
	got := formatErrorDiagnostic(&control.ErrorInfo{Stage: "bootstrap", Code: "tls", Retryable: true})
	if got != "Stage: bootstrap · Category: TLS · Retryable" {
		t.Fatalf("unexpected bounded diagnostic %q", got)
	}
	if got = formatErrorDiagnostic(&control.ErrorInfo{Stage: "secret/path", Code: "private-error"}); got != "" {
		t.Fatalf("unknown metadata was rendered: %q", got)
	}
}

func TestStatisticsFormattingUsesEnglishUnitsAndDaySuffix(t *testing.T) {
	for value, want := range map[uint64]string{1: "1 B", 1024: "1 KiB", 1024 * 1024: "1 MiB"} {
		if got := formatByteCount(value); got != want {
			t.Errorf("formatByteCount(%d) = %q, want %q", value, got, want)
		}
	}
	if got := optionalRate(ptrU64(1024)); got != "1 KiB/s" {
		t.Fatalf("unexpected rate format %q", got)
	}
	if got := formatElapsed(86_401_000); got != "1d 00:00:01" {
		t.Fatalf("unexpected elapsed format %q", got)
	}
}

func ptrU64(v uint64) *uint64 { return &v }

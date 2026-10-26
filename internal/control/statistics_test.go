package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatisticsRatesSaturateAndResetBaseline(t *testing.T) {
	start := time.Unix(0, 0)
	s, id, err := NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil || id == "" {
		t.Fatal("session", err)
	}
	if got := s.Snapshot(start, id); got.UploadBytesPerSecond != nil || got.UploadedBytes == nil || *got.UploadedBytes != 0 {
		t.Fatalf("initial: %+v", got)
	}
	s.AddUploaded(500)
	s.AddDownloaded(900)
	got := s.Snapshot(start.Add(2*time.Second), id)
	if got.UploadBytesPerSecond == nil || *got.UploadBytesPerSecond != 250 || *got.DownloadBytesPerSecond != 450 {
		t.Fatalf("rates: %+v", got)
	}
	s.uploaded.Store(math.MaxUint64 - 3)
	s.AddUploaded(10)
	if s.uploaded.Load() != math.MaxUint64 {
		t.Fatal("counter did not saturate")
	}
	got = s.Snapshot(start.Add(time.Second), id)
	if got.UploadBytesPerSecond != nil {
		t.Fatal("counter/time regression produced a rate")
	}
}

func TestStatisticsNativeCounterRegressionDoesNotUnderflow(t *testing.T) {
	s, id, err := NewStatisticsAccumulator(time.Now(), "native-transport")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot(time.Now(), id); got.UploadedBytes != nil || got.DownloadedBytes != nil {
		t.Fatal("unavailable native counters were fabricated")
	}
	s.UpdateAbsolute(100, 200)
	s.UpdateAbsolute(150, 250)
	s.UpdateAbsolute(2, 3)
	s.UpdateAbsolute(6, 8)
	got := s.Snapshot(time.Now(), id)
	if *got.UploadedBytes != 154 || *got.DownloadedBytes != 255 {
		t.Fatalf("unexpected totals: %+v", got)
	}
}

func TestStatisticsRateSaturates(t *testing.T) {
	start := time.Unix(400, 0)
	s, id, err := NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		t.Fatal(err)
	}
	s.Snapshot(start, id)
	s.AddUploaded(math.MaxUint64)
	got := s.Snapshot(start.Add(time.Nanosecond), id)
	if got.UploadBytesPerSecond == nil || *got.UploadBytesPerSecond != math.MaxUint64 {
		t.Fatalf("rate did not saturate: %+v", got)
	}
}

func TestStatisticsWireShapeAndOpaqueID(t *testing.T) {
	start := time.Unix(500, 0)
	s, id, err := NewStatisticsAccumulator(start, "proxy-payload")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(s.Snapshot(start, id))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"SchemaVersion":1`, `"SessionID":"` + id + `"`, `"UploadedBytes":0`, `"DownloadedBytes":0`, `"Scope":"proxy-payload"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	var old State
	if err := json.Unmarshal([]byte(`{"Active":false,"NeedsRecovery":false,"TrafficLocked":false,"WholeDevice":false,"FullDeviceMode":false,"ClockSynchronized":false,"LocalPort":0,"Status":"idle","ProfileId":null}`), &old); err != nil || old.Statistics != nil {
		t.Fatalf("older service state did not remain unavailable: %+v (%v)", old, err)
	}
}

func TestClassifyErrorUsesTypesAndBoundedMetadata(t *testing.T) {
	for _, tc := range []struct {
		err         error
		stage, code string
		retry       bool
	}{
		{contextDeadline{}, "probe", "timeout", true},
		{&net.DNSError{Err: "private.example", Name: "secret"}, "bootstrap", "dns", true},
		{x509.UnknownAuthorityError{}, "engine", "tls", false},
		{errors.New("localized auth text with secret"), "engine", "unknown", false},
	} {
		got := ClassifyError(tc.stage, tc.err)
		if got.Stage != tc.stage || got.Code != tc.code || got.Retryable != tc.retry {
			t.Fatalf("%+v want stage=%s code=%s retry=%v", got, tc.stage, tc.code, tc.retry)
		}
	}
	secret := "synthetic-private-error-detail"
	data, err := json.Marshal(ClassifyError("engine", errors.New(secret)))
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("raw error escaped in metadata: %s (%v)", data, err)
	}
}

type contextDeadline struct{}

func (contextDeadline) Error() string        { return "deadline" }
func (contextDeadline) Is(target error) bool { return target == context.DeadlineExceeded }

func BenchmarkStatisticsCounter(b *testing.B) {
	stats, _, err := NewStatisticsAccumulator(time.Now(), "proxy-payload")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("atomic-baseline", func(b *testing.B) {
		var counter atomic.Uint64
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			counter.Add(1)
		}
	})
	b.Run("statistics-accumulator", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			stats.AddUploaded(1)
		}
	})
}

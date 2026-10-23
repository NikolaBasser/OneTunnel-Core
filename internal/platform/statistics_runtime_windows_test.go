//go:build windows

package platform

import (
	"errors"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestSuccessfulEngineAttemptClearsStaleStatsWhenUnavailable(t *testing.T) {
	r := &Runtime{}
	r.state.Statistics = &control.ConnectionStatistics{SchemaVersion: 1, SessionID: "old"}
	r.activateStatistics()
	if r.state.Statistics != nil || r.statisticsProvider != nil || r.statisticsAccumulator != nil {
		t.Fatal("new engine attempt retained statistics from an older session")
	}
}

type sequencedCounters struct {
	values []struct {
		up, down uint64
		err      error
	}
	i int
}

func (s *sequencedCounters) Counters() (uint64, uint64, error) {
	value := s.values[s.i]
	if s.i < len(s.values)-1 {
		s.i++
	}
	return value.up, value.down, value.err
}

func TestNativeCounterGapClearsViewAndResetsNextRateBaseline(t *testing.T) {
	start := time.Unix(600, 0)
	stats, id, err := control.NewStatisticsAccumulator(start, "native-transport")
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{statisticsNative: &sequencedCounters{values: []struct {
		up, down uint64
		err      error
	}{{100, 200, nil}, {150, 250, nil}, {0, 0, errors.New("private details")}, {180, 280, nil}, {200, 300, nil}}}, statisticsAccumulator: stats, statisticsSessionID: id}
	r.sampleStatistics(start)
	r.sampleStatistics(start.Add(time.Second))
	if r.state.Statistics == nil || r.state.Statistics.UploadBytesPerSecond == nil {
		t.Fatal("successful samples did not produce a rate")
	}
	r.sampleStatistics(start.Add(2 * time.Second))
	if r.state.Statistics != nil {
		t.Fatal("failed counter read left stale statistics visible")
	}
	r.sampleStatistics(start.Add(3 * time.Second))
	if r.state.Statistics == nil || r.state.Statistics.UploadBytesPerSecond != nil {
		t.Fatal("first recovered sample produced a rate")
	}
	r.sampleStatistics(start.Add(4 * time.Second))
	if r.state.Statistics.UploadBytesPerSecond == nil || *r.state.Statistics.UploadBytesPerSecond != 20 {
		t.Fatalf("recovered rate: %+v", r.state.Statistics)
	}
}

type testStatisticsEngine struct{}

func (testStatisticsEngine) Close() error { return nil }
func (testStatisticsEngine) Statistics(now time.Time) *control.ConnectionStatistics {
	zero := uint64(0)
	return &control.ConnectionStatistics{SchemaVersion: 1, SessionID: "fresh", UploadedBytes: &zero, DownloadedBytes: &zero}
}

func TestEmbeddedStatisticsProviderIsSelectedForNewAttempt(t *testing.T) {
	r := &Runtime{embeddedProxy: testStatisticsEngine{}}
	r.state.Statistics = &control.ConnectionStatistics{SchemaVersion: 1, SessionID: "old"}
	r.activateStatistics()
	if r.statisticsProvider == nil || r.statisticsAccumulator != nil || r.state.Statistics != nil {
		t.Fatal("embedded statistics provider was not activated cleanly")
	}
	view := r.statisticsProvider.Statistics(time.Now())
	if view.SessionID != "fresh" || view.UploadedBytes == nil {
		t.Fatalf("provider view: %+v", view)
	}
}

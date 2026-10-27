package platform

import (
	"context"
	"testing"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func TestQualitySelectionEvidenceAndHold(t *testing.T) {
	now := time.Unix(2000, 0)
	profiles := []control.Profile{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	q := &qualitySelection{held: now, samples: map[string][]qualitySample{}}
	for i := 0; i < 3; i++ {
		q.record("a", qualitySample{now, 400 * time.Millisecond, true})
		q.record("b", qualitySample{now, 150 * time.Millisecond, true})
		q.record("c", qualitySample{now, 250 * time.Millisecond, true})
	}
	if q.choose(profiles, 1, now) != 0 {
		t.Fatal("ignored minimum hold")
	}
	now = now.Add(2 * time.Minute)
	if q.choose(profiles, 1, now) != 0 {
		t.Fatal("single winning round switched")
	}
	if q.choose(profiles, 2, now) != 0 {
		t.Fatal("inferior challenger switched")
	}
	if q.choose(profiles, 1, now) != 1 {
		t.Fatal("sustained best challenger not selected")
	}
	q.record("b", qualitySample{at: now})
	if q.choose(profiles, 1, now) != 0 {
		t.Fatal("failed sample remained eligible")
	}
	q.reset(now)
	if len(q.samples) != 0 || q.wins != 0 || !q.held.Equal(now) {
		t.Fatal("switch retained stale history")
	}
}

func TestQualitySelectionRejectsStaleFutureAndMarginal(t *testing.T) {
	now := time.Unix(3000, 0)
	for _, test := range []struct {
		name    string
		at      time.Time
		latency time.Duration
		ok      bool
	}{
		{"stale", now.Add(-11 * time.Minute), 100 * time.Millisecond, true},
		{"future", now.Add(time.Second), 100 * time.Millisecond, true},
		{"failed", now, 100 * time.Millisecond, false},
		{"relative", now, 350 * time.Millisecond, true},
		{"negative", now, -time.Millisecond, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			q := &qualitySelection{held: now.Add(-3 * time.Minute), samples: map[string][]qualitySample{}}
			for i := 0; i < 3; i++ {
				q.record("a", qualitySample{now, 400 * time.Millisecond, true})
				q.record("b", qualitySample{test.at, test.latency, test.ok})
			}
			for i := 0; i < 3; i++ {
				if q.choose([]control.Profile{{ID: "a"}, {ID: "b"}}, 1, now) != 0 {
					t.Fatal("invalid evidence selected")
				}
			}
		})
	}
}

func TestQualitySwitchUsesRetryHealthAndPromotion(t *testing.T) {
	f := newRetryFixture(t)
	f.r.session, f.r.transportFailed = &Session{}, false
	f.r.retry.quality = &qualitySelection{}
	f.effects.quality = func(context.Context, time.Duration) int { return 1 }
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 1 || f.starts[0] != "backup" || f.r.retry.targets[0].Name != "backup" || f.r.retrying || f.r.transportFailed || f.activated != 1 || !f.retained[0] {
		t.Fatal("quality switch bypassed verified retry path")
	}
}

func TestQualitySwitchCancellationKeepsCurrent(t *testing.T) {
	f := newRetryFixture(t)
	f.r.session, f.r.transportFailed = &Session{}, false
	f.r.retry.quality = &qualitySelection{}
	f.effects.quality = func(context.Context, time.Duration) int { f.r.cancelRetry(); return 1 }
	f.r.maintainConnectionWith(f.effects)
	if len(f.starts) != 0 || f.r.session == nil {
		t.Fatal("cancelled quality probe changed connection")
	}
}

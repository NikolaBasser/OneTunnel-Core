package platform

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type qualitySample struct {
	at      time.Time
	latency time.Duration
	ok      bool
}

type qualitySelection struct {
	held    time.Time
	cursor  int
	winner  string
	wins    int
	samples map[string][]qualitySample
}

func qualityEligible(p control.Profile, full bool) bool {
	return p.Reliability != nil && p.Reliability.AutoSelect && p.Reliability.AutoReconnect && p.Reliability.UseFallbacks && !full && p.Protocol >= 2 && protocol.NetworkOptionsEmpty(p.Network)
}

func (q *qualitySelection) reset(now time.Time) {
	q.held, q.winner, q.wins = now, "", 0
	q.samples = map[string][]qualitySample{}
}

func (q *qualitySelection) record(id string, sample qualitySample) {
	values := append(q.samples[id], sample)
	if len(values) > 3 {
		values = values[len(values)-3:]
	}
	q.samples[id] = values
}

func (q *qualitySelection) median(id string, now time.Time) (time.Duration, bool) {
	values := q.samples[id]
	if len(values) != 3 {
		return 0, false
	}
	latencies := make([]time.Duration, 0, 3)
	for _, sample := range values {
		if !sample.ok || sample.latency < 0 || sample.at.After(now) || now.Sub(sample.at) > 10*time.Minute {
			return 0, false
		}
		latencies = append(latencies, sample.latency)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies[1], true
}

// Only a newly measured challenger can win; repeated timer ticks are not evidence.
func (q *qualitySelection) choose(targets []control.Profile, index int, now time.Time) int {
	if index <= 0 || index >= len(targets) || now.Before(q.held.Add(2*time.Minute)) {
		return 0
	}
	current, currentOK := q.median(targets[0].ID, now)
	best := index
	candidate, candidateOK := q.median(targets[index].ID, now)
	for i := 1; i < len(targets); i++ {
		value, ok := q.median(targets[i].ID, now)
		if ok && (!candidateOK || value < candidate) {
			best, candidate, candidateOK = i, value, true
		}
	}
	if !currentOK || !candidateOK || current-candidate < 50*time.Millisecond || candidate > current*3/4 {
		q.winner, q.wins = "", 0
		return 0
	}
	if best != index {
		return 0
	}
	if q.winner != targets[index].ID {
		q.winner, q.wins = targets[index].ID, 0
	}
	q.wins++
	if q.wins < 2 {
		return 0
	}
	return index
}

// Proxy-only probes have separate engines and journals. Never probe through an active TUN.
func (r *Runtime) measureQuality(ctx context.Context, current time.Duration) int {
	q := r.retry.quality
	if q == nil || r.session == nil || r.session.Kind != "proxy" || r.session.FullDevice || r.lock.needed() || len(r.retry.targets) < 2 {
		return 0
	}
	q.record(r.retry.targets[0].ID, qualitySample{time.Now(), current, true})
	q.cursor = q.cursor%(len(r.retry.targets)-1) + 1
	index := q.cursor
	p := r.retry.targets[index]
	if p.Protocol < 2 || !protocol.NetworkOptionsEmpty(p.Network) {
		return 0
	}
	root, err := os.MkdirTemp(r.root, "quality-")
	if err != nil {
		q.record(p.ID, qualitySample{at: time.Now()})
		return 0
	}
	if err = privateDirectory(root); err != nil {
		_ = os.Remove(root)
		return 0
	}
	probe := &Runtime{directory: r.directory, root: root, lock: trafficLock{owner: "OneTunnel.Quality", root: root}, forceSecureBootstrap: r.forceSecureBootstrap}
	result, err := probe.checkProfile(ctx, &p)
	// A failed cleanup must remain recoverable; never discard its journal.
	if err != nil {
		r.retry.quality = nil
		return 0
	}
	_ = os.Remove(root)
	if ctx.Err() != nil {
		return 0
	}
	var check control.ProfileCheck
	if result == nil || json.Unmarshal([]byte(*result), &check) != nil {
		return 0
	}
	sample := qualitySample{at: time.Now(), ok: check.Success && check.NetworkTest && check.HTTPSLatencyMilliseconds != nil}
	if sample.ok {
		sample.latency = time.Duration(*check.HTTPSLatencyMilliseconds) * time.Millisecond
	}
	q.record(p.ID, sample)
	return q.choose(r.retry.targets, index, time.Now())
}

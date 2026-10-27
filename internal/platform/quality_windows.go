package platform

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
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
	return p.Reliability != nil && p.Reliability.AutoSelect && p.Reliability.AutoReconnect && p.Reliability.UseFallbacks
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

// Probes have separate engines, physically bound outer sockets and no OS adapter.
func (r *Runtime) measureQuality(ctx context.Context, current time.Duration) int {
	q := r.retry.quality
	if q == nil || r.session == nil || len(r.retry.targets) < 2 {
		return 0
	}
	q.record(r.retry.targets[0].ID, qualitySample{time.Now(), current, true})
	q.cursor = q.cursor%(len(r.retry.targets)-1) + 1
	index := q.cursor
	p := r.retry.targets[index]
	latency, err := r.probeQuality(ctx, p)
	if errors.Is(err, errQualityCleanup) {
		r.retry.quality = nil
		r.publish("Автовыбор остановлен: ошибка очистки проверочного движка")
		return 0
	}
	if ctx.Err() != nil {
		return 0
	}
	sample := qualitySample{at: time.Now(), ok: err == nil, latency: latency}
	q.record(p.ID, sample)
	return q.choose(r.retry.targets, index, time.Now())
}

func (r *Runtime) captureQualityUplinks() {
	if r.qualityUplink == nil {
		r.qualityUplink = map[bool]string{}
	}
	for _, address := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if name, err := routeInterface(address); err == nil && validateSharedNativeUplink(name) == nil {
			r.qualityUplink[net.ParseIP(address).To4() == nil] = name
		}
	}
}
func (r *Runtime) qualityInterface(address string) (string, error) {
	name, err := routeInterface(address)
	if err == nil && !strings.HasPrefix(strings.ToLower(name), "onetunnel") {
		return name, nil
	}
	name = r.qualityUplink[net.ParseIP(address).To4() == nil]
	if err = validateSharedNativeUplink(name); err != nil {
		return "", err
	}
	return name, nil
}
func (r *Runtime) qualityCurrentHealth(ctx context.Context) error {
	if r.backendPort > 0 {
		return httpsCheck(ctx, r.backendPort)
	}
	if r.session == nil {
		return context.Canceled
	}
	dialer, err := interfaceDialer(r.session.TunnelName)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := secureBootstrapLookup(ctx, host)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}}
	defer transport.CloseIdleConnections()
	return checkHTTPSProbes(ctx, transport, []httpsProbe{{"https://example.com/", 200, "Example Domain"}, {"https://www.gstatic.com/generate_204", 204, ""}, {"https://captive.apple.com/hotspot-detect.html", 200, "<TITLE>Success</TITLE>"}})
}

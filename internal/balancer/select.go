package balancer

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Select measures the whole candidate snapshot. Unmeasured and unstable nodes
// cannot enter the automatic pool. Workers bound simultaneous engine startup.
func Select(ctx context.Context, nodes []Node, window, maxRTT time.Duration) ([]Node, error) {
	if len(nodes) == 0 || len(nodes) > 4096 || window <= 0 {
		return nil, errors.New("invalid automatic pool candidates")
	}
	type measurement struct {
		samples  []time.Duration
		attempts int
	}
	results := make([]measurement, len(nodes))
	deadline, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	jobs := make(chan int)
	var workers sync.WaitGroup
	var round sync.WaitGroup
	var mu sync.Mutex
	for range min(16, len(nodes)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				if deadline.Err() != nil {
					round.Done()
					continue
				}
				attempt, done := context.WithTimeout(deadline, min(3*time.Second, window/4))
				latency, err := nodes[i].Probe(attempt)
				// A window boundary is not evidence of server loss.
				ended := deadline.Err() != nil
				done()
				if ended {
					round.Done()
					continue
				}
				mu.Lock()
				results[i].attempts++
				if err == nil && latency > 0 && latency <= maxRTT {
					results[i].samples = append(results[i].samples, latency)
				}
				mu.Unlock()
				round.Done()
			}
		}()
	}
	// Queue one complete round before scheduling another, so large libraries
	// are not biased towards their first subscription.
	tick := time.NewTicker(window / 5)
	defer tick.Stop()
scan:
	for {
		for i := range nodes {
			round.Add(1)
			select {
			case jobs <- i:
			case <-deadline.Done():
				round.Done()
				break scan
			}
		}
		round.Wait()
		select {
		case <-tick.C:
		case <-deadline.Done():
			break scan
		}
	}
	close(jobs)
	workers.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	type ranked struct {
		index int
		score time.Duration
	}
	eligible := []ranked{}
	for i, r := range results {
		if len(r.samples) < 2 {
			continue
		}
		sort.Slice(r.samples, func(a, b int) bool { return r.samples[a] < r.samples[b] })
		median := r.samples[len(r.samples)/2]
		jitter := r.samples[len(r.samples)-1] - r.samples[0]
		loss := time.Duration(r.attempts-len(r.samples)) * maxRTT / time.Duration(r.attempts)
		eligible = append(eligible, ranked{i, median + jitter + loss*2})
	}
	sort.SliceStable(eligible, func(i, j int) bool { return eligible[i].score < eligible[j].score })
	if len(eligible) == 0 {
		return nil, errors.New("За 20 секунд нет серверов с двумя успешными проверками. Проверьте доступность серверов или выберите их вручную.")
	}
	selected := make([]Node, 0, 8)
	for _, r := range eligible[:min(8, len(eligible))] {
		selected = append(selected, nodes[r.index])
	}
	return selected, nil
}

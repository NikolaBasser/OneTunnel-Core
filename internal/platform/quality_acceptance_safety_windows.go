//go:build windows && onetunnel_safety_test

package platform

import (
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"os"
	"strings"
	"time"
)

// QualityStepForAcceptance accelerates only the scheduling/hold in a bounded
// dedicated-VM harness. Every metric and switch still uses production effects.
func (r *Runtime) QualityStepForAcceptance() (control.State, map[string][]int64, error) {
	host, _ := os.Hostname()
	if !strings.EqualFold(host, "WIN-67BE833BA6F") {
		return control.State{}, nil, errors.New("dedicated test VM required")
	}
	r.operations.Lock()
	defer r.operations.Unlock()
	if r.retry.quality == nil || r.session == nil || (r.retry.full && !r.lock.needed()) {
		return control.State{}, nil, errors.New("quality acceptance connection/protection unavailable")
	}
	r.retry.next = time.Time{}
	r.retry.quality.held = time.Now().Add(-3 * time.Minute)
	r.maintainConnection()
	r.publish("")
	metrics := map[string][]int64{}
	if r.retry.quality != nil {
		for id, samples := range r.retry.quality.samples {
			for _, sample := range samples {
				latency := int64(-1)
				if sample.ok {
					latency = sample.latency.Milliseconds()
				}
				metrics[id] = append(metrics[id], latency)
			}
		}
	}
	return r.snapshot(), metrics, nil
}

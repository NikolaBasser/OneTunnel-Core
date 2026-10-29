package balancer

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestAutomaticSelectionStabilityCoverageAndCancellation(t *testing.T) {
	nodes := []Node{}
	var active, peak atomic.Int32
	for i := range 22 {
		calls := 0
		nodes = append(nodes, Node{ID: fmt.Sprint(i), Probe: func(ctx context.Context) (time.Duration, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			calls++
			if i == 0 && calls%2 == 0 {
				return 0, errors.New("loss")
			}
			if i == 1 {
				return 0, ErrProbeNotCovered
			}
			if i == 2 {
				return 0, errors.New("down")
			}
			return time.Duration(i+1) * time.Millisecond, nil
		}})
	}
	start := time.Now()
	selected, err := Select(context.Background(), nodes, 200*time.Millisecond, time.Second)
	if err != nil || len(selected) != 8 {
		t.Fatalf("selected %d: %v", len(selected), err)
	}
	if time.Since(start) < 190*time.Millisecond {
		t.Fatal("stability window skipped")
	}
	if peak.Load() > 16 {
		t.Fatal("unbounded engine startup")
	}
	for i, node := range selected {
		if node.ID != fmt.Sprint(i+3) {
			t.Fatalf("unstable/unmeasured candidate selected: %v", selected)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Select(ctx, nodes, time.Second, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = Select(context.Background(), []Node{{Probe: func(context.Context) (time.Duration, error) { return 0, errors.New("down") }}}, 40*time.Millisecond, time.Second); err == nil {
		t.Fatal("all-down selected a server")
	}
}

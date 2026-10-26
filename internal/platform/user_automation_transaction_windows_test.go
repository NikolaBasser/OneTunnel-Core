//go:build windows

package platform

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserAutomationTransactionSerializesConcurrentOperations(t *testing.T) {
	const workers = 6
	var active, maximum atomic.Int32
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if err := UserAutomationTransaction(func() error {
				current := active.Add(1)
				for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
				}
				time.Sleep(10 * time.Millisecond)
				active.Add(-1)
				return nil
			}); err != nil {
				t.Errorf("transaction failed: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent transactions = %d, want 1", got)
	}
}

func TestUserAutomationTransactionRejectsNilCallback(t *testing.T) {
	if err := UserAutomationTransaction(nil); err == nil {
		t.Fatal("nil transaction callback accepted")
	}
}

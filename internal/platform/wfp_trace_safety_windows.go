//go:build windows && onetunnel_safety_test

package platform

import (
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var safetyWFPTrace struct {
	sync.RWMutex
	callback func(uint64, string, string, uint32)
}
var safetyWFPCallID atomic.Uint64

// SetSafetyWFPTrace is test-build-only and cannot enable system policy changes.
func SetSafetyWFPTrace(callback func(uint64, string, string, uint32)) error {
	host, _ := os.Hostname()
	if !strings.EqualFold(host, "WIN-67BE833BA6F") {
		return errors.New("dedicated VM required")
	}
	safetyWFPTrace.Lock()
	safetyWFPTrace.callback = callback
	safetyWFPTrace.Unlock()
	return nil
}
func traceWFPCall(name string) func(uint32) {
	safetyWFPTrace.RLock()
	callback := safetyWFPTrace.callback
	safetyWFPTrace.RUnlock()
	if callback == nil {
		return nil
	}
	id := safetyWFPCallID.Add(1)
	callback(id, name, "begin", 0)
	return func(code uint32) { callback(id, name, "end", code) }
}

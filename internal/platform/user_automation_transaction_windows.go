//go:build windows

package platform

// UserAutomationTransaction serializes current-user proxy and startup
// ownership changes across OneTunnel hosts. The callback runs while the
// current user's named mutex is held; it may call platform operations that
// acquire the same mutex because Windows mutexes are recursive per thread.
func UserAutomationTransaction(operation func() error) error {
	if operation == nil {
		return errUserAutomationBusy
	}
	// Startup writes and proxy leases share ownership state, so wait briefly for
	// an in-flight operation instead of failing on ordinary contention.
	unlock, err := lockUserAutomationTimeout(5000)
	if err != nil {
		return err
	}
	defer unlock()
	return operation()
}

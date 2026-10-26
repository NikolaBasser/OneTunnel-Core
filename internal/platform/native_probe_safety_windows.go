//go:build windows && onetunnel_safety_test && embeddedawg

package platform

import "context"

// ProbeNativeDNSForAcceptance never constructs Runtime or changes OS networking.
func ProbeNativeDNSForAcceptance(ctx context.Context, source string, kind int) (bool, *int64, error) {
	return nativeGroupDNSProbe(ctx, source, kind)
}

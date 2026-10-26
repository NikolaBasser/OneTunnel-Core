//go:build windows && !embeddedawg

package platform

import "context"

func nativeGroupDNSProbe(context.Context, string, int) (bool, *int64, error) { return false, nil, nil }

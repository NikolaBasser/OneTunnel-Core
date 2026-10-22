//go:build windows && !embeddedawg

package platform

import "context"

func embeddedAWGEnabled() bool { return false }
func startEmbeddedAWG(context.Context, string, int, bool, string) (nativeEngine, error) {
	panic("embedded AWG not compiled")
}

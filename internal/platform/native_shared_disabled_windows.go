//go:build windows && (!embeddedawg || !embeddedsingbox || !embeddedtun)

package platform

import (
	"context"
	"errors"
)

func sharedNativeAvailable() bool { return false }
func validateEmbeddedSharedNative([]byte) error {
	return errors.New("shared native policy requires embedded AWG, sing-box and TUN")
}
func startEmbeddedSharedNative(context.Context, string, int, []byte) (interface{ Close() error }, error) {
	return nil, errors.New("shared native policy requires embedded AWG, sing-box and TUN")
}

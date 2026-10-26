//go:build windows && embeddedawg && embeddedsingbox && embeddedtun

package platform

import (
	"context"

	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"
)

func sharedNativeAvailable() bool { return true }
func validateEmbeddedSharedNative(data []byte) error {
	return embeddedsingbox.ValidateWithNativeTransport(data, true)
}
func startEmbeddedSharedNative(ctx context.Context, source string, kind int, data []byte) (interface{ Close() error }, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := embeddedawg.Parse(source, kind, false)
	if err != nil {
		return nil, err
	}
	transport, err := startNativeUserspaceTransport(plan)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = transport.Close()
		return nil, err
	}
	// The sing-box constructor consumes ownership even when construction fails.
	return embeddedsingbox.StartWithNativeTransport(data, true, transport)
}

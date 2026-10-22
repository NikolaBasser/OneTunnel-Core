//go:build windows && embeddedxray

package platform

import "onetunnel/core/internal/embeddedxray"

// Full-device requires the separate experimental TUN build option.
func embeddedXrayAllowed(fullDevice bool) bool { return !fullDevice || fullDeviceEmbeddingEnabled() }
func startEmbeddedXray(data []byte) (interface{ Close() error }, error) {
	return embeddedxray.Start(data)
}

//go:build windows && embeddedsingbox

package platform

import "github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"

// TUN is embedded only in the separate experimental full-device build.
func embeddedSingBoxAllowed(fullDevice, accurateTime bool) bool {
	return !fullDevice || fullDeviceEmbeddingEnabled()
}
func startEmbeddedSingBox(data []byte) (interface{ Close() error }, error) {
	return embeddedsingbox.Start(data)
}

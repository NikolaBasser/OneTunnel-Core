//go:build windows && !embeddedsingbox

package platform

func embeddedSingBoxAllowed(fullDevice, accurateTime bool) bool { return false }
func startEmbeddedSingBox(data []byte) (interface{ Close() error }, error) {
	panic("embedded sing-box not compiled")
}

//go:build windows && !embeddedsingbox

package platform

func embeddedSingBoxAllowed(fullDevice, accurateTime bool) bool { return false }
func startEmbeddedSingBox(data []byte, wholeDevice bool) (interface{ Close() error }, error) {
	panic("embedded sing-box not compiled")
}

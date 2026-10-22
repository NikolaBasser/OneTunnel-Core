//go:build windows && !embeddedxray

package platform

func embeddedXrayAllowed(fullDevice bool) bool { return false }
func startEmbeddedXray(data []byte) (interface{ Close() error }, error) {
	panic("embedded Xray not compiled")
}

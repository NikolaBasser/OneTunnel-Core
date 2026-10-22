//go:build windows && (!embeddedtun || !embeddedxray || !embeddedsingbox)

package platform

func fullDeviceEmbeddingEnabled() bool { return false }

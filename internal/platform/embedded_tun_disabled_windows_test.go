//go:build windows && embeddedxray && embeddedsingbox && !embeddedtun

package platform

import "testing"

func testEmbeddedTunSCM(t *testing.T) { t.Skip("TUN embedding not compiled") }

//go:build windows && embeddedxray && embeddedsingbox && !embeddedawg

package platform

import "testing"

func testEmbeddedAWGSCM(t *testing.T) { t.Skip("embedded AWG not compiled") }

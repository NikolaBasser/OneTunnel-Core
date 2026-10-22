//go:build !embeddedtun

package embeddedsingbox

import "github.com/sagernet/sing-box/adapter/inbound"

func registerTun(registry *inbound.Registry) {}
func tunSupported() bool                     { return false }

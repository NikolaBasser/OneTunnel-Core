//go:build embeddedtun

package embeddedsingbox

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/protocol/tun"
)

func registerTun(registry *inbound.Registry) { tun.RegisterInbound(registry) }
func tunSupported() bool                     { return true }

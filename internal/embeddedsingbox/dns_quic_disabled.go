//go:build !with_quic

package embeddedsingbox

import "github.com/sagernet/sing-box/dns"

func registerQUICDNS(registry *dns.TransportRegistry) {}

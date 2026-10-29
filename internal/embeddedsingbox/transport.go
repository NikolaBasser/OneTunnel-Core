package embeddedsingbox

import (
	"context"
	"errors"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// Dial only the primary transport, never a policy direct/alternate outbound.
func (e *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	out, ok := e.instance.Outbound().Outbound("proxy")
	if !ok {
		return nil, errors.New("primary outbound missing")
	}
	return out.DialContext(ctx, network, M.ParseSocksaddr(address))
}
func (e *Engine) ListenPacketTo(ctx context.Context, address string) (net.PacketConn, error) {
	out, ok := e.instance.Outbound().Outbound("proxy")
	if !ok {
		return nil, errors.New("primary outbound missing")
	}
	return out.ListenPacket(ctx, M.ParseSocksaddr(address))
}

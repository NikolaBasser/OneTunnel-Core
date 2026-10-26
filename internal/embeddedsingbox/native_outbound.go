package embeddedsingbox

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const nativeOutboundType = "onetunnel-native"

// NativeTransport is the already-started, policy-bound userspace native peer.
// It receives only literal IP destinations after sing-box policy DNS lookup.
type NativeTransport interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
	Close() error
	Done() <-chan struct{}
}

type nativeOutboundOptions struct{}

type nativeOutbound struct {
	outbound.Adapter
	dialer dialer.ResolveDialer
}

func registerNativeOutbound(registry *outbound.Registry, transport NativeTransport) {
	outbound.Register[nativeOutboundOptions](registry, nativeOutboundType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ nativeOutboundOptions) (adapter.Outbound, error) {
		if tag != "proxy" || transport == nil {
			return nil, errors.New("invalid native outbound")
		}
		base := &nativeLiteralDialer{transport: transport}
		return &nativeOutbound{
			Adapter: outbound.NewAdapter(nativeOutboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
			dialer:  dialer.NewResolveDialer(ctx, base, false, "", adapter.DNSQueryOptions{}, 0),
		}, nil
	})
}

func (o *nativeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, errors.New("native outbound supports TCP and UDP only")
	}
	return o.dialer.DialContext(ctx, network, destination)
}

func (o *nativeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	return o.dialer.ListenPacket(ctx, destination)
}

type nativeLiteralDialer struct{ transport NativeTransport }

func (d *nativeLiteralDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, errors.New("native transport supports TCP and UDP only")
	}
	address, err := literalNativeAddress(destination)
	if err != nil {
		return nil, err
	}
	return d.transport.DialContext(ctx, network, address)
}

func (d *nativeLiteralDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if _, err := literalNativeAddress(destination); err != nil {
		return nil, err
	}
	// The transport address is the local bind address, not the remote target.
	// The resolved destination remains in sing-box metadata and is supplied to
	// PacketConn.WriteTo by the caller.
	return d.transport.ListenPacket(ctx, N.NetworkUDP, "")
}

func literalNativeAddress(destination M.Socksaddr) (string, error) {
	if !destination.Addr.IsValid() || destination.Fqdn != "" {
		return "", errors.New("native transport requires a resolved IP destination")
	}
	return destination.String(), nil
}

type validationNativeTransport struct{}

func (validationNativeTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("validation transport cannot dial")
}

func (validationNativeTransport) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("validation transport cannot dial")
}

func (validationNativeTransport) Close() error          { return nil }
func (validationNativeTransport) Done() <-chan struct{} { return make(chan struct{}) }

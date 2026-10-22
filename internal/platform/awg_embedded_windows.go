//go:build windows && embeddedawg

package platform

import (
	"context"
	"errors"
	"net"
	"onetunnel/core/internal/embeddedawg"
)

func embeddedAWGEnabled() bool { return true }
func startEmbeddedAWG(ctx context.Context, source string, kind int, full bool, name string) (nativeEngine, error) {
	plan, err := embeddedawg.Parse(source, kind, full)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(plan.Endpoint())
	if err != nil {
		return nil, err
	}
	address, err := resolveEndpoint(ctx, host)
	if err != nil {
		return nil, err
	}
	if err = plan.SetEndpoint(net.JoinHostPort(address, port)); err != nil {
		return nil, err
	}
	adapter, err := routeInterface(address)
	if err != nil {
		return nil, err
	}
	if len(adapter) >= 9 && adapter[:9] == "OneTunnel" {
		return nil, errors.New("physical AWG uplink unavailable")
	}
	uplink, err := net.InterfaceByName(adapter)
	if err != nil {
		return nil, err
	}
	return embeddedawg.StartNative(ctx, plan, name, uint32(uplink.Index))
}

//go:build windows && embeddedawg

package platform

import (
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"net"
)

func embeddedAWGEnabled() bool { return true }
func startEmbeddedAWG(ctx context.Context, source string, kind int, full bool, name string) (nativeEngine, error) {
	plan, err := embeddedawg.Parse(source, kind, full)
	if err != nil {
		return nil, err
	}
	if err = resolveNativePlanEndpoints(ctx, plan); err != nil {
		return nil, err
	}
	uplink, err := sharedNativePeerUplink(plan.Endpoints(), routeInterface, net.InterfaceByName)
	if err != nil {
		return nil, err
	}
	return embeddedawg.StartNative(ctx, plan, name, uint32(uplink.Index))
}

func resolveNativePlanEndpoints(ctx context.Context, plan *embeddedawg.Plan) error {
	return plan.ResolveEndpoints(func(endpoint string) (string, error) {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return "", err
		}
		address, err := resolveEndpoint(ctx, host)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(address, port), nil
	})
}

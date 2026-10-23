//go:build windows && embeddedawg && embeddedsingbox && embeddedtun

package platform

import (
	"context"
	"errors"
	"net"

	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func sharedNativeAvailable() bool { return true }
func validateEmbeddedSharedNative(data []byte) error {
	return embeddedsingbox.ValidateWithNativeTransport(data, true)
}
func startEmbeddedSharedNative(ctx context.Context, source string, kind int, data []byte) (interface{ Close() error }, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := embeddedawg.Parse(source, kind, false)
	if err != nil {
		return nil, err
	}
	uplink, err := sharedNativePhysicalInterface(plan.Endpoint(), routeInterface, net.InterfaceByName)
	if err != nil {
		return nil, err
	}
	list, buffer, err := adapters()
	if err != nil {
		return nil, err
	}
	defer keep(buffer)
	index4, index6, err := sharedNativeAdapterIndices(uplink.Name, list)
	if err != nil {
		return nil, err
	}
	transport, err := embeddedawg.StartTransport(plan, conn.NewDefaultBind(), func(bind conn.Bind) error {
		binder, ok := bind.(interface {
			BindSocketToInterface4(uint32, bool) error
			BindSocketToInterface6(uint32, bool) error
		})
		if !ok {
			return errors.New("native physical binding unavailable")
		}
		if err := binder.BindSocketToInterface4(index4, false); err != nil {
			return errors.New("native IPv4 physical binding failed")
		}
		if err := binder.BindSocketToInterface6(index6, false); err != nil {
			return errors.New("native IPv6 physical binding failed")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = transport.Close()
		return nil, err
	}
	// The sing-box constructor consumes ownership even when construction fails.
	return embeddedsingbox.StartWithNativeTransport(data, true, transport)
}

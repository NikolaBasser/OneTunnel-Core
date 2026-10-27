//go:build windows && embeddedawg

package platform

import (
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"net"
)

func startNativeUserspaceTransport(plan *embeddedawg.Plan) (*embeddedawg.Transport, error) {
	return startNativeUserspaceTransportWithRoute(plan, routeInterface)
}
func startNativeUserspaceTransportWithRoute(plan *embeddedawg.Plan, route func(string) (string, error)) (*embeddedawg.Transport, error) {
	uplink, err := sharedNativePhysicalInterface(plan.Endpoint(), route, net.InterfaceByName)
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
	return embeddedawg.StartTransport(plan, conn.NewDefaultBind(), func(bind conn.Bind) error {
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
}

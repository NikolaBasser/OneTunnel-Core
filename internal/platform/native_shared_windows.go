package platform

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"strings"
)

func validateSharedNativeUplink(name string) error {
	if strings.TrimSpace(name) == "" || strings.HasPrefix(strings.ToLower(name), "onetunnel") {
		return errors.New("physical native uplink unavailable")
	}
	return nil
}
func sharedNativeExited(engine interface{ Close() error }) bool {
	component, ok := engine.(interface{ NativeDone() <-chan struct{} })
	if !ok {
		return false
	}
	select {
	case <-component.NativeDone():
		return true
	default:
		return false
	}
}

func sharedNativePhysicalInterface(endpoint string, route func(string) (string, error), lookup func(string) (*net.Interface, error)) (*net.Interface, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil {
		return nil, errors.New("native endpoint was not pinned")
	}
	physical, err := route(host)
	if err != nil {
		return nil, err
	}
	if err = validateSharedNativeUplink(physical); err != nil {
		return nil, err
	}
	uplink, err := lookup(physical)
	if err != nil {
		return nil, err
	}
	if uplink == nil || uplink.Index <= 0 {
		return nil, errors.New("native physical interface identity unavailable")
	}
	return uplink, nil
}

func sharedNativePeerUplink(endpoints []string, route func(string) (string, error), lookup func(string) (*net.Interface, error)) (*net.Interface, error) {
	var uplink *net.Interface
	for _, endpoint := range endpoints {
		candidate, err := sharedNativePhysicalInterface(endpoint, route, lookup)
		if err != nil {
			return nil, err
		}
		if uplink != nil && candidate.Index != uplink.Index {
			return nil, errors.New("native peers require the same physical uplink")
		}
		uplink = candidate
	}
	if uplink == nil {
		return nil, errors.New("native peers are required")
	}
	return uplink, nil
}

func sharedNativeAdapterIndices(name string, list []*windows.IpAdapterAddresses) (uint32, uint32, error) {
	for _, adapter := range list {
		if windows.UTF16PtrToString(adapter.FriendlyName) == name {
			if adapter.IfIndex == 0 || adapter.Ipv6IfIndex == 0 {
				return 0, 0, errors.New("native physical family binding unavailable")
			}
			return adapter.IfIndex, adapter.Ipv6IfIndex, nil
		}
	}
	return 0, 0, errors.New("native physical adapter disappeared")
}

func (r *Runtime) connectionHealth(ctx context.Context) error {
	return r.connectionHealthWithHTTPS(ctx, httpsCheck)
}
func (r *Runtime) connectionHealthWithHTTPS(ctx context.Context, httpsProbe func(context.Context, int) error) error {
	if hasSharedNativeTransport(r.embeddedProxy) {
		health, ok := r.embeddedProxy.(interface{ NativeHealth(context.Context) error })
		if !ok {
			return errors.New("shared native encrypted DNS health is unavailable")
		}
		return health.NativeHealth(ctx)
	}
	port := r.snapshot().LocalPort
	if r.backendPort > 0 {
		port = r.backendPort
	}
	return httpsProbe(ctx, port)
}
func hasSharedNativeTransport(engine interface{ Close() error }) bool {
	native, ok := engine.(interface{ NativeDone() <-chan struct{} })
	return ok && native.NativeDone() != nil
}

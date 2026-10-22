package platform

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"math/bits"
	"net"
	"net/http"
	"syscall"
)

// Embedded transports are a WFP exception. Pin native tunnel probes to their
// adapter so that the service cannot mistake its direct bypass for VPN access.
func interfaceDialer(name string) (*net.Dialer, error) {
	list, buffer, err := adapters()
	if err != nil {
		return nil, err
	}
	defer keep(buffer)
	var v4, v6 uint32
	for _, adapter := range list {
		if windows.UTF16PtrToString(adapter.FriendlyName) == name {
			v4, v6 = adapter.IfIndex, adapter.Ipv6IfIndex
			break
		}
	}
	if v4 == 0 && v6 == 0 {
		return nil, errors.New("probe interface unavailable")
	}
	dialer := &net.Dialer{}
	dialer.Control = func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			switch network {
			case "tcp4":
				if v4 == 0 {
					socketErr = errors.New("probe IPv4 interface unavailable")
					return
				}
				socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(v4)))
			case "tcp6":
				if v6 == 0 {
					socketErr = errors.New("probe IPv6 interface unavailable")
					return
				}
				socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, int(v6))
			default:
				socketErr = errors.New("unsupported probe socket")
			}
		})
		if err != nil {
			return err
		}
		return socketErr
	}
	return dialer, nil
}
func httpsCheckOnInterface(ctx context.Context, name string) error {
	dialer, err := interfaceDialer(name)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	return checkHTTPSProbes(ctx, transport, []httpsProbe{{"https://example.com/", 200, "Example Domain"}, {"https://www.gstatic.com/generate_204", 204, ""}, {"https://captive.apple.com/hotspot-detect.html", 200, "<TITLE>Success</TITLE>"}})
}

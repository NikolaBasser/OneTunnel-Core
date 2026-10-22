package platform

import (
	"errors"
	"net"
)

func freePort() (int, error) {
	for i := 0; i < 40; i++ {
		tcp, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			return 0, e
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		tcp.Close()
		if e == nil {
			udp.Close()
			return port, nil
		}
	}
	return 0, errors.New("port allocation failed")
}

//go:build windows && embeddedxray

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/embeddedxray"
)

func init() {
	liveSocksFixture = func(physical string) (control.Profile, func(), error) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return control.Profile{}, nil, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"interface": physical}}}}}
		data, _ := json.Marshal(config)
		server, err := embeddedxray.Start(data)
		if err != nil {
			return control.Profile{}, nil, err
		}
		return control.Profile{ID: "ab167fda-7c58-4dfc-a2e1-17fb80f8ddf2", Name: "local SOCKS5 fixture", Protocol: 3, Source: fmt.Sprintf("socks5://127.0.0.1:%d", port)}, func() { server.Close() }, nil
	}
}

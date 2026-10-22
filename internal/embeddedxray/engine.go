// Package embeddedxray owns an in-process Xray instance. It never changes OS
// routes, DNS or firewall policy. Configuration comes from our compiler only.
package embeddedxray

import (
	"bytes"
	"errors"
	"sync"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

type Engine struct {
	instance *core.Instance
	once     sync.Once
	err      error
	done     chan struct{}
}

func Start(data []byte) (*Engine, error) {
	config, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid embedded Xray configuration")
	}
	built, err := config.Build()
	if err != nil {
		return nil, errors.New("unsupported embedded Xray configuration")
	}
	instance, err := core.New(built)
	if err != nil {
		if instance != nil {
			_ = instance.Close()
		}
		return nil, errors.New("embedded Xray initialization failed")
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		return nil, errors.New("embedded Xray startup failed")
	}
	return &Engine{instance: instance, done: make(chan struct{})}, nil
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() { e.err = e.instance.Close(); close(e.done) })
	return e.err
}

func (e *Engine) Done() <-chan struct{} { return e.done }

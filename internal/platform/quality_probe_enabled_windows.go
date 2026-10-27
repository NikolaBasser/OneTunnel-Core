//go:build windows && embeddedawg && embeddedsingbox && embeddedtun && embeddedxray

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedsingbox"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func (r *Runtime) probeQuality(ctx context.Context, p control.Profile) (latency time.Duration, err error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, bootstrapKey{}, &bootstrapResolver{cache: map[string]string{}, secure: true, forceSecure: true, secureLookup: r.secureQualityBootstrap})
	local, err := freePort()
	if err != nil {
		return 0, err
	}
	bridge, err := freePort()
	if err != nil || bridge == local {
		return 0, errors.New("quality port allocation failed")
	}
	network := protocol.CloneNetworkOptions(p.Network)
	if p.Protocol < 2 && protocol.NetworkOptionsEmpty(network) {
		network = &protocol.NetworkOptions{DNS: &protocol.DNSOptions{Transport: "https", ServerIP: "1.1.1.1", ServerName: "cloudflare-dns.com", Port: 443, Path: "/dns-query"}}
	}
	plan, err := protocol.CompileWithNetwork(p.Source, p.Protocol, true, local, bridge, "quality-probe", p.Transport, network)
	if err != nil {
		return 0, err
	}
	config, err := decodeConfig(plan.Proxy)
	if err != nil {
		return 0, err
	}
	if err = prepareQualityConfig(config, r.qualityInterface); err != nil {
		return 0, err
	}
	var xray interface{ Close() error }
	if plan.NeedsXray {
		x, err := decodeConfig(plan.Xray)
		if err != nil {
			return 0, err
		}
		if err = prepareXrayWithBinding(ctx, x, func(stream jsonObject, address string) error {
			if ip := net.ParseIP(address); ip != nil && ip.IsLoopback() {
				return nil
			}
			name, err := r.qualityInterface(address)
			if err != nil {
				return err
			}
			sock := jObject(stream["sockopt"])
			sock["interface"] = name
			stream["sockopt"] = sock
			return nil
		}); err != nil {
			return 0, err
		}
		data, err := json.Marshal(x)
		if err != nil {
			return 0, err
		}
		xray, err = startEmbeddedXray(data)
		clear(data)
		if err != nil {
			return 0, err
		}
		defer func() {
			if xray.Close() != nil {
				err = errQualityCleanup
			}
		}()
		if err = waitPort(ctx, nil, bridge); err != nil {
			return 0, err
		}
	}
	// Pin each actual transport endpoint before constructing any engine.
	for _, raw := range jArray(config["outbounds"]) {
		out := jObject(raw)
		host := jString(out["server"])
		if host == "" {
			continue
		}
		address, e := resolveEndpoint(ctx, host)
		if e != nil {
			return 0, e
		}
		out["server"] = address
		if !net.ParseIP(address).IsLoopback() && jString(out["detour"]) == "" {
			name, e := r.qualityInterface(address)
			if e != nil {
				return 0, e
			}
			out["bind_interface"] = name
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return 0, err
	}
	defer clear(data)
	var engine interface{ Close() error }
	if p.Protocol < 2 {
		plan, err := embeddedawg.Parse(plan.NativeSource, p.Protocol, false)
		if err != nil {
			return 0, err
		}
		if len(r.retry.targets) > 0 && r.retry.targets[0].Protocol < 2 {
			active, e := embeddedawg.Parse(r.retry.targets[0].Source, r.retry.targets[0].Protocol, false)
			if e != nil || plan.SamePeer(active) {
				return 0, errors.New("quality probe cannot reuse active native peer identity")
			}
		}
		host, port, e := net.SplitHostPort(plan.Endpoint())
		if e != nil {
			return 0, e
		}
		address, e := resolveEndpoint(ctx, host)
		if e != nil {
			return 0, e
		}
		if e = plan.SetEndpoint(net.JoinHostPort(address, port)); e != nil {
			return 0, e
		}
		plan.UseEphemeralListenPort()
		transport, e := startNativeUserspaceTransportWithRoute(plan, r.qualityInterface)
		if e != nil {
			return 0, e
		}
		// The capability permits the native outbound; config has no TUN ingress.
		engine, err = embeddedsingbox.StartWithNativeTransport(data, true, transport)
	} else {
		engine, err = startEmbeddedSingBox(data, false)
	}
	if err != nil {
		return 0, err
	}
	defer func() {
		if engine.Close() != nil {
			err = errQualityCleanup
		}
	}()
	if err = waitPort(ctx, nil, local); err != nil {
		return 0, err
	}
	started := time.Now()
	err = httpsCheck(ctx, local)
	return time.Since(started), err
}

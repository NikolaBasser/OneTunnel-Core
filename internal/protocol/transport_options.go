package protocol

import (
	"encoding/json"
	"strconv"
	"strings"
)

// TransportOptions is a bounded, profile-local preference, never an imported
// executable, arbitrary outbound chain, or a replacement routing policy.
type TransportOptions struct {
	Fragment         bool
	FragmentLength   string
	FragmentInterval string
	Noise            bool
	NoiseLength      string
	NoiseDelay       string
	Mux              bool
	MuxConcurrency   int
}

func boundedRange(value string, min, max int) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	previous := min
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < previous || v > max {
			return false
		}
		previous = v
	}
	return true
}

func ValidateOptions(source string, kind int, o *TransportOptions) error {
	if o == nil {
		return nil
	}
	if !boundedRange(o.FragmentLength, 1, 1400) || !boundedRange(o.FragmentInterval, 0, 100) ||
		!boundedRange(o.NoiseLength, 1, 1400) || !boundedRange(o.NoiseDelay, 0, 100) || o.MuxConcurrency < 1 || o.MuxConcurrency > 128 {
		return ErrConfiguration
	}
	if !o.Fragment && !o.Noise && !o.Mux {
		return nil
	}
	if kind != 2 && kind != 4 {
		return ErrConfiguration
	}
	out, err := Outbound(source, kind)
	if err != nil {
		return err
	}
	stream := obj(out["streamSettings"])
	network := s(stream["network"])
	if network == "" {
		network = "tcp"
	}
	udp := kind == 4 || has(network, "kcp mkcp hysteria")
	if o.Fragment && (kind != 2 || udp || !has(s(stream["security"]), "tls reality")) {
		return ErrConfiguration
	}
	// Separate XHTTP download legs need their own endpoint-bound dialer. Refuse
	// rather than silently fragment only one leg of an imported split transport.
	if o.Fragment && obj(obj(stream["xhttpSettings"])["extra"])["downloadSettings"] != nil {
		return ErrConfiguration
	}
	if o.Noise && !udp {
		return ErrConfiguration
	}
	if o.Mux && (kind != 2 || !has(network, "tcp raw ws websocket httpupgrade") || s(one(one(obj(out["settings"])["vnext"])["users"])["flow"]) != "") {
		return ErrConfiguration
	}
	return nil
}

func CompileWithOptions(source string, kind int, tun bool, localPort, bridgePort int, xrayPath string, options *TransportOptions) (Plan, error) {
	if err := ValidateOptions(source, kind, options); err != nil {
		return Plan{}, err
	}
	p, err := Compile(source, kind, tun, localPort, bridgePort, xrayPath)
	if err != nil || options == nil || (!options.Fragment && !options.Noise && !options.Mux) {
		return p, err
	}
	x, err := decodeObject(p.Xray)
	if err != nil {
		return Plan{}, ErrConfiguration
	}
	out := one(x["outbounds"])
	if options.Mux {
		out["mux"] = object{"enabled": true, "concurrency": options.MuxConcurrency, "xudpConcurrency": 0, "xudpProxyUDP443": "skip"}
	}
	if options.Fragment || options.Noise {
		stream := obj(out["streamSettings"])
		sock := obj(stream["sockopt"])
		sock["dialerProxy"] = "onetunnel-transport"
		stream["sockopt"] = sock
		out["streamSettings"] = stream
		settings := object{}
		if options.Fragment {
			settings["fragment"] = object{"packets": "tlshello", "length": options.FragmentLength, "interval": options.FragmentInterval}
		}
		if options.Noise {
			settings["noises"] = []any{object{"type": "rand", "packet": options.NoiseLength, "delay": options.NoiseDelay, "applyTo": "ip"}}
		}
		// Keep the authenticated proxy FIRST: no user traffic can default to
		// freedom. This dialer is reachable only by the generated tag above.
		x["outbounds"] = append(arr(x["outbounds"]), object{"tag": "onetunnel-transport", "protocol": "freedom", "settings": settings, "streamSettings": object{"sockopt": object{}}})
	}
	b, err := json.Marshal(x)
	p.Xray = string(b)
	return p, err
}

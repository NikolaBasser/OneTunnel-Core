package protocol

import "encoding/json"

// Reuse one policy router; only its proxy outbound is an injected pool.
func CompileBalanced(tun bool, localPort int, network *NetworkOptions) (Plan, error) {
	p, e := CompileWithNetwork("socks5://127.0.0.1:1080", 3, true, localPort, 18002, "", nil, network)
	if e != nil {
		return Plan{}, e
	}
	c, e := decodeObject(p.Proxy)
	if e != nil {
		return Plan{}, e
	}
	outs := arr(c["outbounds"])
	if len(outs) == 0 {
		return Plan{}, ErrConfiguration
	}
	outs[0] = object{"type": "onetunnel-native", "tag": "proxy"}
	c["outbounds"] = outs
	if !tun {
		in := []any{}
		for _, raw := range arr(c["inbounds"]) {
			if s(obj(raw)["type"]) != "tun" {
				in = append(in, raw)
			}
		}
		c["inbounds"] = in
	}
	data, e := json.Marshal(c)
	if e != nil {
		return Plan{}, e
	}
	return Plan{LocalPort: localPort, Proxy: string(data)}, nil
}

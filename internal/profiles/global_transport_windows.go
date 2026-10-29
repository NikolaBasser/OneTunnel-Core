package profiles

import "github.com/NikolaBasser/OneTunnel-Core/internal/protocol"

// Only the runtime copy is changed. Subscription/imported source data stays intact.
func globalTransportProfile(p Profile, prefs UserPreferences) (Profile, []string, error) {
	if prefs.Transport == (TransportInput{}) {
		return p, nil, nil
	}
	requested, e := prefs.Transport.Parse()
	if e != nil {
		return p, nil, e
	}
	if e = protocol.ValidateTransportPreferences(&requested); e != nil {
		return p, nil, e
	}
	effective := requested
	effective.Fragment, effective.Noise, effective.Mux = false, false, false
	effective.MuxProtocol = ""
	effective.MuxMaxConnections = 0
	effective.MuxMinStreams = 0
	effective.MuxPadding = false
	effective.XUDPConcurrency = 0
	effective.UDP443Policy = ""
	skipped := []string{}
	for _, feature := range []struct {
		enabled bool
		name    string
		apply   func(*protocol.TransportOptions)
	}{
		{requested.Fragment, "фрагментация TLS", func(o *protocol.TransportOptions) { o.Fragment = true }},
		{requested.Noise, "шумы UDP", func(o *protocol.TransportOptions) { o.Noise = true }},
		{requested.Mux, "MUX", func(o *protocol.TransportOptions) {
			o.Mux = true
			if p.Protocol == 5 || p.Protocol == protocol.Trojan {
				o.MuxProtocol = requested.MuxProtocol
				if o.MuxProtocol == "" || o.MuxProtocol == "xray" {
					o.MuxProtocol = "h2mux"
				}
				o.MuxMaxConnections = requested.MuxMaxConnections
				o.MuxMinStreams = requested.MuxMinStreams
				o.MuxPadding = requested.MuxPadding
			} else {
				o.XUDPConcurrency = requested.XUDPConcurrency
				o.UDP443Policy = requested.UDP443Policy
			}
		}},
	} {
		if !feature.enabled {
			continue
		}
		candidate := effective
		feature.apply(&candidate)
		if protocol.ValidateOptions(p.Source, p.Protocol, &candidate) == nil {
			effective = candidate
		} else {
			skipped = append(skipped, feature.name)
		}
	}
	p.Transport = &effective
	return p, skipped, nil
}

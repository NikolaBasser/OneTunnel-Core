package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var iphlp = windows.NewLazySystemDLL("iphlpapi.dll")
var dnsFlush = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
var guidToLuid = iphlp.NewProc("ConvertInterfaceGuidToLuid")

func adapters() ([]*windows.IpAdapterAddresses, []byte, error) {
	size := uint32(16384)
	for i := 0; i < 4; i++ {
		buffer := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, head, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		out := []*windows.IpAdapterAddresses{}
		for a := head; a != nil; a = a.Next {
			out = append(out, a)
		}
		return out, buffer, nil
	}
	return nil, nil, errors.New("adapter enumeration failed")
}
func routeInterface(address string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", errors.New("invalid route address")
	}
	var sa windows.Sockaddr
	if v := ip.To4(); v != nil {
		x := &windows.SockaddrInet4{}
		copy(x.Addr[:], v)
		sa = x
	} else {
		x := &windows.SockaddrInet6{}
		copy(x.Addr[:], ip.To16())
		sa = x
	}
	var index uint32
	if e := windows.GetBestInterfaceEx(sa, &index); e != nil {
		return "", e
	}
	list, buffer, e := adapters()
	if e != nil {
		return "", e
	}
	defer keep(buffer)
	for _, a := range list {
		if (ip.To4() != nil && a.IfIndex == index) || (ip.To4() == nil && a.Ipv6IfIndex == index) {
			return windows.UTF16PtrToString(a.FriendlyName), nil
		}
	}
	return "", errors.New("route interface absent")
}
func resolveEndpoint(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if resolver, ok := ctx.Value(bootstrapKey{}).(*bootstrapResolver); ok {
		address, err := resolver.lookup(ctx, host)
		if err != nil {
			return "", stageError{stage: "bootstrap", err: err}
		}
		return address, nil
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return "", stageError{stage: "bootstrap", err: e}
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].IP.String(), nil
	}
	return "", stageError{stage: "bootstrap", err: errors.New("no endpoint address")}
}

type stageError struct {
	stage string
	err   error
}

func (e stageError) Error() string { return e.err.Error() }
func (e stageError) Unwrap() error { return e.err }
func failureStage(err error, fallback string) string {
	var staged stageError
	if errors.As(err, &staged) {
		return staged.stage
	}
	return fallback
}

type jsonObject = map[string]any

func jObject(v any) jsonObject {
	r, _ := v.(map[string]any)
	if r == nil {
		return jsonObject{}
	}
	return r
}
func jArray(v any) []any   { r, _ := v.([]any); return r }
func jString(v any) string { r, _ := v.(string); return r }
func first(v any) jsonObject {
	a := jArray(v)
	if len(a) == 0 {
		return jsonObject{}
	}
	return jObject(a[0])
}
func decodeConfig(text string) (jsonObject, error) {
	var c jsonObject
	e := json.Unmarshal([]byte(text), &c)
	return c, e
}
func prepareXray(ctx context.Context, c jsonObject) error {
	out := first(c["outbounds"])
	stream := jObject(out["streamSettings"])
	settings := jObject(out["settings"])
	peer := settings
	switch jString(out["protocol"]) {
	case "vless":
		peer = first(settings["vnext"])
	case "shadowsocks":
		peer = first(settings["servers"])
	}
	host := jString(peer["address"])
	if net.ParseIP(host) == nil {
		address, e := resolveEndpoint(ctx, host)
		if e != nil {
			return e
		}
		for _, key := range []string{"tlsSettings", "realitySettings"} {
			if tls, ok := stream[key].(map[string]any); ok && jString(tls["serverName"]) == "" {
				tls["serverName"] = host
			}
		}
		for _, key := range []string{"xhttpSettings", "httpupgradeSettings"} {
			if x, ok := stream[key].(map[string]any); ok && jString(x["host"]) == "" {
				name := host
				if key == "xhttpSettings" {
					if v := jString(jObject(stream["tlsSettings"])["serverName"]); v != "" {
						name = v
					} else if v := jString(jObject(stream["realitySettings"])["serverName"]); v != "" {
						name = v
					}
				}
				x["host"] = name
			}
		}
		if ws, ok := stream["wsSettings"].(map[string]any); ok {
			headers := jObject(ws["headers"])
			if jString(headers["Host"]) == "" {
				headers["Host"] = host
			}
			ws["headers"] = headers
		}
		peer["address"] = address
	}
	bind := func(s jsonObject, address string) error {
		adapter, e := routeInterface(address)
		if e != nil || strings.HasPrefix(adapter, "OneTunnel") {
			return errors.New("physical uplink unavailable")
		}
		sock := jObject(s["sockopt"])
		sock["interface"] = adapter
		s["sockopt"] = sock
		return nil
	}
	if e := bind(stream, jString(peer["address"])); e != nil {
		return e
	}
	// The generated freedom dialer owns the real endpoint socket. Bind it to
	// the same pre-TUN physical interface, never to the tunnel default route.
	for _, value := range jArray(c["outbounds"]) {
		dialer := jObject(value)
		if jString(dialer["tag"]) == "onetunnel-transport" && jString(dialer["protocol"]) == "freedom" {
			transport := jObject(dialer["streamSettings"])
			if e := bind(transport, jString(peer["address"])); e != nil {
				return e
			}
			dialer["streamSettings"] = transport
		}
	}
	download := jObject(jObject(jObject(stream["xhttpSettings"])["extra"])["downloadSettings"])
	if host := jString(download["address"]); host != "" {
		if net.ParseIP(host) == nil {
			address, e := resolveEndpoint(ctx, host)
			if e != nil {
				return e
			}
			download["address"] = address
			if tls, ok := download["tlsSettings"].(map[string]any); ok && jString(tls["serverName"]) == "" {
				tls["serverName"] = host
			}
			if x, ok := download["xhttpSettings"].(map[string]any); ok && jString(x["host"]) == "" {
				name := jString(jObject(download["tlsSettings"])["serverName"])
				if name == "" {
					name = jString(jObject(download["realitySettings"])["serverName"])
				}
				if name == "" {
					name = host
				}
				x["host"] = name
			}
		}
		return bind(download, jString(download["address"]))
	}
	return nil
}
func discoverClock(ctx context.Context) (bool, string, error) {
	transport := &http.Transport{Proxy: nil}
	if resolver, ok := ctx.Value(bootstrapKey{}).(*bootstrapResolver); ok && resolver.forceSecure {
		dialer := &net.Dialer{}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return resolveAndDialClockEndpoint(ctx, network, address, resolveEndpoint, dialer.DialContext)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	defer client.CloseIdleConnections()
	before := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace?onetunnel="+time.Now().Format("150405.000000000"), nil)
	if response, e := client.Do(req); e == nil {
		response.Body.Close()
		if remote, e := http.ParseTime(response.Header.Get("Date")); e == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			offset := remote.Sub(before.Add(time.Since(before) / 2))
			if offset >= -20*time.Second && offset <= 20*time.Second {
				return false, "", nil
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	server, e := resolveEndpoint(ctx, "time.cloudflare.com")
	return true, server, e
}

func resolveAndDialClockEndpoint(ctx context.Context, network, address string, resolve func(context.Context, string) (string, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return dial(ctx, network, net.JoinHostPort(ip, port))
}

func httpsCheck(ctx context.Context, proxyPort int) error {
	transport := &http.Transport{Proxy: nil}
	if proxyPort > 0 {
		u, _ := url.Parse("http://127.0.0.1:" + itoa(proxyPort))
		transport.Proxy = http.ProxyURL(u)
	}
	defer transport.CloseIdleConnections()
	return checkHTTPSProbes(ctx, transport, []httpsProbe{
		{"https://example.com/", 200, "Example Domain"},
		{"https://www.gstatic.com/generate_204", 204, ""},
		{"https://captive.apple.com/hotspot-detect.html", 200, "<TITLE>Success</TITLE>"},
	})
}

type httpsProbe struct {
	URL    string
	Status int
	Marker string
}

// One unreachable test site must not invalidate an otherwise working proxy.
// The total budget stays bounded; redirects, login pages and invalid TLS never
// count as successful access. Production targets contain no subscription data.
func checkHTTPSProbes(ctx context.Context, transport http.RoundTripper, targets []httpsProbe) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return runHTTPSProbes(ctx, transport, targets)
}

func runHTTPSProbes(ctx context.Context, transport http.RoundTripper, targets []httpsProbe) error {
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error = errors.New("no HTTPS probe succeeded")
	for _, target := range targets {
		req, e := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
		if e != nil || req.URL.Scheme != "https" {
			return errors.New("invalid HTTPS probe target")
		}
		response, e := client.Do(req)
		if e == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
			response.Body.Close()
			if readErr == nil && response.StatusCode == target.Status && (target.Marker == "" || strings.Contains(string(data), target.Marker)) {
				return nil
			}
			last = errors.New("unexpected HTTPS response")
		} else {
			last = e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return last
}
func familyCheck(ctx context.Context, v6 bool) string {
	address := "1.1.1.1:443"
	network := "tcp4"
	if v6 {
		address = "[2606:4700:4700::1111]:443"
		network = "tcp6"
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://one.one.one.one/cdn-cgi/trace", nil)
	r, e := client.Do(req)
	if e == nil {
		r.Body.Close()
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			return "HTTPS доступен"
		}
	}
	return "недоступен (блокировка или отсутствие поддержки — утечка не проверена)"
}

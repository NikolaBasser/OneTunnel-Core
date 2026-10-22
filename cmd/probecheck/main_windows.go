// Diagnostic helper, never included in a release. It receives only a loopback
// port and sends no subscription credentials or endpoint names to test sites.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		return
	}
	port, e := strconv.Atoi(os.Args[1])
	if e != nil || port < 1 || port > 65535 {
		return
	}
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	for _, compat := range []bool{false, true} {
		for _, target := range []string{"https://example.com/", "https://www.gstatic.com/generate_204"} {
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			if compat {
				transport.TLSClientConfig = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
			}
			var mu sync.Mutex
			phase := "start"
			set := func(s string) { mu.Lock(); phase = s; mu.Unlock() }
			trace := &httptrace.ClientTrace{ConnectStart: func(string, string) { set("connect") }, ConnectDone: func(string, string, error) { set("connected") }, TLSHandshakeStart: func() { set("tls") }, TLSHandshakeDone: func(tls.ConnectionState, error) { set("tls-done") }, WroteRequest: func(httptrace.WroteRequestInfo) { set("request-sent") }, GotFirstResponseByte: func() { set("response") }}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			ctx = httptrace.WithClientTrace(ctx, trace)
			request, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
			client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, e := client.Do(request)
			status := 0
			if e == nil {
				status = response.StatusCode
				io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
				response.Body.Close()
			}
			mu.Lock()
			final := phase
			mu.Unlock()
			fmt.Printf("GO TLS: compatibility=%v target=%s stage=%s status=%d error=%v\n", compat, target, final, status, e)
			cancel()
			transport.CloseIdleConnections()
		}
	}
}

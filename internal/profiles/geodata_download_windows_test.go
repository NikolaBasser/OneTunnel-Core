package profiles

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type brokenGeoReader struct{}

func (brokenGeoReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestGeoDownloadReadFailureAndRetry(t *testing.T) {
	if _, e := readBounded(brokenGeoReader{}, 10); !errors.Is(e, io.ErrUnexpectedEOF) || errors.Is(e, errBoundedSize) {
		t.Fatal("read failure mislabeled", e)
	}
	if _, e := readBounded(strings.NewReader("12345"), 4); !errors.Is(e, errBoundedSize) {
		t.Fatal("size bound lost", e)
	}
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "short")
			return
		}
		_, _ = io.WriteString(w, "complete")
	}))
	defer server.Close()
	got, e := downloadLoyalURL(context.Background(), "geosite", server.URL)
	if e != nil || string(got) != "complete" || attempts != 2 {
		t.Fatal("truncated body not retried atomically", string(got), attempts, e)
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "short")
	}))
	defer broken.Close()
	got, e = downloadLoyalURL(context.Background(), "geoip", broken.URL)
	if e == nil || got != nil || strings.Contains(e.Error(), "превыш") || !strings.Contains(e.Error(), "geoip.dat") {
		t.Fatal("truncated data accepted or size error returned", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e = downloadLoyalURL(ctx, "geoip", server.URL); e == nil || got != nil {
		t.Fatal("cancellation ignored")
	}
}

func TestGeoDownloadRouteFallbackAndNoDirectRetry(t *testing.T) {
	calls := 0
	app := &Application{ServiceCall: func(ctx context.Context, r control.Request) (control.Response, int64, error) {
		calls++
		if r.Command != "status" {
			t.Fatal("mutating service call")
		}
		return control.Response{State: control.State{Active: true, LocalPort: 11080}}, 0, nil
	}}
	ctx := app.ruleDownloadContext(context.Background())
	route, ok := ctx.Value(ruleDownloadProxyKey{}).(*url.URL)
	if !ok || route.Scheme != "socks5h" || route.Host != "127.0.0.1:11080" || calls != 1 {
		t.Fatal("active proxy not selected", route)
	}
	app.ServiceCall = func(context.Context, control.Request) (control.Response, int64, error) {
		return control.Response{State: control.State{Active: true, Reconnecting: true, LocalPort: 11080}}, 0, nil
	}
	if app.ruleDownloadContext(context.Background()).Value(ruleDownloadProxyKey{}) != nil {
		t.Fatal("stale endpoint reused")
	}
	directCalls, proxyCalls := 0, 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { directCalls++; io.WriteString(w, "direct") }))
	defer origin.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls++
		if strings.Contains(r.URL.Path, "primary") {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, "through-proxy")
	}))
	defer gateway.Close()
	gatewayURL, _ := url.Parse(gateway.URL)
	routed := context.WithValue(context.Background(), ruleDownloadProxyKey{}, gatewayURL)
	got, err := downloadLoyalSources(routed, "geosite", []string{origin.URL + "/primary", origin.URL + "/fallback"})
	if err != nil || string(got) != "through-proxy" || proxyCalls != 2 || directCalls != 0 {
		t.Fatal("fallback escaped proxy", err, proxyCalls, directCalls)
	}
	if _, err = downloadLoyalURL(routed, "geoip", origin.URL+"/primary"); err == nil || directCalls != 0 {
		t.Fatal("failed proxy retried directly", err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, origin.URL, 302) }))
	defer redirect.Close()
	if _, err = downloadLoyalURL(context.Background(), "geosite", redirect.URL); err == nil || directCalls != 0 {
		t.Fatal("untrusted redirect accepted", err)
	}
}

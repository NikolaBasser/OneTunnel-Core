package profiles

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSubscriptionDownloadBoundaries(t *testing.T) {
	var downgradeRequests int
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { downgradeRequests++; _, _ = w.Write([]byte(vless)) }))
	defer insecure.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/downgrade":
			http.Redirect(w, r, insecure.URL, http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/redirect/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/redirect/"))
			http.Redirect(w, r, fmt.Sprintf("/redirect/%d", n+1), http.StatusFound)
		case r.URL.Path == "/large-length":
			w.Header().Set("Content-Length", strconv.Itoa(MaxBytes+1))
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/large-body":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat("a", MaxBytes+1))
		case r.URL.Path == "/truncated":
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, "short")
		case r.URL.Path == "/invalid":
			_, _ = io.WriteString(w, "not a subscription")
		case r.URL.Path == "/bad-metadata":
			w.Header().Set("Subscription-Userinfo", "upload=-10")
			_, _ = io.WriteString(w, vless)
		default:
			_, _ = io.WriteString(w, vless)
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	client := subscriptionClient()
	client.Transport = server.Client().Transport
	defer client.CloseIdleConnections()
	for _, path := range []string{"/downgrade", "/redirect/0", "/large-length", "/large-body", "/truncated", "/invalid"} {
		t.Run(path, func(t *testing.T) {
			if _, err := downloadWithClient(context.Background(), server.URL+path, client); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	if downgradeRequests != 0 {
		t.Fatal("HTTP downgrade was contacted")
	}
	if _, err := downloadWithClient(context.Background(), insecure.URL, client); err == nil {
		t.Fatal("HTTP subscription accepted")
	}
	if _, err := Download(context.Background(), server.URL+"/private-synthetic-token"); err == nil || strings.Contains(err.Error(), "private-synthetic-token") {
		t.Fatal("untrusted TLS accepted or source exposed")
	}
	result, err := downloadWithClient(context.Background(), server.URL+"/bad-metadata", client)
	if err != nil || result.Metadata != nil || len(result.Profiles) != 1 {
		t.Fatal("invalid optional metadata rejected a valid subscription", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := downloadWithClient(ctx, server.URL, client); err == nil {
		t.Fatal("cancelled download succeeded")
	}
}

package profiles

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

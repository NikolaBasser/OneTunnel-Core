//go:build windows

package platform

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type probeBudgetTransport func(*http.Request) (*http.Response, error)

func (f probeBudgetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type probeBudgetBody struct {
	ctx    context.Context
	closed bool
}

func (b *probeBudgetBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b *probeBudgetBody) Close() error             { b.closed = true; return nil }

func TestHTTPSProbeReservesFallbackBudget(t *testing.T) {
	for _, mode := range []string{"round-trip", "body"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			calls := 0
			var blocked *probeBudgetBody
			transport := probeBudgetTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					if mode == "round-trip" {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					blocked = &probeBudgetBody{ctx: r.Context()}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: blocked}, nil
				}
				if ctx.Err() != nil {
					t.Fatal("fallback received an exhausted parent budget")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("healthy marker"))}, nil
			})
			err := runHTTPSProbes(ctx, transport, []httpsProbe{{"https://slow.invalid/", 200, "marker"}, {"https://healthy.invalid/", 200, "healthy marker"}, {"https://unused.invalid/", 200, "unused"}})
			if err != nil || calls != 2 {
				t.Fatalf("healthy fallback not reached: calls=%d err=%v", calls, err)
			}
			if blocked != nil && !blocked.closed {
				t.Fatal("timed-out response body was not closed")
			}
		})
	}
}
func TestHTTPSProbeCancellationAndFirstSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	transport := probeBudgetTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	targets := []httpsProbe{{"https://first.invalid/", 204, ""}, {"https://second.invalid/", 204, ""}}
	if err := runHTTPSProbes(ctx, transport, targets); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled probe made requests: calls=%d err=%v", calls, err)
	}
	if err := runHTTPSProbes(context.Background(), transport, targets); err != nil || calls != 1 {
		t.Fatalf("first success made extra requests: calls=%d err=%v", calls, err)
	}
}

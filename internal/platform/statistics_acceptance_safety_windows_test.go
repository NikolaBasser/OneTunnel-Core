//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"testing"
)

func TestStatisticsAcceptanceRejectsUnsafeBeforeEffects(t *testing.T) {
	for _, kind := range []int{-1, 0, 1, len(protocol.Names), 2} {
		ctx, cancel := context.WithCancel(context.Background())
		if kind == 2 {
			cancel()
		}
		got := ProbeStatisticsForAcceptance(ctx, "must-not-access", control.Profile{Protocol: kind})
		cancel()
		if got.CheckCompleted || got.NetworkTest || got.Success || got.CleanupError {
			t.Fatal("unsafe input reached effects")
		}
	}
}
func TestStatisticsAcceptanceLifecycleAndFailures(t *testing.T) {
	for _, fault := range []string{"", "start-error", "response-error", "zero-port", "missing", "decreasing", "frozen-elapsed", "identity-change", "restart-reuse", "probe-error", "wait-cancel", "stop-error", "stale-stop"} {
		t.Run(fault, func(t *testing.T) {
			starts, statuses, stops := 0, 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			effects := statisticsAcceptanceEffects{}
			effects.call = func(callctx context.Context, req control.Request) (control.BackendResult, error) {
				if req.FullDevice || len(req.Fallbacks) > 0 {
					t.Fatal("unsafe request")
				}
				if req.Profile != nil && (req.Profile.Network != nil || req.Profile.Reliability != nil) {
					t.Fatal("policy retained")
				}
				switch req.Command {
				case "start":
					starts++
					statuses = 0
					if fault == "start-error" {
						return control.BackendResult{}, errors.New("private")
					}
					if fault == "response-error" {
						s := "private"
						return control.BackendResult{Error: &s}, nil
					}
					s := control.State{Active: true, LocalPort: 1234}
					if fault == "zero-port" {
						s.LocalPort = 0
					}
					return control.BackendResult{State: s}, nil
				case "status":
					statuses++
					id := "first"
					if starts == 2 && fault != "restart-reuse" {
						id = "second"
					}
					if fault == "identity-change" && statuses == 2 {
						id = "changed"
					}
					n := uint64(statuses * 10)
					if fault == "decreasing" && statuses == 2 {
						n = 1
					}
					rate := uint64(0)
					stats := &control.ConnectionStatistics{SchemaVersion: 1, SessionID: id, Scope: "proxy-payload", UploadedBytes: &n, DownloadedBytes: &n, ElapsedMilliseconds: uint64(statuses * 100), UploadBytesPerSecond: &rate, DownloadBytesPerSecond: &rate}
					if fault == "frozen-elapsed" {
						stats.ElapsedMilliseconds = 100
					}
					if fault == "missing" {
						stats = nil
					}
					return control.BackendResult{State: control.State{Active: true, LocalPort: 1234, Statistics: stats}}, nil
				case "stop":
					stops++
					if callctx.Err() != nil {
						t.Fatal("cleanup inherited cancellation")
					}
					if fault == "stop-error" {
						return control.BackendResult{}, errors.New("private")
					}
					s := control.State{}
					if fault == "stale-stop" {
						s.Statistics = &control.ConnectionStatistics{SessionID: "stale"}
					}
					return control.BackendResult{State: s}, nil
				}
				t.Fatal("unexpected command")
				return control.BackendResult{}, nil
			}
			effects.probe = func(_ context.Context, port int) error {
				if port <= 0 {
					t.Fatal("direct probe")
				}
				if fault == "probe-error" {
					return errors.New("private")
				}
				return nil
			}
			effects.wait = func(context.Context) error {
				if fault == "wait-cancel" {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			got := runStatisticsAcceptance(ctx, control.Profile{Protocol: 2, Network: &protocol.NetworkOptions{}, Reliability: &control.ReliabilityOptions{}}, effects)
			if !got.CheckCompleted || stops == 0 {
				t.Fatal("cleanup absent")
			}
			if got.Success != (fault == "") {
				t.Fatalf("fault %s: %+v", fault, got)
			}
			if fault == "" && (starts != 2 || stops != 3 || got.UploadedBytes == 0) {
				t.Fatal("lifecycle incomplete")
			}
			if (fault == "stop-error" || fault == "stale-stop") && !got.CleanupError {
				t.Fatal("cleanup error hidden")
			}
		})
	}
}

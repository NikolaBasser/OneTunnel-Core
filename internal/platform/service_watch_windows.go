package platform

import (
	"context"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"time"
)

type ServiceObservation struct {
	Available   bool
	Response    control.Response
	PeerStarted int64
	Message     string
	CheckedAt   uint64
}

func WatchPublicService(ctx context.Context, emit func(ServiceObservation) error) error {
	var last ServiceObservation
	for ctx.Err() == nil {
		connect, cancel := context.WithTimeout(ctx, 2*time.Second)
		pipe, epoch, err := trustedServicePipe(connect)
		cancel()
		if err == nil {
			stop := context.AfterFunc(ctx, func() { pipe.Close() })
			pipe.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err = control.WriteFrame(pipe, control.Request{Version: control.Version, Command: "watch"})
			fallback := false
			for err == nil && ctx.Err() == nil {
				pipe.SetReadDeadline(time.Now().Add(35 * time.Second))
				var reply control.Response
				reply, err = control.ReadFrame[control.Response](pipe)
				if err != nil || reply.Version != control.Version || !servicePipeCurrent(pipe) {
					break
				}
				if reply.Error != nil {
					fallback = *reply.Error == "unknown_command"
					break
				}
				last = ServiceObservation{Available: true, Response: reply, PeerStarted: epoch, CheckedAt: ObservationClock()}
				if err = emit(last); err != nil {
					pipe.Close()
					stop()
					return err
				}
			}
			pipe.Close()
			stop()
			// Older API-v1 services remain usable until an explicit idle update. Only
			// read-only status is polled; no uncertain mutation is retried.
			if fallback {
				until := time.Now().Add(30 * time.Second)
				for ctx.Err() == nil && time.Now().Before(until) {
					read, cancel := context.WithTimeout(ctx, 4*time.Second)
					reply, birth, e := CallService(read, control.Request{Version: control.Version, Command: "status"})
					cancel()
					if e != nil {
						break
					}
					last = ServiceObservation{Available: true, Response: reply, PeerStarted: birth, CheckedAt: ObservationClock()}
					if e = emit(last); e != nil {
						return e
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(2 * time.Second):
					}
				}
				continue
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		last.Available = false
		last.CheckedAt = ObservationClock()
		last.Message = ServiceErrorMessage("service_unavailable")
		if err := emit(last); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return ctx.Err()
}

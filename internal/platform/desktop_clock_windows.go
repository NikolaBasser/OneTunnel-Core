package platform

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"unsafe"
)

var performanceCounter = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")

// A machine-wide monotonic clock orders observations across the two user Go
// hosts without relying on adjustable wall time or access to SYSTEM processes.
func ObservationClock() uint64 {
	var ticks uint64
	ok, _, _ := performanceCounter.Call(uintptr(unsafe.Pointer(&ticks)))
	if ok == 0 {
		return 0
	}
	return ticks
}
func servicePipeCurrent(pipe net.Conn) bool {
	expected, err := serviceProcess()
	if err != nil {
		return false
	}
	file, ok := pipe.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	var actual uint32
	return windows.GetNamedPipeServerProcessId(windows.Handle(file.Fd()), &actual) == nil && actual == expected
}
func CallService(ctx context.Context, request control.Request) (control.Response, int64, error) {
	prefixed := request
	prefixed.Command = "desktop." + request.Command
	reply, epoch, err := callServiceFrame(ctx, prefixed)
	if err != nil || reply.Error == nil || (*reply.Error != "unknown_command" && *reply.Error != "invalid_request") {
		return reply, epoch, err
	}
	// Explicit rejection means the old service did not perform this command.
	reply, epoch, err = callServiceFrame(ctx, request)
	if err != nil {
		return reply, epoch, err
	}
	// API1's watch snapshot is atomic and revisioned, even on 0.2 services.
	snapshot, birth, snapshotErr := callServiceFrame(ctx, control.Request{Version: control.Version, Command: "watch"})
	if snapshotErr == nil && snapshot.Error == nil && snapshot.Instance == reply.Instance && birth == epoch {
		snapshot.Error = reply.Error
		snapshot.Result = reply.Result
		return snapshot, birth, nil
	}
	return reply, epoch, nil
}

//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
)

// StatisticsAcceptanceCheck reports only current-session measurements and lifecycle evidence.
type StatisticsAcceptanceCheck struct {
	CheckCompleted, NetworkTest, Success, CleanupError  bool
	UploadedBytes, DownloadedBytes, ElapsedMilliseconds uint64
}

type statisticsAcceptanceEffects struct {
	call  func(context.Context, control.Request) (control.BackendResult, error)
	probe func(context.Context, int) error
	wait  func(context.Context) error
}

// ProbeStatisticsForAcceptance uses an isolated proxy listener without changing OS networking.
func ProbeStatisticsForAcceptance(ctx context.Context, directory string, profile control.Profile) (result StatisticsAcceptanceCheck) {
	if ctx.Err() != nil || profile.Protocol < 2 || profile.Protocol >= len(protocol.Names) || !embeddedSingBoxAllowed(false, false) || !embeddedXrayAllowed(false) {
		return
	}
	profile.Reliability, profile.Network = nil, nil
	if control.Validate(control.Request{Version: 1, Command: "start", Profile: &profile}) != "" {
		return
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return
	}
	suffix := hex.EncodeToString(id[:])
	owner := "OneTunnel-Test-" + suffix
	root := filepath.Join(base, "OneTunnel-Phase4Runtime-"+suffix)
	runtime, err := NewSafetyTestRuntime(directory, owner, root, func(control.State) {})
	if err != nil {
		result.CleanupError = true
		return
	}
	runtime.forceSecureBootstrap = true
	var ports []int
	defer func() {
		runtime.Close()
		clean := true
		for _, port := range ports {
			c, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
			if c != nil {
				c.Close()
			}
			if !isAcceptanceListenerStopped(e) {
				clean = false
			}
		}
		rootClean := removeEmptyAcceptanceRuntime(root, owner)
		result.CleanupError = result.CleanupError || !clean || !rootClean
		if result.CleanupError {
			result.Success = false
		}
	}()
	result = runStatisticsAcceptance(ctx, profile, statisticsAcceptanceEffects{
		call: func(ctx context.Context, request control.Request) (control.BackendResult, error) {
			response, err := runtime.Call(ctx, request)
			if response.State.LocalPort > 0 {
				ports = append(ports, response.State.LocalPort)
			}
			return response, err
		},
		probe: httpsCheck,
		wait:  func(ctx context.Context) error { return delay(ctx, 1100*time.Millisecond) },
	})
	return
}

func isAcceptanceListenerStopped(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

func runStatisticsAcceptance(ctx context.Context, profile control.Profile, effects statisticsAcceptanceEffects) (result StatisticsAcceptanceCheck) {
	profile.Reliability, profile.Network = nil, nil
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		stopped, err := effects.call(cleanup, control.Request{Version: 1, Command: "stop"})
		if err != nil || stopped.Error != nil || !statisticsStopped(stopped.State) {
			result.CleanupError = true
			result.Success = false
		}
		result.CheckCompleted = true
	}()
	var previousID string
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return
		}
		started, err := effects.call(ctx, control.Request{Version: 1, Command: "start", Profile: &profile, FullDevice: false})
		if err != nil || started.Error != nil || !statisticsActive(started.State) {
			return
		}
		first, err := effects.call(ctx, control.Request{Version: 1, Command: "status"})
		if err != nil || first.Error != nil || !statisticsActive(first.State) || !statisticsMeasured(first.State.Statistics, false) {
			return
		}
		initial := first.State.Statistics
		if initial.SessionID == previousID {
			return
		}
		result.NetworkTest = true
		if effects.probe(ctx, started.State.LocalPort) != nil || effects.wait(ctx) != nil {
			return
		}
		second, err := effects.call(ctx, control.Request{Version: 1, Command: "status"})
		if err != nil || second.Error != nil || !statisticsActive(second.State) || !statisticsMeasured(second.State.Statistics, true) {
			return
		}
		current := second.State.Statistics
		if current.SessionID != initial.SessionID || current.ElapsedMilliseconds < initial.ElapsedMilliseconds || *current.UploadedBytes < *initial.UploadedBytes || *current.DownloadedBytes < *initial.DownloadedBytes {
			return
		}
		if effects.wait(ctx) != nil {
			return
		}
		third, err := effects.call(ctx, control.Request{Version: 1, Command: "status"})
		if err != nil || third.Error != nil || !statisticsActive(third.State) || !statisticsMeasured(third.State.Statistics, true) {
			return
		}
		last := third.State.Statistics
		if last.SessionID != current.SessionID || last.ElapsedMilliseconds <= current.ElapsedMilliseconds || *last.UploadedBytes < *current.UploadedBytes || *last.DownloadedBytes < *current.DownloadedBytes || last.UploadBytesPerSecond == nil || last.DownloadBytesPerSecond == nil {
			return
		}
		result.UploadedBytes, result.DownloadedBytes, result.ElapsedMilliseconds = *last.UploadedBytes, *last.DownloadedBytes, last.ElapsedMilliseconds
		previousID = last.SessionID
		stopped, err := effects.call(ctx, control.Request{Version: 1, Command: "stop"})
		if err != nil || stopped.Error != nil || !statisticsStopped(stopped.State) {
			result.CleanupError = true
			return
		}
	}
	result.Success = ctx.Err() == nil
	return
}
func statisticsActive(s control.State) bool {
	return s.Active && !s.NeedsRecovery && !s.TrafficLocked && !s.WholeDevice && !s.FullDeviceMode && s.LocalPort > 0
}
func statisticsStopped(s control.State) bool {
	return !s.Active && !s.NeedsRecovery && !s.TrafficLocked && !s.WholeDevice && !s.FullDeviceMode && s.LocalPort == 0 && s.Statistics == nil
}
func statisticsMeasured(s *control.ConnectionStatistics, positive bool) bool {
	return s != nil && s.SchemaVersion == 1 && s.SessionID != "" && s.Scope == "proxy-payload" && s.UploadedBytes != nil && s.DownloadedBytes != nil && (!positive || (*s.UploadedBytes > 0 && *s.DownloadedBytes > 0))
}

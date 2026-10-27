//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"golang.org/x/sys/windows"
)

type ReliabilityAcceptanceReport struct {
	Case                 string `json:"case"`
	Stage                string `json:"stage"`
	Passed               bool   `json:"passed"`
	InitialHTTPS         bool   `json:"initialHTTPS"`
	ReconnectObserved    bool   `json:"reconnectObserved"`
	RestoredHTTPS        bool   `json:"restoredHTTPS"`
	NewStatisticsSession bool   `json:"newStatisticsSession"`
	BackupPromoted       bool   `json:"backupPromoted"`
	RetryStopped         bool   `json:"retryStopped"`
	PortsClosed          bool   `json:"portsClosed"`
	RootRemoved          bool   `json:"rootRemoved"`
	PrimaryConnections   int    `json:"primaryConnections"`
	BackupConnections    int    `json:"backupConnections"`
	ElapsedMilliseconds  int64  `json:"elapsedMilliseconds"`
}

func validReliabilityCase(value string) bool { return value == "reconnect" || value == "fallback" }
func acceptanceConnectTarget(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return false
	}
	return host == "example.com" || host == "www.gstatic.com" || host == "captive.apple.com" || host == "1.1.1.1"
}
func acceptanceRestored(state control.State, profile, previousSession string) bool {
	return statisticsActive(state) && !state.Reconnecting && state.ReconnectAttempt == 0 && !state.TrafficLocked && !state.WholeDevice && state.ProfileID != nil && *state.ProfileID == profile && state.Statistics != nil && state.Statistics.SessionID != "" && state.Statistics.SessionID != previousSession && state.LocalPort > 0
}

type acceptanceGateway struct {
	mu          sync.Mutex
	listener    net.Listener
	server      *http.Server
	address     string
	sockets     map[net.Conn]bool
	connections int
	delay       time.Duration
}

func newAcceptanceGateway() (*acceptanceGateway, error) {
	g := &acceptanceGateway{sockets: map[net.Conn]bool{}}
	return g, g.start()
}
func (g *acceptanceGateway) start() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.listener != nil {
		return nil
	}
	address := g.address
	if address == "" {
		address = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	g.listener, g.address = listener, listener.Addr().String()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { g.serve(listener, w, request) }), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second}
	g.server = server
	go func() { _ = server.Serve(listener) }()
	return nil
}
func (g *acceptanceGateway) stop() {
	g.mu.Lock()
	server := g.server
	g.server = nil
	if g.listener != nil {
		_ = g.listener.Close()
		g.listener = nil
	}
	for socket := range g.sockets {
		_ = socket.Close()
	}
	g.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
}
func (g *acceptanceGateway) count() int { g.mu.Lock(); defer g.mu.Unlock(); return g.connections }
func (g *acceptanceGateway) serve(generation net.Listener, w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || !acceptanceConnectTarget(request.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	g.mu.Lock()
	delay := g.delay
	g.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-request.Context().Done():
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", request.Host)
	cancel()
	if err != nil {
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	client, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	g.mu.Lock()
	if g.listener != generation {
		g.mu.Unlock()
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	g.sockets[client], g.sockets[upstream] = true, true
	g.connections++
	g.mu.Unlock()
	defer func() {
		_ = client.Close()
		_ = upstream.Close()
		g.mu.Lock()
		delete(g.sockets, client)
		delete(g.sockets, upstream)
		g.mu.Unlock()
	}()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffered.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-done
}

// RunReliabilityAcceptance never requests whole-device mode or installs traffic policy.
func RunReliabilityAcceptance(parent context.Context, which, directory string) (report ReliabilityAcceptanceReport) {
	report.Stage = "validate"
	started := time.Now()
	defer func() { report.ElapsedMilliseconds = time.Since(started).Milliseconds() }()
	if !validReliabilityCase(which) || !windows.GetCurrentProcessToken().IsElevated() || !embeddedSingBoxAllowed(false, false) {
		return
	}
	report.Case = which
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	primary, err := newAcceptanceGateway()
	if err != nil {
		return
	}
	defer primary.stop()
	backup, err := newAcceptanceGateway()
	if err != nil {
		return
	}
	defer backup.stop()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return
	}
	id := hex.EncodeToString(random[:])
	owner := "OneTunnel-Test-" + id
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return
	}
	root := filepath.Join(programData, "OneTunnel-Phase4Runtime-"+id)
	var callbackMu sync.Mutex
	ports := map[int]bool{}
	observed, restoreFailed := false, false
	runtime, err := NewSafetyTestRuntime(directory, owner, root, func(state control.State) {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if state.LocalPort > 0 {
			ports[state.LocalPort] = true
		}
		if state.Reconnecting && !observed {
			observed = true
			if which == "reconnect" {
				restoreFailed = primary.start() != nil
			}
		}
	})
	if err != nil {
		return
	}
	runtime.forceSecureBootstrap = true
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		stopped, stopErr := runtime.Call(cleanup, control.Request{Version: control.Version, Command: "stop"})
		done()
		if stopErr == nil && stopped.Error == nil {
			runtime.operations.Lock()
			report.RetryStopped = len(runtime.retry.targets) == 0 && runtime.session == nil
			runtime.operations.Unlock()
			time.Sleep(2200 * time.Millisecond)
			runtime.operations.Lock()
			report.RetryStopped = report.RetryStopped && len(runtime.retry.targets) == 0 && runtime.session == nil
			runtime.operations.Unlock()
		}
		runtime.Close()
		primary.stop()
		backup.stop()
		callbackMu.Lock()
		report.ReconnectObserved = observed
		localPorts := make([]int, 0, len(ports))
		for port := range ports {
			localPorts = append(localPorts, port)
		}
		callbackMu.Unlock()
		report.PortsClosed = len(localPorts) > 0
		for _, port := range localPorts {
			connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)), 250*time.Millisecond)
			if !errors.Is(dialErr, windows.WSAECONNREFUSED) {
				report.PortsClosed = false
				if connection != nil {
					_ = connection.Close()
				}
			}
		}
		report.PrimaryConnections, report.BackupConnections = primary.count(), backup.count()
		if report.RetryStopped && report.PortsClosed && !exists(runtime.journal()) {
			report.RootRemoved = removeEmptyAcceptanceRuntime(root, owner)
		}
		report.Passed = report.Stage == "verified" && report.RetryStopped && report.PortsClosed && report.RootRemoved
	}()
	profile := control.Profile{ID: "15681046-889e-4563-a8ae-6136c534aba1", Name: "Synthetic primary", Group: "Synthetic acceptance", Protocol: 6, Source: "http://" + primary.address, Reliability: &control.ReliabilityOptions{AutoReconnect: true, UseFallbacks: which == "fallback"}}
	alternative := profile
	alternative.ID = "5d97361c-58f2-4c2b-9035-d564f2bd5465"
	alternative.Name = "Synthetic backup"
	alternative.Source = "http://" + backup.address
	request := control.Request{Version: control.Version, Command: "start", Profile: &profile}
	expected := profile.ID
	if which == "fallback" {
		request.Fallbacks = []control.Profile{alternative}
		expected = alternative.ID
	}
	report.Stage = "start"
	if control.Validate(request) != "" {
		return
	}
	initial, err := runtime.Call(ctx, request)
	if err != nil || initial.Error != nil || !statisticsActive(initial.State) || initial.State.Statistics == nil || initial.State.Statistics.SessionID == "" {
		return
	}
	originalSession := initial.State.Statistics.SessionID
	probe, done := context.WithTimeout(ctx, 15*time.Second)
	err = httpsCheck(probe, initial.State.LocalPort)
	done()
	report.InitialHTTPS = err == nil && primary.count() > 0
	if !report.InitialHTTPS {
		report.Stage = "initial_https"
		return
	}
	primary.stop()
	report.Stage = "waiting_for_monitor"
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		callbackMu.Lock()
		failed := restoreFailed
		seen := observed
		callbackMu.Unlock()
		if failed {
			report.Stage = "gateway_restore"
			return
		}
		if !seen {
			continue
		}
		state := runtime.snapshot()
		if !acceptanceRestored(state, expected, originalSession) {
			continue
		}
		report.NewStatisticsSession = true
		probe, done = context.WithTimeout(ctx, 15*time.Second)
		err = httpsCheck(probe, state.LocalPort)
		done()
		report.RestoredHTTPS = err == nil
		if !report.RestoredHTTPS {
			report.Stage = "restored_https"
			return
		}
		runtime.operations.Lock()
		report.BackupPromoted = which == "fallback" && len(runtime.retry.targets) > 0 && runtime.retry.targets[0].ID == expected
		runtime.operations.Unlock()
		if which == "fallback" && (!report.BackupPromoted || backup.count() == 0) {
			report.Stage = "backup_promotion"
			return
		}
		report.Stage = "verified"
		return
	}
}

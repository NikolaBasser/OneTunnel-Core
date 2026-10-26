//go:build windows && onetunnel_safety_test

package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
)

// ProxyAcceptanceCheck contains no profile metadata or raw engine errors.
type ProxyAcceptanceCheck struct {
	CheckCompleted, NetworkTest, Success, CleanupError bool
	HTTPSLatencyMilliseconds                           *int64 `json:",omitempty"`
}

// ProbeProxyForAcceptance runs only the existing non-TUN group check.
func ProbeProxyForAcceptance(ctx context.Context, directory string, profile control.Profile) (result ProxyAcceptanceCheck) {
	// Reject native profiles and external-engine builds before any effects.
	if profile.Protocol < 2 || profile.Protocol >= len(protocol.Names) || ctx.Err() != nil || !embeddedSingBoxAllowed(false, false) || !embeddedXrayAllowed(false) {
		return result
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return result
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return result
	}
	suffix := hex.EncodeToString(id[:])
	owner := "OneTunnel-Test-" + suffix
	root := filepath.Join(programData, "OneTunnel-Phase4Runtime-"+suffix)
	runtime, err := NewSafetyTestRuntime(directory, owner, root, func(control.State) {})
	if err != nil {
		// A partially prepared root is retained, never recursively removed.
		_, statErr := os.Lstat(root)
		result.CleanupError = !os.IsNotExist(statErr)
		return result
	}
	localPort := 0
	defer func() {
		runtime.Close()
		listenerStopped := true
		if localPort != 0 {
			connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 250*time.Millisecond)
			if connection != nil {
				connection.Close()
			}
			listenerStopped = errors.Is(dialErr, windows.WSAECONNREFUSED)
		}
		result.CleanupError = !listenerStopped || !removeEmptyAcceptanceRuntime(root, owner)
		if result.CleanupError {
			result.Success = false
			result.HTTPSLatencyMilliseconds = nil
		}
	}()
	runtime.forceSecureBootstrap = true
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	runtime.operations.Lock()
	response, err := runtime.checkProfileWithProbe(deadline, &profile, func(ctx context.Context, port int) error {
		localPort = port
		return httpsCheck(ctx, port)
	})
	runtime.operations.Unlock()
	if err != nil || response == nil {
		return result
	}
	var check control.ProfileCheck
	if json.Unmarshal([]byte(*response), &check) != nil {
		return result
	}
	result.CheckCompleted, result.NetworkTest = true, check.NetworkTest && localPort > 0
	result.Success = check.Success && result.NetworkTest && deadline.Err() == nil
	if result.Success && check.HTTPSLatencyMilliseconds != nil && *check.HTTPSLatencyMilliseconds >= 0 {
		value := *check.HTTPSLatencyMilliseconds
		result.HTTPSLatencyMilliseconds = &value
	}
	return result
}

func removeEmptyAcceptanceRuntime(root, owner string) bool {
	if verifySafetyTestRoot(root, owner) != nil {
		return false
	}
	runtime := filepath.Join(root, "runtime")
	entries, err := os.ReadDir(runtime)
	if err != nil || len(entries) != 0 {
		return false
	}
	if os.Remove(runtime) != nil {
		return false
	}
	if os.Remove(filepath.Join(root, "safety-owner.json")) != nil {
		return false
	}
	return os.Remove(root) == nil
}

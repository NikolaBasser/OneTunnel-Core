package control

import "github.com/NikolaBasser/OneTunnel-Core/internal/protocol"

func CompatibleFallback(primary, backup Profile, full bool) bool {
	if !protocol.NetworkOptionsEquivalent(primary.Network, backup.Network) {
		return false
	}
	if full {
		return true
	}
	if (primary.Protocol < 2) != (backup.Protocol < 2) {
		return false
	}
	if primary.Protocol >= 2 {
		return true
	}
	first, err := protocol.NativeRouteScope(primary.Source, primary.Protocol)
	if err != nil {
		return false
	}
	second, err := protocol.NativeRouteScope(backup.Source, backup.Protocol)
	return err == nil && first == second
}

// Opt-in profile preferences. Retry targets live only in service memory.
type ReliabilityOptions struct {
	AutoReconnect bool
	UseFallbacks  bool
}

type ProfileCheck struct {
	Success                  bool
	NetworkTest              bool
	Milliseconds             int64
	Message                  string
	HTTPSLatencyMilliseconds *int64 `json:",omitempty"`
}

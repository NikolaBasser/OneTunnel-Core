// Package sdk exposes portable profile policy and the host-supplied connection
// adapter contract. It does not install a VPN, own an OS keystore, or provide
// Swift/Kotlin bindings. Native tunnel and protection adapters remain platform-specific.
package sdk

import (
	"errors"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/profiles"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type Profile = control.Profile
type TransportOptions = protocol.TransportOptions
type NetworkOptions = protocol.NetworkOptions
type DNSOptions = protocol.DNSOptions
type NetworkRule = protocol.NetworkRule
type PolicyTarget = protocol.PolicyTarget
type RuleSet = protocol.RuleSet
type RouteQuery = protocol.RouteQuery
type RoutePrediction = protocol.RoutePrediction
type PolicyAnalysis = protocol.PolicyAnalysis
type ReliabilityOptions = control.ReliabilityOptions
type Request = control.Request
type Response = control.Response
type State = control.State
type Backend = control.Backend
type BackendResult = control.BackendResult

// Factory must return a callable non-nil backend on success. A typed-nil backend
// is invalid host code and must not be returned through the interface.
type Factory = control.Factory
type Controller = control.Manager
type ImportResult = profiles.ImportResult
type MergeResult = profiles.MergeResult
type Plan = protocol.Plan

const APIVersion = control.Version

// Protocol IDs match the persisted profile and API1 contract.
const (
	AmneziaWG   = 0
	WireGuard   = 1
	VLESS       = 2
	SOCKS5      = 3
	Hysteria2   = 4
	Shadowsocks = 5
	HTTP        = protocol.HTTP
	Trojan      = protocol.Trojan
	TUIC        = protocol.TUIC
	AnyTLS      = protocol.AnyTLS
	NaiveProxy  = protocol.Naive
)

var ErrAdapterRequired = errors.New("a native connection adapter is required")
var ErrUnsupportedTarget = errors.New("unsupported foundation target")

// Parse validates and imports a profile without opening a connection or store.
func Parse(name, source string, requested *int) (Profile, error) {
	return profiles.Parse(name, source, requested)
}

func ParseSubscription(payload string) (ImportResult, error) {
	return profiles.ParseSubscription(payload)
}

func Merge(existing, incoming []Profile, group string) (MergeResult, error) {
	return profiles.Merge(existing, incoming, group)
}

func Validate(profile Profile) error { return profiles.Validate(profile) }

// CompileLocal produces the existing local-mode engine plan. Native profiles
// retain their configuration; this is not a portable full-device TUN plan.
func CompileLocal(profile Profile, localPort, bridgePort int) (Plan, error) {
	if err := profiles.Validate(profile); err != nil {
		return Plan{}, err
	}
	return protocol.CompileWithNetwork(profile.Source, profile.Protocol, false, localPort, bridgePort, "", profile.Transport, profile.Network)
}

// NewController requires an explicit host implementation. No unsupported target
// is made operational by a fallback or success-returning adapter.
func NewController(factory Factory) (*Controller, error) {
	if factory == nil {
		return nil, ErrAdapterRequired
	}
	return control.NewManager(func(onState func(State), onFailure func()) (Backend, error) {
		backend, err := factory(onState, onFailure)
		if backend == nil && err == nil {
			return nil, ErrAdapterRequired
		}
		return backend, err
	})
}

// Capabilities describes implemented support, not current connection state.
type Capabilities struct {
	OS               string
	Architecture     string
	PortableAPI      bool
	RuntimeAvailable bool
	SystemProtection bool
}

func CapabilitiesFor(os, architecture string) (Capabilities, error) {
	known := false
	switch os {
	case "windows", "linux", "android":
		known = architecture == "amd64" || architecture == "arm64"
	case "ios":
		known = architecture == "arm64"
	}
	if !known {
		return Capabilities{}, ErrUnsupportedTarget
	}
	runtime := os == "windows" && architecture == "amd64"
	return Capabilities{OS: os, Architecture: architecture, PortableAPI: true, RuntimeAvailable: runtime, SystemProtection: runtime}, nil
}

func AnalyzeNetwork(options *NetworkOptions) (PolicyAnalysis, error) {
	return protocol.AnalyzeNetwork(options)
}
func ExplainRoute(options *NetworkOptions, query RouteQuery) (RoutePrediction, error) {
	return protocol.ExplainRoute(options, query)
}

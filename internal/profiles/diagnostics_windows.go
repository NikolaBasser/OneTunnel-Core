package profiles

import (
	"encoding/json"
	"errors"
	"regexp"
	"runtime"

	"github.com/NikolaBasser/OneTunnel-Core/internal/buildinfo"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

var (
	diagnosticsVersionPattern   = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	diagnosticsRevisionPattern  = regexp.MustCompile(`^(unknown|[a-fA-F0-9]{7,40})$`)
	diagnosticsGoVersionPattern = regexp.MustCompile(`^go[0-9]+(\.[0-9]+){1,2}([A-Za-z0-9.-]+)?$`)
)

var errDiagnosticsUnavailable = errors.New("diagnostics report unavailable")

type diagnosticsReport struct {
	SchemaVersion            int                       `json:"schemaVersion"`
	ProfileHost              diagnosticsBuildInfo      `json:"profileHost"`
	Runtime                  diagnosticsRuntime        `json:"runtime"`
	Profiles                 diagnosticsProfileSummary `json:"profiles"`
	PackageAvailabilityHints diagnosticsPackages       `json:"packageAvailabilityHints"`
}

type diagnosticsBuildInfo struct {
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
	Dirty    bool   `json:"dirty"`
}

type diagnosticsRuntime struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Go     string `json:"goVersion,omitempty"`
}

type diagnosticsProfileSummary struct {
	Total                int                   `json:"total"`
	UnknownProtocolCount int                   `json:"unknownProtocolCount"`
	Protocols            []diagnosticsProtocol `json:"protocols"`
}

type diagnosticsProtocol struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type diagnosticsPackages struct {
	AWG     bool `json:"awg"`
	Xray    bool `json:"xray"`
	SingBox bool `json:"singBox"`
}

func (a *Application) diagnosticsReport() (string, error) {
	if a.Store == nil {
		return "", errDiagnosticsUnavailable
	}
	doc, err := a.Store.Load()
	if err != nil {
		return "", errDiagnosticsUnavailable
	}
	return formatDiagnosticsReport(doc, embeddedCapabilities(a.Directory))
}

func formatDiagnosticsReport(doc Document, capabilities map[string]bool) (string, error) {
	if len(doc.Profiles) > 2000 || len(protocol.Names) != protocol.MaxKind+1 {
		return "", errDiagnosticsUnavailable
	}
	counts := make([]int, len(protocol.Names))
	unknown := 0
	for _, profile := range doc.Profiles {
		if profile.Protocol < 0 || profile.Protocol >= len(counts) {
			unknown++
			continue
		}
		counts[profile.Protocol]++
	}
	protocols := make([]diagnosticsProtocol, len(protocol.Names))
	for id, name := range protocol.Names {
		protocols[id] = diagnosticsProtocol{ID: id, Name: name, Count: counts[id]}
	}

	build := diagnosticsBuildInfo{}
	if len(buildinfo.Version) <= 64 && diagnosticsVersionPattern.MatchString(buildinfo.Version) {
		build.Version = buildinfo.Version
	}
	if diagnosticsRevisionPattern.MatchString(buildinfo.Revision) {
		build.Revision = buildinfo.Revision
	}
	build.Dirty = buildinfo.Dirty != "false"
	goVersion := runtime.Version()
	if len(goVersion) > 32 || !diagnosticsGoVersionPattern.MatchString(goVersion) {
		goVersion = ""
	}

	report := diagnosticsReport{
		SchemaVersion: 1,
		ProfileHost:   build,
		Runtime:       diagnosticsRuntime{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Go: goVersion},
		Profiles:      diagnosticsProfileSummary{Total: len(doc.Profiles), UnknownProtocolCount: unknown, Protocols: protocols},
		PackageAvailabilityHints: diagnosticsPackages{
			AWG: capabilities["amneziawg.exe"], Xray: capabilities["xray.exe"], SingBox: capabilities["sing-box.exe"],
		},
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", errDiagnosticsUnavailable
	}
	return string(encoded), nil
}

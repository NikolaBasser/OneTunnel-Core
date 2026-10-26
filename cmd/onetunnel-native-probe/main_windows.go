//go:build windows && onetunnel_safety_test && embeddedawg

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"github.com/NikolaBasser/OneTunnel-Core/internal/profiles"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"golang.org/x/sys/windows"
)

func main() {
	data := flag.String("data", "", "existing isolated encrypted profile-copy directory")
	scope := flag.String("scope", "native", "native, proxy group checks or statistics lifecycle")
	offset := flag.Int("offset", 0, "skip this many eligible proxy profiles")
	kind := flag.Int("kind", -1, "optional numeric proxy protocol for statistics only; offset follows this filter")
	flag.Parse()
	if flag.NArg() != 0 || validateProbeScopeOffset(*scope, *offset) != nil || validateStatisticsKind(*scope, *kind) != nil {
		fail()
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		fail()
	}
	root, err := validateDataRoot(*data, filepath.Join(base, "OneTunnel"))
	if err != nil {
		fail()
	}
	store, err := profiles.NewStore(root)
	if err != nil {
		fail()
	}
	document, err := store.Load()
	if err != nil {
		fail()
	}
	budget := 180 * time.Second
	if *scope == "proxy" {
		budget = 420 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var result []protocolResult
	if *scope == "native" {
		result = probeProfiles(ctx, document.Profiles, platform.ProbeNativeDNSForAcceptance)
	} else {
		candidates := document.Profiles
		if *scope == "statistics" && *kind != -1 {
			candidates = filterStatisticsKind(candidates, *kind)
		}
		items, err := filterProxyProfilesFromOffset(candidates, *offset)
		if err != nil {
			fail()
		}
		executable, err := os.Executable()
		if err != nil {
			fail()
		}
		if *scope == "statistics" {
			result = probeStatisticsProfiles(ctx, items, func(ctx context.Context, profile profiles.Profile) platform.StatisticsAcceptanceCheck {
				return platform.ProbeStatisticsForAcceptance(ctx, filepath.Dir(executable), profile)
			})
		} else {
			result = probeProxyProfiles(ctx, items, func(ctx context.Context, profile profiles.Profile) platform.ProxyAcceptanceCheck {
				return platform.ProbeProxyForAcceptance(ctx, filepath.Dir(executable), profile)
			})
		}
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		fail()
	}
	if *scope == "statistics" {
		successes := 0
		for _, row := range result {
			if row.CleanupError != 0 {
				fail()
			}
			successes += row.Success
		}
		if ctx.Err() != nil || successes == 0 {
			fail()
		}
	}
	if *scope == "proxy" {
		if ctx.Err() != nil {
			fail()
		}
		for _, row := range result {
			if row.CleanupError != 0 || row.CheckCompleted != row.Count {
				fail()
			}
		}
	}
}

func validateStatisticsKind(scope string, kind int) error {
	if kind == -1 {
		return nil
	}
	if scope != "statistics" || kind < 2 || kind >= len(protocol.Names) {
		return errors.New("invalid statistics protocol")
	}
	return nil
}

func filterStatisticsKind(items []profiles.Profile, kind int) []profiles.Profile {
	var selected []profiles.Profile
	for _, item := range items {
		if item.Protocol == kind {
			selected = append(selected, item)
		}
	}
	return selected
}

func validateProbeScopeOffset(scope string, offset int) error {
	if (scope != "native" && scope != "proxy" && scope != "statistics") || offset < 0 || (scope == "native" && offset != 0) {
		return errors.New("invalid probe scope or offset")
	}
	return nil
}

func filterProxyProfilesFromOffset(items []profiles.Profile, offset int) ([]profiles.Profile, error) {
	eligible := make([]profiles.Profile, 0, len(items))
	for _, item := range items {
		if item.Protocol >= 2 && item.Protocol < len(protocol.Names) {
			eligible = append(eligible, item)
		}
	}
	if offset < 0 || offset > len(eligible) {
		return nil, errors.New("proxy offset exceeds eligible profiles")
	}
	return eligible[offset:], nil
}

func fail() {
	fmt.Fprintln(os.Stderr, "Isolated acceptance could not complete; no profile details are reported.")
	os.Exit(1)
}

func relatedPath(a, b string) bool {
	a, b = strings.ToLower(filepath.Clean(a)), strings.ToLower(filepath.Clean(b))
	return a == b || strings.HasPrefix(a, strings.TrimRight(b, `\`)+`\`) || strings.HasPrefix(b, strings.TrimRight(a, `\`)+`\`)
}

func validateDataRoot(root, forbidden string) (string, error) {
	invalid := errors.New("isolated profile-copy directory required")
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) || relatedPath(root, forbidden) {
		return "", invalid
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return "", invalid
	}
	for path := root; ; path = filepath.Dir(path) {
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", invalid
		}
		if forbiddenInfo, err := os.Stat(forbidden); err == nil {
			candidate, err := os.Stat(path)
			if err != nil || os.SameFile(candidate, forbiddenInfo) {
				return "", invalid
			}
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	// Detect an ancestor selected through an alternative Windows short-name spelling.
	for path := forbidden; ; path = filepath.Dir(path) {
		if other, err := os.Stat(path); err == nil && os.SameFile(info, other) {
			return "", invalid
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	file := filepath.Join(root, "profiles.bin")
	profileInfo, err := os.Lstat(file)
	if err != nil || !profileInfo.Mode().IsRegular() || profileInfo.Size() == 0 || profileInfo.Size() > 32*1024*1024 {
		return "", invalid
	}
	for _, path := range []string{file, filepath.Join(root, "runtime")} {
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if os.IsNotExist(err) && path != file {
			continue
		}
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", invalid
		}
	}
	return root, nil
}

type protocolResult struct {
	Protocol                                            string
	Count, Attempted, Success                           int
	DNSLatencyMilliseconds                              []int64  `json:",omitempty"`
	HTTPSLatencyMilliseconds                            []int64  `json:",omitempty"`
	CheckCompleted, CleanupError                        int      `json:",omitempty"`
	UploadedBytes, DownloadedBytes, ElapsedMilliseconds []uint64 `json:",omitempty"`
}

func probeProxyProfiles(ctx context.Context, items []profiles.Profile, probe func(context.Context, profiles.Profile) platform.ProxyAcceptanceCheck) []protocolResult {
	rows := make([]protocolResult, len(protocol.Names)-2)
	for i := range rows {
		rows[i].Protocol = protocol.Names[i+2]
	}
	for _, item := range items {
		if item.Protocol >= 2 && item.Protocol < len(protocol.Names) {
			rows[item.Protocol-2].Count++
		}
	}
	considered := 0
	for _, item := range items {
		if item.Protocol < 2 || item.Protocol >= len(protocol.Names) {
			continue
		}
		if considered == 32 || ctx.Err() != nil {
			break
		}
		considered++
		deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
		check := probe(deadline, item)
		canceled := deadline.Err() != nil
		cancel()
		row := &rows[item.Protocol-2]
		if check.CleanupError {
			row.CleanupError++
			break
		}
		if check.CheckCompleted {
			row.CheckCompleted++
		}
		if check.NetworkTest {
			row.Attempted++
		}
		if check.CheckCompleted && check.NetworkTest && check.Success && !canceled && check.HTTPSLatencyMilliseconds != nil && *check.HTTPSLatencyMilliseconds >= 0 {
			row.Success++
			row.HTTPSLatencyMilliseconds = append(row.HTTPSLatencyMilliseconds, *check.HTTPSLatencyMilliseconds)
		}
	}
	return rows
}

type nativeProbe func(context.Context, string, int) (bool, *int64, error)

func probeProfiles(ctx context.Context, items []profiles.Profile, probe nativeProbe) []protocolResult {
	rows := []protocolResult{{Protocol: "AmneziaWG"}, {Protocol: "WireGuard"}}
	for _, item := range items {
		if item.Protocol == 0 || item.Protocol == 1 {
			rows[item.Protocol].Count++
		}
	}
	considered := 0
	for _, item := range items {
		if item.Protocol != 0 && item.Protocol != 1 {
			continue
		}
		if considered == 16 || ctx.Err() != nil {
			break
		}
		considered++
		deadline, cancel := context.WithTimeout(ctx, 12*time.Second)
		network, latency, err := probe(deadline, item.Source, item.Protocol)
		canceled := deadline.Err() != nil
		cancel()
		row := &rows[item.Protocol]
		if network {
			row.Attempted++
		}
		if network && err == nil && !canceled && latency != nil && *latency >= 0 {
			row.Success++
			row.DNSLatencyMilliseconds = append(row.DNSLatencyMilliseconds, *latency)
		}
	}
	return rows
}

// A small bounded batch stops after one successful lifecycle per protocol.
func probeStatisticsProfiles(ctx context.Context, items []profiles.Profile, probe func(context.Context, profiles.Profile) platform.StatisticsAcceptanceCheck) []protocolResult {
	rows := make([]protocolResult, len(protocol.Names)-2)
	for i := range rows {
		rows[i].Protocol = protocol.Names[i+2]
	}
	for _, p := range items {
		if p.Protocol >= 2 && p.Protocol < len(protocol.Names) {
			rows[p.Protocol-2].Count++
		}
	}
	attempted := 0
	for _, p := range items {
		if p.Protocol < 2 || p.Protocol >= len(protocol.Names) {
			continue
		}
		row := &rows[p.Protocol-2]
		if row.Success > 0 {
			continue
		}
		if attempted == 6 || ctx.Err() != nil {
			break
		}
		attempted++
		deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
		check := probe(deadline, p)
		canceled := deadline.Err() != nil
		cancel()
		if check.CheckCompleted {
			row.CheckCompleted++
		}
		if check.NetworkTest {
			row.Attempted++
		}
		if check.CleanupError {
			row.CleanupError++
			break
		}
		if check.Success && check.CheckCompleted && check.NetworkTest && !canceled && check.UploadedBytes > 0 && check.DownloadedBytes > 0 {
			row.Success++
			row.UploadedBytes = append(row.UploadedBytes, check.UploadedBytes)
			row.DownloadedBytes = append(row.DownloadedBytes, check.DownloadedBytes)
			row.ElapsedMilliseconds = append(row.ElapsedMilliseconds, check.ElapsedMilliseconds)
		}
	}
	return rows
}

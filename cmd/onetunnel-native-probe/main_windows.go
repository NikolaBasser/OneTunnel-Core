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
	"golang.org/x/sys/windows"
)

func main() {
	data := flag.String("data", "", "existing isolated encrypted profile-copy directory")
	flag.Parse()
	if flag.NArg() != 0 {
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
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	result := probeProfiles(ctx, document.Profiles, platform.ProbeNativeDNSForAcceptance)
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "Native DNS acceptance could not complete; no profile details are reported.")
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
	Protocol                  string
	Count, Attempted, Success int
	DNSLatencyMilliseconds    []int64 `json:",omitempty"`
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

//go:build windows && onetunnel_safety_test

package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
)

func main() {
	which := flag.String("case", "", "reconnect or fallback")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	report := platform.RunReliabilityAcceptance(context.Background(), *which, filepath.Dir(executable))
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if !report.Passed {
		os.Exit(1)
	}
}

package main

import (
	"context"
	"golang.org/x/sys/windows"
	"io"
	"onetunnel/core/internal/control"
	"onetunnel/core/internal/platform"
	"onetunnel/core/internal/profiles"
	"os"
	"path/filepath"
	"time"
)

func main() {
	path, e := os.Executable()
	if e != nil {
		os.Exit(1)
	}
	if len(os.Args) == 3 && os.Args[1] == "--install-service" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if platform.InstallPublicService(ctx, filepath.Dir(path), os.Args[2]) != nil {
			os.Exit(4)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--events" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
		_ = platform.WatchPublicService(ctx, func(event platform.ServiceObservation) error { return control.WriteFrame(os.Stdout, event) })
		return
	}
	store, e := profiles.NewStore(os.Getenv("ONETUNNEL_DATA_DIR"))
	if e != nil {
		os.Exit(2)
	}
	if len(os.Args) == 3 && os.Args[1] == "--recover-legacy" {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user.User.Sid.String() != os.Args[2] || !windows.GetCurrentProcessToken().IsElevated() {
			os.Exit(4)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if platform.LegacyUserRecovery(ctx, store.Root, filepath.Dir(path)) != nil {
			os.Exit(4)
		}
		return
	}
	app := &profiles.Application{Store: store, Directory: filepath.Dir(path), Downloader: profiles.Download}
	if profiles.RunHost(context.Background(), os.Stdin, os.Stdout, app) != nil {
		os.Exit(3)
	}
}

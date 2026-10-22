package main

import (
	"context"
	"onetunnel/core/internal/profiles"
	"os"
	"path/filepath"
)

func main() {
	path, e := os.Executable()
	if e != nil {
		os.Exit(1)
	}
	store, e := profiles.NewStore(os.Getenv("ONETUNNEL_DATA_DIR"))
	if e != nil {
		os.Exit(2)
	}
	app := &profiles.Application{Store: store, Directory: filepath.Dir(path), Downloader: profiles.Download}
	if profiles.RunHost(context.Background(), os.Stdin, os.Stdout, app) != nil {
		os.Exit(3)
	}
}

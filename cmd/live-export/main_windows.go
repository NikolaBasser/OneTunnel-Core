// live-export prepares a protected, machine-DPAPI test copy. It never writes
// the user's store and never prints sources, labels, credentials or endpoints.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/profiles"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "protected live export failed")
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", "", "protected output directory")
	flag.Parse()
	if *out == "" {
		return os.ErrInvalid
	}
	store, err := profiles.NewStore(*out)
	if err != nil {
		return err
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return err
	}
	path := filepath.Join(local, "OneTunnel", "profiles.bin")
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(before)
	plain, err := profiles.Protect(before, false)
	if err != nil {
		return err
	}
	defer clear(plain)
	var doc profiles.Document
	if err = json.Unmarshal(plain, &doc); err != nil {
		return err
	}
	refreshed := 0
	for group, source := range doc.SubscriptionSources {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		batch, e := profiles.Download(ctx, source)
		cancel()
		if e != nil {
			return e
		}
		merged, e := profiles.Merge(doc.Profiles, batch.Profiles, group)
		if e != nil {
			return e
		}
		doc.Profiles = merged.Profiles
		refreshed++
	}
	data, err := json.Marshal(doc.Profiles)
	if err != nil {
		return err
	}
	defer clear(data)
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var encrypted windows.DataBlob
	if err = windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &encrypted); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(encrypted.Data)))
	if err = os.WriteFile(filepath.Join(store.Root, "profiles-machine.bin"), unsafe.Slice(encrypted.Data, encrypted.Size), 0600); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	groups := map[int]int{}
	for _, p := range doc.Profiles {
		groups[p.Protocol]++
	}
	report := map[string]any{"OwnerSID": user.User.Sid.String(), "Profiles": len(doc.Profiles), "RefreshedSubscriptions": refreshed, "Protocols": groups, "OriginalSHA256": fmt.Sprintf("%X", digest), "UserStoreWritten": false}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if err = os.WriteFile(filepath.Join(store.Root, "export-report.json"), encoded, 0600); err != nil {
		return err
	}
	after, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(after) != digest {
		return os.ErrInvalid
	}
	fmt.Printf("Protected copy: %d profiles; %d refreshed subscription(s); original unchanged\n", len(doc.Profiles), refreshed)
	return nil
}

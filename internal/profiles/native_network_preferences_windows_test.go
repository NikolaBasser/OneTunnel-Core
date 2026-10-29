package profiles

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func nativePreferencesSource(kind int) string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	source := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.17.0.2/32\nDNS = 10.17.0.1\n[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	if kind == 0 {
		source = strings.Replace(source, "[Peer]", "Jc = 3\nJmin = 10\nJmax = 30\nS1 = 21\nS2 = 22\nH1 = 100\nH2 = 101\nH3 = 102\nH4 = 103\n[Peer]", 1)
	}
	return source
}

func TestNativeNetworkPreferencesSaveCopyAndBackupPreserveSource(t *testing.T) {
	for _, kind := range []int{0, 1} {
		t.Run(protocol.Names[kind], func(t *testing.T) {
			profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Imported native", "Manual")
			profile.Protocol = kind
			profile.Source = nativePreferencesSource(kind)
			originalSource := profile.Source
			store := managementStore(t, Document{Profiles: []Profile{profile}})
			app := &Application{Store: store, ServiceCall: func(context.Context, control.Request) (control.Response, int64, error) {
				t.Fatal("preferences used service")
				return control.Response{}, 0, nil
			}, Downloader: func(context.Context, string) (ImportResult, error) {
				t.Fatal("preferences used downloader")
				return ImportResult{}, nil
			}}

			view, err := app.networkPreferencesView(profile.ID)
			if err != nil || !view.Supported || !view.CanSave || !strings.Contains(view.Message, "shared TUN") || !strings.Contains(view.Message, "Policy DNS replaces imported DNS") {
				t.Fatalf("native preferences capability: %+v err=%v", view, err)
			}
			input := &NetworkInput{Mode: "https", ServerIP: "10.17.0.1", ServerName: "resolver.example", RulesText: "domain-suffix | direct | internal.example", AllowLAN: true}
			if _, err = app.saveNetworkPreferences(Request{ID: profile.ID, Token: view.Token, NetworkInput: input}); err != nil {
				t.Fatalf("save native policy: %v", err)
			}
			doc, err := store.Load()
			if err != nil || len(doc.Profiles) != 1 || doc.Profiles[0].Source != originalSource || doc.Profiles[0].Protocol != kind || doc.Profiles[0].Network == nil || !doc.Profiles[0].Network.AllowLAN || doc.Profiles[0].Network.DNS == nil || doc.Profiles[0].Network.DNS.ServerIP != "10.17.0.1" {
				t.Fatalf("native source or policy changed: %+v err=%v", doc, err)
			}

			copy, err := app.duplicateProfile(profile.ID, "Imported native copy", "Manual copies", organizationToken(t, store))
			if err != nil || copy.Selected == nil || copy.Selected.Source != originalSource || copy.Selected.Protocol != kind || !protocol.NetworkOptionsEquivalent(copy.Selected.Network, doc.Profiles[0].Network) {
				t.Fatalf("native copy lost source or policy: %+v err=%v", copy, err)
			}

			backup := filepath.Join(t.TempDir(), "native.otbackup")
			if _, err = app.exportBackup(backup, "synthetic native backup password"); err != nil {
				t.Fatal(err)
			}
			restoredStore := managementStore(t, Document{Profiles: []Profile{managementProfile(t, "22222222-2222-4222-8222-222222222222", "Existing", "Manual")}})
			restoring := &Application{Store: restoredStore}
			preview, err := restoring.previewBackupRestore(backup, "synthetic native backup password")
			if err != nil {
				t.Fatal(err)
			}
			restored, err := restoring.applyBackupRestore(preview.Token, false)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, restoredProfile := range restored.Profiles {
				if restoredProfile.ID == profile.ID {
					found = restoredProfile.Source == originalSource && restoredProfile.Protocol == kind && protocol.NetworkOptionsEquivalent(restoredProfile.Network, doc.Profiles[0].Network)
				}
			}
			if !found {
				t.Fatal("native profile source or policy changed in backup restore")
			}
		})
	}
}

func TestNativeNetworkPreferencesExpandRuntimeRoutesAndRejectStaleToken(t *testing.T) {
	for _, kind := range []int{0, 1} {
		t.Run(protocol.Names[kind], func(t *testing.T) {
			profile := managementProfile(t, "11111111-1111-4111-8111-111111111111", "Restricted native", "Manual")
			profile.Protocol = kind
			profile.Source = strings.Replace(nativePreferencesSource(kind), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8", 1)
			store := managementStore(t, Document{Profiles: []Profile{profile}})
			app := &Application{Store: store}
			view, err := app.networkPreferencesView(profile.ID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = app.saveNetworkPreferences(Request{ID: profile.ID, Token: view.Token, NetworkInput: &NetworkInput{Mode: "https", ServerIP: "8.8.8.8", ServerName: "resolver.example", AllowLAN: true}})
			if err != nil {
				t.Fatal("policy DNS outside imported routes must use expanded runtime copy", err)
			}
			doc, _ := store.Load()
			if doc.Profiles[0].Source != profile.Source {
				t.Fatal("saved source changed")
			}
			before := storeBytes(t, store)

			_, err = app.saveNetworkPreferences(Request{ID: profile.ID, Token: "stale-token", NetworkInput: &NetworkInput{Mode: "https", ServerIP: "10.0.0.1", ServerName: "resolver.example", AllowLAN: true}})
			if err == nil || !reflect.DeepEqual(before, storeBytes(t, store)) {
				t.Fatal("stale native preference token changed the store")
			}
		})
	}
}

package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedAvailabilityWithoutExternalExecutables(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "service")
	if os.Mkdir(service, 0700) != nil {
		t.Fatal("directory")
	}
	if os.WriteFile(filepath.Join(service, "OneTunnel.Service.exe"), []byte("fixture"), 0600) != nil {
		t.Fatal("service fixture")
	}
	for _, prefix := range []string{"", "\xef\xbb\xbf"} {
		data := prefix + `{"Runtime":"go","ApiVersion":1,"EmbeddedAWG":true,"EmbeddedXray":true,"EmbeddedSingBox":true}`
		if os.WriteFile(filepath.Join(service, "go-runtime.json"), []byte(data), 0600) != nil {
			t.Fatal("metadata fixture")
		}
		result := embeddedCapabilities(root)
		for _, name := range []string{"amneziawg.exe", "xray.exe", "sing-box.exe"} {
			if !result[name] {
				t.Fatal("embedded engine unavailable without external executable")
			}
		}
	}
	os.Remove(filepath.Join(service, "OneTunnel.Service.exe"))
	if len(embeddedCapabilities(root)) != 0 {
		t.Fatal("metadata without service must not advertise availability")
	}
}

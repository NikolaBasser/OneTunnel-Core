package profiles

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// Packaging metadata is a UI availability hint only. The privileged service
// independently chooses the engine compiled into its own executable.
func embeddedCapabilities(directory string) map[string]bool {
	result := map[string]bool{}
	service := filepath.Join(directory, "service")
	if _, err := os.Stat(filepath.Join(service, "OneTunnel.Service.exe")); err != nil {
		return result
	}
	file, err := os.Open(filepath.Join(service, "go-runtime.json"))
	if err != nil {
		return result
	}
	defer file.Close()
	var metadata struct {
		Runtime                                    string
		ApiVersion                                 int
		EmbeddedAWG, EmbeddedXray, EmbeddedSingBox bool
	}
	data, err := io.ReadAll(io.LimitReader(file, 65536))
	if err != nil || json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))).Decode(&metadata) != nil || metadata.Runtime != "go" || metadata.ApiVersion != 1 {
		return result
	}
	result["amneziawg.exe"] = metadata.EmbeddedAWG
	result["xray.exe"] = metadata.EmbeddedXray
	result["sing-box.exe"] = metadata.EmbeddedSingBox
	return result
}

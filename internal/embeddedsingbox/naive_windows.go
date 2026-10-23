//go:build windows && amd64 && with_naive_outbound && with_purego

package embeddedsingbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"os"
	"path/filepath"
)

func registerNaive(out *outbound.Registry) { naive.RegisterOutbound(out) }

// Never search the service's working directory or PATH for executable code.
// The hash matches the DLL in the checksum-verified, pinned Go dependency.
func loadNaive() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(executable), "libcronet.dll")
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("NaiveProxy component unavailable")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != protocol.NaiveLibrarySHA256 {
		return errors.New("NaiveProxy component checksum mismatch")
	}
	return cronet.LoadLibrary(path)
}

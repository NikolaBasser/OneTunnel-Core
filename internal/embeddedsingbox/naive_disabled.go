//go:build !windows || !amd64 || !with_naive_outbound || !with_purego

package embeddedsingbox

import (
	"errors"
	"github.com/sagernet/sing-box/adapter/outbound"
)

func registerNaive(out *outbound.Registry) {}
func loadNaive() error                     { return errors.New("NaiveProxy is not included in this build") }

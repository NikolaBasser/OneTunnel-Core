//go:build windows && (!embeddedawg || !embeddedsingbox || !embeddedtun || !embeddedxray)

package platform

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"time"
)

func (r *Runtime) probeQuality(context.Context, control.Profile) (time.Duration, error) {
	return 0, errors.New("quality probing requires the full embedded core")
}

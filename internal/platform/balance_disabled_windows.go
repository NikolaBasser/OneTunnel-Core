//go:build windows && (!embeddedawg || !embeddedsingbox || !embeddedtun || !embeddedxray)

package platform

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

func (r *Runtime) startBalanceRouter(context.Context, *control.Balance, []byte, bool) (interface{ Close() error }, error) {
	return nil, errors.New("pool requires complete embedded bundle")
}

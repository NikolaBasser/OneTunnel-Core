package embeddedsingbox

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// This clock is private to the engine. No system clock API is used.
type privateClock struct {
	offset   atomic.Int64
	server   M.Socksaddr
	interval time.Duration
}

func (c *privateClock) TimeFunc() func() time.Time {
	return func() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }
}
func (c *privateClock) update(ctx context.Context) error {
	response, err := ntp.Exchange(ctx, N.SystemDialer, c.server)
	if err != nil {
		return errors.New("embedded time synchronization failed")
	}
	if err = response.Validate(); err != nil {
		return errors.New("invalid embedded time response")
	}
	c.offset.Store(int64(response.ClockOffset))
	return nil
}
func startClock(ctx context.Context, options *option.NTPOptions) (*privateClock, error) {
	// Our runtime resolves the peer before starting an engine. Do not accept
	// extra dialer behaviour or write_to_system through this narrow boundary.
	if options == nil || !options.Enabled {
		return nil, nil
	}
	if options.WriteToSystem {
		return nil, errors.New("system clock writes forbidden")
	}
	if !reflect.DeepEqual(options.DialerOptions, option.DialerOptions{}) {
		return nil, errors.New("unsupported embedded time dialer")
	}
	if _, err := netip.ParseAddr(options.Server); err != nil {
		return nil, errors.New("embedded time server must be resolved")
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 30 * time.Minute
	}
	if interval < time.Minute {
		return nil, errors.New("invalid embedded time interval")
	}
	c := &privateClock{server: options.ServerOptions.Build(), interval: interval}
	if err := c.update(ctx); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *privateClock) run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.update(ctx)
		}
	}
}

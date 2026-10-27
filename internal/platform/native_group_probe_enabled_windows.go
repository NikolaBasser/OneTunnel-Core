//go:build windows && embeddedawg

package platform

import (
	"context"
	"errors"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/embeddedawg"
)

func nativeGroupDNSProbe(ctx context.Context, source string, kind int) (bool, *int64, error) {
	plan, err := embeddedawg.Parse(source, kind, false)
	if err != nil {
		return false, nil, errors.New("Invalid native configuration.")
	}
	target, ok := plan.ProbeDNSAddress()
	if !ok {
		return false, nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	resolver := &bootstrapResolver{cache: map[string]string{}, secure: true, forceSecure: true}
	if inherited, ok := ctx.Value(bootstrapKey{}).(*bootstrapResolver); ok && inherited != nil {
		resolver.secureLookup = inherited.secureLookup
	}
	ctx = context.WithValue(ctx, bootstrapKey{}, resolver)
	if err = resolveNativePlanEndpoints(ctx, plan); err != nil {
		return true, nil, errors.New("Encrypted native endpoint bootstrap failed.")
	}
	plan.UseEphemeralListenPort()
	if err = ctx.Err(); err != nil {
		return true, nil, errors.New("Native DNS check cancelled.")
	}
	transport, err := startNativeUserspaceTransport(plan)
	if err != nil {
		return true, nil, errors.New("Native userspace transport startup failed.")
	}
	defer transport.Close()
	latency, err := transport.ProbeDNS(ctx, target)
	if err != nil {
		return true, nil, errors.New("The tunneled native DNS check failed.")
	}
	milliseconds := latency.Milliseconds()
	return true, &milliseconds, nil
}

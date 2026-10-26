package platform

import (
	"context"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

func (r *Runtime) bootstrapContext(ctx context.Context, profile *control.Profile) context.Context {
	force := r.forceSecureBootstrap || profile != nil && !protocol.NetworkOptionsEmpty(profile.Network)
	resolver := &bootstrapResolver{cache: r.bootstrapIPs, secure: force || r.retrying && r.lock.needed(), forceSecure: force, attempt: r.retry.attempt}
	// Trusted internal callbacks keep endpoint and clock tests network-free.
	if inherited, ok := ctx.Value(bootstrapKey{}).(*bootstrapResolver); ok && inherited != nil {
		resolver.secureLookup = inherited.secureLookup
		resolver.systemLookup = inherited.systemLookup
	}
	return context.WithValue(ctx, bootstrapKey{}, resolver)
}

# OneTunnel Core

Go networking core for OneTunnel, independent of desktop and mobile interfaces.

The core owns protocol handling, profile import, subscription parsing, configuration
planning and connection coordination. Native adapters own operating-system integration.
The Windows runtime embeds Xray, sing-box and AmneziaWG in the Go service.

The Windows user host manages saved subscriptions with manual refresh, an explicit
change preview and one-time Apply/Cancel tokens. Preview never writes the profile
store; intervening changes require a fresh review. Provider-reported usage and
expiry are optional metadata, not connection or entitlement guarantees.

The Windows user host also provides a read-only `diagnostics.report` command.
It returns formatted JSON with bundled profile-host identity, platform, protocol
counts and package engine availability hints. It excludes credentials, profile
names, server addresses, subscription URLs, paths and raw errors. It does not
query the installed service or test connectivity, traffic protection or leaks.

The Windows user host persists optional favorite profile IDs and projects library
views in stored, name or protocol order. Filtering and sorting return profile IDs
without credentials and never reorder persisted profiles or fallback candidates.
Favorites follow stable IDs across edits/subscription updates and are pruned when
profiles disappear. An already-applied favorite choice does not rewrite storage.

Windows group management lists local groups, renames them without merging,
deletes a reviewed group snapshot and persists expand/collapse-all state.
Renames move subscription metadata and retain profile IDs and favorite choices.
Rename/delete require the current store revision token; stale requests are rejected.
These operations never query a subscription or change system networking.

## Protocols

AmneziaWG, WireGuard, VLESS, SOCKS5, Hysteria2, Shadowsocks, HTTP CONNECT/HTTPS proxy,
Trojan, TUIC, AnyTLS and NaiveProxy. VLESS transport support depends on the selected engine
and server configuration. Configuration support is distinct from runtime availability.

## Platform support

| Target | Portable Go API | Native VPN runtime |
| --- | --- | --- |
| Windows x64 | Available | Implemented; service, TUN and WFP protection |
| Windows ARM64 | Foundation | Not available; native dependencies remain unverified |
| Linux amd64 / arm64 | Foundation | Not implemented |
| Android arm64 / amd64 | Foundation | Not implemented |
| iOS arm64 | Foundation | Not implemented |

The portable API does not configure routes, change DNS, unlock protection or store profiles
in plaintext. Non-Windows adapters must implement their native tunnel, socket, lifecycle,
secure-storage and traffic-protection integration. Windows protection semantics are not
automatically available on other systems.

## Go API

```go
import "github.com/NikolaBasser/OneTunnel-Core/sdk"

profile, err := sdk.Parse("Example", "socks5://127.0.0.1:1080", nil)
```

The `sdk` package exposes validated imports, subscription parsing/merge, local configuration
plans, target capabilities and the existing controller/backend contract. A controller requires
an explicit adapter. Local plans are not validated cross-platform full-device tunnel plans.
This typed Go API is not yet a Kotlin/Swift binding, AAR or XCFramework.

Private module access requires suitable GitHub credentials and Go private-module configuration.
The [Windows application](https://github.com/NikolaBasser/OneTunnel-Windows) consumes an exact
clean core revision through its tracked reference rather than a moving branch.

## Build and verification

[BUILD.txt](BUILD.txt) describes the standalone Windows x64 bundle and required toolchain.
The source tree and core CI do not require WPF, .NET or a Windows application checkout.
CI tests the portable API on Linux and the full embedded build on Windows, with separate
foundation library compilation checks for additional targets.

Mobile library compilation does not establish working VPN connections. Android integration
requires [VpnService](https://developer.android.com/develop/connectivity/vpn); iOS integration
requires [Network Extension](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider).
Actual Apple application/framework builds require the appropriate Apple toolchain; see
[Go Mobile](https://go.dev/wiki/Mobile).

## Security and legal notices

The Windows user-mode profile host and privileged service retain separate trust boundaries.
The service authenticates its owner and maintains fail-closed recovery. Profile storage uses
Windows DPAPI; no cross-platform storage replacement is implied by the public Go API.

See [security policy](.github/SECURITY.md), [third-party notices](THIRD-PARTY-NOTICES.txt),
`go.mod`, `go.sum` and the dependency notices included in generated bundles. Preserve upstream
licenses and applicable source-distribution obligations. No additional project-wide license
is granted by this README.

Group check results can be sorted by full check duration and filtered by outcome.
An explicit best-result action selects a successful network check without connecting.
WireGuard/AmneziaWG configuration-only checks are excluded. Results are kept only
in user-host memory, become stale after storage changes, and can be cleared.
The duration includes engine startup, HTTPS probing, and cleanup; it is not ping.

Selected-profile organization supports local copies and manual-group moves.
Copies preserve protocol and transport/reliability options, receive a new ID and
start without a favorite mark. Subscription profiles can be copied to manual
groups; subscription members and managed destination groups cannot be moved.
Both actions require the reviewed storage snapshot and never start a connection.

Proxy profiles can store encrypted DNS and explicit split routing preferences for
whole-device mode. Ordered domain, domain-suffix, IP/subnet and executable-path
rules choose proxy, direct or reject; unmatched traffic stays proxied. Direct rules
are intentional exceptions to VPN routing, not an automatic LAN bypass. Custom
DoH/DoT uses a literal resolver IP, verified TLS identity and proxy detour. Upstream
server-name bootstrap uses the fixed encrypted infrastructure path, separately
from the custom tunneled resolver. Native AWG/WG retain imported DNS/AllowedIPs;
new policies and local proxy mode are incompatible and rejected. A matching new
service build is required; an old strict service refuses unsupported fields.

Portable backups use password-derived authenticated encryption and include profile,
network, favorite, group and subscription settings. Restore previews a complete
library replacement and requires explicit confirmation; enabled subscription
schedules are restored only with a separate opt-in. Runtime/protection state and
machine-specific consent are excluded. Existing backup files are never overwritten.
Optional per-subscription schedules run only while the user app is open, default
off, wait their configured interval and prepare a review instead of applying it.
Tray profile selection uses the Go projection and never starts a connection.

Shared-TUN proxy policies support up to eight additional encrypted resolvers and
64 ordered exact/suffix domain DNS rules. Resolver indices select verified-TLS
DoH/DoT endpoints routed through the proxy; the default resolver remains final.
An opt-in LAN exception sends only RFC1918 IPv4 and IPv6 ULA directly after
explicit user rules. It defaults off, does not exclude OS routes, and never
removes persistent traffic protection. Native AWG/WG remain configuration-driven.

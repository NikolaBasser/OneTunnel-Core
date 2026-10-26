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
An explicit best-result action selects a successful HTTPS network check without connecting.
WireGuard/AmneziaWG DNS-only and configuration-only checks are excluded. Results are kept only
in user-host memory, become stale after storage changes, and can be cleared.
The duration includes engine startup, the HTTPS or tunneled DNS probe, and cleanup; it is not ping.

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
from the custom tunneled resolver. Native AWG/WG with empty preferences retain imported DNS/AllowedIPs;
nonempty full-device policies use the shared TUN; local mode is rejected. A matching new
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
removes persistent traffic protection. Native AWG/WG without network preferences remain configuration-driven.

Connection statistics come from the embedded engine and reset for each successful
connection attempt, including reconnect/fallback. Local-proxy payload includes
connection checks. Whole-device proxy totals count TUN payload and fast-flow
packet bytes; legacy native AWG/WG totals are transport counters. Rates are unavailable
until two samples exist. These are not provider billing counters. Older services
without statistics remain supported and show no fabricated totals. Diagnostics
classify typed failures by bounded stage/category; unsupported authentication
causes remain unknown rather than guessing from log text.

Windows user settings provide off-by-default auto-connect with separate trusted
and public network permissions (unknown is public), an explicit profile/mode,
five-second category debounce and at most three failed starts per category cycle.
Manual Disconnect inhibits automatic starts until off/on or a new user session.
The user app must be open. Startup registration is a separate current-user Run
entry using a validated local installation path; it never enables auto-connect.

System proxy activation is explicit and limited to the authenticated local mixed
listener. It preserves exact typed user values in a DPAPI journal before writes,
requires an acknowledged detached watchdog, and restores only unchanged values
OneTunnel owns. The watchdog handles owner death and three failed loopback checks.
PAC/auto-detection conflicts block activation. External changes are retained and
reported; machine WinHTTP is never modified. Closing the user host releases its
proxy lease without stopping the VPN service. Portable restore disables automatic
activation and excludes machine startup ownership.

Group checks report total check duration separately from successful HTTPS probe
latency. HTTPS latency excludes engine startup and cleanup and is not ICMP RTT.
Saved shared-TUN DNS/routing policies are validated, then left unapplied during
the local server check; infrastructure endpoint bootstrap stays encrypted.
Native WG/AWG group checks use the first eligible imported DNS address through the
embedded userspace transport, preserving original peer AllowedIPs and local address
families. The fixed root SOA query uses no OS adapter or system DNS changes; endpoint
hostname bootstrap is encrypted without a system-resolver fallback. If no eligible
imported DNS target exists, or the build lacks embedded AWG, the result remains
configuration-only. Successful native DNS checks report separate DNS exchange latency,
which may include the initial handshake. They do not establish public internet access,
DNSSEC validation, or absence of DNS/IPv6 leaks, and are excluded from HTTPS-based
best-result selection. Saved shared-TUN policies are validated but not applied to this
imported-DNS probe.

AWG/WireGuard with nonempty full-device network preferences use the shared TUN
and an in-process AWG userspace transport. This mode supports TCP/UDP, preserves
peer AllowedIPs and replaces imported DNS with the configured encrypted policy
resolver. Uncovered destinations fail closed; direct routing requires an explicit
rule. ICMP is unavailable in this mode. Empty preferences preserve legacy native
routing, DNS and ICMP. Resolver addresses must fit peer coverage/address families.
Native policy health checks an uncached encrypted DNS exchange rather than public
HTTPS; success does not certify arbitrary public access or absence of leaks.
Shared-native statistics use TUN ingress scope, without adding AWG wire counters.
Offline Windows recovery is built separately with `build-recovery.ps1 -Output
<new-directory> -GoExecutable <go.exe> -Offline` when the toolchain/modules are
already cached. The resulting `OneTunnel.Recover.exe` runs without Go, .NET,
OneTunnel installation or internet. Default/`--scan` is read-only; explicit
`--recover-all --stop-service` stops OneTunnelCore and transactionally removes
validated OneTunnel persistent WFP objects. `--provider "{GUID}"` targets one
provider. Recovery does not require markers, journals or historical runtime roots
and never resets Windows Firewall or removes unrelated providers. It removes VPN
traffic protection; see recovery/RECOVERY.txt and recovery/AUDIT.txt for scope.

Normal Windows service Stop/Shutdown closes and drains the control pipe before
recovering the owned connection and removing its WFP policy. An unexpected exit
retains persistent traffic protection. Failed ownership checks or cleanup keep
protection and report a failure; the standalone offline recovery tool remains
available. A missing local marker never suppresses owner-scoped WFP cleanup.
Manual disconnect/recovery inhibits automatic connection for the current UI
session, including profile-worker restarts. A new UI session keeps the existing
opt-in automatic-connection behavior. The machine-local inhibition record is
excluded from portable backups; inability to confirm the UI session inhibits
automatic connection. Scoped IPv6 UDP destinations are rejected by the native
transport rather than silently losing their interface zone.

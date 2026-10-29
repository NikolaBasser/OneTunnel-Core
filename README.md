# OneTunnel Core

Go networking core for OneTunnel, independent of desktop and mobile interfaces.

The core owns protocol handling, profile import, subscription parsing, configuration
planning and connection coordination. Native adapters own operating-system integration.
The Windows runtime embeds Xray, sing-box and AmneziaWG in the Go service.

## Current source status — 2026-10-27

Quality selection, proxy chains, multiple WG/AWG peers and advanced DNS/MUX
controls are merged into `main`. This describes current source, not the older
published 0.1.0 Windows package or an automatically upgraded installed service.
The Windows application still selects an exact core revision.

| Area | Verified scope | Remaining limits |
| --- | --- | --- |
| DNS and routing | DoH/DoT/DoQ/DoH3, domain resolver rules, FakeIP, bounded/disabled cache; TLS rejection, proxy outage and real-address CIDR checks. DoH3/FakeIP also pass actual OS TUN with IPv4/IPv6. | No blanket certification of every application, DNS channel or provider. |
| Multiplexing | Shadowsocks/Trojan h2mux/smux/yamux, padding and connection/stream policies; 24 live fixture combinations, concurrent HTTP, UDP and broken-session recovery. VLESS Xray XUDP and UDP443 policies pass. | Server support and valid transport combinations are required. |
| Proxy chains | Two/three Shadowsocks UDP hops; actual three-hop OS TUN, IPv4/IPv6, 512/4096-byte payloads and each-hop outage/recovery. | Other protocol/topology combinations are not exhaustively tested. |
| Multiple native peers | Two-peer WG/AWG native/shared OS interfaces, IPv4/IPv6 TCP/UDP, failure isolation, recovery and counters; AWG 3.1 regression. | Up to eight peers can be configured; live acceptance covers two. |
| Quality selection | Proxy, shared TUN and native WG/AWG; policy-respecting HTTPS measurements, switching and outage recovery. | Measures latency/reachability, not throughput; controlled peers do not certify arbitrary providers. |
| Windows automation | Genuine interactive login starts and connects the app in proxy mode; actual WPF activation launches the production proxy watchdog and owner loss restores WinINET settings. | Whole-device login autoconnect, physical sleep/Wi-Fi and other launch contexts remain separate. |
| UDP-TUN startup | One cold start after reboot and 20 repeated start/stop cycles pass; safety-only WFP tracing finds no unfinished calls. | The original isolated timeout has no established cause: [#24](https://github.com/NikolaBasser/OneTunnel-Core/issues/24). |
| Hardware coverage | Dedicated Windows Server 2025 x64 VM; separate earlier bounded primary-PC LAN acceptance. | Windows ARM64 execution and physical hardware coverage: [#25](https://github.com/NikolaBasser/OneTunnel-Core/issues/25). |

Latest dedicated-VM regression: **323 top-level tests across eight packages**.
The companion Windows application passed **215 isolated session0 WPF assertions**;
interactive hotkey blocks were explicitly skipped in that run. New-control visual
layout and interactive hotkeys are tracked in
[Windows #26](https://github.com/NikolaBasser/OneTunnel-Windows/issues/26).
See the [DNS/MUX acceptance record](docs/DNS-MUX-ACCEPTANCE-2026-10-27.txt).

[Core main CI](https://github.com/NikolaBasser/OneTunnel-Core/actions/runs/40531976406)
and [full Windows pinned-core integration](https://github.com/NikolaBasser/OneTunnel-Windows/actions/runs/40531199702)
passed. Portable Linux ARM64 CI and standalone recovery cross-compilation do not
establish a working Windows ARM64 VPN runtime. Test VM recovery left no owned
test WFP objects, tunnel adapters or recovery tasks; the service was running idle.

## Profile management

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
DoH/DoT/DoQ/DoH3 use literal resolver IPs, verified TLS identity and proxy detours. Upstream
server-name bootstrap uses the fixed encrypted infrastructure path, separately
from the custom tunneled resolver. Native AWG/WG with empty preferences retain imported DNS/AllowedIPs;
nonempty full-device policies use the shared TUN; local mode is rejected. A matching new
service build is required; an old strict service refuses unsupported fields.
Whole-device startup refreshes the interface snapshot before becoming ready so
executable-path rules apply to the first TUN connection.

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
DoH/DoT/DoQ/DoH3 endpoints routed through the proxy; explicit domain rules precede
optional FakeIP and the default resolver remains final.
An opt-in LAN exception sends only RFC1918 IPv4 and IPv6 ULA directly after
explicit user rules. It defaults off, does not exclude OS routes, and never
removes persistent traffic protection. Connected private subnets on the default
uplink receive more-specific TUN routes so explicit reject rules still apply to
LAN traffic. Host/point-to-point prefixes and subnets overlapping the TUN address
ranges are excluded; other interfaces and more-specific physical routes are not
covered by this discovery. Native AWG/WG without network preferences remain
configuration-driven.

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

Windows acceptance tests exercise real registry APIs and DPAPI under exclusively
created test keys, including typed restoration, external edits, partial-write
rollback and loopback-listener loss. They never activate the user's system proxy
or notify WinINET. Separate dedicated-VM acceptance covers real WinINET
switching and production detached-watchdog restoration.
Opt-in dedicated-server acceptance additionally covers real WinINET activation,
production watcher recovery after listener/owner loss, startup registration and
Windows network-category transitions. These tests require explicit build tags
and host guards; they do not run in the default suite. Category-controller tests
use synthetic session/timing inputs. Separate interactive VM acceptance confirms
actual Windows logon and proxy-only automatic connection plus normal Explorer
UI-to-watchdog launch. Scheduled-task launching is not established by that result;
physical sleep and whole-device login autoconnect remain unverified.

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

Advanced policy snapshots accept up to eight additional engine-native proxy
targets and sixteen inline rule sets (4096 members per set, 8192 total). A target
contains `Name`, `Protocol` and an explicit `Source` snapshot; sources remain in
the encrypted profile store and portable encrypted backups. Ordinary list and
operation responses redact target sources. Explicit network-editor requests
include them, so treat advanced editor text as credentials.

Rules retain first-match order. `Kind` may also be `port`, `network` or `rule-set`;
optional `Port`, `Network` and absolute Windows `Process` predicates are combined
with AND. Set members (`domain`, `domain-suffix`, `cidr`) use OR. `Outbound` selects
a named target for a `proxy` rule. Port values are single ports or closed ranges,
and network values are `tcp`/`udp`. References and limits are validated before
network mutation. Targets requiring another Xray instance or native OS tunnel
are rejected; primary profile engine support is unchanged. Sets are portable
inline snapshots, without automatic background remote fetching or runtime filesystem references.

Loyalsoldier imports support [v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
(`geosite.dat`, `geoip.dat`). `network.rules.import`
accepts `NetworkInput` plus `RuleImport` (`Format`, `Category`, `Name`, `Action`,
`Path`, `Download`, `Replace`) and returns a **draft**, record count and source
SHA-256. Formats are `geosite` and `geoip`.
Downloads are explicit and restricted to the official release branches; local
files are also supported. The importer never saves or changes a connection.
New set rules append last; replacement requires `Replace` and preserves all
existing rule actions, conditions and ordering. Saving remains a separate action.

GeoSite exact/suffix/substring/RE2 expressions and one positive boolean attribute
(`google@cn`) retain their matching semantics. GeoIP covers IPv4 and IPv6.
Inverse GeoIP entries are rejected explicitly. Clash imports and downloads have
been removed. Existing snapshots remain usable; retired origin metadata becomes
a local snapshot requiring a geosite/geoip source before it can be refreshed.
Unfetched retired origins are discarded without changing existing packet rules.
No rules are silently dropped or truncated. Source files are limited to 128 MiB each (256 MiB per paired refresh);
compact `RuleSets[].Data.Snapshot` gzip/base64 snapshots have bounded decoding
(16 MiB, 500,000 entries, at most 256 RE2 expressions per set). Encoded snapshots
total at most 3.5 MiB and the complete network policy at most 4 MiB. Existing
inline `Members` limits remain unchanged. Snapshots travel inside encrypted
profiles/backups and require no network access during connection startup.
Manual reimport refreshes a set; there is no background update scheduler.
The Windows user host exposes mutually exclusive routing modes `preset`, `custom`
and `none` through `NetworkInput.RoutingMode`, `PresetRulesText` and
`CustomRulesText`. Separate encrypted per-profile banks survive mode changes,
duplication, subscription refresh by stable profile ID and portable backups.
Only the selected bank is copied into `Profile.Network` and reaches the service;
inactive banks are omitted from ordinary presentation metadata. `none` clears
split rules/targets/sets while retaining separate DNS and LAN preferences.
Legacy manual/mixed policies migrate to custom; plain imported-set policies to
preset; empty policies to none. Existing callers omitting RoutingMode retain the
legacy RulesText behavior. Changes apply after explicit save and reconnect.
The preset editor stores an ordered `PresetConfigText` catalog with each set's
official source format, category and action. `network.presets.configure/remove`
only change a draft; `network.presets.refresh` atomically refreshes all configured
sources, reuses downloads of the same DAT file, and leaves the previous draft
intact if any source fails. Newly configured sets must be refreshed before an
active preset policy is saved. Source files total at most 96 MiB per refresh and
the complete operation is bounded to 110 seconds. Legacy sets lacking origin
metadata require choosing their source before they can be refreshed.
`network.rules.append` validates and appends a `PolicyRule` to a caller-supplied
draft, preserving all other rules, targets and sets. The Windows process picker
supplies exact executable paths, never executes the selected file.
The explicit `none` mode now disables direct LAN exceptions as well: all captured
traffic uses the selected VPN/proxy. The LAN preference is retained for other
modes. This does not change the scope of local-proxy capture or peer AllowedIPs.
Do not apply upstream China-oriented `direct` lists as a universal routing preset.

The existing desktop rules editor accepts either legacy pipe-separated lines or
a strict JSON object containing `Rules`, `Targets` and `RuleSets`. For example:

```json
{"Targets":[{"Name":"work","Protocol":3,"Source":"socks5://127.0.0.1:1080"}],"RuleSets":[{"Name":"sites","Members":[{"Kind":"domain-suffix","Value":"example.com"}]}],"Rules":[{"Kind":"rule-set","Value":"sites","Action":"proxy","Outbound":"work","Network":"tcp","Port":"443"}]}
```

SDK `AnalyzeNetwork` reports identical shadowed matches; `ExplainRoute` predicts
first-match routing using supplied destination/process metadata. User-host
commands `network.analyze` and `network.explain` accept a profile `ID`; the latter
also accepts `PolicyQuery` (`Domain`, `IP`, `Process`, `Network`, `Port`). These APIs
do not open sockets, resolve names or return target credentials. Predictions are
explicitly marked `PredictionOnly`; missing required metadata returns `unknown`.
Port 53 is reserved for the configured TUN DNS policy. Predictions do not certify
the observed OS route, reachability or absence of leaks.

AmneziaWG imports preserve AWG 3.1 header protection, content-padding ranges,
handshake/rekey/keepalive ranges, random trailers and cookie settings through the
embedded device UAPI. Nonzero header keys require all four packet padding sizes
to be at least twelve bytes. WireGuard rejects these AWG-only fields.

Completed proxy group checks retain an in-memory quality history for the current
profile-host session: up to eight checks per profile within thirty minutes, capped
at 256 profiles. The result view reports successful checks and measured HTTPS
median/minimum/maximum latency separately from total check duration. Native DNS,
configuration-only and successful checks without an HTTPS timing do not enter
this history. Configuration changes reset that profile's history; cancelled or
stale batches add nothing. `group.results.clear` with `ClearQuality: true` clears
both results and history. This is a measurement foundation; it does not perform
background probing, automatic quality selection or active-session switching.

Profiles can opt into service-owned proxy quality selection with
`Reliability.AutoSelect`, together with `AutoReconnect` and `UseFallbacks`.
The selected server starts immediately. Every twenty seconds the service checks
its HTTPS health and one compatible backup with an isolated proxy engine.
Only the last three successful HTTPS timings (within ten minutes) qualify;
selection uses their median, a minimum improvement of 25% and 50 ms, two winning
measurements and a two-minute minimum hold. Switching uses the existing bounded
retry path and verifies HTTPS before promotion. Failures invalidate quality
history, and ordinary outage fallback remains available. Stop cancels probes.
Up to eight backups are visited in order; larger groups take longer to qualify.

Quality selection supports proxy, full-device TUN and WG/AWG, preserving saved
DNS/routing policy. It measures HTTPS latency and reachability, not throughput.
A switch creates a new connection/statistics session. Proxy-only quality sessions
keep a stable loopback frontend until explicit stop or terminal failure, so an
existing explicit system-proxy lease survives reconnects. The frontend has no
direct fallback and closes old flows before replacing a backend.
The manual group-check history is separate from service quality decisions.

Quality probes never create OS adapters or alter routes. They retain configured DNS
and policy, bind outer transports to physical interfaces, and reject bypass paths
as proof of primary-server quality. Native probes use separate userspace peers;
reusing the active peer identity is prohibited to prevent WireGuard roaming.

Proxy policy targets support `Via` for bounded chains. An omitted value retains
an independent outbound. `"Via":"@primary"` sends that target through the selected
profile; a target name sends it through that named target. At most eight targets
are allowed; missing links, self-links and cycles are rejected before engine
startup. For example, this routes TCP through entry -> middle -> exit:

```json
{"Targets":[{"Name":"middle","Protocol":3,"Source":"socks5://middle.example:1080","Via":"@primary"},{"Name":"exit","Protocol":6,"Source":"http://exit.example:8080","Via":"middle"}],"Rules":[{"Kind":"network","Value":"tcp","Action":"proxy","Outbound":"exit"}]}
```

DNS keeps its existing configured resolver path through the primary profile;
this example does not change DNS to the exit. Each hop must support the requested
transport; HTTP chains provide TCP, and UDP requires UDP-capable hops throughout.
Additional hops use the existing engine-native target scope; standalone Xray or
native OS-tunnel targets are still rejected. Chain failure never substitutes an
independent direct transport. Quality probes can measure a policy chain only
when its transport dependency actually reaches the selected primary profile.

Native WG/AWG profiles accept up to eight peers. Each peer retains its own
endpoint, key, keepalive and AllowedIPs; duplicate public keys or identical
network prefixes are rejected. Nested prefixes use the engine's longest-prefix
selection. Full-device multi-peer profiles must explicitly provide IPv4 and,
when the interface has IPv6, IPv6 default routes plus DNS. Defaults are never
silently assigned to every peer. Single-peer full-device expansion is unchanged.
All peer endpoints must resolve and use the same physical uplink before startup;
multiple simultaneous physical uplinks are not supported. Diagnostic quality
probes reject an identity shared with any active peer to prevent roaming.

Dedicated Windows VM acceptance covers two- and three-hop Shadowsocks UDP
chains through compiled proxy ingress/routing policy, IPv4/IPv6 destinations,
each hop's outage and recovery. Three-hop UDP also passes through the actual
shared OS TUN, including 4096-byte payloads. Two-peer WG/AWG acceptance covers
native and shared OS interfaces, IPv4/IPv6 TCP/UDP, peer outage/recovery,
failure isolation and counters. AWG 3.1 additionally has a repeated userspace
multi-peer regression. Native interface wrappers expose aggregate encrypted
transport counters to the runtime; shared-TUN counters retain payload scope.
The eight-peer configuration limit is not an eight-peer live acceptance result.
One initial UDP-TUN startup reached the independent 80-second recovery deadline;
A later cold start after VM reboot and 20 repeated starts passed. WFP tracing in safety builds found no incomplete calls (26.5 ms maximum on the cold start, 59.3 ms across ten traced cycles). Ten additional cycles passed without tracing. The initial delay remains unexplained; these results are not a confirmed root-cause fix.

Profile DNS supports HTTPS, TLS, QUIC (`quic`) and HTTP/3 (`h3`). QUIC uses
port 853 by default; HTTP/3 uses port 443 and the same validated path format
as HTTPS. All resolvers retain the proxy detour and TLS name verification.
DoQ/DoH3 require a UDP-capable primary; HTTP/Naive primaries are rejected.
Optional `DNSCache` accepts `Disabled` and `Capacity` (128–65536, default 4096).
Omitting it retains the engine's previous defaults; no stale/never-expire cache
or disk persistence is enabled.

Optional `FakeIP` applies to A/AAAA queries in shared full-device TUN mode.
Explicit domain resolver rules retain precedence; other query types still reach
the real resolver. Mappings are memory-only and reset when the engine stops.
The router restores domains and resolves real addresses before IP/rule-set/LAN
matching so synthetic addresses cannot bypass IP reject rules. Internal endpoint
lookups use `remote-dns` explicitly rather than the FakeIP transport.

Transport settings retain legacy VLESS Xray MUX and add XUDP concurrency plus
UDP443 policy (`skip`, `allow`, `reject`; default remains `skip`). Shadowsocks
and Trojan support `h2mux`, `smux` and `yamux`, optional padding, a connection
count policy or a stream-count policy. With a positive connection count, the
stream limit is inactive and minimum streams controls connection reuse; with
zero connections, the stream limit applies and minimum streams must be zero.
Unsupported protocol/transport combinations are rejected before startup.

Dedicated VM tests cover encrypted DNS, cache hits/disable, TLS rejection,
proxy outage, FakeIP domain/IP rule preservation, multiplex stream sharing,
UDP payloads, broken-session recovery and all three XUDP UDP443 policies.
DoH3 and FakeIP additionally pass through the actual OS TUN. Startup tracing
is available only in explicitly tagged safety builds; production WFP policy
and permitted processes are unchanged.

`network.presets.recommended` downloads geosite.dat + geoip.dat as one atomic preset draft: advertising reject first, category-ru domains direct, RU IP ranges direct, default proxy. It replaces only the preset bank when explicitly saved; custom rules are separate.



The complete Windows bundle supports a shared per-connection server pool through
`Request.Balance` (`Mode`: best/balanced, `Best`: 1..member count, `Interval`:
15..300 seconds, `MaxRTT`: 100..10000 ms, `Members`: 2..8 credential snapshots).
Members may come from unrelated subscriptions/manual groups. Their individual
network policies and recovery settings are excluded; primary profile policy is
applied once by the outer router. Native WG/AWG use isolated userspace transports
and retain AllowedIPs/address families. Duplicate native peer identities fail
closed. Proxy transports are physically bound before the shared TUN starts.
TCP connections and UDP destination sessions stay on one member. New flows rank
recent HTTPS samples by median, spread and failures; balanced mode rotates the
best subset, with remaining eligible members retained as immediate reserves.
All-down never enables a direct fallback. Explicit primary direct/LAN rules still
apply. Node probes and restart are independent of subscription refresh; membership
is a fixed snapshot until reconnect. Established TCP cannot migrate after failure.
Limited-route native peers that cannot cover the common probe remain explicitly
unmeasured, use only covered destinations, and retry failed dials after cooldown.
State.BalanceStatus distinguishes confirmed probes from unmeasured candidates.
The profile host persists comparable `UserSettings.Balance` values; deleting a
selected member disables the saved pool rather than silently selecting another.

Automatic composition (`UserSettings.Balance.Manual=false`, the default) snapshots
the whole library at connection start. `Request.Balance.Automatic` accepts up to
4096 candidates within the existing frame limit. Over 20 seconds, at most 16
temporary engines probe concurrently; each full round precedes the next. Ranking
uses median HTTPS delay, spread and failed-response ratio. At least two successful
samples are required; up to eight measured members remain, with temporary engines
closed before the live pool starts. The HTTPS address is securely resolved once
per pool, so servers share the same measurement target. Restricted native peers
without probe coverage and duplicate native peer aliases are excluded from
automatic composition. Manual composition retains the explicit 2–8 member list.
No measured member means connection failure, with no direct fallback. Automatic
membership is refreshed on the next connection, not during established flows.

Geodata downloads use the authenticated active service's local SOCKS endpoint
when available. Retries and official GitHub release-asset fallback retain that
route; they never fall back directly after a proxy error. Only HTTPS redirects
to GitHub asset hosts are accepted, TLS validation and the 128 MiB limit remain.
Provider category errors include the category and underlying failure while
leaving the previous policy draft intact.

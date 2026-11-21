# Cloudflare WARP and Tailscale on the backup-WAN modem (4.1.2)

Network › WARP and Network › Tailscale replace the CLI-only `warp` helper, the
ROOter `luci-app-go-wireguard` page and the old status-only Tailscale view. The
daemon code is in `crates/cellcored/src/vpn/`.

## What gets installed

| Piece | Where | Notes |
|---|---|---|
| WARP account (consumer) | `/etc/cellcore/vpn/wgcf-account.toml`, `wgcf-profile.conf` (0600, dir 0700) | written by `wgcf`, forced to 0600 after every run |
| WARP state, Zero Trust enrollment | `/etc/cellcore/vpn/warp.json` (0600) | includes the Zero Trust private key and device API token |
| Interface | `network.warp` (`proto wireguard`), `network.warp_peer` (`wireguard_warp`) | `route_allowed_ips 0`, `fwmark 0x1000000`, `ipv6 0`, IPv4 /32 only |
| Firewall | `firewall.warp_zone` (input REJECT, output ACCEPT, forward REJECT, masq, mtu_fix), `firewall.warp_fwd` (lan → warp) | the forwarding only matters once routing mode is "Everything" |
| Routing | `ip -4 rule` priorities 1400–1415, table 51820 | owned by the daemon and rebuilt at start and every minute |

The `wan` interface, the main routing table, QCMAP's tables, mwan3 and the AT
channel are never written. The Route10 `status` contract reads `wan`/`wan_v6`
from ubus and the AT channel only, so its 17 keys are unchanged.

Secrets are write-only: no GET (session or token) returns a WireGuard private
key, the wgcf access token, a WARP+ license, a Zero Trust token or service
token, or a Tailscale auth key. The license goes to `wgcf` through
`WGCF_LICENSE_KEY` (environment, not argv). Zero Trust tokens go to `curl` in a
config on stdin. The Tailscale auth key is handed over as
`--auth-key=file:<0600 file>`, which is deleted right after. The audit log
redacts every field that is not on its allow-list (`licenseKey`, `teamToken`,
`clientId`, `clientSecret`, `authKey` are all redacted; tests assert it).

## Routing policy

Three modes, selected in the UI:

| Mode | Steered into WARP | Typed confirmation |
|---|---|---|
| Off | nothing | – |
| This modem only (default once used) | traffic the modem itself originates (`iif lo`) | – |
| Everything, including Route10 | modem traffic plus everything forwarded from the LAN bridge (`iif br-lan`) | `ROUTE LAN VIA WARP`, with the latency / egress IP / CGNAT-QoS / port-forward warning |

Rule block (`pref` 1400 by default):

```
1400  fwmark 0x1000000/0x1000000 goto 1415   # the tunnel's own UDP and the daemon's health probes
1401  to 10.0.0.0/8      goto 1415          # carrier DNS lives here
1402  to 172.16.0.0/12   goto 1415
1403  to 192.168.0.0/16  goto 1415          # LAN, Route10, the UI
1404  to 100.64.0.0/10   goto 1415          # CGNAT and the tailnet
1405  to 169.254.0.0/16  goto 1415
1406  to 192.0.0.0/24    goto 1415          # T-Mobile CLAT (464XLAT)
1407  to 127.0.0.0/8     goto 1415
1408  to 224.0.0.0/3     goto 1415          # multicast / broadcast
1410  iif lo     lookup 51820
1411  iif br-lan lookup 51820                # "Everything" only
1415  nop                                    # goto target; normal processing continues
```

* The priorities sit after tailscale-tiny's rules (1310–1370 with mwan3; its
  own UDP is caught at 1310 by fwmark 0x80000) and before mwan3's fwmark rules
  (2001+). Excluded traffic jumps to the `nop` and is then routed exactly as
  without WARP.
* The tunnel's UDP carries `fwmark 0x1000000` (netifd `fwmark` option), so it
  can never route into itself. Bit 24 is outside mwan3's `0x3F00` mask and
  tailscale's `0xff0000` mask.
* LinkWatch / latency ICMP sets the same mark while a mode is active, so
  modem-recovery decisions keep measuring the cellular link. The public-IP
  check (`curl --interface rmnet…`) and the Ookla speedtest (`--interface`) bind
  to rmnet for the same reason. With routing Off none of this changes.
* Reverse-path filtering on `warp` is set to loose (2) when the route is
  installed; replies arrive on the tunnel while the main table points at rmnet.

### Fail-back (never a blackhole)

Table 51820 contains exactly one route, `default dev warp`, and only while the
tunnel is proven healthy. A rule whose table has no matching route falls
through to the next rule, so an empty table means the normal cellular path.

* Device gone (ifdown, netifd failure): the kernel removes the route with the
  device. Fail-back is immediate.
* Device up but peer silent: the monitor (every 5 s) reads
  `wg show warp latest-handshakes`. A handshake older than 180 s withdraws the
  route (`ip route flush table 51820`). WireGuard rekeys every 120 s while
  keepalives flow, so a healthy session never gets that old. Worst case is about
  3 minutes of loss before fail-back.
* Return: needs a handshake fresher than 150 s (hysteresis). The tunnel's own
  packets keep using cellular (fwmark), so it can re-handshake while traffic is
  on cellular.
* Every transition emits a `vpn` event (warning when mode is "Everything" or
  failover is active), which reaches the notifier like other events.
* There is deliberately no kill switch: on a backup WAN, connectivity beats
  egress consistency.

Tests that prove this (`cargo test vpn`): `policy::tests::*` (rule plan,
idempotent diff, hysteresis, route actions) and
`vpn::tests::policy_modes_and_failback_never_blackhole`, which drives the
real HTTP routes against a stateful `ip`/`wg` mock. It checks that the route is
held back before the first handshake, installed on a handshake, withdrawn
when the peer goes silent (rules stay), not restored by a stale handshake,
restored by a fresh one, and dropped when the device goes down in "Everything"
mode. It also checks that the main table and `network.wan` are never touched
and that no `unreachable`/`blackhole` route is ever created.

### Failover awareness

`POST /api/v1/vpn/warp/policy`, `/connection` and `/remove`, and
`/api/v1/vpn/tailscale/settings` (only when it changes `exitNode`) are failover-
guarded. While Route10 is failing over through the modem they answer 409
`failover_active` unless `force:true` is sent (the UI asks first). The status
endpoint shows a warning when "Everything" is active during a failover.
WARP "Everything" and a Tailscale exit node exclude each other, because both
claim the default route.

## Consumer WARP (Free / WARP+)

`wgcf register --accept-tos` → `wgcf generate` → install. WARP+ applies with
`wgcf update` and the key in `WGCF_LICENSE_KEY`. The format is checked first:
three groups of 8 alphanumerics. "Show quota and devices" runs `wgcf status`,
which makes a network call, so it is not polled.

## Zero Trust (Teams): choice and trade-offs

**Chosen: WireGuard registration against the WARP client API with a
Cloudflare-issued enrollment token, done natively by the daemon (curl + `wg`).**

| Option | Verdict |
|---|---|
| Official `warp-cli` / Cloudflare One client (documented, supports service tokens via `mdm.xml`) | Not available: glibc/systemd builds only, no musl/OpenWrt. WARP Connector and Mesh connectors have the same limit. |
| **Client-API registration (wgcf-teams / warp.sh style) → kernel WireGuard** | **Chosen.** No new binary, kernel WireGuard on the SDX75, same interface/policy code as consumer WARP. The enrollment *input* is documented: Cloudflare's manual-deployment guide tells headless users to copy `com.cloudflare.warp://<team>.cloudflareaccess.com/auth?token=…` from the success page. Only the API call that consumes it is undocumented. |
| MASQUE client (`usque`) | Kept as a fallback (see below). Userspace Go + TUN (slower on this CPU, a ~10 MB binary to package), and the same undocumented API plus an undocumented protocol. |
| Cloudflare Tunnel (`cloudflared`) | Documented and on OpenWrt, but it publishes inbound services. It does not give the modem a Zero Trust egress identity, so it does not answer this need. |

Enrollment inputs (both write-only):

1. **Team token (recommended).** Open `https://<team>.cloudflareaccess.com/warp`,
   log in, and paste the `com.cloudflare.warp://…` link (or the bare token).
   Tokens expire quickly and are single-use.
2. **Service token (headless, best effort).** Client ID and Secret. The daemon
   presents them to `https://<team>.cloudflareaccess.com/warp` and reads the
   token from the success page. The device enrollment policy must have a
   Service Auth rule for that token. Cloudflare documents service-token
   enrollment only for its own client, so this path is the least certain one
   and needs a live test.

Org-side requirements:

* The device profile that matches this device must use the **WireGuard** tunnel
  protocol. New orgs default to MASQUE, and a MASQUE-only profile returns no
  WireGuard peer. The daemon then refuses with a message pointing here.
* Cloudflare also assigns 3 reserved bytes (`client_id`) per device. The kernel
  module cannot put them in WireGuard headers. Community reports say most orgs
  still accept the tunnel, but this is the main live-test item. If the handshake
  never completes, the MASQUE fallback is the answer.

### What breaks if Cloudflare changes the API

Everything API-specific is in `vpn/teams.rs`: `API_BASE` (`/v0a2483`),
`CLIENT_HEADERS` (client version string), `registration_body`,
`parse_registration`. Failure modes and what the owner sees:

| Change | Effect | Fix |
|---|---|---|
| API version path retired | enrollment returns an error, existing tunnels keep working (WireGuard needs no API) | bump `API_BASE` |
| client-version header rejected | same as above | bump `CLIENT_HEADERS` |
| response shape changes | "Cloudflare's answer has no WireGuard peer / device id"; nothing installed | adjust `parse_registration` (fixture `fixtures/teams_reg.json`) |
| WireGuard dropped for Zero Trust (MASQUE-only) | new enrollments refused; existing ones stop handshaking. **Routing fails back to cellular automatically.** | switch to the usque package |
| reserved bytes enforced | no handshake; fail-back to cellular | usque (it sends them) |
| `/warp` page stops embedding the token for service tokens | service-token path errors; the team-token path still works | none needed |

Consumer WARP has the same class of risk through `wgcf`. It is updated from the feed (Network › WARP › packages).

## Tailscale (tailscale-tiny)

* Install / update `tailscale-tiny` from the feed through a detached opkg job
  (own session, own log, result written by the script, like OTA).
* Start / stop / restart, enable at boot (`/etc/init.d/tailscale`).
* Sign in with an approval link (interactive) or a pre-auth key. The tiny
  build omits the IPN bus, so `tailscale up` returns at once and the daemon
  polls `status` for the link or `Running`. `up --reset` is used and the
  mirrored settings are re-applied right after.
* Settings are mirrored in `/etc/config/tailscale` `settings` (same schema as
  luci-app-tailscale-community-tiny) and applied with `tailscale set`, sending only
  the changed flags. If the CLI refuses, the uci mirror is restored.
* Typed confirmations: `USE EXIT NODE` (with the backup-WAN warning),
  `SHIELDS UP`, `LOG OUT TAILSCALE`.
* Unsupported flags: the flag list comes from `tailscale set --help`. A
  setting whose flag is missing returns 422 and is greyed out in the UI.
  Known omissions of the tiny build: DNS (`ts_omit_dns`), web client, OAuth
  client secrets as auth keys (`ts_omit_oauthkey`, rejected up front),
  tailnet lock, Taildrive, client auto-update.
* The login URL is not shown to `read` API tokens (opening it adopts the node).

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/vpn/warp` | status, tunnel stats, policy, live rules in our range, warnings |
| GET | `/api/v1/vpn/warp/account` | `wgcf status` (network call) or the Zero Trust summary |
| POST | `/api/v1/vpn/warp/register` | `{confirm?}`; 428 `REPLACE WARP ACCOUNT` if any account exists |
| POST | `/api/v1/vpn/warp/license` | `{licenseKey}` |
| POST | `/api/v1/vpn/warp/teams` | `{team, teamToken}` or `{team, clientId, clientSecret}`, `{confirm?}` |
| POST | `/api/v1/vpn/warp/install` | `{mtu?, keepalive?, endpoint?, autostart?, lanDevice?}` |
| POST | `/api/v1/vpn/warp/connection` | `{action: up\|down}` (failover-guarded) |
| POST | `/api/v1/vpn/warp/policy` | `{mode: off\|modem\|lan, confirm?, force?}` (failover-guarded; `lan` needs `ROUTE LAN VIA WARP`) |
| POST | `/api/v1/vpn/warp/remove` | `{confirm: "REMOVE WARP", deleteAccount?}` (failover-guarded) |
| GET | `/api/v1/vpn/tailscale` | package, service, status, peers, settings, capabilities, warnings |
| POST | `/api/v1/vpn/tailscale/service` | `{action: start\|stop\|restart\|enable\|disable}` |
| POST | `/api/v1/vpn/tailscale/login` | `{authKey?}` |
| POST | `/api/v1/vpn/tailscale/logout` | `{confirm: "LOG OUT TAILSCALE"}` |
| POST | `/api/v1/vpn/tailscale/settings` | any of `hostname, acceptRoutes, advertiseRoutes[], advertiseExitNode, exitNode, ssh, shieldsUp`, `{confirm?, force?}` |
| GET / POST | `/api/v1/vpn/packages` | list / `{package, action: install\|upgrade}`; allow-list: tailscale-tiny, wgcf, wireguard-tools, kmod-wireguard |

`read` tokens can call every GET above (no secrets in any of them, and no Tailscale login link).
`rw` tokens can call everything. All POSTs are in the audit log.

## Needs a live test on hardware

1. **Rule priorities vs QCMAP.** QCMAP's own `ip rule`s (tables 5/301) were
   not visible in the fixtures. If one at a priority below 1400 matches
   `iif br-lan`, "Everything" silently does nothing. That fails safe (traffic
   stays on cellular), but it must be checked with `ip -4 rule show`; the
   rules are also listed in GET `/api/v1/vpn/warp`.
2. **IPA hardware offload.** Qualcomm IPA may offload established forwarded
   flows past the kernel's routing decision. Run a LAN client in "Everything"
   mode and confirm that its egress IP is Cloudflare's
   (`curl https://www.cloudflare.com/cdn-cgi/trace` shows `warp=on`).
3. **netifd on QSDK.** Does `ubus call network reload` bring up
   `proto wireguard` (with `fwmark`) without disturbing QCMAP-managed
   interfaces?
4. **Fail-back timing.** Block UDP 2408 upstream (or point the endpoint at a
   black hole) and time the return to cellular (expected 180–185 s). Then
   unblock it and time the return to WARP.
5. **MTU over CLAT.** The outer path is IPv6 via 464XLAT (main route
   `mtu lock 1472`). 1280 is the safe default. Measure whether 1360 works.
6. **Zero Trust:** WireGuard profile, reserved bytes accepted, and the
   service-token path.
7. **LinkWatch under "This modem only":** with the tunnel blackholed, LinkWatch
   must still report the cellular path healthy (bypass mark) and must not
   trigger modem recovery.
8. **tailscale-tiny** `up --reset --auth-key=file:` and `set` flags on 1.104.7,
   and the luci `tailscale-settings` init script re-applying the same uci on
   boot.

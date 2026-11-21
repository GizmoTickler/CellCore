# API tokens

Long-lived bearer tokens for scripts and monitoring. Create, list and revoke them in
System › Security & Units › API tokens. Doing that needs a signed-in browser; a token can never manage tokens.

```
Authorization: Bearer qmt_<16 hex id>_<64 hex secret>
```

The daemon stores only `sha256(token)` in `/etc/cellcore/api_tokens.json` (mode 0600), and the
plaintext is shown once at creation. A token can have an optional expiry of 1–3650 days. The daemon tracks when each token was last used and from which IP, and a revoke takes effect
immediately. After 10 failed token attempts from one IP within a minute, that IP gets HTTP 429 for the rest of the minute. Tokens do not need the
`X-QM-CSRF` header (they are not cookie-borne). Cookie sessions still do.

## Types

| Type | Can | Cannot |
|---|---|---|
| `read` (monitoring) | Every `GET` route a session can read: status, radio, metrics (`/api/v1/metrics`), events, admin read views, OTA status | Any mutation. The WebSocket. Secret-revealing reads: audit log, `/api/v1/modem/secrets`, `/api/v1/admin/backup/download` (contains `/etc/shadow`), SMS inbox, root crontab, config export with `?identifiers=1` |
| `rw` (full ops) | Everything a signed-in browser can do: admin (cron, software, services, processes, firewall, SSH access, DHCP, backups/restore), OTA, reboot, radio, IMEI edit, AT console | Token management, root password change, the WebSocket |

VPN (`/api/v1/vpn/...`, see `docs/WARP.md`): `read` tokens see WARP and Tailscale status, tunnel statistics, peers and
package state. No VPN read ever returns a key, token, license or auth key, and the Tailscale login link is withheld from
`read` tokens because opening it adopts the node into the opener's tailnet. Every VPN mutation needs `rw`.

The two session-only exceptions (token management and the password change) are a hard list in
`tokens.rs` (`is_session_only`) and cannot be overridden by any other rule.

Safety interlocks apply to `rw` tokens exactly as to a browser, as payload fields:

- dangerous AT lines need `"confirm": true`;
- typed confirmations (HTTP 428 with a `confirm` phrase) must be echoed back;
- the failover guard needs `"force": true` (or `?force=true`) for disruptive actions while the
  modem carries failover traffic;
- a config restore is refused outright while failover is active.

## Audit

Every mutating request made with a token is recorded in the audit log under the token's name. Token reads are
counted per token: count, errors, last route, peer and time. Repeated failed token logins are aggregated per peer.
Both counters are kept apart from the main log, so a polling dashboard cannot flush it.

## Migration

Tokens created by the first release stored a `scopes` list. On load they fail closed: any recognised legacy scope
(`read`, `metrics`, `ops`) becomes `read`, and unrecognised entries are dropped. Migration never grants `rw`; issue
a read-write token deliberately. The file is rewritten in the new format.

The config export's `identifiers` flag is enforced inside the export handler on the decoded query, so a read-only
token is refused SIM identifiers however the flag is encoded.

# CellCore

<div align="center">
  <h3>Static Rust cellular gateway appliance (<code>cellcored</code>) &amp; React 19 dashboard for Quectel SDX75 (RM551E-GL / RM55x) modems</h3>
  <p>Zero-CGI, single-binary Rust daemon with native QRTR/QMI/Netlink data plane, Visual Tower Finder &amp; Polar Aim Radar, Prometheus observability, and a self-contained signed <code>opkg</code> feed.</p>
</div>

---

## Architecture

**CellCore** replaces legacy shell CGIs, `socat` AT bridges, `websocat` sidecars, and `sms-tool` with a single static `aarch64-unknown-linux-musl` Rust binary (`/usr/sbin/cellcored`) paired with a precompressed (Brotli + Gzip) React 19 + TypeScript + Tailwind CSS v4 SPA:

- **HTTP/2 + TLS Web & API Server (`:443` / `:80` redirect) + Native ACME:** Serves the dashboard SPA, `/api/v1/*` REST API, `/api/v1/ws` WebSocket stream, scoped Bearer API tokens, CSRF protection, structured audit log, automatic ECDSA P-256 self-signed bootstrap cert, and built-in **RFC 8555 ACME** (**Let's Encrypt**, **ZeroSSL**, **Google Public CA**, Custom CA; **HTTP-01** + **9 native DNS-01 providers** incl. Cloudflare, Route 53, DigitalOcean, Hetzner, Porkbun, DuckDNS, deSEC, RFC 2136 TSIG, Webhook) with zero-downtime TLS hot-reload.
- **Interactive AT Actor (`/dev/smd11`):** Serialized AT command multiplexer with priority preemption, latency histograms, health tracking, and automatic recovery.
- **Native Rust Data Plane (`docs/DATAPLANE.md`):**
  - `coexist` mode observes QRTR (`AF_QIPCRTR`) QMI services (`DMS`, `NAS`, `UIM`, `WDA`, `WDS`) and `RTNETLINK` alongside the vendor connection manager.
  - `native` mode manages `rmnet` child links on `rmnet_ipa0`, WDS dual-stack IPv4/IPv6 bearers, reversible `mwan3`/`fw4` NAT handoff, hardware IPAv5 IP Passthrough, post-boot `performance` CPU governor + `autosleep=off` self-heal, and `r10-modem-ctl` active-WAN reporting.
- **Visual Tower Finder & Polar Aim Radar (`Radio → Antenna Aim`):**
  - Keyless **Esri Street & Satellite** sightline map with 1:1 pixel Timing Advance distance ring, great-circle bearing vector, and ±10° target cone.
  - Phone magnetometer compass + 360° polar RSRP sweep heatmap (`10°` petals), `Keep 4×4 RX Awake` 64 KiB keep-alive burst, dual cross-pol skew tracks (`RX0/RX1`, `RX2/RX3`), per-CC DL/UL MIMO indicators, and `Open on CellMapper` / OpenCelliD / beaconDB integration.
- **Prometheus Observability (`/api/v1/metrics`):**
  - Zero-AT-overhead scrape exposing `cellcore_*` metrics (per-chain RSRP/SINR/RSRQ, serving cell, per-CC bandwidth & DL/UL MIMO layers, Timing Advance, filtered sysfs thermals, dataplane/IPA offload clock, AT latency histogram, data usage, failover state).
- **Multi-Call CLI Symlinks:**
  - `/usr/bin/cellctl` (`status`, `verify`, `upgrade`, `at`, `menu`), `/usr/bin/menu`, `/usr/sbin/r10-modem-ctl`, `/usr/sbin/modem-ctl` (plus `/usr/bin/quecctl` compatibility alias).

---

## Quick Install (SDX75 / SDXPINN)

### Brand-New Out-of-the-Box Modem (Clean-Room Reversible Bootstrap)
```bash
# Dry-run preflight first (no changes written)
./bootstrap.sh --adb --dry-run

# Full bootstrap over USB ADB (installs reversible Rust overlay, SSH key, signed feed & CellCore)
./bootstrap.sh --adb --ssh-key ~/.ssh/id_ed25519.pub

# 1-command reversible rollback back to stock factory rootfs
./bootstrap.sh --adb --revert --purge
```
See **[`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md)** for complete out-of-the-box instructions, offline `--ipk` installs, and rollback details.

### Modem With Existing Writable Overlay
```sh
curl -fsSL https://raw.githubusercontent.com/GizmoTickler/CellCore/main/install.sh | sh
```

Or add the signed feed manually in `/etc/opkg/customfeeds.conf`:

```text
src/gz CellCore-repo https://raw.githubusercontent.com/GizmoTickler/CellCore/main/feed
```

Then run:

```sh
opkg update && opkg install sdxpinn-cellcore
```

Existing `sdxpinn-quecmanager-beta` installations migrate automatically on install: `/etc/quecmanager/*` → `/etc/cellcore/`, `/etc/config/quecmanager` → `/etc/config/cellcore`, and `/etc/config/quecprofiles` → `/etc/config/cellprofiles` (preserving API tokens, Tower Finder home/key/pins, dataplane mode, SIM profiles, and usage history).

---

## Development & Single-Command Release

```bash
# Rust unit tests & lint
cargo test
cargo clippy --all-targets -- -D warnings

# Frontend typecheck + precompressed production build
npm ci && npm run build

# Build, test, cross-compile (aarch64-musl), package .ipk, update & sign feed/
./scripts/release.sh 1.0.0-1
# Optional: also roll out staged upgrade (mgateway0 -> mgateway1)
./scripts/release.sh 1.0.0-1 --deploy
```

---

## License & Acknowledgments

Released under the [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`). Clean-room Rust + TypeScript implementation inspired by concepts from `QuecManager-JS` (MIT) and the SDX75 OpenWrt modem community.

# Changelog

## 1.1.0 — Native ACME Certificates, Clean-Room Reversible Bootstrap & Auto TLS

- **Built-in RFC 8555 ACME Client (`System → Security & Units`):**
  - Issuers: **Let's Encrypt** (Production & Staging), **ZeroSSL** (EAB), **Google Public CA / GTS** (Production & Staging, EAB), and **Custom ACME Directory** URL.
  - Challenges: Built-in **HTTP-01** responder on port `:80` (works even with HTTP→HTTPS redirect enabled) + native **DNS-01** solvers for **Cloudflare**, **AWS Route 53** (pure-Rust SigV4), **DigitalOcean**, **Hetzner**, **Porkbun**, **DuckDNS**, **deSEC**, **RFC 2136 / Knot DNS (HMAC-SHA256 TSIG)**, and **Custom HTTPS Webhook**.
  - Automatic background renewal every 6 h with atomic `/etc/ssl/acme/{fullchain,privkey}.pem` writes and zero-downtime TLS hot-reload.
- **Clean-Room Reversible Factory Bootstrap (`cellcored overlay`, `bootstrap.sh`, `docs/BOOTSTRAP.md`):**
  - Pure-Rust early-boot `overlayfs` + `pivot_root` (`START=03` / `START=13`) with dry-run preflight, free-space guard, factory config backup, and 1-command reversible rollback (`--revert [--purge]`).
- **Automatic Self-Signed ECDSA P-256 TLS Fallback:** Generates a 10-year SAN cert at `/etc/cellcore/tls/` via `atomic_write` if a factory modem has no cert yet.

## 1.0.0 — Initial Standalone CellCore Release

- Detached from legacy `QuecManager-JS` fork into standalone clean-room Rust + TypeScript repository (`GizmoTickler/CellCore`).
- Renamed daemon, CLI, config paths, UCI configs, opkg package, and Prometheus metrics to `cellcored`, `cellctl`, `/etc/cellcore`, `/etc/config/cellcore`, `/etc/config/cellprofiles`, `sdxpinn-cellcore`, and `cellcore_*`.
- Added automatic zero-loss migration from `sdxpinn-quecmanager-beta` (`/etc/quecmanager` → `/etc/cellcore`, UCI configs, API tokens, Tower Finder pins/keys, dataplane config, SIM profiles).
- Self-contained signed `feed/` carrying `sdxpinn-cellcore` and essential companion tools (`ookla-speedtest`, `kmod-wireguard`, `tailscale-tiny`, `wgcf`), plus single-command `./scripts/release.sh` and one-liner `install.sh`.
- Includes full native QRTR/QMI/Netlink dataplane, Visual Tower Finder & Polar Aim Radar (keyless Esri Street + Satellite tiles), `Keep 4×4 RX Awake` 64 KiB DL burst, clean sysfs thermal filtering, post-boot `performance` + `autosleep=off` self-heal, and full `cellcore_*` Prometheus metrics.

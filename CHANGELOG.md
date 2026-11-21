# Changelog

## 1.0.0 — Initial Standalone CellCore Release

- Detached from legacy `QuecManager-JS` fork into standalone clean-room Rust + TypeScript repository (`GizmoTickler/CellCore`).
- Renamed daemon, CLI, config paths, UCI configs, opkg package, and Prometheus metrics to `cellcored`, `cellctl`, `/etc/cellcore`, `/etc/config/cellcore`, `/etc/config/cellprofiles`, `sdxpinn-cellcore`, and `cellcore_*`.
- Added automatic zero-loss migration from `sdxpinn-quecmanager-beta` (`/etc/quecmanager` → `/etc/cellcore`, UCI configs, API tokens, Tower Finder pins/keys, dataplane config, SIM profiles).
- Self-contained signed `feed/` carrying `sdxpinn-cellcore` and essential companion tools (`ookla-speedtest`, `kmod-wireguard`, `tailscale-tiny`, `wgcf`), plus single-command `./scripts/release.sh` and one-liner `install.sh`.
- Includes full native QRTR/QMI/Netlink dataplane, Visual Tower Finder & Polar Aim Radar (keyless Esri Street + Satellite tiles), `Keep 4×4 RX Awake` 64 KiB DL burst, clean sysfs thermal filtering, post-boot `performance` + `autosleep=off` self-heal, and full `cellcore_*` Prometheus metrics.

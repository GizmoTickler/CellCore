# Changelog

## 1.2.0 — SDX75 Deep PHY/QoS/Security Telemetry, QMI DSP Services & Native Rust Speedtest

- **SDX75 Live PHY, QoS & Air-Interface Security Telemetry (`Cellular → Bands & Tuning`):**
  - Auto-enables non-disruptive SDX75 baseband telemetry counters on boot (`nr5g_tx_pwr`, `nr5g_pathloss`, `nr5g_dlMCS`, `nr5g_ulMCS`, `ssb_beam_id`, `used_algo`, `nr5g_mimo_layers`, `c_rnti`, `rrc_state`, `csi_ctrl`).
  - Live **UL TX Power + HPUE Headroom** (`PUSCH`/`PUCCH`/`Max`/`SRS` dBm), **RF Pathloss (dB)**, **DL/UL Modulation & MCS** (`QPSK`..`256QAM`), **5G NR SSB Beamforming Array** (serving + neighbor beams with PCI/RSRP/RSRQ), **Carrier 5QI / QoS Priority** & **Provisioned Session-AMBR Caps**, **RRC State + C-RNTI**, and **Air-Cipher Security Audit** (`NEA0`..`NEA3`, alerting on null cipher only when RRC is `CONNECTED`).
  - Fixed `nr5g_mimo_layers` parsing for 2-field `enabled,layers` responses.
- **Frequency Steering, Handover Hysteresis & Dual-SIM Switching:**
  - Added writable **Preferred 5G NR-ARFCN List** (`nr5g_pref_freq_list`, up to 32 ARFCNs), **Multi-ARFCN 5G Lock** (`nr5g_earfcn_lock`, up to 32 ARFCNs), **Event A3 Handover Offset** (`event_a3_offset`), and **Dual-SIM Slot Switching** (`AT+QUIMSLOT=1|2` + `AT+QSIMDET?` detection status).
- **Direct SDX75 QRTR QMI DSP Services (`GET /api/v1/cellular/dsp`):**
  - Native QMI `TMD` (`0x18`) Thermal Mitigation Device throttling monitor, QMI `SAR` (`0x11`) RF backoff state, sub-ms QMI `NAS` signal probe, and QRTR DSP service discovery (`LOC`, `WMS`, `TIME`, `ANT_SWITCH`, `SMART_TX`).
- **Pure-Rust Multi-Stream Speedtest & Loaded Bufferbloat Engine (`Diagnostics → Speedtest`):**
  - Built-in 4-stream HTTP/1.1 keep-alive Cloudflare Anycast speedtest (`engine: "native" | "auto" | "ookla"`) with concurrent idle + DL-loaded + UL-loaded RTT probing and IQM bufferbloat grading (`A+`..`F`), automatically falling back when `ookla-speedtest` is absent.
- **New `cellcore_*` Prometheus Metrics & Cortex-A55 `-Os` Tuning:**
  - Exported `cellcore_nr5g_tx_power_dbm`, `cellcore_nr5g_tx_headroom_db`, `cellcore_nr5g_pathloss_db`, `cellcore_nr5g_dl_mcs`, `cellcore_nr5g_ul_mcs`, `cellcore_nr5g_mimo_layers`, `cellcore_nr5g_ssb_beam_id`, `cellcore_nr5g_five_qi`, `cellcore_nr5g_ambr_mbps`, `cellcore_air_cipher_null`, `cellcore_rrc_state_code`, `cellcore_qmi_tmd_throttling`, `cellcore_qmi_tmd_mitigation_level`, and `cellcore_qmi_sar_state`.
  - Switched release profile to `opt-level = "s"` for smaller Cortex-A55 I-cache footprint.

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

# Changelog

## 1.3.0 — Dataplane Offloads & IRQ Pinning, Security Posture Hardening & Live Speedtest CA

- **Performance & Dataplane Tuning (`dataplane.rs`, `radio_tuning.rs`, `.cargo/config.toml`):**
  - Enabled `rx-gro-list` and `rx-udp-gro-forwarding` offloads on `eth0` and active `rmnet_data*` plus `gro_flush_timeout=20000` & `napi_defer_hard_irqs=2` NAPI coalescing.
  - Pinned all `eth0-*` PCIe MSI IRQs onto CPUs `2–3` (isolated from modem `ipcc_0` on CPU 0 and Qualcomm `gsi/IPA` on CPU 1).
  - Enabled static-PIE ASLR (`-C relocation-model=pie`) alongside Cortex-A55 hardware ISA (`+aes,+sha2,+crc,+lse`).
  - Added 20 s in-memory cache on `GET /api/v1/cellular/tuning` (`?refresh=1` forces live AT read; `POST` invalidates immediately) for <10 ms Bands & Tuning page loads.
  - Guarded `r10-modem-ctl wan-restart` / `modem-reset` against invoking `ubus call network.interface.wan up/down` when the native dataplane is active so `netifd` never truncates `/tmp/resolv.conf.d/resolv.conf.auto`.
- **Carrier Aggregation Visibility During Speedtests (`telemetry.rs`, `SpeedtestView.tsx`):**
  - Boosted background RF polling to `1 s` during active speedtests and added a live **Carrier Aggregation & RF** bar inside the Speedtest view showing per-carrier bandwidth, MIMO layers, and real-time SCC `Dormant` → `Active` (`pcellState = 2`) transitions.
- **Security & Hardening Suite (`hardening.rs`, `SecurityPostureCard.tsx`, `http.rs`, `reconcile.rs`, `obs/metrics.rs`):**
  - Added `GET /api/v1/security/audit`, `POST /api/v1/security/harden`, `cellctl security <audit|harden>`, and the **Security Posture & Hardening** card under `System → Security & Units` (9 live checks + 1-click Dropbear LAN-only bind, kernel sysctls, 0600 secret permissions, and reversible USB gadget lockdown).
  - Enforced modern HTTP security headers: `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `Referrer-Policy: no-referrer`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy: same-origin`.
  - Switched frontend WebSocket auth to cookie-only (`HttpOnly; SameSite=Strict`) — no more session tokens in `?token=` URLs.
  - Added boot-time `rp_filter=2` & anti-redirect/source-route sysctls and exported `cellcore_tls_cert_days_remaining` + `cellcore_tls_cert_acme_active` Prometheus metrics.

## 1.2.1 — `cellctl acme` CLI, `DELETE /api/v1/system/acme` & Mobile Speedtest Polish

- **ACME CLI (`cellctl acme` & `cellcored acme`):**
  - Added `cellctl acme status [--json]`, `cellctl acme config [flags]` (issuer, email, domains, `dns-01`/`http-01`, EAB KID/HMAC, all 9 DNS providers + repeatable `--dns-cred KEY=VALUE`), `cellctl acme issue` (dispatches via daemon IPC so both `http-01` and `dns-01` work seamlessly from SSH), and `cellctl acme reset`.
  - Also wired `cellctl overlay` directly into `cellctl`.
- **ACME Reset API:** Added `DELETE /api/v1/system/acme` to remove `/etc/ssl/acme/{fullchain,privkey}.pem` and disable auto-renewal (reverting cleanly to self-signed TLS).
- **Mobile UI Polish:** Fixed text clipping on narrow mobile viewports in the Native Rust Cloudflare Speedtest description pill so it wraps cleanly without overflow.
- **Native Rust Speedtest Cellular Performance Upgrade:** Upgraded to 8 DL streams (`90 MB` continuous chunks, `2 MiB` `SO_RCVBUF`, `256 KiB` read buffer) + 6 UL streams (`16 MB` chunks, bounded `128 KiB` `SO_SNDBUF`), `measId` + HTTP `429` backoff handling to prevent Cloudflare rate-limit valleys, 2 s slow-start warmup exclusion, and 1 s rolling sliding-window smoothing for clean cellular traces.

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

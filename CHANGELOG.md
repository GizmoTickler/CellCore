# Changelog

## 1.4.2 — UBIFS `postinst` `sync` Barrier & Standalone `S99dropbear-lan-watchdog`

- **UBIFS Crash-Safe Package Install (`packaging/sdxpinn-cellcore/CONTROL/postinst`):**
  - Added an explicit `sync` barrier before `/etc/init.d/cellcored restart` so OpenWrt UBIFS commits `/usr/sbin/cellcored` data blocks to NAND before daemon startup, preventing a power cut from replaying UBIFS to a 0-byte binary.
- **Standalone POSIX Dropbear Boot Safeguard (`scripts/etc/init.d/dropbear-lan-watchdog`, `hardening.rs`):**
  - Bundled and auto-enabled `/etc/init.d/dropbear-lan-watchdog` (`START=99`), an independent POSIX `/bin/sh` init script that starts Dropbear after `S11network` (and rolls back `Interface='lan'` if port 22 still fails to bind) even if `cellcored` is stopped or absent.

## 1.4.1 — Preserve Hardware IPAv5 / `ioss` Ring Config & Late `START=95` Init Ordering

- **Preserve Qualcomm IPAv5 + `ioss` Hardware Offload Ring Parameters (`dataplane.rs`, `netlink.rs`):**
  - Removed live `WDA_SET_DATA_FORMAT` (`dl_max_size=32768`), `rmnet_ipa0` `32768` parent MTU override, and `IFLA_RMNET_FLAGS` (`CKSUMV5`) mutations on SDX75 Embedded IPA endpoints (`rmnet_ipa0` + `r8125` `ioss`), preserving Qualcomm's boot-initialized IPA GSI ring sizes that faulted when mutated on an active hardware pipe.
  - Restored software-only `ethtool -K` GRO forwarding flags (`rx-gro-list on`, `rx-udp-gro-forwarding on`) and `smp_affinity_list` (`2-3`) so `r8125` + `ioss` DMA rings are never reset at runtime.
  - Scoped `conntrack` cleanup on WAN re-IP to `conntrack -D -q <old_wan_ip>` (only when a previous WAN IP rotates, never global `conntrack -F` on initial attach) so LAN SSH sessions are never dropped during upgrades.
  - Moved `/etc/init.d/cellcored` from `START=14` to `START=95` (`STOP=15`) so `network`, `dnsmasq`, and `dropbear` always start before `cellcored` on boot.

## 1.4.0 — Resiliency & Dead-Man's-Switch, QMAPv5/IRQ Dataplane Offloads, Proactive Alerts & Flash Longevity

- **Resiliency & Autonomous Self-Healing (`telemetry.rs`, `profiles.rs`, `smd.rs`, `ipc.rs`, `reconcile.rs`, `main.rs`):**
  - **Cell-Lock Dead-Man's-Switch (`180 s` default ON):** Automatically clears `common/5g`, `common/4g`, and `nr5g_earfcn_lock` in RAM when unregistered (`SEARCH`/`LIMSRV`) for 180 s while preserving configured cell locks on disk, then re-probes neighbor/SSB cells with `15m → 30m → 60m` exponential backoff during standby and automatically re-locks when the target PCI returns.
  - **Qualcomm `xbl_ramdump` Prevention:** Boot/60 s reconciler disables `/sys/module/qcom_dload_mode/parameters/download_mode` (`1 → 0`) and ensures `/sys/class/remoteproc/remoteproc0/recovery` is `enabled` so kernel/TrustZone faults warm-reboot in 3 s instead of halting in USB Sahara crash-dump mode.
  - **5-Stage LinkWatch Escalation Ladder:** Soft bearer reconnect → verified `CFUN=0 → CFUN=1` (with 3× `resp.ok` retry guard) → temporary cell-lock bypass → verified Dual-SIM failover (`QMI UIM` card-presence pre-check + `45 s` attach cooldown + automatic failback) → `15 m` periodic cooldown retry (`"cooldown"` instead of permanent `"paused"`), plus native IPv6 raw `ICMPv6` echo & `SO_BINDTODEVICE`.
  - **SIM-Swap ICCID Refresh & Boot Scheduler Leak Fix:** Immediate `ICCID`/`IMSI`/`MSISDN` refresh + profile sync on SIM slot switch; boot-time `QNWLOCK` reconciliation when `/tmp/cellcore/cell_lock_sched_engaged` is missing after power loss.
  - **`/dev/smd11` Self-Heal & Daemon Liveness Watchdog:** Reopens `/dev/smd11` (with `/dev/smd7` fallback) after 3 consecutive failed `QMRESYNC` probes; `cellcore-wdt` OS thread aborts for `procd` respawn if monotonic telemetry heartbeats stall `>180 s`.
- **Dataplane Offloads, QMAPv5, Dual-Stack MTU & CPU Isolation (`dataplane.rs`, `netlink.rs`, `qmi/wda.rs`, `reconcile.rs`, `DataPlaneView.tsx`):**
  - **QMAPv5 Checksum Offload & Aggregation:** Negotiates `QMAPv5` (`dl=64/32768`, `ul=16/16384`, flow control enabled, `32768` parent `rmnet_ipa0` MTU) and sets `IFLA_RMNET_FLAGS` (`INGRESS_DEAGGREGATION | INGRESS_MAP_COMMANDS | INGRESS_MAP_CKSUMV5 | EGRESS_MAP_CKSUMV5`).
  - **Dual-Stack `.min()` MTU & Symmetric MSS Clamping:** Uses `.min()` across IPv4/IPv6 WDS MTUs (`1280..=1500`) and clamps TCP MSS symmetrically on both ingress and egress across `nftables` (including IP Passthrough mode) and legacy `iptables`/`ip6tables`.
  - **CPU 2/3 IRQ Split & NAPI/TCP Tuning:** Alternates `eth0-*` PCIe MSI IRQs across CPU 2 (`4`) and CPU 3 (`8`) away from CPU 0 (`ipcc_0`) and CPU 1 (`gsi`/`IPA`), enables `gro_flush_timeout=20000` & `napi_defer_hard_irqs=2` on `rmnet_ipa0`, disables `rx-gro-list` while keeping `gro/gso/tso/rx-udp-gro-forwarding`, sets `tcp_notsent_lowat=131072`, and adds an opt-in **Qualcomm SFE Software Fastpath** toggle.
  - **QRTR SSR Storm Latch & Stale Conntrack Flush:** Collapses multi-service QRTR burst notifications into a single `ModemSsr` recovery, flushes stale `conntrack` entries on WAN IP change, and reloads `odhcpd` on IPv6 prefix rotation.
- **AT Chatter Reduction (>55%) & UBIFS `/etc` Flash Longevity (>95% Fewer Writes) (`telemetry.rs`, `tokens.rs`, `obs/mod.rs`, `auth.rs`, `http.rs`, `acme/mod.rs`):**
  - Combined `AT+QRSRP;+QRSRQ;+QSINR`, dropped redundant `AT+C5GREG?`, skipped `AT+CGCONTRDP` in Native mode and `lte_time_advance`/`lte_csi` on pure `NR5G-SA`, cached `AT+QSPN` per `(mcc, mnc)` and `AT+QMAP="SFE"`, and added `mode: "nr5g"` (`AT+QSCAN=2,1`) fast neighbor scans.
  - Moved 5-minute data-usage and API-token `lastUsedAt` writes to `/tmp/cellcore/` (`0600`), flushing `/etc/cellcore/` only every 6 h, on `≥50 MiB` delta, day rollover, or `SIGTERM`/reboot, with dirty-flag suppression on `obs_state.json`.
  - Monotonic `Instant` timers across LinkWatch, session/rate-limit stores (bounded at 64 sessions / 256 peers), failover detector, and profiles; pre-NTP (`1970`) guards on data-usage buckets and ACME renewal, plus automatic regeneration of `1970`-minted self-signed TLS certs once NTP syncs.
- **SDX75 Radio/DSP Telemetry & Proactive Prometheus Observability (`qmi/dsp.rs`, `radio_tuning.rs`, `obs/metrics.rs`, `obs/events.rs`, `OverviewPage.tsx`, `RadioTuningCard.tsx`):**
  - Reconnectable QRTR `Mutex` in `qmi/dsp.rs`, writable `SAR_RF_SET_STATE=0` (0 dB TX backoff lock), `nr5g_mimo` (`nr5gActiveRank`), `rrc_time_info`, fixed `overheat_ind` status semantic, EN-DC `NR5G` leg preference in `parse_mimo_signal`, and `PRX · TX0` / `DRX` / `MIMO · TX1` / `MIMO` port role badges on `RX0`–`RX3`.
  - Exported 16 new `cellcore_*` Prometheus metrics (`antenna_chain_present`, `antenna_active_chains`, `antenna_rsrp_spread_db`, `nr5g_csi_ri`, `nr5g_csi_cqi`, `nr5g_active_rank`, `ul_ca_active`, `ul_bandwidth_mhz`, `nsa_nr5g_rsrp_dbm`, `nsa_nr5g_sinr_db`, `speedtest_{dl,ul}_loaded_latency_ms`, `ipa_hardware_offload_pct`, `qrtr_ssr_total`, `cell_lock_active`, `cell_lock_bypassed`) and proactive events (`antenna_degraded`, `thermal_throttle`, `sar_backoff`, `air_cipher_null`, `modem_ssr`, `cell_lock_bypassed`), plus failover gating on `/api/v1/cellular/tuning`.

## 1.3.1 — Lockout-Proof Dropbear LAN-Only Hardening & RM551E-GL `<ARFCN>:<SCS>` Frequency Steering

- **Lockout-Proof Dropbear SSH LAN-Only Hardening (`hardening.rs`, `main.rs`):**
  - Fixed the OpenWrt `S11network` → `S19dropbear` `BOOT=1` skip race where setting `dropbear.@dropbear[0].Interface='lan'` could prevent Dropbear from starting on reboot because static `br-lan` fires `interface.up` before `S19dropbear` runs.
  - Added a post-boot **Dropbear Anti-Lockout Watchdog** (`t+12s` and `t+40s` after `cellcored` boot) that inspects `/proc/net/tcp` + `/proc/net/tcp6` on the configured SSH port; if Dropbear missed startup, it invokes `/etc/init.d/dropbear start` cleanly (without `BOOT=1`) so Dropbear binds strictly to the LAN IP, with automatic rollback to wildcard listening if it still fails to bind.
  - Hardened `bind_dropbear_lan_only()` (`POST /api/v1/security/harden` / `cellctl security harden dropbear-lan`) with a live LAN-IP pre-check and a post-restart listener verification + automatic rollback if port 22 fails to come back up.
  - Updated `check_dropbear_lan_only()` to verify both UCI `Interface='lan'` AND live `/proc/net/tcp*` listening state.
- **RM551E-GL `nr5g_pref_freq_list` & `nr5g_earfcn_lock` `<ARFCN>:<SCS>` Syntax (`radio_tuning.rs`, `RadioTuningCard.tsx`):**
  - Updated `AT+QNWCFG="nr5g_pref_freq_list"` and `AT+QNWCFG="nr5g_earfcn_lock"` writer & parser to use the real RM551E-GL colon-separated `<count>,<arfcn1>:<scs1>[:<arfcn2>:<scs2>...]` format (e.g. `1,501390:30` or `2,501390:30:521310:30`), with automatic 3GPP default SCS inference (`30` kHz for FR1 TDD, `15` kHz for FR1 FDD, `120` kHz for FR2) when `:scs` is omitted and full backward compatibility for numeric JSON inputs.
  - Gracefully handles RM551E-GL returning `ERROR` when clearing an already-unlocked `nr5g_earfcn_lock`/`nr5g_pref_freq_list` (`0`) by verifying readback state.

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

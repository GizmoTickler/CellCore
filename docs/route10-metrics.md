# Route10 → modem metrics (proposal)

**Status: proposal only. Nothing on Route10 has been changed.** Apply it
yourself if you want the modem's metrics next to Route10's in Prometheus.

## What the modem offers now

Two new `r10-modem-ctl` subcommands, both allowed by the existing forced
command (`command="/usr/sbin/r10-modem-ctl"` in the modem's
`authorized_keys`):

| Command | Output | Cost on the modem |
|---|---|---|
| `metrics` | Prometheus text exposition (format 0.0.4) | Read from cached daemon state. **No AT commands.** |
| `role active` / `role standby` | `result=ok role=<role> ttl_s=180` | None. Sets the failover hint. |

`status` keeps its 17 RF/WAN keys unchanged at steady state and appends `maintenance_pause=1` while antenna alignment, LinkWatch recovery, or cell-lock recovery is actively running so external watchdogs avoid overlapping resets.

`metrics` prints nothing on stdout when the daemon cannot answer (the reason
goes to stderr and the exit code is 1), so a failed fetch can never write an
error string into a `.prom` file.

The same text is served at `GET /api/v1/metrics` on the modem, authenticated by
either the web UI session or a scoped read-only API token (`Authorization: Bearer`).

## Proposed `cell-watchdog.sh` change

Route10 already polls `status` every 60 s over Dropbear inside the "Modem RF
Telemetry Poll" block, and `uhttpd` on `:9100` serves everything in
`/tmp/cellmon`. Fetch `metrics` in the same block and write it atomically
next to `watchdog.prom`:

```diff
 MDIR="/tmp/cellmon"
 PROM_FILE="$MDIR/watchdog.prom"
+MODEM_PROM="$MDIR/modem.prom"
 STATE_FILE="$MDIR/watchdog.state"
```

```diff
     # 4. Modem RF Telemetry Poll (every 60s when modem_lan_up=1 or flagged)
     if [ "$modem_lan_up" -eq 1 ]; then
         if [ "$need_rf_poll" -eq 1 ] || [ $((now_s - last_rf_poll)) -ge 60 ]; then
             status_out=$(modem_ssh status || true)
             ...
             last_rf_poll="$now_s"
             need_rf_poll=0
+
+            # Modem-side Prometheus metrics (cached state on the modem, no AT).
+            metrics_out=$(modem_ssh metrics 2>/dev/null || true)
+            case "$metrics_out" in
+                "# HELP cellcore_"*)
+                    printf "%s\n" "$metrics_out" > "${MODEM_PROM}.tmp" && mv "${MODEM_PROM}.tmp" "$MODEM_PROM"
+                    ;;
+                *)
+                    # Stale numbers are worse than none: let the scrape see the gap.
+                    rm -f "$MODEM_PROM"
+                    ;;
+            esac
         fi
     else
+        rm -f "$MODEM_PROM"
         modem_at_poll_ok=-1
```

Notes:

- The extra SSH round trip costs about a second per minute. `modem_ssh`
  already enforces the 25 s kill, and the modem answers `metrics` from memory.
- `/tmp/cellmon` is tmpfs, so this adds no flash writes on Route10.
- Exposition is around 10–14 KB (roughly 150 series).

### Scrape

Add a second path to the existing `:9100` job, or a new job (the instance
label is up to you):

```yaml
- job_name: mgateway1-modem
  metrics_path: /modem.prom
  static_configs:
    - targets: ["<route10-lan-ip>:9100"]
```

Note that the file is refreshed every 60 s. Scraping faster only returns the
same sample again.

### Optional: the failover hint

On its own the modem treats itself as "carrying failover traffic" once rmnet
throughput stays above a baseline (default 2 Mbit/s for 60 s, released after
5 min below half of it). Route10 can make this exact by sending a hint. A
fresh hint (within 180 s) always wins over the throughput guess:

```sh
# e.g. at the end of each 60 s RF poll, when Route10 knows which role it is in
if [ -f "$MDIR/failover_active" ]; then
    modem_ssh "role active" >/dev/null 2>&1 || true
else
    modem_ssh "role standby" >/dev/null 2>&1 || true
fi
```

How Route10 decides is up to you. Some options:

- a flag file you touch by hand during planned fiber work;
- a forwarded-bytes threshold on the SC01-facing interface;
- a check of the BGP session state.

While the modem is active it defers its own disruptive work: the scheduled
reboot, the cell-lock schedule, MBN/APN realignment, and LinkWatch CFUN
cycling and SIM switching. In the web UI / API, QSCAN, OTA upgrades, speedtests,
band/mode/cell locks, MBN changes, raw AT commands (`/api/v1/modem/at`), LAN
subnet changes (`/api/v1/network/lan`), dataplane reconfiguration/reconnect
(`/api/v1/dataplane/config`, `/api/v1/dataplane/reconnect`), and reboots require
explicit confirmation (`X-QM-Force: 1`).
**Route10's own `wan-restart` / `modem-reset` / `reboot` are never gated.**
They are logged as events and always run.

## Metric reference (CellCore v1.6.0)

All names are prefixed `cellcore_`. Labels are bounded.

| Metric | Type | Labels |
|---|---|---|
| `build_info` | gauge | `version` |
| `snapshot_age_seconds`, `cfun`, `registered` | gauge | – |
| `rsrp_dbm`, `rsrq_db`, `sinr_db` | gauge | `chain` (0–3) |
| `antenna_chain_present` | gauge | `chain` (0–3) |
| `antenna_active_chains`, `antenna_rsrp_spread_db` | gauge | – |
| `serving_cell_info` (=1) | gauge | `rat`, `band`, `pci`, `arfcn`, `duplex` |
| `serving_rsrp_dbm`, `serving_rsrq_db`, `serving_sinr_db`, `tx_power_dbm`, `nsa_nr5g_rsrp_dbm`, `nsa_nr5g_sinr_db` | gauge | – |
| `ca_components`, `ca_bandwidth_mhz`, `ul_ca_active`, `ul_bandwidth_mhz` | gauge | – |
| `ca_component_bandwidth_mhz`, `ca_component_dl_mimo_layers`, `ca_component_ul_mimo_layers` | gauge | `index`, `role`, `band` |
| `timing_advance` | gauge | `rat` (lte/nr) |
| `timing_advance_meters` | gauge | – |
| `temperature_celsius` | gauge | `sensor` |
| `at_channel_healthy`, `at_queue_depth`, `at_last_latency_seconds` | gauge | – |
| `at_commands_total` | counter | – |
| `at_failures_total` | counter | `kind` (error/timeout/preempted/io) |
| `at_latency_seconds` | histogram | `le` |
| `wan_throughput_bps` | gauge | `direction` |
| `data_cycle_bytes`, `data_today_bytes` | gauge | `direction` |
| `data_cycle_projected_bytes`, `data_cycle_days`, `data_cycle_days_elapsed`, `data_quota_bytes`, `data_cycle_used_ratio`, `standby_bytes_today` | gauge | – |
| `data_lifetime_bytes` | counter | `direction` |
| `ping_up`, `ping_latency_ms`, `ping_latency_avg_ms`, `ping_loss_ratio` | gauge | – |
| `quecwatch_enabled`, `quecwatch_retry`, `cell_lock_active`, `cell_lock_bypassed` | gauge | – |
| `quecwatch_state` (one-hot) | gauge | `state` (`idle`, `healthy`, `degraded`, `failing`, `recovering`, `cooldown`, `disabled`) |
| `speedtest_last_{timestamp_seconds,download_mbps,upload_mbps,ping_ms,jitter_ms}`, `speedtest_{dl,ul}_loaded_latency_ms` | gauge | – |
| `memory_bytes`, `flash_bytes` | gauge | `type` |
| `conntrack_entries`, `conntrack_max`, `device_uptime_seconds`, `wan_up`, `wan_session_uptime_seconds` (0 when down), `eth0_speed_mbps` | gauge | – |
| `wan_disconnects_total` (always emitted, even while WAN is down) | counter | – |
| `iface_{rx,tx}_{errors,drops}_total` | counter | `iface` |
| `process_resident_memory_bytes`, `process_open_fds` | gauge | – |
| `cloudflared_up`, `cloudflared_ha_connections` (when `cloudflared` is installed/running) | gauge | – |
| `events_total` | counter | `type` (27 fixed types) |
| `failover_active`, `failover_hint_fresh`, `failover_avg_bps`, `failover_baseline_bps`, `failover_episode_seconds`, `failover_episode_bytes` | gauge | – |
| `failover_source` (one-hot) | gauge | `source` (hint/throughput) |
| `failover_episodes_total` | counter | – |
| `notifications_{sent,failed}_total` | counter | `sink` (email/webhook/ntfy) |
| `notifications_suppressed_total` | counter | `reason` |
| `notifications_dropped_total` | counter | – |
| `dataplane_mode`, `dataplane_wds_connected`, `dataplane_ipa_clk_mhz`, `dataplane_tuning_warnings`, `ipa_hardware_offload_pct` | gauge | `mode` / `family` |
| `dataplane_indications_total`, `dataplane_netlink_updates_total`, `qrtr_ssr_total` | counter | – |
| `nr5g_csi_{ri,cqi}`, `nr5g_tx_power_dbm`, `nr5g_tx_headroom_db`, `nr5g_pathloss_db`, `nr5g_{dl,ul}_{mcs,mod_order}`, `nr5g_mimo_layers`, `nr5g_active_rank`, `nr5g_ssb_beam_id`, `nr5g_five_qi`, `nr5g_ambr_mbps`, `air_cipher_null`, `rrc_state_code`, `nr5g_{dl,ul}_bler_pct`, `lte_dl_bler_pct` | gauge | `channel` / `apn` / `qfi` / `direction` |
| `rrc_residency_seconds_total` | counter | `state` (`connected`, `idle`, `inactive`) |
| `qmi_tmd_throttling`, `qmi_tmd_mitigation_level`, `qmi_sar_state`, `tls_cert_acme_active`, `tls_cert_days_remaining` | gauge | `device` |

Counters reset when the daemon restarts (standard Prometheus counter
semantics). The exceptions are `data_lifetime_bytes` and
`failover_episodes_total`, which are persisted.

### Example alert rules

```yaml
- alert: BackupModemCarryingTraffic
  expr: cellcore_failover_active == 1
  for: 2m
- alert: BackupModemStandbyLeak
  expr: cellcore_standby_bytes_today > 200 * 1024 * 1024
- alert: BackupModemNotRegistered
  expr: cellcore_registered == 0
  for: 5m
- alert: BackupModemATChannelSlow
  expr: histogram_quantile(0.95, rate(cellcore_at_latency_seconds_bucket[15m])) > 2
```

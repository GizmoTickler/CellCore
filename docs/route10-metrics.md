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

`status` is unchanged (same 17 keys, fresh AT on every call).

`metrics` prints nothing on stdout when the daemon cannot answer (the reason
goes to stderr and the exit code is 1), so a failed fetch can never write an
error string into a `.prom` file.

The same text is served at `GET /api/v1/metrics` on the modem, behind the web
UI session for now. A scoped API token for scrapers is planned.

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
cycling and SIM switching. In the web UI, QSCAN, OTA upgrades, speedtests,
band, mode and cell locks, MBN changes and reboots need an explicit
confirmation.
**Route10's own `wan-restart` / `modem-reset` / `reboot` are never gated.**
They are logged as events and always run.

## Metric reference

All names are prefixed `cellcore_`. Labels are bounded.

| Metric | Type | Labels |
|---|---|---|
| `build_info` | gauge | `version` |
| `snapshot_age_seconds`, `cfun`, `registered` | gauge | – |
| `rsrp_dbm`, `rsrq_db`, `sinr_db` | gauge | `chain` (0–3) |
| `serving_cell_info` (=1) | gauge | `rat`, `band`, `pci`, `arfcn`, `state`, `duplex` |
| `serving_rsrp_dbm`, `serving_rsrq_db`, `serving_sinr_db`, `tx_power_dbm` | gauge | – |
| `ca_components`, `ca_bandwidth_mhz` | gauge | – |
| `ca_component_bandwidth_mhz` | gauge | `index`, `role`, `band` |
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
| `quecwatch_enabled`, `quecwatch_retry` | gauge | – |
| `quecwatch_state` (one-hot) | gauge | `state` |
| `speedtest_last_{timestamp_seconds,download_mbps,upload_mbps,ping_ms,jitter_ms}` | gauge | – |
| `memory_bytes`, `flash_bytes` | gauge | `type` |
| `conntrack_entries`, `conntrack_max`, `device_uptime_seconds`, `wan_up`, `wan_session_uptime_seconds` | gauge | – |
| `wan_disconnects_total` | counter | – |
| `events_total` | counter | `type` (20 fixed types) |
| `failover_active`, `failover_hint_fresh`, `failover_avg_bps`, `failover_baseline_bps`, `failover_episode_seconds`, `failover_episode_bytes` | gauge | – |
| `failover_source` (one-hot) | gauge | `source` (hint/throughput) |
| `failover_episodes_total` | counter | – |
| `notifications_{sent,failed}_total` | counter | `sink` (email/webhook/ntfy) |
| `notifications_suppressed_total` | counter | `reason` |
| `notifications_dropped_total` | counter | – |

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

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::{Mutex, mpsc},
};

use crate::{
    auth::now_secs,
    parsers::{
        clean_at_lines, mask_secret_id, merge_nr5g_mimo_layers, overlay_native_bearer,
        parse_3gpp_rel, parse_active_wwan, parse_carrier_aggregation, parse_mimo_signal,
        parse_nr5g_mimo_info, parse_nr5g_pathloss, parse_qspn_operator, parse_scalar_at_value,
        parse_serving_cell, parse_ssb_beam_id, parse_temp_sensors, parse_time_advance_for_rat,
        read_sysfs_thermals,
    },
    reconcile::current_usb_gadget_udc,
    smd::Priority,
    state::{
        AlertLogEntry, AppState, CarrierMimoLayer, DailyUsageEntry, MemoryTelemetry,
        MonthlyUsageEntry, PingPoint, SignalHistoryPoint, TrafficDirectionStats,
        TrafficHistoryPoint, TrafficInterfaceStats, UptimeTelemetry, format_now_hms,
        format_today_ymd, save_json_atomic,
    },
    uci::{run_cmd, uci_get_blocking},
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(|_| now_secs() * 1000)
}

static ALIGN_KEEP_AWAKE_MS: AtomicU64 = AtomicU64::new(0);
static ALIGN_KEEP_AWAKE_SEQ: AtomicU64 = AtomicU64::new(1);
static ALIGN_KEEP_AWAKE_INFLIGHT: AtomicBool = AtomicBool::new(false);
static ALIGN_BEAM_ID_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

const ALIGN_KEEP_AWAKE_INTERVAL_MS: u64 = 1800;
const ALIGN_KEEP_AWAKE_HOST: &str = "speed.cloudflare.com";
const ALIGN_KEEP_AWAKE_PORT: u16 = 80;
const ALIGN_KEEP_AWAKE_PATH: &str = "/__down?bytes=65536";
const ALIGN_KEEP_AWAKE_MAX_BODY: usize = 256 * 1024;

pub const DATA_USAGE_PATH: &str = "/etc/cellcore/data_usage.json";
pub const DATA_USAGE_TMP_PATH: &str = "/tmp/cellcore/signal_graphs/data_usage.json";
pub const DATA_USAGE_SNAPSHOT_FLUSH_SECS: u64 = 300;

pub fn spawn_background_tasks(state: AppState, mut rf_refresh_rx: mpsc::Receiver<()>) {
    // 1. RF snapshot & identity poller (fast 3s when UI/WS active, 15s when idle, plus on-demand trigger)
    let st_rf = state.clone();
    tokio::spawn(async move {
        let mut init_urcs = true;
        let mut last_history_sec = 0u64;
        loop {
            refresh_modem_snapshot(&st_rf, Priority::Telemetry, init_urcs).await;
            init_urcs = false;

            let now = now_secs();
            if now.saturating_sub(last_history_sec) >= 60 {
                last_history_sec = now;
                record_signal_history_point(&st_rf).await;
            }

            let wait_dur = if st_rf.ws_tx.receiver_count() > 0 {
                Duration::from_secs(3)
            } else {
                Duration::from_secs(15)
            };
            tokio::select! {
                _ = tokio::time::sleep(wait_dur) => {}
                Some(()) = rf_refresh_rx.recv() => {
                    while rf_refresh_rx.try_recv().is_ok() {}
                }
            }
        }
    });

    // 2. High-rate Antenna Alignment poller (400 ms only while active & WS client present)
    let st_align = state.clone();
    tokio::spawn(async move {
        let keep_awake_conn: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        loop {
            let (active, expired, ws_count, keep_awake) = {
                let a = st_align.antenna_align.read().await;
                (
                    a.active,
                    now_secs() >= a.expires_at,
                    st_align.ws_tx.receiver_count(),
                    a.keep_awake,
                )
            };
            if active {
                if expired || ws_count == 0 {
                    ALIGN_KEEP_AWAKE_MS.store(0, Ordering::Relaxed);
                    if let Ok(mut guard) = keep_awake_conn.try_lock() {
                        *guard = None;
                    }
                    let snap = {
                        let mut a = st_align.antenna_align.write().await;
                        a.active = false;
                        a.keep_awake = false;
                        a.clone()
                    };
                    st_align.broadcast_with(|| serde_json::json!({
                        "channel": "antenna_align",
                        "align": snap,
                    }));
                } else {
                    if keep_awake {
                        let now_millis = now_ms();
                        let last = ALIGN_KEEP_AWAKE_MS.load(Ordering::Relaxed);
                        if now_millis.saturating_sub(last) >= ALIGN_KEEP_AWAKE_INTERVAL_MS
                            && ALIGN_KEEP_AWAKE_INFLIGHT
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                                .is_ok()
                        {
                            ALIGN_KEEP_AWAKE_MS.store(now_millis, Ordering::Relaxed);
                            let fallback_host = {
                                let s = st_align.settings.read().await;
                                if s.ping_host.trim().is_empty() {
                                    "1.1.1.1".to_string()
                                } else {
                                    s.ping_host.clone()
                                }
                            };
                            let seq = (ALIGN_KEEP_AWAKE_SEQ
                                .fetch_add(1, Ordering::Relaxed) as u16)
                                .max(1);
                            let conn = keep_awake_conn.clone();
                            let st_burst = st_align.clone();
                            tokio::spawn(async move {
                                struct InflightGuard;
                                impl Drop for InflightGuard {
                                    fn drop(&mut self) {
                                        ALIGN_KEEP_AWAKE_INFLIGHT.store(false, Ordering::Release);
                                    }
                                }
                                let _guard = InflightGuard;
                                let mut slot = conn.lock().await;
                                let res = http_keepalive_dl_burst(
                                    &mut slot,
                                    ALIGN_KEEP_AWAKE_HOST,
                                    ALIGN_KEEP_AWAKE_PORT,
                                    ALIGN_KEEP_AWAKE_PATH,
                                    Duration::from_millis(2500),
                                )
                                .await;
                                let still_awake = {
                                    let a = st_burst.antenna_align.read().await;
                                    a.active && a.keep_awake
                                };
                                if !still_awake {
                                    *slot = None;
                                }
                                drop(slot);
                                if res.is_err() && still_awake {
                                    let _ = icmp_ping_once(&fallback_host, seq).await;
                                }
                            });
                        }
                    } else {
                        ALIGN_KEEP_AWAKE_MS.store(0, Ordering::Relaxed);
                        if let Ok(mut guard) = keep_awake_conn.try_lock() {
                            *guard = None;
                        }
                    }
                    poll_antenna_alignment(&st_align).await;
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(400)) => {}
                        _ = st_align.align_notify.notified() => {}
                    }
                    continue;
                }
            } else {
                ALIGN_KEEP_AWAKE_MS.store(0, Ordering::Relaxed);
                if let Ok(mut guard) = keep_awake_conn.try_lock() {
                    *guard = None;
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                _ = st_align.align_notify.notified() => {}
            }
        }
    });

    // 3. 1s /proc/net/dev + persistent data usage + 2s memory/uptime/internals poller
    let st_net = state.clone();
    tokio::spawn(async move {
        let mut prev_samples: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();
        let mut prev_inst = Instant::now();
        let mut last_flush_sec = now_secs();
        let mut tick_count = 0u64;
        let mut cached_slot = String::from("_a");
        let mut boot_slot_loaded = false;
        let mut cached_wan_up: Option<UptimeTelemetry> = None;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick_count += 1;
            let now_inst = Instant::now();
            let elapsed_secs = now_inst.duration_since(prev_inst).as_secs_f64().max(0.2);
            prev_inst = now_inst;

            poll_network_and_usage(&st_net, &mut prev_samples, elapsed_secs, &mut last_flush_sec).await;

            if tick_count.is_multiple_of(2) {
                if !boot_slot_loaded {
                    boot_slot_loaded = true;
                    if let Ok(slot) = run_cmd("abctl", &["--boot_slot"], Duration::from_secs(2)).await {
                        let trimmed = slot.trim().to_string();
                        if !trimmed.is_empty() {
                            cached_slot = trimmed;
                        }
                    }
                }
                if tick_count % 6 == 2 {
                    cached_wan_up = query_wan_uptime_ubus().await;
                    if let Ok(mut d) = DISCONNECTS.lock() {
                        let n = d.observe(cached_wan_up.as_ref().map(|w| w.uptime_seconds));
                        if let Some(w) = cached_wan_up.as_mut() {
                            w.disconnect_count = Some(n);
                        }
                    }
                }
                poll_system_vitals(&st_net, &cached_slot, cached_wan_up.clone()).await;
            }
        }
    });

    // 4. Native ICMP Latency + CA Keep-Alive + LinkWatch recovery task
    let st_icmp = state.clone();
    tokio::spawn(async move {
        let mut seq = 1u16;
        let mut hourly_acc: Vec<PingPoint> = Vec::new();
        let mut twelve_acc: Vec<PingPoint> = Vec::new();
        let mut daily_acc: Vec<PingPoint> = Vec::new();
        let mut last_hour_flush = now_secs();
        let mut last_twelve_flush = now_secs();
        let mut last_daily_flush = now_secs();
        let mut qw_fail_streak = 0u32;
        let mut qw_high_lat_streak = 0u32;
        let mut qw_retries = 0u32;
        let mut last_qw_probe = 0u64;
        let mut last_ping_sec = 0u64;
        let mut was_qw_enabled = false;

        loop {
            let cfg = st_icmp.settings.read().await.clone();
            let now = now_secs();
            let ping_period = if cfg.keep_alive_enabled {
                1
            } else {
                cfg.ping_interval_sec.clamp(2, 60)
            };
            if cfg.ping_enabled && now.saturating_sub(last_ping_sec) >= ping_period {
                last_ping_sec = now;
                seq = seq.wrapping_add(1).max(1);
                let host = cfg.ping_host.clone();
                let res = icmp_ping_once(&host, seq).await;
                let ts_ms = now_secs() * 1000;
                let pt = match res {
                    Ok(rtt) => PingPoint {
                        timestamp: format_now_hms(),
                        ts: ts_ms,
                        host: host.clone(),
                        latency: (rtt * 100.0).round() / 100.0,
                        packet_loss: 0.0,
                        ok: true,
                    },
                    Err(_) => PingPoint {
                        timestamp: format_now_hms(),
                        ts: ts_ms,
                        host: host.clone(),
                        latency: 0.0,
                        packet_loss: 100.0,
                        ok: false,
                    },
                };

                {
                    let mut rt = st_icmp.ping_realtime.write().await;
                    if rt.len() >= 180 {
                        rt.pop_front();
                    }
                    rt.push_back(pt.clone());
                }
                st_icmp.broadcast_with(|| serde_json::json!({
                    "channel": "ping",
                    "timestamp": pt.timestamp,
                    "host": pt.host,
                    "latency": pt.latency,
                    "packet_loss": pt.packet_loss,
                    "ok": pt.ok,
                }));

                hourly_acc.push(pt.clone());
                twelve_acc.push(pt.clone());
                daily_acc.push(pt.clone());

                let now = now_secs();
                if now.saturating_sub(last_hour_flush) >= 30 {
                    last_hour_flush = now;
                    push_bucket(&st_icmp.ping_hourly, &mut hourly_acc, 120).await;
                }
                if now.saturating_sub(last_twelve_flush) >= 300 {
                    last_twelve_flush = now;
                    push_bucket(&st_icmp.ping_twelvehour, &mut twelve_acc, 144).await;
                }
                if now.saturating_sub(last_daily_flush) >= 600 {
                    last_daily_flush = now;
                    push_bucket(&st_icmp.ping_daily, &mut daily_acc, 144).await;
                }
            }

            // LinkWatch monitoring cycle
            let now = now_secs();
            if !cfg.quecwatch_enabled {
                was_qw_enabled = false;
                qw_fail_streak = 0;
                qw_high_lat_streak = 0;
                qw_retries = 0;
                last_qw_probe = 0;
            } else {
                if !was_qw_enabled {
                    was_qw_enabled = true;
                    qw_fail_streak = 0;
                    qw_high_lat_streak = 0;
                    qw_retries = 0;
                    last_qw_probe = 0;
                }
                if now.saturating_sub(last_qw_probe) >= cfg.quecwatch_interval_sec.max(15) {
                    last_qw_probe = now;
                    seq = seq.wrapping_add(1).max(1);
                    let res = icmp_ping_once(&cfg.quecwatch_target, seq).await;
                    match res {
                        Ok(rtt) => {
                            qw_fail_streak = 0;
                            qw_retries = 0;
                            let rtt_u64 = rtt.round() as u64;
                            if cfg.quecwatch_high_latency && rtt_u64 > cfg.quecwatch_latency_ceiling {
                                qw_high_lat_streak += 1;
                            } else {
                                qw_high_lat_streak = 0;
                            }
                            let mut qw = st_icmp.quecwatch.write().await;
                            qw.status = if qw_high_lat_streak > 0 { "degraded".into() } else { "healthy".into() };
                            qw.message = format!("ICMP reachability OK ({} ms)", rtt_u64);
                            qw.current_latency = rtt_u64;
                            qw.retry = 0;
                            qw.timestamp = now;
                        }
                        Err(err) => {
                            qw_fail_streak += 1;
                            let mut qw = st_icmp.quecwatch.write().await;
                            qw.status = "failing".into();
                            qw.message = format!("Probe failed ({qw_fail_streak}/{}): {err}", cfg.quecwatch_failures);
                            qw.current_latency = 0;
                            qw.timestamp = now;
                            if qw_fail_streak >= cfg.quecwatch_failures && qw_retries < cfg.quecwatch_max_retries {
                                qw_retries += 1;
                                qw.retry = qw_retries;
                                qw.status = "recovering".into();
                                qw.message = format!("Triggering recovery attempt {qw_retries}/{}", cfg.quecwatch_max_retries);
                                drop(qw);
                                if !trigger_quecwatch_recovery(&st_icmp, &cfg, qw_retries).await {
                                    // Deferred while carrying failover traffic: Route10's
                                    // own watchdog owns recovery; do not burn a retry.
                                    qw_retries -= 1;
                                    let mut qw = st_icmp.quecwatch.write().await;
                                    qw.retry = qw_retries;
                                    qw.status = "failing".into();
                                    qw.message = "Recovery deferred: carrying failover traffic (Route10 handles recovery)".into();
                                }
                                qw_fail_streak = 0;
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // 5. Public IP refresh + QuecProfiles & Scheduled Tasks
    let st_prof = state.clone();
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            if tick.is_multiple_of(10) {
                refresh_public_ip(&st_prof).await;
            }
            if tick.is_multiple_of(2) {
                crate::profiles::tick_profiles_and_schedules(&st_prof).await;
            }
            tick += 1;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn push_bucket(
    dest: &tokio::sync::RwLock<VecDeque<PingPoint>>,
    acc: &mut Vec<PingPoint>,
    cap: usize,
) {
    if acc.is_empty() {
        return;
    }
    let ok_vals: Vec<f64> = acc.iter().filter(|p| p.ok).map(|p| p.latency).collect();
    let loss = (acc.iter().filter(|p| !p.ok).count() as f64 / acc.len() as f64) * 100.0;
    let avg = if ok_vals.is_empty() {
        0.0
    } else {
        (ok_vals.iter().sum::<f64>() / ok_vals.len() as f64 * 100.0).round() / 100.0
    };
    let last = acc.last().unwrap();
    let agg = PingPoint {
        timestamp: last.timestamp.clone(),
        ts: last.ts,
        host: last.host.clone(),
        latency: avg,
        packet_loss: (loss * 10.0).round() / 10.0,
        ok: !ok_vals.is_empty(),
    };
    acc.clear();
    let mut ring = dest.write().await;
    if ring.len() >= cap {
        ring.pop_front();
    }
    ring.push_back(agg);
}

/// Returns false when the recovery was deferred (failover traffic).
pub(crate) async fn trigger_quecwatch_recovery(state: &AppState, cfg: &crate::state::DaemonSettings, attempt: u32) -> bool {
    if crate::obs::failover::is_active() {
        state.push_daemon_log("LinkWatch recovery deferred: modem is carrying failover traffic");
        crate::obs::events::work_deferred("LinkWatch recovery (CFUN cycle / SIM switch)", "carrying failover traffic");
        return false;
    }
    crate::obs::events::quecwatch_recovery(
        attempt,
        cfg.quecwatch_max_retries,
        cfg.quecwatch_connection_refresh,
        cfg.quecwatch_auto_sim_failover,
    );
    state.push_daemon_log("LinkWatch initiating recovery cycle");
    state.broadcast_with(|| serde_json::json!({
        "channel": "quecwatch",
        "message": "LinkWatch initiating cellular recovery",
        "timestamp": format_now_hms(),
    }));
    if cfg.quecwatch_connection_refresh || cfg.quecwatch_auto_sim_failover {
        let guard = crate::radio::lock_bounded(state, Duration::from_secs(8)).await;
        if guard.is_none() {
            state.push_daemon_log("LinkWatch: radio_lock busy for 8s; continuing recovery");
        }
        if cfg.quecwatch_connection_refresh {
            let _ = state.smd.exec("AT+CFUN=0", Priority::Emergency, Duration::from_secs(10)).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = state.smd.exec("AT+CFUN=1", Priority::Emergency, Duration::from_secs(12)).await;
        }
        if cfg.quecwatch_auto_sim_failover
            && let Ok(cur_slot_res) = state.smd.exec("AT+QUIMSLOT?", Priority::Emergency, Duration::from_secs(4)).await
        {
            let cur = parse_scalar_at_value(&cur_slot_res.body, "+QUIMSLOT:");
            let next_slot = if cur.trim() == "1" { "2" } else { "1" };
            let _ = state
                .smd
                .exec(format!("AT+QUIMSLOT={next_slot}"), Priority::Emergency, Duration::from_secs(8))
                .await;
        }
        crate::handlers::forget_radio_mode(state);
        drop(guard);
        if cfg.quecwatch_connection_refresh {
            tokio::time::sleep(Duration::from_secs(4)).await;
            let _ = run_cmd("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3)).await;
            let _ = run_cmd("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3)).await;
        }
    }
    let mut alerts = state.alerts.write().await;
    if alerts.len() >= 20 {
        alerts.pop_back();
    }
    alerts.push_front(AlertLogEntry {
        r#type: "quecwatch".into(),
        message: "LinkWatch ran automatic link recovery".into(),
        timestamp: format_now_hms(),
    });
    true
}

pub const ATFWD_SLOW_POLL_SECS: u64 = 60;
static LAST_ATFWD_POLL_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `AT+QMAP="WWAN"` and `AT+QTEMP` cross Qualcomm's `at_fwd` kernel bridge and emit
/// KERN_WARNING lines on every call, so throttle background telemetry polls to 60s.
pub(crate) fn should_poll_atfwd(
    priority: Priority,
    init_urcs: bool,
    thermals_empty: bool,
    now: u64,
    last: u64,
) -> bool {
    priority != Priority::Telemetry
        || init_urcs
        || thermals_empty
        || last == 0
        || now.saturating_sub(last) >= ATFWD_SLOW_POLL_SECS
}

#[cfg(test)]
pub(crate) fn build_telemetry_commands(
    qcainfo_cmd: &str,
    ta_nr_cmd: &str,
    ta_lte_cmd: &str,
    poll_atfwd: bool,
    need_static: bool,
) -> Vec<(String, Duration)> {
    build_telemetry_commands_with_qmap(
        qcainfo_cmd,
        ta_nr_cmd,
        ta_lte_cmd,
        poll_atfwd,
        poll_atfwd,
        need_static,
    )
}

#[cfg(test)]
pub(crate) fn build_telemetry_commands_with_qmap(
    qcainfo_cmd: &str,
    ta_nr_cmd: &str,
    ta_lte_cmd: &str,
    poll_atfwd: bool,
    include_qmap: bool,
    need_static: bool,
) -> Vec<(String, Duration)> {
    build_telemetry_commands_with_opts(
        qcainfo_cmd,
        ta_nr_cmd,
        ta_lte_cmd,
        include_qmap,
        poll_atfwd,
        need_static,
    )
}

pub(crate) fn build_telemetry_commands_with_opts(
    qcainfo_cmd: &str,
    ta_nr_cmd: &str,
    ta_lte_cmd: &str,
    include_qmap: bool,
    include_qtemp: bool,
    need_static: bool,
) -> Vec<(String, Duration)> {
    // Keep at_fwd commands (QMAP WWAN, QTEMP) in their mid-batch positions so trailing
    // baseband queries always follow them; moving them to the end caused a post-CFUN resync miss.
    let mut cmds: Vec<(String, Duration)> = vec![
        ("AT+CFUN?".into(), Duration::from_secs(3)),
        ("AT+QENG=\"servingcell\"".into(), Duration::from_secs(4)),
        (qcainfo_cmd.into(), Duration::from_secs(4)),
        ("AT+QRSRP".into(), Duration::from_secs(3)),
        ("AT+QRSRQ".into(), Duration::from_secs(3)),
        ("AT+QSINR".into(), Duration::from_secs(3)),
        ("AT+QNWCFG=\"nr5g_mimo_info\"".into(), Duration::from_secs(3)),
    ];
    if include_qmap {
        cmds.push(("AT+QMAP=\"WWAN\"".into(), Duration::from_secs(4)));
    }
    cmds.push(("AT+CGCONTRDP".into(), Duration::from_secs(4)));
    if include_qtemp {
        cmds.push(("AT+QTEMP".into(), Duration::from_secs(4)));
    }
    cmds.extend([
        ("AT+QSPN".into(), Duration::from_secs(3)),
        (ta_nr_cmd.into(), Duration::from_secs(3)),
        (ta_lte_cmd.into(), Duration::from_secs(3)),
        ("AT+QUIMSLOT?".into(), Duration::from_secs(3)),
        ("AT+C5GREG?".into(), Duration::from_secs(3)),
    ]);
    if need_static {
        cmds.extend([
            ("AT+CGMI".into(), Duration::from_secs(3)),
            ("AT+CGMM".into(), Duration::from_secs(3)),
            ("AT+QGMR".into(), Duration::from_secs(3)),
            ("AT+QNWCFG=\"3gpp_rel\"".into(), Duration::from_secs(3)),
            ("AT+CGSN".into(), Duration::from_secs(3)),
            ("AT+ICCID".into(), Duration::from_secs(3)),
            ("AT+CIMI".into(), Duration::from_secs(3)),
            ("AT+CNUM".into(), Duration::from_secs(3)),
        ]);
    }
    cmds
}

pub async fn refresh_modem_snapshot(state: &AppState, priority: Priority, init_urcs: bool) {
    let qcainfo_cmd = if init_urcs {
        "AT+QCAINFO=1;+QCAINFO;+QCAINFO=0"
    } else {
        "AT+QCAINFO"
    };
    let ta_nr_cmd = if init_urcs {
        "AT+QNWCFG=\"nr5g_time_advance\",1;+QNWCFG=\"nr5g_time_advance\""
    } else {
        "AT+QNWCFG=\"nr5g_time_advance\""
    };
    let ta_lte_cmd = if init_urcs {
        "AT+QNWCFG=\"lte_time_advance\",1;+QNWCFG=\"lte_time_advance\""
    } else {
        "AT+QNWCFG=\"lte_time_advance\""
    };

    let (need_static, thermals_empty, cached_wwan_raw, cached_thermals) = {
        let m = state.modem.read().await;
        (
            m.identity.revision.is_empty() || m.identity.model.is_empty(),
            m.thermals.is_empty(),
            m.raw_commands
                .get("AT+QMAP=\"WWAN\"")
                .cloned()
                .unwrap_or_default(),
            m.thermals.clone(),
        )
    };

    let sysfs_thermals = tokio::task::spawn_blocking(read_sysfs_thermals)
        .await
        .unwrap_or_default();

    let now = now_secs();
    let poll_atfwd = should_poll_atfwd(
        priority,
        init_urcs,
        thermals_empty && sysfs_thermals.is_empty(),
        now,
        LAST_ATFWD_POLL_SECS.load(std::sync::atomic::Ordering::Relaxed),
    );
    let native_mode = crate::dataplane::is_native_mode();
    let include_qmap = poll_atfwd && !native_mode;
    let include_qtemp = poll_atfwd && sysfs_thermals.is_empty();

    let cmds = build_telemetry_commands_with_opts(
        qcainfo_cmd,
        ta_nr_cmd,
        ta_lte_cmd,
        include_qmap,
        include_qtemp,
        need_static,
    );

    let cmd_names: Vec<String> = cmds.iter().map(|(c, _)| c.clone()).collect();
    let Ok(results) = state.smd.exec_batch(cmds, priority).await else {
        return;
    };

    if poll_atfwd {
        LAST_ATFWD_POLL_SECS.store(now, std::sync::atomic::Ordering::Relaxed);
    }

    let mut raw_map: BTreeMap<String, String> = BTreeMap::new();
    for (name, res) in cmd_names.into_iter().zip(results) {
        if let Ok(r) = res {
            raw_map.insert(name, r.body);
        }
    }

    let get_resp = |needle: &str| -> String {
        raw_map
            .iter()
            .find(|(k, _)| k.contains(needle))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    let mut carriers = parse_carrier_aggregation(&get_resp("QCAINFO"));
    let mimo_info = parse_nr5g_mimo_info(&get_resp("nr5g_mimo_info"));
    merge_nr5g_mimo_layers(&mut carriers, &mimo_info);
    let serving = parse_serving_cell(&get_resp("servingcell"), &carriers);
    let mimo = parse_mimo_signal(&get_resp("QRSRP"), &get_resp("QRSRQ"), &get_resp("QSINR"));
    let wwan_raw = if native_mode {
        String::new()
    } else if include_qmap {
        get_resp("WWAN")
    } else {
        cached_wwan_raw
    };
    let mut bearers = parse_active_wwan(&wwan_raw, &get_resp("CGCONTRDP"));
    if native_mode
        && let Some(ov) = crate::dataplane::native_bearer_overlay().await
    {
        overlay_native_bearer(&mut bearers, ov);
    }
    let time_advance = parse_time_advance_for_rat(
        &get_resp("lte_time_advance"),
        &get_resp("nr5g_time_advance"),
        serving.as_ref().map(|s| s.rat.as_str()),
    );
    let thermals = if !sysfs_thermals.is_empty() {
        sysfs_thermals
    } else if include_qtemp {
        parse_temp_sensors(&get_resp("QTEMP"))
    } else {
        cached_thermals
    };

    let qspn = parse_qspn_operator(&get_resp("QSPN"));
    let operator = if !qspn.is_empty() {
        qspn
    } else if serving.as_ref().is_some_and(|s| s.mcc == "310" && s.mnc == "260") {
        "T-Mobile".into()
    } else if let Some(s) = serving.as_ref().filter(|s| !s.mcc.is_empty()) {
        format!("PLMN {}-{}", s.mcc, s.mnc)
    } else {
        "Searching".into()
    };

    let cfun = parse_scalar_at_value(&get_resp("CFUN"), "+CFUN:")
        .parse::<i32>()
        .unwrap_or(1);
    let sim_slot = parse_scalar_at_value(&get_resp("QUIMSLOT"), "+QUIMSLOT:")
        .parse::<i32>()
        .unwrap_or(1);

    if need_static {
        let prev_imei = tokio::task::spawn_blocking(|| uci_get_blocking("cellcore.imei.previous"))
            .await
            .ok()
            .flatten();
        let mut sec = state.secrets.write().await;
        let cgsn = parse_scalar_at_value(&get_resp("CGSN"), "+CGSN:");
        let imei_val = if cgsn.is_empty() {
            clean_at_lines(&get_resp("CGSN")).into_iter().next().unwrap_or_default()
        } else {
            cgsn
        };
        if !imei_val.is_empty() {
            sec.imei = imei_val;
        }
        let iccid_val = parse_scalar_at_value(&get_resp("ICCID"), "+ICCID:");
        if !iccid_val.is_empty() {
            sec.iccid = iccid_val;
        }
        let imsi_val = parse_scalar_at_value(&get_resp("CIMI"), "");
        if !imsi_val.is_empty() {
            sec.imsi = imsi_val;
        }
        sec.previous_imei = prev_imei;
    }

    let sec_snap = state.secrets.read().await.clone();
    let mut modem = state.modem.write().await;
    modem.updated_at = now_secs();
    modem.operator = operator;
    modem.serving = serving;
    modem.carriers = carriers;
    modem.mimo = mimo;
    modem.bearers = bearers;
    modem.time_advance = time_advance;
    modem.thermals = thermals;
    modem.identity.cfun = cfun;
    modem.identity.sim_slot = sim_slot;
    modem.identity.has_previous_imei = sec_snap.previous_imei.is_some();
    modem.identity.masked_imei = mask_secret_id(&sec_snap.imei);
    modem.identity.masked_iccid = mask_secret_id(&sec_snap.iccid);
    modem.identity.masked_imsi = mask_secret_id(&sec_snap.imsi);

    if need_static {
        let cgmi = parse_scalar_at_value(&get_resp("CGMI"), "+CGMI:");
        if !cgmi.is_empty() {
            modem.identity.manufacturer = cgmi;
        }
        let cgmm = parse_scalar_at_value(&get_resp("CGMM"), "+CGMM:");
        if !cgmm.is_empty() {
            modem.identity.model = cgmm;
        }
        let qgmr = parse_scalar_at_value(&get_resp("QGMR"), "");
        if !qgmr.is_empty() {
            modem.identity.revision = qgmr;
        }
        let rel = parse_3gpp_rel(&get_resp("3gpp_rel"));
        if rel != "N/A" {
            modem.identity.rel = rel;
        }
        let cnum = parse_scalar_at_value(&get_resp("CNUM"), "+CNUM:");
        modem.identity.phone_number = cnum;
    }

    if native_mode {
        modem.raw_commands.remove("AT+QMAP=\"WWAN\"");
    }
    if !init_urcs {
        for stale in [
            "AT+QCAINFO=1;+QCAINFO;+QCAINFO=0",
            "AT+QNWCFG=\"nr5g_time_advance\",1;+QNWCFG=\"nr5g_time_advance\"",
            "AT+QNWCFG=\"lte_time_advance\",1;+QNWCFG=\"lte_time_advance\"",
        ] {
            modem.raw_commands.remove(stale);
        }
    }
    for (k, v) in raw_map {
        // Never keep raw CGSN/ICCID/CIMI inside raw_commands exposed on regular snapshot
        if k.contains("CGSN") || k.contains("ICCID") || k.contains("CIMI") {
            continue;
        }
        modem.raw_commands.insert(k, v);
    }

    let snap_val = modem.clone();
    drop(modem);
    // Event detectors diff consecutive snapshots here (no extra AT).
    crate::obs::events::on_snapshot(&snap_val);

    state.broadcast_with(|| serde_json::json!({
        "channel": "rf_snapshot",
        "modem": snap_val,
    }));
}

fn build_signal_point(vals: &[Option<f64>], ts_ms: u64, label: &str) -> Option<SignalHistoryPoint> {
    let valid: Vec<f64> = vals.iter().copied().flatten().collect();
    if valid.is_empty() {
        return None;
    }
    let avg = (valid.iter().sum::<f64>() / valid.len() as f64 * 10.0).round() / 10.0;
    Some(SignalHistoryPoint {
        ts: ts_ms,
        label: label.to_string(),
        value: avg,
        chains: vals.to_vec(),
    })
}

async fn record_signal_history_point(state: &AppState) {
    let mimo = state.modem.read().await.mimo.clone();
    let ts_ms = now_secs() * 1000;
    let hms = format_now_hms();
    let label = hms.split_whitespace().nth(1).unwrap_or("00:00").get(..5).unwrap_or("00:00");

    if let Some(pt) = build_signal_point(&mimo.rsrp, ts_ms, label) {
        let mut g = state.rsrp_hist.write().await;
        if g.len() >= 180 {
            g.pop_front();
        }
        g.push_back(pt);
    }
    if let Some(pt) = build_signal_point(&mimo.rsrq, ts_ms, label) {
        let mut g = state.rsrq_hist.write().await;
        if g.len() >= 180 {
            g.pop_front();
        }
        g.push_back(pt);
    }
    if let Some(pt) = build_signal_point(&mimo.sinr, ts_ms, label) {
        let mut g = state.sinr_hist.write().await;
        if g.len() >= 180 {
            g.pop_front();
        }
        g.push_back(pt);
    }
}

async fn poll_antenna_alignment(state: &AppState) {
    // Try compound signal query first to cut SMD round-trips during 400 ms alignment.
    let compound_cmds = vec![("AT+QRSRP;+QRSRQ;+QSINR".into(), Duration::from_secs(2))];
    let mut mimo = match state.smd.exec_batch(compound_cmds, Priority::Telemetry).await {
        Ok(res)
            if res
                .first()
                .and_then(|r| r.as_ref().ok())
                .is_some_and(|r| r.ok) =>
        {
            let body = res[0].as_ref().map(|r| r.body.as_str()).unwrap_or("");
            parse_mimo_signal(body, body, body)
        }
        _ => crate::parsers::MimoSignalData::default(),
    };
    if mimo.rsrp.iter().all(|v| v.is_none()) {
        let cmds = vec![
            ("AT+QRSRP".into(), Duration::from_secs(2)),
            ("AT+QRSRQ".into(), Duration::from_secs(2)),
            ("AT+QSINR".into(), Duration::from_secs(2)),
        ];
        let Ok(res) = state.smd.exec_batch(cmds, Priority::Telemetry).await else {
            return;
        };
        let rsrp_raw = res.first().and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
        let rsrq_raw = res.get(1).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
        let sinr_raw = res.get(2).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
        mimo = parse_mimo_signal(rsrp_raw, rsrq_raw, sinr_raw);
    }

    let prev_samples = state.antenna_align.read().await.samples;
    let should_poll_phy = prev_samples == 0 || (prev_samples + 1).is_multiple_of(3);
    let (beam_id, pathloss_db, csi, tx_pwr, mimo_info_raw) = if should_poll_phy {
        let query_beam = !ALIGN_BEAM_ID_UNSUPPORTED.load(Ordering::Relaxed);
        let mut phy_cmds = Vec::with_capacity(5);
        if query_beam {
            phy_cmds.push(("AT+QNWCFG=\"nr5g_ssb_beam_id\"".into(), Duration::from_secs(2)));
        }
        phy_cmds.push(("AT+QNWCFG=\"nr5g_pathloss\"".into(), Duration::from_secs(2)));
        phy_cmds.push(("AT+QNWCFG=\"nr5g_csi\"".into(), Duration::from_secs(2)));
        phy_cmds.push(("AT+QNWCFG=\"nr5g_tx_pwr\"".into(), Duration::from_secs(2)));
        phy_cmds.push(("AT+QNWCFG=\"nr5g_mimo_info\"".into(), Duration::from_secs(2)));
        if let Ok(phy) = state.smd.exec_batch(phy_cmds, Priority::Telemetry).await {
            let get_ok = |i: usize| -> &str {
                phy.get(i)
                    .and_then(|r| r.as_ref().ok())
                    .filter(|r| r.ok)
                    .map(|r| r.body.as_str())
                    .unwrap_or("")
            };
            let off = if query_beam {
                if phy.first().and_then(|r| r.as_ref().ok()).is_some_and(|r| !r.ok) {
                    ALIGN_BEAM_ID_UNSUPPORTED.store(true, Ordering::Relaxed);
                }
                1
            } else {
                0
            };
            let pl = parse_nr5g_pathloss(get_ok(off)).filter(|&v| v > 1.0);
            let tx = crate::radio_tuning::parse_nr5g_tx_pwr(get_ok(off + 2))
                .filter(|v| {
                    let t = v.trim();
                    !t.is_empty() && t != "0" && t != "0.0"
                });
            (
                if query_beam { parse_ssb_beam_id(get_ok(0)) } else { None },
                pl,
                crate::radio_tuning::parse_csi(get_ok(off + 1), "nr5g_csi"),
                tx,
                parse_nr5g_mimo_info(get_ok(off + 3)),
            )
        } else {
            (None, None, None, None, Vec::new())
        }
    } else {
        (None, None, None, None, Vec::new())
    };

    struct CarrierMeta {
        pci: Option<i32>,
        arfcn: i64,
        band: String,
        dl_layers: Option<u8>,
        ul_layers: Option<u8>,
    }

    let modem_meta = {
        let m = state.modem.read().await;
        let serving_pci = m.serving.as_ref().and_then(|s| s.pci);
        let serving_band = m.serving.as_ref().map(|s| s.band.clone()).unwrap_or_default();
        let serving_rat = m.serving.as_ref().map(|s| s.rat.clone()).unwrap_or_default();
        let rrc_state = m.serving.as_ref().map(|s| s.state.clone()).unwrap_or_default();
        let ca_count = m.carriers.len();
        let ca_total_mhz: f64 = m.carriers.iter().filter_map(|c| c.bandwidth_mhz).sum();
        let ta_meters = m.time_advance.active_meters;
        let carriers_ref: Vec<CarrierMeta> = m
            .carriers
            .iter()
            .map(|c| CarrierMeta {
                pci: c.pci,
                arfcn: c.arfcn,
                band: c.band.clone(),
                dl_layers: c.dl_mimo_layers,
                ul_layers: c.ul_mimo_layers,
            })
            .collect();
        (serving_pci, serving_band, serving_rat, rrc_state, ca_count, ca_total_mhz, ta_meters, carriers_ref)
    };

    let mut a = state.antenna_align.write().await;
    let has_new_rsrp = mimo.rsrp.iter().any(|v| v.is_some());
    if has_new_rsrp {
        a.rsrp = mimo.rsrp.clone();
    }
    if mimo.rsrq.iter().any(|v| v.is_some()) {
        a.rsrq = mimo.rsrq.clone();
    }
    if mimo.sinr.iter().any(|v| v.is_some()) {
        a.sinr = mimo.sinr.clone();
    }
    for i in 0..4 {
        if let Some(cur) = mimo.rsrp.get(i).copied().flatten() {
            a.peak_rsrp[i] = Some(a.peak_rsrp[i].map_or(cur, |p| p.max(cur)));
        }
        if let Some(cur) = mimo.sinr.get(i).copied().flatten() {
            a.peak_sinr[i] = Some(a.peak_sinr[i].map_or(cur, |p| p.max(cur)));
        }
    }

    let valid_rsrp: Vec<f64> = a.rsrp.iter().copied().flatten().collect();
    a.active_chains = valid_rsrp.len() as u8;
    if has_new_rsrp && !valid_rsrp.is_empty() {
        let mean_rsrp = ((valid_rsrp.iter().sum::<f64>() / valid_rsrp.len() as f64) * 10.0).round() / 10.0;
        a.peak_mean_rsrp = Some(a.peak_mean_rsrp.map_or(mean_rsrp, |p| p.max(mean_rsrp)));
    }
    let valid_sinr: Vec<f64> = a.sinr.iter().copied().flatten().collect();
    if mimo.sinr.iter().any(|v| v.is_some()) && !valid_sinr.is_empty() {
        let mean_sinr = ((valid_sinr.iter().sum::<f64>() / valid_sinr.len() as f64) * 10.0).round() / 10.0;
        a.peak_mean_sinr = Some(a.peak_mean_sinr.map_or(mean_sinr, |p| p.max(mean_sinr)));
    }
    a.rsrp_spread = if valid_rsrp.len() >= 2 {
        let min = valid_rsrp.iter().copied().fold(f64::INFINITY, f64::min);
        let max = valid_rsrp.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        Some(((max - min) * 10.0).round() / 10.0)
    } else {
        None
    };
    a.pair01_skew = match (a.rsrp.first().copied().flatten(), a.rsrp.get(1).copied().flatten()) {
        (Some(r0), Some(r1)) => Some((((r0 - r1).abs()) * 10.0).round() / 10.0),
        _ => None,
    };
    a.pair23_skew = match (a.rsrp.get(2).copied().flatten(), a.rsrp.get(3).copied().flatten()) {
        (Some(r2), Some(r3)) => Some((((r2 - r3).abs()) * 10.0).round() / 10.0),
        _ => None,
    };

    a.serving_pci = modem_meta.0;
    a.serving_band = modem_meta.1;
    a.serving_rat = modem_meta.2;
    a.rrc_state = modem_meta.3;
    a.ca_count = modem_meta.4;
    a.ca_total_mhz = (modem_meta.5 * 10.0).round() / 10.0;
    a.ta_meters = modem_meta.6;

    if let Some(b) = beam_id {
        a.ssb_beam_id = Some(b);
    }
    if let Some(pl) = pathloss_db {
        a.nr5g_pathloss_db = Some(pl);
    }
    if let Some(c) = csi {
        a.nr5g_mcs = Some(c.mcs);
        a.nr5g_ri = Some(c.ri);
        a.nr5g_cqi = Some(c.cqi);
    }
    if let Some(tp) = tx_pwr {
        a.nr5g_tx_pwr = Some(tp);
    }
    if !mimo_info_raw.is_empty() {
        a.mimo_layers = mimo_info_raw
            .into_iter()
            .map(|(pci, arfcn, dl_layers, ul_layers)| {
                let band = modem_meta
                    .7
                    .iter()
                    .find(|c| c.arfcn == arfcn && c.pci.unwrap_or(pci) == pci)
                    .or_else(|| modem_meta.7.iter().find(|c| c.arfcn == arfcn))
                    .map(|c| c.band.clone())
                    .unwrap_or_default();
                CarrierMimoLayer {
                    pci,
                    arfcn,
                    band,
                    dl_layers,
                    ul_layers,
                }
            })
            .collect();
    } else if a.mimo_layers.is_empty() {
        a.mimo_layers = modem_meta
            .7
            .iter()
            .filter_map(|c| {
                Some(CarrierMimoLayer {
                    pci: c.pci?,
                    arfcn: c.arfcn,
                    band: c.band.clone(),
                    dl_layers: c.dl_layers?,
                    ul_layers: c.ul_layers.unwrap_or(1),
                })
            })
            .collect();
    }

    a.samples += 1;
    a.updated_at = now_secs();
    a.updated_at_ms = now_ms();
    let snap = a.clone();
    drop(a);

    state.broadcast_with(|| serde_json::json!({
        "channel": "antenna_align",
        "align": snap,
    }));
}

struct NetDevRow {
    name: String,
    rx_bytes: u64,
    rx_pkts: u64,
    tx_bytes: u64,
    tx_pkts: u64,
    oper: String,
}

fn read_net_dev_samples() -> Option<Vec<NetDevRow>> {
    let proc_dev = fs::read_to_string(crate::paths::p("/proc/net/dev")).ok()?;
    let mut rows = Vec::new();
    for line in proc_dev.lines().skip(2) {
        let Some((name_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_raw.trim();
        if !(name.starts_with("rmnet") || name == "eth0" || name == "br-lan") {
            continue;
        }
        let cols: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if cols.len() < 10 {
            continue;
        }
        let oper = fs::read_to_string(crate::paths::p(&format!("/sys/class/net/{name}/operstate")))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        rows.push(NetDevRow {
            name: name.to_string(),
            rx_bytes: cols[0],
            rx_pkts: cols[1],
            tx_bytes: cols[8],
            tx_pkts: cols[9],
            oper,
        });
    }
    Some(rows)
}

async fn poll_network_and_usage(
    state: &AppState,
    prev: &mut HashMap<String, (u64, u64, u64, u64)>,
    elapsed_secs: f64,
    last_flush_sec: &mut u64,
) {
    let Ok(Some(rows)) = tokio::task::spawn_blocking(read_net_dev_samples).await else {
        return;
    };
    let mut ifaces = Vec::with_capacity(rows.len());
    for row in rows {
        let NetDevRow { name, rx_bytes, rx_pkts, tx_bytes, tx_pkts, oper } = row;
        let (rx_bps, tx_bps, rx_pps, tx_pps) =
            if let Some(&(pr_b, pr_p, pt_b, pt_p)) = prev.get(&name) {
                let drx_b = rx_bytes.saturating_sub(pr_b);
                let dtx_b = tx_bytes.saturating_sub(pt_b);
                let drx_p = rx_pkts.saturating_sub(pr_p);
                let dtx_p = tx_pkts.saturating_sub(pt_p);
                (
                    ((drx_b as f64 * 8.0) / elapsed_secs) as u64,
                    ((dtx_b as f64 * 8.0) / elapsed_secs) as u64,
                    (drx_p as f64 / elapsed_secs) as u64,
                    (dtx_p as f64 / elapsed_secs) as u64,
                )
            } else {
                (0, 0, 0, 0)
            };
        prev.insert(name.clone(), (rx_bytes, rx_pkts, tx_bytes, tx_pkts));

        ifaces.push(TrafficInterfaceStats {
            name,
            state: oper,
            rx: TrafficDirectionStats {
                bytes_total: rx_bytes,
                bps: rx_bps,
                packets_per_sec: rx_pps,
            },
            tx: TrafficDirectionStats {
                bytes_total: tx_bytes,
                bps: tx_bps,
                packets_per_sec: tx_pps,
            },
        });
    }

    let primary = pick_primary_rmnet(&ifaces);
    let lan = ifaces
        .iter()
        .find(|i| i.name == "eth0")
        .or_else(|| ifaces.iter().find(|i| i.name.starts_with("eth")));

    let rx_bps = primary.map(|p| p.rx.bps).unwrap_or(0);
    let tx_bps = primary.map(|p| p.tx.bps).unwrap_or(0);
    let now_ms = now_secs() * 1000;

    if let Some(p) = primary {
        update_persistent_usage(state, &p.name, p.rx.bytes_total, p.tx.bytes_total, last_flush_sec)
            .await;
    }

    {
        let mut tr = state.traffic.write().await;
        if let Some(p) = primary {
            tr.primary_iface = p.name.clone();
        }
        if let Some(l) = lan {
            tr.lan_iface = l.name.clone();
        }
        tr.interfaces = ifaces.clone();
        if tr.history.len() >= 90 {
            tr.history.pop_front();
        }
        tr.history.push_back(TrafficHistoryPoint {
            ts: now_ms,
            rx_bps,
            tx_bps,
        });
    }

    let usage_today = {
        let u = state.data_usage.read().await;
        let (today, month, _) = format_today_ymd();
        let d = u.daily.iter().find(|e| e.date == today).cloned();
        let m = u.monthly.iter().find(|e| e.month == month).cloned();
        serde_json::json!({
            "todayRx": d.as_ref().map(|x| x.rx_bytes).unwrap_or(0),
            "todayTx": d.as_ref().map(|x| x.tx_bytes).unwrap_or(0),
            "monthRx": m.as_ref().map(|x| x.rx_bytes).unwrap_or(0),
            "monthTx": m.as_ref().map(|x| x.tx_bytes).unwrap_or(0),
        })
    };

    state.broadcast_with(|| serde_json::json!({
        "channel": "network-monitor",
        "interfaces": ifaces,
        "usageSummary": usage_today,
    }));
}

fn pick_primary_rmnet(ifaces: &[TrafficInterfaceStats]) -> Option<&TrafficInterfaceStats> {
    let rmnets: Vec<&TrafficInterfaceStats> = ifaces
        .iter()
        .filter(|i| i.name.starts_with("rmnet"))
        .collect();
    if rmnets.is_empty() {
        return None;
    }
    rmnets
        .iter()
        .copied()
        .find(|i| {
            i.state.eq_ignore_ascii_case("up")
                && (i.rx.bps > 0 || i.tx.bps > 0 || i.rx.bytes_total > 0)
        })
        .or_else(|| rmnets.iter().copied().find(|i| i.state.eq_ignore_ascii_case("up")))
        .or_else(|| rmnets.iter().copied().max_by_key(|i| i.rx.bytes_total))
}

async fn update_persistent_usage(
    state: &AppState,
    iface: &str,
    raw_rx: u64,
    raw_tx: u64,
    last_flush_sec: &mut u64,
) {
    let (today, month, _) = format_today_ymd();
    let mut u = state.data_usage.write().await;

    let (delta_rx, delta_tx) = if u.last_iface != iface {
        u.last_iface = iface.to_string();
        u.last_raw_rx = raw_rx;
        u.last_raw_tx = raw_tx;
        (0, 0)
    } else {
        let drx = if raw_rx >= u.last_raw_rx {
            raw_rx - u.last_raw_rx
        } else {
            raw_rx
        };
        let dtx = if raw_tx >= u.last_raw_tx {
            raw_tx - u.last_raw_tx
        } else {
            raw_tx
        };
        u.last_raw_rx = raw_rx;
        u.last_raw_tx = raw_tx;
        (drx, dtx)
    };

    if delta_rx == 0 && delta_tx == 0 {
        return;
    }

    if let Some(entry) = u.daily.iter_mut().find(|d| d.date == today) {
        entry.rx_bytes = entry.rx_bytes.saturating_add(delta_rx);
        entry.tx_bytes = entry.tx_bytes.saturating_add(delta_tx);
    } else {
        u.daily.push(DailyUsageEntry {
            date: today.clone(),
            rx_bytes: delta_rx,
            tx_bytes: delta_tx,
        });
        if u.daily.len() > 90 {
            let drain_n = u.daily.len() - 90;
            u.daily.drain(0..drain_n);
        }
        *last_flush_sec = 0; // force flush on day change
    }

    if let Some(entry) = u.monthly.iter_mut().find(|m| m.month == month) {
        entry.rx_bytes = entry.rx_bytes.saturating_add(delta_rx);
        entry.tx_bytes = entry.tx_bytes.saturating_add(delta_tx);
    } else {
        u.monthly.push(MonthlyUsageEntry {
            month,
            rx_bytes: delta_rx,
            tx_bytes: delta_tx,
        });
        if u.monthly.len() > 24 {
            let drain_n = u.monthly.len() - 24;
            u.monthly.drain(0..drain_n);
        }
    }

    let now = now_secs();
    let flush_snap = if now.saturating_sub(*last_flush_sec) >= DATA_USAGE_SNAPSHOT_FLUSH_SECS {
        *last_flush_sec = now;
        Some(u.clone())
    } else {
        None
    };
    drop(u);
    if let Some(snap) = flush_snap {
        let p1 = crate::paths::p(DATA_USAGE_PATH);
        let p2 = crate::paths::p(DATA_USAGE_TMP_PATH);
        let _ = tokio::task::spawn_blocking(move || {
            let _ = save_json_atomic(&p1, &snap, 0o600);
            let _ = save_json_atomic(&p2, &snap, 0o644);
        })
        .await;
    }
}

pub async fn flush_persistent_state(state: &AppState) {
    let snap = state.data_usage.read().await.clone();
    let p1 = crate::paths::p(DATA_USAGE_PATH);
    let p2 = crate::paths::p(DATA_USAGE_TMP_PATH);
    // Event ring + observability counters + usage flash flush (SIGTERM and every reboot path).
    let _ = tokio::task::spawn_blocking(move || {
        let _ = save_json_atomic(&p1, &snap, 0o600);
        let _ = save_json_atomic(&p2, &snap, 0o644);
        crate::obs::flush_now(true);
    })
    .await;
}

async fn query_wan_uptime_ubus() -> Option<UptimeTelemetry> {
    if !crate::dataplane::is_native_mode() {
        for iface in ["network.interface.wan", "network.interface.wan_v6"] {
            if let Ok(out) = run_cmd("ubus", &["call", iface, "status"], Duration::from_secs(2)).await
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&out)
                && v.get("up").and_then(|x| x.as_bool()) == Some(true)
            {
                let secs = v.get("uptime").and_then(|x| x.as_u64()).unwrap_or(0);
                return Some(UptimeTelemetry {
                    uptime_seconds: secs,
                    uptime_formatted: format_duration_hms(secs),
                    is_connected: Some(true),
                    disconnect_count: Some(disconnect_count()),
                    timestamp: format_now_hms(),
                });
            }
        }
    }
    if let Ok(Some(_)) = tokio::task::spawn_blocking(crate::netlink::detect_active_rmnet_wan_live).await {
        let secs = crate::dataplane::native_wan_uptime_secs().unwrap_or(1);
        return Some(UptimeTelemetry {
            uptime_seconds: secs,
            uptime_formatted: format_duration_hms(secs),
            is_connected: Some(true),
            disconnect_count: Some(disconnect_count()),
            timestamp: format_now_hms(),
        });
    }
    None
}

struct SystemVitalsRaw {
    mem: MemoryTelemetry,
    dev_up: UptimeTelemetry,
    conntrack_count: u64,
    conntrack_max: u64,
    conntrack_hashsize: u64,
    pcie_aspm: String,
    autosleep: String,
    usb_udc: String,
    usb_controller: String,
    usb_adb_present: bool,
    usrdata_total_bytes: u64,
    usrdata_used_bytes: u64,
    usrdata_avail_bytes: u64,
    mwan3_running: bool,
    eth_speed: String,
}

fn read_system_vitals_blocking() -> SystemVitalsRaw {
    let ts = format_now_hms();
    let mut mem = MemoryTelemetry::default();
    if let Ok(meminfo) = fs::read_to_string(crate::paths::p("/proc/meminfo")) {
        let mut total_kb = 0u64;
        let mut avail_kb = 0u64;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                avail_kb = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        let used_kb = total_kb.saturating_sub(avail_kb);
        mem.total = total_kb * 1024;
        mem.available = avail_kb * 1024;
        mem.used = used_kb * 1024;
        mem.percent = if total_kb > 0 {
            ((used_kb as f64 / total_kb as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };
        mem.timestamp = ts.clone();
    }

    let dev_secs = fs::read_to_string(crate::paths::p("/proc/uptime"))
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0);
    let dev_up = UptimeTelemetry {
        uptime_seconds: dev_secs,
        uptime_formatted: format_duration_hms(dev_secs),
        is_connected: None,
        disconnect_count: None,
        timestamp: ts,
    };

    let conntrack_count = fs::read_to_string(crate::paths::p("/proc/sys/net/netfilter/nf_conntrack_count"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let conntrack_max = fs::read_to_string(crate::paths::p("/proc/sys/net/netfilter/nf_conntrack_max"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let conntrack_hashsize = fs::read_to_string(crate::paths::p("/sys/module/nf_conntrack/parameters/hashsize"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let pcie_aspm = fs::read_to_string(crate::paths::p("/sys/module/pcie_aspm/parameters/policy"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let autosleep = fs::read_to_string(crate::paths::p("/sys/power/autosleep"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let (usb_udc, usb_controller, usb_adb_present) = current_usb_gadget_udc();
    let (usrdata_total_bytes, usrdata_used_bytes, usrdata_avail_bytes) =
        statvfs_bytes(&crate::paths::p("/usrdata"));
    let mwan3_running = is_proc_running("mwan3track");
    let eth_speed = fs::read_to_string(crate::paths::p("/sys/class/net/eth0/speed"))
        .ok()
        .map(|s| format!("{}Mb/s", s.trim()))
        .unwrap_or_else(|| "2500Mb/s".into());

    SystemVitalsRaw {
        mem,
        dev_up,
        conntrack_count,
        conntrack_max,
        conntrack_hashsize,
        pcie_aspm,
        autosleep,
        usb_udc,
        usb_controller,
        usb_adb_present,
        usrdata_total_bytes,
        usrdata_used_bytes,
        usrdata_avail_bytes,
        mwan3_running,
        eth_speed,
    }
}

async fn poll_system_vitals(
    state: &AppState,
    boot_slot: &str,
    wan_up: Option<UptimeTelemetry>,
) {
    let raw = match tokio::task::spawn_blocking(read_system_vitals_blocking).await {
        Ok(r) => r,
        Err(_) => return,
    };

    let mem = raw.mem;
    *state.memory.write().await = mem.clone();

    let dev_up = raw.dev_up;
    *state.device_uptime.write().await = dev_up.clone();

    let sess = match wan_up {
        Some(w) => w,
        None => UptimeTelemetry::disconnected(disconnect_count(), format_now_hms()),
    };
    *state.session_uptime.write().await = sess.clone();
    state.broadcast_with(|| serde_json::json!({
        "channel": "uptime",
        "uptime_seconds": sess.uptime_seconds,
        "uptime_formatted": sess.uptime_formatted,
        "is_connected": sess.is_connected.unwrap_or(false),
        "disconnect_count": sess.disconnect_count.unwrap_or_else(disconnect_count),
        "timestamp": sess.timestamp,
    }));

    state.broadcast_with(|| serde_json::json!({
        "channel": "memory",
        "total": mem.total,
        "used": mem.used,
        "available": mem.available,
        "percent": mem.percent,
        "timestamp": mem.timestamp,
    }));
    state.broadcast_with(|| serde_json::json!({
        "channel": "device_uptime",
        "uptime_seconds": dev_up.uptime_seconds,
        "uptime_formatted": dev_up.uptime_formatted,
        "timestamp": dev_up.timestamp,
    }));

    let keep_alive_enabled = state.settings.read().await.keep_alive_enabled;

    let mut internals = state.internals.write().await;
    internals.conntrack_count = raw.conntrack_count;
    internals.conntrack_max = raw.conntrack_max;
    internals.conntrack_hashsize = raw.conntrack_hashsize;
    internals.pcie_aspm = raw.pcie_aspm;
    internals.autosleep = raw.autosleep;
    internals.boot_slot = boot_slot.to_string();
    internals.usrdata_total_bytes = raw.usrdata_total_bytes;
    internals.usrdata_used_bytes = raw.usrdata_used_bytes;
    internals.usrdata_avail_bytes = raw.usrdata_avail_bytes;
    internals.usb_udc = raw.usb_udc;
    internals.usb_controller = raw.usb_controller;
    internals.usb_adb_present = raw.usb_adb_present;
    internals.mwan3_running = raw.mwan3_running;
    internals.keep_alive_enabled = keep_alive_enabled;
    internals.eth_speed = raw.eth_speed;
}

fn statvfs_bytes(path: &str) -> (u64, u64, u64) {
    let Ok(c_path) = std::ffi::CString::new(path) else {
        return (0, 0, 0);
    };
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut vfs) };
    if rc != 0 {
        return (0, 0, 0);
    }
    let frsize = vfs.f_frsize as u64;
    let total = (vfs.f_blocks as u64).saturating_mul(frsize);
    let avail = (vfs.f_bavail as u64).saturating_mul(frsize);
    let free = (vfs.f_bfree as u64).saturating_mul(frsize);
    let used = total.saturating_sub(free);
    (total, used, avail)
}

fn is_proc_running(needle: &str) -> bool {
    let Ok(entries) = fs::read_dir(crate::paths::p("/proc")) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let cmdline_path = entry.path().join("cmdline");
        if let Ok(bytes) = fs::read(&cmdline_path) {
            let text = String::from_utf8_lossy(&bytes);
            if text.contains(needle) {
                return true;
            }
        }
    }
    false
}

pub fn format_duration_hms(secs: u64) -> String {
    let days = secs / 86_400;
    let hrs = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let rem_s = secs % 60;
    if days > 0 {
        format!("{days}d {hrs}h {mins}m")
    } else if hrs > 0 {
        format!("{hrs}h {mins}m {rem_s}s")
    } else if mins > 0 {
        format!("{mins}m {rem_s}s")
    } else {
        format!("{rem_s}s")
    }
}

async fn refresh_public_ip(state: &AppState) {
    // The public IP shown is the carrier's: bind to rmnet while WARP steers
    // modem traffic (no-op otherwise).
    let bind = crate::vpn::bypass_iface();
    let mut args: Vec<&str> = vec!["-4fsS", "--max-time", "4"];
    if let Some(dev) = bind.as_deref() {
        args.extend(["--interface", dev]);
    }
    args.push("https://api.ipify.org");
    let Ok(out) = run_cmd("curl", &args, Duration::from_secs(5)).await else {
        return;
    };
    let ip: String = out
        .trim()
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '.' || *c == ':')
        .collect();
    if !ip.is_empty() {
        state.modem.write().await.public_ip = Some(ip);
    }
}

async fn connect_keepalive_stream(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let addrs: Vec<SocketAddr> = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "DNS lookup timed out".to_string())?
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("DNS lookup returned no addresses".into());
    }
    let mark = crate::vpn::bypass_mark();
    let mut last_err = String::from("connect failed");
    for addr in addrs {
        let sock = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(|e| format!("socket: {e}"))?;
        if let Some(m) = mark {
            let mv: libc::c_int = m as libc::c_int;
            unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mv as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        match tokio::time::timeout_at(deadline, sock.connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => last_err = format!("connect {addr}: {e}"),
            Err(_) => return Err("TCP connect timed out".into()),
        }
    }
    Err(last_err)
}

async fn http_keepalive_request(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    max_body: usize,
    deadline: tokio::time::Instant,
) -> Result<(usize, bool), String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: CellCore-Align/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    );
    tokio::time::timeout_at(deadline, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "HTTP write timed out".to_string())?
        .map_err(|e| format!("HTTP write failed: {e}"))?;

    let mut hdr_buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        if hdr_buf.len() >= 8192 {
            return Err("HTTP response headers too large".into());
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
            .await
            .map_err(|_| "HTTP header read timed out".to_string())?
            .map_err(|e| format!("HTTP header read failed: {e}"))?;
        if n == 0 {
            return Err("peer closed before headers".into());
        }
        hdr_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = hdr_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let hdr_str = std::str::from_utf8(&hdr_buf[..header_end])
        .map_err(|_| "non-UTF-8 HTTP headers".to_string())?;
    let mut lines = hdr_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code != 200 {
        return Err(format!("unexpected HTTP status {status_code}"));
    }

    let mut content_length: Option<usize> = None;
    let mut close_conn = status_line.starts_with("HTTP/1.0");
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().ok();
            } else if key.eq_ignore_ascii_case("connection") {
                if val.eq_ignore_ascii_case("close") {
                    close_conn = true;
                } else if val.eq_ignore_ascii_case("keep-alive") {
                    close_conn = false;
                }
            }
        }
    }

    let already_read = hdr_buf.len().saturating_sub(header_end + 4);
    let mut drain = [0u8; 8192];
    if let Some(cl) = content_length {
        if cl > max_body {
            return Err(format!("response body {cl} exceeds limit {max_body}"));
        }
        let mut total = already_read;
        while total < cl {
            let want = (cl - total).min(drain.len());
            let n = tokio::time::timeout_at(deadline, stream.read(&mut drain[..want]))
                .await
                .map_err(|_| "HTTP body read timed out".to_string())?
                .map_err(|e| format!("HTTP body read failed: {e}"))?;
            if n == 0 {
                return Err("truncated HTTP response body".into());
            }
            total += n;
        }
        Ok((total, !close_conn))
    } else {
        let mut total = already_read;
        while total < max_body {
            let want = (max_body - total).min(drain.len());
            let n = tokio::time::timeout_at(deadline, stream.read(&mut drain[..want]))
                .await
                .map_err(|_| "HTTP body read timed out".to_string())?
                .map_err(|e| format!("HTTP body read failed: {e}"))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok((total, false))
    }
}

/// Pulls a small downlink burst (64 KiB) over a keep-alive HTTP/1.1 socket so
/// 5G NR basebands (X75 on NR5G-SA) wake and hold secondary RX2/RX3 chains
/// during antenna alignment. Reuses the cached socket across bursts.
async fn http_keepalive_dl_burst(
    conn: &mut Option<TcpStream>,
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<usize, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    if let Some(stream) = conn.as_mut() {
        match http_keepalive_request(stream, host, path, ALIGN_KEEP_AWAKE_MAX_BODY, deadline).await {
            Ok((bytes, keep_alive)) => {
                if !keep_alive {
                    *conn = None;
                }
                return Ok(bytes);
            }
            Err(_) => {
                *conn = None;
            }
        }
    }
    let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
    if rem.is_zero() {
        return Err("keep-awake burst timed out".into());
    }
    let mut stream = connect_keepalive_stream(host, port, rem).await?;
    let (bytes, keep_alive) =
        http_keepalive_request(&mut stream, host, path, ALIGN_KEEP_AWAKE_MAX_BODY, deadline).await?;
    if keep_alive {
        *conn = Some(stream);
    }
    Ok(bytes)
}

pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub async fn icmp_ping_once(target: &str, seq: u16) -> Result<f64, String> {
    let host = target.trim().to_string();
    // Stored targets may predate validation: never hand ping something it reads as a flag.
    if !crate::admin::validate::is_net_target(&host) {
        return Err("Invalid ping target".into());
    }
    let ip_v4 = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        v4
    } else {
        let h_clone = host.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            (h_clone.as_str(), 0u16)
                .to_socket_addrs()
                .ok()
                .and_then(|mut it| it.find_map(|sa| match sa.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                }))
        })
        .await
        .ok()
        .flatten();
        match resolved {
            Some(v4) => v4,
            None => return ping_subprocess_fallback(&host).await,
        }
    };

    let raw_res = tokio::task::spawn_blocking(move || raw_icmp_echo_v4(ip_v4, seq))
        .await
        .map_err(|e| format!("icmp task failed: {e}"))?;
    match raw_res {
        Ok(rtt) => Ok(rtt),
        Err(e) if e.contains("Operation not permitted") || e.contains("EPERM") || e.contains("EACCES") => {
            ping_subprocess_fallback(&host).await
        }
        Err(e) => Err(e),
    }
}

fn raw_icmp_echo_v4(dest: Ipv4Addr, seq: u16) -> Result<f64, String> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if sock < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    struct FdGuard(libc::c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0); }
        }
    }
    let guard = FdGuard(sock);
    // While WARP steers modem traffic, the reachability probe must still
    // measure the cellular path (LinkWatch decides on modem recovery from
    // it): the bypass mark skips the WARP rules. No-op when WARP is off.
    if let Some(mark) = crate::vpn::bypass_mark() {
        let m: libc::c_int = mark as libc::c_int;
        unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &m as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    let ident = (std::process::id() & 0xFFFF) as u16;
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // ICMP Echo Request
    pkt[1] = 0;
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..16].copy_from_slice(b"QUECMGR4");
    let csum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&csum.to_be_bytes());

    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dest).to_be(),
        },
        sin_zero: [0; 8],
    };
    let started = Instant::now();
    let sent = unsafe {
        libc::sendto(
            guard.0,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(format!("sendto: {}", std::io::Error::last_os_error()));
    }

    let deadline = started + Duration::from_millis(1800);
    let mut recv_buf = [0u8; 256];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("ICMP request timed out".into());
        }
        let rem_ms = deadline.duration_since(now).as_millis() as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: guard.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
        if prc <= 0 {
            return Err("ICMP request timed out".into());
        }
        let n = unsafe {
            libc::recv(
                guard.0,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
            )
        };
        if n <= 20 {
            continue;
        }
        let slice = &recv_buf[..n as usize];
        let ihl = ((slice[0] & 0x0F) as usize) * 4;
        if slice.len() < ihl + 8 {
            continue;
        }
        let icmp = &slice[ihl..];
        if icmp[0] == 0
            && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
            && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
        {
            return Ok(started.elapsed().as_secs_f64() * 1000.0);
        }
    }
}

/// RTT from `ping -c 1` output, if a reply was received.
pub fn parse_ping_rtt(out: &str) -> Option<f64> {
    out.split_whitespace().find_map(|tok| {
        let ms = tok.strip_prefix("time=")?;
        let num: String = ms.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        num.parse::<f64>().ok()
    })
}

async fn ping_subprocess_fallback(host: &str) -> Result<f64, String> {
    if !crate::admin::validate::is_net_target(host) {
        return Err("Invalid ping host".into());
    }
    // `--` ends option parsing: the host is an operand even if validation regressed.
    let out = run_cmd("ping", &ping_argv(host), Duration::from_secs(3)).await?;
    // No reply line means no reply: report a failure, not a fake 1 ms RTT.
    parse_ping_rtt(&out).ok_or_else(|| "No ICMP reply".to_string())
}

/// argv for the one-shot ping fallback.
pub fn ping_argv(host: &str) -> [&str; 6] {
    ["-c", "1", "-W", "2", "--", host]
}

/// Counts WAN session drops: an up -> down transition, or the session
/// uptime going backwards (a reconnect between two polls).
#[derive(Debug, Default)]
pub struct DisconnectTracker {
    last_uptime: Option<u64>,
    seen_up: bool,
    pub count: u32,
}

impl DisconnectTracker {
    pub fn observe(&mut self, uptime: Option<u64>) -> u32 {
        match (self.last_uptime, uptime) {
            (Some(_), None) => self.count += 1,
            (Some(prev), Some(cur)) if cur < prev => self.count += 1,
            _ => {}
        }
        if uptime.is_some() {
            self.seen_up = true;
        }
        self.last_uptime = uptime;
        self.count
    }
}

static DISCONNECTS: std::sync::Mutex<DisconnectTracker> = std::sync::Mutex::new(DisconnectTracker {
    last_uptime: None,
    seen_up: false,
    count: 0,
});

fn disconnect_count() -> u32 {
    DISCONNECTS.lock().map(|d| d.count).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::redact_sensitive;

    #[test]
    fn icmp_checksum_rfc_validates() {
        let mut pkt = [0u8; 16];
        pkt[0] = 8;
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[6..8].copy_from_slice(&1u16.to_be_bytes());
        pkt[8..16].copy_from_slice(b"QUECMGR4");
        let c = icmp_checksum(&pkt);
        pkt[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn redacts_imei_and_iccid_numbers() {
        assert_eq!(
            redact_sensitive("Profile ICCID 89012600001234567890 ok"),
            "Profile ICCID [REDACTED_ID] ok"
        );
        assert_eq!(redact_sensitive("ARFCN 521310 PCI 589"), "ARFCN 521310 PCI 589");
    }

    #[test]
    fn ping_without_reply_is_an_error() {
        let ok = "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: seq=0 ttl=117 time=31.452 ms\n";
        assert_eq!(parse_ping_rtt(ok), Some(31.452));
        let lost = "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n\n--- 8.8.8.8 ping statistics ---\n1 packets transmitted, 0 packets received, 100% packet loss\n";
        assert_eq!(parse_ping_rtt(lost), None);
    }

    #[test]
    fn disconnects_are_counted() {
        let mut d = DisconnectTracker::default();
        assert_eq!(d.observe(None), 0, "down at start is not a disconnect");
        assert_eq!(d.observe(Some(10)), 0);
        assert_eq!(d.observe(Some(22)), 0);
        assert_eq!(d.observe(None), 1, "up -> down");
        assert_eq!(d.observe(None), 1);
        assert_eq!(d.observe(Some(3)), 1);
        assert_eq!(d.observe(Some(1)), 2, "uptime went backwards: reconnected between polls");
    }

    #[tokio::test]
    async fn poll_system_vitals_resets_session_uptime_when_wan_drops() {
        let env = crate::paths::TestSandbox::new("vitals-wan-drop");
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let auth = crate::auth::AuthStore::new(env.root.join("sessions"));
                let state = AppState::for_tests(env.root.clone(), auth);
                {
                    let s = state.session_uptime.read().await.clone();
                    assert_eq!(s.is_connected, Some(false));
                    assert_eq!(s.disconnect_count, Some(0));
                    assert_eq!(s.uptime_seconds, 0);
                    assert_eq!(s.uptime_formatted, "0s");
                    let d = state.device_uptime.read().await.clone();
                    assert_eq!(d.is_connected, None);
                    assert_eq!(d.disconnect_count, None);
                }

                let up = UptimeTelemetry {
                    uptime_seconds: 120,
                    uptime_formatted: "2m 0s".into(),
                    is_connected: Some(true),
                    disconnect_count: Some(1),
                    timestamp: "2026-11-18 00:00:00".into(),
                };
                poll_system_vitals(&state, "_a", Some(up)).await;
                assert_eq!(state.session_uptime.read().await.is_connected, Some(true));
                assert_eq!(state.session_uptime.read().await.uptime_seconds, 120);

                poll_system_vitals(&state, "_a", None).await;
                let dropped = state.session_uptime.read().await.clone();
                assert_eq!(dropped.is_connected, Some(false));
                assert_eq!(dropped.uptime_seconds, 0);
                assert_eq!(dropped.uptime_formatted, "0s");
                assert!(dropped.disconnect_count.is_some());
            })
            .await;
    }

    #[tokio::test]
    async fn zero_byte_tick_after_clear_does_not_recreate_daily_row() {
        let env = crate::paths::TestSandbox::new("zero-usage-tick");
        std::fs::create_dir_all(env.root.join("etc/cellcore")).unwrap();
        std::fs::create_dir_all(env.root.join("tmp/cellcore/signal_graphs")).unwrap();

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let auth = crate::auth::AuthStore::new(env.root.join("sessions"));
                let app = AppState::for_tests(env.root.clone(), auth);
                {
                    let mut u = app.data_usage.write().await;
                    u.last_iface = "rmnet_data0".into();
                    u.last_raw_rx = 500;
                    u.last_raw_tx = 200;
                    u.daily.clear();
                    u.monthly.clear();
                    save_json_atomic(DATA_USAGE_PATH, &*u, 0o600).unwrap();
                }

                let mut last_flush = 0u64;
                update_persistent_usage(&app, "rmnet_data0", 500, 200, &mut last_flush).await;
                {
                    let u = app.data_usage.read().await;
                    assert!(u.daily.is_empty());
                    assert!(u.monthly.is_empty());
                }
                let on_disk_idle: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(env.root.join("etc/cellcore/data_usage.json")).unwrap())
                        .unwrap();
                assert_eq!(on_disk_idle["daily"], serde_json::json!([]));

                update_persistent_usage(&app, "rmnet_data0", 1524, 200, &mut last_flush).await;
                {
                    let u = app.data_usage.read().await;
                    assert_eq!(u.daily.len(), 1);
                    assert_eq!(u.daily[0].rx_bytes, 1024);
                    assert_eq!(u.monthly.len(), 1);
                }
                let on_disk_active: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(env.root.join("etc/cellcore/data_usage.json")).unwrap())
                        .unwrap();
                assert_eq!(on_disk_active["daily"][0]["rxBytes"], serde_json::json!(1024));
            })
            .await;
    }

    #[test]
    fn should_poll_atfwd_throttles_background_ticks_for_60s() {
        assert!(should_poll_atfwd(Priority::Interactive, false, false, 100, 95));
        assert!(should_poll_atfwd(Priority::Telemetry, true, false, 100, 95));
        assert!(should_poll_atfwd(Priority::Telemetry, false, true, 100, 95));
        assert!(should_poll_atfwd(Priority::Telemetry, false, false, 100, 0));
        assert!(should_poll_atfwd(Priority::Telemetry, false, false, 160, 100));
        assert!(!should_poll_atfwd(Priority::Telemetry, false, false, 159, 100));
    }

    #[test]
    fn telemetry_command_order_keeps_atfwd_mid_batch() {
        let with_atfwd: Vec<String> = build_telemetry_commands(
            "AT+QCAINFO",
            "AT+QNWCFG=\"nr5g_time_advance\"",
            "AT+QNWCFG=\"lte_time_advance\"",
            true,
            false,
        )
        .into_iter()
        .map(|(c, _)| c)
        .collect();
        let qrsrp_i = with_atfwd.iter().position(|c| c == "AT+QRSRP").unwrap();
        let qmap_i = with_atfwd.iter().position(|c| c == "AT+QMAP=\"WWAN\"").unwrap();
        let cgcont_i = with_atfwd.iter().position(|c| c == "AT+CGCONTRDP").unwrap();
        let qtemp_i = with_atfwd.iter().position(|c| c == "AT+QTEMP").unwrap();
        let qspn_i = with_atfwd.iter().position(|c| c == "AT+QSPN").unwrap();
        assert!(qrsrp_i < qmap_i && qmap_i < cgcont_i && cgcont_i < qtemp_i && qtemp_i < qspn_i);
        // Five fast baseband commands always trail AT+QTEMP so /dev/smd11 recovers cleanly.
        assert_eq!(with_atfwd.len() - qtemp_i - 1, 5);

        let fast_only: Vec<String> = build_telemetry_commands(
            "AT+QCAINFO",
            "AT+QNWCFG=\"nr5g_time_advance\"",
            "AT+QNWCFG=\"lte_time_advance\"",
            false,
            false,
        )
        .into_iter()
        .map(|(c, _)| c)
        .collect();
        assert!(!fast_only.iter().any(|c| c == "AT+QMAP=\"WWAN\"" || c == "AT+QTEMP"));
    }

    #[test]
    fn telemetry_command_order_omits_qmap_in_native_mode_while_keeping_qtemp_and_trailing_baseband() {
        let native_cmds: Vec<String> = build_telemetry_commands_with_qmap(
            "AT+QCAINFO",
            "AT+QNWCFG=\"nr5g_time_advance\"",
            "AT+QNWCFG=\"lte_time_advance\"",
            true,
            false,
            false,
        )
        .into_iter()
        .map(|(c, _)| c)
        .collect();
        assert!(!native_cmds.iter().any(|c| c == "AT+QMAP=\"WWAN\""));
        let cgcont_i = native_cmds.iter().position(|c| c == "AT+CGCONTRDP").unwrap();
        let qtemp_i = native_cmds.iter().position(|c| c == "AT+QTEMP").unwrap();
        assert!(cgcont_i < qtemp_i);
        assert_eq!(native_cmds.len() - qtemp_i - 1, 5);
    }

    #[tokio::test]
    async fn http_keepalive_dl_burst_reuses_socket_and_reconnects_on_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicU64::new(0));
        let reqs = Arc::new(AtomicU64::new(0));
        let accepts_srv = accepts.clone();
        let reqs_srv = reqs.clone();

        let server = tokio::spawn(async move {
            // Connection 1 serves 2 keep-alive requests then closes; connection 2 serves 1.
            for max_reqs in [2usize, 1usize] {
                let (mut sock, _) = listener.accept().await.unwrap();
                accepts_srv.fetch_add(1, Ordering::SeqCst);
                let payload = vec![b'X'; 65536];
                for _ in 0..max_reqs {
                    let mut req_buf = Vec::new();
                    let mut tmp = [0u8; 512];
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap();
                        assert!(n > 0);
                        req_buf.extend_from_slice(&tmp[..n]);
                        if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    reqs_srv.fetch_add(1, Ordering::SeqCst);
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        payload.len()
                    );
                    sock.write_all(hdr.as_bytes()).await.unwrap();
                    sock.write_all(&payload).await.unwrap();
                }
            }
        });

        let mut conn: Option<TcpStream> = None;
        let b1 = http_keepalive_dl_burst(&mut conn, "127.0.0.1", port, "/__down?bytes=65536", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(b1, 65536);
        assert!(conn.is_some());

        let b2 = http_keepalive_dl_burst(&mut conn, "127.0.0.1", port, "/__down?bytes=65536", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(b2, 65536);
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "second burst must reuse keep-alive socket");
        assert_eq!(reqs.load(Ordering::SeqCst), 2);

        // Give server a moment to close connection 1 after its 2nd response, then burst 3 reconnects.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let b3 = http_keepalive_dl_burst(&mut conn, "127.0.0.1", port, "/__down?bytes=65536", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(b3, 65536);
        assert_eq!(accepts.load(Ordering::SeqCst), 2, "third burst should transparently reconnect");
        assert_eq!(reqs.load(Ordering::SeqCst), 3);

        server.await.unwrap();
    }
}

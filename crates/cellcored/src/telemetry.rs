use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
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
        MimoSignalData, ServingCellInfo, clean_at_lines, mask_secret_id, merge_nr5g_mimo_layers,
        overlay_native_bearer, parse_3gpp_rel, parse_active_wwan, parse_carrier_aggregation,
        parse_mimo_signal, parse_neighbor_cells, parse_nr5g_mimo_info, parse_nr5g_pathloss,
        parse_qspn_operator, parse_scalar_at_value, parse_serving_cell, parse_ssb_beam_id,
        parse_temp_sensors, parse_time_advance_for_rat, read_sysfs_thermals,
    },
    reconcile::current_usb_gadget_udc,
    smd::Priority,
    state::{
        AlertLogEntry, AppState, CarrierMimoLayer, CellLockBypassReason, DailyUsageEntry,
        DataUsageState, MemoryTelemetry, MonthlyUsageEntry, PingPoint, SignalHistoryPoint,
        TrafficDirectionStats, TrafficHistoryPoint, TrafficInterfaceStats, UptimeTelemetry,
        format_now_hms, format_today_ymd, load_json_or_default, mono_ms, save_json_compact_atomic,
        save_json_compact_tmpfs,
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
static COMPOUND_RF_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

pub fn reset_compound_rf_cache() {
    COMPOUND_RF_UNSUPPORTED.store(false, Ordering::Relaxed);
}

const ALIGN_KEEP_AWAKE_INTERVAL_MS: u64 = 1000;
const ALIGN_KEEP_AWAKE_HOST: &str = "speed.cloudflare.com";
const ALIGN_KEEP_AWAKE_PORT: u16 = 80;
const ALIGN_KEEP_AWAKE_PATH: &str = "/__down?bytes=32768";
const ALIGN_KEEP_AWAKE_MAX_BODY: usize = 256 * 1024;
const ALIGN_SECONDARY_HOLD_MS: u64 = 2500;

pub const DATA_USAGE_PATH: &str = "/etc/cellcore/data_usage.json";
pub const DATA_USAGE_TMP_PATH: &str = "/tmp/cellcore/data_usage.json";
pub const DATA_USAGE_SNAPSHOT_FLUSH_SECS: u64 = 300;
pub const DATA_USAGE_ETC_FLUSH_SECS: u64 = 6 * 3600;
pub const DATA_USAGE_ETC_FLUSH_BYTES: u64 = 512 * 1024 * 1024;
pub const DATA_USAGE_ETC_MIN_DEBOUNCE_SECS: u64 = 3600;
pub const CELL_LOCK_BYPASS_TMP_PATH: &str = "/tmp/cellcore/cell_lock_bypassed.json";

pub const LIVENESS_WATCHDOG_CHECK_SECS: u64 = 30;
pub const LIVENESS_WATCHDOG_TIMEOUT_MS: u64 = 180_000;
pub const QSCAN_WATCHDOG_GRACE_MS: u64 = 200_000;
/// Extra slack beyond an in-flight console AT command's timeout for resync/RF batch completion.
pub const CONSOLE_AT_WATCHDOG_OVERHEAD_MS: u64 = 20_000;
/// Hard ceiling on watchdog grace granted to an in-flight console AT command so a wedged daemon still aborts.
pub const CONSOLE_AT_WATCHDOG_MAX_GRACE_MS: u64 = 90_000;
pub const RSS_WARN_BYTES: u64 = 80 * 1024 * 1024;
pub const FD_WARN_COUNT: u64 = 256;
pub const LINKWATCH_COOLDOWN_SECS: u64 = 900;
pub const SIM_ATTACH_SETTLE_MS: u64 = 45_000;
pub const CLOUDFLARED_METRICS_ADDR: &str = "127.0.0.1:20241";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedCellLockBypass {
    bypassed: bool,
    reason: u8,
    ts: u64,
}

/// Load persisted cell-lock bypass state from tmpfs (`/tmp/cellcore/cell_lock_bypassed.json`).
pub fn load_initial_cell_lock_bypass() -> (bool, CellLockBypassReason) {
    let p = crate::paths::p(CELL_LOCK_BYPASS_TMP_PATH);
    if let Ok(raw) = fs::read_to_string(&p)
        && let Ok(rec) = serde_json::from_str::<PersistedCellLockBypass>(&raw)
        && rec.bypassed
    {
        return (true, CellLockBypassReason::from_u8(rec.reason));
    }
    (false, CellLockBypassReason::None)
}

fn persist_cell_lock_bypass_state(bypassed: bool, reason: CellLockBypassReason) {
    if bypassed {
        let rec = PersistedCellLockBypass {
            bypassed: true,
            reason: reason.to_u8(),
            ts: now_secs(),
        };
        let _ = save_json_compact_tmpfs(CELL_LOCK_BYPASS_TMP_PATH, &rec, 0o600);
    } else {
        let _ = fs::remove_file(crate::paths::p(CELL_LOCK_BYPASS_TMP_PATH));
    }
}

pub(crate) fn clear_cell_lock_bypass_state(state: &AppState) {
    state.cell_lock_bypassed.store(false, Ordering::Release);
    state
        .cell_lock_bypass_reason
        .store(CellLockBypassReason::None.to_u8(), Ordering::Release);
    persist_cell_lock_bypass_state(false, CellLockBypassReason::None);
}

struct RecoveryGuard(Arc<AtomicBool>);

impl RecoveryGuard {
    fn acquire(flag: &Arc<AtomicBool>) -> Self {
        flag.store(true, Ordering::Release);
        Self(Arc::clone(flag))
    }
}

impl Drop for RecoveryGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Load whichever of `/tmp/cellcore/data_usage.json` and `/etc/cellcore/data_usage.json`
/// has the newer mtime and parses cleanly, avoiding stale tmpfs snapshots overriding newer flash state.
pub fn load_initial_data_usage() -> DataUsageState {
    let tmp_p = crate::paths::p(DATA_USAGE_TMP_PATH);
    let etc_p = crate::paths::p(DATA_USAGE_PATH);
    let read_pair = |path: &str| -> Option<(Option<SystemTime>, DataUsageState)> {
        let raw = fs::read_to_string(path).ok()?;
        let parsed = serde_json::from_str::<DataUsageState>(&raw).ok()?;
        let mtime = fs::metadata(path).ok().and_then(|m| m.modified().ok());
        Some((mtime, parsed))
    };
    match (read_pair(&tmp_p), read_pair(&etc_p)) {
        (Some((Some(tm), tv)), Some((Some(em), ev))) => {
            if em > tm {
                ev
            } else {
                tv
            }
        }
        (Some((_, tv)), Some((_, _))) => tv,
        (Some((_, tv)), None) => tv,
        (None, Some((_, ev))) => ev,
        (None, None) => load_json_or_default(DATA_USAGE_PATH),
    }
}

pub fn parse_proc_statm_rss_bytes(statm: &str, page_size: u64) -> Option<u64> {
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(resident_pages.saturating_mul(page_size))
}

fn sample_self_rss_and_fds() -> (u64, u64) {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_bytes = if page_size > 0 { page_size as u64 } else { 4096 };
    let rss = fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| parse_proc_statm_rss_bytes(&s, page_bytes))
        .unwrap_or(0);
    let fds = fs::read_dir("/proc/self/fd")
        .map(|it| it.count() as u64)
        .unwrap_or(0);
    (rss, fds)
}

/// Pure watchdog RF grace predicate: grants bounded grace while an active
/// `AT+QSCAN` (`<= QSCAN_WATCHDOG_GRACE_MS`) or a tracked console AT command
/// (`<= (timeout + overhead).min(CONSOLE_AT_WATCHDOG_MAX_GRACE_MS)`) is in flight.
pub fn watchdog_rf_in_grace(
    now_ms: u64,
    qscan_started_ms: u64,
    console_at_started_ms: u64,
    console_at_timeout_ms: u64,
) -> bool {
    let in_qscan =
        qscan_started_ms > 0 && now_ms.saturating_sub(qscan_started_ms) <= QSCAN_WATCHDOG_GRACE_MS;
    let in_console_at = if console_at_started_ms > 0 {
        let budget = console_at_timeout_ms
            .saturating_add(CONSOLE_AT_WATCHDOG_OVERHEAD_MS)
            .min(CONSOLE_AT_WATCHDOG_MAX_GRACE_MS);
        now_ms.saturating_sub(console_at_started_ms) <= budget
    } else {
        false
    };
    in_qscan || in_console_at
}

/// Spawn a dedicated lightweight OS thread (`cellcore-wdt`) outside the Tokio runtime
/// that checks independent monotonic heartbeats (`rf`, `net`, `linkwatch`, `http`)
/// every 30s, samples RSS/FD counts, and aborts if any loop stalls >180s
/// (with bounded grace on `rf` while `AT+QSCAN` or a tracked console AT command runs).
pub fn spawn_liveness_watchdog(state: &AppState) {
    let init = mono_ms();
    state.hb_rf_ms.store(init, Ordering::Release);
    state.hb_net_ms.store(init, Ordering::Release);
    state.hb_linkwatch_ms.store(init, Ordering::Release);
    state.hb_http_ms.store(init, Ordering::Release);
    let (rss0, fds0) = sample_self_rss_and_fds();
    state.process_rss_bytes.store(rss0, Ordering::Relaxed);
    state.process_open_fds.store(fds0, Ordering::Relaxed);

    let st = state.clone();
    let _ = std::thread::Builder::new()
        .name("cellcore-wdt".into())
        .spawn(move || {
            let mut last_rss_warn_ms: u64 = 0;
            let mut last_fd_warn_ms: u64 = 0;
            loop {
                std::thread::sleep(Duration::from_secs(LIVENESS_WATCHDOG_CHECK_SECS));
                let now = mono_ms();

                let (rss, fds) = sample_self_rss_and_fds();
                st.process_rss_bytes.store(rss, Ordering::Relaxed);
                st.process_open_fds.store(fds, Ordering::Relaxed);
                if rss > RSS_WARN_BYTES && now.saturating_sub(last_rss_warn_ms) >= 300_000 {
                    last_rss_warn_ms = now;
                    let msg = format!(
                        "cellcore-wdt: high RSS {:.1} MiB (> {} MiB threshold)",
                        rss as f64 / (1024.0 * 1024.0),
                        RSS_WARN_BYTES / (1024 * 1024)
                    );
                    eprintln!("{msg}");
                    st.push_daemon_log(msg);
                }
                if fds > FD_WARN_COUNT && now.saturating_sub(last_fd_warn_ms) >= 300_000 {
                    last_fd_warn_ms = now;
                    let msg = format!(
                        "cellcore-wdt: high open FD count {fds} (> {FD_WARN_COUNT} threshold)"
                    );
                    eprintln!("{msg}");
                    st.push_daemon_log(msg);
                }

                let qscan_start = st.qscan_started_ms.load(Ordering::Acquire);
                let (console_at_start, console_at_timeout) = st.console_at_window();
                let rf_in_grace = watchdog_rf_in_grace(
                    now,
                    qscan_start,
                    console_at_start,
                    console_at_timeout,
                );

                let checks: [(&str, &Arc<AtomicU64>, bool); 4] = [
                    ("rf", &st.hb_rf_ms, rf_in_grace),
                    ("net", &st.hb_net_ms, false),
                    ("linkwatch", &st.hb_linkwatch_ms, false),
                    ("http", &st.hb_http_ms, false),
                ];
                for (name, hb, grace) in checks {
                    if grace {
                        continue;
                    }
                    let last = hb.load(Ordering::Acquire);
                    if last > 0 && now.saturating_sub(last) > LIVENESS_WATCHDOG_TIMEOUT_MS {
                        eprintln!(
                            "cellcore-wdt: {name} loop stalled for {} ms (> {} ms); aborting for procd respawn",
                            now.saturating_sub(last),
                            LIVENESS_WATCHDOG_TIMEOUT_MS
                        );
                        std::process::abort();
                    }
                }
            }
        });
}

#[derive(Debug, Default)]
pub(crate) struct CellLockDeadmanTracker {
    pub unregistered_since: Option<Instant>,
    pub bypassed_since: Option<Instant>,
    pub last_reprobe: Option<Instant>,
    pub reprobe_stage: u8,
    pub trial_relock_inflight: Arc<AtomicBool>,
}

impl CellLockDeadmanTracker {
    pub fn reprobe_backoff(stage: u8) -> Duration {
        match stage {
            0 => Duration::from_secs(15 * 60),
            1 => Duration::from_secs(30 * 60),
            _ => Duration::from_secs(60 * 60),
        }
    }
}

pub fn is_modem_registered(serving: Option<&ServingCellInfo>) -> bool {
    let Some(s) = serving else {
        return false;
    };
    let st = s.state.trim().to_ascii_uppercase();
    !st.is_empty()
        && !matches!(st.as_str(), "SEARCH" | "LIMSRV" | "DISCONNECTED" | "UNKNOWN")
        && !s.rat.trim().is_empty()
}

pub type CellLockTarget = (i32, Option<i64>);

pub fn target_cell_lock_params(
    cfg: &crate::state::DaemonSettings,
) -> (Option<CellLockTarget>, Option<CellLockTarget>) {
    let nr_parts: Vec<&str> = cfg
        .cell_lock_nr5g
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let nr = nr_parts.first().and_then(|s| s.parse::<i32>().ok()).map(|pci| {
        let arfcn = nr_parts.get(1).and_then(|s| s.parse::<i64>().ok());
        (pci, arfcn)
    });
    let lte_parts: Vec<&str> = cfg
        .cell_lock_lte
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let lte = if lte_parts.len() >= 3 {
        lte_parts[2].parse::<i32>().ok().map(|pci| {
            let earfcn = lte_parts[1].parse::<i64>().ok();
            (pci, earfcn)
        })
    } else {
        lte_parts
            .first()
            .and_then(|s| s.parse::<i32>().ok())
            .map(|pci| (pci, None))
    };
    (nr, lte)
}

pub fn target_cell_lock_pcis(cfg: &crate::state::DaemonSettings) -> (Option<i32>, Option<i32>) {
    let (nr, lte) = target_cell_lock_params(cfg);
    (nr.map(|(p, _)| p), lte.map(|(p, _)| p))
}

pub fn serving_matches_cell_lock(
    serving: &ServingCellInfo,
    cfg: &crate::state::DaemonSettings,
    require_arfcn: bool,
) -> bool {
    if !is_modem_registered(Some(serving)) {
        return false;
    }
    let Some(got_pci) = serving.pci else {
        return false;
    };
    let (nr, lte) = target_cell_lock_params(cfg);
    let matches_pair = |target: Option<(i32, Option<i64>)>| -> bool {
        let Some((want_pci, want_arfcn)) = target else {
            return false;
        };
        if got_pci != want_pci {
            return false;
        }
        match (want_arfcn, serving.arfcn) {
            (Some(wa), Some(ga)) => wa == ga,
            (Some(_), None) => !require_arfcn,
            (None, _) => true,
        }
    };
    matches_pair(nr) || matches_pair(lte)
}

pub fn is_within_cell_lock_schedule(cfg: &crate::state::DaemonSettings, now_min: u16) -> bool {
    if !cfg.cell_lock_sched_enabled {
        return true;
    }
    match (
        crate::profiles::parse_hhmm(&cfg.cell_lock_start_time),
        crate::profiles::parse_hhmm(&cfg.cell_lock_end_time),
    ) {
        (Some(start), Some(end)) => {
            if start <= end {
                now_min >= start && now_min < end
            } else {
                now_min >= start || now_min < end
            }
        }
        _ => false,
    }
}

async fn sim_ready_for_deadman(state: &AppState) -> bool {
    match state
        .smd
        .exec("AT+CPIN?", Priority::Background, Duration::from_secs(3))
        .await
    {
        Ok(r) if !r.ok => false,
        Ok(r) => {
            let up = r.body.to_ascii_uppercase();
            if up.contains("+CPIN:") {
                up.contains("READY")
            } else {
                true
            }
        }
        Err(_) => false,
    }
}

async fn push_alert(state: &AppState, kind: &str, message: impl Into<String>) {
    let msg = message.into();
    let mut alerts = state.alerts.write().await;
    if alerts.len() >= 20 {
        alerts.pop_back();
    }
    alerts.push_front(AlertLogEntry {
        r#type: kind.into(),
        message: msg,
        timestamp: format_now_hms(),
    });
}

pub(crate) async fn bypass_cell_lock_temporarily(
    state: &AppState,
    reason: &str,
    bypass_kind: CellLockBypassReason,
) -> bool {
    let _rec_guard = RecoveryGuard::acquire(&state.recovery_in_progress);
    let (has_nr, has_lte) = {
        let cfg = state.settings.read().await;
        (!cfg.cell_lock_nr5g.is_empty(), !cfg.cell_lock_lte.is_empty())
    };
    let _guard = crate::radio::lock_bounded(state, Duration::from_secs(6)).await;
    let cmds = vec![
        ("AT+QNWLOCK=\"common/5g\",0".into(), Duration::from_secs(5)),
        ("AT+QNWLOCK=\"common/4g\",0".into(), Duration::from_secs(5)),
        ("AT+QNWCFG=\"nr5g_earfcn_lock\",0".into(), Duration::from_secs(4)),
        ("AT+QNWLOCK=\"save_ctrl\",0,0".into(), Duration::from_secs(4)),
    ];
    let verified_ok = match state.smd.exec_batch(cmds, Priority::Emergency).await {
        Ok(res) => {
            let nr_ok = res.first().and_then(|r| r.as_ref().ok()).is_some_and(|r| r.ok);
            let lte_ok = res.get(1).and_then(|r| r.as_ref().ok()).is_some_and(|r| r.ok);
            match (has_nr, has_lte) {
                (true, true) => nr_ok && lte_ok,
                (true, false) => nr_ok,
                (false, true) => lte_ok,
                (false, false) => nr_ok || lte_ok,
            }
        }
        Err(_) => false,
    };
    if !verified_ok {
        state.push_daemon_log(format!(
            "Cell-lock bypass AT clear failed ({reason}); leaving bypass state unchanged"
        ));
        return false;
    }
    state.cell_lock_bypassed.store(true, Ordering::Release);
    state
        .cell_lock_bypass_reason
        .store(bypass_kind.to_u8(), Ordering::Release);
    persist_cell_lock_bypass_state(true, bypass_kind);
    state.push_daemon_log(reason);
    push_alert(state, "cell_lock_deadman", reason).await;
    crate::obs::emit(
        crate::obs::EventKind::CellLockBypassed,
        crate::obs::Severity::Warning,
        "Cell lock temporarily bypassed (dead-man's-switch)",
        serde_json::json!({ "bypassed": true, "reason": reason }),
    );
    true
}

pub(crate) async fn restore_cell_lock_from_settings(
    state: &AppState,
    cfg: &crate::state::DaemonSettings,
) {
    let _rec_guard = RecoveryGuard::acquire(&state.recovery_in_progress);
    if !cfg.cell_lock_nr5g.is_empty() {
        let cmd = format!("AT+QNWLOCK=\"common/5g\",{}", cfg.cell_lock_nr5g);
        let _ = state.smd.exec(cmd, Priority::Background, Duration::from_secs(6)).await;
    }
    if !cfg.cell_lock_lte.is_empty() {
        let cmd = format!("AT+QNWLOCK=\"common/4g\",{}", cfg.cell_lock_lte);
        let _ = state.smd.exec(cmd, Priority::Background, Duration::from_secs(6)).await;
    }
    let save_cmd = format!(
        "AT+QNWLOCK=\"save_ctrl\",{},{}",
        if cfg.cell_lock_lte_persist { 1 } else { 0 },
        if cfg.cell_lock_nr5g_persist { 1 } else { 0 }
    );
    let _ = state
        .smd
        .exec(save_cmd, Priority::Background, Duration::from_secs(5))
        .await;
    clear_cell_lock_bypass_state(state);
    let msg = "Cell-lock dead-man's-switch restored configured cell lock after target cell re-appeared";
    state.push_daemon_log(msg);
    push_alert(state, "cell_lock_deadman", msg).await;
    crate::obs::emit(
        crate::obs::EventKind::CellLockBypassed,
        crate::obs::Severity::Info,
        "Configured cell lock restored",
        serde_json::json!({ "bypassed": false, "reason": msg }),
    );
}

async fn run_trial_cell_lock_restore(
    state: AppState,
    cfg: crate::state::DaemonSettings,
    trial_attach_wait: Duration,
) -> bool {
    let _rec_guard = RecoveryGuard::acquire(&state.recovery_in_progress);
    {
        let _guard = crate::radio::lock_bounded(&state, Duration::from_secs(6)).await;
        if !cfg.cell_lock_nr5g.is_empty() {
            let _ = state
                .smd
                .exec(
                    format!("AT+QNWLOCK=\"common/5g\",{}", cfg.cell_lock_nr5g),
                    Priority::Background,
                    Duration::from_secs(6),
                )
                .await;
        }
        if !cfg.cell_lock_lte.is_empty() {
            let _ = state
                .smd
                .exec(
                    format!("AT+QNWLOCK=\"common/4g\",{}", cfg.cell_lock_lte),
                    Priority::Background,
                    Duration::from_secs(6),
                )
                .await;
        }
    }
    if !trial_attach_wait.is_zero() {
        tokio::time::sleep(trial_attach_wait).await;
    }
    let matched = state
        .smd
        .exec("AT+QENG=\"servingcell\"", Priority::Background, Duration::from_secs(4))
        .await
        .ok()
        .and_then(|r| parse_serving_cell(&r.body, &[]))
        .is_some_and(|s| serving_matches_cell_lock(&s, &cfg, true));
    let _guard = crate::radio::lock_bounded(&state, Duration::from_secs(6)).await;
    if matched {
        let save_cmd = format!(
            "AT+QNWLOCK=\"save_ctrl\",{},{}",
            if cfg.cell_lock_lte_persist { 1 } else { 0 },
            if cfg.cell_lock_nr5g_persist { 1 } else { 0 }
        );
        let _ = state
            .smd
            .exec(save_cmd, Priority::Background, Duration::from_secs(5))
            .await;
        clear_cell_lock_bypass_state(&state);
        let msg = "Cell-lock 60m trial re-probe attached to target PCI/ARFCN; restored cell lock";
        state.push_daemon_log(msg);
        push_alert(&state, "cell_lock_deadman", msg).await;
        crate::obs::emit(
            crate::obs::EventKind::CellLockBypassed,
            crate::obs::Severity::Info,
            "Configured cell lock restored",
            serde_json::json!({ "bypassed": false, "reason": msg }),
        );
        true
    } else {
        let clear_cmds = vec![
            ("AT+QNWLOCK=\"common/5g\",0".into(), Duration::from_secs(5)),
            ("AT+QNWLOCK=\"common/4g\",0".into(), Duration::from_secs(5)),
            ("AT+QNWCFG=\"nr5g_earfcn_lock\",0".into(), Duration::from_secs(4)),
            ("AT+QNWLOCK=\"save_ctrl\",0,0".into(), Duration::from_secs(4)),
        ];
        let _ = state.smd.exec_batch(clear_cmds, Priority::Emergency).await;
        state.push_daemon_log(
            "Cell-lock 60m trial re-probe did not attach to target PCI/ARFCN; keeping bypass active",
        );
        false
    }
}

fn ssb_response_matches_pci(body: &str, want_pci: i32) -> bool {
    for line in clean_at_lines(body) {
        if !line.to_ascii_lowercase().contains("ssb_beam_id") {
            continue;
        }
        for tok in line.split([',', ':', '"', ' ']) {
            if tok.trim().parse::<i32>().ok() == Some(want_pci) {
                return true;
            }
        }
    }
    false
}

pub(crate) async fn tick_cell_lock_deadman(
    state: &AppState,
    tracker: &mut CellLockDeadmanTracker,
    now: Instant,
    trial_attach_wait: Duration,
) {
    let cfg = state.settings.read().await.clone();
    let has_lock = !cfg.cell_lock_nr5g.is_empty() || !cfg.cell_lock_lte.is_empty();
    if !has_lock {
        *tracker = CellLockDeadmanTracker::default();
        if state.cell_lock_bypassed.load(Ordering::Acquire) {
            clear_cell_lock_bypass_state(state);
        }
        return;
    }

    let (cfun, serving) = {
        let m = state.modem.read().await;
        (m.identity.cfun, m.serving.clone())
    };

    if !state.cell_lock_bypassed.load(Ordering::Acquire) {
        tracker.bypassed_since = None;
        tracker.last_reprobe = None;
        tracker.reprobe_stage = 0;
        if !cfg.cell_lock_deadman_enabled || cfun != 1 || is_modem_registered(serving.as_ref()) {
            tracker.unregistered_since = None;
            return;
        }
        if cfg.cell_lock_sched_enabled {
            let now_min = (crate::obs::usage_cycle::local_now().1 / 60) as u16;
            if !is_within_cell_lock_schedule(&cfg, now_min) {
                tracker.unregistered_since = None;
                return;
            }
        }
        let since = *tracker.unregistered_since.get_or_insert(now);
        if now.saturating_duration_since(since)
            >= Duration::from_secs(cfg.cell_lock_deadman_secs.max(1))
        {
            if !sim_ready_for_deadman(state).await {
                tracker.unregistered_since = None;
                state.push_daemon_log(
                    "Cell-lock dead-man's-switch skipped: SIM absent or PIN-locked",
                );
                return;
            }
            if bypass_cell_lock_temporarily(
                state,
                "Cell-lock dead-man's-switch temporarily cleared live lock after prolonged loss of registration",
                CellLockBypassReason::Deadman,
            )
            .await
            {
                tracker.unregistered_since = None;
                tracker.bypassed_since = Some(now);
                tracker.last_reprobe = Some(now);
                tracker.reprobe_stage = 0;
            }
        }
        return;
    }

    // Currently bypassed:
    tracker.unregistered_since = None;
    let bypass_reason =
        CellLockBypassReason::from_u8(state.cell_lock_bypass_reason.load(Ordering::Acquire));
    if !cfg.cell_lock_deadman_enabled {
        // Never undo an active LinkWatch Stage 3 bypass just because deadman is disabled.
        if bypass_reason == CellLockBypassReason::LinkWatch {
            return;
        }
        let _guard = crate::radio::lock_bounded(state, Duration::from_secs(6)).await;
        restore_cell_lock_from_settings(state, &cfg).await;
        *tracker = CellLockDeadmanTracker::default();
        return;
    }
    if crate::obs::failover::is_active() || tracker.trial_relock_inflight.load(Ordering::Acquire) {
        return;
    }

    let wait_dur = CellLockDeadmanTracker::reprobe_backoff(tracker.reprobe_stage);
    let anchor = tracker
        .last_reprobe
        .unwrap_or_else(|| *tracker.bypassed_since.get_or_insert(now));
    if now.saturating_duration_since(anchor) < wait_dur {
        return;
    }
    tracker.last_reprobe = Some(now);

    let (want_nr_pci, want_lte_pci) = target_cell_lock_pcis(&cfg);
    let mut visible = serving
        .as_ref()
        .is_some_and(|s| serving_matches_cell_lock(s, &cfg, false));

    if !visible {
        let mut probe_cmds = vec![("AT+QENG=\"neighbourcell\"".into(), Duration::from_secs(5))];
        if want_nr_pci.is_some() {
            probe_cmds.push(("AT+QNWCFG=\"ssb_beam_id\"".into(), Duration::from_secs(3)));
        }
        if let Ok(res) = state.smd.exec_batch(probe_cmds, Priority::Background).await {
            if let Some(Ok(nb)) = res.first() {
                let cells = parse_neighbor_cells(&nb.body);
                visible = cells.iter().any(|c| {
                    c.pci.is_some() && (c.pci == want_nr_pci || c.pci == want_lte_pci)
                });
            }
            if !visible
                && let Some(np) = want_nr_pci
                && let Some(Ok(ssb)) = res.get(1)
                && ssb.ok
            {
                visible = ssb_response_matches_pci(&ssb.body, np)
                    || (parse_ssb_beam_id(&ssb.body).is_some()
                        && serving.as_ref().and_then(|s| s.pci) == Some(np));
            }
        }
    }

    if visible {
        let _guard = crate::radio::lock_bounded(state, Duration::from_secs(6)).await;
        restore_cell_lock_from_settings(state, &cfg).await;
        *tracker = CellLockDeadmanTracker::default();
        return;
    }

    // On the 60m backoff stage, run the 25s trial re-lock in a spawned task so the RF loop never stalls.
    if tracker.reprobe_stage >= 2 {
        if trial_attach_wait.is_zero() {
            if run_trial_cell_lock_restore(state.clone(), cfg, Duration::ZERO).await {
                *tracker = CellLockDeadmanTracker::default();
                return;
            }
        } else if tracker
            .trial_relock_inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let flag = Arc::clone(&tracker.trial_relock_inflight);
            let st_clone = state.clone();
            tokio::spawn(async move {
                struct InflightDrop(Arc<AtomicBool>);
                impl Drop for InflightDrop {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _drop_guard = InflightDrop(flag);
                let _ = run_trial_cell_lock_restore(st_clone, cfg, trial_attach_wait).await;
            });
        }
    }

    tracker.reprobe_stage = (tracker.reprobe_stage + 1).min(2);
}

pub const BAND_ESCAPE_UNREG_SECS: u64 = 45;
pub const BAND_ESCAPE_RESTORE_HEALTHY_SECS: u64 = 60;

#[derive(Debug, Default)]
pub struct BandLockEscapeTracker {
    pub unregistered_since: Option<Instant>,
    pub saved_mode_pref: Option<String>,
    pub healthy_standby_since: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandEscapeAction {
    None,
    ProbeAndEscape,
    Restore,
}

/// True when the active radio configuration restricts fallback connectivity
/// during failover: `mode_pref == "NR5G"` only, or an NR5G band lock that
/// excludes low-band `n71`.
pub fn is_restrictive_band_or_mode(mode_pref: &str, nr5g_bands: &[String]) -> bool {
    let mode_upper = mode_pref.trim().to_ascii_uppercase();
    let nr_only = mode_upper == "NR5G";
    let missing_n71 = !nr5g_bands.is_empty() && !nr5g_bands.iter().any(|b| b.trim() == "71");
    nr_only || missing_n71
}

/// Pure failover-aware band-lock escape state machine.
pub fn evaluate_band_escape(
    tracker: &mut BandLockEscapeTracker,
    failover_active: bool,
    cfun: i32,
    registered: bool,
    now: Instant,
) -> BandEscapeAction {
    if tracker.saved_mode_pref.is_none() {
        tracker.healthy_standby_since = None;
        if !failover_active || cfun != 1 || registered {
            tracker.unregistered_since = None;
            return BandEscapeAction::None;
        }
        let since = *tracker.unregistered_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= Duration::from_secs(BAND_ESCAPE_UNREG_SECS) {
            BandEscapeAction::ProbeAndEscape
        } else {
            BandEscapeAction::None
        }
    } else {
        tracker.unregistered_since = None;
        if failover_active || cfun != 1 || !registered {
            tracker.healthy_standby_since = None;
            return BandEscapeAction::None;
        }
        let since = *tracker.healthy_standby_since.get_or_insert(now);
        if now.saturating_duration_since(since)
            >= Duration::from_secs(BAND_ESCAPE_RESTORE_HEALTHY_SECS)
        {
            BandEscapeAction::Restore
        } else {
            BandEscapeAction::None
        }
    }
}

pub(crate) async fn tick_band_lock_escape(
    state: &AppState,
    tracker: &mut BandLockEscapeTracker,
    now: Instant,
) {
    let (cfun, serving) = {
        let m = state.modem.read().await;
        (m.identity.cfun, m.serving.clone())
    };
    let action = evaluate_band_escape(
        tracker,
        crate::obs::failover::is_active(),
        cfun,
        is_modem_registered(serving.as_ref()),
        now,
    );
    match action {
        BandEscapeAction::None => {}
        BandEscapeAction::ProbeAndEscape => {
            if !sim_ready_for_deadman(state).await {
                tracker.unregistered_since = Some(now);
                return;
            }
            let _guard = crate::radio::lock_bounded(state, Duration::from_secs(6)).await;
            let cmds = vec![
                ("AT+QNWPREFCFG=\"mode_pref\"".into(), Duration::from_secs(4)),
                ("AT+QNWPREFCFG=\"nr5g_band\"".into(), Duration::from_secs(4)),
            ];
            let Ok(res) = state.smd.exec_batch(cmds, Priority::Emergency).await else {
                tracker.unregistered_since = Some(now);
                return;
            };
            let mode_body = res
                .first()
                .and_then(|r| r.as_ref().ok())
                .map(|r| r.body.as_str())
                .unwrap_or("");
            let nr_body = res
                .get(1)
                .and_then(|r| r.as_ref().ok())
                .map(|r| r.body.as_str())
                .unwrap_or("");
            let mode_pref = crate::handlers::parse_mode_pref(mode_body)
                .unwrap_or_else(|| "AUTO".into());
            let nr5g_bands = crate::parsers::parse_qnw_band_list(nr_body, "nr5g_band");
            if !is_restrictive_band_or_mode(&mode_pref, &nr5g_bands) {
                tracker.unregistered_since = Some(now);
                return;
            }
            let widened = if mode_pref.eq_ignore_ascii_case("AUTO") {
                true
            } else {
                state
                    .smd
                    .exec(
                        "AT+QNWPREFCFG=\"mode_pref\",AUTO",
                        Priority::Emergency,
                        Duration::from_secs(6),
                    )
                    .await
                    .is_ok_and(|r| r.ok)
            };
            if widened {
                tracker.saved_mode_pref = Some(mode_pref.clone());
                tracker.unregistered_since = None;
                tracker.healthy_standby_since = None;
                crate::handlers::forget_radio_mode(state);
                let msg = format!(
                    "Failover band-lock escape hatch widened mode_pref from {mode_pref} to AUTO after {}s unregistered",
                    BAND_ESCAPE_UNREG_SECS
                );
                state.push_daemon_log(&msg);
                push_alert(state, "band_escape", &msg).await;
                crate::obs::emit(
                    crate::obs::EventKind::BandChange,
                    crate::obs::Severity::Warning,
                    "Failover band-lock escape hatch widened mode_pref to AUTO",
                    serde_json::json!({
                        "escaped": true,
                        "previousModePref": mode_pref,
                        "newModePref": "AUTO",
                        "nr5gBands": nr5g_bands,
                    }),
                );
            } else {
                tracker.unregistered_since = Some(now);
            }
        }
        BandEscapeAction::Restore => {
            let Some(saved) = tracker.saved_mode_pref.clone() else {
                return;
            };
            let _guard = crate::radio::lock_bounded(state, Duration::from_secs(6)).await;
            let restored = if saved.eq_ignore_ascii_case("AUTO") {
                true
            } else {
                state
                    .smd
                    .exec(
                        format!("AT+QNWPREFCFG=\"mode_pref\",{saved}"),
                        Priority::Background,
                        Duration::from_secs(6),
                    )
                    .await
                    .is_ok_and(|r| r.ok)
            };
            if restored {
                tracker.saved_mode_pref = None;
                tracker.healthy_standby_since = None;
                crate::handlers::forget_radio_mode(state);
                let msg = format!(
                    "Restored mode_pref to {saved} after failover ended and registration stayed healthy for {}s",
                    BAND_ESCAPE_RESTORE_HEALTHY_SECS
                );
                state.push_daemon_log(&msg);
                push_alert(state, "band_escape", &msg).await;
                crate::obs::emit(
                    crate::obs::EventKind::BandChange,
                    crate::obs::Severity::Info,
                    format!("Restored mode_pref to {saved} after failover"),
                    serde_json::json!({
                        "escaped": false,
                        "restoredModePref": saved,
                    }),
                );
            } else {
                tracker.healthy_standby_since = Some(now);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct UsageFlushTracker {
    pub pending_pre_ntp_rx: u64,
    pub pending_pre_ntp_tx: u64,
    pub bytes_since_etc_flush: u64,
    pub pending_tmp_dirty: bool,
    pub last_tmp_flush: Option<Instant>,
    pub last_etc_flush: Option<Instant>,
}

impl UsageFlushTracker {
    pub fn new_at_boot(now: Instant) -> Self {
        Self {
            last_tmp_flush: Some(now),
            last_etc_flush: Some(now),
            ..Default::default()
        }
    }
}

pub fn parse_eth_sysfs_speed(
    carrier_raw: Option<&str>,
    speed_raw: Option<&str>,
    duplex_raw: Option<&str>,
) -> (String, String) {
    let duplex = duplex_raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();
    if carrier_raw.is_some_and(|c| c.trim() == "0") {
        return ("down".into(), "down".into());
    }
    let Some(sp_str) = speed_raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return ("down".into(), "down".into());
    };
    match sp_str.parse::<i64>() {
        Ok(sp) if sp > 0 => (format!("{sp}Mb/s"), duplex),
        _ => ("down".into(), "down".into()),
    }
}

pub fn read_eth0_speed_and_duplex() -> (String, String) {
    let carrier = fs::read_to_string(crate::paths::p("/sys/class/net/eth0/carrier")).ok();
    let speed = fs::read_to_string(crate::paths::p("/sys/class/net/eth0/speed")).ok();
    let duplex = fs::read_to_string(crate::paths::p("/sys/class/net/eth0/duplex")).ok();
    parse_eth_sysfs_speed(carrier.as_deref(), speed.as_deref(), duplex.as_deref())
}

pub fn is_eth0_degraded_auto(eth_link_speed_cfg: &str, actual_speed: &str, duplex: &str) -> bool {
    eth_link_speed_cfg.trim().eq_ignore_ascii_case("auto")
        && actual_speed != "down"
        && (actual_speed == "100Mb/s"
            || actual_speed == "10Mb/s"
            || duplex.trim().eq_ignore_ascii_case("half"))
}

pub fn spawn_background_tasks(state: AppState, mut rf_refresh_rx: mpsc::Receiver<()>) {
    // 1. RF snapshot, identity poller & cell-lock dead-man's-switch (monotonic Instant timers)
    let st_rf = state.clone();
    tokio::spawn(async move {
        let mut init_urcs = true;
        let mut last_history: Option<Instant> = None;
        let mut deadman = CellLockDeadmanTracker::default();
        let mut band_escape = BandLockEscapeTracker::default();
        loop {
            st_rf.hb_rf_ms.store(mono_ms(), Ordering::Release);
            refresh_modem_snapshot(&st_rf, Priority::Telemetry, init_urcs).await;
            st_rf.hb_rf_ms.store(mono_ms(), Ordering::Release);
            init_urcs = false;

            let now_inst = Instant::now();
            tick_cell_lock_deadman(
                &st_rf,
                &mut deadman,
                now_inst,
                Duration::from_secs(25),
            )
            .await;
            tick_band_lock_escape(&st_rf, &mut band_escape, now_inst).await;

            if last_history.is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(60)) {
                last_history = Some(now_inst);
                record_signal_history_point(&st_rf).await;
            }

            let st_running = st_rf.speedtest_live.read().await.running;
            let wait_dur = if st_running {
                Duration::from_secs(5)
            } else if st_rf.ws_tx.receiver_count() > 0 {
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
                        let now_millis = mono_ms();
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

    // 3. 1s /proc/net/dev + persistent data usage + 2s/10s fast vitals + 30s slow vitals + eth0 auto-heal
    let st_net = state.clone();
    tokio::spawn(async move {
        let mut prev_samples: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();
        let mut operstate_cache: HashMap<String, String> = HashMap::new();
        let mut last_operstate_refresh: Option<Instant> = None;
        let mut prev_inst = Instant::now();
        let mut usage_tracker = UsageFlushTracker::new_at_boot(prev_inst);
        let mut last_vitals: Option<Instant> = None;
        let mut last_slow_vitals: Option<Instant> = None;
        let mut slow_vitals_cache = SlowVitalsCache::default();
        let mut last_wan_check: Option<Instant> = None;
        let mut cached_slot = String::from("_a");
        let mut boot_slot_loaded = false;
        let mut cached_wan_up: Option<UptimeTelemetry> = None;
        let mut eth_degraded_since: Option<Instant> = None;
        let mut last_eth_reneg: Option<Instant> = None;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            st_net.hb_net_ms.store(mono_ms(), Ordering::Release);
            let now_inst = Instant::now();
            let elapsed_secs = now_inst.duration_since(prev_inst).as_secs_f64().max(0.2);
            prev_inst = now_inst;

            let refresh_operstate = last_operstate_refresh
                .is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(5));
            if refresh_operstate {
                last_operstate_refresh = Some(now_inst);
            }
            poll_network_and_usage(
                &st_net,
                &mut prev_samples,
                &mut operstate_cache,
                refresh_operstate,
                elapsed_secs,
                &mut usage_tracker,
                now_inst,
            )
            .await;

            let vitals_period = if st_net.ws_tx.receiver_count() > 0 {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(10)
            };
            if last_vitals.is_none_or(|t| now_inst.saturating_duration_since(t) >= vitals_period) {
                last_vitals = Some(now_inst);
                let refresh_slow = last_slow_vitals
                    .is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(30));
                if refresh_slow {
                    last_slow_vitals = Some(now_inst);
                }
                if !boot_slot_loaded {
                    boot_slot_loaded = true;
                    if let Ok(slot) = run_cmd("abctl", &["--boot_slot"], Duration::from_secs(2)).await {
                        let trimmed = slot.trim().to_string();
                        if !trimmed.is_empty() {
                            cached_slot = trimmed;
                        }
                    }
                }
                if last_wan_check.is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(6)) {
                    last_wan_check = Some(now_inst);
                    cached_wan_up = query_wan_uptime_ubus().await;
                    if let Ok(mut d) = DISCONNECTS.lock() {
                        let n = d.observe(cached_wan_up.as_ref().map(|w| w.uptime_seconds));
                        if let Some(w) = cached_wan_up.as_mut() {
                            w.disconnect_count = Some(n);
                        }
                    }
                }
                poll_system_vitals(
                    &st_net,
                    &cached_slot,
                    cached_wan_up.clone(),
                    refresh_slow,
                    &mut slow_vitals_cache,
                    &mut eth_degraded_since,
                    &mut last_eth_reneg,
                )
                .await;
            }
        }
    });

    // 4. Native ICMP Latency + CA Keep-Alive + 5-Stage LinkWatch recovery + Preferred SIM failback
    let st_icmp = state.clone();
    tokio::spawn(async move {
        let mut seq = 1u16;
        let mut hourly_acc: Vec<PingPoint> = Vec::new();
        let mut twelve_acc: Vec<PingPoint> = Vec::new();
        let mut daily_acc: Vec<PingPoint> = Vec::new();
        let mut last_hour_flush = Instant::now();
        let mut last_twelve_flush = Instant::now();
        let mut last_daily_flush = Instant::now();
        let mut qw_fail_streak = 0u32;
        let mut qw_high_lat_streak = 0u32;
        let mut qw_retries = 0u32;
        let mut last_qw_probe: Option<Instant> = None;
        let mut last_qw_cooldown_try: Option<Instant> = None;
        let mut last_ping: Option<Instant> = None;
        let mut was_qw_enabled = false;
        let mut non_preferred_sim_since: Option<Instant> = None;

        loop {
            st_icmp.hb_linkwatch_ms.store(mono_ms(), Ordering::Release);
            let now_inst = Instant::now();
            let (
                ping_enabled,
                ping_period,
                preferred_sim_slot,
                sim_failback_mins,
                qw_enabled,
                qw_interval_sec,
                qw_high_latency,
                qw_latency_ceiling,
                qw_max_retries,
                qw_failures,
            ) = {
                let s = st_icmp.settings.read().await;
                let period = if s.keep_alive_enabled {
                    Duration::from_secs(1)
                } else {
                    Duration::from_secs(s.ping_interval_sec.clamp(2, 60))
                };
                (
                    s.ping_enabled,
                    period,
                    s.preferred_sim_slot,
                    s.sim_failback_mins,
                    s.quecwatch_enabled,
                    s.quecwatch_interval_sec,
                    s.quecwatch_high_latency,
                    s.quecwatch_latency_ceiling,
                    s.quecwatch_max_retries,
                    s.quecwatch_failures,
                )
            };
            if ping_enabled
                && last_ping.is_none_or(|t| now_inst.saturating_duration_since(t) >= ping_period)
            {
                last_ping = Some(now_inst);
                seq = seq.wrapping_add(1).max(1);
                let host = st_icmp.settings.read().await.ping_host.clone();
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
                daily_acc.push(pt);

                let flush_now = Instant::now();
                if flush_now.saturating_duration_since(last_hour_flush) >= Duration::from_secs(30) {
                    last_hour_flush = flush_now;
                    push_bucket(&st_icmp.ping_hourly, &mut hourly_acc, 120).await;
                }
                if flush_now.saturating_duration_since(last_twelve_flush) >= Duration::from_secs(300) {
                    last_twelve_flush = flush_now;
                    push_bucket(&st_icmp.ping_twelvehour, &mut twelve_acc, 144).await;
                }
                if flush_now.saturating_duration_since(last_daily_flush) >= Duration::from_secs(600) {
                    last_daily_flush = flush_now;
                    push_bucket(&st_icmp.ping_daily, &mut daily_acc, 144).await;
                }
            }

            // Preferred SIM failback (monotonic timer, skipped during active failover)
            tick_preferred_sim_failback(
                &st_icmp,
                preferred_sim_slot,
                sim_failback_mins,
                &mut non_preferred_sim_since,
                Instant::now(),
            )
            .await;

            // LinkWatch monitoring cycle (monotonic Instant timers + 45s SIM settle + 900s cooldown)
            let now_wall = now_secs();
            let now_inst = Instant::now();
            if !qw_enabled {
                was_qw_enabled = false;
                qw_fail_streak = 0;
                qw_high_lat_streak = 0;
                qw_retries = 0;
                last_qw_probe = None;
                last_qw_cooldown_try = None;
            } else {
                if !was_qw_enabled {
                    was_qw_enabled = true;
                    qw_fail_streak = 0;
                    qw_high_lat_streak = 0;
                    qw_retries = 0;
                    last_qw_probe = None;
                    last_qw_cooldown_try = None;
                }
                let sim_sw_ms = st_icmp.sim_switched_at_ms.load(Ordering::Acquire);
                let in_sim_settle =
                    sim_sw_ms > 0 && mono_ms().saturating_sub(sim_sw_ms) < SIM_ATTACH_SETTLE_MS;
                let probe_interval = Duration::from_secs(qw_interval_sec.max(15));
                if !in_sim_settle
                    && last_qw_probe.is_none_or(|t| now_inst.saturating_duration_since(t) >= probe_interval)
                {
                    last_qw_probe = Some(now_inst);
                    let qw_target = st_icmp.settings.read().await.quecwatch_target.clone();
                    let ipv6_only = is_bearer_ipv6_only(&st_icmp).await;
                    let targets = linkwatch_probe_targets(&qw_target, ipv6_only);
                    let mut res: Result<(String, f64), String> = Err("No LinkWatch targets".into());
                    for tgt in &targets {
                        seq = seq.wrapping_add(1).max(1);
                        match icmp_ping_once(tgt, seq).await {
                            Ok(rtt) => {
                                res = Ok((tgt.clone(), rtt));
                                break;
                            }
                            Err(e) => {
                                res = Err(format!("{tgt}: {e}"));
                            }
                        }
                    }
                    match res {
                        Ok((hit_target, rtt)) => {
                            qw_fail_streak = 0;
                            qw_retries = 0;
                            last_qw_cooldown_try = None;
                            let rtt_u64 = rtt.round() as u64;
                            if qw_high_latency && rtt_u64 > qw_latency_ceiling {
                                qw_high_lat_streak += 1;
                            } else {
                                qw_high_lat_streak = 0;
                            }
                            let mut qw = st_icmp.quecwatch.write().await;
                            qw.status = if qw_high_lat_streak > 0 { "degraded".into() } else { "healthy".into() };
                            qw.message = format!("ICMP reachability OK via {hit_target} ({rtt_u64} ms)");
                            qw.current_latency = rtt_u64;
                            qw.retry = 0;
                            qw.timestamp = now_wall;
                        }
                        Err(err) => {
                            qw_fail_streak += 1;
                            let mut qw = st_icmp.quecwatch.write().await;
                            qw.current_latency = 0;
                            qw.timestamp = now_wall;
                            if qw_retries >= qw_max_retries {
                                qw.status = "cooldown".into();
                                let anchor = *last_qw_cooldown_try.get_or_insert(now_inst);
                                if now_inst.saturating_duration_since(anchor)
                                    >= Duration::from_secs(LINKWATCH_COOLDOWN_SECS)
                                {
                                    last_qw_cooldown_try = Some(now_inst);
                                    let cd_attempt = qw_retries.saturating_add(1);
                                    qw.message = format!(
                                        "Cooldown recovery retry (every 15m after {} retries): {err}",
                                        qw_max_retries
                                    );
                                    drop(qw);
                                    let rec_cfg = st_icmp.settings.read().await.clone();
                                    let _ = trigger_quecwatch_recovery(&st_icmp, &rec_cfg, cd_attempt).await;
                                    qw_fail_streak = 0;
                                } else {
                                    let rem = LINKWATCH_COOLDOWN_SECS.saturating_sub(
                                        now_inst.saturating_duration_since(anchor).as_secs(),
                                    );
                                    qw.message = format!("Max retries reached; next cooldown retry in {rem}s ({err})");
                                }
                            } else {
                                qw.status = "failing".into();
                                qw.message = format!("Probe failed ({qw_fail_streak}/{}): {err}", qw_failures);
                                if qw_fail_streak >= qw_failures {
                                    qw_retries += 1;
                                    qw.retry = qw_retries;
                                    qw.status = "recovering".into();
                                    qw.message = format!("Triggering recovery attempt {qw_retries}/{}", qw_max_retries);
                                    drop(qw);
                                    let rec_cfg = st_icmp.settings.read().await.clone();
                                    if !trigger_quecwatch_recovery(&st_icmp, &rec_cfg, qw_retries).await {
                                        // Deferred while carrying failover traffic: Route10's
                                        // own watchdog owns recovery; do not burn a retry.
                                        qw_retries -= 1;
                                        let mut qw = st_icmp.quecwatch.write().await;
                                        qw.retry = qw_retries;
                                        qw.status = "failing".into();
                                        qw.message = "Recovery deferred: carrying failover traffic (Route10 handles recovery)".into();
                                    } else if qw_retries >= qw_max_retries {
                                        last_qw_cooldown_try = Some(Instant::now());
                                    }
                                    qw_fail_streak = 0;
                                }
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // 5. Public IP refresh + QuecProfiles & Scheduled Tasks + SDX75 PHY & QMI DSP telemetry (Instant timers)
    let st_prof = state.clone();
    tokio::spawn(async move {
        let mut last_public_ip: Option<Instant> = None;
        let mut last_profiles: Option<Instant> = None;
        crate::radio_tuning::enable_phy_telemetry_counters(&st_prof).await;
        loop {
            let now_inst = Instant::now();
            if last_public_ip.is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(300)) {
                last_public_ip = Some(now_inst);
                refresh_public_ip(&st_prof).await;
                let cert = crate::acme::inspect_active_cert().await;
                *st_prof.tls_cert_info.write().await = cert;
            }
            if last_profiles.is_none_or(|t| now_inst.saturating_duration_since(t) >= Duration::from_secs(60)) {
                last_profiles = Some(now_inst);
                crate::profiles::tick_profiles_and_schedules(&st_prof).await;
            }
            let _ = crate::radio_tuning::poll_phy_telemetry(&st_prof).await;
            let dsp = crate::qmi::dsp::probe_dsp_telemetry().await;
            *st_prof.dsp_telemetry.write().await = dsp;
            st_prof
                .dsp_telemetry_updated_ms
                .store(mono_ms(), Ordering::Release);
            poll_cloudflared_metrics(&st_prof).await;
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

/// Issue `AT+CFUN=1` and verify `resp.ok`, retrying up to 3 times with 2s backoff so a
/// transient SMD glitch or slow baseband transition never strands the modem in `CFUN=0`.
pub(crate) async fn ensure_cfun_one_with_retries(state: &AppState, timeout: Duration) -> bool {
    for attempt in 1..=3u8 {
        match state.smd.exec("AT+CFUN=1", Priority::Emergency, timeout).await {
            Ok(r) if r.ok => return true,
            Ok(r) => {
                state.push_daemon_log(format!(
                    "AT+CFUN=1 rejected on attempt {attempt}/3: {}",
                    r.body.trim()
                ));
            }
            Err(e) => {
                state.push_daemon_log(format!(
                    "AT+CFUN=1 failed/timed out on attempt {attempt}/3: {e}"
                ));
            }
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    push_alert(
        state,
        "modem_cfun",
        "AT+CFUN=1 failed after 3 attempts; modem may require hardware reset",
    )
    .await;
    false
}

pub fn parse_qsimstat_inserted(body: &str) -> Option<bool> {
    for line in clean_at_lines(body) {
        let Some(rest) = line.strip_prefix("+QSIMSTAT:") else {
            continue;
        };
        let mut parts = rest.split(',').map(str::trim);
        let _enable = parts.next()?;
        let status = parts.next()?.parse::<u8>().ok()?;
        return match status {
            1 => Some(true),
            0 => Some(false),
            _ => None,
        };
    }
    None
}

/// Pure SIM slot presence policy:
/// - When QMI UIM reports `card_state`, it is authoritative for both active and inactive slots.
/// - Without QMI UIM, `AT+QSIMSTAT?` is only valid for the currently active slot; inactive slots
///   fail closed so recovery never switches into an unverified empty tray.
pub fn decide_sim_slot_presence(
    target_slot: u8,
    active_slot: Option<u8>,
    uim_card_state: Option<&str>,
    qsimstat_inserted: Option<bool>,
) -> bool {
    if !(1..=2).contains(&target_slot) {
        return false;
    }
    if let Some(st) = uim_card_state {
        return st.eq_ignore_ascii_case("present");
    }
    if active_slot == Some(target_slot) {
        return qsimstat_inserted.unwrap_or(false);
    }
    false
}

/// Check whether `target_slot` (`1` or `2`) actually has a SIM card inserted via QMI UIM
/// (`0x0B`), waiting briefly for QRTR UIM service discovery instead of checking `snapshot()` at 0ms.
/// For an inactive slot where QRTR UIM is unavailable, fail closed (never misuse `AT+QSIMSTAT?`,
/// which only reports the active slot).
pub(crate) async fn is_sim_slot_present(state: &AppState, target_slot: u8) -> bool {
    if !(1..=2).contains(&target_slot) {
        return false;
    }
    #[cfg(not(test))]
    {
        if let Ok(bus) = crate::qmi::qrtr::shared_bus() {
            let (ind_tx, _ind_rx) = mpsc::channel(4);
            let uim_state = if let Ok(ep) = bus
                .open_service(crate::qmi::SVC_UIM, "UIM_CHK", ind_tx, Duration::from_secs(2))
                .await
                && let Ok(cs) = crate::qmi::uim::get_card_status(ep.as_ref()).await
            {
                cs.slots
                    .into_iter()
                    .find(|s| s.slot == target_slot)
                    .map(|s| s.card_state)
            } else {
                None
            };
            // On a QRTR-capable modem, QMI UIM is authoritative; never fall back to AT+QSIMSTAT?
            // for an unconfirmed slot.
            return decide_sim_slot_presence(target_slot, None, uim_state, None);
        }

        // Non-QRTR host fallback: AT+QSIMSTAT? only describes the currently active slot, so
        // fail closed for inactive slots.
        let active_slot = state
            .smd
            .exec("AT+QUIMSLOT?", Priority::Emergency, Duration::from_secs(3))
            .await
            .ok()
            .and_then(|r| {
                r.ok.then(|| {
                    parse_scalar_at_value(&r.body, "+QUIMSLOT:")
                        .trim()
                        .parse::<u8>()
                        .ok()
                })
                .flatten()
            });
        if active_slot != Some(target_slot) {
            return false;
        }
        let inserted = state
            .smd
            .exec("AT+QSIMSTAT?", Priority::Emergency, Duration::from_secs(3))
            .await
            .ok()
            .filter(|r| r.ok)
            .and_then(|r| parse_qsimstat_inserted(&r.body));
        decide_sim_slot_presence(target_slot, active_slot, None, inserted)
    }
    #[cfg(test)]
    {
        // Unit tests run against FakeModem / mock SMD without host QRTR UIM.
        match state
            .smd
            .exec("AT+QSIMSTAT?", Priority::Emergency, Duration::from_secs(3))
            .await
        {
            Ok(r) if !r.ok => false,
            Ok(r) => parse_qsimstat_inserted(&r.body).unwrap_or(true),
            Err(_) => false,
        }
    }
}

async fn try_verified_sim_switch(state: &AppState, target_slot: u8, reason: &str) -> bool {
    if !is_sim_slot_present(state, target_slot).await {
        state.push_daemon_log(format!(
            "{reason}: skipped switch to SIM slot {target_slot} (no SIM detected)"
        ));
        return false;
    }
    match state
        .smd
        .exec(
            format!("AT+QUIMSLOT={target_slot}"),
            Priority::Emergency,
            Duration::from_secs(8),
        )
        .await
    {
        Ok(r) if r.ok => {
            crate::handlers::post_sim_slot(state).await;
            state.push_daemon_log(format!("{reason}: switched to SIM slot {target_slot}"));
            true
        }
        _ => false,
    }
}

async fn tick_preferred_sim_failback(
    state: &AppState,
    preferred_sim_slot: u8,
    sim_failback_mins: u64,
    non_preferred_since: &mut Option<Instant>,
    now: Instant,
) {
    if !(1..=2).contains(&preferred_sim_slot) || crate::obs::failover::is_active() {
        *non_preferred_since = None;
        return;
    }
    let cur_slot = state.modem.read().await.identity.sim_slot;
    if !(1..=2).contains(&cur_slot) || cur_slot == i32::from(preferred_sim_slot) {
        *non_preferred_since = None;
        return;
    }
    let since = *non_preferred_since.get_or_insert(now);
    if now.saturating_duration_since(since) < Duration::from_secs(sim_failback_mins.max(1) * 60)
    {
        return;
    }
    *non_preferred_since = Some(now);
    let _guard = crate::radio::lock_bounded(state, Duration::from_secs(8)).await;
    if try_verified_sim_switch(state, preferred_sim_slot, "Preferred SIM failback").await {
        crate::handlers::forget_radio_mode(state);
        *non_preferred_since = None;
    }
}

async fn run_stage2_cfun_cycle(state: &AppState) {
    let guard = crate::radio::lock_bounded(state, Duration::from_secs(8)).await;
    if guard.is_none() {
        state.push_daemon_log("LinkWatch: radio_lock busy for 8s; continuing CFUN recovery");
    }
    let _ = state
        .smd
        .exec("AT+CFUN=0", Priority::Emergency, Duration::from_secs(10))
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = ensure_cfun_one_with_retries(state, Duration::from_secs(12)).await;
    crate::handlers::forget_radio_mode(state);
    drop(guard);
    if crate::dataplane::is_native_mode() {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = crate::dataplane::trigger_native_reconnect_if_active().await;
    } else {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let _ = run_cmd("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3)).await;
        let _ = run_cmd("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3)).await;
    }
}

/// Strictly parse `+QUIMSLOT: <1|2>`. Returns `None` on empty, error, or
/// out-of-range replies so transient AT failures never fabricate slot `1`.
pub fn parse_quimslot_reply(body: &str) -> Option<i32> {
    parse_scalar_at_value(body, "+QUIMSLOT:")
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|s| (1..=2).contains(s))
}

async fn run_stage4_dual_sim_failover(state: &AppState) -> bool {
    let guard = crate::radio::lock_bounded(state, Duration::from_secs(8)).await;
    if guard.is_none() {
        state.push_daemon_log("LinkWatch: radio_lock busy for 8s; continuing SIM failover");
    }
    let switched = if let Ok(cur_slot_res) = state
        .smd
        .exec("AT+QUIMSLOT?", Priority::Emergency, Duration::from_secs(4))
        .await
        && cur_slot_res.ok
        && let Some(cur) = parse_quimslot_reply(&cur_slot_res.body)
    {
        let next_slot: u8 = if cur == 1 { 2 } else { 1 };
        try_verified_sim_switch(state, next_slot, "LinkWatch Dual-SIM failover").await
    } else {
        false
    };
    crate::handlers::forget_radio_mode(state);
    drop(guard);
    switched
}

/// 5-stage LinkWatch recovery escalation ladder.
/// Returns `false` when recovery was deferred because the modem is carrying failover traffic.
pub(crate) async fn trigger_quecwatch_recovery(
    state: &AppState,
    cfg: &crate::state::DaemonSettings,
    attempt: u32,
) -> bool {
    if !cfg.quecwatch_connection_refresh && !cfg.quecwatch_auto_sim_failover {
        return true;
    }
    if crate::obs::failover::is_active() {
        state.push_daemon_log("LinkWatch recovery deferred: modem is carrying failover traffic");
        crate::obs::events::work_deferred("LinkWatch recovery (CFUN cycle / SIM switch)", "carrying failover traffic");
        return false;
    }
    let _rec_guard = RecoveryGuard::acquire(&state.recovery_in_progress);
    crate::obs::events::quecwatch_recovery(
        attempt,
        cfg.quecwatch_max_retries,
        cfg.quecwatch_connection_refresh,
        cfg.quecwatch_auto_sim_failover,
    );
    state.push_daemon_log(format!("LinkWatch initiating recovery cycle (attempt {attempt})"));
    state.broadcast_with(|| serde_json::json!({
        "channel": "quecwatch",
        "message": format!("LinkWatch initiating cellular recovery (stage {attempt})"),
        "timestamp": format_now_hms(),
    }));

    let has_cell_lock = !cfg.cell_lock_nr5g.is_empty() || !cfg.cell_lock_lte.is_empty();

    if !cfg.quecwatch_connection_refresh && cfg.quecwatch_auto_sim_failover {
        let _ = run_stage4_dual_sim_failover(state).await;
    } else if cfg.quecwatch_connection_refresh {
        match attempt {
            0 | 1 => {
                // Stage 1: Soft bearer reconnect (Native WDS reconnect in Native mode, ubus wan up in Coexist).
                if crate::dataplane::is_native_mode() {
                    let _ = crate::dataplane::trigger_native_reconnect_if_active().await;
                    state.push_daemon_log("LinkWatch Stage 1: triggered native WDS bearer reconnect");
                } else if run_cmd(
                    "ubus",
                    &["call", "network.interface.wan", "up"],
                    Duration::from_secs(3),
                )
                .await
                .is_ok()
                {
                    let _ = run_cmd(
                        "ubus",
                        &["call", "network.interface.wan_v6", "up"],
                        Duration::from_secs(3),
                    )
                    .await;
                    state.push_daemon_log("LinkWatch Stage 1: triggered ubus wan reconnect");
                } else {
                    // Standalone Linux without ubus: escalate immediately to Stage 2 CFUN cycle.
                    run_stage2_cfun_cycle(state).await;
                }
            }
            2 => {
                // Stage 2: Verified AT+CFUN=0 -> AT+CFUN=1 cycle.
                run_stage2_cfun_cycle(state).await;
            }
            3 => {
                // Stage 3: Temporary cell-lock bypass if any lock is active, else escalate.
                if has_cell_lock && !state.cell_lock_bypassed.load(Ordering::Acquire) {
                    let _ = bypass_cell_lock_temporarily(
                        state,
                        "LinkWatch Stage 3 temporarily bypassed cell lock to restore reachability",
                        CellLockBypassReason::LinkWatch,
                    )
                    .await;
                } else if cfg.quecwatch_auto_sim_failover {
                    if !run_stage4_dual_sim_failover(state).await {
                        run_stage2_cfun_cycle(state).await;
                    }
                } else {
                    run_stage2_cfun_cycle(state).await;
                }
            }
            _ => {
                // Stage 4+: Verified Dual-SIM failover (with fallback to verified CFUN=0/1).
                if cfg.quecwatch_auto_sim_failover {
                    if !run_stage4_dual_sim_failover(state).await {
                        run_stage2_cfun_cycle(state).await;
                    }
                } else {
                    run_stage2_cfun_cycle(state).await;
                }
            }
        }
    }

    push_alert(state, "quecwatch", "LinkWatch ran automatic link recovery").await;
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

#[cfg(test)]
pub(crate) fn build_telemetry_commands_with_opts(
    qcainfo_cmd: &str,
    ta_nr_cmd: &str,
    ta_lte_cmd: &str,
    include_qmap: bool,
    include_qtemp: bool,
    need_static: bool,
) -> Vec<(String, Duration)> {
    build_telemetry_commands_full(
        qcainfo_cmd,
        ta_nr_cmd,
        Some(ta_lte_cmd),
        include_qmap,
        true,
        include_qtemp,
        true,
        need_static,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_telemetry_commands_full(
    qcainfo_cmd: &str,
    ta_nr_cmd: &str,
    ta_lte_cmd: Option<&str>,
    include_qmap: bool,
    include_cgcontrdp: bool,
    include_qtemp: bool,
    include_qspn: bool,
    need_static: bool,
    need_sim_identity: bool,
) -> Vec<(String, Duration)> {
    // Keep at_fwd commands (QMAP WWAN, QTEMP) in their mid-batch positions so trailing
    // baseband queries always follow them; moving them to the end caused a post-CFUN resync miss.
    // Combine AT+QRSRP;+QRSRQ;+QSINR into one compound query unless cached as unsupported on this firmware.
    let mut cmds: Vec<(String, Duration)> = vec![
        ("AT+CFUN?".into(), Duration::from_secs(3)),
        ("AT+QENG=\"servingcell\"".into(), Duration::from_secs(4)),
        (qcainfo_cmd.into(), Duration::from_secs(4)),
    ];
    if COMPOUND_RF_UNSUPPORTED.load(Ordering::Relaxed) {
        cmds.push(("AT+QRSRP".into(), Duration::from_secs(2)));
        cmds.push(("AT+QRSRQ".into(), Duration::from_secs(2)));
        cmds.push(("AT+QSINR".into(), Duration::from_secs(2)));
    } else {
        cmds.push(("AT+QRSRP;+QRSRQ;+QSINR".into(), Duration::from_secs(3)));
    }
    cmds.push(("AT+QNWCFG=\"nr5g_mimo_info\"".into(), Duration::from_secs(3)));
    if include_qmap {
        cmds.push(("AT+QMAP=\"WWAN\"".into(), Duration::from_secs(4)));
    }
    if include_cgcontrdp {
        cmds.push(("AT+CGCONTRDP".into(), Duration::from_secs(4)));
    }
    if include_qtemp {
        cmds.push(("AT+QTEMP".into(), Duration::from_secs(4)));
    }
    if include_qspn {
        cmds.push(("AT+QSPN".into(), Duration::from_secs(3)));
    }
    cmds.push((ta_nr_cmd.into(), Duration::from_secs(3)));
    if let Some(lte_ta) = ta_lte_cmd {
        cmds.push((lte_ta.into(), Duration::from_secs(3)));
    }
    cmds.push(("AT+QUIMSLOT?".into(), Duration::from_secs(3)));
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
    } else if need_sim_identity {
        cmds.extend([
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
    let ta_lte_raw = if init_urcs {
        "AT+QNWCFG=\"lte_time_advance\",1;+QNWCFG=\"lte_time_advance\""
    } else {
        "AT+QNWCFG=\"lte_time_advance\""
    };

    let (need_static, thermals_empty, cached_wwan_raw, cached_thermals, prev_rat, prev_plmn) = {
        let m = state.modem.read().await;
        (
            m.identity.revision.is_empty() || m.identity.model.is_empty(),
            m.thermals.is_empty(),
            m.raw_commands
                .get("AT+QMAP=\"WWAN\"")
                .cloned()
                .unwrap_or_default(),
            m.thermals.clone(),
            m.serving.as_ref().map(|s| s.rat.clone()).unwrap_or_default(),
            m.serving
                .as_ref()
                .map(|s| (s.mcc.clone(), s.mnc.clone()))
                .unwrap_or_default(),
        )
    };
    let need_sim_identity = {
        let sec = state.secrets.read().await;
        sec.iccid.is_empty() || sec.imsi.is_empty()
    };
    let cached_spn = state.spn_cache.read().await.clone();
    let spn_cache_hit = !init_urcs
        && !prev_plmn.0.is_empty()
        && !prev_plmn.1.is_empty()
        && cached_spn.0 == prev_plmn.0
        && cached_spn.1 == prev_plmn.1
        && !cached_spn.2.is_empty();

    let sysfs_thermals = tokio::task::spawn_blocking(read_sysfs_thermals)
        .await
        .unwrap_or_default();

    let mono_now_secs = mono_ms() / 1000;
    let poll_atfwd = should_poll_atfwd(
        priority,
        init_urcs,
        thermals_empty && sysfs_thermals.is_empty(),
        mono_now_secs,
        LAST_ATFWD_POLL_SECS.load(std::sync::atomic::Ordering::Relaxed),
    );
    let native_mode = crate::dataplane::is_native_mode();
    let include_qmap = poll_atfwd && !native_mode;
    let include_cgcontrdp = !native_mode;
    let include_qtemp = poll_atfwd && sysfs_thermals.is_empty();
    let include_qspn = !spn_cache_hit;
    let ta_lte_cmd = if !init_urcs && prev_rat == "NR5G-SA" {
        None
    } else {
        Some(ta_lte_raw)
    };

    let cmds = build_telemetry_commands_full(
        qcainfo_cmd,
        ta_nr_cmd,
        ta_lte_cmd,
        include_qmap,
        include_cgcontrdp,
        include_qtemp,
        include_qspn,
        need_static,
        need_sim_identity,
    );

    let cmd_names: Vec<String> = cmds.iter().map(|(c, _)| c.clone()).collect();
    let Ok(results) = state.smd.exec_batch(cmds, priority).await else {
        return;
    };

    if poll_atfwd {
        LAST_ATFWD_POLL_SECS.store(mono_now_secs, std::sync::atomic::Ordering::Relaxed);
    }

    let mut raw_map: BTreeMap<String, String> = BTreeMap::new();
    for (name, res) in cmd_names.into_iter().zip(results) {
        if let Ok(r) = res {
            raw_map.insert(name, r.body);
        }
    }

    // Fallback to individual QRSRP/QRSRQ/QSINR if compound command returned empty/error on non-standard firmware,
    // and cache compound failure until SMD reconnect so subsequent ticks avoid the wasted round-trip.
    let mut mimo = if let Some(compound_sig) = raw_map.get("AT+QRSRP;+QRSRQ;+QSINR") {
        let parsed = parse_mimo_signal(compound_sig, compound_sig, compound_sig);
        if parsed.rsrp.iter().all(|v| v.is_none())
            && !compound_sig.contains("+QRSRP:")
            && let Ok(fb) = state
                .smd
                .exec_batch(
                    vec![
                        ("AT+QRSRP".into(), Duration::from_secs(2)),
                        ("AT+QRSRQ".into(), Duration::from_secs(2)),
                        ("AT+QSINR".into(), Duration::from_secs(2)),
                    ],
                    priority,
                )
                .await
        {
            let r0 = fb.first().and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let r1 = fb.get(1).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let r2 = fb.get(2).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let fb_mimo = parse_mimo_signal(r0, r1, r2);
            if fb_mimo.rsrp.iter().any(|v| v.is_some()) || r0.contains("+QRSRP:") {
                COMPOUND_RF_UNSUPPORTED.store(true, Ordering::Relaxed);
            }
            fb_mimo
        } else {
            parsed
        }
    } else {
        let r0 = raw_map.get("AT+QRSRP").map(String::as_str).unwrap_or("");
        let r1 = raw_map.get("AT+QRSRQ").map(String::as_str).unwrap_or("");
        let r2 = raw_map.get("AT+QSINR").map(String::as_str).unwrap_or("");
        parse_mimo_signal(r0, r1, r2)
    };
    let _ = &mut mimo;

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
    let wwan_raw = if native_mode {
        String::new()
    } else if include_qmap {
        get_resp("WWAN")
    } else {
        cached_wwan_raw
    };
    let cgcontrdp_raw = if include_cgcontrdp {
        get_resp("CGCONTRDP")
    } else {
        String::new()
    };
    let mut bearers = parse_active_wwan(&wwan_raw, &cgcontrdp_raw);
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

    let cur_mcc = serving.as_ref().map(|s| s.mcc.clone()).unwrap_or_default();
    let cur_mnc = serving.as_ref().map(|s| s.mnc.clone()).unwrap_or_default();
    let mut qspn = if include_qspn {
        let parsed = parse_qspn_operator(&get_resp("QSPN"));
        if !parsed.is_empty() && !cur_mcc.is_empty() && !cur_mnc.is_empty() {
            *state.spn_cache.write().await = (cur_mcc.clone(), cur_mnc.clone(), parsed.clone());
        }
        parsed
    } else if cur_mcc == cached_spn.0 && cur_mnc == cached_spn.1 {
        cached_spn.2
    } else {
        String::new()
    };
    if qspn.is_empty()
        && !include_qspn
        && !cur_mcc.is_empty()
        && let Ok(spn_res) = state
            .smd
            .exec("AT+QSPN", priority, Duration::from_secs(3))
            .await
    {
        let parsed = parse_qspn_operator(&spn_res.body);
        if !parsed.is_empty() {
            *state.spn_cache.write().await = (cur_mcc.clone(), cur_mnc.clone(), parsed.clone());
            qspn = parsed;
        }
    }

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
    let parsed_sim_slot = parse_quimslot_reply(&get_resp("QUIMSLOT"));
    let (sim_slot, prev_sim_slot, sim_slot_changed) = if let Some(slot) = parsed_sim_slot {
        let prev = state.last_sim_slot.swap(slot, Ordering::AcqRel);
        (slot, prev, prev != 0 && prev != slot)
    } else {
        let prev = state.last_sim_slot.load(Ordering::Acquire);
        let preserved = if (1..=2).contains(&prev) {
            prev
        } else {
            state.modem.read().await.identity.sim_slot
        };
        (preserved, prev, false)
    };
    let mut trigger_profile_sync = false;
    let mut extra_cnum: Option<String> = None;

    if sim_slot_changed {
        {
            let mut sec = state.secrets.write().await;
            sec.iccid.clear();
            sec.imsi.clear();
        }
        *state.spn_cache.write().await = (String::new(), String::new(), String::new());
        state.sim_switched_at_ms.store(mono_ms(), Ordering::Release);
    }

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
    } else if sim_slot_changed {
        // SIM slot changed since previous poll and AT+ICCID wasn't in this batch yet: query immediately!
        if let Ok(sim_res) = state
            .smd
            .exec_batch(
                vec![
                    ("AT+ICCID".into(), Duration::from_secs(3)),
                    ("AT+CIMI".into(), Duration::from_secs(3)),
                    ("AT+CNUM".into(), Duration::from_secs(3)),
                ],
                Priority::Interactive,
            )
            .await
        {
            let r_iccid = sim_res.first().and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let r_cimi = sim_res.get(1).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let r_cnum = sim_res.get(2).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
            let mut sec = state.secrets.write().await;
            let iccid_val = parse_scalar_at_value(r_iccid, "+ICCID:");
            if !iccid_val.is_empty() {
                sec.iccid = iccid_val;
                trigger_profile_sync = true;
            }
            let imsi_val = parse_scalar_at_value(r_cimi, "");
            if !imsi_val.is_empty() {
                sec.imsi = imsi_val;
            }
            extra_cnum = Some(parse_scalar_at_value(r_cnum, "+CNUM:"));
        }
    } else if need_sim_identity {
        let mut sec = state.secrets.write().await;
        let iccid_val = parse_scalar_at_value(&get_resp("ICCID"), "+ICCID:");
        if !iccid_val.is_empty() {
            sec.iccid = iccid_val;
            if prev_sim_slot == 0 {
                trigger_profile_sync = true;
            }
        }
        let imsi_val = parse_scalar_at_value(&get_resp("CIMI"), "");
        if !imsi_val.is_empty() {
            sec.imsi = imsi_val;
        }
        extra_cnum = Some(parse_scalar_at_value(&get_resp("CNUM"), "+CNUM:"));
    }

    let phy_tx_pwr = {
        let phy = state.phy_diag.read().await;
        phy.nr5g_tx_pwr_detail.as_ref().map(|t| f64::from(t.pusch_dbm))
    };
    let mut serving = serving;
    if let Some(s) = serving.as_mut()
        && s.tx_power.is_none()
    {
        s.tx_power = phy_tx_pwr;
    }
    if cfun != 1 {
        state.phy_diag_updated_ms.store(0, Ordering::Release);
        state.dsp_telemetry_updated_ms.store(0, Ordering::Release);
        *state.phy_diag.write().await = crate::radio_tuning::PhyDiagnostics::default();
        *state.dsp_telemetry.write().await = crate::qmi::dsp::DspTelemetrySnapshot::default();
    }

    let sec_snap = state.secrets.read().await.clone();
    let mut modem = state.modem.write().await;
    modem.updated_at = now_secs();
    modem.updated_mono_ms = mono_ms();
    stabilize_idle_mimo_chains(
        &mut mimo,
        &modem.mimo,
        serving.as_ref(),
        modem.serving.as_ref(),
    );
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
    } else if let Some(cnum) = extra_cnum {
        modem.identity.phone_number = cnum;
    }

    if native_mode {
        modem.raw_commands.remove("AT+QMAP=\"WWAN\"");
        modem.raw_commands.remove("AT+CGCONTRDP");
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
    if trigger_profile_sync {
        crate::profiles::tick_iccid_profile_sync(state).await;
    }
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
    // Try compound signal query first to cut SMD round-trips during 400 ms alignment,
    // skipping straight to individual commands if compound RF is cached as unsupported.
    let tried_compound = !COMPOUND_RF_UNSUPPORTED.load(Ordering::Relaxed);
    let mut mimo = if tried_compound {
        let compound_cmds = vec![("AT+QRSRP;+QRSRQ;+QSINR".into(), Duration::from_secs(2))];
        match state.smd.exec_batch(compound_cmds, Priority::Telemetry).await {
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
        }
    } else {
        crate::parsers::MimoSignalData::default()
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
        if tried_compound && (mimo.rsrp.iter().any(|v| v.is_some()) || rsrp_raw.contains("+QRSRP:")) {
            COMPOUND_RF_UNSUPPORTED.store(true, Ordering::Relaxed);
        }
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
    let now_mono = mono_ms();
    let has_new_rsrp = mimo.rsrp.iter().any(|v| v.is_some());
    if has_new_rsrp {
        if a.rsrp.len() < 4 {
            a.rsrp.resize(4, None);
        }
        if a.rsrq.len() < 4 {
            a.rsrq.resize(4, None);
        }
        if a.sinr.len() < 4 {
            a.sinr.resize(4, None);
        }
        for i in 0..4 {
            let cur_r = mimo.rsrp.get(i).copied().flatten();
            let cur_q = mimo.rsrq.get(i).copied().flatten();
            let cur_s = mimo.sinr.get(i).copied().flatten();
            if let Some(r) = cur_r {
                a.rsrp[i] = Some(r);
                a.rsrq[i] = cur_q;
                a.sinr[i] = cur_s;
                a.last_chain_ms[i] = now_mono;
            } else if !a.keep_awake
                || a.last_chain_ms[i] == 0
                || now_mono.saturating_sub(a.last_chain_ms[i]) > ALIGN_SECONDARY_HOLD_MS
            {
                a.rsrp[i] = None;
                a.rsrq[i] = None;
                a.sinr[i] = None;
            }
        }
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
    rx_errors: u64,
    rx_drops: u64,
    tx_bytes: u64,
    tx_pkts: u64,
    tx_errors: u64,
    tx_drops: u64,
    oper: Option<String>,
}

fn read_net_dev_samples(read_operstate: bool) -> Option<Vec<NetDevRow>> {
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
        if cols.len() < 12 {
            continue;
        }
        let oper = if read_operstate {
            Some(
                fs::read_to_string(crate::paths::p(&format!("/sys/class/net/{name}/operstate")))
                    .unwrap_or_else(|_| "unknown".into())
                    .trim()
                    .to_string(),
            )
        } else {
            None
        };
        rows.push(NetDevRow {
            name: name.to_string(),
            rx_bytes: cols[0],
            rx_pkts: cols[1],
            rx_errors: cols[2],
            rx_drops: cols[3],
            tx_bytes: cols[8],
            tx_pkts: cols[9],
            tx_errors: cols[10],
            tx_drops: cols[11],
            oper,
        });
    }
    Some(rows)
}

async fn poll_network_and_usage(
    state: &AppState,
    prev: &mut HashMap<String, (u64, u64, u64, u64)>,
    operstate_cache: &mut HashMap<String, String>,
    refresh_operstate: bool,
    elapsed_secs: f64,
    tracker: &mut UsageFlushTracker,
    mono_now: Instant,
) {
    let read_oper = refresh_operstate || operstate_cache.is_empty();
    let Ok(Some(rows)) = crate::paths::spawn_blocking(move || read_net_dev_samples(read_oper)).await else {
        return;
    };
    let mut ifaces = Vec::with_capacity(rows.len());
    for row in rows {
        let NetDevRow {
            name,
            rx_bytes,
            rx_pkts,
            rx_errors,
            rx_drops,
            tx_bytes,
            tx_pkts,
            tx_errors,
            tx_drops,
            oper,
        } = row;
        let oper_state = match oper {
            Some(s) => {
                operstate_cache.insert(name.clone(), s.clone());
                s
            }
            None => operstate_cache
                .get(&name)
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
        };
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
            state: oper_state,
            rx: TrafficDirectionStats {
                bytes_total: rx_bytes,
                bps: rx_bps,
                packets_per_sec: rx_pps,
                errors: rx_errors,
                drops: rx_drops,
            },
            tx: TrafficDirectionStats {
                bytes_total: tx_bytes,
                bps: tx_bps,
                packets_per_sec: tx_pps,
                errors: tx_errors,
                drops: tx_drops,
            },
        });
    }

    let primary = pick_primary_rmnet(&ifaces);
    let lan = ifaces
        .iter()
        .find(|i| i.name == "eth0")
        .or_else(|| ifaces.iter().find(|i| i.name.starts_with("eth")));

    let primary_name = primary.map(|p| p.name.clone());
    let lan_name = lan.map(|l| l.name.clone());
    let rx_bps = primary.map(|p| p.rx.bps).unwrap_or(0);
    let tx_bps = primary.map(|p| p.tx.bps).unwrap_or(0);
    let now_ms_val = now_secs() * 1000;

    if let Some(p) = primary {
        update_persistent_usage_with_clock(
            state,
            &p.name,
            p.rx.bytes_total,
            p.tx.bytes_total,
            tracker,
            now_secs(),
            format_today_ymd(),
            mono_now,
        )
        .await;
    }

    let ws_ifaces = (state.ws_tx.receiver_count() > 0).then(|| ifaces.clone());
    {
        let mut tr = state.traffic.write().await;
        if let Some(p_name) = primary_name {
            tr.primary_iface = p_name;
        }
        if let Some(l_name) = lan_name {
            tr.lan_iface = l_name;
        }
        tr.interfaces = ifaces;
        if tr.history.len() >= 90 {
            tr.history.pop_front();
        }
        tr.history.push_back(TrafficHistoryPoint {
            ts: now_ms_val,
            rx_bps,
            tx_bps,
        });
    }

    if let Some(ws_ifaces) = ws_ifaces {
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
            "interfaces": ws_ifaces,
            "usageSummary": usage_today,
        }));
    }
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_persistent_usage_with_clock(
    state: &AppState,
    iface: &str,
    raw_rx: u64,
    raw_tx: u64,
    tracker: &mut UsageFlushTracker,
    wall_now_secs: u64,
    ymd: (String, String, u8),
    mono_now: Instant,
) {
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

    // Hold pre-NTP deltas in memory until wall clock >= 2025-01-01 so 1970-01-01 buckets never form.
    if wall_now_secs < crate::state::MIN_VALID_WALL_CLOCK_SECS {
        tracker.pending_pre_ntp_rx = tracker.pending_pre_ntp_rx.saturating_add(delta_rx);
        tracker.pending_pre_ntp_tx = tracker.pending_pre_ntp_tx.saturating_add(delta_tx);
        return;
    }

    let total_rx = delta_rx.saturating_add(std::mem::take(&mut tracker.pending_pre_ntp_rx));
    let total_tx = delta_tx.saturating_add(std::mem::take(&mut tracker.pending_pre_ntp_tx));
    let mut day_rolled_over = false;

    if total_rx > 0 || total_tx > 0 {
        let (today, month, _) = ymd;

        if let Some(entry) = u.daily.iter_mut().find(|d| d.date == today) {
            entry.rx_bytes = entry.rx_bytes.saturating_add(total_rx);
            entry.tx_bytes = entry.tx_bytes.saturating_add(total_tx);
        } else {
            u.daily.push(DailyUsageEntry {
                date: today,
                rx_bytes: total_rx,
                tx_bytes: total_tx,
            });
            if u.daily.len() > 90 {
                let drain_n = u.daily.len() - 90;
                u.daily.drain(0..drain_n);
            }
            day_rolled_over = true;
        }

        if let Some(entry) = u.monthly.iter_mut().find(|m| m.month == month) {
            entry.rx_bytes = entry.rx_bytes.saturating_add(total_rx);
            entry.tx_bytes = entry.tx_bytes.saturating_add(total_tx);
        } else {
            u.monthly.push(MonthlyUsageEntry {
                month,
                rx_bytes: total_rx,
                tx_bytes: total_tx,
            });
            if u.monthly.len() > 24 {
                let drain_n = u.monthly.len() - 24;
                u.monthly.drain(0..drain_n);
            }
        }

        tracker.bytes_since_etc_flush = tracker
            .bytes_since_etc_flush
            .saturating_add(total_rx)
            .saturating_add(total_tx);
        tracker.pending_tmp_dirty = true;
    }

    // Run flush checks even on zero-delta ticks so buffered bytes still flush at 6h / 5m boundaries,
    // while enforcing a >= 300s minimum debounce on the 50 MiB flash flush trigger.
    let etc_debounce_ok = tracker.last_etc_flush.is_none_or(|t| {
        mono_now.saturating_duration_since(t) >= Duration::from_secs(DATA_USAGE_ETC_MIN_DEBOUNCE_SECS)
    });
    let flush_etc = day_rolled_over
        || (tracker.bytes_since_etc_flush >= DATA_USAGE_ETC_FLUSH_BYTES && etc_debounce_ok)
        || (tracker.bytes_since_etc_flush > 0
            && tracker.last_etc_flush.is_none_or(|t| {
                mono_now.saturating_duration_since(t) >= Duration::from_secs(DATA_USAGE_ETC_FLUSH_SECS)
            }));
    let flush_tmp = flush_etc
        || (tracker.pending_tmp_dirty
            && tracker.last_tmp_flush.is_none_or(|t| {
                mono_now.saturating_duration_since(t)
                    >= Duration::from_secs(DATA_USAGE_SNAPSHOT_FLUSH_SECS)
            }));

    if !flush_tmp && !flush_etc {
        return;
    }

    let snap = u.clone();
    drop(u);

    let p_etc = crate::paths::p(DATA_USAGE_PATH);
    let p_tmp = crate::paths::p(DATA_USAGE_TMP_PATH);
    let res = tokio::task::spawn_blocking(move || {
        let tmp_ok = save_json_compact_tmpfs(&p_tmp, &snap, 0o600).is_ok();
        let etc_ok = if flush_etc {
            save_json_compact_atomic(&p_etc, &snap, 0o600).is_ok()
        } else {
            false
        };
        (tmp_ok, etc_ok)
    })
    .await;

    if let Ok((tmp_ok, etc_ok)) = res {
        if tmp_ok {
            tracker.last_tmp_flush = Some(mono_now);
            tracker.pending_tmp_dirty = false;
        }
        if flush_etc && etc_ok {
            tracker.last_etc_flush = Some(mono_now);
            tracker.bytes_since_etc_flush = 0;
        }
    }
}

pub async fn flush_persistent_state(state: &AppState) {
    let snap = state.data_usage.read().await.clone();
    let tokens = state.tokens.clone();
    let p1 = crate::paths::p(DATA_USAGE_PATH);
    let p2 = crate::paths::p(DATA_USAGE_TMP_PATH);
    // Event ring + observability counters + API token usage + data usage flash flush (SIGTERM / reboot).
    let _ = tokio::task::spawn_blocking(move || {
        let _ = save_json_compact_atomic(&p1, &snap, 0o600);
        let _ = save_json_compact_tmpfs(&p2, &snap, 0o600);
        tokens.flush_tokens_usage();
        crate::obs::flush_now(true);
    })
    .await;
}

/// During RRC Idle (`NOCONN`) 4x4 MIMO power-save, Qualcomm modems power down
/// RX2/RX3 so `AT+QRSRP` reports `-140 dBm` (`None`) on chains 2 & 3 while
/// chains 0 & 1 remain healthy. Retain the last connected chain 2/3 readings
/// while remaining on the same serving cell so Prometheus `antenna_chain_present`
/// and `antenna_active_chains` do not falsely flap to 2 chains during idle.
pub(crate) fn stabilize_idle_mimo_chains(
    mimo: &mut MimoSignalData,
    prev_mimo: &MimoSignalData,
    serving: Option<&ServingCellInfo>,
    prev_serving: Option<&ServingCellInfo>,
) {
    let is_idle = serving.is_some_and(|s| s.state.eq_ignore_ascii_case("NOCONN"));
    if !is_idle {
        return;
    }
    let same_cell = match (serving, prev_serving) {
        (Some(cur), Some(prev)) => {
            cur.rat == prev.rat
                && cur.band == prev.band
                && cur.pci == prev.pci
                && cur.arfcn == prev.arfcn
        }
        _ => false,
    };
    if !same_cell {
        return;
    }
    let rx0_ok = mimo.rsrp.first().and_then(|v| *v).is_some_and(f64::is_finite);
    let rx1_ok = mimo.rsrp.get(1).and_then(|v| *v).is_some_and(f64::is_finite);
    if !rx0_ok || !rx1_ok {
        return;
    }
    for idx in 2..4 {
        if mimo.rsrp.get(idx).and_then(|v| *v).is_none()
            && let Some(prev_r) = prev_mimo.rsrp.get(idx).and_then(|v| *v).filter(|x| x.is_finite())
        {
            if mimo.rsrp.len() <= idx {
                mimo.rsrp.resize(idx + 1, None);
            }
            mimo.rsrp[idx] = Some(prev_r);
            if mimo.rsrq.get(idx).and_then(|v| *v).is_none()
                && let Some(prev_q) = prev_mimo.rsrq.get(idx).and_then(|v| *v).filter(|x| x.is_finite())
            {
                if mimo.rsrq.len() <= idx {
                    mimo.rsrq.resize(idx + 1, None);
                }
                mimo.rsrq[idx] = Some(prev_q);
            }
            if mimo.sinr.get(idx).and_then(|v| *v).is_none()
                && let Some(prev_s) = prev_mimo.sinr.get(idx).and_then(|v| *v).filter(|x| x.is_finite())
            {
                if mimo.sinr.len() <= idx {
                    mimo.sinr.resize(idx + 1, None);
                }
                mimo.sinr[idx] = Some(prev_s);
            }
        }
    }
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
    if (!crate::dataplane::is_native_mode() || crate::dataplane::is_wds_connected())
        && let Ok(Some(_)) =
            tokio::task::spawn_blocking(crate::netlink::detect_active_rmnet_wan_live).await
    {
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

#[derive(Default, Clone)]
struct SlowVitalsCache {
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
}

struct FastVitalsRaw {
    mem: MemoryTelemetry,
    dev_up: UptimeTelemetry,
    conntrack_count: u64,
    conntrack_max: u64,
    eth_speed: String,
    eth_duplex: String,
    slow: Option<SlowVitalsCache>,
}

fn read_system_vitals_blocking(refresh_slow: bool, native_mode: bool) -> FastVitalsRaw {
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
    let (eth_speed, eth_duplex) = read_eth0_speed_and_duplex();

    let slow = if refresh_slow {
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
        let mwan3_running = if native_mode {
            false
        } else {
            is_mwan3track_running()
        };
        Some(SlowVitalsCache {
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
        })
    } else {
        None
    };

    FastVitalsRaw {
        mem,
        dev_up,
        conntrack_count,
        conntrack_max,
        eth_speed,
        eth_duplex,
        slow,
    }
}

async fn poll_system_vitals(
    state: &AppState,
    boot_slot: &str,
    wan_up: Option<UptimeTelemetry>,
    refresh_slow: bool,
    slow_cache: &mut SlowVitalsCache,
    eth_degraded_since: &mut Option<Instant>,
    last_eth_reneg: &mut Option<Instant>,
) {
    let native_mode = crate::dataplane::is_native_mode();
    let raw = match crate::paths::spawn_blocking(move || read_system_vitals_blocking(refresh_slow, native_mode)).await {
        Ok(r) => r,
        Err(_) => return,
    };
    if let Some(slow) = raw.slow {
        *slow_cache = slow;
    }

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

    let (keep_alive_enabled, eth_link_speed_cfg) = {
        let s = state.settings.read().await;
        (s.keep_alive_enabled, s.eth_link_speed.clone())
    };

    let now_inst = Instant::now();
    if is_eth0_degraded_auto(&eth_link_speed_cfg, &raw.eth_speed, &raw.eth_duplex)
        && !crate::obs::failover::is_active()
    {
        let since = *eth_degraded_since.get_or_insert(now_inst);
        if now_inst.saturating_duration_since(since) >= Duration::from_secs(60)
            && last_eth_reneg.is_none_or(|t| {
                now_inst.saturating_duration_since(t) >= Duration::from_secs(3600)
            })
        {
            *last_eth_reneg = Some(now_inst);
            *eth_degraded_since = None;
            let partner_can_gig = run_cmd("ethtool", &["eth0"], Duration::from_secs(2))
                .await
                .is_ok_and(|out| partner_supports_gigabit(&out));
            if partner_can_gig {
                state.push_daemon_log(format!(
                    "eth0 negotiated degraded link ({} {}); link partner advertises >=1000Mb/s, running ethtool -r eth0",
                    raw.eth_speed, raw.eth_duplex
                ));
                let _ = run_cmd("ethtool", &["-r", "eth0"], Duration::from_secs(3)).await;
            } else {
                state.push_daemon_log(format!(
                    "eth0 at {} {} but link partner does not advertise 1000/2500baseT; skipping ethtool -r",
                    raw.eth_speed, raw.eth_duplex
                ));
            }
        }
    } else {
        *eth_degraded_since = None;
    }

    let mut internals = state.internals.write().await;
    internals.conntrack_count = raw.conntrack_count;
    internals.conntrack_max = raw.conntrack_max;
    internals.conntrack_hashsize = slow_cache.conntrack_hashsize;
    internals.pcie_aspm = slow_cache.pcie_aspm.clone();
    internals.autosleep = slow_cache.autosleep.clone();
    internals.boot_slot = boot_slot.to_string();
    internals.usrdata_total_bytes = slow_cache.usrdata_total_bytes;
    internals.usrdata_used_bytes = slow_cache.usrdata_used_bytes;
    internals.usrdata_avail_bytes = slow_cache.usrdata_avail_bytes;
    internals.usb_udc = slow_cache.usb_udc.clone();
    internals.usb_controller = slow_cache.usb_controller.clone();
    internals.usb_adb_present = slow_cache.usb_adb_present;
    internals.mwan3_running = slow_cache.mwan3_running;
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

pub fn partner_supports_gigabit(ethtool_out: &str) -> bool {
    crate::handlers::parse_partner_advertised_speeds(ethtool_out)
        .is_some_and(|speeds| speeds.iter().any(|s| s.parse::<u32>().is_ok_and(|v| v >= 1000)))
}

fn is_mwan3track_running() -> bool {
    let var_run = crate::paths::p("/var/run");
    if let Ok(entries) = fs::read_dir(&var_run) {
        let mut saw_pidfile = false;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("mwan3track") && name.ends_with(".pid") {
                saw_pidfile = true;
                if let Ok(pid_raw) = fs::read_to_string(entry.path()) {
                    let pid = pid_raw.trim();
                    if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
                        let cmd_path = crate::paths::p(&format!("/proc/{pid}/cmdline"));
                        if let Ok(bytes) = fs::read(&cmd_path)
                            && String::from_utf8_lossy(&bytes).contains("mwan3track")
                        {
                            return true;
                        }
                    }
                }
            }
        }
        if saw_pidfile {
            return false;
        }
    }
    if !std::path::Path::new(&crate::paths::p("/etc/init.d/mwan3")).exists() {
        return false;
    }
    is_proc_running("mwan3track")
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

/// Parse `cloudflared_tunnel_ha_connections` from a Prometheus `/metrics` exposition body.
pub fn parse_cloudflared_metrics(body: &str) -> Option<u64> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("cloudflared_tunnel_ha_connections") else {
            continue;
        };
        if !rest.starts_with(' ') && !rest.starts_with('\t') && !rest.starts_with('{') {
            continue;
        }
        let val_str = trimmed.split_whitespace().last()?;
        if let Ok(v) = val_str.parse::<f64>()
            && v.is_finite()
            && v >= 0.0
        {
            return Some(v.round() as u64);
        }
    }
    None
}

async fn scrape_local_cloudflared_metrics(addr: &str) -> Option<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut stream = tokio::time::timeout_at(deadline, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let req = format!(
        "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: CellCore/1.6\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout_at(deadline, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    while buf.len() < 128 * 1024 {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    parse_cloudflared_metrics(body)
}

async fn poll_cloudflared_metrics(state: &AppState) {
    let (present, running) = crate::paths::spawn_blocking(|| {
        let present = std::path::Path::new(&crate::paths::p("/usr/bin/cloudflared")).exists()
            || std::path::Path::new(&crate::paths::p("/usr/sbin/cloudflared")).exists();
        let running = present && is_proc_running("cloudflared");
        (present, running)
    })
    .await
    .unwrap_or((false, false));

    let ha_conns = if running {
        scrape_local_cloudflared_metrics(CLOUDFLARED_METRICS_ADDR).await
    } else {
        None
    };

    let mut internals = state.internals.write().await;
    internals.cloudflared_present = present;
    internals.cloudflared_running = running;
    internals.cloudflared_ha_connections = ha_conns.unwrap_or(0);
    internals.cloudflared_up = running && ha_conns.is_some_and(|c| c > 0);
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
        } else {
            let _ = bind_socket_to_cellular_wan(sock.as_raw_fd(), addr.ip().is_loopback());
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

const WAN_IFACE_CACHE_TTL_MS: u64 = 5_000;
static CACHED_WAN_IFACE: std::sync::Mutex<Option<(u64, Option<String>)>> =
    std::sync::Mutex::new(None);
static ICMP_IDENT_SEQ: AtomicU16 = AtomicU16::new(1);

fn detect_cached_cellular_wan_iface() -> Option<String> {
    if let Some(dev) = crate::vpn::bypass_iface() {
        return Some(dev);
    }
    let now = mono_ms();
    if let Ok(g) = CACHED_WAN_IFACE.lock()
        && let Some((ts, ref cached)) = *g
        && now.saturating_sub(ts) < WAN_IFACE_CACHE_TTL_MS
    {
        return cached.clone();
    }
    let fresh = crate::netlink::detect_active_rmnet_wan_live();
    if let Ok(mut g) = CACHED_WAN_IFACE.lock() {
        *g = Some((now, fresh.clone()));
    }
    fresh
}

fn invalidate_cached_wan_iface() {
    if let Ok(mut g) = CACHED_WAN_IFACE.lock() {
        *g = None;
    }
}

/// Fail-closed `SO_BINDTODEVICE`: for non-loopback targets, if no active cellular WAN
/// interface is present or `setsockopt(SO_BINDTODEVICE)` fails, return `Err` instead of
/// sending on an unbound socket (which could route out LAN and report false healthy).
pub fn bind_socket_to_cellular_wan_with<F>(
    sock: libc::c_int,
    is_loopback: bool,
    detect_iface: F,
) -> Result<Option<String>, String>
where
    F: FnOnce() -> Option<String>,
{
    if is_loopback {
        return Ok(None);
    }
    let Some(iface) = detect_iface().filter(|s| !s.is_empty()) else {
        return Err("No active cellular WAN interface for SO_BINDTODEVICE (fail-closed)".into());
    };
    let c_if = std::ffi::CString::new(iface.as_str())
        .map_err(|_| format!("Invalid cellular WAN interface name: {iface}"))?;
    let rc = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            c_if.as_ptr() as *const libc::c_void,
            c_if.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "SO_BINDTODEVICE({iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Some(iface))
}

fn bind_socket_to_cellular_wan(
    sock: libc::c_int,
    is_loopback: bool,
) -> Result<Option<String>, String> {
    bind_socket_to_cellular_wan_with(sock, is_loopback, detect_cached_cellular_wan_iface)
}

/// Build the ordered LinkWatch probe target list (primary + secondary fallback),
/// automatically picking IPv6 targets when the active bearer is IPv6-only.
pub fn linkwatch_probe_targets(primary: &str, ipv6_only: bool) -> Vec<String> {
    let p = primary.trim();
    let mut out = Vec::with_capacity(3);
    if ipv6_only {
        if !p.is_empty() && p.parse::<Ipv4Addr>().is_err() {
            out.push(p.to_string());
        }
        for fb in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            if !out.iter().any(|x| x.eq_ignore_ascii_case(fb)) {
                out.push(fb.to_string());
            }
            if out.len() >= 2 {
                break;
            }
        }
    } else {
        let primary_eff = if p.is_empty() { "8.8.8.8" } else { p };
        out.push(primary_eff.to_string());
        let secondary = if primary_eff.parse::<Ipv6Addr>().is_ok() {
            if primary_eff.eq_ignore_ascii_case("2606:4700:4700::1111") {
                "2001:4860:4860::8888"
            } else {
                "2606:4700:4700::1111"
            }
        } else if primary_eff == "1.1.1.1" {
            "8.8.8.8"
        } else {
            "1.1.1.1"
        };
        out.push(secondary.to_string());
    }
    out
}

async fn is_bearer_ipv6_only(state: &AppState) -> bool {
    let m = state.modem.read().await;
    let has_v4 = m.bearers.iter().any(|b| {
        b.ipv4
            .as_deref()
            .is_some_and(|ip| !ip.is_empty() && ip != "0.0.0.0")
    });
    let has_v6 = m.bearers.iter().any(|b| {
        b.ipv6
            .as_deref()
            .is_some_and(|ip| !ip.is_empty() && ip != "::")
    });
    has_v6 && !has_v4
}

struct CachedRawIcmpSock {
    fd: libc::c_int,
    iface: Option<String>,
    mark: Option<u32>,
    is_loopback: bool,
}

impl Drop for CachedRawIcmpSock {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

static RAW_ICMP_V4_CACHE: std::sync::Mutex<Option<CachedRawIcmpSock>> =
    std::sync::Mutex::new(None);
static RAW_ICMP_V6_CACHE: std::sync::Mutex<Option<CachedRawIcmpSock>> =
    std::sync::Mutex::new(None);

fn drain_stale_icmp_packets(fd: libc::c_int) {
    let mut discard = [0u8; 256];
    for _ in 0..32 {
        let n = unsafe {
            libc::recv(
                fd,
                discard.as_mut_ptr() as *mut libc::c_void,
                discard.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n <= 0 {
            break;
        }
    }
}

fn next_icmp_ident() -> u16 {
    let tick = ICMP_IDENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid_lo = (std::process::id() & 0xFFFF) as u16;
    (pid_lo.wrapping_add(tick)) | 1
}

fn open_and_configure_raw_icmp(
    domain: libc::c_int,
    proto: libc::c_int,
    is_loopback: bool,
    iface: Option<&str>,
    mark: Option<u32>,
) -> Result<CachedRawIcmpSock, String> {
    let sock = unsafe { libc::socket(domain, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if sock < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    let holder = CachedRawIcmpSock {
        fd: sock,
        iface: iface.map(str::to_string),
        mark,
        is_loopback,
    };
    let bound = bind_socket_to_cellular_wan_with(holder.fd, is_loopback, || iface.map(str::to_string))?;
    let _ = bound;
    if let Some(m) = mark {
        let mv: libc::c_int = m as libc::c_int;
        unsafe {
            libc::setsockopt(
                holder.fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mv as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok(holder)
}

pub async fn icmp_ping_once(target: &str, seq: u16) -> Result<f64, String> {
    let host = target.trim().to_string();
    // Stored targets may predate validation: never hand ping something it reads as a flag.
    if !crate::admin::validate::is_net_target(&host) {
        return Err("Invalid ping target".into());
    }
    let resolved_ip: Option<IpAddr> = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        Some(IpAddr::V4(v4))
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        Some(IpAddr::V6(v6))
    } else {
        let h_clone = host.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let addrs: Vec<SocketAddr> = (h_clone.as_str(), 0u16)
                    .to_socket_addrs()
                    .ok()?
                    .collect();
                addrs
                    .iter()
                    .find_map(|sa| match sa.ip() {
                        IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
                        IpAddr::V6(_) => None,
                    })
                    .or_else(|| addrs.first().map(SocketAddr::ip))
            }),
        )
        .await
        .map_err(|_| format!("DNS lookup timed out for {host}"))?
        .ok()
        .flatten()
    };

    match resolved_ip {
        Some(IpAddr::V4(ip_v4)) => {
            let raw_res = tokio::task::spawn_blocking(move || raw_icmp_echo_v4(ip_v4, seq))
                .await
                .map_err(|e| format!("icmp task failed: {e}"))?;
            match raw_res {
                Ok(rtt) => Ok(rtt),
                Err(e)
                    if e.contains("Operation not permitted")
                        || e.contains("EPERM")
                        || e.contains("EACCES") =>
                {
                    let iface = if ip_v4.is_loopback() {
                        None
                    } else {
                        let dev = tokio::task::spawn_blocking(detect_cached_cellular_wan_iface)
                            .await
                            .ok()
                            .flatten();
                        if dev.is_none() {
                            return Err("No active cellular WAN interface (fail-closed)".into());
                        }
                        dev
                    };
                    ping_subprocess_fallback(&host, false, iface.as_deref()).await
                }
                Err(e) => Err(e),
            }
        }
        Some(IpAddr::V6(ip_v6)) => {
            let raw_res = tokio::task::spawn_blocking(move || raw_icmp_echo_v6(ip_v6, seq))
                .await
                .map_err(|e| format!("icmp6 task failed: {e}"))?;
            match raw_res {
                Ok(rtt) => Ok(rtt),
                Err(e)
                    if e.contains("Operation not permitted")
                        || e.contains("EPERM")
                        || e.contains("EACCES") =>
                {
                    let iface = if ip_v6.is_loopback() {
                        None
                    } else {
                        let dev = tokio::task::spawn_blocking(detect_cached_cellular_wan_iface)
                            .await
                            .ok()
                            .flatten();
                        if dev.is_none() {
                            return Err("No active cellular WAN interface (fail-closed)".into());
                        }
                        dev
                    };
                    ping_subprocess_fallback(&host, true, iface.as_deref()).await
                }
                Err(e) => Err(e),
            }
        }
        None => Err(format!("DNS lookup returned no addresses for {host}")),
    }
}

fn raw_icmp_echo_v4(dest: Ipv4Addr, seq: u16) -> Result<f64, String> {
    let is_loopback = dest.is_loopback();
    let iface = if is_loopback {
        None
    } else {
        let Some(dev) = detect_cached_cellular_wan_iface() else {
            return Err("No active cellular WAN interface for SO_BINDTODEVICE (fail-closed)".into());
        };
        Some(dev)
    };
    let mark = crate::vpn::bypass_mark();

    let mut cache = RAW_ICMP_V4_CACHE
        .lock()
        .map_err(|_| "ICMPv4 socket mutex poisoned".to_string())?;
    let need_reopen = match cache.as_ref() {
        Some(c) => c.iface != iface || c.mark != mark || c.is_loopback != is_loopback,
        None => true,
    };
    if need_reopen {
        *cache = None;
        let fresh = open_and_configure_raw_icmp(
            libc::AF_INET,
            libc::IPPROTO_ICMP,
            is_loopback,
            iface.as_deref(),
            mark,
        )?;
        *cache = Some(fresh);
    }
    let fd = cache.as_ref().unwrap().fd;
    drain_stale_icmp_packets(fd);

    let ident = next_icmp_ident();
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
    loop {
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        *cache = None;
        invalidate_cached_wan_iface();
        return Err(format!("sendto: {err}"));
    }

    let deadline = started + Duration::from_millis(1800);
    let mut recv_buf = [0u8; 256];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("ICMP request timed out".into());
        }
        let rem_ms = deadline.duration_since(now).as_millis().max(1) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
        if prc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            *cache = None;
            invalidate_cached_wan_iface();
            return Err(format!("poll: {err}"));
        }
        if prc == 0 {
            return Err("ICMP request timed out".into());
        }
        let n = unsafe {
            libc::recv(
                fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            *cache = None;
            invalidate_cached_wan_iface();
            return Err(format!("recv: {err}"));
        }
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

fn raw_icmp_echo_v6(dest: Ipv6Addr, seq: u16) -> Result<f64, String> {
    let is_loopback = dest.is_loopback();
    let iface = if is_loopback {
        None
    } else {
        let Some(dev) = detect_cached_cellular_wan_iface() else {
            return Err("No active cellular WAN interface for SO_BINDTODEVICE (fail-closed)".into());
        };
        Some(dev)
    };
    let mark = crate::vpn::bypass_mark();

    let mut cache = RAW_ICMP_V6_CACHE
        .lock()
        .map_err(|_| "ICMPv6 socket mutex poisoned".to_string())?;
    let need_reopen = match cache.as_ref() {
        Some(c) => c.iface != iface || c.mark != mark || c.is_loopback != is_loopback,
        None => true,
    };
    if need_reopen {
        *cache = None;
        let fresh = open_and_configure_raw_icmp(
            libc::AF_INET6,
            libc::IPPROTO_ICMPV6,
            is_loopback,
            iface.as_deref(),
            mark,
        )?;
        *cache = Some(fresh);
    }
    let fd = cache.as_ref().unwrap().fd;
    drain_stale_icmp_packets(fd);

    let ident = next_icmp_ident();
    let mut pkt = [0u8; 16];
    pkt[0] = 128; // ICMPv6 Echo Request (kernel fills checksum at offset 2 for IPPROTO_ICMPV6)
    pkt[1] = 0;
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..16].copy_from_slice(b"QUECMGR6");

    let sa = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: dest.octets(),
        },
        sin6_scope_id: 0,
    };
    let started = Instant::now();
    loop {
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        *cache = None;
        invalidate_cached_wan_iface();
        return Err(format!("sendto6: {err}"));
    }

    let deadline = started + Duration::from_millis(1800);
    let mut recv_buf = [0u8; 256];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("ICMPv6 request timed out".into());
        }
        let rem_ms = deadline.duration_since(now).as_millis().max(1) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
        if prc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            *cache = None;
            invalidate_cached_wan_iface();
            return Err(format!("poll6: {err}"));
        }
        if prc == 0 {
            return Err("ICMPv6 request timed out".into());
        }
        let n = unsafe {
            libc::recv(
                fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            *cache = None;
            invalidate_cached_wan_iface();
            return Err(format!("recv6: {err}"));
        }
        if n < 8 {
            continue;
        }
        let icmp6 = &recv_buf[..n as usize];
        // SOCK_RAW IPPROTO_ICMPV6 delivers the ICMPv6 header directly (Echo Reply = 129).
        if icmp6[0] == 129
            && u16::from_be_bytes([icmp6[4], icmp6[5]]) == ident
            && u16::from_be_bytes([icmp6[6], icmp6[7]]) == seq
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

async fn ping_subprocess_fallback(
    host: &str,
    ipv6: bool,
    iface: Option<&str>,
) -> Result<f64, String> {
    if !crate::admin::validate::is_net_target(host) {
        return Err("Invalid ping host".into());
    }
    let mut args: Vec<&str> = Vec::with_capacity(9);
    if ipv6 {
        args.push("-6");
    }
    if let Some(dev) = iface.filter(|d| !d.is_empty()) {
        args.extend(["-I", dev]);
    }
    args.extend(ping_argv(host));
    // `--` ends option parsing: the host is an operand even if validation regressed.
    let out = run_cmd("ping", &args, Duration::from_secs(3)).await?;
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

pub fn disconnect_count() -> u32 {
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
                let mut slow_cache = SlowVitalsCache::default();
                let mut eth_deg = None;
                let mut eth_ren = None;
                poll_system_vitals(&state, "_a", Some(up), true, &mut slow_cache, &mut eth_deg, &mut eth_ren).await;
                assert_eq!(state.session_uptime.read().await.is_connected, Some(true));
                assert_eq!(state.session_uptime.read().await.uptime_seconds, 120);

                poll_system_vitals(&state, "_a", None, false, &mut slow_cache, &mut eth_deg, &mut eth_ren).await;
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
        std::fs::create_dir_all(env.root.join("tmp/cellcore")).unwrap();

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
                    save_json_compact_atomic(DATA_USAGE_PATH, &*u, 0o600).unwrap();
                }

                let mut tracker = UsageFlushTracker::default();
                let valid_wall = crate::state::MIN_VALID_WALL_CLOCK_SECS + 3600;
                let ymd = ("2026-11-21".to_string(), "2026-11".to_string(), 21u8);
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    500,
                    200,
                    &mut tracker,
                    valid_wall,
                    ymd.clone(),
                    Instant::now(),
                )
                .await;
                {
                    let u = app.data_usage.read().await;
                    assert!(u.daily.is_empty());
                    assert!(u.monthly.is_empty());
                }
                let on_disk_idle: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(env.root.join("etc/cellcore/data_usage.json")).unwrap())
                        .unwrap();
                assert_eq!(on_disk_idle["daily"], serde_json::json!([]));

                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    1524,
                    200,
                    &mut tracker,
                    valid_wall,
                    ymd,
                    Instant::now(),
                )
                .await;
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
        let qrsrp_i = with_atfwd
            .iter()
            .position(|c| c == "AT+QRSRP;+QRSRQ;+QSINR")
            .unwrap();
        let qmap_i = with_atfwd.iter().position(|c| c == "AT+QMAP=\"WWAN\"").unwrap();
        let cgcont_i = with_atfwd.iter().position(|c| c == "AT+CGCONTRDP").unwrap();
        let qtemp_i = with_atfwd.iter().position(|c| c == "AT+QTEMP").unwrap();
        let qspn_i = with_atfwd.iter().position(|c| c == "AT+QSPN").unwrap();
        assert!(!with_atfwd.iter().any(|c| c == "AT+C5GREG?"));
        assert!(qrsrp_i < qmap_i && qmap_i < cgcont_i && cgcont_i < qtemp_i && qtemp_i < qspn_i);
        // Four fast baseband commands always trail AT+QTEMP so /dev/smd11 recovers cleanly.
        assert_eq!(with_atfwd.len() - qtemp_i - 1, 4);

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
        assert_eq!(native_cmds.len() - qtemp_i - 1, 4);

        // Native mode + NR5G-SA + cached QSPN omits QMAP, CGCONTRDP, QSPN, and lte_time_advance (6 cmds total!)
        let lean_sa: Vec<String> = build_telemetry_commands_full(
            "AT+QCAINFO",
            "AT+QNWCFG=\"nr5g_time_advance\"",
            None,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .into_iter()
        .map(|(c, _)| c)
        .collect();
        assert_eq!(
            lean_sa,
            vec![
                "AT+CFUN?",
                "AT+QENG=\"servingcell\"",
                "AT+QCAINFO",
                "AT+QRSRP;+QRSRQ;+QSINR",
                "AT+QNWCFG=\"nr5g_mimo_info\"",
                "AT+QNWCFG=\"nr5g_time_advance\"",
                "AT+QUIMSLOT?",
            ]
        );
    }

    #[test]
    fn eth0_sysfs_speed_reports_down_on_carrier_zero_or_negative_speed() {
        assert_eq!(
            parse_eth_sysfs_speed(Some("0\n"), Some("2500\n"), Some("full\n")),
            ("down".into(), "down".into())
        );
        assert_eq!(
            parse_eth_sysfs_speed(Some("1\n"), Some("-1\n"), Some("unknown\n")),
            ("down".into(), "down".into())
        );
        assert_eq!(
            parse_eth_sysfs_speed(None, None, None),
            ("down".into(), "down".into())
        );
        assert_eq!(
            parse_eth_sysfs_speed(Some("1\n"), Some("2500\n"), Some("full\n")),
            ("2500Mb/s".into(), "full".into())
        );
        assert!(is_eth0_degraded_auto("auto", "100Mb/s", "full"));
        assert!(is_eth0_degraded_auto("auto", "2500Mb/s", "half"));
        assert!(!is_eth0_degraded_auto("auto", "2500Mb/s", "full"));
        assert!(!is_eth0_degraded_auto("auto", "down", "down"));
        assert!(!is_eth0_degraded_auto("100", "100Mb/s", "full"));
    }

    #[tokio::test]
    async fn usage_flush_cuts_etc_wear_to_6h_or_50mib_and_blocks_1970_pre_ntp_buckets() {
        let sbx = crate::paths::TestSandbox::new("usage-wear-cut");
        std::fs::create_dir_all(sbx.root.join("etc/cellcore")).unwrap();
        std::fs::create_dir_all(sbx.root.join("tmp/cellcore")).unwrap();

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests(sbx.root.clone(), auth);
                {
                    let mut u = app.data_usage.write().await;
                    u.last_iface = "rmnet_data0".into();
                    u.last_raw_rx = 0;
                    u.last_raw_tx = 0;
                }

                let mut tracker = UsageFlushTracker::default();
                let t0 = Instant::now();

                // 1. Pre-NTP wall clock (e.g. 42s in 1970): holds delta in memory, NO 1970-01-01 bucket!
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    4096,
                    1024,
                    &mut tracker,
                    42,
                    ("1970-01-01".into(), "1970-01".into(), 1),
                    t0,
                )
                .await;
                assert!(app.data_usage.read().await.daily.is_empty());
                assert!(!sbx.root.join("etc/cellcore/data_usage.json").exists());

                // 2. NTP syncs -> first post-NTP tick folds held 4096+1024 + new 1000 into 2026-11-21
                // and flushes initial daily bucket to /etc and /tmp (0600).
                let valid_wall = crate::state::MIN_VALID_WALL_CLOCK_SECS + 100;
                let ymd = ("2026-11-21".to_string(), "2026-11".to_string(), 21u8);
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    5096,
                    1024,
                    &mut tracker,
                    valid_wall,
                    ymd.clone(),
                    t0,
                )
                .await;
                assert_eq!(app.data_usage.read().await.daily[0].rx_bytes, 5096);
                let etc_file = sbx.root.join("etc/cellcore/data_usage.json");
                let tmp_file = sbx.root.join("tmp/cellcore/data_usage.json");
                assert!(etc_file.exists() && tmp_file.exists());
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    assert_eq!(
                        std::fs::metadata(&tmp_file).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }

                // 3. 10 minutes later (+1 MiB): writes /tmp snapshot (5m), does NOT touch /etc (<6h & <50MiB)!
                let t_10m = t0 + Duration::from_secs(600);
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    5096 + 1024 * 1024,
                    1024,
                    &mut tracker,
                    valid_wall + 600,
                    ymd.clone(),
                    t_10m,
                )
                .await;
                let etc_v: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&etc_file).unwrap()).unwrap();
                let tmp_v: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&tmp_file).unwrap()).unwrap();
                assert_eq!(etc_v["daily"][0]["rxBytes"], 5096, "/etc must not be rewritten at 10m");
                assert_eq!(tmp_v["daily"][0]["rxBytes"], 5096 + 1024 * 1024, "/tmp updated at 5m");

                // 4. Startup load_initial_data_usage prefers fresher /tmp snapshot over stale /etc.
                let loaded = load_initial_data_usage();
                assert_eq!(loaded.daily[0].rx_bytes, 5096 + 1024 * 1024);

                // 5. >= 512 MiB accumulated delta triggers /etc flush once past the 3600s debounce even before 6h.
                let big_rx = 5096 + 520 * 1024 * 1024;
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    big_rx,
                    1024,
                    &mut tracker,
                    valid_wall + 3605,
                    ymd.clone(),
                    t0 + Duration::from_secs(3605),
                )
                .await;
                let etc_after_512m: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&etc_file).unwrap()).unwrap();
                assert_eq!(etc_after_512m["daily"][0]["rxBytes"], big_rx);

                // 6. Small delta after 6 hours also flushes /etc.
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    big_rx + 2048,
                    1024,
                    &mut tracker,
                    valid_wall + 3605 + DATA_USAGE_ETC_FLUSH_SECS + 10,
                    ymd,
                    t0 + Duration::from_secs(3605 + DATA_USAGE_ETC_FLUSH_SECS + 10),
                )
                .await;
                let etc_after_6h: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&etc_file).unwrap()).unwrap();
                assert_eq!(etc_after_6h["daily"][0]["rxBytes"], big_rx + 2048);
            })
            .await;
    }

    #[tokio::test]
    async fn cell_lock_deadman_clears_live_lock_preserves_settings_and_reprobes() {
        let sbx = crate::paths::TestSandbox::new("deadman-reprobe");
        let modem = crate::fakeat::FakeModem::new(crate::fakeat::Radio::new("2:66", "41", "41", "AUTO", 0));
        modem.with(|s| {
            s.lock5g = Some("589,521310,30,41".into());
        });

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, modem.client());
                {
                    let mut s = app.settings.write().await;
                    s.cell_lock_deadman_enabled = true;
                    s.cell_lock_deadman_secs = 180;
                    s.cell_lock_nr5g = "589,521310,30,41".into();
                    s.cell_lock_nr5g_persist = true;
                }
                {
                    // Simulate unregistered SEARCH state on modem.
                    let mut m = app.modem.write().await;
                    m.identity.cfun = 1;
                    m.serving = None;
                }

                let mut tracker = CellLockDeadmanTracker::default();
                let t0 = Instant::now();

                // At t=0 and t=179s: still within 180s grace window.
                tick_cell_lock_deadman(&app, &mut tracker, t0, Duration::ZERO).await;
                tick_cell_lock_deadman(&app, &mut tracker, t0 + Duration::from_secs(179), Duration::ZERO).await;
                assert!(!app.cell_lock_bypassed.load(Ordering::Acquire));
                assert_eq!(modem.with(|s| s.lock5g.as_deref().unwrap_or("0").to_string()), "589,521310,30,41");

                // At t=180s: deadman fires -> clears live modem lock + save_ctrl=0,0 while keeping settings!
                tick_cell_lock_deadman(&app, &mut tracker, t0 + Duration::from_secs(180), Duration::ZERO).await;
                assert!(app.cell_lock_bypassed.load(Ordering::Acquire));
                assert_eq!(modem.with(|s| s.lock5g.as_deref().unwrap_or("0").to_string()), "0");
                assert_eq!(modem.with(|s| s.save_ctrl.as_deref().unwrap_or("0,0").to_string()), "0,0");
                assert_eq!(app.settings.read().await.cell_lock_nr5g, "589,521310,30,41");

                // Re-probe at +15m when target PCI 589 is NOT visible -> stays bypassed and escalates stage to 30m.
                let t_15m = t0 + Duration::from_secs(180 + 15 * 60);
                tick_cell_lock_deadman(&app, &mut tracker, t_15m, Duration::ZERO).await;
                assert!(app.cell_lock_bypassed.load(Ordering::Acquire));
                assert_eq!(tracker.reprobe_stage, 1);

                // Re-probe at +45m (15m + 30m) when modem sees target PCI 589 -> restores QNWLOCK + save_ctrl!
                {
                    let mut m = app.modem.write().await;
                    m.serving = Some(ServingCellInfo {
                        state: "NOCONN".into(),
                        rat: "NR5G-SA".into(),
                        pci: Some(589),
                        ..Default::default()
                    });
                }
                let t_45m = t_15m + Duration::from_secs(30 * 60);
                tick_cell_lock_deadman(&app, &mut tracker, t_45m, Duration::ZERO).await;
                assert!(!app.cell_lock_bypassed.load(Ordering::Acquire));
                assert_eq!(modem.with(|s| s.lock5g.as_deref().unwrap_or("0").to_string()), "589,521310,30,41");
                assert_eq!(modem.with(|s| s.save_ctrl.as_deref().unwrap_or("0,0").to_string()), "0,1");
            })
            .await;
    }

    #[tokio::test]
    async fn sim_slot_change_immediately_requeries_iccid_and_imsi_without_waiting_for_need_static() {
        let sbx = crate::paths::TestSandbox::new("sim-swap-iccid");
        let sim_iccid = Arc::new(std::sync::Mutex::new("89012601111111111111".to_string()));
        let sim_imsi = Arc::new(std::sync::Mutex::new("310260111111111".to_string()));
        let sim_slot = Arc::new(std::sync::Mutex::new(1i32));

        let iccid_c = sim_iccid.clone();
        let imsi_c = sim_imsi.clone();
        let slot_c = sim_slot.clone();

        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let body = match cmd.as_str() {
                        "AT+CGMI" => "+CGMI: Quectel".to_string(),
                        "AT+CGMM" => "+CGMM: RM551E-GL".to_string(),
                        "AT+QGMR" => "RM551EGL00AAR01A02M8G".to_string(),
                        "AT+ICCID" => format!("+ICCID: {}", *iccid_c.lock().unwrap()),
                        "AT+CIMI" => imsi_c.lock().unwrap().clone(),
                        "AT+QUIMSLOT?" => format!("+QUIMSLOT: {}", *slot_c.lock().unwrap()),
                        "AT+CFUN?" => "+CFUN: 1".to_string(),
                        _ => String::new(),
                    };
                    let reply = if body.is_empty() {
                        format!("{cmd}\r\r\nOK\r\n")
                    } else {
                        format!("{cmd}\r\r\n{body}\r\nOK\r\n")
                    };
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });

        use std::os::unix::io::IntoRawFd;
        let fd_opt = std::sync::Mutex::new(Some(a.into_raw_fd()));
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_opt.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, smd);

                // Poll 1: populates static revision/model + SIM1 ICCID/IMSI.
                refresh_modem_snapshot(&app, Priority::Telemetry, true).await;
                assert_eq!(app.secrets.read().await.iccid, "89012601111111111111");
                assert_eq!(app.secrets.read().await.imsi, "310260111111111");
                assert!(!app.modem.read().await.identity.revision.is_empty());

                // Switch SIM slot to 2 with brand-new ICCID/IMSI (need_static is now FALSE!).
                *sim_slot.lock().unwrap() = 2;
                *sim_iccid.lock().unwrap() = "89014102222222222222".into();
                *sim_imsi.lock().unwrap() = "310410222222222".into();

                // Poll 2: detects sim_slot 1 -> 2 and immediately refreshes ICCID & IMSI!
                refresh_modem_snapshot(&app, Priority::Telemetry, false).await;
                assert_eq!(app.modem.read().await.identity.sim_slot, 2);
                assert_eq!(app.secrets.read().await.iccid, "89014102222222222222");
                assert_eq!(app.secrets.read().await.imsi, "310410222222222");
                assert!(app.modem.read().await.identity.masked_iccid.ends_with("2222"));
            })
            .await;
    }

    #[tokio::test]
    async fn cfun_one_guard_retries_on_failure_and_linkwatch_stage3_bypasses_cell_lock() {
        let sbx = crate::paths::TestSandbox::new("cfun-guard-stage3");
        let cfun_tries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tries_c = cfun_tries.clone();

        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let reply = if cmd == "AT+CFUN=1" {
                        let k = tries_c.fetch_add(1, Ordering::SeqCst) + 1;
                        if k == 1 {
                            format!("{cmd}\r\r\nERROR\r\n")
                        } else {
                            format!("{cmd}\r\r\nOK\r\n")
                        }
                    } else if cmd == "AT+QSIMSTAT?" {
                        format!("{cmd}\r\r\n+QSIMSTAT: 1,0\r\nOK\r\n")
                    } else if cmd == "AT+QUIMSLOT?" {
                        format!("{cmd}\r\r\n+QUIMSLOT: 1\r\nOK\r\n")
                    } else {
                        format!("{cmd}\r\r\nOK\r\n")
                    };
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });

        use std::os::unix::io::IntoRawFd;
        let fd_opt = std::sync::Mutex::new(Some(a.into_raw_fd()));
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_opt.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, smd);

                // 1. CFUN=1 fails once, succeeds on retry 2.
                assert!(ensure_cfun_one_with_retries(&app, Duration::from_secs(2)).await);
                assert_eq!(cfun_tries.load(Ordering::SeqCst), 2);

                // 2. LinkWatch Stage 3 temporarily bypasses configured cell lock.
                let cfg = crate::state::DaemonSettings {
                    quecwatch_connection_refresh: true,
                    cell_lock_nr5g: "589,521310,30,41".into(),
                    ..Default::default()
                };
                assert!(trigger_quecwatch_recovery(&app, &cfg, 3).await);
                assert!(app.cell_lock_bypassed.load(Ordering::Acquire));

                // 3. SIM presence check rejects switch when +QSIMSTAT reports absent (0).
                assert!(!try_verified_sim_switch(&app, 2, "test").await);
            })
            .await;
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

    #[test]
    fn sim_slot_presence_fails_closed_for_inactive_slot_without_uim() {
        // QMI UIM is authoritative for both active and inactive slots.
        assert!(decide_sim_slot_presence(2, Some(1), Some("present"), None));
        assert!(!decide_sim_slot_presence(2, Some(1), Some("absent"), Some(true)));
        // Without QMI UIM, an inactive slot MUST fail closed even if AT+QSIMSTAT? says inserted (active slot)!
        assert!(!decide_sim_slot_presence(2, Some(1), None, Some(true)));
        assert!(!decide_sim_slot_presence(2, None, None, Some(true)));
        // Active slot can still use AT+QSIMSTAT?
        assert!(decide_sim_slot_presence(1, Some(1), None, Some(true)));
        assert!(!decide_sim_slot_presence(1, Some(1), None, Some(false)));
    }

    #[test]
    fn fail_closed_bind_socket_rejects_missing_wan_and_allows_loopback() {
        assert_eq!(
            bind_socket_to_cellular_wan_with(-1, true, || None),
            Ok(None),
            "loopback targets do not require a cellular WAN interface"
        );
        let err = bind_socket_to_cellular_wan_with(-1, false, || None)
            .expect_err("non-loopback target must fail closed when no cellular WAN exists");
        assert!(err.contains("fail-closed"));
    }

    #[test]
    fn linkwatch_targets_support_secondary_fallback_and_ipv6_only() {
        assert_eq!(
            linkwatch_probe_targets("8.8.8.8", false),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
        assert_eq!(
            linkwatch_probe_targets("1.1.1.1", false),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
        assert_eq!(
            linkwatch_probe_targets("8.8.8.8", true),
            vec![
                "2606:4700:4700::1111".to_string(),
                "2001:4860:4860::8888".to_string()
            ]
        );
        assert_eq!(
            linkwatch_probe_targets("2606:4700:4700::1111", true),
            vec![
                "2606:4700:4700::1111".to_string(),
                "2001:4860:4860::8888".to_string()
            ]
        );
    }

    #[test]
    fn parses_cloudflared_ha_connections_and_statm_and_partner_speed() {
        let body = "# HELP cloudflared_tunnel_ha_connections Count of active HA connections\n\
                    # TYPE cloudflared_tunnel_ha_connections gauge\n\
                    cloudflared_tunnel_ha_connections 4\n\
                    cloudflared_tunnel_ha_connections_total 99\n";
        assert_eq!(parse_cloudflared_metrics(body), Some(4));
        assert_eq!(parse_cloudflared_metrics("unrelated_metric 1\n"), None);

        assert_eq!(parse_proc_statm_rss_bytes("10240 2048 512 10 0 1500 0\n", 4096), Some(8_388_608));
        assert_eq!(parse_proc_statm_rss_bytes("invalid", 4096), None);

        let ethtool_gig = "Settings for eth0:\n\tLink partner advertised link modes: 100baseT/Full 1000baseT/Full 2500baseT/Full\n";
        let ethtool_fast = "Settings for eth0:\n\tLink partner advertised link modes: 10baseT/Full 100baseT/Full\n";
        assert!(partner_supports_gigabit(ethtool_gig));
        assert!(!partner_supports_gigabit(ethtool_fast));
    }

    #[tokio::test]
    async fn linkwatch_stage3_bypass_not_undone_when_deadman_disabled_and_noop_recovery_skips_alert() {
        let sbx = crate::paths::TestSandbox::new("stage3-deadman-coord");
        let modem = crate::fakeat::FakeModem::new(crate::fakeat::Radio::new("2:66", "41", "41", "AUTO", 0));
        modem.with(|s| {
            s.lock5g = Some("589,521310,30,41".into());
        });

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, modem.client());

                // Both connection_refresh and auto_sim_failover disabled -> skips alert!
                let noop_cfg = crate::state::DaemonSettings {
                    quecwatch_connection_refresh: false,
                    quecwatch_auto_sim_failover: false,
                    ..Default::default()
                };
                assert!(trigger_quecwatch_recovery(&app, &noop_cfg, 1).await);
                assert!(app.alerts.read().await.is_empty());

                // Stage 3 bypass with deadman DISABLED must persist and must NOT be undone by deadman tick!
                {
                    let mut s = app.settings.write().await;
                    s.cell_lock_deadman_enabled = false;
                    s.cell_lock_nr5g = "589,521310,30,41".into();
                }
                let s3_cfg = crate::state::DaemonSettings {
                    quecwatch_connection_refresh: true,
                    cell_lock_nr5g: "589,521310,30,41".into(),
                    ..Default::default()
                };
                assert!(trigger_quecwatch_recovery(&app, &s3_cfg, 3).await);
                assert!(app.cell_lock_bypassed.load(Ordering::Acquire));
                assert_eq!(
                    CellLockBypassReason::from_u8(app.cell_lock_bypass_reason.load(Ordering::Acquire)),
                    CellLockBypassReason::LinkWatch
                );
                assert_eq!(load_initial_cell_lock_bypass(), (true, CellLockBypassReason::LinkWatch));

                let mut tracker = CellLockDeadmanTracker::default();
                tick_cell_lock_deadman(&app, &mut tracker, Instant::now(), Duration::ZERO).await;
                assert!(
                    app.cell_lock_bypassed.load(Ordering::Acquire),
                    "disabled deadman must not undo LinkWatch Stage 3 bypass"
                );
            })
            .await;
    }

    #[tokio::test]
    async fn data_usage_etc_512mib_flush_obeys_3600s_debounce_and_flushes_on_zero_delta() {
        let sbx = crate::paths::TestSandbox::new("usage-debounce-3600s");
        std::fs::create_dir_all(sbx.root.join("etc/cellcore")).unwrap();
        std::fs::create_dir_all(sbx.root.join("tmp/cellcore")).unwrap();

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests(sbx.root.clone(), auth);
                let t0 = Instant::now();
                let mut tracker = UsageFlushTracker::new_at_boot(t0);
                let valid_wall = crate::state::MIN_VALID_WALL_CLOCK_SECS + 100;
                let ymd = ("2026-11-22".to_string(), "2026-11".to_string(), 22u8);

                {
                    let mut u = app.data_usage.write().await;
                    u.last_iface = "rmnet_data0".into();
                    u.daily.push(DailyUsageEntry {
                        date: ymd.0.clone(),
                        rx_bytes: 1000,
                        tx_bytes: 0,
                    });
                    u.monthly.push(MonthlyUsageEntry {
                        month: ymd.1.clone(),
                        rx_bytes: 1000,
                        tx_bytes: 0,
                    });
                    save_json_compact_atomic(DATA_USAGE_PATH, &*u, 0o600).unwrap();
                }

                // +520 MiB at t0 + 600s (< 3600s debounce): must NOT rewrite /etc yet!
                let over_threshold = 520 * 1024 * 1024;
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    over_threshold,
                    0,
                    &mut tracker,
                    valid_wall + 600,
                    ymd.clone(),
                    t0 + Duration::from_secs(600),
                )
                .await;
                let etc_early: DataUsageState = load_json_or_default(DATA_USAGE_PATH);
                assert_eq!(etc_early.daily[0].rx_bytes, 1000, "/etc flush must debounce for 3600s");

                // Zero-delta tick at t0 + 3605s (>= 3600s debounce): buffered 520 MiB flushes to /etc!
                update_persistent_usage_with_clock(
                    &app,
                    "rmnet_data0",
                    over_threshold,
                    0,
                    &mut tracker,
                    valid_wall + 3605,
                    ymd,
                    t0 + Duration::from_secs(3605),
                )
                .await;
                let etc_after: DataUsageState = load_json_or_default(DATA_USAGE_PATH);
                assert_eq!(etc_after.daily[0].rx_bytes, 1000 + over_threshold);
            })
            .await;
    }

    #[test]
    fn watchdog_rf_grace_covers_console_at_and_bounds_ceiling() {
        // Idle -> no grace
        assert!(!watchdog_rf_in_grace(100_000, 0, 0, 0));
        // Active 60s console AT (e.g. AT+COPS=?) -> grace for 60s + 20s overhead = 80s
        assert!(watchdog_rf_in_grace(100_000 + 60_000, 0, 100_000, 60_000));
        assert!(watchdog_rf_in_grace(100_000 + 80_000, 0, 100_000, 60_000));
        assert!(!watchdog_rf_in_grace(100_000 + 80_001, 0, 100_000, 60_000));
        // Even if a huge timeout is passed, grace is hard-capped at CONSOLE_AT_WATCHDOG_MAX_GRACE_MS (90s)
        assert!(watchdog_rf_in_grace(
            100_000 + CONSOLE_AT_WATCHDOG_MAX_GRACE_MS,
            0,
            100_000,
            300_000
        ));
        assert!(!watchdog_rf_in_grace(
            100_000 + CONSOLE_AT_WATCHDOG_MAX_GRACE_MS + 1,
            0,
            100_000,
            300_000
        ));
        // QSCAN grace still works up to QSCAN_WATCHDOG_GRACE_MS
        assert!(watchdog_rf_in_grace(100_000 + QSCAN_WATCHDOG_GRACE_MS, 100_000, 0, 0));
        assert!(!watchdog_rf_in_grace(100_000 + QSCAN_WATCHDOG_GRACE_MS + 1, 100_000, 0, 0));
    }

    #[tokio::test]
    async fn failed_quimslot_preserves_last_known_slot_without_churn() {
        assert_eq!(parse_quimslot_reply("+QUIMSLOT: 1"), Some(1));
        assert_eq!(parse_quimslot_reply("+QUIMSLOT: 2"), Some(2));
        assert_eq!(parse_quimslot_reply(""), None);
        assert_eq!(parse_quimslot_reply("ERROR"), None);
        assert_eq!(parse_quimslot_reply("+QUIMSLOT: 0"), None);
        assert_eq!(parse_quimslot_reply("+QUIMSLOT: 9"), None);

        let sbx = crate::paths::TestSandbox::new("quimslot-fail-preserve");
        let fail_slot = Arc::new(AtomicBool::new(false));
        let fail_c = fail_slot.clone();

        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let reply = match cmd.as_str() {
                        "AT+CGMI" => format!("{cmd}\r\r\n+CGMI: Quectel\r\nOK\r\n"),
                        "AT+CGMM" => format!("{cmd}\r\r\n+CGMM: RM551E-GL\r\nOK\r\n"),
                        "AT+QGMR" => format!("{cmd}\r\r\nRM551EGL00AAR01A02M8G\r\nOK\r\n"),
                        "AT+ICCID" => format!("{cmd}\r\r\n+ICCID: 89014102222222222222\r\nOK\r\n"),
                        "AT+CIMI" => format!("{cmd}\r\r\n310410222222222\r\nOK\r\n"),
                        "AT+CFUN?" => format!("{cmd}\r\r\n+CFUN: 1\r\nOK\r\n"),
                        "AT+QUIMSLOT?" => {
                            if fail_c.load(Ordering::SeqCst) {
                                format!("{cmd}\r\r\nERROR\r\n")
                            } else {
                                format!("{cmd}\r\r\n+QUIMSLOT: 2\r\nOK\r\n")
                            }
                        }
                        _ => format!("{cmd}\r\r\nOK\r\n"),
                    };
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });

        use std::os::unix::io::IntoRawFd;
        let fd_opt = std::sync::Mutex::new(Some(a.into_raw_fd()));
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_opt.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, smd);

                // Poll 1: establishes SIM slot 2 and caches ICCID/IMSI.
                refresh_modem_snapshot(&app, Priority::Telemetry, true).await;
                assert_eq!(app.modem.read().await.identity.sim_slot, 2);
                assert_eq!(app.last_sim_slot.load(Ordering::Acquire), 2);
                assert_eq!(app.secrets.read().await.iccid, "89014102222222222222");
                assert_eq!(app.sim_switched_at_ms.load(Ordering::Acquire), 0);

                // Poll 2: AT+QUIMSLOT? fails with ERROR -> must preserve slot 2 and NOT wipe ICCID or set sim_switched_at_ms!
                fail_slot.store(true, Ordering::SeqCst);
                refresh_modem_snapshot(&app, Priority::Telemetry, false).await;
                assert_eq!(app.modem.read().await.identity.sim_slot, 2);
                assert_eq!(app.last_sim_slot.load(Ordering::Acquire), 2);
                assert_eq!(app.secrets.read().await.iccid, "89014102222222222222");
                assert_eq!(app.sim_switched_at_ms.load(Ordering::Acquire), 0);
            })
            .await;
    }

    #[test]
    fn idle_mimo_stabilization_retains_rx2_rx3_only_during_same_cell_noconn() {
        let prev_cell = ServingCellInfo {
            state: "CONNECT".into(),
            rat: "NR5G-SA".into(),
            band: "n41".into(),
            pci: Some(42),
            arfcn: Some(521310),
            ..Default::default()
        };
        let prev_mimo = MimoSignalData {
            rsrp: vec![Some(-90.0), Some(-92.0), Some(-94.0), Some(-96.0)],
            rsrq: vec![Some(-10.0), Some(-11.0), Some(-12.0), Some(-13.0)],
            sinr: vec![Some(18.0), Some(17.0), Some(16.0), Some(15.0)],
            rat: "NR5G".into(),
        };

        // RRC Idle (NOCONN) on same cell with RX2/RX3 powered down (-140 -> None) retains chains 2 & 3.
        let mut idle_same = ServingCellInfo { state: "NOCONN".into(), ..prev_cell.clone() };
        let mut cur = MimoSignalData {
            rsrp: vec![Some(-91.0), Some(-93.0), None, None],
            rsrq: vec![Some(-10.0), Some(-11.0), None, None],
            sinr: vec![Some(17.0), Some(16.0), None, None],
            rat: "NR5G".into(),
        };
        stabilize_idle_mimo_chains(&mut cur, &prev_mimo, Some(&idle_same), Some(&prev_cell));
        assert_eq!(cur.rsrp, vec![Some(-91.0), Some(-93.0), Some(-94.0), Some(-96.0)]);
        assert_eq!(cur.sinr, vec![Some(17.0), Some(16.0), Some(16.0), Some(15.0)]);

        // Real chain drop while RRC CONNECT must NOT be masked.
        let mut cur_conn = MimoSignalData {
            rsrp: vec![Some(-91.0), Some(-93.0), None, None],
            rsrq: vec![Some(-10.0), Some(-11.0), None, None],
            sinr: vec![Some(17.0), Some(16.0), None, None],
            rat: "NR5G".into(),
        };
        stabilize_idle_mimo_chains(&mut cur_conn, &prev_mimo, Some(&prev_cell), Some(&prev_cell));
        assert_eq!(cur_conn.rsrp[2], None);
        assert_eq!(cur_conn.rsrp[3], None);

        // Handover to a different PCI in NOCONN must NOT carry over old cell's chains.
        idle_same.pci = Some(99);
        let mut cur_ho = MimoSignalData {
            rsrp: vec![Some(-91.0), Some(-93.0), None, None],
            rsrq: vec![None; 4],
            sinr: vec![None; 4],
            rat: "NR5G".into(),
        };
        stabilize_idle_mimo_chains(&mut cur_ho, &prev_mimo, Some(&idle_same), Some(&prev_cell));
        assert_eq!(cur_ho.rsrp[2], None);
        assert_eq!(cur_ho.rsrp[3], None);
    }

    #[test]
    fn failover_band_lock_escape_hatch_policy_and_timers() {
        // Pure restrictiveness predicate
        assert!(is_restrictive_band_or_mode("NR5G", &["41".into(), "71".into()]));
        assert!(is_restrictive_band_or_mode("LTE:NR5G", &["41".into(), "25".into()]));
        assert!(!is_restrictive_band_or_mode("AUTO", &["41".into(), "71".into()]));
        assert!(!is_restrictive_band_or_mode("LTE:NR5G", &[]));

        let t0 = Instant::now();
        let mut tr = BandLockEscapeTracker::default();

        // Standby unregistered must NEVER trigger escape
        assert_eq!(evaluate_band_escape(&mut tr, false, 1, false, t0), BandEscapeAction::None);
        assert_eq!(
            evaluate_band_escape(&mut tr, false, 1, false, t0 + Duration::from_secs(120)),
            BandEscapeAction::None
        );

        // Failover active + unregistered for < 45 s -> wait
        assert_eq!(evaluate_band_escape(&mut tr, true, 1, false, t0), BandEscapeAction::None);
        assert_eq!(
            evaluate_band_escape(&mut tr, true, 1, false, t0 + Duration::from_secs(44)),
            BandEscapeAction::None
        );
        // At 45 s -> ProbeAndEscape
        assert_eq!(
            evaluate_band_escape(&mut tr, true, 1, false, t0 + Duration::from_secs(45)),
            BandEscapeAction::ProbeAndEscape
        );

        // Simulate escape committed
        tr.saved_mode_pref = Some("NR5G".into());
        tr.unregistered_since = None;

        // Still in failover -> never restore yet
        let t1 = t0 + Duration::from_secs(50);
        assert_eq!(evaluate_band_escape(&mut tr, true, 1, true, t1), BandEscapeAction::None);
        assert_eq!(
            evaluate_band_escape(&mut tr, true, 1, true, t1 + Duration::from_secs(120)),
            BandEscapeAction::None
        );

        // Failover ended & registered healthy -> wait 60 s then Restore
        let t2 = t1 + Duration::from_secs(125);
        assert_eq!(evaluate_band_escape(&mut tr, false, 1, true, t2), BandEscapeAction::None);
        assert_eq!(
            evaluate_band_escape(&mut tr, false, 1, true, t2 + Duration::from_secs(59)),
            BandEscapeAction::None
        );
        assert_eq!(
            evaluate_band_escape(&mut tr, false, 1, true, t2 + Duration::from_secs(60)),
            BandEscapeAction::Restore
        );
    }
}

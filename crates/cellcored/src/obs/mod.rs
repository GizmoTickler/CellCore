//! Observability for the backup-WAN modem: Prometheus metrics, an event log,
//! failover awareness, billing-cycle usage and notifications.
//!
//! Ground rules:
//! - Everything here works from state the daemon already caches. Nothing in
//!   this module sends AT commands, except the opt-in SMS forwarder
//!   ([`notify::sms_forward_tick`]), which the UI labels as adding light AT
//!   traffic.
//! - Nothing here changes the radio or the link. Failover awareness only
//!   *defers* daemon-initiated disruptive work; Route10's recovery commands
//!   always run.
//! - State lives in one process-wide [`Obs`] (not in `AppState`) so this
//!   feature does not touch the shared state struct. Locks are std mutexes,
//!   never held across an `.await`.
//! - Flash writes are bounded: the event ring and counters are flushed hourly
//!   and on SIGTERM / reboot through the crash-safe [`atomic_write`] helper.
//!
//! [`atomic_write`]: crate::state::atomic_write

pub mod config;
pub mod events;
pub mod failover;
pub mod metrics;
pub mod notify;
pub mod usage_cycle;

mod api;

use std::{
    collections::VecDeque,
    sync::{
        LazyLock, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::{
    auth::now_secs,
    state::{
        AppState, ETC_QM_DIR, load_json_or_default, mono_ms, save_json_atomic,
        save_json_atomic_async, save_json_compact_atomic,
    },
};

pub use api::{metrics_routes, routes};
pub use events::{EventKind, Severity, emit};

pub const OBS_STATE_PATH: &str = "/etc/cellcore/obs_state.json";
pub const OBS_CONFIG_PATH: &str = "/etc/cellcore/observability.json";
pub const EVENTS_PATH: &str = "/etc/cellcore/events.json";
/// Periodic flush check interval (monotonic).
pub const FLUSH_INTERVAL_SECS: u64 = 3600;
/// Gate hourly `obs_state.json` flash writes on >= 10 MiB delta or >= 24h (eliminating standby NAND wear).
pub const OBS_FLUSH_MIN_BYTES: u64 = 10 * 1024 * 1024;
pub const OBS_FLUSH_MAX_INTERVAL_SECS: u64 = 24 * 3600;

/// Poison-tolerant lock: a panic is an abort in release builds, so a
/// poisoned mutex can only be seen in tests; never propagate it.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Counters and memos that survive restarts (`obs_state.json`, 0600).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct PersistedObs {
    pub lifetime_rx: u64,
    pub lifetime_tx: u64,
    /// Lifetime counters were seeded from the monthly history once.
    pub lifetime_seeded: bool,
    pub usage: usage_cycle::UsageMemo,
    pub failover_episodes: u64,
    pub episode: Option<failover::Episode>,
    pub last_ota_started_at: u64,
    pub last_version: String,
    /// Set on a clean SIGTERM; cleared at start. Absent at start = the last
    /// run ended without a clean shutdown (crash, power loss, hard reset).
    pub clean_shutdown: bool,
    /// Why the next start happens, recorded right before a requested reboot.
    pub pending_boot_reason: Option<String>,
    pub deferred_reboot_at: Option<u64>,
    pub sms_seen: VecDeque<String>,
    pub sms_seen_initialized: bool,
}

pub struct Obs {
    pub persisted: Mutex<PersistedObs>,
    pub state_dirty: AtomicBool,
    last_flushed: Mutex<Option<PersistedObs>>,
    last_state_flush_mono_ms: AtomicU64,
    pub config: Mutex<config::ObsConfig>,
    pub events: Mutex<events::EventStore>,
    pub detector: Mutex<events::SnapshotDetector>,
    pub failover: Mutex<failover::FailoverRuntime>,
    pub notify: Mutex<notify::NotifyRuntime>,
    ws: OnceLock<broadcast::Sender<axum::extract::ws::Utf8Bytes>>,
    notify_tx: OnceLock<mpsc::Sender<events::Event>>,
}

static OBS: LazyLock<Obs> = LazyLock::new(|| Obs {
    persisted: Mutex::new(PersistedObs::default()),
    state_dirty: AtomicBool::new(false),
    last_flushed: Mutex::new(None),
    last_state_flush_mono_ms: AtomicU64::new(0),
    config: Mutex::new(config::ObsConfig::default()),
    events: Mutex::new(events::EventStore::default()),
    detector: Mutex::new(events::SnapshotDetector::default()),
    failover: Mutex::new(failover::FailoverRuntime::default()),
    notify: Mutex::new(notify::NotifyRuntime::default()),
    ws: OnceLock::new(),
    notify_tx: OnceLock::new(),
});

pub fn obs() -> &'static Obs {
    &OBS
}

impl Obs {
    pub fn mark_state_dirty(&self) {
        self.state_dirty.store(true, Ordering::Relaxed);
    }

    pub fn take_state_dirty(&self) -> bool {
        self.state_dirty.swap(false, Ordering::Relaxed)
    }

    pub fn has_ws_clients(&self) -> bool {
        self.ws.get().is_some_and(|tx| tx.receiver_count() > 0)
    }

    fn broadcast(&self, value: &serde_json::Value) {
        if let Some(tx) = self.ws.get()
            && tx.receiver_count() > 0
            && let Ok(text) = serde_json::to_string(value)
        {
            let _ = tx.send(axum::extract::ws::Utf8Bytes::from(text));
        }
    }
}

/// Why this start happened, from what the previous run left behind.
pub fn boot_reason(prev: &PersistedObs, device_uptime_secs: u64, first_run: bool) -> String {
    if let Some(r) = prev.pending_boot_reason.as_deref().filter(|r| !r.is_empty()) {
        return r.to_string();
    }
    if first_run {
        return "first start".into();
    }
    let system_boot = device_uptime_secs < 300;
    match (system_boot, prev.clean_shutdown) {
        (true, true) => "system boot after a clean shutdown".into(),
        (true, false) => "system boot without a clean shutdown (power loss or hard reset)".into(),
        (false, true) => "daemon restart".into(),
        (false, false) => "daemon restart after a crash".into(),
    }
}

/// Load persisted state, record the daemon start, spawn the background
/// tasks. Called once from `main` after `AppState` exists.
pub fn start(state: &AppState) {
    let _ = std::fs::create_dir_all(crate::paths::p(ETC_QM_DIR));
    let first_run = !std::path::Path::new(&crate::paths::p(OBS_STATE_PATH)).exists();
    let mut prev: PersistedObs = load_json_or_default(OBS_STATE_PATH);
    let disk_baseline = (!first_run).then(|| prev.clone());
    *lock(&OBS.config) = load_json_or_default(OBS_CONFIG_PATH);
    {
        let stored: events::StoredEvents = load_json_or_default(EVENTS_PATH);
        lock(&OBS.events).restore(stored);
    }
    let _ = OBS.ws.set(state.ws_tx.clone());
    let (ntx, nrx) = mpsc::channel(notify::QUEUE_CAP);
    let _ = OBS.notify_tx.set(ntx);

    let reason = boot_reason(&prev, crate::ipc::read_proc_uptime_secs(), first_run);
    let version_change = (!prev.last_version.is_empty() && prev.last_version != state.version)
        .then(|| prev.last_version.clone());
    prev.pending_boot_reason = None;
    prev.clean_shutdown = false;
    prev.last_version = state.version.clone();
    if let Some(ep) = prev.episode.as_ref() {
        // A restart in the middle of an episode: keep counting from here.
        lock(&OBS.failover).resume(ep.clone());
    }
    let dirty_at_start = disk_baseline.as_ref() != Some(&prev);
    *lock(&OBS.last_flushed) = disk_baseline;
    *lock(&OBS.persisted) = prev;
    OBS.state_dirty.store(dirty_at_start, Ordering::Relaxed);
    OBS.last_state_flush_mono_ms
        .store(mono_ms(), Ordering::Release);

    emit(
        EventKind::DaemonStart,
        Severity::Info,
        format!("cellcored {} started", state.version),
        serde_json::json!({ "reason": reason, "version": state.version }),
    );
    if let Some(from) = version_change {
        emit(
            EventKind::OtaInstall,
            Severity::Info,
            format!("Updated {from} → {}", state.version),
            serde_json::json!({ "from": from, "to": state.version, "state": "succeeded" }),
        );
    }

    tokio::spawn(notify::run_notifier(nrx));
    tokio::spawn(run_obs_loop(state.clone()));
}

/// Immediate flush to flash (SIGTERM / reboot / tests).
/// Skips NAND writes for `/etc/cellcore/obs_state.json` when unchanged (`!state_dirty`).
pub fn flush_now(clean_shutdown: bool) {
    flush_impl(true, clean_shutdown, mono_ms());
}

/// Hourly periodic flush: gates `obs_state.json` flash writes on `state_dirty`
/// (episode/OTA/boot_reason), `>= 10 MiB` traffic delta, or `>= 24h` elapsed,
/// eliminating 8,760 standby writes/year on UBIFS flash.
pub fn flush_periodic() {
    flush_impl(false, false, mono_ms());
}

fn flush_impl(force: bool, clean_shutdown: bool, now_mono_ms: u64) {
    let snapshot = {
        let mut ev = lock(&OBS.events);
        let dirty = ev.take_dirty();
        dirty.then(|| ev.to_stored())
    };
    if let Some(stored) = snapshot {
        let _ = save_json_compact_atomic(EVENTS_PATH, &stored, 0o600);
    }
    let maybe_state = {
        let mut p = lock(&OBS.persisted);
        if clean_shutdown && !p.clean_shutdown {
            p.clean_shutdown = true;
            OBS.mark_state_dirty();
        }
        let cur_ep = lock(&OBS.failover).episode.clone();
        if p.episode != cur_ep {
            p.episode = cur_ep;
            OBS.mark_state_dirty();
        }
        let mut last = lock(&OBS.last_flushed);
        let changed = last.as_ref() != Some(&*p);
        let flagged = OBS.state_dirty.load(Ordering::Relaxed);
        if !changed && !flagged {
            None
        } else {
            let byte_delta = match last.as_ref() {
                Some(prev) => p
                    .lifetime_rx
                    .saturating_add(p.lifetime_tx)
                    .saturating_sub(prev.lifetime_rx.saturating_add(prev.lifetime_tx)),
                None => OBS_FLUSH_MIN_BYTES,
            };
            let last_ms = OBS.last_state_flush_mono_ms.load(Ordering::Acquire);
            let elapsed_secs = if last_ms == 0 {
                OBS_FLUSH_MAX_INTERVAL_SECS
            } else {
                now_mono_ms.saturating_sub(last_ms) / 1000
            };
            let should_write = force
                || clean_shutdown
                || flagged
                || byte_delta >= OBS_FLUSH_MIN_BYTES
                || elapsed_secs >= OBS_FLUSH_MAX_INTERVAL_SECS;
            if should_write {
                OBS.take_state_dirty();
                let cloned = p.clone();
                *last = Some(cloned.clone());
                Some(cloned)
            } else {
                None
            }
        }
    };
    if let Some(p) = maybe_state
        && save_json_compact_atomic(OBS_STATE_PATH, &p, 0o600).is_ok()
    {
        OBS.last_state_flush_mono_ms
            .store(now_mono_ms, Ordering::Release);
    }
}

/// Record why the coming reboot happens; the reboot paths flush right after
/// (`telemetry::flush_persistent_state`), and the next start reports it.
pub fn set_boot_reason(reason: &str) {
    lock(&OBS.persisted).pending_boot_reason = Some(reason.to_string());
    OBS.mark_state_dirty();
}

#[allow(dead_code)]
pub fn save_config() -> Result<(), String> {
    let cfg = lock(&OBS.config).clone();
    save_json_atomic(OBS_CONFIG_PATH, &cfg, 0o600)
}

pub async fn save_config_async() -> Result<(), String> {
    let cfg = lock(&OBS.config).clone();
    save_json_atomic_async(OBS_CONFIG_PATH, cfg, 0o600).await
}

async fn run_obs_loop(state: AppState) {
    let mut tick: u64 = 0;
    let mut last_flush_ms = mono_ms();
    let mut last_sms_ms = 0u64;
    let mut usage_probe = usage_cycle::DeltaProbe::default();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        tick = tick.wrapping_add(1);
        let now = now_secs();
        let now_m = mono_ms();

        // 1 s: byte deltas + failover state machine
        let (iface, rx, tx, bps) = {
            let tr = state.traffic.read().await;
            let p = tr.interfaces.iter().find(|i| i.name == tr.primary_iface);
            match p {
                Some(p) => (p.name.clone(), p.rx.bytes_total, p.tx.bytes_total, p.rx.bps.saturating_add(p.tx.bps)),
                None => (String::new(), 0, 0, 0),
            }
        };
        let (drx, dtx) = if iface.is_empty() { (0, 0) } else { usage_probe.observe(&iface, rx, tx) };
        let st_active = crate::speedtest::is_self_traffic_active();
        failover::on_tick_with_self_traffic(now, bps, drx.saturating_add(dtx), st_active);
        usage_cycle::on_bytes(drx, dtx, failover::is_active() || st_active);

        if tick.is_multiple_of(15) {
            failover::broadcast_status();
        }
        if tick.is_multiple_of(30) {
            let usage = state.data_usage.read().await.clone();
            usage_cycle::check_alerts(&usage, now);
        }
        if tick.is_multiple_of(60) {
            failover::check_deferred_reboot(&state, now).await;
            events::check_ota_status();
        }
        let sms = lock(&OBS.config).notify.sms_forward.clone();
        if sms.enabled
            && (last_sms_ms == 0
                || now_m.saturating_sub(last_sms_ms)
                    >= sms.interval_secs.max(notify::SMS_MIN_INTERVAL_SECS) * 1000)
        {
            last_sms_ms = now_m;
            notify::sms_forward_tick(&state).await;
        }
        if now_m.saturating_sub(last_flush_ms) >= FLUSH_INTERVAL_SECS * 1000 {
            last_flush_ms = now_m;
            tokio::task::spawn_blocking(flush_periodic);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_reasons() {
        let mut p = PersistedObs::default();
        assert_eq!(boot_reason(&p, 50, true), "first start");
        assert!(boot_reason(&p, 50, false).contains("without a clean shutdown"));
        assert_eq!(boot_reason(&p, 5000, false), "daemon restart after a crash");
        p.clean_shutdown = true;
        assert_eq!(boot_reason(&p, 5000, false), "daemon restart");
        assert!(boot_reason(&p, 20, false).contains("after a clean shutdown"));
        p.pending_boot_reason = Some("reboot requested via IPC".into());
        assert_eq!(boot_reason(&p, 20, false), "reboot requested via IPC");
    }

    #[test]
    fn persisted_state_tolerates_old_files() {
        let p: PersistedObs = serde_json::from_str(r#"{"lifetimeRx":5}"#).unwrap();
        assert_eq!(p.lifetime_rx, 5);
        assert!(!p.clean_shutdown);
        assert!(p.episode.is_none());
    }

    #[test]
    fn flush_now_skips_nand_write_when_state_not_dirty() {
        let env = crate::paths::TestSandbox::new("obs-dirty-flush");
        env.write("/etc/cellcore/.keep", "");
        let state_file = env.root.join("etc/cellcore/obs_state.json");

        {
            let mut p = lock(&OBS.persisted);
            *p = PersistedObs::default();
            p.lifetime_rx = 42;
            *lock(&OBS.last_flushed) = None;
            OBS.mark_state_dirty();
        }
        flush_now(false);
        assert!(state_file.exists(), "first dirty flush must write obs_state.json");

        // Remove file without mutating state: an idle hourly flush must NOT rewrite NAND.
        std::fs::remove_file(&state_file).unwrap();
        flush_now(false);
        assert!(!state_file.exists(), "unchanged state must not write obs_state.json");

        // Marking state dirty via set_boot_reason writes again.
        set_boot_reason("manual reboot");
        flush_now(false);
        assert!(state_file.exists(), "dirty state must write obs_state.json");
    }
}

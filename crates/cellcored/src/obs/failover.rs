//! Failover awareness: is the modem carrying production traffic right now?
//!
//! Two inputs: an explicit hint from Route10 (`r10-modem-ctl role
//! active|standby`), which wins while fresh, and sustained rmnet throughput
//! above a configurable baseline. While active, daemon-initiated disruptive
//! work is deferred and user-initiated disruptive API calls need
//! `force: true`. Route10's own recovery commands are never gated.

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{
    config::FailoverConfig,
    events::{EventKind, Severity, emit, work_deferred},
    lock, obs,
};
use crate::{auth::now_secs, state::AppState};

/// Samples (1 s each) averaged before comparing with the baseline.
pub const AVG_WINDOW: usize = 10;
/// A deferred scheduled reboot runs once the link has been standby this long ...
pub const DEFERRED_REBOOT_QUIET_SECS: u64 = 600;
/// ... and is dropped if that does not happen within this long.
pub const DEFERRED_REBOOT_MAX_AGE_SECS: u64 = 6 * 3600;
const GUARD_MAX_BODY: usize = 64 * 1024;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Cheap check for the deferral points (scheduler, LinkWatch, profiles).
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Active,
    Standby,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s.trim() {
            "active" => Some(Role::Active),
            "standby" => Some(Role::Standby),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Active => "active",
            Role::Standby => "standby",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Hint,
    Throughput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Episode {
    pub started_at: u64,
    pub bytes: u64,
    pub source: Source,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EpisodeSummary {
    pub started_at: u64,
    pub ended_at: u64,
    pub duration_secs: u64,
    pub bytes: u64,
    pub source: Source,
}

/// Throughput side of the decision, with hysteresis: on after the average
/// has stayed >= baseline for `sustain_secs`, off after it has stayed below
/// half the baseline for `release_secs`.
/// Uses monotonic `Instant` so NTP clock jumps never trigger false failover episodes.
#[derive(Debug, Default, Clone)]
pub struct ThroughputDetector {
    window: VecDeque<u64>,
    above_since: Option<Instant>,
    below_since: Option<Instant>,
    pub active: bool,
    pub avg_bps: u64,
}

impl ThroughputDetector {
    pub fn tick(&mut self, mono_now: Instant, bps: u64, cfg: &FailoverConfig) -> bool {
        if self.window.len() >= AVG_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(bps);
        self.avg_bps = self.window.iter().sum::<u64>() / self.window.len() as u64;
        let base = cfg.baseline_bps.max(1);
        if self.avg_bps >= base {
            self.above_since.get_or_insert(mono_now);
            self.below_since = None;
        } else if self.avg_bps < base / 2 {
            self.below_since.get_or_insert(mono_now);
            self.above_since = None;
        } else {
            // Between half and full baseline: hold the current state.
            self.above_since = None;
            self.below_since = None;
        }
        if !self.active
            && self
                .above_since
                .is_some_and(|t| mono_now.saturating_duration_since(t) >= Duration::from_secs(cfg.sustain_secs))
        {
            self.active = true;
        } else if self.active
            && self
                .below_since
                .is_some_and(|t| mono_now.saturating_duration_since(t) >= Duration::from_secs(cfg.release_secs))
        {
            self.active = false;
        }
        self.active
    }
}

/// Combine the hint and the throughput detector. A fresh hint (monotonic TTL) wins.
pub fn decide(
    hint: Option<(Role, Instant)>,
    throughput_active: bool,
    mono_now: Instant,
    cfg: &FailoverConfig,
) -> (bool, Option<Source>) {
    if let Some((role, at)) = hint
        && mono_now.saturating_duration_since(at) <= Duration::from_secs(cfg.hint_ttl_secs)
    {
        return (role == Role::Active, Some(Source::Hint));
    }
    if cfg.throughput_detect && throughput_active {
        return (true, Some(Source::Throughput));
    }
    (false, None)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    Started(Episode),
    Ended(EpisodeSummary),
}

#[derive(Debug, Default)]
pub struct FailoverRuntime {
    pub throughput: ThroughputDetector,
    pub active: bool,
    pub source: Option<Source>,
    /// When the current state (active or standby) began (unix seconds).
    pub since: u64,
    /// Monotonic timestamp (`mono_ms()`) when the current state began.
    pub since_mono_ms: u64,
    pub hint: Option<(Role, Instant)>,
    pub episode: Option<Episode>,
    pub(crate) episode_started_mono: Option<Instant>,
    pub last_episode: Option<EpisodeSummary>,
    /// Monotonic timestamp (`mono_ms()`) when a scheduled reboot was deferred.
    pub deferred_reboot_mono_ms: Option<u64>,
    /// Work already reported as deferred in this episode (one event each).
    pub deferred_noted: Vec<&'static str>,
}

impl FailoverRuntime {
    /// Monotonic elapsed seconds of the current episode (falling back to wall clock only on resumed episodes).
    pub fn episode_elapsed_secs(&self, now_wall: u64) -> u64 {
        if let Some(mono) = self.episode_started_mono {
            mono.elapsed().as_secs()
        } else {
            self.episode
                .as_ref()
                .map(|e| now_wall.saturating_sub(e.started_at))
                .unwrap_or(0)
        }
    }

    /// Continue an episode that was running when the daemon restarted. The
    /// throughput side starts "on", so the episode ends only after
    /// `release_secs` of low traffic (or a standby hint), not on the first tick.
    pub fn resume(&mut self, ep: Episode) {
        self.active = true;
        self.throughput.active = true;
        self.source = Some(ep.source);
        self.since = ep.started_at;
        self.since_mono_ms = crate::state::mono_ms();
        self.episode = Some(ep);
        self.episode_started_mono = None;
        ACTIVE.store(true, Ordering::Relaxed);
    }

    /// One second of input. Pure apart from the struct itself.
    pub fn tick(
        &mut self,
        now: u64,
        mono_now: Instant,
        bps: u64,
        bytes: u64,
        cfg: &FailoverConfig,
    ) -> Option<Transition> {
        let tp = self.throughput.tick(mono_now, bps, cfg);
        self.apply_decision(tp, now, mono_now, bytes, cfg)
    }

    pub fn apply_decision(
        &mut self,
        tp: bool,
        now: u64,
        mono_now: Instant,
        bytes: u64,
        cfg: &FailoverConfig,
    ) -> Option<Transition> {
        let (want, source) = decide(self.hint, tp, mono_now, cfg);
        if let Some(ep) = self.episode.as_mut() {
            ep.bytes = ep.bytes.saturating_add(bytes);
        }
        if want == self.active {
            if want {
                self.source = source;
            }
            return None;
        }
        self.active = want;
        let prev_since = std::mem::replace(&mut self.since, now);
        self.since_mono_ms = crate::state::mono_ms();
        self.deferred_noted.clear();
        if want {
            let ep = Episode { started_at: now, bytes: 0, source: source.unwrap_or(Source::Throughput) };
            self.source = source;
            self.episode = Some(ep.clone());
            self.episode_started_mono = Some(mono_now);
            Some(Transition::Started(ep))
        } else {
            self.source = None;
            let ep = self.episode.take().unwrap_or(Episode {
                started_at: prev_since,
                bytes: 0,
                source: Source::Throughput,
            });
            let duration_secs = self
                .episode_started_mono
                .take()
                .map(|t| mono_now.saturating_duration_since(t).as_secs())
                .unwrap_or_else(|| now.saturating_sub(ep.started_at));
            let sum = EpisodeSummary {
                started_at: ep.started_at,
                ended_at: now,
                duration_secs,
                bytes: ep.bytes,
                source: ep.source,
            };
            self.last_episode = Some(sum.clone());
            Some(Transition::Ended(sum))
        }
    }
}

pub fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", U[i]) }
}

pub fn human_secs(s: u64) -> String {
    crate::telemetry::format_duration_hms(s)
}

fn emit_transition(tr: Transition) {
    match tr {
        Transition::Started(ep) => {
            lock(&obs().persisted).failover_episodes += 1;
            obs().mark_state_dirty();
            emit(
                EventKind::FailoverStart,
                Severity::Warning,
                match ep.source {
                    Source::Hint => "Carrying failover traffic (router hint)".to_string(),
                    Source::Throughput => "Carrying failover traffic (sustained throughput)".to_string(),
                },
                serde_json::json!({ "source": ep.source, "startedAt": ep.started_at }),
            );
        }
        Transition::Ended(sum) => {
            obs().mark_state_dirty();
            emit(
                EventKind::FailoverEnd,
                Severity::Info,
                format!(
                    "Failover ended after {} ({})",
                    human_secs(sum.duration_secs),
                    human_bytes(sum.bytes)
                ),
                serde_json::to_value(&sum).unwrap_or_default(),
            );
        }
    }
    broadcast_status();
}

/// Called every second by the obs loop.
pub fn on_tick(now: u64, bps: u64, bytes: u64) {
    let mono_now = Instant::now();
    let cfg = lock(&obs().config).failover.clone();
    let tr = {
        let mut f = lock(&obs().failover);
        let tr = f.tick(now, mono_now, bps, bytes, &cfg);
        ACTIVE.store(f.active, Ordering::Relaxed);
        tr
    };
    if let Some(tr) = tr {
        emit_transition(tr);
    }
}

/// `r10-modem-ctl role active|standby` (IPC).
pub fn set_hint(role: Role) -> String {
    let now = now_secs();
    let mono_now = Instant::now();
    let cfg = lock(&obs().config).failover.clone();
    let tr = {
        let mut f = lock(&obs().failover);
        f.hint = Some((role, mono_now));
        let tp = f.throughput.active;
        let tr = f.apply_decision(tp, now, mono_now, 0, &cfg);
        ACTIVE.store(f.active, Ordering::Relaxed);
        tr
    };
    if let Some(tr) = tr {
        emit_transition(tr);
    } else {
        broadcast_status();
    }
    format!("result=ok role={} ttl_s={}\n", role.as_str(), cfg.hint_ttl_secs)
}

pub fn status_json() -> serde_json::Value {
    let cfg = lock(&obs().config).failover.clone();
    let episodes = lock(&obs().persisted).failover_episodes;
    let f = lock(&obs().failover);
    let mono_now = Instant::now();
    let hint = f.hint.map(|(r, at)| {
        let age = mono_now.saturating_duration_since(at).as_secs();
        serde_json::json!({
            "role": r,
            "ageSecs": age,
            "fresh": age <= cfg.hint_ttl_secs,
        })
    });
    serde_json::json!({
        "active": f.active,
        "source": f.source,
        "since": f.since,
        "avgBps": f.throughput.avg_bps,
        "baselineBps": cfg.baseline_bps,
        "throughputActive": f.throughput.active,
        "hint": hint,
        "episode": f.episode,
        "lastEpisode": f.last_episode,
        "episodesTotal": episodes,
        "config": cfg,
    })
}

pub fn broadcast_status() {
    if !obs().has_ws_clients() {
        return;
    }
    obs().broadcast(&serde_json::json!({ "channel": "failover", "failover": status_json() }));
}

/// Record deferred periodic work once per episode (the scheduler ticks
/// every minute; one event per kind of work is enough).
pub fn note_deferred(what: &'static str) {
    let first = {
        let mut f = lock(&obs().failover);
        let first = !f.deferred_noted.contains(&what);
        if first {
            f.deferred_noted.push(what);
        }
        first
    };
    if first {
        work_deferred(what, "carrying failover traffic");
    }
}

/// Scheduled reboot hit its minute while carrying traffic: remember it.
pub fn defer_scheduled_reboot(now: u64) {
    let first = {
        let mut p = lock(&obs().persisted);
        let first = p.deferred_reboot_at.is_none();
        if first {
            p.deferred_reboot_at = Some(now);
            obs().mark_state_dirty();
        }
        first
    };
    if first {
        lock(&obs().failover).deferred_reboot_mono_ms = Some(crate::state::mono_ms());
        work_deferred("scheduled reboot", "runs after 10 min back in standby, or is dropped after 6 h");
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeferredReboot {
    Wait,
    Run,
    Drop,
}

pub fn deferred_reboot_action(deferred_at: u64, now: u64, active: bool, standby_since: u64) -> DeferredReboot {
    if now.saturating_sub(deferred_at) > DEFERRED_REBOOT_MAX_AGE_SECS {
        return DeferredReboot::Drop;
    }
    if !active && now.saturating_sub(standby_since) >= DEFERRED_REBOOT_QUIET_SECS {
        return DeferredReboot::Run;
    }
    DeferredReboot::Wait
}

pub async fn check_deferred_reboot(state: &AppState, now: u64) {
    let Some(at) = lock(&obs().persisted).deferred_reboot_at else {
        return;
    };
    let mono_now_s = crate::state::mono_ms() / 1000;
    let (active, since_mono_s, deferred_mono_s) = {
        let mut f = lock(&obs().failover);
        let def_ms = *f.deferred_reboot_mono_ms.get_or_insert_with(crate::state::mono_ms);
        let s_ms = if f.since_mono_ms == 0 {
            f.since_mono_ms = crate::state::mono_ms();
            f.since_mono_ms
        } else {
            f.since_mono_ms
        };
        (f.active, s_ms / 1000, def_ms / 1000)
    };
    let _ = now;
    match deferred_reboot_action(deferred_mono_s, mono_now_s, active, since_mono_s) {
        DeferredReboot::Wait => {}
        DeferredReboot::Drop => {
            lock(&obs().persisted).deferred_reboot_at = None;
            lock(&obs().failover).deferred_reboot_mono_ms = None;
            obs().mark_state_dirty();
            emit(
                EventKind::ScheduledReboot,
                Severity::Warning,
                "Deferred scheduled reboot dropped (link stayed busy for 6 h)",
                serde_json::json!({ "deferredAt": at, "ran": false }),
            );
        }
        DeferredReboot::Run => {
            lock(&obs().persisted).deferred_reboot_at = None;
            lock(&obs().failover).deferred_reboot_mono_ms = None;
            obs().mark_state_dirty();
            emit(
                EventKind::ScheduledReboot,
                Severity::Info,
                "Running deferred scheduled reboot",
                serde_json::json!({ "deferredAt": at, "ran": true }),
            );
            state.push_daemon_log("Running deferred scheduled reboot (link back in standby)");
            super::set_boot_reason("deferred scheduled reboot");
            crate::telemetry::flush_persistent_state(state).await;
            let _ = crate::uci::run_cmd("sync", &[], Duration::from_secs(3)).await;
            let _ = crate::uci::run_cmd("/sbin/reboot", &[], Duration::from_secs(3)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// API guard for user-initiated disruptive actions
// ---------------------------------------------------------------------------

/// The user-initiated actions that can interrupt traffic. OTA only for the
/// "upgrade" action (checked against the body).
pub fn disruptive_action(method: &Method, path: &str) -> Option<&'static str> {
    let m = method.as_str();
    match (m, path) {
        ("POST", "/api/v1/cellular/scan") => Some("cell scan (QSCAN)"),
        ("POST", "/api/v1/system/ota") => Some("OTA upgrade"),
        ("POST", "/api/v1/system/firmware-ab/switch") => Some("A/B slot switch"),
        ("POST", "/api/v1/system/firmware-ab/flash") => Some("A/B firmware flash & reboot"),
        ("POST", "/api/v1/speedtest/start") => Some("speedtest"),
        ("POST", "/api/v1/cellular/bands") => Some("band lock"),
        ("POST", "/api/v1/cellular/mode") => Some("network mode change"),
        ("POST" | "DELETE", "/api/v1/cellular/cell-lock") => Some("cell lock"),
        ("POST", "/api/v1/cellular/tuning") => Some("radio tuning"),
        ("POST", "/api/v1/cellular/mbn") => Some("MBN change"),
        ("POST", "/api/v1/admin/software/self-upgrade") => Some("CellCore self-upgrade"),
        ("POST", "/api/v1/system/reboot") => Some("reboot"),
        ("POST", "/api/v1/vpn/warp/policy") => Some("WARP routing change"),
        ("POST", "/api/v1/vpn/warp/connection") => Some("WARP tunnel up/down"),
        ("POST", "/api/v1/vpn/warp/remove") => Some("WARP removal"),
        ("POST", "/api/v1/vpn/tailscale/settings") => Some("Tailscale exit node change"),
        ("POST", "/api/v1/dataplane/config") => Some("dataplane config change"),
        ("POST", "/api/v1/dataplane/reconnect") => Some("dataplane reconnect"),
        ("POST", "/api/v1/network/lan") => Some("network/LAN change"),
        ("POST", "/api/v1/modem/at") => Some("raw AT command"),
        _ => None,
    }
}

fn query_force(query: Option<&str>) -> bool {
    query.is_some_and(|q| {
        q.split('&').any(|kv| matches!(kv, "force=true" | "force=1"))
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum GuardVerdict {
    Pass,
    Forced,
    Block,
}

/// Pure decision for the guard. `body` is the parsed JSON body (or Null).
pub fn guard_verdict(active: bool, action: Option<&str>, path: &str, body: &serde_json::Value, query: Option<&str>) -> GuardVerdict {
    let Some(_) = action.filter(|_| active) else {
        return GuardVerdict::Pass;
    };
    if path == "/api/v1/system/ota" && body.get("action").and_then(|a| a.as_str()) != Some("upgrade") {
        return GuardVerdict::Pass;
    }
    // Flashing the inactive A/B slot without rebooting (or dry-run) does not interrupt active traffic.
    if path == "/api/v1/system/firmware-ab/flash"
        && (body.get("dryRun").and_then(|v| v.as_bool()) == Some(true)
            || body.get("reboot").and_then(|v| v.as_bool()) != Some(true))
    {
        return GuardVerdict::Pass;
    }
    // Only the exit node moves traffic among the Tailscale settings.
    if path == "/api/v1/vpn/tailscale/settings" && body.get("exitNode").is_none() {
        return GuardVerdict::Pass;
    }
    // Changing the lock *schedule* settings does not touch the radio.
    if path == "/api/v1/cellular/cell-lock" && body.get("scheduleEnabled").is_some() && body.get("rat").is_none() {
        return GuardVerdict::Pass;
    }
    if body.get("force").and_then(|f| f.as_bool()) == Some(true) || query_force(query) {
        GuardVerdict::Forced
    } else {
        GuardVerdict::Block
    }
}

/// Route layer on the protected router (inside auth): while carrying
/// failover traffic, disruptive calls need `force: true` (body) or
/// `?force=true`. Everything else passes untouched and unbuffered.
pub async fn guard_middleware(req: Request, next: Next) -> Response {
    let action = disruptive_action(req.method(), req.uri().path());
    if action.is_none() || !is_active() {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, GUARD_MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "status": "error", "error": "Request body too large" })),
            )
                .into_response();
        }
    };
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    match guard_verdict(true, action, &path, &json, query.as_deref()) {
        GuardVerdict::Pass => {}
        GuardVerdict::Forced => {
            let what = action.unwrap_or("action");
            emit(
                EventKind::ForcedAction,
                Severity::Warning,
                format!("{what} forced while carrying failover traffic"),
                serde_json::json!({ "action": what, "path": path }),
            );
        }
        GuardVerdict::Block => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "status": "error",
                    "code": "failover_active",
                    "error": format!(
                        "The modem is carrying failover traffic; {} would interrupt it. Resend with force:true to proceed.",
                        action.unwrap_or("this action")
                    ),
                    "failover": status_json(),
                })),
            )
                .into_response();
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FailoverConfig {
        FailoverConfig { throughput_detect: true, baseline_bps: 1000, sustain_secs: 30, release_secs: 60, hint_ttl_secs: 180 }
    }

    #[test]
    fn throughput_needs_sustain_and_releases_with_hysteresis() {
        let c = cfg();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut d = ThroughputDetector::default();
        // a 5 s burst does not count
        for t in 0..5 {
            assert!(!d.tick(at(t), 50_000, &c));
        }
        for t in 5..30 {
            d.tick(at(t), 0, &c);
        }
        assert!(!d.active);
        let mut went_active = None;
        for t in 100..200 {
            if d.tick(at(t), 5000, &c) && went_active.is_none() {
                went_active = Some(t);
            }
        }
        // the 10 s mean reaches the baseline at t=101; active 30 s later
        assert_eq!(went_active, Some(131));
        // between half and full baseline: holds
        for t in 200..400 {
            assert!(d.tick(at(t), 700, &c), "hysteresis band holds active at {t}");
        }
        // below half: releases after release_secs (+ window drain)
        let mut released = None;
        for t in 400..600 {
            if !d.tick(at(t), 0, &c) && released.is_none() {
                released = Some(t);
            }
        }
        let r = released.expect("released");
        assert!((460..=470).contains(&r), "released at {r}");
    }

    #[test]
    fn fresh_hint_wins_then_expires_on_monotonic_instant() {
        let c = cfg();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(decide(Some((Role::Standby, at(100))), true, at(150), &c), (false, Some(Source::Hint)));
        assert_eq!(decide(Some((Role::Active, at(100))), false, at(280), &c), (true, Some(Source::Hint)));
        assert_eq!(decide(Some((Role::Active, at(100))), false, at(281), &c), (false, None), "stale hint ignored");
        assert_eq!(decide(Some((Role::Standby, at(100))), true, at(281), &c), (true, Some(Source::Throughput)));
        let mut off = c.clone();
        off.throughput_detect = false;
        assert_eq!(decide(None, true, at(0), &off), (false, None));
    }

    #[test]
    fn ntp_wall_clock_jump_does_not_trigger_false_failover_or_expire_hint() {
        let c = cfg();
        let t0 = Instant::now();
        let mut f = FailoverRuntime {
            hint: Some((Role::Standby, t0)),
            ..Default::default()
        };
        // Standby hint arrives before NTP sync (unix epoch = 120), plus a 1 s traffic spike.
        assert_eq!(f.tick(120, t0, 50_000, 5000, &c), None);
        assert!(!f.active);

        // NTP jumps wall clock by +1.79 billion seconds 1 monotonic second later!
        let ntp_now = 1_795_200_000;
        assert_eq!(f.tick(ntp_now, t0 + Duration::from_secs(1), 50_000, 5000, &c), None);
        assert!(!f.active, "NTP jump must not expire fresh standby hint or satisfy sustain_secs");

        // Even without a hint, a 1 s burst across an NTP wall-clock jump must NOT trigger sustain!
        let mut f2 = FailoverRuntime::default();
        assert_eq!(f2.tick(100, t0, 50_000, 1000, &c), None);
        assert_eq!(f2.tick(ntp_now, t0 + Duration::from_secs(1), 50_000, 1000, &c), None);
        assert!(!f2.active, "ThroughputDetector must use monotonic Instant");
    }

    #[test]
    fn episodes_record_duration_and_bytes() {
        let c = cfg();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut f = FailoverRuntime::default();
        assert_eq!(f.tick(1, at(1), 0, 0, &c), None);
        f.hint = Some((Role::Active, at(10)));
        let Some(Transition::Started(ep)) = f.tick(10, at(10), 0, 0, &c) else { panic!("start") };
        assert_eq!(ep.source, Source::Hint);
        for t in 11..=70 {
            assert_eq!(f.tick(t, at(t), 0, 1000, &c), None);
        }
        f.hint = Some((Role::Standby, at(71)));
        let Some(Transition::Ended(sum)) = f.tick(71, at(71), 0, 500, &c) else { panic!("end") };
        assert_eq!(sum.duration_secs, 61);
        assert_eq!(sum.bytes, 60 * 1000 + 500);
        assert!(!f.active);
        assert_eq!(f.last_episode.as_ref(), Some(&sum));
    }

    #[test]
    fn deferred_reboot_waits_for_quiet_standby_and_expires() {
        assert_eq!(deferred_reboot_action(1000, 1100, true, 0), DeferredReboot::Wait);
        assert_eq!(deferred_reboot_action(1000, 1500, false, 1200), DeferredReboot::Wait, "only 300 s standby");
        assert_eq!(deferred_reboot_action(1000, 1800, false, 1200), DeferredReboot::Run);
        assert_eq!(deferred_reboot_action(1000, 1000 + 6 * 3600 + 1, false, 0), DeferredReboot::Drop);
    }

    #[test]
    fn guard_blocks_disruptive_calls_only_while_active() {
        let null = serde_json::Value::Null;
        let scan = disruptive_action(&Method::POST, "/api/v1/cellular/scan");
        assert!(scan.is_some());
        let tuning = disruptive_action(&Method::POST, "/api/v1/cellular/tuning");
        assert_eq!(tuning, Some("radio tuning"));
        assert_eq!(guard_verdict(true, tuning, "/api/v1/cellular/tuning", &serde_json::json!({"nrCaEnabled":true}), None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, tuning, "/api/v1/cellular/tuning", &serde_json::json!({"nrCaEnabled":true,"force":true}), None), GuardVerdict::Forced);
        assert!(disruptive_action(&Method::GET, "/api/v1/cellular/tuning").is_none());
        assert_eq!(guard_verdict(false, scan, "/api/v1/cellular/scan", &null, None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, scan, "/api/v1/cellular/scan", &null, None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, scan, "/api/v1/cellular/scan", &null, Some("force=true")), GuardVerdict::Forced);
        let force = serde_json::json!({ "bands": "1:2", "force": true });
        let bands = disruptive_action(&Method::POST, "/api/v1/cellular/bands");
        assert_eq!(guard_verdict(true, bands, "/api/v1/cellular/bands", &force, None), GuardVerdict::Forced);
        let not_bool = serde_json::json!({ "force": "true" });
        assert_eq!(guard_verdict(true, bands, "/api/v1/cellular/bands", &not_bool, None), GuardVerdict::Block);
        // OTA check is harmless; only upgrade is gated
        let ota = disruptive_action(&Method::POST, "/api/v1/system/ota");
        let check = serde_json::json!({ "action": "check" });
        let up = serde_json::json!({ "action": "upgrade" });
        assert_eq!(guard_verdict(true, ota, "/api/v1/system/ota", &check, None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, ota, "/api/v1/system/ota", &up, None), GuardVerdict::Block);
        // A/B firmware switch is gated while active; flash is only gated when reboot:true and not dryRun
        let ab_sw = disruptive_action(&Method::POST, "/api/v1/system/firmware-ab/switch");
        assert!(ab_sw.is_some());
        assert_eq!(guard_verdict(true, ab_sw, "/api/v1/system/firmware-ab/switch", &serde_json::json!({"reboot":true}), None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, ab_sw, "/api/v1/system/firmware-ab/switch", &serde_json::json!({"reboot":true,"force":true}), None), GuardVerdict::Forced);
        let ab_fl = disruptive_action(&Method::POST, "/api/v1/system/firmware-ab/flash");
        assert!(ab_fl.is_some());
        assert_eq!(guard_verdict(true, ab_fl, "/api/v1/system/firmware-ab/flash", &serde_json::json!({"path":"/tmp/fw.zip","dryRun":true,"reboot":true}), None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, ab_fl, "/api/v1/system/firmware-ab/flash", &serde_json::json!({"path":"/tmp/fw.zip","activateSlot":false,"reboot":false}), None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, ab_fl, "/api/v1/system/firmware-ab/flash", &serde_json::json!({"path":"/tmp/fw.zip","activateSlot":true,"reboot":true}), None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, ab_fl, "/api/v1/system/firmware-ab/flash", &serde_json::json!({"path":"/tmp/fw.zip","activateSlot":true,"reboot":true,"force":true}), None), GuardVerdict::Forced);
        // reads and unrelated writes are never gated
        assert!(disruptive_action(&Method::GET, "/api/v1/cellular/scan").is_none());
        assert!(disruptive_action(&Method::POST, "/api/v1/modem/refresh").is_none());
        assert!(disruptive_action(&Method::DELETE, "/api/v1/cellular/cell-lock").is_some());
        let lock = disruptive_action(&Method::POST, "/api/v1/cellular/cell-lock");
        let sched = serde_json::json!({ "scheduleEnabled": true, "startTime": "08:00" });
        let pin = serde_json::json!({ "rat": "nr5g", "pci": 1 });
        assert_eq!(guard_verdict(true, lock, "/api/v1/cellular/cell-lock", &sched, None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, lock, "/api/v1/cellular/cell-lock", &pin, None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, lock, "/api/v1/cellular/cell-lock", &null, None), GuardVerdict::Block, "DELETE has no body");
        // VPN: routing changes are gated; Tailscale settings only for the exit node
        let pol = disruptive_action(&Method::POST, "/api/v1/vpn/warp/policy");
        assert_eq!(guard_verdict(true, pol, "/api/v1/vpn/warp/policy", &serde_json::json!({"mode":"lan"}), None), GuardVerdict::Block);
        assert_eq!(guard_verdict(true, pol, "/api/v1/vpn/warp/policy", &serde_json::json!({"mode":"lan","force":true}), None), GuardVerdict::Forced);
        assert!(disruptive_action(&Method::GET, "/api/v1/vpn/warp").is_none());
        let ts = disruptive_action(&Method::POST, "/api/v1/vpn/tailscale/settings");
        assert_eq!(guard_verdict(true, ts, "/api/v1/vpn/tailscale/settings", &serde_json::json!({"ssh":true}), None), GuardVerdict::Pass);
        assert_eq!(guard_verdict(true, ts, "/api/v1/vpn/tailscale/settings", &serde_json::json!({"exitNode":"nas01"}), None), GuardVerdict::Block);
        // v1.6.0: dataplane config/reconnect, network/lan, and raw modem/at are gated while active
        for path in [
            "/api/v1/dataplane/config",
            "/api/v1/dataplane/reconnect",
            "/api/v1/network/lan",
            "/api/v1/modem/at",
        ] {
            let act = disruptive_action(&Method::POST, path);
            assert!(act.is_some(), "expected {path} to be guarded");
            assert_eq!(guard_verdict(true, act, path, &null, None), GuardVerdict::Block, "{path}");
            assert_eq!(guard_verdict(true, act, path, &serde_json::json!({"force":true}), None), GuardVerdict::Forced, "{path}");
            assert_eq!(guard_verdict(false, act, path, &null, None), GuardVerdict::Pass, "{path}");
            assert!(disruptive_action(&Method::GET, path).is_none(), "GET {path} must not be gated");
        }
    }

    #[test]
    fn set_hint_updates_failover_active_synchronously() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                let mut f = lock(&obs().failover);
                f.hint = None;
                f.active = false;
                f.source = None;
                f.episode = None;
                f.last_episode = None;
                ACTIVE.store(false, Ordering::Relaxed);
            }
        }
        let _reset = Reset;
        assert!(!is_active());
        let out = set_hint(Role::Active);
        assert!(out.contains("role=active"), "{out}");
        assert!(is_active(), "is_active must reflect active hint immediately without waiting for on_tick");
        assert_eq!(status_json()["active"], serde_json::json!(true));

        let out2 = set_hint(Role::Standby);
        assert!(out2.contains("role=standby"), "{out2}");
        assert!(!is_active(), "is_active must reflect standby hint immediately");
        assert_eq!(status_json()["active"], serde_json::json!(false));
    }
}

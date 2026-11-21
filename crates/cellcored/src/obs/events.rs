//! Event log: a bounded RAM ring, detectors that diff consecutive telemetry
//! snapshots (no extra AT), and the hooks other modules call.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::{lock, obs};
use crate::{auth::now_secs, state::ModemSnapshot};

/// RAM ring size; the flushed file holds the same.
pub const RING_CAP: usize = 1000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Handover,
    BandChange,
    RatChange,
    CaChange,
    RegistrationLost,
    RegistrationRegained,
    BearerChange,
    PublicIpChange,
    QuecwatchRecovery,
    R10Action,
    ScheduledReboot,
    DaemonStart,
    OtaInstall,
    FailoverStart,
    FailoverEnd,
    WorkDeferred,
    ForcedAction,
    UsageThreshold,
    StandbyLeak,
    SmsReceived,
    /// WARP / Tailscale routing changes and tunnel fail-back.
    Vpn,
}

impl EventKind {
    pub const ALL: [EventKind; 21] = [
        EventKind::Handover,
        EventKind::BandChange,
        EventKind::RatChange,
        EventKind::CaChange,
        EventKind::RegistrationLost,
        EventKind::RegistrationRegained,
        EventKind::BearerChange,
        EventKind::PublicIpChange,
        EventKind::QuecwatchRecovery,
        EventKind::R10Action,
        EventKind::ScheduledReboot,
        EventKind::DaemonStart,
        EventKind::OtaInstall,
        EventKind::FailoverStart,
        EventKind::FailoverEnd,
        EventKind::WorkDeferred,
        EventKind::ForcedAction,
        EventKind::UsageThreshold,
        EventKind::StandbyLeak,
        EventKind::SmsReceived,
        EventKind::Vpn,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Handover => "handover",
            EventKind::BandChange => "band_change",
            EventKind::RatChange => "rat_change",
            EventKind::CaChange => "ca_change",
            EventKind::RegistrationLost => "registration_lost",
            EventKind::RegistrationRegained => "registration_regained",
            EventKind::BearerChange => "bearer_change",
            EventKind::PublicIpChange => "public_ip_change",
            EventKind::QuecwatchRecovery => "quecwatch_recovery",
            EventKind::R10Action => "r10_action",
            EventKind::ScheduledReboot => "scheduled_reboot",
            EventKind::DaemonStart => "daemon_start",
            EventKind::OtaInstall => "ota_install",
            EventKind::FailoverStart => "failover_start",
            EventKind::FailoverEnd => "failover_end",
            EventKind::WorkDeferred => "work_deferred",
            EventKind::ForcedAction => "forced_action",
            EventKind::UsageThreshold => "usage_threshold",
            EventKind::StandbyLeak => "standby_leak",
            EventKind::SmsReceived => "sms_received",
            EventKind::Vpn => "vpn",
        }
    }

    pub fn parse(s: &str) -> Option<EventKind> {
        EventKind::ALL.iter().copied().find(|k| k.as_str() == s)
    }

    /// Notification default when the owner has not set this type: the
    /// things worth a phone buzz on a backup link, not routine radio churn.
    pub fn notify_default(self) -> bool {
        matches!(
            self,
            EventKind::RegistrationLost
                | EventKind::QuecwatchRecovery
                | EventKind::R10Action
                | EventKind::FailoverStart
                | EventKind::FailoverEnd
                | EventKind::UsageThreshold
                | EventKind::StandbyLeak
                | EventKind::OtaInstall
                | EventKind::SmsReceived
                | EventKind::Vpn
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: u64,
    /// Unix seconds.
    pub ts: u64,
    #[serde(rename = "type")]
    pub kind: EventKind,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StoredEvents {
    pub next_id: u64,
    pub events: Vec<Event>,
}

/// Bounded ring + per-type counters (since daemon start, for Prometheus).
#[derive(Debug, Default)]
pub struct EventStore {
    ring: VecDeque<Event>,
    next_id: u64,
    dirty: bool,
    pub counts: BTreeMap<EventKind, u64>,
}

impl EventStore {
    pub fn restore(&mut self, stored: StoredEvents) {
        let mut evs = stored.events;
        if evs.len() > RING_CAP {
            evs.drain(..evs.len() - RING_CAP);
        }
        let max_id = evs.iter().map(|e| e.id).max().unwrap_or(0);
        self.next_id = stored.next_id.max(max_id + 1).max(1);
        self.ring = evs.into();
    }

    pub fn push(&mut self, kind: EventKind, severity: Severity, title: String, detail: serde_json::Value, ts: u64) -> Event {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        let ev = Event { id, ts, kind, severity, title, detail };
        if self.ring.len() >= RING_CAP {
            self.ring.pop_front();
        }
        self.ring.push_back(ev.clone());
        *self.counts.entry(kind).or_insert(0) += 1;
        self.dirty = true;
        ev
    }

    pub fn take_dirty(&mut self) -> bool {
        std::mem::replace(&mut self.dirty, false)
    }

    pub fn to_stored(&self) -> StoredEvents {
        StoredEvents { next_id: self.next_id, events: self.ring.iter().cloned().collect() }
    }

    /// Newest first. `since` = unix seconds (inclusive), `kinds` empty = all.
    pub fn query(&self, since: Option<u64>, kinds: &[EventKind], limit: usize) -> Vec<Event> {
        self.ring
            .iter()
            .rev()
            .filter(|e| since.is_none_or(|s| e.ts >= s))
            .filter(|e| kinds.is_empty() || kinds.contains(&e.kind))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }
}

/// Record an event: ring + counter, WebSocket push, notifier queue. Never
/// blocks (the notifier queue is bounded; a full queue drops and counts).
pub fn emit(kind: EventKind, severity: Severity, title: impl Into<String>, detail: serde_json::Value) {
    let o = obs();
    let ev = lock(&o.events).push(kind, severity, title.into(), detail, now_secs());
    o.broadcast(&serde_json::json!({ "channel": "event", "event": ev }));
    if let Some(tx) = o.notify_tx.get()
        && tx.try_send(ev).is_err()
    {
        lock(&o.notify).dropped += 1;
    }
}

// ---------------------------------------------------------------------------
// Snapshot diff detectors
// ---------------------------------------------------------------------------

/// The parts of a telemetry snapshot the detectors compare.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RadioView {
    /// None = the serving-cell query failed this round (unknown, not "lost").
    pub serving: Option<ServingView>,
    pub cfun: i32,
    /// Secondary component carriers as (band, arfcn).
    pub scc: BTreeSet<(String, i64)>,
    /// Bearer addresses (v4 and v6) across active bearers.
    pub bearer_ips: BTreeSet<String>,
    pub public_ip: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServingView {
    pub state: String,
    pub rat: String,
    pub band: String,
    pub pci: Option<i32>,
    pub arfcn: Option<i64>,
}

impl RadioView {
    pub fn from_snapshot(m: &ModemSnapshot) -> Self {
        Self {
            serving: m.serving.as_ref().map(|s| ServingView {
                state: s.state.to_ascii_uppercase(),
                rat: s.rat.clone(),
                band: s.band.clone(),
                pci: s.pci,
                arfcn: s.arfcn,
            }),
            cfun: m.identity.cfun,
            scc: m
                .carriers
                .iter()
                .filter(|c| c.role.eq_ignore_ascii_case("SCC"))
                .map(|c| (c.band.clone(), c.arfcn))
                .collect(),
            bearer_ips: m
                .bearers
                .iter()
                .flat_map(|b| [b.ipv4.clone(), b.ipv6.clone()])
                .flatten()
                .filter(|ip| !ip.is_empty() && ip != "0.0.0.0" && ip != "::")
                .collect(),
            public_ip: m.public_ip.clone().filter(|ip| !ip.is_empty()),
        }
    }

    /// Some(true) registered, Some(false) not, None unknown.
    pub fn registered(&self) -> Option<bool> {
        if self.cfun != 1 {
            return Some(false);
        }
        let s = self.serving.as_ref()?;
        match s.state.as_str() {
            "NOCONN" | "CONNECT" => Some(true),
            "SEARCH" | "LIMSRV" | "NOSERVICE" | "NO SERVICE" => Some(false),
            _ => None,
        }
    }
}

/// A value that must be seen on `need` consecutive samples before it is
/// accepted (one failed AT reply must not look like a dropped carrier).
#[derive(Debug, Clone, Default)]
pub struct Confirm<T: PartialEq + Clone> {
    pub confirmed: Option<T>,
    pending: Option<T>,
    seen: u32,
}

impl<T: PartialEq + Clone> Confirm<T> {
    /// Returns (old, new) when a different value becomes confirmed. The very
    /// first confirmed value is a baseline and returns None.
    pub fn observe(&mut self, v: T, need: u32) -> Option<(T, T)> {
        if self.confirmed.as_ref() == Some(&v) {
            self.pending = None;
            self.seen = 0;
            return None;
        }
        if self.pending.as_ref() == Some(&v) {
            self.seen += 1;
        } else {
            self.pending = Some(v.clone());
            self.seen = 1;
        }
        if self.seen >= need {
            self.pending = None;
            self.seen = 0;
            let old = self.confirmed.replace(v.clone());
            return old.map(|o| (o, v));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    pub kind: EventKind,
    pub severity: Severity,
    pub title: String,
    pub detail: serde_json::Value,
}

fn det(kind: EventKind, severity: Severity, title: String, detail: serde_json::Value) -> Detected {
    Detected { kind, severity, title, detail }
}

#[derive(Debug, Default)]
pub struct SnapshotDetector {
    cell: Option<ServingView>,
    registered: Confirm<bool>,
    lost_at: Option<u64>,
    scc: Confirm<BTreeSet<(String, i64)>>,
    bearers: Confirm<BTreeSet<String>>,
    public_ip: Option<String>,
}

fn cell_label(s: &ServingView) -> String {
    format!(
        "{} {} PCI {} ARFCN {}",
        s.rat,
        s.band,
        s.pci.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        s.arfcn.map(|a| a.to_string()).unwrap_or_else(|| "-".into())
    )
}

fn scc_list(set: &BTreeSet<(String, i64)>) -> Vec<String> {
    set.iter().map(|(b, a)| format!("{b}@{a}")).collect()
}

impl SnapshotDetector {
    /// Compare this snapshot with what was seen before. Pure: no I/O.
    pub fn observe(&mut self, v: &RadioView, now: u64) -> Vec<Detected> {
        let mut out = Vec::new();

        // Registration (needs two consecutive samples to change).
        if let Some(reg) = v.registered()
            && let Some((_, new)) = self.registered.observe(reg, 2)
        {
            if new {
                let down = self.lost_at.take().map(|t| now.saturating_sub(t));
                out.push(det(
                    EventKind::RegistrationRegained,
                    Severity::Info,
                    match down {
                        Some(s) => format!("Registration regained after {s} s"),
                        None => "Registration regained".into(),
                    },
                    serde_json::json!({ "downSecs": down, "cfun": v.cfun }),
                ));
            } else {
                self.lost_at = Some(now);
                out.push(det(
                    EventKind::RegistrationLost,
                    Severity::Critical,
                    "Registration lost".into(),
                    serde_json::json!({
                        "cfun": v.cfun,
                        "state": v.serving.as_ref().map(|s| s.state.clone()),
                    }),
                ));
            }
        }
        let registered = self.registered.confirmed == Some(true);

        // Serving cell: RAT > band > PCI/ARFCN, one event per change.
        if let Some(cur) = v.serving.as_ref().filter(|_| registered && v.registered() == Some(true)) {
            if let Some(prev) = self.cell.as_ref() {
                let cell_moved = prev.pci != cur.pci || prev.arfcn != cur.arfcn;
                let detail = serde_json::json!({
                    "from": { "rat": prev.rat, "band": prev.band, "pci": prev.pci, "arfcn": prev.arfcn },
                    "to": { "rat": cur.rat, "band": cur.band, "pci": cur.pci, "arfcn": cur.arfcn },
                });
                if prev.rat != cur.rat {
                    out.push(det(EventKind::RatChange, Severity::Warning, format!("RAT {} → {}", prev.rat, cur.rat), detail));
                } else if prev.band != cur.band {
                    out.push(det(EventKind::BandChange, Severity::Info, format!("Band {} → {} ({})", prev.band, cur.band, cell_label(cur)), detail));
                } else if cell_moved {
                    out.push(det(EventKind::Handover, Severity::Info, format!("Handover to {}", cell_label(cur)), detail));
                }
            }
            self.cell = Some(cur.clone());
        }

        // Carrier aggregation set (confirmed over two samples).
        if registered
            && let Some((old, new)) = self.scc.observe(v.scc.clone(), 2)
        {
            let added: BTreeSet<_> = new.difference(&old).cloned().collect();
            let dropped: BTreeSet<_> = old.difference(&new).cloned().collect();
            let title = match (added.is_empty(), dropped.is_empty()) {
                (false, true) => format!("CA added {}", scc_list(&added).join(", ")),
                (true, false) => format!("CA dropped {}", scc_list(&dropped).join(", ")),
                _ => format!("CA changed: +{} −{}", scc_list(&added).join(", "), scc_list(&dropped).join(", ")),
            };
            out.push(det(
                EventKind::CaChange,
                Severity::Info,
                title,
                serde_json::json!({
                    "added": scc_list(&added),
                    "dropped": scc_list(&dropped),
                    "components": new.len() + 1,
                }),
            ));
        }

        // Bearer addresses (confirmed over two samples).
        if let Some((old, new)) = self.bearers.observe(v.bearer_ips.clone(), 2) {
            let title = if new.is_empty() {
                "Data bearer down (no IP)".to_string()
            } else if old.is_empty() {
                "Data bearer up".to_string()
            } else {
                "Bearer IP changed".to_string()
            };
            let sev = if new.is_empty() { Severity::Warning } else { Severity::Info };
            out.push(det(
                EventKind::BearerChange,
                sev,
                title,
                serde_json::json!({ "from": old, "to": new }),
            ));
        }

        // Public IP (refreshed every 5 min by the telemetry task).
        if let Some(ip) = v.public_ip.as_ref() {
            if let Some(prev) = self.public_ip.as_ref()
                && prev != ip
            {
                out.push(det(
                    EventKind::PublicIpChange,
                    Severity::Info,
                    format!("Public IP {prev} → {ip}"),
                    serde_json::json!({ "from": prev, "to": ip }),
                ));
            }
            self.public_ip = Some(ip.clone());
        }
        out
    }
}

/// Telemetry write point hook: called with each fresh snapshot.
pub fn on_snapshot(m: &ModemSnapshot) {
    let view = RadioView::from_snapshot(m);
    let found = lock(&obs().detector).observe(&view, now_secs());
    for d in found {
        emit(d.kind, d.severity, d.title, d.detail);
    }
}

/// Route10 recovery action received over IPC (recorded; never gated).
pub fn r10_action(action: &str) {
    let sev = if action == "wan-restart" { Severity::Warning } else { Severity::Critical };
    emit(
        EventKind::R10Action,
        sev,
        format!("External router requested {action}"),
        serde_json::json!({ "action": action }),
    );
}

pub fn quecwatch_recovery(attempt: u32, max: u32, refresh: bool, sim_failover: bool) {
    emit(
        EventKind::QuecwatchRecovery,
        Severity::Warning,
        format!("LinkWatch recovery attempt {attempt}/{max}"),
        serde_json::json!({ "attempt": attempt, "max": max, "cfunCycle": refresh, "simFailover": sim_failover }),
    );
}

pub fn work_deferred(what: &str, why: &str) {
    emit(
        EventKind::WorkDeferred,
        Severity::Info,
        format!("Deferred {what}: carrying failover traffic"),
        serde_json::json!({ "work": what, "reason": why }),
    );
}

/// OTA result from the installer's status record, reported once per run.
pub fn check_ota_status() {
    let Some(st) = crate::ota::read_upgrade_status() else {
        return;
    };
    if !(st.state == "succeeded" || st.state == "failed") || st.started_at == 0 {
        return;
    }
    {
        let mut p = lock(&obs().persisted);
        if p.last_ota_started_at == st.started_at {
            return;
        }
        p.last_ota_started_at = st.started_at;
    }
    let ok = st.state == "succeeded";
    emit(
        EventKind::OtaInstall,
        if ok { Severity::Info } else { Severity::Warning },
        if ok {
            format!("OTA install {} → {} succeeded", st.from, st.target)
        } else {
            format!("OTA install of {} failed", st.target)
        },
        serde_json::json!({
            "from": st.from,
            "to": st.target,
            "state": st.state,
            "exitCode": st.exit_code,
            "message": st.message,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serving(state: &str, rat: &str, band: &str, pci: i32, arfcn: i64) -> Option<ServingView> {
        Some(ServingView { state: state.into(), rat: rat.into(), band: band.into(), pci: Some(pci), arfcn: Some(arfcn) })
    }

    fn view(s: Option<ServingView>) -> RadioView {
        RadioView { serving: s, cfun: 1, ..Default::default() }
    }

    fn kinds(v: &[Detected]) -> Vec<EventKind> {
        v.iter().map(|d| d.kind).collect()
    }

    /// Feed the same view until registration and the confirm-gated values
    /// (which start counting once registered) have a baseline.
    fn settle(d: &mut SnapshotDetector, v: &RadioView, t: u64) -> Vec<Detected> {
        let mut a = d.observe(v, t);
        a.extend(d.observe(v, t + 1));
        a.extend(d.observe(v, t + 2));
        a
    }

    #[test]
    fn handover_band_and_rat_changes() {
        let mut d = SnapshotDetector::default();
        assert!(settle(&mut d, &view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310)), 0).is_empty(), "baseline");
        let h = d.observe(&view(serving("CONNECT", "NR5G-SA", "n41", 589, 521310)), 10);
        assert_eq!(kinds(&h), vec![EventKind::Handover]);
        assert!(h[0].title.contains("PCI 589"));
        let b = d.observe(&view(serving("CONNECT", "NR5G-SA", "n71", 100, 126270)), 20);
        assert_eq!(kinds(&b), vec![EventKind::BandChange], "inter-band move is one event");
        let r = d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 875)), 30);
        assert_eq!(kinds(&r), vec![EventKind::RatChange]);
        assert!(d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 875)), 31).is_empty(), "no change, no event");
        // ARFCN-only change is a handover too
        assert_eq!(kinds(&d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 900)), 32)), vec![EventKind::Handover]);
    }

    #[test]
    fn failed_qeng_is_unknown_not_lost() {
        let mut d = SnapshotDetector::default();
        settle(&mut d, &view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310)), 0);
        for t in 1..5 {
            assert!(d.observe(&view(None), t).is_empty());
        }
        // and the cell is not reported as a handover when it comes back
        assert!(d.observe(&view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310)), 9).is_empty());
    }

    #[test]
    fn registration_loss_needs_two_samples_and_reports_downtime() {
        let mut d = SnapshotDetector::default();
        settle(&mut d, &view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310)), 0);
        let blip = view(serving("SEARCH", "NR5G-SA", "n41", 258, 521310));
        assert!(d.observe(&blip, 10).is_empty(), "single sample is a blip");
        assert!(d.observe(&view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310)), 11).is_empty());
        assert!(d.observe(&blip, 20).is_empty());
        let lost = d.observe(&blip, 23);
        assert_eq!(kinds(&lost), vec![EventKind::RegistrationLost]);
        assert_eq!(lost[0].severity, Severity::Critical);
        // CFUN=0 counts as not registered
        let mut off = view(None);
        off.cfun = 0;
        assert!(d.observe(&off, 30).is_empty(), "already lost");
        let back = view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310));
        assert!(d.observe(&back, 60).is_empty());
        let regained = d.observe(&back, 63);
        assert_eq!(kinds(&regained), vec![EventKind::RegistrationRegained]);
        assert_eq!(regained[0].detail["downSecs"], 40);
    }

    #[test]
    fn ca_add_and_drop_are_confirmed() {
        let mut d = SnapshotDetector::default();
        let mut v = view(serving("CONNECT", "NR5G-SA", "n41", 258, 521310));
        v.scc = [("n41".to_string(), 501390)].into_iter().collect();
        assert!(settle(&mut d, &v, 0).is_empty());
        let mut glitch = v.clone();
        glitch.scc.clear(); // QCAINFO failed once
        assert!(d.observe(&glitch, 5).is_empty());
        assert!(d.observe(&v, 6).is_empty());
        let mut more = v.clone();
        more.scc.insert(("n25".into(), 396970));
        assert!(d.observe(&more, 10).is_empty());
        let added = d.observe(&more, 11);
        assert_eq!(kinds(&added), vec![EventKind::CaChange]);
        assert_eq!(added[0].detail["added"][0], "n25@396970");
        assert_eq!(added[0].detail["components"], 3);
        d.observe(&glitch, 20);
        let dropped = d.observe(&glitch, 21);
        assert_eq!(dropped[0].detail["dropped"].as_array().map(|a| a.len()), Some(2));
        assert!(dropped[0].title.starts_with("CA dropped"));
    }

    #[test]
    fn bearer_and_public_ip_changes() {
        let mut d = SnapshotDetector::default();
        let mut v = view(serving("CONNECT", "NR5G-SA", "n41", 258, 521310));
        v.bearer_ips = ["10.1.2.3".to_string()].into_iter().collect();
        v.public_ip = Some("172.58.1.1".into());
        assert!(settle(&mut d, &v, 0).is_empty());
        let mut v2 = v.clone();
        v2.bearer_ips = ["10.9.9.9".to_string()].into_iter().collect();
        v2.public_ip = Some("172.58.2.2".into());
        let first = d.observe(&v2, 5);
        assert_eq!(kinds(&first), vec![EventKind::PublicIpChange], "public IP is immediate");
        let second = d.observe(&v2, 6);
        assert_eq!(kinds(&second), vec![EventKind::BearerChange]);
        assert_eq!(second[0].title, "Bearer IP changed");
        let mut down = v2.clone();
        down.bearer_ips.clear();
        down.public_ip = None; // unknown public IP is not a change
        d.observe(&down, 7);
        let gone = d.observe(&down, 8);
        assert_eq!(gone[0].title, "Data bearer down (no IP)");
        assert_eq!(gone[0].severity, Severity::Warning);
    }

    #[test]
    fn ring_is_bounded_and_query_filters() {
        let mut s = EventStore::default();
        for i in 0..(RING_CAP as u64 + 50) {
            let k = if i % 2 == 0 { EventKind::Handover } else { EventKind::CaChange };
            s.push(k, Severity::Info, format!("e{i}"), serde_json::Value::Null, 1000 + i);
        }
        assert_eq!(s.len(), RING_CAP);
        assert_eq!(s.counts[&EventKind::Handover], (RING_CAP as u64 + 50) / 2);
        let newest = s.query(None, &[], 3);
        assert_eq!(newest[0].title, format!("e{}", RING_CAP + 49));
        assert!(newest[0].id > newest[1].id);
        let h = s.query(Some(1000 + RING_CAP as u64 + 40), &[EventKind::Handover], 100);
        assert!(h.iter().all(|e| e.kind == EventKind::Handover && e.ts >= 1000 + RING_CAP as u64 + 40));
        assert_eq!(h.len(), 5);
        assert!(s.take_dirty());
        assert!(!s.take_dirty());
        // restore keeps ids monotonic
        let mut r = EventStore::default();
        r.restore(s.to_stored());
        let e = r.push(EventKind::DaemonStart, Severity::Info, "x".into(), serde_json::Value::Null, 0);
        assert!(e.id > newest[0].id);
    }

    #[test]
    fn kind_names_roundtrip() {
        for k in EventKind::ALL {
            assert_eq!(EventKind::parse(k.as_str()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(k.as_str()));
        }
    }
}

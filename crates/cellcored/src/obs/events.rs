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
    AntennaDegraded,
    ThermalThrottle,
    SarBackoff,
    AirCipherNull,
    ModemSsr,
    CellLockBypassed,
}

impl EventKind {
    pub const ALL: [EventKind; 27] = [
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
        EventKind::AntennaDegraded,
        EventKind::ThermalThrottle,
        EventKind::SarBackoff,
        EventKind::AirCipherNull,
        EventKind::ModemSsr,
        EventKind::CellLockBypassed,
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
            EventKind::AntennaDegraded => "antenna_degraded",
            EventKind::ThermalThrottle => "thermal_throttle",
            EventKind::SarBackoff => "sar_backoff",
            EventKind::AirCipherNull => "air_cipher_null",
            EventKind::ModemSsr => "modem_ssr",
            EventKind::CellLockBypassed => "cell_lock_bypassed",
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
                | EventKind::AntennaDegraded
                | EventKind::ThermalThrottle
                | EventKind::SarBackoff
                | EventKind::AirCipherNull
                | EventKind::ModemSsr
                | EventKind::CellLockBypassed
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
    urgent_dirty: bool,
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
        if severity >= Severity::Warning {
            self.urgent_dirty = true;
        }
        ev
    }

    #[allow(dead_code)]
    pub fn take_dirty(&mut self) -> bool {
        self.urgent_dirty = false;
        std::mem::replace(&mut self.dirty, false)
    }

    /// Take dirty snapshot if `force` is set, any `Warning`/`Critical` event arrived
    /// (`urgent_dirty`), or `allow_info_flush` (6 h routine flush) is true.
    pub fn take_flush_snapshot(&mut self, force: bool, allow_info_flush: bool) -> Option<StoredEvents> {
        if !self.dirty {
            return None;
        }
        if force || self.urgent_dirty || allow_info_flush {
            self.dirty = false;
            self.urgent_dirty = false;
            Some(self.to_stored())
        } else {
            None
        }
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

/// Slots reserved in the notifier queue for non-SMS alerts so an SMS burst
/// cannot fill the queue and drop critical WAN/failover notifications.
pub const NOTIFY_QUEUE_CRITICAL_RESERVE: usize = 8;

/// Record an event: ring + counter, WebSocket push, notifier queue. Never
/// blocks (the notifier queue is bounded; a full queue drops and counts).
pub fn emit(kind: EventKind, severity: Severity, title: impl Into<String>, detail: serde_json::Value) {
    let o = obs();
    let ev = lock(&o.events).push(kind, severity, title.into(), detail, now_secs());
    if o.has_ws_clients() {
        o.broadcast(&serde_json::json!({ "channel": "event", "event": ev }));
    }
    if let Some(tx) = o.notify_tx.get()
        && ((kind == EventKind::SmsReceived && tx.capacity() <= NOTIFY_QUEUE_CRITICAL_RESERVE)
            || tx.try_send(ev).is_err())
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
    /// Per-chain RSRP (dBm) across RX0..RX3 (`None` when absent/sentinel).
    pub chain_rsrp: Vec<Option<f64>>,
    pub any_throttling: Option<bool>,
    pub sar_rf_state: Option<u32>,
    pub null_cipher_alert: Option<bool>,
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
            chain_rsrp: m
                .mimo
                .rsrp
                .iter()
                .take(4)
                .map(|v| v.filter(|x| x.is_finite() && *x != -140.0 && *x != -32768.0))
                .collect(),
            any_throttling: None,
            sar_rf_state: None,
            null_cipher_alert: None,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CellIdentity {
    rat: String,
    band: String,
    pci: Option<i32>,
    arfcn: Option<i64>,
}

#[derive(Debug, Default)]
pub struct SnapshotDetector {
    cell: Confirm<CellIdentity>,
    registered: Confirm<bool>,
    lost_at: Option<u64>,
    scc: Confirm<BTreeSet<(String, i64)>>,
    bearers: Confirm<BTreeSet<String>>,
    public_ip: Option<String>,
    saw_multi_chain: bool,
    antenna_degraded_streak: u32,
    antenna_healthy_streak: u32,
    antenna_degraded_active: bool,
    throttling_active: bool,
    last_sar_backoff: u32,
    null_cipher_active: bool,
}

fn cell_id_label(s: &CellIdentity) -> String {
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

        // Serving cell: RAT > band > PCI/ARFCN, one event per change (confirmed over 2 samples).
        if let Some(cur) = v.serving.as_ref().filter(|_| registered && v.registered() == Some(true)) {
            let cid = CellIdentity {
                rat: cur.rat.clone(),
                band: cur.band.clone(),
                pci: cur.pci,
                arfcn: cur.arfcn,
            };
            if let Some((prev, next)) = self.cell.observe(cid, 2) {
                let cell_moved = prev.pci != next.pci || prev.arfcn != next.arfcn;
                let detail = serde_json::json!({
                    "from": { "rat": prev.rat, "band": prev.band, "pci": prev.pci, "arfcn": prev.arfcn },
                    "to": { "rat": next.rat, "band": next.band, "pci": next.pci, "arfcn": next.arfcn },
                });
                if prev.rat != next.rat {
                    out.push(det(
                        EventKind::RatChange,
                        Severity::Warning,
                        format!("RAT {} → {}", prev.rat, next.rat),
                        detail,
                    ));
                } else if prev.band != next.band {
                    out.push(det(
                        EventKind::BandChange,
                        Severity::Info,
                        format!("Band {} → {} ({})", prev.band, next.band, cell_id_label(&next)),
                        detail,
                    ));
                } else if cell_moved {
                    out.push(det(
                        EventKind::Handover,
                        Severity::Info,
                        format!("Handover to {}", cell_id_label(&next)),
                        detail,
                    ));
                }
            }
        }

        // Antenna chain health (3 consecutive RRC-connected/active snapshots).
        if let Some(cur) = v.serving.as_ref().filter(|_| v.registered() == Some(true)) {
            let present: Vec<f64> = v
                .chain_rsrp
                .iter()
                .take(4)
                .filter_map(|x| *x)
                .filter(|x| x.is_finite())
                .collect();
            let active_chains = present.len();
            if active_chains >= 2 {
                self.saw_multi_chain = true;
            }
            if cur.state == "CONNECT" && active_chains >= 1 {
                let rat_up = cur.rat.to_ascii_uppercase();
                let is_nr_or_lte = rat_up.contains("NR5G") || rat_up.contains("LTE");
                let spread_db = (active_chains >= 2).then(|| {
                    let hi = present.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    let lo = present.iter().copied().fold(f64::INFINITY, f64::min);
                    ((hi - lo) * 10.0).round() / 10.0
                });
                let spread_bad = spread_db.is_some_and(|sp| sp > 13.0);
                let single_chain_drop = active_chains == 1 && is_nr_or_lte && self.saw_multi_chain;
                if spread_bad || single_chain_drop {
                    self.antenna_degraded_streak += 1;
                    self.antenna_healthy_streak = 0;
                    if !self.antenna_degraded_active && self.antenna_degraded_streak >= 3 {
                        self.antenna_degraded_active = true;
                        let title = if let Some(sp) = spread_db.filter(|&s| s > 13.0) {
                            format!("Antenna RSRP imbalance ({sp:.1} dB spread across {active_chains} chains)")
                        } else {
                            format!("MIMO degraded to single receive chain on {}", cur.rat)
                        };
                        out.push(det(
                            EventKind::AntennaDegraded,
                            Severity::Warning,
                            title,
                            serde_json::json!({
                                "activeChains": active_chains,
                                "rsrpSpreadDb": spread_db,
                                "chainRsrp": v.chain_rsrp,
                                "rat": cur.rat,
                                "band": cur.band,
                            }),
                        ));
                    }
                } else {
                    self.antenna_degraded_streak = 0;
                    self.antenna_healthy_streak += 1;
                    if self.antenna_degraded_active && self.antenna_healthy_streak >= 3 {
                        self.antenna_degraded_active = false;
                        out.push(det(
                            EventKind::AntennaDegraded,
                            Severity::Info,
                            format!("Antenna chains recovered ({active_chains} chains balanced)"),
                            serde_json::json!({
                                "recovered": true,
                                "activeChains": active_chains,
                                "rsrpSpreadDb": spread_db,
                                "chainRsrp": v.chain_rsrp,
                                "rat": cur.rat,
                                "band": cur.band,
                            }),
                        ));
                    }
                }
            }
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

        if let Some(throttling) = v.any_throttling {
            out.extend(self.observe_thermal(throttling, serde_json::json!({ "anyThrottling": throttling })));
        }
        if let Some(sar) = v.sar_rf_state {
            out.extend(self.observe_sar(sar));
        }
        if let Some(null_cipher) = v.null_cipher_alert {
            out.extend(self.observe_null_cipher(null_cipher, serde_json::json!({ "nullCipherAlert": null_cipher })));
        }
        out
    }

    pub fn observe_thermal(&mut self, any_throttling: bool, detail: serde_json::Value) -> Option<Detected> {
        if any_throttling && !self.throttling_active {
            self.throttling_active = true;
            return Some(det(
                EventKind::ThermalThrottle,
                Severity::Warning,
                "Modem QMI thermal mitigation active".into(),
                detail,
            ));
        }
        if !any_throttling && self.throttling_active {
            self.throttling_active = false;
            let mut d = detail;
            if let Some(obj) = d.as_object_mut() {
                obj.insert("recovered".into(), serde_json::Value::Bool(true));
            }
            return Some(det(
                EventKind::ThermalThrottle,
                Severity::Info,
                "Modem QMI thermal mitigation cleared".into(),
                d,
            ));
        }
        None
    }

    pub fn observe_sar(&mut self, sar_state: u32) -> Option<Detected> {
        if sar_state > 0 && self.last_sar_backoff != sar_state {
            self.last_sar_backoff = sar_state;
            return Some(det(
                EventKind::SarBackoff,
                Severity::Warning,
                format!("SAR RF transmit backoff active (state {sar_state})"),
                serde_json::json!({ "sarState": sar_state }),
            ));
        }
        if sar_state == 0 {
            self.last_sar_backoff = 0;
        }
        None
    }

    pub fn observe_null_cipher(&mut self, null_cipher_alert: bool, detail: serde_json::Value) -> Option<Detected> {
        if null_cipher_alert && !self.null_cipher_active {
            self.null_cipher_active = true;
            return Some(det(
                EventKind::AirCipherNull,
                Severity::Critical,
                "Unencrypted air-interface cipher (NEA0/EEA0) while RRC Connected".into(),
                detail,
            ));
        }
        if !null_cipher_alert && self.null_cipher_active {
            self.null_cipher_active = false;
            let mut d = detail;
            if let Some(obj) = d.as_object_mut() {
                obj.insert("recovered".into(), serde_json::Value::Bool(true));
            }
            return Some(det(
                EventKind::AirCipherNull,
                Severity::Info,
                "Air-interface encryption restored (null cipher cleared)".into(),
                d,
            ));
        }
        None
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

/// QMI DSP telemetry hook: checks TMD thermal throttling and SAR backoff state.
pub fn on_dsp_telemetry(dsp: &crate::qmi::dsp::DspTelemetrySnapshot) {
    if !dsp.qrtr_available {
        return;
    }
    let mut found = Vec::new();
    {
        let mut det = lock(&obs().detector);
        let active_devs: Vec<serde_json::Value> = dsp
            .tmd_devices
            .iter()
            .filter(|d| d.throttling)
            .map(|d| serde_json::json!({ "device": d.name, "level": d.current_level, "max": d.max_level }))
            .collect();
        if let Some(d) = det.observe_thermal(dsp.any_throttling, serde_json::json!({ "devices": active_devs })) {
            found.push(d);
        }
        if let Some(sar) = dsp.sar_rf_state
            && let Some(d) = det.observe_sar(sar)
        {
            found.push(d);
        }
    }
    for d in found {
        emit(d.kind, d.severity, d.title, d.detail);
    }
}

/// SDX75 PHY diagnostics hook: checks RRC-Connected null air-cipher alert (`NEA0`/`EEA0`).
pub fn on_phy_diagnostics(phy: &crate::radio_tuning::PhyDiagnostics) {
    let Some(sec) = phy.air_security.as_ref() else {
        return;
    };
    let found = {
        let mut det = lock(&obs().detector);
        det.observe_null_cipher(
            sec.null_cipher_alert,
            serde_json::json!({
                "rat": sec.rat,
                "cipherName": sec.cipher_name,
                "integrityName": sec.integrity_name,
            }),
        )
    };
    if let Some(d) = found {
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
        obs().mark_state_dirty();
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
        // Single-sample blip is debounced by Confirm(2)
        assert!(d.observe(&view(serving("CONNECT", "NR5G-SA", "n41", 589, 521310)), 10).is_empty());
        let h = d.observe(&view(serving("CONNECT", "NR5G-SA", "n41", 589, 521310)), 11);
        assert_eq!(kinds(&h), vec![EventKind::Handover]);
        assert!(h[0].title.contains("PCI 589"));
        assert!(d.observe(&view(serving("CONNECT", "NR5G-SA", "n71", 100, 126270)), 20).is_empty());
        let b = d.observe(&view(serving("CONNECT", "NR5G-SA", "n71", 100, 126270)), 21);
        assert_eq!(kinds(&b), vec![EventKind::BandChange], "inter-band move is one event");
        assert!(d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 875)), 30).is_empty());
        let r = d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 875)), 31);
        assert_eq!(kinds(&r), vec![EventKind::RatChange]);
        assert!(d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 875)), 32).is_empty(), "no change, no event");
        // ARFCN-only change is a handover too (confirmed over 2 samples)
        assert!(d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 900)), 33).is_empty());
        assert_eq!(kinds(&d.observe(&view(serving("CONNECT", "LTE", "B2", 1, 900)), 34)), vec![EventKind::Handover]);
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
        assert!(EventKind::AntennaDegraded.notify_default());
        assert!(EventKind::ThermalThrottle.notify_default());
        assert!(EventKind::SarBackoff.notify_default());
        assert!(EventKind::AirCipherNull.notify_default());
        assert!(EventKind::ModemSsr.notify_default());
    }

    #[test]
    fn antenna_degraded_requires_three_connected_snapshots_and_detects_spread_or_chain_loss() {
        let mut d = SnapshotDetector::default();
        let mut healthy = view(serving("CONNECT", "NR5G-SA", "n41", 258, 521310));
        healthy.chain_rsrp = vec![Some(-88.0), Some(-90.0), Some(-89.0), Some(-91.0)];
        assert!(settle(&mut d, &healthy, 0).is_empty());

        // RRC Idle (NOCONN) with sleeping secondary chains must NOT trigger AntennaDegraded!
        let mut idle_one_chain = view(serving("NOCONN", "NR5G-SA", "n41", 258, 521310));
        idle_one_chain.chain_rsrp = vec![Some(-88.0), None, None, None];
        for t in 10..16 {
            assert!(d.observe(&idle_one_chain, t).is_empty(), "idle chain sleep at {t}");
        }

        // 2-snapshot RSRP spread blip (>13 dB) clears on 3rd healthy snapshot without firing.
        let mut spread_bad = healthy.clone();
        spread_bad.chain_rsrp = vec![Some(-84.0), Some(-86.0), Some(-85.0), Some(-101.0)]; // 17 dB spread
        assert!(d.observe(&spread_bad, 20).is_empty());
        assert!(d.observe(&spread_bad, 21).is_empty());
        assert!(d.observe(&healthy, 22).is_empty());

        // 3 consecutive RRC-connected snapshots with >13 dB spread triggers AntennaDegraded once.
        assert!(d.observe(&spread_bad, 30).is_empty());
        assert!(d.observe(&spread_bad, 31).is_empty());
        let ev1 = d.observe(&spread_bad, 32);
        assert_eq!(kinds(&ev1), vec![EventKind::AntennaDegraded]);
        assert_eq!(ev1[0].detail["rsrpSpreadDb"], 17.0);
        assert!(d.observe(&spread_bad, 33).is_empty(), "no duplicate spam while still degraded");

        // Recover across 3 healthy connected snapshots (emits AntennaDegraded Info recovery on 3rd), then drop to 1 chain -> triggers again!
        assert!(d.observe(&healthy, 40).is_empty());
        assert!(d.observe(&healthy, 41).is_empty());
        let rec = d.observe(&healthy, 42);
        assert_eq!(kinds(&rec), vec![EventKind::AntennaDegraded]);
        assert_eq!(rec[0].severity, Severity::Info);
        assert_eq!(rec[0].detail["recovered"], true);
        let mut single_chain = healthy.clone();
        single_chain.chain_rsrp = vec![Some(-88.0), None, None, None];
        assert!(d.observe(&single_chain, 50).is_empty());
        assert!(d.observe(&single_chain, 51).is_empty());
        let ev2 = d.observe(&single_chain, 52);
        assert_eq!(kinds(&ev2), vec![EventKind::AntennaDegraded]);
        assert_eq!(ev2[0].detail["activeChains"], 1);
    }

    #[test]
    fn detects_thermal_throttle_sar_backoff_and_null_cipher_edges() {
        let mut d = SnapshotDetector::default();
        let mut v = view(serving("CONNECT", "NR5G-SA", "n41", 258, 521310));
        assert!(settle(&mut d, &v, 0).is_empty());

        v.any_throttling = Some(true);
        v.sar_rf_state = Some(2);
        v.null_cipher_alert = Some(true);
        let evs = d.observe(&v, 10);
        assert_eq!(
            kinds(&evs),
            vec![EventKind::ThermalThrottle, EventKind::SarBackoff, EventKind::AirCipherNull]
        );
        // Holding state does not re-fire; clearing emits Info recovery for thermal & null cipher.
        assert!(d.observe(&v, 11).is_empty());
        v.any_throttling = Some(false);
        v.sar_rf_state = Some(0);
        v.null_cipher_alert = Some(false);
        let cleared = d.observe(&v, 12);
        assert_eq!(kinds(&cleared), vec![EventKind::ThermalThrottle, EventKind::AirCipherNull]);
        assert_eq!(cleared[0].severity, Severity::Info);
        assert_eq!(cleared[0].detail["recovered"], true);
        assert_eq!(cleared[1].severity, Severity::Info);
        assert_eq!(cleared[1].detail["recovered"], true);
        // Re-entering fires again.
        v.any_throttling = Some(true);
        assert_eq!(kinds(&d.observe(&v, 13)), vec![EventKind::ThermalThrottle]);
    }
}

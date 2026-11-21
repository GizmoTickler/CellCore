//! Event-driven notifications: a gate (per-type enable, quiet hours,
//! dedupe, rate limit) in front of three sinks — msmtp (the existing
//! `/etc/msmtprc`), a generic / Alertmanager-compatible webhook, and ntfy.
//!
//! No shell anywhere: msmtp and curl run argv-only through
//! [`crate::admin::exec::run`] with a hard timeout. curl reads its whole
//! request (URL, headers, body) from a config on stdin, so tokens and
//! header values never appear in a process listing. Every URL and header
//! was validated when it was saved (`config::validate_*`).

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::Path,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::{
    config::{NotifyConfig, NtfySink, WebhookFormat, WebhookSink},
    events::{Event, EventKind, Severity, emit},
    lock, obs,
};
use crate::{
    admin::exec::{ExecOpts, KIB, run},
    auth::now_secs,
    smd::Priority,
    state::AppState,
};

pub const QUEUE_CAP: usize = 64;
pub const SMS_MIN_INTERVAL_SECS: u64 = 120;
const SINK_TIMEOUT_SECS: u64 = 15;
const DEDUPE_MAP_CAP: usize = 256;
const SMS_SEEN_CAP: usize = 200;
pub const MSMTPRC: &str = "/etc/msmtprc";
pub const RECIPIENT_FILE: &str = "/etc/cellcore_alert_recipient";

/// What a sink sends: an event, or a test message.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    pub id: u64,
    pub ts: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    pub detail: serde_json::Value,
}

impl From<&Event> for Notice {
    fn from(e: &Event) -> Self {
        Self {
            id: e.id,
            ts: e.ts,
            kind: e.kind.as_str().to_string(),
            severity: e.severity,
            title: e.title.clone(),
            detail: e.detail.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suppress {
    Disabled,
    TypeOff,
    Quiet,
    Dedupe,
    Rate,
}

impl Suppress {
    pub fn as_str(self) -> &'static str {
        match self {
            Suppress::Disabled => "disabled",
            Suppress::TypeOff => "type_off",
            Suppress::Quiet => "quiet_hours",
            Suppress::Dedupe => "dedupe",
            Suppress::Rate => "rate_limit",
        }
    }

    pub const ALL: [Suppress; 5] = [Suppress::Disabled, Suppress::TypeOff, Suppress::Quiet, Suppress::Dedupe, Suppress::Rate];
}

/// Minutes-of-day window; start > end wraps past midnight; start == end is empty.
pub fn in_window(now: u16, start: u16, end: u16) -> bool {
    if start == end {
        false
    } else if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

#[derive(Debug, Default)]
pub struct Gate {
    last_sent: HashMap<String, u64>,
    window: VecDeque<u64>,
}

impl Gate {
    /// Decide whether `ev` goes out now. Records the send when it does.
    pub fn decide(&mut self, cfg: &NotifyConfig, kind: EventKind, severity: Severity, title: &str, now: u64, local_min: u16) -> Result<(), Suppress> {
        if !cfg.enabled {
            return Err(Suppress::Disabled);
        }
        if !cfg.kind_enabled(kind) {
            return Err(Suppress::TypeOff);
        }
        if cfg.quiet.enabled
            && !(cfg.quiet.allow_critical && severity == Severity::Critical)
            && let (Some(s), Some(e)) = (crate::profiles::parse_hhmm(&cfg.quiet.start), crate::profiles::parse_hhmm(&cfg.quiet.end))
            && in_window(local_min, s, e)
        {
            return Err(Suppress::Quiet);
        }
        let key = format!("{}|{title}", kind.as_str());
        if cfg.dedupe_secs > 0
            && self.last_sent.get(&key).is_some_and(|t| now.saturating_sub(*t) < cfg.dedupe_secs)
        {
            return Err(Suppress::Dedupe);
        }
        while self.window.front().is_some_and(|t| now.saturating_sub(*t) >= 3600) {
            self.window.pop_front();
        }
        if self.window.len() >= cfg.rate_per_hour as usize {
            return Err(Suppress::Rate);
        }
        self.window.push_back(now);
        if self.last_sent.len() >= DEDUPE_MAP_CAP {
            let horizon = cfg.dedupe_secs.max(1);
            self.last_sent.retain(|_, t| now.saturating_sub(*t) < horizon);
            if self.last_sent.len() >= DEDUPE_MAP_CAP {
                self.last_sent.clear();
            }
        }
        self.last_sent.insert(key, now);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NotifyRuntime {
    pub gate: Gate,
    pub sent: BTreeMap<&'static str, u64>,
    pub failed: BTreeMap<&'static str, u64>,
    pub suppressed: BTreeMap<&'static str, u64>,
    /// Events dropped because the notifier queue was full.
    pub dropped: u64,
    pub last_error: Option<serde_json::Value>,
    pub last_sent_at: u64,
}

pub const SINKS: [&str; 3] = ["email", "webhook", "ntfy"];

// ---------------------------------------------------------------------------
// Payload builders (pure)
// ---------------------------------------------------------------------------

pub fn rfc3339(ts: u64) -> String {
    let (d, s) = super::usage_cycle::civil_from_unix(ts as i64, 0);
    format!("{}T{:02}:{:02}:{:02}Z", d.ymd(), s / 3600, (s % 3600) / 60, s % 60)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').take(64).collect::<String>())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "quecmanager".into())
}

pub fn detail_text(detail: &serde_json::Value) -> String {
    match detail {
        serde_json::Value::Object(m) if !m.is_empty() => m
            .iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => format!("{k}: {s}"),
                other => format!("{k}: {other}"),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn webhook_body(n: &Notice, fmt: WebhookFormat, host: &str, version: &str) -> String {
    let v = match fmt {
        WebhookFormat::Json => serde_json::json!({
            "source": "quecmanager",
            "host": host,
            "version": version,
            "event": n,
        }),
        WebhookFormat::Alertmanager => serde_json::json!([{
            "labels": {
                "alertname": format!("CellCore_{}", n.kind),
                "severity": n.severity.as_str(),
                "instance": host,
                "type": n.kind,
                "job": "quecmanager",
            },
            "annotations": {
                "summary": n.title,
                "description": detail_text(&n.detail),
            },
            "startsAt": rfc3339(n.ts),
            // Events are points in time: let Alertmanager resolve them.
            "endsAt": rfc3339(n.ts + 900),
        }]),
    };
    v.to_string()
}

/// ntfy JSON publishing: POST to the server root with the topic in the body
/// (UTF-8 titles work this way, unlike the Title header).
pub fn ntfy_target(url: &str) -> Result<(String, String), String> {
    let (base, topic) = url.trim().trim_end_matches('/').rsplit_once('/').ok_or("ntfy URL must end in /<topic>")?;
    if base.len() < 8 || !base[..8].eq_ignore_ascii_case("https://") {
        return Err("ntfy URL must be https://server/<topic>".into());
    }
    let server = &base[8..];
    if server.is_empty()
        || server.starts_with('/')
        || server.ends_with('/')
        || server.starts_with(':')
        || server.ends_with(':')
        || server.chars().any(char::is_whitespace)
    {
        return Err("ntfy URL must be https://server/<topic>".into());
    }
    if topic.is_empty() || topic.len() > 64 || !topic.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("ntfy topic must be 1-64 letters, digits, '-' or '_'".into());
    }
    Ok((format!("https://{server}/"), topic.to_string()))
}

pub fn ntfy_body(n: &Notice, topic: &str) -> String {
    let priority = match n.severity {
        Severity::Critical => 5,
        Severity::Warning => 4,
        Severity::Info => 3,
    };
    let msg = {
        let d = detail_text(&n.detail);
        if d.is_empty() { n.title.clone() } else { d }
    };
    serde_json::json!({
        "topic": topic,
        "title": n.title,
        "message": msg,
        "priority": priority,
        "tags": [n.kind],
    })
    .to_string()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// One header line, no CR/LF; RFC 2047 encoded when not plain ASCII.
pub fn mail_header_value(s: &str) -> String {
    let clean: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    if clean.is_ascii() { clean } else { format!("=?UTF-8?B?{}?=", b64(clean.as_bytes())) }
}

pub fn email_message(recipient: &str, n: &Notice, host: &str) -> String {
    let mut body = format!("{}\n\nSeverity: {}\nType: {}\nTime: {}\nHost: {host}\n", n.title, n.severity.as_str(), n.kind, rfc3339(n.ts));
    let d = detail_text(&n.detail);
    if !d.is_empty() {
        body.push('\n');
        body.push_str(&d);
        body.push('\n');
    }
    // Dot-lines and bare CRs are left to msmtp; strip other controls.
    let body: String = body.chars().filter(|c| *c == '\n' || !c.is_control()).collect();
    format!(
        "To: {recipient}\nSubject: {}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n{body}",
        mail_header_value(&format!("[CellCore] {}", n.title))
    )
}

/// Quote a value for a curl config file line.
pub fn curl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The complete curl request as a config read from stdin (`curl -q -K -`).
pub fn curl_config(url: &str, headers: &[(String, String)], body: &str) -> String {
    let mut cfg = String::from("silent\nshow-error\nfail\nproto = \"=http,https\"\nmax-time = 12\nconnect-timeout = 6\nrequest = \"POST\"\n");
    cfg.push_str(&format!("url = {}\n", curl_quote(url)));
    cfg.push_str("header = \"Content-Type: application/json\"\n");
    for (k, v) in headers {
        cfg.push_str(&format!("header = {}\n", curl_quote(&format!("{k}: {v}"))));
    }
    // data-raw: a leading '@' is never read as a file name.
    cfg.push_str(&format!("data-raw = {}\n", curl_quote(body)));
    cfg
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

async fn curl_post(url: &str, headers: &[(String, String)], body: &str) -> Result<(), String> {
    // Re-validate at send time: the stored config may predate a validator.
    let url = super::config::validate_url(url)?;
    for (k, v) in headers {
        super::config::validate_header_name(k)?;
        super::config::validate_header_value(v)?;
    }
    let cfg = curl_config(&url, headers, body);
    let out = run("curl", &["-q", "-K", "-"], ExecOpts::new(SINK_TIMEOUT_SECS, 16 * KIB).stdin(cfg.into_bytes())).await?;
    if out.ok() { Ok(()) } else { Err(out.err_summary("curl")) }
}

pub fn email_ready() -> Option<String> {
    if !Path::new(&crate::paths::p(MSMTPRC)).exists() {
        return None;
    }
    let r = std::fs::read_to_string(crate::paths::p(RECIPIENT_FILE)).ok()?.trim().to_string();
    crate::handlers::is_plain_email(&r).then_some(r)
}

async fn send_email(n: &Notice, host: &str) -> Result<(), String> {
    let recip = email_ready().ok_or("Email is not configured (set the sender and recipient under Alerts first)")?;
    let msg = email_message(&recip, n, host);
    let out = run("msmtp", &["-C", &crate::paths::p(MSMTPRC), "--", &recip], ExecOpts::new(SINK_TIMEOUT_SECS + 15, 16 * KIB).stdin(msg.into_bytes())).await?;
    if out.ok() { Ok(()) } else { Err(out.err_summary("msmtp")) }
}

async fn send_webhook(w: &WebhookSink, n: &Notice, host: &str, version: &str) -> Result<(), String> {
    let headers: Vec<(String, String)> = w.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect();
    curl_post(&w.url, &headers, &webhook_body(n, w.format, host, version)).await
}

async fn send_ntfy(s: &NtfySink, n: &Notice) -> Result<(), String> {
    let (base, topic) = ntfy_target(&s.url)?;
    let mut headers = Vec::new();
    if !s.token.is_empty() {
        headers.push(("Authorization".to_string(), format!("Bearer {}", s.token)));
    }
    curl_post(&base, &headers, &ntfy_body(n, &topic)).await
}

/// Send to every enabled sink (or only `only`); returns per-sink results.
pub async fn dispatch(cfg: &NotifyConfig, n: &Notice, only: Option<&str>) -> Vec<(&'static str, Result<(), String>)> {
    let host = hostname();
    let version = env!("CARGO_PKG_VERSION");
    let mut res = Vec::new();
    let want = |s: &str, enabled: bool| only.map_or(enabled, |o| o == s);
    if want("email", cfg.email.enabled) {
        res.push(("email", send_email(n, &host).await));
    }
    if want("webhook", cfg.webhook.enabled) {
        let r = if cfg.webhook.url.is_empty() { Err("Webhook URL is not set".into()) } else { send_webhook(&cfg.webhook, n, &host, version).await };
        res.push(("webhook", r));
    }
    if want("ntfy", cfg.ntfy.enabled) {
        let r = if cfg.ntfy.url.is_empty() { Err("ntfy URL is not set".into()) } else { send_ntfy(&cfg.ntfy, n).await };
        res.push(("ntfy", r));
    }
    let mut rt = lock(&obs().notify);
    for (sink, r) in &res {
        match r {
            Ok(()) => {
                *rt.sent.entry(sink).or_insert(0) += 1;
                rt.last_sent_at = now_secs();
            }
            Err(e) => {
                *rt.failed.entry(sink).or_insert(0) += 1;
                rt.last_error = Some(serde_json::json!({ "sink": sink, "error": e, "ts": now_secs() }));
            }
        }
    }
    res
}

fn local_minute() -> u16 {
    let (_, secs) = super::usage_cycle::local_now();
    (secs / 60) as u16
}

pub async fn run_notifier(mut rx: mpsc::Receiver<Event>) {
    while let Some(ev) = rx.recv().await {
        let cfg = lock(&obs().config).notify.clone();
        let verdict = lock(&obs().notify).gate.decide(&cfg, ev.kind, ev.severity, &ev.title, now_secs(), local_minute());
        match verdict {
            Err(why) => {
                *lock(&obs().notify).suppressed.entry(why.as_str()).or_insert(0) += 1;
            }
            Ok(()) => {
                let _ = dispatch(&cfg, &Notice::from(&ev), None).await;
            }
        }
    }
}

pub async fn send_test(only: Option<&str>) -> serde_json::Value {
    let cfg = lock(&obs().config).notify.clone();
    let n = Notice {
        id: 0,
        ts: now_secs(),
        kind: "test".into(),
        severity: Severity::Info,
        title: "CellCore test notification".into(),
        detail: serde_json::json!({ "note": "If you can read this, this channel works." }),
    };
    let res = dispatch(&cfg, &n, only).await;
    let results: Vec<_> = res
        .iter()
        .map(|(s, r)| serde_json::json!({ "sink": s, "ok": r.is_ok(), "error": r.as_ref().err() }))
        .collect();
    serde_json::json!({ "results": results })
}

pub fn status_json() -> serde_json::Value {
    let rt = lock(&obs().notify);
    serde_json::json!({
        "sent": rt.sent,
        "failed": rt.failed,
        "suppressed": rt.suppressed,
        "dropped": rt.dropped,
        "lastError": rt.last_error,
        "lastSentAt": rt.last_sent_at,
        "emailReady": email_ready().is_some(),
    })
}

// ---------------------------------------------------------------------------
// Optional carrier-SMS forwarding (the one feature that adds AT traffic)
// ---------------------------------------------------------------------------

pub fn sms_key(sender: &str, timestamp: &str, text: &str) -> String {
    let mut h = Sha256::new();
    h.update(sender.as_bytes());
    h.update([0]);
    h.update(timestamp.as_bytes());
    h.update([0]);
    h.update(text.as_bytes());
    hex::encode(&h.finalize()[..12])
}

/// Which of `keys` are new. The first poll after enabling only learns what
/// is already in the inbox (no flood of old messages).
pub fn sms_new(seen: &mut VecDeque<String>, initialized: &mut bool, keys: &[String]) -> Vec<usize> {
    let mut new = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        if seen.contains(k) {
            continue;
        }
        if *initialized {
            new.push(i);
        }
        if seen.len() >= SMS_SEEN_CAP {
            seen.pop_front();
        }
        seen.push_back(k.clone());
    }
    *initialized = true;
    new
}

pub async fn sms_forward_tick(state: &AppState) {
    let cmds = vec![
        ("AT+CMGF=0".into(), std::time::Duration::from_secs(4)),
        ("AT+CPMS=\"ME\",\"ME\",\"ME\"".into(), std::time::Duration::from_secs(4)),
        ("AT+CMGL=4".into(), std::time::Duration::from_secs(10)),
    ];
    let Ok(res) = state.smd.exec_batch(cmds, Priority::Background).await else {
        return;
    };
    let Some(Ok(cmgl)) = res.get(2) else {
        return;
    };
    let msgs = crate::sms::parse_cmgl_response(&cmgl.body);
    let keys: Vec<String> = msgs.iter().map(|m| sms_key(&m.sender, &m.timestamp, &m.text)).collect();
    let new = {
        let mut p = lock(&obs().persisted);
        let mut init = p.sms_seen_initialized;
        let n = sms_new(&mut p.sms_seen, &mut init, &keys);
        p.sms_seen_initialized = init;
        n
    };
    for i in new {
        let m = &msgs[i];
        let text: String = m.text.chars().take(480).collect();
        emit(
            EventKind::SmsReceived,
            Severity::Info,
            format!("SMS from {}", m.sender.chars().take(32).collect::<String>()),
            serde_json::json!({ "from": m.sender, "time": m.timestamp, "text": text }),
        );
    }
}

/// Reset the "first poll learns the inbox" state when forwarding is turned on.
pub fn sms_forward_enabled_changed(enabled: bool) {
    if enabled {
        lock(&obs().persisted).sms_seen_initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obs::config::QuietHours;

    fn cfg() -> NotifyConfig {
        NotifyConfig { enabled: true, dedupe_secs: 600, rate_per_hour: 3, ..Default::default() }
    }

    #[test]
    fn gate_type_enable_and_defaults() {
        let mut g = Gate::default();
        let mut c = cfg();
        assert_eq!(g.decide(&c, EventKind::Handover, Severity::Info, "h", 0, 600), Err(Suppress::TypeOff), "handover is off by default");
        c.kinds.insert("handover".into(), true);
        assert_eq!(g.decide(&c, EventKind::Handover, Severity::Info, "h", 0, 600), Ok(()));
        c.kinds.insert("registration_lost".into(), false);
        assert_eq!(g.decide(&c, EventKind::RegistrationLost, Severity::Critical, "x", 0, 600), Err(Suppress::TypeOff));
        c.enabled = false;
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "x", 0, 600), Err(Suppress::Disabled));
    }

    #[test]
    fn gate_dedupes_within_window() {
        let mut g = Gate::default();
        let c = cfg();
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "A", 100, 0), Ok(()));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "A", 699, 0), Err(Suppress::Dedupe));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "B", 699, 0), Ok(()), "different title");
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "A", 700, 0), Ok(()), "window passed");
    }

    #[test]
    fn gate_rate_limits_per_rolling_hour() {
        let mut g = Gate::default();
        let c = cfg();
        for (i, t) in [0u64, 10, 20].iter().enumerate() {
            assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, &format!("e{i}"), *t, 0), Ok(()));
        }
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "e3", 30, 0), Err(Suppress::Rate));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "e3", 3599, 0), Err(Suppress::Rate));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "e3", 3600, 0), Ok(()), "first slot freed");
        // a rate-limited event does not consume the dedupe key
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "e4", 3601, 0), Err(Suppress::Rate));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "e4", 3610, 0), Ok(()));
    }

    #[test]
    fn gate_quiet_hours_wrap_midnight_and_let_critical_through() {
        let mut g = Gate::default();
        let mut c = cfg();
        c.rate_per_hour = 100;
        c.dedupe_secs = 0;
        c.quiet = QuietHours { enabled: true, start: "22:00".into(), end: "07:00".into(), allow_critical: true };
        let at = |h: u16, m: u16| h * 60 + m;
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "q", 0, at(23, 30)), Err(Suppress::Quiet));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "q", 0, at(6, 59)), Err(Suppress::Quiet));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "q", 0, at(7, 0)), Ok(()));
        assert_eq!(g.decide(&c, EventKind::FailoverStart, Severity::Warning, "q", 0, at(21, 59)), Ok(()));
        assert_eq!(g.decide(&c, EventKind::RegistrationLost, Severity::Critical, "q", 0, at(2, 0)), Ok(()));
        c.quiet.allow_critical = false;
        assert_eq!(g.decide(&c, EventKind::RegistrationLost, Severity::Critical, "q", 0, at(2, 0)), Err(Suppress::Quiet));
        assert!(!in_window(100, 100, 100), "empty window");
        assert!(in_window(600, 540, 1020));
    }

    #[test]
    fn dedupe_map_is_bounded() {
        let mut g = Gate::default();
        let mut c = cfg();
        c.rate_per_hour = u32::MAX;
        for i in 0..(DEDUPE_MAP_CAP as u64 * 3) {
            let _ = g.decide(&c, EventKind::FailoverStart, Severity::Warning, &format!("t{i}"), i, 0);
        }
        assert!(g.last_sent.len() <= DEDUPE_MAP_CAP);
    }

    fn notice() -> Notice {
        Notice {
            id: 7,
            ts: 1_772_953_200,
            kind: "failover_start".into(),
            severity: Severity::Warning,
            title: "Carrying \"failover\" traffic → now".into(),
            detail: serde_json::json!({ "source": "hint" }),
        }
    }

    #[test]
    fn curl_config_cannot_be_escaped() {
        let body = webhook_body(&notice(), WebhookFormat::Json, "mgw", "4.1.1");
        let cfg = curl_config("https://h/x", &[("X-Token".into(), "abc".into())], &body);
        // every line is a known directive; the JSON body stays on one quoted line
        for line in cfg.lines() {
            let ok = ["silent", "show-error", "fail"].contains(&line)
                || ["proto = ", "max-time = ", "connect-timeout = ", "request = ", "url = ", "header = ", "data-raw = "].iter().any(|p| line.starts_with(p));
            assert!(ok, "unexpected line {line:?}");
        }
        assert_eq!(cfg.lines().filter(|l| l.starts_with("data-raw")).count(), 1);
        assert!(cfg.contains(r#"\"title\":\"Carrying \\\"failover\\\" traffic → now\""#), "{cfg}");
        let evil = curl_quote("a\"\nurl = \"file:///etc/shadow");
        assert!(!evil.contains('\n'));
        assert_eq!(evil.matches('"').count() - evil.matches("\\\"").count(), 2, "only the outer quotes are live");
    }

    #[test]
    fn alertmanager_payload_shape() {
        let v: serde_json::Value = serde_json::from_str(&webhook_body(&notice(), WebhookFormat::Alertmanager, "mgw", "4.1.1")).unwrap();
        let a = &v[0];
        assert_eq!(a["labels"]["alertname"], "CellCore_failover_start");
        assert_eq!(a["labels"]["severity"], "warning");
        assert_eq!(a["labels"]["instance"], "mgw");
        assert_eq!(a["startsAt"], "2026-03-08T07:00:00Z");
        assert_eq!(a["endsAt"], "2026-03-08T07:15:00Z");
        assert_eq!(a["annotations"]["description"], "source: hint");
        let j: serde_json::Value = serde_json::from_str(&webhook_body(&notice(), WebhookFormat::Json, "mgw", "4.1.1")).unwrap();
        assert_eq!(j["event"]["type"], "failover_start");
        assert_eq!(j["event"]["id"], 7);
    }

    #[test]
    fn ntfy_url_and_body() {
        assert_eq!(ntfy_target("https://ntfy.sh/my-topic").unwrap(), ("https://ntfy.sh/".into(), "my-topic".into()));
        assert_eq!(ntfy_target("HTTPS://ntfy.sh/my-topic").unwrap(), ("https://ntfy.sh/".into(), "my-topic".into()));
        assert_eq!(ntfy_target("https://n.example.com/sub/alerts_1/").unwrap(), ("https://n.example.com/sub/".into(), "alerts_1".into()));
        assert!(ntfy_target("https://ntfy.sh").is_err());
        assert!(ntfy_target("https://ntfy.sh/a.b").is_err());
        assert!(ntfy_target("http://ntfy.sh/my-topic").is_err());
        assert!(ntfy_target("https:///my-topic").is_err());
        assert!(ntfy_target("https://ntfy.sh//my-topic").is_err());
        let b: serde_json::Value = serde_json::from_str(&ntfy_body(&notice(), "t")).unwrap();
        assert_eq!(b["priority"], 4);
        assert_eq!(b["topic"], "t");
        assert_eq!(b["tags"][0], "failover_start");
    }

    #[test]
    fn email_headers_cannot_be_injected() {
        let mut n = notice();
        n.title = "evil\r\nBcc: victim@example.com".into();
        let m = email_message("me@example.com", &n, "mgw");
        let (headers, _) = m.split_once("\n\n").unwrap();
        assert!(!headers.lines().any(|l| l.starts_with("Bcc")), "{headers}");
        assert_eq!(headers.lines().count(), 5);
        let enc = mail_header_value("[CellCore] Band n41 → n71");
        assert!(enc.starts_with("=?UTF-8?B?") && enc.is_ascii());
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
        assert_eq!(b64(b"M"), "TQ==");
    }

    #[test]
    fn sms_first_poll_learns_then_reports_new() {
        let mut seen = VecDeque::new();
        let mut init = false;
        let k = |s: &str| sms_key("+1555", "26/11/18", s);
        assert!(sms_new(&mut seen, &mut init, &[k("old1"), k("old2")]).is_empty());
        assert_eq!(sms_new(&mut seen, &mut init, &[k("old1"), k("new"), k("old2")]), vec![1]);
        assert!(sms_new(&mut seen, &mut init, &[k("new")]).is_empty());
        assert_ne!(k("a"), sms_key("+1555", "26/11/18", "b"));
        for i in 0..(SMS_SEEN_CAP * 2) {
            sms_new(&mut seen, &mut init, &[k(&i.to_string())]);
        }
        assert!(seen.len() <= SMS_SEEN_CAP);
    }
}

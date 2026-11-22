//! Audit log of mutating requests and security-relevant events.
//!
//! * A middleware on the protected router records every POST/PUT/PATCH/DELETE:
//!   time, method, route template, status, peer, auth kind (session / token +
//!   token name) and a **redacted** summary of the query and JSON body.
//! * Out-of-band events (firewall auto-rollback, IPC recovery actions from
//!   Route10, failed token authentication) are recorded with [`AuditLog::event`].
//! * Entries live in a bounded RAM ring, go to syslog (`logger`, argv only)
//!   and are persisted with the crash-safe writer in two rotating segments.
//!
//! Redaction is allowlist-based: a body value is only ever shown when its key
//! is in [`SHOWN_KEYS`] *and* its name does not look secret *and* the value
//! survives [`scrub_value`] (identifier-length digit runs and long token-like
//! runs are replaced). Every other value is logged as `<redacted>`.

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

pub const AUDIT_DIR: &str = "/etc/cellcore/audit";
const SEGMENT_FILE: &str = "audit.json";
const ROTATED_FILE: &str = "audit.1.json";
/// Entries per persisted segment; two segments (current + rotated) are kept.
pub const SEGMENT_CAP: usize = 200;
/// RAM ring size (both segments).
pub const RING_CAP: usize = SEGMENT_CAP * 2;
/// Bodies above this are not read by the audit layer (only their size is logged).
pub const MAX_CAPTURE: usize = 64 * 1024;
const SUMMARY_CAP: usize = 600;
const VALUE_CAP: usize = 80;
const FLUSH_DEBOUNCE: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: u64,
    pub ts: u64,
    /// `http` for a request, `event` for an out-of-band record.
    pub kind: String,
    pub method: String,
    pub route: String,
    pub status: u16,
    pub peer: String,
    /// `session`, `token`, `ipc`, `system`.
    pub auth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_name: Option<String>,
    pub summary: String,
}

/// Failed authentication, aggregated per peer. Kept apart from the entry
/// ring so unauthenticated traffic can never evict real audit records.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthFailure {
    pub peer: String,
    pub count: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub last_route: String,
}

/// Peers tracked individually; the rest only bump `overflow`.
pub const AUTH_FAIL_PEERS: usize = 32;
/// A peer's counter restarts after this long without failures.
const AUTH_FAIL_WINDOW: u64 = 3600;

/// GET requests made with an API token, aggregated per token name.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenReads {
    pub token_name: String,
    pub count: u64,
    pub errors: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub last_route: String,
    pub last_peer: String,
}

/// Token names tracked (MAX_TOKENS plus room for revoked ones).
const TOKEN_READ_SLOTS: usize = 32;

#[derive(Default)]
struct FailInner {
    peers: Vec<AuthFailure>,
    overflow: u64,
}

#[derive(Default)]
struct Inner {
    ring: VecDeque<AuditEntry>,
    segment: Vec<AuditEntry>,
    next_id: u64,
    dirty: bool,
}

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<Inner>>,
    failures: Arc<Mutex<FailInner>>,
    token_reads: Arc<Mutex<Vec<TokenReads>>>,
    dir: Option<Arc<PathBuf>>,
    syslog: bool,
    wake: Arc<Notify>,
}

/// One request/event to record (the log fills in id and time).
pub struct NewEntry<'a> {
    pub kind: &'a str,
    pub method: &'a str,
    pub route: &'a str,
    pub status: u16,
    pub peer: &'a str,
    pub auth: &'a str,
    pub token_name: Option<&'a str>,
    pub summary: String,
}

/// Extra detail a handler attaches to its response for the audit record
/// (e.g. the AT classification). Must not contain secrets; it is scrubbed anyway.
#[derive(Clone, Debug)]
pub struct AuditNote(pub String);

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub method: Option<String>,
    pub route: Option<String>,
    pub auth: Option<String>,
    pub token: Option<String>,
    /// `ok` (< 400), `error` (>= 400) or an exact code.
    pub status: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AuditLog {
    /// `dir = None` keeps the log in RAM only (tests).
    pub fn new(dir: Option<PathBuf>, syslog: bool) -> Self {
        let mut inner = Inner::default();
        if let Some(d) = &dir {
            let old: Vec<AuditEntry> = read_segment(&d.join(ROTATED_FILE));
            let cur: Vec<AuditEntry> = read_segment(&d.join(SEGMENT_FILE));
            for e in old.iter().chain(cur.iter()) {
                inner.next_id = inner.next_id.max(e.id + 1);
                inner.ring.push_back(e.clone());
            }
            while inner.ring.len() > RING_CAP {
                inner.ring.pop_front();
            }
            inner.segment = cur;
        }
        Self {
            inner: Arc::new(Mutex::new(inner)),
            failures: Arc::new(Mutex::new(FailInner::default())),
            token_reads: Arc::new(Mutex::new(Vec::new())),
            dir: dir.map(Arc::new),
            syslog,
            wake: Arc::new(Notify::new()),
        }
    }

    #[cfg(test)]
    pub fn ram_only() -> Self {
        Self::new(None, false)
    }

    /// Background flusher: coalesces writes so a burst of requests costs one
    /// flash write. Call once from the daemon's runtime.
    pub fn spawn_flusher(&self) {
        if self.dir.is_none() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                me.wake.notified().await;
                tokio::time::sleep(FLUSH_DEBOUNCE).await;
                let m = me.clone();
                let _ = tokio::task::spawn_blocking(move || m.flush_now()).await;
            }
        });
    }

    pub fn record(&self, e: NewEntry<'_>) -> AuditEntry {
        let entry = {
            let mut g = lock(&self.inner);
            let entry = AuditEntry {
                id: g.next_id,
                ts: crate::auth::now_secs(),
                kind: e.kind.to_string(),
                method: e.method.to_string(),
                route: clip(&scrub_value(e.route), 160),
                status: e.status,
                peer: clip(e.peer, 64),
                auth: e.auth.to_string(),
                token_name: e.token_name.map(|n| clip(&scrub_value(n), 40)),
                summary: clip(&scrub_value(&e.summary), SUMMARY_CAP),
            };
            g.next_id += 1;
            g.ring.push_back(entry.clone());
            while g.ring.len() > RING_CAP {
                g.ring.pop_front();
            }
            g.segment.push(entry.clone());
            g.dirty = true;
            entry
        };
        self.wake.notify_one();
        if self.syslog {
            let line = syslog_line(&entry);
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    let _ = crate::uci::run_cmd("logger", &["-t", "cellcored-audit", "-p", "authpriv.notice", &line], Duration::from_secs(3)).await;
                });
            }
        }
        entry
    }

    /// Count a failed (unauthenticated) API-token attempt. Bounded memory:
    /// at most [`AUTH_FAIL_PEERS`] peers, everything else is a single counter.
    /// Syslog gets one line per peer per window, not one per attempt.
    pub fn auth_failure(&self, peer: &str, route: &str) {
        let now = crate::auth::now_secs();
        let first_in_window = {
            let mut g = self.failures.lock().unwrap_or_else(|e| e.into_inner());
            g.peers.retain(|f| now.saturating_sub(f.last_ts) <= AUTH_FAIL_WINDOW);
            if let Some(f) = g.peers.iter_mut().find(|f| f.peer == peer) {
                f.count += 1;
                f.last_ts = now;
                f.last_route = clip(&scrub_value(route), 120);
                false
            } else if g.peers.len() < AUTH_FAIL_PEERS {
                g.peers.push(AuthFailure {
                    peer: clip(peer, 64),
                    count: 1,
                    first_ts: now,
                    last_ts: now,
                    last_route: clip(&scrub_value(route), 120),
                });
                true
            } else {
                g.overflow += 1;
                false
            }
        };
        if first_in_window && self.syslog {
            let line = format!("API token authentication failed from {} on {}", clip(peer, 64), clip(&scrub_value(route), 120));
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    let _ = crate::uci::run_cmd("logger", &["-t", "cellcored-audit", "-p", "authpriv.warning", &line], Duration::from_secs(3)).await;
                });
            }
        }
    }

    /// Count a GET made with an API token (bounded: the least recently used
    /// name is replaced when all slots are taken).
    pub fn token_read(&self, name: &str, route: &str, peer: &str, status: u16) {
        let now = crate::auth::now_secs();
        let mut g = self.token_reads.lock().unwrap_or_else(|e| e.into_inner());
        let name = clip(&scrub_value(name), 40);
        let idx = match g.iter().position(|t| t.token_name == name) {
            Some(i) => i,
            None => {
                if g.len() >= TOKEN_READ_SLOTS
                    && let Some(oldest) = g.iter().enumerate().min_by_key(|(_, t)| t.last_ts).map(|(i, _)| i)
                {
                    g.remove(oldest);
                }
                g.push(TokenReads {
                    token_name: name,
                    count: 0,
                    errors: 0,
                    first_ts: now,
                    last_ts: now,
                    last_route: String::new(),
                    last_peer: String::new(),
                });
                g.len() - 1
            }
        };
        let t = &mut g[idx];
        t.count += 1;
        if status >= 400 {
            t.errors += 1;
        }
        t.last_ts = now;
        t.last_route = clip(&scrub_value(route), 120);
        t.last_peer = clip(peer, 64);
    }

    pub fn token_reads(&self) -> Vec<TokenReads> {
        let mut v = self.token_reads.lock().unwrap_or_else(|e| e.into_inner()).clone();
        v.sort_by_key(|t| std::cmp::Reverse(t.last_ts));
        v
    }

    /// Aggregated auth failures (most recent first) and the overflow counter.
    pub fn auth_failures(&self) -> (Vec<AuthFailure>, u64) {
        let g = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = g.peers.clone();
        v.sort_by_key(|f| std::cmp::Reverse(f.last_ts));
        (v, g.overflow)
    }

    /// Out-of-band event (no HTTP request behind it).
    pub fn event(&self, auth: &str, action: &str, summary: impl Into<String>) {
        self.record(NewEntry {
            kind: "event",
            method: "-",
            route: action,
            status: 0,
            peer: "local",
            auth,
            token_name: None,
            summary: summary.into(),
        });
    }

    /// Persist the current segment (rotating when full). Synchronous: call from
    /// a blocking context or at shutdown.
    pub fn flush_now(&self) {
        let Some(dir) = self.dir.as_deref() else { return };
        let (segment, rotate) = {
            let mut g = lock(&self.inner);
            if !g.dirty {
                return;
            }
            g.dirty = false;
            let rotate = g.segment.len() >= SEGMENT_CAP;
            let seg = if rotate { std::mem::take(&mut g.segment) } else { g.segment.clone() };
            (seg, rotate)
        };
        let _ = fs::create_dir_all(dir);
        let cur = dir.join(SEGMENT_FILE);
        let Ok(json) = serde_json::to_vec(&segment) else { return };
        if rotate {
            // Full segment becomes the rotated file; the current one restarts empty.
            let _ = crate::state::atomic_write(&dir.join(ROTATED_FILE), &json, 0o600);
            let _ = crate::state::atomic_write(&cur, b"[]", 0o600);
        } else {
            let _ = crate::state::atomic_write(&cur, &json, 0o600);
        }
    }

    /// Newest first, filtered.
    pub fn query(&self, f: &AuditFilter) -> Vec<AuditEntry> {
        let limit = f.limit.unwrap_or(200).clamp(1, RING_CAP);
        let lc = |s: &Option<String>| s.as_ref().map(|x| x.trim().to_ascii_lowercase()).filter(|x| !x.is_empty());
        let (method, route, auth, token, q) = (lc(&f.method), lc(&f.route), lc(&f.auth), lc(&f.token), lc(&f.q));
        let status = lc(&f.status);
        let g = lock(&self.inner);
        g.ring
            .iter()
            .rev()
            .filter(|e| f.since.is_none_or(|s| e.ts >= s))
            .filter(|e| f.until.is_none_or(|u| e.ts <= u))
            .filter(|e| method.as_ref().is_none_or(|m| e.method.eq_ignore_ascii_case(m)))
            .filter(|e| route.as_ref().is_none_or(|r| e.route.to_ascii_lowercase().contains(r.as_str())))
            .filter(|e| auth.as_ref().is_none_or(|a| e.auth.eq_ignore_ascii_case(a)))
            .filter(|e| token.as_ref().is_none_or(|t| e.token_name.as_ref().is_some_and(|n| n.to_ascii_lowercase().contains(t.as_str()))))
            .filter(|e| match status.as_deref() {
                None => true,
                Some("ok") => e.status < 400,
                Some("error") => e.status >= 400,
                Some(code) => code.parse::<u16>().is_ok_and(|c| c == e.status),
            })
            .filter(|e| {
                q.as_ref().is_none_or(|q| {
                    e.summary.to_ascii_lowercase().contains(q.as_str()) || e.route.to_ascii_lowercase().contains(q.as_str())
                })
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).ring.len()
    }
}

fn read_segment(p: &Path) -> Vec<AuditEntry> {
    fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn syslog_line(e: &AuditEntry) -> String {
    let who = match &e.token_name {
        Some(n) => format!("{}:{n}", e.auth),
        None => e.auth.clone(),
    };
    // Control characters are already impossible (scrub_value), keep it one line anyway.
    format!("{} {} status={} peer={} auth={} {}", e.method, e.route, e.status, e.peer, who, e.summary)
        .replace(['\n', '\r'], " ")
}

// ───────────────────────────── Redaction ─────────────────────────────

/// Keys whose (scrubbed) values may appear in the log. Everything else is `<redacted>`.
pub const SHOWN_KEYS: &[&str] = &[
    // generic
    "action", "enabled", "enable", "mode", "type", "kind", "index", "id", "name", "confirm", "dryRun", "items", "scopes",
    "expiresInDays", "version", "limit", "count", "target", "tool", "signal", "pid", "service", "rat", "persist",
    // radio
    "pci", "arfcn", "scs", "band", "lteBands", "nsaNr5gBands", "nr5gBands", "modePref", "nr5gDisableMode", "simSlot",
    "profileName", "paused", "pdpType", "apn", "networkType", "mobileProvider", "mbnProfile", "timeoutSecs",
    "scheduleEnabled", "startTime", "endTime",
    // network / settings
    "slot", "ttl", "hl", "mtu", "nic", "servers", "temperatureUnit", "measurementUnit", "httpsRedirect", "billingCycleDay",
    "quotaBytes", "host", "interval", "keepAlive", "pingTarget", "pingInterval", "pingFailures", "maxRetries",
    "connectionRefresh", "autoSimFailover", "highLatencyMonitoring", "latencyCeiling", "scheduledRebootEnabled",
    "scheduledRebootTime", "scheduledRebootDays", "serverId",
    // admin module
    "hostname", "timezone", "zonename", "ntpEnabled", "ntpServers", "port", "proto", "src", "dest", "srcDport", "destIp",
    "destPort", "family", "section", "mac", "ip", "leasetime", "package", "packages", "includeIdentifiers",
    // vpn module (secrets such as licenseKey, teamToken, clientId/Secret, authKey, tunnelToken stay redacted)
    "team", "acceptRoutes", "advertiseRoutes", "advertiseExitNode", "exitNode", "ssh", "shieldsUp", "keepalive",
    "endpoint", "autostart", "deleteAccount", "force", "lanDevice",
    "edgeIpVersion", "protocol", "loopbackIp", "deleteToken", "deleteBinary",
];

/// Substrings that make a key secret regardless of the allowlist.
const SECRET_KEY_MARKERS: &[&str] = &[
    "pass", "secret", "token", "key", "imei", "iccid", "imsi", "auth", "cred", "psk", "cookie", "csrf", "smtp", "signature",
    "cert", "private", "salt", "hash", "session", "bearer",
];
/// Short secret names matched exactly (as substrings they would hit `ping`, `output`, ...).
const SECRET_KEY_EXACT: &[&str] = &["pin", "pin1", "pin2", "puk", "otp", "sig"];

pub fn key_is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEY_MARKERS.iter().any(|m| k.contains(m)) || SECRET_KEY_EXACT.contains(&k.as_str())
}

fn key_is_shown(key: &str) -> bool {
    SHOWN_KEYS.contains(&key) && !key_is_secret(key)
}

/// Replace identifier-length digit runs (IMEI 15, IMSI 15, ICCID 18-20 and
/// anything >= 14 digits) and long token-like runs (>= 24 chars of
/// `[A-Za-z0-9_-]`: session tokens, API tokens, keys); drop control chars.
pub fn scrub_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.is_empty() {
            return;
        }
        let digits = run.bytes().filter(u8::is_ascii_digit).count();
        let longest_digits = run
            .split(|c: char| !c.is_ascii_digit())
            .map(str::len)
            .max()
            .unwrap_or(0);
        if run.len() >= 24 || run.to_ascii_lowercase().starts_with("qmt_") {
            out.push_str("<redacted>");
        } else if longest_digits >= 14 || (digits >= 14 && digits * 2 >= run.len()) {
            out.push_str("<id>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            if ch.is_control() {
                out.push(' ');
            } else {
                out.push(ch);
            }
        }
    }
    flush(&mut run, &mut out);
    out
}

fn shown_scalar(v: &Value) -> Option<String> {
    let raw = match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", clip(&scrub_value(s), VALUE_CAP)),
        _ => return None,
    };
    Some(scrub_value(&raw))
}

fn describe(path: &str, v: &Value, shown: bool, depth: usize, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            if depth >= 3 {
                out.push(format!("{path}={{…}}"));
                return;
            }
            for (k, val) in map.iter().take(24) {
                let kk = clip(&scrub_value(k), 32);
                let p = if path.is_empty() { kk } else { format!("{path}.{kk}") };
                describe(&p, val, key_is_shown(k), depth + 1, out);
            }
            if map.len() > 24 {
                out.push(format!("{path}…(+{} keys)", map.len() - 24));
            }
        }
        Value::Array(items) => {
            if !shown || depth >= 3 {
                out.push(format!("{path}=<redacted:{} items>", items.len()));
                return;
            }
            let mut parts = Vec::new();
            for it in items.iter().take(8) {
                match it {
                    Value::Object(_) | Value::Array(_) => {
                        let mut sub = Vec::new();
                        describe("", it, true, depth + 1, &mut sub);
                        parts.push(format!("{{{}}}", sub.join(" ")));
                    }
                    _ => parts.push(shown_scalar(it).unwrap_or_default()),
                }
            }
            if items.len() > 8 {
                parts.push(format!("…+{}", items.len() - 8));
            }
            out.push(format!("{path}=[{}]", parts.join(",")));
        }
        _ => {
            if shown {
                out.push(format!("{path}={}", shown_scalar(v).unwrap_or_default()));
            } else {
                out.push(format!("{path}=<redacted>"));
            }
        }
    }
}

/// Redacted one-line summary of a JSON body.
pub fn summarize_json(bytes: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return format!("[unparsable JSON body, {} bytes]", bytes.len());
    };
    let mut out = Vec::new();
    match &v {
        Value::Object(_) => describe("", &v, false, 0, &mut out),
        Value::Array(a) => out.push(format!("[array of {}]", a.len())),
        _ => out.push("[scalar body]".into()),
    }
    clip(&out.join(" "), SUMMARY_CAP)
}

/// Redacted summary of a URL query string (same allowlist as bodies).
pub fn summarize_query(q: &str) -> String {
    let mut out = Vec::new();
    for kv in q.split('&').filter(|s| !s.is_empty()).take(16) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let kk = clip(&scrub_value(k), 32);
        if key_is_shown(k) {
            out.push(format!("?{kk}={}", clip(&scrub_value(v), VALUE_CAP)));
        } else {
            out.push(format!("?{kk}=<redacted>"));
        }
    }
    out.join(" ")
}

pub fn summarize_body(content_type: Option<&str>, body: Option<&[u8]>, declared_len: Option<u64>) -> String {
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    match body {
        Some([]) => String::new(),
        Some(b) if ct.contains("json") || b.first().is_some_and(|c| *c == b'{' || *c == b'[') => summarize_json(b),
        Some(b) => format!("[{} bytes {}]", b.len(), clip(&scrub_value(&ct), 40)),
        None => match declared_len {
            Some(0) | None if ct.is_empty() => String::new(),
            Some(n) => format!("[{n} bytes {} not captured]", clip(&scrub_value(&ct), 40)),
            None => format!("[streamed {} body not captured]", clip(&scrub_value(&ct), 40)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_fields_show_others_are_redacted() {
        let s = summarize_json(br#"{"action":"upgrade","version":"4.1.2","password":"hunter2","smtpPassword":"x","foo":"bar"}"#);
        assert!(s.contains("action=\"upgrade\""), "{s}");
        assert!(s.contains("version=\"4.1.2\""), "{s}");
        assert!(s.contains("password=<redacted>"), "{s}");
        assert!(s.contains("smtpPassword=<redacted>"), "{s}");
        assert!(s.contains("foo=<redacted>"), "{s}");
        assert!(!s.contains("hunter2") && !s.contains("bar"), "{s}");
    }

    #[test]
    fn identifiers_are_scrubbed_even_in_shown_fields() {
        let s = summarize_json(br#"{"command":"AT+EGMR=1,7,\"356938035643809\"","name":"89014103211118510720"}"#);
        assert!(!s.contains("356938035643809") && !s.contains("8901410321111851072"), "{s}");
        assert!(s.contains("command=<redacted>"), "raw AT commands are never logged: {s}");
        let t = summarize_json(br#"{"name":"qmt_0123456789abcdef_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#);
        assert!(!t.contains("0123456789abcdef0123"), "{t}");
        let n = summarize_json(br#"{"quotaBytes":356938035643809}"#);
        assert!(!n.contains("356938035643809"), "{n}");
    }

    #[test]
    fn nested_and_query() {
        let s = summarize_json(br#"{"items":["bands","mode"],"bundle":{"settings":{"x":1},"alerts":{"smtpPassword":"p"}}}"#);
        assert!(s.contains("items=[\"bands\",\"mode\"]"), "{s}");
        assert!(!s.contains("\"p\""), "{s}");
        let q = summarize_query("rat=lte&token=abc&confirm=RESTORE");
        assert_eq!(q, "?rat=lte ?token=<redacted> ?confirm=RESTORE");
    }

    #[test]
    fn ring_is_bounded_filters_and_persists_with_rotation() {
        let dir = std::env::temp_dir().join(format!("qm-audit-{}-{}", std::process::id(), crate::auth::now_secs()));
        let _ = fs::remove_dir_all(&dir);
        let log = AuditLog::new(Some(dir.clone()), false);
        for i in 0..(RING_CAP + 50) {
            log.record(NewEntry {
                kind: "http",
                method: if i % 2 == 0 { "POST" } else { "DELETE" },
                route: "/api/v1/cellular/bands",
                status: if i % 3 == 0 { 500 } else { 200 },
                peer: "192.0.2.1",
                auth: if i % 5 == 0 { "token" } else { "session" },
                token_name: (i % 5 == 0).then_some("ci-bot"),
                summary: format!("n={i}"),
            });
            if i % 37 == 0 {
                log.flush_now();
            }
        }
        log.flush_now();
        assert_eq!(log.len(), RING_CAP);
        let all = log.query(&AuditFilter { limit: Some(1000), ..Default::default() });
        assert_eq!(all.len(), RING_CAP);
        assert!(all[0].id > all[1].id, "newest first");
        let tok = log.query(&AuditFilter { auth: Some("token".into()), token: Some("CI".into()), ..Default::default() });
        assert!(!tok.is_empty() && tok.iter().all(|e| e.token_name.as_deref() == Some("ci-bot")));
        let errs = log.query(&AuditFilter { status: Some("error".into()), method: Some("post".into()), ..Default::default() });
        assert!(errs.iter().all(|e| e.status >= 400 && e.method == "POST"));
        // reload from disk: current + rotated segments
        let again = AuditLog::new(Some(dir.clone()), false);
        assert!(again.len() > SEGMENT_CAP / 2 && again.len() <= RING_CAP, "{}", again.len());
        let names: Vec<String> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"audit.json".to_string()) && names.contains(&"audit.1.json".to_string()), "{names:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_failures_are_bounded_and_never_evict_entries() {
        let log = AuditLog::ram_only();
        log.event("system", "keep-me", "authenticated record");
        for i in 0..10_000u32 {
            log.auth_failure(&format!("10.0.{}.{}", i / 256, i % 256), "/api/v1/bootstrap");
        }
        for _ in 0..500 {
            log.auth_failure("10.0.0.1", "/api/v1/bootstrap");
        }
        assert_eq!(log.len(), 1, "failures never enter the entry ring");
        assert_eq!(log.query(&AuditFilter::default())[0].route, "keep-me");
        let (peers, overflow) = log.auth_failures();
        assert_eq!(peers.len(), AUTH_FAIL_PEERS);
        assert_eq!(overflow, 10_000 - AUTH_FAIL_PEERS as u64);
        assert_eq!(peers.iter().find(|p| p.peer == "10.0.0.1").map(|p| p.count), Some(501));
    }

    #[test]
    fn token_reads_are_counted_per_token_and_bounded() {
        let log = AuditLog::ram_only();
        for i in 0..100 {
            log.token_read("grafana", "/api/v1/metrics", "192.0.2.4", if i % 10 == 0 { 500 } else { 200 });
        }
        for i in 0..(TOKEN_READ_SLOTS + 5) {
            log.token_read(&format!("t{i}"), "/api/v1/bootstrap", "192.0.2.5", 200);
        }
        let r = log.token_reads();
        assert_eq!(r.len(), TOKEN_READ_SLOTS);
        assert_eq!(log.len(), 0, "reads never enter the entry ring");
        let mut fresh = AuditLog::ram_only();
        fresh.token_read("grafana", "/api/v1/metrics", "192.0.2.4", 200);
        fresh.token_read("grafana", "/api/v1/events", "192.0.2.4", 403);
        let g = &fresh.token_reads()[0];
        assert_eq!((g.count, g.errors, g.last_route.as_str()), (2, 1, "/api/v1/events"));
        fresh = AuditLog::ram_only();
        assert!(fresh.token_reads().is_empty());
    }

    // ---- property test: no planted secret ever reaches an entry ----

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
        fn digits(&mut self, n: usize) -> String {
            (0..n).map(|i| char::from(b'0' + if i == 0 { 1 + self.below(9) as u8 } else { self.below(10) as u8 })).collect()
        }
        fn hex(&mut self, n: usize) -> String {
            (0..n).map(|_| char::from(b"0123456789abcdef"[self.below(16) as usize])).collect()
        }
        fn word(&mut self, n: usize) -> String {
            const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&*";
            (0..n).map(|_| char::from(A[self.below(A.len() as u64) as usize])).collect()
        }
    }

    const SECRET_KEYS: &[&str] = &[
        "password", "currentPassword", "newPassword", "smtpPassword", "smtp_pass", "secret", "token", "apiToken", "key",
        "privateKey", "imei", "iccid", "imsi", "pin", "psk", "authKey", "csrfToken", "sessionId", "notifierSecret",
    ];
    const OTHER_KEYS: &[&str] = &["foo", "data", "value", "payload", "extra", "x", "body", "content", "blob", "settings"];

    /// Kinds of secrets: identifiers and tokens must be scrubbed under *any*
    /// key; free-form passwords are protected by the key allowlist.
    fn plant(r: &mut Rng) -> (Value, String, bool) {
        match r.below(6) {
            0 => {
                let s = r.digits(15);
                (Value::String(format!("AT+EGMR=1,7,\"{s}\"")), s, true)
            }
            1 => {
                let n = 18 + r.below(3) as usize;
                let s = r.digits(n);
                (Value::String(s.clone()), s, true)
            }
            2 => {
                let s = format!("qmt_{}_{}", r.hex(16), r.hex(64));
                (Value::String(format!("Bearer {s}")), s, true)
            }
            3 => {
                let s = r.hex(64);
                (Value::String(s.clone()), s, true)
            }
            4 => {
                let s = r.digits(15);
                (serde_json::from_str(&s).unwrap_or(Value::Null), s, true)
            }
            _ => {
                let len = 10 + r.below(14) as usize;
                let s = r.word(len);
                (Value::String(s.clone()), s, false)
            }
        }
    }

    fn random_doc(r: &mut Rng, secrets: &mut Vec<String>, depth: usize) -> Value {
        let mut map = serde_json::Map::new();
        for _ in 0..(1 + r.below(6)) {
            let (v, s, anywhere) = plant(r);
            let key = if anywhere {
                match r.below(3) {
                    0 => SHOWN_KEYS[r.below(SHOWN_KEYS.len() as u64) as usize].to_string(),
                    1 => SECRET_KEYS[r.below(SECRET_KEYS.len() as u64) as usize].to_string(),
                    _ => OTHER_KEYS[r.below(OTHER_KEYS.len() as u64) as usize].to_string(),
                }
            } else if r.below(2) == 0 {
                SECRET_KEYS[r.below(SECRET_KEYS.len() as u64) as usize].to_string()
            } else {
                OTHER_KEYS[r.below(OTHER_KEYS.len() as u64) as usize].to_string()
            };
            let v = match r.below(4) {
                0 => Value::Array(vec![Value::from(1), v]),
                1 if depth < 3 => {
                    let mut inner = serde_json::Map::new();
                    inner.insert(key.clone(), v);
                    Value::Object(inner)
                }
                _ => v,
            };
            secrets.push(s);
            map.insert(key, v);
            if depth < 2 && r.below(4) == 0 {
                let k = OTHER_KEYS[r.below(OTHER_KEYS.len() as u64) as usize].to_string();
                map.insert(k, random_doc(r, secrets, depth + 1));
            }
        }
        // harmless shown values alongside
        map.insert("action".into(), Value::from("apply"));
        Value::Object(map)
    }

    #[test]
    fn property_no_secret_ever_lands_in_the_log() {
        let log = AuditLog::ram_only();
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..3000 {
            let mut secrets = Vec::new();
            let doc = random_doc(&mut r, &mut secrets, 0);
            let body = serde_json::to_vec(&doc).unwrap();
            let summary = summarize_body(Some("application/json"), Some(&body), None);
            let qs: Vec<String> = secrets.iter().take(2).enumerate().map(|(i, s)| format!("{}={s}", SECRET_KEYS[i])).collect();
            let q = summarize_query(&qs.join("&"));
            let e = log.record(NewEntry {
                kind: "http",
                method: "POST",
                route: "/api/v1/x",
                status: 200,
                peer: "192.0.2.9",
                auth: "token",
                token_name: Some("bot"),
                summary: format!("{q} {summary}"),
            });
            let line = format!("{} {}", serde_json::to_string(&e).unwrap(), syslog_line(&e));
            for s in &secrets {
                let probe = &s[..s.len().min(12)];
                assert!(!line.contains(probe), "round {round}: secret {s} leaked in {line}\nfrom {doc}");
            }
            assert!(e.summary.contains("action=\"apply\""), "{}", e.summary);
        }
    }
}

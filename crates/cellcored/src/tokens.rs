//! Long-lived API tokens for automation, in two types.
//!
//! Format: `qmt_<16 hex id>_<64 hex secret>` (85 chars). The `qmt_` prefix and
//! the `_` separators make a token impossible to confuse with a session token
//! (32..64 plain hex), so the auth middleware picks exactly one path.
//! Only `sha256(token)` is stored; the plaintext is returned once on creation.
//!
//! * `read` (monitoring): every GET/HEAD route a session can read, minus the
//!   secret-revealing reads in [`READ_DENY`] (audit log, IMEI/ICCID/IMSI
//!   secrets, the OpenWrt backup archive with /etc/shadow, SMS bodies, the
//!   root crontab, the config export with SIM identifiers). No mutations and
//!   no WebSocket.
//! * `rw` (full ops): everything a browser session can do, including admin,
//!   OTA, reboot, radio, IMEI edit and the AT console (dangerous lines still
//!   need `confirm:true`; typed confirmations and the failover gate's
//!   `force:true` apply exactly as for a browser).
//!
//! Exactly two things stay browser-session-only for every token, in a hard
//! list no other table can override: token management and the root
//! password change ([`is_session_only`]).
//!
//! Tokens stored by earlier builds with `scopes` are migrated on load, failing
//! closed: any recognised legacy scope becomes `read`. Read-write access is
//! never granted by migration; the owner issues an `rw` token deliberately.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{constant_time_eq, now_secs};

pub const TOKENS_PATH: &str = "/etc/cellcore/api_tokens.json";
pub const TOKEN_USAGE_TMP_PATH: &str = "/tmp/cellcore/token_usage.json";
pub const TOKEN_PREFIX: &str = "qmt_";
const ID_HEX: usize = 16;
const SECRET_HEX: usize = 64;
pub const TOKEN_LEN: usize = TOKEN_PREFIX.len() + ID_HEX + 1 + SECRET_HEX;
pub const MAX_TOKENS: usize = 16;
pub const MAX_NAME_LEN: usize = 40;
pub const MAX_EXPIRY_DAYS: u32 = 3650;
/// Default expiry applied to new `rw` tokens when the caller omits expiry.
pub const DEFAULT_RW_EXPIRY_DAYS: u32 = 90;
pub const MAX_FAILURE_PEERS: usize = 256;
const FAIL_WINDOW_SECS: u64 = 60;
const FAIL_MAX: u32 = 10;
/// last-used is flushed to volatile tmpfs at most every 5 minutes (never `/etc` on normal reads).
const LAST_USED_TMP_PERSIST_SECS: u64 = 300;

/// Browser-session-only for every token type. Hard list: checked before
/// anything else and never relaxed by the type rules below.
const SESSION_ONLY_EXACT: &[&str] = &["/api/v1/system/password"];
const SESSION_ONLY_PREFIX: &[&str] = &["/api/v1/security/tokens"];

/// The WebSocket authenticates with a session (query token) and is
/// re-validated against the session store; it is not offered to tokens.
const NO_TOKEN_TRANSPORT: &[&str] = &["/api/v1/ws"];

/// Secret-revealing or privileged reads a `read` token may not make.
/// Keeps Prometheus (`/api/v1/metrics`), bootstrap/status, failover, cellular
/// telemetry, tower-finder, dataplane and VPN status routes open for monitoring.
pub const READ_DENY: &[&str] = &[
    "/api/v1/audit",
    "/api/v1/modem/secrets",
    "/api/v1/admin/backup",
    "/api/v1/admin/backup/download",
    "/api/v1/sms",
    "/api/v1/events",
    "/api/v1/notify",
    "/api/v1/admin/cron",
    "/api/v1/admin/services/rc-local",
    "/api/v1/admin/software/feeds",
    "/api/v1/admin/software/self-upgrade",
    "/api/v1/admin/access",
    "/api/v1/system/ota",
    "/api/v1/system/logs",
    "/api/v1/system/maintenance",
    "/api/v1/system/acme",
    "/api/v1/cellular/profiles",
    "/api/v1/security/audit",
];

/// The config export is readable, but not with SIM identifiers.
const EXPORT_ROUTE: &str = "/api/v1/system/config-backup/export";

pub fn is_session_only(route: &str) -> bool {
    SESSION_ONLY_EXACT.contains(&route)
        || SESSION_ONLY_PREFIX
            .iter()
            .any(|p| route == *p || route.strip_prefix(p).is_some_and(|rest| rest.starts_with('/')))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// Monitoring: GET only, minus [`READ_DENY`].
    Read,
    /// Full operations: everything a session can do except the session-only pair.
    Rw,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Read => "read",
            TokenKind::Rw => "rw",
        }
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_query_component(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_flag(query: Option<&str>, key: &str) -> bool {
    query.is_some_and(|q| {
        q.split('&').filter(|kv| !kv.is_empty()).any(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, "1"));
            decode_query_component(k) == key
                && !matches!(
                    decode_query_component(v).trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "no" | "off"
                )
        })
    })
}

/// Whether a token of `kind` may call `method route` (route = matched template).
pub fn token_may_access(kind: TokenKind, method: &Method, route: &str, query: Option<&str>) -> Result<(), &'static str> {
    if is_session_only(route) {
        return Err("Token management and the password change require an interactive login session");
    }
    if NO_TOKEN_TRANSPORT.contains(&route) {
        return Err("The WebSocket needs a login session; poll the REST API instead");
    }
    match kind {
        TokenKind::Rw => Ok(()),
        TokenKind::Read => {
            if *method != Method::GET && *method != Method::HEAD {
                return Err("Read-only token: changes need a read-write token");
            }
            if READ_DENY.contains(&route) {
                return Err("Read-only tokens cannot read secrets (audit log, identifiers, backups, SMS, crontab)");
            }
            if route == EXPORT_ROUTE && query_flag(query, "identifiers") {
                return Err("Read-only tokens cannot export SIM identifiers");
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    /// hex(sha256(full token))
    pub hash: String,
    pub kind: TokenKind,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub last_used_ip: Option<String>,
}

/// On-disk shape across versions (`scopes` = first release, `kind` = now).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRecord {
    id: String,
    name: String,
    hash: String,
    #[serde(default)]
    kind: Option<TokenKind>,
    #[serde(default)]
    scopes: Vec<String>,
    created_at: u64,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    last_used_at: Option<u64>,
    #[serde(default)]
    last_used_ip: Option<String>,
}

/// Legacy scoped records fail closed: `read`/`metrics`/`ops`/`rw` scopes all
/// become `read`; anything unrecognised is dropped. Returns the record and
/// whether it was migrated.
fn migrate(r: StoredRecord) -> Option<(TokenRecord, bool)> {
    let (kind, migrated) = match r.kind {
        Some(k) => (k, false),
        None if r.scopes.iter().any(|s| matches!(s.as_str(), "read" | "metrics" | "ops" | "rw")) => (TokenKind::Read, true),
        None => return None,
    };
    Some((
        TokenRecord {
            id: r.id,
            name: r.name,
            hash: r.hash,
            kind,
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip,
        },
        migrated,
    ))
}

/// What the API returns about a token (never the hash).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub kind: TokenKind,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub expired: bool,
    pub last_used_at: Option<u64>,
    pub last_used_ip: Option<String>,
}

impl TokenRecord {
    fn info(&self, now: u64) -> TokenInfo {
        TokenInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind,
            created_at: self.created_at,
            expires_at: self.expires_at,
            expired: self.expires_at.is_some_and(|e| now >= e),
            last_used_at: self.last_used_at,
            last_used_ip: self.last_used_ip.clone(),
        }
    }
}

/// An authenticated API token, as seen by the middleware and handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAuth {
    pub id: String,
    pub name: String,
    pub kind: TokenKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    RateLimited,
    Invalid,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct TokenUsageOverlay {
    last_used_at: Option<u64>,
    last_used_ip: Option<String>,
}

#[derive(Default)]
struct Inner {
    tokens: Vec<TokenRecord>,
    failures: HashMap<IpAddr, (Instant, u32)>,
    last_tmp_flush: Option<Instant>,
    usage_dirty: bool,
}

#[derive(Clone)]
pub struct TokenStore {
    path: Option<Arc<PathBuf>>,
    inner: Arc<Mutex<Inner>>,
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Strict syntax check; also returns the id part.
pub fn parse_token(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    if token.len() != TOKEN_LEN {
        return None;
    }
    let (id, secret) = rest.split_once('_')?;
    let hex_lower = |s: &str| s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (id.len() == ID_HEX && secret.len() == SECRET_HEX && hex_lower(id) && hex_lower(secret)).then_some(id)
}

pub fn validate_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.len() > MAX_NAME_LEN {
        return Err(format!("Name must be 1-{MAX_NAME_LEN} characters"));
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.')) {
        return Err("Name may contain letters, digits, space, '-', '_' and '.' only".into());
    }
    Ok(n.to_string())
}

impl TokenStore {
    /// `path = None` keeps tokens in RAM only (tests).
    pub fn new(path: Option<PathBuf>) -> Self {
        let stored: Vec<StoredRecord> = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let total = stored.len();
        let mut changed = false;
        let mut tokens: Vec<TokenRecord> = stored
            .into_iter()
            .filter_map(migrate)
            .filter(|(t, _)| parse_token(&format!("{TOKEN_PREFIX}{}_{}", t.id, "0".repeat(SECRET_HEX))).is_some() && t.hash.len() == 64)
            .map(|(t, m)| {
                changed |= m;
                t
            })
            .collect();
        changed |= tokens.len() != total;
        if path.is_some()
            && let Ok(raw_usage) = std::fs::read(crate::paths::p(TOKEN_USAGE_TMP_PATH))
            && let Ok(usage_map) = serde_json::from_slice::<HashMap<String, TokenUsageOverlay>>(&raw_usage)
        {
            for tok in &mut tokens {
                if let Some(ov) = usage_map.get(&tok.id)
                    && ov.last_used_at.unwrap_or(0) >= tok.last_used_at.unwrap_or(0)
                    && ov.last_used_at.is_some()
                {
                    tok.last_used_at = ov.last_used_at;
                    if ov.last_used_ip.is_some() {
                        tok.last_used_ip = ov.last_used_ip.clone();
                    }
                }
            }
        }
        let store = Self {
            path: path.map(Arc::new),
            inner: Arc::new(Mutex::new(Inner { tokens, ..Default::default() })),
        };
        if changed {
            let g = lock(&store.inner);
            let _ = store.persist(&g.tokens);
        }
        store
    }

    #[cfg(test)]
    pub fn ram_only() -> Self {
        Self::new(None)
    }

    fn persist(&self, tokens: &[TokenRecord]) -> Result<(), String> {
        let Some(p) = self.path.as_deref() else { return Ok(()) };
        let json = serde_json::to_vec_pretty(tokens).map_err(|e| e.to_string())?;
        crate::state::atomic_write(p, &json, 0o600)
    }

    fn persist_tmp_usage(&self, tokens: &[TokenRecord]) {
        if self.path.is_none() {
            return;
        }
        let mut map = HashMap::with_capacity(tokens.len());
        for t in tokens {
            if t.last_used_at.is_some() || t.last_used_ip.is_some() {
                map.insert(
                    t.id.clone(),
                    TokenUsageOverlay {
                        last_used_at: t.last_used_at,
                        last_used_ip: t.last_used_ip.clone(),
                    },
                );
            }
        }
        if let Ok(json) = serde_json::to_vec(&map) {
            let tmp_p = crate::paths::p(TOKEN_USAGE_TMP_PATH);
            let _ = crate::state::atomic_write(Path::new(&tmp_p), &json, 0o600);
        }
    }

    /// Flush in-memory `last_used_at` / `last_used_ip` metadata to `/etc/cellcore/api_tokens.json`
    /// on clean shutdown (`SIGTERM` / reboot).
    pub fn flush_tokens_usage(&self) {
        let mut g = lock(&self.inner);
        if !g.usage_dirty || self.path.is_none() {
            return;
        }
        if self.persist(&g.tokens).is_ok() {
            g.usage_dirty = false;
        }
        self.persist_tmp_usage(&g.tokens);
    }

    pub fn list(&self) -> Vec<TokenInfo> {
        let now = now_secs();
        lock(&self.inner).tokens.iter().map(|t| t.info(now)).collect()
    }

    /// Create a token. Returns its info and the plaintext (shown once).
    /// New `rw` tokens default to expiring in [`DEFAULT_RW_EXPIRY_DAYS`] (90 days)
    /// when `expires_in_days` is omitted.
    pub fn create(&self, name: &str, kind: TokenKind, expires_in_days: Option<u32>) -> Result<(TokenInfo, String), String> {
        let name = validate_name(name)?;
        if let Some(d) = expires_in_days
            && !(1..=MAX_EXPIRY_DAYS).contains(&d)
        {
            return Err(format!("Expiry must be 1-{MAX_EXPIRY_DAYS} days"));
        }
        let effective_days = match (kind, expires_in_days) {
            (TokenKind::Rw, None) => Some(DEFAULT_RW_EXPIRY_DAYS),
            (_, days) => days,
        };
        let id = crate::auth::random_hex(ID_HEX / 2)?;
        let secret = crate::auth::random_hex(SECRET_HEX / 2)?;
        let token = format!("{TOKEN_PREFIX}{id}_{secret}");
        let now = now_secs();
        let rec = TokenRecord {
            id,
            name,
            hash: hash_token(&token),
            kind,
            created_at: now,
            expires_at: effective_days.map(|d| now + u64::from(d) * 86_400),
            last_used_at: None,
            last_used_ip: None,
        };
        let mut g = lock(&self.inner);
        if g.tokens.len() >= MAX_TOKENS {
            return Err(format!("At most {MAX_TOKENS} tokens; revoke one first"));
        }
        if g.tokens.iter().any(|t| t.name.eq_ignore_ascii_case(&rec.name)) {
            return Err("A token with this name already exists".into());
        }
        g.tokens.push(rec.clone());
        if let Err(e) = self.persist(&g.tokens) {
            g.tokens.pop();
            return Err(e);
        }
        g.usage_dirty = false;
        Ok((rec.info(now), token))
    }

    pub fn revoke(&self, id: &str) -> Result<Option<String>, String> {
        let mut g = lock(&self.inner);
        let Some(pos) = g.tokens.iter().position(|t| t.id == id) else { return Ok(None) };
        let removed = g.tokens.remove(pos);
        if let Err(e) = self.persist(&g.tokens) {
            g.tokens.insert(pos, removed);
            return Err(e);
        }
        g.usage_dirty = false;
        self.persist_tmp_usage(&g.tokens);
        Ok(Some(removed.name))
    }

    /// Revoke every stored API token (e.g. on root password reset).
    /// Returns the number of tokens revoked.
    pub fn revoke_all(&self) -> Result<usize, String> {
        let mut g = lock(&self.inner);
        let count = g.tokens.len();
        if count == 0 {
            return Ok(0);
        }
        let prev = std::mem::take(&mut g.tokens);
        if let Err(e) = self.persist(&g.tokens) {
            g.tokens = prev;
            return Err(e);
        }
        g.usage_dirty = false;
        self.persist_tmp_usage(&g.tokens);
        Ok(count)
    }

    /// Authenticate a bearer value that starts with the token prefix.
    /// Failed attempts are counted per IP *before* any lookup.
    pub fn authenticate(&self, presented: &str, ip: IpAddr) -> Result<TokenAuth, TokenError> {
        let now = now_secs();
        let now_mono = Instant::now();
        let win = Duration::from_secs(FAIL_WINDOW_SECS);
        let mut g = lock(&self.inner);
        g.failures.retain(|_, (start, _)| now_mono.saturating_duration_since(*start) <= win);
        if g.failures.get(&ip).is_some_and(|(_, n)| *n >= FAIL_MAX) {
            return Err(TokenError::RateLimited);
        }
        let fail = |g: &mut Inner| {
            if !g.failures.contains_key(&ip)
                && g.failures.len() >= MAX_FAILURE_PEERS
                && let Some(oldest_ip) = g
                    .failures
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| *k)
            {
                g.failures.remove(&oldest_ip);
            }
            let e = g.failures.entry(ip).or_insert((now_mono, 0));
            e.1 += 1;
        };
        let Some(id) = parse_token(presented) else {
            fail(&mut g);
            return Err(TokenError::Invalid);
        };
        let want = hash_token(presented);
        let Some(idx) = g.tokens.iter().position(|t| t.id == id) else {
            fail(&mut g);
            return Err(TokenError::Invalid);
        };
        if !constant_time_eq(&g.tokens[idx].hash, &want) {
            fail(&mut g);
            return Err(TokenError::Invalid);
        }
        if g.tokens[idx].expires_at.is_some_and(|e| now >= e) {
            return Err(TokenError::Expired);
        }
        let ip_s = ip.to_string();
        let t = &mut g.tokens[idx];
        t.last_used_at = Some(now);
        t.last_used_ip = Some(ip_s);
        let auth = TokenAuth {
            id: t.id.clone(),
            name: t.name.clone(),
            kind: t.kind,
        };
        g.usage_dirty = true;
        if g.last_tmp_flush
            .is_none_or(|l| now_mono.saturating_duration_since(l) >= Duration::from_secs(LAST_USED_TMP_PERSIST_SECS))
        {
            g.last_tmp_flush = Some(now_mono);
            self.persist_tmp_usage(&g.tokens);
        }
        Ok(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn create_hashes_and_authenticates() {
        let dir = std::env::temp_dir().join(format!("qm-tok-{}-{}", std::process::id(), now_secs()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("api_tokens.json");
        let st = TokenStore::new(Some(path.clone()));
        let (info, tok) = st.create("ci bot", TokenKind::Rw, Some(30)).unwrap();
        assert_eq!(tok.len(), TOKEN_LEN);
        assert!(tok.starts_with("qmt_"));
        assert_eq!(info.kind, TokenKind::Rw);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(&tok[21..]), "plaintext secret persisted");
        assert!(on_disk.contains(&hash_token(&tok)));
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        }
        let a = st.authenticate(&tok, ip("192.0.2.5")).unwrap();
        assert_eq!(a.name, "ci bot");
        let l = st.list();
        assert_eq!(l[0].last_used_ip.as_deref(), Some("192.0.2.5"));
        // reload from disk
        let st2 = TokenStore::new(Some(path.clone()));
        assert!(st2.authenticate(&tok, ip("192.0.2.5")).is_ok());
        // revoke
        assert_eq!(st2.revoke(&info.id).unwrap().as_deref(), Some("ci bot"));
        assert_eq!(st2.authenticate(&tok, ip("192.0.2.5")), Err(TokenError::Invalid));
        assert!(TokenStore::new(Some(path)).list().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_secret_and_session_tokens_are_rejected() {
        let st = TokenStore::ram_only();
        let (_, tok) = st.create("a", TokenKind::Read, None).unwrap();
        let mut forged = tok.clone();
        forged.replace_range(TOKEN_LEN - 1.., if tok.ends_with('0') { "1" } else { "0" });
        assert_eq!(st.authenticate(&forged, ip("192.0.2.1")), Err(TokenError::Invalid));
        // a session token is never an API token
        let session = crate::auth::random_hex(32).unwrap();
        assert!(parse_token(&session).is_none());
        assert!(parse_token(&tok.to_uppercase()).is_none());
        assert!(!crate::auth::is_valid_token_syntax(&tok));
        assert!(parse_token(&format!("{tok}0")).is_none());
        assert!(parse_token("qmt_0123456789abcdef_").is_none());
    }

    #[test]
    fn expiry_is_enforced() {
        let st = TokenStore::ram_only();
        let (info, tok) = st.create("short", TokenKind::Read, Some(1)).unwrap();
        lock(&st.inner).tokens[0].expires_at = Some(now_secs() - 1);
        assert_eq!(st.authenticate(&tok, ip("192.0.2.2")), Err(TokenError::Expired));
        assert!(st.list().iter().any(|t| t.id == info.id && t.expired));
        assert!(st.create("bad", TokenKind::Read, Some(0)).is_err());
        assert!(st.create("bad", TokenKind::Read, Some(MAX_EXPIRY_DAYS + 1)).is_err());
        assert!(st.create("bad\nname", TokenKind::Read, None).is_err());
        assert!(st.create("short", TokenKind::Read, None).is_err(), "duplicate name");
    }

    #[test]
    fn failed_attempts_are_rate_limited_per_ip() {
        let st = TokenStore::ram_only();
        let (_, tok) = st.create("a", TokenKind::Read, None).unwrap();
        let bad = format!("qmt_{}_{}", "0".repeat(16), "0".repeat(64));
        for _ in 0..FAIL_MAX {
            assert_eq!(st.authenticate(&bad, ip("192.0.2.66")), Err(TokenError::Invalid));
        }
        assert_eq!(st.authenticate(&bad, ip("192.0.2.66")), Err(TokenError::RateLimited));
        // even the right token is refused from that IP during the window
        assert_eq!(st.authenticate(&tok, ip("192.0.2.66")), Err(TokenError::RateLimited));
        assert!(st.authenticate(&tok, ip("192.0.2.67")).is_ok());
    }

    #[test]
    fn type_matrix() {
        let (r, w) = (TokenKind::Read, TokenKind::Rw);
        let (get, post, del, put, head) = (Method::GET, Method::POST, Method::DELETE, Method::PUT, Method::HEAD);
        // read: GET only
        assert!(token_may_access(r, &get, "/api/v1/bootstrap", None).is_ok());
        assert!(token_may_access(r, &head, "/api/v1/bootstrap", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/metrics", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/admin/processes", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/cellular/bands", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/cellular/tower-finder", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/vpn/cloudflared", None).is_ok());
        assert!(token_may_access(r, &get, "/api/v1/system/ota", None).is_err());
        assert!(token_may_access(r, &get, "/api/v1/events", None).is_err());
        assert!(token_may_access(r, &get, "/api/v1/notify", None).is_err());
        assert!(token_may_access(r, &get, "/api/v1/admin/services/rc-local", None).is_err());
        assert!(token_may_access(r, &get, "/api/v1/admin/software/feeds", None).is_err());
        assert!(token_may_access(r, &post, "/api/v1/cellular/bands", None).is_err());
        assert!(token_may_access(r, &del, "/api/v1/cellular/cell-lock", None).is_err());
        assert!(token_may_access(r, &put, "/api/v1/admin/cron", None).is_err());
        for p in READ_DENY {
            assert!(token_may_access(r, &get, p, None).is_err(), "{p}");
            assert!(token_may_access(w, &get, p, None).is_ok(), "rw reads {p}");
        }
        assert!(token_may_access(r, &get, EXPORT_ROUTE, None).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=1")).is_err());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("x=1&identifiers=true")).is_err());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=0")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=no")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=off")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=OFF")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=%20No%20")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=")).is_ok());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=maybe")).is_err());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("identifiers=no&identifiers=1")).is_err());
        assert!(token_may_access(r, &get, EXPORT_ROUTE, Some("%69dentifiers=1")).is_err());
        assert!(token_may_access(w, &get, EXPORT_ROUTE, Some("identifiers=1")).is_ok());
        // rw: everything a session can do
        for (m, p) in [
            (&post, "/api/v1/modem/at"),
            (&post, "/api/v1/modem/imei"),
            (&put, "/api/v1/admin/cron"),
            (&post, "/api/v1/admin/software/install"),
            (&post, "/api/v1/admin/access/keys"),
            (&post, "/api/v1/admin/backup/restore"),
            (&post, "/api/v1/system/config-backup/apply"),
            (&post, "/api/v1/system/ota"),
            (&post, "/api/v1/system/reboot"),
        ] {
            assert!(token_may_access(w, m, p, None).is_ok(), "{m} {p}");
        }
        // the hard session-only pair, for both types and every method
        for k in [r, w] {
            for m in [&get, &post, &del, &put] {
                for p in ["/api/v1/system/password", "/api/v1/security/tokens", "/api/v1/security/tokens/{id}"] {
                    assert!(token_may_access(k, m, p, None).is_err(), "{k:?} {m} {p}");
                }
                assert!(token_may_access(k, m, "/api/v1/ws", None).is_err());
            }
        }
        assert!(!is_session_only("/api/v1/security/tokensx"));
        assert!(!is_session_only("/api/v1/system/passwords"));
    }

    #[test]
    fn legacy_scoped_tokens_are_migrated() {
        let dir = std::env::temp_dir().join(format!("qm-tok-mig-{}-{}", std::process::id(), now_secs()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api_tokens.json");
        let tok = |id: char| format!("qmt_{}_{}", id.to_string().repeat(16), "a".repeat(64));
        let rec = |id: char, name: &str, scopes: &str| {
            format!(
                r#"{{"id":"{}","name":"{name}","hash":"{}","scopes":{scopes},"createdAt":1,"lastUsedIp":"192.0.2.1"}}"#,
                id.to_string().repeat(16),
                hash_token(&tok(id))
            )
        };
        let legacy = format!(
            "[{},{},{},{},{}]",
            rec('1', "ops-only", r#"["ops"]"#),
            rec('2', "read-ops", r#"["read","ops"]"#),
            rec('3', "metrics", r#"["metrics"]"#),
            rec('4', "read", r#"["read"]"#),
            rec('5', "bogus", r#"["admin"]"#),
        );
        std::fs::write(&path, legacy).unwrap();
        let st = TokenStore::new(Some(path.clone()));
        let kinds: Vec<(String, TokenKind)> = st.list().into_iter().map(|t| (t.name, t.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("ops-only".into(), TokenKind::Read),
                ("read-ops".into(), TokenKind::Read),
                ("metrics".into(), TokenKind::Read),
                ("read".into(), TokenKind::Read),
            ],
            "legacy scopes never become rw; unknown scopes are dropped (fail closed)"
        );
        // the secrets still authenticate, with the migrated type
        assert_eq!(st.authenticate(&tok('3'), ip("192.0.2.9")).unwrap().kind, TokenKind::Read);
        assert_eq!(st.authenticate(&tok('1'), ip("192.0.2.9")).unwrap().kind, TokenKind::Read);
        // rewritten in the new format
        let disk = std::fs::read_to_string(&path).unwrap();
        assert!(disk.contains(r#""kind": "read""#) && !disk.contains(r#""kind": "rw""#), "{disk}");
        assert!(!disk.contains("scopes") && !disk.contains("bogus"), "{disk}");
        assert_eq!(TokenStore::new(Some(path)).list().len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn token_authenticate_defers_etc_write_until_flush_and_caps_failures() {
        let sbx = crate::paths::TestSandbox::new("tok-tmpfs-flush");
        std::fs::create_dir_all(sbx.root.join("etc/cellcore")).unwrap();
        std::fs::create_dir_all(sbx.root.join("tmp/cellcore")).unwrap();
        let etc_path = sbx.root.join("etc/cellcore/api_tokens.json");

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let st = TokenStore::new(Some(etc_path.clone()));
                let (_, secret) = st.create(" exporter ", TokenKind::Read, None).unwrap();
                let before_etc = std::fs::read_to_string(&etc_path).unwrap();
                assert!(
                    before_etc.contains("\"lastUsedAt\": null"),
                    "newly created token has null lastUsedAt: {before_etc}"
                );

                // Authenticate writes tmpfs overlay (0600) without rewriting /etc/cellcore/api_tokens.json!
                st.authenticate(&secret, ip("192.0.2.44")).unwrap();
                let after_auth_etc = std::fs::read_to_string(&etc_path).unwrap();
                assert_eq!(
                    before_etc, after_auth_etc,
                    "authenticate() must not write /etc/cellcore/api_tokens.json"
                );
                let tmp_path = sbx.root.join("tmp/cellcore/token_usage.json");
                assert!(tmp_path.exists(), "tmpfs token usage snapshot should be written");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(&tmp_path).unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600);
                }

                // Startup reloads last_used_at from /tmp/cellcore/token_usage.json even before /etc flush.
                let reloaded = TokenStore::new(Some(etc_path.clone()));
                assert_eq!(
                    reloaded.list()[0].last_used_ip.as_deref(),
                    Some("192.0.2.44")
                );

                // Clean shutdown flushes dirty usage to /etc/cellcore/api_tokens.json.
                st.flush_tokens_usage();
                let flushed_etc = std::fs::read_to_string(&etc_path).unwrap();
                assert!(flushed_etc.contains("192.0.2.44"), "{flushed_etc}");

                // Cap failures map at MAX_FAILURE_PEERS (256).
                for i in 0..(MAX_FAILURE_PEERS + 32) {
                    let peer = IpAddr::from([198, 51, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8]);
                    let _ = st.authenticate("qmt_bad", peer);
                }
                assert!(lock(&st.inner).failures.len() <= MAX_FAILURE_PEERS);
            })
            .await;
    }

    #[test]
    fn rw_tokens_default_to_90_day_expiry_and_revoke_all_clears_store() {
        let dir = std::env::temp_dir().join(format!("qm-tok-revall-{}-{}", std::process::id(), now_secs()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("api_tokens.json");
        let st = TokenStore::new(Some(path.clone()));

        // Omitting expiry on rw defaults to DEFAULT_RW_EXPIRY_DAYS (90 days).
        let (rw_def, rw_tok) = st.create("ops-default", TokenKind::Rw, None).unwrap();
        assert_eq!(
            rw_def.expires_at,
            Some(rw_def.created_at + u64::from(DEFAULT_RW_EXPIRY_DAYS) * 86_400)
        );
        assert!(!rw_def.expired);

        // Explicit expiry up to MAX_EXPIRY_DAYS still honored.
        let (rw_exp, _) = st.create("ops-365", TokenKind::Rw, Some(365)).unwrap();
        assert_eq!(rw_exp.expires_at, Some(rw_exp.created_at + 365 * 86_400));

        // Read tokens omitting expiry remain non-expiring.
        let (rd_info, rd_tok) = st.create("mon", TokenKind::Read, None).unwrap();
        assert_eq!(rd_info.expires_at, None);

        // revoke_all removes every token from memory and disk.
        assert_eq!(st.revoke_all().unwrap(), 3);
        assert!(st.list().is_empty());
        assert_eq!(st.authenticate(&rw_tok, ip("192.0.2.10")), Err(TokenError::Invalid));
        assert_eq!(st.authenticate(&rd_tok, ip("192.0.2.10")), Err(TokenError::Invalid));
        assert!(TokenStore::new(Some(path)).list().is_empty());
        assert_eq!(st.revoke_all().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

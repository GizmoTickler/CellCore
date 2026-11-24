use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::sync::{Mutex, Semaphore, watch};

const CRYPT_B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub const SESSION_DIR: &str = "/tmp/cellcore/sessions";
pub const SESSION_MAX_AGE_SECS: u64 = 28_800; // 8 hours
pub const SESSION_IDLE_AGE_SECS: u64 = 7_200; // 2 hours
/// Minimum interval between rewriting a session file in `/tmp` on `touch`.
pub const SESSION_PERSIST_INTERVAL_SECS: u64 = 120;
pub const MAX_SESSIONS: usize = 64;
pub const MAX_RATE_LIMIT_PEERS: usize = 256;
const RATE_WINDOW_SECS: u64 = 60;
const RATE_MAX_FAILS: u32 = 5;
/// sha-crypt cost grows with len(password)^2; real passwords are far shorter.
pub const MAX_PASSWORD_LEN: usize = 256;
/// At most this many password hashes are computed at once (2-core SoC).
pub const MAX_CONCURRENT_VERIFY: usize = 2;
const VERIFY_SLOT_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub token: String,
    pub csrf_token: String,
    pub created_at: u64,
    pub last_seen: u64,
    #[serde(skip, default = "Instant::now")]
    pub created_mono: Instant,
    #[serde(skip, default = "Instant::now")]
    pub last_seen_mono: Instant,
    #[serde(skip, default = "Instant::now")]
    pub last_persisted_mono: Instant,
}

#[derive(Debug)]
struct RateEntry {
    window_start: Instant,
    failures: u32,
}

#[derive(Clone)]
pub struct AuthStore {
    session_dir: PathBuf,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    rate_limits: Arc<Mutex<HashMap<IpAddr, RateEntry>>>,
    verify_slots: Arc<Semaphore>,
    revocations: Arc<watch::Sender<u64>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    TooLong,
    Busy,
}

fn session_filename_hash(token: &str) -> String {
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    digest[..32].to_string()
}

fn is_session_expired_mono(rec: &SessionRecord, now_mono: Instant) -> bool {
    now_mono.saturating_duration_since(rec.created_mono) > Duration::from_secs(SESSION_MAX_AGE_SECS)
        || now_mono.saturating_duration_since(rec.last_seen_mono) > Duration::from_secs(SESSION_IDLE_AGE_SECS)
}

impl AuthStore {
    pub fn new(session_dir: impl Into<PathBuf>) -> Self {
        let dir = session_dir.into();
        let mut loaded: HashMap<String, SessionRecord> = HashMap::new();
        if let Ok(entries) = fs::read_dir(&dir) {
            let now = now_secs();
            let now_mono = Instant::now();
            let wall_valid = now >= crate::state::MIN_VALID_WALL_CLOCK_SECS;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json")
                    && let Ok(text) = fs::read_to_string(&path)
                    && let Ok(mut rec) = serde_json::from_str::<SessionRecord>(&text)
                {
                    let wall_ok = if wall_valid && rec.created_at >= crate::state::MIN_VALID_WALL_CLOCK_SECS {
                        now.saturating_sub(rec.created_at) <= SESSION_MAX_AGE_SECS
                            && now.saturating_sub(rec.last_seen) <= SESSION_IDLE_AGE_SECS
                    } else {
                        true
                    };
                    if wall_ok {
                        if wall_valid && rec.created_at >= crate::state::MIN_VALID_WALL_CLOCK_SECS {
                            let age = Duration::from_secs(now.saturating_sub(rec.created_at));
                            let idle = Duration::from_secs(now.saturating_sub(rec.last_seen));
                            rec.created_mono = now_mono.checked_sub(age).unwrap_or(now_mono);
                            rec.last_seen_mono = now_mono.checked_sub(idle).unwrap_or(now_mono);
                        } else {
                            rec.created_mono = now_mono;
                            rec.last_seen_mono = now_mono;
                        }
                        rec.last_persisted_mono = now_mono;
                        loaded.insert(rec.token.clone(), rec);
                        continue;
                    }
                }
                if path.is_file() {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        while loaded.len() > MAX_SESSIONS {
            let Some(oldest) = loaded
                .iter()
                .min_by_key(|(_, r)| r.last_seen_mono)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            loaded.remove(&oldest);
            let _ = fs::remove_file(dir.join(format!("{}.json", session_filename_hash(&oldest))));
            let _ = fs::remove_file(dir.join(format!("{oldest}.json")));
        }
        Self {
            session_dir: dir,
            sessions: Arc::new(Mutex::new(loaded)),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            verify_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFY)),
            revocations: Arc::new(watch::channel(0u64).0),
        }
    }

    /// Bumped whenever sessions are revoked; long-lived connections
    /// (WebSockets) re-validate their token when it changes.
    pub fn subscribe_revocations(&self) -> watch::Receiver<u64> {
        self.revocations.subscribe()
    }

    fn notify_revoked(&self) {
        self.revocations.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Atomically check the per-IP limit and count this attempt *before* any
    /// expensive work, so parallel requests cannot all slip under the limit.
    /// Returns false when the caller must be rejected. A successful login
    /// clears the counter via `clear_failures`.
    pub async fn begin_attempt(&self, ip: IpAddr) -> bool {
        let mut map = self.rate_limits.lock().await;
        let now = Instant::now();
        let win = Duration::from_secs(RATE_WINDOW_SECS);
        if !map.contains_key(&ip) && map.len() >= MAX_RATE_LIMIT_PEERS {
            map.retain(|_, v| now.saturating_duration_since(v.window_start) <= win);
            while map.len() >= MAX_RATE_LIMIT_PEERS {
                let Some(oldest_ip) = map
                    .iter()
                    .min_by_key(|(_, v)| v.window_start)
                    .map(|(k, _)| *k)
                else {
                    break;
                };
                map.remove(&oldest_ip);
            }
        }
        let entry = map.entry(ip).or_insert(RateEntry {
            window_start: now,
            failures: 0,
        });
        if now.saturating_duration_since(entry.window_start) > win {
            entry.window_start = now;
            entry.failures = 0;
        }
        if entry.failures >= RATE_MAX_FAILS {
            return false;
        }
        entry.failures += 1;
        true
    }

    /// Verify a password against the root shadow entry with a length cap and
    /// a bound on concurrent hash computations.
    pub async fn verify_password_bounded<F>(&self, plain: &str, verify: F) -> Result<bool, VerifyError>
    where
        F: FnOnce(String) -> bool + Send + 'static,
    {
        if plain.len() > MAX_PASSWORD_LEN {
            return Err(VerifyError::TooLong);
        }
        let permit = tokio::time::timeout(VERIFY_SLOT_WAIT, Arc::clone(&self.verify_slots).acquire_owned())
            .await
            .map_err(|_| VerifyError::Busy)?
            .map_err(|_| VerifyError::Busy)?;
        let pw = plain.to_string();
        let res = crate::paths::spawn_blocking(move || {
            let _permit = permit;
            verify(pw)
        })
        .await
        .unwrap_or(false);
        Ok(res)
    }

    pub fn ensure_dir(&self) {
        let _ = fs::create_dir_all(&self.session_dir);
        let _ = fs::set_permissions(&self.session_dir, fs::Permissions::from_mode(0o700));
    }

    pub async fn clear_failures(&self, ip: IpAddr) {
        self.rate_limits.lock().await.remove(&ip);
    }

    pub async fn create_session(&self) -> Result<SessionRecord, String> {
        self.ensure_dir();
        let token = random_hex(32)?;
        let csrf_token = random_hex(16)?;
        let now = now_secs();
        let now_mono = Instant::now();
        let rec = SessionRecord {
            token: token.clone(),
            csrf_token,
            created_at: now,
            last_seen: now,
            created_mono: now_mono,
            last_seen_mono: now_mono,
            last_persisted_mono: now_mono,
        };
        let mut evicted_any = false;
        {
            let mut sessions = self.sessions.lock().await;
            let expired: Vec<String> = sessions
                .iter()
                .filter(|(_, r)| is_session_expired_mono(r, now_mono))
                .map(|(k, _)| k.clone())
                .collect();
            for tok in expired {
                sessions.remove(&tok);
                self.remove_session_files(&tok);
                evicted_any = true;
            }
            while sessions.len() >= MAX_SESSIONS {
                let Some(oldest_tok) = sessions
                    .iter()
                    .min_by_key(|(_, r)| r.last_seen_mono)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                sessions.remove(&oldest_tok);
                self.remove_session_files(&oldest_tok);
                evicted_any = true;
            }
            sessions.insert(token, rec.clone());
        }
        if evicted_any {
            self.notify_revoked();
        }
        self.persist_session(&rec);
        Ok(rec)
    }

    pub async fn validate_token(&self, token: &str, touch: bool) -> Option<SessionRecord> {
        if !is_valid_token_syntax(token) {
            return None;
        }
        let now = now_secs();
        let now_mono = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let expired = sessions
            .get(token)
            .is_some_and(|rec| is_session_expired_mono(rec, now_mono));
        if expired {
            sessions.remove(token);
            self.remove_session_files(token);
            return None;
        }
        let rec = sessions.get_mut(token)?;
        if touch {
            rec.last_seen = now;
            rec.last_seen_mono = now_mono;
            let should_persist = now_mono.saturating_duration_since(rec.last_persisted_mono)
                >= Duration::from_secs(SESSION_PERSIST_INTERVAL_SECS);
            if should_persist {
                rec.last_persisted_mono = now_mono;
            }
            let cloned = rec.clone();
            drop(sessions);
            if should_persist {
                self.persist_session(&cloned);
            }
            return Some(cloned);
        }
        Some(rec.clone())
    }

    pub async fn revoke_session(&self, token: &str) {
        if !is_valid_token_syntax(token) {
            return;
        }
        self.sessions.lock().await.remove(token);
        self.remove_session_files(token);
        self.notify_revoked();
    }

    pub async fn revoke_except(&self, keep_token: Option<&str>) {
        let mut sessions = self.sessions.lock().await;
        let to_remove: Vec<String> = sessions
            .keys()
            .filter(|k| Some(k.as_str()) != keep_token)
            .cloned()
            .collect();
        for tok in to_remove {
            sessions.remove(&tok);
            self.remove_session_files(&tok);
        }
        drop(sessions);
        self.notify_revoked();
    }

    pub async fn prune_expired(&self) {
        let now_mono = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, rec)| is_session_expired_mono(rec, now_mono))
            .map(|(k, _)| k.clone())
            .collect();
        let any_expired = !expired.is_empty();
        for tok in expired {
            sessions.remove(&tok);
            self.remove_session_files(&tok);
        }
        drop(sessions);
        if any_expired {
            self.notify_revoked();
        }

        let mut rates = self.rate_limits.lock().await;
        rates.retain(|_, v| now_mono.saturating_duration_since(v.window_start) <= Duration::from_secs(RATE_WINDOW_SECS));
    }

    fn session_path(&self, token: &str) -> PathBuf {
        self.session_dir.join(format!("{}.json", session_filename_hash(token)))
    }

    fn legacy_session_path(&self, token: &str) -> PathBuf {
        self.session_dir.join(format!("{token}.json"))
    }

    fn remove_session_files(&self, token: &str) {
        let _ = fs::remove_file(self.session_path(token));
        let _ = fs::remove_file(self.legacy_session_path(token));
    }

    fn persist_session(&self, rec: &SessionRecord) {
        let path = self.session_path(&rec.token);
        if let Ok(json) = serde_json::to_vec(rec) {
            if crate::state::atomic_write_tmpfs(&path, &json, 0o600).is_err() {
                self.ensure_dir();
                let _ = crate::state::atomic_write_tmpfs(&path, &json, 0o600);
            }
            let legacy = self.legacy_session_path(&rec.token);
            if legacy != path {
                let _ = fs::remove_file(legacy);
            }
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

pub fn random_hex(num_bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; num_bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(hex::encode(buf))
}

pub fn random_crypt_salt(len: usize) -> Result<String, String> {
    let n = len.clamp(8, 16);
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(buf
        .into_iter()
        .map(|b| CRYPT_B64[(b as usize) & 0x3f] as char)
        .collect())
}

pub fn is_valid_token_syntax(tok: &str) -> bool {
    (32..=64).contains(&tok.len()) && tok.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ba = a.as_bytes();
    let bb = b.as_bytes();
    if ba.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ba.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_shadow_password(plain: &str, user: &str) -> bool {
    verify_shadow_password_in_file(plain, user, Path::new(&crate::paths::p("/etc/shadow")))
}

pub fn verify_shadow_password_in_file(plain: &str, user: &str, shadow_path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(shadow_path) else {
        return false;
    };
    let Some(stored_hash) = contents.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let hash = parts.next()?;
        if name == user {
            Some(hash.trim().to_string())
        } else {
            None
        }
    }) else {
        return false;
    };
    verify_crypt_hash(plain, &stored_hash)
}

pub fn update_shadow_password(user: &str, old_plain: &str, new_plain: &str) -> Result<(), String> {
    update_shadow_password_in_file(user, old_plain, new_plain, Path::new(&crate::paths::p("/etc/shadow")))
}

pub fn update_shadow_password_in_file(
    user: &str,
    old_plain: &str,
    new_plain: &str,
    shadow_path: &Path,
) -> Result<(), String> {
    if old_plain.len() > MAX_PASSWORD_LEN || !verify_shadow_password_in_file(old_plain, user, shadow_path) {
        return Err("Current password is incorrect".into());
    }
    if new_plain.len() < 8 {
        return Err("New password must be at least 8 characters".into());
    }
    if new_plain.len() > MAX_PASSWORD_LEN {
        return Err(format!("New password must be at most {MAX_PASSWORD_LEN} characters"));
    }
    if new_plain.contains('\n') || new_plain.contains('\r') || new_plain.contains('\0') {
        return Err("Invalid characters in password".into());
    }
    let salt = random_crypt_salt(16)?;
    let new_hash = sha512_crypt(new_plain.as_bytes(), &salt, None);

    let orig = fs::read_to_string(shadow_path).map_err(|e| format!("Read shadow failed: {e}"))?;
    let days_since_epoch = now_secs() / 86_400;
    let mut found = false;
    let mut new_lines = Vec::new();
    for line in orig.lines() {
        let cols: Vec<&str> = line.split(':').collect();
        if cols.first().copied() == Some(user) && cols.len() >= 2 {
            found = true;
            let mut updated: Vec<String> = cols.iter().map(|s| (*s).to_string()).collect();
            updated[1] = new_hash.clone();
            if updated.len() >= 3 && !updated[2].is_empty() {
                updated[2] = days_since_epoch.to_string();
            }
            new_lines.push(updated.join(":"));
        } else {
            new_lines.push(line.to_string());
        }
    }
    if !found {
        return Err("User entry not found in /etc/shadow".into());
    }
    let out = format!("{}\n", new_lines.join("\n"));
    // 0600 from creation, fsync'd file + directory: a power cut leaves either
    // the old or the new shadow, never an empty one.
    crate::state::atomic_write(shadow_path, out.as_bytes(), 0o600)
        .map_err(|e| format!("Replace shadow failed: {e}"))
}

pub fn verify_crypt_hash(plain: &str, stored_hash: &str) -> bool {
    if plain.len() > MAX_PASSWORD_LEN {
        return false;
    }
    if stored_hash.is_empty() || stored_hash.starts_with('*') || stored_hash.starts_with('!') {
        return false;
    }
    let computed = if let Some(rest) = stored_hash.strip_prefix("$1$") {
        let salt = rest.split('$').next().unwrap_or("");
        let salt = &salt[..salt.len().min(8)];
        md5_crypt(plain.as_bytes(), salt)
    } else if let Some(rest) = stored_hash.strip_prefix("$5$") {
        let (rounds, salt) = parse_sha_crypt_params(rest);
        sha256_crypt(plain.as_bytes(), salt, rounds)
    } else if let Some(rest) = stored_hash.strip_prefix("$6$") {
        let (rounds, salt) = parse_sha_crypt_params(rest);
        sha512_crypt(plain.as_bytes(), salt, rounds)
    } else {
        return false;
    };
    constant_time_eq(&computed, stored_hash)
}

fn parse_sha_crypt_params(rest: &str) -> (Option<usize>, &str) {
    if let Some(after_rounds) = rest.strip_prefix("rounds=")
        && let Some((num_str, tail)) = after_rounds.split_once('$')
        && let Ok(rounds) = num_str.parse::<usize>()
    {
        let salt = tail.split('$').next().unwrap_or("");
        let salt = &salt[..salt.len().min(16)];
        return (Some(rounds), salt);
    }
    let salt = rest.split('$').next().unwrap_or("");
    let salt = &salt[..salt.len().min(16)];
    (None, salt)
}

fn b64_from_24bit(out: &mut String, b2: u8, b1: u8, b0: u8, n: usize) {
    let mut w = ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32);
    for _ in 0..n {
        out.push(CRYPT_B64[(w & 0x3f) as usize] as char);
        w >>= 6;
    }
}

pub fn md5_crypt(key: &[u8], salt: &str) -> String {
    let salt_bytes = &salt.as_bytes()[..salt.len().min(8)];

    let mut alt = Md5::new();
    alt.update(key);
    alt.update(salt_bytes);
    alt.update(key);
    let mut alt_res = alt.finalize();

    let mut ctx = Md5::new();
    ctx.update(key);
    ctx.update(b"$1$");
    ctx.update(salt_bytes);

    let mut cnt = key.len();
    while cnt > 16 {
        ctx.update(&alt_res[..]);
        cnt -= 16;
    }
    ctx.update(&alt_res[..cnt]);

    let mut len = key.len();
    while len > 0 {
        if (len & 1) != 0 {
            ctx.update([0u8]);
        } else if let Some(&first) = key.first() {
            ctx.update([first]);
        } else {
            ctx.update([0u8]);
        }
        len >>= 1;
    }
    let mut final_res = ctx.finalize();

    for i in 0..1000 {
        let mut c = Md5::new();
        if (i & 1) != 0 {
            c.update(key);
        } else {
            c.update(&final_res[..]);
        }
        if i % 3 != 0 {
            c.update(salt_bytes);
        }
        if i % 7 != 0 {
            c.update(key);
        }
        if (i & 1) != 0 {
            c.update(&final_res[..]);
        } else {
            c.update(key);
        }
        final_res = c.finalize();
    }

    let mut out = format!("$1${}$", std::str::from_utf8(salt_bytes).unwrap_or(""));
    b64_from_24bit(&mut out, final_res[0], final_res[6], final_res[12], 4);
    b64_from_24bit(&mut out, final_res[1], final_res[7], final_res[13], 4);
    b64_from_24bit(&mut out, final_res[2], final_res[8], final_res[14], 4);
    b64_from_24bit(&mut out, final_res[3], final_res[9], final_res[15], 4);
    b64_from_24bit(&mut out, final_res[4], final_res[10], final_res[5], 4);
    b64_from_24bit(&mut out, 0, 0, final_res[11], 2);
    let _ = &mut alt_res;
    out
}

pub fn sha256_crypt(key: &[u8], salt: &str, rounds_opt: Option<usize>) -> String {
    let salt_bytes = &salt.as_bytes()[..salt.len().min(16)];
    let rounds = rounds_opt.unwrap_or(5000).clamp(1000, 999_999_999);

    let mut b_ctx = Sha256::new();
    b_ctx.update(key);
    b_ctx.update(salt_bytes);
    b_ctx.update(key);
    let b_res = b_ctx.finalize();

    let mut ctx = Sha256::new();
    ctx.update(key);
    ctx.update(salt_bytes);

    let mut cnt = key.len();
    while cnt > 32 {
        ctx.update(&b_res[..]);
        cnt -= 32;
    }
    ctx.update(&b_res[..cnt]);

    let mut len = key.len();
    while len > 0 {
        if (len & 1) != 0 {
            ctx.update(&b_res[..]);
        } else {
            ctx.update(key);
        }
        len >>= 1;
    }
    let a_res = ctx.finalize();

    let mut dp_ctx = Sha256::new();
    for _ in 0..key.len() {
        dp_ctx.update(key);
    }
    let dp_res = dp_ctx.finalize();
    let p_bytes = expand_bytes(&dp_res, key.len());

    let mut ds_ctx = Sha256::new();
    for _ in 0..(16 + a_res[0] as usize) {
        ds_ctx.update(salt_bytes);
    }
    let ds_res = ds_ctx.finalize();
    let s_bytes = expand_bytes(&ds_res, salt_bytes.len());

    let mut cur = a_res;
    for r in 0..rounds {
        let mut c = Sha256::new();
        if (r & 1) != 0 {
            c.update(&p_bytes);
        } else {
            c.update(&cur[..]);
        }
        if r % 3 != 0 {
            c.update(&s_bytes);
        }
        if r % 7 != 0 {
            c.update(&p_bytes);
        }
        if (r & 1) != 0 {
            c.update(&cur[..]);
        } else {
            c.update(&p_bytes);
        }
        cur = c.finalize();
    }

    let mut out = if let Some(r_orig) = rounds_opt {
        format!(
            "$5$rounds={}${}",
            r_orig.clamp(1000, 999_999_999),
            std::str::from_utf8(salt_bytes).unwrap_or("")
        )
    } else {
        format!("$5${}", std::str::from_utf8(salt_bytes).unwrap_or(""))
    };
    out.push('$');
    b64_from_24bit(&mut out, cur[0], cur[10], cur[20], 4);
    b64_from_24bit(&mut out, cur[21], cur[1], cur[11], 4);
    b64_from_24bit(&mut out, cur[12], cur[22], cur[2], 4);
    b64_from_24bit(&mut out, cur[3], cur[13], cur[23], 4);
    b64_from_24bit(&mut out, cur[24], cur[4], cur[14], 4);
    b64_from_24bit(&mut out, cur[15], cur[25], cur[5], 4);
    b64_from_24bit(&mut out, cur[6], cur[16], cur[26], 4);
    b64_from_24bit(&mut out, cur[27], cur[7], cur[17], 4);
    b64_from_24bit(&mut out, cur[18], cur[28], cur[8], 4);
    b64_from_24bit(&mut out, cur[9], cur[19], cur[29], 4);
    b64_from_24bit(&mut out, 0, cur[31], cur[30], 3);
    out
}

pub fn sha512_crypt(key: &[u8], salt: &str, rounds_opt: Option<usize>) -> String {
    let salt_bytes = &salt.as_bytes()[..salt.len().min(16)];
    let rounds = rounds_opt.unwrap_or(5000).clamp(1000, 999_999_999);

    let mut b_ctx = Sha512::new();
    b_ctx.update(key);
    b_ctx.update(salt_bytes);
    b_ctx.update(key);
    let b_res = b_ctx.finalize();

    let mut ctx = Sha512::new();
    ctx.update(key);
    ctx.update(salt_bytes);

    let mut cnt = key.len();
    while cnt > 64 {
        ctx.update(&b_res[..]);
        cnt -= 64;
    }
    ctx.update(&b_res[..cnt]);

    let mut len = key.len();
    while len > 0 {
        if (len & 1) != 0 {
            ctx.update(&b_res[..]);
        } else {
            ctx.update(key);
        }
        len >>= 1;
    }
    let a_res = ctx.finalize();

    let mut dp_ctx = Sha512::new();
    for _ in 0..key.len() {
        dp_ctx.update(key);
    }
    let dp_res = dp_ctx.finalize();
    let p_bytes = expand_bytes(&dp_res, key.len());

    let mut ds_ctx = Sha512::new();
    for _ in 0..(16 + a_res[0] as usize) {
        ds_ctx.update(salt_bytes);
    }
    let ds_res = ds_ctx.finalize();
    let s_bytes = expand_bytes(&ds_res, salt_bytes.len());

    let mut cur = a_res;
    for r in 0..rounds {
        let mut c = Sha512::new();
        if (r & 1) != 0 {
            c.update(&p_bytes);
        } else {
            c.update(&cur[..]);
        }
        if r % 3 != 0 {
            c.update(&s_bytes);
        }
        if r % 7 != 0 {
            c.update(&p_bytes);
        }
        if (r & 1) != 0 {
            c.update(&cur[..]);
        } else {
            c.update(&p_bytes);
        }
        cur = c.finalize();
    }

    let mut out = if let Some(r_orig) = rounds_opt {
        format!(
            "$6$rounds={}${}",
            r_orig.clamp(1000, 999_999_999),
            std::str::from_utf8(salt_bytes).unwrap_or("")
        )
    } else {
        format!("$6${}", std::str::from_utf8(salt_bytes).unwrap_or(""))
    };
    out.push('$');
    b64_from_24bit(&mut out, cur[0], cur[21], cur[42], 4);
    b64_from_24bit(&mut out, cur[22], cur[43], cur[1], 4);
    b64_from_24bit(&mut out, cur[44], cur[2], cur[23], 4);
    b64_from_24bit(&mut out, cur[3], cur[24], cur[45], 4);
    b64_from_24bit(&mut out, cur[25], cur[46], cur[4], 4);
    b64_from_24bit(&mut out, cur[47], cur[5], cur[26], 4);
    b64_from_24bit(&mut out, cur[6], cur[27], cur[48], 4);
    b64_from_24bit(&mut out, cur[28], cur[49], cur[7], 4);
    b64_from_24bit(&mut out, cur[50], cur[8], cur[29], 4);
    b64_from_24bit(&mut out, cur[9], cur[30], cur[51], 4);
    b64_from_24bit(&mut out, cur[31], cur[52], cur[10], 4);
    b64_from_24bit(&mut out, cur[53], cur[11], cur[32], 4);
    b64_from_24bit(&mut out, cur[12], cur[33], cur[54], 4);
    b64_from_24bit(&mut out, cur[34], cur[55], cur[13], 4);
    b64_from_24bit(&mut out, cur[56], cur[14], cur[35], 4);
    b64_from_24bit(&mut out, cur[15], cur[36], cur[57], 4);
    b64_from_24bit(&mut out, cur[37], cur[58], cur[16], 4);
    b64_from_24bit(&mut out, cur[59], cur[17], cur[38], 4);
    b64_from_24bit(&mut out, cur[18], cur[39], cur[60], 4);
    b64_from_24bit(&mut out, cur[40], cur[61], cur[19], 4);
    b64_from_24bit(&mut out, cur[62], cur[20], cur[41], 4);
    b64_from_24bit(&mut out, 0, 0, cur[63], 2);
    out
}

fn expand_bytes(block: &[u8], target_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_len);
    let mut rem = target_len;
    while rem >= block.len() && !block.is_empty() {
        out.extend_from_slice(block);
        rem -= block.len();
    }
    if rem > 0 {
        out.extend_from_slice(&block[..rem]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypt_matches_openssl_vectors() {
        assert!(verify_crypt_hash(
            "Tr0ub4dor&3",
            "$1$ab12cd34$kP4uzP2AfM8LLXE0LjYsQ/"
        ));
        assert!(verify_crypt_hash(
            "Tr0ub4dor&3",
            "$5$salty123$n0w.gpR2hZ5d.soXap2oPzqwN8sVSnhk182vICsPpK8"
        ));
        assert!(verify_crypt_hash(
            "Tr0ub4dor&3",
            "$6$longsalt12345678$w9STR1y4K7vwbfZPgCjAA6oEqJoBcWiOfntdgp7s9/krQWljdCjqwySYjbzLRoIj8ly80ZNAwr8Ya42sDcKWf1"
        ));
        assert!(verify_crypt_hash(
            "Tr0ub4dor&3",
            "$6$rounds=5000$longsalt12345678$w9STR1y4K7vwbfZPgCjAA6oEqJoBcWiOfntdgp7s9/krQWljdCjqwySYjbzLRoIj8ly80ZNAwr8Ya42sDcKWf1"
        ));
        assert!(!verify_crypt_hash(
            "WrongPass!",
            "$6$longsalt12345678$w9STR1y4K7vwbfZPgCjAA6oEqJoBcWiOfntdgp7s9/krQWljdCjqwySYjbzLRoIj8ly80ZNAwr8Ya42sDcKWf1"
        ));
    }

    #[test]
    fn oversized_password_is_rejected_without_hashing() {
        // On the unpatched code a 64 KiB password costs ~4 GiB of SHA-512
        // input (O(len^2)); it must now be refused immediately.
        let huge = "A".repeat(64 * 1024);
        let started = std::time::Instant::now();
        assert!(!verify_crypt_hash(
            &huge,
            "$6$longsalt12345678$w9STR1y4K7vwbfZPgCjAA6oEqJoBcWiOfntdgp7s9/krQWljdCjqwySYjbzLRoIj8ly80ZNAwr8Ya42sDcKWf1"
        ));
        assert!(started.elapsed() < Duration::from_millis(200), "took {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn parallel_attempts_cannot_bypass_rate_limit() {
        let store = AuthStore::new(std::env::temp_dir().join("qm-auth-rl-none"));
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let mut handles = Vec::new();
        for _ in 0..40 {
            let st = store.clone();
            handles.push(tokio::spawn(async move { st.begin_attempt(ip).await }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, RATE_MAX_FAILS as usize);
        store.clear_failures(ip).await;
        assert!(store.begin_attempt(ip).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_verifications_are_bounded_and_length_capped() {
        let store = AuthStore::new(std::env::temp_dir().join("qm-auth-sem-none"));
        assert_eq!(
            store.verify_password_bounded(&"x".repeat(MAX_PASSWORD_LEN + 1), |_| true).await,
            Err(VerifyError::TooLong)
        );
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let st = store.clone();
            let (a, p) = (Arc::clone(&active), Arc::clone(&peak));
            handles.push(tokio::spawn(async move {
                st.verify_password_bounded("pw", move |_| {
                    let now = a.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    p.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    a.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    true
                })
                .await
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), Ok(true));
        }
        assert!(peak.load(std::sync::atomic::Ordering::SeqCst) <= MAX_CONCURRENT_VERIFY);
    }

    #[test]
    fn shadow_update_caps_length_and_writes_0600() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("qm-shadow-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let shadow = dir.join("shadow");
        let hash = sha512_crypt(b"OldPassw0rd", "abcdefgh", None);
        fs::write(&shadow, format!("root:{hash}:19000:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n")).unwrap();
        assert!(update_shadow_password_in_file("root", "OldPassw0rd", &"n".repeat(MAX_PASSWORD_LEN + 1), &shadow).is_err());
        update_shadow_password_in_file("root", "OldPassw0rd", "NewPassw0rd!", &shadow).unwrap();
        assert!(verify_shadow_password_in_file("NewPassw0rd!", "root", &shadow));
        assert!(fs::read_to_string(&shadow).unwrap().contains("daemon:*:0:0:99999:7:::"));
        assert_eq!(fs::metadata(&shadow).unwrap().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn revocation_is_signalled_to_subscribers() {
        let dir = std::env::temp_dir().join(format!("qm-auth-rev-{}", std::process::id()));
        let store = AuthStore::new(&dir);
        let mut rx = store.subscribe_revocations();
        let a = store.create_session().await.unwrap();
        let b = store.create_session().await.unwrap();
        store.revoke_session(&a.token).await;
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();
        assert!(store.validate_token(&a.token, false).await.is_none());
        store.revoke_except(None).await;
        assert!(rx.has_changed().unwrap());
        assert!(store.validate_token(&b.token, false).await.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn session_and_rate_limit_caps_evict_oldest_monotonic_entries() {
        let dir = std::env::temp_dir().join(format!("qm-auth-caps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = AuthStore::new(&dir);

        let first = store.create_session().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = store.create_session().await.unwrap();
        for _ in 2..MAX_SESSIONS {
            let _ = store.create_session().await.unwrap();
        }
        assert_eq!(store.sessions.lock().await.len(), MAX_SESSIONS);

        // Touch `first` so `second` becomes the oldest idle session.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(store.validate_token(&first.token, true).await.is_some());

        let extra = store.create_session().await.unwrap();
        assert_eq!(store.sessions.lock().await.len(), MAX_SESSIONS);
        assert!(
            store.validate_token(&second.token, false).await.is_none(),
            "oldest idle session must be evicted at MAX_SESSIONS"
        );
        assert!(store.validate_token(&first.token, false).await.is_some());
        assert!(store.validate_token(&extra.token, false).await.is_some());

        // Cap rate_limits at MAX_RATE_LIMIT_PEERS (256).
        for i in 0..(MAX_RATE_LIMIT_PEERS + 20) {
            let peer = IpAddr::from([10, 99, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8]);
            let _ = store.begin_attempt(peer).await;
        }
        assert!(store.rate_limits.lock().await.len() <= MAX_RATE_LIMIT_PEERS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn touch_throttles_session_file_rewrites_to_120s() {
        let dir = std::env::temp_dir().join(format!("qm-auth-throttle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = AuthStore::new(&dir);
        let sess = store.create_session().await.unwrap();
        let hashed_path = dir.join(format!("{}.json", session_filename_hash(&sess.token)));
        let legacy_path = dir.join(format!("{}.json", sess.token));
        assert!(hashed_path.exists(), "session must persist under sha256[..32].json");
        assert!(!legacy_path.exists(), "plaintext token filename must not be written");

        // Remove the file to observe whether a rapid touch rewrites it.
        fs::remove_file(&hashed_path).unwrap();
        assert!(store.validate_token(&sess.token, true).await.is_some());
        assert!(!hashed_path.exists(), "rapid touch within 120s must not rewrite session file");

        // Age last_persisted_mono beyond 120s and touch again -> rewrites file.
        {
            let mut g = store.sessions.lock().await;
            let rec = g.get_mut(&sess.token).unwrap();
            rec.last_persisted_mono = Instant::now() - Duration::from_secs(SESSION_PERSIST_INTERVAL_SECS + 1);
        }
        assert!(store.validate_token(&sess.token, true).await.is_some());
        assert!(hashed_path.exists(), "touch after 120s must persist updated session file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn legacy_plaintext_session_file_survives_restart_and_cleans_up_on_revoke() {
        let dir = std::env::temp_dir().join(format!("qm-auth-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let tok = random_hex(32).unwrap();
        let now = now_secs();
        let legacy = dir.join(format!("{tok}.json"));
        let rec_json = serde_json::json!({
            "token": tok,
            "csrf_token": "0123456789abcdef0123456789abcdef",
            "created_at": now,
            "last_seen": now,
        });
        fs::write(&legacy, rec_json.to_string()).unwrap();

        let store = AuthStore::new(&dir);
        assert!(store.validate_token(&tok, false).await.is_some(), "legacy session file must load");
        store.revoke_session(&tok).await;
        assert!(!legacy.exists(), "revoking legacy session must remove legacy file");
        let _ = fs::remove_dir_all(&dir);
    }
}

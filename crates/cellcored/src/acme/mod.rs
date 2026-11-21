//! Pure-Rust RFC 8555 ACME client with HTTP-01 & multi-provider DNS-01 support.
//!
//! Supported issuers:
//! * Let's Encrypt (Production & Staging)
//! * ZeroSSL (with External Account Binding / EAB)
//! * Google Public CA / Google Trust Services (Production & Staging, with EAB)
//! * Custom ACME directory URL (optional EAB)
//!
//! Issued certificates are persisted atomically via `state::atomic_write` to
//! `/etc/ssl/acme/fullchain.pem` (`0644`) and `/etc/ssl/acme/privkey.pem` (`0600`),
//! where `http.rs` hot-reloads TLS automatically with zero daemon restart.

pub mod dns;

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{Json, extract::State, http::StatusCode, response::{IntoResponse, Response}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::{
    admin::exec::{ExecOpts, run},
    http::HttpCtx,
    state::atomic_write,
};

use self::dns::{DnsProvider, cleanup_txt, decode_base64_std, hmac_sha256, present_txt};

pub const ACME_CONFIG_PATH: &str = "/etc/cellcore/acme.json";
pub const ACME_STATE_DIR: &str = "/etc/cellcore/acme";
pub const ACME_CERT_PATH: &str = "/etc/ssl/acme/fullchain.pem";
pub const ACME_KEY_PATH: &str = "/etc/ssl/acme/privkey.pem";
const ACME_HTTP_TIMEOUT_SECS: u64 = 25;

/// In-memory HTTP-01 challenge map (`token -> key_authorization`), read by port `:80`.
static HTTP01_CHALLENGES: OnceLock<Arc<RwLock<HashMap<String, String>>>> = OnceLock::new();
/// Prevents concurrent issuance runs from stepping on each other.
static ISSUE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
/// In-memory runtime progress / last error status.
static RUNTIME_STATUS: OnceLock<RwLock<AcmeRunState>> = OnceLock::new();

pub fn http01_registry() -> &'static Arc<RwLock<HashMap<String, String>>> {
    HTTP01_CHALLENGES.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

pub async fn lookup_http01_token(token: &str) -> Option<String> {
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    http01_registry().read().await.get(token).cloned()
}

fn issue_lock() -> &'static Mutex<()> {
    ISSUE_LOCK.get_or_init(|| Mutex::new(()))
}

fn run_state() -> &'static RwLock<AcmeRunState> {
    RUNTIME_STATUS.get_or_init(|| RwLock::new(AcmeRunState::default()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AcmeIssuer {
    #[default]
    Letsencrypt,
    LetsencryptStaging,
    Zerossl,
    Google,
    GoogleStaging,
    Custom,
}

impl AcmeIssuer {
    pub fn directory_url(self, custom_url: &str) -> Result<String, String> {
        match self {
            Self::Letsencrypt => Ok("https://acme-v02.api.letsencrypt.org/directory".into()),
            Self::LetsencryptStaging => Ok("https://acme-staging-v02.api.letsencrypt.org/directory".into()),
            Self::Zerossl => Ok("https://acme.zerossl.com/v2/DV90".into()),
            Self::Google => Ok("https://dv.acme-v02.api.pki.goog/directory".into()),
            Self::GoogleStaging => Ok("https://dv.acme-v02.test-api.pki.goog/directory".into()),
            Self::Custom => {
                let u = custom_url.trim();
                if u.starts_with("https://") && u.len() <= 256 {
                    Ok(u.to_string())
                } else {
                    Err("Custom ACME directory URL must start with https://".into())
                }
            }
        }
    }

    pub fn requires_eab(self) -> bool {
        matches!(self, Self::Zerossl | Self::Google | Self::GoogleStaging)
    }

    pub fn key_tag(self) -> &'static str {
        match self {
            Self::Letsencrypt => "letsencrypt",
            Self::LetsencryptStaging => "letsencrypt_staging",
            Self::Zerossl => "zerossl",
            Self::Google => "google",
            Self::GoogleStaging => "google_staging",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMethod {
    #[default]
    Dns01,
    Http01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub issuer: AcmeIssuer,
    pub custom_directory_url: String,
    pub email: String,
    pub domains: Vec<String>,
    pub validation: ValidationMethod,
    pub eab_kid: String,
    pub eab_hmac_key: String,
    pub dns_provider: DnsProvider,
    pub dns_credentials: HashMap<String, String>,
    pub propagation_seconds: u64,
    pub renew_before_days: u32,
    pub account_urls: HashMap<String, String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: AcmeIssuer::Letsencrypt,
            custom_directory_url: String::new(),
            email: String::new(),
            domains: Vec::new(),
            validation: ValidationMethod::Dns01,
            eab_kid: String::new(),
            eab_hmac_key: String::new(),
            dns_provider: DnsProvider::Cloudflare,
            dns_credentials: HashMap::new(),
            propagation_seconds: 30,
            renew_before_days: 30,
            account_urls: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeRunState {
    pub running: bool,
    pub last_attempt_ts: Option<u64>,
    pub last_success_ts: Option<u64>,
    pub last_error: Option<String>,
    pub last_message: Option<String>,
    pub log: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveCertInfo {
    pub source: String,
    pub path: String,
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: Option<i64>,
}

pub fn load_config() -> AcmeConfig {
    let path = crate::paths::p(ACME_CONFIG_PATH);
    fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_config(cfg: &AcmeConfig) -> Result<(), String> {
    let raw = serde_json::to_vec_pretty(cfg).map_err(|e| format!("serialize acme config: {e}"))?;
    atomic_write(Path::new(&crate::paths::p(ACME_CONFIG_PATH)), &raw, 0o600)
}

// ---------------------------------------------------------------------------
// Base64URL + JWS ES256 / EAB HS256 helpers (RFC 7515, RFC 7638, RFC 8555)
// ---------------------------------------------------------------------------

pub fn b64url(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = u32::from(data[i]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
    }
    out
}

/// Convert ASN.1 DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to fixed 64-byte P1363 `r || s`.
pub fn der_sig_to_p1363(der: &[u8]) -> Result<[u8; 64], String> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err("invalid DER ECDSA signature header".into());
    }
    let mut idx = 2usize;
    if der[1] & 0x80 != 0 {
        let nbytes = (der[1] & 0x7f) as usize;
        idx = 2 + nbytes;
    }
    let read_int = |pos: &mut usize| -> Result<[u8; 32], String> {
        if *pos + 2 > der.len() || der[*pos] != 0x02 {
            return Err("expected DER INTEGER".into());
        }
        let len = der[*pos + 1] as usize;
        *pos += 2;
        if *pos + len > der.len() {
            return Err("truncated DER INTEGER".into());
        }
        let slice = &der[*pos..*pos + len];
        *pos += len;
        let trimmed = slice.iter().position(|&b| b != 0).map_or(&slice[slice.len()..], |p| &slice[p..]);
        if trimmed.len() > 32 {
            return Err("DER INTEGER exceeds 32 bytes for P-256".into());
        }
        let mut out = [0u8; 32];
        out[32 - trimmed.len()..].copy_from_slice(trimmed);
        Ok(out)
    };
    let r = read_int(&mut idx)?;
    let s = read_int(&mut idx)?;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s);
    Ok(sig)
}

/// Canonical RFC 7638 JWK JSON and SHA-256 thumbprint for a P-256 `(x, y)` public point.
pub fn p256_jwk_and_thumbprint(x: &[u8; 32], y: &[u8; 32]) -> (serde_json::Value, String) {
    let xb = b64url(x);
    let yb = b64url(y);
    // Keys MUST be in lexicographical order for RFC 7638 thumbprint.
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{xb}","y":"{yb}"}}"#);
    let thumb = b64url(&Sha256::digest(canonical.as_bytes()));
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": xb,
        "y": yb,
    });
    (jwk, thumb)
}

/// Build an RFC 8555 Section 7.3.4 External Account Binding (EAB) JWS object using HS256.
pub fn build_eab_jws(
    eab_kid: &str,
    eab_hmac_b64: &str,
    new_account_url: &str,
    account_jwk: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let hmac_key = decode_base64_std(eab_hmac_b64.trim())?;
    let protected = serde_json::json!({
        "alg": "HS256",
        "kid": eab_kid.trim(),
        "url": new_account_url,
    });
    let prot_b64 = b64url(protected.to_string().as_bytes());
    let pay_b64 = b64url(account_jwk.to_string().as_bytes());
    let signing_input = format!("{prot_b64}.{pay_b64}");
    let mac = hmac_sha256(&hmac_key, signing_input.as_bytes());
    Ok(serde_json::json!({
        "protected": prot_b64,
        "payload": pay_b64,
        "signature": b64url(&mac),
    }))
}

async fn ensure_account_key(key_path: &Path) -> Result<([u8; 32], [u8; 32]), String> {
    if !key_path.exists() {
        let out = run(
            "openssl",
            &["ecparam", "-name", "prime256v1", "-genkey", "-noout"],
            ExecOpts::new(10, 16 * 1024),
        )
        .await?;
        if !out.ok() {
            return Err(format!("generate ACME account key: {}", out.err_summary("openssl")));
        }
        atomic_write(key_path, &out.stdout, 0o600)?;
    }
    let pub_out = run(
        "openssl",
        &["ec", "-in", key_path.to_str().unwrap_or(""), "-pubout", "-outform", "DER"],
        ExecOpts::new(10, 16 * 1024),
    )
    .await?;
    if !pub_out.ok() {
        return Err(format!("read ACME account pubkey: {}", pub_out.err_summary("openssl")));
    }
    let der = &pub_out.stdout;
    if der.len() < 65 || der[der.len() - 65] != 0x04 {
        return Err("unexpected P-256 SubjectPublicKeyInfo DER layout".into());
    }
    let pt = &der[der.len() - 64..];
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pt[..32]);
    y.copy_from_slice(&pt[32..]);
    Ok((x, y))
}

async fn sign_es256(key_path: &Path, input: &[u8]) -> Result<String, String> {
    let out = run(
        "openssl",
        &["dgst", "-sha256", "-sign", key_path.to_str().unwrap_or("")],
        ExecOpts::new(10, 16 * 1024).stdin(input.to_vec()),
    )
    .await?;
    if !out.ok() {
        return Err(format!("ES256 sign failed: {}", out.err_summary("openssl")));
    }
    let sig = der_sig_to_p1363(&out.stdout)?;
    Ok(b64url(&sig))
}

async fn generate_domain_key_and_csr_der(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_out = run(
        "openssl",
        &["ecparam", "-name", "prime256v1", "-genkey", "-noout"],
        ExecOpts::new(10, 16 * 1024),
    )
    .await?;
    if !key_out.ok() {
        return Err(format!("generate cert private key: {}", key_out.err_summary("openssl")));
    }
    let tmp_dir = PathBuf::from(crate::paths::p("/tmp/cellcore"));
    let _ = fs::create_dir_all(&tmp_dir);
    let tmp_key = tmp_dir.join(format!("acme-domain-{}.key", crate::auth::now_secs()));
    atomic_write(&tmp_key, &key_out.stdout, 0o600)?;

    let cn = domains.first().map(String::as_str).unwrap_or("cellcore.local");
    let san_list = domains
        .iter()
        .map(|d| format!("DNS:{d}"))
        .collect::<Vec<_>>()
        .join(",");
    let subj = format!("/CN={cn}");
    let san_ext = format!("subjectAltName={san_list}");

    let csr_out = run(
        "openssl",
        &[
            "req",
            "-new",
            "-key",
            tmp_key.to_str().unwrap_or(""),
            "-subj",
            &subj,
            "-addext",
            &san_ext,
            "-outform",
            "DER",
        ],
        ExecOpts::new(10, 64 * 1024),
    )
    .await;
    let _ = fs::remove_file(&tmp_key);
    let csr = csr_out?;
    if !csr.ok() || csr.stdout.is_empty() {
        return Err(format!("generate CSR failed: {}", csr.err_summary("openssl")));
    }
    Ok((key_out.stdout, csr.stdout))
}

// ---------------------------------------------------------------------------
// ACME HTTPS transport (via curl with header capture for Replay-Nonce & Location)
// ---------------------------------------------------------------------------

struct AcmeHttpResp {
    status: u16,
    nonce: Option<String>,
    location: Option<String>,
    body: String,
}

fn curl_esc(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 2);
    out.push('"');
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn acme_http(method: &str, url: &str, body: Option<&str>) -> Result<AcmeHttpResp, String> {
    let hdr_file = PathBuf::from(crate::paths::p("/tmp/cellcore"))
        .join(format!("acme-hdr-{}-{}.txt", std::process::id(), crate::auth::now_secs()));
    let _ = fs::create_dir_all(hdr_file.parent().unwrap_or(Path::new("/tmp")));
    let mut cfg = format!(
        "url = {}\nrequest = {}\nsilent\nshow-error\nmax-time = {ACME_HTTP_TIMEOUT_SECS}\nproto = \"=https\"\ndump-header = {}\nheader = \"User-Agent: CellCore/1.0.0\"\nwrite-out = \"\\n%{{http_code}}\"\n",
        curl_esc(url),
        curl_esc(method),
        curl_esc(hdr_file.to_str().unwrap_or("/tmp/acme-hdr.txt")),
    );
    if method == "HEAD" {
        cfg.push_str("head\n");
    }
    if let Some(b) = body {
        cfg.push_str("header = \"Content-Type: application/jose+json\"\n");
        cfg.push_str(&format!("data-raw = {}\n", curl_esc(b)));
    }
    let out = run(
        "curl",
        &["-q", "-K", "-"],
        ExecOpts::new(ACME_HTTP_TIMEOUT_SECS + 4, 512 * 1024).stdin(cfg.into_bytes()),
    )
    .await;
    let hdr_raw = fs::read_to_string(&hdr_file).unwrap_or_default();
    let _ = fs::remove_file(&hdr_file);
    let out = out?;
    if !out.ok() {
        return Err(out.err_summary("acme-http"));
    }

    let mut nonce = None;
    let mut location = None;
    for line in hdr_raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if kl == "replay-nonce" && !val.is_empty() {
                nonce = Some(val);
            } else if kl == "location" && !val.is_empty() {
                location = Some(val);
            }
        }
    }

    let raw = out.stdout_str();
    let (resp_body, code_str) = raw.rsplit_once('\n').unwrap_or(("", raw.trim()));
    let status: u16 = code_str.trim().parse().unwrap_or(0);
    Ok(AcmeHttpResp {
        status,
        nonce,
        location,
        body: resp_body.to_string(),
    })
}

async fn post_jws(
    key_path: &Path,
    url: &str,
    nonce: &mut String,
    kid: Option<&str>,
    jwk: Option<&serde_json::Value>,
    payload: Option<&serde_json::Value>,
) -> Result<AcmeHttpResp, String> {
    let mut protected = serde_json::json!({
        "alg": "ES256",
        "nonce": nonce.as_str(),
        "url": url,
    });
    if let Some(k) = kid {
        protected["kid"] = serde_json::json!(k);
    } else if let Some(j) = jwk {
        protected["jwk"] = j.clone();
    }
    let prot_b64 = b64url(protected.to_string().as_bytes());
    let pay_b64 = match payload {
        Some(p) => b64url(p.to_string().as_bytes()),
        None => String::new(), // POST-as-GET (RFC 8555 §6.3)
    };
    let signing_input = format!("{prot_b64}.{pay_b64}");
    let sig = sign_es256(key_path, signing_input.as_bytes()).await?;
    let body = serde_json::json!({
        "protected": prot_b64,
        "payload": pay_b64,
        "signature": sig,
    })
    .to_string();
    let resp = acme_http("POST", url, Some(&body)).await?;
    if let Some(n) = &resp.nonce {
        *nonce = n.clone();
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Active certificate inspection
// ---------------------------------------------------------------------------

pub async fn inspect_active_cert() -> ActiveCertInfo {
    let acme_c = crate::paths::p(ACME_CERT_PATH);
    let self_c = crate::paths::p("/etc/cellcore/tls/cert.pem");
    let uhttpd_c = crate::paths::p("/etc/uhttpd.crt");

    let (source, path) = if Path::new(&acme_c).exists() {
        ("acme", acme_c)
    } else if Path::new(&self_c).exists() {
        ("self-signed", self_c)
    } else if Path::new(&uhttpd_c).exists() {
        ("uhttpd", uhttpd_c)
    } else {
        return ActiveCertInfo {
            source: "none".into(),
            ..Default::default()
        };
    };

    let out = match run(
        "openssl",
        &[
            "x509",
            "-in",
            &path,
            "-noout",
            "-subject",
            "-issuer",
            "-dates",
            "-ext",
            "subjectAltName",
        ],
        ExecOpts::new(6, 32 * 1024),
    )
    .await
    {
        Ok(o) if o.ok() => o.stdout_str(),
        _ => {
            return ActiveCertInfo {
                source: source.into(),
                path,
                ..Default::default()
            };
        }
    };

    let mut info = ActiveCertInfo {
        source: source.into(),
        path: path.clone(),
        ..Default::default()
    };
    for line in out.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("subject=") {
            info.subject = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("issuer=") {
            info.issuer = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("notBefore=") {
            info.not_before = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("notAfter=") {
            info.not_after = v.trim().to_string();
        } else if t.contains("DNS:") || t.contains("IP Address:") {
            for part in t.split(',') {
                let p = part.trim();
                if let Some(d) = p.strip_prefix("DNS:") {
                    info.sans.push(d.trim().to_string());
                } else if let Some(ip) = p.strip_prefix("IP Address:") {
                    info.sans.push(ip.trim().to_string());
                }
            }
        }
    }

    // Compute days remaining via openssl -checkend or date parse
    if let Ok(end_epoch) = parse_openssl_not_after_epoch(&info.not_after) {
        let now = crate::auth::now_secs() as i64;
        info.days_remaining = Some((end_epoch - now) / 86_400);
    }
    info
}

/// Parse OpenSSL ASN1 time string like `Feb 19 12:00:00 2027 GMT` into UTC unix timestamp.
pub fn parse_openssl_not_after_epoch(s: &str) -> Result<i64, String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return Err("short date".into());
    }
    let mon: i64 = match parts[0] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Err("unknown month".into()),
    };
    let day: i64 = parts[1].parse().map_err(|_| "bad day")?;
    let hms: Vec<i64> = parts[2]
        .split(':')
        .map(|p| p.parse::<i64>().map_err(|_| "bad time"))
        .collect::<Result<_, _>>()?;
    if hms.len() != 3 {
        return Err("bad hms".into());
    }
    let year: i64 = parts[3].parse().map_err(|_| "bad year")?;
    // Howard Hinnant days_from_civil
    let y = year - i64::from(mon <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = if mon > 2 { mon - 3 } else { mon + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + hms[0] * 3600 + hms[1] * 60 + hms[2])
}

// ---------------------------------------------------------------------------
// Core RFC 8555 issuance flow
// ---------------------------------------------------------------------------

async fn append_log(msg: impl Into<String>) {
    let s = msg.into();
    eprintln!("cellcored: acme: {s}");
    let mut st = run_state().write().await;
    st.log.push(s);
    if st.log.len() > 80 {
        let drop = st.log.len() - 80;
        st.log.drain(0..drop);
    }
}

pub async fn issue_certificate(mut cfg: AcmeConfig) -> Result<String, String> {
    let _guard = issue_lock()
        .try_lock()
        .map_err(|_| "An ACME certificate operation is already in progress".to_string())?;

    if cfg.domains.is_empty() {
        return Err("Configure at least one domain name before issuing a certificate".into());
    }
    for d in &cfg.domains {
        let clean = d.trim();
        if clean.is_empty()
            || clean.len() > 253
            || !clean
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'*')
        {
            return Err(format!("Invalid domain name: {d}"));
        }
        if clean.starts_with("*.") && cfg.validation == ValidationMethod::Http01 {
            return Err("Wildcard domains (*.example.com) require DNS-01 validation".into());
        }
    }

    let dir_url = cfg.issuer.directory_url(&cfg.custom_directory_url)?;
    {
        let mut st = run_state().write().await;
        st.running = true;
        st.last_attempt_ts = Some(crate::auth::now_secs());
        st.last_error = None;
        st.last_message = Some(format!("Starting ACME issuance for {}", cfg.domains.join(", ")));
        st.log.clear();
    }

    let result = issue_inner(&mut cfg, &dir_url).await;
    let mut st = run_state().write().await;
    st.running = false;
    match &result {
        Ok(msg) => {
            st.last_success_ts = Some(crate::auth::now_secs());
            st.last_error = None;
            st.last_message = Some(msg.clone());
            let _ = save_config(&cfg);
        }
        Err(e) => {
            st.last_error = Some(e.clone());
            st.last_message = Some(format!("Failed: {e}"));
        }
    }
    result
}

async fn issue_inner(cfg: &mut AcmeConfig, dir_url: &str) -> Result<String, String> {
    append_log(format!("Fetching ACME directory: {dir_url}")).await;
    let dir_resp = acme_http("GET", dir_url, None).await?;
    if dir_resp.status != 200 {
        return Err(format!("ACME directory HTTP {}: {}", dir_resp.status, dir_resp.body));
    }
    let dir: serde_json::Value = serde_json::from_str(&dir_resp.body)
        .map_err(|e| format!("parse ACME directory JSON: {e}"))?;
    let new_nonce_url = dir["newNonce"].as_str().ok_or("directory missing newNonce")?;
    let new_account_url = dir["newAccount"].as_str().ok_or("directory missing newAccount")?;
    let new_order_url = dir["newOrder"].as_str().ok_or("directory missing newOrder")?;

    let nonce_resp = acme_http("HEAD", new_nonce_url, None).await?;
    let mut nonce = nonce_resp.nonce.ok_or("ACME server did not return Replay-Nonce")?;

    // Load or generate persistent per-issuer ECDSA P-256 account key
    let state_dir = PathBuf::from(crate::paths::p(ACME_STATE_DIR));
    let _ = fs::create_dir_all(&state_dir);
    let acct_key_path = state_dir.join(format!("account_{}.key", cfg.issuer.key_tag()));
    let (pub_x, pub_y) = ensure_account_key(&acct_key_path).await?;
    let (jwk, thumbprint) = p256_jwk_and_thumbprint(&pub_x, &pub_y);

    // Register or locate ACME account
    let acct_cache_key = format!("{}|{}", cfg.issuer.key_tag(), dir_url);
    let kid = if let Some(cached) = cfg.account_urls.get(&acct_cache_key).filter(|u| !u.is_empty()) {
        append_log("Reusing existing ACME account registration").await;
        cached.clone()
    } else {
        append_log("Registering ACME account...").await;
        let mut payload = serde_json::json!({ "termsOfServiceAgreed": true });
        if !cfg.email.trim().is_empty() {
            payload["contact"] = serde_json::json!([format!("mailto:{}", cfg.email.trim())]);
        }
        if !cfg.eab_kid.trim().is_empty() && !cfg.eab_hmac_key.trim().is_empty() {
            let eab = build_eab_jws(&cfg.eab_kid, &cfg.eab_hmac_key, new_account_url, &jwk)?;
            payload["externalAccountBinding"] = eab;
        } else if cfg.issuer.requires_eab() {
            return Err(format!(
                "Issuer '{}' requires External Account Binding (EAB Key ID + HMAC Key)",
                cfg.issuer.key_tag()
            ));
        }
        let resp = post_jws(&acct_key_path, new_account_url, &mut nonce, None, Some(&jwk), Some(&payload)).await?;
        if !(200..300).contains(&resp.status) {
            return Err(format!("ACME newAccount failed (HTTP {}): {}", resp.status, resp.body));
        }
        let loc = resp.location.ok_or("ACME newAccount missing Location header")?;
        cfg.account_urls.insert(acct_cache_key, loc.clone());
        let _ = save_config(cfg);
        loc
    };

    // Create new order
    let identifiers: Vec<serde_json::Value> = cfg
        .domains
        .iter()
        .map(|d| serde_json::json!({ "type": "dns", "value": d.trim() }))
        .collect();
    append_log(format!("Creating order for {} domain(s)...", identifiers.len())).await;
    let order_resp = post_jws(
        &acct_key_path,
        new_order_url,
        &mut nonce,
        Some(&kid),
        None,
        Some(&serde_json::json!({ "identifiers": identifiers })),
    )
    .await?;
    if !(200..300).contains(&order_resp.status) {
        return Err(format!("ACME newOrder failed (HTTP {}): {}", order_resp.status, order_resp.body));
    }
    let order_url = order_resp.location.ok_or("ACME newOrder missing Location header")?;
    let order_json: serde_json::Value = serde_json::from_str(&order_resp.body)
        .map_err(|e| format!("parse order JSON: {e}"))?;
    let finalize_url = order_json["finalize"]
        .as_str()
        .ok_or("order missing finalize URL")?
        .to_string();
    let authzs: Vec<String> = order_json["authorizations"]
        .as_array()
        .ok_or("order missing authorizations")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    // Solve every pending authorization
    let want_type = match cfg.validation {
        ValidationMethod::Dns01 => "dns-01",
        ValidationMethod::Http01 => "http-01",
    };

    for authz_url in &authzs {
        let ar = post_jws(&acct_key_path, authz_url, &mut nonce, Some(&kid), None, None).await?;
        let aj: serde_json::Value = serde_json::from_str(&ar.body)
            .map_err(|e| format!("parse authz JSON: {e}"))?;
        let domain = aj["identifier"]["value"].as_str().unwrap_or("unknown").to_string();
        if aj["status"].as_str() == Some("valid") {
            append_log(format!("Authorization already valid for {domain}")).await;
            continue;
        }
        let ch = aj["challenges"]
            .as_array()
            .and_then(|arr| arr.iter().find(|c| c["type"].as_str() == Some(want_type)))
            .ok_or_else(|| format!("ACME server did not offer {want_type} challenge for {domain}"))?;
        let ch_url = ch["url"].as_str().ok_or("challenge missing url")?.to_string();
        let token = ch["token"].as_str().ok_or("challenge missing token")?.to_string();
        let key_auth = format!("{token}.{thumbprint}");

        let mut dns_handle = None;
        if cfg.validation == ValidationMethod::Http01 {
            append_log(format!("Serving HTTP-01 challenge for {domain} on port 80")).await;
            http01_registry().write().await.insert(token.clone(), key_auth.clone());
        } else {
            let txt_digest = b64url(&Sha256::digest(key_auth.as_bytes()));
            append_log(format!(
                "Publishing DNS-01 TXT for _acme-challenge.{} via {}",
                domain.trim_start_matches("*."),
                cfg.dns_provider.as_str()
            ))
            .await;
            let h = present_txt(cfg.dns_provider, &cfg.dns_credentials, &domain, &txt_digest).await?;
            dns_handle = Some(h);
            let wait = cfg.propagation_seconds.clamp(5, 300);
            append_log(format!("Waiting {wait}s for DNS propagation...")).await;
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }

        // Trigger validation & poll with guaranteed cleanup
        let trigger_res = async {
            append_log(format!("Triggering {want_type} validation for {domain}...")).await;
            let tr = post_jws(
                &acct_key_path,
                &ch_url,
                &mut nonce,
                Some(&kid),
                None,
                Some(&serde_json::json!({})),
            )
            .await?;
            if !(200..300).contains(&tr.status) {
                return Err(format!("challenge trigger HTTP {}: {}", tr.status, tr.body));
            }
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let pr = post_jws(&acct_key_path, authz_url, &mut nonce, Some(&kid), None, None).await?;
                let pj: serde_json::Value = serde_json::from_str(&pr.body).unwrap_or_default();
                match pj["status"].as_str() {
                    Some("valid") => {
                        append_log(format!("Validated {domain} ({want_type})")).await;
                        return Ok(());
                    }
                    Some("invalid") => {
                        return Err(format!("ACME validation failed for {domain}: {}", pr.body));
                    }
                    _ => {}
                }
            }
            Err(format!("Timed out waiting for ACME validation on {domain}"))
        }
        .await;

        if cfg.validation == ValidationMethod::Http01 {
            http01_registry().write().await.remove(&token);
        }
        if let Some(h) = &dns_handle {
            append_log(format!("Cleaning up DNS-01 TXT record {}", h.fqdn)).await;
            let _ = cleanup_txt(&cfg.dns_credentials, h).await;
        }
        trigger_res?;
    }

    // Generate domain private key + CSR and finalize order
    append_log("Generating ECDSA P-256 certificate key & CSR...").await;
    let (domain_key_pem, csr_der) = generate_domain_key_and_csr_der(&cfg.domains).await?;
    let fin_resp = post_jws(
        &acct_key_path,
        &finalize_url,
        &mut nonce,
        Some(&kid),
        None,
        Some(&serde_json::json!({ "csr": b64url(&csr_der) })),
    )
    .await?;
    if !(200..300).contains(&fin_resp.status) {
        return Err(format!("ACME finalize failed (HTTP {}): {}", fin_resp.status, fin_resp.body));
    }

    // Poll order until certificate URL is ready
    let mut cert_url: Option<String> = serde_json::from_str::<serde_json::Value>(&fin_resp.body)
        .ok()
        .and_then(|v| v["certificate"].as_str().map(str::to_string));

    for _ in 0..30 {
        if cert_url.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let or = post_jws(&acct_key_path, &order_url, &mut nonce, Some(&kid), None, None).await?;
        let oj: serde_json::Value = serde_json::from_str(&or.body).unwrap_or_default();
        match oj["status"].as_str() {
            Some("valid") => {
                cert_url = oj["certificate"].as_str().map(str::to_string);
            }
            Some("invalid") => {
                return Err(format!("ACME order became invalid: {}", or.body));
            }
            _ => {}
        }
    }
    let cert_url = cert_url.ok_or("Timed out waiting for ACME certificate issuance")?;

    append_log("Downloading issued certificate chain...").await;
    let cert_resp = post_jws(&acct_key_path, &cert_url, &mut nonce, Some(&kid), None, None).await?;
    if !(200..300).contains(&cert_resp.status) || !cert_resp.body.contains("BEGIN CERTIFICATE") {
        return Err(format!("Certificate download failed (HTTP {})", cert_resp.status));
    }

    // Persist atomically to /etc/ssl/acme/ (picked up automatically by http.rs TLS hot-reloader)
    let cert_path = PathBuf::from(crate::paths::p(ACME_CERT_PATH));
    let key_path = PathBuf::from(crate::paths::p(ACME_KEY_PATH));
    if let Some(p) = cert_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    atomic_write(&key_path, &domain_key_pem, 0o600)?;
    atomic_write(&cert_path, cert_resp.body.as_bytes(), 0o644)?;

    let summary = format!(
        "Issued {} certificate for {} (TLS hot-reloads automatically)",
        cfg.issuer.key_tag(),
        cfg.domains.join(", ")
    );
    append_log(summary.clone()).await;
    Ok(summary)
}

/// Background renewal loop: checks every 6 hours and renews automatically when due.
pub fn spawn_renewal_task() {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            let cfg = load_config();
            if cfg.enabled && !cfg.domains.is_empty() {
                let active = inspect_active_cert().await;
                let needs_renew = active.source != "acme"
                    || active
                        .days_remaining
                        .is_none_or(|d| d <= i64::from(cfg.renew_before_days));
                if needs_renew {
                    eprintln!("cellcored: acme: automatic renewal triggered");
                    if let Err(e) = issue_certificate(cfg).await {
                        eprintln!("cellcored: acme: automatic renewal failed: {e}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// HTTP API handlers (`/api/v1/system/acme*`)
// ---------------------------------------------------------------------------

fn redacted_config(cfg: &AcmeConfig) -> serde_json::Value {
    let saved_dns_keys: Vec<String> = cfg
        .dns_credentials
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, _)| k.clone())
        .collect();
    serde_json::json!({
        "enabled": cfg.enabled,
        "issuer": cfg.issuer,
        "customDirectoryUrl": cfg.custom_directory_url,
        "email": cfg.email,
        "domains": cfg.domains,
        "validation": cfg.validation,
        "eabKid": cfg.eab_kid,
        "hasEabHmacKey": !cfg.eab_hmac_key.trim().is_empty(),
        "dnsProvider": cfg.dns_provider,
        "savedDnsCredentialKeys": saved_dns_keys,
        "propagationSeconds": cfg.propagation_seconds,
        "renewBeforeDays": cfg.renew_before_days,
    })
}

pub async fn get_acme(State(_ctx): State<HttpCtx>) -> Response {
    let cfg = load_config();
    let cert = inspect_active_cert().await;
    let status = run_state().read().await.clone();
    Json(serde_json::json!({
        "status": "ok",
        "cert": cert,
        "config": redacted_config(&cfg),
        "runState": status,
    }))
    .into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PutAcmeReq {
    pub enabled: Option<bool>,
    pub issuer: Option<AcmeIssuer>,
    pub custom_directory_url: Option<String>,
    pub email: Option<String>,
    pub domains: Option<Vec<String>>,
    pub validation: Option<ValidationMethod>,
    pub eab_kid: Option<String>,
    pub eab_hmac_key: Option<String>,
    pub clear_eab: bool,
    pub dns_provider: Option<DnsProvider>,
    pub dns_credentials: Option<HashMap<String, String>>,
    pub propagation_seconds: Option<u64>,
    pub renew_before_days: Option<u32>,
}

pub async fn put_acme(State(ctx): State<HttpCtx>, Json(req): Json<PutAcmeReq>) -> Response {
    let mut cfg = load_config();
    if let Some(e) = req.enabled {
        cfg.enabled = e;
    }
    if let Some(iss) = req.issuer {
        cfg.issuer = iss;
    }
    if let Some(u) = req.custom_directory_url {
        cfg.custom_directory_url = u.trim().to_string();
    }
    if let Some(em) = req.email {
        cfg.email = em.trim().to_string();
    }
    if let Some(doms) = req.domains {
        cfg.domains = doms
            .into_iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
    }
    if let Some(v) = req.validation {
        cfg.validation = v;
    }
    if req.clear_eab {
        cfg.eab_kid.clear();
        cfg.eab_hmac_key.clear();
    } else {
        if let Some(k) = req.eab_kid {
            cfg.eab_kid = k.trim().to_string();
        }
        if let Some(h) = req.eab_hmac_key
            && !h.trim().is_empty()
        {
            cfg.eab_hmac_key = h.trim().to_string();
        }
    }
    if let Some(p) = req.dns_provider {
        if p != cfg.dns_provider {
            cfg.dns_credentials.clear();
        }
        cfg.dns_provider = p;
    }
    if let Some(creds) = req.dns_credentials {
        for (k, v) in creds {
            if !v.trim().is_empty() {
                cfg.dns_credentials.insert(k, v.trim().to_string());
            }
        }
    }
    if let Some(ps) = req.propagation_seconds {
        cfg.propagation_seconds = ps.clamp(5, 300);
    }
    if let Some(rb) = req.renew_before_days {
        cfg.renew_before_days = rb.clamp(7, 60);
    }

    if let Err(e) = save_config(&cfg) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "error": e })),
        )
            .into_response();
    }
    ctx.app.push_daemon_log(format!(
        "ACME config updated (issuer={}, validation={:?})",
        cfg.issuer.key_tag(),
        cfg.validation
    ));
    let cert = inspect_active_cert().await;
    let status = run_state().read().await.clone();
    Json(serde_json::json!({
        "status": "ok",
        "cert": cert,
        "config": redacted_config(&cfg),
        "runState": status,
    }))
    .into_response()
}

pub async fn post_acme_issue(State(ctx): State<HttpCtx>) -> Response {
    let cfg = load_config();
    if cfg.domains.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "Save at least one domain before starting certificate issuance"
            })),
        )
            .into_response();
    }
    if issue_lock().try_lock().is_err() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "error": "An ACME issuance is already running"
            })),
        )
            .into_response();
    }
    // Spawn in background so long DNS-01 propagation doesn't hit browser HTTP timeouts; UI polls GET /api/v1/system/acme
    let app = ctx.app.clone();
    tokio::spawn(async move {
        let res = issue_certificate(cfg).await;
        match res {
            Ok(msg) => app.push_daemon_log(format!("ACME: {msg}")),
            Err(e) => app.push_daemon_log(format!("ACME failed: {e}")),
        }
    });
    Json(serde_json::json!({
        "status": "ok",
        "started": true,
        "message": "ACME certificate issuance started"
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_encodes_without_padding() {
        assert_eq!(b64url(b"hello"), "aGVsbG8");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn issuer_urls_and_eab_requirements_match_spec() {
        assert_eq!(
            AcmeIssuer::Letsencrypt.directory_url("").unwrap(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(
            AcmeIssuer::Zerossl.directory_url("").unwrap(),
            "https://acme.zerossl.com/v2/DV90"
        );
        assert_eq!(
            AcmeIssuer::Google.directory_url("").unwrap(),
            "https://dv.acme-v02.api.pki.goog/directory"
        );
        assert!(!AcmeIssuer::Letsencrypt.requires_eab());
        assert!(AcmeIssuer::Zerossl.requires_eab());
        assert!(AcmeIssuer::Google.requires_eab());
        assert!(AcmeIssuer::Custom.directory_url("http://insecure").is_err());
        assert!(AcmeIssuer::Custom.directory_url("https://ca.local/acme/directory").is_ok());
    }

    #[test]
    fn eab_jws_signs_account_jwk_with_hs256() {
        let (jwk, thumb) = p256_jwk_and_thumbprint(&[1u8; 32], &[2u8; 32]);
        assert_eq!(thumb.len(), 43); // 32 bytes base64url without padding
        let eab = build_eab_jws(
            "test-eab-kid",
            "c3VwZXJzZWNyZXRrZXk=",
            "https://dv.acme-v02.api.pki.goog/new-account",
            &jwk,
        )
        .unwrap();
        assert!(eab["protected"].as_str().unwrap().len() > 20);
        assert!(eab["payload"].as_str().unwrap().len() > 20);
        assert_eq!(eab["signature"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn parses_openssl_not_after_timestamp() {
        let ts = parse_openssl_not_after_epoch("Feb 19 12:00:00 2027 GMT").unwrap();
        assert_eq!(ts, 1_803_038_400);
    }

    #[test]
    fn der_ecdsa_signature_converts_to_fixed_64_bytes() {
        // Minimal valid DER SEQUENCE with 33-byte r (leading 0x00) and 31-byte s
        let mut der = vec![0x30, 68, 0x02, 33, 0x00];
        der.extend_from_slice(&[0xaa; 32]);
        der.push(0x02);
        der.push(31);
        der.extend_from_slice(&[0xbb; 31]);
        let sig = der_sig_to_p1363(&der).unwrap();
        assert_eq!(&sig[..32], &[0xaa; 32]);
        assert_eq!(sig[32], 0x00);
        assert_eq!(&sig[33..], &[0xbb; 31]);
    }
}

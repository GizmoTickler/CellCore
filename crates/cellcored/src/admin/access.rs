//! Access › dropbear settings (uci `dropbear`) and `/etc/dropbear/authorized_keys`.
//!
//! Lock-out guards:
//! - password login can only be turned off while at least one key without a
//!   forced command exists, and the last such key cannot be removed while
//!   password login is off;
//! - dropbear changes are applied, then verified (running and listening on the new
//!   port); on failure the previous config is restored and dropbear restarted.

use std::time::Duration;

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    audit, bad, conflict, exec::{KIB, run_ok}, mutate_lock, ok, require_confirm, server,
    services::service_state,
    ucicfg::{self, Op, of_type},
    validate::parse_port,
};
use crate::http::HttpCtx;

pub const AUTH_KEYS_PATH: &str = "/etc/dropbear/authorized_keys";
const MAX_KEYS_FILE: usize = 64 * 1024;
const MAX_KEYS: usize = 50;

// ── base64 (standard alphabet) ──────────────────────────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding, and 1 leftover char is never valid.
    if bits >= 6 || acc != 0 {
        return None;
    }
    Some(out)
}

pub fn b64_encode_nopad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

// ── SSH public keys ─────────────────────────────────────────────────────────

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthKey {
    pub line: usize,
    pub key_type: String,
    pub bits: u32,
    pub fingerprint: String,
    pub comment: String,
    pub options: Option<String>,
    /// Forced command (`command="…"`): the key cannot open a shell.
    pub forced_command: Option<String>,
}

impl AuthKey {
    pub fn grants_shell(&self) -> bool {
        self.forced_command.is_none() && !self.options.as_deref().is_some_and(|o| has_option(o, "restrict"))
    }
}

fn read_wire_string(b: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len_bytes: [u8; 4] = b.get(*pos..*pos + 4)?.try_into().ok()?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    *pos += 4;
    let v = b.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    Some(v)
}

/// Split an authorized_keys options prefix at the first unquoted whitespace.
fn split_options(line: &str) -> Option<(&str, &str)> {
    let mut in_q = false;
    let mut esc = false;
    for (i, c) in line.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if in_q => esc = true,
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => return Some((&line[..i], line[i..].trim_start())),
            _ => {}
        }
    }
    None
}

fn has_option(opts: &str, name: &str) -> bool {
    opts.split(',').any(|o| o.trim().eq_ignore_ascii_case(name))
}

fn forced_command(opts: &str) -> Option<String> {
    let idx = opts.to_ascii_lowercase().find("command=\"")?;
    let rest = &opts[idx + 9..];
    let mut out = String::new();
    let mut esc = false;
    for c in rest.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// Parse one authorized_keys line. `Ok(None)` for blank lines and comments.
pub fn parse_key_line(raw: &str, line_no: usize) -> Result<Option<AuthKey>, String> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if line.len() > 16 * 1024 || line.chars().any(|c| c.is_control() && c != '\t') {
        return Err("key line too long or contains control characters".into());
    }
    let first = line.split_whitespace().next().unwrap_or("");
    let (options, rest) = if KEY_TYPES.contains(&first) {
        (None, line)
    } else {
        let (o, r) = split_options(line).ok_or("expected '<type> <base64> [comment]'")?;
        (Some(o.to_string()), r)
    };
    let mut parts = rest.splitn(3, char::is_whitespace);
    let key_type = parts.next().unwrap_or("").to_string();
    let b64 = parts.next().unwrap_or("");
    let comment = parts.next().unwrap_or("").trim().to_string();
    if !KEY_TYPES.contains(&key_type.as_str()) {
        return Err(format!("unsupported key type {key_type:?}"));
    }
    let blob = b64_decode(b64).ok_or("key data is not valid base64")?;
    let mut pos = 0;
    let inner_type = read_wire_string(&blob, &mut pos).ok_or("truncated key data")?;
    if inner_type != key_type.as_bytes() {
        return Err("key type does not match the encoded key".into());
    }
    let bits = match key_type.as_str() {
        "ssh-rsa" => {
            let _e = read_wire_string(&blob, &mut pos).ok_or("truncated RSA exponent")?;
            let n = read_wire_string(&blob, &mut pos).ok_or("truncated RSA modulus")?;
            let n: Vec<u8> = n.into_iter().skip_while(|&b| b == 0).collect();
            match n.first() {
                Some(&hi) => ((n.len() - 1) * 8) as u32 + (8 - hi.leading_zeros()),
                None => return Err("empty RSA modulus".into()),
            }
        }
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
            let pk = read_wire_string(&blob, &mut pos).ok_or("truncated ed25519 key")?;
            if pk.len() != 32 {
                return Err("ed25519 key must be 32 bytes".into());
            }
            256
        }
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => 256,
        "ecdsa-sha2-nistp384" => 384,
        "ecdsa-sha2-nistp521" => 521,
        _ => 1024,
    };
    let fingerprint = format!("SHA256:{}", b64_encode_nopad(&Sha256::digest(&blob)));
    let forced = options.as_deref().and_then(forced_command);
    Ok(Some(AuthKey { line: line_no, key_type, bits, fingerprint, comment, options, forced_command: forced }))
}

pub fn parse_authorized_keys(text: &str) -> (Vec<AuthKey>, Vec<(usize, String)>) {
    let mut keys = Vec::new();
    let mut errors = Vec::new();
    for (i, l) in text.lines().enumerate() {
        match parse_key_line(l, i + 1) {
            Ok(Some(k)) => keys.push(k),
            Ok(None) => {}
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (keys, errors)
}

/// New file content with every line carrying `fingerprint` removed.
pub fn remove_key(text: &str, fingerprint: &str) -> (String, usize) {
    let mut removed = 0;
    let mut out = String::with_capacity(text.len());
    for (i, l) in text.lines().enumerate() {
        if let Ok(Some(k)) = parse_key_line(l, i + 1)
            && k.fingerprint == fingerprint
        {
            removed += 1;
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    (out, removed)
}

/// Would the box still be reachable over SSH after this change?
pub fn ssh_access_ok(keys: &[AuthKey], password_login: bool) -> bool {
    password_login || keys.iter().any(AuthKey::grants_shell)
}

/// The crash-safe writer: unique 0600 temp file, fsync, rename, fsync of
/// /etc/dropbear (a lost rename here can lock the owner out of SSH).
fn write_keys_atomic(content: &str) -> Result<(), String> {
    crate::state::atomic_write(std::path::Path::new(AUTH_KEYS_PATH), content.as_bytes(), 0o600)
}

fn read_keys_file() -> String {
    std::fs::read(crate::paths::p(AUTH_KEYS_PATH))
        .map(|b| String::from_utf8_lossy(&b[..b.len().min(MAX_KEYS_FILE)]).into_owned())
        .unwrap_or_default()
}

// ── listening sockets (/proc/net/tcp{,6}) ───────────────────────────────────

/// Ports in LISTEN state from /proc/net/tcp or /proc/net/tcp6 text.
pub fn parse_listen_ports(text: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let _sl = it.next()?;
            let local = it.next()?;
            let _rem = it.next()?;
            let st = it.next()?;
            if st != "0A" {
                return None;
            }
            let port_hex = local.rsplit_once(':')?.1;
            u16::from_str_radix(port_hex, 16).ok()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn listening_ports() -> Vec<u16> {
    let mut v = Vec::new();
    for p in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(t) = std::fs::read_to_string(p) {
            v.extend(parse_listen_ports(&t));
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

// ── dropbear config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DropbearCfg {
    pub id: String,
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub root_password_auth: bool,
    pub interface: String,
    pub max_auth_tries: Option<String>,
}

impl DropbearCfg {
    /// Root is the only account; it can log in with a password only when both
    /// flags are on (dropbear `-s` disables all, `-g` disables root).
    pub fn password_login(&self) -> bool {
        self.password_auth && self.root_password_auth
    }
}

pub fn dropbear_instances(sections: &[ucicfg::UciSection]) -> Vec<DropbearCfg> {
    of_type(sections, "dropbear")
        .into_iter()
        .map(|s| DropbearCfg {
            id: s.id.clone(),
            enabled: s.flag("enable", true),
            port: s.get("Port").and_then(|p| p.parse().ok()).unwrap_or(22),
            password_auth: s.flag("PasswordAuth", true),
            root_password_auth: s.flag("RootPasswordAuth", true),
            interface: s.get_or("Interface", "").to_string(),
            max_auth_tries: s.get("MaxAuthTries").map(str::to_string),
        })
        .collect()
}

async fn network_interfaces() -> Vec<String> {
    ucicfg::show("network")
        .await
        .map(|s| of_type(&s, "interface").into_iter().map(|i| i.id.clone()).collect())
        .unwrap_or_default()
}

pub async fn get_access() -> Response {
    let sections = match ucicfg::show("dropbear").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let text = read_keys_file();
    let (keys, errors) = parse_authorized_keys(&text);
    let instances = dropbear_instances(&sections);
    let state = service_state("dropbear").await;
    ok(serde_json::json!({
        "instances": instances,
        "service": state,
        "listening": listening_ports(),
        "interfaces": network_interfaces().await,
        "keys": keys,
        "keyErrors": errors.into_iter().map(|(l, e)| serde_json::json!({ "line": l, "error": e })).collect::<Vec<_>>(),
        "shellKeys": keys.iter().filter(|k| k.grants_shell()).count(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropbearReq {
    id: String,
    port: String,
    password_auth: bool,
    root_password_auth: bool,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_dropbear(State(ctx): State<HttpCtx>, Json(req): Json<DropbearReq>) -> Response {
    let Some(port) = parse_port(req.port.trim()) else {
        return bad("Port must be 1–65535");
    };
    let _g = mutate_lock().await;
    let sections = match ucicfg::show("dropbear").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let instances = dropbear_instances(&sections);
    let Some(cur) = instances.iter().find(|i| i.id == req.id).cloned() else {
        return bad("Unknown dropbear instance");
    };
    if !req.interface.is_empty() && !network_interfaces().await.contains(&req.interface) {
        return bad("Unknown network interface");
    }
    let (keys, _) = parse_authorized_keys(&read_keys_file());
    if !ssh_access_ok(&keys, req.password_auth && req.root_password_auth) {
        return conflict("Password login cannot be turned off: there is no authorized key that can open a shell. Add one first.");
    }
    let risky = port != cur.port || req.interface != cur.interface;
    if risky
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "APPLY",
            "Changing the SSH port or listening interface can cut off SSH clients (including automation). Type APPLY to continue.",
        )
    {
        return r;
    }
    if port != cur.port && listening_ports().contains(&port) {
        return conflict(format!("Port {port} is already in use by another service"));
    }

    let snapshot = match ucicfg::export("dropbear").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let ops = vec![
        Op::set(&cur.id, "Port", port.to_string()),
        Op::set(&cur.id, "PasswordAuth", if req.password_auth { "on" } else { "off" }),
        Op::set(&cur.id, "RootPasswordAuth", if req.root_password_auth { "on" } else { "off" }),
        Op::set_or_clear(&cur.id, "Interface", &req.interface),
    ];
    if let Err(e) = ucicfg::apply("dropbear", None, ops).await {
        return server(e);
    }
    let restart = run_ok("/etc/init.d/dropbear", &["restart"], 20, 16 * KIB).await;

    // Verify: dropbear running and listening on the new port.
    let mut verified = false;
    if restart.is_ok() {
        for _ in 0..12 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if service_state("dropbear").await.running && listening_ports().contains(&port) {
                verified = true;
                break;
            }
        }
    }
    if !verified {
        let rb = ucicfg::restore_snapshot("dropbear", &snapshot).await;
        let rs = run_ok("/etc/init.d/dropbear", &["restart"], 20, 16 * KIB).await;
        audit(&ctx, format!("dropbear change failed verification; rolled back (restore {:?}, restart {:?})", rb.is_ok(), rs.is_ok()));
        return server(format!(
            "dropbear did not come back on port {port}; the previous settings were restored.{}",
            restart.err().map(|e| format!(" ({e})")).unwrap_or_default()
        ));
    }
    audit(&ctx, format!("dropbear: port={port} password={} root_password={} iface={:?}", req.password_auth, req.root_password_auth, req.interface));
    ok(serde_json::json!({ "status": "ok", "port": port }))
}

#[derive(Deserialize)]
pub struct AddKeyReq {
    key: String,
}

pub async fn post_key(State(ctx): State<HttpCtx>, Json(req): Json<AddKeyReq>) -> Response {
    let line = req.key.trim();
    if line.lines().count() != 1 {
        return bad("Paste exactly one public key line");
    }
    let key = match parse_key_line(line, 0) {
        Ok(Some(k)) => k,
        Ok(None) => return bad("Empty key"),
        Err(e) => return bad(format!("Not a valid public key: {e}")),
    };
    let _g = mutate_lock().await;
    let text = read_keys_file();
    let (keys, _) = parse_authorized_keys(&text);
    if keys.iter().any(|k| k.fingerprint == key.fingerprint) {
        return conflict("This key is already authorized");
    }
    if keys.len() >= MAX_KEYS || text.len() + line.len() + 1 > MAX_KEYS_FILE {
        return conflict("authorized_keys is full");
    }
    let mut content = text;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(line);
    content.push('\n');
    if let Err(e) = write_keys_atomic(&content) {
        return server(e);
    }
    audit(&ctx, format!("authorized key added {} {}", key.key_type, key.fingerprint));
    ok(serde_json::json!({ "status": "ok", "key": key }))
}

#[derive(Deserialize)]
pub struct DeleteKeyReq {
    fingerprint: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn delete_key(State(ctx): State<HttpCtx>, Json(req): Json<DeleteKeyReq>) -> Response {
    let _g = mutate_lock().await;
    let text = read_keys_file();
    let (keys, _) = parse_authorized_keys(&text);
    let Some(target) = keys.iter().find(|k| k.fingerprint == req.fingerprint).cloned() else {
        return bad("No such key");
    };
    let remaining: Vec<AuthKey> = keys.into_iter().filter(|k| k.fingerprint != req.fingerprint).collect();
    let sections = match ucicfg::show("dropbear").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let pw = dropbear_instances(&sections).iter().any(DropbearCfg::password_login);
    if !ssh_access_ok(&remaining, pw) {
        return conflict("This is the last key that can open a shell and password login is off; removing it would lock you out of SSH.");
    }
    if let Some(cmd) = &target.forced_command
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "REMOVE",
            &format!("This key runs a fixed command ({cmd}); automation such as a failover watchdog may depend on it. Type REMOVE to delete it."),
        )
    {
        return r;
    }
    let (content, n) = remove_key(&text, &req.fingerprint);
    if n == 0 {
        return bad("No such key");
    }
    if let Err(e) = write_keys_atomic(&content) {
        return server(e);
    }
    audit(&ctx, format!("authorized key removed {}", req.fingerprint));
    ok(serde_json::json!({ "status": "ok", "removed": n }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &str = include_str!("fixtures/authorized_keys.txt");

    #[test]
    fn base64_roundtrip() {
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = b64_encode_nopad(s);
            assert_eq!(b64_decode(&enc).unwrap(), s);
        }
        assert_eq!(b64_encode_nopad(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zm9vYg==").unwrap(), b"foob");
        assert!(b64_decode("Zm9v!").is_none());
        assert!(b64_decode("Z").is_none());
    }

    #[test]
    fn parses_keys_and_fingerprints_match_ssh_keygen() {
        let (keys, errors) = parse_authorized_keys(KEYS);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(keys.len(), 3);

        let rsa = &keys[0];
        assert_eq!(rsa.key_type, "ssh-rsa");
        assert_eq!(rsa.bits, 2048);
        assert_eq!(rsa.fingerprint, "SHA256:J3BcQT/4jxqzUCk4bxi8WVWLTLfjqxYKYVUr0PPElJM");
        assert!(rsa.grants_shell());

        let ed = &keys[1];
        assert_eq!(ed.key_type, "ssh-ed25519");
        assert_eq!(ed.bits, 256);
        assert_eq!(ed.fingerprint, "SHA256:+koFzSg8FlrpaYP5o8XIh4a2x7yWtSzBbPfAJqM35Fc");
        assert_eq!(ed.comment, "watchdog");
        assert_eq!(ed.forced_command.as_deref(), Some("/usr/sbin/r10-modem-ctl"));
        assert!(!ed.grants_shell());

        let ec = &keys[2];
        assert_eq!(ec.key_type, "ecdsa-sha2-nistp256");
        assert_eq!(ec.fingerprint, "SHA256:0DztYBHyxH4/NgNZulZeBkCZ6jREvkKvnGhEFGb/Xxo");
        assert_eq!(ec.comment, "ops key");
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(parse_key_line("ssh-ed25519 notbase64!!", 1).is_err());
        assert!(parse_key_line("ssh-foo AAAA", 1).is_err());
        assert!(parse_key_line("garbage", 1).is_err());
        // Type in the blob must match the declared type.
        let ed = KEYS.lines().nth(3).unwrap();
        let b64 = ed.split_whitespace().nth(2).unwrap();
        assert!(parse_key_line(&format!("ssh-rsa {b64}"), 1).is_err());
        assert_eq!(parse_key_line("# comment", 1).unwrap(), None);
        assert_eq!(parse_key_line("   ", 1).unwrap(), None);
    }

    #[test]
    fn options_with_quoted_spaces() {
        let ed = KEYS.lines().nth(3).unwrap();
        let b64 = ed.split_whitespace().nth(2).unwrap();
        let line = format!("from=\"10.0.0.1\",command=\"echo a \\\"b\\\" c\" ssh-ed25519 {b64} c1");
        let k = parse_key_line(&line, 7).unwrap().unwrap();
        assert_eq!(k.forced_command.as_deref(), Some("echo a \"b\" c"));
        assert_eq!(k.comment, "c1");
        assert_eq!(k.line, 7);
        let r = parse_key_line(&format!("restrict ssh-ed25519 {b64}"), 1).unwrap().unwrap();
        assert!(!r.grants_shell());
    }

    #[test]
    fn remove_and_lockout_guard() {
        let (keys, _) = parse_authorized_keys(KEYS);
        let (content, n) = remove_key(KEYS, &keys[0].fingerprint);
        assert_eq!(n, 1);
        assert!(content.starts_with("# managed by test\n"));
        let (left, _) = parse_authorized_keys(&content);
        assert_eq!(left.len(), 2);
        // ecdsa key still grants a shell
        assert!(ssh_access_ok(&left, false));
        let only_forced: Vec<_> = left.into_iter().filter(|k| !k.grants_shell()).collect();
        assert!(!ssh_access_ok(&only_forced, false));
        assert!(ssh_access_ok(&only_forced, true));
    }

    #[test]
    fn parses_listen_ports_from_proc() {
        let v4 = parse_listen_ports(include_str!("fixtures/proc_net_tcp.txt"));
        assert!(v4.contains(&443));
        assert!(v4.contains(&8080));
        let v6 = parse_listen_ports(include_str!("fixtures/proc_net_tcp6.txt"));
        assert!(v6.contains(&53));
    }

    #[test]
    fn dropbear_defaults_and_password_login() {
        let s = ucicfg::parse_uci_show("dropbear", include_str!("fixtures/uci_dropbear.txt"));
        let d = dropbear_instances(&s);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].port, 22);
        assert!(!d[0].password_auth);
        assert!(!d[0].password_login());
        assert!(d[0].enabled);
        let s2 = ucicfg::parse_uci_show("dropbear", "dropbear.x=dropbear\n");
        assert!(dropbear_instances(&s2)[0].password_login());
    }
}

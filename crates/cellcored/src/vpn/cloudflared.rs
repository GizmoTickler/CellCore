//! Cloudflare Tunnel (`cloudflared`) remote-access management.
//!
//! Manages the standalone static `cloudflared` daemon (outbound-only HTTP/2 or
//! QUIC tunnel into Cloudflare Zero Trust for remote CellCore UI, SSH, and
//! WARP private-network routing). Keeps the tunnel token strictly write-only
//! (`0600` at `/etc/cloudflared/token`, passed via `--token-file`, never in
//! argv or GET responses).

use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::paths;
use crate::{
    admin::{
        audit, bad,
        exec::{ExecOpts, KIB, MIB, run, run_ok},
        mutate_lock, ok, require_confirm, server,
    },
    auth::now_secs,
    http::HttpCtx,
};

const BIN_PATH: &str = "/usr/bin/cloudflared";
const INIT_PATH: &str = "/etc/init.d/cloudflared";
const TOKEN_DIR: &str = "/etc/cloudflared";
const TOKEN_PATH: &str = "/etc/cloudflared/token";
const DEFAULT_METRICS_PORT: u16 = 20241;
const GITHUB_RELEASE_API_URL: &str =
    "https://api.github.com/repos/cloudflare/cloudflared/releases/latest";
const ASSET_NAME_ARM64: &str = "cloudflared-linux-arm64";
const EXPECTED_DOWNLOAD_PREFIX: &str =
    "https://github.com/cloudflare/cloudflared/releases/download/";

static INSTALL_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct CloudflaredConfig {
    /// "auto" | "6" | "4"
    pub edge_ip_version: String,
    /// "http2" | "quic" | "auto"
    pub protocol: String,
    /// Optional private IPv4 (/32) bound to `lo` for WARP private network routing.
    pub loopback_ip: Option<String>,
    /// Start automatically on boot (`/etc/init.d/cloudflared enable`).
    pub autostart: bool,
    /// Loopback Prometheus metrics port (`127.0.0.1:<port>`).
    pub metrics_port: u16,
}

impl Default for CloudflaredConfig {
    fn default() -> Self {
        Self {
            edge_ip_version: "auto".into(),
            protocol: "http2".into(),
            loopback_ip: None,
            autostart: true,
            metrics_port: DEFAULT_METRICS_PORT,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct InstallJob {
    pub state: String,
    pub action: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    pub version_after: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveMetrics {
    pub connected: bool,
    pub ha_connections: u32,
    pub edge_locations: Vec<String>,
    pub total_requests: u64,
}

static VERSION_CACHE: Mutex<Option<(u64, String)>> = Mutex::new(None);

fn cfg_file() -> PathBuf {
    paths().state.join("cloudflared.json")
}

fn job_file() -> PathBuf {
    paths().run.join("cloudflared-job.json")
}

fn log_file() -> PathBuf {
    paths().run.join("cloudflared-job.log")
}

fn bin_path() -> PathBuf {
    crate::paths::p(BIN_PATH).into()
}

fn init_path() -> PathBuf {
    crate::paths::p(INIT_PATH).into()
}

fn token_dir() -> PathBuf {
    crate::paths::p(TOKEN_DIR).into()
}

fn token_path() -> PathBuf {
    crate::paths::p(TOKEN_PATH).into()
}

fn pid_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        !s.rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z')
    })
}

pub fn read_job() -> Option<InstallJob> {
    let mut j: InstallJob = serde_json::from_slice(&std::fs::read(job_file()).ok()?).ok()?;
    if j.state == "running" {
        let alive = match j.pid {
            Some(pid) if pid == std::process::id() => INSTALL_IN_PROGRESS.load(Ordering::Acquire),
            Some(pid) => pid_alive(pid),
            None => INSTALL_IN_PROGRESS.load(Ordering::Acquire),
        };
        if !alive {
            j.state = "failed".into();
            j.message = Some("Installer stopped before reporting a result".into());
        }
    }
    Some(j)
}

pub fn job_json() -> serde_json::Value {
    let tail: Vec<String> = std::fs::read_to_string(log_file())
        .unwrap_or_default()
        .lines()
        .rev()
        .take(30)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(str::to_string)
        .collect();
    serde_json::json!({ "job": read_job(), "log": tail })
}

pub fn validate_edge_ip_version(v: &str) -> Result<String, String> {
    let norm = v.trim().to_ascii_lowercase();
    match norm.as_str() {
        "auto" | "4" | "6" => Ok(norm),
        _ => Err("edgeIpVersion must be one of: auto, 6, 4".into()),
    }
}

pub fn validate_protocol(v: &str) -> Result<String, String> {
    let norm = v.trim().to_ascii_lowercase();
    match norm.as_str() {
        "http2" | "quic" | "auto" => Ok(norm),
        _ => Err("protocol must be one of: http2, quic, auto".into()),
    }
}

pub fn validate_loopback_ip(raw: &str) -> Result<Option<String>, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let ip_str = s.strip_suffix("/32").unwrap_or(s);
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| "loopbackIp must be a valid IPv4 address (e.g. 10.254.224.1)".to_string())?;
    let oct = ip.octets();
    let is_cgnat = oct[0] == 100 && (64..=127).contains(&oct[1]);
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("loopbackIp must be a unicast private IPv4 address (not 127.x/0.0.0.0/multicast)".into());
    }
    if !(ip.is_private() || is_cgnat) {
        return Err("loopbackIp must be in RFC1918 (10/8, 172.16/12, 192.168/16) or CGNAT (100.64/10)".into());
    }
    Ok(Some(ip.to_string()))
}

pub fn validate_tunnel_token(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.len() < 32 || t.len() > 4096 {
        return Err("Tunnel token length looks invalid (expected 32–4096 characters)".into());
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=' | b'+' | b'/'))
    {
        return Err("Tunnel token contains invalid characters".into());
    }
    Ok(t.to_string())
}

/// Infer settings from an existing `/etc/init.d/cloudflared` script when
/// `cloudflared.json` has not been created yet (seamless adoption of manually
/// provisioned tunnels).
pub fn parse_init_script_config(script: &str) -> CloudflaredConfig {
    let mut cfg = CloudflaredConfig::default();
    for line in script.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("ip addr replace ")
            && let Some(cidr) = rest.split_whitespace().next()
            && let Ok(Some(ip)) = validate_loopback_ip(cidr)
        {
            cfg.loopback_ip = Some(ip);
        }
        if let Some(idx) = l.find("--edge-ip-version ")
            && let Some(val) = l[idx + "--edge-ip-version ".len()..].split_whitespace().next()
            && let Ok(v) = validate_edge_ip_version(val.trim_end_matches('\\'))
        {
            cfg.edge_ip_version = v;
        }
        if let Some(idx) = l.find("--protocol ")
            && let Some(val) = l[idx + "--protocol ".len()..].split_whitespace().next()
            && let Ok(v) = validate_protocol(val.trim_end_matches('\\'))
        {
            cfg.protocol = v;
        }
        if let Some(idx) = l.find("--metrics 127.0.0.1:")
            && let Some(val) = l[idx + "--metrics 127.0.0.1:".len()..].split_whitespace().next()
            && let Ok(port) = val.trim_end_matches('\\').parse::<u16>()
            && port >= 1024
        {
            cfg.metrics_port = port;
        }
    }
    cfg
}

pub fn load_config() -> CloudflaredConfig {
    let p = cfg_file();
    if p.is_file() {
        return crate::state::load_json_or_default(&p.display().to_string());
    }
    if let Ok(script) = std::fs::read_to_string(init_path()) {
        return parse_init_script_config(&script);
    }
    CloudflaredConfig::default()
}

fn save_config(cfg: &CloudflaredConfig) -> Result<(), String> {
    let dir = paths().state;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create vpn state dir: {e}"))?;
    let bytes = serde_json::to_vec(cfg).map_err(|e| format!("serialize cloudflared config: {e}"))?;
    crate::state::atomic_write(&cfg_file(), &bytes, 0o600)
}

pub fn render_init_script(cfg: &CloudflaredConfig) -> String {
    let port = if cfg.metrics_port >= 1024 {
        cfg.metrics_port
    } else {
        DEFAULT_METRICS_PORT
    };
    let mut loop_cmd = String::new();
    if let Some(ip) = cfg.loopback_ip.as_deref()
        && !ip.is_empty()
    {
        loop_cmd = format!("    ip addr replace {ip}/32 dev lo 2>/dev/null || true\n");
    }
    let proto_line = if cfg.protocol == "auto" {
        String::new()
    } else {
        format!("        --protocol {} \\\n", cfg.protocol)
    };
    format!(
        "#!/bin/sh /etc/rc.common\n\
START=96\n\
STOP=10\n\
USE_PROCD=1\n\
\n\
start_service() {{\n\
    [ -x {BIN_PATH} ] || return 0\n\
    [ -s {TOKEN_PATH} ] || return 0\n\
{loop_cmd}\
    procd_open_instance cloudflared\n\
    procd_set_param command {BIN_PATH} \\\n\
        --no-autoupdate \\\n\
        --edge-ip-version {} \\\n\
        --loglevel warn \\\n\
        --metrics 127.0.0.1:{port} \\\n\
        tunnel run \\\n\
{proto_line}\
        --token-file {TOKEN_PATH}\n\
    procd_set_param env GOMEMLIMIT=48MiB GOGC=50\n\
    procd_set_param respawn 3600 10 0\n\
    procd_set_param stdout 0\n\
    procd_set_param stderr 1\n\
    procd_set_param file {TOKEN_PATH}\n\
    procd_close_instance\n\
}}\n",
        cfg.edge_ip_version,
    )
}

pub fn parse_metrics(body: &str) -> LiveMetrics {
    let mut out = LiveMetrics::default();
    let mut locs: Vec<String> = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_prefix("cloudflared_tunnel_ha_connections ")
            && let Ok(v) = rest.trim().parse::<f64>()
        {
            out.ha_connections = v.max(0.0).round() as u32;
        } else if let Some(rest) = l.strip_prefix("cloudflared_tunnel_total_requests ")
            && let Ok(v) = rest.trim().parse::<f64>()
        {
            out.total_requests = v.max(0.0).round() as u64;
        } else if l.starts_with("cloudflared_tunnel_server_locations{")
            && l.ends_with(" 1")
            && let Some(idx) = l.find("edge_location=\"")
        {
            let rest = &l[idx + "edge_location=\"".len()..];
            if let Some(end) = rest.find('"') {
                let colo = &rest[..end];
                if !colo.is_empty() && !locs.iter().any(|x| x == colo) {
                    locs.push(colo.to_string());
                }
            }
        }
    }
    locs.sort();
    out.edge_locations = locs;
    out.connected = out.ha_connections > 0;
    out
}

async fn scrape_metrics(port: u16) -> Option<LiveMetrics> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = format!("127.0.0.1:{port}");
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
        let req = format!(
            "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::with_capacity(16 * 1024);
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() >= 256 * 1024 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
        Some(parse_metrics(body))
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), fut)
        .await
        .ok()
        .flatten()
}

async fn installed_version() -> Option<String> {
    let p = bin_path();
    let meta = std::fs::metadata(&p).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(g) = VERSION_CACHE.lock()
        && let Some((cached_m, ver)) = g.as_ref()
        && *cached_m == mtime
    {
        return Some(ver.clone());
    }
    let out = run_ok(&p.display().to_string(), &["--version"], 5, 4 * KIB)
        .await
        .ok()?;
    let ver = out
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .strip_prefix("cloudflared version ")
        .unwrap_or_else(|| out.lines().next().unwrap_or("").trim())
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if ver.is_empty() {
        return None;
    }
    if let Ok(mut g) = VERSION_CACHE.lock() {
        *g = Some((mtime, ver.clone()));
    }
    Some(ver)
}

fn is_running() -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return false;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(ent.path().join("comm"))
            && comm.trim() == "cloudflared"
        {
            return true;
        }
    }
    false
}

fn is_enabled_at_boot() -> bool {
    let rc_dir = crate::paths::p("/etc/rc.d");
    let Ok(rd) = std::fs::read_dir(rc_dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let n = e.file_name();
        let s = n.to_string_lossy();
        s.starts_with('S') && s.ends_with("cloudflared")
    })
}

async fn recent_logs() -> Vec<String> {
    let out = run_ok("logread", &[], 3, 256 * KIB).await.unwrap_or_default();
    let lines: Vec<String> = out
        .lines()
        .filter(|l| l.contains("cloudflared"))
        .rev()
        .take(20)
        .map(str::to_string)
        .collect();
    lines.into_iter().rev().collect()
}

pub async fn get_cloudflared() -> Response {
    let installed = bin_path().is_file();
    let version = if installed {
        installed_version().await
    } else {
        None
    };
    let token_configured = std::fs::metadata(token_path())
        .map(|m| m.is_file() && m.len() > 16)
        .unwrap_or(false);
    let cfg = load_config();
    let running = is_running();
    let enabled_at_boot = is_enabled_at_boot();
    let metrics = if running {
        scrape_metrics(cfg.metrics_port).await.unwrap_or_default()
    } else {
        LiveMetrics::default()
    };
    let logs = if installed {
        recent_logs().await
    } else {
        Vec::new()
    };
    ok(serde_json::json!({
        "installed": installed,
        "version": version,
        "tokenConfigured": token_configured,
        "service": {
            "running": running,
            "enabledAtBoot": enabled_at_boot,
        },
        "config": cfg,
        "metrics": metrics,
        "logs": logs,
        "job": job_json(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReq {
    #[serde(default)]
    tunnel_token: Option<String>,
    #[serde(default)]
    edge_ip_version: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    loopback_ip: Option<String>,
    #[serde(default)]
    autostart: Option<bool>,
}

pub async fn post_config(State(ctx): State<HttpCtx>, Json(req): Json<ConfigReq>) -> Response {
    let _g = mutate_lock().await;
    let prev = load_config();
    let mut cfg = prev.clone();

    if let Some(v) = req.edge_ip_version.as_deref() {
        match validate_edge_ip_version(v) {
            Ok(norm) => cfg.edge_ip_version = norm,
            Err(e) => return bad(e),
        }
    }
    if let Some(v) = req.protocol.as_deref() {
        match validate_protocol(v) {
            Ok(norm) => cfg.protocol = norm,
            Err(e) => return bad(e),
        }
    }
    if let Some(v) = req.loopback_ip.as_deref() {
        match validate_loopback_ip(v) {
            Ok(opt) => cfg.loopback_ip = opt,
            Err(e) => return bad(e),
        }
    }
    if let Some(auto) = req.autostart {
        cfg.autostart = auto;
    }

    let new_token = match req.tunnel_token.as_deref() {
        Some(raw) if !raw.trim().is_empty() => match validate_tunnel_token(raw) {
            Ok(t) => Some(t),
            Err(e) => return bad(e),
        },
        _ => None,
    };

    let cfg_for_disk = cfg.clone();
    let tok_for_disk = new_token.clone();
    let disk_res = tokio::task::spawn_blocking(move || -> Result<(), String> {
        if let Some(tok) = tok_for_disk {
            let dir = token_dir();
            std::fs::create_dir_all(&dir).map_err(|e| format!("create token dir: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            crate::state::atomic_write(&token_path(), tok.as_bytes(), 0o600)?;
        }
        save_config(&cfg_for_disk)?;
        let script = render_init_script(&cfg_for_disk);
        crate::state::atomic_write(&init_path(), script.as_bytes(), 0o755)?;
        Ok(())
    })
    .await;

    match disk_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return server(e),
        Err(e) => return server(format!("save task failed: {e}")),
    }

    // Remove previous loopback IP if it changed or was cleared.
    if prev.loopback_ip != cfg.loopback_ip {
        if let Some(old_ip) = prev.loopback_ip.as_deref() {
            let _ = run(
                "ip",
                &["addr", "del", &format!("{old_ip}/32"), "dev", "lo"],
                crate::admin::exec::ExecOpts::new(5, 4 * KIB),
            )
            .await;
        }
        if let Some(new_ip) = cfg.loopback_ip.as_deref() {
            let _ = run(
                "ip",
                &["addr", "replace", &format!("{new_ip}/32"), "dev", "lo"],
                crate::admin::exec::ExecOpts::new(5, 4 * KIB),
            )
            .await;
        }
    }

    let init = init_path().display().to_string();
    let enable_action = if cfg.autostart { "enable" } else { "disable" };
    let _ = run(
        &init,
        &[enable_action],
        crate::admin::exec::ExecOpts::new(10, 8 * KIB),
    )
    .await;

    let has_token = std::fs::metadata(token_path())
        .map(|m| m.is_file() && m.len() > 16)
        .unwrap_or(false);
    let restarted = if bin_path().is_file() && has_token {
        let _ = run(
            &init,
            &["restart"],
            crate::admin::exec::ExecOpts::new(15, 16 * KIB),
        )
        .await;
        true
    } else {
        false
    };

    audit(
        &ctx,
        format!(
            "vpn: cloudflared config saved (edge={}, proto={}, loopback={}, token_updated={}, restarted={})",
            cfg.edge_ip_version,
            cfg.protocol,
            cfg.loopback_ip.as_deref().unwrap_or("none"),
            new_token.is_some(),
            restarted
        ),
    );
    ok(serde_json::json!({
        "config": cfg,
        "tokenConfigured": has_token,
        "restarted": restarted,
    }))
}

#[derive(Deserialize)]
pub struct ServiceReq {
    action: String,
}

pub async fn post_service(State(ctx): State<HttpCtx>, Json(req): Json<ServiceReq>) -> Response {
    if !matches!(
        req.action.as_str(),
        "start" | "stop" | "restart" | "enable" | "disable"
    ) {
        return bad("action must be start, stop, restart, enable or disable");
    }
    if !bin_path().is_file() {
        return bad("cloudflared is not installed yet");
    }
    let _g = mutate_lock().await;
    if !init_path().is_file() {
        let cfg = load_config();
        let script = render_init_script(&cfg);
        if let Err(e) = crate::state::atomic_write(&init_path(), script.as_bytes(), 0o755) {
            return server(e);
        }
    }
    let init = init_path().display().to_string();
    let res = run(
        &init,
        &[&req.action],
        crate::admin::exec::ExecOpts::new(20, 16 * KIB),
    )
    .await;
    match res {
        Ok(r) if r.code == Some(0) => {
            if matches!(req.action.as_str(), "enable" | "disable") {
                let mut cfg = load_config();
                cfg.autostart = req.action == "enable";
                let _ = save_config(&cfg);
            }
            audit(&ctx, format!("vpn: cloudflared service {}", req.action));
            ok(serde_json::json!({ "action": req.action }))
        }
        Ok(r) => server(format!(
            "cloudflared {} failed (rc {:?}): {}",
            req.action,
            r.code,
            r.stderr.trim()
        )),
        Err(e) => server(format!("cloudflared {}: {e}", req.action)),
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extract the `cloudflared-linux-arm64` download URL and pinned SHA-256 digest
/// from a GitHub Releases API JSON response. Fails closed if no valid 64-hex
/// SHA-256 checksum is published or if the download URL is outside the expected
/// GitHub release download prefix.
pub fn parse_release_arm64_asset(release_json: &str) -> Result<(String, String), String> {
    let v: serde_json::Value =
        serde_json::from_str(release_json).map_err(|e| format!("parse GitHub release JSON: {e}"))?;
    let assets = v
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or("GitHub release metadata missing assets array")?;
    let asset = assets
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(ASSET_NAME_ARM64))
        .ok_or("GitHub release missing cloudflared-linux-arm64 asset")?;
    let url = asset
        .get("browser_download_url")
        .and_then(|u| u.as_str())
        .map(str::trim)
        .filter(|u| u.starts_with(EXPECTED_DOWNLOAD_PREFIX))
        .ok_or("cloudflared asset download URL is missing or outside trusted GitHub release prefix")?
        .to_string();

    if let Some(raw_digest) = asset.get("digest").and_then(|d| d.as_str()) {
        let cand = raw_digest
            .trim()
            .strip_prefix("sha256:")
            .unwrap_or(raw_digest.trim());
        if is_sha256_hex(cand) {
            return Ok((url, cand.to_ascii_lowercase()));
        }
    }

    if let Some(body) = v.get("body").and_then(|b| b.as_str()) {
        for line in body.lines() {
            if !line.contains(ASSET_NAME_ARM64) {
                continue;
            }
            for tok in line.split(|c: char| c.is_whitespace() || matches!(c, ':' | '|' | '`' | ',' | ';')) {
                let cand = tok.strip_prefix("sha256:").unwrap_or(tok);
                if is_sha256_hex(cand) {
                    return Ok((url, cand.to_ascii_lowercase()));
                }
            }
        }
    }

    Err("GitHub release metadata did not include a verifiable SHA-256 checksum for cloudflared-linux-arm64".into())
}

/// Verify ELF64 little-endian `EM_AARCH64` (183) header before chmod/exec.
pub fn verify_aarch64_elf_header(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 20 {
        return Err("downloaded cloudflared binary is truncated (< 20 bytes)".into());
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err("downloaded cloudflared file is not an ELF binary".into());
    }
    if bytes[4] != 2 {
        return Err(format!("expected ELF64 binary (EI_CLASS=2), got {}", bytes[4]));
    }
    if bytes[5] != 1 {
        return Err(format!("expected little-endian ELF (EI_DATA=1), got {}", bytes[5]));
    }
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if e_machine != 183 {
        return Err(format!("expected EM_AARCH64 (183) binary, got e_machine={e_machine}"));
    }
    Ok(())
}

/// Stream-verify a downloaded binary's ELF64 aarch64 header AND SHA-256 digest
/// BEFORE marking executable, running `--version`, or moving into place.
pub fn verify_downloaded_binary(path: &Path, expected_sha256: &str) -> Result<String, String> {
    let want = expected_sha256.trim().to_ascii_lowercase();
    if !is_sha256_hex(&want) {
        return Err("expected SHA-256 checksum is invalid".into());
    }
    let mut f = std::fs::File::open(path).map_err(|e| format!("open downloaded binary: {e}"))?;
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(64);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read downloaded binary: {e}"))?;
        if n == 0 {
            break;
        }
        if header.len() < 64 {
            let take = (64 - header.len()).min(n);
            header.extend_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
    }
    verify_aarch64_elf_header(&header)?;
    let actual = hex::encode(hasher.finalize());
    if actual != want {
        return Err(format!("SHA-256 checksum mismatch: expected {want}, got {actual}"));
    }
    Ok(actual)
}

fn append_job_log(line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file())
    {
        let _ = writeln!(f, "[{}] {line}", now_secs());
    }
}

fn save_job(job: &InstallJob) {
    let _ = crate::state::atomic_write(
        &job_file(),
        &serde_json::to_vec(job).unwrap_or_default(),
        0o644,
    );
}

struct InstallGuard;

impl Drop for InstallGuard {
    fn drop(&mut self) {
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }
}

async fn run_verified_install(action: String, started: u64) {
    let _guard = InstallGuard;
    let bp = bin_path();
    let tmp = PathBuf::from(format!("{}.new.{}", bp.display(), std::process::id()));

    let outcome: Result<String, String> = async {
        append_job_log("Fetching latest cloudflared release metadata and SHA-256 checksum from GitHub...");
        let meta = run(
            "curl",
            &[
                "-fsSL",
                "--proto",
                "=https",
                "--connect-timeout",
                "15",
                "--max-time",
                "30",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "User-Agent: CellCore",
                GITHUB_RELEASE_API_URL,
            ],
            ExecOpts::new(35, MIB),
        )
        .await?;
        if !meta.ok() {
            return Err(format!("fetch GitHub release metadata: {}", meta.err_summary("curl")));
        }
        let (download_url, expected_sha) = parse_release_arm64_asset(&meta.stdout_str())?;
        append_job_log(&format!(
            "Downloading {ASSET_NAME_ARM64} (expected SHA-256: {expected_sha})..."
        ));

        let tmp_s = tmp.display().to_string();
        let dl = run(
            "curl",
            &[
                "-fsSL",
                "--proto",
                "=https",
                "--connect-timeout",
                "15",
                "--max-time",
                "240",
                "-o",
                &tmp_s,
                &download_url,
            ],
            ExecOpts::new(250, 64 * KIB),
        )
        .await?;
        if !dl.ok() {
            return Err(format!("download cloudflared: {}", dl.err_summary("curl")));
        }

        // Verify SHA-256 and ELF64 aarch64 header BEFORE chmod +x or executing as root.
        let tmp_chk = tmp.clone();
        let sha_chk = expected_sha.clone();
        tokio::task::spawn_blocking(move || verify_downloaded_binary(&tmp_chk, &sha_chk))
            .await
            .map_err(|e| format!("verification task panicked: {e}"))??;
        append_job_log("Verified SHA-256 checksum and ELF64 aarch64 header");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod downloaded binary: {e}"))?;
        }

        let ver_out = run_ok(&tmp_s, &["--version"], 10, 8 * KIB)
            .await
            .map_err(|e| format!("downloaded binary failed --version check: {e}"))?;
        let ver = ver_out
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .strip_prefix("cloudflared version ")
            .unwrap_or_else(|| ver_out.lines().next().unwrap_or("").trim())
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if ver.is_empty() {
            return Err("downloaded binary returned empty --version output".into());
        }

        if let Some(parent) = bp.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        crate::state::atomic_rename_file(&tmp, &bp)
            .map_err(|e| format!("install binary to {}: {e}", bp.display()))?;
        if let Ok(mut g) = VERSION_CACHE.lock() {
            *g = None;
        }
        let _ = run("sync", &[], ExecOpts::new(10, 4 * KIB)).await;
        append_job_log(&format!("Installed verified cloudflared {ver}"));

        if init_path().is_file()
            && std::fs::metadata(token_path()).is_ok_and(|m| m.is_file() && m.len() > 0)
        {
            append_job_log("Restarting cloudflared service...");
            let init_s = init_path().display().to_string();
            let _ = run(&init_s, &["restart"], ExecOpts::new(20, 16 * KIB)).await;
        }
        Ok(ver)
    }
    .await;

    let _ = std::fs::remove_file(&tmp);
    let finished = now_secs();
    let job = match outcome {
        Ok(ver) => InstallJob {
            state: "succeeded".into(),
            action,
            started_at: started,
            finished_at: Some(finished),
            exit_code: Some(0),
            pid: Some(std::process::id()),
            version_after: Some(ver),
            message: None,
        },
        Err(e) => {
            append_job_log(&format!("FAILED: {e}"));
            InstallJob {
                state: "failed".into(),
                action,
                started_at: started,
                finished_at: Some(finished),
                exit_code: Some(1),
                pid: Some(std::process::id()),
                version_after: None,
                message: Some(e),
            }
        }
    };
    save_job(&job);
}

pub async fn post_install(State(ctx): State<HttpCtx>) -> Response {
    let _g = mutate_lock().await;
    if INSTALL_IN_PROGRESS.load(Ordering::Acquire) || read_job().is_some_and(|j| j.state == "running") {
        return crate::admin::conflict("A cloudflared install/update job is already running");
    }
    if crate::ota::upgrade_running() {
        return crate::admin::conflict("A CellCore update is running; try again when it finishes");
    }
    let action = if bin_path().is_file() {
        "upgrade"
    } else {
        "install"
    };
    let started = now_secs();
    let job = InstallJob {
        state: "running".into(),
        action: action.into(),
        started_at: started,
        pid: Some(std::process::id()),
        ..Default::default()
    };
    let _ = std::fs::create_dir_all(paths().run);
    let _ = std::fs::write(log_file(), b"");
    if let Err(e) = crate::state::atomic_write(
        &job_file(),
        &serde_json::to_vec(&job).unwrap_or_default(),
        0o644,
    ) {
        return server(e);
    }
    INSTALL_IN_PROGRESS.store(true, Ordering::Release);
    let act_owned = action.to_string();
    tokio::spawn(async move {
        run_verified_install(act_owned, started).await;
    });
    audit(&ctx, format!("vpn: cloudflared {action} started"));
    ok(serde_json::json!({ "job": job }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct RemoveReq {
    confirm: Option<String>,
    delete_token: bool,
    delete_binary: bool,
}

pub async fn post_remove(State(ctx): State<HttpCtx>, Json(req): Json<RemoveReq>) -> Response {
    if let Err(resp) = require_confirm(
        req.confirm.as_deref(),
        "REMOVE CLOUDFLARE TUNNEL",
        "Removes the Cloudflare Tunnel service, init script, and loopback IP.",
    ) {
        return resp;
    }
    let _g = mutate_lock().await;
    let prev = load_config();
    let init = init_path();
    if init.is_file() {
        let s = init.display().to_string();
        let _ = run(&s, &["stop"], crate::admin::exec::ExecOpts::new(15, 8 * KIB)).await;
        let _ = run(&s, &["disable"], crate::admin::exec::ExecOpts::new(10, 8 * KIB)).await;
        let _ = std::fs::remove_file(&init);
    }
    if let Some(old_ip) = prev.loopback_ip.as_deref() {
        let _ = run(
            "ip",
            &["addr", "del", &format!("{old_ip}/32"), "dev", "lo"],
            crate::admin::exec::ExecOpts::new(5, 4 * KIB),
        )
        .await;
    }
    let _ = std::fs::remove_file(cfg_file());
    if req.delete_token {
        let _ = std::fs::remove_file(token_path());
    }
    if req.delete_binary {
        let _ = std::fs::remove_file(bin_path());
        if let Ok(mut g) = VERSION_CACHE.lock() {
            *g = None;
        }
    }
    audit(
        &ctx,
        format!(
            "vpn: cloudflared removed (delete_token={}, delete_binary={})",
            req.delete_token, req.delete_binary
        ),
    );
    ok(serde_json::json!({ "removed": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_edge_proto_loopback_and_token() {
        assert_eq!(validate_edge_ip_version("auto").unwrap(), "auto");
        assert_eq!(validate_edge_ip_version("6").unwrap(), "6");
        assert!(validate_edge_ip_version("ipv6").is_err());

        assert_eq!(validate_protocol("http2").unwrap(), "http2");
        assert_eq!(validate_protocol("quic").unwrap(), "quic");
        assert!(validate_protocol("tcp").is_err());

        assert_eq!(validate_loopback_ip("").unwrap(), None);
        assert_eq!(
            validate_loopback_ip("10.254.224.1/32").unwrap(),
            Some("10.254.224.1".into())
        );
        assert_eq!(
            validate_loopback_ip("100.64.1.2").unwrap(),
            Some("100.64.1.2".into())
        );
        assert!(validate_loopback_ip("127.0.0.1").is_err());
        assert!(validate_loopback_ip("8.8.8.8").is_err());

        assert!(validate_tunnel_token("short").is_err());
        assert!(validate_tunnel_token("eyJhIjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAifQ== bad").is_err());
        assert!(validate_tunnel_token("eyJhIjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTYifQ==").is_ok());
    }

    #[test]
    fn renders_and_roundtrips_init_script_without_token_on_argv() {
        let cfg = CloudflaredConfig {
            edge_ip_version: "6".into(),
            protocol: "http2".into(),
            loopback_ip: Some("10.254.224.1".into()),
            autostart: true,
            metrics_port: 20241,
        };
        let script = render_init_script(&cfg);
        assert!(script.contains("--token-file /etc/cloudflared/token"));
        assert!(!script.contains("--token "));
        assert!(script.contains("ip addr replace 10.254.224.1/32 dev lo"));
        assert!(script.contains("--edge-ip-version 6"));
        assert!(script.contains("--protocol http2"));

        let parsed = parse_init_script_config(&script);
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn parses_prometheus_metrics_and_colos() {
        let sample = "\
# HELP cloudflared_tunnel_ha_connections Number of active HA connections
cloudflared_tunnel_ha_connections 4
cloudflared_tunnel_total_requests 128
cloudflared_tunnel_server_locations{connection_id=\"0\",edge_location=\"ord12\"} 1
cloudflared_tunnel_server_locations{connection_id=\"1\",edge_location=\"ord02\"} 1
cloudflared_tunnel_server_locations{connection_id=\"2\",edge_location=\"ord11\"} 1
cloudflared_tunnel_server_locations{connection_id=\"3\",edge_location=\"ord02\"} 0
";
        let m = parse_metrics(sample);
        assert!(m.connected);
        assert_eq!(m.ha_connections, 4);
        assert_eq!(m.total_requests, 128);
        assert_eq!(m.edge_locations, vec!["ord02", "ord11", "ord12"]);
    }

    #[test]
    fn tunnel_token_is_redacted_by_audit() {
        assert!(crate::audit::key_is_secret("tunnelToken"));
    }

    #[test]
    fn parses_release_checksum_and_fails_closed_when_missing_or_untrusted() {
        let sha = "a".repeat(64);
        let with_digest = serde_json::json!({
            "assets": [{
                "name": "cloudflared-linux-arm64",
                "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/2026.5.0/cloudflared-linux-arm64",
                "digest": format!("sha256:{sha}")
            }]
        })
        .to_string();
        let (url, got) = parse_release_arm64_asset(&with_digest).unwrap();
        assert!(url.ends_with("/cloudflared-linux-arm64"));
        assert_eq!(got, sha);

        let sha_body = "0123456789abcdef".repeat(4);
        let with_body = serde_json::json!({
            "body": format!("Checksums:\ncloudflared-linux-arm64: {sha_body}\n"),
            "assets": [{
                "name": "cloudflared-linux-arm64",
                "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/2026.5.0/cloudflared-linux-arm64"
            }]
        })
        .to_string();
        let (_, got2) = parse_release_arm64_asset(&with_body).unwrap();
        assert_eq!(got2, sha_body);

        // Missing checksum MUST fail closed.
        let missing = serde_json::json!({
            "body": "No checksums here",
            "assets": [{
                "name": "cloudflared-linux-arm64",
                "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/2026.5.0/cloudflared-linux-arm64"
            }]
        })
        .to_string();
        assert!(parse_release_arm64_asset(&missing).is_err());

        // Untrusted URL MUST fail closed.
        let evil = serde_json::json!({
            "assets": [{
                "name": "cloudflared-linux-arm64",
                "browser_download_url": "https://evil.example/cloudflared-linux-arm64",
                "digest": format!("sha256:{sha}")
            }]
        })
        .to_string();
        assert!(parse_release_arm64_asset(&evil).is_err());
    }

    #[test]
    fn verifies_elf64_aarch64_header_and_sha256_before_exec() {
        let mut good_elf = vec![0u8; 64];
        good_elf[0..4].copy_from_slice(b"\x7fELF");
        good_elf[4] = 2; // ELFCLASS64
        good_elf[5] = 1; // ELFDATA2LSB
        good_elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        assert!(verify_aarch64_elf_header(&good_elf).is_ok());

        // Reject shell script, x86_64 ELF, truncated file.
        assert!(verify_aarch64_elf_header(b"#!/bin/sh\necho pwned\n").is_err());
        let mut x86_elf = good_elf.clone();
        x86_elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        assert!(verify_aarch64_elf_header(&x86_elf).is_err());
        assert!(verify_aarch64_elf_header(&good_elf[..10]).is_err());

        let sbx = crate::paths::TestSandbox::new("cf-verify");
        let bin = sbx.write("/tmp/cf-bin", &good_elf);
        let digest = hex::encode(Sha256::digest(&good_elf));
        assert_eq!(verify_downloaded_binary(&bin, &digest).unwrap(), digest);
        // Checksum mismatch fails closed.
        assert!(verify_downloaded_binary(&bin, &"f".repeat(64)).is_err());
        // Wrong arch with matching checksum still fails closed.
        let bad_bin = sbx.write("/tmp/cf-x86", &x86_elf);
        let x86_digest = hex::encode(Sha256::digest(&x86_elf));
        assert!(verify_downloaded_binary(&bad_bin, &x86_digest).is_err());
    }
}

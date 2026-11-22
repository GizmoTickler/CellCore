//! Cloudflare Tunnel (`cloudflared`) remote-access management.
//!
//! Manages the standalone static `cloudflared` daemon (outbound-only HTTP/2 or
//! QUIC tunnel into Cloudflare Zero Trust for remote CellCore UI, SSH, and
//! WARP private-network routing). Keeps the tunnel token strictly write-only
//! (`0600` at `/etc/cloudflared/token`, passed via `--token-file`, never in
//! argv or GET responses).

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Mutex,
};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};

use super::paths;
use crate::{
    admin::{
        audit, bad,
        exec::{KIB, run, run_ok},
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
const RELEASE_URL_ARM64: &str =
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64";

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
    if j.state == "running" && j.pid.is_some() && !j.pid.is_some_and(pid_alive) {
        j.state = "failed".into();
        j.message = Some("Installer stopped before reporting a result".into());
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

const INSTALL_SCRIPT: &str = r#"
status="$1"; url="$2"; bin="$3"; started="$4"; action="$5"
tmp="${bin}.new.$$"
echo "[$(date)] Downloading cloudflared-linux-arm64 from GitHub..."
curl -fsSL --connect-timeout 15 --max-time 240 -o "$tmp" "$url"
rc=$?
ver=""
if [ "$rc" -eq 0 ] && [ -s "$tmp" ]; then
  chmod 0755 "$tmp"
  ver=$("$tmp" --version 2>&1 | head -n 1 | sed -n 's/^cloudflared version \([^ ]*\).*/\1/p')
  if [ -n "$ver" ]; then
    mv -f "$tmp" "$bin"
    chmod 0755 "$bin"
    sync
    echo "[$(date)] Installed cloudflared $ver"
    if [ -x /etc/init.d/cloudflared ] && [ -s /etc/cloudflared/token ]; then
      echo "[$(date)] Restarting cloudflared service..."
      /etc/init.d/cloudflared restart || true
    fi
  else
    echo "[$(date)] Downloaded binary failed --version check"
    rm -f "$tmp"
    rc=1
  fi
else
  echo "[$(date)] Download failed (rc=$rc)"
  rm -f "$tmp"
fi
st=failed; if [ "$rc" -eq 0 ] && [ -n "$ver" ]; then st=succeeded; fi
printf '{"state":"%s","action":"%s","startedAt":%s,"finishedAt":%s,"exitCode":%s,"versionAfter":"%s"}\n' \
  "$st" "$action" "$started" "$(date +%s)" "$rc" "$ver" > "${status}.tmp" && mv "${status}.tmp" "$status"
"#;

pub async fn post_install(State(ctx): State<HttpCtx>) -> Response {
    let _g = mutate_lock().await;
    if read_job().is_some_and(|j| j.state == "running") {
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
    let mut job = InstallJob {
        state: "running".into(),
        action: action.into(),
        started_at: started,
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
    let jf = job_file().display().to_string();
    let bp = bin_path().display().to_string();
    match crate::ota::spawn_detached(
        INSTALL_SCRIPT,
        &[&jf, RELEASE_URL_ARM64, &bp, &started.to_string(), action],
        Path::new(&log_file()),
    ) {
        Ok(pid) => {
            job.pid = Some(pid);
            if read_job().is_some_and(|j| j.state == "running") {
                let _ = crate::state::atomic_write(
                    &job_file(),
                    &serde_json::to_vec(&job).unwrap_or_default(),
                    0o644,
                );
            }
            audit(&ctx, format!("vpn: cloudflared {action} started"));
            ok(serde_json::json!({ "job": job }))
        }
        Err(e) => server(format!("start cloudflared {action}: {e}")),
    }
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
}

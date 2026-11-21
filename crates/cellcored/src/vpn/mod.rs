//! VPN management: Cloudflare WARP (consumer Free / WARP+ through `wgcf`,
//! Zero Trust through the client registration API) as a native OpenWrt
//! `proto wireguard` interface with backup-WAN-safe policy routing, and a
//! full Tailscale manager for the `tailscale-tiny` package.
//!
//! Ground rules (same as `admin/`): argv-only exec with timeouts, validated
//! inputs, uci with revert-on-error, one mutation lock, typed confirmations
//! (HTTP 428) for anything that can cut the owner off or move Route10's
//! failover traffic, crash-safe 0600 writes for secrets, and every secret
//! write-only: no GET returns a key, token, license or auth key.

pub mod parse;
pub mod policy;
pub mod teams;
pub mod validate;

mod pkg;
mod tailscale;
mod warp;

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{http::HttpCtx, state::AppState};

pub(crate) fn parse_optional_json<T: serde::de::DeserializeOwned + Default>(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<T, Box<Response>> {
    if body.is_empty() {
        return Ok(T::default());
    }
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mime = ct.split(';').next().unwrap_or("").trim();
    if !mime.eq_ignore_ascii_case("application/json")
        && !mime.to_ascii_lowercase().ends_with("+json")
    {
        return Err(Box::new(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "Content-Type must be application/json",
                })),
            )
                .into_response(),
        ));
    }
    serde_json::from_slice::<T>(body)
        .map_err(|e| Box::new(crate::admin::bad(format!("Invalid JSON body: {e}"))))
}

pub use policy::{BYPASS_MARK, Mode};

/// `/api/v1/vpn/...`; merged into the protected router in `http.rs`.
/// (Kept above every test-only item: the route-enumeration test scans
/// this file's non-test prefix.)
pub fn routes() -> Router<HttpCtx> {
    Router::new()
        .route("/api/v1/vpn/warp", get(warp::get_warp))
        .route("/api/v1/vpn/warp/account", get(warp::get_account))
        .route("/api/v1/vpn/warp/register", post(warp::post_register))
        .route("/api/v1/vpn/warp/license", post(warp::post_license))
        .route("/api/v1/vpn/warp/teams", post(warp::post_teams))
        .route("/api/v1/vpn/warp/install", post(warp::post_install))
        .route("/api/v1/vpn/warp/connection", post(warp::post_connection))
        .route("/api/v1/vpn/warp/policy", post(warp::post_policy))
        .route("/api/v1/vpn/warp/remove", post(warp::post_remove))
        .route("/api/v1/vpn/tailscale", get(tailscale::get_tailscale))
        .route("/api/v1/vpn/tailscale/service", post(tailscale::post_service))
        .route("/api/v1/vpn/tailscale/login", post(tailscale::post_login))
        .route("/api/v1/vpn/tailscale/logout", post(tailscale::post_logout))
        .route("/api/v1/vpn/tailscale/settings", post(tailscale::post_settings))
        .route("/api/v1/vpn/packages", get(pkg::get_packages).post(pkg::post_package))
}

/// Filesystem roots. Overridable in tests only.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Persistent state (0700 dir, 0600 files): wgcf account, profile, warp.json.
    pub state: PathBuf,
    /// Volatile job files and logs.
    pub run: PathBuf,
    pub sys_net: PathBuf,
    pub sys_module: PathBuf,
    pub proc_sys: PathBuf,
    /// Where programs are looked up for "is it installed" checks.
    pub bin_dirs: Vec<PathBuf>,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            state: PathBuf::from("/etc/cellcore/vpn"),
            run: PathBuf::from("/tmp/cellcore/vpn"),
            sys_net: PathBuf::from("/sys/class/net"),
            sys_module: PathBuf::from("/sys/module"),
            proc_sys: PathBuf::from("/proc/sys"),
            bin_dirs: ["/usr/bin", "/usr/sbin", "/bin", "/sbin"].iter().map(PathBuf::from).collect(),
        }
    }
}

static PATHS: RwLock<Option<Paths>> = RwLock::new(None);

pub fn paths() -> Paths {
    PATHS.read().ok().and_then(|g| g.clone()).unwrap_or_default()
}

#[cfg(test)]
pub fn set_paths(p: Option<Paths>) {
    if let Ok(mut g) = PATHS.write() {
        *g = p;
    }
}

/// Is `prog` installed (by file, not by running it)?
pub fn have(prog: &str) -> bool {
    if prog.starts_with('/') {
        #[cfg(test)]
        if let Some(d) = crate::admin::exec::BIN_OVERRIDE.read().ok().and_then(|g| g.clone()) {
            return d.join(crate::admin::exec::mock_name(prog)).is_file();
        }
        return Path::new(prog).is_file();
    }
    paths().bin_dirs.iter().any(|d| d.join(prog).is_file())
}

/// WireGuard interface / device name and uci section ids.
pub const WG_IF: &str = "warp";
pub const WG_PEER: &str = "warp_peer";
pub const FW_ZONE: &str = "warp_zone";
pub const FW_FWD: &str = "warp_fwd";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarpKind {
    /// Free or WARP+ through wgcf.
    Consumer,
    /// Cloudflare Zero Trust device.
    Teams,
}

/// `warp.json` (0600). Holds the Zero Trust secrets too.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct WarpState {
    pub kind: Option<WarpKind>,
    pub policy: Mode,
    pub policy_changed_at: u64,
    pub installed: bool,
    pub autostart: bool,
    pub mtu: u16,
    pub keepalive: u16,
    /// `host:port` override for the peer endpoint.
    pub endpoint: Option<String>,
    pub pref: u32,
    pub table: u32,
    pub lan_dev: String,
    pub teams: Option<teams::TeamsDevice>,
    /// Zero Trust WireGuard private key (secret).
    pub teams_private_key: String,
}

impl Default for WarpState {
    fn default() -> Self {
        Self {
            kind: None,
            policy: Mode::Off,
            policy_changed_at: 0,
            installed: false,
            autostart: true,
            mtu: 1280,
            keepalive: 25,
            endpoint: None,
            pref: policy::DEFAULT_PREF,
            table: policy::DEFAULT_TABLE,
            lan_dev: "br-lan".into(),
            teams: None,
            teams_private_key: String::new(),
        }
    }
}

impl WarpState {
    pub fn plan(&self) -> policy::Plan {
        policy::Plan { mode: self.policy, pref: self.pref, table: self.table, lan_dev: self.lan_dev.clone() }
    }
}

pub fn state_file() -> PathBuf {
    paths().state.join("warp.json")
}

pub fn load_state() -> WarpState {
    std::fs::read(state_file()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_state(st: &WarpState) -> Result<(), String> {
    ensure_state_dir()?;
    let json = serde_json::to_vec_pretty(st).map_err(|e| e.to_string())?;
    crate::state::atomic_write(&state_file(), &json, 0o600)?;
    MODE.store(mode_code(st.policy), Ordering::Relaxed);
    Ok(())
}

pub fn ensure_state_dir() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let d = paths().state;
    std::fs::create_dir_all(&d).map_err(|e| format!("create {}: {e}", d.display()))?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

/// Write a secret file 0600 (crash-safe).
pub fn write_secret(path: &Path, data: &[u8]) -> Result<(), String> {
    crate::state::atomic_write(path, data, 0o600)
}

/// Force a file wgcf wrote to 0600.
pub fn chmod_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Replace every occurrence of each secret in tool output before it is
/// returned or logged.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for s in secrets.iter().filter(|s| s.len() >= 6) {
        out = out.replace(*s, "<redacted>");
    }
    out
}

// ── policy mode cache for other modules ────────────────────────────────────

static MODE: AtomicU8 = AtomicU8::new(0);

fn mode_code(m: Mode) -> u8 {
    match m {
        Mode::Off => 0,
        Mode::Modem => 1,
        Mode::Lan => 2,
    }
}

pub fn current_mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        1 => Mode::Modem,
        2 => Mode::Lan,
        _ => Mode::Off,
    }
}

/// Mark for sockets that must measure the cellular path (LinkWatch /
/// latency ICMP) while WARP steers modem traffic. `None` when WARP steering
/// is off, so nothing changes for anyone not using WARP.
pub fn bypass_mark() -> Option<u32> {
    (current_mode() != Mode::Off).then_some(BYPASS_MARK)
}

/// Cellular device to bind tools that cannot set a mark (curl for the public
/// IP, the Ookla CLI) while WARP steering is on.
pub fn bypass_iface() -> Option<String> {
    if current_mode() == Mode::Off {
        return None;
    }
    let dev = crate::ipc::detect_first_up_rmnet();
    (dev != "none").then_some(dev)
}

// ── runtime (monitor) ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Runtime {
    pub usable: bool,
    pub route_installed: bool,
    pub device_present: bool,
    pub handshake_age: Option<u64>,
    pub last_transition: u64,
    pub failbacks: u64,
    pub last_error: Option<String>,
}

pub static RUNTIME: Mutex<Runtime> = Mutex::new(Runtime {
    usable: false,
    route_installed: false,
    device_present: false,
    handshake_age: None,
    last_transition: 0,
    failbacks: 0,
    last_error: None,
});

pub fn runtime() -> Runtime {
    crate::obs::lock(&RUNTIME).clone()
}

/// Seconds between monitor ticks.
pub const TICK_SECS: u64 = 5;

/// Boot reconcile and the fail-back monitor. Called once from `main`.
pub fn start(state: &AppState) {
    let st = load_state();
    MODE.store(mode_code(st.policy), Ordering::Relaxed);
    let app = state.clone();
    tokio::spawn(async move {
        if let Err(e) = warp::reconcile_rules(&load_state()).await {
            app.push_daemon_log(format!("vpn: boot rule reconcile failed: {e}"));
        }
        let mut n: u64 = 0;
        loop {
            warp::tick(crate::auth::now_secs()).await;
            n = n.wrapping_add(1);
            // Rules are re-asserted every minute (another tool may flush them).
            if n.is_multiple_of(12)
                && current_mode() != Mode::Off
                && let Err(e) = warp::reconcile_rules(&load_state()).await
            {
                crate::obs::lock(&RUNTIME).last_error = Some(e);
            }
            tokio::time::sleep(Duration::from_secs(TICK_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests;

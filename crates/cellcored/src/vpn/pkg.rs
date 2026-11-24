//! Install / upgrade the VPN packages from the configured opkg feeds, detached
//! from the daemon exactly like the OTA installer (own session, own log,
//! result written by the script itself), so a slow cellular download never
//! blocks a request and survives a daemon restart.

use std::path::{Path, PathBuf};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};

use super::paths;
use crate::{
    admin::{audit, bad, conflict, exec::KIB, mutate_lock, ok, server},
    auth::now_secs,
    http::HttpCtx,
};

/// Packages this page may install. `wireguard-tools` comes from the OpenWrt
/// feeds; the rest from the owner's signed SDXPINN feed.
pub const ALLOWED: &[&str] = &["tailscale-tiny", "wgcf", "wireguard-tools", "kmod-wireguard"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Job {
    pub state: String,
    pub package: String,
    pub action: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    pub installed_after: Option<String>,
    pub message: Option<String>,
}

fn job_file() -> PathBuf {
    paths().run.join("pkg-job.json")
}

fn log_file() -> PathBuf {
    paths().run.join("pkg-job.log")
}

fn pid_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'))
}

pub fn read_job() -> Option<Job> {
    let mut j: Job = serde_json::from_slice(&std::fs::read(job_file()).ok()?).ok()?;
    if j.state == "running" && !j.pid.is_some_and(pid_alive) && j.pid.is_some() {
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

pub fn job_running() -> bool {
    read_job().is_some_and(|j| j.state == "running")
}

const SCRIPT: &str = r#"
status="$1"; opkg="$2"; action="$3"; pkg="$4"; started="$5"
echo "[$(date)] opkg update"
"$opkg" update
if [ "$action" = "upgrade" ]; then
  echo "[$(date)] opkg upgrade $pkg"; "$opkg" upgrade "$pkg"
else
  echo "[$(date)] opkg install $pkg"; "$opkg" install "$pkg"
fi
rc=$?
ver=$("$opkg" list-installed "$pkg" | sed -n "s/^$pkg - \([^ ]*\).*/\1/p" | head -n 1)
st=failed; if [ "$rc" -eq 0 ] && [ -n "$ver" ]; then st=succeeded; fi
echo "[$(date)] opkg exited $rc; installed: ${ver:-none} -> $st"
printf '{"state":"%s","package":"%s","action":"%s","startedAt":%s,"finishedAt":%s,"exitCode":%s,"installedAfter":"%s"}\n' \
  "$st" "$pkg" "$action" "$started" "$(date +%s)" "$rc" "$ver" > "$status.tmp" && mv "$status.tmp" "$status"
"#;

/// Resolve the opkg binary the detached script runs (mockable in tests).
fn opkg_path() -> String {
    #[cfg(test)]
    if let Some(d) = crate::admin::exec::BIN_OVERRIDE.read().ok().and_then(|g| g.clone()) {
        let p = d.join("opkg");
        if p.is_file() {
            return p.display().to_string();
        }
    }
    "opkg".into()
}

pub fn start_job(package: &str, action: &str) -> Result<Job, String> {
    if !ALLOWED.contains(&package) {
        return Err(format!("{package} is not a VPN package"));
    }
    if !matches!(action, "install" | "upgrade") {
        return Err("action must be install or upgrade".into());
    }
    if job_running() {
        return Err("Another package job is still running".into());
    }
    if crate::ota::upgrade_running() {
        return Err("A CellCore update is running; try again when it finishes".into());
    }
    let started = now_secs();
    let mut job = Job { state: "running".into(), package: package.into(), action: action.into(), started_at: started, ..Default::default() };
    let _ = std::fs::create_dir_all(paths().run);
    let _ = std::fs::write(log_file(), b"");
    crate::state::atomic_write_tmpfs(&job_file(), &serde_json::to_vec(&job).unwrap_or_default(), 0o644)?;
    let jf = job_file().display().to_string();
    let pid = crate::ota::spawn_detached(SCRIPT, &[&jf, &opkg_path(), action, package, &started.to_string()], Path::new(&log_file()))?;
    job.pid = Some(pid);
    if read_job().is_some_and(|j| j.state == "running") {
        let _ = crate::state::atomic_write_tmpfs(&job_file(), &serde_json::to_vec(&job).unwrap_or_default(), 0o644);
    }
    if package.starts_with("tailscale") {
        super::tailscale::forget_flags();
    }
    Ok(job)
}

async fn installed(pkg: &str) -> Option<String> {
    let out = crate::admin::exec::run_ok("opkg", &["list-installed", pkg], 10, 64 * KIB).await.ok()?;
    crate::ota::newest(&crate::ota::parse_opkg_versions(&out, pkg))
}

pub async fn get_packages() -> Response {
    let mut list = Vec::new();
    for p in ALLOWED {
        list.push(serde_json::json!({ "name": p, "installed": installed(p).await }));
    }
    ok(serde_json::json!({ "packages": list, "job": job_json() }))
}

#[derive(Deserialize)]
pub struct PkgReq {
    package: String,
    action: String,
}

pub async fn post_package(State(ctx): State<HttpCtx>, Json(req): Json<PkgReq>) -> Response {
    if !ALLOWED.contains(&req.package.as_str()) {
        return bad(format!("Only {} can be installed here", ALLOWED.join(", ")));
    }
    let _g = mutate_lock().await;
    match start_job(&req.package, &req.action) {
        Ok(j) => {
            audit(&ctx, format!("vpn: opkg {} {} started", req.action, req.package));
            ok(serde_json::json!({ "status": "started", "job": j }))
        }
        Err(e) if e.contains("running") => conflict(e),
        Err(e) => server(e),
    }
}

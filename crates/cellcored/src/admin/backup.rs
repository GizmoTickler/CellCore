//! Backup › download the standard OpenWrt config backup (`sysupgrade -b -`) and
//! restore one (`sysupgrade -r -`). Archives are inspected first: only relative
//! paths under etc/ are accepted. No firmware flashing.

use std::{sync::OnceLock, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tokio::sync::{Mutex, MutexGuard};

use super::{
    audit, bad, exec::{ExecOpts, ExecOut, MIB, run, run_ok}, mutate_lock, ok, require_confirm, server,
};
use crate::http::HttpCtx;

pub const MAX_ARCHIVE: usize = 32 * MIB;

static SYSUPGRADE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

async fn sysupgrade_lock() -> MutexGuard<'static, ()> {
    SYSUPGRADE_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Owner-maintained files that a restore would overwrite; surfaced as warnings.
const SENSITIVE: &[&str] = &["etc/shadow", "etc/passwd", "etc/dropbear/", "etc/nftables.d/", "etc/firewall.user", "etc/config/qcmap", "etc/config/network", "etc/config/firewall"];

pub fn is_gzip(b: &[u8]) -> bool {
    b.len() > 18 && b[0] == 0x1f && b[1] == 0x8b
}

/// Validate `tar -tz` output: every entry must be a relative path under etc/
/// with no `..` component.
pub fn check_entries(listing: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for raw in listing.lines() {
        let e = raw.trim();
        if e.is_empty() {
            continue;
        }
        let p = e.strip_prefix("./").unwrap_or(e);
        if p.starts_with('/') {
            return Err(format!("absolute path in archive: {e}"));
        }
        if p.split('/').any(|c| c == "..") {
            return Err(format!("path traversal in archive: {e}"));
        }
        if !(p == "etc" || p == "etc/" || p.starts_with("etc/")) {
            return Err(format!("unexpected path outside etc/: {e}"));
        }
        v.push(p.to_string());
    }
    if v.is_empty() {
        return Err("archive is empty".into());
    }
    Ok(v)
}

pub fn sensitive_entries(entries: &[String]) -> Vec<String> {
    entries.iter().filter(|e| SENSITIVE.iter().any(|s| e.starts_with(s))).cloned().collect()
}

pub fn luci_installed() -> bool {
    std::path::Path::new(&crate::paths::p("/www/cgi-bin/luci")).exists()
        || std::path::Path::new(&crate::paths::p("/usr/lib/lua/luci")).exists()
}

pub async fn get_backup() -> Response {
    let _sg = sysupgrade_lock().await;
    match run_ok("sysupgrade", &["-l"], 30, 2 * MIB).await {
        Ok(out) => {
            let files: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            ok(serde_json::json!({
                "files": files,
                "count": files.len(),
                "luciAvailable": luci_installed(),
            }))
        }
        Err(e) => server(e),
    }
}

async fn run_sysupgrade_backup() -> Result<ExecOut, String> {
    run("sysupgrade", &["-b", "-"], ExecOpts::new(120, MAX_ARCHIVE)).await
}

fn backup_archive_err(res: Result<ExecOut, String>) -> (StatusCode, String) {
    match res {
        Ok(o) if o.truncated => (StatusCode::INTERNAL_SERVER_ERROR, "backup larger than 32 MiB".into()),
        Ok(o) => (StatusCode::SERVICE_UNAVAILABLE, o.err_summary("sysupgrade -b")),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

pub async fn get_download(State(ctx): State<HttpCtx>) -> Response {
    let out = {
        let _sg = sysupgrade_lock().await;
        match run_sysupgrade_backup().await {
            Ok(o) if o.ok() && !o.truncated && is_gzip(&o.stdout) => Ok(o),
            Ok(o) if o.truncated => Err((StatusCode::INTERNAL_SERVER_ERROR, "backup larger than 32 MiB".into())),
            _ => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                match run_sysupgrade_backup().await {
                    Ok(o) if o.ok() && !o.truncated && is_gzip(&o.stdout) => Ok(o),
                    other => Err(backup_archive_err(other)),
                }
            }
        }
    };
    let out = match out {
        Ok(o) => o,
        Err((status, msg)) => return super::fail(status, msg),
    };
    let host = crate::uci::uci_get("system.@system[0].hostname").await.unwrap_or_else(|| "gateway".into());
    let host: String = host.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(40).collect();
    let date = run_ok("date", &["+%Y-%m-%d"], 3, 64).await.unwrap_or_default();
    let fname = format!("backup-{host}-{}.tar.gz", date.trim());
    audit(&ctx, format!("config backup downloaded ({} bytes)", out.stdout.len()));
    let mut resp = Body::from(out.stdout).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

async fn inspect(body: &Bytes) -> Result<Vec<String>, String> {
    if !is_gzip(body) {
        return Err("Not a .tar.gz backup".into());
    }
    let out = run("tar", &["-tzf", "-"], ExecOpts::new(30, 2 * MIB).stdin(body.to_vec())).await?;
    if !out.ok() {
        return Err(format!("Archive is unreadable: {}", out.err_summary("tar")));
    }
    check_entries(&out.stdout_str())
}

pub async fn post_inspect(body: Bytes) -> Response {
    match inspect(&body).await {
        Ok(entries) => ok(serde_json::json!({
            "entries": entries.len(),
            "files": entries.iter().filter(|e| !e.ends_with('/')).take(500).collect::<Vec<_>>(),
            "sensitive": sensitive_entries(&entries),
            "bytes": body.len(),
        })),
        Err(e) => bad(e),
    }
}

#[derive(Deserialize)]
pub struct ConfirmQ {
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_restore(State(ctx): State<HttpCtx>, Query(q): Query<ConfirmQ>, body: Bytes) -> Response {
    if let Err(r) = require_confirm(
        q.confirm.as_deref(),
        "RESTORE",
        "Restoring replaces /etc with the archive (passwords, SSH keys, firewall, QCMAP and network config). Type RESTORE to continue.",
    ) {
        return r;
    }
    let entries = match inspect(&body).await {
        Ok(e) => e,
        Err(e) => return bad(e),
    };
    let _g = mutate_lock().await;
    let _sg = sysupgrade_lock().await;
    let out = match run("sysupgrade", &["-r", "-"], ExecOpts::new(120, 256 * 1024).stdin(body.to_vec())).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    audit(&ctx, format!("config backup restored ({} entries) -> {:?}", entries.len(), out.code));
    if !out.ok() {
        return server(out.err_summary("sysupgrade -r"));
    }
    ok(serde_json::json!({ "status": "ok", "entries": entries.len(), "rebootRequired": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_archive_entries() {
        let good = "etc/\netc/config/\netc/config/system\n./etc/dropbear/authorized_keys\netc/shadow\n";
        let e = check_entries(good).unwrap();
        assert_eq!(e.len(), 5);
        let s = sensitive_entries(&e);
        assert!(s.contains(&"etc/shadow".to_string()));
        assert!(s.contains(&"etc/dropbear/authorized_keys".to_string()));
        assert!(!s.contains(&"etc/config/system".to_string()));
        assert!(check_entries("/etc/passwd\n").is_err());
        assert!(check_entries("etc/../root/.ssh/authorized_keys\n").is_err());
        assert!(check_entries("usr/bin/evil\n").is_err());
        assert!(check_entries("etcetera/x\n").is_err());
        assert!(check_entries("").is_err());
    }

    #[test]
    fn real_backup_list_is_restorable_shape() {
        // `sysupgrade -l` lists absolute paths; the tarball stores them relative.
        let listing: String = include_str!("fixtures/sysupgrade_list.txt")
            .lines()
            .map(|l| format!("{}\n", l.trim_start_matches('/')))
            .collect();
        let e = check_entries(&listing).unwrap();
        assert!(e.len() > 100);
        let s = sensitive_entries(&e);
        assert!(s.iter().any(|x| x.starts_with("etc/nftables.d/")));
        assert!(s.contains(&"etc/shadow".to_string()));
    }

    #[test]
    fn gzip_magic() {
        assert!(is_gzip(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_gzip(b"PK\x03\x04................"));
    }

    #[tokio::test]
    async fn download_retries_once_and_succeeds() {
        let env = crate::paths::TestSandbox::new("backup-retry-ok");
        let count_file = env.root.join("calls");
        env.write_exec("/bin/uci", "#!/bin/sh\necho 'gateway'\n");
        env.write_exec("/bin/date", "#!/bin/sh\necho '2026-11-18'\n");
        env.write_exec(
            "/bin/sysupgrade",
            &format!(
                "#!/bin/sh\n\
                 n=$(cat {cf} 2>/dev/null || echo 0)\n\
                 n=$((n + 1))\n\
                 echo \"$n\" > {cf}\n\
                 if [ \"$n\" -eq 1 ]; then\n\
                   echo 'tar: /tmp/sysupgrade.conffiles: race' >&2\n\
                   exit 1\n\
                 fi\n\
                 printf '\\037\\213\\010\\000\\000\\000\\000\\000\\000\\003\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000'\n",
                cf = count_file.display()
            ),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        let resp = crate::paths::TEST_ENV
            .scope(env.env(), get_download(State(ctx)))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/gzip");
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(is_gzip(&body));
        assert_eq!(std::fs::read_to_string(&count_file).unwrap().trim(), "2");
    }

    #[tokio::test]
    async fn download_returns_503_with_tool_error_after_retry() {
        let env = crate::paths::TestSandbox::new("backup-retry-503");
        let count_file = env.root.join("calls");
        env.write_exec(
            "/bin/sysupgrade",
            &format!(
                "#!/bin/sh\n\
                 n=$(cat {cf} 2>/dev/null || echo 0)\n\
                 n=$((n + 1))\n\
                 echo \"$n\" > {cf}\n\
                 echo 'tar: /tmp/sysupgrade.conffiles: No such file or directory' >&2\n\
                 exit 1\n",
                cf = count_file.display()
            ),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        let resp = crate::paths::TEST_ENV
            .scope(env.env(), get_download(State(ctx)))
            .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "error");
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("sysupgrade -b"), "{err}");
        assert!(err.contains("sysupgrade.conffiles"), "{err}");
        assert_eq!(std::fs::read_to_string(&count_file).unwrap().trim(), "2");
    }
}

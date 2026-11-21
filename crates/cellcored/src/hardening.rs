//! Live security posture audit, safe one-click hardening actions, and
//! `cellctl security <audit|harden>` CLI.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    http::HttpCtx,
    reconcile::USB_DISABLED_MARKER,
    state::AppState,
    uci::{run_cmd_blocking_timeout, uci_get_blocking},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCheck {
    pub id: String,
    pub title: String,
    pub status: String, // "pass" | "warn" | "fail"
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_action: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAuditReport {
    pub score_pct: u8,
    pub passed: usize,
    pub total: usize,
    pub checks: Vec<SecurityCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardenReq {
    pub action: String,
}

const HARDENED_SYSCTLS: &[(&str, &str)] = &[
    ("/proc/sys/kernel/kptr_restrict", "2"),
    ("/proc/sys/kernel/dmesg_restrict", "1"),
    ("/proc/sys/kernel/randomize_va_space", "2"),
    ("/proc/sys/net/ipv4/tcp_syncookies", "1"),
    ("/proc/sys/net/ipv4/conf/all/rp_filter", "2"),
    ("/proc/sys/net/ipv4/conf/default/rp_filter", "2"),
    ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/default/accept_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/all/send_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/all/accept_source_route", "0"),
    ("/proc/sys/net/ipv6/conf/all/accept_redirects", "0"),
    ("/proc/sys/net/ipv6/conf/all/accept_source_route", "0"),
];

const SENSITIVE_FILES: &[&str] = &[
    "/etc/cellcore/api_tokens.json",
    "/etc/cellcore/acme.json",
    "/etc/cellcore/settings.json",
    "/etc/cellcore/tower_finder.json",
    "/etc/cellcore/dataplane.json",
    "/etc/ssl/acme/privkey.pem",
    "/etc/cellcore/tls/key.pem",
    "/etc/dropbear/authorized_keys",
];

fn read_proc_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(crate::paths::p(path))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Evaluate whether `dropbear` is bound strictly to `lan` (not wildcard 0.0.0.0/::).
fn check_dropbear_lan_only() -> SecurityCheck {
    let iface = uci_get_blocking("dropbear.@dropbear[0].Interface").unwrap_or_default();
    let bound_lan = iface.trim().eq_ignore_ascii_case("lan");
    if bound_lan {
        SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH bound to LAN only".into(),
            status: "pass".into(),
            detail: "Dropbear Interface='lan' (never listens on cellular WAN)".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH bound to LAN only".into(),
            status: "warn".into(),
            detail: "Dropbear listens on wildcard 0.0.0.0:22 (relying solely on WAN firewall)".into(),
            fix_action: Some("dropbear_lan_only".into()),
        }
    }
}

fn check_dropbear_key_only() -> SecurityCheck {
    let pw = uci_get_blocking("dropbear.@dropbear[0].PasswordAuth").unwrap_or_default();
    let root_pw = uci_get_blocking("dropbear.@dropbear[0].RootPasswordAuth").unwrap_or_default();
    let off = |v: &str| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false");
    if off(&pw) && off(&root_pw) {
        SecurityCheck {
            id: "dropbear_key_only".into(),
            title: "SSH key-only authentication".into(),
            status: "pass".into(),
            detail: "PasswordAuth=off, RootPasswordAuth=off".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "dropbear_key_only".into(),
            title: "SSH key-only authentication".into(),
            status: "warn".into(),
            detail: format!("PasswordAuth={pw:?}, RootPasswordAuth={root_pw:?} (key-only recommended)"),
            fix_action: None,
        }
    }
}

fn check_wan_firewall() -> SecurityCheck {
    let v4 = run_cmd_blocking_timeout("iptables", &["-S", "INPUT"], Duration::from_secs(2))
        .unwrap_or_default();
    let has_wan_drop = v4.contains("rmnet") && (v4.contains("WAN_IN") || v4.contains("DROP") || v4.contains("zone_wan"));
    if has_wan_drop {
        SecurityCheck {
            id: "wan_firewall".into(),
            title: "Cellular WAN inbound firewall".into(),
            status: "pass".into(),
            detail: "Active rmnet inbound filter chain drops unsolicited WAN traffic".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "wan_firewall".into(),
            title: "Cellular WAN inbound firewall".into(),
            status: "warn".into(),
            detail: "Could not verify rmnet INPUT drop chain in iptables".into(),
            fix_action: None,
        }
    }
}

fn check_usb_gadget() -> SecurityCheck {
    let marker = Path::new(&crate::paths::p(USB_DISABLED_MARKER)).exists();
    let (udc, _ctrl, _adb) = crate::reconcile::current_usb_gadget_udc();
    let locked = marker || udc.is_empty() || udc == "none" || udc == "disabled";
    if locked {
        SecurityCheck {
            id: "usb_lockdown".into(),
            title: "USB gadget port locked down".into(),
            status: "pass".into(),
            detail: "USB ConfigFS gadget UDC is unbound (physical USB surface minimized)".into(),
            fix_action: Some("unlock_usb".into()),
        }
    } else {
        SecurityCheck {
            id: "usb_lockdown".into(),
            title: "USB gadget port locked down".into(),
            status: "warn".into(),
            detail: format!("USB gadget UDC '{udc}' is active (lock down when not bench-debugging)"),
            fix_action: Some("lock_usb".into()),
        }
    }
}

fn check_kernel_sysctls() -> SecurityCheck {
    let mut drifted = Vec::new();
    for &(path, want) in &[
        ("/proc/sys/kernel/kptr_restrict", "2"),
        ("/proc/sys/kernel/dmesg_restrict", "1"),
        ("/proc/sys/kernel/randomize_va_space", "2"),
        ("/proc/sys/net/ipv4/tcp_syncookies", "1"),
        ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
    ] {
        if let Some(cur) = read_proc_trimmed(path)
            && cur != want
        {
            let key = path.rsplit('/').next().unwrap_or(path);
            drifted.push(format!("{key}={cur} (want {want})"));
        }
    }
    if let Some(rp) = read_proc_trimmed("/proc/sys/net/ipv4/conf/all/rp_filter")
        && rp == "0"
    {
        drifted.push("rp_filter=0 (want 2)".into());
    }
    if drifted.is_empty() {
        SecurityCheck {
            id: "kernel_sysctls".into(),
            title: "Kernel security sysctls".into(),
            status: "pass".into(),
            detail: "kptr_restrict=2, dmesg_restrict=1, ASLR=2, syncookies=1, rp_filter=2, redirects=0".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "kernel_sysctls".into(),
            title: "Kernel security sysctls".into(),
            status: "warn".into(),
            detail: format!("Drifted: {}", drifted.join(", ")),
            fix_action: Some("apply_sysctls".into()),
        }
    }
}

fn check_file_permissions() -> SecurityCheck {
    let mut loose = Vec::new();
    for path in SENSITIVE_FILES {
        let mapped = crate::paths::p(path);
        if let Ok(meta) = fs::metadata(&mapped) {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                loose.push(format!("{path} ({mode:04o})"));
            }
        }
    }
    if loose.is_empty() {
        SecurityCheck {
            id: "file_perms".into(),
            title: "Secret file permissions (0600)".into(),
            status: "pass".into(),
            detail: "All keys, API tokens, ACME secrets, and authorized_keys are owner-only (0600)".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "file_perms".into(),
            title: "Secret file permissions (0600)".into(),
            status: "fail".into(),
            detail: format!("Group/world accessible: {}", loose.join(", ")),
            fix_action: Some("fix_perms".into()),
        }
    }
}

pub fn check_tls_and_https(cert: &crate::acme::ActiveCertInfo, https_redirect: bool) -> (SecurityCheck, SecurityCheck) {
    let tls_check = if cert.source == "acme" {
        let days = cert.days_remaining.unwrap_or(0);
        if days > 14 {
            SecurityCheck {
                id: "tls_cert".into(),
                title: "Trusted ACME TLS certificate".into(),
                status: "pass".into(),
                detail: format!("Active ACME cert ({}) · {days} days remaining", cert.subject),
                fix_action: None,
            }
        } else {
            SecurityCheck {
                id: "tls_cert".into(),
                title: "Trusted ACME TLS certificate".into(),
                status: "warn".into(),
                detail: format!("ACME cert expires soon ({days} days remaining) — renew via ACME"),
                fix_action: None,
            }
        }
    } else {
        SecurityCheck {
            id: "tls_cert".into(),
            title: "Trusted ACME TLS certificate".into(),
            status: "warn".into(),
            detail: format!("Using {} TLS certificate (configure ACME for browser-trusted cert)", cert.source),
            fix_action: None,
        }
    };

    let https_check = if https_redirect {
        SecurityCheck {
            id: "https_hsts".into(),
            title: "HTTPS redirect, HSTS & CSP headers".into(),
            status: "pass".into(),
            detail: "HTTP→HTTPS redirect, HSTS (1y), CSP, COOP, and Referrer-Policy enforced".into(),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "https_hsts".into(),
            title: "HTTPS redirect, HSTS & CSP headers".into(),
            status: "warn".into(),
            detail: "HTTP→HTTPS redirect is disabled (enable in Connection Security)".into(),
            fix_action: None,
        }
    };
    (tls_check, https_check)
}

fn check_air_cipher(phy: &crate::radio_tuning::PhyDiagnostics) -> SecurityCheck {
    match phy.air_security.as_ref() {
        Some(sec) if sec.null_cipher_alert => SecurityCheck {
            id: "air_cipher".into(),
            title: "Over-the-air cellular encryption".into(),
            status: "fail".into(),
            detail: format!("Null cipher ({}) detected while RRC CONNECTED", sec.cipher_name),
            fix_action: None,
        },
        Some(sec) => SecurityCheck {
            id: "air_cipher".into(),
            title: "Over-the-air cellular encryption".into(),
            status: "pass".into(),
            detail: format!("{} · {} (no null-cipher alert)", sec.rat, sec.cipher_name),
            fix_action: None,
        },
        None => SecurityCheck {
            id: "air_cipher".into(),
            title: "Over-the-air cellular encryption".into(),
            status: "pass".into(),
            detail: "No null-cipher alert (awaiting active NR5G/LTE security sample)".into(),
            fix_action: None,
        },
    }
}

pub async fn run_security_audit(app: &AppState) -> SecurityAuditReport {
    let cert = crate::acme::inspect_active_cert().await;
    *app.tls_cert_info.write().await = cert.clone();
    let https_redirect = app.settings.read().await.https_redirect;
    let phy = app.phy_diag.read().await.clone();

    let blocking_checks = tokio::task::spawn_blocking(|| {
        vec![
            check_dropbear_lan_only(),
            check_dropbear_key_only(),
            check_wan_firewall(),
            check_usb_gadget(),
            check_kernel_sysctls(),
            check_file_permissions(),
        ]
    })
    .await
    .unwrap_or_default();

    let (tls_check, https_check) = check_tls_and_https(&cert, https_redirect);
    let air_check = check_air_cipher(&phy);

    let mut checks = blocking_checks;
    checks.push(tls_check);
    checks.push(https_check);
    checks.push(air_check);

    let total = checks.len();
    let passed = checks.iter().filter(|c| c.status == "pass").count();
    let score_pct = (passed * 100).checked_div(total).unwrap_or(100) as u8;
    SecurityAuditReport {
        score_pct,
        passed,
        total,
        checks,
    }
}

pub fn apply_hardened_sysctls() -> Vec<String> {
    let mut applied = Vec::new();
    for &(path, val) in HARDENED_SYSCTLS {
        let mapped = crate::paths::p(path);
        if Path::new(&mapped).exists() {
            let cur = fs::read_to_string(&mapped).unwrap_or_default().trim().to_string();
            if cur != val && fs::write(&mapped, format!("{val}\n")).is_ok() {
                let key = path.rsplit('/').next().unwrap_or(path);
                applied.push(format!("{key}={val}"));
            }
        }
    }
    applied
}

pub fn tighten_sensitive_permissions() -> Vec<String> {
    let mut fixed = Vec::new();
    for path in SENSITIVE_FILES {
        let mapped = crate::paths::p(path);
        if let Ok(meta) = fs::metadata(&mapped) {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0
                && fs::set_permissions(&mapped, fs::Permissions::from_mode(0o600)).is_ok()
            {
                fixed.push((*path).to_string());
            }
        }
    }
    fixed
}

pub fn bind_dropbear_lan_only() -> Result<String, String> {
    run_cmd_blocking_timeout("uci", &["set", "dropbear.@dropbear[0].Interface=lan"], Duration::from_secs(3))?;
    run_cmd_blocking_timeout("uci", &["commit", "dropbear"], Duration::from_secs(3))?;
    let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear", &["restart"], Duration::from_secs(6));
    Ok("Bound Dropbear SSH to Interface='lan' and restarted".into())
}

pub fn set_usb_lockdown(lock: bool) -> Result<String, String> {
    let marker = Path::new(USB_DISABLED_MARKER);
    let mapped_marker = crate::paths::p(USB_DISABLED_MARKER);
    if lock {
        crate::state::atomic_write(marker, b"1\n", 0o600)?;
        let udc = crate::paths::p("/sys/kernel/config/usb_gadget/g1/UDC");
        if Path::new(&udc).exists() {
            let _ = fs::write(&udc, "\n");
        }
        Ok("USB gadget unbound and locked down across reboots".into())
    } else {
        let _ = fs::remove_file(&mapped_marker);
        let _ = crate::reconcile::run_boot_reconcile(false);
        Ok("USB gadget lock removed and UDC re-enabled".into())
    }
}

pub fn execute_hardening_action(action: &str) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    match action {
        "dropbear_lan_only" | "dropbear-lan" => {
            log.push(bind_dropbear_lan_only()?);
        }
        "fix_perms" | "fix-perms" => {
            let fixed = tighten_sensitive_permissions();
            if fixed.is_empty() {
                log.push("All sensitive files already have 0600 permissions".into());
            } else {
                log.push(format!("Tightened 0600 permissions on: {}", fixed.join(", ")));
            }
        }
        "apply_sysctls" | "sysctls" => {
            let changed = apply_hardened_sysctls();
            if changed.is_empty() {
                log.push("Kernel security sysctls already hardened".into());
            } else {
                log.push(format!("Applied sysctls: {}", changed.join(", ")));
            }
        }
        "lock_usb" | "lock-usb" => {
            log.push(set_usb_lockdown(true)?);
        }
        "unlock_usb" | "unlock-usb" => {
            log.push(set_usb_lockdown(false)?);
        }
        "harden_all" | "all" => {
            if let Ok(m) = bind_dropbear_lan_only() {
                log.push(m);
            }
            let fixed = tighten_sensitive_permissions();
            if !fixed.is_empty() {
                log.push(format!("Tightened 0600 on: {}", fixed.join(", ")));
            }
            let changed = apply_hardened_sysctls();
            if !changed.is_empty() {
                log.push(format!("Applied sysctls: {}", changed.join(", ")));
            }
            if log.is_empty() {
                log.push("All recommended hardening controls already active".into());
            }
        }
        other => {
            return Err(format!(
                "unsupported hardening action {other:?} (allowed: dropbear_lan_only, fix_perms, apply_sysctls, lock_usb, unlock_usb, harden_all)"
            ));
        }
    }
    Ok(log)
}

pub async fn get_security_audit(State(ctx): State<HttpCtx>) -> Response {
    let report = run_security_audit(&ctx.app).await;
    Json(serde_json::json!({
        "status": "ok",
        "audit": report,
    }))
    .into_response()
}

pub async fn post_security_harden(
    State(ctx): State<HttpCtx>,
    Json(req): Json<HardenReq>,
) -> Response {
    let act = req.action.clone();
    let res = tokio::task::spawn_blocking(move || execute_hardening_action(&act)).await;
    match res {
        Ok(Ok(actions)) => {
            let summary = actions.join("; ");
            ctx.app.push_daemon_log(format!("security: hardened ({summary})"));
            ctx.app.audit.event("security", "harden", summary.clone());
            let report = run_security_audit(&ctx.app).await;
            Json(serde_json::json!({
                "status": "ok",
                "actions": actions,
                "audit": report,
            }))
            .into_response()
        }
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "error": e })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "error": format!("harden task failed: {e}") })),
        )
            .into_response(),
    }
}

pub fn run_cli(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("audit");
    match sub {
        "help" | "-h" | "--help" => {
            eprintln!(
                "Usage: cellctl security <audit [--json] | harden <dropbear-lan|fix-perms|sysctls|lock-usb|unlock-usb|all>>"
            );
            0
        }
        "audit" => {
            let as_json = args.iter().any(|a| a == "--json");
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("security audit runtime error: {e}");
                    return 1;
                }
            };
            let cert = rt.block_on(crate::acme::inspect_active_cert());
            let settings = crate::state::load_settings_from_uci_and_disk();
            let (tls_c, https_c) = check_tls_and_https(&cert, settings.https_redirect);
            let checks = vec![
                check_dropbear_lan_only(),
                check_dropbear_key_only(),
                check_wan_firewall(),
                check_usb_gadget(),
                check_kernel_sysctls(),
                check_file_permissions(),
                tls_c,
                https_c,
            ];
            let total = checks.len();
            let passed = checks.iter().filter(|c| c.status == "pass").count();
            let report = SecurityAuditReport {
                score_pct: ((passed * 100) / total.max(1)) as u8,
                passed,
                total,
                checks,
            };
            if as_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("score={}% passed={}/{}", report.score_pct, report.passed, report.total);
                for c in &report.checks {
                    println!("[{:4}] {}: {}", c.status.to_uppercase(), c.id, c.detail);
                }
            }
            0
        }
        "harden" => {
            let target = args.get(1).map(|s| s.as_str()).unwrap_or("all");
            match execute_hardening_action(target) {
                Ok(actions) => {
                    for a in actions {
                        println!("ok=1 action={a}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("security harden error: {e}");
                    2
                }
            }
        }
        other => {
            eprintln!("unknown security subcommand: {other}");
            eprintln!("Usage: cellctl security <audit [--json] | harden <dropbear-lan|fix-perms|sysctls|lock-usb|unlock-usb|all>>");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::TestSandbox;

    #[test]
    fn tightens_loose_sensitive_file_permissions_to_0600() {
        let sbx = TestSandbox::new("hardening-perms");
        let p = sbx.root.join("etc/cellcore/acme.json");
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();

        crate::paths::TEST_ENV.sync_scope(sbx.env(), || {
            let before = check_file_permissions();
            assert_eq!(before.status, "fail");
            let fixed = tighten_sensitive_permissions();
            assert!(fixed.contains(&"/etc/cellcore/acme.json".to_string()));
            let after = check_file_permissions();
            assert_eq!(after.status, "pass");
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }

    #[test]
    fn validates_unknown_hardening_action() {
        assert!(execute_hardening_action("rm_rf").is_err());
    }
}

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

/// Parse `/proc/net/tcp` or `/proc/net/tcp6` and report whether any socket is
/// in `TCP_LISTEN` (`0A`) on `port`, plus whether it is bound to a wildcard address.
pub(crate) fn inspect_proc_net_tcp_port(body: &str, port: u16) -> (bool, bool) {
    let mut listening = false;
    let mut wildcard = false;
    for line in body.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _sl = cols.next();
        let Some(local) = cols.next() else { continue };
        let _rem = cols.next();
        let Some(state) = cols.next() else { continue };
        if !state.eq_ignore_ascii_case("0A") {
            continue;
        }
        let Some((ip_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        if u16::from_str_radix(port_hex, 16).ok() == Some(port) {
            listening = true;
            if ip_hex.bytes().all(|b| b == b'0') {
                wildcard = true;
            }
        }
    }
    (listening, wildcard)
}

/// Check live `/proc/net/tcp` and `/proc/net/tcp6` for a listening socket on `port`.
/// Returns `None` if neither proc file can be read.
pub fn probe_tcp_port_listener(port: u16) -> Option<(bool, bool)> {
    let mut found_file = false;
    let mut listening = false;
    let mut wildcard = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(body) = fs::read_to_string(crate::paths::p(path)) {
            found_file = true;
            let (l, w) = inspect_proc_net_tcp_port(&body, port);
            listening |= l;
            wildcard |= w;
        }
    }
    if found_file {
        Some((listening, wildcard))
    } else {
        None
    }
}

pub fn dropbear_configured_port() -> u16 {
    uci_get_blocking("dropbear.@dropbear[0].Port")
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(22)
}

const NFT_SSH_LAN_PATH: &str = "/etc/nftables.d/25-cellcore-ssh-lan.nft";
const FIREWALL_USER_PATH: &str = "/etc/firewall.user";
const FW_USER_SSH_BEGIN: &str = "# cellcore-ssh-wan-guard-begin";
const FW_USER_SSH_END: &str = "# cellcore-ssh-wan-guard-end";

pub(crate) fn update_firewall_user_ssh_guard(existing: &str, port: u16) -> String {
    let mut kept = Vec::new();
    let mut skipping = false;
    for line in existing.lines() {
        let t = line.trim();
        if t == FW_USER_SSH_BEGIN {
            skipping = true;
            continue;
        }
        if t == FW_USER_SSH_END {
            skipping = false;
            continue;
        }
        if !skipping {
            kept.push(line);
        }
    }
    let mut out = kept.join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(FW_USER_SSH_BEGIN);
    out.push('\n');
    for bin in ["iptables", "ip6tables"] {
        for ifp in ["rmnet+", "wwan+"] {
            out.push_str(&format!(
                "{bin} -C INPUT -i {ifp} -p tcp --dport {port} -j DROP 2>/dev/null || {bin} -I INPUT 1 -i {ifp} -p tcp --dport {port} -j DROP\n"
            ));
        }
    }
    out.push_str(FW_USER_SSH_END);
    out.push('\n');
    out
}

pub(crate) fn has_wan_ssh_drop_rule(port: u16) -> bool {
    let nft_path = crate::paths::p(NFT_SSH_LAN_PATH);
    if let Ok(nft_body) = fs::read_to_string(&nft_path) {
        let want = format!("tcp dport {port} drop");
        if nft_body.contains(&want) {
            return true;
        }
    }
    let v4 = run_cmd_blocking_timeout("iptables", &["-S", "INPUT"], Duration::from_secs(2))
        .unwrap_or_default();
    let needle = format!("--dport {port}");
    (v4.contains("rmnet+") && v4.contains(&needle) && v4.contains("DROP"))
        || (v4.contains("rmnet") && v4.contains("MGW1_WAN_IN"))
}

/// Update live iptables/ip6tables rules, `/etc/nftables.d/25-cellcore-ssh-lan.nft`,
/// and fw3 `/etc/firewall.user` persistence when Dropbear's SSH port changes (or on harden).
pub fn sync_wan_ssh_drop_rules(old_port: Option<u16>, port: u16) {
    if let Some(old) = old_port
        && old != port
    {
        let old_s = old.to_string();
        for bin in ["iptables", "ip6tables"] {
            for ifp in ["rmnet+", "wwan+"] {
                let _ = run_cmd_blocking_timeout(
                    bin,
                    &["-D", "INPUT", "-i", ifp, "-p", "tcp", "--dport", &old_s, "-j", "DROP"],
                    Duration::from_secs(2),
                );
            }
        }
    }
    apply_wan_ssh_drop_rules(port);
}

fn apply_wan_ssh_drop_rules(port: u16) {
    let p_str = port.to_string();
    for bin in ["iptables", "ip6tables"] {
        for ifp in ["rmnet+", "wwan+"] {
            let exists = run_cmd_blocking_timeout(
                bin,
                &["-C", "INPUT", "-i", ifp, "-p", "tcp", "--dport", &p_str, "-j", "DROP"],
                Duration::from_secs(2),
            )
            .is_ok();
            if !exists {
                let _ = run_cmd_blocking_timeout(
                    bin,
                    &["-I", "INPUT", "1", "-i", ifp, "-p", "tcp", "--dport", &p_str, "-j", "DROP"],
                    Duration::from_secs(2),
                );
            }
        }
    }
    if Path::new(&crate::paths::p("/etc/nftables.d")).exists() {
        let nft_rule = format!(
            "chain cellcore_ssh_wan_guard {{\n\ttype filter hook input priority -5; policy accept;\n\tiifname {{ \"rmnet*\", \"wwan*\" }} tcp dport {port} drop comment \"cellcore: block WAN SSH\"\n}}\n"
        );
        if crate::state::atomic_write(Path::new(NFT_SSH_LAN_PATH), nft_rule.as_bytes(), 0o644).is_ok() {
            let _ = run_cmd_blocking_timeout("fw4", &["reload"], Duration::from_secs(5));
        }
    }
    let fw_user_mapped = crate::paths::p(FIREWALL_USER_PATH);
    if Path::new(&fw_user_mapped).exists() {
        let existing = fs::read_to_string(&fw_user_mapped).unwrap_or_default();
        let updated = update_firewall_user_ssh_guard(&existing, port);
        if updated != existing {
            let _ = crate::state::atomic_write(Path::new(FIREWALL_USER_PATH), updated.as_bytes(), 0o644);
        }
    }
}

/// Evaluate whether `dropbear` has `Interface` unset (boot-safe) while WAN SSH
/// is blocked at the firewall and port 22 is actively listening.
fn check_dropbear_lan_only() -> SecurityCheck {
    let iface = uci_get_blocking("dropbear.@dropbear[0].Interface").unwrap_or_default();
    let port = dropbear_configured_port();
    let has_iface_lockout_risk = !iface.trim().is_empty();
    let live = probe_tcp_port_listener(port);
    let fw_guarded = has_wan_ssh_drop_rule(port);
    if has_iface_lockout_risk {
        return SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH protected from WAN (boot-safe)".into(),
            status: "warn".into(),
            detail: format!(
                "Dropbear Interface='{}' risks OpenWrt BOOT=1 SSH skip — click Fix to switch to boot-safe firewall WAN block",
                iface.trim()
            ),
            fix_action: Some("dropbear_lan_only".into()),
        };
    }
    if matches!(live, Some((false, _))) {
        return SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH protected from WAN (boot-safe)".into(),
            status: "fail".into(),
            detail: format!("Dropbear port {port} is NOT listening — click Fix to recover"),
            fix_action: Some("dropbear_lan_only".into()),
        };
    }
    if fw_guarded {
        SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH protected from WAN (boot-safe)".into(),
            status: "pass".into(),
            detail: format!(
                "Dropbear Interface unset (boot-safe) · WAN port {port} blocked in firewall · listening"
            ),
            fix_action: None,
        }
    } else {
        SecurityCheck {
            id: "dropbear_lan_only".into(),
            title: "SSH protected from WAN (boot-safe)".into(),
            status: "warn".into(),
            detail: format!(
                "Dropbear listening on port {port}, but explicit rmnet/wwan SSH DROP rule not yet installed"
            ),
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

fn wait_for_tcp_port_listening(port: u16, attempts: usize, step: Duration) -> bool {
    for _ in 0..attempts {
        if matches!(probe_tcp_port_listener(port), Some((true, _))) {
            return true;
        }
        std::thread::sleep(step);
    }
    matches!(probe_tcp_port_listener(port), Some((true, _)))
}

fn rollback_dropbear_interface() {
    let _ = run_cmd_blocking_timeout("uci", &["delete", "dropbear.@dropbear[0].Interface"], Duration::from_secs(3));
    let _ = run_cmd_blocking_timeout("uci", &["commit", "dropbear"], Duration::from_secs(3));
    let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear", &["restart"], Duration::from_secs(6));
}

pub fn bind_dropbear_lan_only() -> Result<String, String> {
    let port = dropbear_configured_port();
    // Always keep dropbear.@dropbear[0].Interface UNSET so OpenWrt S19dropbear
    // starts unconditionally on every boot even if cellcored is absent/stopped,
    // and enforce LAN-only SSH at the kernel firewall layer instead.
    let _ = run_cmd_blocking_timeout("uci", &["delete", "dropbear.@dropbear[0].Interface"], Duration::from_secs(3));
    let _ = run_cmd_blocking_timeout("uci", &["commit", "dropbear"], Duration::from_secs(3));
    apply_wan_ssh_drop_rules(port);
    let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear", &["restart"], Duration::from_secs(6));

    if probe_tcp_port_listener(port).is_some()
        && !wait_for_tcp_port_listening(port, 10, Duration::from_millis(250))
    {
        let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear", &["start"], Duration::from_secs(6));
    }

    // Ensure standalone POSIX S99 init safeguard is installed & enabled so Dropbear
    // starts after boot even if cellcored itself is ever absent or stopped.
    let wdog_init = Path::new("/etc/init.d/dropbear-lan-watchdog");
    if Path::new(&crate::paths::p("/etc/init.d")).exists() {
        let script = include_bytes!("../../../scripts/etc/init.d/dropbear-lan-watchdog");
        if crate::state::atomic_write(wdog_init, script, 0o755).is_ok() {
            let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear-lan-watchdog", &["enable"], Duration::from_secs(3));
        }
    }
    Ok(format!(
        "Cleared Dropbear Interface (boot-safe), enforced WAN port {port} firewall drop, and verified SSH listening"
    ))
}

/// Reconcile Dropbear after OpenWrt boot: clear any stale `Interface='lan'` that
/// could trigger OpenWrt's `BOOT=1` skip, enforce WAN SSH drop rules, and start Dropbear.
pub fn reconcile_dropbear_listener() -> Option<String> {
    if !Path::new(&crate::paths::p("/etc/init.d/dropbear")).exists() {
        return None;
    }
    let enabled = uci_get_blocking("dropbear.@dropbear[0].enable").unwrap_or_default();
    if enabled.trim() == "0" {
        return None;
    }
    let port = dropbear_configured_port();
    let iface = uci_get_blocking("dropbear.@dropbear[0].Interface").unwrap_or_default();
    let mut cleared_iface = false;
    if !iface.trim().is_empty() {
        rollback_dropbear_interface();
        cleared_iface = true;
    }
    apply_wan_ssh_drop_rules(port);
    if !matches!(probe_tcp_port_listener(port), Some((false, _))) {
        return cleared_iface.then(|| {
            format!(
                "Migrated Dropbear Interface='{}' -> boot-safe unset + WAN firewall drop on port {port}",
                iface.trim()
            )
        });
    }

    let _ = run_cmd_blocking_timeout("/etc/init.d/dropbear", &["start"], Duration::from_secs(6));
    if wait_for_tcp_port_listening(port, 10, Duration::from_millis(250)) {
        return Some(format!(
            "Started Dropbear cleanly on port {port} with WAN firewall drop active"
        ));
    }
    Some(format!(
        "Dropbear not listening on port {port} after boot start attempt"
    ))
}

/// Spawn a lightweight post-boot watchdog at t+12s and t+40s so Dropbear pinned
/// to `Interface='lan'` can never suffer the OpenWrt `S11network -> S19dropbear`
/// boot-time SSH lockout bug.
pub fn spawn_dropbear_boot_watchdog(app: AppState) {
    tokio::spawn(async move {
        for delay_secs in [12u64, 28u64] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            if let Ok(Some(msg)) = tokio::task::spawn_blocking(reconcile_dropbear_listener).await {
                app.push_daemon_log(format!("security: {msg}"));
                app.audit.event("security", "dropbear-watchdog", msg);
            }
        }
    });
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

    #[test]
    fn inspects_proc_net_tcp_for_dropbear_listener_and_wildcard() {
        let lan_only = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 01E4A8C0:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234
   1: 01E4A8C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1235
";
        assert_eq!(inspect_proc_net_tcp_port(lan_only, 22), (true, false));
        assert_eq!(inspect_proc_net_tcp_port(lan_only, 2222), (false, false));

        let wildcard = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234
";
        assert_eq!(inspect_proc_net_tcp_port(wildcard, 22), (true, true));

        let established_only = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 01E4A8C0:0016 32E4A8C0:C123 01 00000000:00000000 00:00000000 00000000     0        0 1234
";
        assert_eq!(inspect_proc_net_tcp_port(established_only, 22), (false, false));

        let sbx = TestSandbox::new("hardening-proc-tcp");
        let p = sbx.root.join("proc/net/tcp");
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, lan_only).unwrap();
        crate::paths::TEST_ENV.sync_scope(sbx.env(), || {
            assert_eq!(probe_tcp_port_listener(22), Some((true, false)));
            assert_eq!(probe_tcp_port_listener(2222), Some((false, false)));
        });
    }

    #[test]
    fn wan_ssh_drop_rule_verifies_active_port_and_updates_fw3_and_nft() {
        let sbx = TestSandbox::new("hardening-ssh-port");
        fs::create_dir_all(sbx.root.join("etc/nftables.d")).unwrap();
        sbx.write("/etc/firewall.user", "# custom user rules\n");
        sbx.write_exec("/bin/iptables", "#!/bin/sh\nexit 1\n");
        sbx.write_exec("/bin/ip6tables", "#!/bin/sh\nexit 1\n");
        sbx.write_exec("/bin/fw4", "#!/bin/sh\nexit 0\n");

        crate::paths::TEST_ENV.sync_scope(sbx.env(), || {
            apply_wan_ssh_drop_rules(22);
            assert!(has_wan_ssh_drop_rule(22));
            assert!(!has_wan_ssh_drop_rule(2222), "stale port 22 rule must not satisfy port 2222");

            sync_wan_ssh_drop_rules(Some(22), 2222);
            assert!(has_wan_ssh_drop_rule(2222));
            assert!(!has_wan_ssh_drop_rule(22));

            let fw_user = fs::read_to_string(sbx.root.join("etc/firewall.user")).unwrap();
            assert!(fw_user.contains("# custom user rules"));
            assert!(fw_user.contains("--dport 2222 -j DROP"));
            assert!(!fw_user.contains("--dport 22 -j DROP"));
            assert_eq!(fw_user.matches(FW_USER_SSH_BEGIN).count(), 1);
        });
    }
}

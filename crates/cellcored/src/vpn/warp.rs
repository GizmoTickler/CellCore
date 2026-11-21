//! WARP handlers: consumer account (wgcf), Zero Trust enrollment, the native
//! `proto wireguard` interface, and the routing policy + fail-back monitor.

use std::path::PathBuf;

use axum::{Json, extract::State, response::Response};
use serde::Deserialize;

use super::{
    FW_FWD, FW_ZONE, Mode, RUNTIME, WG_IF, WG_PEER, WarpKind, WarpState, chmod_600, ensure_state_dir, have, load_state,
    parse::{self, WgProfile},
    paths,
    policy::{self, Health, RouteAction},
    redact, save_state, teams, validate,
};
use crate::{
    admin::{
        audit, bad, conflict,
        exec::{ExecOpts, KIB, MIB, run, run_ok},
        fail, mutate_lock, ok, require_confirm, server,
        ucicfg::{self, Op},
    },
    auth::now_secs,
    http::HttpCtx,
    obs::{EventKind, Severity, emit, failover},
};

pub const CONFIRM_REPLACE: &str = "REPLACE WARP ACCOUNT";
pub const CONFIRM_LAN: &str = "ROUTE LAN VIA WARP";
pub const CONFIRM_REMOVE: &str = "REMOVE WARP";

fn account_file() -> PathBuf {
    paths().state.join("wgcf-account.toml")
}

fn profile_file() -> PathBuf {
    paths().state.join("wgcf-profile.conf")
}

fn s(p: &std::path::Path) -> String {
    p.display().to_string()
}

fn consumer_account() -> Option<parse::WgcfAccount> {
    let t = std::fs::read_to_string(account_file()).ok()?;
    let a = parse::parse_wgcf_account(&t);
    (!a.device_id.is_empty() && a.has_private_key).then_some(a)
}

// ── live data ───────────────────────────────────────────────────────────────

fn device_present() -> bool {
    paths().sys_net.join(WG_IF).exists()
}

async fn wg_dump() -> Option<parse::WgDump> {
    let out = run("wg", &["show", WG_IF, "dump"], ExecOpts::new(5, 64 * KIB)).await.ok()?;
    out.ok().then(|| parse::parse_wg_dump(&out.stdout_str())).flatten()
}

async fn latest_handshake() -> Option<u64> {
    let out = run("wg", &["show", WG_IF, "latest-handshakes"], ExecOpts::new(5, 16 * KIB)).await.ok()?;
    out.ok().then(|| parse::parse_latest_handshake(&out.stdout_str())).flatten()
}

async fn route_present(table: u32) -> bool {
    let t = table.to_string();
    match run("ip", &["-4", "route", "show", "table", &t], ExecOpts::new(5, 64 * KIB)).await {
        Ok(o) if o.ok() => o.stdout_str().lines().any(|l| l.starts_with("default")),
        _ => false,
    }
}

async fn live_rules() -> Result<Vec<(u32, String)>, String> {
    Ok(parse::parse_ip_rules(&run_ok("ip", &["-4", "rule", "show"], 5, 256 * KIB).await?))
}

async fn iface_status() -> serde_json::Value {
    let path = format!("network.interface.{WG_IF}");
    match run_ok("ubus", &["call", &path, "status"], 5, 64 * KIB).await {
        Ok(t) => serde_json::from_str(&t).unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    }
}

/// Bring the ip rules in our range in line with the stored policy.
pub async fn reconcile_rules(st: &WarpState) -> Result<policy::RuleDiff, String> {
    let plan = st.plan();
    let diff = policy::diff_rules(&plan, &live_rules().await?);
    for p in &diff.delete_prefs {
        let ps = p.to_string();
        let _ = run("ip", &["-4", "rule", "del", "pref", &ps], ExecOpts::new(5, KIB)).await;
    }
    for (p, t) in &diff.add {
        let argv = policy::Plan::add_argv(*p, t);
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        run_ok("ip", &a, 5, KIB).await?;
    }
    Ok(diff)
}

/// One monitor step: measure tunnel health and install / withdraw the
/// table's default route. Returns the action taken.
pub async fn tick(now: u64) -> RouteAction {
    let st = load_state();
    // Never installed and nothing left behind: no process spawns every 5 s.
    if !st.installed && st.policy == Mode::Off && !crate::obs::lock(&RUNTIME).route_installed && !device_present() {
        return RouteAction::Keep;
    }
    let present = device_present();
    let latest = if present { latest_handshake().await } else { None };
    let age = policy::handshake_age(latest, now);
    let was = crate::obs::lock(&RUNTIME).usable;
    let usable = policy::tunnel_usable(was, Health { device_present: present, handshake_age: age });
    let route = route_present(st.table).await;
    let action = policy::route_action(st.policy, route, usable);
    let table = st.table.to_string();
    let mut err = None;
    match action {
        RouteAction::Install => {
            // Replies arrive on the tunnel while the main table points at
            // rmnet: loose reverse-path filtering for this device only.
            let rp = paths().proc_sys.join(format!("net/ipv4/conf/{WG_IF}/rp_filter"));
            let _ = std::fs::write(rp, b"2");
            if let Err(e) = run_ok("ip", &["-4", "route", "replace", "default", "dev", WG_IF, "table", &table], 5, KIB).await {
                err = Some(e);
            }
        }
        RouteAction::Withdraw => {
            if let Err(e) = run_ok("ip", &["-4", "route", "flush", "table", &table], 5, KIB).await {
                err = Some(e);
            }
        }
        RouteAction::Keep => {}
    }
    let installed_now = match action {
        RouteAction::Install => err.is_none(),
        RouteAction::Withdraw => err.is_some() && route,
        RouteAction::Keep => route,
    };
    let mut rt = crate::obs::lock(&RUNTIME);
    let changed = rt.usable != usable;
    rt.usable = usable;
    rt.device_present = present;
    rt.handshake_age = age;
    rt.route_installed = installed_now;
    if err.is_some() {
        rt.last_error = err.clone();
    }
    if changed && st.policy != Mode::Off {
        rt.last_transition = now;
        if !usable {
            rt.failbacks += 1;
        }
        drop(rt);
        let fo = failover::is_active();
        if usable {
            emit(
                EventKind::Vpn,
                Severity::Info,
                "WARP tunnel healthy: steering traffic through Cloudflare again",
                serde_json::json!({ "mode": st.policy.as_str(), "handshakeAge": age, "failoverActive": fo }),
            );
        } else {
            let why = if !present { "interface down" } else if age.is_none() { "no handshake yet" } else { "peer silent" };
            emit(
                EventKind::Vpn,
                if st.policy == Mode::Lan || fo { Severity::Warning } else { Severity::Info },
                format!("WARP tunnel unusable ({why}): traffic falls back to the cellular path"),
                serde_json::json!({ "mode": st.policy.as_str(), "reason": why, "handshakeAge": age, "failoverActive": fo }),
            );
        }
    }
    action
}

// ── GET ─────────────────────────────────────────────────────────────────────

pub async fn get_warp() -> Response {
    let st = load_state();
    let acct = consumer_account();
    let dump = if device_present() { wg_dump().await } else { None };
    let iface = iface_status().await;
    let now = now_secs();
    let rt = super::runtime();
    let peer = dump.as_ref().and_then(|d| d.peers.first());
    let plan = st.plan();
    let rules: Vec<serde_json::Value> = live_rules()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|(p, _)| plan.owns(*p))
        .map(|(p, t)| serde_json::json!({ "pref": p, "rule": t }))
        .collect();
    let fo = failover::is_active();
    let mut warnings: Vec<String> = Vec::new();
    if st.policy == Mode::Lan && fo {
        warnings.push("Upstream failover is active on this modem right now, and that traffic exits through Cloudflare.".into());
    }
    if st.policy != Mode::Off && !rt.usable {
        warnings.push("The tunnel is not usable; traffic is taking the normal cellular path (fail-back).".into());
    }
    if st.installed && !have("wg") {
        warnings.push("wireguard-tools is not installed; tunnel statistics are unavailable.".into());
    }
    let consumer = acct.as_ref().map(|a| {
        serde_json::json!({
            "deviceId": a.device_id,
            "licenseSet": !a.license_key.is_empty(),
            "profileReady": profile_file().is_file(),
        })
    });
    ok(serde_json::json!({
        "tools": {
            "wgcf": have("wgcf"),
            "wg": have("wg"),
            "curl": have("curl"),
            "kernelModule": paths().sys_module.join("wireguard").exists(),
        },
        "account": {
            "kind": st.kind,
            "consumer": consumer,
            "teams": st.teams.as_ref().map(|t| t.public_json()),
        },
        "interface": {
            "installed": st.installed,
            "autostart": st.autostart,
            "up": iface.get("up").and_then(|v| v.as_bool()).unwrap_or(false),
            "uptime": iface.get("uptime").and_then(|v| v.as_u64()),
            "devicePresent": device_present(),
            "mtu": st.mtu,
            "keepalive": st.keepalive,
            "endpointOverride": st.endpoint,
            "publicKey": dump.as_ref().map(|d| d.public_key.clone()),
            "endpoint": peer.and_then(|p| p.endpoint.clone()),
            "handshakeAge": peer.and_then(|p| policy::handshake_age(Some(p.latest_handshake), now)),
            "rxBytes": peer.map(|p| p.rx_bytes),
            "txBytes": peer.map(|p| p.tx_bytes),
        },
        "policy": {
            "mode": st.policy,
            "changedAt": st.policy_changed_at,
            "usable": rt.usable,
            "routeInstalled": rt.route_installed,
            "failingBack": st.policy != Mode::Off && !rt.usable,
            "failbacks": rt.failbacks,
            "lastTransition": rt.last_transition,
            "lastError": rt.last_error,
            "pref": st.pref,
            "table": st.table,
            "lanDevice": st.lan_dev,
            "rules": rules,
            "staleSecs": policy::STALE_SECS,
        },
        "failoverActive": fo,
        "warnings": warnings,
    }))
}

/// Account details from Cloudflare (network call, so separate from GET /warp).
pub async fn get_account() -> Response {
    let st = load_state();
    match st.kind {
        Some(WarpKind::Consumer) if consumer_account().is_some() => {
            let cfg = s(&account_file());
            match run("wgcf", &["status", "--config", &cfg], ExecOpts::new(45, 256 * KIB)).await {
                Ok(o) => {
                    let text = o.log();
                    let lic = consumer_account().map(|a| a.license_key).unwrap_or_default();
                    match parse::parse_wgcf_status(&text) {
                        Some(stt) => ok(serde_json::json!({ "kind": "consumer", "status": stt })),
                        None => fail(axum::http::StatusCode::BAD_GATEWAY, redact(&o.err_summary("wgcf status"), &[&lic])),
                    }
                }
                Err(e) => server(e),
            }
        }
        Some(WarpKind::Teams) => ok(serde_json::json!({ "kind": "teams", "teams": st.teams.as_ref().map(|t| t.public_json()) })),
        _ => ok(serde_json::json!({ "kind": null })),
    }
}

// ── consumer ────────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterReq {
    #[serde(default)]
    confirm: Option<String>,
}

fn has_any_account(st: &WarpState) -> bool {
    consumer_account().is_some() || st.teams.is_some()
}

async fn wgcf_generate() -> Result<(), String> {
    let (cfg, prof) = (s(&account_file()), s(&profile_file()));
    run_ok("wgcf", &["generate", "--config", &cfg, "--profile", &prof], 60, 64 * KIB).await?;
    chmod_600(&profile_file());
    Ok(())
}

pub async fn post_register(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: RegisterReq = match super::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    if !have("wgcf") {
        return conflict("wgcf is not installed; install it from Software (package wgcf) first");
    }
    let _g = mutate_lock().await;
    let mut st = load_state();
    if has_any_account(&st)
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            CONFIRM_REPLACE,
            "This replaces the current WARP registration; its keys are deleted and a WARP+ license must be applied again.",
        )
    {
        return r;
    }
    if let Err(e) = ensure_state_dir() {
        return server(e);
    }
    let _ = std::fs::remove_file(account_file());
    let _ = std::fs::remove_file(profile_file());
    let cfg = s(&account_file());
    let out = match run("wgcf", &["register", "--accept-tos", "--config", &cfg], ExecOpts::new(60, 64 * KIB)).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    chmod_600(&account_file());
    if !out.ok() || consumer_account().is_none() {
        return fail(axum::http::StatusCode::BAD_GATEWAY, out.err_summary("wgcf register"));
    }
    if let Err(e) = wgcf_generate().await {
        return fail(axum::http::StatusCode::BAD_GATEWAY, e);
    }
    st.kind = Some(WarpKind::Consumer);
    st.teams = None;
    st.teams_private_key.clear();
    if let Err(e) = save_state(&st) {
        return server(e);
    }
    audit(&ctx, "vpn: WARP consumer device registered");
    ok(serde_json::json!({ "status": "ok", "needsInstall": !st.installed, "deviceId": consumer_account().map(|a| a.device_id) }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseReq {
    license_key: String,
}

pub async fn post_license(State(ctx): State<HttpCtx>, Json(req): Json<LicenseReq>) -> Response {
    let key = req.license_key.trim().to_string();
    if !validate::is_warp_license(&key) {
        return bad("That does not look like a WARP+ license key (three groups of 8 letters/digits: xxxxxxxx-xxxxxxxx-xxxxxxxx)");
    }
    let _g = mutate_lock().await;
    if consumer_account().is_none() {
        return conflict("Register a WARP device first");
    }
    let cfg = s(&account_file());
    // The key goes in through wgcf's environment binding, never argv.
    let out = match run("wgcf", &["update", "--config", &cfg], ExecOpts::new(60, 64 * KIB).env("WGCF_LICENSE_KEY", &key)).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    chmod_600(&account_file());
    if !out.ok() {
        return fail(axum::http::StatusCode::BAD_GATEWAY, redact(&out.err_summary("wgcf update"), &[&key]));
    }
    if let Err(e) = wgcf_generate().await {
        return fail(axum::http::StatusCode::BAD_GATEWAY, redact(&e, &[&key]));
    }
    let bound = consumer_account().is_some_and(|a| a.license_key == key);
    audit(&ctx, format!("vpn: WARP+ license applied (bound={bound})"));
    ok(serde_json::json!({ "status": "ok", "licenseSet": bound }))
}

// ── Zero Trust ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsReq {
    team: String,
    #[serde(default)]
    team_token: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    confirm: Option<String>,
}

async fn curl_stdin(cfg: String, timeout: u64) -> Result<String, String> {
    let out = run("curl", &["-q", "-K", "-"], ExecOpts::new(timeout, MIB).stdin(cfg.into_bytes())).await?;
    if out.ok() { Ok(out.stdout_str()) } else { Err(out.err_summary("curl")) }
}

pub async fn post_teams(State(ctx): State<HttpCtx>, Json(req): Json<TeamsReq>) -> Response {
    let Some(team) = validate::team_name(&req.team) else {
        return bad("Team name: the part before .cloudflareaccess.com");
    };
    enum Cred {
        Token(String),
        Service(String, String),
    }
    let cred = match (req.team_token.as_deref().map(str::trim).filter(|s| !s.is_empty()), req.client_id.as_deref(), req.client_secret.as_deref()) {
        (Some(t), _, _) => match validate::team_token(t) {
            Some(t) => Cred::Token(t),
            None => return bad("Team token: paste the com.cloudflare.warp://… link (or the token) from the success page"),
        },
        (None, Some(id), Some(sec)) => {
            let (id, sec) = (id.trim(), sec.trim());
            if !validate::is_access_client_id(id) || !validate::is_access_client_secret(sec) {
                return bad("Service token: Client ID ends in .access and the Client Secret is 64 hex characters");
            }
            Cred::Service(id.to_string(), sec.to_string())
        }
        _ => return bad("Give either a team token or a service token (Client ID and Client Secret)"),
    };
    if !have("curl") || !have("wg") {
        return conflict("Zero Trust enrollment needs curl and wireguard-tools (wg) installed");
    }
    let _g = mutate_lock().await;
    let mut st = load_state();
    if has_any_account(&st)
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            CONFIRM_REPLACE,
            "This replaces the current WARP registration with a Zero Trust device.",
        )
    {
        return r;
    }
    let (jwt, secrets): (String, Vec<String>) = match cred {
        Cred::Token(t) => (t.clone(), vec![t]),
        Cred::Service(id, sec) => {
            let page = match curl_stdin(teams::service_token_config(&team, &id, &sec), 40).await {
                Ok(p) => p,
                Err(e) => return fail(axum::http::StatusCode::BAD_GATEWAY, redact(&e, &[&id, &sec])),
            };
            match teams::token_from_success_page(&page) {
                Some(t) => (t.clone(), vec![t, id, sec]),
                None => {
                    return fail(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "Cloudflare did not return an enrollment token for this service token. Check that the device enrollment policy has a Service Auth rule for it, or enroll with a team token instead.",
                    );
                }
            }
        }
    };
    let sref: Vec<&str> = secrets.iter().map(String::as_str).collect();
    // Fresh WireGuard key pair for this device.
    let private = match run_ok("wg", &["genkey"], 5, KIB).await {
        Ok(k) if validate::is_wg_key(k.trim()) => k.trim().to_string(),
        Ok(_) => return server("wg genkey returned an unexpected value"),
        Err(e) => return server(e),
    };
    let public = match run("wg", &["pubkey"], ExecOpts::new(5, KIB).stdin(format!("{private}\n").into_bytes())).await {
        Ok(o) if o.ok() && validate::is_wg_key(o.stdout_str().trim()) => o.stdout_str().trim().to_string(),
        _ => return server("wg pubkey failed"),
    };
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
    let name = if crate::admin::validate::is_host_label(&host) { host } else { "quecmanager".into() };
    let body = teams::registration_body(&public, &name, &teams::rfc3339_now());
    let resp = match curl_stdin(teams::registration_config(&jwt, &body), 40).await {
        Ok(r) => r,
        Err(e) => return fail(axum::http::StatusCode::BAD_GATEWAY, redact(&e, &sref)),
    };
    let dev = match teams::parse_registration(&resp, &team) {
        Ok(d) => d,
        Err(e) => return fail(axum::http::StatusCode::BAD_GATEWAY, redact(&e, &sref)),
    };
    let _ = std::fs::remove_file(account_file());
    let _ = std::fs::remove_file(profile_file());
    st.kind = Some(WarpKind::Teams);
    st.teams = Some(dev.clone());
    st.teams_private_key = private;
    if let Err(e) = save_state(&st) {
        return server(e);
    }
    audit(&ctx, format!("vpn: enrolled into Zero Trust team {team} as {}", dev.device_id));
    let mut warn = Vec::new();
    if !dev.client_id.is_empty() {
        warn.push("Cloudflare assigned reserved bytes to this device; the kernel WireGuard module cannot send them. Most Zero Trust orgs accept the tunnel anyway; verify the handshake after Install.");
    }
    ok(serde_json::json!({ "status": "ok", "needsInstall": true, "teams": dev.public_json(), "warnings": warn }))
}

// ── install as a native wireguard interface ────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallReq {
    #[serde(default)]
    mtu: Option<u16>,
    #[serde(default)]
    keepalive: Option<u16>,
    /// `host:port`; empty string clears the override.
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    autostart: Option<bool>,
    /// LAN bridge whose forwarded traffic policy `lan` steers (default br-lan).
    #[serde(default)]
    lan_device: Option<String>,
}

/// The peer and address set to install, from whichever account exists.
pub fn build_profile(st: &WarpState) -> Result<WgProfile, String> {
    match st.kind {
        Some(WarpKind::Consumer) => {
            let t = std::fs::read_to_string(profile_file()).map_err(|_| "No WARP profile yet; register first".to_string())?;
            parse::parse_wg_profile(&t)
        }
        Some(WarpKind::Teams) => {
            let d = st.teams.as_ref().ok_or("No Zero Trust enrollment")?;
            let (h, p) = d.endpoint();
            parse::parse_wg_profile(&format!(
                "[Interface]\nPrivateKey = {}\nAddress = {}/32\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {h}:{p}\n",
                st.teams_private_key, d.address_v4, d.peer_public_key
            ))
        }
        None => Err("Register WARP or enroll in Zero Trust first".into()),
    }
}

/// uci ops for /etc/config/network. IPv4 only: the backup path is IPv4.
pub fn network_ops(st: &WarpState, p: &WgProfile) -> Result<Vec<Op>, String> {
    let (host, port) = match st.endpoint.as_deref() {
        Some(e) => validate::endpoint(e).ok_or("invalid endpoint override")?,
        None => validate::endpoint(&p.endpoint).ok_or("profile endpoint invalid")?,
    };
    let addr = p.v4_address().ok_or("no IPv4 address")?;
    let addr = if addr.contains('/') { addr.to_string() } else { format!("{addr}/32") };
    Ok(vec![
        Op::Section { section: WG_IF.into(), stype: "interface".into() },
        Op::set(WG_IF, "proto", "wireguard"),
        Op::set(WG_IF, "private_key", p.private_key.clone()),
        Op::SetList { section: WG_IF.into(), option: "addresses".into(), values: vec![addr] },
        Op::set(WG_IF, "mtu", st.mtu.to_string()),
        Op::set(WG_IF, "fwmark", format!("{:#x}", policy::BYPASS_MARK)),
        Op::set(WG_IF, "auto", if st.autostart { "1" } else { "0" }),
        Op::set(WG_IF, "ipv6", "0"),
        Op::Section { section: WG_PEER.into(), stype: format!("wireguard_{WG_IF}") },
        Op::set(WG_PEER, "description", "Cloudflare WARP (CellCore)"),
        Op::set(WG_PEER, "public_key", p.peer_public_key.clone()),
        Op::set(WG_PEER, "endpoint_host", host),
        Op::set(WG_PEER, "endpoint_port", port.to_string()),
        Op::set(WG_PEER, "persistent_keepalive", st.keepalive.to_string()),
        // Never let netifd add 0.0.0.0/0 to the main table: steering is ours.
        Op::set(WG_PEER, "route_allowed_ips", "0"),
        Op::SetList { section: WG_PEER.into(), option: "allowed_ips".into(), values: vec!["0.0.0.0/0".into()] },
    ])
}

/// uci ops for /etc/config/firewall: an outbound-only zone with masquerade
/// and MSS clamping, plus lan→warp forwarding (it only matters once policy
/// `lan` actually routes LAN traffic into the tunnel).
pub fn firewall_ops() -> Vec<Op> {
    vec![
        Op::Section { section: FW_ZONE.into(), stype: "zone".into() },
        Op::set(FW_ZONE, "name", WG_IF),
        Op::SetList { section: FW_ZONE.into(), option: "network".into(), values: vec![WG_IF.into()] },
        Op::set(FW_ZONE, "input", "REJECT"),
        Op::set(FW_ZONE, "output", "ACCEPT"),
        Op::set(FW_ZONE, "forward", "REJECT"),
        Op::set(FW_ZONE, "masq", "1"),
        Op::set(FW_ZONE, "mtu_fix", "1"),
        Op::Section { section: FW_FWD.into(), stype: "forwarding".into() },
        Op::set(FW_FWD, "src", "lan"),
        Op::set(FW_FWD, "dest", WG_IF),
    ]
}

async fn reload_network() -> Result<(), String> {
    run_ok("ubus", &["call", "network", "reload"], 30, 64 * KIB).await.map(|_| ())
}

async fn reload_firewall() -> Result<(), String> {
    match run_ok("fw4", &["reload"], 60, 64 * KIB).await {
        Ok(_) => Ok(()),
        Err(e) if e.starts_with("spawn fw4:") => {
            run_ok("fw3", &["reload"], 60, 64 * KIB).await.map(|_| ())
        }
        Err(e) => Err(e),
    }
}

pub async fn post_install(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: InstallReq = match super::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let _g = mutate_lock().await;
    let mut st = load_state();
    if let Some(m) = req.mtu {
        if !(1280..=1420).contains(&m) {
            return bad("MTU must be 1280-1420 (WireGuard over cellular: 1280 is the safe default)");
        }
        st.mtu = m;
    }
    if let Some(k) = req.keepalive {
        if !(10..=120).contains(&k) {
            return bad("Keepalive must be 10-120 seconds");
        }
        st.keepalive = k;
    }
    if let Some(e) = req.endpoint.as_deref() {
        let e = e.trim();
        if e.is_empty() {
            st.endpoint = None;
        } else if validate::endpoint(e).is_some() {
            st.endpoint = Some(e.to_string());
        } else {
            return bad("Endpoint must be host:port (for example engage.cloudflareclient.com:2408)");
        }
    }
    if let Some(a) = req.autostart {
        st.autostart = a;
    }
    if let Some(d) = req.lan_device.as_deref() {
        if !validate::is_ifname(d.trim()) {
            return bad("LAN device must be an interface name such as br-lan");
        }
        st.lan_dev = d.trim().to_string();
    }
    let profile = match build_profile(&st) {
        Ok(p) => p,
        Err(e) => return conflict(e),
    };
    if crate::admin::firewall::change_pending() {
        return conflict("A firewall change is waiting for confirmation in Admin › Firewall; confirm or revert it first");
    }
    let net_ops = match network_ops(&st, &profile) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    let net_snapshot = ucicfg::export("network").await.ok();
    if let Err(e) = ucicfg::apply("network", None, net_ops).await {
        return server(redact(&e, &[&profile.private_key]));
    }
    if let Err(e) = ucicfg::apply("firewall", None, firewall_ops()).await {
        if let Some(snap) = net_snapshot {
            let _ = ucicfg::restore_snapshot("network", &snap).await;
        }
        return server(e);
    }
    let mut errors = Vec::new();
    if let Err(e) = reload_network().await {
        errors.push(e);
    }
    if let Err(e) = reload_firewall().await {
        errors.push(e);
    }
    st.installed = true;
    if let Err(e) = save_state(&st) {
        return server(e);
    }
    if st.autostart {
        let _ = run("ifup", &[WG_IF], ExecOpts::new(20, 16 * KIB)).await;
    }
    audit(&ctx, format!("vpn: WARP interface installed (mtu {}, keepalive {}, autostart {})", st.mtu, st.keepalive, st.autostart));
    ok(serde_json::json!({ "status": "ok", "errors": errors }))
}

#[derive(Deserialize)]
pub struct ConnReq {
    action: String,
}

pub async fn post_connection(State(ctx): State<HttpCtx>, Json(req): Json<ConnReq>) -> Response {
    let prog = match req.action.as_str() {
        "up" => "ifup",
        "down" => "ifdown",
        _ => return bad("action must be up or down"),
    };
    let _g = mutate_lock().await;
    if !load_state().installed {
        return conflict("Install the WARP interface first");
    }
    let out = match run(prog, &[WG_IF], ExecOpts::new(20, 16 * KIB)).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    if !out.ok() {
        return server(out.err_summary(prog));
    }
    // Withdraw/restore the steering route right away instead of on the next tick.
    let _ = tick(now_secs()).await;
    audit(&ctx, format!("vpn: WARP interface {}", req.action));
    ok(serde_json::json!({ "status": "ok" }))
}

// ── routing policy ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReq {
    mode: Mode,
    #[serde(default)]
    confirm: Option<String>,
}

pub const LAN_WARNING: &str = "All LAN traffic forwarded by this modem (Route10's failover traffic) will exit through Cloudflare: \
higher latency, a Cloudflare egress IP instead of the carrier's (some sites and geolocation will differ), \
carrier CGNAT/QoS no longer applies to individual flows, and inbound port forwards stop working for that traffic. \
If the tunnel fails, traffic falls back to the normal cellular path within about 3 minutes.";

/// Exit node configured in Tailscale (uci mirror); WARP `lan` and a
/// Tailscale exit node both claim the default route.
async fn tailscale_exit_node() -> Option<String> {
    run_ok("uci", &["-q", "get", "tailscale.settings.exit_node"], 5, KIB)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn post_policy(State(ctx): State<HttpCtx>, Json(req): Json<PolicyReq>) -> Response {
    let _g = mutate_lock().await;
    let mut st = load_state();
    if req.mode != Mode::Off && !st.installed {
        return conflict("Install the WARP interface before steering traffic into it");
    }
    if req.mode == Mode::Lan {
        if let Err(r) = require_confirm(req.confirm.as_deref(), CONFIRM_LAN, LAN_WARNING) {
            return r;
        }
        if let Some(x) = tailscale_exit_node().await {
            return conflict(format!("Tailscale is using exit node {x}; clear it before routing LAN traffic through WARP"));
        }
    }
    let prev = st.policy;
    st.policy = req.mode;
    st.policy_changed_at = now_secs();
    if let Err(e) = save_state(&st) {
        return server(e);
    }
    let diff = match reconcile_rules(&st).await {
        Ok(d) => d,
        Err(e) => {
            // Roll the stored policy back and remove whatever was half-added.
            st.policy = prev;
            let _ = save_state(&st);
            let _ = reconcile_rules(&st).await;
            return server(format!("could not apply routing rules: {e}"));
        }
    };
    let action = tick(now_secs()).await;
    let fo = failover::is_active();
    emit(
        EventKind::Vpn,
        if req.mode == Mode::Lan || (fo && prev == Mode::Lan) { Severity::Warning } else { Severity::Info },
        format!("WARP routing: {} → {}", prev.as_str(), req.mode.as_str()),
        serde_json::json!({ "from": prev.as_str(), "to": req.mode.as_str(), "failoverActive": fo }),
    );
    audit(&ctx, format!("vpn: WARP routing {} -> {} (failover active: {fo})", prev.as_str(), req.mode.as_str()));
    let rt = super::runtime();
    ok(serde_json::json!({
        "status": "ok",
        "mode": req.mode,
        "rulesChanged": !diff.is_empty(),
        "routeAction": format!("{action:?}"),
        "usable": rt.usable,
        "failoverActive": fo,
        "warning": (fo && req.mode == Mode::Lan).then_some("Upstream failover is active right now; its traffic now exits through Cloudflare."),
    }))
}

// ── remove ──────────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveReq {
    #[serde(default)]
    confirm: Option<String>,
    #[serde(default)]
    delete_account: bool,
}

pub async fn post_remove(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: RemoveReq = match super::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    if let Err(r) = require_confirm(
        req.confirm.as_deref(),
        CONFIRM_REMOVE,
        "Removes the WARP interface, its firewall zone and the routing rules; traffic goes back to the plain cellular path.",
    ) {
        return r;
    }
    let _g = mutate_lock().await;
    if crate::admin::firewall::change_pending() {
        return conflict("A firewall change is waiting for confirmation in Admin › Firewall; confirm or revert it first");
    }
    let mut st = load_state();
    st.policy = Mode::Off;
    let _ = save_state(&st);
    let mut errors: Vec<String> = Vec::new();
    if let Err(e) = reconcile_rules(&st).await {
        errors.push(e);
    }
    let table = st.table.to_string();
    let _ = run("ip", &["-4", "route", "flush", "table", &table], ExecOpts::new(5, KIB)).await;
    let _ = run("ifdown", &[WG_IF], ExecOpts::new(20, 16 * KIB)).await;
    let del = |sec: &str| Op::Delete { section: sec.into(), option: None };
    if let Err(e) = ucicfg::apply("network", None, vec![del(WG_IF), del(WG_PEER)]).await {
        errors.push(e);
    }
    if let Err(e) = ucicfg::apply("firewall", None, vec![del(FW_ZONE), del(FW_FWD)]).await {
        errors.push(e);
    }
    let _ = reload_network().await;
    let _ = reload_firewall().await;
    st.installed = false;
    if req.delete_account {
        if let Some(d) = st.teams.as_ref()
            && !d.device_token.is_empty()
            && let Err(e) = curl_stdin(teams::delete_config(&d.device_id, &d.device_token), 30).await
        {
            errors.push(format!("Cloudflare unenroll: {}", redact(&e, &[&d.device_token])));
        }
        let _ = std::fs::remove_file(account_file());
        let _ = std::fs::remove_file(profile_file());
        st.kind = None;
        st.teams = None;
        st.teams_private_key.clear();
    }
    let _ = save_state(&st);
    let _ = tick(now_secs()).await;
    audit(&ctx, format!("vpn: WARP removed (account deleted: {})", req.delete_account));
    ok(serde_json::json!({ "status": "ok", "errors": errors }))
}

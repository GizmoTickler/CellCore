//! Tailscale manager for the `tailscale-tiny` package.
//!
//! Settings are mirrored in `/etc/config/tailscale` (`settings` section, the
//! schema luci-app-tailscale-community-tiny uses, so both UIs agree) and
//! applied live with `tailscale set`, which changes only the flags given.
//! tailscaled persists its prefs itself, so they survive a reboot either way.
//!
//! tailscale-tiny is built with many `ts_omit_*` tags. Before passing a flag
//! we check `tailscale set --help`; a missing flag is reported as unsupported
//! (HTTP 422) instead of failing silently. Known gaps of the tiny build:
//! no DNS (`--accept-dns` is forced off), no web client, no OAuth client
//! secrets as auth keys (`ts_omit_oauthkey`), no IPN bus (so `tailscale up`
//! returns at once and login is followed by polling `status`).

use std::sync::Mutex;

use axum::{Extension, Json, extract::State, http::StatusCode, response::Response};
use serde::Deserialize;

use super::{
    Mode, have,
    parse::{self, TsStatus},
    paths, validate, write_secret,
};
use crate::{
    admin::{
        audit, bad, conflict,
        exec::{ExecOpts, KIB, run, run_ok},
        fail, mutate_lock, ok, require_confirm, server,
        ucicfg::{self, Op, of_type},
    },
    http::{AuthCtx, HttpCtx},
    obs::failover,
    tokens::TokenKind,
};

pub const INIT: &str = "/etc/init.d/tailscale";
pub const CONFIRM_EXIT: &str = "USE EXIT NODE";
pub const CONFIRM_SHIELDS: &str = "SHIELDS UP";
pub const CONFIRM_LOGOUT: &str = "LOG OUT TAILSCALE";
pub const PACKAGES: &[&str] = &["tailscale-tiny", "tailscale"];

pub const EXIT_WARNING: &str = "Every connection this modem makes, and LAN traffic it forwards, will leave through another \
tailnet device: latency goes up, the public IP becomes that device's, and if that device or its uplink fails the \
traffic stops until the exit node is cleared. On a backup WAN that can take upstream failover down with it.";

static FLAGS: Mutex<Option<Vec<String>>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, Default)]
pub struct TailscalePulse {
    pub enabled: bool,
    pub running: bool,
    pub logged_in: bool,
}

static PULSE_CACHE: Mutex<TailscalePulse> = Mutex::new(TailscalePulse {
    enabled: false,
    running: false,
    logged_in: false,
});

pub fn cached_pulse() -> TailscalePulse {
    *crate::obs::lock(&PULSE_CACHE)
}

fn update_pulse_cache(enabled: bool, running: bool, logged_in: Option<bool>) {
    let mut g = crate::obs::lock(&PULSE_CACHE);
    g.enabled = enabled;
    g.running = running;
    if let Some(li) = logged_in {
        g.logged_in = li;
    } else if !running {
        g.logged_in = false;
    }
}

/// Flags `tailscale set` accepts on this build (cached for the daemon's life;
/// a package upgrade restarts nothing here, so the cache is dropped on install).
pub async fn set_flags() -> Vec<String> {
    if let Some(f) = crate::obs::lock(&FLAGS).clone() {
        return f;
    }
    let f = match run("tailscale", &["set", "--help"], ExecOpts::new(10, 64 * crate::admin::exec::KIB)).await {
        Ok(o) => parse::parse_help_flags(&o.log()),
        Err(_) => Vec::new(),
    };
    if !f.is_empty() {
        *crate::obs::lock(&FLAGS) = Some(f.clone());
    }
    f
}

pub fn forget_flags() {
    *crate::obs::lock(&FLAGS) = None;
}

async fn installed_package() -> Option<(String, String)> {
    for p in PACKAGES {
        if let Ok(out) = run_ok("opkg", &["list-installed", p], 10, 64 * KIB).await
            && let Some(v) = crate::ota::newest(&crate::ota::parse_opkg_versions(&out, p))
        {
            return Some((p.to_string(), v));
        }
    }
    None
}

async fn service_state() -> (bool, bool) {
    if !have(INIT) {
        return (false, false);
    }
    let running = run(INIT, &["status"], ExecOpts::new(5, KIB)).await.is_ok_and(|o| o.stdout_str().trim() == "running");
    let enabled = run(INIT, &["enabled"], ExecOpts::new(5, KIB)).await.is_ok_and(|o| o.ok());
    (running, enabled)
}

async fn ts_status() -> Result<TsStatus, String> {
    let t = run_ok("tailscale", &["status", "--json"], 8, 2 * crate::admin::exec::MIB).await?;
    parse::parse_ts_status(&t)
}

/// Desired settings as mirrored in uci.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub hostname: String,
    pub accept_routes: bool,
    pub advertise_routes: Vec<String>,
    pub advertise_exit_node: bool,
    pub exit_node: String,
    pub ssh: bool,
    pub shields_up: bool,
}

pub fn settings_from_uci(sections: &[ucicfg::UciSection]) -> Settings {
    let Some(s) = sections.iter().find(|s| s.id == "settings").or_else(|| of_type(sections, "settings").into_iter().next()) else {
        return Settings::default();
    };
    Settings {
        hostname: s.get_or("hostname", "").to_string(),
        accept_routes: s.flag("accept_routes", false),
        advertise_routes: s.list("advertise_routes"),
        advertise_exit_node: s.flag("advertise_exit_node", false),
        exit_node: s.get_or("exit_node", "").to_string(),
        ssh: s.flag("ssh", false),
        shields_up: s.flag("shields_up", false),
    }
}

async fn lan_cidr() -> Option<String> {
    let dev = super::load_state().lan_dev;
    let out = run_ok("ip", &["-4", "-o", "addr", "show", "dev", &dev], 5, 16 * KIB).await.ok()?;
    let (ip, p) = parse::parse_ip_addr_cidr(&out)?;
    Some(format!("{}/{p}", validate::network_of(ip, p)))
}

fn is_read_token(a: &Option<Extension<AuthCtx>>) -> bool {
    a.as_ref().and_then(|e| e.0.token.as_ref()).is_some_and(|t| t.kind == TokenKind::Read)
}

pub async fn get_tailscale(auth: Option<Extension<AuthCtx>>) -> Response {
    let pkg = installed_package().await;
    let (running, enabled) = service_state().await;
    let mut status = if running { ts_status().await.ok() } else { None };
    let logged_in = status
        .as_ref()
        .is_some_and(|s| s.backend_state == "Running");
    update_pulse_cache(enabled, running, Some(logged_in));
    if is_read_token(&auth)
        && let Some(s) = status.as_mut()
    {
        // A login link adopts this node into whoever opens it: not for monitoring tokens.
        s.auth_url = None;
    }
    let settings = ucicfg::show("tailscale").await.map(|s| settings_from_uci(&s)).unwrap_or_default();
    let flags = if have("tailscale") { set_flags().await } else { Vec::new() };
    let wanted = ["hostname", "accept-routes", "advertise-routes", "advertise-exit-node", "exit-node", "ssh", "shields-up"];
    let unsupported: Vec<&str> = if flags.is_empty() { Vec::new() } else { wanted.iter().copied().filter(|w| !flags.iter().any(|f| f == w)).collect() };
    let tiny = pkg.as_ref().is_some_and(|(p, _)| p == "tailscale-tiny");
    let mut warnings: Vec<String> = Vec::new();
    if !settings.exit_node.is_empty() || status.as_ref().is_some_and(|s| s.exit_node_in_use.is_some()) {
        warnings.push("An exit node is in use: this modem's traffic leaves through another tailnet device.".into());
    }
    if settings.advertise_exit_node {
        warnings.push("This modem offers itself as an exit node: tailnet devices that pick it use cellular data.".into());
    }
    if settings.shields_up {
        warnings.push("Shields up: nothing on the tailnet can connect to this modem (including Tailscale SSH).".into());
    }
    if failover::is_active() {
        warnings.push("Upstream failover is active on this modem right now.".into());
    }
    ok(serde_json::json!({
        "package": pkg.as_ref().map(|(p, v)| serde_json::json!({ "name": p, "version": v })),
        "installed": pkg.is_some() || have("tailscale"),
        "service": { "running": running, "enabledAtBoot": enabled },
        "status": status,
        "settings": settings,
        "capabilities": {
            "flags": flags,
            "unsupported": unsupported,
            "tiny": tiny,
            "oauthKeys": !tiny,
            "dns": !tiny,
        },
        "lanCidr": lan_cidr().await,
        "warnings": warnings,
        "warpLanActive": super::current_mode() == Mode::Lan,
        "job": super::pkg::job_json(),
    }))
}

#[derive(Deserialize)]
pub struct ServiceReq {
    action: String,
}

pub async fn post_service(State(ctx): State<HttpCtx>, Json(req): Json<ServiceReq>) -> Response {
    if !matches!(req.action.as_str(), "start" | "stop" | "restart" | "enable" | "disable") {
        return bad("action must be start, stop, restart, enable or disable");
    }
    if !have(INIT) {
        return conflict("Tailscale is not installed");
    }
    let _g = mutate_lock().await;
    let out = match run(INIT, &[req.action.as_str()], ExecOpts::new(30, 16 * KIB)).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    // `enabled`-style init actions return non-zero on some builds even when they worked;
    // procd also stops/starts daemons asynchronously on SIGTERM, so wait briefly for
    // `start`/`stop`/`restart` to settle before declaring failure.
    let action = req.action.as_str();
    let max_polls = if matches!(action, "start" | "stop" | "restart") { 30 } else { 1 };
    let mut running = false;
    let mut enabled = false;
    let mut ok_now = false;
    for attempt in 0..max_polls {
        (running, enabled) = service_state().await;
        ok_now = match action {
            "start" | "restart" => running,
            "stop" => !running,
            "enable" => enabled,
            _ => !enabled,
        };
        if ok_now || attempt + 1 == max_polls {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    audit(&ctx, format!("vpn: tailscale service {} (running={running}, enabled={enabled})", req.action));
    update_pulse_cache(enabled, running, None);
    if !ok_now {
        return server(format!("tailscale {} did not take effect: {}", req.action, out.err_summary(INIT)));
    }
    ok(serde_json::json!({ "status": "ok", "running": running, "enabledAtBoot": enabled }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginReq {
    #[serde(default)]
    auth_key: Option<String>,
}

/// `tailscale set` argv for the given settings fields (only those present).
pub fn set_argv(s: &Settings, fields: &[&str]) -> Vec<String> {
    let mut a = vec!["set".to_string()];
    for f in fields {
        match *f {
            "hostname" if !s.hostname.is_empty() => a.push(format!("--hostname={}", s.hostname)),
            "accept-routes" => a.push(format!("--accept-routes={}", s.accept_routes)),
            "advertise-routes" => a.push(format!("--advertise-routes={}", s.advertise_routes.join(","))),
            "advertise-exit-node" => a.push(format!("--advertise-exit-node={}", s.advertise_exit_node)),
            "exit-node" => {
                a.push(format!("--exit-node={}", s.exit_node));
                if !s.exit_node.is_empty() {
                    // Keep the modem's LAN (Route10, the UI) reachable while an exit node is used.
                    a.push("--exit-node-allow-lan-access=true".into());
                }
            }
            "ssh" => a.push(format!("--ssh={}", s.ssh)),
            "shields-up" => a.push(format!("--shields-up={}", s.shields_up)),
            _ => {}
        }
    }
    a
}

pub const ALL_FIELDS: &[&str] = &["hostname", "accept-routes", "advertise-routes", "advertise-exit-node", "exit-node", "ssh", "shields-up"];

async fn apply_live(s: &Settings, fields: &[&str]) -> Result<(), String> {
    let argv = set_argv(s, fields);
    if argv.len() <= 1 {
        return Ok(());
    }
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_ok("tailscale", &a, 20, 64 * KIB).await.map(|_| ())
}

pub async fn post_login(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: LoginReq = match super::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let key = req.auth_key.as_deref().map(str::trim).filter(|k| !k.is_empty()).map(str::to_string);
    let tiny = installed_package().await.is_some_and(|(p, _)| p == "tailscale-tiny");
    if let Some(k) = key.as_deref() {
        if validate::is_ts_oauth_secret(k) && tiny {
            return fail(StatusCode::UNPROCESSABLE_ENTITY, "tailscale-tiny is built without OAuth client support; create a pre-auth key (tskey-auth-…) instead");
        }
        if !validate::is_ts_authkey(k) {
            return bad("An auth key starts with tskey- (create one in the Tailscale admin console › Settings › Keys)");
        }
    }
    let _g = mutate_lock().await;
    let (running, _) = service_state().await;
    if !running {
        if !have(INIT) {
            return conflict("Install Tailscale first");
        }
        let _ = run(INIT, &["start"], ExecOpts::new(30, 16 * KIB)).await;
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
    let keyfile = paths().run.join("ts-authkey");
    let mut args: Vec<String> = vec!["up".into(), "--reset".into()];
    if let Some(k) = key.as_deref() {
        if let Err(e) = write_secret(&keyfile, k.as_bytes()) {
            return server(e);
        }
        // `file:` keeps the key out of argv (and so out of ps / logs).
        args.push(format!("--auth-key=file:{}", keyfile.display()));
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run("tailscale", &a, ExecOpts::new(45, 64 * KIB)).await;
    let _ = std::fs::remove_file(&keyfile);
    let out = match out {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    let secrets: Vec<&str> = key.iter().map(String::as_str).collect();
    // `--reset` cleared prefs: put the mirrored settings back.
    let settings = ucicfg::show("tailscale").await.map(|s| settings_from_uci(&s)).unwrap_or_default();
    let flags = set_flags().await;
    let fields: Vec<&str> = ALL_FIELDS.iter().copied().filter(|f| flags.is_empty() || flags.iter().any(|x| x == f)).collect();
    let reapply = apply_live(&settings, &fields).await.err();
    // The tiny build has no IPN bus: `up` returns immediately. Poll briefly.
    let mut st = None;
    for _ in 0..10 {
        if let Ok(s) = ts_status().await {
            let done = s.backend_state == "Running" || s.auth_url.is_some();
            st = Some(s);
            if done {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    }
    audit(&ctx, format!("vpn: tailscale login ({})", if key.is_some() { "auth key" } else { "interactive" }));
    let Some(st) = st else {
        return fail(StatusCode::BAD_GATEWAY, super::redact(&out.err_summary("tailscale up"), &secrets));
    };
    if !out.ok() && st.backend_state != "Running" && st.auth_url.is_none() {
        return fail(StatusCode::BAD_GATEWAY, super::redact(&out.err_summary("tailscale up"), &secrets));
    }
    {
        let mut g = crate::obs::lock(&PULSE_CACHE);
        g.running = true;
        g.logged_in = st.backend_state == "Running";
    }
    ok(serde_json::json!({
        "status": "ok",
        "backendState": st.backend_state,
        "authUrl": st.auth_url,
        "settingsReapplied": reapply.is_none(),
        "reapplyError": reapply,
    }))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfirmReq {
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_logout(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: ConfirmReq = match super::parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    if let Err(r) = require_confirm(
        req.confirm.as_deref(),
        CONFIRM_LOGOUT,
        "Logs this modem out of the tailnet: remote access over Tailscale stops until it is approved again.",
    ) {
        return r;
    }
    let _g = mutate_lock().await;
    match run_ok("tailscale", &["logout"], 30, 16 * KIB).await {
        Ok(_) => {
            crate::obs::lock(&PULSE_CACHE).logged_in = false;
            audit(&ctx, "vpn: tailscale logged out");
            ok(serde_json::json!({ "status": "ok" }))
        }
        Err(e) => server(e),
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsReq {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    accept_routes: Option<bool>,
    #[serde(default)]
    advertise_routes: Option<Vec<String>>,
    #[serde(default)]
    advertise_exit_node: Option<bool>,
    #[serde(default)]
    exit_node: Option<String>,
    #[serde(default)]
    ssh: Option<bool>,
    #[serde(default)]
    shields_up: Option<bool>,
    #[serde(default)]
    confirm: Option<String>,
    /// Consumed by the failover guard.
    #[serde(default)]
    #[allow(dead_code)]
    force: Option<bool>,
}

/// Validate and merge a settings request. Returns the new settings and the
/// `tailscale set` flags it touches.
#[allow(clippy::result_large_err)]
pub fn merge_settings(cur: &Settings, req: &SettingsReq) -> Result<(Settings, Vec<&'static str>), String> {
    let mut s = cur.clone();
    let mut fields = Vec::new();
    if let Some(h) = req.hostname.as_deref() {
        let h = h.trim();
        if !h.is_empty() && !validate::is_ts_hostname(h) {
            return Err("Hostname: one label of letters, digits and '-' (no dots)".into());
        }
        s.hostname = h.to_string();
        fields.push("hostname");
    }
    if let Some(v) = req.accept_routes {
        s.accept_routes = v;
        fields.push("accept-routes");
    }
    if let Some(r) = req.advertise_routes.as_ref() {
        if r.len() > 16 {
            return Err("At most 16 subnet routes".into());
        }
        let mut out: Vec<String> = Vec::new();
        for c in r {
            let c = validate::canonical_v4_cidr(c)?;
            if !out.contains(&c) {
                out.push(c);
            }
        }
        s.advertise_routes = out;
        fields.push("advertise-routes");
    }
    if let Some(v) = req.advertise_exit_node {
        s.advertise_exit_node = v;
        fields.push("advertise-exit-node");
    }
    if let Some(x) = req.exit_node.as_deref() {
        let x = x.trim();
        if !x.is_empty() && !validate::is_exit_node(x) {
            return Err("Exit node: a tailnet IP or device name".into());
        }
        s.exit_node = x.to_string();
        fields.push("exit-node");
    }
    if let Some(v) = req.ssh {
        s.ssh = v;
        fields.push("ssh");
    }
    if let Some(v) = req.shields_up {
        s.shields_up = v;
        fields.push("shields-up");
    }
    if !s.exit_node.is_empty() && s.advertise_exit_node {
        return Err("A node cannot use an exit node and offer itself as one at the same time".into());
    }
    Ok((s, fields))
}

pub fn uci_ops(s: &Settings) -> Vec<Op> {
    let b = |v: bool| if v { "1" } else { "0" };
    vec![
        Op::Section { section: "settings".into(), stype: "settings".into() },
        Op::set_or_clear("settings", "hostname", &s.hostname),
        Op::set("settings", "accept_routes", b(s.accept_routes)),
        Op::SetList { section: "settings".into(), option: "advertise_routes".into(), values: s.advertise_routes.clone() },
        Op::set("settings", "advertise_exit_node", b(s.advertise_exit_node)),
        Op::set_or_clear("settings", "exit_node", &s.exit_node),
        Op::set("settings", "ssh", b(s.ssh)),
        Op::set("settings", "shields_up", b(s.shields_up)),
    ]
}

pub async fn post_settings(State(ctx): State<HttpCtx>, Json(req): Json<SettingsReq>) -> Response {
    let _g = mutate_lock().await;
    let sections = ucicfg::show("tailscale").await.unwrap_or_default();
    let cur = settings_from_uci(&sections);
    let (new, fields) = match merge_settings(&cur, &req) {
        Ok(x) => x,
        Err(e) => return bad(e),
    };
    if fields.is_empty() {
        return bad("Nothing to change");
    }
    if new.exit_node != cur.exit_node && !new.exit_node.is_empty() {
        if super::current_mode() == Mode::Lan {
            return conflict("WARP is routing LAN traffic; set WARP routing to modem-only or off before using a Tailscale exit node");
        }
        if let Err(r) = require_confirm(req.confirm.as_deref(), CONFIRM_EXIT, EXIT_WARNING) {
            return r;
        }
    }
    if new.shields_up && !cur.shields_up
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            CONFIRM_SHIELDS,
            "Shields up blocks every incoming tailnet connection to this modem, including Tailscale SSH and the web UI over the tailnet.",
        )
    {
        return r;
    }
    let running = service_state().await.0;
    if running {
        let flags = set_flags().await;
        if !flags.is_empty() {
            let missing: Vec<&str> = fields.iter().copied().filter(|f| !flags.iter().any(|x| x == f)).collect();
            if !missing.is_empty() {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("This Tailscale build does not support: {}", missing.iter().map(|m| format!("--{m}")).collect::<Vec<_>>().join(", ")),
                );
            }
        }
    }
    let snapshot = ucicfg::export("tailscale").await.ok();
    if let Err(e) = ucicfg::apply("tailscale", None, uci_ops(&new)).await {
        return server(e);
    }
    if running && let Err(e) = apply_live(&new, &fields).await {
        if let Some(snap) = snapshot {
            let _ = ucicfg::restore_snapshot("tailscale", &snap).await;
        }
        return fail(StatusCode::BAD_GATEWAY, format!("tailscale refused the change (nothing saved): {e}"));
    }
    audit(&ctx, format!("vpn: tailscale settings changed: {}", fields.join(",")));
    if fields.contains(&"exit-node") {
        crate::obs::emit(
            crate::obs::EventKind::Vpn,
            crate::obs::Severity::Warning,
            if new.exit_node.is_empty() { "Tailscale exit node cleared".to_string() } else { format!("Tailscale exit node set: {}", new.exit_node) },
            serde_json::json!({ "exitNode": new.exit_node, "failoverActive": failover::is_active() }),
        );
    }
    ok(serde_json::json!({ "status": "ok", "settings": new, "applied": running }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(j: &str) -> SettingsReq {
        serde_json::from_str(j).unwrap()
    }

    #[test]
    fn merges_and_validates_settings() {
        let cur = Settings::default();
        let (s, f) = merge_settings(&cur, &req(r#"{"advertiseRoutes":["192.168.224.0/22","192.168.224.0/22"],"acceptRoutes":true}"#)).unwrap();
        assert_eq!(s.advertise_routes, vec!["192.168.224.0/22"]);
        assert!(s.accept_routes);
        assert_eq!(f, vec!["accept-routes", "advertise-routes"]);
        assert!(merge_settings(&cur, &req(r#"{"advertiseRoutes":["192.168.224.1/22"]}"#)).unwrap_err().contains("192.168.224.0/22"));
        assert!(merge_settings(&cur, &req(r#"{"hostname":"a.b"}"#)).is_err());
        assert!(merge_settings(&cur, &req(r#"{"exitNode":"--ssh"}"#)).is_err());
        assert!(merge_settings(&cur, &req(r#"{"exitNode":"nas01","advertiseExitNode":true}"#)).is_err());
        let (s, _) = merge_settings(&cur, &req(r#"{"hostname":" mgateway1 "}"#)).unwrap();
        assert_eq!(s.hostname, "mgateway1");
        assert!(serde_json::from_str::<SettingsReq>(r#"{"bogus":1}"#).is_err(), "unknown fields refused");
    }

    #[test]
    fn set_argv_only_touches_given_fields() {
        let s = Settings { exit_node: "100.64.0.7".into(), advertise_routes: vec!["192.168.224.0/22".into()], ..Default::default() };
        assert_eq!(set_argv(&s, &["exit-node"]), vec!["set", "--exit-node=100.64.0.7", "--exit-node-allow-lan-access=true"]);
        assert_eq!(set_argv(&s, &["advertise-routes", "ssh"]), vec!["set", "--advertise-routes=192.168.224.0/22", "--ssh=false"]);
        let cleared = Settings::default();
        assert_eq!(set_argv(&cleared, &["exit-node", "advertise-routes"]), vec!["set", "--exit-node=", "--advertise-routes="]);
        assert_eq!(set_argv(&cleared, &["hostname"]), vec!["set"], "empty hostname is left alone");
    }

    #[test]
    fn uci_settings_round_trip() {
        let text = "tailscale.settings=settings\ntailscale.settings.accept_routes='1'\ntailscale.settings.advertise_routes='192.168.224.0/22' '10.9.0.0/16'\ntailscale.settings.exit_node='nas01'\ntailscale.settings.ssh='1'\n";
        let s = settings_from_uci(&ucicfg::parse_uci_show("tailscale", text));
        assert!(s.accept_routes && s.ssh && !s.shields_up);
        assert_eq!(s.advertise_routes, vec!["192.168.224.0/22", "10.9.0.0/16"]);
        assert_eq!(s.exit_node, "nas01");
        assert_eq!(settings_from_uci(&[]), Settings::default());
    }
}

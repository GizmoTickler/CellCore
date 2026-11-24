use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    auth::{
        MAX_PASSWORD_LEN, SESSION_MAX_AGE_SECS, VerifyError, now_secs, update_shadow_password,
        verify_shadow_password,
    },
    http::{HttpCtx, extract_session_token},
    parsers::{
        MpdnRule, QmapLanIpInfo, is_valid_mac, parse_mbn_list, parse_mpdn_rules, parse_neighbor_cells,
        parse_qmap_lan_ip, parse_qnw_band_list, parse_qscan_entries, parse_reg_state,
        parse_scalar_at_value, validate_imei_luhn,
    },
    profiles::{ProfileInput, delete_profile as remove_profile, toggle_profile_pause, upsert_profile_noting},
    reconcile::{run_boot_reconcile, set_usb_gadget_enabled},
    smd::Priority,
    sms::{encode_submit_pdus, parse_cmgl_response},
    speedtest::{SPEEDTEST_HISTORY_PATH, start_speedtest, stop_speedtest},
    state::{
        AppState, ETC_QM_DIR, format_now_hms, redact_sensitive, save_json_atomic_async,
        save_json_compact_atomic_async, save_json_compact_tmpfs_async,
    },
    telemetry::{
        DATA_USAGE_PATH, DATA_USAGE_TMP_PATH, icmp_ping_once, refresh_modem_snapshot,
    },
    uci::{
        detect_wan_rmnet_ifaces_blocking, ensure_uci_config_file, is_valid_uci_ident, run_cmd,
        uci_add_section, uci_commit, uci_get, uci_set, uci_show,
    },
};

const SETTINGS_JSON_PATH: &str = "/etc/cellcore/settings.json";
const TAILSCALE_INIT: &str = "/etc/init.d/tailscale";

fn err_resp(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "status": "error", "error": msg.into() })),
    )
        .into_response()
}

pub async fn get_auth_status(State(ctx): State<HttpCtx>, headers: HeaderMap) -> Response {
    let Some(tok) = extract_session_token(&headers) else {
        return Json(serde_json::json!({ "authenticated": false, "state": "invalid" })).into_response();
    };
    if let Some(sess) = ctx.app.auth.validate_token(&tok, false).await {
        Json(serde_json::json!({
            "authenticated": true,
            "state": "valid",
            "csrfToken": sess.csrf_token,
            "version": ctx.app.version,
        }))
        .into_response()
    } else {
        Json(serde_json::json!({ "authenticated": false, "state": "invalid" })).into_response()
    }
}

#[derive(Deserialize)]
pub struct LoginReq {
    password: String,
}

pub async fn post_login(
    State(ctx): State<HttpCtx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginReq>,
) -> Response {
    let ip: IpAddr = peer.ip();
    match check_root_password(&ctx, ip, &body.password).await {
        Ok(()) => {}
        Err(resp) => return resp,
    }

    ctx.app.auth.clear_failures(ip).await;
    match ctx.app.auth.create_session().await {
        Ok(sess) => {
            let cookie = format!(
                "qm_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}; Secure",
                sess.token, SESSION_MAX_AGE_SECS
            );
            let mut resp = Json(serde_json::json!({
                "status": "success",
                "token": sess.token,
                "csrfToken": sess.csrf_token,
                "version": ctx.app.version,
            }))
            .into_response();
            if let Ok(hv) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(header::SET_COOKIE, hv);
            }
            resp
        }
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Throttled, length-capped, concurrency-bounded root password check shared
/// by login, IMEI edit and password change. The attempt is counted *before*
/// hashing; success clears the per-IP counter.
#[allow(clippy::result_large_err)]
async fn check_root_password(ctx: &HttpCtx, ip: IpAddr, password: &str) -> Result<(), Response> {
    if !ctx.app.auth.begin_attempt(ip).await {
        return Err(err_resp(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts. Retry in 60s.",
        ));
    }
    match ctx
        .app
        .auth
        .verify_password_bounded(password, |pw| verify_shadow_password(&pw, "root"))
        .await
    {
        Ok(true) => {
            ctx.app.auth.clear_failures(ip).await;
            Ok(())
        }
        Ok(false) | Err(VerifyError::TooLong) => {
            Err(err_resp(StatusCode::UNAUTHORIZED, "Invalid administrator password"))
        }
        Err(VerifyError::Busy) => Err(err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "Password verification busy, retry shortly",
        )),
    }
}

pub async fn post_logout(State(ctx): State<HttpCtx>, headers: HeaderMap) -> Response {
    if let Some(tok) = extract_session_token(&headers) {
        ctx.app.auth.revoke_session(&tok).await;
    }
    let mut resp = Json(serde_json::json!({ "status": "success" })).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("qm_session=deleted; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure"),
    );
    resp
}

pub async fn get_public_preview(State(ctx): State<HttpCtx>) -> Response {
    let m = ctx.app.modem.read().await;
    let total_mhz: f64 = m.carriers.iter().filter_map(|c| c.bandwidth_mhz).sum();
    Json(serde_json::json!({
        "version": ctx.app.version,
        "model": if m.identity.model.is_empty() { "RM551E-GL" } else { &m.identity.model },
        "operator": if m.operator.is_empty() { "Cellular WAN" } else { &m.operator },
        "rat": m.mimo.rat,
        "carriers": m.carriers,
        "carrierCount": m.carriers.len(),
        "totalBandwidthMhz": total_mhz,
        "mimo": m.mimo,
    }))
    .into_response()
}

pub async fn get_overview_pulse(State(ctx): State<HttpCtx>) -> Response {
    let (lw_enabled, cl_active, cl_pci, cl_earfcn) = {
        let s = ctx.app.settings.read().await;
        let active = !s.cell_lock_nr5g.is_empty() || !s.cell_lock_lte.is_empty();
        let (nr, lte) = crate::telemetry::target_cell_lock_params(&s);
        let chosen = nr.or(lte);
        let pci = chosen.and_then(|(p, _)| u32::try_from(p).ok());
        let earfcn = chosen.and_then(|(_, a)| a.and_then(|v| u32::try_from(v).ok()));
        (s.quecwatch_enabled, active, pci, earfcn)
    };
    let (lw_state, lw_retry) = {
        let qw = ctx.app.quecwatch.read().await;
        let st = if !lw_enabled && qw.status.is_empty() {
            "disabled".to_string()
        } else {
            qw.status.clone()
        };
        (st, qw.retry)
    };
    let cl_bypassed = ctx
        .app
        .cell_lock_bypassed
        .load(std::sync::atomic::Ordering::Acquire);
    let cl_bypass_reason = crate::state::CellLockBypassReason::from_u8(
        ctx.app
            .cell_lock_bypass_reason
            .load(std::sync::atomic::Ordering::Acquire),
    )
    .as_str();
    let (dsp_throttling, dsp_sar_state) = {
        let d = ctx.app.dsp_telemetry.read().await;
        (d.any_throttling, d.sar_rf_state.unwrap_or(0))
    };
    let warp_mode = crate::vpn::current_mode().as_str();
    let warp_usable = crate::vpn::runtime().usable;
    let ts = crate::vpn::cached_tailscale_pulse();
    let (cf_enabled, cf_running, cf_ha_connections) = {
        let i = ctx.app.internals.read().await;
        (
            i.cloudflared_present,
            i.cloudflared_running,
            u32::try_from(i.cloudflared_ha_connections).unwrap_or(u32::MAX),
        )
    };

    Json(serde_json::json!({
        "linkWatch": {
            "enabled": lw_enabled,
            "state": lw_state,
            "retry": lw_retry,
        },
        "cellLock": {
            "active": cl_active,
            "bypassed": cl_bypassed,
            "bypassReason": cl_bypass_reason,
            "pci": cl_pci,
            "earfcn": cl_earfcn,
        },
        "dsp": {
            "tmdThrottling": dsp_throttling,
            "sarState": dsp_sar_state,
        },
        "warp": {
            "mode": warp_mode,
            "usable": warp_usable,
        },
        "tailscale": {
            "enabled": ts.enabled,
            "running": ts.running,
            "loggedIn": ts.logged_in,
        },
        "cloudflared": {
            "enabled": cf_enabled,
            "running": cf_running,
            "haConnections": cf_ha_connections,
        },
    }))
    .into_response()
}

pub async fn get_bootstrap(State(ctx): State<HttpCtx>) -> Response {
    let modem = ctx.app.modem.read().await.clone();
    let rsrp_hist: Vec<_> = ctx.app.rsrp_hist.read().await.iter().cloned().collect();
    let sinr_hist: Vec<_> = ctx.app.sinr_hist.read().await.iter().cloned().collect();
    let rsrq_hist: Vec<_> = ctx.app.rsrq_hist.read().await.iter().cloned().collect();
    let tr = ctx.app.traffic.read().await;
    let traffic_json = serde_json::json!({
        "primaryIface": tr.primary_iface,
        "lanIface": tr.lan_iface,
        "interfaces": tr.interfaces,
        "history": tr.history.iter().cloned().collect::<Vec<_>>(),
    });
    drop(tr);
    let data_usage = ctx.app.data_usage.read().await.clone();
    let ping_realtime: Vec<_> = ctx.app.ping_realtime.read().await.iter().cloned().collect();
    let memory = ctx.app.memory.read().await.clone();
    let device_uptime = ctx.app.device_uptime.read().await.clone();
    let session_uptime = ctx.app.session_uptime.read().await.clone();
    let internals = ctx.app.internals.read().await.clone();
    let speedtest_live = ctx.app.speedtest_live.read().await.clone();
    let speedtest_history = ctx.app.speedtest_history.read().await.clone();
    let settings = ctx.app.settings.read().await.clone();
    let antenna_align = ctx.app.antenna_align.read().await.clone();
    let alerts: Vec<_> = ctx.app.alerts.read().await.iter().cloned().collect();

    Json(serde_json::json!({
        "version": ctx.app.version,
        "modem": modem,
        "signalHistory": {
            "rsrp": rsrp_hist,
            "sinr": sinr_hist,
        },
        "rsrqHistory": rsrq_hist,
        "traffic": traffic_json,
        "dataUsage": data_usage,
        "pingHistory": ping_realtime,
        "memory": memory,
        "deviceUptime": device_uptime,
        "sessionUptime": session_uptime,
        "internals": internals,
        "speedtest": speedtest_live,
        "speedtestHistory": speedtest_history,
        "settings": settings,
        "antennaAlign": antenna_align,
        "alerts": alerts,
    }))
    .into_response()
}

pub async fn post_modem_refresh(State(ctx): State<HttpCtx>) -> Response {
    refresh_modem_snapshot(&ctx.app, Priority::Interactive, false).await;
    Json(serde_json::json!({ "status": "success", "modem": *ctx.app.modem.read().await })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtExecReq {
    command: String,
    timeout_secs: Option<u64>,
    /// Required (`true`) for commands the AT guard classifies as dangerous.
    #[serde(default)]
    confirm: bool,
}

/// Maximum timeout (seconds) for standard raw AT console commands.
pub const MAX_CONSOLE_AT_TIMEOUT_SECS: u64 = 30;
/// Maximum timeout (seconds) for confirmed long-blocking RF scan commands (`AT+COPS=?`, `AT+QSCAN`).
pub const MAX_CONSOLE_SCAN_TIMEOUT_SECS: u64 = 60;

pub async fn post_modem_at(
    State(ctx): State<HttpCtx>,
    who: Option<axum::Extension<crate::http::AuthCtx>>,
    Json(body): Json<AtExecReq>,
) -> Response {
    let verdict = match crate::atguard::classify(&body.command) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
    };
    // The raw command never reaches the audit log: names, form and class only.
    let note = crate::audit::AuditNote(crate::atguard::audit_summary(&verdict));
    if verdict.class == crate::atguard::AtClass::Blocked {
        let mut resp = err_resp(
            StatusCode::FORBIDDEN,
            format!("Blocked AT command: {}", verdict.reason),
        );
        resp.extensions_mut().insert(note);
        return resp;
    }
    let is_scan = crate::atguard::is_long_blocking_scan(&verdict);
    if verdict.class == crate::atguard::AtClass::Dangerous || is_scan {
        // Any authenticated caller that reached this POST (sessions and rw
        // tokens; read tokens never get here) may confirm.
        let may_operate = who.is_some();
        if !body.confirm || !may_operate {
            let label = if verdict.class == crate::atguard::AtClass::Dangerous {
                "Dangerous AT command"
            } else {
                "Long-blocking scan AT command"
            };
            let mut resp = (
                StatusCode::PRECONDITION_REQUIRED,
                Json(serde_json::json!({
                    "status": "error",
                    "error": format!("{label}: {}. Resend with confirm=true to run it.", verdict.reason),
                    "classification": verdict,
                })),
            )
                .into_response();
            resp.extensions_mut().insert(note);
            return resp;
        }
    }
    let (default_secs, max_secs) = if is_scan {
        (30, MAX_CONSOLE_SCAN_TIMEOUT_SECS)
    } else {
        (12, MAX_CONSOLE_AT_TIMEOUT_SECS)
    };
    let dur = Duration::from_secs(body.timeout_secs.unwrap_or(default_secs).clamp(1, max_secs));
    let _console_guard = ctx.app.begin_console_at(dur);
    let deadline = tokio::time::Instant::now() + dur;
    // The console may change the mode behind the band-lock checks' back
    // (before: a band write reading the cache meanwhile; after: one that
    // noted the mode while this command was queued).
    // A console write of the radio configuration waits for (and holds off)
    // the radio endpoints' read-plan-write, bounded by the caller's deadline.
    let _radio = if crate::radio::is_radio_write(&body.command) {
        match tokio::time::timeout_at(deadline, crate::radio::lock(&ctx.app)).await {
            Ok(guard) => Some(guard),
            Err(_) => {
                let mut resp = err_resp(
                    StatusCode::BAD_GATEWAY,
                    format!("AT command timed out ({}): radio busy", body.command),
                );
                resp.extensions_mut().insert(note);
                return resp;
            }
        }
    } else {
        None
    };
    let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
    note_raw_at_command(&ctx.app, &body.command);
    // timeoutSecs is the caller's whole budget, time spent queued included.
    let mut exec = ctx.app.smd.exec_within(&body.command, Priority::Interactive, rem).await;
    if let Err(ref e) = exec
        && e.starts_with(crate::smd::NOT_SENT)
    {
        let rem_retry = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !rem_retry.is_zero() {
            exec = ctx.app.smd.exec_within(&body.command, Priority::Interactive, rem_retry).await;
        }
    }
    note_raw_at_command(&ctx.app, &body.command);
    let mut resp = match exec {
        Ok(res) => Json(serde_json::json!({
            "command": res.command,
            "response": res.body,
            "status": if res.ok { "success" } else { "error" },
            "latencyMs": res.latency_ms,
            "classification": verdict,
        }))
        .into_response(),
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, e),
    };
    resp.extensions_mut().insert(note);
    resp
}

pub async fn get_modem_secrets(State(ctx): State<HttpCtx>) -> Response {
    let sec = ctx.app.secrets.read().await.clone();
    Json(serde_json::json!({
        "imei": sec.imei,
        "iccid": sec.iccid,
        "imsi": sec.imsi,
        "previousImei": sec.previous_imei,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditImeiReq {
    imei: String,
    password: String,
    #[serde(default)]
    apply_now: bool,
}

pub async fn post_modem_imei(
    State(ctx): State<HttpCtx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<EditImeiReq>,
) -> Response {
    let imei = body.imei.trim().to_string();
    if !validate_imei_luhn(&imei) {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "IMEI must be 15 digits passing Luhn checksum validation",
        );
    }
    match check_root_password(&ctx, peer.ip(), &body.password).await {
        Ok(()) => {}
        Err(resp) if resp.status() == StatusCode::UNAUTHORIZED => {
            return err_resp(StatusCode::FORBIDDEN, "Administrator password verification failed");
        }
        Err(resp) => return resp,
    }

    let current_imei = ctx.app.secrets.read().await.imei.clone();
    if !current_imei.is_empty() && validate_imei_luhn(&current_imei) && current_imei != imei {
        ensure_uci_config_file("cellcore").await;
        let _ = uci_set("cellcore.imei", "imei").await;
        let _ = uci_set("cellcore.imei.previous", &current_imei).await;
        let _ = uci_commit("cellcore").await;
        ctx.app.secrets.write().await.previous_imei = Some(current_imei);
    }

    let at_cmd = format!("AT+EGMR=1,7,\"{imei}\"");
    match ctx.app.smd.exec(at_cmd, Priority::Interactive, Duration::from_secs(8)).await {
        Ok(res) if res.ok => {
            ctx.app.push_daemon_log("IMEI updated via authenticated session [REDACTED]");
            ctx.app.secrets.write().await.imei = imei;
            if body.apply_now {
                // a radio power cycle: not in the middle of a radio change
                let _radio = crate::radio::lock(&ctx.app).await;
                let _ = ctx.app.smd.exec("AT+CFUN=0", Priority::Interactive, Duration::from_secs(10)).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = ctx.app.smd.exec("AT+CFUN=1", Priority::Interactive, Duration::from_secs(12)).await;
            }
            refresh_modem_snapshot(&ctx.app, Priority::Interactive, false).await;
            Json(serde_json::json!({
                "status": "success",
                "message": if body.apply_now { "IMEI updated and radio restarted" } else { "IMEI written to modem NVRAM" },
            }))
            .into_response()
        }
        Ok(res) => err_resp(StatusCode::BAD_REQUEST, format!("Modem rejected IMEI change: {}", res.body)),
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, e),
    }
}

pub async fn get_profiles(State(ctx): State<HttpCtx>) -> Response {
    // Legacy stored values (TTL "064", band 0) come back normalised, with a warning each.
    let (profiles, warnings) = crate::profiles::list_profiles_noting().await;
    let mbn_raw = ctx
        .app
        .smd
        .exec("AT+QMBNCFG=\"List\"", Priority::Interactive, Duration::from_secs(5))
        .await
        .map(|r| r.body)
        .unwrap_or_default();
    let autosel_raw = ctx
        .app
        .smd
        .exec("AT+QMBNCFG=\"AutoSel\"", Priority::Interactive, Duration::from_secs(4))
        .await
        .map(|r| r.body)
        .unwrap_or_default();
    let apn_raw = ctx
        .app
        .smd
        .exec("AT+CGDCONT?", Priority::Interactive, Duration::from_secs(4))
        .await
        .map(|r| r.body)
        .unwrap_or_default();
    let mbn_profiles = parse_mbn_list(&mbn_raw);
    let mbn_auto_sel = parse_scalar_at_value(&autosel_raw, "+QMBNCFG:")
        .split(',')
        .next_back()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    Json(serde_json::json!({
        "status": "success",
        "profiles": profiles,
        "warnings": warnings,
        "mbnProfiles": mbn_profiles,
        "mbnAutoSel": mbn_auto_sel,
        "apnRaw": apn_raw,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileMutateReq {
    pub index: Option<usize>,
    #[serde(flatten)]
    pub profile: ProfileInput,
}

fn profile_err(e: crate::profiles::ProfileError) -> Response {
    match e {
        crate::profiles::ProfileError::NotFound(_) => err_resp(StatusCode::NOT_FOUND, e.to_string()),
        crate::profiles::ProfileError::Invalid(m) => err_resp(StatusCode::BAD_REQUEST, m),
        crate::profiles::ProfileError::Tool(m) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, m),
    }
}

pub async fn post_profile(State(ctx): State<HttpCtx>, Json(body): Json<ProfileMutateReq>) -> Response {
    // Band lists are checked against what the modem reports (3GPP when unknown).
    let reported = reported_bands(&ctx.app);
    match upsert_profile_noting(body.index, body.profile, &reported, crate::profiles::ProfileOrigin::Api).await {
        Ok(warnings) => Json(serde_json::json!({ "status": "success", "warnings": warnings })).into_response(),
        Err(e) => profile_err(e),
    }
}

#[derive(Deserialize)]
pub struct IndexQuery {
    index: usize,
}

pub async fn delete_profile(Query(q): Query<IndexQuery>) -> Response {
    match remove_profile(q.index).await {
        Ok(()) => Json(serde_json::json!({ "status": "success" })).into_response(),
        Err(e) => profile_err(e),
    }
}

#[derive(Deserialize)]
pub struct PauseProfileReq {
    index: usize,
    paused: bool,
}

pub async fn post_profile_pause(Json(body): Json<PauseProfileReq>) -> Response {
    match toggle_profile_pause(body.index, body.paused).await {
        Ok(()) => Json(serde_json::json!({ "status": "success" })).into_response(),
        Err(e @ crate::profiles::ProfileError::Tool(_)) => profile_err(e),
        // A missing profile is a bad request here (the index comes from the body).
        Err(e) => err_resp(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbnActionReq {
    action: String,
    profile_name: Option<String>,
    enabled: Option<bool>,
}

pub async fn post_mbn(State(ctx): State<HttpCtx>, Json(body): Json<MbnActionReq>) -> Response {
    let cmd = match body.action.as_str() {
        "autosel" => format!("AT+QMBNCFG=\"AutoSel\",{}", if body.enabled.unwrap_or(false) { 1 } else { 0 }),
        "select" => {
            let Some(name) = body.profile_name.filter(|s| !s.is_empty() && !s.contains('"')) else {
                return err_resp(StatusCode::BAD_REQUEST, "Invalid MBN profile name");
            };
            format!("AT+QMBNCFG=\"Select\",\"{name}\"")
        }
        "deactivate" => "AT+QMBNCFG=\"Deactivate\"".to_string(),
        _ => return err_resp(StatusCode::BAD_REQUEST, "Unsupported MBN action"),
    };
    match ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(8)).await {
        Ok(r) if r.ok => Json(serde_json::json!({ "status": "success", "response": r.body })).into_response(),
        Ok(r) => err_resp(StatusCode::BAD_REQUEST, r.body),
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, e),
    }
}

pub async fn get_bands(State(ctx): State<HttpCtx>) -> Response {
    let cmds = vec![
        ("AT+QNWPREFCFG=\"policy_band\"".into(), Duration::from_secs(4)),
        ("AT+QNWPREFCFG=\"lte_band\"".into(), Duration::from_secs(4)),
        ("AT+QNWPREFCFG=\"nsa_nr5g_band\"".into(), Duration::from_secs(4)),
        ("AT+QNWPREFCFG=\"nr5g_band\"".into(), Duration::from_secs(4)),
    ];
    let Ok(res) = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await else {
        return err_resp(StatusCode::BAD_GATEWAY, "AT queue error");
    };
    let s = |i: usize| res.get(i).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
    if res.first().is_some_and(|r| r.as_ref().is_ok_and(|r| r.ok)) && s(0).contains("+QNWPREFCFG") {
        // The supported set: the policy report plus what is configured right now.
        let reported = [s(0), s(1), s(2), s(3)].join("\n");
        radio_cache(&ctx.app, |c| c.policy_band = Some(reported));
    }
    Json(serde_json::json!({
        "lteBands": parse_qnw_band_list(s(1), "lte_band"),
        "nsaNr5gBands": parse_qnw_band_list(s(2), "nsa_nr5g_band"),
        "nr5gBands": parse_qnw_band_list(s(3), "nr5g_band"),
        "policyRaw": s(0),
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BandLockReq {
    lte_bands: Vec<String>,
    nsa_nr5g_bands: Vec<String>,
    nr5g_bands: Vec<String>,
    /// Optional network mode applied together with the bands (checked as one
    /// change, written after the bands).
    #[serde(default)]
    mode_pref: Option<String>,
    #[serde(default)]
    nr5g_disable_mode: Option<i32>,
}

/// A band-lock RAT. NSA NR rides on an LTE anchor; SA NR stands alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandRat {
    Lte,
    NsaNr5g,
    SaNr5g,
}

impl BandRat {
    pub fn key(self) -> &'static str {
        match self {
            BandRat::Lte => "lte_band",
            BandRat::NsaNr5g => "nsa_nr5g_band",
            BandRat::SaNr5g => "nr5g_band",
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            BandRat::Lte => "LTE",
            BandRat::NsaNr5g => "NR5G-NSA",
            BandRat::SaNr5g => "NR5G-SA",
        }
    }
}

/// 3GPP band numbers, used when the modem does not report its own list
/// (E-UTRA bands 1..108 per TS 36.101; NR FR1 n1..n113 and FR2 n257..n263 per TS 38.101).
pub fn is_known_band(rat: BandRat, n: u16) -> bool {
    match rat {
        BandRat::Lte => (1..=108).contains(&n),
        BandRat::NsaNr5g | BandRat::SaNr5g => (1..=113).contains(&n) || (257..=263).contains(&n),
    }
}

/// The RATs the modem may use under `mode_pref` / `nr5g_disable_mode`
/// (0 = none disabled, 1 = SA disabled, 2 = NSA disabled). `mode_pref` is any
/// value [`crate::radio::mode_rats`] understands (AUTO, LTE, NR5G and their
/// ':' combinations); NSA needs both LTE (anchor) and NR. An unknown mode
/// counts every RAT as active (strictest).
pub fn active_band_rats(mode_pref: &str, nr5g_disable: i32) -> Vec<BandRat> {
    let sa = nr5g_disable != 1;
    let nsa = nr5g_disable != 2;
    let (lte, nr) = crate::radio::mode_rats(mode_pref).unwrap_or((true, true));
    let mut v = Vec::new();
    if lte {
        v.push(BandRat::Lte);
    }
    if lte && nr && nsa {
        v.push(BandRat::NsaNr5g);
    }
    if nr && sa {
        v.push(BandRat::SaNr5g);
    }
    v
}

/// Validate one requested band list: digits only, a band the modem reports
/// (or, without a modem list, a 3GPP band), deduplicated, in request order.
pub fn clean_band_list(rat: BandRat, arr: &[String], supported: Option<&[String]>) -> Result<Vec<String>, String> {
    if arr.len() > 128 {
        return Err(format!("Too many {} bands", rat.label()));
    }
    let mut clean: Vec<String> = Vec::new();
    for b in arr {
        let t = b.trim();
        if t.is_empty() || t.len() > 3 || !t.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!("Invalid band ID: {t}"));
        }
        let n: u16 = t.parse().map_err(|_| format!("Invalid band ID: {t}"))?;
        let canon = n.to_string();
        let known = match supported {
            Some(list) if !list.is_empty() => list.iter().any(|s| s == &canon),
            _ => is_known_band(rat, n),
        };
        if !known {
            return Err(format!("{} band {canon} is not supported by this modem", rat.label()));
        }
        if !clean.contains(&canon) {
            clean.push(canon);
        }
    }
    Ok(clean)
}

/// Refuse a radio configuration the modem could not use. The invariant: the
/// mode allows at least one RAT (`NR5G` with SA disabled allows none), and no
/// RAT the mode allows is left without a band (writing `0` there takes that
/// RAT, and possibly the whole WAN, off the air). Together they guarantee at
/// least one usable RAT that has at least one band.
pub fn check_bands_cover_mode(
    lte: &[String],
    nsa: &[String],
    sa: &[String],
    mode_pref: &str,
    nr5g_disable: i32,
) -> Result<(), String> {
    let active = active_band_rats(mode_pref, nr5g_disable);
    let mode = mode_pref.trim().to_ascii_uppercase();
    if active.is_empty() {
        let off = match nr5g_disable {
            1 => "5G SA",
            2 => "5G NSA",
            _ => "every RAT it uses",
        };
        return Err(format!(
            "Network mode {mode} with {off} disabled leaves the modem no network it can use. Enable {off} or choose another network mode"
        ));
    }
    let empty: Vec<&str> = active
        .into_iter()
        .filter(|r| match r {
            BandRat::Lte => lte.is_empty(),
            BandRat::NsaNr5g => nsa.is_empty(),
            BandRat::SaNr5g => sa.is_empty(),
        })
        .map(BandRat::label)
        .collect();
    if empty.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Select at least one band for {} (network mode {mode}): an empty list would leave the modem without a usable band",
            empty.join(", "),
        ))
    }
}

/// What the band-lock checks know about the modem: the supported-band report
/// (`policy_band`) and the last mode read or written. Kept per daemon
/// (AppState). The mode is only a fallback for when the modem cannot be read
/// before a write; it is dropped whenever anything else may have changed it.
#[derive(Debug, Default)]
pub struct RadioCache {
    policy_band: Option<String>,
    mode: Option<(String, i32)>,
}

fn radio_cache<R>(app: &AppState, f: impl FnOnce(&mut RadioCache) -> R) -> R {
    let mut g = app.radio.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g)
}

/// Forget the cached mode (e.g. after a raw AT command may have changed it).
pub fn forget_radio_mode(app: &AppState) {
    radio_cache(app, |c| c.mode = None);
}

/// Called for every raw AT command (HTTP console, IPC: cellctl, menu,
/// r10-modem-ctl): anything that writes radio configuration or resets the
/// modem may change the mode.
pub fn note_raw_at_command(app: &AppState, command: &str) {
    if crate::radio::is_radio_write(command) {
        forget_radio_mode(app);
    }
}

/// The supported-band report learnt from the last GET /cellular/bands.
pub fn reported_bands(app: &AppState) -> String {
    radio_cache(app, |c| c.policy_band.clone()).unwrap_or_default()
}

/// Unknown: AUTO with nothing disabled, which requires every RAT to keep a band.
fn cached_mode(app: &AppState) -> (String, i32) {
    radio_cache(app, |c| c.mode.clone()).unwrap_or_else(|| ("AUTO".into(), 0))
}

fn note_mode(app: &AppState, mode: String, disable: i32) {
    radio_cache(app, |c| c.mode = Some((mode, disable)));
}

pub(crate) fn parse_mode_pref(body: &str) -> Option<String> {
    body.lines()
        .find(|l| l.contains("mode_pref"))
        .and_then(|l| l.split(',').nth(1))
        .map(|s| s.trim().trim_matches('"').to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

pub(crate) fn parse_nr5g_disable(body: &str) -> Option<i32> {
    body.lines()
        .find(|l| l.contains("nr5g_disable_mode"))
        .and_then(|l| l.split(',').nth(1))
        .and_then(|s| s.trim().parse::<i32>().ok())
}

/// First failed band command, if any (transport error or modem ERROR).
pub fn band_batch_failure(results: &[Result<crate::smd::AtResponse, String>]) -> Option<String> {
    results.iter().find_map(|r| match r {
        Err(e) => Some(format!("Band lock failed: {e}")),
        Ok(res) if !res.ok => Some(format!("Modem rejected {}: {}", res.command, res.body)),
        Ok(_) => None,
    })
}

/// The band lists and network mode, as one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioConfig {
    pub lte: Vec<String>,
    pub nsa: Vec<String>,
    pub sa: Vec<String>,
    pub mode: String,
    pub disable: i32,
}

impl RadioConfig {
    fn list_mut(&mut self, rat: BandRat) -> &mut Vec<String> {
        match rat {
            BandRat::Lte => &mut self.lte,
            BandRat::NsaNr5g => &mut self.nsa,
            BandRat::SaNr5g => &mut self.sa,
        }
    }

    pub fn check(&self) -> Result<(), String> {
        check_bands_cover_mode(&self.lte, &self.nsa, &self.sa, &self.mode, self.disable)
    }

    /// The same configuration on the modem: band lists as sets, mode_pref
    /// value ignoring case.
    pub fn same(&self, other: &RadioConfig) -> bool {
        use crate::radio::same_list;
        same_list(&self.lte, &other.lte)
            && same_list(&self.nsa, &other.nsa)
            && same_list(&self.sa, &other.sa)
            && self.mode.eq_ignore_ascii_case(&other.mode)
            && self.disable == other.disable
    }

    /// As reported in a failure response (`finalState`).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "lteBands": self.lte,
            "nsaNr5gBands": self.nsa,
            "nr5gBands": self.sa,
            "modePref": self.mode,
            "nr5gDisableMode": self.disable,
        })
    }

    /// One line for messages and logs.
    pub fn describe(&self) -> String {
        let l = |v: &[String]| if v.is_empty() { "none".to_string() } else { v.join(":") };
        format!(
            "LTE {}, NR5G-NSA {}, NR5G-SA {}, mode_pref {}, nr5g_disable_mode {}",
            l(&self.lte),
            l(&self.nsa),
            l(&self.sa),
            self.mode,
            self.disable
        )
    }

    pub(crate) fn apply(&mut self, step: &RadioStep) {
        match step {
            RadioStep::Bands(rat, list) => *self.list_mut(*rat) = list.clone(),
            RadioStep::Mode(m) => self.mode = m.clone(),
            RadioStep::Disable(d) => self.disable = *d,
        }
    }
}

const BAND_RATS: [BandRat; 3] = [BandRat::Lte, BandRat::NsaNr5g, BandRat::SaNr5g];

/// One QNWPREFCFG write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioStep {
    Bands(BandRat, Vec<String>),
    Mode(String),
    Disable(i32),
}

impl RadioStep {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            RadioStep::Bands(rat, _) => rat.key(),
            RadioStep::Mode(_) => "mode_pref",
            RadioStep::Disable(_) => "nr5g_disable_mode",
        }
    }

    pub(crate) fn command(&self) -> String {
        match self {
            RadioStep::Bands(rat, list) => {
                let v = if list.is_empty() { "0".to_string() } else { list.join(":") };
                format!("AT+QNWPREFCFG=\"{}\",{v}", rat.key())
            }
            RadioStep::Mode(m) => format!("AT+QNWPREFCFG=\"mode_pref\",{m}"),
            RadioStep::Disable(d) => format!("AT+QNWPREFCFG=\"nr5g_disable_mode\",{d}"),
        }
    }
}

/// Order the writes of a radio change so that, starting from `cur` (or the
/// strictest assumption when `None`), every intermediate state keeps the
/// invariant ([`RadioConfig::check`]): first the non-empty band lists (they
/// never take a band away from a RAT that has one), then the mode (`mode_pref` /
/// `nr5g_disable_mode` in whichever order keeps the state in between valid),
/// and only then the lists that become empty. When `cur` is `Some`, no-op
/// steps that leave `state` unchanged (`next.same(&state)`) are dropped.
pub fn plan_radio_steps_from(
    cur: Option<&RadioConfig>,
    bands: Option<&[Vec<String>; 3]>,
    mode: Option<&str>,
    disable: Option<i32>,
) -> Vec<RadioStep> {
    let mut steps: Vec<RadioStep> = Vec::new();
    if let Some(lists) = bands {
        for (rat, list) in BAND_RATS.iter().zip(lists) {
            if !list.is_empty() {
                steps.push(RadioStep::Bands(*rat, list.clone()));
            }
        }
    }
    let mut widened = cur.cloned().unwrap_or_else(|| RadioConfig {
        lte: Vec::new(),
        nsa: Vec::new(),
        sa: Vec::new(),
        mode: "AUTO".to_string(),
        disable: 0,
    });
    for s in &steps {
        widened.apply(s);
    }
    let mut mode_steps: Vec<RadioStep> = mode.map(|m| RadioStep::Mode(m.to_string())).into_iter().collect();
    mode_steps.extend(disable.map(RadioStep::Disable));
    if mode_steps.len() == 2 {
        let midway_ok = |first: &RadioStep| {
            let mut s = widened.clone();
            s.apply(first);
            s.check().is_ok()
        };
        if !midway_ok(&mode_steps[0]) && midway_ok(&mode_steps[1]) {
            mode_steps.swap(0, 1);
        }
    }
    steps.extend(mode_steps);
    if let Some(lists) = bands {
        for (rat, list) in BAND_RATS.iter().zip(lists) {
            if list.is_empty() {
                steps.push(RadioStep::Bands(*rat, Vec::new()));
            }
        }
    }
    let Some(known_cur) = cur else {
        return steps;
    };
    let mut state = known_cur.clone();
    let mut out = Vec::with_capacity(steps.len());
    for step in steps {
        let mut next = state.clone();
        next.apply(&step);
        if !next.same(&state) {
            out.push(step);
            state = next;
        }
    }
    out
}

pub fn plan_radio_steps(cur: &RadioConfig, bands: Option<&[Vec<String>; 3]>, mode: Option<&str>, disable: Option<i32>) -> Vec<RadioStep> {
    plan_radio_steps_from(Some(cur), bands, mode, disable)
}

/// Read the band lists and the mode from the modem. The bool is false when
/// the `mode_pref` value is not one [`crate::radio::mode_rats`] understands;
/// `mode` preserves `raw_mode` so a request setting `modePref` repairs it
/// instead of looking like a no-op (while `RadioConfig::check` treats unknown
/// modes under the strictest assumption). Err: a key could not be read at all.
/// An understood mode is remembered.
pub(crate) async fn read_radio_fields(app: &AppState) -> Result<(RadioConfig, bool), String> {
    let keys = ["lte_band", "nsa_nr5g_band", "nr5g_band", "mode_pref", "nr5g_disable_mode"];
    let cmds = keys.iter().map(|k| (format!("AT+QNWPREFCFG=\"{k}\""), Duration::from_secs(4))).collect();
    let res = app.smd.exec_batch(cmds, Priority::Interactive).await?;
    let mut bodies = Vec::new();
    for (k, r) in keys.iter().zip(&res) {
        match r {
            Ok(r) if r.ok => bodies.push(r.body.clone()),
            Ok(r) => return Err(format!("{k}: {}", r.body.trim())),
            Err(e) => return Err(format!("{k}: {e}")),
        }
    }
    if bodies.len() != keys.len() {
        return Err("incomplete reply".into());
    }
    let raw_mode = parse_mode_pref(&bodies[3]).ok_or("unreadable mode_pref")?;
    let disable = parse_nr5g_disable(&bodies[4]).ok_or("unreadable nr5g_disable_mode")?;
    let known = crate::radio::mode_rats(&raw_mode).is_some();
    if known {
        note_mode(app, raw_mode.clone(), disable);
    }
    let cfg = RadioConfig {
        lte: parse_qnw_band_list(&bodies[0], "lte_band"),
        nsa: parse_qnw_band_list(&bodies[1], "nsa_nr5g_band"),
        sa: parse_qnw_band_list(&bodies[2], "nr5g_band"),
        mode: raw_mode,
        disable,
    };
    Ok((cfg, known))
}

/// Error response for a radio change that stopped at a failed write: 422 when
/// the modem answered ERROR, 502 when the command did not complete. It says
/// what was applied, whether the failed write itself landed, and what the
/// daemon then found on the modem and did about it (`rollback`).
fn radio_write_failure(what: &str, f: &crate::radio::Failure) -> Response {
    use crate::radio::Outcome;
    let status = if matches!(f.outcome, Outcome::Refused(_)) { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::BAD_GATEWAY };
    let detail = match &f.outcome {
        Outcome::Refused(body) => {
            let res = crate::smd::AtResponse { command: f.failed_cmd.clone(), raw: body.clone(), body: body.clone(), ok: false, latency_ms: 0 };
            band_batch_failure(&[Ok(res)]).unwrap_or_default()
        }
        Outcome::Lost(e) | Outcome::NotSent(e) => format!("{} not confirmed by the modem: {e}", f.failed),
        Outcome::Ok => format!("{} failed", f.failed),
    };
    let rb = &f.rollback;
    let state = match &rb.final_state {
        Some(s) if rb.safe => format!("the modem now holds {}", s.describe()),
        Some(s) => format!("the modem now holds {}, which leaves it without a usable band", s.describe()),
        None => "the radio configuration could not be read back, so the modem may be left partially changed".to_string(),
    };
    let partial = if !f.partial() {
        "nothing was changed".to_string()
    } else {
        let mut parts = Vec::new();
        if !f.applied.is_empty() {
            parts.push(format!("already applied: {}", f.applied.join(", ")));
        }
        match f.failed_write_applied {
            Some(true) => parts.push(match f.outcome {
                Outcome::Refused(_) => format!("{} was applied even though the modem returned an error", f.failed),
                _ => format!("{} was applied although its reply was lost", f.failed),
            }),
            None => parts.push(format!("{} may have been applied", f.failed)),
            Some(false) => {}
        }
        if !rb.restored.is_empty() {
            parts.push(format!("rolled back: {}", rb.restored.join(", ")));
        }
        if !rb.failed.is_empty() {
            parts.push(format!("rollback failed for {}", rb.failed.join(", ")));
        }
        if !rb.not_restorable.is_empty() {
            parts.push(format!("previous value unknown, not restored: {}", rb.not_restorable.join(", ")));
        }
        parts.push(if rb.ok { "everything is back as it was".to_string() } else { state.clone() });
        parts.join("; ")
    };
    (
        status,
        Json(serde_json::json!({
            "status": "error",
            "error": format!("{what}: {} ({partial})", detail.trim()),
            "failed": f.failed,
            "applied": f.applied,
            "notApplied": f.not_applied,
            "partial": f.partial(),
            "failedWriteApplied": f.failed_write_applied,
            "rollback": {
                "attempted": f.partial(),
                "ok": rb.ok,
                "safe": rb.safe,
                "restored": rb.restored,
                "failed": rb.failed,
                "notRestorable": rb.not_restorable,
                "finalState": rb.final_state.as_ref().map(RadioConfig::to_json),
            },
        })),
    )
        .into_response()
}

/// Run a planned change (see [`crate::radio::run_change`]); a failure is
/// logged and turned into the error response.
async fn run_radio_change(
    ctx: &HttpCtx,
    what: &str,
    pre: Option<&RadioConfig>,
    target: Option<&RadioConfig>,
    writes: Vec<crate::radio::PlannedWrite>,
) -> Result<Vec<String>, Box<Response>> {
    let io = crate::radio::SmdRadio { app: &ctx.app };
    crate::radio::run_change(&io, pre, target, writes).await.map_err(|f| {
        if f.partial() {
            let end = match &f.rollback.final_state {
                Some(s) => s.describe(),
                None => "unreadable".into(),
            };
            ctx.app.push_daemon_log(format!(
                "{what}: {} failed after {} write(s); rollback ok={} safe={}; radio now {end}",
                f.failed,
                f.applied.len(),
                f.rollback.ok,
                f.rollback.safe
            ));
        }
        Box::new(radio_write_failure(what, &f))
    })
}

/// Bands the modem reports for a RAT family: every `+QNWPREFCFG` line it
/// answered for that family (policy_band and the current lists). The modem
/// files some NSA bands only under nr5g_band/nrdc_nr5g_band, so NR bands are
/// pooled across the NR keys. Empty when nothing is known (3GPP fallback).
pub fn modem_band_set(reported: &str, rat: BandRat) -> Vec<String> {
    let keys: &[&str] = match rat {
        BandRat::Lte => &["lte_band"],
        BandRat::NsaNr5g | BandRat::SaNr5g => &["nsa_nr5g_band", "nr5g_band", "nrdc_nr5g_band"],
    };
    let mut out: Vec<String> = Vec::new();
    for line in reported.lines() {
        for k in keys {
            for b in parse_qnw_band_list(line, k) {
                if !out.contains(&b) {
                    out.push(b);
                }
            }
        }
    }
    out
}

/// A network mode the API accepts as input.
fn valid_mode_pref(m: &str) -> Option<String> {
    let up = m.trim().to_ascii_uppercase();
    matches!(up.as_str(), "AUTO" | "NR5G" | "LTE" | "LTE:NR5G").then_some(up)
}

/// Current radio configuration for a write, read fresh from the modem.
/// Returns `(real_cur, rollback_pre, fallback)`:
/// - `real_cur` is `Some` whenever `read_radio_fields` succeeded (even if
///   `mode_pref` is unknown), and `None` on read error so no-op skipping and
///   `known_different` are disabled;
/// - `rollback_pre` is `Some` only when the mode was also understood;
/// - `fallback` provides `(mode, disable)` when the request omits them.
async fn radio_before_write(ctx: &HttpCtx) -> (Option<RadioConfig>, Option<RadioConfig>, (String, i32)) {
    match read_radio_fields(&ctx.app).await {
        Ok((c, true)) => {
            let fb = (c.mode.clone(), c.disable);
            (Some(c.clone()), Some(c), fb)
        }
        Ok((c, false)) => {
            let fb = (c.mode.clone(), c.disable);
            (Some(c), None, fb)
        }
        Err(_) => (None, None, cached_mode(&ctx.app)),
    }
}

pub async fn post_bands(State(ctx): State<HttpCtx>, Json(body): Json<BandLockReq>) -> Response {
    // Everything is validated before the first write. Bands and mode are one
    // radio change: the result must satisfy the invariant, and so must every
    // state the modem passes through on the way (see plan_radio_steps).
    let mode = match body.mode_pref.as_deref().map(|m| (m, valid_mode_pref(m))) {
        Some((_, Some(m))) => Some(m),
        Some((_, None)) => return err_resp(StatusCode::BAD_REQUEST, "Invalid mode preference (AUTO, LTE, NR5G or LTE:NR5G)"),
        None => None,
    };
    if let Some(d) = body.nr5g_disable_mode
        && !(0..=2).contains(&d)
    {
        return err_resp(StatusCode::BAD_REQUEST, "Invalid nr5g_disable_mode (0, 1 or 2)");
    }
    let reported = reported_bands(&ctx.app);
    let (sup_lte, sup_nsa, sup_sa) = (
        modem_band_set(&reported, BandRat::Lte),
        modem_band_set(&reported, BandRat::NsaNr5g),
        modem_band_set(&reported, BandRat::SaNr5g),
    );
    let lists = match (
        clean_band_list(BandRat::Lte, &body.lte_bands, Some(&sup_lte)),
        clean_band_list(BandRat::NsaNr5g, &body.nsa_nr5g_bands, Some(&sup_nsa)),
        clean_band_list(BandRat::SaNr5g, &body.nr5g_bands, Some(&sup_sa)),
    ) {
        (Ok(a), Ok(b), Ok(c)) => [a, b, c],
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return err_resp(StatusCode::BAD_REQUEST, e),
    };
    // One radio change at a time, from the read to the last write (and repair).
    let _radio = crate::radio::lock(&ctx.app).await;
    let (cur, pre, (fb_mode, fb_disable)) = radio_before_write(&ctx).await;
    let target = RadioConfig {
        lte: lists[0].clone(),
        nsa: lists[1].clone(),
        sa: lists[2].clone(),
        mode: mode.clone().unwrap_or(fb_mode),
        disable: body.nr5g_disable_mode.unwrap_or(fb_disable),
    };
    if let Err(e) = target.check() {
        return err_resp(StatusCode::BAD_REQUEST, e);
    }
    let known_different = cur.is_some();
    let steps = plan_radio_steps_from(cur.as_ref(), Some(&lists), mode.as_deref(), body.nr5g_disable_mode);
    let writes = steps.into_iter().map(|s| crate::radio::PlannedWrite::radio(s, known_different)).collect();
    match run_radio_change(&ctx, "Band lock", pre.as_ref(), Some(&target), writes).await {
        Ok(applied) => {
            if pre.is_some() || mode.is_some() {
                note_mode(&ctx.app, target.mode, target.disable);
            } else {
                forget_radio_mode(&ctx.app);
            }
            Json(serde_json::json!({ "status": "success", "applied": applied })).into_response()
        }
        Err(resp) => {
            forget_radio_mode(&ctx.app);
            *resp
        }
    }
}

pub async fn get_mode(State(ctx): State<HttpCtx>) -> Response {
    let cmds = vec![
        ("AT+QNWPREFCFG=\"mode_pref\"".into(), Duration::from_secs(4)),
        ("AT+QNWPREFCFG=\"nr5g_disable_mode\"".into(), Duration::from_secs(4)),
        ("AT+QUIMSLOT?".into(), Duration::from_secs(4)),
        ("AT+CGDCONT?".into(), Duration::from_secs(4)),
    ];
    let Ok(res) = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await else {
        return err_resp(StatusCode::BAD_GATEWAY, "AT queue error");
    };
    let b = |i: usize| res.get(i).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
    let mode_pref = b(0)
        .lines()
        .find_map(|l| l.split(',').nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "AUTO".into());
    let nr5g_disable = b(1)
        .lines()
        .find_map(|l| l.split(',').nth(1))
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);
    let cached_slot = ctx.app.modem.read().await.identity.sim_slot;
    let sim_slot = crate::telemetry::parse_quimslot_reply(b(2))
        .unwrap_or(if (1..=2).contains(&cached_slot) { cached_slot } else { 1 });
    let ok = |i: usize| res.get(i).is_some_and(|r| r.as_ref().is_ok_and(|r| r.ok));
    match (ok(0).then(|| parse_mode_pref(b(0))).flatten(), ok(1).then(|| parse_nr5g_disable(b(1))).flatten()) {
        (Some(m), Some(d)) => note_mode(&ctx.app, m, d),
        _ => forget_radio_mode(&ctx.app),
    }

    Json(serde_json::json!({
        "modePref": mode_pref,
        "nr5gDisableMode": nr5g_disable,
        "simSlot": sim_slot,
        "apnRaw": b(3),
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeMutateReq {
    mode_pref: Option<String>,
    nr5g_disable_mode: Option<i32>,
    sim_slot: Option<i32>,
    apn: Option<String>,
    pdp_type: Option<String>,
}

pub async fn post_mode(State(ctx): State<HttpCtx>, Json(body): Json<ModeMutateReq>) -> Response {
    // Validate the whole request first: nothing is written unless every field is valid.
    let mode = match body.mode_pref.as_deref().map(|m| m.trim().to_ascii_uppercase()) {
        Some(up) if !matches!(up.as_str(), "AUTO" | "NR5G" | "LTE" | "LTE:NR5G") => {
            return err_resp(StatusCode::BAD_REQUEST, "Invalid mode preference (AUTO, LTE, NR5G or LTE:NR5G)");
        }
        m => m,
    };
    if let Some(d) = body.nr5g_disable_mode
        && !(0..=2).contains(&d)
    {
        return err_resp(StatusCode::BAD_REQUEST, "Invalid nr5g_disable_mode (0, 1 or 2)");
    }
    if let Some(slot) = body.sim_slot
        && !(1..=2).contains(&slot)
    {
        return err_resp(StatusCode::BAD_REQUEST, "SIM slot must be 1 or 2");
    }
    if body.pdp_type.is_some() && body.apn.is_none() {
        return err_resp(StatusCode::BAD_REQUEST, "pdpType is only accepted together with apn");
    }
    let apn = match body.apn.as_deref() {
        Some(apn) => {
            let clean = match crate::profiles::validate_apn(apn) {
                Ok(a) => a,
                Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
            };
            let pdp = match crate::profiles::validate_pdp_type(body.pdp_type.as_deref().unwrap_or("IPV4V6")) {
                Ok(p) => p,
                Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
            };
            Some((pdp, clean))
        }
        None => None,
    };
    // A mode change is checked against the bands on the modem right now (read
    // fresh: the mode may have been changed from the console or over IPC),
    // and must leave the modem a RAT it can use.
    let mode_change = mode.is_some() || body.nr5g_disable_mode.is_some();
    let mut writes: Vec<crate::radio::PlannedWrite> = Vec::new();
    let mut target: Option<RadioConfig> = None;
    let mut pre: Option<RadioConfig> = None;
    // One radio change at a time, from the read to the last write (and repair).
    let _radio = crate::radio::lock(&ctx.app).await;
    if mode_change {
        let cur = match read_radio_fields(&ctx.app).await {
            Ok((c, true)) => {
                pre = Some(c.clone());
                c
            }
            // A mode_pref value this daemon does not understand: a request
            // that names the new mode can still be checked (against the
            // bands, read fine) on the strictest assumption; one that only
            // changes nr5g_disable_mode cannot.
            Ok((c, false)) if mode.is_some() => c,
            Ok((_, false)) => {
                return err_resp(
                    StatusCode::BAD_GATEWAY,
                    "Could not check the new mode: the modem reports a network mode this daemon does not understand. Set the network mode as well",
                );
            }
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Could not read the band configuration to check the new mode: {e}")),
        };
        let next = RadioConfig {
            mode: mode.clone().unwrap_or_else(|| cur.mode.clone()),
            disable: body.nr5g_disable_mode.unwrap_or(cur.disable),
            ..cur.clone()
        };
        if let Err(e) = next.check() {
            let msg = if active_band_rats(&next.mode, next.disable).is_empty() { e } else { format!("{e}. Change the band lock first.") };
            return err_resp(StatusCode::CONFLICT, msg);
        }
        let steps = plan_radio_steps(&cur, None, mode.as_deref(), body.nr5g_disable_mode);
        writes.extend(steps.into_iter().map(|s| crate::radio::PlannedWrite::radio(s, true)));
        target = Some(next);
    }
    // Previous SIM slot / APN, so a failure later in the sequence can put them back.
    let mut reads: Vec<(String, Duration)> = Vec::new();
    if body.sim_slot.is_some() {
        reads.push(("AT+QUIMSLOT?".into(), Duration::from_secs(4)));
    }
    if apn.is_some() {
        reads.push(("AT+CGDCONT?".into(), Duration::from_secs(4)));
    }
    let prev = if reads.is_empty() { Vec::new() } else { ctx.app.smd.exec_batch(reads, Priority::Interactive).await.unwrap_or_default() };
    let prev_body = |prefix: &str| {
        prev.iter().find_map(|r| r.as_ref().ok().filter(|r| r.ok && r.body.contains(prefix)).map(|r| r.body.clone()))
    };
    if let Some(slot) = body.sim_slot {
        let prev_slot = prev_body("+QUIMSLOT:")
            .and_then(|b| parse_scalar_at_value(&b, "+QUIMSLOT:").trim().parse::<i32>().ok())
            .filter(|s| (1..=2).contains(s));
        if prev_slot != Some(slot) {
            let undo = prev_slot.map(|s| format!("AT+QUIMSLOT={s}"));
            writes.push(crate::radio::PlannedWrite::sim_slot(slot, undo, prev_slot.is_some(), Duration::from_secs(8)));
        }
    }
    if let Some((pdp, clean)) = apn {
        let prev_cgd = prev_body("+CGDCONT:")
            .and_then(|b| crate::profiles::parse_cgdcont(&b, 1))
            .and_then(|(p, a)| Some((crate::profiles::validate_pdp_type(&p).ok()?, crate::profiles::validate_apn(&a).ok()?)));
        let same = prev_cgd
            .as_ref()
            .is_some_and(|(p, a)| p.eq_ignore_ascii_case(&pdp) && a.eq_ignore_ascii_case(&clean));
        if !same {
            let undo = prev_cgd.as_ref().map(|(p, a)| format!("AT+CGDCONT=1,\"{p}\",\"{a}\""));
            writes.push(crate::radio::PlannedWrite::apn(pdp, clean, undo, prev_cgd.is_some(), Duration::from_secs(6)));
        }
    }
    let result = run_radio_change(&ctx, "Network settings", pre.as_ref(), target.as_ref(), writes).await;
    match (&result, target) {
        (Ok(_), Some(t)) => note_mode(&ctx.app, t.mode, t.disable),
        (Err(_), Some(_)) => forget_radio_mode(&ctx.app),
        _ => {}
    }
    if result.is_ok() && body.sim_slot.is_some() {
        post_sim_slot(&ctx.app).await;
    }
    refresh_modem_snapshot(&ctx.app, Priority::Interactive, false).await;
    match result {
        Ok(applied) => Json(serde_json::json!({ "status": "success", "applied": applied })).into_response(),
        Err(resp) => *resp,
    }
}

/// Clear cached SIM identity (`iccid`, `imsi`, `spn`) and record the monotonic
/// SIM-switch timestamp so the next telemetry poll immediately re-queries
/// `AT+ICCID` / `AT+CIMI` and syncs the matching `QuecProfile`.
pub async fn post_sim_slot(app: &AppState) {
    {
        let mut sec = app.secrets.write().await;
        sec.iccid.clear();
        sec.imsi.clear();
    }
    *app.spn_cache.write().await = (String::new(), String::new(), String::new());
    app.last_sim_slot.store(0, std::sync::atomic::Ordering::Release);
    app.sim_switched_at_ms
        .store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
}

pub async fn get_cell_lock(State(ctx): State<HttpCtx>) -> Response {
    let cmds = vec![
        ("AT+QNWLOCK=\"common/4g\"".into(), Duration::from_secs(4)),
        ("AT+QNWLOCK=\"common/5g\"".into(), Duration::from_secs(4)),
        ("AT+QNWLOCK=\"save_ctrl\"".into(), Duration::from_secs(4)),
    ];
    let res = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await.ok();
    let get_b = |i: usize| -> String {
        res.as_ref()
            .and_then(|v| v.get(i))
            .and_then(|r| r.as_ref().ok())
            .map(|r| r.body.clone())
            .unwrap_or_default()
    };
    let s = ctx.app.settings.read().await.clone();
    let bypassed = ctx
        .app
        .cell_lock_bypassed
        .load(std::sync::atomic::Ordering::Acquire);
    Json(serde_json::json!({
        "lteRaw": get_b(0),
        "nr5gRaw": get_b(1),
        "saveCtrlRaw": get_b(2),
        "bypassed": bypassed,
        "cellLockDeadmanEnabled": s.cell_lock_deadman_enabled,
        "cellLockDeadmanSecs": s.cell_lock_deadman_secs,
        "schedule": {
            "enabled": s.cell_lock_sched_enabled,
            "startTime": s.cell_lock_start_time,
            "endTime": s.cell_lock_end_time,
            "lteLock": s.cell_lock_lte,
            "nr5gLock": s.cell_lock_nr5g,
            "ltePersist": s.cell_lock_lte_persist,
            "nr5gPersist": s.cell_lock_nr5g_persist,
            "deadmanEnabled": s.cell_lock_deadman_enabled,
            "deadmanSecs": s.cell_lock_deadman_secs,
            "bypassed": bypassed,
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CellLockReq {
    rat: Option<String>,
    pci: Option<i64>,
    arfcn: Option<i64>,
    scs: Option<i64>,
    band: Option<i64>,
    persist: Option<bool>,
    schedule_enabled: Option<bool>,
    start_time: Option<String>,
    end_time: Option<String>,
    #[serde(default, alias = "cell_lock_deadman_enabled", alias = "deadmanEnabled")]
    cell_lock_deadman_enabled: Option<bool>,
    #[serde(default, alias = "cell_lock_deadman_secs", alias = "deadmanSecs")]
    cell_lock_deadman_secs: Option<u64>,
}

/// LTE cell lock: PCI 0..503 (TS 36.211), EARFCN 0..262143 (TS 36.101).
pub fn validate_lte_lock(pci: i64, earfcn: i64) -> Result<(), String> {
    if !(0..=503).contains(&pci) {
        return Err("LTE PCI must be 0..503".into());
    }
    if !(0..=262_143).contains(&earfcn) {
        return Err("LTE EARFCN must be 0..262143".into());
    }
    Ok(())
}

/// NR cell lock: PCI 0..1007 (TS 38.211), NR-ARFCN 0..3279165 (TS 38.104),
/// SCS 15/30/60/120/240 kHz, and a 3GPP NR band number.
pub fn validate_nr5g_lock(pci: i64, arfcn: i64, scs: i64, band: i64) -> Result<(), String> {
    if !(0..=1007).contains(&pci) {
        return Err("NR PCI must be 0..1007".into());
    }
    if !(0..=3_279_165).contains(&arfcn) {
        return Err("NR-ARFCN must be 0..3279165".into());
    }
    if !matches!(scs, 15 | 30 | 60 | 120 | 240) {
        return Err("SCS must be 15, 30, 60, 120 or 240 kHz".into());
    }
    if !u16::try_from(band).is_ok_and(|b| is_known_band(BandRat::SaNr5g, b)) {
        return Err("NR band must be a 3GPP NR band number (n1..n113, n257..n263)".into());
    }
    Ok(())
}

pub async fn post_cell_lock(State(ctx): State<HttpCtx>, Json(body): Json<CellLockReq>) -> Response {
    if let Some(secs) = body.cell_lock_deadman_secs
        && !(1..=86_400).contains(&secs)
    {
        return err_resp(StatusCode::BAD_REQUEST, "cellLockDeadmanSecs must be 1..86400");
    }
    if body.rat.is_none()
        && (body.schedule_enabled.is_some()
            || body.cell_lock_deadman_enabled.is_some()
            || body.cell_lock_deadman_secs.is_some())
    {
        for t in [&body.start_time, &body.end_time].into_iter().flatten() {
            if crate::profiles::parse_hhmm(t).is_none() {
                return err_resp(StatusCode::BAD_REQUEST, "Times must be HH:MM (24 h)");
            }
        }
        let (snap, dm_en, dm_secs) = {
            let mut s = ctx.app.settings.write().await;
            if let Some(en) = body.schedule_enabled {
                s.cell_lock_sched_enabled = en;
            }
            if let Some(st) = body.start_time {
                s.cell_lock_start_time = st;
            }
            if let Some(et) = body.end_time {
                s.cell_lock_end_time = et;
            }
            if let Some(dm_en) = body.cell_lock_deadman_enabled {
                s.cell_lock_deadman_enabled = dm_en;
            }
            if let Some(dm_secs) = body.cell_lock_deadman_secs {
                s.cell_lock_deadman_secs = dm_secs;
            }
            (s.clone(), s.cell_lock_deadman_enabled, s.cell_lock_deadman_secs)
        };
        if let Err(e) = crate::state::save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await {
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not save the cell-lock schedule: {e}"));
        }
        let bypassed = ctx
            .app
            .cell_lock_bypassed
            .load(std::sync::atomic::Ordering::Acquire);
        return Json(serde_json::json!({
            "status": "success",
            "bypassed": bypassed,
            "cellLockDeadmanEnabled": dm_en,
            "cellLockDeadmanSecs": dm_secs,
        }))
        .into_response();
    }

    if !matches!(body.rat.as_deref(), Some("nr5g" | "lte")) {
        return err_resp(StatusCode::BAD_REQUEST, "rat must be nr5g or lte");
    }
    // A cell lock changes the radio: one radio change at a time.
    let _radio = crate::radio::lock(&ctx.app).await;
    match body.rat.as_deref() {
        Some("nr5g") => {
            let (Some(pci), Some(arfcn), Some(scs), Some(band)) = (body.pci, body.arfcn, body.scs, body.band) else {
                return err_resp(StatusCode::BAD_REQUEST, "NR5G lock requires pci, arfcn, scs, band");
            };
            if let Err(e) = validate_nr5g_lock(pci, arfcn, scs, band) {
                return err_resp(StatusCode::BAD_REQUEST, e);
            }
            let params = format!("{pci},{arfcn},{scs},{band}");
            let cmd = format!("AT+QNWLOCK=\"common/5g\",{params}");
            match ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(10)).await {
                Ok(r) if r.ok => {}
                Ok(r) => return err_resp(StatusCode::UNPROCESSABLE_ENTITY, format!("Modem rejected the 5G cell lock: {}", r.body.trim())),
                Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
            }
            let mut s = ctx.app.settings.write().await;
            s.cell_lock_nr5g = params;
            if let Some(p) = body.persist {
                s.cell_lock_nr5g_persist = p;
            }
            if let Some(dm_en) = body.cell_lock_deadman_enabled {
                s.cell_lock_deadman_enabled = dm_en;
            }
            if let Some(dm_secs) = body.cell_lock_deadman_secs {
                s.cell_lock_deadman_secs = dm_secs;
            }
        }
        Some("lte") => {
            let (Some(pci), Some(arfcn)) = (body.pci, body.arfcn) else {
                return err_resp(StatusCode::BAD_REQUEST, "LTE lock requires pci and arfcn");
            };
            if let Err(e) = validate_lte_lock(pci, arfcn) {
                return err_resp(StatusCode::BAD_REQUEST, e);
            }
            let params = format!("1,{arfcn},{pci}");
            let cmd = format!("AT+QNWLOCK=\"common/4g\",{params}");
            match ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(10)).await {
                Ok(r) if r.ok => {}
                Ok(r) => return err_resp(StatusCode::UNPROCESSABLE_ENTITY, format!("Modem rejected the LTE cell lock: {}", r.body.trim())),
                Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
            }
            let mut s = ctx.app.settings.write().await;
            s.cell_lock_lte = params;
            if let Some(p) = body.persist {
                s.cell_lock_lte_persist = p;
            }
            if let Some(dm_en) = body.cell_lock_deadman_enabled {
                s.cell_lock_deadman_enabled = dm_en;
            }
            if let Some(dm_secs) = body.cell_lock_deadman_secs {
                s.cell_lock_deadman_secs = dm_secs;
            }
        }
        _ => return err_resp(StatusCode::BAD_REQUEST, "rat must be nr5g or lte"),
    }
    crate::telemetry::clear_cell_lock_bypass_state(&ctx.app);

    // Keep the lock across modem reboots (save_ctrl), then the daemon's own
    // record of it. The lock itself is already applied: a failure in either
    // step is reported as such instead of a success.
    let s = ctx.app.settings.read().await.clone();
    let save_ctrl = ctx
        .app
        .smd
        .exec(
            format!(
                "AT+QNWLOCK=\"save_ctrl\",{},{}",
                if s.cell_lock_lte_persist { 1 } else { 0 },
                if s.cell_lock_nr5g_persist { 1 } else { 0 }
            ),
            Priority::Interactive,
            Duration::from_secs(6),
        )
        .await;
    let saved = crate::state::save_json_atomic_async(SETTINGS_JSON_PATH, s.clone(), 0o600).await;
    let not_saved = saved.as_ref().err().map(|e| format!("; the lock was not saved to the settings either: {e}")).unwrap_or_default();
    match save_ctrl {
        Ok(r) if !r.ok => {
            return err_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Cell lock applied, but the modem rejected save_ctrl (keeping it across reboots): {}{not_saved}", r.body.trim()),
            );
        }
        Err(e) => {
            return err_resp(StatusCode::BAD_GATEWAY, format!("Cell lock applied, but save_ctrl was not confirmed by the modem: {e}{not_saved}"));
        }
        Ok(_) => {}
    }
    if let Err(e) = saved {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Cell lock applied, but the settings could not be saved: {e}"));
    }
    Json(serde_json::json!({
        "status": "success",
        "bypassed": false,
        "cellLockDeadmanEnabled": s.cell_lock_deadman_enabled,
        "cellLockDeadmanSecs": s.cell_lock_deadman_secs,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct RatQuery {
    rat: Option<String>,
}

pub(crate) fn qnwlock_is_unlocked(body: &str, key: &str) -> bool {
    for line in body.lines() {
        let t = line.trim();
        if t.get(..9).is_some_and(|p| p.eq_ignore_ascii_case("+QNWLOCK:")) {
            let mut parts = t.get(9..).unwrap_or("").split(',').map(|s| s.trim().trim_matches('"'));
            if let (Some(k), Some(val)) = (parts.next(), parts.next())
                && k.eq_ignore_ascii_case(key)
            {
                return val == "0";
            }
        }
    }
    false
}

pub async fn delete_cell_lock(State(ctx): State<HttpCtx>, Query(q): Query<RatQuery>) -> Response {
    let rats: &[(&str, &str)] = match q.rat.as_deref() {
        Some("lte") => &[("lte", "LTE")],
        Some("nr5g") => &[("nr5g", "5G")],
        _ => &[("lte", "LTE"), ("nr5g", "5G")],
    };
    let (mut rejected, mut transport) = (Vec::new(), Vec::new());
    // Unlocking changes the radio: one radio change at a time.
    let _radio = crate::radio::lock(&ctx.app).await;
    for (rat, label) in rats {
        let key = if *rat == "lte" { "common/4g" } else { "common/5g" };
        let read_cmd = format!("AT+QNWLOCK=\"{key}\"");
        if let Ok(pre) = ctx.app.smd.exec(&read_cmd, Priority::Interactive, Duration::from_secs(6)).await
            && pre.ok
            && qnwlock_is_unlocked(&pre.body, key)
        {
            let mut s = ctx.app.settings.write().await;
            if *rat == "lte" {
                s.cell_lock_lte.clear();
            } else {
                s.cell_lock_nr5g.clear();
            }
            continue;
        }
        let cmd = format!("AT+QNWLOCK=\"{key}\",0");
        match ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(8)).await {
            Ok(r) if r.ok => {
                let mut s = ctx.app.settings.write().await;
                if *rat == "lte" {
                    s.cell_lock_lte.clear();
                } else {
                    s.cell_lock_nr5g.clear();
                }
            }
            Ok(r) => {
                let already_unlocked = ctx
                    .app
                    .smd
                    .exec(&read_cmd, Priority::Interactive, Duration::from_secs(6))
                    .await
                    .is_ok_and(|post| post.ok && qnwlock_is_unlocked(&post.body, key));
                if already_unlocked {
                    let mut s = ctx.app.settings.write().await;
                    if *rat == "lte" {
                        s.cell_lock_lte.clear();
                    } else {
                        s.cell_lock_nr5g.clear();
                    }
                } else {
                    rejected.push(format!("Modem rejected the {label} unlock: {}", r.body.trim()));
                }
            }
            Err(e) => transport.push(format!("{label} unlock not confirmed by the modem: {e}")),
        }
    }
    {
        let s = ctx.app.settings.read().await;
        if s.cell_lock_lte.is_empty() && s.cell_lock_nr5g.is_empty() {
            crate::telemetry::clear_cell_lock_bypass_state(&ctx.app);
        }
    }
    let s_snap = ctx.app.settings.read().await.clone();
    let saved = crate::state::save_json_atomic_async(SETTINGS_JSON_PATH, s_snap, 0o600).await;
    if !transport.is_empty() || !rejected.is_empty() {
        let status = if transport.is_empty() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::BAD_GATEWAY };
        let mut msg: Vec<String> = transport.into_iter().chain(rejected).collect();
        if let Err(e) = saved {
            msg.push(format!("settings not saved: {e}"));
        }
        return err_resp(status, msg.join("; "));
    }
    if let Err(e) = saved {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Cell lock removed, but the settings could not be saved: {e}"));
    }
    Json(serde_json::json!({ "status": "success" })).into_response()
}

pub async fn get_cell_scan(State(ctx): State<HttpCtx>) -> Response {
    let running = ctx.app.qscan_running.lock().await.is_some();
    let neighbors = if running {
        Vec::new()
    } else {
        let n_res = ctx
            .app
            .smd
            .exec("AT+QENG=\"neighbourcell\"", Priority::Interactive, Duration::from_secs(6))
            .await
            .map(|r| r.body)
            .unwrap_or_default();
        parse_neighbor_cells(&n_res)
    };
    let last_scan = ctx.app.qscan_last.read().await.clone();
    Json(serde_json::json!({
        "neighbors": neighbors,
        "scanRunning": running,
        "scanResult": last_scan,
    }))
    .into_response()
}

#[derive(Default, Deserialize)]
pub struct CellScanReq {
    #[serde(default)]
    pub mode: Option<String>,
}

pub fn qscan_command_for_mode(mode: Option<&str>) -> Result<(&'static str, &'static str), &'static str> {
    match mode.map(|m| m.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("all") => Ok(("all", "AT+QSCAN=3,1")),
        Some("nr5g") | Some("5g") => Ok(("nr5g", "AT+QSCAN=2,1")),
        Some("lte") | Some("4g") => Ok(("lte", "AT+QSCAN=1,1")),
        Some(_) => Err("Scan mode must be 'nr5g', 'lte', or 'all'"),
    }
}

pub async fn post_cell_scan(State(ctx): State<HttpCtx>, body: axum::body::Bytes) -> Response {
    let parsed_mode = if body.iter().all(|b| b.is_ascii_whitespace()) {
        None
    } else {
        match serde_json::from_slice::<CellScanReq>(&body) {
            Ok(req) => req.mode,
            Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid scan request JSON"),
        }
    };
    let (mode_label, qscan_cmd) = match qscan_command_for_mode(parsed_mode.as_deref()) {
        Ok(pair) => pair,
        Err(msg) => return err_resp(StatusCode::BAD_REQUEST, msg),
    };

    let mut guard = ctx.app.qscan_running.lock().await;
    if guard.is_some() {
        return Json(serde_json::json!({ "status": "running", "message": "Cell scan already running" })).into_response();
    }
    *guard = Some(serde_json::json!({ "startedAt": now_secs(), "mode": mode_label }));
    ctx.app
        .qscan_started_ms
        .store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
    drop(guard);

    let app = ctx.app.clone();
    tokio::spawn(async move {
        let res = app
            .smd
            .exec(qscan_cmd, Priority::Interactive, Duration::from_secs(180))
            .await;
        match res {
            Ok(r) if r.ok => {
                let entries = parse_qscan_entries(&r.body);
                *app.qscan_last.write().await = Some(serde_json::json!({
                    "status": "completed",
                    "mode": mode_label,
                    "timestamp": format_now_hms(),
                    "entries": entries,
                    "raw": r.body,
                }));
            }
            Ok(r) => {
                let err = if r.body.trim().is_empty() {
                    "Cell scan failed".to_string()
                } else {
                    r.body
                };
                *app.qscan_last.write().await = Some(serde_json::json!({
                    "status": "error",
                    "mode": mode_label,
                    "error": err,
                    "timestamp": format_now_hms(),
                }));
            }
            Err(e) => {
                *app.qscan_last.write().await = Some(serde_json::json!({
                    "status": "error",
                    "mode": mode_label,
                    "error": e,
                    "timestamp": format_now_hms(),
                }));
            }
        }
        *app.qscan_running.lock().await = None;
        app.qscan_started_ms
            .store(0, std::sync::atomic::Ordering::Release);
    });

    Json(serde_json::json!({ "status": "started", "mode": mode_label })).into_response()
}

pub async fn delete_cell_scan(State(ctx): State<HttpCtx>) -> Response {
    *ctx.app.qscan_last.write().await = None;
    Json(serde_json::json!({ "status": "cleared" })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlignReq {
    active: bool,
    #[serde(default)]
    reset_peaks: bool,
    #[serde(default)]
    reset_chain: Option<u8>,
    #[serde(default)]
    keep_awake: Option<bool>,
}

pub async fn get_antenna_align(State(ctx): State<HttpCtx>) -> Response {
    let a = ctx.app.antenna_align.read().await.clone();
    Json(serde_json::json!({ "status": "ok", "align": a })).into_response()
}

pub async fn post_antenna_align(State(ctx): State<HttpCtx>, Json(body): Json<AlignReq>) -> Response {
    let snap = {
        let mut a = ctx.app.antenna_align.write().await;
        a.active = body.active;
        if body.active {
            a.expires_at = now_secs() + 300;
            if let Some(ka) = body.keep_awake {
                a.keep_awake = ka;
            }
        } else {
            a.keep_awake = false;
        }
        if body.reset_peaks {
            a.peak_rsrp = vec![None, None, None, None];
            a.peak_sinr = vec![None, None, None, None];
            a.peak_mean_rsrp = None;
            a.peak_mean_sinr = None;
            a.samples = 0;
        } else if let Some(ch) = body.reset_chain
            && (ch as usize) < 4
        {
            let idx = ch as usize;
            if idx < a.peak_rsrp.len() {
                a.peak_rsrp[idx] = a.rsrp.get(idx).copied().flatten();
            }
            if idx < a.peak_sinr.len() {
                a.peak_sinr[idx] = a.sinr.get(idx).copied().flatten();
            }
        }
        a.clone()
    };
    ctx.app.align_notify.notify_one();
    ctx.app.broadcast_with(|| serde_json::json!({
        "channel": "antenna_align",
        "align": snap,
    }));
    Json(serde_json::json!({ "status": "ok", "align": snap })).into_response()
}

pub async fn get_network_lan(State(ctx): State<HttpCtx>) -> Response {
    let native_mode = crate::dataplane::is_native_mode();
    let cmds = if native_mode {
        vec![("AT+QCFG=\"usbnet\"".into(), Duration::from_secs(4))]
    } else {
        vec![
            ("AT+QMAP=\"LANIP\"".into(), Duration::from_secs(4)),
            ("AT+QMAP=\"MPDN_RULE\"".into(), Duration::from_secs(4)),
            ("AT+QMAP=\"DHCPV4DNS\"".into(), Duration::from_secs(4)),
            ("AT+QCFG=\"usbnet\"".into(), Duration::from_secs(4)),
        ]
    };
    let res = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await.ok();
    let get_b = |i: usize| -> String {
        res.as_ref()
            .and_then(|v| v.get(i))
            .and_then(|r| r.as_ref().ok())
            .map(|r| r.body.clone())
            .unwrap_or_default()
    };

    let (lan_ip, mpdn_rules, dhcp_dns_raw, usbnet_raw) = if native_mode {
        (resolve_live_lan_ip(None).await, Vec::new(), String::new(), get_b(0))
    } else {
        let lan_ip = resolve_live_lan_ip(parse_qmap_lan_ip(&get_b(0))).await;
        let mut mpdn_rules = parse_mpdn_rules(&get_b(1));
        if mpdn_rules.iter().any(|r| r.mode != "0" && r.mac.is_empty())
            && Path::new(&crate::paths::p("/etc/config/qcmap_lan")).exists()
        {
            let qcmap_show = uci_show("qcmap_lan").await;
            enrich_mpdn_rules_from_qcmap_lan(&mut mpdn_rules, &qcmap_show);
        }
        (lan_ip, mpdn_rules, get_b(2), get_b(3))
    };
    let arp_clients = read_arp_macs();
    let settings = ctx.app.settings.read().await.clone();

    let live_ttl = read_live_mangle_val("iptables", "--ttl-set");
    let live_hl = read_live_mangle_val("ip6tables", "--hl-set");
    let mtu_iface = detect_wan_rmnet_ifaces_blocking()
        .into_iter()
        .next()
        .unwrap_or_else(|| "rmnet_data0".into());
    let live_mtu_opt = fs::read_to_string(crate::paths::p(&format!("/sys/class/net/{mtu_iface}/mtu")))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok());
    let mtu_enabled = Path::new(&crate::paths::p("/etc/firewall.user.mtu")).exists();
    let file_mtu = if mtu_enabled {
        fs::read_to_string(crate::paths::p("/etc/firewall.user.mtu"))
            .ok()
            .and_then(|content| {
                content
                    .split_whitespace()
                    .skip_while(|&w| w != "mtu")
                    .nth(1)
                    .and_then(|v| v.parse::<u16>().ok())
            })
            .filter(|v| (1280..=1500).contains(v))
    } else {
        None
    };
    let live_mtu = if mtu_enabled {
        live_mtu_opt
            .filter(|&v| v != 1500)
            .or(settings.mtu_value)
            .or(file_mtu)
            .or(live_mtu_opt)
            .unwrap_or(1500)
    } else {
        live_mtu_opt.unwrap_or(1500)
    };
    let (eth_speed, _) = crate::telemetry::read_eth0_speed_and_duplex();
    let dns_uci = uci_get("dhcp.lan.dhcp_option").await.unwrap_or_default();
    let tailscale = query_tailscale_status().await;

    Json(serde_json::json!({
        "lanIp": lan_ip,
        "mpdnRules": mpdn_rules,
        "dhcpDnsRaw": dhcp_dns_raw,
        "usbnetRaw": usbnet_raw,
        "arpClients": arp_clients,
        "ethLink": {
            "currentLimit": settings.eth_link_speed,
            "actualSpeed": eth_speed,
        },
        "ttl": {
            "enabled": live_ttl.unwrap_or(0) > 0,
            "ttl": live_ttl.or(settings.ttl_value).unwrap_or(0),
            "hl": live_hl.or(settings.hl_value).unwrap_or(0),
        },
        "mtu": {
            "enabled": mtu_enabled,
            "value": live_mtu,
        },
        "dns": {
            "uciOption": dns_uci,
            "custom": settings.custom_dns,
        },
        "tailscale": tailscale,
    }))
    .into_response()
}

/// Parse OpenWrt `ubus call network.interface.lan status` IPv4 gateway + prefix.
fn parse_ubus_lan_ipv4(status_json: &str) -> Option<(Ipv4Addr, u8)> {
    let v: serde_json::Value = serde_json::from_str(status_json).ok()?;
    let a = v.get("ipv4-address")?.as_array()?.first()?;
    let ip = a.get("address")?.as_str()?.trim().parse::<Ipv4Addr>().ok()?;
    let mask = u8::try_from(a.get("mask")?.as_u64()?).ok()?;
    (1..=32).contains(&mask).then_some((ip, mask))
}

/// Parse UCI `network.lan` IPv4 gateway + CIDR prefix length.
fn parse_uci_lan_ipv4(ipaddr_raw: &str, netmask_raw: Option<&str>) -> Option<(Ipv4Addr, u8)> {
    let raw = ipaddr_raw.trim();
    if let Some((ip_s, pfx_s)) = raw.split_once('/') {
        let ip = ip_s.trim().parse::<Ipv4Addr>().ok()?;
        let pfx = pfx_s.trim().parse::<u8>().ok()?;
        if (1..=32).contains(&pfx) {
            return Some((ip, pfx));
        }
    }
    let ip = raw.parse::<Ipv4Addr>().ok()?;
    let prefix = netmask_raw
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .filter(|&bits| bits != 0 && bits.leading_ones() + bits.trailing_zeros() == 32)
        .map(|bits| bits.leading_ones() as u8)
        .unwrap_or(24);
    Some((ip, prefix))
}

/// Read active DHCPv4 pool start/end for the LAN subnet from `/var/etc/dnsmasq.conf*`.
fn read_dnsmasq_lan_dhcp_range(gw: Ipv4Addr, mask_u32: u32) -> Option<(String, String)> {
    let net_u32 = u32::from(gw) & mask_u32;
    let var_etc = crate::paths::p("/var/etc");
    let mut files: Vec<std::path::PathBuf> = fs::read_dir(&var_etc)
        .ok()?
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("dnsmasq.conf"))
        })
        .collect();
    files.sort();

    let mut untagged_fallback: Option<(String, String)> = None;
    for path in files {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for raw_line in text.lines() {
            let Some(rest) = raw_line.trim().strip_prefix("dhcp-range=") else {
                continue;
            };
            let tokens: Vec<&str> = rest.split(',').map(str::trim).collect();
            if tokens.contains(&"static") {
                continue;
            }
            let is_lan_tag = tokens
                .iter()
                .any(|&t| matches!(t, "set:lan" | "tag:lan" | "lan"));
            let mut ips = tokens
                .iter()
                .filter_map(|t| t.parse::<Ipv4Addr>().ok())
                .filter(|ip| (u32::from(*ip) & mask_u32) == net_u32);
            if let (Some(start), Some(end)) = (ips.next(), ips.next()) {
                let pair = (start.to_string(), end.to_string());
                if is_lan_tag {
                    return Some(pair);
                }
                if untagged_fallback.is_none() {
                    untagged_fallback = Some(pair);
                }
            }
        }
    }
    untagged_fallback
}

/// Compute the DHCPv4 pool start/end from UCI `dhcp.lan` options (`start`, `limit`, `ignore`, `dhcpv4`).
fn pool_from_uci_dhcp_lan(
    gw: Ipv4Addr,
    prefix: u8,
    opts: &std::collections::BTreeMap<String, String>,
) -> (String, String) {
    let ignored = opts
        .get("ignore")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
    let v4_disabled = opts
        .get("dhcpv4")
        .is_some_and(|v| matches!(v.as_str(), "disabled" | "0"));
    if ignored || v4_disabled {
        return (String::new(), String::new());
    }
    let mask_u32 = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix.min(32)) };
    let net_u32 = u32::from(gw) & mask_u32;
    let bcast_u32 = net_u32 | !mask_u32;
    let max_host = if prefix >= 31 { bcast_u32 } else { bcast_u32.saturating_sub(1) };
    let raw_start = match opts.get("start").map(|s| s.trim()) {
        Some(s) if !s.is_empty() => {
            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                u32::from(ip)
            } else if let Ok(off) = s.parse::<u32>() {
                net_u32.saturating_add(off)
            } else {
                net_u32.saturating_add(100)
            }
        }
        _ => net_u32.saturating_add(100),
    };
    let limit: u32 = opts
        .get("limit")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(150);
    if limit == 0 {
        return (String::new(), String::new());
    }
    let start_u32 = raw_start.clamp(net_u32, max_host);
    let end_u32 = start_u32.saturating_add(limit - 1).min(max_host);
    (Ipv4Addr::from(start_u32).to_string(), Ipv4Addr::from(end_u32).to_string())
}

async fn resolve_lan_gateway_cidr() -> Option<(Ipv4Addr, u8)> {
    if let Ok(ubus_out) = run_cmd("ubus", &["call", "network.interface.lan", "status"], Duration::from_secs(3)).await
        && let Some(pair) = parse_ubus_lan_ipv4(&ubus_out)
    {
        return Some(pair);
    }
    let net_raw = uci_show("network.lan").await;
    let net_secs = parse_uci_sections(&net_raw, "network");
    let lan_sec = net_secs.get("lan")?;
    let ipaddr = lan_sec.opts.get("ipaddr").map(String::as_str)?;
    parse_uci_lan_ipv4(ipaddr, lan_sec.opts.get("netmask").map(String::as_str))
}

/// Prefer OpenWrt's live LAN interface (`ubus`/`network.lan`) and `dnsmasq`/`dhcp.lan` pool over stale `AT+QMAP="LANIP"`.
async fn resolve_live_lan_ip(qmap_fallback: Option<QmapLanIpInfo>) -> Option<QmapLanIpInfo> {
    if !Path::new(&crate::paths::p("/etc/config/network")).exists() {
        return qmap_fallback;
    }
    let Some((gw_ip, prefix)) = resolve_lan_gateway_cidr().await else {
        return qmap_fallback;
    };

    let mask_u32 = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix.min(32)) };
    let dotted = Ipv4Addr::from(mask_u32);
    let netmask = format!("{dotted} (/{prefix})");

    let (pool_start, pool_end) = if let Some(pair) = read_dnsmasq_lan_dhcp_range(gw_ip, mask_u32) {
        pair
    } else {
        let dhcp_raw = uci_show("dhcp.lan").await;
        let dhcp_secs = parse_uci_sections(&dhcp_raw, "dhcp");
        match dhcp_secs.get("lan") {
            Some(sec) => pool_from_uci_dhcp_lan(gw_ip, prefix, &sec.opts),
            None => (String::new(), String::new()),
        }
    };

    let raw = if pool_start.is_empty() {
        gw_ip.to_string()
    } else {
        format!("{pool_start}, {pool_end}, {gw_ip}")
    };
    Some(QmapLanIpInfo {
        pool_start,
        pool_end,
        gateway_ip: gw_ip.to_string(),
        netmask,
        raw,
    })
}

fn read_arp_macs() -> Vec<serde_json::Value> {
    let mut hosts_by_ip = std::collections::HashMap::new();
    let mut hosts_by_mac = std::collections::HashMap::new();
    if let Ok(leases) = fs::read_to_string(crate::paths::p("/tmp/dhcp.leases")) {
        for line in leases.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[3] != "*" {
                hosts_by_mac.insert(cols[1].to_ascii_lowercase(), cols[3].to_string());
                hosts_by_ip.insert(cols[2].to_string(), cols[3].to_string());
            }
        }
    }
    let mut out = Vec::new();
    if let Ok(arp) = fs::read_to_string(crate::paths::p("/proc/net/arp")) {
        for line in arp.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                let ip = cols[0];
                let flags = cols[2];
                let mac = cols[3].to_ascii_lowercase();
                if mac.is_empty() || mac == "00:00:00:00:00:00" || flags == "0x0" {
                    continue;
                }
                let hostname = hosts_by_ip
                    .get(ip)
                    .or_else(|| hosts_by_mac.get(&mac))
                    .cloned()
                    .unwrap_or_else(|| ip.to_string());
                out.push(serde_json::json!({ "hostname": hostname, "ip": ip, "mac": mac }));
            }
        }
    }
    out
}

fn read_live_mangle_val(bin: &str, flag: &str) -> Option<u8> {
    let out = crate::uci::run_cmd_blocking(bin, &["-t", "mangle", "-S", "POSTROUTING"]).ok()?;
    for tok in out.split_whitespace().collect::<Vec<_>>().windows(2) {
        if tok[0] == flag
            && let Ok(n) = tok[1].parse::<u8>()
        {
            return Some(n);
        }
    }
    None
}

async fn query_tailscale_status() -> serde_json::Value {
    let installed = Path::new(&crate::paths::p("/etc/init.d/tailscale")).exists();
    if !installed {
        return serde_json::json!({ "installed": false, "running": false, "authenticated": false, "peers": [] });
    }
    let running = run_cmd("/etc/init.d/tailscale", &["status"], Duration::from_secs(2))
        .await
        .map(|s| s.trim() == "running")
        .unwrap_or(false);
    let mut authenticated = false;
    let mut login_url: Option<String> = None;
    let mut self_ip: Option<String> = None;
    let mut peers = Vec::new();
    if running
        && let Ok(ts_json) = run_cmd("tailscale", &["status", "--json"], Duration::from_secs(3)).await
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&ts_json)
    {
        authenticated = v.get("BackendState").and_then(|s| s.as_str()) == Some("Running");
        login_url = v
            .get("AuthURL")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        self_ip = v
            .get("Self")
            .and_then(|s| s.get("TailscaleIPs"))
            .and_then(|a| a.get(0))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        if let Some(map) = v.get("Peer").and_then(|p| p.as_object()) {
            for (_, pv) in map {
                peers.push(serde_json::json!({
                    "hostName": pv.get("HostName").and_then(|x| x.as_str()).unwrap_or("peer"),
                    "ip": pv.get("TailscaleIPs").and_then(|a| a.get(0)).and_then(|x| x.as_str()).unwrap_or("--"),
                    "online": pv.get("Online").and_then(|x| x.as_bool()).unwrap_or(false),
                    "os": pv.get("OS").and_then(|x| x.as_str()).unwrap_or(""),
                }));
            }
        }
    }
    serde_json::json!({
        "installed": true,
        "running": running,
        "authenticated": authenticated,
        "loginUrl": login_url,
        "selfIp": self_ip,
        "peers": peers,
    })
}

pub fn parse_partner_advertised_speeds(ethtool_out: &str) -> Option<Vec<&'static str>> {
    let mut found_header = false;
    let mut collecting = false;
    let mut speeds = std::collections::BTreeSet::<u32>::new();

    for line in ethtool_out.lines() {
        let trimmed = line.trim();
        if !found_header {
            if let Some(idx) = trimmed.find("Link partner advertised link modes:") {
                found_header = true;
                collecting = true;
                let rest = trimmed[idx + "Link partner advertised link modes:".len()..].trim();
                if rest.eq_ignore_ascii_case("Not reported") {
                    collecting = false;
                } else {
                    collect_ethtool_speeds(rest, &mut speeds);
                }
            }
            continue;
        }
        if !collecting {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains(':') || trimmed.eq_ignore_ascii_case("Not reported") {
            break;
        }
        collect_ethtool_speeds(trimmed, &mut speeds);
    }

    if !found_header {
        return None;
    }
    Some(
        speeds
            .into_iter()
            .filter_map(|s| match s {
                10 => Some("10"),
                100 => Some("100"),
                1000 => Some("1000"),
                2500 => Some("2500"),
                5000 => Some("5000"),
                10000 => Some("10000"),
                _ => None,
            })
            .collect(),
    )
}

fn collect_ethtool_speeds(segment: &str, out: &mut std::collections::BTreeSet<u32>) {
    for tok in segment.split_whitespace() {
        let lower = tok.to_ascii_lowercase();
        let speed = if lower.starts_with("10base") {
            Some(10)
        } else if lower.starts_with("100base") {
            Some(100)
        } else if lower.starts_with("1000base") {
            Some(1000)
        } else if lower.starts_with("2500base") {
            Some(2500)
        } else if lower.starts_with("5000base") {
            Some(5000)
        } else if lower.starts_with("10000base") {
            Some(10000)
        } else {
            None
        };
        if let Some(s) = speed {
            out.insert(s);
        }
    }
}

pub fn check_partner_speed_limit(ethtool_out: &str, limit: &str) -> Result<(), String> {
    let Some(speeds) = parse_partner_advertised_speeds(ethtool_out) else {
        return Ok(());
    };
    if !speeds.is_empty() && !speeds.contains(&limit) {
        return Err(format!(
            "Link partner does not advertise {limit} Mb/s (advertised: {} Mb/s)",
            speeds.join(", ")
        ));
    }
    Ok(())
}

async fn clean_live_tcpmss_rules(ifaces: &[String]) {
    for bin in ["iptables", "ip6tables"] {
        let Ok(rules) = run_cmd(bin, &["-t", "mangle", "-S", "FORWARD"], Duration::from_secs(3)).await else {
            continue;
        };
        for line in rules.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("-A FORWARD ") || !trimmed.contains("TCPMSS") {
                continue;
            }
            let matches_wan = ifaces.iter().any(|i| trimmed.contains(i))
                || trimmed.contains("rmnet_data")
                || trimmed.contains("wwan");
            if !matches_wan {
                continue;
            }
            let toks: Vec<&str> = trimmed.split_whitespace().collect();
            if toks.len() < 3 {
                continue;
            }
            let mut del_args: Vec<&str> = Vec::with_capacity(toks.len() + 2);
            del_args.extend(["-t", "mangle", "-D"]);
            del_args.extend(&toks[1..]);
            let _ = run_cmd(bin, &del_args, Duration::from_secs(3)).await;
        }
    }
}

async fn apply_live_tcpmss_rules(ifaces: &[String], mtu_val: u32) {
    if !(1280..1500).contains(&mtu_val) {
        return;
    }
    let mss4 = (mtu_val - 40).to_string();
    let mss6 = (mtu_val - 60).to_string();
    for iface in ifaces {
        let trimmed = iface.trim();
        if !trimmed.starts_with("rmnet_data") && !trimmed.starts_with("wwan") {
            continue;
        }
        for dir in ["-o", "-i"] {
            let _ = run_cmd(
                "iptables",
                &[
                    "-t", "mangle", "-A", "FORWARD", dir, trimmed, "-p", "tcp",
                    "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss4,
                ],
                Duration::from_secs(3),
            )
            .await;
            let _ = run_cmd(
                "ip6tables",
                &[
                    "-t", "mangle", "-A", "FORWARD", dir, trimmed, "-p", "tcp",
                    "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss6,
                ],
                Duration::from_secs(3),
            )
            .await;
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NetworkMutateReq {
    MpdnRule { slot: i32, mode: i32, mac: Option<String> },
    EthLimit { limit: String },
    Ttl { enabled: bool, ttl: u8, hl: u8 },
    Mtu { enabled: bool, mtu: u16 },
    Dns { enabled: bool, nic: Option<String>, servers: Option<Vec<String>> },
    TailscaleToggle { enabled: bool },
}

fn extract_xml_u32_tag(block: &str, tag: &str) -> Option<u32> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let (_, after_open) = block.split_once(&open)?;
    let (inner, _) = after_open.split_once(&close)?;
    inner.trim().parse::<u32>().ok()
}

fn parse_mobileap_wwan_profiles(
    xml: &str,
) -> (std::collections::BTreeSet<u32>, std::collections::BTreeSet<u32>) {
    let mut profiles = std::collections::BTreeSet::new();
    let mut used_umts = std::collections::BTreeSet::new();
    let mut rest = xml;
    while let Some((_, after_start)) = rest.split_once("<MobileAPWanCfg>") {
        let Some((block, tail)) = after_start.split_once("</MobileAPWanCfg>") else {
            break;
        };
        if let Some(p) = extract_xml_u32_tag(block, "Profile") {
            profiles.insert(p);
        }
        if let Some(u) = extract_xml_u32_tag(block, "V4_UMTS_PROFILE_INDEX") {
            used_umts.insert(u);
        }
        rest = tail;
    }
    (profiles, used_umts)
}

async fn write_qcmap_stage(stdin: &mut tokio::process::ChildStdin, data: &[u8]) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    stdin.write_all(data).await.map_err(|e| format!("write QCMAP_CLI stdin: {e}"))?;
    stdin.flush().await.map_err(|e| format!("flush QCMAP_CLI stdin: {e}"))
}

async fn run_qcmap_cli_create_wwan_policy(umts: u32, timeout: Duration) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let prog = crate::paths::program("/usr/bin/QCMAP_CLI");
    let mut child = Command::new(&prog)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn QCMAP_CLI ({prog}): {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "QCMAP_CLI missing piped stdin".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "QCMAP_CLI missing piped stdout".to_string())?;

    // Hold stdin open across all 3 stages until child.kill(): QCMAP_CLI busy-loops on EOF.
    let mut lines = BufReader::new(stdout).lines();
    let mut collected = String::new();
    let failure_markers = [
        "Failed to Create WWAN policy",
        "Max Profiles reached",
        "Invalid/Duplicate Profile request",
        "Invalid ip familiy",
        "Invalid tech preference",
        "Couldn't setup QcMapClient",
        "MobileAP Enable fails",
    ];

    let handshake = tokio::time::timeout(timeout, async {
        // Stage 1: wait for QCMAP server UP indication before sending menu commands.
        let mut up = false;
        while let Ok(Some(line)) = lines.next_line().await {
            if !collected.is_empty() {
                collected.push('\n');
            }
            collected.push_str(&line);
            if line.contains("Couldn't setup QcMapClient") {
                return Err(format!("QCMAP_CLI failed to connect: {line}"));
            }
            if line.contains("QCMAP_Server status update on MDM: UP") {
                up = true;
                break;
            }
        }
        if !up {
            return Err(format!(
                "QCMAP_CLI exited before MDM UP: {}",
                collected.trim()
            ));
        }

        // Stage 2: acquire mobile_ap_handle via idempotent EnableMobileAP (1 -> 2 -> 1).
        write_qcmap_stage(&mut stdin, b"1\n2\n1\n").await?;
        let mut enabled = false;
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push('\n');
            collected.push_str(&line);
            if line.contains("MobileAP Enable fails") {
                return Err(format!("QCMAP_CLI {line}"));
            }
            if line.contains("MobileAP Enable succeeds") {
                enabled = true;
                break;
            }
        }
        if !enabled {
            return Err(format!(
                "QCMAP_CLI exited before MobileAP Enable: {}",
                collected.trim()
            ));
        }

        // Stage 3: create WWAN profile (6 -> 2 -> 25 -> tech=0 -> subs=0 -> UMTS -> cdma=0 -> apn="" -> ip=10).
        let payload = format!("6\n2\n25\n0\n0\n{umts}\n0\n\n10\n");
        write_qcmap_stage(&mut stdin, payload.as_bytes()).await?;
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push('\n');
            collected.push_str(&line);
            if line.contains("Create WWAN policy succeeds")
                || failure_markers.iter().any(|m| line.contains(m))
            {
                break;
            }
        }
        Ok(())
    })
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;
    drop(stdin);

    match handshake {
        Err(_) => {
            return Err(format!(
                "QCMAP_CLI timed out creating WWAN policy (UMTS={umts})"
            ));
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok(())) => {}
    }

    if !collected.contains("Create WWAN policy succeeds") {
        let err_line = collected
            .lines()
            .rev()
            .find(|l| failure_markers.iter().any(|m| l.contains(m)) || l.contains("Error"))
            .unwrap_or_else(|| collected.trim())
            .trim();
        return Err(format!(
            "QCMAP_CLI Create WWAN policy (UMTS={umts}) failed: {err_line}"
        ));
    }
    Ok(collected)
}

fn parse_qmap_csv(line: &str) -> Option<Vec<&str>> {
    let t = line.trim();
    if t.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("+QMAP:")) {
        Some(t.get(6..).unwrap_or("").trim().split(',').map(|s| s.trim().trim_matches('"')).collect())
    } else {
        None
    }
}

fn qmap_vlan_is_enabled(body: &str, vlan_id: i32) -> bool {
    for line in body.lines() {
        let Some(parts) = parse_qmap_csv(line) else {
            continue;
        };
        if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("VLAN"))
            && parts.get(1).and_then(|s| s.parse::<i32>().ok()) == Some(vlan_id)
        {
            return !matches!(parts.get(2).copied(), Some(s) if s.eq_ignore_ascii_case("disable") || s == "0");
        }
    }
    false
}

fn mpdn_slot_vlan(body: &str, slot: i32) -> Option<i32> {
    for line in body.lines() {
        let Some(parts) = parse_qmap_csv(line) else {
            continue;
        };
        if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("MPDN_rule"))
            && parts.get(1).and_then(|s| s.parse::<i32>().ok()) == Some(slot)
        {
            return parts.get(3).and_then(|s| s.parse::<i32>().ok());
        }
    }
    None
}

fn mpdn_vlan_used_by_other_slot(body: &str, excluded_slot: i32, vlan_id: i32) -> bool {
    for line in body.lines() {
        let Some(parts) = parse_qmap_csv(line) else {
            continue;
        };
        if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("MPDN_rule"))
            && let Some(row_slot) = parts.get(1).and_then(|s| s.parse::<i32>().ok())
            && row_slot != excluded_slot
            && (parts.get(2).copied() != Some("0") || parts.get(4).copied() != Some("0"))
            && parts.get(3).and_then(|s| s.parse::<i32>().ok()) == Some(vlan_id)
        {
            return true;
        }
    }
    false
}

fn mpdn_slot_is_empty(body: &str, slot: i32) -> bool {
    for line in body.lines() {
        let Some(parts) = parse_qmap_csv(line) else {
            continue;
        };
        if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("MPDN_rule"))
            && parts.get(1).and_then(|s| s.parse::<i32>().ok()) == Some(slot)
        {
            return parts.get(2).copied() == Some("0") && parts.get(4).copied() == Some("0");
        }
    }
    false
}

#[derive(Default)]
struct UciSection {
    sec_type: String,
    opts: std::collections::BTreeMap<String, String>,
}

fn trim_uci_quotes(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix('\'')
        .and_then(|x| x.strip_suffix('\''))
        .or_else(|| t.strip_prefix('"').and_then(|x| x.strip_suffix('"')))
        .unwrap_or(t)
}

fn parse_uci_sections(uci_show_out: &str, config: &str) -> std::collections::BTreeMap<String, UciSection> {
    let mut sections: std::collections::BTreeMap<String, UciSection> = std::collections::BTreeMap::new();
    let prefix = format!("{config}.");
    for raw in uci_show_out.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let Some((lhs, rhs)) = rest.split_once('=') else {
            continue;
        };
        let val = trim_uci_quotes(rhs).to_string();
        if let Some((sec, opt)) = lhs.split_once('.') {
            sections.entry(sec.to_string()).or_default().opts.insert(opt.to_string(), val);
        } else {
            sections.entry(lhs.to_string()).or_default().sec_type = val;
        }
    }
    sections
}

/// On SDX75 (RM551E-GL), `AT+QMAP="MPDN_rule"` only outputs 5 integer fields and
/// omits `<IPPT_info>`. QCMAP persists the active passthrough MAC in `qcmap_lan`.
fn enrich_mpdn_rules_from_qcmap_lan(rules: &mut [MpdnRule], qcmap_show: &str) {
    let sections = parse_uci_sections(qcmap_show, "qcmap_lan");
    let profiles: Vec<&UciSection> = sections
        .iter()
        .filter(|(k, s)| s.sec_type == "profile" || k.starts_with("@profile["))
        .map(|(_, s)| s)
        .collect();
    for rule in rules.iter_mut() {
        if rule.mode == "0" || !rule.mac.is_empty() {
            continue;
        }
        if let Some(mac) = profiles.iter().find_map(|p| {
            (p.opts.get("ippt_enable").map(String::as_str) == Some("1"))
                .then(|| p.opts.get("ippt_bridge_context").and_then(|v| v.parse::<i32>().ok()))
                .flatten()
                .filter(|&ctx| ctx == rule.vlan_id)
                .and_then(|_| p.opts.get("ippt_mac_addr"))
                .filter(|m| is_valid_mac(m))
        }) {
            rule.mac = mac.clone();
        }
    }
}

fn qmap_has_any_secondary_vlan_enabled(body: &str) -> bool {
    for line in body.lines() {
        let Some(parts) = parse_qmap_csv(line) else {
            continue;
        };
        if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("VLAN"))
            && let Some(vlan_id) = parts.get(1).and_then(|s| s.parse::<i32>().ok())
            && vlan_id >= 2
            && !matches!(parts.get(2).copied(), Some(s) if s.eq_ignore_ascii_case("disable") || s == "0")
        {
            return true;
        }
    }
    false
}

/// Prevent `/etc/data/lan_config.sh::add_vlan` from rebooting (`eth_vlan_count` `0 -> 1`).
async fn prepare_qcmap_ipa_vlan_enable() {
    prepare_qcmap_ipa_vlan_min(1).await;
}

/// Prevent `/etc/data/lan_config.sh::del_vlan` from rebooting (`eth_vlan_count == 1`).
async fn prepare_qcmap_ipa_vlan_disable() {
    prepare_qcmap_ipa_vlan_min(2).await;
}

async fn prepare_qcmap_ipa_vlan_min(min_count: i32) {
    if !Path::new(&crate::paths::p("/etc/config/qcmap_lan")).exists() {
        return;
    }
    let cur = uci_get("qcmap_lan.@ipa_vlan_phy_config[0].eth_vlan_count")
        .await
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    if cur < min_count {
        let _ = uci_set(
            "qcmap_lan.@ipa_vlan_phy_config[0].eth_vlan_count",
            &min_count.to_string(),
        )
        .await;
        let _ = uci_commit("qcmap_lan").await;
    }
}

async fn reconcile_qcmap_ipa_vlan_count(smd: &crate::smd::SmdClient) {
    if !Path::new(&crate::paths::p("/etc/config/qcmap_lan")).exists() {
        return;
    }
    if let Ok(vr) = smd
        .exec("AT+QMAP=\"VLAN\"", Priority::Interactive, Duration::from_secs(6))
        .await
        && vr.ok
        && vr.body.to_ascii_uppercase().contains("+QMAP:")
        && !qmap_has_any_secondary_vlan_enabled(&vr.body)
    {
        let _ = uci_set("qcmap_lan.@ipa_vlan_phy_config[0].eth_vlan_count", "0").await;
        let _ = uci_commit("qcmap_lan").await;
    }
}

async fn disable_qcmap_vlan_non_rebooting(smd: &crate::smd::SmdClient, vlan_id: i32) {
    prepare_qcmap_ipa_vlan_disable().await;
    let _ = smd
        .exec(
            format!("AT+QMAP=\"VLAN\",{vlan_id},\"disable\""),
            Priority::Interactive,
            Duration::from_secs(15),
        )
        .await;
    reconcile_qcmap_ipa_vlan_count(smd).await;
}

fn qcmap_policy_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn repair_qcmap_wwan_uci_inner(profiles: &std::collections::BTreeSet<u32>) -> Result<bool, String> {
    if !Path::new(&crate::paths::p("/etc/config/qcmap_lan")).exists() {
        return Ok(false);
    }
    let bind_val = uci_get("ql_cust_config.@qcmap_configs[0].bind_when_create_wwan")
        .await
        .filter(|v| v == "0" || v == "1")
        .unwrap_or_else(|| "1".into());
    let qcmap_show = uci_show("qcmap_lan").await;
    let qcmap_secs = parse_uci_sections(&qcmap_show, "qcmap_lan");
    let existing_qcmap_profiles: Vec<&UciSection> = qcmap_secs
        .iter()
        .filter(|(k, s)| s.sec_type == "profile" || k.starts_with("@profile["))
        .map(|(_, s)| s)
        .collect();
    let mut profile_count = existing_qcmap_profiles.len();
    let existing_profile_ids: std::collections::BTreeSet<u32> = existing_qcmap_profiles
        .iter()
        .filter_map(|s| s.opts.get("profile_id").and_then(|v| v.parse::<u32>().ok()))
        .collect();

    let fw_show = uci_show("firewall").await;
    let fw_secs = parse_uci_sections(&fw_show, "firewall");

    let mut changed_dhcp = false;
    let mut changed_net = false;
    let mut changed_qcmap = false;
    let mut changed_fw = false;

    for p in (2u32..=4).filter(|p| profiles.contains(p)) {
        let wan = format!("wan{p}");
        let wan_v6 = format!("wan{p}_v6");
        let lan_wan = format!("lan_wan{p}");
        let p_str = p.to_string();

        if uci_get(&format!("dhcp.{wan}")).await.is_none() {
            uci_set(&format!("dhcp.{wan}"), "dhcp").await?;
            uci_set(&format!("dhcp.{wan}.interface"), &wan).await?;
            uci_set(&format!("dhcp.{wan}.ignore"), "1").await?;
            changed_dhcp = true;
        }

        if uci_get(&format!("network.{wan}")).await.is_none() {
            uci_set(&format!("network.{wan}"), "interface").await?;
            uci_set(&format!("network.{wan}.proto"), "rmnet").await?;
            uci_set(&format!("network.{wan}.profile"), &p_str).await?;
            uci_set(&format!("network.{wan}.type"), "internet").await?;
            uci_set(&format!("network.{wan}.bind"), &bind_val).await?;
            uci_set(&format!("network.{wan}.ipv6"), "0").await?;
            uci_set(&format!("network.{wan}.defaultroute"), "0").await?;
            changed_net = true;
        }

        if uci_get(&format!("network.{wan_v6}")).await.is_none() {
            uci_set(&format!("network.{wan_v6}"), "interface").await?;
            uci_set(&format!("network.{wan_v6}.proto"), "rmnet").await?;
            uci_set(&format!("network.{wan_v6}.profile"), &p_str).await?;
            uci_set(&format!("network.{wan_v6}.type"), "internet").await?;
            uci_set(&format!("network.{wan_v6}.bind"), &bind_val).await?;
            uci_set(&format!("network.{wan_v6}.ipv6"), "1").await?;
            uci_set(&format!("network.{wan_v6}.defaultroute"), "0").await?;
            changed_net = true;
        }

        if !existing_profile_ids.contains(&p) {
            let sec = uci_add_section("qcmap_lan", "profile").await?;
            uci_set(&format!("qcmap_lan.{sec}.profile_id"), &p_str).await?;
            uci_set(&format!("qcmap_lan.{sec}.nat_type"), "SYM").await?;
            uci_set(&format!("qcmap_lan.{sec}.firewall_enabled"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.pkts_allowed"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.no_of_snat_rules"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.no_of_v4_fw_rules"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.no_of_v6_fw_rules"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.ip_type"), "10").await?;
            uci_set(&format!("qcmap_lan.{sec}.ipv4_nat_disable"), "0").await?;
            uci_set(&format!("qcmap_lan.{sec}.bh_present"), "wan").await?;
            uci_set(&format!("qcmap_lan.{sec}.bh_present_v6"), "wan").await?;
            profile_count += 1;
            changed_qcmap = true;
        }

        let has_wan_zone = fw_secs
            .values()
            .any(|s| s.sec_type == "zone" && s.opts.get("name").map(String::as_str) == Some(&wan));
        if !has_wan_zone {
            let z = uci_add_section("firewall", "zone").await?;
            uci_set(&format!("firewall.{z}.name"), &wan).await?;
            uci_set(&format!("firewall.{z}.network"), &wan).await?;
            uci_set(&format!("firewall.{z}.input"), "REJECT").await?;
            uci_set(&format!("firewall.{z}.output"), "ACCEPT").await?;
            uci_set(&format!("firewall.{z}.forward"), "REJECT").await?;
            uci_set(&format!("firewall.{z}.masq"), "1").await?;
            changed_fw = true;
        }

        let has_lan_wan_zone = fw_secs
            .values()
            .any(|s| s.sec_type == "zone" && s.opts.get("name").map(String::as_str) == Some(&lan_wan));
        if !has_lan_wan_zone {
            let lz = uci_add_section("firewall", "zone").await?;
            uci_set(&format!("firewall.{lz}.name"), &lan_wan).await?;
            uci_set(&format!("firewall.{lz}.input"), "ACCEPT").await?;
            uci_set(&format!("firewall.{lz}.output"), "ACCEPT").await?;
            uci_set(&format!("firewall.{lz}.forward"), "ACCEPT").await?;
            changed_fw = true;
        }

        let has_fwd = fw_secs.values().any(|s| {
            s.sec_type == "forwarding"
                && s.opts.get("src").map(String::as_str) == Some(&lan_wan)
                && s.opts.get("dest").map(String::as_str) == Some(&wan)
        });
        if !has_fwd {
            let f = uci_add_section("firewall", "forwarding").await?;
            uci_set(&format!("firewall.{f}.src"), &lan_wan).await?;
            uci_set(&format!("firewall.{f}.dest"), &wan).await?;
            changed_fw = true;
        }
    }

    if changed_qcmap {
        uci_set(
            "qcmap_lan.@no_of_configs[0].no_of_profiles",
            &profile_count.to_string(),
        )
        .await?;
        uci_commit("qcmap_lan").await?;
    }
    if changed_dhcp {
        uci_commit("dhcp").await?;
    }
    if changed_net {
        uci_commit("network").await?;
    }
    if changed_fw {
        uci_commit("firewall").await?;
    }
    if changed_net || changed_fw || changed_dhcp {
        let _ = run_cmd("ubus", &["call", "network", "reload"], Duration::from_secs(5)).await;
        let _ = run_cmd("/etc/init.d/firewall", &["reload"], Duration::from_secs(10)).await;
        let _ = run_cmd("/etc/init.d/dnsmasq", &["reload"], Duration::from_secs(5)).await;
    }

    Ok(changed_dhcp || changed_net || changed_qcmap || changed_fw)
}

/// Repair missing `wan{2..4}` UCI entries for QCMAP profiles already in `/etc/data/mobileap_cfg.xml`.
pub(crate) async fn repair_qcmap_wwan_uci_for_existing_xml_profiles() -> Result<bool, String> {
    let _guard = qcmap_policy_lock().lock().await;
    let xml_path = crate::paths::p("/etc/data/mobileap_cfg.xml");
    if !Path::new(&xml_path).exists() || !Path::new(&crate::paths::p("/etc/config/qcmap_lan")).exists() {
        return Ok(false);
    }
    let xml = tokio::fs::read_to_string(&xml_path)
        .await
        .map_err(|e| format!("read {xml_path}: {e}"))?;
    let (profiles, _) = parse_mobileap_wwan_profiles(&xml);
    repair_qcmap_wwan_uci_inner(&profiles).await
}

/// Prevent `libql_atcop.so::ql_get_vlan_wwan_profile_id` from entering an unbounded
/// `Ql_MoblieAP_PDN_Config_Create` loop by ensuring `/etc/data/mobileap_cfg.xml` / QCMAP
/// has 4 WWAN policies (`Profile` 1..=4) and matching UCI sections before any `AT+QMAP="MPDN_rule"` write.
async fn ensure_qcmap_four_wwan_policies() -> Result<(), String> {
    let _guard = qcmap_policy_lock().lock().await;

    let xml_path = crate::paths::p("/etc/data/mobileap_cfg.xml");
    if !Path::new(&xml_path).exists() {
        return Ok(());
    }
    let xml = tokio::fs::read_to_string(&xml_path)
        .await
        .map_err(|e| format!("read {xml_path}: {e}"))?;
    let (mut profiles, mut used_umts) = parse_mobileap_wwan_profiles(&xml);
    if profiles.len() >= 4 && profiles.contains(&4) {
        repair_qcmap_wwan_uci_inner(&profiles).await?;
        return Ok(());
    }

    let needed = 4usize
        .saturating_sub(profiles.len())
        .max(usize::from(!profiles.contains(&4)));
    for _ in 0..needed {
        let umts = (22u32..=30)
            .find(|u| !used_umts.contains(u))
            .ok_or_else(|| "No free UMTS profile index in 22..=30 for QCMAP WWAN policy".to_string())?;
        run_qcmap_cli_create_wwan_policy(umts, Duration::from_secs(10)).await?;
        used_umts.insert(umts);
    }

    let mut ready = false;
    for attempt in 0..10 {
        let xml2 = tokio::fs::read_to_string(&xml_path)
            .await
            .map_err(|e| format!("re-read {xml_path}: {e}"))?;
        let (profiles2, _) = parse_mobileap_wwan_profiles(&xml2);
        if profiles2.len() >= 4 && profiles2.contains(&4) {
            profiles = profiles2;
            ready = true;
            break;
        }
        if attempt < 9 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    if !ready {
        return Err("QCMAP WWAN policy table has fewer than 4 entries; refusing MPDN_rule to prevent atfwd-daemon lockup".into());
    }
    repair_qcmap_wwan_uci_inner(&profiles).await?;
    Ok(())
}

pub async fn post_network_lan(State(ctx): State<HttpCtx>, Json(body): Json<NetworkMutateReq>) -> Response {
    match body {
        NetworkMutateReq::MpdnRule { slot, mode, mac } => {
            if !(0..=3).contains(&slot) || !(0..=1).contains(&mode) {
                return err_resp(StatusCode::BAD_REQUEST, "Invalid MPDN slot or mode");
            }
            if mode == 1 {
                let m = mac.unwrap_or_default().trim().to_string();
                if !is_valid_mac(&m) {
                    return err_resp(StatusCode::BAD_REQUEST, "Valid MAC address required for passthrough");
                }
                if slot > 0
                    && let Err(e) = ensure_qcmap_four_wwan_policies().await
                {
                    return err_resp(StatusCode::BAD_GATEWAY, e);
                }
                if let Ok(pre) = ctx
                    .app
                    .smd
                    .exec("AT+QMAP=\"MPDN_rule\"", Priority::Interactive, Duration::from_secs(6))
                    .await
                    && pre.ok
                    && !mpdn_slot_is_empty(&pre.body, slot)
                {
                    match ctx
                        .app
                        .smd
                        .exec(
                            format!("AT+QMAP=\"MPDN_rule\",{slot}"),
                            Priority::Interactive,
                            Duration::from_secs(15),
                        )
                        .await
                    {
                        Ok(clr) if clr.ok => {}
                        Ok(clr) => return err_resp(StatusCode::BAD_REQUEST, clr.body),
                        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
                    }
                }
                let vlan_id = if slot == 0 { 0 } else { slot + 1 };
                let mut newly_enabled_vlan = false;
                if vlan_id > 0
                    && let Ok(vr) = ctx
                        .app
                        .smd
                        .exec("AT+QMAP=\"VLAN\"", Priority::Interactive, Duration::from_secs(6))
                        .await
                    && vr.ok
                    && vr.body.to_ascii_uppercase().contains("+QMAP:")
                    && !qmap_vlan_is_enabled(&vr.body, vlan_id)
                {
                    prepare_qcmap_ipa_vlan_enable().await;
                    match ctx
                        .app
                        .smd
                        .exec(
                            format!("AT+QMAP=\"VLAN\",{vlan_id},\"enable\""),
                            Priority::Interactive,
                            Duration::from_secs(15),
                        )
                        .await
                    {
                        Ok(en) if en.ok => {
                            newly_enabled_vlan = true;
                        }
                        Ok(en) => return err_resp(StatusCode::BAD_REQUEST, en.body),
                        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
                    }
                }
                let cmd = format!("AT+QMAP=\"MPDN_rule\",{slot},1,{vlan_id},1,1,\"{m}\"");
                match ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(15)).await {
                    Ok(r) if r.ok => Json(serde_json::json!({ "status": "success" })).into_response(),
                    Ok(r) => {
                        if newly_enabled_vlan {
                            disable_qcmap_vlan_non_rebooting(&ctx.app.smd, vlan_id).await;
                        }
                        err_resp(StatusCode::BAD_REQUEST, r.body)
                    }
                    Err(e) => {
                        if newly_enabled_vlan {
                            disable_qcmap_vlan_non_rebooting(&ctx.app.smd, vlan_id).await;
                        }
                        err_resp(StatusCode::BAD_GATEWAY, e)
                    }
                }
            } else {
                let pre = ctx
                    .app
                    .smd
                    .exec("AT+QMAP=\"MPDN_rule\"", Priority::Interactive, Duration::from_secs(6))
                    .await;
                if let Ok(ref pr) = pre
                    && pr.ok
                    && mpdn_slot_is_empty(&pr.body, slot)
                {
                    return Json(serde_json::json!({ "status": "success" })).into_response();
                }
                let prev_vlan = pre.as_ref().ok().filter(|r| r.ok).and_then(|r| mpdn_slot_vlan(&r.body, slot));
                let cmd = format!("AT+QMAP=\"MPDN_rule\",{slot}");
                let clear_res = ctx.app.smd.exec(cmd, Priority::Interactive, Duration::from_secs(15)).await;
                let cleared = match clear_res {
                    Ok(r) if r.ok => true,
                    Ok(r) => {
                        let already_empty = ctx
                            .app
                            .smd
                            .exec("AT+QMAP=\"MPDN_rule\"", Priority::Interactive, Duration::from_secs(6))
                            .await
                            .is_ok_and(|post| post.ok && mpdn_slot_is_empty(&post.body, slot));
                        if !already_empty {
                            return err_resp(StatusCode::BAD_REQUEST, r.body);
                        }
                        true
                    }
                    Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
                };
                if cleared && slot > 0 {
                    let vlan_id = prev_vlan.filter(|v| *v >= 2).unwrap_or(slot + 1);
                    if let (Ok(post_mpdn), Ok(vr)) = (
                        ctx.app
                            .smd
                            .exec("AT+QMAP=\"MPDN_rule\"", Priority::Interactive, Duration::from_secs(6))
                            .await,
                        ctx.app
                            .smd
                            .exec("AT+QMAP=\"VLAN\"", Priority::Interactive, Duration::from_secs(6))
                            .await,
                    ) && post_mpdn.ok
                        && vr.ok
                        && vr.body.to_ascii_uppercase().contains("+QMAP:")
                        && qmap_vlan_is_enabled(&vr.body, vlan_id)
                        && !mpdn_vlan_used_by_other_slot(&post_mpdn.body, slot, vlan_id)
                    {
                        disable_qcmap_vlan_non_rebooting(&ctx.app.smd, vlan_id).await;
                    }
                }
                Json(serde_json::json!({ "status": "success" })).into_response()
            }
        }
        NetworkMutateReq::EthLimit { limit } => {
            let adv = match limit.as_str() {
                "auto" => None,
                "10" => Some("0x003"),
                "100" => Some("0x00f"),
                "1000" => Some("0x02f"),
                _ => return err_resp(StatusCode::BAD_REQUEST, "Invalid Ethernet limit"),
            };
            if matches!(limit.as_str(), "10" | "100" | "1000")
                && let Ok(info) = run_cmd("ethtool", &["eth0"], Duration::from_secs(4)).await
                && let Err(msg) = check_partner_speed_limit(&info, &limit)
            {
                return err_resp(StatusCode::BAD_REQUEST, msg);
            }
            let res = match adv {
                None => match run_cmd("ethtool", &["-s", "eth0", "autoneg", "on", "advertise", "0x80000000002f"], Duration::from_secs(4)).await {
                    Ok(out) => Ok(out),
                    Err(_) => run_cmd("ethtool", &["-s", "eth0", "autoneg", "on"], Duration::from_secs(4)).await,
                },
                Some(h) => run_cmd("ethtool", &["-s", "eth0", "advertise", h, "autoneg", "on"], Duration::from_secs(4)).await,
            };
            if let Err(e) = res {
                return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            let _ = run_cmd("ethtool", &["-r", "eth0"], Duration::from_secs(3)).await;
            ensure_uci_config_file("cellcore").await;
            let _ = uci_set("cellcore.eth_link", "eth_link").await;
            let _ = uci_set("cellcore.eth_link.speed_limit", &limit).await;
            let _ = uci_commit("cellcore").await;
            let snap = {
                let mut s = ctx.app.settings.write().await;
                s.eth_link_speed = limit;
                s.clone()
            };
            let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
            Json(serde_json::json!({ "status": "success" })).into_response()
        }
        NetworkMutateReq::Ttl { enabled, ttl, hl } => {
            if enabled && (!(1..=255).contains(&ttl) || !(1..=255).contains(&hl)) {
                return err_resp(StatusCode::BAD_REQUEST, "TTL and HL must be 1..255");
            }
            for (bin, flag) in [("iptables", "--ttl-set"), ("ip6tables", "--hl-set")] {
                let target = if bin == "iptables" { "TTL" } else { "HL" };
                for _ in 0..8 {
                    let Some(old) = read_live_mangle_val(bin, flag) else { break };
                    if run_cmd(bin, &["-t", "mangle", "-D", "POSTROUTING", "-o", "rmnet+", "-j", target, flag, &old.to_string()], Duration::from_secs(3))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            if enabled {
                let script = format!(
                    "iptables -t mangle -C POSTROUTING -o rmnet+ -j TTL --ttl-set {ttl} 2>/dev/null || iptables -t mangle -A POSTROUTING -o rmnet+ -j TTL --ttl-set {ttl}\n\
                     ip6tables -t mangle -C POSTROUTING -o rmnet+ -j HL --hl-set {hl} 2>/dev/null || ip6tables -t mangle -A POSTROUTING -o rmnet+ -j HL --hl-set {hl}\n"
                );
                let _ = crate::state::atomic_write(Path::new("/etc/firewall.user.ttl"), script.as_bytes(), 0o644);
                let _ = run_cmd("iptables", &["-t", "mangle", "-A", "POSTROUTING", "-o", "rmnet+", "-j", "TTL", "--ttl-set", &ttl.to_string()], Duration::from_secs(3)).await;
                let _ = run_cmd("ip6tables", &["-t", "mangle", "-A", "POSTROUTING", "-o", "rmnet+", "-j", "HL", "--hl-set", &hl.to_string()], Duration::from_secs(3)).await;
                let mut s = ctx.app.settings.write().await;
                s.ttl_value = Some(ttl);
                s.hl_value = Some(hl);
            } else {
                let _ = fs::remove_file(crate::paths::p("/etc/firewall.user.ttl"));
                let mut s = ctx.app.settings.write().await;
                s.ttl_value = None;
                s.hl_value = None;
            }
            Json(serde_json::json!({ "status": "success" })).into_response()
        }
        NetworkMutateReq::Mtu { enabled, mtu } => {
            let val = if enabled {
                if !(1280..=1500).contains(&mtu) {
                    return err_resp(StatusCode::BAD_REQUEST, "MTU must be 1280..1500");
                }
                mtu
            } else {
                let mapped_mtu = crate::paths::p("/etc/firewall.user.mtu");
                let _ = tokio::task::spawn_blocking(move || fs::remove_file(&mapped_mtu)).await;
                1500
            };
            let ifaces = tokio::task::spawn_blocking(detect_wan_rmnet_ifaces_blocking)
                .await
                .unwrap_or_default();
            // Always clean stale TCPMSS clamp rules before applying updated ones (or disabling).
            clean_live_tcpmss_rules(&ifaces).await;
            let val_s = val.to_string();
            for iface in &ifaces {
                let _ = run_cmd("ip", &["link", "set", iface, "mtu", &val_s], Duration::from_secs(3)).await;
            }
            if enabled {
                let script = crate::reconcile::build_mtu_firewall_script(&ifaces, u32::from(val));
                if !script.is_empty() {
                    let mapped_mtu = crate::paths::p("/etc/firewall.user.mtu");
                    let script_bytes = script.into_bytes();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::state::atomic_write(Path::new(&mapped_mtu), &script_bytes, 0o644)
                    })
                    .await;
                }
                if (1280..1500).contains(&val) {
                    apply_live_tcpmss_rules(&ifaces, u32::from(val)).await;
                }
                let snap = {
                    let mut s = ctx.app.settings.write().await;
                    s.mtu_value = Some(val);
                    s.clone()
                };
                let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
            } else {
                let snap = {
                    let mut s = ctx.app.settings.write().await;
                    s.mtu_value = None;
                    s.clone()
                };
                let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
            }
            Json(serde_json::json!({ "status": "success" })).into_response()
        }
        NetworkMutateReq::Dns { enabled, nic, servers } => {
            let iface = nic.unwrap_or_else(|| "lan".into());
            if !is_valid_uci_ident(&iface) {
                return err_resp(StatusCode::BAD_REQUEST, "Invalid interface name");
            }
            if enabled {
                let list = servers.unwrap_or_default();
                if list.is_empty() || !list.iter().all(|ip| ip.parse::<Ipv4Addr>().is_ok()) {
                    return err_resp(StatusCode::BAD_REQUEST, "Valid IPv4 DNS server(s) required");
                }
                let opt = format!("6,{}", list.join(","));
                let _ = uci_set(&format!("dhcp.{iface}.dhcp_option"), &opt).await;
                let _ = uci_commit("dhcp").await;
                ctx.app.settings.write().await.custom_dns = Some(list);
            } else {
                let _ = run_cmd("uci", &["-q", "delete", &format!("dhcp.{iface}.dhcp_option")], Duration::from_secs(3)).await;
                let _ = uci_commit("dhcp").await;
                ctx.app.settings.write().await.custom_dns = None;
            }
            let _ = run_cmd("/etc/init.d/dnsmasq", &["restart"], Duration::from_secs(5)).await;
            Json(serde_json::json!({ "status": "success" })).into_response()
        }
        NetworkMutateReq::TailscaleToggle { enabled } => {
            if !Path::new(&crate::paths::p(TAILSCALE_INIT)).exists() {
                return err_resp(
                    StatusCode::CONFLICT,
                    "Tailscale is not installed. Install the tailscale package (System › Software) first, then start it here.",
                );
            }
            let action = if enabled { "start" } else { "stop" };
            match run_cmd(TAILSCALE_INIT, &[action], Duration::from_secs(6)).await {
                Ok(_) => {
                    for _ in 0..20 {
                        let running = run_cmd(TAILSCALE_INIT, &["status"], Duration::from_secs(2))
                            .await
                            .map(|s| s.trim() == "running")
                            .unwrap_or(false);
                        if running == enabled {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                    Json(serde_json::json!({ "status": "success" })).into_response()
                }
                Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Tailscale {action} failed: {e}")),
            }
        }
    }
}

pub async fn get_data_usage(State(ctx): State<HttpCtx>) -> Response {
    Json(ctx.app.data_usage.read().await.clone()).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataUsageConfigReq {
    billing_cycle_day: Option<u8>,
    /// absent = keep, null = clear, number = set
    #[serde(default, deserialize_with = "deserialize_present")]
    quota_bytes: Option<Option<u64>>,
}

fn deserialize_present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

pub async fn post_data_usage(State(ctx): State<HttpCtx>, Json(body): Json<DataUsageConfigReq>) -> Response {
    let snap = {
        let mut u = ctx.app.data_usage.write().await;
        if let Some(d) = body.billing_cycle_day {
            // 29-31 are valid: short months start the cycle on their last day.
            u.billing_cycle_day = d.clamp(1, 31);
        }
        if let Some(q) = body.quota_bytes {
            u.quota_bytes = q;
        }
        u.clone()
    };
    let _ = save_json_compact_atomic_async(DATA_USAGE_PATH, snap.clone(), 0o600).await;
    let _ = save_json_compact_tmpfs_async(DATA_USAGE_TMP_PATH, snap.clone(), 0o600).await;
    Json(serde_json::json!({ "status": "success", "dataUsage": snap })).into_response()
}

pub async fn delete_data_usage(State(ctx): State<HttpCtx>) -> Response {
    let snap = {
        let mut u = ctx.app.data_usage.write().await;
        u.daily.clear();
        u.monthly.clear();
        u.clone()
    };
    let _ = save_json_compact_atomic_async(DATA_USAGE_PATH, snap.clone(), 0o600).await;
    let _ = save_json_compact_tmpfs_async(DATA_USAGE_TMP_PATH, snap.clone(), 0o600).await;
    Json(serde_json::json!({ "status": "success", "dataUsage": snap })).into_response()
}

pub async fn get_health(State(ctx): State<HttpCtx>) -> Response {
    let native_mode = crate::dataplane::is_native_mode();
    let mut cmds = vec![
        ("AT+CPIN?".into(), Duration::from_secs(4)),
        ("AT+C5GREG=2;+C5GREG?".into(), Duration::from_secs(4)),
        ("AT+CEREG=2;+CEREG?".into(), Duration::from_secs(4)),
    ];
    if !native_mode {
        cmds.push(("AT+QMAP=\"WWAN\"".into(), Duration::from_secs(4)));
    }
    let res = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await.ok();
    let b = |i: usize| -> String {
        res.as_ref()
            .and_then(|v| v.get(i))
            .and_then(|r| r.as_ref().ok())
            .map(|r| r.body.clone())
            .unwrap_or_default()
    };
    let cpin = b(0).contains("READY");
    let c5greg = parse_reg_state(&b(1));
    let cereg = parse_reg_state(&b(2));
    let wwan_up = if native_mode {
        tokio::task::spawn_blocking(crate::netlink::detect_active_rmnet_wan_live)
            .await
            .ok()
            .flatten()
            .is_some()
    } else {
        b(3).contains("1,")
    };
    let wwan_label = if native_mode { "Native WWAN Session" } else { "QMAP WWAN Session" };
    let icmp_ok = icmp_ping_once("8.8.8.8", 9001).await.is_ok();
    let reg_ok = matches!(c5greg.stat, Some(1) | Some(5)) || matches!(cereg.stat, Some(1) | Some(5));
    let reg_detail = if c5greg.stat.is_some() { c5greg.label } else { cereg.label };

    let checks = vec![
        serde_json::json!({ "label": "SIM Card Status", "ok": cpin, "detail": if cpin { "CPIN READY" } else { "Check SIM" } }),
        serde_json::json!({ "label": "5G NR Registration", "ok": reg_ok, "detail": reg_detail }),
        serde_json::json!({ "label": wwan_label, "ok": wwan_up, "detail": if wwan_up { "Data Bearer UP" } else { "Disconnected" } }),
        serde_json::json!({ "label": "Upstream Reachability", "ok": icmp_ok, "detail": if icmp_ok { "8.8.8.8 Reachable" } else { "ICMP Unreachable" } }),
    ];
    let passed = checks
        .iter()
        .filter(|c| c.get("ok").and_then(|x| x.as_bool()) == Some(true))
        .count();
    Json(serde_json::json!({ "checks": checks, "passed": passed, "total": 4 })).into_response()
}

pub async fn get_quecwatch(State(ctx): State<HttpCtx>) -> Response {
    let s = ctx.app.settings.read().await.clone();
    let rt = ctx.app.quecwatch.read().await.clone();
    Json(serde_json::json!({
        "enabled": s.quecwatch_enabled,
        "config": {
            "pingTarget": s.quecwatch_target,
            "pingInterval": s.quecwatch_interval_sec,
            "pingFailures": s.quecwatch_failures,
            "maxRetries": s.quecwatch_max_retries,
            "connectionRefresh": s.quecwatch_connection_refresh,
            "autoSimFailover": s.quecwatch_auto_sim_failover,
            "preferredSimSlot": s.preferred_sim_slot,
            "simFailbackMins": s.sim_failback_mins,
            "highLatencyMonitoring": s.quecwatch_high_latency,
            "latencyCeiling": s.quecwatch_latency_ceiling,
        },
        "runtime": rt,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkWatchUpdateReq {
    enabled: bool,
    ping_target: Option<String>,
    ping_interval: Option<u64>,
    ping_failures: Option<u32>,
    max_retries: Option<u32>,
    connection_refresh: Option<bool>,
    auto_sim_failover: Option<bool>,
    #[serde(default, alias = "preferred_sim_slot")]
    preferred_sim_slot: Option<u8>,
    #[serde(default, alias = "sim_failback_mins")]
    sim_failback_mins: Option<u64>,
    high_latency_monitoring: Option<bool>,
    latency_ceiling: Option<u64>,
}

pub async fn post_quecwatch(State(ctx): State<HttpCtx>, Json(body): Json<LinkWatchUpdateReq>) -> Response {
    let target = match body.ping_target.as_deref().filter(|x| !x.trim().is_empty()).map(clean_ping_target) {
        Some(Ok(h)) => Some(h),
        Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, e),
        None => None,
    };
    if let Some(slot) = body.preferred_sim_slot
        && slot > 2
    {
        return err_resp(StatusCode::BAD_REQUEST, "preferredSimSlot must be 0 (none), 1, or 2");
    }
    let snap = {
        let mut s = ctx.app.settings.write().await;
        s.quecwatch_enabled = body.enabled;
        if let Some(t) = target {
            s.quecwatch_target = t;
        }
        if let Some(i) = body.ping_interval {
            s.quecwatch_interval_sec = i.clamp(15, 3600);
        }
        if let Some(f) = body.ping_failures {
            s.quecwatch_failures = f.clamp(1, 20);
        }
        if let Some(r) = body.max_retries {
            s.quecwatch_max_retries = r.clamp(1, 20);
        }
        if let Some(v) = body.connection_refresh {
            s.quecwatch_connection_refresh = v;
        }
        if let Some(v) = body.auto_sim_failover {
            s.quecwatch_auto_sim_failover = v;
        }
        if let Some(slot) = body.preferred_sim_slot {
            s.preferred_sim_slot = slot;
        }
        if let Some(mins) = body.sim_failback_mins {
            s.sim_failback_mins = mins.clamp(1, 1440);
        }
        if let Some(v) = body.high_latency_monitoring {
            s.quecwatch_high_latency = v;
        }
        if let Some(v) = body.latency_ceiling {
            s.quecwatch_latency_ceiling = v.clamp(20, 2000);
        }
        s.clone()
    };
    let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
    Json(serde_json::json!({ "status": "success" })).into_response()
}

#[derive(Deserialize)]
pub struct WindowQuery {
    window: Option<String>,
}

pub async fn get_latency(State(ctx): State<HttpCtx>, Query(q): Query<WindowQuery>) -> Response {
    let w = q.window.as_deref().unwrap_or("realtime");
    let data = match w {
        "hourly" => ctx.app.ping_hourly.read().await.iter().cloned().collect::<Vec<_>>(),
        "twelvehour" => ctx.app.ping_twelvehour.read().await.iter().cloned().collect::<Vec<_>>(),
        "daily" => ctx.app.ping_daily.read().await.iter().cloned().collect::<Vec<_>>(),
        _ => ctx.app.ping_realtime.read().await.iter().cloned().collect::<Vec<_>>(),
    };
    let s = ctx.app.settings.read().await.clone();
    Json(serde_json::json!({
        "window": w,
        "data": data,
        "config": {
            "enabled": s.ping_enabled,
            "host": s.ping_host,
            "interval": s.ping_interval_sec,
            "keepAlive": s.keep_alive_enabled,
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyCfgReq {
    enabled: Option<bool>,
    host: Option<String>,
    interval: Option<u64>,
    keep_alive: Option<bool>,
}

/// Ping / health-check target: a host name or an IP literal, never a flag.
pub fn clean_ping_target(raw: &str) -> Result<String, String> {
    let h = raw.trim();
    if crate::admin::validate::is_net_target(h) {
        Ok(h.to_string())
    } else {
        Err("Host must be a host name, IPv4 or IPv6 address".into())
    }
}

pub async fn post_latency(State(ctx): State<HttpCtx>, Json(body): Json<LatencyCfgReq>) -> Response {
    let host = match body.host.as_deref().filter(|x| !x.trim().is_empty()).map(clean_ping_target) {
        Some(Ok(h)) => Some(h),
        Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, e),
        None => None,
    };
    let snap = {
        let mut s = ctx.app.settings.write().await;
        if let Some(v) = body.enabled {
            s.ping_enabled = v;
        }
        if let Some(h) = host {
            s.ping_host = h;
        }
        if let Some(i) = body.interval {
            s.ping_interval_sec = i.clamp(2, 60);
        }
        if let Some(k) = body.keep_alive {
            s.keep_alive_enabled = k;
        }
        s.clone()
    };
    let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
    Json(serde_json::json!({ "status": "success" })).into_response()
}

pub async fn get_speedtest_servers() -> Response {
    Json(serde_json::json!({ "status": "success", "servers": [] })).into_response()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpeedtestStartReq {
    #[allow(dead_code)]
    server_id: Option<i64>,
    engine: Option<String>,
}

pub async fn post_speedtest_start(
    State(ctx): State<HttpCtx>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req = if body.is_empty() {
        SpeedtestStartReq::default()
    } else {
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mime = ct.split(';').next().unwrap_or("").trim();
        if !mime.eq_ignore_ascii_case("application/json")
            && !mime.to_ascii_lowercase().ends_with("+json")
        {
            return err_resp(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            );
        }
        match serde_json::from_slice::<SpeedtestStartReq>(&body) {
            Ok(v) => v,
            Err(e) => return err_resp(StatusCode::BAD_REQUEST, format!("Invalid JSON body: {e}")),
        }
    };
    if req.server_id.is_some_and(|id| id <= 0) {
        return err_resp(StatusCode::BAD_REQUEST, "serverId must be a positive server number");
    }
    if let Some(other) = req.engine.as_deref().map(str::trim).filter(|s| !s.is_empty())
        && !matches!(other, "auto" | "native")
    {
        return err_resp(
            StatusCode::BAD_REQUEST,
            format!("Unsupported speedtest engine {other:?} (CellCore uses the built-in native engine)"),
        );
    }
    match start_speedtest(ctx.app.clone()).await {
        Ok(()) => Json(serde_json::json!({ "status": "started" })).into_response(),
        Err(e) => err_resp(StatusCode::CONFLICT, e),
    }
}

pub async fn post_speedtest_stop(State(ctx): State<HttpCtx>) -> Response {
    let _ = stop_speedtest(&ctx.app).await;
    Json(serde_json::json!({ "status": "stopped" })).into_response()
}

pub async fn get_speedtest_history(State(ctx): State<HttpCtx>) -> Response {
    let live = ctx.app.speedtest_live.read().await.clone();
    let history = ctx.app.speedtest_history.read().await.clone();
    Json(serde_json::json!({ "live": live, "history": history })).into_response()
}

pub async fn delete_speedtest_history(State(ctx): State<HttpCtx>) -> Response {
    let snap = {
        let mut hist = ctx.app.speedtest_history.write().await;
        hist.clear();
        hist.clone()
    };
    let _ = save_json_atomic_async(SPEEDTEST_HISTORY_PATH, snap, 0o600).await;
    Json(serde_json::json!({ "status": "success" })).into_response()
}

pub async fn get_sms_inbox(State(ctx): State<HttpCtx>) -> Response {
    let cmds = vec![
        ("AT+CMGF=0".into(), Duration::from_secs(4)),
        ("AT+CPMS=\"ME\",\"ME\",\"ME\"".into(), Duration::from_secs(4)),
        ("AT+CMGL=4".into(), Duration::from_secs(10)),
    ];
    let Ok(res) = ctx.app.smd.exec_batch(cmds, Priority::Interactive).await else {
        return err_resp(StatusCode::BAD_GATEWAY, "Failed to query SMS inbox");
    };
    let cmgl = res.get(2).and_then(|r| r.as_ref().ok()).map(|r| r.body.as_str()).unwrap_or("");
    let msgs = parse_cmgl_response(cmgl);
    Json(serde_json::json!({ "messages": msgs })).into_response()
}

#[derive(Deserialize)]
pub struct SendSmsReq {
    phone: String,
    message: String,
}

pub async fn post_sms_send(State(ctx): State<HttpCtx>, Json(body): Json<SendSmsReq>) -> Response {
    let ref_byte = (now_secs() & 0xFF) as u8;
    let pdus = match encode_submit_pdus(&body.phone, &body.message, ref_byte) {
        Ok(p) => p,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
    };
    let _ = ctx.app.smd.exec("AT+CMGF=0", Priority::Interactive, Duration::from_secs(4)).await;
    for pdu in &pdus {
        let cmgs = format!("AT+CMGS={}", pdu.tpdu_len);
        match ctx
            .app
            .smd
            .exec_pdu(cmgs, &pdu.hex_pdu, Priority::Interactive, Duration::from_secs(20))
            .await
        {
            Ok(r) if r.ok => {}
            Ok(r) => return err_resp(StatusCode::BAD_GATEWAY, format!("Modem SMS error: {}", r.body)),
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, e),
        }
    }
    Json(serde_json::json!({ "status": "success", "segments": pdus.len() })).into_response()
}

#[derive(Deserialize)]
pub struct DeleteSmsReq {
    indices: Vec<i32>,
}

pub async fn delete_sms(State(ctx): State<HttpCtx>, Json(body): Json<DeleteSmsReq>) -> Response {
    let _ = ctx.app.smd.exec("AT+CMGF=0", Priority::Interactive, Duration::from_secs(4)).await;
    for idx in body.indices {
        if idx >= 0 {
            let _ = ctx
                .app
                .smd
                .exec(format!("AT+CMGD={idx}"), Priority::Interactive, Duration::from_secs(5))
                .await;
        }
    }
    Json(serde_json::json!({ "status": "success" })).into_response()
}

pub async fn get_system_internals(State(ctx): State<HttpCtx>) -> Response {
    Json(ctx.app.internals.read().await.clone()).into_response()
}

#[derive(Deserialize)]
pub struct UsbGadgetReq {
    enabled: bool,
}

pub async fn post_usb_gadget(State(ctx): State<HttpCtx>, Json(body): Json<UsbGadgetReq>) -> Response {
    match set_usb_gadget_enabled(body.enabled) {
        Ok(udc) => {
            ctx.app.internals.write().await.usb_udc = udc.clone();
            Json(serde_json::json!({ "status": "success", "usbUdc": udc })).into_response()
        }
        Err(e) => err_resp(StatusCode::BAD_REQUEST, e),
    }
}

pub async fn post_reconcile(State(ctx): State<HttpCtx>) -> Response {
    let enf = ctx.enforce_uhttpd_loopback;
    let report = tokio::task::spawn_blocking(move || run_boot_reconcile(enf))
        .await
        .unwrap_or_default();
    ctx.app.internals.write().await.last_reconcile = Some(report.clone());
    Json(serde_json::json!({ "status": "success", "report": report })).into_response()
}

#[derive(Deserialize)]
pub struct LogsQuery {
    source: Option<String>,
    lines: Option<usize>,
    search: Option<String>,
}

pub async fn get_logs(State(ctx): State<HttpCtx>, Query(q): Query<LogsQuery>) -> Response {
    let limit = q.lines.unwrap_or(100).clamp(10, 500);
    let src = q.source.as_deref().unwrap_or("system");
    let raw_lines: Vec<String> = if src == "quecmanager" {
        ctx.app.daemon_logs.read().await.iter().cloned().collect()
    } else {
        run_cmd("logread", &["-l", &limit.to_string()], Duration::from_secs(4))
            .await
            .unwrap_or_default()
            .lines()
            .map(redact_sensitive)
            .collect()
    };
    let needle = q.search.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let filtered: Vec<String> = raw_lines
        .into_iter()
        .filter(|l| needle.is_empty() || l.to_ascii_lowercase().contains(&needle))
        .rev()
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Json(serde_json::json!({ "logs": filtered, "source": src })).into_response()
}

pub async fn get_maintenance(State(ctx): State<HttpCtx>) -> Response {
    let s = ctx.app.settings.read().await.clone();
    let has_smtp = Path::new(&crate::paths::p("/etc/msmtprc")).exists();
    let recip = fs::read_to_string(crate::paths::p("/etc/cellcore_alert_recipient"))
        .unwrap_or_default()
        .trim()
        .to_string();
    Json(serde_json::json!({
        "scheduledReboot": {
            "enabled": s.scheduled_reboot_enabled,
            "time": s.scheduled_reboot_time,
            "days": s.scheduled_reboot_days,
        },
        "alerts": {
            "smtpConfigured": has_smtp,
            "recipient": recip,
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceReq {
    scheduled_reboot_enabled: Option<bool>,
    scheduled_reboot_time: Option<String>,
    scheduled_reboot_days: Option<Vec<String>>,
    smtp_sender: Option<String>,
    smtp_password: Option<String>,
    smtp_recipient: Option<String>,
}

pub const WEEKDAYS: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

/// Scheduled-reboot days: lower-case weekday names, each at most once.
pub fn clean_reboot_days(days: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for d in days {
        let l = d.trim().to_ascii_lowercase();
        if !WEEKDAYS.contains(&l.as_str()) {
            return Err(format!("Unknown reboot day {:?} (use weekday names, e.g. sunday)", d.chars().take(16).collect::<String>()));
        }
        if !out.contains(&l) {
            out.push(l);
        }
    }
    Ok(out)
}

pub async fn post_maintenance(State(ctx): State<HttpCtx>, Json(body): Json<MaintenanceReq>) -> Response {
    // Validate everything before writing anything.
    let time = match body.scheduled_reboot_time.as_deref() {
        Some(t) => match crate::profiles::parse_hhmm(t) {
            Some(m) => Some(format!("{:02}:{:02}", m / 60, m % 60)),
            None => return err_resp(StatusCode::BAD_REQUEST, "Reboot time must be HH:MM (24 h)"),
        },
        None => None,
    };
    let days = match body.scheduled_reboot_days.as_deref().map(clean_reboot_days) {
        Some(Ok(d)) => Some(d),
        Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, e),
        None => None,
    };
    if body.scheduled_reboot_enabled == Some(true) && days.as_ref().is_some_and(|d| d.is_empty()) {
        return err_resp(StatusCode::BAD_REQUEST, "Pick at least one day for the scheduled reboot");
    }
    let smtp = match (body.smtp_sender.as_deref(), body.smtp_password.as_deref(), body.smtp_recipient.as_deref()) {
        (None, None, None) => None,
        (Some(sender), Some(pass), Some(recip)) => {
            let cfg = match build_msmtprc(sender, pass) {
                Ok(c) => c,
                Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
            };
            let recip = recip.trim();
            if !is_plain_email(recip) {
                return err_resp(StatusCode::BAD_REQUEST, "Invalid recipient address");
            }
            Some((cfg, recip.to_string()))
        }
        _ => return err_resp(StatusCode::BAD_REQUEST, "SMTP needs sender, password and recipient together"),
    };

    if let Some(en) = body.scheduled_reboot_enabled {
        let snap = {
            let mut s = ctx.app.settings.write().await;
            s.scheduled_reboot_enabled = en;
            if let Some(t) = time {
                s.scheduled_reboot_time = t;
            }
            if let Some(d) = days {
                s.scheduled_reboot_days = d;
            }
            s.clone()
        };
        let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap, 0o600).await;
    }
    if let Some((cfg, recip)) = smtp {
        // 0600 from creation: the file holds the SMTP password.
        if let Err(e) = crate::state::atomic_write(Path::new("/etc/msmtprc"), cfg.as_bytes(), 0o600) {
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
        let _ = crate::state::atomic_write(
            Path::new("/etc/cellcore_alert_recipient"),
            format!("{recip}\n").as_bytes(),
            0o600,
        );
    }
    Json(serde_json::json!({ "status": "success" })).into_response()
}

/// A bare address: no whitespace/control characters (so nothing can start a
/// new msmtprc directive), one '@', sane length.
pub fn is_plain_email(s: &str) -> bool {
    s.len() <= 254
        && s.matches('@').count() == 1
        && !s.starts_with('@')
        && !s.ends_with('@')
        && !s.starts_with('-')
        && s.chars().all(|c| !c.is_whitespace() && !c.is_control() && !matches!(c, '"' | '#' | '\\' | '\'' | '`' | ',' | ';' | '<' | '>' | '(' | ')'))
}

pub fn build_msmtprc(sender: &str, password: &str) -> Result<String, String> {
    let sender = sender.trim();
    if !is_plain_email(sender) {
        return Err("Invalid sender address".into());
    }
    if password.is_empty() || password.len() > 256 || password.chars().any(|c| c.is_control()) {
        return Err("Invalid SMTP password".into());
    }
    if password != password.trim() {
        return Err("SMTP password must not start or end with whitespace".into());
    }
    Ok(format!(
        "defaults\nauth on\ntls on\ntls_trust_file /etc/ssl/certs/ca-certificates.crt\n\naccount default\nhost smtp.gmail.com\nport 587\nfrom {sender}\nuser {sender}\npassword {password}\n"
    ))
}

pub async fn post_reboot(State(ctx): State<HttpCtx>) -> Response {
    crate::obs::set_boot_reason("reboot from the web UI");
    crate::telemetry::flush_persistent_state(&ctx.app).await;
    tokio::spawn(async {
        let _ = run_cmd("sync", &[], Duration::from_secs(3)).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = run_cmd("/sbin/reboot", &[], Duration::from_secs(3)).await;
    });
    Json(serde_json::json!({ "status": "rebooting" })).into_response()
}

pub async fn get_ota(State(ctx): State<HttpCtx>) -> Response {
    Json(crate::ota::ota_info(&ctx.app.build_package, &ctx.app.version).await).into_response()
}

#[derive(Deserialize)]
pub struct OtaReq {
    action: String,
    #[serde(default)]
    version: Option<String>,
}

pub async fn post_ota(State(ctx): State<HttpCtx>, Json(body): Json<OtaReq>) -> Response {
    match body.action.as_str() {
        "check" => {
            if crate::ota::upgrade_running() {
                return err_resp(StatusCode::CONFLICT, "An upgrade is running; check again when it finishes");
            }
            let rec = crate::ota::check_feed().await;
            let mut info = crate::ota::ota_info(&ctx.app.build_package, &ctx.app.version).await;
            if let Some(obj) = info.as_object_mut() {
                obj.insert("status".into(), serde_json::json!(if rec.ok { "success" } else { "error" }));
                obj.insert("check".into(), serde_json::to_value(&rec).unwrap_or_default());
            }
            if rec.ok {
                Json(info).into_response()
            } else {
                let msg = rec.error.clone().unwrap_or_else(|| "Feed check failed".into());
                (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "status": "error", "error": msg, "info": info }))).into_response()
            }
        }
        "upgrade" => match crate::ota::start_upgrade(&ctx.app.build_package, body.version.as_deref()).await {
            Ok(st) => {
                ctx.app.push_daemon_log(format!("OTA upgrade started: {} -> {}", st.from, st.target));
                (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "started", "upgrade": st }))).into_response()
            }
            Err(e) => err_resp(StatusCode::CONFLICT, e),
        },
        _ => err_resp(StatusCode::BAD_REQUEST, "Unknown OTA action"),
    }
}

pub async fn get_settings(State(ctx): State<HttpCtx>) -> Response {
    Json(ctx.app.settings.read().await.clone()).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsReq {
    temperature_unit: Option<String>,
    measurement_unit: Option<String>,
    https_redirect: Option<bool>,
    antenna_labels: Option<[String; 4]>,
}

pub async fn post_settings(State(ctx): State<HttpCtx>, Json(body): Json<SettingsReq>) -> Response {
    let snap = {
        let mut s = ctx.app.settings.write().await;
        if let Some(t) = body.temperature_unit
            && matches!(t.as_str(), "celsius" | "fahrenheit")
        {
            s.temperature_unit = t;
        }
        if let Some(m) = body.measurement_unit
            && matches!(m.as_str(), "mi" | "km")
        {
            s.measurement_unit = m;
        }
        if let Some(r) = body.https_redirect {
            s.https_redirect = r;
            ctx.app
                .https_redirect_cached
                .store(r, std::sync::atomic::Ordering::Release);
        }
        if let Some(labels) = body.antenna_labels {
            s.antenna_labels = labels.map(|l| crate::state::sanitize_antenna_label(&l));
        }
        s.clone()
    };
    let etc_dir = crate::paths::p(ETC_QM_DIR);
    let _ = tokio::task::spawn_blocking(move || fs::create_dir_all(&etc_dir)).await;
    let _ = save_json_atomic_async(SETTINGS_JSON_PATH, snap.clone(), 0o600).await;
    Json(serde_json::json!({ "status": "success", "settings": snap })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeReq {
    current_password: String,
    new_password: String,
}

pub async fn post_change_password(
    State(ctx): State<HttpCtx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeReq>,
) -> Response {
    if body.new_password.len() > MAX_PASSWORD_LEN {
        return err_resp(
            StatusCode::BAD_REQUEST,
            format!("New password must be at most {MAX_PASSWORD_LEN} characters"),
        );
    }
    if let Err(resp) = check_root_password(&ctx, peer.ip(), &body.current_password).await {
        if resp.status() == StatusCode::UNAUTHORIZED {
            return err_resp(StatusCode::BAD_REQUEST, "Current password is incorrect");
        }
        return resp;
    }
    let cur = body.current_password.clone();
    let new_p = body.new_password.clone();
    let res = crate::paths::spawn_blocking(move || update_shadow_password("root", &cur, &new_p))
        .await
        .unwrap_or_else(|e| Err(format!("Task failed: {e}")));
    match res {
        Ok(()) => {
            let keep = extract_session_token(&headers);
            ctx.app.auth.revoke_except(keep.as_deref()).await;
            let revoked_tokens = match ctx.app.tokens.revoke_all() {
                Ok(n) => n,
                Err(e) => {
                    ctx.app.push_daemon_log(format!(
                        "Root password changed, but failed to persist API token revocation: {e}"
                    ));
                    0
                }
            };
            if revoked_tokens > 0 {
                ctx.app.push_daemon_log(format!(
                    "Root password changed: revoked {revoked_tokens} API token(s) and other sessions"
                ));
            }
            Json(serde_json::json!({ "status": "success", "revokedTokens": revoked_tokens })).into_response()
        }
        Err(e) => err_resp(StatusCode::BAD_REQUEST, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn data_usage_post_without_quota_keeps_it() {
        let keep: DataUsageConfigReq = serde_json::from_str(r#"{"billingCycleDay":5}"#).unwrap();
        assert_eq!(keep.quota_bytes, None);
        let clear: DataUsageConfigReq = serde_json::from_str(r#"{"quotaBytes":null}"#).unwrap();
        assert_eq!(clear.quota_bytes, Some(None));
        let set: DataUsageConfigReq = serde_json::from_str(r#"{"quotaBytes":1073741824}"#).unwrap();
        assert_eq!(set.quota_bytes, Some(Some(1_073_741_824)));
    }

    #[test]
    fn msmtprc_rejects_injection() {
        let ok = build_msmtprc("me@gmail.com", "app pass word").unwrap();
        assert!(ok.contains("user me@gmail.com\npassword app pass word\n"));
        assert!(build_msmtprc("me@gmail.com\nhost evil.example", "x").is_err());
        assert!(build_msmtprc("me@gmail.com", "x\nhost evil.example").is_err());
        assert!(build_msmtprc("me@gmail.com", "x\rtls off").is_err());
        assert!(build_msmtprc("me @gmail.com", "x").is_err());
        assert!(!is_plain_email("a@b\nc"));
        assert!(is_plain_email("alerts@example.com"));
    }

    #[test]
    fn band_checks_follow_the_active_mode() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (l, n, sa, e) = (v(&["2"]), v(&["41"]), v(&["41"]), v(&[]));
        assert!(check_bands_cover_mode(&e, &e, &e, "AUTO", 0).is_err());
        assert!(check_bands_cover_mode(&l, &n, &sa, "AUTO", 0).is_ok());
        assert!(check_bands_cover_mode(&l, &n, &e, "AUTO", 0).is_err(), "SA active in AUTO");
        assert!(check_bands_cover_mode(&l, &n, &e, "AUTO", 1).is_ok(), "SA disabled");
        assert!(check_bands_cover_mode(&l, &e, &sa, "LTE:NR5G", 2).is_ok(), "NSA disabled");
        assert!(check_bands_cover_mode(&l, &e, &e, "LTE", 0).is_ok());
        assert!(check_bands_cover_mode(&e, &n, &sa, "LTE", 0).is_err());
        assert!(check_bands_cover_mode(&e, &e, &sa, "NR5G", 0).is_ok());
        assert!(check_bands_cover_mode(&l, &n, &e, "NR5G", 0).is_err());
        assert!(check_bands_cover_mode(&e, &e, &e, "bogus", 0).is_err(), "unknown mode is strictest");

        let policy = vec!["2".to_string(), "66".to_string()];
        assert_eq!(clean_band_list(BandRat::Lte, &v(&[" 66", "02", "66"]), Some(&policy)).unwrap(), v(&["66", "2"]));
        assert!(clean_band_list(BandRat::Lte, &v(&["7"]), Some(&policy)).is_err(), "not reported by the modem");
        assert!(clean_band_list(BandRat::Lte, &v(&["7"]), None).is_ok(), "3GPP band without a modem list");
        for bad in ["0", "109", "999", "-1", "1.5", "", "2;AT"] {
            assert!(clean_band_list(BandRat::Lte, &v(&[bad]), None).is_err(), "{bad:?}");
        }
        assert!(clean_band_list(BandRat::SaNr5g, &v(&["258"]), None).is_ok());
        // live RM551E: NSA n25 is configured but only listed under nr5g_band
        let rep = "+QNWPREFCFG: \"lte_band\",1:2:66\n+QNWPREFCFG: \"nsa_nr5g_band\",41:71\n+QNWPREFCFG: \"nr5g_band\",25:41\n+QNWPREFCFG: \"nsa_nr5g_band\",25:41";
        let nsa = modem_band_set(rep, BandRat::NsaNr5g);
        assert!(clean_band_list(BandRat::NsaNr5g, &v(&["25", "71"]), Some(&nsa)).is_ok());
        assert!(clean_band_list(BandRat::NsaNr5g, &v(&["79"]), Some(&nsa)).is_err());
        assert_eq!(modem_band_set(rep, BandRat::Lte), v(&["1", "2", "66"]));
        assert!(clean_band_list(BandRat::SaNr5g, &v(&["200"]), None).is_err());
    }

    /// Exhaustive: from every valid configuration to every requested change
    /// (mode x nr5g_disable_mode x band lists, mode / disable given or not),
    /// a change the checks accept is planned so that every intermediate state
    /// is valid too, and writing it lands exactly on the target.
    #[test]
    fn every_prefix_of_a_planned_radio_change_is_valid() {
        let modes = ["AUTO", "LTE", "NR5G", "LTE:NR5G"];
        let lists = |p: u8| -> [Vec<String>; 3] {
            [
                if p & 1 != 0 { vec!["2".into()] } else { vec![] },
                if p & 2 != 0 { vec!["41".into()] } else { vec![] },
                if p & 4 != 0 { vec!["71".into()] } else { vec![] },
            ]
        };
        let cfg = |l: &[Vec<String>; 3], m: &str, d: i32| RadioConfig { lte: l[0].clone(), nsa: l[1].clone(), sa: l[2].clone(), mode: m.into(), disable: d };
        let (mut plans, mut refused) = (0, 0);
        for sm in modes {
            for sd in 0..=2 {
                for sp in 0..8u8 {
                    let start = cfg(&lists(sp), sm, sd);
                    if start.check().is_err() {
                        continue;
                    }
                    for tm in [None, Some("AUTO"), Some("LTE"), Some("NR5G"), Some("LTE:NR5G")] {
                        for td in [None, Some(0), Some(1), Some(2)] {
                            for tp in 0..8u8 {
                                let want = lists(tp);
                                let target = cfg(&want, tm.unwrap_or(sm), td.unwrap_or(sd));
                                if target.check().is_err() {
                                    refused += 1;
                                    continue;
                                }
                                let steps = plan_radio_steps(&start, Some(&want), tm, td);
                                let mut s = start.clone();
                                for step in &steps {
                                    s.apply(step);
                                    assert!(s.check().is_ok(), "{start:?} -> {target:?}: after {step:?} {s:?} via {steps:?}");
                                }
                                assert_eq!(s, target, "{steps:?}");
                                plans += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(plans > 1000 && refused > 1000, "{plans} planned, {refused} refused");
        // NR5G with SA disabled has no RAT at all, whatever the bands
        let all = lists(7);
        assert!(cfg(&all, "NR5G", 1).check().is_err());
        assert!(check_bands_cover_mode(&[], &[], &[], "NR5G", 1).is_err());
    }

    #[test]
    fn cell_lock_ranges() {
        assert!(validate_lte_lock(503, 262_143).is_ok());
        assert!(validate_lte_lock(504, 1).is_err());
        assert!(validate_lte_lock(0, 262_144).is_err());
        assert!(validate_nr5g_lock(1007, 3_279_165, 240, 41).is_ok());
        assert!(validate_nr5g_lock(1008, 1, 30, 41).is_err());
        assert!(validate_nr5g_lock(1, -1, 30, 41).is_err());
        assert!(validate_nr5g_lock(1, 1, 45, 41).is_err());
        assert!(validate_nr5g_lock(1, 1, 30, 0).is_err());
        assert!(validate_nr5g_lock(1, 1, 30, 70_000).is_err());
    }

    #[test]
    fn ping_targets_and_reboot_days() {
        assert!(clean_ping_target("-f 8.8.8.8").is_err());
        assert!(clean_ping_target("--help").is_err());
        assert_eq!(clean_ping_target(" dns.google ").unwrap(), "dns.google");
        assert!(clean_ping_target("2001:4860:4860::8888").is_ok());
        assert_eq!(clean_reboot_days(&["Sunday".into(), "sunday".into()]).unwrap(), vec!["sunday".to_string()]);
        assert!(clean_reboot_days(&["someday".into()]).is_err());
        assert_eq!(crate::telemetry::ping_argv("8.8.8.8"), ["-c", "1", "-W", "2", "--", "8.8.8.8"]);
    }

    #[test]
    fn band_lock_reports_modem_errors() {
        let ok = |c: &str| crate::smd::AtResponse { command: c.into(), raw: String::new(), body: String::new(), ok: true, latency_ms: 1 };
        let mut bad = ok("AT+QNWPREFCFG=\"nr5g_band\",99999");
        bad.ok = false;
        bad.body = "ERROR".into();
        assert_eq!(band_batch_failure(&[Ok(ok("a")), Ok(ok("b"))]), None);
        assert!(band_batch_failure(&[Ok(ok("a")), Ok(bad)]).unwrap().contains("nr5g_band"));
        assert!(band_batch_failure(&[Err("AT command timed out".into())]).is_some());
    }

    const SC01_ETHTOOL: &str = "\
Settings for eth0:
\tSupported ports: [ TP MII ]
\tSupported link modes:   100baseT/Full
\t                        1000baseT/Full
\t                        2500baseT/Full
\tAdvertised link modes:  100baseT/Full
\t                        1000baseT/Full
\t                        2500baseT/Full
\tLink partner advertised link modes:  100baseT/Full
\t                                     1000baseT/Full
\t                                     10000baseT/Full
\t                                     2500baseT/Full
\t                                     5000baseT/Full
\tLink partner advertised pause frame use: Symmetric Receive-only
\tLink partner advertised auto-negotiation: Yes
\tSpeed: 2500Mb/s
";

    #[test]
    fn parses_partner_advertised_speeds_real_sc01_and_edge_cases() {
        assert_eq!(parse_partner_advertised_speeds(""), None);
        assert_eq!(
            parse_partner_advertised_speeds(SC01_ETHTOOL),
            Some(vec!["100", "1000", "2500", "5000", "10000"])
        );
        assert!(check_partner_speed_limit(SC01_ETHTOOL, "10").is_err());
        assert!(check_partner_speed_limit(SC01_ETHTOOL, "100").is_ok());
        assert!(check_partner_speed_limit(SC01_ETHTOOL, "1000").is_ok());

        let not_rep = "Settings for eth0:\n\tLink partner advertised link modes:  Not reported\n\tSpeed: Unknown!\n";
        assert_eq!(parse_partner_advertised_speeds(not_rep), Some(vec![]));
        assert!(check_partner_speed_limit(not_rep, "100").is_ok());
    }

    fn spawn_fake_modem_ctx(
        dir: &Path,
        mut responder: impl FnMut(&str) -> String + Send + 'static,
    ) -> (HttpCtx, Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;

        let (a, mut b) = UnixStream::pair().unwrap();
        let fd_a = Some(a.into_raw_fd());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 1024];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    if cmd.is_empty() {
                        continue;
                    }
                    seen2.lock().unwrap().push(cmd.clone());
                    let reply = responder(&cmd);
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });
        let fd_slot = std::sync::Mutex::new(fd_a);
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_slot.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));
        let mut ctx = HttpCtx::for_tests(dir);
        ctx.app.smd = smd;
        (ctx, seen)
    }

    #[tokio::test]
    async fn eth_limit_refuses_unadvertised_speed_and_auto_falls_back() {
        let env = crate::paths::TestSandbox::new("eth-limit");
        let calls = env.root.join("calls.log");
        env.write("/sc01.txt", SC01_ETHTOOL);
        env.write_exec(
            "/bin/ethtool",
            &format!(
                "#!/bin/sh\n\
                 echo \"ethtool $*\" >> {log}\n\
                 if [ \"$1\" = \"eth0\" ]; then\n\
                   cat {sc01}\n\
                   exit 0\n\
                 fi\n\
                 if [ \"$1\" = \"-s\" ] && [ \"$5\" = \"advertise\" ] && [ \"$6\" = \"0x80000000002f\" ]; then\n\
                   exit 1\n\
                 fi\n\
                 exit 0\n",
                log = calls.display(),
                sc01 = env.root.join("sc01.txt").display(),
            ),
        );
        env.write_exec(
            "/bin/uci",
            &format!("#!/bin/sh\necho \"uci $*\" >> {}\nexit 0\n", calls.display()),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // 1. Disallowed 10 Mb/s -> 400 Bad Request, no ethtool -s or uci calls
                let resp10 = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::EthLimit { limit: "10".into() }),
                )
                .await;
                assert_eq!(resp10.status(), StatusCode::BAD_REQUEST);
                let body10 = axum::body::to_bytes(resp10.into_body(), 4096).await.unwrap();
                let v10: serde_json::Value = serde_json::from_slice(&body10).unwrap();
                assert!(v10["error"].as_str().unwrap().contains("100, 1000"), "{v10}");
                let log10 = std::fs::read_to_string(&calls).unwrap();
                assert_eq!(log10.lines().collect::<Vec<_>>(), vec!["ethtool eth0"]);

                // 2. Allowed 100 Mb/s -> succeeds
                std::fs::write(&calls, "").unwrap();
                let resp100 = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::EthLimit { limit: "100".into() }),
                )
                .await;
                assert_eq!(resp100.status(), StatusCode::OK);
                let log100 = std::fs::read_to_string(&calls).unwrap();
                assert!(log100.contains("ethtool -s eth0 advertise 0x00f autoneg on"), "{log100}");
                assert!(log100.contains("uci set cellcore.eth_link.speed_limit=100"), "{log100}");

                // 3. Auto tries 0x80000000002f first and falls back to `autoneg on`
                std::fs::write(&calls, "").unwrap();
                let resp_auto = post_network_lan(
                    State(ctx),
                    Json(NetworkMutateReq::EthLimit { limit: "auto".into() }),
                )
                .await;
                assert_eq!(resp_auto.status(), StatusCode::OK);
                let log_auto = std::fs::read_to_string(&calls).unwrap();
                assert!(log_auto.contains("ethtool -s eth0 autoneg on advertise 0x80000000002f"), "{log_auto}");
                assert!(log_auto.contains("ethtool -s eth0 autoneg on\n"), "{log_auto}");
            })
            .await;
    }

    #[tokio::test]
    async fn qscan_poll_skips_at_while_running_and_records_error_status() {
        let env = crate::paths::TestSandbox::new("qscan");
        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, |cmd| {
            if cmd == "AT+QSCAN=3,1" {
                "\r\n+CME ERROR: 30\r\n".into()
            } else {
                "\r\nOK\r\n".into()
            }
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // While scan is running, get_cell_scan must NOT send AT+QENG="neighbourcell"
                *ctx.app.qscan_running.lock().await = Some(serde_json::json!({ "startedAt": 1 }));
                let resp = get_cell_scan(State(ctx.clone())).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["scanRunning"], true);
                assert_eq!(v["neighbors"].as_array().unwrap().len(), 0);
                assert!(!seen.lock().unwrap().iter().any(|c| c.contains("neighbourcell")));
                *ctx.app.qscan_running.lock().await = None;

                // post_cell_scan when AT+QSCAN=3,1 returns !ok records status="error"
                let start = post_cell_scan(State(ctx.clone()), axum::body::Bytes::new()).await;
                assert_eq!(start.status(), StatusCode::OK);
                for _ in 0..50 {
                    if ctx.app.qscan_running.lock().await.is_none()
                        && ctx.app.qscan_last.read().await.is_some()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let last = ctx.app.qscan_last.read().await.clone().unwrap();
                assert_eq!(last["status"], "error", "{last}");
                assert!(last["error"].as_str().unwrap().contains("CME ERROR"), "{last}");
            })
            .await;
    }

    #[tokio::test]
    async fn mbn_deactivate_mpdn_clear_ttl_loop_and_mtu_fallback() {
        let env = crate::paths::TestSandbox::new("lan-triage");
        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, |_| "\r\nOK\r\n".into());

        // TTL cleanup loops until read_live_mangle_val returns None
        let ipt_count = env.root.join("ipt_count");
        std::fs::write(&ipt_count, "2\n").unwrap();
        let ipt_script = format!(
            "#!/bin/sh\n\
             n=$(cat {cf})\n\
             if [ \"$3\" = \"-S\" ]; then\n\
               if [ \"$n\" -gt 0 ]; then\n\
                 echo \"-A POSTROUTING -o rmnet+ -j TTL --ttl-set 65\"\n\
               fi\n\
               exit 0\n\
             fi\n\
             if [ \"$3\" = \"-D\" ]; then\n\
               n=$((n - 1))\n\
               echo \"$n\" > {cf}\n\
             fi\n\
             exit 0\n",
            cf = ipt_count.display()
        );
        env.write_exec("/bin/iptables", &ipt_script);
        env.write_exec("/bin/ip6tables", "#!/bin/sh\nexit 0\n");
        env.write_exec("/bin/uci", "#!/bin/sh\nexit 0\n");
        env.write_exec("/bin/ip", "#!/bin/sh\nexit 0\n");

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // MBN deactivate uses 0-arg AT+QMBNCFG="Deactivate"
                let r_mbn = post_mbn(
                    State(ctx.clone()),
                    Json(MbnActionReq {
                        action: "deactivate".into(),
                        profile_name: None,
                        enabled: None,
                    }),
                )
                .await;
                assert_eq!(r_mbn.status(), StatusCode::OK);

                // MPDN_rule mode 0 uses 1-arg AT+QMAP="MPDN_rule",<slot>
                let r_mpdn = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule { slot: 0, mode: 0, mac: None }),
                )
                .await;
                assert_eq!(r_mpdn.status(), StatusCode::OK);
                let cmds = seen.lock().unwrap().clone();
                assert!(cmds.contains(&"AT+QMBNCFG=\"Deactivate\"".to_string()), "{cmds:?}");
                assert!(cmds.contains(&"AT+QMAP=\"MPDN_rule\",0".to_string()), "{cmds:?}");

                let r_ttl = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::Ttl { enabled: false, ttl: 0, hl: 0 }),
                )
                .await;
                assert_eq!(r_ttl.status(), StatusCode::OK);
                assert_eq!(std::fs::read_to_string(&ipt_count).unwrap().trim(), "0");

                // get_network_lan uses settings.mtu_value when /etc/firewall.user.mtu exists without active rmnet_data0
                env.write("/etc/firewall.user.mtu", "ip link set rmnet_data0 mtu 1420\n");
                ctx.app.settings.write().await.mtu_value = Some(1420);
                let r_lan = get_network_lan(State(ctx.clone())).await;
                assert_eq!(r_lan.status(), StatusCode::OK);
                let lan_body = axum::body::to_bytes(r_lan.into_body(), 8192).await.unwrap();
                let lan_v: serde_json::Value = serde_json::from_slice(&lan_body).unwrap();
                assert_eq!(lan_v["mtu"]["enabled"], true);
                assert_eq!(lan_v["mtu"]["value"], 1420);

                // get_bootstrap emits disconnected sessionUptime while keeping deviceUptime unchanged
                let r_boot = get_bootstrap(State(ctx)).await;
                assert_eq!(r_boot.status(), StatusCode::OK);
                let boot_body = axum::body::to_bytes(r_boot.into_body(), 16384).await.unwrap();
                let boot_v: serde_json::Value = serde_json::from_slice(&boot_body).unwrap();
                assert_eq!(boot_v["sessionUptime"]["isConnected"], false);
                assert_eq!(boot_v["sessionUptime"]["disconnectCount"], 0);
                assert_eq!(boot_v["sessionUptime"]["uptimeSeconds"], 0);
                assert_eq!(boot_v["sessionUptime"]["uptimeFormatted"], "0s");
                assert!(boot_v["deviceUptime"].get("isConnected").is_none());
                assert!(boot_v["deviceUptime"].get("disconnectCount").is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn delete_cell_lock_is_idempotent_when_already_unlocked() {
        assert!(qnwlock_is_unlocked("+QNWLOCK: \"common/4g\",0", "common/4g"));
        assert!(qnwlock_is_unlocked("+QNWLOCK: \"common/5g\",0", "common/5g"));
        assert!(!qnwlock_is_unlocked("+QNWLOCK: \"common/4g\",1,66786,371", "common/4g"));

        let env = crate::paths::TestSandbox::new("cell-lock-idempotent");
        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, |cmd| match cmd {
            "AT+QNWLOCK=\"common/4g\"" => "\r\n+QNWLOCK: \"common/4g\",0\r\n\r\nOK\r\n".into(),
            "AT+QNWLOCK=\"common/5g\"" => "\r\n+QNWLOCK: \"common/5g\",0\r\n\r\nOK\r\n".into(),
            "AT+QNWLOCK=\"common/4g\",0" | "AT+QNWLOCK=\"common/5g\",0" => "\r\nERROR\r\n".into(),
            _ => "\r\nOK\r\n".into(),
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let mut s = ctx.app.settings.write().await;
                s.cell_lock_lte = "1,66786,371".into();
                s.cell_lock_nr5g = "589,521310,30,41".into();
                drop(s);

                let resp = delete_cell_lock(State(ctx.clone()), Query(RatQuery { rat: None })).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let cmds = seen.lock().unwrap().clone();
                assert!(!cmds.iter().any(|c| c.ends_with(",0")), "should skip redundant unlock writes: {cmds:?}");
                let s = ctx.app.settings.read().await;
                assert!(s.cell_lock_lte.is_empty());
                assert!(s.cell_lock_nr5g.is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn mpdn_rule_bootstraps_qcmap_policies_and_idempotent_disable() {
        let env = crate::paths::TestSandbox::new("mpdn-qcmap-bootstrap");
        let xml_path = env.root.join("etc/data/mobileap_cfg.xml");
        fs::create_dir_all(xml_path.parent().unwrap()).unwrap();
        fs::write(
            &xml_path,
            "<system><MobileAPCfg><MobileAPWanCfg><Profile>1</Profile><V4_UMTS_PROFILE_INDEX>1</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></MobileAPCfg>\
<ConcurrentMobileAPCfg><Config><MobileAPWanCfg><Profile>2</Profile><V4_UMTS_PROFILE_INDEX>22</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></Config>\
<Config><MobileAPWanCfg><Profile>3</Profile><V4_UMTS_PROFILE_INDEX>24</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></Config></ConcurrentMobileAPCfg></system>",
        )
        .unwrap();

        let cli_path = env.root.join("usr/bin/QCMAP_CLI");
        let stdin_log = env.root.join("qcmap_stdin.txt");
        let calls_log = env.root.join("qcmap_calls.txt");
        fs::create_dir_all(cli_path.parent().unwrap()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let script = format!(
                "#!/bin/sh\n\
                 echo call >> {calls}\n\
                 : > {slog}\n\
                 echo 'QCMAP_Server status update on MDM: UP'\n\
                 i=0\n\
                 while [ \"$i\" -lt 3 ] && IFS= read -r line; do\n\
                   printf '%s\\n' \"$line\" >> {slog}\n\
                   i=$((i + 1))\n\
                 done\n\
                 echo 'MobileAP Enable succeeds.'\n\
                 i=0\n\
                 while [ \"$i\" -lt 9 ] && IFS= read -r line; do\n\
                   printf '%s\\n' \"$line\" >> {slog}\n\
                   i=$((i + 1))\n\
                 done\n\
                 cat <<'EOF' > {xml}\n\
<system><MobileAPCfg><MobileAPWanCfg><Profile>1</Profile><V4_UMTS_PROFILE_INDEX>1</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></MobileAPCfg>\
<ConcurrentMobileAPCfg><Config><MobileAPWanCfg><Profile>2</Profile><V4_UMTS_PROFILE_INDEX>22</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></Config>\
<Config><MobileAPWanCfg><Profile>3</Profile><V4_UMTS_PROFILE_INDEX>24</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></Config>\
<Config><MobileAPWanCfg><Profile>4</Profile><V4_UMTS_PROFILE_INDEX>23</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></Config></ConcurrentMobileAPCfg></system>\n\
EOF\n\
                 echo 'Create WWAN policy succeeds, profile_handle=4'\n\
                 sleep 5\n",
                calls = calls_log.display(),
                slog = stdin_log.display(),
                xml = xml_path.display(),
            );
            fs::write(&cli_path, script).unwrap();
            let mut perm = fs::metadata(&cli_path).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(&cli_path, perm).unwrap();
        }

        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, move |cmd| {
            if cmd == "AT+QMAP=\"MPDN_rule\"" {
                "\r\n+QMAP: \"MPDN_rule\",0,0,0,0,0\r\n+QMAP: \"MPDN_rule\",3,0,0,0,0\r\n\r\nOK\r\n".into()
            } else if cmd == "AT+QMAP=\"VLAN\"" {
                "\r\n+QMAP: \"VLAN\",0\r\n\r\nOK\r\n".into()
            } else {
                "\r\nOK\r\n".into()
            }
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // First mode=1 on slot=3 bootstraps Profile 4 (UMTS=23) via QCMAP_CLI, enables VLAN 4, then writes MPDN_rule
                let on = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 3,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:01".into()),
                    }),
                )
                .await;
                assert_eq!(on.status(), StatusCode::OK);
                let captured = fs::read_to_string(&stdin_log).unwrap();
                assert_eq!(captured, "1\n2\n1\n6\n2\n25\n0\n0\n23\n0\n\n10\n");
                let cmds = seen.lock().unwrap().clone();
                let vlan_idx = cmds.iter().position(|c| c == "AT+QMAP=\"VLAN\",4,\"enable\"");
                let mpdn_idx = cmds
                    .iter()
                    .position(|c| c == "AT+QMAP=\"MPDN_rule\",3,1,4,1,1,\"02:00:5e:10:00:01\"");
                assert!(vlan_idx.is_some() && mpdn_idx.is_some() && vlan_idx < mpdn_idx, "{cmds:?}");

                // slot=0 mode=1 uses VLAN 0 directly without enabling extra VLANs or re-invoking QCMAP_CLI
                let on0 = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 0,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:02".into()),
                    }),
                )
                .await;
                assert_eq!(on0.status(), StatusCode::OK);
                assert_eq!(fs::read_to_string(&calls_log).unwrap().lines().count(), 1);
                let cmds = seen.lock().unwrap().clone();
                assert!(
                    cmds.contains(&"AT+QMAP=\"MPDN_rule\",0,1,0,1,1,\"02:00:5e:10:00:02\"".to_string()),
                    "{cmds:?}"
                );
                assert!(!cmds.iter().any(|c| c.starts_with("AT+QMAP=\"VLAN\",0,")));

                // mode=0 on already-empty slot 3 skips AT+QMAP="MPDN_rule",3 write
                let off = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule { slot: 3, mode: 0, mac: None }),
                )
                .await;
                assert_eq!(off.status(), StatusCode::OK);
                assert!(!seen.lock().unwrap().iter().any(|c| c == "AT+QMAP=\"MPDN_rule\",3"));
            })
            .await;

        // Refuses MPDN_rule write when QCMAP_CLI fails to create Profile 4
        let env2 = crate::paths::TestSandbox::new("mpdn-qcmap-refuse");
        let xml2 = env2.root.join("etc/data/mobileap_cfg.xml");
        fs::create_dir_all(xml2.parent().unwrap()).unwrap();
        fs::write(
            &xml2,
            "<system><MobileAPCfg><MobileAPWanCfg><Profile>1</Profile><V4_UMTS_PROFILE_INDEX>1</V4_UMTS_PROFILE_INDEX></MobileAPWanCfg></MobileAPCfg></system>",
        )
        .unwrap();
        let cli2 = env2.root.join("usr/bin/QCMAP_CLI");
        fs::create_dir_all(cli2.parent().unwrap()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(
                &cli2,
                "#!/bin/sh\n\
                 echo 'QCMAP_Server status update on MDM: UP'\n\
                 echo 'MobileAP Enable succeeds.'\n\
                 echo '  Failed to Create WWAN policy. Error 0x1a'\n",
            )
            .unwrap();
            let mut perm = fs::metadata(&cli2).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(&cli2, perm).unwrap();
        }
        let (ctx2, seen2) = spawn_fake_modem_ctx(&env2.root, |_| "\r\nOK\r\n".into());
        crate::paths::TEST_ENV
            .scope(env2.env(), async {
                let refused = post_network_lan(
                    State(ctx2),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 3,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:01".into()),
                    }),
                )
                .await;
                assert_eq!(refused.status(), StatusCode::BAD_GATEWAY);
            })
            .await;
        assert!(!seen2.lock().unwrap().iter().any(|c| c.contains("MPDN_rule")));
    }

    #[test]
    fn enrich_mpdn_rules_reads_active_qcmap_lan_mac_only() {
        let mut rules = parse_mpdn_rules(
            "+QMAP: \"MPDN_rule\",0,0,0,0,0\r\n\
             +QMAP: \"MPDN_rule\",3,1,4,1,1\r\n",
        );
        let qcmap_show = "\
qcmap_lan.@profile[0]=profile\n\
qcmap_lan.@profile[0].profile_id='1'\n\
qcmap_lan.@profile[0].ippt_enable='0'\n\
qcmap_lan.@profile[0].ippt_bridge_context='0'\n\
qcmap_lan.@profile[0].ippt_mac_addr='02:00:5e:10:00:06'\n\
qcmap_lan.@profile[3]=profile\n\
qcmap_lan.@profile[3].profile_id='4'\n\
qcmap_lan.@profile[3].ippt_enable='1'\n\
qcmap_lan.@profile[3].ippt_bridge_context='4'\n\
qcmap_lan.@profile[3].ippt_mac_addr='02:00:5e:10:00:01'\n";
        enrich_mpdn_rules_from_qcmap_lan(&mut rules, qcmap_show);
        assert_eq!(rules[0].mac, "");
        assert_eq!(rules[1].mac, "02:00:5e:10:00:01");
    }

    #[tokio::test]
    async fn mpdn_rule_repairs_uci_guards_eth_vlan_count_overwrites_and_rolls_back_vlan() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};

        let env = crate::paths::TestSandbox::new("mpdn-uci-vlan-guard");
        let xml_path = env.root.join("etc/data/mobileap_cfg.xml");
        fs::create_dir_all(xml_path.parent().unwrap()).unwrap();
        fs::write(
            &xml_path,
            "<system><MobileAPCfg><MobileAPWanCfg><Profile>1</Profile></MobileAPWanCfg></MobileAPCfg>\
<ConcurrentMobileAPCfg><Config><MobileAPWanCfg><Profile>2</Profile></MobileAPWanCfg></Config>\
<Config><MobileAPWanCfg><Profile>3</Profile></MobileAPWanCfg></Config>\
<Config><MobileAPWanCfg><Profile>4</Profile></MobileAPWanCfg></Config></ConcurrentMobileAPCfg></system>",
        )
        .unwrap();
        let qcmap_cfg = env.root.join("etc/config/qcmap_lan");
        fs::create_dir_all(qcmap_cfg.parent().unwrap()).unwrap();
        fs::write(&qcmap_cfg, "").unwrap();

        let uci_kv = env.root.join("uci_kv.txt");
        let uci_log = env.root.join("uci_calls.log");
        fs::write(
            &uci_kv,
            "ql_cust_config.@qcmap_configs[0].bind_when_create_wwan=1\n\
             qcmap_lan.@ipa_vlan_phy_config[0].eth_vlan_count=0\n\
             qcmap_lan.@no_of_configs[0].no_of_profiles=1\n",
        )
        .unwrap();
        let fake_uci = env.root.join("bin/uci");
        let script = format!(
            "#!/bin/sh\n\
             kv={kv}\n\
             log={log}\n\
             echo \"$*\" >> \"$log\"\n\
             [ \"$1\" = \"-q\" ] && shift\n\
             case \"$1\" in\n\
               get)\n\
                 val=$(grep -F \"$2=\" \"$kv\" | tail -n1 | cut -d= -f2-)\n\
                 [ -n \"$val\" ] || exit 1\n\
                 printf '%s\\n' \"$val\"\n\
                 ;;\n\
               set)\n\
                 k=\"${{2%%=*}}\"\n\
                 v=\"${{2#*=}}\"\n\
                 grep -v -F \"$k=\" \"$kv\" > \"$kv.tmp\" || true\n\
                 printf '%s=%s\\n' \"$k\" \"$v\" >> \"$kv.tmp\"\n\
                 mv \"$kv.tmp\" \"$kv\"\n\
                 ;;\n\
               add)\n\
                 idx=$(grep -c '=zone\\|=forwarding\\|=profile' \"$kv\" || true)\n\
                 sec=\"cfg$idx\"\n\
                 printf '%s.%s=%s\\n' \"$2\" \"$sec\" \"$3\" >> \"$kv\"\n\
                 printf '%s\\n' \"$sec\"\n\
                 ;;\n\
               show)\n\
                 grep -E \"^$2\\.\" \"$kv\" || true\n\
                 ;;\n\
               commit)\n\
                 ;;\n\
             esac\n",
            kv = uci_kv.display(),
            log = uci_log.display(),
        );
        fs::write(&fake_uci, script).unwrap();
        let mut perm = fs::metadata(&fake_uci).unwrap().permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&fake_uci, perm).unwrap();

        let slot3_active = std::sync::Arc::new(AtomicBool::new(false));
        let vlan4_active = std::sync::Arc::new(AtomicBool::new(false));
        let fail_mpdn_write = std::sync::Arc::new(AtomicBool::new(false));
        let s3 = slot3_active.clone();
        let v4 = vlan4_active.clone();
        let fail_w = fail_mpdn_write.clone();

        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, move |cmd| {
            if cmd == "AT+QMAP=\"MPDN_rule\"" {
                if s3.load(Ordering::SeqCst) {
                    "\r\n+QMAP: \"MPDN_rule\",3,1,4,1,1\r\n\r\nOK\r\n".into()
                } else {
                    "\r\n+QMAP: \"MPDN_rule\",3,0,0,0,0\r\n\r\nOK\r\n".into()
                }
            } else if cmd == "AT+QMAP=\"VLAN\"" {
                if v4.load(Ordering::SeqCst) {
                    "\r\n+QMAP: \"VLAN\",4,\"enable\",1\r\n\r\nOK\r\n".into()
                } else {
                    "\r\n+QMAP: \"VLAN\",0\r\n\r\nOK\r\n".into()
                }
            } else if cmd == "AT+QMAP=\"VLAN\",4,\"enable\"" {
                v4.store(true, Ordering::SeqCst);
                "\r\nOK\r\n".into()
            } else if cmd == "AT+QMAP=\"VLAN\",4,\"disable\"" {
                v4.store(false, Ordering::SeqCst);
                "\r\nOK\r\n".into()
            } else if cmd == "AT+QMAP=\"MPDN_rule\",3" {
                s3.store(false, Ordering::SeqCst);
                "\r\nOK\r\n".into()
            } else if cmd.starts_with("AT+QMAP=\"MPDN_rule\",3,1,") {
                if fail_w.load(Ordering::SeqCst) {
                    "\r\nERROR\r\n".into()
                } else {
                    s3.store(true, Ordering::SeqCst);
                    "\r\nOK\r\n".into()
                }
            } else {
                "\r\nOK\r\n".into()
            }
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // 1. Boot repair populates dhcp/network/qcmap_lan/firewall for profiles 2..=4
                let repaired = repair_qcmap_wwan_uci_for_existing_xml_profiles().await.unwrap();
                assert!(repaired);
                let kv = fs::read_to_string(&uci_kv).unwrap();
                assert!(kv.contains("network.wan4=interface"), "{kv}");
                assert!(kv.contains("network.wan4_v6=interface"), "{kv}");
                assert!(kv.contains("dhcp.wan4=dhcp"), "{kv}");
                assert!(kv.contains("firewall.cfg"), "{kv}");
                assert!(kv.contains("profile_id=4"), "{kv}");

                // 2. Failed MPDN_rule rolls back newly enabled VLAN 4 with 2 -> 0 eth_vlan_count guards
                fail_mpdn_write.store(true, Ordering::SeqCst);
                let err_res = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 3,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:01".into()),
                    }),
                )
                .await;
                assert_eq!(err_res.status(), StatusCode::BAD_REQUEST);
                assert!(!vlan4_active.load(Ordering::SeqCst));
                let cmds = seen.lock().unwrap().clone();
                assert!(cmds.contains(&"AT+QMAP=\"VLAN\",4,\"disable\"".to_string()), "{cmds:?}");
                let kv_after_fail = fs::read_to_string(&uci_kv).unwrap();
                assert!(kv_after_fail.contains("eth_vlan_count=0"), "{kv_after_fail}");

                // 3. Successful enable, then overwrite active slot clears first, then disable resets count=0
                fail_mpdn_write.store(false, Ordering::SeqCst);
                let ok1 = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 3,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:01".into()),
                    }),
                )
                .await;
                assert_eq!(ok1.status(), StatusCode::OK);
                assert!(fs::read_to_string(&uci_log).unwrap().contains("eth_vlan_count=1"));

                seen.lock().unwrap().clear();
                let ok2 = post_network_lan(
                    State(ctx.clone()),
                    Json(NetworkMutateReq::MpdnRule {
                        slot: 3,
                        mode: 1,
                        mac: Some("02:00:5e:10:00:02".into()),
                    }),
                )
                .await;
                assert_eq!(ok2.status(), StatusCode::OK);
                let overwrite_cmds = seen.lock().unwrap().clone();
                let clr_i = overwrite_cmds.iter().position(|c| c == "AT+QMAP=\"MPDN_rule\",3");
                let set_i = overwrite_cmds
                    .iter()
                    .position(|c| c == "AT+QMAP=\"MPDN_rule\",3,1,4,1,1,\"02:00:5e:10:00:02\"");
                assert!(clr_i.is_some() && set_i.is_some() && clr_i < set_i, "{overwrite_cmds:?}");

                let off = post_network_lan(
                    State(ctx),
                    Json(NetworkMutateReq::MpdnRule { slot: 3, mode: 0, mac: None }),
                )
                .await;
                assert_eq!(off.status(), StatusCode::OK);
                assert!(!vlan4_active.load(Ordering::SeqCst));
                assert!(fs::read_to_string(&uci_kv).unwrap().contains("eth_vlan_count=0"));
            })
            .await;
    }

    #[tokio::test]
    async fn resolve_live_lan_ip_prefers_ubus_and_dnsmasq_over_stale_qmap() {
        use std::os::unix::fs::PermissionsExt;

        let env = crate::paths::TestSandbox::new("lan-live-ubus-dnsmasq");
        fs::create_dir_all(env.root.join("etc/config")).unwrap();
        fs::write(env.root.join("etc/config/network"), "config interface 'lan'\n").unwrap();
        fs::create_dir_all(env.root.join("var/etc")).unwrap();
        fs::write(
            env.root.join("var/etc/dnsmasq.conf.lan_dns"),
            "domain-needed\ndhcp-range=set:lan,192.168.228.2,192.168.228.3,255.255.252.0,12h\n",
        )
        .unwrap();

        let fake_ubus = env.root.join("bin/ubus");
        fs::write(
            &fake_ubus,
            "#!/bin/sh\nprintf '{\"ipv4-address\":[{\"address\":\"192.168.228.1\",\"mask\":22}]}'\n",
        )
        .unwrap();
        fs::set_permissions(&fake_ubus, fs::Permissions::from_mode(0o755)).unwrap();

        let stale = parse_qmap_lan_ip("+QMAP: \"LANIP\",192.168.224.100,192.168.227.99,192.168.224.1");
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let got = resolve_live_lan_ip(stale).await.unwrap();
                assert_eq!(got.gateway_ip, "192.168.228.1");
                assert_eq!(got.pool_start, "192.168.228.2");
                assert_eq!(got.pool_end, "192.168.228.3");
                assert_eq!(got.netmask, "255.255.252.0 (/22)");
            })
            .await;
    }

    #[tokio::test]
    async fn resolve_live_lan_ip_falls_back_to_uci_network_and_dhcp_lan() {
        use std::os::unix::fs::PermissionsExt;

        let env = crate::paths::TestSandbox::new("lan-live-uci-fallback");
        fs::create_dir_all(env.root.join("etc/config")).unwrap();
        fs::write(env.root.join("etc/config/network"), "config interface 'lan'\n").unwrap();

        let fake_uci = env.root.join("bin/uci");
        fs::write(
            &fake_uci,
            "#!/bin/sh\n\
             [ \"$1\" = \"-q\" ] && shift\n\
             case \"$1:$2\" in\n\
               show:network.lan)\n\
                 printf \"network.lan=interface\\nnetwork.lan.ipaddr='192.168.228.1'\\nnetwork.lan.netmask='255.255.252.0'\\n\"\n\
                 ;;\n\
               show:dhcp.lan)\n\
                 printf \"dhcp.lan=dhcp\\ndhcp.lan.dhcpv4='server'\\ndhcp.lan.start='2'\\ndhcp.lan.limit='2'\\n\"\n\
                 ;;\n\
             esac\n",
        )
        .unwrap();
        fs::set_permissions(&fake_uci, fs::Permissions::from_mode(0o755)).unwrap();

        let stale = parse_qmap_lan_ip("+QMAP: \"LANIP\",192.168.224.100,192.168.227.99,192.168.224.1");
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let got = resolve_live_lan_ip(stale).await.unwrap();
                assert_eq!(got.gateway_ip, "192.168.228.1");
                assert_eq!(got.pool_start, "192.168.228.2");
                assert_eq!(got.pool_end, "192.168.228.3");
                assert_eq!(got.netmask, "255.255.252.0 (/22)");
            })
            .await;
    }

    #[tokio::test]
    async fn resolve_live_lan_ip_keeps_qmap_fallback_without_openwrt_network_cfg() {
        let env = crate::paths::TestSandbox::new("lan-live-no-openwrt");
        let stale = parse_qmap_lan_ip("+QMAP: \"LANIP\",192.168.224.100,192.168.227.99,192.168.224.1");
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let got = resolve_live_lan_ip(stale.clone()).await.unwrap();
                assert_eq!(got.gateway_ip, "192.168.224.1");
                assert_eq!(got.pool_start, "192.168.224.100");
                assert_eq!(got.pool_end, "192.168.227.99");
                assert_eq!(got.netmask, "255.255.252.0 (/22)");
            })
            .await;
    }

    #[tokio::test]
    async fn post_modem_at_reopens_and_retries_once_when_idle_stream_broke_before_send() {
        use std::collections::VecDeque;
        use std::io::{Read, Write};
        use std::net::Shutdown;
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;

        let env = crate::paths::TestSandbox::new("at-retry-broken-smd");
        let (a1, mut b1) = UnixStream::pair().unwrap();
        let (a2, mut b2) = UnixStream::pair().unwrap();

        let t1 = std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 256];
            while let Ok(n) = b1.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.contains(&b'\r') {
                    acc.clear();
                    let _ = b1.write_all(b"\r\nOK\r\n");
                    let _ = b1.shutdown(Shutdown::Both);
                    break;
                }
            }
        });
        let t2 = std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b2.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    if cmd.is_empty() {
                        continue;
                    }
                    let reply = if cmd == "ATI" {
                        "\r\nQuectel\r\nRM551E-GL\r\n\r\nOK\r\n"
                    } else {
                        "\r\nOK\r\n"
                    };
                    let _ = b2.write_all(reply.as_bytes());
                }
            }
        });

        let fds = std::sync::Mutex::new(VecDeque::from([a1.into_raw_fd(), a2.into_raw_fd()]));
        let mut ctx = HttpCtx::for_tests(&env.root);
        ctx.app.smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fds.lock().unwrap().pop_front().ok_or_else(|| "closed".into())
        }));

        // Warm open port 1, then wait for its peer shutdown to reach the reader as an idle EOF.
        let _ = ctx.app.smd.exec("AT", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
        let _ = t1.join();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = post_modem_at(
            State(ctx),
            None,
            Json(AtExecReq {
                command: "ATI".into(),
                timeout_secs: Some(4),
                confirm: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["response"].as_str().unwrap_or("").contains("Quectel"), "{v}");
        drop(t2);
    }

    #[tokio::test]
    async fn cell_lock_api_exposes_deadman_and_scan_supports_nr5g_fast_mode() {
        let env = crate::paths::TestSandbox::new("cell-lock-deadman-scan");
        std::fs::create_dir_all(env.root.join("etc/cellcore")).unwrap();
        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, |cmd| {
            if cmd.starts_with("AT+QSCAN=") {
                "\r\n+QSCAN: \"NR5G\",310,260,521310,589,-82,-11,22,41\r\nOK\r\n".into()
            } else {
                "\r\nOK\r\n".into()
            }
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                ctx.app
                    .cell_lock_bypassed
                    .store(true, std::sync::atomic::Ordering::Release);
                let get1 = get_cell_lock(State(ctx.clone())).await;
                assert_eq!(get1.status(), StatusCode::OK);
                let b1 = axum::body::to_bytes(get1.into_body(), 4096).await.unwrap();
                let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
                assert_eq!(v1["cellLockDeadmanEnabled"], true);
                assert_eq!(v1["cellLockDeadmanSecs"], 180);
                assert_eq!(v1["bypassed"], true);
                assert!(v1.get("lteRaw").is_some() && v1.get("schedule").is_some());

                // Update deadman config via POST /api/v1/cellular/cell-lock without touching radio
                let req: CellLockReq = serde_json::from_value(serde_json::json!({
                    "cellLockDeadmanEnabled": false,
                    "cellLockDeadmanSecs": 240,
                }))
                .unwrap();
                let post_dm = post_cell_lock(State(ctx.clone()), Json(req)).await;
                assert_eq!(post_dm.status(), StatusCode::OK);
                assert!(!ctx.app.settings.read().await.cell_lock_deadman_enabled);
                assert_eq!(ctx.app.settings.read().await.cell_lock_deadman_secs, 240);

                // Fast 5G-only scan uses AT+QSCAN=2,1
                seen.lock().unwrap().clear();
                let scan_nr = post_cell_scan(
                    State(ctx.clone()),
                    axum::body::Bytes::from_static(br#"{"mode":"nr5g"}"#),
                )
                .await;
                assert_eq!(scan_nr.status(), StatusCode::OK);
                for _ in 0..50 {
                    if ctx.app.qscan_running.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
                assert!(
                    seen.lock().unwrap().iter().any(|c| c == "AT+QSCAN=2,1"),
                    "expected AT+QSCAN=2,1 in {:?}",
                    *seen.lock().unwrap()
                );

                // LTE-only scan uses AT+QSCAN=1,1
                seen.lock().unwrap().clear();
                let scan_lte = post_cell_scan(
                    State(ctx.clone()),
                    axum::body::Bytes::from_static(br#"{"mode":"lte"}"#),
                )
                .await;
                assert_eq!(scan_lte.status(), StatusCode::OK);
                for _ in 0..50 {
                    if ctx.app.qscan_running.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
                assert!(seen.lock().unwrap().iter().any(|c| c == "AT+QSCAN=1,1"));

                // Invalid mode -> 400
                let bad = post_cell_scan(
                    State(ctx.clone()),
                    axum::body::Bytes::from_static(br#"{"mode":"gsm"}"#),
                )
                .await;
                assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
            })
            .await;
    }

    #[tokio::test]
    async fn post_modem_at_blocks_egmr_cmgs_qprtpara_qfotadl_andf_and_requires_confirm_for_scans() {
        let env = crate::paths::TestSandbox::new("at-console-guard");
        let (ctx, seen) = spawn_fake_modem_ctx(&env.root, |_| "\r\nOK\r\n".into());
        let auth_ext = Some(axum::Extension(crate::http::AuthCtx {
            token: Some(crate::tokens::TokenAuth {
                id: "0123456789abcdef".into(),
                name: "ops".into(),
                kind: crate::tokens::TokenKind::Rw,
            }),
            peer: None,
        }));

        // Even with confirm=true and an rw token, blocked commands are 403 and NEVER reach SMD.
        for cmd in [
            "AT+EGMR=1,7,\"356938035643809\"",
            "AT+QPRTPARA=1",
            "AT+QFOTADL=\"http://example.com/fw.zip\"",
            "AT&F",
            "AT&F0",
            "AT+CMGS=20",
            "AT+CMGW=20",
        ] {
            let resp = post_modem_at(
                State(ctx.clone()),
                auth_ext.clone(),
                Json(AtExecReq {
                    command: cmd.into(),
                    timeout_secs: Some(10),
                    confirm: true,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "expected 403 for {cmd}");
        }

        // Long-blocking scan commands require confirm=true (428 without confirm).
        for scan in ["AT+COPS=?", "AT+QSCAN=3,1"] {
            let resp = post_modem_at(
                State(ctx.clone()),
                auth_ext.clone(),
                Json(AtExecReq {
                    command: scan.into(),
                    timeout_secs: Some(180),
                    confirm: false,
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::PRECONDITION_REQUIRED, "expected 428 for {scan}");
        }

        // Non-ASCII AT input returns 400 Bad Request cleanly without panicking.
        let non_ascii = post_modem_at(
            State(ctx.clone()),
            auth_ext.clone(),
            Json(AtExecReq {
                command: "ATé".into(),
                timeout_secs: Some(5),
                confirm: true,
            }),
        )
        .await;
        assert_eq!(non_ascii.status(), StatusCode::BAD_REQUEST);
        assert!(seen.lock().unwrap().is_empty(), "blocked/unconfirmed/non-ASCII commands must never reach SMD");

        // Confirmed AT+COPS=? executes cleanly and clears console_at_window on completion.
        let confirmed_scan = post_modem_at(
            State(ctx.clone()),
            auth_ext,
            Json(AtExecReq {
                command: "AT+COPS=?".into(),
                timeout_secs: Some(180),
                confirm: true,
            }),
        )
        .await;
        assert_eq!(confirmed_scan.status(), StatusCode::OK);
        assert_eq!(ctx.app.console_at_window(), (0, 0));
    }

    #[tokio::test]
    async fn post_change_password_revokes_all_api_tokens_and_other_sessions() {
        let env = crate::paths::TestSandbox::new("pw-revoke-tokens");
        let old_pw = "OldPassword!23";
        let new_pw = "NewPassword!45";
        let old_hash = crate::auth::sha512_crypt(old_pw.as_bytes(), "saltsalt12345678", Some(1000));
        env.write("/etc/shadow", format!("root:{old_hash}:20000:0:99999:7:::\n"));

        let ctx = HttpCtx::for_tests(&env.root);
        let sess_keep = ctx.app.auth.create_session().await.unwrap();
        let sess_other = ctx.app.auth.create_session().await.unwrap();
        let (_, rw_tok) = ctx.app.tokens.create("ops", crate::tokens::TokenKind::Rw, None).unwrap();
        let (_, rd_tok) = ctx.app.tokens.create("mon", crate::tokens::TokenKind::Read, None).unwrap();

        let peer = SocketAddr::from(([192, 168, 224, 50], 40000));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", sess_keep.token)).unwrap(),
        );

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let resp = post_change_password(
                    State(ctx.clone()),
                    ConnectInfo(peer),
                    headers,
                    Json(PasswordChangeReq {
                        current_password: old_pw.into(),
                        new_password: new_pw.into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["revokedTokens"], 2);

                // All API tokens are revoked immediately.
                assert!(ctx.app.tokens.list().is_empty());
                assert_eq!(
                    ctx.app.tokens.authenticate(&rw_tok, peer.ip()),
                    Err(crate::tokens::TokenError::Invalid)
                );
                assert_eq!(
                    ctx.app.tokens.authenticate(&rd_tok, peer.ip()),
                    Err(crate::tokens::TokenError::Invalid)
                );
                // Other sessions are revoked while the caller's session remains valid.
                assert!(ctx.app.auth.validate_token(&sess_other.token, false).await.is_none());
                assert!(ctx.app.auth.validate_token(&sess_keep.token, false).await.is_some());
            })
            .await;
    }
}

//! RF, Carrier Aggregation (CA), 4×4 MIMO, UL 256QAM, C-DRX / RRC-Inactive latency,
//! and band-priority tuning over Quectel `AT+QNWCFG` / `AT+QNWPREFCFG`, plus live
//! PHY/MAC link-adaptation diagnostics (`MCS`, `RI`, `CQI`, `PMI`, MIMO layers, SFE).

use std::time::Duration;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{admin::bad, http::HttpCtx, smd::Priority};

const READ_TIMEOUT: Duration = Duration::from_secs(4);
const WRITE_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsiMetrics {
    pub mcs: i32,
    pub ri: i32,
    pub cqi: i32,
    pub pmi: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RadioTuningState {
    pub lte_ca_enabled: Option<bool>,
    pub nr_ca_enabled: Option<bool>,
    pub lte4mimo_enabled: Option<bool>,
    pub nr4mimo_enabled: Option<bool>,
    pub nr_ul256qam_fr1: Option<bool>,
    pub nr_ul256qam_fr2: Option<bool>,
    pub dss_enabled: Option<bool>,
    pub nrdc_enabled: Option<bool>,
    pub rat_acq_order: Option<String>,
    pub lte_cdrx_enabled: Option<bool>,
    pub nr_cdrx_enabled: Option<bool>,
    pub rrc_inactive_enabled: Option<bool>,
    pub data_centric: Option<bool>,
    pub overheat_ind_enabled: Option<bool>,
    pub lte_band_priority: Vec<String>,
    pub nr5g_band_priority: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhyDiagnostics {
    pub nr5g_csi: Option<CsiMetrics>,
    pub lte_csi: Option<CsiMetrics>,
    pub nr5g_mimo_layers: Option<u32>,
    pub nr5g_tx_pwr: Option<String>,
    pub nr5g_ambr: Option<String>,
    pub overheat_ind: Option<bool>,
    pub sfe_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RadioTuningPatch {
    pub lte_ca_enabled: Option<bool>,
    pub nr_ca_enabled: Option<bool>,
    pub lte4mimo_enabled: Option<bool>,
    pub nr4mimo_enabled: Option<bool>,
    pub nr_ul256qam_fr1: Option<bool>,
    pub nr_ul256qam_fr2: Option<bool>,
    pub dss_enabled: Option<bool>,
    pub nrdc_enabled: Option<bool>,
    pub rat_acq_order: Option<String>,
    pub lte_cdrx_enabled: Option<bool>,
    pub nr_cdrx_enabled: Option<bool>,
    pub rrc_inactive_enabled: Option<bool>,
    pub data_centric: Option<bool>,
    pub overheat_ind_enabled: Option<bool>,
    pub lte_band_priority: Option<Vec<String>>,
    pub nr5g_band_priority: Option<Vec<String>>,
}

impl RadioTuningPatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.lte_ca_enabled.is_none()
            && self.nr_ca_enabled.is_none()
            && self.lte4mimo_enabled.is_none()
            && self.nr4mimo_enabled.is_none()
            && self.nr_ul256qam_fr1.is_none()
            && self.nr_ul256qam_fr2.is_none()
            && self.dss_enabled.is_none()
            && self.nrdc_enabled.is_none()
            && self.rat_acq_order.is_none()
            && self.lte_cdrx_enabled.is_none()
            && self.nr_cdrx_enabled.is_none()
            && self.rrc_inactive_enabled.is_none()
            && self.data_centric.is_none()
            && self.overheat_ind_enabled.is_none()
            && self.lte_band_priority.is_none()
            && self.nr5g_band_priority.is_none()
    }
}

fn bad_gateway(msg: impl Into<String>, applied: Vec<String>) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "status": "error",
            "error": msg.into(),
            "applied": applied,
        })),
    )
        .into_response()
}

/// Extract the trimmed value tail after `"<key>",` on a `+Q*:` response line.
pub(crate) fn extract_keyed_tail(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\",").to_ascii_lowercase();
    for line in body.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(pos) = lower.find(&needle) {
            let tail = trimmed[pos + needle.len()..].trim();
            if !tail.is_empty() {
                return Some(tail.to_string());
            }
        }
    }
    None
}

fn parse_first_int(body: &str, key: &str) -> Option<i32> {
    let tail = extract_keyed_tail(body, key)?;
    let tok = tail.split(',').next()?.trim().trim_matches('"');
    tok.parse::<i32>().ok()
}

fn parse_bool_normal(body: &str, key: &str) -> Option<bool> {
    match parse_first_int(body, key)? {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    }
}

// `disable_lte_ca`, `disable_nr_ca`, and `dis_4mimo_enable` report 0 when active.
fn parse_bool_inverted(body: &str, key: &str) -> Option<bool> {
    match parse_first_int(body, key)? {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

fn parse_two_bools(body: &str, key: &str) -> (Option<bool>, Option<bool>) {
    let Some(tail) = extract_keyed_tail(body, key) else {
        return (None, None);
    };
    let mut parts = tail.split(',').map(|s| s.trim().trim_matches('"').parse::<i32>().ok());
    let first = match parts.next().flatten() {
        Some(1) => Some(true),
        Some(0) => Some(false),
        _ => None,
    };
    let second = match parts.next().flatten() {
        Some(1) => Some(true),
        Some(0) => Some(false),
        _ => None,
    };
    (first, second)
}

fn parse_band_priority(body: &str, key: &str) -> Vec<String> {
    let Some(tail) = extract_keyed_tail(body, key) else {
        return Vec::new();
    };
    let clean = tail.trim_matches('"').trim();
    if clean.is_empty() || clean == "0" {
        return Vec::new();
    }
    clean
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "0")
        .map(str::to_string)
        .collect()
}

pub(crate) fn parse_csi(body: &str, key: &str) -> Option<CsiMetrics> {
    let tail = extract_keyed_tail(body, key)?;
    let vals: Vec<i32> = tail
        .split(',')
        .take(4)
        .filter_map(|s| s.trim().trim_matches('"').parse::<i32>().ok())
        .collect();
    if vals.len() < 4 {
        return None;
    }
    if !(0..=31).contains(&vals[0]) || !(0..=8).contains(&vals[1]) || !(0..=15).contains(&vals[2]) {
        return None;
    }
    Some(CsiMetrics {
        mcs: vals[0],
        ri: vals[1],
        cqi: vals[2],
        pmi: vals[3],
    })
}

pub(crate) fn parse_nr5g_tx_pwr(body: &str) -> Option<String> {
    extract_keyed_tail(body, "nr5g_tx_pwr")
        .map(|s| s.trim_matches('"').trim().to_string())
        .filter(|s| !s.is_empty() && s != "-32768")
}

fn parse_sfe_enabled(body: &str) -> Option<bool> {
    let tail = extract_keyed_tail(body, "SFE")?;
    let val = tail.split(',').next()?.trim().trim_matches('"').to_ascii_lowercase();
    match val.as_str() {
        "enable" | "enabled" | "1" => Some(true),
        "disable" | "disabled" | "0" => Some(false),
        _ => None,
    }
}

pub fn validate_rat_acq_order(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_uppercase();
    if trimmed.is_empty() {
        return Err("ratAcqOrder must not be empty (expected e.g. NR5G:LTE:WCDMA)".into());
    }
    let mut seen: Vec<&'static str> = Vec::new();
    for tok in trimmed.split(':') {
        let canonical = match tok.trim() {
            "NR5G" => "NR5G",
            "LTE" => "LTE",
            "WCDMA" => "WCDMA",
            other => {
                return Err(format!(
                    "invalid RAT in ratAcqOrder: {other:?} (allowed: NR5G, LTE, WCDMA)"
                ));
            }
        };
        if seen.contains(&canonical) {
            return Err(format!("duplicate RAT {canonical} in ratAcqOrder"));
        }
        seen.push(canonical);
    }
    Ok(seen.join(":"))
}

pub fn validate_band_priority(list: &[String], label: &str) -> Result<String, String> {
    if list.len() > 16 {
        return Err(format!("{label} accepts at most 16 bands"));
    }
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for item in list {
        let clean = item.trim();
        if clean.is_empty() || !clean.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid band number {item:?} in {label}"));
        }
        let Ok(num) = clean.parse::<u16>() else {
            return Err(format!("invalid band number {item:?} in {label}"));
        };
        if !(1..=261).contains(&num) {
            return Err(format!("band {num} out of range (1..=261) in {label}"));
        }
        let s = num.to_string();
        if out.contains(&s) {
            return Err(format!("duplicate band {s} in {label}"));
        }
        out.push(s);
    }
    if out.is_empty() {
        Ok("0".into())
    } else {
        Ok(out.join(":"))
    }
}

pub(crate) fn parse_snapshot(resps: &[Option<String>]) -> (RadioTuningState, PhyDiagnostics) {
    let body = |idx: usize| resps.get(idx).and_then(|o| o.as_deref()).unwrap_or("");
    let (ul256_fr1, ul256_fr2) = parse_two_bools(body(4), "nr5g_ul_256qam");

    let overheat = parse_bool_normal(body(19), "overheat_ind");
    let tuning = RadioTuningState {
        lte_ca_enabled: parse_bool_inverted(body(0), "disable_lte_ca"),
        nr_ca_enabled: parse_bool_inverted(body(1), "disable_nr_ca"),
        lte4mimo_enabled: parse_bool_inverted(body(2), "dis_4mimo_enable"),
        nr4mimo_enabled: parse_bool_normal(body(3), "nr5g_4mimo_enable"),
        nr_ul256qam_fr1: ul256_fr1,
        nr_ul256qam_fr2: ul256_fr2,
        dss_enabled: parse_bool_normal(body(5), "dss_enable"),
        nrdc_enabled: parse_bool_normal(body(6), "nrdc_mode"),
        rat_acq_order: extract_keyed_tail(body(7), "rat_acq_order")
            .map(|s| s.trim_matches('"').trim().to_string())
            .filter(|s| !s.is_empty()),
        lte_cdrx_enabled: parse_bool_normal(body(8), "lte_cdrx"),
        nr_cdrx_enabled: parse_bool_normal(body(9), "nr5g_cdrx"),
        rrc_inactive_enabled: parse_bool_normal(body(10), "rrc_inactive"),
        data_centric: parse_bool_normal(body(11), "ue_usage_setting"),
        overheat_ind_enabled: overheat,
        lte_band_priority: parse_band_priority(body(12), "lte_band_priority"),
        nr5g_band_priority: parse_band_priority(body(13), "nr5g_band_priority"),
    };

    let phy = PhyDiagnostics {
        nr5g_csi: parse_csi(body(14), "nr5g_csi"),
        lte_csi: parse_csi(body(15), "lte_csi"),
        nr5g_mimo_layers: parse_first_int(body(16), "nr5g_mimo_layers")
            .and_then(|v| u32::try_from(v).ok()),
        nr5g_tx_pwr: parse_nr5g_tx_pwr(body(17)),
        nr5g_ambr: extract_keyed_tail(body(18), "nr5g_ambr")
            .map(|s| s.trim_matches('"').trim().to_string())
            .filter(|s| !s.is_empty()),
        overheat_ind: overheat,
        sfe_enabled: parse_sfe_enabled(body(20)),
    };

    (tuning, phy)
}

const READ_CMDS: &[&str] = &[
    r#"AT+QNWCFG="disable_lte_ca""#,
    r#"AT+QNWCFG="disable_nr_ca""#,
    r#"AT+QNWCFG="dis_4mimo_enable""#,
    r#"AT+QNWCFG="nr5g_4mimo_enable""#,
    r#"AT+QNWCFG="nr5g_ul_256qam""#,
    r#"AT+QNWCFG="dss_enable""#,
    r#"AT+QNWPREFCFG="nrdc_mode""#,
    r#"AT+QNWPREFCFG="rat_acq_order""#,
    r#"AT+QNWCFG="lte_cdrx""#,
    r#"AT+QNWCFG="nr5g_cdrx""#,
    r#"AT+QNWCFG="rrc_inactive""#,
    r#"AT+QNWPREFCFG="ue_usage_setting""#,
    r#"AT+QNWCFG="lte_band_priority""#,
    r#"AT+QNWCFG="nr5g_band_priority""#,
    r#"AT+QNWCFG="nr5g_csi""#,
    r#"AT+QNWCFG="lte_csi""#,
    r#"AT+QNWCFG="nr5g_mimo_layers""#,
    r#"AT+QNWCFG="nr5g_tx_pwr""#,
    r#"AT+QNWCFG="nr5g_ambr""#,
    r#"AT+QNWCFG="overheat_ind""#,
    r#"AT+QMAP="SFE""#,
];

pub async fn read_tuning_snapshot(app: &crate::state::AppState) -> Result<(RadioTuningState, PhyDiagnostics), String> {
    let cmds: Vec<(String, Duration)> = READ_CMDS
        .iter()
        .map(|&c| (c.to_string(), READ_TIMEOUT))
        .collect();
    let results = app
        .smd
        .exec_batch(cmds, Priority::Interactive)
        .await
        .map_err(|e| format!("AT queue error: {e}"))?;
    let bodies: Vec<Option<String>> = results
        .into_iter()
        .map(|r| match r {
            Ok(resp) if resp.ok => Some(resp.body),
            _ => None,
        })
        .collect();
    Ok(parse_snapshot(&bodies))
}

pub async fn get_tuning(State(ctx): State<HttpCtx>) -> Response {
    let Ok((tuning, phy)) = read_tuning_snapshot(&ctx.app).await else {
        return bad_gateway("AT queue error", Vec::new());
    };
    Json(serde_json::json!({
        "status": "ok",
        "tuning": tuning,
        "phy": phy,
    }))
    .into_response()
}

pub async fn apply_tuning_patch(
    app: &crate::state::AppState,
    req: RadioTuningPatch,
) -> Result<Vec<String>, (StatusCode, String, Vec<String>)> {
    if req.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No radio tuning fields specified".into(), Vec::new()));
    }
    let norm_rat_order = match req.rat_acq_order.as_deref() {
        Some(s) => match validate_rat_acq_order(s) {
            Ok(v) => Some(v),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e, Vec::new())),
        },
        None => None,
    };
    let lte_prio_val = match req.lte_band_priority.as_deref() {
        Some(list) => match validate_band_priority(list, "lteBandPriority") {
            Ok(v) => Some(v),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e, Vec::new())),
        },
        None => None,
    };
    let nr_prio_val = match req.nr5g_band_priority.as_deref() {
        Some(list) => match validate_band_priority(list, "nr5gBandPriority") {
            Ok(v) => Some(v),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e, Vec::new())),
        },
        None => None,
    };

    let _radio = crate::radio::lock(app).await;

    // `nr5g_ul_256qam` takes both FR1 and FR2 flags; read first when only one side is set.
    let ul256_pair = match (req.nr_ul256qam_fr1, req.nr_ul256qam_fr2) {
        (Some(fr1), Some(fr2)) => Some((fr1, fr2)),
        (Some(fr1), None) => {
            let cur_fr2 = app
                .smd
                .exec(r#"AT+QNWCFG="nr5g_ul_256qam""#, Priority::Interactive, READ_TIMEOUT)
                .await
                .ok()
                .filter(|r| r.ok)
                .and_then(|r| parse_two_bools(&r.body, "nr5g_ul_256qam").1)
                .unwrap_or(true);
            Some((fr1, cur_fr2))
        }
        (None, Some(fr2)) => {
            let cur_fr1 = app
                .smd
                .exec(r#"AT+QNWCFG="nr5g_ul_256qam""#, Priority::Interactive, READ_TIMEOUT)
                .await
                .ok()
                .filter(|r| r.ok)
                .and_then(|r| parse_two_bools(&r.body, "nr5g_ul_256qam").0)
                .unwrap_or(true);
            Some((cur_fr1, fr2))
        }
        (None, None) => None,
    };

    let mut writes: Vec<(String, String)> = Vec::new();
    let mut push_write = |label: &str, cmd: String| writes.push((label.to_string(), cmd));

    if let Some(on) = req.lte_ca_enabled {
        push_write("lteCaEnabled", format!(r#"AT+QNWCFG="disable_lte_ca",{}"#, u8::from(!on)));
    }
    if let Some(on) = req.nr_ca_enabled {
        push_write("nrCaEnabled", format!(r#"AT+QNWCFG="disable_nr_ca",{}"#, u8::from(!on)));
    }
    if let Some(on) = req.lte4mimo_enabled {
        push_write("lte4mimoEnabled", format!(r#"AT+QNWCFG="dis_4mimo_enable",{}"#, u8::from(!on)));
    }
    if let Some(on) = req.nr4mimo_enabled {
        push_write("nr4mimoEnabled", format!(r#"AT+QNWCFG="nr5g_4mimo_enable",{}"#, u8::from(on)));
    }
    if let Some((fr1, fr2)) = ul256_pair {
        push_write(
            "nrUl256qam",
            format!(r#"AT+QNWCFG="nr5g_ul_256qam",{},{}"#, u8::from(fr1), u8::from(fr2)),
        );
    }
    if let Some(on) = req.dss_enabled {
        push_write("dssEnabled", format!(r#"AT+QNWCFG="dss_enable",{}"#, u8::from(on)));
    }
    if let Some(on) = req.nrdc_enabled {
        push_write("nrdcEnabled", format!(r#"AT+QNWPREFCFG="nrdc_mode",{}"#, u8::from(on)));
    }
    if let Some(order) = norm_rat_order {
        push_write("ratAcqOrder", format!(r#"AT+QNWPREFCFG="rat_acq_order",{order}"#));
    }
    if let Some(on) = req.lte_cdrx_enabled {
        let v = u8::from(on);
        push_write("lteCdrxEnabled", format!(r#"AT+QNWCFG="lte_cdrx",{v},{v}"#));
    }
    if let Some(on) = req.nr_cdrx_enabled {
        push_write("nrCdrxEnabled", format!(r#"AT+QNWCFG="nr5g_cdrx",{}"#, u8::from(on)));
    }
    if let Some(on) = req.rrc_inactive_enabled {
        push_write("rrcInactiveEnabled", format!(r#"AT+QNWCFG="rrc_inactive",{}"#, u8::from(on)));
    }
    if let Some(on) = req.data_centric {
        push_write("dataCentric", format!(r#"AT+QNWPREFCFG="ue_usage_setting",{}"#, u8::from(on)));
    }
    if let Some(on) = req.overheat_ind_enabled {
        push_write("overheatIndEnabled", format!(r#"AT+QNWCFG="overheat_ind",{}"#, u8::from(on)));
    }
    if let Some(val) = lte_prio_val {
        push_write("lteBandPriority", format!(r#"AT+QNWCFG="lte_band_priority",{val}"#));
    }
    if let Some(val) = nr_prio_val {
        push_write("nr5gBandPriority", format!(r#"AT+QNWCFG="nr5g_band_priority",{val}"#));
    }

    let mut applied = Vec::new();
    for (label, cmd) in writes {
        match app.smd.exec(&cmd, Priority::Interactive, WRITE_TIMEOUT).await {
            Ok(r) if r.ok => applied.push(label),
            Ok(r) => {
                let err_msg = r.body.trim();
                let detail = if err_msg.is_empty() { "ERROR" } else { err_msg };
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("{label} rejected by modem: {detail}"),
                    applied,
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("{label} AT command failed: {e}"),
                    applied,
                ));
            }
        }
    }

    let summary = applied.join(", ");
    app.push_daemon_log(format!("cellular: radio tuning updated ({summary})"));
    app.audit.event("cellular", "tuning", summary);
    Ok(applied)
}

pub async fn post_tuning(State(ctx): State<HttpCtx>, Json(req): Json<RadioTuningPatch>) -> Response {
    match apply_tuning_patch(&ctx.app, req).await {
        Ok(applied) => Json(serde_json::json!({
            "status": "ok",
            "applied": applied,
            "note": "Some RF/CA/MIMO changes take effect after a radio cycle (AT+CFUN=0/1) or reboot.",
        }))
        .into_response(),
        Err((StatusCode::BAD_REQUEST, msg, _)) => bad(msg),
        Err((_, msg, applied)) => bad_gateway(msg, applied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        net::SocketAddr,
        os::fd::RawFd,
        sync::{Arc, Mutex},
        thread,
    };
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, header},
    };
    use tower::ServiceExt;

    use crate::{
        auth::AuthStore,
        paths::TestSandbox,
        smd::SmdClient,
        state::AppState,
        tokens::TokenKind,
    };

    #[test]
    fn parses_real_rm551e_responses_and_polarities() {
        let resps = vec![
            Some(r#"+QNWCFG: "disable_lte_ca",0"#.into()),
            Some(r#"+QNWCFG: "disable_nr_ca",1"#.into()),
            Some(r#"+QNWCFG: "dis_4mimo_enable",1"#.into()),
            Some(r#"+QNWCFG: "nr5g_4mimo_enable",1"#.into()),
            Some(r#"+QNWCFG: "nr5g_ul_256qam",1,0"#.into()),
            Some(r#"+QNWCFG: "dss_enable",1"#.into()),
            Some(r#"+QNWPREFCFG: "nrdc_mode",0"#.into()),
            Some(r#"+QNWPREFCFG: "rat_acq_order",LTE:NR5G:WCDMA"#.into()),
            Some(r#"+QNWCFG: "lte_cdrx",1,1"#.into()),
            Some(r#"+QNWCFG: "nr5g_cdrx",0"#.into()),
            Some(r#"+QNWCFG: "rrc_inactive",0"#.into()),
            Some(r#"+QNWPREFCFG: "ue_usage_setting",1"#.into()),
            Some(r#"+QNWCFG: "lte_band_priority",66:2:41"#.into()),
            Some(r#"+QNWCFG: "nr5g_band_priority",0"#.into()),
            Some(r#"+QNWCFG: "nr5g_csi",21,4,15,7"#.into()),
            None,
            Some(r#"+QNWCFG: "nr5g_mimo_layers",4"#.into()),
            Some(r#"+QNWCFG: "nr5g_tx_pwr",0"#.into()),
            None,
            Some(r#"+QNWCFG: "overheat_ind",1"#.into()),
            Some(r#"+QMAP: "SFE","disable""#.into()),
        ];

        let (tuning, phy) = parse_snapshot(&resps);
        assert_eq!(tuning.lte_ca_enabled, Some(true));
        assert_eq!(tuning.nr_ca_enabled, Some(false));
        assert_eq!(tuning.lte4mimo_enabled, Some(false));
        assert_eq!(tuning.nr4mimo_enabled, Some(true));
        assert_eq!(tuning.nr_ul256qam_fr1, Some(true));
        assert_eq!(tuning.nr_ul256qam_fr2, Some(false));
        assert_eq!(tuning.dss_enabled, Some(true));
        assert_eq!(tuning.nrdc_enabled, Some(false));
        assert_eq!(tuning.rat_acq_order.as_deref(), Some("LTE:NR5G:WCDMA"));
        assert_eq!(tuning.lte_cdrx_enabled, Some(true));
        assert_eq!(tuning.nr_cdrx_enabled, Some(false));
        assert_eq!(tuning.rrc_inactive_enabled, Some(false));
        assert_eq!(tuning.data_centric, Some(true));
        assert_eq!(tuning.overheat_ind_enabled, Some(true));
        assert_eq!(tuning.lte_band_priority, vec!["66", "2", "41"]);
        assert!(tuning.nr5g_band_priority.is_empty());

        assert_eq!(phy.nr5g_csi, Some(CsiMetrics { mcs: 21, ri: 4, cqi: 15, pmi: 7 }));
        assert_eq!(parse_csi(r#"+QNWCFG: "nr5g_csi",255,255,255,255"#, "nr5g_csi"), None);
        assert_eq!(phy.lte_csi, None);
        assert_eq!(phy.nr5g_mimo_layers, Some(4));
        assert_eq!(phy.nr5g_tx_pwr.as_deref(), Some("0"));
        assert_eq!(phy.nr5g_ambr, None);
        assert_eq!(phy.overheat_ind, Some(true));
        assert_eq!(phy.sfe_enabled, Some(false));
    }

    #[test]
    fn validates_rat_acq_order_and_band_priority() {
        assert_eq!(validate_rat_acq_order("nr5g:lte").unwrap(), "NR5G:LTE");
        assert_eq!(validate_rat_acq_order("LTE:NR5G:WCDMA").unwrap(), "LTE:NR5G:WCDMA");
        assert!(validate_rat_acq_order("").is_err());
        assert!(validate_rat_acq_order("GSM").is_err());
        assert!(validate_rat_acq_order("NR5G:NR5G").is_err());

        assert_eq!(validate_band_priority(&[], "nr5g").unwrap(), "0");
        assert_eq!(
            validate_band_priority(&["41".into(), "77".into(), "25".into()], "nr5g").unwrap(),
            "41:77:25"
        );
        assert!(validate_band_priority(&["0".into()], "nr5g").is_err());
        assert!(validate_band_priority(&["262".into()], "nr5g").is_err());
        assert!(validate_band_priority(&["41;+CFUN=0".into()], "nr5g").is_err());
        assert!(validate_band_priority(&["41".into(), "41".into()], "nr5g").is_err());
    }

    fn socketpair() -> Result<(RawFd, RawFd), String> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
            return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
        }
        Ok((fds[0], fds[1]))
    }

    fn write_all(fd: RawFd, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let n = unsafe { libc::write(fd, data[off..].as_ptr() as *const libc::c_void, data.len() - off) };
            if n <= 0 {
                return;
            }
            off += n as usize;
        }
    }

    fn scripted_smd(sent: Arc<Mutex<Vec<String>>>) -> SmdClient {
        SmdClient::spawn_with_opener(Box::new(move || {
            let (ours, theirs) = socketpair()?;
            let log = Arc::clone(&sent);
            thread::spawn(move || {
                let mut acc = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = unsafe { libc::read(theirs, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    acc.extend_from_slice(&buf[..n as usize]);
                    while let Some(pos) = acc.iter().position(|&b| b == b'\r' || b == b'\n') {
                        let line: Vec<u8> = acc.drain(..=pos).collect();
                        let cmd = String::from_utf8_lossy(&line).trim().to_string();
                        if cmd.is_empty() {
                            continue;
                        }
                        if cmd != "ATE0" && !cmd.starts_with("AT+QMRESYNC=") {
                            log.lock().unwrap().push(cmd.clone());
                        }
                        let resp = match cmd.as_str() {
                            r#"AT+QNWCFG="nr5g_ul_256qam""# => "\r\n+QNWCFG: \"nr5g_ul_256qam\",1,0\r\n\r\nOK\r\n",
                            r#"AT+QNWCFG="dis_4mimo_enable""# => "\r\n+QNWCFG: \"dis_4mimo_enable\",1\r\n\r\nOK\r\n",
                            r#"AT+QNWCFG="disable_nr_ca""# => "\r\n+QNWCFG: \"disable_nr_ca\",0\r\n\r\nOK\r\n",
                            r#"AT+QMAP="SFE""# => "\r\n+QMAP: \"SFE\",\"disable\"\r\n\r\nOK\r\n",
                            _ => "\r\nOK\r\n",
                        };
                        write_all(theirs, resp.as_bytes());
                    }
                }
                unsafe {
                    libc::shutdown(theirs, libc::SHUT_RDWR);
                    libc::close(theirs);
                }
            });
            Ok(ours)
        }))
    }

    async fn call_router(router: &Router, auth_hdr: &str, method: Method, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "192.168.228.1")
            .header("authorization", auth_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 228, 50], 40000))));
        let resp = router.clone().oneshot(req).await.unwrap();
        let st = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (st, json)
    }

    #[tokio::test]
    async fn endpoint_emits_inverted_booleans_and_preserves_ul256_fr2() {
        let sbx = TestSandbox::new("radio_tuning");
        let www = sbx.root.join("www");
        fs::create_dir_all(&www).unwrap();
        let auth = AuthStore::new(sbx.root.join("sessions"));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let app = AppState::for_tests_with_smd(www, auth, scripted_smd(Arc::clone(&sent)));
        let (_, rw_tok) = app.tokens.create("ops", TokenKind::Rw, None).unwrap();
        let rw = format!("Bearer {rw_tok}");

        let router = crate::http::build_router(crate::http::HttpCtx {
            app,
            proxy: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http(),
            enforce_uhttpd_loopback: true,
        });

        let (st, v) = call_router(&router, &rw, Method::POST, "/api/v1/cellular/tuning", "{}").await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");

        let (st, v) = call_router(&router, &rw, Method::POST, "/api/v1/cellular/tuning", r#"{"ratAcqOrder":"BAD"}"#).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");

        let (st, v) = call_router(
            &router,
            &rw,
            Method::POST,
            "/api/v1/cellular/tuning",
            r#"{"lte4mimoEnabled":true,"nrCaEnabled":false,"nrUl256qamFr1":false,"lteCdrxEnabled":false,"overheatIndEnabled":false,"nr5gBandPriority":["41","77"]}"#,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{v}");

        let cmds = sent.lock().unwrap().clone();
        assert!(cmds.contains(&r#"AT+QNWCFG="dis_4mimo_enable",0"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="disable_nr_ca",1"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="nr5g_ul_256qam",0,0"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="lte_cdrx",0,0"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="overheat_ind",0"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="nr5g_band_priority",41:77"#.to_string()), "{cmds:?}");

        let (st, v) = call_router(&router, &rw, Method::GET, "/api/v1/cellular/tuning", "").await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(v["tuning"]["lte4mimoEnabled"], false);
        assert_eq!(v["tuning"]["nrCaEnabled"], true);
        assert_eq!(v["phy"]["sfeEnabled"], false);
    }
}

//! RF, Carrier Aggregation (CA), 4×4 MIMO, UL 256QAM, C-DRX / RRC-Inactive latency,
//! frequency steering, Dual-SIM switching, and band-priority tuning over Quectel
//! `AT+QNWCFG` / `AT+QNWPREFCFG` / `AT+QUIMSLOT`, plus live SDX75 PHY/MAC/QoS/Security
//! diagnostics (`CSI`, `TX Power + HPUE Headroom`, `Pathloss`, `DL/UL MCS`, `SSB Beams`,
//! `5QI / QoS`, `AMBR`, `Air Cipher / Integrity`, `RRC State`, `C-RNTI`, `MIMO layers`, `SFE`).

use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::{admin::bad, http::HttpCtx, smd::Priority};

const READ_TIMEOUT: Duration = Duration::from_secs(4);
const WRITE_TIMEOUT: Duration = Duration::from_secs(6);

/// Max NR-ARFCN value per 3GPP TS 38.104 (0..=3,279,165).
const MAX_NR_ARFCN: u32 = 3_279_165;

/// Non-disruptive SDX75 telemetry counters enabled once on boot so live PHY/QoS/Security
/// metrics are populated immediately without affecting the RF link.
const PHY_ENABLE_KEYS: &[&str] = &[
    "nr5g_tx_pwr",
    "nr5g_pathloss",
    "nr5g_dlMCS",
    "nr5g_ulMCS",
    "ssb_beam_id",
    "used_algo",
    "nr5g_mimo_layers",
    "c_rnti",
    "rrc_state",
    "csi_ctrl",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsiMetrics {
    pub mcs: i32,
    pub ri: i32,
    pub cqi: i32,
    pub pmi: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPowerDetail {
    pub pusch_dbm: i32,
    pub pucch_dbm: i32,
    pub max_dbm: i32,
    pub srs_dbm: i32,
    pub headroom_db: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McsDetail {
    pub mcs: u8,
    pub mod_order: u8,
    pub modulation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsbBeamEntry {
    pub pci: i32,
    pub beam_id: i32,
    pub serving_beam_id: i32,
    pub rsrp_dbm: i32,
    pub rsrq_db: i32,
    pub is_serving: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosBearerEntry {
    pub cid: u8,
    pub apn: String,
    pub qfi: u8,
    pub five_qi: u8,
    pub priority_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmbrEntry {
    pub apn: String,
    pub ul_mbps: u64,
    pub dl_mbps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AirSecurityInfo {
    pub rat: String,
    pub cipher_id: u8,
    pub cipher_name: String,
    pub integrity_id: u8,
    pub integrity_name: String,
    /// True ONLY when RRC is `CONNECTED` and the air cipher is null (`NEA0`/`EEA0`).
    pub null_cipher_alert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RrcStateInfo {
    pub rat: String,
    pub state_code: u8,
    pub state_name: String,
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
    pub nr5g_pref_freq_list: Vec<String>,
    pub nr5g_earfcn_lock: Vec<String>,
    pub event_a3_enabled: Option<bool>,
    pub event_a3_offset: Option<u8>,
    pub sim_slot: Option<u8>,
    pub sim_det_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PhyDiagnostics {
    pub nr5g_csi: Option<CsiMetrics>,
    pub lte_csi: Option<CsiMetrics>,
    pub nr5g_mimo_layers: Option<u32>,
    pub nr5g_tx_pwr: Option<String>,
    pub nr5g_tx_pwr_detail: Option<TxPowerDetail>,
    pub nr5g_pathloss_db: Option<i32>,
    pub nr5g_dl_mcs: Option<McsDetail>,
    pub nr5g_ul_mcs: Option<McsDetail>,
    pub ssb_beams: Vec<SsbBeamEntry>,
    pub qos_bearers: Vec<QosBearerEntry>,
    pub ambr_caps: Vec<AmbrEntry>,
    pub nr5g_ambr: Option<String>,
    pub air_security: Option<AirSecurityInfo>,
    pub rrc_state: Option<RrcStateInfo>,
    pub c_rnti: Option<u32>,
    pub overheat_ind: Option<bool>,
    pub sfe_enabled: Option<bool>,
}

/// Accept either `["501390:30", "521310:30"]`, `["501390"]`, or legacy `[501390]`.
fn deserialize_opt_arfcn_list<'de, D>(de: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ArfcnEntry {
        Str(String),
        Num(u32),
    }
    let opt = Option::<Vec<ArfcnEntry>>::deserialize(de)?;
    Ok(opt.map(|items| {
        items
            .into_iter()
            .map(|e| match e {
                ArfcnEntry::Str(s) => s,
                ArfcnEntry::Num(n) => n.to_string(),
            })
            .collect()
    }))
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
    #[serde(default, deserialize_with = "deserialize_opt_arfcn_list")]
    pub nr5g_pref_freq_list: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_opt_arfcn_list")]
    pub nr5g_earfcn_lock: Option<Vec<String>>,
    pub event_a3_enabled: Option<bool>,
    pub event_a3_offset: Option<u8>,
    pub sim_slot: Option<u8>,
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
            && self.nr5g_pref_freq_list.is_none()
            && self.nr5g_earfcn_lock.is_none()
            && self.event_a3_enabled.is_none()
            && self.event_a3_offset.is_none()
            && self.sim_slot.is_none()
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

/// Extract the trimmed value tail after `"<key>",` on the first matching `+Q*:` response line.
pub(crate) fn extract_keyed_tail(body: &str, key: &str) -> Option<String> {
    extract_all_keyed_tails(body, key).into_iter().next()
}

/// Extract all trimmed value tails after `"<key>",` across multi-line `+Q*:` responses.
pub(crate) fn extract_all_keyed_tails(body: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\",").to_ascii_lowercase();
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(pos) = lower.find(&needle) {
            let tail = trimmed[pos + needle.len()..].trim();
            if !tail.is_empty() {
                out.push(tail.to_string());
            }
        }
    }
    out
}

fn parse_first_int(body: &str, key: &str) -> Option<i32> {
    let tail = extract_keyed_tail(body, key)?;
    let tok = tail.split(',').next()?.trim().trim_matches('"');
    tok.parse::<i32>().ok()
}

fn parse_ints(tail: &str) -> Vec<i32> {
    tail.split(',')
        .filter_map(|s| s.trim().trim_matches('"').parse::<i32>().ok())
        .collect()
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

/// Default 3GPP NR subcarrier spacing (kHz) when an ARFCN is given without `:scs`.
pub(crate) fn default_nr_scs_khz(arfcn: u32) -> u16 {
    if arfcn >= 2_016_667 {
        120 // FR2 mmWave
    } else if arfcn >= 499_200 {
        30 // FR1 mid-band TDD (n41, n48, n77, n78, n79)
    } else {
        15 // FR1 FDD low/mid bands (n71, n5, n12, n25, n66, n2)
    }
}

/// Parse `+QNWCFG: "<key>",<count>,<arfcn1>:<scs1>[:<arfcn2>:<scs2>...]` (or legacy comma-separated ARFCNs; count=0 when unset).
pub(crate) fn parse_arfcn_list(body: &str, key: &str) -> Vec<String> {
    let Some(tail) = extract_keyed_tail(body, key) else {
        return Vec::new();
    };
    let mut parts = tail.splitn(2, ',');
    let Some(count) = parts
        .next()
        .and_then(|s| s.trim().trim_matches('"').parse::<usize>().ok())
    else {
        return Vec::new();
    };
    if count == 0 {
        return Vec::new();
    }
    let Some(rest) = parts.next().map(|s| s.trim().trim_matches('"')) else {
        return Vec::new();
    };
    let limit = count.min(32);
    if rest.contains(':') {
        let nums: Vec<u32> = rest
            .split([':', ','])
            .filter_map(|s| s.trim().trim_matches('"').parse::<u32>().ok())
            .collect();
        let mut out = Vec::new();
        for &[arfcn, scs] in nums.as_chunks::<2>().0.iter().take(limit) {
            if arfcn > 0 && arfcn <= MAX_NR_ARFCN && matches!(scs, 15 | 30 | 60 | 120) {
                out.push(format!("{arfcn}:{scs}"));
            }
        }
        out
    } else {
        rest.split(',')
            .filter_map(|s| s.trim().trim_matches('"').parse::<u32>().ok())
            .filter(|&v| v > 0 && v <= MAX_NR_ARFCN)
            .take(limit)
            .map(|v| format!("{v}:{}", default_nr_scs_khz(v)))
            .collect()
    }
}

/// Parse `+QNWCFG: "event_a3_offset",<enable>,<offset>`.
pub(crate) fn parse_event_a3(body: &str) -> (Option<bool>, Option<u8>) {
    let Some(tail) = extract_keyed_tail(body, "event_a3_offset") else {
        return (None, None);
    };
    let vals = parse_ints(&tail);
    let enabled = vals.first().and_then(|&v| match v {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    });
    let offset = vals.get(1).and_then(|&v| u8::try_from(v).ok());
    (enabled, offset)
}

/// Parse `+QUIMSLOT: <slot>` (1 or 2).
pub(crate) fn parse_quimslot(body: &str) -> Option<u8> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("+QUIMSLOT:") {
            let tok = rest.trim().split(',').next()?.trim().trim_matches('"');
            if let Ok(slot) = tok.parse::<u8>()
                && (1..=2).contains(&slot)
            {
                return Some(slot);
            }
        }
    }
    None
}

/// Parse `+QSIMDET: <enable>,<insert_level>`.
pub(crate) fn parse_qsimdet(body: &str) -> Option<bool> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("+QSIMDET:") {
            let tok = rest.trim().split(',').next()?.trim().trim_matches('"');
            return match tok.parse::<i32>().ok()? {
                1 => Some(true),
                0 => Some(false),
                _ => None,
            };
        }
    }
    None
}

pub(crate) fn parse_csi(body: &str, key: &str) -> Option<CsiMetrics> {
    let tail = extract_keyed_tail(body, key)?;
    let vals = parse_ints(&tail);
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

/// Parse `+QNWCFG: "nr5g_mimo_layers",1,2` (enabled, layers) or legacy single-int `4`.
pub(crate) fn parse_mimo_layers(body: &str) -> Option<u32> {
    let tail = extract_keyed_tail(body, "nr5g_mimo_layers")?;
    let vals = parse_ints(&tail);
    match vals.as_slice() {
        [1, layers, ..] if (1..=8).contains(layers) => Some(*layers as u32),
        [0, ..] => None,
        [single] if (1..=8).contains(single) => Some(*single as u32),
        _ => None,
    }
}

/// Parse `+QNWCFG: "nr5g_tx_pwr",1,24,18,26,0` -> `(enabled, pusch, pucch, max, srs)`.
pub(crate) fn parse_nr5g_tx_pwr_detail(body: &str) -> Option<TxPowerDetail> {
    let tail = extract_keyed_tail(body, "nr5g_tx_pwr")?;
    let vals = parse_ints(&tail);
    if vals.len() < 5 || vals[0] != 1 {
        return None;
    }
    let (pusch, pucch, max_dbm, srs) = (vals[1], vals[2], vals[3], vals[4]);
    if pusch <= -100 || max_dbm <= 0 || max_dbm > 40 {
        return None;
    }
    Some(TxPowerDetail {
        pusch_dbm: pusch,
        pucch_dbm: pucch,
        max_dbm,
        srs_dbm: srs,
        headroom_db: (max_dbm - pusch).max(0),
    })
}

pub(crate) fn parse_nr5g_tx_pwr(body: &str) -> Option<String> {
    if let Some(d) = parse_nr5g_tx_pwr_detail(body) {
        return Some(format!("{} / {} dBm (HPUE +{} dB)", d.pusch_dbm, d.max_dbm, d.headroom_db));
    }
    extract_keyed_tail(body, "nr5g_tx_pwr")
        .map(|s| s.trim_matches('"').trim().to_string())
        .filter(|s| !s.is_empty() && s != "-32768")
}

/// Parse `+QNWCFG: "nr5g_pathloss",1,114` -> `114 dB`.
pub(crate) fn parse_pathloss_db(body: &str) -> Option<i32> {
    let tail = extract_keyed_tail(body, "nr5g_pathloss")?;
    let vals = parse_ints(&tail);
    match vals.as_slice() {
        [1, pl, ..] if (20..=200).contains(pl) => Some(*pl),
        _ => None,
    }
}

fn modulation_name(order: u8) -> &'static str {
    match order {
        0 => "QPSK",
        1 => "16QAM",
        2 => "64QAM",
        3 => "256QAM",
        4 => "1024QAM",
        _ => "Unknown",
    }
}

/// Parse `+QNWCFG: "nr5g_dlMCS",1,31,3` or `+QNWCFG: "nr5g_ulMCS",1,7,2`.
pub(crate) fn parse_mcs_detail(body: &str, key: &str) -> Option<McsDetail> {
    let tail = extract_keyed_tail(body, key)?;
    let vals = parse_ints(&tail);
    if vals.len() < 3 || vals[0] != 1 {
        return None;
    }
    let mcs = u8::try_from(vals[1]).ok().filter(|&v| v <= 31)?;
    let order = u8::try_from(vals[2]).ok().filter(|&v| v <= 4)?;
    Some(McsDetail {
        mcs,
        mod_order: order,
        modulation: modulation_name(order).to_string(),
    })
}

/// Parse multi-line `+QNWCFG: "ssb_beam_id",1,<serving_beam>,<beam_id>,<rsrp>,<rsrq>,<pci>`.
pub(crate) fn parse_ssb_beams(body: &str) -> Vec<SsbBeamEntry> {
    let mut out = Vec::new();
    for tail in extract_all_keyed_tails(body, "ssb_beam_id") {
        let vals = parse_ints(&tail);
        if vals.len() < 6 || vals[0] != 1 {
            continue;
        }
        let serving_beam_id = vals[1];
        let beam_id = vals[2];
        let rsrp_dbm = vals[3];
        let rsrq_db = vals[4];
        let pci = vals[5];
        if !(-160..=-20).contains(&rsrp_dbm) || !(0..=1007).contains(&pci) {
            continue;
        }
        out.push(SsbBeamEntry {
            pci,
            beam_id,
            serving_beam_id,
            rsrp_dbm,
            rsrq_db,
            is_serving: beam_id == serving_beam_id && out.iter().all(|e: &SsbBeamEntry| !e.is_serving),
        });
    }
    // Sort serving beam first, then strongest RSRP
    out.sort_by(|a, b| b.is_serving.cmp(&a.is_serving).then_with(|| b.rsrp_dbm.cmp(&a.rsrp_dbm)));
    out
}

fn five_qi_label(five_qi: u8) -> &'static str {
    match five_qi {
        1 => "Conversational Voice",
        2 => "Conversational Video",
        5 => "IMS Signaling",
        6 => "Postpaid Priority (5QI 6)",
        7 => "Standard Interactive (5QI 7)",
        8 => "Deprioritized (5QI 8)",
        9 => "Best-Effort / FWA (5QI 9)",
        _ => "Custom QoS Flow",
    }
}

/// Parse multi-line `+QNWCFG: "nr5g_qos",<cid>,"<apn>",<qfi>,<5qi>`.
pub(crate) fn parse_nr5g_qos(body: &str) -> Vec<QosBearerEntry> {
    let mut out = Vec::new();
    for tail in extract_all_keyed_tails(body, "nr5g_qos") {
        let parts: Vec<&str> = tail.split(',').map(|s| s.trim().trim_matches('"')).collect();
        if parts.len() < 4 {
            continue;
        }
        let (Ok(cid), Ok(qfi), Ok(five_qi)) = (
            parts[0].parse::<u8>(),
            parts[2].parse::<u8>(),
            parts[3].parse::<u8>(),
        ) else {
            continue;
        };
        let apn = parts[1].to_string();
        if apn.is_empty() {
            continue;
        }
        out.push(QosBearerEntry {
            cid,
            apn,
            qfi,
            five_qi,
            priority_label: five_qi_label(five_qi).to_string(),
        });
    }
    out
}

fn ambr_to_mbps(unit: u32, val: u64) -> u64 {
    // 3GPP TS 24.501 Session-AMBR unit encoding:
    // 1=1Kbps, 2=4Kbps, 3=16Kbps, 4=64Kbps, 5=256Kbps, 6=1Mbps, 7=4Mbps, 8=16Mbps, 9=64Mbps, 10=256Mbps, 11=1Gbps
    match unit {
        1 => val / 1000,
        2 => (val * 4) / 1000,
        3 => (val * 16) / 1000,
        4 => (val * 64) / 1000,
        5 => (val * 256) / 1000,
        6 => val,
        7 => val * 4,
        8 => val * 16,
        9 => val * 64,
        10 => val * 256,
        11 => val * 1000,
        _ => val,
    }
}

/// Parse multi-line `+QNWCFG: "nr5g_ambr","<apn>",<ul_unit>,<ul_val>,<dl_unit>,<dl_val>`.
pub(crate) fn parse_nr5g_ambr_list(body: &str) -> Vec<AmbrEntry> {
    let mut out = Vec::new();
    for tail in extract_all_keyed_tails(body, "nr5g_ambr") {
        let parts: Vec<&str> = tail.split(',').map(|s| s.trim().trim_matches('"')).collect();
        if parts.len() < 5 {
            continue;
        }
        let apn = parts[0].to_string();
        if apn.is_empty() {
            continue;
        }
        let (Ok(ul_u), Ok(ul_v), Ok(dl_u), Ok(dl_v)) = (
            parts[1].parse::<u32>(),
            parts[2].parse::<u64>(),
            parts[3].parse::<u32>(),
            parts[4].parse::<u64>(),
        ) else {
            continue;
        };
        out.push(AmbrEntry {
            apn,
            ul_mbps: ambr_to_mbps(ul_u, ul_v),
            dl_mbps: ambr_to_mbps(dl_u, dl_v),
        });
    }
    out
}

/// Parse `+QNWCFG: "rrc_state",1,"NR5G",1`.
pub(crate) fn parse_rrc_state(body: &str) -> Option<RrcStateInfo> {
    let tail = extract_keyed_tail(body, "rrc_state")?;
    let parts: Vec<&str> = tail.split(',').map(|s| s.trim().trim_matches('"')).collect();
    if parts.len() < 3 || parts[0] != "1" {
        return None;
    }
    let rat = parts[1].to_string();
    let code = parts[2].parse::<u8>().ok()?;
    let state_name = match code {
        0 => "Disconnected",
        1 => "Idle",
        2 => "Connected",
        3 => "Inactive",
        _ => "Unknown",
    }
    .to_string();
    Some(RrcStateInfo {
        rat,
        state_code: code,
        state_name,
    })
}

/// Parse `+QNWCFG: "used_algo",1,<rat_code>,<cipher_id>,<integrity_id>`.
/// Cross-checks `rrc_state` so null-cipher alerts NEVER fire on RRC Idle (`0,0`).
pub(crate) fn parse_used_algo(body: &str, rrc: Option<&RrcStateInfo>) -> Option<AirSecurityInfo> {
    let tail = extract_keyed_tail(body, "used_algo")?;
    let vals = parse_ints(&tail);
    if vals.len() < 4 || vals[0] != 1 {
        return None;
    }
    let rat_code = vals[1];
    let cipher_id = u8::try_from(vals[2]).ok()?;
    let integrity_id = u8::try_from(vals[3]).ok()?;
    let is_nr = rat_code == 12;
    let rat = match rat_code {
        12 => "NR5G".to_string(),
        7 => "LTE".to_string(),
        other => format!("RAT-{other}"),
    };
    let prefix = if is_nr { "NEA" } else { "EEA" };
    let int_prefix = if is_nr { "NIA" } else { "EIA" };
    let cipher_name = match cipher_id {
        0 => format!("{prefix}0 (Null)"),
        1 => format!("128-{prefix}1 (SNOW 3G)"),
        2 => format!("128-{prefix}2 (AES-CTR)"),
        3 => format!("128-{prefix}3 (ZUC)"),
        other => format!("{prefix}{other}"),
    };
    let integrity_name = match integrity_id {
        0 => format!("{int_prefix}0 (None)"),
        1 => format!("128-{int_prefix}1 (SNOW 3G)"),
        2 => format!("128-{int_prefix}2 (AES-CMAC)"),
        3 => format!("128-{int_prefix}3 (ZUC)"),
        other => format!("{int_prefix}{other}"),
    };
    let is_connected = rrc.is_some_and(|r| r.state_code == 2);
    Some(AirSecurityInfo {
        rat,
        cipher_id,
        cipher_name,
        integrity_id,
        integrity_name,
        null_cipher_alert: is_connected && cipher_id == 0,
    })
}

/// Parse `+QNWCFG: "c_rnti",1,12,47956`.
pub(crate) fn parse_c_rnti(body: &str) -> Option<u32> {
    let tail = extract_keyed_tail(body, "c_rnti")?;
    let vals = parse_ints(&tail);
    if vals.len() < 3 || vals[0] != 1 {
        return None;
    }
    u32::try_from(vals[2]).ok().filter(|&v| v > 0)
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

pub fn validate_arfcn_list(list: &[String], label: &str) -> Result<String, String> {
    if list.len() > 32 {
        return Err(format!("{label} accepts at most 32 ARFCNs"));
    }
    let mut seen_arfcns: Vec<u32> = Vec::with_capacity(list.len());
    let mut pairs: Vec<String> = Vec::with_capacity(list.len());
    for raw in list {
        let clean = raw.trim();
        if clean.is_empty() {
            continue;
        }
        let (arfcn_s, scs_opt) = match clean.split_once(':') {
            Some((a, s)) => (a.trim(), Some(s.trim())),
            None => (clean, None),
        };
        let Ok(arfcn) = arfcn_s.parse::<u32>() else {
            return Err(format!("invalid NR-ARFCN {raw:?} in {label} (expected e.g. 501390:30)"));
        };
        if arfcn == 0 || arfcn > MAX_NR_ARFCN {
            return Err(format!("ARFCN {arfcn} out of range (1..={MAX_NR_ARFCN}) in {label}"));
        }
        let scs = match scs_opt {
            Some(s) => match s.parse::<u16>() {
                Ok(v) if matches!(v, 15 | 30 | 60 | 120) => v,
                _ => {
                    return Err(format!(
                        "invalid SCS {s:?} for ARFCN {arfcn} in {label} (allowed: 15, 30, 60, 120 kHz)"
                    ));
                }
            },
            None => default_nr_scs_khz(arfcn),
        };
        if seen_arfcns.contains(&arfcn) {
            return Err(format!("duplicate ARFCN {arfcn} in {label}"));
        }
        seen_arfcns.push(arfcn);
        pairs.push(format!("{arfcn}:{scs}"));
    }
    if pairs.is_empty() {
        Ok("0".into())
    } else {
        Ok(format!("{},{}", pairs.len(), pairs.join(":")))
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_phy_from_bodies(
    nr5g_csi: &str,
    lte_csi: &str,
    mimo_layers: &str,
    tx_pwr: &str,
    ambr: &str,
    overheat: Option<bool>,
    sfe: &str,
    pathloss: &str,
    dl_mcs: &str,
    ul_mcs: &str,
    ssb_beam: &str,
    qos: &str,
    rrc: &str,
    used_algo: &str,
    c_rnti: &str,
) -> PhyDiagnostics {
    let rrc_state = parse_rrc_state(rrc);
    let ambr_caps = parse_nr5g_ambr_list(ambr);
    let ambr_summary = if let Some(first) = ambr_caps.first() {
        Some(format!("DL {} / UL {} Mbps ({})", first.dl_mbps, first.ul_mbps, first.apn))
    } else {
        extract_keyed_tail(ambr, "nr5g_ambr")
            .map(|s| s.trim_matches('"').trim().to_string())
            .filter(|s| !s.is_empty())
    };
    PhyDiagnostics {
        nr5g_csi: parse_csi(nr5g_csi, "nr5g_csi"),
        lte_csi: parse_csi(lte_csi, "lte_csi"),
        nr5g_mimo_layers: parse_mimo_layers(mimo_layers),
        nr5g_tx_pwr: parse_nr5g_tx_pwr(tx_pwr),
        nr5g_tx_pwr_detail: parse_nr5g_tx_pwr_detail(tx_pwr),
        nr5g_pathloss_db: parse_pathloss_db(pathloss),
        nr5g_dl_mcs: parse_mcs_detail(dl_mcs, "nr5g_dlMCS"),
        nr5g_ul_mcs: parse_mcs_detail(ul_mcs, "nr5g_ulMCS"),
        ssb_beams: parse_ssb_beams(ssb_beam),
        qos_bearers: parse_nr5g_qos(qos),
        ambr_caps,
        nr5g_ambr: ambr_summary,
        air_security: parse_used_algo(used_algo, rrc_state.as_ref()),
        rrc_state,
        c_rnti: parse_c_rnti(c_rnti),
        overheat_ind: overheat,
        sfe_enabled: parse_sfe_enabled(sfe),
    }
}

pub(crate) fn parse_snapshot(resps: &[Option<String>]) -> (RadioTuningState, PhyDiagnostics) {
    let body = |idx: usize| resps.get(idx).and_then(|o| o.as_deref()).unwrap_or("");
    let (ul256_fr1, ul256_fr2) = parse_two_bools(body(4), "nr5g_ul_256qam");
    let (a3_en, a3_off) = parse_event_a3(body(31));

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
        nr5g_pref_freq_list: parse_arfcn_list(body(29), "nr5g_pref_freq_list"),
        nr5g_earfcn_lock: parse_arfcn_list(body(30), "nr5g_earfcn_lock"),
        event_a3_enabled: a3_en,
        event_a3_offset: a3_off,
        sim_slot: parse_quimslot(body(32)),
        sim_det_enabled: parse_qsimdet(body(33)),
    };

    let phy = parse_phy_from_bodies(
        body(14),
        body(15),
        body(16),
        body(17),
        body(18),
        overheat,
        body(20),
        body(21),
        body(22),
        body(23),
        body(24),
        body(25),
        body(26),
        body(27),
        body(28),
    );

    (tuning, phy)
}

const READ_CMDS: &[&str] = &[
    r#"AT+QNWCFG="disable_lte_ca""#,       // 0
    r#"AT+QNWCFG="disable_nr_ca""#,        // 1
    r#"AT+QNWCFG="dis_4mimo_enable""#,     // 2
    r#"AT+QNWCFG="nr5g_4mimo_enable""#,    // 3
    r#"AT+QNWCFG="nr5g_ul_256qam""#,       // 4
    r#"AT+QNWCFG="dss_enable""#,           // 5
    r#"AT+QNWPREFCFG="nrdc_mode""#,        // 6
    r#"AT+QNWPREFCFG="rat_acq_order""#,    // 7
    r#"AT+QNWCFG="lte_cdrx""#,             // 8
    r#"AT+QNWCFG="nr5g_cdrx""#,            // 9
    r#"AT+QNWCFG="rrc_inactive""#,         // 10
    r#"AT+QNWPREFCFG="ue_usage_setting""#, // 11
    r#"AT+QNWCFG="lte_band_priority""#,    // 12
    r#"AT+QNWCFG="nr5g_band_priority""#,   // 13
    r#"AT+QNWCFG="nr5g_csi""#,             // 14
    r#"AT+QNWCFG="lte_csi""#,              // 15
    r#"AT+QNWCFG="nr5g_mimo_layers""#,     // 16
    r#"AT+QNWCFG="nr5g_tx_pwr""#,          // 17
    r#"AT+QNWCFG="nr5g_ambr""#,            // 18
    r#"AT+QNWCFG="overheat_ind""#,         // 19
    r#"AT+QMAP="SFE""#,                    // 20
    r#"AT+QNWCFG="nr5g_pathloss""#,        // 21
    r#"AT+QNWCFG="nr5g_dlMCS""#,           // 22
    r#"AT+QNWCFG="nr5g_ulMCS""#,           // 23
    r#"AT+QNWCFG="ssb_beam_id""#,          // 24
    r#"AT+QNWCFG="nr5g_qos""#,             // 25
    r#"AT+QNWCFG="rrc_state""#,            // 26
    r#"AT+QNWCFG="used_algo""#,            // 27
    r#"AT+QNWCFG="c_rnti""#,               // 28
    r#"AT+QNWCFG="nr5g_pref_freq_list""#,  // 29
    r#"AT+QNWCFG="nr5g_earfcn_lock""#,     // 30
    r#"AT+QNWCFG="event_a3_offset""#,      // 31
    "AT+QUIMSLOT?",                        // 32
    "AT+QSIMDET?",                         // 33
];

const PHY_POLL_CMDS: &[&str] = &[
    r#"AT+QNWCFG="nr5g_csi""#,         // 0
    r#"AT+QNWCFG="lte_csi""#,          // 1
    r#"AT+QNWCFG="nr5g_mimo_layers""#, // 2
    r#"AT+QNWCFG="nr5g_tx_pwr""#,      // 3
    r#"AT+QNWCFG="nr5g_ambr""#,        // 4
    r#"AT+QNWCFG="overheat_ind""#,     // 5
    r#"AT+QMAP="SFE""#,                // 6
    r#"AT+QNWCFG="nr5g_pathloss""#,    // 7
    r#"AT+QNWCFG="nr5g_dlMCS""#,       // 8
    r#"AT+QNWCFG="nr5g_ulMCS""#,       // 9
    r#"AT+QNWCFG="ssb_beam_id""#,      // 10
    r#"AT+QNWCFG="nr5g_qos""#,         // 11
    r#"AT+QNWCFG="rrc_state""#,        // 12
    r#"AT+QNWCFG="used_algo""#,        // 13
    r#"AT+QNWCFG="c_rnti""#,           // 14
];

/// Enable non-disruptive SDX75 PHY telemetry counters once on startup.
pub async fn enable_phy_telemetry_counters(app: &crate::state::AppState) {
    let cmds: Vec<(String, Duration)> = PHY_ENABLE_KEYS
        .iter()
        .map(|k| (format!(r#"AT+QNWCFG="{k}",1"#), READ_TIMEOUT))
        .collect();
    let _ = app.smd.exec_batch(cmds, Priority::Telemetry).await;
}

/// Lightweight PHY-only poll used by the 30 s background loop to keep Prometheus
/// metrics warm without querying all 34 tuning keys.
pub async fn poll_phy_telemetry(app: &crate::state::AppState) -> Result<PhyDiagnostics, String> {
    let cmds: Vec<(String, Duration)> = PHY_POLL_CMDS
        .iter()
        .map(|&c| (c.to_string(), READ_TIMEOUT))
        .collect();
    let results = app
        .smd
        .exec_batch(cmds, Priority::Telemetry)
        .await
        .map_err(|e| format!("AT queue error: {e}"))?;
    let bodies: Vec<Option<String>> = results
        .into_iter()
        .map(|r| match r {
            Ok(resp) if resp.ok => Some(resp.body),
            _ => None,
        })
        .collect();
    let body = |idx: usize| bodies.get(idx).and_then(|o| o.as_deref()).unwrap_or("");
    let overheat = parse_bool_normal(body(5), "overheat_ind");
    let phy = parse_phy_from_bodies(
        body(0),
        body(1),
        body(2),
        body(3),
        body(4),
        overheat,
        body(6),
        body(7),
        body(8),
        body(9),
        body(10),
        body(11),
        body(12),
        body(13),
        body(14),
    );
    *app.phy_diag.write().await = phy.clone();
    Ok(phy)
}

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
    let (tuning, phy) = parse_snapshot(&bodies);
    *app.phy_diag.write().await = phy.clone();
    Ok((tuning, phy))
}

#[derive(Debug, Default, Deserialize)]
pub struct TuningQuery {
    pub refresh: Option<u8>,
}

const TUNING_CACHE_TTL: Duration = Duration::from_secs(20);

pub async fn get_tuning(State(ctx): State<HttpCtx>, Query(q): Query<TuningQuery>) -> Response {
    let force_refresh = q.refresh.unwrap_or(0) != 0;
    if !force_refresh
        && let Some((tuning, phy, ts)) = ctx.app.tuning_cache.read().await.as_ref()
        && ts.elapsed() < TUNING_CACHE_TTL
    {
        return Json(serde_json::json!({
            "status": "ok",
            "tuning": tuning,
            "phy": phy,
            "cached": true,
        }))
        .into_response();
    }
    let Ok((tuning, phy)) = read_tuning_snapshot(&ctx.app).await else {
        return bad_gateway("AT queue error", Vec::new());
    };
    *ctx.app.tuning_cache.write().await = Some((tuning.clone(), phy.clone(), Instant::now()));
    Json(serde_json::json!({
        "status": "ok",
        "tuning": tuning,
        "phy": phy,
        "cached": false,
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
    let pref_freq_val = match req.nr5g_pref_freq_list.as_deref() {
        Some(list) => match validate_arfcn_list(list, "nr5gPrefFreqList") {
            Ok(v) => Some(v),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e, Vec::new())),
        },
        None => None,
    };
    let earfcn_lock_val = match req.nr5g_earfcn_lock.as_deref() {
        Some(list) => match validate_arfcn_list(list, "nr5gEarfcnLock") {
            Ok(v) => Some(v),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e, Vec::new())),
        },
        None => None,
    };
    if let Some(slot) = req.sim_slot
        && !(1..=2).contains(&slot)
    {
        return Err((StatusCode::BAD_REQUEST, "simSlot must be 1 or 2".into(), Vec::new()));
    }

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

    // `event_a3_offset` takes both enable and offset; preserve the unset side when needed.
    let a3_pair = match (req.event_a3_enabled, req.event_a3_offset) {
        (Some(en), Some(off)) => Some((en, off)),
        (Some(en), None) => {
            let cur_off = app
                .smd
                .exec(r#"AT+QNWCFG="event_a3_offset""#, Priority::Interactive, READ_TIMEOUT)
                .await
                .ok()
                .filter(|r| r.ok)
                .and_then(|r| parse_event_a3(&r.body).1)
                .unwrap_or(5);
            Some((en, cur_off))
        }
        (None, Some(off)) => Some((true, off)),
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
    if let Some(val) = pref_freq_val {
        push_write("nr5gPrefFreqList", format!(r#"AT+QNWCFG="nr5g_pref_freq_list",{val}"#));
    }
    if let Some(val) = earfcn_lock_val {
        push_write("nr5gEarfcnLock", format!(r#"AT+QNWCFG="nr5g_earfcn_lock",{val}"#));
    }
    if let Some((en, off)) = a3_pair {
        push_write(
            "eventA3Offset",
            format!(r#"AT+QNWCFG="event_a3_offset",{},{off}"#, u8::from(en)),
        );
    }
    if let Some(slot) = req.sim_slot {
        push_write("simSlot", format!("AT+QUIMSLOT={slot}"));
    }

    let mut applied = Vec::new();
    for (label, cmd) in writes {
        match app.smd.exec(&cmd, Priority::Interactive, WRITE_TIMEOUT).await {
            Ok(r) if r.ok => applied.push(label),
            Ok(r) => {
                // RM551E-GL returns ERROR if clearing `nr5g_earfcn_lock` / `nr5g_pref_freq_list`
                // with `,0` when it is already unset (0). Verify current readback before failing.
                let already_cleared = if cmd == r#"AT+QNWCFG="nr5g_earfcn_lock",0"# {
                    app.smd
                        .exec(r#"AT+QNWCFG="nr5g_earfcn_lock""#, Priority::Interactive, READ_TIMEOUT)
                        .await
                        .ok()
                        .filter(|q| q.ok)
                        .is_some_and(|q| parse_arfcn_list(&q.body, "nr5g_earfcn_lock").is_empty())
                } else if cmd == r#"AT+QNWCFG="nr5g_pref_freq_list",0"# {
                    app.smd
                        .exec(r#"AT+QNWCFG="nr5g_pref_freq_list""#, Priority::Interactive, READ_TIMEOUT)
                        .await
                        .ok()
                        .filter(|q| q.ok)
                        .is_some_and(|q| parse_arfcn_list(&q.body, "nr5g_pref_freq_list").is_empty())
                } else {
                    false
                };
                if already_cleared {
                    applied.push(label);
                    continue;
                }
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

    *app.tuning_cache.write().await = None;
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
            "note": "Some RF/CA/MIMO/SIM changes take effect after a radio cycle (AT+CFUN=0/1) or reboot.",
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
            Some(r#"+QNWCFG: "nr5g_mimo_layers",1,2"#.into()),
            Some(r#"+QNWCFG: "nr5g_tx_pwr",1,24,18,26,0"#.into()),
            Some("+QNWCFG: \"nr5g_ambr\",\"fast.t-mobile.com\",6,4294,6,4294\r\n+QNWCFG: \"nr5g_ambr\",\"ims\",6,50,6,50".into()),
            Some(r#"+QNWCFG: "overheat_ind",1"#.into()),
            Some(r#"+QMAP: "SFE","disable""#.into()),
            Some(r#"+QNWCFG: "nr5g_pathloss",1,114"#.into()),
            Some(r#"+QNWCFG: "nr5g_dlMCS",1,31,3"#.into()),
            Some(r#"+QNWCFG: "nr5g_ulMCS",1,7,2"#.into()),
            Some("+QNWCFG: \"ssb_beam_id\",1,3,3,-95,-11,589\r\n+QNWCFG: \"ssb_beam_id\",1,3,5,-101,-13,589\r\n+QNWCFG: \"ssb_beam_id\",1,3,1,-108,-15,412".into()),
            Some("+QNWCFG: \"nr5g_qos\",1,\"fast.t-mobile.com\",1,6\r\n+QNWCFG: \"nr5g_qos\",2,\"ims\",2,5".into()),
            Some(r#"+QNWCFG: "rrc_state",1,"NR5G",1"#.into()),
            Some(r#"+QNWCFG: "used_algo",1,12,0,0"#.into()),
            Some(r#"+QNWCFG: "c_rnti",1,12,47956"#.into()),
            Some(r#"+QNWCFG: "nr5g_pref_freq_list",2,501390:30:632628:30"#.into()),
            Some(r#"+QNWCFG: "nr5g_earfcn_lock",1,501390:30"#.into()),
            Some(r#"+QNWCFG: "event_a3_offset",0,5"#.into()),
            Some("+QUIMSLOT: 1".into()),
            Some("+QSIMDET: 0,1".into()),
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
        assert_eq!(tuning.nr5g_pref_freq_list, vec!["501390:30", "632628:30"]);
        assert_eq!(tuning.nr5g_earfcn_lock, vec!["501390:30"]);
        assert_eq!(tuning.event_a3_enabled, Some(false));
        assert_eq!(tuning.event_a3_offset, Some(5));
        assert_eq!(tuning.sim_slot, Some(1));
        assert_eq!(tuning.sim_det_enabled, Some(false));

        assert_eq!(phy.nr5g_csi, Some(CsiMetrics { mcs: 21, ri: 4, cqi: 15, pmi: 7 }));
        assert_eq!(parse_csi(r#"+QNWCFG: "nr5g_csi",255,255,255,255"#, "nr5g_csi"), None);
        assert_eq!(phy.lte_csi, None);
        assert_eq!(phy.nr5g_mimo_layers, Some(2));
        assert_eq!(parse_mimo_layers(r#"+QNWCFG: "nr5g_mimo_layers",4"#), Some(4));
        assert_eq!(
            phy.nr5g_tx_pwr_detail,
            Some(TxPowerDetail { pusch_dbm: 24, pucch_dbm: 18, max_dbm: 26, srs_dbm: 0, headroom_db: 2 })
        );
        assert_eq!(phy.nr5g_pathloss_db, Some(114));
        assert_eq!(
            phy.nr5g_dl_mcs,
            Some(McsDetail { mcs: 31, mod_order: 3, modulation: "256QAM".into() })
        );
        assert_eq!(
            phy.nr5g_ul_mcs,
            Some(McsDetail { mcs: 7, mod_order: 2, modulation: "64QAM".into() })
        );
        assert_eq!(phy.ssb_beams.len(), 3);
        assert!(phy.ssb_beams[0].is_serving);
        assert_eq!(phy.ssb_beams[0].beam_id, 3);
        assert_eq!(phy.ssb_beams[0].rsrp_dbm, -95);
        assert_eq!(phy.qos_bearers.len(), 2);
        assert_eq!(phy.qos_bearers[0].five_qi, 6);
        assert_eq!(phy.ambr_caps.len(), 2);
        assert_eq!(phy.ambr_caps[0].dl_mbps, 4294);
        assert_eq!(phy.rrc_state.as_ref().map(|r| r.state_name.as_str()), Some("Idle"));
        // IDLE with used_algo=0,0 must NOT raise a null-cipher alert!
        let sec = phy.air_security.as_ref().unwrap();
        assert_eq!(sec.cipher_id, 0);
        assert!(!sec.null_cipher_alert);
        // CONNECTED with used_algo=0,0 MUST raise a null-cipher alert!
        let connected = RrcStateInfo { rat: "NR5G".into(), state_code: 2, state_name: "Connected".into() };
        assert!(parse_used_algo(r#"+QNWCFG: "used_algo",1,12,0,0"#, Some(&connected)).unwrap().null_cipher_alert);
        assert!(!parse_used_algo(r#"+QNWCFG: "used_algo",1,12,2,2"#, Some(&connected)).unwrap().null_cipher_alert);
        assert_eq!(phy.c_rnti, Some(47956));
        assert_eq!(phy.overheat_ind, Some(true));
        assert_eq!(phy.sfe_enabled, Some(false));
    }

    #[test]
    fn validates_rat_acq_order_band_priority_and_arfcns() {
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

        assert_eq!(validate_arfcn_list(&[], "pref").unwrap(), "0");
        assert_eq!(
            validate_arfcn_list(&["501390:30".into(), "632628".into()], "pref").unwrap(),
            "2,501390:30:632628:30"
        );
        assert_eq!(
            validate_arfcn_list(&["397470".into()], "pref").unwrap(),
            "1,397470:15"
        );
        assert!(validate_arfcn_list(&["0".into()], "pref").is_err());
        assert!(validate_arfcn_list(&["501390:45".into()], "pref").is_err());
        assert!(validate_arfcn_list(&["4000000".into()], "pref").is_err());
        assert!(validate_arfcn_list(&["521310:30".into(), "521310:30".into()], "pref").is_err());
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
                            r#"AT+QNWCFG="nr5g_pathloss""# => "\r\n+QNWCFG: \"nr5g_pathloss\",1,114\r\n\r\nOK\r\n",
                            "AT+QUIMSLOT?" => "\r\n+QUIMSLOT: 1\r\n\r\nOK\r\n",
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

        let (st, v) = call_router(&router, &rw, Method::POST, "/api/v1/cellular/tuning", r#"{"simSlot":3}"#).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");

        let (st, v) = call_router(
            &router,
            &rw,
            Method::POST,
            "/api/v1/cellular/tuning",
            r#"{"lte4mimoEnabled":true,"nrCaEnabled":false,"nrUl256qamFr1":false,"lteCdrxEnabled":false,"overheatIndEnabled":false,"nr5gBandPriority":["41","77"],"nr5gPrefFreqList":[521310,632628],"eventA3Enabled":true,"eventA3Offset":6,"simSlot":2}"#,
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
        assert!(cmds.contains(&r#"AT+QNWCFG="nr5g_pref_freq_list",2,521310:30:632628:30"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&r#"AT+QNWCFG="event_a3_offset",1,6"#.to_string()), "{cmds:?}");
        assert!(cmds.contains(&"AT+QUIMSLOT=2".to_string()), "{cmds:?}");

        let (st, v) = call_router(&router, &rw, Method::GET, "/api/v1/cellular/tuning", "").await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(v["tuning"]["lte4mimoEnabled"], false);
        assert_eq!(v["tuning"]["nrCaEnabled"], true);
        assert_eq!(v["tuning"]["simSlot"], 1);
        assert_eq!(v["phy"]["sfeEnabled"], false);
        assert_eq!(v["phy"]["nr5gPathlossDb"], 114);
    }
}

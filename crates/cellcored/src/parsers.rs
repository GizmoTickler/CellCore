use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServingCellInfo {
    pub state: String,
    pub rat: String,
    pub duplex_mode: String,
    pub mcc: String,
    pub mnc: String,
    pub cell_id: String,
    pub pci: Option<i32>,
    pub tac: String,
    pub arfcn: Option<i64>,
    pub band: String,
    pub ul_bandwidth_mhz: Option<f64>,
    pub dl_bandwidth_mhz: Option<f64>,
    pub rsrp: Option<f64>,
    pub rsrq: Option<f64>,
    pub sinr: Option<f64>,
    pub tx_power: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scs_khz: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_pci: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_arfcn: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_band: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_rsrp: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_sinr: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_rsrq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsa_nr5g_bw_mhz: Option<f64>,
    pub srxlev: Option<f64>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MimoSignalData {
    pub rsrp: Vec<Option<f64>>,
    pub rsrq: Vec<Option<f64>>,
    pub sinr: Vec<Option<f64>>,
    pub rat: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CarrierComponent {
    pub role: String,
    pub arfcn: i64,
    pub bandwidth_code: i32,
    pub bandwidth_mhz: Option<f64>,
    pub band: String,
    pub pci: Option<i32>,
    pub pcell_state: Option<i32>,
    pub ul_configured: bool,
    pub ul_arfcn: Option<i64>,
    pub ul_bandwidth_mhz: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsrp: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsrq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rssi: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sinr: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dl_mimo_layers: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ul_mimo_layers: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WwanBearerInfo {
    pub iface: String,
    pub cid: i32,
    pub ip_type: String,
    pub status: String,
    pub apn: String,
    pub ipv4: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_dns1: Option<String>,
    pub ipv4_dns2: Option<String>,
    pub ipv6: Option<String>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_dns1: Option<String>,
    pub ipv6_dns2: Option<String>,
    pub ipv6_prefix_length: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TimeAdvanceInfo {
    pub nr5g_raw: Option<i64>,
    pub nr5g_steps: Option<i64>,
    pub nr5g_meters: Option<i64>,
    pub lte_ta: Option<i64>,
    pub lte_meters: Option<i64>,
    pub active_meters: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempSensor {
    pub sensor: String,
    pub celsius: f64,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MbnProfile {
    pub index: i32,
    pub selected: bool,
    pub activated: bool,
    pub name: String,
    pub version: String,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QmapLanIpInfo {
    pub pool_start: String,
    pub pool_end: String,
    pub gateway_ip: String,
    pub netmask: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MpdnRule {
    pub slot: i32,
    pub apn_slot: i32,
    pub vlan_id: i32,
    pub mode: String,
    pub mac: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeighborCellInfo {
    pub rat: String,
    pub r#type: String,
    pub arfcn: Option<i64>,
    pub pci: Option<i32>,
    pub rsrp: Option<f64>,
    pub rsrq: Option<f64>,
    pub sinr: Option<f64>,
    pub srxlev: Option<f64>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QscanEntry {
    pub rat: String,
    pub mcc: String,
    pub mnc: String,
    pub arfcn: Option<i64>,
    pub pci: Option<i32>,
    pub rsrp: Option<f64>,
    pub rsrq: Option<f64>,
    pub srxlev: Option<f64>,
    pub scs: String,
    pub band: String,
    pub cell_id: String,
    pub tac: String,
    pub bandwidth: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegStateInfo {
    pub stat: Option<i32>,
    pub label: String,
    pub tac: String,
    pub cell_id: String,
}

pub fn clean_at_lines(resp: &str) -> Vec<String> {
    resp.lines()
        .map(|l| l.trim().trim_end_matches('\r'))
        .filter(|l| {
            !l.is_empty()
                && *l != "OK"
                && *l != "ERROR"
                && !l.starts_with("+CME ERROR")
                && !l.starts_with("+CMS ERROR")
                && !is_at_echo(l)
        })
        .map(|s| s.to_string())
        .collect()
}

fn is_at_echo(line: &str) -> bool {
    let up = line.to_ascii_uppercase();
    up == "AT" || up.starts_with("AT+") || up.starts_with("ATE")
}

pub fn unquote(v: Option<&str>) -> String {
    let Some(raw) = v else {
        return String::new();
    };
    let s = raw.trim();
    if s == "-" || s.eq_ignore_ascii_case("null") || s.eq_ignore_ascii_case("N/A") {
        return String::new();
    }
    s.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(s)
        .trim()
        .to_string()
}

fn to_i32(v: Option<&str>) -> Option<i32> {
    let s = unquote(v);
    if s.is_empty() {
        return None;
    }
    s.parse::<i32>().ok()
}

fn to_i64(v: Option<&str>) -> Option<i64> {
    let s = unquote(v);
    if s.is_empty() {
        return None;
    }
    s.parse::<i64>().ok()
}

fn to_f64(v: Option<&str>) -> Option<f64> {
    let s = unquote(v);
    if s.is_empty() {
        return None;
    }
    s.parse::<f64>().ok().filter(|n| n.is_finite())
}

pub fn split_csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                fields.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    fields.push(cur.trim().to_string());
    fields
}

pub fn parse_scalar_at_value(resp: &str, prefix: &str) -> String {
    for line in clean_at_lines(resp) {
        if !prefix.is_empty() {
            if let Some(rest) = line.strip_prefix(prefix) {
                let cleaned = rest.trim_start_matches([':', ' ', '\t']);
                return unquote(Some(cleaned));
            }
            continue;
        }
        return unquote(Some(&line));
    }
    String::new()
}

pub fn decode_nr_bw_mhz(code: Option<i32>, arfcn: Option<i64>, from_qeng: bool) -> Option<f64> {
    let c = code?;
    let is_fr1 = arfcn.is_some_and(|a| a > 0 && a < 2_054_166);
    if from_qeng && is_fr1 && c == 14 {
        return Some(90.0);
    }
    let mhz = match c {
        0 => 5.0,
        1 => 10.0,
        2 => 15.0,
        3 => 20.0,
        4 => 25.0,
        5 => 30.0,
        6 => 40.0,
        7 => 50.0,
        8 => 60.0,
        9 => 70.0,
        10 => 80.0,
        11 => 90.0,
        12 => 100.0,
        13 => 200.0,
        14 => 400.0,
        _ => return None,
    };
    if is_fr1 && mhz > 100.0 {
        return None;
    }
    Some(mhz)
}

pub fn decode_lte_bw_mhz(code: Option<i32>) -> Option<f64> {
    match code? {
        0 | 6 => Some(1.4),
        1 | 15 => Some(3.0),
        2 | 25 => Some(5.0),
        3 | 50 => Some(10.0),
        4 | 75 => Some(15.0),
        5 | 100 => Some(20.0),
        _ => None,
    }
}

fn decode_scs_khz(code: Option<i32>) -> Option<u32> {
    match code? {
        0 => Some(15),
        1 => Some(30),
        2 => Some(60),
        3 => Some(120),
        4 => Some(240),
        _ => None,
    }
}

pub fn parse_carrier_aggregation(resp: &str) -> Vec<CarrierComponent> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QCAINFO:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let role = unquote(f.first().map(|s| s.as_str())).to_ascii_uppercase();
        if role != "PCC" && role != "SCC" {
            continue;
        }
        let Some(arfcn) = to_i64(f.get(1).map(|s| s.as_str())) else {
            continue;
        };
        let Some(bw_code) = to_i32(f.get(2).map(|s| s.as_str())) else {
            continue;
        };
        let band_raw = unquote(f.get(3).map(|s| s.as_str()));
        let is_nr = band_raw.to_ascii_uppercase().contains("NR5G");
        let bandwidth_mhz = if is_nr {
            decode_nr_bw_mhz(Some(bw_code), Some(arfcn), false)
        } else {
            decode_lte_bw_mhz(Some(bw_code))
        };

        let (pcell_state, pci, ul_configured, ul_arfcn, ul_bandwidth_mhz, rsrp, rsrq, rssi, sinr) = if is_nr {
            let pcell_state = if role == "SCC" {
                to_i32(f.get(4).map(|s| s.as_str()))
            } else {
                None
            };
            let pci = if role == "PCC" {
                to_i32(f.get(4).map(|s| s.as_str()))
            } else {
                to_i32(f.get(5).map(|s| s.as_str()))
            };
            let ul_flag = if role == "SCC" {
                to_i32(f.get(6).map(|s| s.as_str()))
            } else {
                None
            };
            let ul_bw_code = if role == "SCC" {
                to_i32(f.get(7).map(|s| s.as_str()))
            } else {
                None
            };
            let ul_arfcn = if role == "SCC" {
                to_i64(f.get(8).map(|s| s.as_str()))
            } else {
                None
            };
            let ul_bandwidth_mhz = if role == "SCC" && ul_bw_code.is_some() {
                decode_nr_bw_mhz(ul_bw_code, ul_arfcn.or(Some(arfcn)), false)
            } else {
                None
            };
            (pcell_state, pci, role == "PCC" || ul_flag == Some(1), ul_arfcn, ul_bandwidth_mhz, None, None, None, None)
        } else {
            // Quectel LTE +QCAINFO: "PCC"|"SCC",<earfcn>,<bw>,<band>,<state>,<pcid>,<rsrp>,<rsrq>,<rssi>,<sinr>
            let (pcell_state, pci) = if f.len() >= 6 {
                (to_i32(f.get(4).map(|s| s.as_str())), to_i32(f.get(5).map(|s| s.as_str())))
            } else {
                (None, to_i32(f.get(4).map(|s| s.as_str())))
            };
            let filt = |v: Option<f64>| v.filter(|&x| x != -140.0 && x != -32768.0);
            (
                pcell_state,
                pci,
                role == "PCC",
                None,
                None,
                filt(to_f64(f.get(6).map(|s| s.as_str()))),
                filt(to_f64(f.get(7).map(|s| s.as_str()))),
                filt(to_f64(f.get(8).map(|s| s.as_str()))),
                filt(to_f64(f.get(9).map(|s| s.as_str()))),
            )
        };

        let compact_band = compact_band_name(&band_raw);
        out.push(CarrierComponent {
            role: role.clone(),
            arfcn,
            bandwidth_code: bw_code,
            bandwidth_mhz,
            band: compact_band,
            pci,
            pcell_state,
            ul_configured,
            ul_arfcn,
            ul_bandwidth_mhz,
            rsrp,
            rsrq,
            rssi,
            sinr,
            dl_mimo_layers: None,
            ul_mimo_layers: None,
        });
    }
    out
}

fn compact_band_name(band_raw: &str) -> String {
    let up = band_raw.trim().to_ascii_uppercase();
    if let Some(rest) = up.strip_prefix("NR5G BAND ") {
        return format!("n{}", rest.trim());
    }
    if let Some(rest) = up.strip_prefix("LTE BAND ") {
        return format!("B{}", rest.trim());
    }
    if band_raw.trim().is_empty() {
        "-".into()
    } else {
        band_raw.trim().to_string()
    }
}

pub fn parse_serving_cell(
    qeng_resp: &str,
    carriers: &[CarrierComponent],
) -> Option<ServingCellInfo> {
    let pcc = carriers.iter().find(|c| c.role == "PCC");
    let mut header_only: Option<ServingCellInfo> = None;
    let mut endc_anchor: Option<ServingCellInfo> = None;

    for line in clean_at_lines(qeng_resp) {
        let Some(body) = line.strip_prefix("+QENG:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let kind = unquote(f.first().map(|s| s.as_str())).to_ascii_lowercase();
        if kind == "servingcell" {
            let state = {
                let s = unquote(f.get(1).map(|s| s.as_str()));
                if s.is_empty() { "UNKNOWN".into() } else { s }
            };
            let rat = unquote(f.get(2).map(|s| s.as_str())).to_ascii_uppercase();
            if rat == "NR5G-SA" {
                let arfcn = to_i64(f.get(9).map(|s| s.as_str()));
                let band_num = unquote(f.get(10).map(|s| s.as_str()));
                let dl_code = to_i32(f.get(11).map(|s| s.as_str()));
                let pci = to_i32(f.get(7).map(|s| s.as_str()));
                let raw_dl_bw = decode_nr_bw_mhz(dl_code, arfcn, true);
                let resolved_bw = pcc.and_then(|c| c.bandwidth_mhz).or(raw_dl_bw);
                return Some(ServingCellInfo {
                    state,
                    rat,
                    duplex_mode: non_empty_or(unquote(f.get(3).map(|s| s.as_str())), "-"),
                    mcc: unquote(f.get(4).map(|s| s.as_str())),
                    mnc: unquote(f.get(5).map(|s| s.as_str())),
                    cell_id: unquote(f.get(6).map(|s| s.as_str())),
                    pci,
                    tac: unquote(f.get(8).map(|s| s.as_str())),
                    arfcn,
                    band: if band_num.is_empty() {
                        pcc.map(|c| c.band.clone()).unwrap_or_else(|| "-".into())
                    } else {
                        format!("n{band_num}")
                    },
                    ul_bandwidth_mhz: resolved_bw,
                    dl_bandwidth_mhz: resolved_bw,
                    rsrp: to_f64(f.get(12).map(|s| s.as_str())),
                    rsrq: to_f64(f.get(13).map(|s| s.as_str())),
                    sinr: to_f64(f.get(14).map(|s| s.as_str())),
                    tx_power: None,
                    scs_khz: decode_scs_khz(to_i32(f.get(15).map(|s| s.as_str()))),
                    srxlev: to_f64(f.get(16).map(|s| s.as_str())),
                    raw: line,
                    ..Default::default()
                });
            }
            if rat == "LTE" {
                let band_num = unquote(f.get(9).map(|s| s.as_str()));
                return Some(ServingCellInfo {
                    state,
                    rat,
                    duplex_mode: non_empty_or(unquote(f.get(3).map(|s| s.as_str())), "-"),
                    mcc: unquote(f.get(4).map(|s| s.as_str())),
                    mnc: unquote(f.get(5).map(|s| s.as_str())),
                    cell_id: unquote(f.get(6).map(|s| s.as_str())),
                    pci: to_i32(f.get(7).map(|s| s.as_str())),
                    tac: unquote(f.get(12).map(|s| s.as_str())),
                    arfcn: to_i64(f.get(8).map(|s| s.as_str())),
                    band: if band_num.is_empty() {
                        "-".into()
                    } else {
                        format!("B{band_num}")
                    },
                    ul_bandwidth_mhz: decode_lte_bw_mhz(to_i32(f.get(10).map(|s| s.as_str()))),
                    dl_bandwidth_mhz: decode_lte_bw_mhz(to_i32(f.get(11).map(|s| s.as_str()))),
                    rsrp: to_f64(f.get(13).map(|s| s.as_str())),
                    rsrq: to_f64(f.get(14).map(|s| s.as_str())),
                    sinr: to_f64(f.get(16).map(|s| s.as_str())),
                    tx_power: None,
                    srxlev: to_f64(f.get(17).map(|s| s.as_str())),
                    raw: line,
                    ..Default::default()
                });
            }
            if rat.is_empty() {
                // Multi-line EN-DC (or SEARCH) header; defer returning so following `+QENG: "LTE",...` / `"NR5G-NSA",...` lines populate.
                header_only = Some(ServingCellInfo {
                    state,
                    rat: "UNKNOWN".into(),
                    duplex_mode: non_empty_or(unquote(f.get(3).map(|s| s.as_str())), "-"),
                    mcc: unquote(f.get(4).map(|s| s.as_str())),
                    mnc: unquote(f.get(5).map(|s| s.as_str())),
                    cell_id: unquote(f.get(6).map(|s| s.as_str())),
                    pci: to_i32(f.get(7).map(|s| s.as_str())),
                    tac: unquote(f.get(8).map(|s| s.as_str())),
                    arfcn: to_i64(f.get(9).map(|s| s.as_str())),
                    band: non_empty_or(unquote(f.get(10).map(|s| s.as_str())), "-"),
                    ul_bandwidth_mhz: None,
                    dl_bandwidth_mhz: None,
                    rsrp: to_f64(f.get(12).map(|s| s.as_str())),
                    rsrq: to_f64(f.get(13).map(|s| s.as_str())),
                    sinr: to_f64(f.get(14).map(|s| s.as_str())),
                    tx_power: None,
                    srxlev: None,
                    raw: line,
                    ..Default::default()
                });
                continue;
            }
            return Some(ServingCellInfo {
                state,
                rat,
                duplex_mode: non_empty_or(unquote(f.get(3).map(|s| s.as_str())), "-"),
                mcc: unquote(f.get(4).map(|s| s.as_str())),
                mnc: unquote(f.get(5).map(|s| s.as_str())),
                cell_id: unquote(f.get(6).map(|s| s.as_str())),
                pci: to_i32(f.get(7).map(|s| s.as_str())),
                tac: unquote(f.get(8).map(|s| s.as_str())),
                arfcn: to_i64(f.get(9).map(|s| s.as_str())),
                band: non_empty_or(unquote(f.get(10).map(|s| s.as_str())), "-"),
                ul_bandwidth_mhz: None,
                dl_bandwidth_mhz: None,
                rsrp: to_f64(f.get(12).map(|s| s.as_str())),
                rsrq: to_f64(f.get(13).map(|s| s.as_str())),
                sinr: to_f64(f.get(14).map(|s| s.as_str())),
                tx_power: None,
                srxlev: None,
                raw: line,
                ..Default::default()
            });
        }
        if kind == "lte" {
            let band_num = unquote(f.get(7).map(|s| s.as_str()));
            endc_anchor = Some(ServingCellInfo {
                state: header_only
                    .as_ref()
                    .map(|h| h.state.clone())
                    .unwrap_or_else(|| "CONNECT".into()),
                rat: "LTE (EN-DC)".into(),
                duplex_mode: non_empty_or(unquote(f.get(1).map(|s| s.as_str())), "-"),
                mcc: unquote(f.get(2).map(|s| s.as_str())),
                mnc: unquote(f.get(3).map(|s| s.as_str())),
                cell_id: unquote(f.get(4).map(|s| s.as_str())),
                pci: to_i32(f.get(5).map(|s| s.as_str())),
                tac: unquote(f.get(10).map(|s| s.as_str())),
                arfcn: to_i64(f.get(6).map(|s| s.as_str())),
                band: if band_num.is_empty() {
                    "-".into()
                } else {
                    format!("B{band_num}")
                },
                ul_bandwidth_mhz: decode_lte_bw_mhz(to_i32(f.get(8).map(|s| s.as_str()))),
                dl_bandwidth_mhz: decode_lte_bw_mhz(to_i32(f.get(9).map(|s| s.as_str()))),
                rsrp: to_f64(f.get(11).map(|s| s.as_str())),
                rsrq: to_f64(f.get(12).map(|s| s.as_str())),
                sinr: to_f64(f.get(14).map(|s| s.as_str())),
                tx_power: None,
                srxlev: to_f64(f.get(16).map(|s| s.as_str())),
                raw: line,
                ..Default::default()
            });
            continue;
        }
        if kind == "nr5g-nsa" {
            let nr_pci = to_i32(f.get(3).map(|s| s.as_str()));
            let nr_rsrp = to_f64(f.get(4).map(|s| s.as_str()));
            let nr_sinr = to_f64(f.get(5).map(|s| s.as_str()));
            let nr_rsrq = to_f64(f.get(6).map(|s| s.as_str()));
            let nr_arfcn = to_i64(f.get(7).map(|s| s.as_str()));
            let nr_band_num = unquote(f.get(8).map(|s| s.as_str()));
            let nr_bw = decode_nr_bw_mhz(to_i32(f.get(9).map(|s| s.as_str())), nr_arfcn, true);
            let nr_scs = decode_scs_khz(to_i32(f.get(10).map(|s| s.as_str())));
            let nr_band = (!nr_band_num.is_empty()).then(|| format!("n{nr_band_num}"));

            let info = endc_anchor.get_or_insert_with(|| ServingCellInfo {
                state: header_only
                    .as_ref()
                    .map(|h| h.state.clone())
                    .unwrap_or_else(|| "CONNECT".into()),
                rat: "NR5G-NSA".into(),
                mcc: unquote(f.get(1).map(|s| s.as_str())),
                mnc: unquote(f.get(2).map(|s| s.as_str())),
                pci: nr_pci,
                arfcn: nr_arfcn,
                band: nr_band.clone().unwrap_or_else(|| "-".into()),
                dl_bandwidth_mhz: nr_bw,
                ul_bandwidth_mhz: nr_bw,
                rsrp: nr_rsrp,
                sinr: nr_sinr,
                rsrq: nr_rsrq,
                raw: line.clone(),
                ..Default::default()
            });
            info.nsa_nr5g_pci = nr_pci;
            info.nsa_nr5g_arfcn = nr_arfcn;
            info.nsa_nr5g_band = nr_band;
            info.nsa_nr5g_rsrp = nr_rsrp;
            info.nsa_nr5g_sinr = nr_sinr;
            info.nsa_nr5g_rsrq = nr_rsrq;
            info.nsa_nr5g_bw_mhz = nr_bw;
            if let Some(s) = nr_scs {
                info.scs_khz = Some(s);
            }
        }
    }
    endc_anchor.or(header_only)
}

fn non_empty_or(val: String, fallback: &str) -> String {
    if val.is_empty() {
        fallback.into()
    } else {
        val
    }
}

pub fn parse_mimo_signal(qrsrp_resp: &str, qrsrq_resp: &str, qsinr_resp: &str) -> MimoSignalData {
    let parse_tuples = |resp: &str, prefix: &str| -> Vec<(Vec<Option<f64>>, String)> {
        clean_at_lines(resp)
            .into_iter()
            .filter(|l| l.starts_with(prefix))
            .map(|line| {
                let rest = line[prefix.len()..].trim_start_matches([':', ' ', '\t']);
                let f = split_csv_fields(rest);
                let vals = (0..4)
                    .map(|i| {
                        to_f64(f.get(i).map(|s| s.as_str()))
                            .filter(|&n| n != -140.0 && n != -32768.0 && n != 255.0)
                    })
                    .collect();
                let rat = unquote(f.get(4).map(|s| s.as_str()));
                (vals, rat)
            })
            .collect()
    };

    let pick_best = |tuples: Vec<(Vec<Option<f64>>, String)>, preferred_rat: Option<&str>| -> (Vec<Option<f64>>, String) {
        let is_nr = |r: &str| r.to_ascii_uppercase().contains("NR5G");
        let has_valid = |v: &[Option<f64>]| v.iter().any(Option::is_some);

        if let Some(pref) = preferred_rat {
            let want_nr = is_nr(pref);
            if let Some(hit) = tuples
                .iter()
                .find(|(v, r)| is_nr(r) == want_nr && has_valid(v))
            {
                return hit.clone();
            }
        }
        // In EN-DC when both `,LTE` and `,NR5G` lines are present, prefer `,NR5G` when valid.
        if let Some(nr) = tuples.iter().find(|(v, r)| is_nr(r) && has_valid(v)) {
            return nr.clone();
        }
        if let Some(valid) = tuples.iter().find(|(v, _)| has_valid(v)) {
            return valid.clone();
        }
        if let Some(nr_any) = tuples.iter().find(|(_, r)| is_nr(r)) {
            return nr_any.clone();
        }
        tuples
            .into_iter()
            .next()
            .unwrap_or_else(|| (vec![None, None, None, None], String::new()))
    };

    let (rsrp, r1) = pick_best(parse_tuples(qrsrp_resp, "+QRSRP"), None);
    let pref = (!r1.is_empty()).then_some(r1.as_str());
    let (rsrq, r2) = pick_best(parse_tuples(qrsrq_resp, "+QRSRQ"), pref);
    let (sinr, r3) = pick_best(parse_tuples(qsinr_resp, "+QSINR"), pref);
    let rat = [r1, r2, r3]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_else(|| "NR5G".into());
    MimoSignalData {
        rsrp,
        rsrq,
        sinr,
        rat,
    }
}

fn format_ipv6_rfc5952(hextets: &[u16; 8]) -> String {
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    let mut in_run = false;
    for (i, &h) in hextets.iter().enumerate() {
        if h == 0 {
            if !in_run {
                cur_start = i;
                cur_len = 1;
                in_run = true;
            } else {
                cur_len += 1;
            }
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            in_run = false;
        }
    }
    if best_len < 2 {
        return hextets
            .iter()
            .map(|h| format!("{h:x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    let left = hextets[..best_start]
        .iter()
        .map(|h| format!("{h:x}"))
        .collect::<Vec<_>>()
        .join(":");
    let right = hextets[best_start + best_len..]
        .iter()
        .map(|h| format!("{h:x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("{left}::{right}")
}

pub fn decode_3gpp_address(raw: Option<&str>) -> (String, Option<u8>) {
    let s = unquote(raw);
    if s.is_empty() {
        return (String::new(), None);
    }
    if s.contains(':') {
        let mut parts = s.splitn(2, '/');
        let addr = parts.next().unwrap_or("").trim().to_string();
        let plen = parts.next().and_then(|p| p.trim().parse::<u8>().ok());
        return (addr, plen);
    }
    let octets_opt: Option<Vec<u8>> = s.split('.').map(|p| p.parse::<u8>().ok()).collect();
    let Some(octets) = octets_opt else {
        return (s, None);
    };
    if octets.len() == 4 {
        return (
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            None,
        );
    }
    if octets.len() == 8 {
        let mut prefix = 0u8;
        'outer4: for &b in &octets[4..8] {
            for bit in (0..8).rev() {
                if (b >> bit) & 1 == 1 {
                    prefix += 1;
                } else {
                    break 'outer4;
                }
            }
        }
        return (
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
            if prefix > 0 { Some(prefix) } else { None },
        );
    }
    if octets.len() == 16 || octets.len() == 32 {
        let mut hextets = [0u16; 8];
        for i in 0..8 {
            hextets[i] = ((octets[i * 2] as u16) << 8) | (octets[i * 2 + 1] as u16);
        }
        let plen = if octets.len() == 32 {
            let mut bits = 0u8;
            'outer6: for &b in &octets[16..32] {
                for bit in (0..8).rev() {
                    if (b >> bit) & 1 == 1 {
                        bits += 1;
                    } else {
                        break 'outer6;
                    }
                }
            }
            if bits > 0 { Some(bits) } else { None }
        } else {
            None
        };
        return (format_ipv6_rfc5952(&hextets), plen);
    }
    (s, None)
}

pub fn parse_active_wwan(qmap_wwan_resp: &str, cgcontrdp_resp: &str) -> Vec<WwanBearerInfo> {
    let mut by_cid: BTreeMap<i32, WwanBearerInfo> = BTreeMap::new();

    for line in clean_at_lines(cgcontrdp_resp) {
        let Some(body) = line.strip_prefix("+CGCONTRDP:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let cid = to_i32(f.first().map(|s| s.as_str())).unwrap_or(1);
        let apn = unquote(f.get(2).map(|s| s.as_str()));
        let (loc_addr, loc_plen) = decode_3gpp_address(f.get(3).map(|s| s.as_str()));
        let (gw_addr, _) = decode_3gpp_address(f.get(4).map(|s| s.as_str()));
        let (dns1_addr, _) = decode_3gpp_address(f.get(5).map(|s| s.as_str()));
        let (dns2_addr, _) = decode_3gpp_address(f.get(6).map(|s| s.as_str()));

        let entry = by_cid.entry(cid).or_insert_with(|| WwanBearerInfo {
            iface: "rmnet_data1".into(),
            cid,
            ip_type: "IPV4V6".into(),
            status: "CONNECTED".into(),
            apn: apn.clone(),
            ..Default::default()
        });
        if loc_addr.contains(':') {
            entry.ipv6 = Some(loc_addr);
            entry.ipv6_prefix_length = loc_plen;
            if !gw_addr.is_empty() {
                entry.ipv6_gateway = Some(gw_addr);
            }
            if !dns1_addr.is_empty() {
                entry.ipv6_dns1 = Some(dns1_addr);
            }
            if !dns2_addr.is_empty() {
                entry.ipv6_dns2 = Some(dns2_addr);
            }
        } else if !loc_addr.is_empty() {
            entry.ipv4 = Some(loc_addr);
            if !gw_addr.is_empty() {
                entry.ipv4_gateway = Some(gw_addr);
            }
            if !dns1_addr.is_empty() {
                entry.ipv4_dns1 = Some(dns1_addr);
            }
            if !dns2_addr.is_empty() {
                entry.ipv4_dns2 = Some(dns2_addr);
            }
        }
        if entry.apn.is_empty() && !apn.is_empty() {
            entry.apn = apn;
        }
    }

    for line in clean_at_lines(qmap_wwan_resp) {
        let Some(body) = line.strip_prefix("+QMAP:") else {
            continue;
        };
        let f = split_csv_fields(body);
        if !unquote(f.first().map(|s| s.as_str())).eq_ignore_ascii_case("WWAN") {
            continue;
        }
        let state_num = to_i32(f.get(1).map(|s| s.as_str()));
        let cid = to_i32(f.get(2).map(|s| s.as_str())).unwrap_or(1);
        let ip_type = unquote(f.get(3).map(|s| s.as_str())).to_ascii_uppercase();
        let addr = unquote(f.get(4).map(|s| s.as_str()));
        let iface = unquote(f.get(5).map(|s| s.as_str()));

        let entry = by_cid.entry(cid).or_insert_with(|| WwanBearerInfo {
            iface: if iface.is_empty() {
                "rmnet_data1".into()
            } else {
                iface.clone()
            },
            cid,
            ip_type: if ip_type == "IPV4" || ip_type == "IPV6" {
                ip_type.clone()
            } else {
                "IPV4V6".into()
            },
            status: if state_num == Some(1) {
                "CONNECTED".into()
            } else {
                "DISCONNECTED".into()
            },
            apn: String::new(),
            ..Default::default()
        });
        if iface.starts_with("rmnet") {
            entry.iface = iface;
        }
        if state_num == Some(1) {
            entry.status = "CONNECTED".into();
        }
        if ip_type == "IPV4" && !addr.is_empty() && addr != "0.0.0.0" {
            entry.ipv4 = Some(addr);
        } else if ip_type == "IPV6" && !addr.is_empty() && addr != "::" {
            entry.ipv6 = Some(addr);
        }
    }

    by_cid.into_values().collect()
}

pub fn overlay_native_bearer(
    bearers: &mut Vec<WwanBearerInfo>,
    overlay: crate::dataplane::NativeBearerOverlay,
) {
    let has_v4 = overlay.ipv4.as_deref().is_some_and(|s| !s.is_empty());
    let has_v6 = overlay.ipv6.as_deref().is_some_and(|s| !s.is_empty());
    if !has_v4 && !has_v6 && !overlay.connected {
        return;
    }

    if bearers.is_empty() {
        bearers.push(WwanBearerInfo {
            iface: overlay.iface.clone(),
            cid: i32::from(overlay.profile_index),
            ip_type: match (has_v4, has_v6) {
                (true, true) => "IPV4V6".into(),
                (true, false) => "IPV4".into(),
                _ => "IPV6".into(),
            },
            status: if overlay.connected { "CONNECTED" } else { "DISCONNECTED" }.into(),
            apn: String::new(),
            ..Default::default()
        });
    }

    let b = &mut bearers[0];
    b.iface = overlay.iface;
    if overlay.connected {
        b.status = "CONNECTED".into();
    }
    if has_v4 {
        b.ipv4 = overlay.ipv4;
        if let Some(gw) = overlay.ipv4_gateway.filter(|s| !s.is_empty()) {
            b.ipv4_gateway = Some(gw);
        }
        if let Some(d1) = overlay.ipv4_dns1.filter(|s| !s.is_empty()) {
            b.ipv4_dns1 = Some(d1);
        }
        if let Some(d2) = overlay.ipv4_dns2.filter(|s| !s.is_empty()) {
            b.ipv4_dns2 = Some(d2);
        }
    }
    if has_v6 {
        b.ipv6 = overlay.ipv6;
        if let Some(plen) = overlay.ipv6_prefix_length {
            b.ipv6_prefix_length = Some(plen);
        }
        if let Some(gw) = overlay.ipv6_gateway.filter(|s| !s.is_empty()) {
            b.ipv6_gateway = Some(gw);
        }
        if let Some(d1) = overlay.ipv6_dns1.filter(|s| !s.is_empty()) {
            b.ipv6_dns1 = Some(d1);
        }
        if let Some(d2) = overlay.ipv6_dns2.filter(|s| !s.is_empty()) {
            b.ipv6_dns2 = Some(d2);
        }
    }
    if b.ipv4.is_some() && b.ipv6.is_some() {
        b.ip_type = "IPV4V6".into();
    }
}

pub fn parse_nr5g_mimo_info(resp: &str) -> Vec<(i32, i64, u8, u8)> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        if !line.to_ascii_lowercase().contains("nr5g_mimo_info") {
            continue;
        }
        let body = line.strip_prefix("+QNWCFG:").unwrap_or(&line);
        let f = split_csv_fields(body);
        let Some(pci) = to_i32(f.get(1).map(|s| s.as_str())) else { continue };
        let Some(arfcn) = to_i64(f.get(2).map(|s| s.as_str())) else { continue };
        let Some(dl) = to_i32(f.get(3).map(|s| s.as_str())).and_then(|v| u8::try_from(v).ok()) else { continue };
        let ul = to_i32(f.get(4).map(|s| s.as_str()))
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0);
        out.push((pci, arfcn, dl, ul));
    }
    out
}

pub fn merge_nr5g_mimo_layers(carriers: &mut [CarrierComponent], info: &[(i32, i64, u8, u8)]) {
    for &(pci, arfcn, dl, ul) in info {
        let idx = carriers
            .iter()
            .position(|c| c.dl_mimo_layers.is_none() && c.arfcn == arfcn && c.pci == Some(pci))
            .or_else(|| carriers.iter().position(|c| c.dl_mimo_layers.is_none() && c.arfcn == arfcn));
        if let Some(i) = idx {
            carriers[i].dl_mimo_layers = Some(dl);
            carriers[i].ul_mimo_layers = Some(ul);
        }
    }
}

pub fn parse_ssb_beam_id(resp: &str) -> Option<i32> {
    for line in clean_at_lines(resp) {
        if !line.to_ascii_lowercase().contains("ssb_beam_id") {
            continue;
        }
        let body = line.strip_prefix("+QNWCFG:").unwrap_or(&line);
        let f = split_csv_fields(body);
        if f.len() >= 3
            && let Some(valid) = to_i32(f.get(1).map(|s| s.as_str()))
            && valid == 0
        {
            continue;
        }
        let candidate = f
            .iter()
            .skip(1)
            .rev()
            .find_map(|s| to_i32(Some(s.as_str())))
            .filter(|&v| (0..=64).contains(&v));
        if candidate.is_some() {
            return candidate;
        }
    }
    None
}

pub fn parse_nr5g_pathloss(resp: &str) -> Option<f64> {
    for line in clean_at_lines(resp) {
        if !line.to_ascii_lowercase().contains("nr5g_pathloss") {
            continue;
        }
        let body = line.strip_prefix("+QNWCFG:").unwrap_or(&line);
        let f = split_csv_fields(body);
        let cand = f
            .iter()
            .skip(1)
            .rev()
            .find_map(|s| to_f64(Some(s.as_str())))
            .filter(|&v| v.is_finite() && (20.0..=180.0).contains(&v));
        if cand.is_some() {
            return cand;
        }
    }
    None
}

#[cfg(test)]
pub fn parse_time_advance(lte_resp: &str, nr5g_resp: &str) -> TimeAdvanceInfo {
    parse_time_advance_for_rat(lte_resp, nr5g_resp, None)
}

pub fn parse_time_advance_for_rat(
    lte_resp: &str,
    nr5g_resp: &str,
    serving_rat: Option<&str>,
) -> TimeAdvanceInfo {
    let mut info = TimeAdvanceInfo::default();
    for line in clean_at_lines(nr5g_resp) {
        if !line.contains("nr5g_time_advance") {
            continue;
        }
        let f = split_csv_fields(line.strip_prefix("+QNWCFG:").unwrap_or(&line));
        let valid = to_i32(f.get(1).map(|s| s.as_str()));
        let raw = to_i64(f.get(2).map(|s| s.as_str()));
        if valid == Some(1)
            && let Some(r) = raw
            && (0..20_000_000).contains(&r)
        {
            info.nr5g_raw = Some(r);
            info.nr5g_meters = Some((r as f64 * 0.07624).round() as i64);
            info.nr5g_steps = Some((r as f64 / 512.0).round() as i64);
            break;
        }
    }
    for line in clean_at_lines(lte_resp) {
        if !line.contains("lte_time_advance") {
            continue;
        }
        let f = split_csv_fields(line.strip_prefix("+QNWCFG:").unwrap_or(&line));
        let valid = if f.len() >= 3 {
            to_i32(f.get(1).map(|s| s.as_str()))
        } else {
            Some(1)
        };
        let ta = if f.len() >= 3 {
            to_i64(f.get(2).map(|s| s.as_str()))
        } else {
            to_i64(f.get(1).map(|s| s.as_str()))
        };
        if valid == Some(1)
            && let Some(t) = ta
            && (0..65_535).contains(&t)
        {
            info.lte_ta = Some(t);
            info.lte_meters = Some((t as f64 * 78.12).round() as i64);
            break;
        }
    }
    let is_nr_sa = serving_rat.is_some_and(|r| r.contains("NR5G-SA"));
    info.active_meters = if is_nr_sa {
        info.nr5g_meters
    } else {
        info.nr5g_meters.or(info.lte_meters)
    };
    info
}

pub fn parse_3gpp_rel(resp: &str) -> String {
    for line in clean_at_lines(resp) {
        let stripped = line.strip_prefix("+QNWCFG:").unwrap_or(&line);
        let f = split_csv_fields(stripped);
        let token = unquote(f.get(1).map(|s| s.as_str()));
        let candidate = if token.is_empty() {
            line.replace("\"3gpp_rel\"", "")
        } else {
            token
        };
        let digits: String = candidate
            .trim()
            .trim_start_matches(['R', 'r'])
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            return format!("3GPP Rel-{digits}");
        }
    }
    "N/A".into()
}

pub fn infer_lan_netmask(pool_start: &str, pool_end: &str, gateway_ip: &str) -> String {
    let parse_v4 = |ip: &str| -> Option<u32> {
        let octs: Vec<u32> = ip.split('.').map(|o| o.parse::<u32>().ok()).collect::<Option<_>>()?;
        if octs.len() != 4 || octs.iter().any(|&x| x > 255) {
            return None;
        }
        Some((octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3])
    };
    let nums: Vec<u32> = [pool_start, pool_end, gateway_ip]
        .into_iter()
        .filter_map(parse_v4)
        .collect();
    if nums.len() < 2 {
        return String::new();
    }
    let min_ip = *nums.iter().min().unwrap_or(&0);
    let max_ip = *nums.iter().max().unwrap_or(&0);
    let xor = min_ip ^ max_ip;
    let host_bits = if xor == 0 {
        8
    } else {
        (32 - xor.leading_zeros()).max(2)
    };
    let prefix = 32 - host_bits;
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    format!(
        "{}.{}.{}.{} (/{prefix})",
        (mask >> 24) & 255,
        (mask >> 16) & 255,
        (mask >> 8) & 255,
        mask & 255
    )
}

pub fn parse_qmap_lan_ip(resp: &str) -> Option<QmapLanIpInfo> {
    for line in clean_at_lines(resp) {
        if !line.to_ascii_uppercase().contains("LANIP") {
            continue;
        }
        let body = line.strip_prefix("+QMAP:").unwrap_or(&line);
        let f = split_csv_fields(body);
        let ips: Vec<String> = f
            .into_iter()
            .skip(1)
            .map(|s| unquote(Some(&s)))
            .filter(|s| !s.is_empty())
            .collect();
        if ips.len() >= 4 {
            let raw = ips.join(", ");
            return Some(QmapLanIpInfo {
                pool_start: ips[0].clone(),
                pool_end: ips[1].clone(),
                gateway_ip: ips[2].clone(),
                netmask: ips[3].clone(),
                raw,
            });
        }
        if ips.len() == 3 {
            let mask = infer_lan_netmask(&ips[0], &ips[1], &ips[2]);
            let raw = ips.join(", ");
            return Some(QmapLanIpInfo {
                pool_start: ips[0].clone(),
                pool_end: ips[1].clone(),
                gateway_ip: ips[2].clone(),
                netmask: mask,
                raw,
            });
        }
        if !ips.is_empty() {
            let raw = ips.join(", ");
            return Some(QmapLanIpInfo {
                pool_start: ips.first().cloned().unwrap_or_default(),
                pool_end: ips.get(1).cloned().unwrap_or_default(),
                gateway_ip: ips.first().cloned().unwrap_or_default(),
                netmask: String::new(),
                raw,
            });
        }
    }
    None
}

pub fn parse_mpdn_rules(resp: &str) -> Vec<MpdnRule> {
    let mut rules = Vec::new();
    for line in clean_at_lines(resp) {
        if !line.to_ascii_uppercase().contains("MPDN_RULE") {
            continue;
        }
        let body = line.strip_prefix("+QMAP:").unwrap_or(&line);
        let f = split_csv_fields(body);
        let Some(slot) = to_i32(f.get(1).map(|s| s.as_str())) else {
            continue;
        };
        let Some(apn_slot) = to_i32(f.get(2).map(|s| s.as_str())) else {
            continue;
        };
        let vlan_id = to_i32(f.get(3).map(|s| s.as_str())).unwrap_or(0);
        let mode = non_empty_or(unquote(f.get(4).map(|s| s.as_str())), "0");
        let cand = unquote(f.get(6).or_else(|| f.get(5)).map(|s| s.as_str()));
        let mac = if is_valid_mac(&cand) {
            cand
        } else {
            String::new()
        };
        rules.push(MpdnRule {
            slot,
            apn_slot,
            vlan_id,
            mode,
            mac,
            raw: line,
        });
    }
    rules
}

pub fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn classify_thermal_domain(sensor: &str) -> &'static str {
    let s = sensor.to_ascii_lowercase();
    if s.contains("cpu") || s.contains("apss") || s.contains("nspss") {
        "CPU Cluster"
    } else if s.contains("mdm") || s.contains("modem") || s.contains("ddr") || s.contains("q6") {
        "Baseband & DSP"
    } else if s.contains("rf")
        || s.contains("pa")
        || s.contains("qtm")
        || s.contains("sdr")
        || s.contains("fbrx")
        || s.contains("xo")
    {
        "RF Transceiver"
    } else {
        "PHY & Chassis"
    }
}

pub fn parse_temp_sensors(resp: &str) -> Vec<TempSensor> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QTEMP:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let sensor = unquote(f.first().map(|s| s.as_str()));
        if let Some(celsius) = to_f64(f.get(1).map(|s| s.as_str()))
            && !sensor.is_empty()
            && celsius > -40.0
            && celsius < 150.0
        {
            let domain = classify_thermal_domain(&sensor).to_string();
            out.push(TempSensor {
                sensor,
                celsius,
                domain,
            });
        }
    }
    out
}

pub fn parse_sysfs_thermal_entry(sensor: &str, raw_millic: &str) -> Option<TempSensor> {
    let name = sensor.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("zeroc") {
        return None;
    }
    let millic: i64 = raw_millic.trim().parse().ok()?;
    // Reject Qualcomm unpopulated/open-circuit NTC sentinels (-273°C, -40.96°C) and bogus highs.
    if millic <= -35_000 || millic > 150_000 {
        return None;
    }
    let celsius = (millic as f64 / 100.0).round() / 10.0;
    Some(TempSensor {
        sensor: name.to_string(),
        celsius,
        domain: classify_thermal_domain(name).to_string(),
    })
}

pub fn read_sysfs_thermals() -> Vec<TempSensor> {
    let base_s = crate::paths::p("/sys/class/thermal");
    let Ok(rd) = fs::read_dir(Path::new(&base_s)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(name) = fname.to_str() else { continue };
        if !name.starts_with("thermal_zone") {
            continue;
        }
        let dir = ent.path();
        let Ok(sensor) = fs::read_to_string(dir.join("type")) else {
            continue;
        };
        let Ok(temp_raw) = fs::read_to_string(dir.join("temp")) else {
            continue;
        };
        if let Some(t) = parse_sysfs_thermal_entry(&sensor, &temp_raw) {
            out.push(t);
        }
    }
    out.sort_by(|a, b| a.sensor.cmp(&b.sensor));
    out
}

pub fn parse_mbn_list(resp: &str) -> Vec<MbnProfile> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QMBNCFG:") else {
            continue;
        };
        let f = split_csv_fields(body);
        if !unquote(f.first().map(|s| s.as_str())).eq_ignore_ascii_case("list") {
            continue;
        }
        let Some(index) = to_i32(f.get(1).map(|s| s.as_str())) else {
            continue;
        };
        let selected = to_i32(f.get(2).map(|s| s.as_str())) == Some(1);
        let activated = to_i32(f.get(3).map(|s| s.as_str())) == Some(1);
        let name = unquote(f.get(4).map(|s| s.as_str()));
        if !name.is_empty() {
            out.push(MbnProfile {
                index,
                selected,
                activated,
                name,
                version: unquote(f.get(5).map(|s| s.as_str())),
                date: unquote(f.get(6).map(|s| s.as_str())),
            });
        }
    }
    out
}

pub fn parse_qspn_operator(resp: &str) -> String {
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QSPN:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let full = unquote(f.first().map(|s| s.as_str()));
        if !full.is_empty() {
            return full;
        }
        let short = unquote(f.get(1).map(|s| s.as_str()));
        if !short.is_empty() {
            return short;
        }
    }
    String::new()
}

pub fn parse_reg_state(resp: &str) -> RegStateInfo {
    for line in clean_at_lines(resp) {
        let body = line
            .strip_prefix("+C5GREG:")
            .or_else(|| line.strip_prefix("+CEREG:"))
            .or_else(|| line.strip_prefix("+CGREG:"))
            .or_else(|| line.strip_prefix("+CREG:"));
        let Some(body) = body else {
            continue;
        };
        let f = split_csv_fields(body);
        let f0 = to_i32(f.first().map(|s| s.as_str()));
        let f1 = to_i32(f.get(1).map(|s| s.as_str()));
        let stat = match (f0, f1) {
            (Some(n), Some(s)) if (0..=2).contains(&n) && (0..=11).contains(&s) => Some(s),
            _ => f0,
        };
        let label = match stat {
            Some(0) => "Not Registered".into(),
            Some(1) => "Registered (Home)".into(),
            Some(2) => "Searching".into(),
            Some(3) => "Denied".into(),
            Some(4) => "Unknown".into(),
            Some(5) => "Registered (Roaming)".into(),
            Some(s) => format!("State {s}"),
            None => "Unknown".into(),
        };
        return RegStateInfo {
            stat,
            label,
            tac: unquote(f.get(2).map(|s| s.as_str())),
            cell_id: unquote(f.get(3).map(|s| s.as_str())),
        };
    }
    RegStateInfo {
        stat: None,
        label: "Unknown".into(),
        tac: String::new(),
        cell_id: String::new(),
    }
}

pub fn parse_neighbor_cells(resp: &str) -> Vec<NeighborCellInfo> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QENG:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let kind = unquote(f.first().map(|s| s.as_str())).to_ascii_lowercase();
        if !kind.contains("neighbourcell") && !kind.contains("neighborcell") {
            continue;
        }
        let rat = non_empty_or(
            unquote(f.get(1).map(|s| s.as_str())).to_ascii_uppercase(),
            if kind.contains("nr") { "NR5G" } else { "LTE" },
        );
        out.push(NeighborCellInfo {
            rat,
            r#type: if kind.contains("inter") {
                "inter".into()
            } else {
                "intra".into()
            },
            arfcn: to_i64(f.get(2).map(|s| s.as_str())),
            pci: to_i32(f.get(3).map(|s| s.as_str())),
            rsrp: to_f64(f.get(4).map(|s| s.as_str())).filter(|&v| v != -140.0),
            rsrq: to_f64(f.get(5).map(|s| s.as_str())).filter(|&v| v != -140.0),
            sinr: to_f64(f.get(6).map(|s| s.as_str())),
            srxlev: to_f64(f.get(7).map(|s| s.as_str())),
            raw: line,
        });
    }
    out
}

pub fn parse_qscan_entries(resp: &str) -> Vec<QscanEntry> {
    let mut out = Vec::new();
    for line in clean_at_lines(resp) {
        let Some(body) = line.strip_prefix("+QSCAN:") else {
            continue;
        };
        let f = split_csv_fields(body);
        let rat = unquote(f.first().map(|s| s.as_str())).to_ascii_uppercase();
        if rat.is_empty() {
            continue;
        }
        out.push(QscanEntry {
            rat,
            mcc: unquote(f.get(1).map(|s| s.as_str())),
            mnc: unquote(f.get(2).map(|s| s.as_str())),
            arfcn: to_i64(f.get(3).map(|s| s.as_str())),
            pci: to_i32(f.get(4).map(|s| s.as_str())),
            rsrp: to_f64(f.get(5).map(|s| s.as_str())).filter(|&v| v != -140.0 && v != -32768.0),
            rsrq: to_f64(f.get(6).map(|s| s.as_str())).filter(|&v| v != -140.0 && v != -32768.0),
            srxlev: to_f64(f.get(7).map(|s| s.as_str())),
            scs: unquote(f.get(8).map(|s| s.as_str())),
            cell_id: unquote(f.get(10).map(|s| s.as_str())),
            tac: unquote(f.get(11).map(|s| s.as_str())),
            bandwidth: unquote(f.get(12).map(|s| s.as_str())),
            band: unquote(f.get(13).map(|s| s.as_str())),
            raw: line,
        });
    }
    out
}

pub fn parse_qnw_band_list(resp: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    for line in clean_at_lines(resp) {
        if !line.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()) {
            continue;
        }
        let body = line.strip_prefix("+QNWPREFCFG:").unwrap_or(&line);
        let f = split_csv_fields(body);
        let val = unquote(f.get(1).map(|s| s.as_str()));
        return val
            .split(':')
            .map(|x| x.trim().trim_start_matches('0'))
            .filter(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
            .map(|s| s.to_string())
            .collect();
    }
    Vec::new()
}

pub fn validate_imei_luhn(imei: &str) -> bool {
    if imei.len() != 15 || !imei.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    for (idx, b) in imei.bytes().enumerate() {
        let mut d = (b - b'0') as u32;
        if idx % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

pub fn mask_secret_id(val: &str) -> String {
    let t = val.trim();
    if t.is_empty() {
        return "--".into();
    }
    // Count characters, not bytes: slicing at a byte offset inside a
    // multi-byte character panics (and panic=abort kills the daemon).
    let chars: Vec<char> = t.chars().collect();
    if chars.len() <= 4 {
        return "••••".into();
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}{tail}", "•".repeat(chars.len() - 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_sdx75_responses() {
        let qcainfo = r#"+QCAINFO: "PCC",521310,11,"NR5G BAND 41",589"#;
        let carriers = parse_carrier_aggregation(qcainfo);
        assert_eq!(carriers.len(), 1);
        assert_eq!(carriers[0].band, "n41");
        assert_eq!(carriers[0].bandwidth_mhz, Some(90.0));
        assert_eq!(carriers[0].pci, Some(589));

        let qeng = r#"+QENG: "servingcell","NOCONN","NR5G-SA","TDD",310,260,10250D138,589,B0FB00,521310,41,14,-95,-10,14,1,42"#;
        let sc = parse_serving_cell(qeng, &carriers).expect("serving cell");
        assert_eq!(sc.band, "n41");
        assert_eq!(sc.dl_bandwidth_mhz, Some(90.0));
        assert_eq!(sc.pci, Some(589));
        assert_eq!(sc.scs_khz, Some(30));
        assert_eq!(sc.tx_power, None);

        let lanip = parse_qmap_lan_ip(r#"+QMAP: "LANIP",192.168.224.100,192.168.227.99,192.168.224.1"#).unwrap();
        assert_eq!(lanip.gateway_ip, "192.168.224.1");
        assert_eq!(lanip.netmask, "255.255.252.0 (/22)");

        assert_eq!(parse_3gpp_rel(r#"+QNWCFG: "3gpp_rel",R17,R17"#), "3GPP Rel-17");

        let ta = parse_time_advance("", r#"+QNWCFG: "nr5g_time_advance",1,49552"#);
        assert_eq!(ta.nr5g_steps, Some(97));
        assert_eq!(ta.nr5g_meters, Some(3778));

        let ta_nr_sa = parse_time_advance_for_rat(r#"+QNWCFG: "lte_time_advance",1,0"#, r#"+QNWCFG: "nr5g_time_advance",0,0"#, Some("NR5G-SA"));
        assert_eq!(ta_nr_sa.active_meters, None);

        let (v6, plen) = decode_3gpp_address(Some(
            "38.7.251.145.22.0.36.104.0.0.0.0.0.0.0.2.255.255.255.255.255.255.255.255.0.0.0.0.0.0.0.0",
        ));
        assert_eq!(v6, "2607:fb91:1600:2468::2");
        assert_eq!(plen, Some(64));

        assert!(validate_imei_luhn("490154203237518"));
        assert!(!validate_imei_luhn("490154203237519"));
        assert_eq!(mask_secret_id("490154203237518"), "•••••••••••7518");
    }

    #[test]
    fn parses_lte_qcainfo_nr5g_mimo_layers_compound_mimo_sysfs_thermals_and_native_bearer() {
        let lte_ca = concat!(
            "+QCAINFO: \"PCC\",1950,100,\"LTE BAND 4\",1,100,-88,-9,-60,15\r\n",
            "+QCAINFO: \"SCC\",66986,100,\"LTE BAND 66\",2,102,-91,-11,-63,12\r\n",
            "+QCAINFO: \"SCC\",426530,3,\"NR5G BAND 66\",2,654,1,3,346500\r\n",
        );
        let mut ccs = parse_carrier_aggregation(lte_ca);
        assert_eq!(ccs.len(), 3);
        assert_eq!(ccs[0].pci, Some(100));
        assert_eq!(ccs[0].rsrp, Some(-88.0));
        assert_eq!(ccs[0].ul_arfcn, None);
        assert_eq!(ccs[1].pci, Some(102));
        assert_eq!(ccs[1].rsrp, Some(-91.0));
        assert_eq!(ccs[1].pcell_state, Some(2));
        assert_eq!(ccs[1].ul_arfcn, None);
        assert_eq!(ccs[2].pci, Some(654));
        assert!(ccs[2].ul_configured);
        assert_eq!(ccs[2].ul_arfcn, Some(346500));
        assert_eq!(ccs[2].ul_bandwidth_mhz, Some(20.0));

        let mimo_info = parse_nr5g_mimo_info("+QNWCFG: \"nr5g_mimo_info\",654,426530,2,1\r\nOK");
        merge_nr5g_mimo_layers(&mut ccs, &mimo_info);
        assert_eq!(ccs[2].dl_mimo_layers, Some(2));
        assert_eq!(ccs[2].ul_mimo_layers, Some(1));

        assert_eq!(parse_ssb_beam_id("+QNWCFG: \"ssb_beam_id\",1,5\r\n"), Some(5));
        assert_eq!(parse_ssb_beam_id("+QNWCFG: \"ssb_beam_id\",255\r\n"), None);
        assert_eq!(parse_nr5g_pathloss("+QNWCFG: \"nr5g_pathloss\",114\r\n"), Some(114.0));

        let compound = "+QRSRP: -102,-103,-140,-140,LTE\r\n+QRSRP: -93,-101,-92,-92,NR5G\r\n+QRSRQ: -11,-12,-10,-11,NR5G\r\n+QSINR: 15,11,17,20,NR5G\r\nOK";
        let sig = parse_mimo_signal(compound, compound, compound);
        assert_eq!(sig.rat, "NR5G");
        assert_eq!(sig.rsrp, vec![Some(-93.0), Some(-101.0), Some(-92.0), Some(-92.0)]);
        assert_eq!(sig.sinr, vec![Some(15.0), Some(11.0), Some(17.0), Some(20.0)]);

        // Reverse EN-DC order (NR5G before LTE) must keep NR5G rather than letting LTE overwrite it.
        let compound_rev = "+QRSRP: -93,-101,-92,-92,NR5G\r\n+QRSRP: -102,-103,-140,-140,LTE\r\n+QRSRQ: -10,-11,-10,-11,NR5G\r\n+QRSRQ: -13,-14,-140,-140,LTE\r\n+QSINR: 18,16,19,21,NR5G\r\n+QSINR: 8,7,-32768,-32768,LTE\r\nOK";
        let sig_rev = parse_mimo_signal(compound_rev, compound_rev, compound_rev);
        assert_eq!(sig_rev.rat, "NR5G");
        assert_eq!(sig_rev.rsrp, vec![Some(-93.0), Some(-101.0), Some(-92.0), Some(-92.0)]);
        assert_eq!(sig_rev.sinr, vec![Some(18.0), Some(16.0), Some(19.0), Some(21.0)]);

        // LTE anchor where modem emits sentinel -140/-32768 NR5G line must fall back cleanly to valid LTE!
        let lte_with_dead_nr = "+QRSRP: -95,-98,-101,-103,LTE\r\n+QRSRP: -140,-140,-140,-140,NR5G\r\n+QRSRQ: -9,-10,-11,-11,LTE\r\n+QRSRQ: -32768,-32768,-32768,-32768,NR5G\r\n+QSINR: 14,12,10,9,LTE\r\n+QSINR: -32768,-32768,-32768,-32768,NR5G\r\nOK";
        let sig_lte = parse_mimo_signal(lte_with_dead_nr, lte_with_dead_nr, lte_with_dead_nr);
        assert_eq!(sig_lte.rat, "LTE");
        assert_eq!(sig_lte.rsrp, vec![Some(-95.0), Some(-98.0), Some(-101.0), Some(-103.0)]);
        assert_eq!(sig_lte.sinr, vec![Some(14.0), Some(12.0), Some(10.0), Some(9.0)]);

        let sbx = crate::paths::TestSandbox::new("sysfs-therm");
        sbx.write("/sys/class/thermal/thermal_zone0/type", "sdr0-pa1\n");
        sbx.write("/sys/class/thermal/thermal_zone0/temp", "41250\n");
        sbx.write("/sys/class/thermal/thermal_zone1/type", "dead-zone\n");
        sbx.write("/sys/class/thermal/thermal_zone1/temp", "-273000\n");
        let therms = read_sysfs_thermals();
        assert_eq!(therms.len(), 1);
        assert_eq!(therms[0].sensor, "sdr0-pa1");
        assert_eq!(therms[0].celsius, 41.3);
        assert_eq!(therms[0].domain, "RF Transceiver");

        let mut bearers = vec![];
        overlay_native_bearer(
            &mut bearers,
            crate::dataplane::NativeBearerOverlay {
                iface: "rmnet_data1".into(),
                profile_index: 1,
                connected: true,
                ipv4: Some("192.0.0.2".into()),
                ipv4_gateway: Some("192.0.0.1".into()),
                ipv4_dns1: Some("192.0.0.30".into()),
                ipv6: Some("2607:fb91:1689:832::2".into()),
                ipv6_prefix_length: Some(64),
                ..Default::default()
            },
        );
        assert_eq!(bearers.len(), 1);
        assert_eq!(bearers[0].ipv4.as_deref(), Some("192.0.0.2"));
        assert_eq!(bearers[0].ipv4_gateway.as_deref(), Some("192.0.0.1"));
        assert_eq!(bearers[0].ipv4_dns1.as_deref(), Some("192.0.0.30"));
        assert_eq!(bearers[0].ipv6.as_deref(), Some("2607:fb91:1689:832::2"));
        assert_eq!(bearers[0].ip_type, "IPV4V6");
    }

    #[test]
    fn mask_secret_id_handles_non_ascii() {
        assert_eq!(mask_secret_id("8901260\u{e9}12345"), "•••••••••2345");
        assert_eq!(mask_secret_id("ab\u{e9}\u{e9}9"), "•b\u{e9}\u{e9}9");
        assert_eq!(mask_secret_id("\u{1F4F6}\u{1F4F6}\u{1F4F6}\u{1F4F6}\u{1F4F6}"), "•\u{1F4F6}\u{1F4F6}\u{1F4F6}\u{1F4F6}");
        assert_eq!(mask_secret_id("  "), "--");
    }

    #[test]
    fn serving_cell_parses_multiline_endc_and_search() {
        let endc = "+QENG: \"servingcell\",\"NOCONN\"\r\n\
                    +QENG: \"LTE\",\"FDD\",310,260,1A2B3C,100,1950,4,5,5,A1B2,-90,-10,-62,15\r\n\
                    +QENG: \"NR5G-NSA\",310,260,589,-93,14,-10,521310,41,12\r\nOK";
        let sc = parse_serving_cell(endc, &[]).expect("en-dc lte anchor");
        assert_eq!(sc.state, "NOCONN");
        assert_eq!(sc.rat, "LTE (EN-DC)");
        assert_eq!(sc.band, "B4");
        assert_eq!(sc.rsrp, Some(-90.0));
        assert_eq!(sc.rsrq, Some(-10.0));
        assert_eq!(sc.nsa_nr5g_pci, Some(589));
        assert_eq!(sc.nsa_nr5g_arfcn, Some(521310));
        assert_eq!(sc.nsa_nr5g_band.as_deref(), Some("n41"));
        assert_eq!(sc.nsa_nr5g_rsrp, Some(-93.0));
        assert_eq!(sc.nsa_nr5g_sinr, Some(14.0));
        assert_eq!(sc.nsa_nr5g_rsrq, Some(-10.0));
        assert_eq!(sc.nsa_nr5g_bw_mhz, Some(100.0));

        let search = "+QENG: \"servingcell\",\"SEARCH\"\r\nOK";
        let s2 = parse_serving_cell(search, &[]).expect("search state");
        assert_eq!(s2.state, "SEARCH");
        assert_eq!(s2.rat, "UNKNOWN");
        assert_eq!(s2.band, "-");
    }

    #[test]
    fn wwan_bearer_always_emits_nullable_address_keys() {
        let b = WwanBearerInfo {
            iface: "rmnet_data0".into(),
            cid: 1,
            ip_type: "IPV4V6".into(),
            status: "DISCONNECTED".into(),
            apn: "fast.t-mobile.com".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&b).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "ipv4",
            "ipv4Gateway",
            "ipv4Dns1",
            "ipv4Dns2",
            "ipv6",
            "ipv6Gateway",
            "ipv6Dns1",
            "ipv6Dns2",
            "ipv6PrefixLength",
        ] {
            assert!(obj.contains_key(key), "missing key {key} in {v}");
            assert!(obj[key].is_null(), "expected null for {key}, got {}", obj[key]);
        }
    }
}

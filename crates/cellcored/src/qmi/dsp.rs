//! Clean-room QRTR QMI codecs for Snapdragon X75 DSP telemetry services:
//! * `TMD` (`0x18`): Thermal Mitigation Device — reports live DSP throttling levels
//! * `SAR` (`0x11`): RF Specific Absorption Rate — reports FCC SAR / Smart Transmit backoff state
//! * `NAS` (`0x03`): Sub-millisecond QMI signal strength snapshot (zero `/dev/smd11` AT contention)
//! * Service capability discovery (`LOC`, `WMS`, `TIME`, `ANT_SWITCH`, `SMART_TX`)

use std::{
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tokio::sync::{Mutex, mpsc};

use super::{
    QmiClient, QmiError, SVC_SAR, SVC_TMD,
    codec::{TlvWriter, check_result_tlv, find_tlv},
    nas::SignalInfoSnapshot,
    qrtr::{QrtrBus, QrtrServiceClient, shared_bus},
};
use crate::http::HttpCtx;

const QMI_TIMEOUT: Duration = Duration::from_secs(2);

pub const TMD_GET_MITIGATION_DEVICE_LIST: u16 = 0x0020;
pub const TMD_GET_MITIGATION_LEVEL: u16 = 0x0022;
pub const SAR_RF_SET_STATE: u16 = 0x0001;
pub const SAR_RF_GET_STATE: u16 = 0x0002;

#[derive(Default)]
struct DspClientCache {
    ssr_epoch: u64,
    tmd_client: Option<Arc<QrtrServiceClient>>,
    sar_client: Option<Arc<QrtrServiceClient>>,
    tmd_device_list: Option<Vec<(String, u8)>>,
}

impl DspClientCache {
    fn reset_if_ssr(&mut self, ssr_count: u64) {
        if self.ssr_epoch != ssr_count {
            self.ssr_epoch = ssr_count;
            self.tmd_client = None;
            self.sar_client = None;
            self.tmd_device_list = None;
        }
    }
}

static DSP_CACHE: Mutex<DspClientCache> = Mutex::const_new(DspClientCache {
    ssr_epoch: 0,
    tmd_client: None,
    sar_client: None,
    tmd_device_list: None,
});

/// Filter out irrelevant non-cellular TMD mitigation devices from 30s polling
/// (`wlan*`, `mmw*`, `cpuv_restriction_cold`).
pub fn is_relevant_tmd_device(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    !n.is_empty()
        && !n.starts_with("wlan")
        && !n.starts_with("mmw")
        && n != "cpuv_restriction_cold"
}

fn is_transport_err(e: &QmiError) -> bool {
    matches!(e, QmiError::Io(_) | QmiError::Timeout | QmiError::Ssr)
}

async fn ensure_cached_client(
    bus: &Arc<QrtrBus>,
    service: u32,
    tag: &'static str,
    ssr_count: u64,
) -> Result<Arc<QrtrServiceClient>, QmiError> {
    {
        let mut cache = DSP_CACHE.lock().await;
        cache.reset_if_ssr(ssr_count);
        let slot = match service {
            SVC_TMD => &mut cache.tmd_client,
            SVC_SAR => &mut cache.sar_client,
            _ => &mut cache.tmd_client,
        };
        if let Some(c) = slot.as_ref().filter(|c| c.is_alive()) {
            return Ok(Arc::clone(c));
        }
        *slot = None;
    }
    let (ind_tx, _ind_rx) = mpsc::channel(4);
    let client = bus.open_service(service, tag, ind_tx, QMI_TIMEOUT).await?;
    let mut cache = DSP_CACHE.lock().await;
    cache.reset_if_ssr(ssr_count);
    let slot = match service {
        SVC_TMD => &mut cache.tmd_client,
        SVC_SAR => &mut cache.sar_client,
        _ => &mut cache.tmd_client,
    };
    *slot = Some(Arc::clone(&client));
    Ok(client)
}

async fn invalidate_cached_client(service: u32, clear_tmd_list: bool) {
    let mut cache = DSP_CACHE.lock().await;
    match service {
        SVC_TMD => {
            cache.tmd_client = None;
            if clear_tmd_list {
                cache.tmd_device_list = None;
            }
        }
        SVC_SAR => cache.sar_client = None,
        _ => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TmdDeviceInfo {
    pub name: String,
    pub max_level: u8,
    pub current_level: u8,
    pub requested_level: u8,
    pub throttling: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DspTelemetrySnapshot {
    pub qrtr_available: bool,
    pub dsp_service_count: usize,
    pub capabilities: DspCapabilities,
    pub sar_rf_state: Option<u32>,
    pub sar_label: String,
    pub tmd_devices: Vec<TmdDeviceInfo>,
    pub any_throttling: bool,
    pub qmi_signal: Option<SignalInfoSnapshot>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DspCapabilities {
    pub tmd: bool,
    pub sar: bool,
    pub smart_transmit: bool,
    pub ant_switch: bool,
    pub loc_gnss: bool,
    pub wms_sms: bool,
    pub time_svc: bool,
}

/// Parse `TMD_GET_MITIGATION_DEVICE_LIST_RESP` TLV `0x10`:
/// `[count: u8] repeat { [name_len: u8][name: utf8][max_level: u8] }`
pub fn parse_tmd_device_list(tlv: &[u8]) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    if tlv.is_empty() {
        return out;
    }
    let count = tlv[0] as usize;
    let mut idx = 1usize;
    for _ in 0..count {
        if idx >= tlv.len() {
            break;
        }
        let nlen = tlv[idx] as usize;
        idx += 1;
        if idx + nlen + 1 > tlv.len() {
            break;
        }
        let name = String::from_utf8_lossy(&tlv[idx..idx + nlen]).to_string();
        idx += nlen;
        let max_level = tlv[idx];
        idx += 1;
        if !name.is_empty() {
            out.push((name, max_level));
        }
    }
    out
}

pub fn sar_state_label(state: Option<u32>) -> String {
    match state {
        None => "Unavailable".into(),
        Some(0) => "Default (no backoff)".into(),
        Some(n) => format!("SAR Backoff State {n}"),
    }
}

pub async fn query_tmd_device_list(client: &dyn QmiClient) -> Result<Vec<(String, u8)>, QmiError> {
    let tlvs = client.rpc(TMD_GET_MITIGATION_DEVICE_LIST, Vec::new(), QMI_TIMEOUT).await?;
    check_result_tlv(&tlvs)?;
    let list = find_tlv(&tlvs, 0x10)
        .map(parse_tmd_device_list)
        .unwrap_or_default();
    Ok(list
        .into_iter()
        .filter(|(name, _)| is_relevant_tmd_device(name))
        .take(24)
        .collect())
}

pub async fn query_tmd_levels(
    client: &dyn QmiClient,
    devices: &[(String, u8)],
) -> Result<Vec<TmdDeviceInfo>, QmiError> {
    let mut out = Vec::with_capacity(devices.len());
    for (name, max_level) in devices.iter().take(24) {
        let mut w = TlvWriter::new();
        let mut dev_tlv = Vec::with_capacity(1 + name.len());
        dev_tlv.push(name.len().min(255) as u8);
        dev_tlv.extend_from_slice(&name.as_bytes()[..name.len().min(255)]);
        w.push_bytes(0x01, &dev_tlv)?;

        let (cur, req) = match client.rpc(TMD_GET_MITIGATION_LEVEL, w.finish(), QMI_TIMEOUT).await {
            Ok(rt) if check_result_tlv(&rt).is_ok() => {
                let c = find_tlv(&rt, 0x10).and_then(|b| b.first().copied()).unwrap_or(0);
                let r = find_tlv(&rt, 0x11).and_then(|b| b.first().copied()).unwrap_or(0);
                (c, r)
            }
            Err(e) if is_transport_err(&e) => return Err(e),
            _ => (0, 0),
        };
        out.push(TmdDeviceInfo {
            name: name.clone(),
            max_level: *max_level,
            current_level: cur,
            requested_level: req,
            throttling: cur > 0,
        });
    }
    Ok(out)
}

#[allow(dead_code)]
pub async fn query_tmd_devices(client: &dyn QmiClient) -> Result<Vec<TmdDeviceInfo>, QmiError> {
    let list = query_tmd_device_list(client).await?;
    query_tmd_levels(client, &list).await
}

pub async fn query_sar_state(client: &dyn QmiClient) -> Result<u32, QmiError> {
    let tlvs = client.rpc(SAR_RF_GET_STATE, Vec::new(), QMI_TIMEOUT).await?;
    check_result_tlv(&tlvs)?;
    let bytes = find_tlv(&tlvs, 0x10)
        .ok_or_else(|| QmiError::Malformed("SAR_RF_GET_STATE missing TLV 0x10".into()))?;
    if bytes.len() < 4 {
        return Err(QmiError::Malformed("SAR_RF_GET_STATE TLV 0x10 too short".into()));
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub async fn set_sar_state_rpc(client: &dyn QmiClient, state: u32) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u32(0x01, state);
    let tlvs = client.rpc(SAR_RF_SET_STATE, w.finish(), QMI_TIMEOUT).await?;
    check_result_tlv(&tlvs)
}

/// Set QMI SAR RF state (`SAR_RF_SET_STATE = 0x0001`, e.g. `0` = Default / No Backoff).
pub async fn set_sar_rf_state(state: u32) -> Result<(), QmiError> {
    let bus = shared_bus()?;
    let ssr_count = bus.snapshot().ssr_count;
    let ep = ensure_cached_client(&bus, SVC_SAR, "SAR", ssr_count).await?;
    match set_sar_state_rpc(ep.as_ref(), state).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_transport_err(&e) {
                invalidate_cached_client(SVC_SAR, false).await;
            }
            Err(e)
        }
    }
}

/// Probe live SDX75 DSP services directly over QRTR (`AF_QIPCRTR`), reusing
/// persistent `SVC_TMD` and `SVC_SAR` client handles and caching the filtered
/// TMD device list once per SSR epoch.
pub async fn probe_dsp_telemetry() -> DspTelemetrySnapshot {
    let now = crate::auth::now_secs();
    let Ok(bus) = shared_bus() else {
        return DspTelemetrySnapshot {
            sar_label: sar_state_label(None),
            updated_at: now,
            ..Default::default()
        };
    };

    if bus.snapshot().services.is_empty() {
        let _ = bus.wait_for_service(SVC_TMD, Duration::from_millis(400)).await;
    }
    let bsnap = bus.snapshot();
    let ssr_count = bsnap.ssr_count;
    let services = bsnap.services;
    let has_svc = |id: u32| services.iter().any(|s| s.service == id);
    let caps = DspCapabilities {
        tmd: has_svc(SVC_TMD),
        sar: has_svc(SVC_SAR),
        smart_transmit: has_svc(87),
        ant_switch: has_svc(74),
        loc_gnss: has_svc(0x10),
        wms_sms: has_svc(0x05),
        time_svc: has_svc(0x16),
    };

    let tmd_devices = if caps.tmd {
        match ensure_cached_client(&bus, SVC_TMD, "TMD", ssr_count).await {
            Ok(ep) => {
                let cached_list = {
                    let mut cache = DSP_CACHE.lock().await;
                    cache.reset_if_ssr(ssr_count);
                    cache.tmd_device_list.clone()
                };
                let dev_list = match cached_list {
                    Some(list) => Ok(list),
                    None => match query_tmd_device_list(ep.as_ref()).await {
                        Ok(list) => {
                            let mut cache = DSP_CACHE.lock().await;
                            cache.reset_if_ssr(ssr_count);
                            cache.tmd_device_list = Some(list.clone());
                            Ok(list)
                        }
                        Err(e) => {
                            if is_transport_err(&e) {
                                invalidate_cached_client(SVC_TMD, matches!(e, QmiError::Ssr)).await;
                            }
                            Err(e)
                        }
                    },
                };
                match dev_list {
                    Ok(list) => match query_tmd_levels(ep.as_ref(), &list).await {
                        Ok(devs) => devs,
                        Err(e) => {
                            if is_transport_err(&e) {
                                invalidate_cached_client(SVC_TMD, matches!(e, QmiError::Ssr)).await;
                            }
                            Vec::new()
                        }
                    },
                    Err(_) => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let sar_rf_state = if caps.sar {
        match ensure_cached_client(&bus, SVC_SAR, "SAR", ssr_count).await {
            Ok(ep) => match query_sar_state(ep.as_ref()).await {
                Ok(st) => Some(st),
                Err(e) => {
                    if is_transport_err(&e) {
                        invalidate_cached_client(SVC_SAR, false).await;
                    }
                    None
                }
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let any_throttling = tmd_devices.iter().any(|d| d.throttling);
    let snap = DspTelemetrySnapshot {
        qrtr_available: true,
        dsp_service_count: services.len(),
        capabilities: caps,
        sar_rf_state,
        sar_label: sar_state_label(sar_rf_state),
        tmd_devices,
        any_throttling,
        // NAS_GET_SIGNAL_INFO is already polled by dataplane.rs; avoid duplicate QMI traffic.
        qmi_signal: None,
        updated_at: now,
    };
    crate::obs::events::on_dsp_telemetry(&snap);
    snap
}

pub async fn get_dsp_telemetry(State(ctx): State<HttpCtx>) -> Response {
    let snap = probe_dsp_telemetry().await;
    *ctx.app.dsp_telemetry.write().await = snap.clone();
    Json(serde_json::json!({
        "status": "ok",
        "dsp": snap,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tmd_mitigation_device_list_tlv() {
        // 2 devices: "pa" (max 3), "modem" (max 4)
        let mut tlv = vec![2u8];
        tlv.push(2);
        tlv.extend_from_slice(b"pa");
        tlv.push(3);
        tlv.push(5);
        tlv.extend_from_slice(b"modem");
        tlv.push(4);
        let parsed = parse_tmd_device_list(&tlv);
        assert_eq!(parsed, vec![("pa".into(), 3), ("modem".into(), 4)]);
    }

    #[test]
    fn sar_labels_format_default_and_backoff() {
        assert_eq!(sar_state_label(None), "Unavailable");
        assert_eq!(sar_state_label(Some(0)), "Default (no backoff)");
        assert_eq!(sar_state_label(Some(2)), "SAR Backoff State 2");
    }

    #[tokio::test]
    async fn encodes_sar_rf_set_state_zero() {
        use crate::qmi::{
            codec::{make_result_ok_tlv, parse_tlvs, read_u32_le},
            test_support::MockQmiClient,
        };
        let mock = MockQmiClient::new(|msg_id, req_bytes| {
            assert_eq!(msg_id, SAR_RF_SET_STATE);
            let req_tlvs = parse_tlvs(req_bytes)?;
            assert_eq!(read_u32_le(&req_tlvs, 0x01), Some(0));
            parse_tlvs(&make_result_ok_tlv())
        });
        set_sar_state_rpc(&mock, 0).await.unwrap();
    }

    #[test]
    fn filters_irrelevant_non_cellular_tmd_devices() {
        assert!(is_relevant_tmd_device("pa"));
        assert!(is_relevant_tmd_device("modem"));
        assert!(is_relevant_tmd_device("modem_lte_dsc"));
        assert!(!is_relevant_tmd_device("wlan"));
        assert!(!is_relevant_tmd_device("wlan_tx"));
        assert!(!is_relevant_tmd_device("mmw0"));
        assert!(!is_relevant_tmd_device("mmw_pa1"));
        assert!(!is_relevant_tmd_device("cpuv_restriction_cold"));
        assert!(!is_relevant_tmd_device(""));
    }

    #[tokio::test]
    async fn query_tmd_device_list_filters_and_caches_levels() {
        use crate::qmi::{
            codec::{make_result_ok_tlv, parse_tlvs},
            test_support::MockQmiClient,
        };
        let mock = MockQmiClient::new(|msg_id, _| {
            let mut w = TlvWriter::new();
            match msg_id {
                TMD_GET_MITIGATION_DEVICE_LIST => {
                    let devs: &[(&str, u8)] = &[
                        ("pa", 3),
                        ("wlan", 2),
                        ("mmw0", 4),
                        ("cpuv_restriction_cold", 1),
                        ("modem", 4),
                    ];
                    let mut raw = vec![devs.len() as u8];
                    for (name, max) in devs {
                        raw.push(name.len() as u8);
                        raw.extend_from_slice(name.as_bytes());
                        raw.push(*max);
                    }
                    w.push_bytes(0x10, &raw).unwrap();
                }
                TMD_GET_MITIGATION_LEVEL => {
                    w.push_u8(0x10, 1).push_u8(0x11, 2);
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });
        let cached = query_tmd_device_list(&mock).await.unwrap();
        assert_eq!(cached, vec![("pa".into(), 3), ("modem".into(), 4)]);
        let levels = query_tmd_levels(&mock, &cached).await.unwrap();
        assert_eq!(levels.len(), 2);
        assert!(levels[0].throttling);
        assert_eq!(levels[0].current_level, 1);
        assert_eq!(levels[0].requested_level, 2);
        // 1 list call + 2 level calls (irrelevant devices never polled!)
        assert_eq!(mock.calls.lock().unwrap().len(), 3);
    }
}

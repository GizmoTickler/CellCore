//! Clean-room QRTR QMI codecs for Snapdragon X75 DSP telemetry services:
//! * `TMD` (`0x18`): Thermal Mitigation Device — reports live DSP throttling levels
//! * `SAR` (`0x11`): RF Specific Absorption Rate — reports FCC SAR / Smart Transmit backoff state
//! * `NAS` (`0x03`): Sub-millisecond QMI signal strength snapshot (zero `/dev/smd11` AT contention)
//! * Service capability discovery (`LOC`, `WMS`, `TIME`, `ANT_SWITCH`, `SMART_TX`)

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tokio::sync::mpsc;

use super::{
    QmiClient, QmiError, SVC_NAS, SVC_SAR, SVC_TMD,
    codec::{TlvWriter, check_result_tlv, find_tlv},
    nas::{self, SignalInfoSnapshot},
    qrtr::QrtrBus,
};
use crate::http::HttpCtx;

const QMI_TIMEOUT: Duration = Duration::from_secs(2);

pub const TMD_GET_MITIGATION_DEVICE_LIST: u16 = 0x0020;
pub const TMD_GET_MITIGATION_LEVEL: u16 = 0x0022;
pub const SAR_RF_GET_STATE: u16 = 0x0002;

static DSP_QRTR_BUS: OnceLock<Option<Arc<QrtrBus>>> = OnceLock::new();

fn shared_dsp_bus() -> Option<Arc<QrtrBus>> {
    DSP_QRTR_BUS
        .get_or_init(|| QrtrBus::connect().ok())
        .clone()
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

pub async fn query_tmd_devices(client: &dyn QmiClient) -> Result<Vec<TmdDeviceInfo>, QmiError> {
    let tlvs = client.rpc(TMD_GET_MITIGATION_DEVICE_LIST, Vec::new(), QMI_TIMEOUT).await?;
    check_result_tlv(&tlvs)?;
    let list = find_tlv(&tlvs, 0x10)
        .map(parse_tmd_device_list)
        .unwrap_or_default();

    let mut out = Vec::with_capacity(list.len());
    for (name, max_level) in list.into_iter().take(24) {
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
            _ => (0, 0),
        };
        out.push(TmdDeviceInfo {
            name,
            max_level,
            current_level: cur,
            requested_level: req,
            throttling: cur > 0,
        });
    }
    Ok(out)
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

/// Probe live SDX75 DSP services directly over QRTR (`AF_QIPCRTR`).
pub async fn probe_dsp_telemetry() -> DspTelemetrySnapshot {
    let now = crate::auth::now_secs();
    let Some(bus) = shared_dsp_bus() else {
        return DspTelemetrySnapshot {
            sar_label: sar_state_label(None),
            updated_at: now,
            ..Default::default()
        };
    };

    if bus.snapshot().services.is_empty() {
        let _ = bus.send_lookup().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let services = bus.snapshot().services;
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

    let (ind_tx, _ind_rx) = mpsc::channel(8);

    let tmd_devices = if caps.tmd {
        match bus.open_service(SVC_TMD, "TMD", ind_tx.clone(), QMI_TIMEOUT).await {
            Ok(ep) => query_tmd_devices(ep.as_ref()).await.unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let sar_rf_state = if caps.sar {
        match bus.open_service(SVC_SAR, "SAR", ind_tx.clone(), QMI_TIMEOUT).await {
            Ok(ep) => query_sar_state(ep.as_ref()).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    let qmi_signal = if has_svc(SVC_NAS) {
        match bus.open_service(SVC_NAS, "NAS_DSP", ind_tx, QMI_TIMEOUT).await {
            Ok(ep) => nas::get_signal_info(ep.as_ref()).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    let any_throttling = tmd_devices.iter().any(|d| d.throttling);
    DspTelemetrySnapshot {
        qrtr_available: true,
        dsp_service_count: services.len(),
        capabilities: caps,
        sar_rf_state,
        sar_label: sar_state_label(sar_rf_state),
        tmd_devices,
        any_throttling,
        qmi_signal,
        updated_at: now,
    }
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
}

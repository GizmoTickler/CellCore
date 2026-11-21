//! QMI Network Access Service (`NAS`, `0x03`) client helpers and indication parsers.

use std::{collections::HashMap, time::Duration};

use serde::Serialize;

use super::{
    QmiClient, QmiError,
    codec::{TlvWriter, check_result_tlv, find_tlv, read_u8},
};

pub const NAS_INDICATION_REGISTER: u16 = 0x0003;
#[allow(dead_code)]
pub const NAS_GET_SERVING_SYSTEM: u16 = 0x0024;
#[allow(dead_code)]
pub const NAS_SERVING_SYSTEM_IND: u16 = 0x0024;
pub const NAS_GET_RF_BAND_INFO: u16 = 0x0031;
pub const NAS_GET_SYS_INFO: u16 = 0x004D;
pub const NAS_SYS_INFO_IND: u16 = 0x004E;
pub const NAS_GET_SIGNAL_INFO: u16 = 0x004F;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SysInfoSnapshot {
    pub lte_srv_status: Option<u8>,
    pub lte_ps_attached: bool,
    pub nr5g_srv_status: Option<u8>,
    pub nr5g_ps_attached: bool,
    pub endc_available: Option<bool>,
    pub restrict_dcnr: Option<bool>,
    pub registered: bool,
    pub rat: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalInfoSnapshot {
    pub lte_rssi_dbm: Option<i8>,
    pub lte_rsrq_db: Option<i8>,
    pub lte_rsrp_dbm: Option<i16>,
    pub lte_snr_db: Option<f32>,
    pub nr5g_rsrp_dbm: Option<i16>,
    pub nr5g_rsrq_db: Option<i16>,
    pub nr5g_snr_db: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RfBandEntry {
    pub radio_if: u8,
    pub band: u16,
    pub arfcn: u32,
    pub bandwidth_raw: Option<u32>,
}

fn parse_ps_domain(tlv: &[u8]) -> bool {
    // LTE / NR5G sys_info common prefix: [srv_domain_valid: u8, srv_domain: u8, ...]
    tlv.len() >= 2 && tlv[0] == 1 && (tlv[1] & 0x02) != 0
}

pub fn parse_sys_info_tlvs(tlvs: &[(u8, Vec<u8>)]) -> SysInfoSnapshot {
    let lte_srv_status = find_tlv(tlvs, 0x14).and_then(|v| v.first().copied());
    let nr5g_srv_status = find_tlv(tlvs, 0x4A).and_then(|v| v.first().copied());
    let lte_ps_attached = find_tlv(tlvs, 0x19).is_some_and(parse_ps_domain);
    let nr5g_ps_attached = find_tlv(tlvs, 0x4B).is_some_and(parse_ps_domain);
    let endc_available = read_u8(tlvs, 0x4E).map(|v| v != 0);
    let restrict_dcnr = read_u8(tlvs, 0x4F).map(|v| v != 0);

    let lte_ok = lte_srv_status == Some(2) && lte_ps_attached;
    let nr_ok = nr5g_srv_status == Some(2) && nr5g_ps_attached;
    let registered = lte_ok || nr_ok;
    let rat = match (lte_ok, nr_ok, endc_available.unwrap_or(false)) {
        (true, true, _) => "NR5G-NSA+SA",
        (false, true, _) => "NR5G-SA",
        (true, false, true) => "NR5G-NSA",
        (true, false, false) => "LTE",
        _ => "none",
    };

    SysInfoSnapshot {
        lte_srv_status,
        lte_ps_attached,
        nr5g_srv_status,
        nr5g_ps_attached,
        endc_available,
        restrict_dcnr,
        registered,
        rat,
    }
}

pub fn parse_signal_info_tlvs(tlvs: &[(u8, Vec<u8>)]) -> SignalInfoSnapshot {
    let mut out = SignalInfoSnapshot::default();
    if let Some(lte) = find_tlv(tlvs, 0x14)
        && lte.len() >= 6
    {
        out.lte_rssi_dbm = Some(lte[0] as i8);
        out.lte_rsrq_db = Some(lte[1] as i8);
        let rsrp = i16::from_le_bytes([lte[2], lte[3]]);
        if rsrp > -32000 {
            out.lte_rsrp_dbm = Some(rsrp);
        }
        let snr = i16::from_le_bytes([lte[4], lte[5]]);
        if snr > -32000 {
            out.lte_snr_db = Some(snr as f32 / 10.0);
        }
    }
    if let Some(nr) = find_tlv(tlvs, 0x17)
        && nr.len() >= 4
    {
        let rsrp = i16::from_le_bytes([nr[0], nr[1]]);
        if rsrp > -32000 {
            out.nr5g_rsrp_dbm = Some(rsrp);
        }
        let snr = i16::from_le_bytes([nr[2], nr[3]]);
        if snr > -32000 {
            out.nr5g_snr_db = Some(snr as f32 / 10.0);
        }
    }
    if let Some(rsrq_raw) = find_tlv(tlvs, 0x18)
        && rsrq_raw.len() >= 2
    {
        let rsrq = i16::from_le_bytes([rsrq_raw[0], rsrq_raw[1]]);
        if rsrq > -32000 {
            out.nr5g_rsrq_db = Some(rsrq);
        }
    }
    out
}

pub fn parse_rf_band_info_tlvs(tlvs: &[(u8, Vec<u8>)]) -> Vec<RfBandEntry> {
    let mut bw_by_rat: HashMap<u8, Vec<u32>> = HashMap::new();
    if let Some(bw) = find_tlv(tlvs, 0x12)
        && !bw.is_empty()
    {
        let count = bw[0] as usize;
        let mut pos = 1;
        for _ in 0..count {
            if pos + 5 > bw.len() {
                break;
            }
            bw_by_rat
                .entry(bw[pos])
                .or_default()
                .push(u32::from_le_bytes([bw[pos + 1], bw[pos + 2], bw[pos + 3], bw[pos + 4]]));
            pos += 5;
        }
    }

    let mut rat_cursors: HashMap<u8, usize> = HashMap::new();
    let mut next_bw = |radio_if: u8| -> Option<u32> {
        let list = bw_by_rat.get(&radio_if)?;
        let idx = rat_cursors.entry(radio_if).or_insert(0);
        let val = list.get(*idx).or_else(|| list.last()).copied();
        *idx += 1;
        val
    };

    let mut out = Vec::new();
    if let Some(ext) = find_tlv(tlvs, 0x11)
        && !ext.is_empty()
    {
        let count = ext[0] as usize;
        let mut pos = 1;
        for _ in 0..count {
            if pos + 7 > ext.len() {
                break;
            }
            let radio_if = ext[pos];
            let band = u16::from_le_bytes([ext[pos + 1], ext[pos + 2]]);
            let arfcn = u32::from_le_bytes([ext[pos + 3], ext[pos + 4], ext[pos + 5], ext[pos + 6]]);
            let bandwidth_raw = next_bw(radio_if);
            out.push(RfBandEntry {
                radio_if,
                band,
                arfcn,
                bandwidth_raw,
            });
            pos += 7;
        }
        return out;
    }

    if let Some(basic) = find_tlv(tlvs, 0x01)
        && !basic.is_empty()
    {
        let count = basic[0] as usize;
        let mut pos = 1;
        for _ in 0..count {
            if pos + 5 > basic.len() {
                break;
            }
            let radio_if = basic[pos];
            let band = u16::from_le_bytes([basic[pos + 1], basic[pos + 2]]);
            let arfcn = u16::from_le_bytes([basic[pos + 3], basic[pos + 4]]) as u32;
            let bandwidth_raw = next_bw(radio_if);
            out.push(RfBandEntry {
                radio_if,
                band,
                arfcn,
                bandwidth_raw,
            });
            pos += 5;
        }
    }
    out
}

pub async fn register_sys_info_ind(client: &dyn QmiClient) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x18, 0x01);
    let tlvs = client
        .rpc(NAS_INDICATION_REGISTER, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)
}

pub async fn get_sys_info(client: &dyn QmiClient) -> Result<SysInfoSnapshot, QmiError> {
    let tlvs = client
        .rpc(NAS_GET_SYS_INFO, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_sys_info_tlvs(&tlvs))
}

pub async fn get_signal_info(client: &dyn QmiClient) -> Result<SignalInfoSnapshot, QmiError> {
    let tlvs = client
        .rpc(NAS_GET_SIGNAL_INFO, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_signal_info_tlvs(&tlvs))
}

pub async fn get_rf_band_info(client: &dyn QmiClient) -> Result<Vec<RfBandEntry>, QmiError> {
    let tlvs = client
        .rpc(NAS_GET_RF_BAND_INFO, Vec::new(), Duration::from_secs(3))
        .await?;
    match check_result_tlv(&tlvs) {
        Ok(()) => Ok(parse_rf_band_info_tlvs(&tlvs)),
        Err(QmiError::Protocol { .. }) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{
        codec::{TlvWriter, make_result_ok_tlv, parse_tlvs},
        test_support::MockQmiClient,
    };

    #[tokio::test]
    async fn decodes_nr5g_sa_sys_signal_and_band() {
        let mock = MockQmiClient::new(|msg_id, _| {
            let mut w = TlvWriter::new();
            match msg_id {
                NAS_GET_SYS_INFO => {
                    w.push_bytes(0x4A, &[2, 2, 1]).unwrap();
                    w.push_bytes(0x4B, &[1, 2, 0, 0]).unwrap();
                    w.push_u8(0x4E, 0);
                }
                NAS_GET_SIGNAL_INFO => {
                    // NR5G RSRP = -82 dBm, SNR = 23.5 dB (235 tenths), RSRQ = -11 dB
                    let mut nr = Vec::new();
                    nr.extend_from_slice(&(-82i16).to_le_bytes());
                    nr.extend_from_slice(&235i16.to_le_bytes());
                    w.push_bytes(0x17, &nr).unwrap();
                    w.push_bytes(0x18, &(-11i16).to_le_bytes()).unwrap();
                }
                NAS_GET_RF_BAND_INFO => {
                    // 1 entry: NR5G(12), band 41, arfcn 521310
                    let mut ext = vec![1u8, 12];
                    ext.extend_from_slice(&41u16.to_le_bytes());
                    ext.extend_from_slice(&521310u32.to_le_bytes());
                    w.push_bytes(0x11, &ext).unwrap();
                    let mut bw = vec![1u8, 12];
                    bw.extend_from_slice(&90u32.to_le_bytes());
                    w.push_bytes(0x12, &bw).unwrap();
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });

        let sys = get_sys_info(&mock).await.unwrap();
        assert!(sys.registered);
        assert!(sys.nr5g_ps_attached);
        assert_eq!(sys.rat, "NR5G-SA");

        let sig = get_signal_info(&mock).await.unwrap();
        assert_eq!(sig.nr5g_rsrp_dbm, Some(-82));
        assert_eq!(sig.nr5g_rsrq_db, Some(-11));
        assert_eq!(sig.nr5g_snr_db, Some(23.5));

        let bands = get_rf_band_info(&mock).await.unwrap();
        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].band, 41);
        assert_eq!(bands[0].arfcn, 521310);
        assert_eq!(bands[0].bandwidth_raw, Some(90));
    }

    #[tokio::test]
    async fn decodes_multi_cc_band_bw_per_occurrence_and_registers_sys_info_ind() {
        let mock = MockQmiClient::new(|msg_id, req_tlvs| {
            let mut w = TlvWriter::new();
            match msg_id {
                NAS_INDICATION_REGISTER => {
                    let parsed = parse_tlvs(req_tlvs)?;
                    assert_eq!(read_u8(&parsed, 0x18), Some(1));
                }
                NAS_GET_RF_BAND_INFO => {
                    // 3 NR5G entries: n41 (90), n66 (20), n25 (15)
                    let mut ext = vec![3u8];
                    for (band, arfcn) in [(41u16, 521310u32), (66u16, 426530u32), (25u16, 393410u32)] {
                        ext.push(12);
                        ext.extend_from_slice(&band.to_le_bytes());
                        ext.extend_from_slice(&arfcn.to_le_bytes());
                    }
                    w.push_bytes(0x11, &ext).unwrap();

                    let mut bw = vec![3u8];
                    for mhz in [90u32, 20u32, 15u32] {
                        bw.push(12);
                        bw.extend_from_slice(&mhz.to_le_bytes());
                    }
                    w.push_bytes(0x12, &bw).unwrap();
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });

        register_sys_info_ind(&mock).await.unwrap();
        let bands = get_rf_band_info(&mock).await.unwrap();
        assert_eq!(bands.len(), 3);
        assert_eq!(bands[0].bandwidth_raw, Some(90));
        assert_eq!(bands[1].bandwidth_raw, Some(20));
        assert_eq!(bands[2].bandwidth_raw, Some(15));
    }
}

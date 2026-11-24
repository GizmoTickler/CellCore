//! QMI Wireless Data Service (`WDS`, `0x01`) client helpers for dual-stack
//! data session control, mux binding, runtime IP/DNS/MTU settings, and 3GPP
//! profile inspection.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use serde::Serialize;

use super::{
    QmiClient, QmiError,
    codec::{TlvWriter, check_result_tlv, find_tlv, read_u8, read_u16_le, read_u32_le},
};

pub const WDS_START_NETWORK_INTERFACE: u16 = 0x0020;
pub const WDS_STOP_NETWORK_INTERFACE: u16 = 0x0021;
pub const WDS_GET_PKT_SRVC_STATUS: u16 = 0x0022;
pub const WDS_PKT_SRVC_STATUS_IND: u16 = 0x0022;
#[allow(dead_code)]
pub const WDS_GET_CURRENT_CHANNEL_RATE: u16 = 0x0023;
pub const WDS_GET_PKT_STATISTICS: u16 = 0x0024;
pub const WDS_GET_PROFILE_LIST: u16 = 0x002A;
pub const WDS_GET_PROFILE_SETTINGS: u16 = 0x002B;
pub const WDS_GET_RUNTIME_SETTINGS: u16 = 0x002D;
pub const WDS_SET_CLIENT_IP_FAMILY_PREF: u16 = 0x004D;
pub const WDS_SET_AUTO_CONNECT: u16 = 0x0051;
pub const WDS_BIND_MUX_DATA_PORT: u16 = 0x00A2;

pub const RUNTIME_SETTINGS_MASK: u32 = 0x0000_6B10;
pub const PKT_STATS_MASK_ALL: u32 = 0x0000_03FF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PktConnStatus {
    Disconnected,
    Connected,
    Suspended,
    Authenticating,
    Unknown(u8),
}

impl PktConnStatus {
    pub fn from_raw(v: u8) -> Self {
        match v {
            1 => Self::Disconnected,
            2 => Self::Connected,
            3 => Self::Suspended,
            4 => Self::Authenticating,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PktSrvcStatus {
    pub status: PktConnStatus,
    pub reconfig_required: bool,
    pub ip_family: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WdsRuntimeSettings {
    pub ipv4_addr: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_netmask: Option<String>,
    pub ipv4_prefix_len: Option<u8>,
    pub ipv4_dns1: Option<String>,
    pub ipv4_dns2: Option<String>,
    pub ipv6_addr: Option<String>,
    pub ipv6_prefix_len: Option<u8>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_dns1: Option<String>,
    pub ipv6_dns2: Option<String>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WdsProfileSummary {
    pub index: u8,
    pub name: String,
    pub pdp_type: Option<&'static str>,
    pub apn: String,
    pub username: String,
    pub auth: Option<&'static str>,
    pub has_password: bool,
    pub cid: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct StartParams<'a> {
    pub profile_index: u8,
    pub ip_family: u8, // 4 = IPv4, 6 = IPv6, 7 = IPv4v6
    pub apn: Option<&'a str>,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub auth: Option<u8>,
}

fn read_le_ipv4(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<Ipv4Addr> {
    // QMI WDS encodes IPv4 addresses/masks/DNS as little-endian u32 scalars.
    read_u32_le(tlvs, tag).filter(|&v| v != 0).map(Ipv4Addr::from)
}

fn read_be_ipv6(bytes: &[u8]) -> Option<Ipv6Addr> {
    if bytes.len() < 16 {
        return None;
    }
    let arr: [u8; 16] = bytes[..16].try_into().ok()?;
    let addr = Ipv6Addr::from(arr);
    (!addr.is_unspecified()).then_some(addr)
}

pub fn parse_pkt_srvc_status_tlvs(tlvs: &[(u8, Vec<u8>)]) -> Result<PktSrvcStatus, QmiError> {
    let raw = find_tlv(tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("WDS pkt_srvc_status missing TLV 0x01".into()))?;
    if raw.is_empty() {
        return Err(QmiError::Malformed("WDS pkt_srvc_status TLV 0x01 empty".into()));
    }
    Ok(PktSrvcStatus {
        status: PktConnStatus::from_raw(raw[0]),
        reconfig_required: raw.get(1).copied().unwrap_or(0) != 0,
        ip_family: read_u8(tlvs, 0x12),
    })
}

pub fn parse_runtime_settings_tlvs(tlvs: &[(u8, Vec<u8>)]) -> WdsRuntimeSettings {
    let ipv4 = read_le_ipv4(tlvs, 0x1E);
    let gw4 = read_le_ipv4(tlvs, 0x20);
    let mask4 = read_le_ipv4(tlvs, 0x21);
    let prefix4 = mask4.map(|m| u32::from(m).leading_ones() as u8);
    let dns4_1 = read_le_ipv4(tlvs, 0x15);
    let dns4_2 = read_le_ipv4(tlvs, 0x16);

    let (v6_addr, v6_plen) = match find_tlv(tlvs, 0x25) {
        Some(b) if b.len() >= 17 => (read_be_ipv6(&b[..16]), Some(b[16].min(128))),
        _ => (None, None),
    };
    let v6_gw = find_tlv(tlvs, 0x26).and_then(read_be_ipv6);
    let v6_dns1 = find_tlv(tlvs, 0x27).and_then(read_be_ipv6);
    let v6_dns2 = find_tlv(tlvs, 0x28).and_then(read_be_ipv6);
    let mtu = read_u32_le(tlvs, 0x29).filter(|&m| (576..=65535).contains(&m));

    WdsRuntimeSettings {
        ipv4_addr: ipv4.map(|a| a.to_string()),
        ipv4_gateway: gw4.map(|a| a.to_string()),
        ipv4_netmask: mask4.map(|a| a.to_string()),
        ipv4_prefix_len: prefix4,
        ipv4_dns1: dns4_1.map(|a| a.to_string()),
        ipv4_dns2: dns4_2.map(|a| a.to_string()),
        ipv6_addr: v6_addr.map(|a| a.to_string()),
        ipv6_prefix_len: v6_plen,
        ipv6_gateway: v6_gw.map(|a| a.to_string()),
        ipv6_dns1: v6_dns1.map(|a| a.to_string()),
        ipv6_dns2: v6_dns2.map(|a| a.to_string()),
        mtu,
    }
}

pub async fn bind_mux_data_port(
    client: &dyn QmiClient,
    ep_type: u32,
    iface_id: u32,
    mux_id: u8,
) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    let mut ep = Vec::with_capacity(8);
    ep.extend_from_slice(&ep_type.to_le_bytes());
    ep.extend_from_slice(&iface_id.to_le_bytes());
    w.push_bytes(0x10, &ep)?
        .push_u8(0x11, mux_id)
        .push_u32(0x13, 1); // 1 = tethered/RmNet client type
    let tlvs = client
        .rpc(WDS_BIND_MUX_DATA_PORT, w.finish(), Duration::from_secs(5))
        .await?;
    check_result_tlv(&tlvs)
}

pub async fn set_client_ip_family_pref(client: &dyn QmiClient, ip_family: u8) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x01, ip_family);
    let tlvs = client
        .rpc(WDS_SET_CLIENT_IP_FAMILY_PREF, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)
}

#[allow(dead_code)]
pub async fn set_auto_connect(client: &dyn QmiClient, enabled: bool) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x01, if enabled { 1 } else { 0 });
    let tlvs = client
        .rpc(WDS_SET_AUTO_CONNECT, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)
}

pub async fn start_network_interface(
    client: &dyn QmiClient,
    p: &StartParams<'_>,
) -> Result<u32, QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x30, 1) // 3GPP technology preference
        .push_u8(0x31, p.profile_index)
        .push_u8(0x19, p.ip_family);
    if let Some(apn) = p.apn.filter(|s| !s.is_empty()) {
        w.push_str(0x14, apn)?;
    }
    if let Some(auth) = p.auth {
        w.push_u8(0x16, auth);
    }
    if let Some(u) = p.username.filter(|s| !s.is_empty()) {
        w.push_str(0x17, u)?;
    }
    if let Some(pw) = p.password.filter(|s| !s.is_empty()) {
        w.push_str(0x18, pw)?;
    }
    let tlvs = client
        .rpc(WDS_START_NETWORK_INTERFACE, w.finish(), Duration::from_secs(120))
        .await?;
    if let Err(e) = check_result_tlv(&tlvs) {
        let cer = read_u16_le(&tlvs, 0x10);
        return Err(match (e, cer) {
            (QmiError::Protocol { code }, Some(reason)) => {
                QmiError::Io(format!("WDS start failed: qmi={code:#x} call_end_reason={reason}"))
            }
            (other, _) => other,
        });
    }
    read_u32_le(&tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("WDS start missing pkt_data_handle TLV 0x01".into()))
}

pub async fn stop_network_interface(client: &dyn QmiClient, handle: u32) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u32(0x01, handle);
    let tlvs = client
        .rpc(WDS_STOP_NETWORK_INTERFACE, w.finish(), Duration::from_secs(15))
        .await?;
    check_result_tlv(&tlvs)
}

pub async fn get_pkt_srvc_status(client: &dyn QmiClient) -> Result<PktSrvcStatus, QmiError> {
    let tlvs = client
        .rpc(WDS_GET_PKT_SRVC_STATUS, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    parse_pkt_srvc_status_tlvs(&tlvs)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WdsChannelRate {
    pub tx_bps: u32,
    pub rx_bps: u32,
    pub max_tx_bps: u32,
    pub max_rx_bps: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WdsPktStatistics {
    pub tx_packets_ok: Option<u32>,
    pub rx_packets_ok: Option<u32>,
    pub tx_errors: Option<u32>,
    pub rx_errors: Option<u32>,
    pub tx_overflows: Option<u32>,
    pub rx_overflows: Option<u32>,
    pub tx_bytes_ok: Option<u64>,
    pub rx_bytes_ok: Option<u64>,
    pub tx_dropped: Option<u32>,
    pub rx_dropped: Option<u32>,
}

fn read_u64_le(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<u64> {
    find_tlv(tlvs, tag).and_then(|v| {
        (v.len() >= 8)
            .then(|| u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
    })
}

#[allow(dead_code)]
pub fn parse_channel_rate_tlvs(tlvs: &[(u8, Vec<u8>)]) -> Result<WdsChannelRate, QmiError> {
    let raw = find_tlv(tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("WDS current_channel_rate missing TLV 0x01".into()))?;
    if raw.len() < 16 {
        return Err(QmiError::Malformed(format!(
            "WDS current_channel_rate TLV 0x01 too short ({} bytes)",
            raw.len()
        )));
    }
    Ok(WdsChannelRate {
        tx_bps: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        rx_bps: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        max_tx_bps: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
        max_rx_bps: u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]),
    })
}

pub fn parse_pkt_statistics_tlvs(tlvs: &[(u8, Vec<u8>)]) -> WdsPktStatistics {
    WdsPktStatistics {
        tx_packets_ok: read_u32_le(tlvs, 0x10),
        rx_packets_ok: read_u32_le(tlvs, 0x11),
        tx_errors: read_u32_le(tlvs, 0x12),
        rx_errors: read_u32_le(tlvs, 0x13),
        tx_overflows: read_u32_le(tlvs, 0x14),
        rx_overflows: read_u32_le(tlvs, 0x15),
        tx_bytes_ok: read_u64_le(tlvs, 0x19),
        rx_bytes_ok: read_u64_le(tlvs, 0x1A),
        tx_dropped: read_u32_le(tlvs, 0x1B),
        rx_dropped: read_u32_le(tlvs, 0x1C),
    }
}

#[allow(dead_code)]
pub async fn get_current_channel_rate(client: &dyn QmiClient) -> Result<WdsChannelRate, QmiError> {
    let tlvs = client
        .rpc(WDS_GET_CURRENT_CHANNEL_RATE, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    parse_channel_rate_tlvs(&tlvs)
}

pub async fn get_pkt_statistics(client: &dyn QmiClient) -> Result<WdsPktStatistics, QmiError> {
    let mut w = TlvWriter::new();
    w.push_u32(0x01, PKT_STATS_MASK_ALL);
    let tlvs = client
        .rpc(WDS_GET_PKT_STATISTICS, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_pkt_statistics_tlvs(&tlvs))
}

pub async fn get_runtime_settings(client: &dyn QmiClient) -> Result<WdsRuntimeSettings, QmiError> {
    let mut w = TlvWriter::new();
    w.push_u32(0x10, RUNTIME_SETTINGS_MASK);
    let tlvs = client
        .rpc(WDS_GET_RUNTIME_SETTINGS, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_runtime_settings_tlvs(&tlvs))
}

fn pdp_type_str(raw: u8) -> &'static str {
    match raw {
        0 => "IPV4",
        2 => "IPV6",
        3 => "IPV4V6",
        _ => "OTHER",
    }
}

fn auth_str(raw: u8) -> &'static str {
    match raw {
        0 => "NONE",
        1 => "PAP",
        2 => "CHAP",
        3 => "PAP_OR_CHAP",
        _ => "UNKNOWN",
    }
}

pub async fn get_profile_list(client: &dyn QmiClient) -> Result<Vec<(u8, String)>, QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x10, 0); // 3GPP profile type
    let tlvs = client
        .rpc(WDS_GET_PROFILE_LIST, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    let raw = find_tlv(&tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("WDS profile list missing TLV 0x01".into()))?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let count = raw[0] as usize;
    let mut pos = 1usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 3 > raw.len() {
            return Err(QmiError::Malformed("truncated WDS profile list entry".into()));
        }
        let _ptype = raw[pos];
        let pindex = raw[pos + 1];
        let name_len = raw[pos + 2] as usize;
        pos += 3;
        if pos + name_len > raw.len() {
            return Err(QmiError::Malformed("truncated WDS profile list name".into()));
        }
        let name = String::from_utf8_lossy(&raw[pos..pos + name_len])
            .trim_end_matches('\0')
            .to_string();
        pos += name_len;
        out.push((pindex, name));
    }
    Ok(out)
}

pub async fn get_profile_settings(
    client: &dyn QmiClient,
    profile_index: u8,
    fallback_name: String,
) -> Result<WdsProfileSummary, QmiError> {
    let mut w = TlvWriter::new();
    w.push_bytes(0x01, &[0u8, profile_index])?; // type=0 (3GPP), index
    let tlvs = client
        .rpc(WDS_GET_PROFILE_SETTINGS, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    let name = find_tlv(&tlvs, 0x10)
        .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_name);
    let pdp_type = read_u8(&tlvs, 0x11).map(pdp_type_str);
    let apn = find_tlv(&tlvs, 0x14)
        .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    let username = find_tlv(&tlvs, 0x1B)
        .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    let has_password = find_tlv(&tlvs, 0x1C).is_some_and(|b| !b.is_empty());
    let auth = read_u8(&tlvs, 0x1D).map(auth_str);
    let cid = read_u8(&tlvs, 0x25);
    Ok(WdsProfileSummary {
        index: profile_index,
        name,
        pdp_type,
        apn,
        username,
        auth,
        has_password,
        cid,
    })
}

pub async fn list_profiles(client: &dyn QmiClient) -> Result<Vec<WdsProfileSummary>, QmiError> {
    let list = get_profile_list(client).await?;
    let mut out = Vec::with_capacity(list.len());
    for (idx, name) in list {
        if let Ok(p) = get_profile_settings(client, idx, name).await {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{
        codec::{make_result_ok_tlv, parse_tlvs},
        test_support::MockQmiClient,
    };

    #[tokio::test]
    async fn runtime_settings_decode_le32_v4_and_be_v6() {
        // 100.64.1.2 as LE32 u32 value: (100<<24)|(64<<16)|(1<<8)|2 = 0x64400102
        // Stored little-endian on wire -> [0x02, 0x01, 0x40, 0x64]
        let mock = MockQmiClient::new(|msg_id, req| {
            let mut w = TlvWriter::new();
            match msg_id {
                WDS_GET_RUNTIME_SETTINGS => {
                    let rtlvs = parse_tlvs(req)?;
                    assert_eq!(read_u32_le(&rtlvs, 0x10), Some(RUNTIME_SETTINGS_MASK));
                    w.push_u32(0x1E, u32::from(Ipv4Addr::new(100, 64, 1, 2)))
                        .push_u32(0x20, u32::from(Ipv4Addr::new(100, 64, 1, 1)))
                        .push_u32(0x21, u32::from(Ipv4Addr::new(255, 255, 255, 252)))
                        .push_u32(0x15, u32::from(Ipv4Addr::new(1, 1, 1, 1)))
                        .push_u32(0x16, u32::from(Ipv4Addr::new(1, 0, 0, 1)))
                        .push_u32(0x29, 1420);
                    let mut v6 = Ipv6Addr::new(0x2600, 0x1000, 0, 0, 0, 0, 0, 0x12).octets().to_vec();
                    v6.push(64);
                    w.push_bytes(0x25, &v6).unwrap();
                    let v6_dns: [u8; 16] = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets();
                    w.push_bytes(0x27, &v6_dns).unwrap();
                }
                WDS_GET_PKT_SRVC_STATUS => {
                    w.push_bytes(0x01, &[2, 0]).unwrap();
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });

        let rt = get_runtime_settings(&mock).await.unwrap();
        assert_eq!(rt.ipv4_addr.as_deref(), Some("100.64.1.2"));
        assert_eq!(rt.ipv4_gateway.as_deref(), Some("100.64.1.1"));
        assert_eq!(rt.ipv4_netmask.as_deref(), Some("255.255.255.252"));
        assert_eq!(rt.ipv4_prefix_len, Some(30));
        assert_eq!(rt.ipv4_dns1.as_deref(), Some("1.1.1.1"));
        assert_eq!(rt.ipv4_dns2.as_deref(), Some("1.0.0.1"));
        assert_eq!(rt.ipv6_addr.as_deref(), Some("2600:1000::12"));
        assert_eq!(rt.ipv6_prefix_len, Some(64));
        assert_eq!(rt.ipv6_dns1.as_deref(), Some("2606:4700:4700::1111"));
        assert_eq!(rt.mtu, Some(1420));

        let st = get_pkt_srvc_status(&mock).await.unwrap();
        assert_eq!(st.status, PktConnStatus::Connected);
        assert!(!st.reconfig_required);
    }

    #[tokio::test]
    async fn profile_list_and_password_redaction() {
        let mock = MockQmiClient::new(|msg_id, _| {
            let mut w = TlvWriter::new();
            match msg_id {
                WDS_GET_PROFILE_LIST => {
                    // 1 entry: type=0, index=1, name="vzwinternet"
                    let mut raw = vec![1u8, 0, 1, 11];
                    raw.extend_from_slice(b"vzwinternet");
                    w.push_bytes(0x01, &raw).unwrap();
                }
                WDS_GET_PROFILE_SETTINGS => {
                    w.push_str(0x10, "profile1").unwrap();
                    w.push_u8(0x11, 3);
                    w.push_str(0x14, "vzwinternet").unwrap();
                    w.push_str(0x1B, "user1").unwrap();
                    w.push_str(0x1C, "SUPER_SECRET_PASSWORD").unwrap();
                    w.push_u8(0x1D, 1);
                    w.push_u8(0x25, 1);
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });

        let profiles = list_profiles(&mock).await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].apn, "vzwinternet");
        assert_eq!(profiles[0].pdp_type, Some("IPV4V6"));
        assert_eq!(profiles[0].auth, Some("PAP"));
        assert!(profiles[0].has_password);
        let serialized = serde_json::to_string(&profiles).unwrap();
        assert!(!serialized.contains("SUPER_SECRET_PASSWORD"));
    }

    #[test]
    fn reconfig_required_indication_detected() {
        let ind = parse_pkt_srvc_status_tlvs(&[(0x01, vec![2, 1])]).unwrap();
        assert_eq!(ind.status, PktConnStatus::Connected);
        assert!(ind.reconfig_required);
    }

    #[tokio::test]
    async fn decodes_current_channel_rate_and_pkt_statistics() {
        let mock = MockQmiClient::new(|msg_id, req| {
            let mut w = TlvWriter::new();
            match msg_id {
                WDS_GET_CURRENT_CHANNEL_RATE => {
                    let mut raw = Vec::with_capacity(16);
                    raw.extend_from_slice(&150_000_000u32.to_le_bytes());
                    raw.extend_from_slice(&1_200_000_000u32.to_le_bytes());
                    raw.extend_from_slice(&300_000_000u32.to_le_bytes());
                    raw.extend_from_slice(&2_500_000_000u32.to_le_bytes());
                    w.push_bytes(0x01, &raw).unwrap();
                }
                WDS_GET_PKT_STATISTICS => {
                    let rtlvs = parse_tlvs(req)?;
                    assert_eq!(read_u32_le(&rtlvs, 0x01), Some(PKT_STATS_MASK_ALL));
                    w.push_u32(0x10, 1000)
                        .push_u32(0x11, 2000)
                        .push_u32(0x12, 1)
                        .push_u32(0x13, 2)
                        .push_u32(0x14, 0)
                        .push_u32(0x15, 3)
                        .push_u32(0x1B, 4)
                        .push_u32(0x1C, 5);
                    w.push_bytes(0x19, &1_500_000u64.to_le_bytes()).unwrap();
                    w.push_bytes(0x1A, &9_876_543_210u64.to_le_bytes()).unwrap();
                }
                other => return Err(QmiError::Malformed(format!("unexpected {other:#x}"))),
            }
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });

        let rate = get_current_channel_rate(&mock).await.unwrap();
        assert_eq!(rate.tx_bps, 150_000_000);
        assert_eq!(rate.rx_bps, 1_200_000_000);
        assert_eq!(rate.max_tx_bps, 300_000_000);
        assert_eq!(rate.max_rx_bps, 2_500_000_000);

        let stats = get_pkt_statistics(&mock).await.unwrap();
        assert_eq!(stats.tx_packets_ok, Some(1000));
        assert_eq!(stats.rx_packets_ok, Some(2000));
        assert_eq!(stats.tx_errors, Some(1));
        assert_eq!(stats.rx_errors, Some(2));
        assert_eq!(stats.tx_overflows, Some(0));
        assert_eq!(stats.rx_overflows, Some(3));
        assert_eq!(stats.tx_bytes_ok, Some(1_500_000));
        assert_eq!(stats.rx_bytes_ok, Some(9_876_543_210));
        assert_eq!(stats.tx_dropped, Some(4));
        assert_eq!(stats.rx_dropped, Some(5));
    }
}

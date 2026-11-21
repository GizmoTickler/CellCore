//! QMI Wireless Data Administrative (`WDA`, `0x1A`) client helpers.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    QmiClient, QmiError,
    codec::{TlvWriter, check_result_tlv, read_u8, read_u32_le},
};

pub const WDA_SET_DATA_FORMAT: u16 = 0x0020;
pub const WDA_GET_DATA_FORMAT: u16 = 0x0021;

#[allow(dead_code)]
pub const LINK_PROT_802_3: u32 = 1;
#[allow(dead_code)]
pub const LINK_PROT_RAW_IP: u32 = 2;

#[allow(dead_code)]
pub const AGG_NONE: u32 = 0;
#[allow(dead_code)]
pub const AGG_QMAP_V1: u32 = 5;
#[allow(dead_code)]
pub const AGG_QMAP_V4: u32 = 8;
#[allow(dead_code)]
pub const AGG_QMAP_V5: u32 = 9;

pub const EP_TYPE_EMBEDDED: u32 = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WdaDataFormat {
    pub qos_format: Option<bool>,
    pub link_protocol: Option<u32>,
    pub ul_agg_protocol: Option<u32>,
    pub dl_agg_protocol: Option<u32>,
    pub dl_max_datagrams: Option<u32>,
    pub dl_max_size: Option<u32>,
    pub ul_max_datagrams: Option<u32>,
    pub ul_max_size: Option<u32>,
    pub dl_min_padding: Option<u32>,
    #[serde(default)]
    pub flow_control: Option<u8>,
}

fn parse_data_format_resp(tlvs: &[(u8, Vec<u8>)]) -> WdaDataFormat {
    WdaDataFormat {
        qos_format: read_u8(tlvs, 0x10).map(|v| v != 0),
        link_protocol: read_u32_le(tlvs, 0x11),
        ul_agg_protocol: read_u32_le(tlvs, 0x12),
        dl_agg_protocol: read_u32_le(tlvs, 0x13),
        dl_max_datagrams: read_u32_le(tlvs, 0x15),
        dl_max_size: read_u32_le(tlvs, 0x16),
        ul_max_datagrams: read_u32_le(tlvs, 0x17).or_else(|| read_u32_le(tlvs, 0x1D)),
        ul_max_size: read_u32_le(tlvs, 0x18).or_else(|| read_u32_le(tlvs, 0x1E)),
        dl_min_padding: read_u32_le(tlvs, 0x1A),
        flow_control: read_u8(tlvs, 0x1B),
    }
}

pub async fn get_data_format(
    client: &dyn QmiClient,
    ep: Option<(u32, u32)>,
) -> Result<WdaDataFormat, QmiError> {
    let mut w = TlvWriter::new();
    if let Some((ep_type, iface_id)) = ep {
        let mut ep_bytes = Vec::with_capacity(8);
        ep_bytes.extend_from_slice(&ep_type.to_le_bytes());
        ep_bytes.extend_from_slice(&iface_id.to_le_bytes());
        w.push_bytes(0x10, &ep_bytes)?;
    }
    let tlvs = client
        .rpc(WDA_GET_DATA_FORMAT, w.finish(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_data_format_resp(&tlvs))
}

#[allow(clippy::too_many_arguments)]
pub async fn set_data_format(
    client: &dyn QmiClient,
    link_protocol: u32,
    ul_agg: u32,
    dl_agg: u32,
    dl_max_dgrams: u32,
    dl_max_size: u32,
    ul_max_dgrams: u32,
    ul_max_size: u32,
    flow_control: u8,
    ep: (u32, u32),
) -> Result<WdaDataFormat, QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x10, 0)
        .push_u32(0x11, link_protocol)
        .push_u32(0x12, ul_agg)
        .push_u32(0x13, dl_agg)
        .push_u32(0x15, dl_max_dgrams)
        .push_u32(0x16, dl_max_size);
    let mut ep_bytes = Vec::with_capacity(8);
    ep_bytes.extend_from_slice(&ep.0.to_le_bytes());
    ep_bytes.extend_from_slice(&ep.1.to_le_bytes());
    w.push_bytes(0x17, &ep_bytes)?;
    w.push_u32(0x1A, 0)
        .push_u8(0x1B, flow_control)
        .push_u32(0x1D, ul_max_dgrams)
        .push_u32(0x1E, ul_max_size);
    let tlvs = client
        .rpc(WDA_SET_DATA_FORMAT, w.finish(), Duration::from_secs(5))
        .await?;
    check_result_tlv(&tlvs)?;
    Ok(parse_data_format_resp(&tlvs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{
        codec::{make_result_ok_tlv, parse_tlvs},
        test_support::MockQmiClient,
    };

    #[tokio::test]
    async fn decodes_qmap_raw_ip_format() {
        let mock = MockQmiClient::new(|msg_id, _| {
            assert_eq!(msg_id, WDA_GET_DATA_FORMAT);
            let mut w = TlvWriter::new();
            w.push_u8(0x10, 0)
                .push_u32(0x11, LINK_PROT_RAW_IP)
                .push_u32(0x12, AGG_QMAP_V5)
                .push_u32(0x13, AGG_QMAP_V5)
                .push_u32(0x15, 32)
                .push_u32(0x16, 16384)
                .push_u8(0x1B, 1);
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });
        let fmt = get_data_format(&mock, Some((EP_TYPE_EMBEDDED, 1))).await.unwrap();
        assert_eq!(fmt.qos_format, Some(false));
        assert_eq!(fmt.link_protocol, Some(LINK_PROT_RAW_IP));
        assert_eq!(fmt.dl_agg_protocol, Some(AGG_QMAP_V5));
        assert_eq!(fmt.dl_max_datagrams, Some(32));
        assert_eq!(fmt.dl_max_size, Some(16384));
        assert_eq!(fmt.flow_control, Some(1));
    }

    #[tokio::test]
    async fn encodes_qmapv5_set_data_format_tlvs() {
        let mock = MockQmiClient::new(|msg_id, req_bytes| {
            assert_eq!(msg_id, WDA_SET_DATA_FORMAT);
            let req_tlvs = parse_tlvs(req_bytes)?;
            assert_eq!(read_u32_le(&req_tlvs, 0x11), Some(LINK_PROT_RAW_IP));
            assert_eq!(read_u32_le(&req_tlvs, 0x12), Some(AGG_QMAP_V5));
            assert_eq!(read_u32_le(&req_tlvs, 0x13), Some(AGG_QMAP_V5));
            assert_eq!(read_u32_le(&req_tlvs, 0x15), Some(64));
            assert_eq!(read_u32_le(&req_tlvs, 0x16), Some(32768));
            assert_eq!(read_u32_le(&req_tlvs, 0x1A), Some(0));
            assert_eq!(read_u8(&req_tlvs, 0x1B), Some(1));
            assert_eq!(read_u32_le(&req_tlvs, 0x1D), Some(16));
            assert_eq!(read_u32_le(&req_tlvs, 0x1E), Some(16384));

            let mut w = TlvWriter::new();
            w.push_u8(0x10, 0)
                .push_u32(0x11, LINK_PROT_RAW_IP)
                .push_u32(0x12, AGG_QMAP_V5)
                .push_u32(0x13, AGG_QMAP_V5)
                .push_u32(0x15, 64)
                .push_u32(0x16, 32768)
                .push_u32(0x17, 16)
                .push_u32(0x18, 16384)
                .push_u32(0x1A, 0)
                .push_u8(0x1B, 1);
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });
        let fmt = set_data_format(
            &mock,
            LINK_PROT_RAW_IP,
            AGG_QMAP_V5,
            AGG_QMAP_V5,
            64,
            32768,
            16,
            16384,
            1,
            (EP_TYPE_EMBEDDED, 1),
        )
        .await
        .unwrap();
        assert_eq!(fmt.dl_agg_protocol, Some(AGG_QMAP_V5));
        assert_eq!(fmt.dl_max_datagrams, Some(64));
        assert_eq!(fmt.dl_max_size, Some(32768));
        assert_eq!(fmt.ul_max_datagrams, Some(16));
        assert_eq!(fmt.ul_max_size, Some(16384));
        assert_eq!(fmt.dl_min_padding, Some(0));
        assert_eq!(fmt.flow_control, Some(1));
    }
}

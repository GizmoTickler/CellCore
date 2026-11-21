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
}

fn parse_data_format_resp(tlvs: &[(u8, Vec<u8>)]) -> WdaDataFormat {
    WdaDataFormat {
        qos_format: read_u8(tlvs, 0x10).map(|v| v != 0),
        link_protocol: read_u32_le(tlvs, 0x11),
        ul_agg_protocol: read_u32_le(tlvs, 0x12),
        dl_agg_protocol: read_u32_le(tlvs, 0x13),
        dl_max_datagrams: read_u32_le(tlvs, 0x15),
        dl_max_size: read_u32_le(tlvs, 0x16),
        ul_max_datagrams: read_u32_le(tlvs, 0x17),
        ul_max_size: read_u32_le(tlvs, 0x18),
        dl_min_padding: read_u32_le(tlvs, 0x1A),
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

#[allow(dead_code)]
pub async fn set_data_format(
    client: &dyn QmiClient,
    link_protocol: u32,
    ul_agg: u32,
    dl_agg: u32,
    dl_max_dgrams: u32,
    dl_max_size: u32,
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
                .push_u32(0x16, 16384);
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
    }
}

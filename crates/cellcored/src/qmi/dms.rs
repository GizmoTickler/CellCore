//! QMI Device Management Service (`DMS`, `0x02`) client helpers.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    QmiClient, QmiError,
    codec::{TlvWriter, check_result_tlv, find_tlv, read_u8},
};

pub const DMS_GET_DEVICE_REV_ID: u16 = 0x0023;
pub const DMS_GET_OPERATING_MODE: u16 = 0x002D;
#[allow(dead_code)]
pub const DMS_SET_OPERATING_MODE: u16 = 0x002E;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperatingMode {
    Online,
    LowPower,
    FactoryTest,
    Offline,
    Resetting,
    ShuttingDown,
    PersistentLowPower,
    ModeOnlyLowPower,
    Unknown(u8),
}

impl OperatingMode {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::Online,
            1 => Self::LowPower,
            2 => Self::FactoryTest,
            3 => Self::Offline,
            4 => Self::Resetting,
            5 => Self::ShuttingDown,
            6 => Self::PersistentLowPower,
            7 => Self::ModeOnlyLowPower,
            other => Self::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::LowPower => "low-power",
            Self::FactoryTest => "factory-test",
            Self::Offline => "offline",
            Self::Resetting => "resetting",
            Self::ShuttingDown => "shutting-down",
            Self::PersistentLowPower => "persistent-low-power",
            Self::ModeOnlyLowPower => "mode-only-low-power",
            Self::Unknown(_) => "unknown",
        }
    }
}

pub async fn get_device_rev_id(client: &dyn QmiClient) -> Result<String, QmiError> {
    let tlvs = client
        .rpc(DMS_GET_DEVICE_REV_ID, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    let bytes = find_tlv(&tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("DMS rev id missing TLV 0x01".into()))?;
    Ok(String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string())
}

pub async fn get_operating_mode(client: &dyn QmiClient) -> Result<OperatingMode, QmiError> {
    let tlvs = client
        .rpc(DMS_GET_OPERATING_MODE, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    let raw = read_u8(&tlvs, 0x01)
        .ok_or_else(|| QmiError::Malformed("DMS operating mode missing TLV 0x01".into()))?;
    Ok(OperatingMode::from_raw(raw))
}

#[allow(dead_code)]
pub async fn set_operating_mode(client: &dyn QmiClient, mode: u8) -> Result<(), QmiError> {
    let mut w = TlvWriter::new();
    w.push_u8(0x01, mode);
    let tlvs = client
        .rpc(DMS_SET_OPERATING_MODE, w.finish(), Duration::from_secs(10))
        .await?;
    check_result_tlv(&tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{
        codec::{make_result_ok_tlv, parse_tlvs},
        test_support::MockQmiClient,
    };

    #[tokio::test]
    async fn rev_and_operating_mode_decode() {
        let mock = MockQmiClient::new(|msg_id, req| {
            let mut w = TlvWriter::new();
            match msg_id {
                DMS_GET_DEVICE_REV_ID => {
                    w.push_str(0x01, "RM551EGL00AAR01A01M8G_01.001.01.001\0").unwrap();
                    let mut out = parse_tlvs(&make_result_ok_tlv())?;
                    out.extend(parse_tlvs(&w.finish())?);
                    Ok(out)
                }
                DMS_GET_OPERATING_MODE => {
                    w.push_u8(0x01, 0);
                    let mut out = parse_tlvs(&make_result_ok_tlv())?;
                    out.extend(parse_tlvs(&w.finish())?);
                    Ok(out)
                }
                DMS_SET_OPERATING_MODE => {
                    let req_tlvs = parse_tlvs(req)?;
                    assert_eq!(read_u8(&req_tlvs, 0x01), Some(1));
                    parse_tlvs(&make_result_ok_tlv())
                }
                other => Err(QmiError::Malformed(format!("unexpected msg {other:#x}"))),
            }
        });
        assert_eq!(get_device_rev_id(&mock).await.unwrap(), "RM551EGL00AAR01A01M8G_01.001.01.001");
        assert_eq!(get_operating_mode(&mock).await.unwrap(), OperatingMode::Online);
        set_operating_mode(&mock, 1).await.unwrap();
    }
}

//! QMI User Identity Module (`UIM`, `0x0B`) client helpers.

use std::time::Duration;

use serde::Serialize;

use super::{
    QmiClient, QmiError,
    codec::{check_result_tlv, find_tlv},
};

#[allow(dead_code)]
pub const UIM_VERIFY_PIN: u16 = 0x0026;
pub const UIM_GET_CARD_STATUS: u16 = 0x002F;
#[allow(dead_code)]
pub const UIM_POWER_DOWN: u16 = 0x0030;
#[allow(dead_code)]
pub const UIM_POWER_UP: u16 = 0x0031;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UimSlotStatus {
    pub slot: u8,
    pub card_state: &'static str,
    pub pin1_state: &'static str,
    pub app_type: &'static str,
    pub app_state: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UimCardStatus {
    pub num_slots: u8,
    pub slots: Vec<UimSlotStatus>,
}

fn card_state_str(v: u8) -> &'static str {
    match v {
        0 => "absent",
        1 => "present",
        2 => "error",
        _ => "unknown",
    }
}

fn pin_state_str(v: u8) -> &'static str {
    match v {
        1 => "enabled-not-verified",
        2 => "enabled-verified",
        3 => "disabled",
        4 => "blocked",
        5 => "perm-blocked",
        _ => "unknown",
    }
}

fn app_type_str(v: u8) -> &'static str {
    match v {
        0 => "none",
        1 => "sim",
        2 => "usim",
        3 => "ruim",
        4 => "csim",
        5 => "isim",
        _ => "unknown",
    }
}

fn app_state_str(v: u8) -> &'static str {
    match v {
        1 => "detected",
        2 => "pin1-req",
        3 => "puk1-req",
        7 => "ready",
        _ => "unknown",
    }
}

/// Parse TLV `0x10` (`card_status`) from `QMI_UIM_GET_CARD_STATUS_RESP`.
pub fn parse_card_status_tlv(data: &[u8]) -> Result<UimCardStatus, QmiError> {
    if data.len() < 5 {
        return Err(QmiError::Malformed(format!(
            "UIM card_status TLV 0x10 too short ({} bytes)",
            data.len()
        )));
    }
    // Layout: [index_gw_pri:u16 LE, index_1x_pri:u16 LE, num_slots:u8, slots...]
    let num_slots = data[4];
    let mut pos = 5usize;
    let mut slots = Vec::with_capacity(num_slots as usize);
    for idx in 0..num_slots {
        // Per slot header: [card_state:u8, upin_state:u8, upin_retries:u8, upuk_retries:u8, error_code:u8, num_apps:u8]
        if pos + 6 > data.len() {
            return Err(QmiError::Malformed("truncated UIM slot header".into()));
        }
        let card_state = data[pos];
        let num_apps = data[pos + 5];
        pos += 6;
        let mut first_pin1 = 0u8;
        let mut first_app_type = 0u8;
        let mut first_app_state = 0u8;
        for a_idx in 0..num_apps {
            // App fixed fields (10 bytes): [app_type:u8, app_state:u8, perso_state:u8, perso_feat:u8, perso_retries:u8, perso_unblock:u8, aid_len:u8, ...]
            // Followed by aid[aid_len], upin1_replaced:u8, pin1_state:u8, pin1_retries:u8, puk1_retries:u8, pin2_state:u8, pin2_retries:u8, puk2_retries:u8
            if pos + 7 > data.len() {
                return Err(QmiError::Malformed("truncated UIM app header".into()));
            }
            let app_type = data[pos];
            let app_state = data[pos + 1];
            let aid_len = data[pos + 6] as usize;
            pos += 7;
            if pos + aid_len + 7 > data.len() {
                return Err(QmiError::Malformed("truncated UIM app tail".into()));
            }
            pos += aid_len;
            let pin1_state = data[pos + 1];
            pos += 7;
            if a_idx == 0 {
                first_pin1 = pin1_state;
                first_app_type = app_type;
                first_app_state = app_state;
            }
        }
        slots.push(UimSlotStatus {
            slot: idx + 1,
            card_state: card_state_str(card_state),
            pin1_state: pin_state_str(first_pin1),
            app_type: app_type_str(first_app_type),
            app_state: app_state_str(first_app_state),
        });
    }
    Ok(UimCardStatus { num_slots, slots })
}

pub async fn get_card_status(client: &dyn QmiClient) -> Result<UimCardStatus, QmiError> {
    let tlvs = client
        .rpc(UIM_GET_CARD_STATUS, Vec::new(), Duration::from_secs(3))
        .await?;
    check_result_tlv(&tlvs)?;
    let raw = find_tlv(&tlvs, 0x10)
        .ok_or_else(|| QmiError::Malformed("UIM get_card_status missing TLV 0x10".into()))?;
    parse_card_status_tlv(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi::{
        codec::{TlvWriter, make_result_ok_tlv, parse_tlvs},
        test_support::MockQmiClient,
    };

    #[tokio::test]
    async fn parses_dual_slot_card_status() {
        let mut raw = vec![0x00, 0x00, 0xFF, 0xFF, 2];
        // Slot 1: present, 1 USIM ready app with 3-byte AID and disabled PIN1 (3)
        raw.extend_from_slice(&[1, 3, 3, 10, 0, 1]);
        raw.extend_from_slice(&[2, 7, 0, 0, 0, 0, 3, 0xA0, 0x00, 0x01, 0, 3, 3, 10, 3, 3, 10]);
        // Slot 2: absent, 0 apps
        raw.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        let mock = MockQmiClient::new(move |msg_id, _| {
            assert_eq!(msg_id, UIM_GET_CARD_STATUS);
            let mut w = TlvWriter::new();
            w.push_bytes(0x10, &raw).unwrap();
            let mut out = parse_tlvs(&make_result_ok_tlv())?;
            out.extend(parse_tlvs(&w.finish())?);
            Ok(out)
        });
        let st = get_card_status(&mock).await.unwrap();
        assert_eq!(st.num_slots, 2);
        assert_eq!(st.slots[0].card_state, "present");
        assert_eq!(st.slots[0].app_type, "usim");
        assert_eq!(st.slots[0].app_state, "ready");
        assert_eq!(st.slots[0].pin1_state, "disabled");
        assert_eq!(st.slots[1].card_state, "absent");
    }
}

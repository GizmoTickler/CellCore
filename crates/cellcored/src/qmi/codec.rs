//! QMI SDU (Service Data Unit) & TLV binary codec for QRTR (`AF_QIPCRTR`).
//!
//! Over QRTR, QMI messages carry the compact 7-byte QMUX SDU header directly
//! without the 6-byte USB `QCQMI_HDR` framing:
//!   `[0]`    `ctl_flags: u8` (`0x00` = REQ, `0x02` = RSP, `0x04` = IND)
//!   `[1..3]` `tx_id: u16` LE
//!   `[3..5]` `msg_id: u16` LE
//!   `[5..7]` `msg_len: u16` LE
//!   `[7..7+msg_len]` TLV sequence: `[tag: u8, len: u16 LE, value: [u8; len]]`

use super::QmiError;

pub const QMI_FLAG_REQUEST: u8 = 0x00;
pub const QMI_FLAG_RESPONSE: u8 = 0x02;
pub const QMI_FLAG_INDICATION: u8 = 0x04;
pub const QMI_SDU_HDR_LEN: usize = 7;
pub const TLV_RESULT: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiSdu {
    pub ctl_flags: u8,
    pub tx_id: u16,
    pub msg_id: u16,
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

/// Incremental builder for outgoing QMI TLV payloads.
#[derive(Debug, Default, Clone)]
pub struct TlvWriter {
    buf: Vec<u8>,
}

impl TlvWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, tag: u8, val: &[u8]) -> Result<&mut Self, QmiError> {
        let len = u16::try_from(val.len())
            .map_err(|_| QmiError::Malformed(format!("TLV {tag:#04x} exceeds u16 length")))?;
        self.buf.push(tag);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(val);
        Ok(self)
    }

    pub fn push_u8(&mut self, tag: u8, v: u8) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&1u16.to_le_bytes());
        self.buf.push(v);
        self
    }

    #[allow(dead_code)]
    pub fn push_u16(&mut self, tag: u8, v: u16) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&2u16.to_le_bytes());
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn push_u32(&mut self, tag: u8, v: u32) -> &mut Self {
        self.buf.push(tag);
        self.buf.extend_from_slice(&4u16.to_le_bytes());
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn push_str(&mut self, tag: u8, s: &str) -> Result<&mut Self, QmiError> {
        self.push_bytes(tag, s.as_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Encode a QMI-over-QRTR request frame (`ctl_flags = 0x00`).
pub fn encode_sdu(ctl_flags: u8, tx_id: u16, msg_id: u16, tlvs: &[u8]) -> Result<Vec<u8>, QmiError> {
    let msg_len = u16::try_from(tlvs.len())
        .map_err(|_| QmiError::Malformed("QMI SDU payload exceeds 65535 bytes".into()))?;
    let mut out = Vec::with_capacity(QMI_SDU_HDR_LEN + tlvs.len());
    out.push(ctl_flags);
    out.extend_from_slice(&tx_id.to_le_bytes());
    out.extend_from_slice(&msg_id.to_le_bytes());
    out.extend_from_slice(&msg_len.to_le_bytes());
    out.extend_from_slice(tlvs);
    Ok(out)
}

pub fn encode_request(tx_id: u16, msg_id: u16, tlvs: &[u8]) -> Result<Vec<u8>, QmiError> {
    encode_sdu(QMI_FLAG_REQUEST, tx_id, msg_id, tlvs)
}

/// Parse TLV bytes `[tag: u8, len: u16 LE, val: [u8; len]]` safely without panics.
pub fn parse_tlvs(payload: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, QmiError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        if pos + 3 > payload.len() {
            return Err(QmiError::Malformed(format!(
                "truncated TLV header at offset {pos} (total {})",
                payload.len()
            )));
        }
        let tag = payload[pos];
        let len = u16::from_le_bytes([payload[pos + 1], payload[pos + 2]]) as usize;
        pos += 3;
        if pos + len > payload.len() {
            return Err(QmiError::Malformed(format!(
                "truncated TLV {tag:#04x} body: need {len}, have {}",
                payload.len() - pos
            )));
        }
        out.push((tag, payload[pos..pos + len].to_vec()));
        pos += len;
    }
    Ok(out)
}

/// Decode a QMI-over-QRTR SDU frame.
pub fn decode_sdu(buf: &[u8]) -> Result<QmiSdu, QmiError> {
    if buf.len() < QMI_SDU_HDR_LEN {
        return Err(QmiError::Malformed(format!(
            "QMI frame too short: {} bytes",
            buf.len()
        )));
    }
    let ctl_flags = buf[0];
    let tx_id = u16::from_le_bytes([buf[1], buf[2]]);
    let msg_id = u16::from_le_bytes([buf[3], buf[4]]);
    let msg_len = u16::from_le_bytes([buf[5], buf[6]]) as usize;
    if QMI_SDU_HDR_LEN + msg_len > buf.len() {
        return Err(QmiError::Malformed(format!(
            "QMI SDU length mismatch: header declares {msg_len}, packet has {} body bytes",
            buf.len() - QMI_SDU_HDR_LEN
        )));
    }
    let tlvs = parse_tlvs(&buf[QMI_SDU_HDR_LEN..QMI_SDU_HDR_LEN + msg_len])?;
    Ok(QmiSdu {
        ctl_flags,
        tx_id,
        msg_id,
        tlvs,
    })
}

pub fn find_tlv(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<&[u8]> {
    tlvs.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
}

pub fn read_u8(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<u8> {
    find_tlv(tlvs, tag).and_then(|v| v.first().copied())
}

pub fn read_u16_le(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<u16> {
    find_tlv(tlvs, tag).and_then(|v| (v.len() >= 2).then(|| u16::from_le_bytes([v[0], v[1]])))
}

pub fn read_u32_le(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<u32> {
    find_tlv(tlvs, tag).and_then(|v| {
        (v.len() >= 4).then(|| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    })
}

/// Inspect the standard QMI Result TLV (`0x02`: `{ result: u16 LE, error: u16 LE }`).
/// Returns `Ok(())` when `0x02` reports `result == 0` (or is absent), and
/// `Err(QmiError::Protocol { code })` when `result != 0`.
pub fn check_result_tlv(tlvs: &[(u8, Vec<u8>)]) -> Result<(), QmiError> {
    let Some(val) = find_tlv(tlvs, TLV_RESULT) else {
        return Ok(());
    };
    if val.len() < 4 {
        return Err(QmiError::Malformed(format!(
            "result TLV 0x02 too short ({} bytes)",
            val.len()
        )));
    }
    let result = u16::from_le_bytes([val[0], val[1]]);
    let error = u16::from_le_bytes([val[2], val[3]]);
    if result == 0 {
        Ok(())
    } else {
        Err(QmiError::Protocol { code: error })
    }
}

#[cfg(test)]
pub(crate) fn make_result_ok_tlv() -> Vec<u8> {
    let mut w = TlvWriter::new();
    let _ = w.push_bytes(TLV_RESULT, &[0, 0, 0, 0]);
    w.finish()
}

#[cfg(test)]
pub(crate) fn make_result_err_tlv(code: u16) -> Vec<u8> {
    let mut w = TlvWriter::new();
    let c = code.to_le_bytes();
    let _ = w.push_bytes(TLV_RESULT, &[1, 0, c[0], c[1]]);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sdu_and_tlvs() {
        let mut w = TlvWriter::new();
        w.push_u8(0x01, 4).push_u32(0x10, 0x0000_6B10);
        w.push_str(0x14, "internet").unwrap();
        let req = encode_request(0x1234, 0x0020, &w.finish()).unwrap();

        assert_eq!(req[0], QMI_FLAG_REQUEST);
        assert_eq!(u16::from_le_bytes([req[1], req[2]]), 0x1234);
        assert_eq!(u16::from_le_bytes([req[3], req[4]]), 0x0020);
        let sdu = decode_sdu(&req).unwrap();
        assert_eq!(sdu.tx_id, 0x1234);
        assert_eq!(sdu.msg_id, 0x0020);
        assert_eq!(read_u8(&sdu.tlvs, 0x01), Some(4));
        assert_eq!(read_u32_le(&sdu.tlvs, 0x10), Some(0x0000_6B10));
        assert_eq!(find_tlv(&sdu.tlvs, 0x14), Some(b"internet".as_slice()));
    }

    #[test]
    fn result_tlv_ok_and_error() {
        let ok_tlvs = parse_tlvs(&make_result_ok_tlv()).unwrap();
        assert!(check_result_tlv(&ok_tlvs).is_ok());

        let err_tlvs = parse_tlvs(&make_result_err_tlv(0x000E)).unwrap();
        assert_eq!(
            check_result_tlv(&err_tlvs),
            Err(QmiError::Protocol { code: 0x000E })
        );
    }

    #[test]
    fn malformed_frames_never_panic() {
        assert!(matches!(decode_sdu(&[]), Err(QmiError::Malformed(_))));
        assert!(matches!(decode_sdu(&[0, 1, 2, 3, 4, 5]), Err(QmiError::Malformed(_))));
        // Header claims 10 bytes, only 2 present
        assert!(matches!(
            decode_sdu(&[2, 1, 0, 32, 0, 10, 0, 1, 1]),
            Err(QmiError::Malformed(_))
        ));
        // TLV claims 5 bytes, only 2 present
        assert!(matches!(
            decode_sdu(&[2, 1, 0, 32, 0, 5, 0, 0x02, 5, 0, 1, 2]),
            Err(QmiError::Malformed(_))
        ));
        // Truncated result TLV
        let short_res = vec![(TLV_RESULT, vec![1, 0])];
        assert!(matches!(check_result_tlv(&short_res), Err(QmiError::Malformed(_))));
    }
}

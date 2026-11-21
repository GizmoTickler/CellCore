use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmsMessage {
    pub indices: Vec<i32>,
    pub sender: String,
    pub timestamp: String,
    pub text: String,
    pub reference: Option<String>,
    pub total_parts: u8,
    pub received_parts: u8,
    pub raw_pdu: String,
}

#[derive(Debug, Clone)]
struct DecodedSegment {
    index: i32,
    sender: String,
    timestamp: String,
    text: String,
    concat: Option<(u16, u8, u8)>, // (ref, total, seq)
    raw_pdu: String,
}

pub fn parse_cmgl_response(raw: &str) -> Vec<SmsMessage> {
    let mut segments = Vec::new();
    let lines: Vec<&str> = raw.lines().map(|l| l.trim()).collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(rest) = line.strip_prefix("+CMGL:") {
            let parts: Vec<&str> = rest.split(',').collect();
            let index = parts
                .first()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .unwrap_or(-1);
            let mut j = i + 1;
            while j < lines.len() && lines[j].is_empty() {
                j += 1;
            }
            if j < lines.len()
                && !lines[j].starts_with("+CMGL:")
                && lines[j].bytes().all(|b| b.is_ascii_hexdigit())
                && index >= 0
                && let Some(seg) = decode_deliver_pdu(index, lines[j])
            {
                segments.push(seg);
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    reassemble_segments(segments)
}

fn reassemble_segments(segments: Vec<DecodedSegment>) -> Vec<SmsMessage> {
    let mut grouped: BTreeMap<(String, u16), Vec<DecodedSegment>> = BTreeMap::new();
    let mut singles = Vec::new();

    for seg in segments {
        if let Some((ref_id, _, _)) = seg.concat {
            grouped
                .entry((seg.sender.clone(), ref_id))
                .or_default()
                .push(seg);
        } else {
            singles.push(SmsMessage {
                indices: vec![seg.index],
                sender: seg.sender,
                timestamp: seg.timestamp,
                text: seg.text,
                reference: None,
                total_parts: 1,
                received_parts: 1,
                raw_pdu: seg.raw_pdu,
            });
        }
    }

    for ((_, ref_id), mut parts) in grouped {
        parts.sort_by_key(|p| p.concat.map(|c| c.2).unwrap_or(0));
        let total_parts = parts.first().and_then(|p| p.concat.map(|c| c.1)).unwrap_or(1);
        let received_parts = parts.len() as u8;
        let indices: Vec<i32> = parts.iter().map(|p| p.index).collect();
        let text: String = parts.iter().map(|p| p.text.as_str()).collect();
        let first = &parts[0];
        singles.push(SmsMessage {
            indices,
            sender: first.sender.clone(),
            timestamp: first.timestamp.clone(),
            text,
            reference: Some(format!("{ref_id}")),
            total_parts,
            received_parts,
            raw_pdu: first.raw_pdu.clone(),
        });
    }

    singles.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    singles
}

fn decode_deliver_pdu(index: i32, hex_str: &str) -> Option<DecodedSegment> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let smsc_len = bytes[0] as usize;
    let mut pos = 1 + smsc_len;
    if pos >= bytes.len() {
        return None;
    }

    let first_octet = bytes[pos];
    pos += 1;
    let mti = first_octet & 0x03;
    let udhi = (first_octet & 0x40) != 0;

    // 0x00 = SMS-DELIVER, 0x01 = SMS-SUBMIT (ignore status reports gracefully)
    if mti == 0x01 {
        // SMS-SUBMIT stored
        pos += 1; // MR
    }

    if pos + 2 > bytes.len() {
        return None;
    }
    let addr_len_digits = bytes[pos] as usize;
    let addr_toa = bytes[pos + 1];
    pos += 2;
    let addr_octets = addr_len_digits.div_ceil(2);
    if pos + addr_octets > bytes.len() {
        return None;
    }
    let sender = decode_address(&bytes[pos..pos + addr_octets], addr_len_digits, addr_toa);
    pos += addr_octets;

    if pos + 2 > bytes.len() {
        return None;
    }
    let _pid = bytes[pos];
    let dcs = bytes[pos + 1];
    pos += 2;

    let timestamp = if mti == 0x00 {
        if pos + 7 > bytes.len() {
            return None;
        }
        let ts = decode_scts(&bytes[pos..pos + 7]);
        pos += 7;
        ts
    } else {
        let vpf = (first_octet >> 3) & 0x03;
        let vp_len = match vpf {
            2 => 1,
            1 | 3 => 7,
            _ => 0,
        };
        pos = pos.saturating_add(vp_len).min(bytes.len());
        "Sent".into()
    };

    if pos >= bytes.len() {
        return None;
    }
    let udl = bytes[pos] as usize;
    pos += 1;
    let ud = bytes.get(pos..)?;

    let coding = match (dcs >> 2) & 0x03 {
        0 => Coding::Gsm7,
        2 => Coding::Ucs2,
        _ => {
            if (dcs & 0xF0) == 0x00 {
                Coding::Gsm7
            } else if (dcs & 0x0C) == 0x08 {
                Coding::Ucs2
            } else {
                Coding::Octets
            }
        }
    };

    let mut udhl = 0usize;
    let mut concat = None;
    if udhi && !ud.is_empty() {
        udhl = 1 + (ud[0] as usize);
        if udhl <= ud.len() {
            concat = parse_concat_udh(&ud[1..udhl]);
        } else {
            udhl = 0;
        }
    }

    let text = match coding {
        Coding::Gsm7 => decode_gsm7_with_udhl(ud, udl, udhl),
        Coding::Ucs2 => {
            let body = ud.get(udhl..).unwrap_or(&[]);
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        Coding::Octets => String::from_utf8_lossy(ud.get(udhl..).unwrap_or(&[])).to_string(),
    };

    Some(DecodedSegment {
        index,
        sender,
        timestamp,
        text,
        concat,
        raw_pdu: hex_str.to_string(),
    })
}

enum Coding {
    Gsm7,
    Ucs2,
    Octets,
}

fn parse_concat_udh(udh: &[u8]) -> Option<(u16, u8, u8)> {
    let mut i = 0;
    while i + 2 <= udh.len() {
        let iei = udh[i];
        let ielen = udh[i + 1] as usize;
        let data = udh.get(i + 2..i + 2 + ielen)?;
        if iei == 0x00 && data.len() == 3 {
            return Some((data[0] as u16, data[1], data[2]));
        }
        if iei == 0x08 && data.len() == 4 {
            let ref16 = u16::from_be_bytes([data[0], data[1]]);
            return Some((ref16, data[2], data[3]));
        }
        i += 2 + ielen;
    }
    None
}

fn decode_bcd_digits(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        let lo = b & 0x0F;
        let hi = (b >> 4) & 0x0F;
        if lo < 10 {
            out.push((b'0' + lo) as char);
        }
        if hi < 10 {
            out.push((b'0' + hi) as char);
        }
    }
    out
}

fn decode_address(bytes: &[u8], digit_len: usize, toa: u8) -> String {
    let ton = (toa >> 4) & 0x07;
    if ton == 0x05 {
        // Alphanumeric sender encoded as packed GSM-7 septets
        let septets = (digit_len * 4) / 7;
        return decode_gsm7_with_udhl(bytes, septets, 0);
    }
    let mut digits = decode_bcd_digits(bytes);
    digits.truncate(digit_len);
    if ton == 0x01 && !digits.is_empty() {
        format!("+{digits}")
    } else {
        digits
    }
}

/// TP-SCTS: seven semi-octets (swapped BCD) YY MM DD hh mm ss TZ. Returns "YYYY-MM-DD hh:mm:ss",
/// or an empty string when any digit is not BCD (0xF filler, corrupt PDU) or a field is out of
/// range: an invalid stamp must read as "unknown", never as a made-up date like 20165-165-165.
fn decode_scts(bytes: &[u8]) -> String {
    let dec = |b: u8| -> Option<u8> {
        let (lo, hi) = (b & 0x0F, (b >> 4) & 0x0F);
        (lo < 10 && hi < 10).then_some(lo * 10 + hi)
    };
    let fields: Option<Vec<u8>> = bytes.iter().take(6).map(|&b| dec(b)).collect();
    let Some(f) = fields.filter(|f| f.len() == 6) else {
        return String::new();
    };
    let (yr, mo, day, hr, min, sec) = (f[0], f[1], f[2], f[3], f[4], f[5]);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) || hr > 23 || min > 59 || sec > 59 {
        return String::new();
    }
    format!("20{yr:02}-{mo:02}-{day:02} {hr:02}:{min:02}:{sec:02}")
}

const GSM7_BASIC: [char; 128] = [
    '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
    'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u{1B}', 'Æ', 'æ', 'ß', 'É',
    ' ', '!', '"', '#', '¤', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
    '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];

fn gsm7_ext_decode(code: u8) -> Option<char> {
    match code {
        0x0A => Some('\u{000C}'),
        0x14 => Some('^'),
        0x28 => Some('{'),
        0x29 => Some('}'),
        0x2F => Some('\\'),
        0x3C => Some('['),
        0x3D => Some('~'),
        0x3E => Some(']'),
        0x40 => Some('|'),
        0x65 => Some('€'),
        _ => None,
    }
}

fn gsm7_encode_char(ch: char) -> Option<(Option<u8>, u8)> {
    if let Some(pos) = GSM7_BASIC.iter().position(|&c| c == ch && c != '\u{1B}') {
        return Some((None, pos as u8));
    }
    let ext = match ch {
        '^' => 0x14,
        '{' => 0x28,
        '}' => 0x29,
        '\\' => 0x2F,
        '[' => 0x3C,
        '~' => 0x3D,
        ']' => 0x3E,
        '|' => 0x40,
        '€' => 0x65,
        _ => return None,
    };
    Some((Some(0x1B), ext))
}

fn decode_gsm7_with_udhl(ud: &[u8], udl_septets: usize, udhl_bytes: usize) -> String {
    let skip_septets = (udhl_bytes * 8).div_ceil(7);
    let mut out = String::new();
    let mut esc = false;

    for s_idx in skip_septets..udl_septets {
        let bit_pos = s_idx * 7;
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        if byte_idx >= ud.len() {
            break;
        }
        let low = ud[byte_idx] >> bit_off;
        let high = if bit_off > 1 && byte_idx + 1 < ud.len() {
            ud[byte_idx + 1] << (8 - bit_off)
        } else {
            0
        };
        let septet = (low | high) & 0x7F;
        if esc {
            esc = false;
            out.push(gsm7_ext_decode(septet).unwrap_or(' '));
        } else if septet == 0x1B {
            esc = true;
        } else {
            out.push(GSM7_BASIC[septet as usize]);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct EncodedSmsPdu {
    pub tpdu_len: usize,
    pub hex_pdu: String,
}

pub fn validate_phone_number(phone: &str) -> Result<String, String> {
    let clean: String = phone.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || clean.len() > 20 {
        return Err("Invalid phone number length".into());
    }
    let rest = clean.strip_prefix('+').unwrap_or(&clean);
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Phone number must contain only digits and optional leading +".into());
    }
    Ok(clean)
}

pub fn encode_submit_pdus(phone: &str, message: &str, concat_ref: u8) -> Result<Vec<EncodedSmsPdu>, String> {
    let valid_phone = validate_phone_number(phone)?;
    if message.is_empty() {
        return Err("Message body cannot be empty".into());
    }
    let (da_bytes, da_len, da_toa) = encode_phone_address(&valid_phone);

    // Check whether full message fits GSM-7
    let mut septets = Vec::new();
    let mut is_gsm7 = true;
    for ch in message.chars() {
        if let Some((ext, code)) = gsm7_encode_char(ch) {
            if let Some(e) = ext {
                septets.push(e);
            }
            septets.push(code);
        } else {
            is_gsm7 = false;
            break;
        }
    }

    let mut pdus = Vec::new();
    if is_gsm7 {
        if septets.len() <= 160 {
            let packed = pack_gsm7(&septets, 0);
            pdus.push(build_tpdu(&da_bytes, da_len, da_toa, false, 0x00, septets.len() as u8, &packed));
        } else {
            let chunks: Vec<&[u8]> = septets.chunks(153).collect();
            let total = chunks.len();
            if total > 10 {
                return Err("Message exceeds maximum 10 segments".into());
            }
            for (idx, chunk) in chunks.into_iter().enumerate() {
                let udh = [0x05u8, 0x00, 0x03, concat_ref, total as u8, (idx + 1) as u8];
                // UDH is 6 bytes = 48 bits; pad 1 bit to reach 49 bits (7 septets)
                let packed_body = pack_gsm7(chunk, 1);
                let mut ud = Vec::with_capacity(udh.len() + packed_body.len());
                ud.extend_from_slice(&udh);
                ud.extend_from_slice(&packed_body);
                let udl = (7 + chunk.len()) as u8;
                pdus.push(build_tpdu(&da_bytes, da_len, da_toa, true, 0x00, udl, &ud));
            }
        }
    } else {
        let units: Vec<u16> = message.encode_utf16().collect();
        if units.len() <= 70 {
            let body: Vec<u8> = units.iter().flat_map(|u| u.to_be_bytes()).collect();
            pdus.push(build_tpdu(&da_bytes, da_len, da_toa, false, 0x08, body.len() as u8, &body));
        } else {
            let chunks: Vec<&[u16]> = units.chunks(67).collect();
            let total = chunks.len();
            if total > 10 {
                return Err("Message exceeds maximum 10 UCS-2 segments".into());
            }
            for (idx, chunk) in chunks.into_iter().enumerate() {
                let mut ud = vec![0x05u8, 0x00, 0x03, concat_ref, total as u8, (idx + 1) as u8];
                for &u in chunk {
                    ud.extend_from_slice(&u.to_be_bytes());
                }
                pdus.push(build_tpdu(&da_bytes, da_len, da_toa, true, 0x08, ud.len() as u8, &ud));
            }
        }
    }
    Ok(pdus)
}

fn encode_phone_address(phone: &str) -> (Vec<u8>, u8, u8) {
    let (toa, digits) = if let Some(rest) = phone.strip_prefix('+') {
        (0x91u8, rest)
    } else {
        (0x81u8, phone)
    };
    let len = digits.len() as u8;
    let b: Vec<u8> = digits.bytes().map(|c| c - b'0').collect();
    let mut octets = Vec::with_capacity(b.len().div_ceil(2));
    for pair in b.chunks(2) {
        let lo = pair[0];
        let hi = if pair.len() == 2 { pair[1] } else { 0x0F };
        octets.push((hi << 4) | lo);
    }
    (octets, len, toa)
}

fn pack_gsm7(septets: &[u8], initial_bit_offset: usize) -> Vec<u8> {
    let total_bits = initial_bit_offset + septets.len() * 7;
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    for (idx, &s) in septets.iter().enumerate() {
        let bit_pos = initial_bit_offset + idx * 7;
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        out[byte_idx] |= (s & 0x7F) << bit_off;
        if bit_off > 1 && byte_idx + 1 < out.len() {
            out[byte_idx + 1] |= (s & 0x7F) >> (8 - bit_off);
        }
    }
    out
}

fn build_tpdu(
    da_bytes: &[u8],
    da_len: u8,
    da_toa: u8,
    udhi: bool,
    dcs: u8,
    udl: u8,
    ud: &[u8],
) -> EncodedSmsPdu {
    let mut tpdu = Vec::with_capacity(8 + da_bytes.len() + ud.len());
    tpdu.push(if udhi { 0x41 } else { 0x01 }); // SMS-SUBMIT, no VPF
    tpdu.push(0x00); // MR
    tpdu.push(da_len);
    tpdu.push(da_toa);
    tpdu.extend_from_slice(da_bytes);
    tpdu.push(0x00); // PID
    tpdu.push(dcs);
    tpdu.push(udl);
    tpdu.extend_from_slice(ud);

    let tpdu_len = tpdu.len();
    let mut full = Vec::with_capacity(1 + tpdu_len);
    full.push(0x00); // use stored SMSC
    full.extend_from_slice(&tpdu);
    EncodedSmsPdu {
        tpdu_len,
        hex_pdu: hex::encode_upper(full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_gsm7_and_ucs2_roundtrip() {
        let single = encode_submit_pdus("+15551234567", "Hello 5G!", 1).unwrap();
        assert_eq!(single.len(), 1);
        let decoded = decode_deliver_pdu(0, &single[0].hex_pdu).unwrap();
        assert_eq!(decoded.sender, "+15551234567");
        assert_eq!(decoded.text, "Hello 5G!");

        let long_gsm: String = "A".repeat(180);
        let multi = encode_submit_pdus("5551234567", &long_gsm, 42).unwrap();
        assert_eq!(multi.len(), 2);
        let s1 = decode_deliver_pdu(1, &multi[0].hex_pdu).unwrap();
        let s2 = decode_deliver_pdu(2, &multi[1].hex_pdu).unwrap();
        let combined = reassemble_segments(vec![s1, s2]);
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].text, long_gsm);
        assert_eq!(combined[0].total_parts, 2);

        let ucs = encode_submit_pdus("+15551234567", "Signal OK 📶🚀", 7).unwrap();
        assert_eq!(ucs.len(), 1);
        let d_ucs = decode_deliver_pdu(3, &ucs[0].hex_pdu).unwrap();
        assert_eq!(d_ucs.text, "Signal OK 📶🚀");
    }

    #[test]
    fn scts_valid_decodes() {
        // 2026-11-18 12:21:42, TZ byte ignored
        assert_eq!(decode_scts(&[0x62, 0x11, 0x81, 0x21, 0x12, 0x24, 0x00]), "2026-11-18 12:21:42");
    }

    #[test]
    fn scts_non_bcd_is_unknown_not_a_bogus_date() {
        // All-0xFF SCTS used to render as "20165-165-165 165:165:165".
        assert_eq!(decode_scts(&[0xFF; 7]), "");
        // a single non-BCD nibble is enough to reject it
        assert_eq!(decode_scts(&[0x62, 0x11, 0x81, 0x2F, 0x12, 0x24, 0x00]), "");
    }

    #[test]
    fn scts_out_of_range_fields_are_unknown() {
        assert_eq!(decode_scts(&[0x62, 0x31, 0x81, 0x21, 0x12, 0x24, 0x00]), ""); // month 13
        assert_eq!(decode_scts(&[0x62, 0x11, 0x00, 0x21, 0x12, 0x24, 0x00]), ""); // day 0
        assert_eq!(decode_scts(&[0x62, 0x11, 0x81, 0x42, 0x12, 0x24, 0x00]), ""); // hour 24
        assert_eq!(decode_scts(&[0x62, 0x11, 0x81, 0x21, 0x06, 0x24, 0x00]), ""); // minute 60
    }

    #[test]
    fn sms_message_json_shape_is_the_ui_contract() {
        // The UI reads exactly these keys (src/types/cellcore.ts SmsMessage).
        let m = SmsMessage {
            indices: vec![3, 4],
            sender: "+15555550100".into(),
            timestamp: String::new(),
            text: "hi".into(),
            reference: None,
            total_parts: 2,
            received_parts: 2,
            raw_pdu: String::new(),
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["indices", "rawPdu", "receivedParts", "reference", "sender", "text", "timestamp", "totalParts"]);
    }
}

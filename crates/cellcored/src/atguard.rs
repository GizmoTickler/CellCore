//! Classifier for the web AT console (`POST /api/v1/modem/at`).
//!
//! Every command line is split into its individual commands (`;` outside
//! quotes, basic commands such as `E0`/`&F` concatenated after `AT`) and each
//! one is classified:
//!
//! * `read`      – queries (`?`), tests (`=?`), `ATI`, and a list of known
//!   read-only executes / query-style writes;
//! * `caution`   – long-running or session-affecting but recoverable
//!   (`QSCAN`, `QENG`, `COPS=?`, SMS/URC settings);
//! * `dangerous` – anything that can cut the backup WAN off or change modem
//!   identity/firmware/USB/SIM state, **and every write or execute this file
//!   does not know** (fail closed).
//!
//! The line's class is the worst of its parts. The IPC `QuectelAt` path
//! (root-only socket) does not go through here.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AtClass {
    Read,
    Caution,
    Dangerous,
    Blocked,
}

impl AtClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AtClass::Read => "read",
            AtClass::Caution => "caution",
            AtClass::Dangerous => "dangerous",
            AtClass::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AtPart {
    /// The command as it was parsed (e.g. `+QNWPREFCFG="lte_band",3:7`).
    pub text: String,
    /// Upper-cased command name with its prefix (`+CFUN`, `&F`, `I`).
    pub name: String,
    pub class: AtClass,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AtVerdict {
    pub class: AtClass,
    pub parts: Vec<AtPart>,
    /// Reason of the worst part (what the UI shows inline).
    pub reason: String,
}

pub const MAX_AT_LEN: usize = 1024;

/// Read-only executes (`AT+NAME` without arguments).
const READ_EXEC: &[&str] = &[
    "CSQ", "QRSRP", "QRSRQ", "QSINR", "QNWINFO", "QSPN", "CGSN", "GSN", "CIMI", "CCID", "QCCID", "CNUM", "QTEMP", "QGMR", "GMR",
    "CGMR", "GMI", "CGMI", "GMM", "CGMM", "QCAINFO", "CGCONTRDP", "CGPADDR", "CEER", "CLCC", "QCSQ", "QGDCNT", "QGDNRCNT",
    "QNWINFO", "CPAS", "CLAC", "QLTS",
];

/// Write-form commands that only query (`AT+CMGR=3`, `AT+CGPADDR=1`).
const READ_SET: &[&str] = &["CMGL", "CMGR", "CGPADDR", "CGCONTRDP", "QLTS", "CEER", "QCSQ"];

/// Long-running or session-affecting, but nothing that needs a confirmation
/// (except long-blocking scans checked via [`is_long_blocking_scan`]).
const CAUTION_SET: &[&str] = &[
    "QSCAN", "QENG", "CMGF", "CSCS", "CMEE", "CREG", "CEREG", "CGREG", "C5GREG", "CNMI", "CPMS", "CMGD", "CSMS", "QINDCFG",
];
const CAUTION_EXEC: &[&str] = &["QSCAN"];

/// Commands that are always blocked in the raw web AT console (exec or write form).
const BLOCKED: &[(&str, &str)] = &[
    ("QPRTPARA", "restoring or overwriting factory parameters is blocked in the AT console"),
    ("QFOTADL", "modem firmware download is blocked in the AT console"),
    ("CMGS", "interactive SMS prompt mode (+CMGS) is blocked in the AT console; use the SMS API"),
    ("CMGW", "interactive SMS prompt mode (+CMGW) is blocked in the AT console; use the SMS API"),
];

fn blocked_reason(name: &str) -> Option<&'static str> {
    BLOCKED.iter().find(|(n, _)| *n == name).map(|(_, r)| *r)
}

/// `AT+NAME="key"` (one argument) reads, `AT+NAME="key",value` writes.
const KEYED_CONFIG: &[&str] = &["QNWPREFCFG", "QNWLOCK", "QCFG", "QNWCFG", "QMAP", "QMBNCFG", "QINDCFG"];

/// Commands that are dangerous in every non-query form, with the reason shown to the user.
const DANGER: &[(&str, &str)] = &[
    ("EGMR", "writes the IMEI"),
    ("CFUN", "changes radio power or resets the modem"),
    ("QPOWD", "powers the modem off"),
    ("CPOF", "powers the modem off"),
    ("CPWROFF", "powers the modem off"),
    ("QRST", "resets the modem"),
    ("CRESET", "resets the modem"),
    ("RESET", "resets the modem"),
    ("QPRTPARA", "restores or overwrites factory parameters"),
    ("QUIMSLOT", "switches the active SIM slot"),
    ("CGDCONT", "rewrites PDP contexts / APNs"),
    ("CGATT", "attaches or detaches from the packet network"),
    ("CGACT", "activates or deactivates the data bearer"),
    ("COPS", "changes network registration"),
    ("CLCK", "changes SIM / facility locks"),
    ("CPIN", "enters a SIM PIN (wrong PINs lock the SIM)"),
    ("CPWD", "changes a SIM password"),
    ("QFOTADL", "downloads modem firmware"),
    ("QFASTBOOT", "reboots into fastboot"),
    ("QSIMDET", "changes SIM hot-plug detection"),
    ("QSIMSTAT", "changes SIM status reporting"),
];

fn danger_reason(name: &str) -> Option<&'static str> {
    DANGER.iter().find(|(n, _)| *n == name).map(|(_, r)| *r)
}

/// `QCFG` keys whose writes are called out explicitly (all QCFG writes are
/// dangerous anyway; this only sharpens the message).
fn qcfg_reason(key: &str) -> &'static str {
    match key {
        "usbnet" | "usbcfg" | "usbspeed" => "changes the USB network mode (can drop the data link to the host)",
        k if k.starts_with("pcie") => "changes the PCIe mode",
        "data_interface" => "changes the data interface",
        k if k.starts_with("sim") => "changes SIM configuration",
        "ims" => "changes IMS (voice) configuration",
        "nat" | "ippass" => "changes NAT / IP passthrough",
        _ => "writes modem configuration (unknown QCFG key: fail closed)",
    }
}

enum Form {
    Exec,
    Read,
    Test,
    Set(Vec<String>),
}

/// Remove whitespace outside quotes (the modem ignores it there).
fn squash_unquoted_ws(s: &str) -> Result<String, ()> {
    let mut out = String::with_capacity(s.len());
    let mut in_q = false;
    for c in s.chars() {
        if c == '"' {
            in_q = !in_q;
            out.push(c);
        } else if in_q || !c.is_whitespace() {
            out.push(c);
        }
    }
    if in_q { Err(()) } else { Ok(out) }
}

/// Split on `sep` outside double quotes.
fn split_unquoted(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        if c == '"' {
            in_q = !in_q;
            cur.push(c);
        } else if c == sep && !in_q {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

fn unquote_lower(arg: &str) -> String {
    let a = arg.trim();
    let a = a.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(a);
    a.to_ascii_lowercase()
}

fn strip_at_prefix(s: &str) -> &str {
    if s.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("AT")) {
        s.get(2..).unwrap_or(s)
    } else {
        s
    }
}

fn is_ext_prefix(c: char) -> bool {
    matches!(c, '+' | '$' | '^' | '%' | '*' | '#')
}

fn part(text: &str, name: String, class: AtClass, reason: impl Into<String>) -> AtPart {
    AtPart {
        text: text.to_string(),
        name,
        class,
        reason: reason.into(),
    }
}

fn classify_extended(seg: &str) -> AtPart {
    let mut chars = seg.chars();
    let prefix = chars.next().unwrap_or('+');
    let rest: String = chars.collect();
    let name_len = rest.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'_').count();
    let name = rest.get(..name_len).unwrap_or("").to_ascii_uppercase();
    let full_name = format!("{prefix}{name}");
    if name.is_empty() {
        return part(seg, full_name, AtClass::Dangerous, "unrecognised command syntax");
    }
    let tail = rest.get(name_len..).unwrap_or("");
    let form = if tail.is_empty() {
        Form::Exec
    } else if tail == "?" {
        Form::Read
    } else if tail == "=?" {
        Form::Test
    } else if let Some(args) = tail.strip_prefix('=') {
        Form::Set(split_unquoted(args, ',').iter().map(|a| a.trim().to_string()).collect())
    } else {
        return part(seg, full_name, AtClass::Dangerous, "unrecognised command syntax");
    };

    // Only standard (+) commands are known; vendor prefixes fail closed unless they are queries.
    let known = prefix == '+';
    match form {
        Form::Read => part(seg, full_name, AtClass::Read, "query"),
        Form::Test if known && name == "COPS" => {
            part(seg, full_name, AtClass::Caution, "scans for networks; can take minutes and pauses data")
        }
        Form::Test => part(seg, full_name, AtClass::Read, "test (lists supported values)"),
        Form::Exec => {
            if known && name == "EGMR" {
                part(
                    seg,
                    full_name,
                    AtClass::Blocked,
                    "IMEI changes are blocked in the AT console; use /api/v1/modem/imei",
                )
            } else if known && let Some(r) = blocked_reason(&name) {
                part(seg, full_name, AtClass::Blocked, r)
            } else if known && let Some(r) = danger_reason(&name) {
                part(seg, full_name, AtClass::Dangerous, r)
            } else if known && READ_EXEC.contains(&name.as_str()) {
                part(seg, full_name, AtClass::Read, "read-only")
            } else if known && CAUTION_EXEC.contains(&name.as_str()) {
                part(seg, full_name, AtClass::Caution, "long-running scan")
            } else {
                part(seg, full_name, AtClass::Dangerous, "unknown action command (fail closed)")
            }
        }
        Form::Set(args) => {
            if !known {
                return part(seg, full_name, AtClass::Dangerous, "vendor write command (fail closed)");
            }
            let first = args.first().map(|a| unquote_lower(a)).unwrap_or_default();
            let n = args.len();
            if name == "EGMR" {
                return if first == "0" {
                    part(seg, full_name, AtClass::Read, "reads a stored identity")
                } else {
                    part(
                        seg,
                        full_name,
                        AtClass::Blocked,
                        "IMEI changes are blocked in the AT console; use /api/v1/modem/imei",
                    )
                };
            }
            if let Some(r) = blocked_reason(&name) {
                return part(seg, full_name, AtClass::Blocked, r);
            }
            if let Some(r) = danger_reason(&name) {
                return part(seg, full_name, AtClass::Dangerous, r);
            }
            if KEYED_CONFIG.contains(&name.as_str()) {
                if name == "QMBNCFG" {
                    return match (first.as_str(), n) {
                        ("list", 1) | ("autosel", 1) | ("select", 1) => part(seg, full_name, AtClass::Read, "query"),
                        ("autosel", _) => part(seg, full_name, AtClass::Dangerous, "changes automatic carrier-firmware (MBN) selection"),
                        ("select", _) => part(seg, full_name, AtClass::Dangerous, "selects a carrier firmware (MBN) profile"),
                        ("deactivate", _) => part(seg, full_name, AtClass::Dangerous, "deactivates the carrier firmware (MBN)"),
                        _ => part(seg, full_name, AtClass::Dangerous, "changes carrier firmware (MBN) state (fail closed)"),
                    };
                }
                if n <= 1 {
                    return part(seg, full_name, AtClass::Read, "query");
                }
                return match name.as_str() {
                    "QNWPREFCFG" => part(seg, full_name, AtClass::Dangerous, "changes band / network-mode preferences"),
                    "QNWLOCK" => part(seg, full_name, AtClass::Dangerous, "locks or unlocks cells"),
                    "QCFG" => part(seg, full_name, AtClass::Dangerous, qcfg_reason(&first)),
                    "QMAP" => part(seg, full_name, AtClass::Dangerous, "changes LAN / passthrough mapping"),
                    "QINDCFG" => part(seg, full_name, AtClass::Caution, "changes unsolicited result reporting"),
                    _ => part(seg, full_name, AtClass::Dangerous, "writes modem configuration (fail closed)"),
                };
            }
            if READ_SET.contains(&name.as_str()) {
                return part(seg, full_name, AtClass::Read, "read-only");
            }
            if CAUTION_SET.contains(&name.as_str()) {
                let why = match name.as_str() {
                    "QSCAN" => "long-running cell scan",
                    "QENG" => "engineering query; some modes are slow",
                    "CMGD" => "deletes SMS",
                    _ => "changes session/reporting settings",
                };
                return part(seg, full_name, AtClass::Caution, why);
            }
            part(seg, full_name, AtClass::Dangerous, "unknown write command (fail closed)")
        }
    }
}

/// Basic (V.250) commands concatenated in one segment, e.g. `E0V1`, `I`, `&F`.
fn classify_basic(seg: &str, out: &mut Vec<AtPart>) {
    let b = seg.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let (name, class, reason): (String, AtClass, &str);
        if b[i] == b'&' {
            match seg.get(i + 1..).and_then(|s| s.chars().next()) {
                Some(ch) if ch.is_ascii() => {
                    let letter = (ch as u8).to_ascii_uppercase();
                    i += 2;
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    name = format!("&{}", letter as char);
                    (class, reason) = match letter {
                        b'V' => (AtClass::Read, "shows the active profile"),
                        b'F' => (AtClass::Blocked, "factory reset (&F) is blocked in the AT console"),
                        b'W' => (AtClass::Dangerous, "stores the active profile"),
                        _ => (AtClass::Dangerous, "unknown basic command (fail closed)"),
                    };
                }
                Some(ch) => {
                    i += 1 + ch.len_utf8();
                    name = "&?".into();
                    (class, reason) = (AtClass::Dangerous, "non-ASCII basic command (fail closed)");
                }
                None => {
                    i = b.len();
                    name = "&?".into();
                    (class, reason) = (AtClass::Dangerous, "unknown basic command (fail closed)");
                }
            }
        } else if !b[i].is_ascii() {
            let step = seg.get(i..).and_then(|s| s.chars().next()).map_or(1, char::len_utf8);
            i = (i + step).min(b.len());
            name = "?".into();
            (class, reason) = (AtClass::Dangerous, "non-ASCII basic command (fail closed)");
        } else {
            let letter = b[i].to_ascii_uppercase();
            i += 1;
            name = (letter as char).to_string();
            match letter {
                b'I' => {
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    (class, reason) = (AtClass::Read, "identification");
                }
                b'S' => {
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    if b.get(i) == Some(&b'?') {
                        i += 1;
                        (class, reason) = (AtClass::Read, "reads an S-register");
                    } else {
                        while i < b.len() && (b[i] == b'=' || b[i].is_ascii_digit()) {
                            i += 1;
                        }
                        (class, reason) = (AtClass::Dangerous, "writes an S-register");
                    }
                }
                b'D' => {
                    // ATD consumes the rest of the line as a dial string.
                    i = b.len();
                    (class, reason) = (AtClass::Dangerous, "dials");
                }
                b'Z' => {
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    (class, reason) = (AtClass::Dangerous, "resets the modem configuration");
                }
                _ => {
                    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'=' || b[i] == b'?') {
                        i += 1;
                    }
                    (class, reason) = (
                        AtClass::Dangerous,
                        if matches!(letter, b'E' | b'V' | b'Q') {
                            "changes the console format the daemon depends on"
                        } else {
                            "unknown basic command (fail closed)"
                        },
                    );
                }
            }
        }
        let slice = seg.get(start..i.min(seg.len())).unwrap_or("");
        out.push(part(slice, name, class, reason));
    }
}

/// Parse the portion of an `AT...` command line after the leading `AT` into
/// its classified parts (without `MAX_AT_LEN`). Returns `Err(())` on an
/// unterminated quote.
pub(crate) fn parse_at_parts(line_after_at: &str) -> Result<Vec<AtPart>, ()> {
    let mut parts = Vec::new();
    let body = squash_unquoted_ws(line_after_at)?;
    if body.is_empty() {
        return Ok(parts);
    }
    for (idx, raw) in split_unquoted(&body, ';').into_iter().enumerate() {
        let seg = if idx == 0 { raw.as_str() } else { strip_at_prefix(&raw) };
        if seg.is_empty() {
            continue;
        }
        // Leading basic commands, then (optionally) one extended command.
        let ext_at = {
            let mut in_q = false;
            seg.char_indices().find_map(|(i, c)| {
                if c == '"' {
                    in_q = !in_q;
                }
                (!in_q && is_ext_prefix(c)).then_some(i)
            })
        };
        // ATD dials and swallows the rest of the segment (`ATD+1555...;`):
        // a dial before the first extended prefix makes the whole segment basic.
        let dial_at = {
            let b = seg.as_bytes();
            (0..b.len()).find(|&i| b[i].eq_ignore_ascii_case(&b'D') && (i == 0 || b[i - 1] != b'&'))
        };
        let ext_at = match (ext_at, dial_at) {
            (Some(e), Some(d)) if d < e => None,
            (e, _) => e,
        };
        let (basic, ext) = match ext_at {
            Some(i) => (&seg[..i], Some(&seg[i..])),
            None => (seg, None),
        };
        if !basic.is_empty() {
            if basic.contains('"') {
                parts.push(part(basic, "?".into(), AtClass::Dangerous, "unrecognised command syntax"));
            } else {
                classify_basic(basic, &mut parts);
            }
        }
        if let Some(e) = ext {
            parts.push(classify_extended(e));
        }
    }
    Ok(parts)
}

/// True if any part is a long-blocking RF scan (`AT+COPS=?` or `AT+QSCAN`),
/// which requires explicit confirmation and bounded timeout handling in the AT console.
pub fn is_long_blocking_scan(v: &AtVerdict) -> bool {
    v.parts.iter().any(|p| {
        (p.name == "+COPS" && p.text.ends_with("=?"))
            || (p.name == "+QSCAN" && p.class == AtClass::Caution)
    })
}

/// True if any line in `input` contains a dangerous/blocked AT command (or
/// malformed / non-ASCII / unquoted input that fails closed). Used by the raw
/// AT / IPC paths to decide when the radio lock and cached-mode invalidation apply.
pub fn has_dangerous_part(input: &str) -> bool {
    if !input.is_ascii() {
        return true;
    }
    for raw in input.split(['\r', '\n']) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !line.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("AT")) {
            return true;
        }
        match parse_at_parts(line.get(2..).unwrap_or("")) {
            Ok(parts) if parts.iter().any(|p| p.class >= AtClass::Dangerous) => return true,
            Ok(_) => {}
            Err(()) => return true,
        }
    }
    false
}

/// Classify one console line. `Err` for input that is refused outright
/// (empty, too long, control characters, not starting with `AT`).
pub fn classify(input: &str) -> Result<AtVerdict, String> {
    let line = input.trim();
    if line.is_empty() {
        return Err("Empty AT command".into());
    }
    if line.len() > MAX_AT_LEN {
        return Err(format!("AT command longer than {MAX_AT_LEN} characters"));
    }
    if line.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return Err("AT command contains control or non-ASCII characters".into());
    }
    if !line.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("AT")) {
        return Err("AT command must start with AT".into());
    }
    let Ok(parts) = parse_at_parts(&line[2..]) else {
        return Ok(single(line, AtClass::Dangerous, "unterminated quote (fail closed)"));
    };
    if parts.is_empty() {
        return Ok(single(line, AtClass::Read, "attention / link check"));
    }
    let worst = parts.iter().max_by_key(|p| p.class).map(|p| (p.class, p.reason.clone()));
    let (class, reason) = worst.unwrap_or((AtClass::Dangerous, "unparsed".into()));
    Ok(AtVerdict { class, parts, reason })
}

/// Commands whose arguments carry credentials or identities (PINs, IMEI,
/// APN user/password, SMS recipients/content): never logged.
const SENSITIVE_ARGS: &[&str] = &[
    "+CPIN", "+CPIN2", "+CLCK", "+CPWD", "+CPUK", "+EGMR", "+CGAUTH", "+QICSGP", "+CMGS", "+CMGW", "+CSCA", "+CUSD", "+CNUM",
    "+QCCID", "+CCID", "+CIMI", "+CGSN", "+GSN", "+QFOTADL", "D",
];

/// Audit-safe description of a verdict: class plus each command's name and
/// form. Arguments are kept (bounded) only for standard commands that do not
/// carry credentials or identities; everything else shows `=<redacted>`.
pub fn audit_summary(v: &AtVerdict) -> String {
    let cmds: Vec<String> = v
        .parts
        .iter()
        .take(8)
        .map(|p| {
            let tail = p.text.get(p.name.len()..).unwrap_or("");
            let standard = p.name.starts_with('+') && !SENSITIVE_ARGS.contains(&p.name.as_str());
            // a "name" that is not a word (e.g. digits after a dial) is data, not a command
            let named = p.name.chars().nth(1).is_some_and(|c| c.is_ascii_alphabetic()) || p.name.len() == 1;
            if !named {
                return "<redacted>".to_string();
            }
            let bare = tail.is_empty() || tail == "?" || tail == "=?";
            let form = if bare || (standard && tail.starts_with('=') && tail.len() <= 48) {
                tail.to_string()
            } else {
                "=<redacted>".to_string()
            };
            format!("{}{form}", p.name)
        })
        .collect();
    format!("at_class={} at_cmds={}", v.class.as_str(), cmds.join(";"))
}

fn single(text: &str, class: AtClass, reason: &str) -> AtVerdict {
    AtVerdict {
        class,
        parts: vec![part(text, "AT".into(), class, reason)],
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> AtClass {
        classify(s).unwrap_or_else(|e| panic!("{s}: {e}")).class
    }

    #[test]
    fn queries_and_tests_are_read_only() {
        for s in [
            "AT",
            "at",
            "ATI",
            "ati0",
            "AT&V",
            "ATS0?",
            "AT+CFUN?",
            "AT+CFUN=?",
            "AT+QCFG=?",
            "AT+CGDCONT?",
            "AT+QUIMSLOT?",
            "AT+QNWLOCK=\"common/4g\"",
            "AT+QNWLOCK=\"save_ctrl\"",
            "AT+QNWPREFCFG=\"lte_band\"",
            "AT+QNWPREFCFG=\"mode_pref\"",
            "AT+QCFG=\"usbnet\"",
            "AT+QCFG=\"pcie/mode\"",
            "AT+QMBNCFG=\"List\"",
            "AT+QMBNCFG=\"AutoSel\"",
            "AT+QNWCFG=\"nr5g_time_advance\"",
            "AT+QMAP=\"WWAN\"",
            "AT+QCAINFO",
            "AT+QGMR",
            "AT+CGMI;+CGMM",
            "AT+QRSRP;+QSINR",
            "AT+CGCONTRDP",
            "AT+EGMR=0,7",
            "AT+CMGL=\"ALL\"",
            "AT$QCRMCALL?",
        ] {
            assert_eq!(c(s), AtClass::Read, "{s}");
        }
    }

    #[test]
    fn caution_commands() {
        for s in ["AT+QSCAN=3,1", "AT+QENG=\"servingcell\"", "AT+QENG=\"neighbourcell\"", "AT+COPS=?", "AT+CMGF=0", "AT+CMGD=3"] {
            assert_eq!(c(s), AtClass::Caution, "{s}");
        }
    }

    #[test]
    fn dangerous_commands() {
        for s in [
            "AT+CFUN=0",
            "AT+CFUN=1",
            "AT+CFUN=4",
            "AT+CFUN=1,1",
            "AT+QCFG=\"usbnet\",1",
            "AT+QCFG=\"pcie/mode\",1",
            "AT+QCFG=\"data_interface\",1,0",
            "AT+QCFG=\"sim/onchip\",1",
            "AT+QCFG=\"whatever\",1",
            "AT+QMBNCFG=\"Deactivate\"",
            "AT+QMBNCFG=\"Deactivate\",\"ROW_Commercial\"",
            "AT+QMBNCFG=\"Select\",\"ROW_Commercial\"",
            "AT+QMBNCFG=\"AutoSel\",0",
            "AT+QNWPREFCFG=\"lte_band\",1:3:7",
            "AT+QNWPREFCFG=\"mode_pref\",NR5G",
            "AT+QNWLOCK=\"common/4g\",1,66786,123",
            "AT+QNWLOCK=\"common/5g\",0",
            "AT+QUIMSLOT=2",
            "AT+CGDCONT=1,\"IPV4V6\",\"fast.t-mobile.com\"",
            "AT+QPOWD",
            "AT+QPOWD=1",
            "AT+CPOF",
            "AT+CRESET",
            "ATZ",
            "ATE0",
            "ATD*99#",
            "AT+CGATT=0",
            "AT+COPS=2",
            "AT+CPIN=\"1234\"",
        ] {
            assert_eq!(c(s), AtClass::Dangerous, "{s}");
        }
    }

    #[test]
    fn blocked_commands_cannot_run_in_console() {
        for s in [
            "AT+EGMR=1,7,\"356938035643809\"",
            "at+egmr=1,7,\"356938035643809\"",
            "AT+EGMR=2,7,\"356938035643809\"",
            "AT+EGMR",
            "AT+QPRTPARA",
            "AT+QPRTPARA=1",
            "AT+QPRTPARA=3",
            "AT+QFOTADL",
            "AT+QFOTADL=\"http://x/y.zip\"",
            "AT&F",
            "AT&F0",
            "ATI;&F",
            "AT+CMGS=20",
            "AT+CMGS=\"+15551234567\"",
            "AT+CMGS",
            "AT+CMGW=20",
            "AT+CMGW",
            "AT+CSQ;+CMGS=10",
            "AT+CSQ;+EGMR=1,7,\"356938035643809\"",
        ] {
            assert_eq!(c(s), AtClass::Blocked, "{s}");
        }
        // Reading IMEI via EGMR=0,7 remains read-only.
        assert_eq!(c("AT+EGMR=0,7"), AtClass::Read);
    }

    #[test]
    fn long_blocking_scans_are_detected() {
        for s in ["AT+COPS=?", "AT+QSCAN=3,1", "AT+QSCAN", "AT+CSQ;+COPS=?"] {
            let v = classify(s).unwrap();
            assert!(is_long_blocking_scan(&v), "expected long-blocking scan for {s}");
        }
        for s in ["AT+CSQ", "AT+COPS?", "AT+QENG=\"servingcell\"", "AT+CFUN?"] {
            let v = classify(s).unwrap();
            assert!(!is_long_blocking_scan(&v), "unexpected scan flag for {s}");
        }
    }

    #[test]
    fn non_ascii_utf8_never_panics_in_classify_or_has_dangerous_part() {
        for s in [
            "ATé",
            "AT&é",
            "AT€",
            "AT+QÉ",
            "AT+CSQ;é",
            "AT&€0",
            "AT+EGMR=1,7,\"é\"",
            "éAT+CSQ",
            "AT\u{1F680}",
            "AT&\u{1F680}",
        ] {
            assert!(classify(s).is_err(), "classify must reject {s:?}");
            assert!(has_dangerous_part(s), "has_dangerous_part must fail closed on {s:?}");
            // Direct parse_at_parts fuzzing must also never panic on multi-byte UTF-8.
            let _ = parse_at_parts(s);
        }
    }

    #[test]
    fn unknown_writes_and_actions_fail_closed() {
        for s in ["AT+QNEWCMD=1", "AT+QNEWCMD", "AT$QCPWD=1", "AT^RESET", "AT%X=1", "ATX", "AT+QCFG\"usbnet\""] {
            assert_eq!(c(s), AtClass::Dangerous, "{s}");
        }
        // unknown *queries* are fine
        assert_eq!(c("AT+QNEWCMD?"), AtClass::Read);
        assert_eq!(c("AT+QNEWCMD=?"), AtClass::Read);
    }

    #[test]
    fn casing_and_whitespace_do_not_bypass() {
        for s in [
            "at+cfun=0",
            "At+CfUn=0",
            "  AT + CFUN = 0  ",
            "AT+CFUN =0",
            "AT+qcfg=\"USBNET\",1",
            "AT+QCFG = \"usbnet\" , 1",
            "AT+QNWPREFCFG= \"lte_band\" ,3",
        ] {
            assert_eq!(c(s), AtClass::Dangerous, "{s}");
        }
        assert_eq!(c("at+egmr=1,7,\"356938035643809\""), AtClass::Blocked);
        assert_eq!(c("  at+cfun?  "), AtClass::Read);
        assert_eq!(c("AT+QNWLOCK = \"common/4g\""), AtClass::Read);
    }

    #[test]
    fn chained_commands_take_the_worst_class() {
        assert_eq!(c("AT+CSQ;+CFUN=0"), AtClass::Dangerous);
        assert_eq!(c("AT+CSQ;AT+CFUN=0"), AtClass::Dangerous);
        assert_eq!(c("AT+CSQ; +CFUN=0"), AtClass::Dangerous);
        assert_eq!(c("AT+CSQ;;+QSCAN=3,1"), AtClass::Caution);
        assert_eq!(c("AT+CSQ;"), AtClass::Read);
        assert_eq!(c("ATI;&F"), AtClass::Blocked);
        assert_eq!(c("ATE0+CSQ"), AtClass::Dangerous);
        let d = classify("ATD+15551234567;").unwrap();
        assert_eq!((d.class, d.parts.len()), (AtClass::Dangerous, 1));
        assert_eq!(c("ATI+CSQ"), AtClass::Read);
        let v = classify("AT+CSQ;+QSCAN=3,1;+CFUN=4").unwrap();
        assert_eq!(v.parts.len(), 3);
        assert_eq!(v.parts.iter().map(|p| p.class).collect::<Vec<_>>(), vec![AtClass::Read, AtClass::Caution, AtClass::Dangerous]);
        assert!(v.reason.contains("radio"));
    }

    #[test]
    fn quoted_arguments_cannot_smuggle_separators() {
        // `;` inside quotes is an argument, not a new command
        assert_eq!(c("AT+QNWLOCK=\"common/4g;+CFUN=0\""), AtClass::Read);
        let v = classify("AT+CMGL=\"ALL;+CFUN=0\"").unwrap();
        assert_eq!(v.parts.len(), 1);
        // but a quoted first arg plus a value is still a write
        assert_eq!(c("AT+QCFG=\"usbnet,x\",1"), AtClass::Dangerous);
        // an unterminated quote is refused as dangerous
        assert_eq!(c("AT+QNWLOCK=\"common/4g"), AtClass::Dangerous);
        // keyed reads with a quoted comma are still one argument
        assert_eq!(c("AT+QCFG=\"a,b\""), AtClass::Read);
    }

    #[test]
    fn aliases_of_power_and_reset() {
        for s in ["AT+QPOWD", "AT+CPOF", "AT+CPWROFF", "AT+QRST=1,0", "AT+CRESET", "AT+RESET", "ATZ0", "AT&W"] {
            assert_eq!(c(s), AtClass::Dangerous, "{s}");
        }
    }

    #[test]
    fn audit_summary_hides_credentials_and_identities() {
        let s = audit_summary(&classify("AT+CPIN=\"1234\";+CSQ;+QNWPREFCFG=\"lte_band\",2:66").unwrap());
        assert_eq!(s, "at_class=dangerous at_cmds=+CPIN=<redacted>;+CSQ;+QNWPREFCFG=\"lte_band\",2:66");
        for cmd in [
            "AT+EGMR=1,7,\"356938035643809\"",
            "AT+CLCK=\"SC\",0,\"9876\"",
            "AT+CPWD=\"SC\",\"1111\",\"2222\"",
            "AT+QICSGP=1,1,\"apn\",\"user\",\"s3cretpw\",1",
            "AT$QCPWD=\"s3cretpw\"",
            "ATD+15551234567;",
        ] {
            let s = audit_summary(&classify(cmd).unwrap());
            for secret in ["356938035643809", "9876", "1111", "2222", "s3cretpw", "15551234567"] {
                assert!(!s.contains(secret), "{cmd} -> {s}");
            }
        }
        assert_eq!(audit_summary(&classify("AT+CFUN=0").unwrap()), "at_class=dangerous at_cmds=+CFUN=0");
    }

    #[test]
    fn refused_inputs() {
        for s in ["", "   ", "CFUN=0", "+CFUN=0", "AT+CFUN?\r\nAT+CFUN=0", "AT+CSQ\rAT+CFUN=0", "AT+CSQ\u{1a}", "AT+CSQ\0", "AT+QÉ"] {
            assert!(classify(s).is_err(), "{s:?}");
        }
        assert!(classify(&format!("AT{}", "+CSQ;".repeat(300))).is_err());
        // surrounding whitespace is trimmed, exactly as the AT queue does
        assert_eq!(c("AT+CSQ\r\n"), AtClass::Read);
    }

    #[test]
    fn has_dangerous_part_handles_spacing_quotes_and_multiline() {
        for s in [
            "AT+CFUN =0",
            "AT + QNWPREFCFG = \"lte_band\" , 2:66",
            "AT+QPRTPARA=1",
            "AT&F",
            "ATZ",
            "AT+QNWLOCK=\"common/4g",
            "AT+CSQ\r\nAT+CFUN=0",
            "AT+CSQ\rAT&F",
        ] {
            assert!(has_dangerous_part(s), "{s:?}");
        }
        for s in [
            "",
            "   \r\n  ",
            "AT",
            "ATI",
            "AT+CFUN?",
            "AT+QNWPREFCFG=\"lte_band\"",
            "AT+QNWLOCK=\"common/4g;+CFUN=0\"",
            "AT+QENG=\"servingcell\"",
        ] {
            assert!(!has_dangerous_part(s), "{s:?}");
        }
    }
}

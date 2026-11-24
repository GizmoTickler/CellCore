use std::{
    fs,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    auth::now_secs,
    parsers::parse_mbn_list,
    smd::Priority,
    state::AppState,
    uci::{ensure_uci_config_file, run_cmd, uci_add_section, uci_commit, uci_delete, uci_set, uci_show, uci_show_checked},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct QuecProfileItem {
    pub index: usize,
    pub name: String,
    pub iccid: String,
    #[serde(default)]
    pub imei: String,
    pub apn: String,
    pub pdp_type: String,
    pub lte_bands: String,
    pub sa_nr5g_bands: String,
    pub nsa_nr5g_bands: String,
    pub network_type: String,
    pub ttl: String,
    pub mobile_provider: String,
    pub mbn_profile: String,
    pub paused: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInput {
    pub name: String,
    pub iccid: String,
    #[serde(default)]
    pub imei: String,
    pub apn: String,
    #[serde(default = "def_pdp")]
    pub pdp_type: String,
    #[serde(default)]
    pub lte_bands: String,
    #[serde(default)]
    pub sa_nr5g_bands: String,
    #[serde(default)]
    pub nsa_nr5g_bands: String,
    #[serde(default = "def_net")]
    pub network_type: String,
    #[serde(default = "def_zero")]
    pub ttl: String,
    #[serde(default = "def_provider")]
    pub mobile_provider: String,
    #[serde(default)]
    pub mbn_profile: String,
}

fn def_pdp() -> String { "IPV4V6".into() }
fn def_net() -> String { "LTE:NR5G".into() }
fn def_zero() -> String { "0".into() }
fn def_provider() -> String { "Other".into() }

/// A value as `uci show` prints it: single-quoted, with each `'` inside
/// written as `'\''`.
pub fn uci_show_value(raw: &str) -> String {
    let t = raw.trim();
    match t.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
        Some(inner) => inner.replace("'\\''", "'"),
        None => t.to_string(),
    }
}

pub async fn list_profiles() -> Vec<QuecProfileItem> {
    list_profiles_noting().await.0
}

/// The stored profiles, with legacy values normalised (see
/// [`normalize_stored`]), and a warning for each value that was.
pub async fn list_profiles_noting() -> (Vec<QuecProfileItem>, Vec<String>) {
    let raw = uci_show("cellprofiles").await;
    let mut by_idx: std::collections::BTreeMap<usize, std::collections::HashMap<String, String>> =
        std::collections::BTreeMap::new();

    for line in raw.lines() {
        let Some(rest) = line.strip_prefix("cellprofiles.@profile[") else {
            continue;
        };
        let Some((idx_str, field_part)) = rest.split_once("].") else {
            continue;
        };
        let Ok(idx) = idx_str.parse::<usize>() else {
            continue;
        };
        let Some((k, v_raw)) = field_part.split_once('=') else {
            continue;
        };
        let val = uci_show_value(v_raw);
        by_idx.entry(idx).or_default().insert(k.to_string(), val);
    }

    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (index, mut map) in by_idx {
        let name = map.get("name").cloned().unwrap_or_default();
        let iccid = map.get("iccid").cloned().unwrap_or_default();
        let apn = map.get("apn").cloned().unwrap_or_default();
        if name.is_empty() || iccid.is_empty() || apn.is_empty() {
            continue;
        }
        for (key, label) in [("ttl", "TTL"), ("lte_bands", "LTE"), ("sa_nr5g_bands", "NR5G-SA"), ("nsa_nr5g_bands", "NR5G-NSA")] {
            if let Some(v) = map.get_mut(key) {
                let (clean, note) = if key == "ttl" { normalize_stored_ttl(v) } else { normalize_stored_bands(label, v) };
                if let Some(n) = note {
                    warnings.push(format!("profile {name:?}: {n}"));
                }
                *v = clean;
            }
        }
        out.push(QuecProfileItem {
            index,
            name,
            iccid,
            imei: map.get("imei").cloned().unwrap_or_default(),
            apn,
            pdp_type: map.get("pdp_type").cloned().unwrap_or_else(def_pdp),
            lte_bands: map.get("lte_bands").cloned().unwrap_or_default(),
            sa_nr5g_bands: map.get("sa_nr5g_bands").cloned().unwrap_or_default(),
            nsa_nr5g_bands: map.get("nsa_nr5g_bands").cloned().unwrap_or_default(),
            network_type: map.get("network_type").cloned().unwrap_or_else(def_net),
            ttl: map.get("ttl").cloned().unwrap_or_else(def_zero),
            mobile_provider: map.get("mobile_provider").cloned().unwrap_or_else(def_provider),
            mbn_profile: map.get("mbn_profile").cloned().unwrap_or_default(),
            paused: map.get("paused").cloned().unwrap_or_else(def_zero),
        });
    }
    (out, warnings)
}

/// A TTL as older releases could store it, with leading zeros ("064"): read
/// as the plain number (64). Anything else is returned as it is (and refused
/// by [`clean_profile_ttl`] if invalid). Returns the value and, if it was
/// changed, a warning.
pub fn normalize_stored_ttl(raw: &str) -> (String, Option<String>) {
    let t = raw.trim();
    if t.len() > 1 && t.len() <= 4 && t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()) {
        let n = t.trim_start_matches('0');
        let n = if n.is_empty() { "0" } else { n };
        return (n.to_string(), Some(format!("stored TTL {t:?} read as {n}")));
    }
    (t.to_string(), None)
}

/// A band list as older releases could store it: ',' separators and band
/// `0` entries (no band). The zeros are dropped and `,` is rewritten to `:`
/// (both with a warning). Other entries are kept as they are (and checked by
/// [`clean_profile_bands`]).
pub fn normalize_stored_bands(label: &str, raw: &str) -> (String, Option<String>) {
    let t = raw.trim();
    if t.is_empty() {
        return (String::new(), None);
    }
    let parts: Vec<&str> = t.split([':', ',']).map(str::trim).collect();
    let zero = |p: &&str| !p.is_empty() && p.bytes().all(|b| b == b'0');
    let kept: Vec<&str> = parts.iter().copied().filter(|p| !zero(p)).collect();
    let dropped_zero = kept.len() != parts.len();
    let had_comma = t.contains(',');
    let note = match (dropped_zero, had_comma) {
        (true, true) => Some(format!("band 0 dropped and ',' converted to ':' in the stored {label} list {t:?}")),
        (true, false) => Some(format!("band 0 dropped from the stored {label} list {t:?}")),
        (false, true) => Some(format!("comma-separated stored {label} list {t:?} converted to ':'")),
        (false, false) => None,
    };
    (kept.join(":"), note)
}

/// APN network identifier: labels of letters, digits and hyphens joined by
/// dots (3GPP TS 23.003 §9.1; `_` tolerated as some carriers use it). Nothing
/// that could break out of the quoted AT string.
pub fn validate_apn(apn: &str) -> Result<String, String> {
    let a = apn.trim();
    let ok = !a.is_empty()
        && a.len() <= 100
        && !a.starts_with('.')
        && !a.ends_with('.')
        && !a.contains("..")
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if ok { Ok(a.to_string()) } else { Err("Invalid APN (letters, digits, '.', '-', '_' only)".into()) }
}

/// PDP type whitelist; returns the canonical spelling.
pub fn validate_pdp_type(pdp: &str) -> Result<String, String> {
    let up = pdp.trim().to_ascii_uppercase();
    match up.as_str() {
        "IP" | "IPV6" | "IPV4V6" => Ok(up),
        _ => Err("PDP type must be IP, IPV6 or IPV4V6".into()),
    }
}

/// Free-text profile fields (name, provider, MBN name). They are stored with
/// `uci set` (an argv, no shell; uci quotes the value itself), shown by the UI
/// as text, and the MBN name is sent inside a quoted AT string. Refused: control
/// characters (line breaks), `"` and `\` (AT / uci quoting), and `:` (the
/// colon-separated state files). Apostrophes and other printable text are fine.
fn plain_text(s: &str, max: usize) -> bool {
    s.chars().count() <= max && !s.chars().any(|c| c.is_control() || matches!(c, '"' | '\\' | ':'))
}

/// A profile name (trimmed): 1..64 characters of [`plain_text`].
pub fn clean_profile_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("Profile name is required".into());
    }
    if n.contains(':') {
        return Err("Profile name cannot contain colons".into());
    }
    if !plain_text(n, 64) {
        return Err("Profile name: up to 64 characters, no line breaks, double quotes or backslashes".into());
    }
    Ok(n.to_string())
}

/// A band list stored with a profile: band numbers separated by ':' (or ','
/// as older releases stored them), each one a band the modem reports for that
/// RAT (`reported`, the policy_band answer) or, when that is unknown, a 3GPP
/// band. "" = no change. Stored colon-separated.
pub fn clean_profile_bands(rat: crate::handlers::BandRat, raw: &str, reported: &str) -> Result<String, String> {
    Ok(clean_profile_bands_noting(rat, raw, reported)?.0)
}

/// Like [`clean_profile_bands`], also returning a warning when a legacy
/// comma-separated list is converted to `:`.
pub fn clean_profile_bands_noting(rat: crate::handlers::BandRat, raw: &str, reported: &str) -> Result<(String, Option<String>), String> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok((String::new(), None));
    }
    if t.len() > 512 {
        return Err("Band list too long".into());
    }
    let parts: Vec<String> = t.split([':', ',']).map(|b| b.trim().to_string()).collect();
    if parts.iter().any(String::is_empty) {
        return Err(format!("Invalid band list: {t}"));
    }
    let supported = crate::handlers::modem_band_set(reported, rat);
    let clean = crate::handlers::clean_band_list(rat, &parts, Some(&supported))?.join(":");
    let warning = t
        .contains(',')
        .then(|| format!("{} bands: comma-separated list {t:?} converted to ':' ({clean:?})", rat.label()));
    Ok((clean, warning))
}

/// Profile TTL: "0" (or empty) = no TTL override, else a plain decimal 1..255
/// (no sign, no leading zero). Empty is stored as "0".
pub fn clean_profile_ttl(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() || t == "0" {
        return Ok("0".into());
    }
    let ok = t.len() <= 3 && !t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()) && t.parse::<u16>().is_ok_and(|v| (1..=255).contains(&v));
    if ok { Ok(t.to_string()) } else { Err("TTL must be 0 (off) or 1..255".into()) }
}

/// Network type of a profile, as NEW input (API create / change): AUTO, or
/// LTE and NR5G joined by ':' in any order, each once (LTE, NR5G, LTE:NR5G,
/// NR5G:LTE), any case, stored upper-case. Empty = not set.
pub fn clean_network_type(raw: &str) -> Result<String, String> {
    let up = raw.trim().to_ascii_uppercase();
    if up.is_empty() || up == "AUTO" {
        return Ok(up);
    }
    let toks: Vec<&str> = up.split(':').collect();
    let ok = toks.iter().all(|t| matches!(*t, "LTE" | "NR5G")) && !(toks.len() == 2 && toks[0] == toks[1]) && toks.len() <= 2;
    if ok { Ok(up) } else { Err("Network type must be AUTO, LTE, NR5G or LTE:NR5G (or NR5G:LTE)".into()) }
}

/// Network type a profile already holds (stored by an older release, or in a
/// configuration backup). Nothing in the daemon writes it to the modem today;
/// it is stored, shown, and was historically sent as a mode_pref value. Known
/// modes are normalised (AUTO, LTE, NR5G, LTE:NR5G, any case); other values
/// are kept as long as they stay a plain mode-token list (letters, digits,
/// ':'), so nothing could break out of an AT parameter. Empty = not set.
pub fn clean_stored_network_type(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    let up = t.to_ascii_uppercase();
    if matches!(up.as_str(), "AUTO" | "LTE" | "NR5G" | "LTE:NR5G") {
        return Ok(up);
    }
    if t.len() <= 32 && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b':') {
        Ok(t.to_string())
    } else {
        Err("Network type: letters, digits and ':' only (e.g. LTE:NR5G)".into())
    }
}

/// Validate and normalise every field of a profile before anything is
/// written. Shared by the profiles API and the configuration-backup restore.
/// `reported` is the modem's supported-band report ("" = unknown).
/// `stored_network_type`: the network type the profile already holds (an
/// edit) or carried by a backup; that value is accepted by the legacy rules
/// ([`clean_stored_network_type`]), any other by the new-input rules.
pub fn validate_profile_input(p: ProfileInput, reported: &str, stored_network_type: Option<&str>) -> Result<ProfileInput, String> {
    validate_profile_input_noting(p, reported, stored_network_type).map(|(p, _)| p)
}

/// Like [`validate_profile_input`], also returning any legacy band-list
/// normalisation warnings.
pub fn validate_profile_input_noting(
    mut p: ProfileInput,
    reported: &str,
    stored_network_type: Option<&str>,
) -> Result<(ProfileInput, Vec<String>), String> {
    p.iccid = p.iccid.trim().to_string();
    p.imei = p.imei.trim().to_string();
    if p.name.trim().is_empty() || p.iccid.is_empty() || p.apn.trim().is_empty() {
        return Err("Profile name, ICCID, and APN are required".into());
    }
    if p.name.contains(':') || p.apn.contains(':') {
        return Err("Profile name and APN cannot contain colons".into());
    }
    p.name = clean_profile_name(&p.name)?;
    p.apn = validate_apn(&p.apn)?;
    p.pdp_type = validate_pdp_type(&p.pdp_type)?;
    if !p.iccid.bytes().all(|b| b.is_ascii_digit()) || p.iccid.len() < 10 || p.iccid.len() > 20 {
        return Err("ICCID must be 10..20 digits".into());
    }
    if !(p.imei.is_empty() || crate::parsers::validate_imei_luhn(&p.imei)) {
        return Err("IMEI must be 15 digits with a valid check digit".into());
    }
    p.mbn_profile = p.mbn_profile.trim().to_string();
    if p.mbn_profile.contains(['"', '\n', '\r']) || !plain_text(&p.mbn_profile, 64) {
        return Err("Invalid MBN profile name".into());
    }
    use crate::handlers::BandRat;
    let mut warnings = Vec::new();
    for (rat, v) in [
        (BandRat::Lte, &mut p.lte_bands),
        (BandRat::SaNr5g, &mut p.sa_nr5g_bands),
        (BandRat::NsaNr5g, &mut p.nsa_nr5g_bands),
    ] {
        let (clean, note) = clean_profile_bands_noting(rat, v, reported)
            .map_err(|e| format!("{} bands: {e}", rat.label()))?;
        *v = clean;
        warnings.extend(note);
    }
    p.network_type = match stored_network_type {
        Some(st) if p.network_type.trim().eq_ignore_ascii_case(st.trim()) => clean_stored_network_type(&p.network_type)?,
        _ => clean_network_type(&p.network_type)?,
    };
    p.ttl = clean_profile_ttl(&p.ttl)?;
    p.mobile_provider = p.mobile_provider.trim().to_string();
    if !plain_text(&p.mobile_provider, 32) {
        return Err("Invalid mobile provider".into());
    }
    Ok((p, warnings))
}

/// Does UCI section `@profile[index]` exist? A missing `cellprofiles`
/// config means no profiles; a failing `uci` is an error, not "missing".
async fn profile_exists(index: usize) -> Result<bool, ProfileError> {
    Ok(stored_profile(index).await?.is_some())
}

/// The `key=value` lines of section `@profile[index]` (None: no such section).
async fn stored_profile(index: usize) -> Result<Option<std::collections::HashMap<String, String>>, ProfileError> {
    let needle = format!("cellprofiles.@profile[{index}]");
    let shown = uci_show_checked("cellprofiles")
        .await
        .map_err(|e| ProfileError::Tool(format!("Could not read the profiles: {e}")))?;
    let mut found = false;
    let mut fields = std::collections::HashMap::new();
    for l in shown.lines() {
        let Some(rest) = l.strip_prefix(&needle) else { continue };
        if rest.starts_with('=') {
            found = true;
        } else if let Some((k, v)) = rest.strip_prefix('.').and_then(|r| r.split_once('=')) {
            found = true;
            fields.insert(k.to_string(), uci_show_value(v));
        }
    }
    Ok(found.then_some(fields))
}

/// Where a profile written by [`upsert_profile`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOrigin {
    /// The profiles API: new input, except a network type the edited
    /// profile already holds.
    Api,
    /// A configuration backup: values a profile held, normalised already
    /// ([`normalize_stored`]); its network type follows the legacy rules.
    Stored,
}

/// Why a profile operation failed: the index does not exist, the input is
/// invalid, or the profile store (uci) could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum ProfileError {
    NotFound(usize),
    Invalid(String),
    Tool(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::NotFound(i) => write!(f, "No profile at index {i}"),
            ProfileError::Invalid(e) | ProfileError::Tool(e) => f.write_str(e),
        }
    }
}

impl From<String> for ProfileError {
    fn from(e: String) -> Self {
        ProfileError::Invalid(e)
    }
}

impl From<ProfileError> for String {
    fn from(e: ProfileError) -> Self {
        e.to_string()
    }
}

pub async fn upsert_profile(edit_index: Option<usize>, p: ProfileInput, reported: &str, origin: ProfileOrigin) -> Result<(), ProfileError> {
    upsert_profile_noting(edit_index, p, reported, origin).await.map(|_| ())
}

pub async fn upsert_profile_noting(
    edit_index: Option<usize>,
    p: ProfileInput,
    reported: &str,
    origin: ProfileOrigin,
) -> Result<Vec<String>, ProfileError> {
    // Validate field and network-type syntax before touching UCI.
    let pre_net = p.network_type.clone();
    validate_profile_input(p.clone(), reported, Some(&pre_net))?;
    let current = match edit_index {
        Some(idx) => stored_profile(idx).await?,
        None => None,
    };
    let stored_net = match origin {
        ProfileOrigin::Stored => Some(p.network_type.clone()),
        ProfileOrigin::Api => current.as_ref().map(|c| c.get("network_type").cloned().unwrap_or_else(def_net)),
    };
    let (p, warnings) = validate_profile_input_noting(p, reported, stored_net.as_deref())?;
    if let Some(idx) = edit_index
        && current.is_none()
    {
        return Err(ProfileError::NotFound(idx));
    }
    ensure_uci_config_file("cellprofiles").await;

    let prefix = match edit_index {
        Some(idx) => format!("cellprofiles.@profile[{idx}]"),
        None => {
            let sec = uci_add_section("cellprofiles", "profile").await?;
            format!("cellprofiles.{sec}")
        }
    };

    for (k, v) in [
        ("name", p.name.as_str()),
        ("iccid", p.iccid.as_str()),
        ("imei", p.imei.as_str()),
        ("apn", p.apn.as_str()),
        ("pdp_type", p.pdp_type.as_str()),
        ("lte_bands", p.lte_bands.as_str()),
        ("sa_nr5g_bands", p.sa_nr5g_bands.as_str()),
        ("nsa_nr5g_bands", p.nsa_nr5g_bands.as_str()),
        ("network_type", p.network_type.as_str()),
        ("ttl", p.ttl.as_str()),
        ("mobile_provider", p.mobile_provider.as_str()),
        ("mbn_profile", p.mbn_profile.as_str()),
        ("paused", "0"),
    ] {
        uci_set(&format!("{prefix}.{k}"), v).await?;
    }
    uci_commit("cellprofiles").await?;
    Ok(warnings)
}

pub async fn delete_profile(index: usize) -> Result<(), ProfileError> {
    if !profile_exists(index).await? {
        return Err(ProfileError::NotFound(index));
    }
    uci_delete(&format!("cellprofiles.@profile[{index}]")).await;
    Ok(uci_commit("cellprofiles").await?)
}

pub async fn toggle_profile_pause(index: usize, paused: bool) -> Result<(), ProfileError> {
    if !profile_exists(index).await? {
        return Err(ProfileError::NotFound(index));
    }
    uci_set(
        &format!("cellprofiles.@profile[{index}].paused"),
        if paused { "1" } else { "0" },
    )
    .await?;
    Ok(uci_commit("cellprofiles").await?)
}

static LAST_DRIFT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_REBOOT_MIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What the drift check last did, so it applies a fix once instead of every
/// 5 minutes when the modem does not (or cannot yet) reflect it.
#[derive(Default)]
struct DriftMemo {
    mbn_selected: Option<String>,
    apn_applied: Option<(String, String, u64)>,
}

static DRIFT_MEMO: std::sync::Mutex<DriftMemo> = std::sync::Mutex::new(DriftMemo {
    mbn_selected: None,
    apn_applied: None,
});

const APN_REAPPLY_BACKOFF_SECS: u64 = 3600;

/// (pdp_type, apn) of context `cid` from an AT+CGDCONT? response.
pub fn parse_cgdcont(body: &str, cid: u32) -> Option<(String, String)> {
    body.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("+CGDCONT:")?;
        let f = crate::parsers::split_csv_fields(rest);
        if f.first()?.trim().parse::<u32>().ok()? != cid {
            return None;
        }
        Some((
            crate::parsers::unquote(f.get(1).map(|s| s.as_str())),
            crate::parsers::unquote(f.get(2).map(|s| s.as_str())),
        ))
    })
}

/// Select the profile's MBN only if it is not already *selected* (a
/// selected-but-not-activated MBN is waiting for a reboot — re-selecting
/// changes nothing) and we have not already selected it this run.
pub fn mbn_select_needed(mbns: &[crate::parsers::MbnProfile], wanted: &str, already_selected_by_us: Option<&str>) -> bool {
    let selected = mbns.iter().any(|m| m.selected && m.name == wanted);
    !selected && already_selected_by_us != Some(wanted)
}

/// Re-apply CGDCONT only on a real mismatch of context 1 (exact APN, case
/// insensitive, and PDP type), and not again within an hour for the same
/// values if the modem keeps reverting them.
pub fn apn_apply_needed(current: Option<(String, String)>, wanted_pdp: &str, wanted_apn: &str, last: Option<&(String, String, u64)>, now: u64) -> bool {
    if let Some((pdp, apn)) = &current
        && apn.eq_ignore_ascii_case(wanted_apn)
        && pdp.eq_ignore_ascii_case(wanted_pdp)
    {
        return false;
    }
    !last.is_some_and(|(p, a, t)| p == wanted_pdp && a == wanted_apn && now.saturating_sub(*t) < APN_REAPPLY_BACKOFF_SECS)
}

pub fn parse_hhmm(s: &str) -> Option<u16> {
    let (h, m) = s.trim().split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u16>().ok()?, m.parse::<u16>().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchedAction {
    Engage,
    Release,
    Nothing,
}

/// The schedule only removes locks that it engaged itself; manual locks
/// outside the window are left alone.
pub fn cell_lock_sched_action(now_min: u16, start: &str, end: &str, engaged: bool, has_locks: bool) -> SchedAction {
    let should_lock = match (parse_hhmm(start), parse_hhmm(end)) {
        (Some(s), Some(e)) => in_time_window(now_min, s, e),
        _ => false,
    };
    match (should_lock, engaged) {
        (true, false) if has_locks => SchedAction::Engage,
        (false, true) => SchedAction::Release,
        _ => SchedAction::Nothing,
    }
}

const SCHED_ENGAGED_MARKER: &str = "/tmp/cellcore/cell_lock_sched_engaged";
pub const MIN_SCHEDULED_REBOOT_UPTIME_SECS: u64 = 180;
pub const LAST_SCHEDULED_REBOOT_MIN_PATH: &str = "/etc/cellcore/last_scheduled_reboot_min";

/// Read kernel uptime in whole seconds from `/proc/uptime`.
pub fn read_proc_uptime_secs() -> Option<u64> {
    let raw = fs::read_to_string(crate::paths::p("/proc/uptime")).ok()?;
    let secs_f = raw.split_whitespace().next()?.parse::<f64>().ok()?;
    (secs_f.is_finite() && secs_f >= 0.0).then_some(secs_f as u64)
}

pub fn read_last_scheduled_reboot_min() -> Option<u64> {
    fs::read_to_string(crate::paths::p(LAST_SCHEDULED_REBOOT_MIN_PATH))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

pub fn persist_last_scheduled_reboot_min(min: u64) -> Result<(), String> {
    crate::state::atomic_write(
        std::path::Path::new(LAST_SCHEDULED_REBOOT_MIN_PATH),
        format!("{min}\n").as_bytes(),
        0o600,
    )
}

/// Boot-loop guard for scheduled reboots:
/// 1. System uptime must be at least `MIN_SCHEDULED_REBOOT_UPTIME_SECS` (180s).
/// 2. Wall clock must be NTP-synced (`>= MIN_VALID_WALL_CLOCK_SECS`).
/// 3. Current wall-clock minute (`now_secs / 60`) must strictly exceed any
///    persisted `/etc/cellcore/last_scheduled_reboot_min`.
pub fn should_allow_scheduled_reboot(
    now_secs: u64,
    uptime_secs: Option<u64>,
    last_persisted_min: Option<u64>,
) -> Result<(), &'static str> {
    if now_secs < crate::state::MIN_VALID_WALL_CLOCK_SECS {
        return Err("wall clock not NTP-synced yet");
    }
    match uptime_secs {
        Some(u) if u >= MIN_SCHEDULED_REBOOT_UPTIME_SECS => {}
        _ => return Err("system uptime below 180s boot-loop guard"),
    }
    let this_min = now_secs / 60;
    if last_persisted_min.is_some_and(|prev| this_min <= prev) {
        return Err("wall clock has not advanced past last scheduled reboot minute");
    }
    Ok(())
}

fn mono_secs() -> u64 {
    crate::state::mono_ms() / 1000
}

async fn sync_active_iccid_profile(state: &AppState, mono_now: u64) {
    let iccid = state.secrets.read().await.iccid.clone();
    if iccid.is_empty() {
        return;
    }
    let profiles = list_profiles().await;
    let Some(prof) = profiles.into_iter().find(|p| p.iccid == iccid && p.paused != "1") else {
        return;
    };
    // MBN select / APN rewrite: not in the middle of a radio change.
    let _radio = crate::radio::lock(state).await;
    if !prof.mbn_profile.is_empty()
        && !prof.mbn_profile.contains(['"', '\n', '\r'])
        && let Ok(mbn_res) = state.smd.exec("AT+QMBNCFG=\"List\"", Priority::Background, Duration::from_secs(4)).await
    {
        let mbns = parse_mbn_list(&mbn_res.body);
        let ours = DRIFT_MEMO.lock().ok().and_then(|m| m.mbn_selected.clone());
        if mbn_select_needed(&mbns, &prof.mbn_profile, ours.as_deref()) {
            state.push_daemon_log(format!(
                "QuecProfiles selecting MBN profile {} (AutoSel=0, applies after reboot)",
                prof.mbn_profile
            ));
            let _ = state.smd.exec("AT+QMBNCFG=\"AutoSel\",0", Priority::Background, Duration::from_secs(4)).await;
            let _ = state
                .smd
                .exec(
                    format!("AT+QMBNCFG=\"Select\",\"{}\"", prof.mbn_profile),
                    Priority::Background,
                    Duration::from_secs(5),
                )
                .await;
            if let Ok(mut m) = DRIFT_MEMO.lock() {
                m.mbn_selected = Some(prof.mbn_profile.clone());
            }
        }
    }
    if let (Ok(apn), Ok(pdp)) = (validate_apn(&prof.apn), validate_pdp_type(&prof.pdp_type))
        && let Ok(cgd) = state.smd.exec("AT+CGDCONT?", Priority::Background, Duration::from_secs(4)).await
    {
        let current = parse_cgdcont(&cgd.body, 1);
        let last = DRIFT_MEMO.lock().ok().and_then(|m| m.apn_applied.clone());
        if apn_apply_needed(current, &pdp, &apn, last.as_ref(), mono_now) {
            let cmd = format!("AT+CGDCONT=1,\"{pdp}\",\"{apn}\"");
            let _ = state.smd.exec(cmd, Priority::Background, Duration::from_secs(5)).await;
            if let Ok(mut m) = DRIFT_MEMO.lock() {
                m.apn_applied = Some((pdp, apn.clone(), mono_now));
            }
            state.push_daemon_log(format!("QuecProfiles restored APN={apn}"));
        }
    }
}

/// Immediately synchronize the MBN/APN profile for a newly detected SIM ICCID
/// (e.g. right after a SIM slot switch), resetting per-SIM drift memoization.
pub async fn tick_iccid_profile_sync(state: &AppState) {
    if let Ok(mut m) = DRIFT_MEMO.lock() {
        m.mbn_selected = None;
        m.apn_applied = None;
    }
    let mono_now = mono_secs();
    LAST_DRIFT_SECS.store(mono_now, std::sync::atomic::Ordering::Relaxed);
    if crate::obs::failover::is_active() {
        crate::obs::failover::note_deferred("MBN/APN realignment");
        return;
    }
    sync_active_iccid_profile(state, mono_now).await;
}

/// Evaluate and apply scheduled cell-lock transitions, checking actual modem
/// `AT+QNWLOCK` state on first tick when `/tmp/cellcore/cell_lock_sched_engaged`
/// is absent so a pre-restart scheduled lock is never leaked outside its window.
pub async fn tick_cell_lock_scheduler(
    state: &AppState,
    cfg: &crate::state::DaemonSettings,
    now_min: u16,
) {
    if state.cell_lock_bypassed.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let marker_path = crate::paths::p(SCHED_ENGAGED_MARKER);
    let mut engaged = std::path::Path::new(&marker_path).exists();
    if !engaged
        && cfg.cell_lock_sched_enabled
        && !state.sched_boot_checked.load(std::sync::atomic::Ordering::Acquire)
    {
        let probe_cmds = vec![
            ("AT+QNWLOCK=\"common/5g\"".into(), Duration::from_secs(4)),
            ("AT+QNWLOCK=\"common/4g\"".into(), Duration::from_secs(4)),
        ];
        if let Ok(res) = state.smd.exec_batch(probe_cmds, Priority::Background).await {
            let mut any_ok = false;
            let mut modem_locked = false;
            for (idx, key) in [(0usize, "common/5g"), (1usize, "common/4g")] {
                if let Some(Ok(r)) = res.get(idx)
                    && r.ok
                {
                    any_ok = true;
                    if r.body.to_ascii_lowercase().contains("+qnwlock:")
                        && !crate::handlers::qnwlock_is_unlocked(&r.body, key)
                    {
                        modem_locked = true;
                    }
                }
            }
            if any_ok {
                state
                    .sched_boot_checked
                    .store(true, std::sync::atomic::Ordering::Release);
                if modem_locked {
                    engaged = true;
                    let _ = crate::state::atomic_write(
                        std::path::Path::new(&marker_path),
                        b"1\n",
                        0o600,
                    );
                }
            }
        }
    } else if engaged {
        state
            .sched_boot_checked
            .store(true, std::sync::atomic::Ordering::Release);
    }

    if cfg.cell_lock_sched_enabled || engaged {
        let has_locks = !cfg.cell_lock_nr5g.is_empty() || !cfg.cell_lock_lte.is_empty();
        let action = if cfg.cell_lock_sched_enabled {
            cell_lock_sched_action(
                now_min,
                &cfg.cell_lock_start_time,
                &cfg.cell_lock_end_time,
                engaged,
                has_locks,
            )
        } else {
            // schedule switched off while its lock was engaged: undo it
            SchedAction::Release
        };
        // Engaging or releasing a lock re-selects the cell: hold the current
        // state while carrying failover traffic; the next tick catches up.
        let action = if action != SchedAction::Nothing && crate::obs::failover::is_active() {
            crate::obs::failover::note_deferred("scheduled cell lock change");
            SchedAction::Nothing
        } else {
            action
        };
        // Engaging / releasing a lock is a radio change: one at a time.
        let _radio = if action != SchedAction::Nothing {
            Some(crate::radio::lock(state).await)
        } else {
            None
        };
        let status_path = crate::paths::p("/tmp/cell_lock_status.json");
        match action {
            SchedAction::Engage => {
                let mut any_sent = false;
                let mut all_ok = true;
                if !cfg.cell_lock_nr5g.is_empty() {
                    any_sent = true;
                    let cmd = format!("AT+QNWLOCK=\"common/5g\",{}", cfg.cell_lock_nr5g);
                    if !matches!(state.smd.exec(cmd, Priority::Background, Duration::from_secs(5)).await, Ok(r) if r.ok) {
                        all_ok = false;
                    }
                }
                if !cfg.cell_lock_lte.is_empty() {
                    any_sent = true;
                    let cmd = format!("AT+QNWLOCK=\"common/4g\",{}", cfg.cell_lock_lte);
                    if !matches!(state.smd.exec(cmd, Priority::Background, Duration::from_secs(5)).await, Ok(r) if r.ok) {
                        all_ok = false;
                    }
                }
                if any_sent && all_ok {
                    let _ = crate::state::atomic_write(std::path::Path::new(&marker_path), b"1\n", 0o600);
                    let _ = crate::state::atomic_write(
                        std::path::Path::new(&status_path),
                        b"{\"status\":\"active\",\"locked\":1}",
                        0o600,
                    );
                    state.push_daemon_log("Scheduled Cell Lock engaged");
                } else {
                    state.push_daemon_log("Scheduled Cell Lock engage failed (AT did not return OK); will retry");
                }
            }
            SchedAction::Release => {
                let ok5 = matches!(
                    state
                        .smd
                        .exec("AT+QNWLOCK=\"common/5g\",0", Priority::Background, Duration::from_secs(5))
                        .await,
                    Ok(r) if r.ok
                );
                let ok4 = matches!(
                    state
                        .smd
                        .exec("AT+QNWLOCK=\"common/4g\",0", Priority::Background, Duration::from_secs(5))
                        .await,
                    Ok(r) if r.ok
                );
                if ok5 && ok4 {
                    let _ = fs::remove_file(&marker_path);
                    let _ = crate::state::atomic_write(
                        std::path::Path::new(&status_path),
                        b"{\"status\":\"inactive\",\"locked\":0}",
                        0o600,
                    );
                    state.push_daemon_log("Scheduled Cell Lock cleared");
                } else {
                    state.push_daemon_log("Scheduled Cell Lock release failed (AT did not return OK); will retry");
                }
            }
            SchedAction::Nothing => {}
        }
    }
}

pub async fn tick_profiles_and_schedules(state: &AppState) {
    // 1. QuecProfiles drift check every 5 min (monotonic clock, read-first, non-disruptive)
    let mono_now = mono_secs();
    let last_drift = LAST_DRIFT_SECS.load(std::sync::atomic::Ordering::Relaxed);
    let failover_active = crate::obs::failover::is_active();
    if failover_active && mono_now.saturating_sub(last_drift) >= 300 {
        // MBN select / APN rewrite can drop the bearer: not while it carries traffic.
        crate::obs::failover::note_deferred("MBN/APN realignment");
    } else if last_drift == 0 || mono_now.saturating_sub(last_drift) >= 300 {
        LAST_DRIFT_SECS.store(mono_now, std::sync::atomic::Ordering::Relaxed);
        sync_active_iccid_profile(state, mono_now).await;
    }

    // 2. Scheduled Cell Lock & Scheduled Reboot in local wall-clock time
    let now = now_secs();
    let (hhmm, now_min, weekday) = {
        let dt = crate::tz::local_at(now as i64);
        (
            format!("{:02}:{:02}", dt.hour, dt.minute),
            u16::from(dt.hour) * 60 + u16::from(dt.minute),
            dt.weekday_name(),
        )
    };

    let cfg = state.settings.read().await.clone();
    if cfg.scheduled_reboot_enabled
        && cfg.scheduled_reboot_time == hhmm
        && cfg.scheduled_reboot_days.iter().any(|d| d.eq_ignore_ascii_case(weekday))
    {
        let this_min = now / 60;
        if LAST_REBOOT_MIN.load(std::sync::atomic::Ordering::Relaxed) != this_min {
            let uptime = read_proc_uptime_secs();
            let last_persisted = read_last_scheduled_reboot_min();
            if let Err(reason) = should_allow_scheduled_reboot(now, uptime, last_persisted) {
                LAST_REBOOT_MIN.store(this_min, std::sync::atomic::Ordering::Relaxed);
                state.push_daemon_log(format!("Scheduled reboot skipped: {reason}"));
            } else if state.ab_flash.job.read().await.running {
                LAST_REBOOT_MIN.store(this_min, std::sync::atomic::Ordering::Relaxed);
                state.push_daemon_log(
                    "Scheduled reboot deferred: A/B NAND firmware flash is in progress",
                );
                crate::obs::failover::defer_scheduled_reboot(now);
            } else if crate::obs::failover::is_active() {
                LAST_REBOOT_MIN.store(this_min, std::sync::atomic::Ordering::Relaxed);
                state.push_daemon_log("Scheduled reboot deferred: modem is carrying failover traffic");
                crate::obs::failover::defer_scheduled_reboot(now);
            } else {
                LAST_REBOOT_MIN.store(this_min, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = persist_last_scheduled_reboot_min(this_min) {
                    state.push_daemon_log(format!(
                        "Scheduled reboot aborted: failed to persist last_scheduled_reboot_min: {e}"
                    ));
                } else {
                    state.push_daemon_log("Scheduled reboot triggered");
                    crate::obs::emit(
                        crate::obs::EventKind::ScheduledReboot,
                        crate::obs::Severity::Info,
                        "Scheduled reboot",
                        serde_json::json!({ "time": hhmm, "day": weekday, "ran": true }),
                    );
                    crate::obs::set_boot_reason("scheduled reboot");
                    crate::telemetry::flush_persistent_state(state).await;
                    let _ = run_cmd("sync", &[], Duration::from_secs(3)).await;
                    let _ = run_cmd("/sbin/reboot", &[], Duration::from_secs(3)).await;
                }
            }
        }
    }

    tick_cell_lock_scheduler(state, &cfg, now_min).await;
}

/// Minutes-of-day window; `start > end` wraps past midnight.
fn in_time_window(now: u16, start: u16, end: u16) -> bool {
    if start == end {
        return false;
    }
    if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::MbnProfile;

    fn mbn(name: &str, selected: bool, activated: bool) -> MbnProfile {
        MbnProfile { index: 0, selected, activated, name: name.into(), version: String::new(), date: String::new() }
    }

    #[test]
    fn mbn_selected_pending_reboot_is_not_reselected() {
        let pending = vec![mbn("Commercial-TMO", true, false), mbn("ROW_Generic", false, true)];
        // old code re-issued Select every 5 min because it wanted selected && activated
        assert!(!mbn_select_needed(&pending, "Commercial-TMO", None));
        let other = vec![mbn("ROW_Generic", true, true)];
        assert!(mbn_select_needed(&other, "Commercial-TMO", None));
        assert!(!mbn_select_needed(&other, "Commercial-TMO", Some("Commercial-TMO")), "select once per run");
    }

    #[test]
    fn cgdcont_compares_exact_context_one() {
        let body = "+CGDCONT: 1,\"IPV4V6\",\"fast.t-mobile.com.mnc260\",\"0.0.0.0\",0,0\n+CGDCONT: 2,\"IPV4V6\",\"ims\",\"\",0,0";
        let cur = parse_cgdcont(body, 1);
        assert_eq!(cur, Some(("IPV4V6".into(), "fast.t-mobile.com.mnc260".into())));
        // substring match ("fast.t-mobile.com" is contained) no longer hides a mismatch
        assert!(apn_apply_needed(cur.clone(), "IPV4V6", "fast.t-mobile.com", None, 1000));
        assert!(!apn_apply_needed(cur.clone(), "IPV4V6", "FAST.T-MOBILE.COM.MNC260", None, 1000));
        assert!(apn_apply_needed(cur.clone(), "IP", "fast.t-mobile.com.mnc260", None, 1000));
        // the APN only on cid 2 does not count
        assert!(apn_apply_needed(parse_cgdcont(body, 1), "IPV4V6", "ims", None, 1000));
        // same values applied recently and reverted by the modem: no loop
        let last = ("IPV4V6".to_string(), "fast.t-mobile.com".to_string(), 1000u64);
        assert!(!apn_apply_needed(cur.clone(), "IPV4V6", "fast.t-mobile.com", Some(&last), 1300));
        assert!(apn_apply_needed(cur, "IPV4V6", "fast.t-mobile.com", Some(&last), 1000 + APN_REAPPLY_BACKOFF_SECS));
    }

    #[test]
    fn apn_and_pdp_are_validated() {
        assert_eq!(validate_apn(" fast.t-mobile.com ").unwrap(), "fast.t-mobile.com");
        assert!(validate_apn("ims_apn-1").is_ok());
        for bad in ["", "a\"b", "a,\"IP\"", "x\r\nAT+CFUN=0", "a..b", ".a", "with space", &"a".repeat(101)] {
            assert!(validate_apn(bad).is_err(), "{bad:?}");
        }
        assert_eq!(validate_pdp_type("ipv4v6").unwrap(), "IPV4V6");
        assert!(validate_pdp_type("IP\",\"evil").is_err());
        assert!(validate_pdp_type("PPP").is_err());
    }

    #[test]
    fn cell_lock_schedule_uses_minutes_and_only_releases_its_own_lock() {
        assert_eq!(parse_hhmm("8:05"), Some(485));
        assert_eq!(parse_hhmm("08:05"), Some(485));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("8:5"), None);
        // lexical compare got "8:00".."22:00" wrong ("9:30" > "22:00" as strings)
        assert_eq!(cell_lock_sched_action(9 * 60 + 30, "8:00", "22:00", false, true), SchedAction::Engage);
        // overnight window
        assert_eq!(cell_lock_sched_action(60, "22:00", "06:00", false, true), SchedAction::Engage);
        assert_eq!(cell_lock_sched_action(12 * 60, "22:00", "06:00", true, true), SchedAction::Release);
        // outside the window a manual lock (not engaged by the schedule) is left alone
        assert_eq!(cell_lock_sched_action(23 * 60, "08:00", "22:00", false, true), SchedAction::Nothing);
        // nothing configured -> nothing to engage
        assert_eq!(cell_lock_sched_action(10 * 60, "08:00", "22:00", false, false), SchedAction::Nothing);
        // invalid times never lock
        assert_eq!(cell_lock_sched_action(10 * 60, "bogus", "22:00", false, true), SchedAction::Nothing);
    }

    #[test]
    fn stored_and_input_band_normalization_warnings() {
        assert_eq!(normalize_stored_bands("LTE", "2:66"), ("2:66".into(), None));
        let (clean, note) = normalize_stored_bands("LTE", "2,66");
        assert_eq!(clean, "2:66");
        assert!(note.as_deref().is_some_and(|w| w.contains("','") || w.contains("comma")), "{note:?}");
        let (clean, note) = normalize_stored_bands("LTE", "0,2,66");
        assert_eq!(clean, "2:66");
        assert!(note.as_deref().is_some_and(|w| w.contains("band 0") && w.contains("','")), "{note:?}");
        let (clean, note) = normalize_stored_bands("LTE", "2:0:66");
        assert_eq!(clean, "2:66");
        assert!(note.as_deref().is_some_and(|w| w.contains("band 0")), "{note:?}");

        use crate::handlers::BandRat;
        let (clean, note) = clean_profile_bands_noting(BandRat::Lte, "2,66", "").unwrap();
        assert_eq!(clean, "2:66");
        assert!(note.as_deref().is_some_and(|w| w.contains("comma") && w.contains("':'")), "{note:?}");
        assert_eq!(clean_profile_bands_noting(BandRat::Lte, "2:66", "").unwrap(), ("2:66".into(), None));
        assert!(clean_profile_bands_noting(BandRat::Lte, "0,2,66", "").is_err());
    }

    #[tokio::test]
    async fn upsert_validates_fields_before_index_lookup() {
        let dir = std::env::temp_dir().join(format!("qm-prof-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root/etc/config")).unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let uci = dir.join("bin/uci");
        // Fake uci that returns "Entry not found" (no profiles exist) and logs every call.
        let log = dir.join("uci.log");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$1\" = -q ] && shift\n\
             if [ \"$1\" = show ]; then echo 'uci: Entry not found' >&2; exit 1; fi\nexit 0\n",
            log.display()
        );
        std::fs::write(&uci, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&uci, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = crate::paths::TestEnv {
            root: Some(dir.join("root").display().to_string()),
            bin: Some(dir.join("bin").display().to_string()),
        };
        let valid = || ProfileInput {
            name: "TMO".into(),
            iccid: "89012600000000000017".into(),
            imei: String::new(),
            apn: "fast.t-mobile.com".into(),
            pdp_type: "IPV4V6".into(),
            lte_bands: String::new(),
            sa_nr5g_bands: String::new(),
            nsa_nr5g_bands: String::new(),
            network_type: "LTE:NR5G".into(),
            ttl: "0".into(),
            mobile_provider: "T-Mobile".into(),
            mbn_profile: String::new(),
        };

        crate::paths::TEST_ENV
            .scope(env, async {
                // Invalid fields + missing index -> Invalid (400), without running uci show
                let mut bad_apn = valid();
                bad_apn.apn = "bad\"apn".into();
                let err = upsert_profile_noting(Some(999), bad_apn, "", ProfileOrigin::Api).await.unwrap_err();
                assert!(matches!(err, ProfileError::Invalid(_)), "{err:?}");
                assert!(!log.exists(), "uci must not be called when field validation fails");

                // Legacy / unsupported networkType on a missing index -> Invalid (400)
                for net in ["WCDMA:LTE", "GSM"] {
                    let mut p = valid();
                    p.network_type = net.into();
                    let err = upsert_profile_noting(Some(999), p, "", ProfileOrigin::Api).await.unwrap_err();
                    assert!(matches!(err, ProfileError::Invalid(_)), "{net}: {err:?}");
                }

                // Valid fields + missing index -> NotFound (404)
                let err = upsert_profile_noting(Some(999), valid(), "", ProfileOrigin::Api).await.unwrap_err();
                assert_eq!(err, ProfileError::NotFound(999));
            })
            .await;
    }

    #[tokio::test]
    async fn scheduler_boot_leak_clears_modem_lock_when_marker_missing_outside_window() {
        use std::io::{Read, Write};
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;

        let sbx = crate::paths::TestSandbox::new("sched-boot-leak");
        std::fs::create_dir_all(sbx.root.join("tmp/cellcore")).unwrap();
        let lock_5g = std::sync::Arc::new(std::sync::Mutex::new("589,521310,30,41".to_string()));
        let lock_5g_srv = lock_5g.clone();

        let (a, mut b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let body = if cmd == "AT+QNWLOCK=\"common/5g\"" {
                        format!("+QNWLOCK: \"common/5g\",{}", *lock_5g_srv.lock().unwrap())
                    } else if cmd == "AT+QNWLOCK=\"common/4g\"" {
                        "+QNWLOCK: \"common/4g\",0".to_string()
                    } else if let Some(val) = cmd.strip_prefix("AT+QNWLOCK=\"common/5g\",") {
                        *lock_5g_srv.lock().unwrap() = val.trim().to_string();
                        String::new()
                    } else {
                        String::new()
                    };
                    let reply = if body.is_empty() {
                        format!("{cmd}\r\r\nOK\r\n")
                    } else {
                        format!("{cmd}\r\r\n{body}\r\nOK\r\n")
                    };
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });
        let fd_opt = std::sync::Mutex::new(Some(a.into_raw_fd()));
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_opt.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, smd);
                let cfg = crate::state::DaemonSettings {
                    cell_lock_sched_enabled: true,
                    cell_lock_start_time: "08:00".into(),
                    cell_lock_end_time: "18:00".into(),
                    cell_lock_nr5g: "589,521310,30,41".into(),
                    ..Default::default()
                };

                // Outside schedule window (23:00) with missing /tmp marker, boot check sees live
                // QNWLOCK on modem and immediately releases the leaked lock.
                tick_cell_lock_scheduler(&app, &cfg, 23 * 60).await;
                assert!(app.sched_boot_checked.load(std::sync::atomic::Ordering::Acquire));
                assert_eq!(*lock_5g.lock().unwrap(), "0");
                assert!(!sbx.root.join("tmp/cellcore/cell_lock_sched_engaged").exists());
            })
            .await;
    }

    #[test]
    fn scheduled_reboot_boot_loop_guard_checks_uptime_ntp_and_persisted_min() {
        let valid_ts = crate::state::MIN_VALID_WALL_CLOCK_SECS + 3600;
        let this_min = valid_ts / 60;

        // Pre-NTP wall clock -> rejected
        assert!(should_allow_scheduled_reboot(1_000_000, Some(600), None).is_err());
        // Missing or low uptime (< 180s) -> rejected
        assert!(should_allow_scheduled_reboot(valid_ts, None, None).is_err());
        assert!(should_allow_scheduled_reboot(valid_ts, Some(179), None).is_err());
        // Wall clock not strictly past persisted last_scheduled_reboot_min -> rejected
        assert!(should_allow_scheduled_reboot(valid_ts, Some(300), Some(this_min)).is_err());
        assert!(should_allow_scheduled_reboot(valid_ts, Some(300), Some(this_min + 5)).is_err());
        // Valid NTP + uptime >= 180s + strictly advanced past persisted minute -> allowed
        assert!(should_allow_scheduled_reboot(valid_ts, Some(180), None).is_ok());
        assert!(should_allow_scheduled_reboot(valid_ts, Some(300), Some(this_min - 1)).is_ok());

        let sbx = crate::paths::TestSandbox::new("sched-reboot-guard");
        sbx.write("/proc/uptime", "245.78 120.00\n");
        crate::paths::TEST_ENV.sync_scope(sbx.env(), || {
            assert_eq!(read_proc_uptime_secs(), Some(245));
            assert_eq!(read_last_scheduled_reboot_min(), None);
            persist_last_scheduled_reboot_min(this_min).unwrap();
            assert_eq!(read_last_scheduled_reboot_min(), Some(this_min));
            assert!(
                should_allow_scheduled_reboot(
                    valid_ts,
                    read_proc_uptime_secs(),
                    read_last_scheduled_reboot_min()
                )
                .is_err()
            );
            assert!(
                should_allow_scheduled_reboot(
                    valid_ts + 60,
                    read_proc_uptime_secs(),
                    read_last_scheduled_reboot_min()
                )
                .is_ok()
            );
        });
    }

    #[tokio::test]
    async fn scheduler_only_writes_or_removes_engaged_marker_after_at_ok() {
        use std::io::{Read, Write};
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicBool, Ordering};

        let sbx = crate::paths::TestSandbox::new("sched-marker-ok");
        std::fs::create_dir_all(sbx.root.join("tmp/cellcore")).unwrap();
        let allow_ok = std::sync::Arc::new(AtomicBool::new(false));
        let allow_ok_srv = allow_ok.clone();

        let (a, mut b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(n) = b.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let reply = if allow_ok_srv.load(Ordering::Relaxed) {
                        format!("{cmd}\r\r\nOK\r\n")
                    } else {
                        format!("{cmd}\r\r\nERROR\r\n")
                    };
                    let _ = b.write_all(reply.as_bytes());
                }
            }
        });
        let fd_opt = std::sync::Mutex::new(Some(a.into_raw_fd()));
        let smd = crate::smd::SmdClient::spawn_with_opener(Box::new(move || {
            fd_opt.lock().unwrap().take().ok_or_else(|| "closed".into())
        }));

        crate::paths::TEST_ENV
            .scope(sbx.env(), async {
                let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
                let app = AppState::for_tests_with_smd(sbx.root.clone(), auth, smd);
                app.sched_boot_checked.store(true, Ordering::Release);
                let cfg = crate::state::DaemonSettings {
                    cell_lock_sched_enabled: true,
                    cell_lock_start_time: "08:00".into(),
                    cell_lock_end_time: "18:00".into(),
                    cell_lock_nr5g: "589,521310,30,41".into(),
                    ..Default::default()
                };
                let marker = sbx.root.join("tmp/cellcore/cell_lock_sched_engaged");

                // AT returns ERROR -> Engage must NOT write marker
                tick_cell_lock_scheduler(&app, &cfg, 10 * 60).await;
                assert!(!marker.exists(), "marker must not be written when AT fails");

                // AT returns OK -> Engage writes marker
                allow_ok.store(true, Ordering::Relaxed);
                tick_cell_lock_scheduler(&app, &cfg, 10 * 60).await;
                assert!(marker.exists(), "marker must be written when AT succeeds");

                // AT returns ERROR -> Release must NOT remove marker
                allow_ok.store(false, Ordering::Relaxed);
                tick_cell_lock_scheduler(&app, &cfg, 20 * 60).await;
                assert!(marker.exists(), "marker must not be removed when Release AT fails");

                // AT returns OK -> Release removes marker
                allow_ok.store(true, Ordering::Relaxed);
                tick_cell_lock_scheduler(&app, &cfg, 20 * 60).await;
                assert!(!marker.exists(), "marker must be removed when Release AT succeeds");
            })
            .await;
    }
}

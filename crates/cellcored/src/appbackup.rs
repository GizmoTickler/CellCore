//! CellCore configuration backup / restore (app level; the admin module's
//! `sysupgrade -b` archive covers OpenWrt's /etc).
//!
//! * **Export** a versioned JSON bundle of CellCore settings, APN profiles,
//!   data-usage plan, monitoring/maintenance settings, the cell-lock schedule,
//!   TTL/MTU/DNS policy and the radio preferences read from the modem at
//!   export time (band prefs, network mode, cell locks, MBN AutoSel/selection).
//! * Credentials are **never** exported (SMTP password, API tokens, sessions):
//!   no AEAD/KDF is available in the dependency tree that is safe to rely on.
//!   SIM identifiers in profiles (ICCID/IMEI) are left out unless asked for.
//! * **Restore** validates strictly, shows a per-item dry-run diff, then applies
//!   the selected items through the same handlers the UI uses, non-radio items
//!   first and radio items last. Radio items are off by default and the whole
//!   restore is refused while the WAN is failed over (observability failover state).

use std::{collections::BTreeMap, fs, path::Path, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    handlers,
    http::HttpCtx,
    parsers::{clean_at_lines, parse_mbn_list, parse_qnw_band_list, split_csv_fields, unquote, validate_imei_luhn},
    profiles::{self, ProfileInput, list_profiles, parse_hhmm, toggle_profile_pause, upsert_profile, validate_apn, validate_pdp_type},
    smd::Priority,
    state::{AppState, ETC_QM_DIR, save_json_atomic},
};

pub const BUNDLE_FORMAT: &str = "quecmanager-config";
pub const BUNDLE_VERSION: u32 = 1;
pub const MAX_BUNDLE_BYTES: usize = 128 * 1024;
pub const MAX_PROFILES: usize = 16;
const RECIPIENT_PATH: &str = "/etc/cellcore_alert_recipient";
const MSMTPRC_PATH: &str = "/etc/msmtprc";
pub const CONFIRM_PHRASE: &str = "RESTORE";

// ───────────────────────────── Schema ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub created_at: u64,
    pub app_version: String,
    /// Profiles carry ICCID/IMEI only when this is true.
    pub includes_identifiers: bool,
    pub preferences: Preferences,
    pub latency: Latency,
    pub quecwatch: Quecwatch,
    pub maintenance: Maintenance,
    pub data_usage: DataUsagePlan,
    pub policy: Policy,
    pub profiles: Vec<Profile>,
    pub cell_lock_schedule: CellLockSchedule,
    /// Read from the modem at export time; absent if the modem did not answer.
    #[serde(default)]
    pub radio: Option<Radio>,
    /// Native/Coexist dataplane and kernel tuning config; absent in legacy exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataplane: Option<crate::dataplane::DataplaneConfig>,
    /// Live RF/CA/MIMO/C-DRX tuning toggles; absent in legacy exports or when radio skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_tuning: Option<crate::radio_tuning::RadioTuningState>,
    /// Legacy profile values normalised when the bundle was read (not part of
    /// the file): reported with the restore.
    #[serde(skip)]
    pub legacy_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preferences {
    pub temperature_unit: String,
    pub measurement_unit: String,
    pub https_redirect: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Latency {
    pub enabled: bool,
    pub host: String,
    pub interval_sec: u64,
    pub keep_alive: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quecwatch {
    pub enabled: bool,
    pub target: String,
    pub interval_sec: u64,
    pub failures: u32,
    pub max_retries: u32,
    pub connection_refresh: bool,
    pub auto_sim_failover: bool,
    pub high_latency: bool,
    pub latency_ceiling: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Maintenance {
    pub scheduled_reboot_enabled: bool,
    pub scheduled_reboot_time: String,
    pub scheduled_reboot_days: Vec<String>,
    pub alert_recipient: String,
    /// Informational: the SMTP password itself is never exported.
    pub smtp_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataUsagePlan {
    pub billing_cycle_day: u8,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub ttl: Option<u8>,
    #[serde(default)]
    pub hl: Option<u8>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub dns_servers: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    /// Empty unless the bundle includes identifiers.
    pub iccid: String,
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
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CellLockSchedule {
    pub enabled: bool,
    pub start_time: String,
    pub end_time: String,
    /// Lock parameters the schedule engages (`1,<earfcn>,<pci>` / `<pci>,<arfcn>,<scs>,<band>`).
    pub lte: String,
    pub nr5g: String,
    pub lte_persist: bool,
    pub nr5g_persist: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Radio {
    pub lte_bands: Vec<String>,
    pub nsa_nr5g_bands: Vec<String>,
    pub nr5g_bands: Vec<String>,
    pub mode_pref: String,
    pub nr5g_disable_mode: i32,
    #[serde(default)]
    pub lte_lock: Option<LteLock>,
    #[serde(default)]
    pub nr5g_lock: Option<NrLock>,
    #[serde(default)]
    pub mbn_auto_sel: Option<bool>,
    #[serde(default)]
    pub mbn_selected: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LteLock {
    pub earfcn: i64,
    pub pci: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NrLock {
    pub pci: i32,
    pub arfcn: i64,
    pub scs: i32,
    pub band: i32,
}

// ───────────────────────────── Items ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    Preferences,
    Latency,
    Quecwatch,
    Maintenance,
    DataUsage,
    Policy,
    Profiles,
    CellLockSchedule,
    RadioMbn,
    RadioMode,
    RadioBands,
    RadioCellLock,
    Dataplane,
    RadioTuning,
}

/// Apply order: non-radio first, radio-affecting next, raw radio last
/// (carrier firmware, then mode, then bands, then cell lock, then dataplane & tuning).
pub const APPLY_ORDER: [Item; 14] = [
    Item::Preferences,
    Item::Latency,
    Item::Quecwatch,
    Item::Maintenance,
    Item::DataUsage,
    Item::Policy,
    Item::Profiles,
    Item::CellLockSchedule,
    Item::RadioMbn,
    Item::RadioMode,
    Item::RadioBands,
    Item::RadioCellLock,
    Item::Dataplane,
    Item::RadioTuning,
];

impl Item {
    pub fn id(self) -> &'static str {
        match self {
            Item::Preferences => "preferences",
            Item::Latency => "latency",
            Item::Quecwatch => "quecwatch",
            Item::Maintenance => "maintenance",
            Item::DataUsage => "dataUsage",
            Item::Policy => "policy",
            Item::Profiles => "profiles",
            Item::CellLockSchedule => "cellLockSchedule",
            Item::RadioMbn => "radio.mbn",
            Item::RadioMode => "radio.mode",
            Item::RadioBands => "radio.bands",
            Item::RadioCellLock => "radio.cellLock",
            Item::Dataplane => "dataplane",
            Item::RadioTuning => "radioTuning",
        }
    }

    pub fn from_id(id: &str) -> Option<Item> {
        APPLY_ORDER.into_iter().find(|i| i.id() == id)
    }

    pub fn label(self) -> &'static str {
        match self {
            Item::Preferences => "Units & HTTPS redirect",
            Item::Latency => "Latency monitor",
            Item::Quecwatch => "Health watch (LinkWatch)",
            Item::Maintenance => "Scheduled reboot & alert recipient",
            Item::DataUsage => "Data plan (cycle day, quota)",
            Item::Policy => "TTL · MTU · DNS policy",
            Item::Profiles => "APN profiles",
            Item::CellLockSchedule => "Cell-lock schedule",
            Item::RadioMbn => "Carrier firmware (MBN) selection",
            Item::RadioMode => "Network mode",
            Item::RadioBands => "Band preferences",
            Item::RadioCellLock => "Cell locks",
            Item::Dataplane => "Dataplane mode & kernel tuning",
            Item::RadioTuning => "Radio tuning (CA / MIMO / C-DRX)",
        }
    }

    /// Radio items touch the live cellular link; they are opt-in.
    pub fn is_radio(self) -> bool {
        matches!(
            self,
            Item::Profiles
                | Item::CellLockSchedule
                | Item::RadioMbn
                | Item::RadioMode
                | Item::RadioBands
                | Item::RadioCellLock
                | Item::Dataplane
                | Item::RadioTuning
        )
    }
}

/// The selected items in apply order (duplicates collapsed).
pub fn plan(selected: &[Item]) -> Vec<Item> {
    APPLY_ORDER.into_iter().filter(|i| selected.contains(i)).collect()
}

// ───────────────────────────── Validation ─────────────────────────────

fn safe_text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\' || c == '\'')
}

fn host_ok(h: &str) -> bool {
    // Same rule as the latency/LinkWatch APIs: never something ping reads as a flag.
    handlers::clean_ping_target(h).is_ok_and(|c| c == h)
}

fn band_list_ok(v: &[String]) -> bool {
    v.len() <= 128 && v.iter().all(|b| !b.is_empty() && b.len() <= 3 && b.bytes().all(|c| c.is_ascii_digit()))
}

fn lock_params_ok(s: &str) -> bool {
    s.len() <= 64 && s.bytes().all(|c| c.is_ascii_digit() || c == b',')
}

pub fn parse_bundle(bytes: &[u8]) -> Result<Bundle, Vec<String>> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(vec![format!("Bundle is larger than {} KiB", MAX_BUNDLE_BYTES / 1024)]);
    }
    // Check the envelope first so an unknown version is reported as such,
    // not as a schema mismatch.
    let mut v: Value = serde_json::from_slice(bytes).map_err(|e| vec![format!("Not valid JSON: {e}")])?;
    if let Some(obj) = v.as_object_mut()
        && obj.len() == 1
        && let Some(inner) = obj.remove("bundle")
    {
        v = inner;
    }
    bundle_from_value(v)
}

pub fn bundle_from_value(v: Value) -> Result<Bundle, Vec<String>> {
    let Some(obj) = v.as_object() else {
        return Err(vec!["Bundle must be a JSON object".into()]);
    };
    if obj.get("format").and_then(Value::as_str) != Some(BUNDLE_FORMAT) {
        return Err(vec![format!("Not a CellCore configuration bundle (format must be \"{BUNDLE_FORMAT}\")")]);
    }
    match obj.get("version").and_then(Value::as_u64) {
        Some(n) if n == u64::from(BUNDLE_VERSION) => {}
        Some(n) => return Err(vec![format!("Unsupported bundle version {n} (this build reads version {BUNDLE_VERSION})")]),
        None => return Err(vec!["Bundle version missing".into()]),
    }
    let mut b: Bundle = serde_json::from_value(v).map_err(|e| vec![format!("Malformed bundle: {e}")])?;
    // Profiles hold stored values: an older release's TTL "064" or band 0
    // entries restore normalised (and are reported), not refused.
    for p in &mut b.profiles {
        let (ttl, n) = profiles::normalize_stored_ttl(&p.ttl);
        p.ttl = ttl;
        b.legacy_notes.extend(n.map(|n| format!("profile {:?}: {n}", p.name)));
        for (label, v) in [("LTE", &mut p.lte_bands), ("NR5G-SA", &mut p.sa_nr5g_bands), ("NR5G-NSA", &mut p.nsa_nr5g_bands)] {
            let (clean, n) = profiles::normalize_stored_bands(label, v);
            *v = clean;
            b.legacy_notes.extend(n.map(|n| format!("profile {:?}: {n}", p.name)));
        }
    }
    validate(&b)?;
    Ok(b)
}

pub fn validate(b: &Bundle) -> Result<(), Vec<String>> {
    fn need(e: &mut Vec<String>, ok: bool, msg: &str) {
        if !ok {
            e.push(msg.to_string());
        }
    }
    let mut e = Vec::new();
    need(&mut e, safe_text(&b.app_version, 32), "appVersion invalid");
    let p = &b.preferences;
    need(&mut e, matches!(p.temperature_unit.as_str(), "celsius" | "fahrenheit"), "preferences.temperatureUnit must be celsius or fahrenheit");
    need(&mut e, matches!(p.measurement_unit.as_str(), "mi" | "km"), "preferences.measurementUnit must be mi or km");
    let l = &b.latency;
    need(&mut e, host_ok(&l.host), "latency.host invalid");
    need(&mut e, (2..=60).contains(&l.interval_sec), "latency.intervalSec must be 2..60");
    let q = &b.quecwatch;
    need(&mut e, host_ok(&q.target), "quecwatch.target invalid");
    need(&mut e, (15..=3600).contains(&q.interval_sec), "quecwatch.intervalSec must be 15..3600");
    need(&mut e, (1..=20).contains(&q.failures), "quecwatch.failures must be 1..20");
    need(&mut e, (1..=20).contains(&q.max_retries), "quecwatch.maxRetries must be 1..20");
    need(&mut e, (20..=2000).contains(&q.latency_ceiling), "quecwatch.latencyCeiling must be 20..2000");
    let m = &b.maintenance;
    need(&mut e, parse_hhmm(&m.scheduled_reboot_time).is_some(), "maintenance.scheduledRebootTime must be HH:MM");
    const DAYS: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
    need(&mut e, 
        m.scheduled_reboot_days.len() <= 7 && m.scheduled_reboot_days.iter().all(|d| DAYS.contains(&d.as_str())),
        "maintenance.scheduledRebootDays must be weekday names",
    );
    need(&mut e, m.alert_recipient.is_empty() || handlers::is_plain_email(&m.alert_recipient), "maintenance.alertRecipient invalid");
    let d = &b.data_usage;
    need(&mut e, (1..=31).contains(&d.billing_cycle_day), "dataUsage.billingCycleDay must be 1..31");
    need(&mut e, d.quota_bytes.is_none_or(|q| q <= 1 << 50), "dataUsage.quotaBytes too large");
    let po = &b.policy;
    need(&mut e, po.ttl.is_none_or(|t| t >= 1) && po.hl.is_none_or(|t| t >= 1), "policy.ttl/hl must be 1..255");
    need(&mut e, po.ttl.is_some() == po.hl.is_some(), "policy.ttl and policy.hl go together");
    need(&mut e, po.mtu.is_none_or(|m| (1280..=1500).contains(&m)), "policy.mtu must be 1280..1500");
    need(&mut e, 
        po.dns_servers
            .as_ref()
            .is_none_or(|s| !s.is_empty() && s.len() <= 4 && s.iter().all(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())),
        "policy.dnsServers must be 1-4 IPv4 addresses",
    );
    need(&mut e, b.profiles.len() <= MAX_PROFILES, "too many profiles");
    let mut names = std::collections::HashSet::new();
    for (i, pr) in b.profiles.iter().enumerate() {
        let tag = format!("profiles[{i}]");
        // Same field rules as the profiles API (a profile it accepted, e.g.
        // "Mom's SIM" or legacy comma-separated bands, must restore).
        if profiles::clean_profile_name(&pr.name).is_err() || !names.insert(pr.name.to_ascii_lowercase()) {
            e.push(format!("{tag}.name invalid or duplicate"));
        }
        if !(pr.iccid.is_empty() || (pr.iccid.len() >= 10 && pr.iccid.len() <= 20 && pr.iccid.bytes().all(|c| c.is_ascii_digit()))) {
            e.push(format!("{tag}.iccid invalid"));
        }
        if !b.includes_identifiers && (!pr.iccid.is_empty() || !pr.imei.is_empty()) {
            e.push(format!("{tag} carries identifiers but includesIdentifiers is false"));
        }
        if !(pr.imei.is_empty() || validate_imei_luhn(&pr.imei)) {
            e.push(format!("{tag}.imei invalid"));
        }
        if validate_apn(&pr.apn).is_err() {
            e.push(format!("{tag}.apn invalid"));
        }
        if validate_pdp_type(&pr.pdp_type).is_err() {
            e.push(format!("{tag}.pdpType invalid"));
        }
        use handlers::BandRat;
        // Stored values: legacy forms are checked as they restore (normalised).
        if ![(BandRat::Lte, &pr.lte_bands), (BandRat::SaNr5g, &pr.sa_nr5g_bands), (BandRat::NsaNr5g, &pr.nsa_nr5g_bands)]
            .iter()
            .all(|(rat, s)| profiles::clean_profile_bands(*rat, &profiles::normalize_stored_bands("", s).0, "").is_ok())
        {
            e.push(format!("{tag} band lists invalid"));
        }
        if profiles::clean_stored_network_type(&pr.network_type).is_err() {
            e.push(format!("{tag}.networkType invalid"));
        }
        if profiles::clean_profile_ttl(&profiles::normalize_stored_ttl(&pr.ttl).0).is_err() {
            e.push(format!("{tag}.ttl invalid"));
        }
        if !safe_text(&pr.mobile_provider, 32) || !safe_text(&pr.mbn_profile, 64) {
            e.push(format!("{tag} provider/MBN invalid"));
        }
    }
    let c = &b.cell_lock_schedule;
    need(&mut e, parse_hhmm(&c.start_time).is_some() && parse_hhmm(&c.end_time).is_some(), "cellLockSchedule times must be HH:MM");
    need(&mut e, lock_params_ok(&c.lte) && lock_params_ok(&c.nr5g), "cellLockSchedule lock parameters invalid");
    if let Some(r) = &b.radio {
        need(&mut e, band_list_ok(&r.lte_bands) && band_list_ok(&r.nsa_nr5g_bands) && band_list_ok(&r.nr5g_bands), "radio band lists invalid");
        if let Err(msg) = handlers::check_bands_cover_mode(&r.lte_bands, &r.nsa_nr5g_bands, &r.nr5g_bands, &r.mode_pref, r.nr5g_disable_mode) {
            e.push(format!("radio bands: {msg}"));
        }
        need(&mut e, matches!(r.mode_pref.as_str(), "AUTO" | "NR5G" | "LTE" | "LTE:NR5G"), "radio.modePref invalid");
        need(&mut e, (0..=2).contains(&r.nr5g_disable_mode), "radio.nr5gDisableMode must be 0..2");
        if let Some(lk) = r.lte_lock {
            need(&mut e, handlers::validate_lte_lock(i64::from(lk.pci), lk.earfcn).is_ok(), "radio.lteLock out of range");
        }
        if let Some(nk) = r.nr5g_lock {
            need(&mut e, 
                handlers::validate_nr5g_lock(i64::from(nk.pci), nk.arfcn, i64::from(nk.scs), i64::from(nk.band)).is_ok(),
                "radio.nr5gLock out of range",
            );
        }
        need(&mut e, r.mbn_selected.as_deref().is_none_or(|s| !s.is_empty() && safe_text(s, 64)), "radio.mbnSelected invalid");
    }
    if let Some(dp) = &b.dataplane
        && let Err(msg) = crate::dataplane::validate_full_config(dp)
    {
        e.push(format!("dataplane: {msg}"));
    }
    if let Some(rt) = &b.radio_tuning {
        if let Some(order) = rt.rat_acq_order.as_deref()
            && let Err(msg) = crate::radio_tuning::validate_rat_acq_order(order)
        {
            e.push(format!("radioTuning.ratAcqOrder: {msg}"));
        }
        if let Err(msg) = crate::radio_tuning::validate_band_priority(&rt.lte_band_priority, "radioTuning.lteBandPriority") {
            e.push(msg);
        }
        if let Err(msg) = crate::radio_tuning::validate_band_priority(&rt.nr5g_band_priority, "radioTuning.nr5gBandPriority") {
            e.push(msg);
        }
    }
    if e.is_empty() { Ok(()) } else { Err(e) }
}

// ───────────────────────────── Radio read ─────────────────────────────

pub const RADIO_QUERIES: [&str; 9] = [
    "AT+QNWPREFCFG=\"lte_band\"",
    "AT+QNWPREFCFG=\"nsa_nr5g_band\"",
    "AT+QNWPREFCFG=\"nr5g_band\"",
    "AT+QNWPREFCFG=\"mode_pref\"",
    "AT+QNWPREFCFG=\"nr5g_disable_mode\"",
    "AT+QNWLOCK=\"common/4g\"",
    "AT+QNWLOCK=\"common/5g\"",
    "AT+QMBNCFG=\"AutoSel\"",
    "AT+QMBNCFG=\"List\"",
];

fn fields_after(body: &str, prefix: &str, key: &str) -> Option<Vec<String>> {
    clean_at_lines(body).into_iter().find_map(|line| {
        let rest = line.strip_prefix(prefix)?;
        let f = split_csv_fields(rest);
        unquote(f.first().map(String::as_str)).eq_ignore_ascii_case(key).then(|| f[1..].iter().map(|x| unquote(Some(x))).collect())
    })
}

/// Parse the replies to [`RADIO_QUERIES`] (same order). `None` if the modem
/// answered none of the band queries.
pub fn parse_radio(bodies: &[String]) -> Option<Radio> {
    let b = |i: usize| bodies.get(i).map(String::as_str).unwrap_or("");
    if (0..5).all(|i| b(i).trim().is_empty()) {
        return None;
    }
    let num = |s: Option<&String>| s.and_then(|x| x.trim().parse::<i64>().ok());
    let mode_pref = fields_after(b(3), "+QNWPREFCFG:", "mode_pref")
        .and_then(|f| f.first().cloned())
        .map(|s| s.to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "AUTO".into());
    let nr5g_disable_mode = fields_after(b(4), "+QNWPREFCFG:", "nr5g_disable_mode")
        .and_then(|f| num(f.first()))
        .unwrap_or(0) as i32;
    let lte_lock = fields_after(b(5), "+QNWLOCK:", "common/4g").and_then(|f| {
        // "common/4g",<num>,<earfcn>,<pci>[,...]; num 0 = no lock
        if num(f.first())? < 1 {
            return None;
        }
        Some(LteLock { earfcn: num(f.get(1))?, pci: num(f.get(2))? as i32 })
    });
    let nr5g_lock = fields_after(b(6), "+QNWLOCK:", "common/5g").and_then(|f| {
        // "common/5g",<pci>,<arfcn>,<scs>,<band>  or  "common/5g",0
        if f.len() < 4 {
            return None;
        }
        Some(NrLock {
            pci: num(f.first())? as i32,
            arfcn: num(f.get(1))?,
            scs: num(f.get(2))? as i32,
            band: num(f.get(3))? as i32,
        })
    });
    let mbn_auto_sel = fields_after(b(7), "+QMBNCFG:", "autosel").and_then(|f| num(f.first())).map(|n| n == 1);
    let mbn_selected = parse_mbn_list(b(8)).into_iter().find(|m| m.selected).map(|m| m.name);
    Some(Radio {
        lte_bands: parse_qnw_band_list(b(0), "lte_band"),
        nsa_nr5g_bands: parse_qnw_band_list(b(1), "nsa_nr5g_band"),
        nr5g_bands: parse_qnw_band_list(b(2), "nr5g_band"),
        mode_pref,
        nr5g_disable_mode,
        lte_lock,
        nr5g_lock,
        mbn_auto_sel,
        mbn_selected,
    })
}

async fn read_radio(app: &AppState) -> Option<Radio> {
    let cmds = RADIO_QUERIES.iter().map(|c| (c.to_string(), Duration::from_secs(5))).collect();
    let res = app.smd.exec_batch(cmds, Priority::Interactive).await.ok()?;
    let bodies: Vec<String> = res
        .iter()
        .map(|r| r.as_ref().ok().filter(|x| x.ok).map(|x| x.body.clone()).unwrap_or_default())
        .collect();
    parse_radio(&bodies)
}

// ───────────────────────────── Export ─────────────────────────────

/// Snapshot of the current configuration in bundle form.
pub async fn collect(app: &AppState, include_identifiers: bool, with_radio: bool) -> Bundle {
    let s = app.settings.read().await.clone();
    let du = app.data_usage.read().await.clone();
    let recipient = fs::read_to_string(crate::paths::p(RECIPIENT_PATH)).unwrap_or_default().trim().to_string();
    let profiles = list_profiles()
        .await
        .into_iter()
        .take(MAX_PROFILES)
        .map(|p| Profile {
            name: p.name,
            iccid: if include_identifiers { p.iccid } else { String::new() },
            imei: if include_identifiers { p.imei } else { String::new() },
            apn: p.apn,
            pdp_type: p.pdp_type,
            lte_bands: p.lte_bands,
            sa_nr5g_bands: p.sa_nr5g_bands,
            nsa_nr5g_bands: p.nsa_nr5g_bands,
            network_type: p.network_type,
            ttl: p.ttl,
            mobile_provider: p.mobile_provider,
            mbn_profile: p.mbn_profile,
            paused: p.paused == "1",
        })
        .collect();
    let radio = if with_radio { read_radio(app).await } else { None };
    let dataplane = Some(crate::dataplane::load_config());
    let radio_tuning = if with_radio {
        crate::radio_tuning::read_tuning_snapshot(app)
            .await
            .ok()
            .map(|(t, _)| t)
    } else {
        None
    };
    Bundle {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        created_at: crate::auth::now_secs(),
        app_version: app.version.clone(),
        includes_identifiers: include_identifiers,
        preferences: Preferences {
            temperature_unit: s.temperature_unit.clone(),
            measurement_unit: s.measurement_unit.clone(),
            https_redirect: s.https_redirect,
        },
        latency: Latency {
            enabled: s.ping_enabled,
            host: s.ping_host.clone(),
            interval_sec: s.ping_interval_sec,
            keep_alive: s.keep_alive_enabled,
        },
        quecwatch: Quecwatch {
            enabled: s.quecwatch_enabled,
            target: s.quecwatch_target.clone(),
            interval_sec: s.quecwatch_interval_sec,
            failures: s.quecwatch_failures,
            max_retries: s.quecwatch_max_retries,
            connection_refresh: s.quecwatch_connection_refresh,
            auto_sim_failover: s.quecwatch_auto_sim_failover,
            high_latency: s.quecwatch_high_latency,
            latency_ceiling: s.quecwatch_latency_ceiling,
        },
        maintenance: Maintenance {
            scheduled_reboot_enabled: s.scheduled_reboot_enabled,
            scheduled_reboot_time: s.scheduled_reboot_time.clone(),
            scheduled_reboot_days: s.scheduled_reboot_days.clone(),
            alert_recipient: recipient,
            smtp_configured: Path::new(&crate::paths::p(MSMTPRC_PATH)).exists(),
        },
        data_usage: DataUsagePlan {
            billing_cycle_day: du.billing_cycle_day,
            quota_bytes: du.quota_bytes,
        },
        policy: Policy {
            ttl: s.ttl_value,
            hl: s.hl_value,
            mtu: s.mtu_value,
            dns_servers: s.custom_dns.clone(),
        },
        profiles,
        cell_lock_schedule: CellLockSchedule {
            enabled: s.cell_lock_sched_enabled,
            start_time: s.cell_lock_start_time.clone(),
            end_time: s.cell_lock_end_time.clone(),
            lte: s.cell_lock_lte.clone(),
            nr5g: s.cell_lock_nr5g.clone(),
            lte_persist: s.cell_lock_lte_persist,
            nr5g_persist: s.cell_lock_nr5g_persist,
        },
        radio,
        dataplane,
        radio_tuning,
        legacy_notes: Vec::new(),
    }
}

// ───────────────────────────── Dry-run diff ─────────────────────────────

/// The part of a bundle an item restores, as JSON (`None` = not in the bundle).
pub fn item_value(b: &Bundle, item: Item) -> Option<Value> {
    let r = b.radio.as_ref();
    Some(match item {
        Item::Preferences => json!(b.preferences),
        Item::Latency => json!(b.latency),
        Item::Quecwatch => json!(b.quecwatch),
        Item::Maintenance => json!({
            "scheduledRebootEnabled": b.maintenance.scheduled_reboot_enabled,
            "scheduledRebootTime": b.maintenance.scheduled_reboot_time,
            "scheduledRebootDays": b.maintenance.scheduled_reboot_days,
            "alertRecipient": b.maintenance.alert_recipient,
        }),
        Item::DataUsage => json!(b.data_usage),
        Item::Policy => json!(b.policy),
        Item::Profiles => {
            let by_name: serde_json::Map<String, Value> = b.profiles.iter().map(|p| (p.name.clone(), json!(p))).collect();
            Value::Object(by_name)
        }
        Item::CellLockSchedule => json!(b.cell_lock_schedule),
        Item::RadioMbn => json!({ "autoSel": r?.mbn_auto_sel, "selected": r?.mbn_selected }),
        Item::RadioMode => json!({ "modePref": r?.mode_pref, "nr5gDisableMode": r?.nr5g_disable_mode }),
        Item::RadioBands => json!({ "lte": r?.lte_bands.join(":"), "nsaNr5g": r?.nsa_nr5g_bands.join(":"), "nr5g": r?.nr5g_bands.join(":") }),
        Item::RadioCellLock => json!({ "lte": r?.lte_lock, "nr5g": r?.nr5g_lock }),
        Item::Dataplane => json!(b.dataplane.as_ref()?),
        Item::RadioTuning => json!(b.radio_tuning.as_ref()?),
    })
}

fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, x) in m {
                let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&p, x, out);
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Change {
    pub field: String,
    pub from: Value,
    pub to: Value,
}

pub fn diff(current: &Value, wanted: &Value) -> Vec<Change> {
    let (mut a, mut b) = (BTreeMap::new(), BTreeMap::new());
    flatten("", current, &mut a);
    flatten("", wanted, &mut b);
    let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let (f, t) = (a.get(k).cloned().unwrap_or(Value::Null), b.get(k).cloned().unwrap_or(Value::Null));
            (f != t).then(|| Change { field: k.clone(), from: f, to: t })
        })
        .take(64)
        .collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemPreview {
    pub id: &'static str,
    pub label: &'static str,
    pub radio: bool,
    pub default_selected: bool,
    pub applicable: bool,
    pub changes: Vec<Change>,
    pub note: Option<String>,
}

pub fn preview(current: &Bundle, wanted: &Bundle) -> Vec<ItemPreview> {
    APPLY_ORDER
        .into_iter()
        .map(|item| {
            let want = item_value(wanted, item);
            let cur = item_value(current, item).unwrap_or(Value::Null);
            let changes = want.as_ref().map(|w| diff(&cur, w)).unwrap_or_default();
            let mut note = None;
            let mut applicable = want.is_some();
            if want.is_none() {
                note = Some(match item {
                    Item::Dataplane => "Not included in this legacy bundle".into(),
                    Item::RadioTuning => "Not in this bundle (legacy export or modem did not answer)".into(),
                    _ => "Not in this bundle (the modem did not answer at export time)".into(),
                });
            }
            if item == Item::Profiles {
                let unmatched = wanted
                    .profiles
                    .iter()
                    .filter(|p| p.iccid.is_empty() && !current.profiles.iter().any(|c| c.name.eq_ignore_ascii_case(&p.name)))
                    .count();
                if unmatched > 0 {
                    note = Some(format!(
                        "{unmatched} profile(s) have no ICCID in this bundle and no same-named profile here; they will be skipped"
                    ));
                }
                applicable = !wanted.profiles.is_empty();
            }
            if item == Item::Maintenance && wanted.maintenance.smtp_configured && !current.maintenance.smtp_configured {
                note = Some("The SMTP password is never exported: re-enter it under Maintenance to send alerts".into());
            }
            ItemPreview {
                id: item.id(),
                label: item.label(),
                radio: item.is_radio(),
                default_selected: !item.is_radio() && applicable && !changes.is_empty(),
                applicable,
                changes,
                note,
            }
        })
        .collect()
}

// ───────────────────────────── Apply ─────────────────────────────

/// Whether the WAN is currently failed over to this modem. Restores are
/// refused while it is (and re-checked before every radio item).
pub trait FailoverGuard {
    fn failover_active(&self) -> bool;
}

/// The live failover state from the observability module.
pub struct ObsFailover;

impl FailoverGuard for ObsFailover {
    fn failover_active(&self) -> bool {
        crate::obs::failover::is_active()
    }
}

/// Single wiring point for the failover state.
pub fn failover_guard(_app: &AppState) -> impl FailoverGuard {
    ObsFailover
}

pub(crate) trait Applier {
    async fn apply(&self, item: Item, bundle: &Bundle) -> Result<String, String>;
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ItemResult {
    pub id: &'static str,
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, PartialEq)]
pub enum RestoreError {
    FailoverActive,
}

/// Apply `selected` items in [`APPLY_ORDER`]. A failed radio item stops the
/// remaining radio items; failover is re-checked before every radio item.
pub(crate) async fn run_restore<A: Applier, G: FailoverGuard>(
    applier: &A,
    guard: &G,
    bundle: &Bundle,
    selected: &[Item],
) -> Result<Vec<ItemResult>, RestoreError> {
    if guard.failover_active() {
        return Err(RestoreError::FailoverActive);
    }
    let mut out = Vec::new();
    let mut radio_failed = false;
    for item in plan(selected) {
        if item.is_radio() {
            if radio_failed {
                out.push(ItemResult { id: item.id(), ok: false, message: "skipped: an earlier radio item failed".into() });
                continue;
            }
            if guard.failover_active() {
                out.push(ItemResult { id: item.id(), ok: false, message: "skipped: WAN failover became active".into() });
                radio_failed = true;
                continue;
            }
        }
        match applier.apply(item, bundle).await {
            Ok(m) => out.push(ItemResult { id: item.id(), ok: true, message: m }),
            Err(e) => {
                radio_failed |= item.is_radio();
                out.push(ItemResult { id: item.id(), ok: false, message: e });
            }
        }
    }
    Ok(out)
}

/// Applies items through the existing handlers (same validation and side
/// effects as the UI).
struct HandlerApplier {
    ctx: HttpCtx,
    /// Network mode and band preferences are both being restored: they are
    /// one radio change, validated together and written in the safe order
    /// (a backup's mode checked against the device's current bands, or its
    /// bands against the current mode, could be refused although the backup
    /// itself is consistent).
    radio_together: bool,
}

fn req<T: DeserializeOwned>(v: Value) -> Result<Json<T>, String> {
    serde_json::from_value(v).map(Json).map_err(|e| format!("internal request build failed: {e}"))
}

async fn outcome(r: Response) -> Result<(), String> {
    if r.status().is_success() {
        return Ok(());
    }
    let status = r.status();
    let body = axum::body::to_bytes(r.into_body(), 16 * 1024).await.unwrap_or_default();
    let msg = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}"));
    Err(msg)
}

impl Applier for HandlerApplier {
    async fn apply(&self, item: Item, b: &Bundle) -> Result<String, String> {
        let st = || State(self.ctx.clone());
        match item {
            Item::Preferences => {
                let p = &b.preferences;
                outcome(
                    handlers::post_settings(
                        st(),
                        req(json!({ "temperatureUnit": p.temperature_unit, "measurementUnit": p.measurement_unit, "httpsRedirect": p.https_redirect }))?,
                    )
                    .await,
                )
                .await?;
            }
            Item::Latency => {
                let l = &b.latency;
                outcome(
                    handlers::post_latency(
                        st(),
                        req(json!({ "enabled": l.enabled, "host": l.host, "interval": l.interval_sec, "keepAlive": l.keep_alive }))?,
                    )
                    .await,
                )
                .await?;
            }
            Item::Quecwatch => {
                let q = &b.quecwatch;
                outcome(
                    handlers::post_quecwatch(
                        st(),
                        req(json!({
                            "enabled": q.enabled, "pingTarget": q.target, "pingInterval": q.interval_sec,
                            "pingFailures": q.failures, "maxRetries": q.max_retries, "connectionRefresh": q.connection_refresh,
                            "autoSimFailover": q.auto_sim_failover, "highLatencyMonitoring": q.high_latency,
                            "latencyCeiling": q.latency_ceiling,
                        }))?,
                    )
                    .await,
                )
                .await?;
            }
            Item::Maintenance => {
                let m = &b.maintenance;
                outcome(
                    handlers::post_maintenance(
                        st(),
                        req(json!({
                            "scheduledRebootEnabled": m.scheduled_reboot_enabled,
                            "scheduledRebootTime": m.scheduled_reboot_time,
                            "scheduledRebootDays": m.scheduled_reboot_days,
                        }))?,
                    )
                    .await,
                )
                .await?;
                if !m.alert_recipient.is_empty() {
                    crate::state::atomic_write(Path::new(RECIPIENT_PATH), format!("{}\n", m.alert_recipient).as_bytes(), 0o600)?;
                }
            }
            Item::DataUsage => {
                let d = &b.data_usage;
                outcome(
                    handlers::post_data_usage(st(), req(json!({ "billingCycleDay": d.billing_cycle_day, "quotaBytes": d.quota_bytes }))?)
                        .await,
                )
                .await?;
            }
            Item::Policy => {
                let p = &b.policy;
                let ttl = json!({ "action": "ttl", "enabled": p.ttl.is_some(), "ttl": p.ttl.unwrap_or(65), "hl": p.hl.unwrap_or(65) });
                let mtu = json!({ "action": "mtu", "enabled": p.mtu.is_some(), "mtu": p.mtu.unwrap_or(1500) });
                let dns = json!({ "action": "dns", "enabled": p.dns_servers.is_some(), "servers": p.dns_servers });
                for body in [ttl, mtu, dns] {
                    outcome(handlers::post_network_lan(st(), req(body)?).await).await?;
                }
            }
            Item::Profiles => {
                let existing = list_profiles().await;
                let (mut done, mut skipped) = (0, 0);
                for p in &b.profiles {
                    let found = existing.iter().find(|e| e.name.eq_ignore_ascii_case(&p.name));
                    let (iccid, imei) = if p.iccid.is_empty() {
                        match found {
                            Some(e) => (e.iccid.clone(), if p.imei.is_empty() { e.imei.clone() } else { p.imei.clone() }),
                            None => {
                                skipped += 1;
                                continue;
                            }
                        }
                    } else {
                        (p.iccid.clone(), p.imei.clone())
                    };
                    let input = ProfileInput {
                        name: p.name.clone(),
                        iccid,
                        imei,
                        apn: p.apn.clone(),
                        pdp_type: p.pdp_type.clone(),
                        lte_bands: p.lte_bands.clone(),
                        sa_nr5g_bands: p.sa_nr5g_bands.clone(),
                        nsa_nr5g_bands: p.nsa_nr5g_bands.clone(),
                        network_type: p.network_type.clone(),
                        ttl: p.ttl.clone(),
                        mobile_provider: p.mobile_provider.clone(),
                        mbn_profile: p.mbn_profile.clone(),
                    };
                    let reported = handlers::reported_bands(&self.ctx.app);
                    upsert_profile(found.map(|e| e.index), input, &reported, profiles::ProfileOrigin::Stored)
                        .await
                        .map_err(|e| format!("{}: {e}", p.name))?;
                    if p.paused
                        && let Some(now) = list_profiles().await.into_iter().find(|e| e.name.eq_ignore_ascii_case(&p.name))
                    {
                        toggle_profile_pause(now.index, true).await?;
                    }
                    done += 1;
                }
                let mut msg = format!("{done} profile(s) restored, {skipped} skipped");
                if !b.legacy_notes.is_empty() {
                    msg.push_str(&format!("; legacy values normalised: {}", b.legacy_notes.join("; ")));
                }
                return Ok(msg);
            }
            Item::CellLockSchedule => {
                let c = &b.cell_lock_schedule;
                outcome(
                    handlers::post_cell_lock(
                        st(),
                        req(json!({ "scheduleEnabled": c.enabled, "startTime": c.start_time, "endTime": c.end_time }))?,
                    )
                    .await,
                )
                .await?;
                let mut s = self.ctx.app.settings.write().await;
                s.cell_lock_lte = c.lte.clone();
                s.cell_lock_nr5g = c.nr5g.clone();
                s.cell_lock_lte_persist = c.lte_persist;
                s.cell_lock_nr5g_persist = c.nr5g_persist;
                save_json_atomic(&format!("{ETC_QM_DIR}/settings.json"), &*s, 0o600)?;
            }
            Item::RadioMbn => {
                let r = b.radio.as_ref().ok_or("no radio section")?;
                if let Some(auto) = r.mbn_auto_sel {
                    outcome(handlers::post_mbn(st(), req(json!({ "action": "autosel", "enabled": auto }))?).await).await?;
                }
                if r.mbn_auto_sel != Some(true)
                    && let Some(name) = &r.mbn_selected
                {
                    outcome(handlers::post_mbn(st(), req(json!({ "action": "select", "profileName": name }))?).await).await?;
                }
            }
            Item::RadioMode if self.radio_together => {
                let r = b.radio.as_ref().ok_or("no radio section")?;
                outcome(
                    handlers::post_bands(
                        st(),
                        req(json!({
                            "lteBands": r.lte_bands,
                            "nsaNr5gBands": r.nsa_nr5g_bands,
                            "nr5gBands": r.nr5g_bands,
                            "modePref": r.mode_pref,
                            "nr5gDisableMode": r.nr5g_disable_mode,
                        }))?,
                    )
                    .await,
                )
                .await?;
                return Ok("applied together with the band preferences".into());
            }
            Item::RadioBands if self.radio_together => {
                // Already written with the network mode (a failure there skips this item).
                return Ok("applied together with the network mode".into());
            }
            Item::RadioMode => {
                let r = b.radio.as_ref().ok_or("no radio section")?;
                outcome(
                    handlers::post_mode(st(), req(json!({ "modePref": r.mode_pref, "nr5gDisableMode": r.nr5g_disable_mode }))?).await,
                )
                .await?;
            }
            Item::RadioBands => {
                let r = b.radio.as_ref().ok_or("no radio section")?;
                outcome(
                    handlers::post_bands(
                        st(),
                        req(json!({ "lteBands": r.lte_bands, "nsaNr5gBands": r.nsa_nr5g_bands, "nr5gBands": r.nr5g_bands }))?,
                    )
                    .await,
                )
                .await?;
            }
            Item::RadioCellLock => {
                let r = b.radio.as_ref().ok_or("no radio section")?;
                match r.lte_lock {
                    Some(l) => outcome(handlers::post_cell_lock(st(), req(json!({ "rat": "lte", "pci": l.pci, "arfcn": l.earfcn }))?).await).await?,
                    None => outcome(handlers::delete_cell_lock(st(), Query(rat_query("lte")?)).await).await?,
                }
                match r.nr5g_lock {
                    Some(n) => {
                        outcome(
                            handlers::post_cell_lock(
                                st(),
                                req(json!({ "rat": "nr5g", "pci": n.pci, "arfcn": n.arfcn, "scs": n.scs, "band": n.band }))?,
                            )
                            .await,
                        )
                        .await?
                    }
                    None => outcome(handlers::delete_cell_lock(st(), Query(rat_query("nr5g")?)).await).await?,
                }
            }
            Item::Dataplane => {
                let dp = b.dataplane.clone().ok_or("no dataplane section")?;
                crate::dataplane::apply_config_from_backup(&self.ctx.app, dp).await?;
            }
            Item::RadioTuning => {
                let rt = b.radio_tuning.clone().ok_or("no radioTuning section")?;
                let patch = crate::radio_tuning::RadioTuningPatch {
                    lte_ca_enabled: rt.lte_ca_enabled,
                    nr_ca_enabled: rt.nr_ca_enabled,
                    lte4mimo_enabled: rt.lte4mimo_enabled,
                    nr4mimo_enabled: rt.nr4mimo_enabled,
                    nr_ul256qam_fr1: rt.nr_ul256qam_fr1,
                    nr_ul256qam_fr2: rt.nr_ul256qam_fr2,
                    dss_enabled: rt.dss_enabled,
                    nrdc_enabled: rt.nrdc_enabled,
                    rat_acq_order: rt.rat_acq_order,
                    lte_cdrx_enabled: rt.lte_cdrx_enabled,
                    nr_cdrx_enabled: rt.nr_cdrx_enabled,
                    rrc_inactive_enabled: rt.rrc_inactive_enabled,
                    data_centric: rt.data_centric,
                    overheat_ind_enabled: rt.overheat_ind_enabled,
                    lte_band_priority: if rt.lte_band_priority.is_empty() {
                        None
                    } else {
                        Some(rt.lte_band_priority)
                    },
                    nr5g_band_priority: if rt.nr5g_band_priority.is_empty() {
                        None
                    } else {
                        Some(rt.nr5g_band_priority)
                    },
                    nr5g_pref_freq_list: if rt.nr5g_pref_freq_list.is_empty() {
                        None
                    } else {
                        Some(rt.nr5g_pref_freq_list)
                    },
                    nr5g_earfcn_lock: if rt.nr5g_earfcn_lock.is_empty() {
                        None
                    } else {
                        Some(rt.nr5g_earfcn_lock)
                    },
                    event_a3_enabled: rt.event_a3_enabled,
                    event_a3_offset: rt.event_a3_offset,
                    sim_slot: None,
                };
                if patch.is_empty() {
                    return Ok("skipped: no radioTuning fields present".into());
                }
                let applied = crate::radio_tuning::apply_tuning_patch(&self.ctx.app, patch)
                    .await
                    .map_err(|(_, msg, _)| msg)?;
                return Ok(format!("applied ({} field(s))", applied.len()));
            }
        }
        Ok("applied".into())
    }
}

fn rat_query(rat: &str) -> Result<handlers::RatQuery, String> {
    serde_json::from_value(json!({ "rat": rat })).map_err(|e| e.to_string())
}

// ───────────────────────────── HTTP ─────────────────────────────

fn fail(status: StatusCode, msg: impl Into<String>, errors: Option<Vec<String>>) -> Response {
    (status, Json(json!({ "status": "error", "error": msg.into(), "errors": errors }))).into_response()
}

/// Any present `identifiers` value other than an explicit off counts as a
/// request, so encoding tricks can only ever fail closed.
fn export_wants_identifiers(q: &ExportQuery) -> bool {
    q.identifiers.as_deref().is_some_and(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no" | "off"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportQuery {
    #[serde(default)]
    identifiers: Option<String>,
}

async fn get_export(
    State(ctx): State<HttpCtx>,
    who: Option<axum::Extension<crate::http::AuthCtx>>,
    Query(q): Query<ExportQuery>,
) -> Response {
    let ids = export_wants_identifiers(&q);
    // Authoritative check on the decoded query (the router-level token check is
    // only a pre-filter): read-only tokens never receive SIM identifiers.
    if ids && who.as_ref().and_then(|w| w.token.as_ref()).is_some_and(|t| t.kind == crate::tokens::TokenKind::Read) {
        return fail(StatusCode::FORBIDDEN, "Read-only tokens cannot export SIM identifiers", None);
    }
    let bundle = collect(&ctx.app, ids, true).await;
    let Ok(body) = serde_json::to_vec_pretty(&bundle) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "serialize failed", None);
    };
    let name = format!("quecmanager-config-{}.json", bundle.created_at);
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

async fn post_preview(State(ctx): State<HttpCtx>, body: Bytes) -> Response {
    let bundle = match parse_bundle(&body) {
        Ok(b) => b,
        Err(errs) => return fail(StatusCode::BAD_REQUEST, "Bundle rejected", Some(errs)),
    };
    let current = collect(
        &ctx.app,
        bundle.includes_identifiers,
        bundle.radio.is_some() || bundle.radio_tuning.is_some(),
    )
    .await;
    let failover = failover_guard(&ctx.app).failover_active();
    Json(json!({
        "status": "success",
        "bundle": {
            "createdAt": bundle.created_at,
            "appVersion": bundle.app_version,
            "includesIdentifiers": bundle.includes_identifiers,
            "hasRadio": bundle.radio.is_some() || bundle.radio_tuning.is_some(),
            "hasDataplane": bundle.dataplane.is_some(),
            "profiles": bundle.profiles.len(),
        },
        "failoverActive": failover,
        "items": preview(&current, &bundle),
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyReq {
    bundle: Value,
    items: Vec<String>,
    #[serde(default)]
    confirm: Option<String>,
}

async fn post_apply(State(ctx): State<HttpCtx>, body: Bytes) -> Response {
    if body.len() > MAX_BUNDLE_BYTES + 4096 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "Bundle too large", None);
    }
    let r: ApplyReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return fail(StatusCode::BAD_REQUEST, format!("Malformed request: {e}"), None),
    };
    let mut items = Vec::new();
    for id in &r.items {
        match Item::from_id(id) {
            Some(i) => items.push(i),
            None => return fail(StatusCode::BAD_REQUEST, format!("Unknown item {id:?}"), None),
        }
    }
    if items.is_empty() {
        return fail(StatusCode::BAD_REQUEST, "Select at least one item", None);
    }
    let bundle = match bundle_from_value(r.bundle) {
        Ok(b) => b,
        Err(errs) => return fail(StatusCode::BAD_REQUEST, "Bundle rejected", Some(errs)),
    };
    let radio = items.iter().filter(|i| i.is_radio()).count();
    let why = if radio > 0 {
        format!("Restores {} item(s), {radio} of them on the live radio (the link may drop). Type RESTORE to apply.", items.len())
    } else {
        format!("Restores {} item(s) over the current configuration. Type RESTORE to apply.", items.len())
    };
    if let Err(resp) = crate::admin::require_confirm(r.confirm.as_deref(), CONFIRM_PHRASE, &why) {
        return resp;
    }
    let _g = crate::admin::mutate_lock().await;
    let radio_together = items.contains(&Item::RadioMode) && items.contains(&Item::RadioBands);
    let applier = HandlerApplier { ctx: ctx.clone(), radio_together };
    let guard = failover_guard(&ctx.app);
    match run_restore(&applier, &guard, &bundle, &items).await {
        Err(RestoreError::FailoverActive) => fail(
            StatusCode::CONFLICT,
            "The WAN is failed over to this modem; restore is refused until it fails back",
            None,
        ),
        Ok(results) => {
            let ok = results.iter().all(|r| r.ok);
            ctx.app.push_daemon_log(format!(
                "config restore: {}",
                results.iter().map(|r| format!("{}={}", r.id, if r.ok { "ok" } else { "fail" })).collect::<Vec<_>>().join(" ")
            ));
            let mut resp = (
                if ok { StatusCode::OK } else { StatusCode::MULTI_STATUS },
                Json(json!({ "status": if ok { "success" } else { "partial" }, "results": results })),
            )
                .into_response();
            resp.extensions_mut().insert(crate::audit::AuditNote(format!(
                "restored: {}",
                results.iter().map(|r| format!("{}={}", r.id, if r.ok { "ok" } else { "fail" })).collect::<Vec<_>>().join(",")
            )));
            resp
        }
    }
}

pub fn routes() -> Router<HttpCtx> {
    const P: &str = "/api/v1/system/config-backup";
    Router::new()
        .route(&format!("{P}/export"), get(get_export))
        .route(&format!("{P}/preview"), post(post_preview).layer(DefaultBodyLimit::max(MAX_BUNDLE_BYTES)))
        .route(&format!("{P}/apply"), post(post_apply).layer(DefaultBodyLimit::max(MAX_BUNDLE_BYTES + 4096)))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    pub fn sample() -> Bundle {
        Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            created_at: 1_790_000_000,
            app_version: "4.1.1".into(),
            includes_identifiers: false,
            preferences: Preferences { temperature_unit: "celsius".into(), measurement_unit: "km".into(), https_redirect: true },
            latency: Latency { enabled: true, host: "1.1.1.1".into(), interval_sec: 5, keep_alive: false },
            quecwatch: Quecwatch {
                enabled: true,
                target: "8.8.8.8".into(),
                interval_sec: 60,
                failures: 3,
                max_retries: 5,
                connection_refresh: true,
                auto_sim_failover: false,
                high_latency: false,
                latency_ceiling: 150,
            },
            maintenance: Maintenance {
                scheduled_reboot_enabled: false,
                scheduled_reboot_time: "04:00".into(),
                scheduled_reboot_days: vec!["sunday".into()],
                alert_recipient: "ops@example.com".into(),
                smtp_configured: true,
            },
            data_usage: DataUsagePlan { billing_cycle_day: 5, quota_bytes: Some(100 << 30) },
            policy: Policy { ttl: Some(65), hl: Some(65), mtu: None, dns_servers: Some(vec!["1.1.1.1".into()]) },
            profiles: vec![Profile {
                name: "T-Mobile".into(),
                iccid: String::new(),
                imei: String::new(),
                apn: "fast.t-mobile.com".into(),
                pdp_type: "IPV4V6".into(),
                lte_bands: "2:4:12:66:71".into(),
                sa_nr5g_bands: "41:71".into(),
                nsa_nr5g_bands: "41".into(),
                network_type: "LTE:NR5G".into(),
                ttl: "0".into(),
                mobile_provider: "T-Mobile".into(),
                mbn_profile: "Commercial-TMO".into(),
                paused: false,
            }],
            cell_lock_schedule: CellLockSchedule {
                enabled: false,
                start_time: "08:00".into(),
                end_time: "22:00".into(),
                lte: String::new(),
                nr5g: "123,520110,30,41".into(),
                lte_persist: false,
                nr5g_persist: true,
            },
            radio: Some(Radio {
                lte_bands: vec!["2".into(), "66".into()],
                nsa_nr5g_bands: vec!["41".into()],
                nr5g_bands: vec!["41".into(), "71".into()],
                mode_pref: "LTE:NR5G".into(),
                nr5g_disable_mode: 0,
                lte_lock: None,
                nr5g_lock: Some(NrLock { pci: 123, arfcn: 520_110, scs: 30, band: 41 }),
                mbn_auto_sel: Some(false),
                mbn_selected: Some("Commercial-TMO".into()),
            }),
            dataplane: None,
            radio_tuning: None,
            legacy_notes: Vec::new(),
        }
    }

    fn reparse(v: Value) -> Result<Bundle, Vec<String>> {
        parse_bundle(&serde_json::to_vec(&v).unwrap())
    }

    #[test]
    fn roundtrip_and_strict_schema() {
        let b = sample();
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(reparse(v.clone()).unwrap(), b);
        // unknown version / format
        let mut x = v.clone();
        x["version"] = json!(2);
        assert!(reparse(x).unwrap_err()[0].contains("Unsupported bundle version 2"));
        let mut x = v.clone();
        x["format"] = json!("something-else");
        assert!(reparse(x).is_err());
        let mut x = v.clone();
        x.as_object_mut().unwrap().remove("version");
        assert!(reparse(x).is_err());
        // unknown fields anywhere
        let mut x = v.clone();
        x["extra"] = json!(1);
        assert!(reparse(x).is_err());
        let mut x = v.clone();
        x["policy"]["smtpPassword"] = json!("p");
        assert!(reparse(x).is_err());
        let mut x = v.clone();
        x["radio"]["nr5gLock"]["foo"] = json!(1);
        assert!(reparse(x).is_err());
        // missing required section
        let mut x = v.clone();
        x.as_object_mut().unwrap().remove("quecwatch");
        assert!(reparse(x).is_err());
        // oversize
        let big = vec![b' '; MAX_BUNDLE_BYTES + 1];
        assert!(parse_bundle(&big).unwrap_err()[0].contains("larger"));
        assert!(parse_bundle(b"[1,2]").is_err());
        assert!(parse_bundle(b"{").is_err());
        // post_preview wrapped `{ "bundle": <Bundle> }` succeeds; extra keys or invalid inner reject
        assert_eq!(reparse(json!({ "bundle": v })).unwrap(), b);
        assert!(reparse(json!({ "bundle": v, "extra": 1 })).is_err());
        let mut bad_inner = v.clone();
        bad_inner["version"] = json!(99);
        assert!(reparse(json!({ "bundle": bad_inner })).is_err());
    }

    #[test]
    fn malformed_entries_are_rejected() {
        type Mutation = Box<dyn Fn(&mut Bundle)>;
        let bad: Vec<Mutation> = vec![
            Box::new(|b| b.preferences.temperature_unit = "kelvin".into()),
            Box::new(|b| b.latency.host = "8.8.8.8; reboot".into()),
            Box::new(|b| b.latency.interval_sec = 0),
            Box::new(|b| b.quecwatch.failures = 99),
            Box::new(|b| b.maintenance.scheduled_reboot_time = "25:00".into()),
            Box::new(|b| b.maintenance.scheduled_reboot_days = vec!["funday".into()]),
            Box::new(|b| b.maintenance.alert_recipient = "a@b\nhost evil".into()),
            Box::new(|b| b.data_usage.billing_cycle_day = 0),
            Box::new(|b| b.data_usage.billing_cycle_day = 32),
            Box::new(|b| b.policy.mtu = Some(9000)),
            Box::new(|b| b.policy.ttl = Some(0)),
            Box::new(|b| b.policy.hl = None),
            Box::new(|b| b.policy.dns_servers = Some(vec!["not-an-ip".into()])),
            Box::new(|b| b.profiles[0].apn = "bad\"apn".into()),
            Box::new(|b| b.profiles[0].iccid = "8901".into()),
            Box::new(|b| b.profiles[0].iccid = "89014103211118510720".into()), // identifiers without the flag
            Box::new(|b| b.profiles[0].lte_bands = "2;4".into()),
            Box::new(|b| b.profiles[0].mbn_profile = "x\"y".into()),
            Box::new(|b| b.profiles.push(b.profiles[0].clone())),
            Box::new(|b| b.cell_lock_schedule.nr5g = "1,2;3".into()),
            Box::new(|b| b.radio.as_mut().unwrap().lte_bands = vec!["2a".into()]),
            Box::new(|b| b.radio.as_mut().unwrap().mode_pref = "GSM".into()),
            Box::new(|b| b.radio.as_mut().unwrap().nr5g_lock = Some(NrLock { pci: 5000, arfcn: 1, scs: 30, band: 41 })),
            Box::new(|b| b.radio.as_mut().unwrap().mbn_selected = Some("a\"b".into())),
        ];
        for (i, f) in bad.iter().enumerate() {
            let mut b = sample();
            f(&mut b);
            assert!(validate(&b).is_err(), "case {i} accepted");
            assert!(reparse(serde_json::to_value(&b).unwrap()).is_err(), "case {i} parsed");
        }
        let mut ok = sample();
        ok.includes_identifiers = true;
        ok.data_usage.billing_cycle_day = 31;
        ok.profiles[0].iccid = "89014103211118510720".into();
        ok.profiles[0].imei = "356938035643809".into();
        assert!(validate(&ok).is_ok());
        assert!(reparse(serde_json::to_value(&ok).unwrap()).is_ok());
    }

    #[test]
    fn parses_radio_replies() {
        let bodies: Vec<String> = [
            "+QNWPREFCFG: \"lte_band\",2:4:66\r\nOK",
            "+QNWPREFCFG: \"nsa_nr5g_band\",41\r\nOK",
            "+QNWPREFCFG: \"nr5g_band\",41:71\r\nOK",
            "+QNWPREFCFG: \"mode_pref\",LTE:NR5G\r\nOK",
            "+QNWPREFCFG: \"nr5g_disable_mode\",0\r\nOK",
            "+QNWLOCK: \"common/4g\",1,66786,123\r\nOK",
            "+QNWLOCK: \"common/5g\",0\r\nOK",
            "+QMBNCFG: \"AutoSel\",0\r\nOK",
            "+QMBNCFG: \"List\",0,0,0,\"ROW_Commercial\",0x0A010809,20230404\r\n+QMBNCFG: \"List\",1,1,1,\"Commercial-TMO\",0x0A0C1F01,20230512\r\nOK",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let r = parse_radio(&bodies).unwrap();
        assert_eq!(r.lte_bands, vec!["2", "4", "66"]);
        assert_eq!(r.nr5g_bands, vec!["41", "71"]);
        assert_eq!(r.mode_pref, "LTE:NR5G");
        assert_eq!(r.lte_lock, Some(LteLock { earfcn: 66786, pci: 123 }));
        assert_eq!(r.nr5g_lock, None);
        assert_eq!(r.mbn_auto_sel, Some(false));
        assert_eq!(r.mbn_selected.as_deref(), Some("Commercial-TMO"));
        let mut b2 = bodies.clone();
        b2[5] = "+QNWLOCK: \"common/4g\",0\r\nOK".into();
        b2[6] = "+QNWLOCK: \"common/5g\",123,520110,30,41\r\nOK".into();
        let r2 = parse_radio(&b2).unwrap();
        assert_eq!(r2.lte_lock, None);
        assert_eq!(r2.nr5g_lock, Some(NrLock { pci: 123, arfcn: 520_110, scs: 30, band: 41 }));
        assert!(parse_radio(&vec![String::new(); 9]).is_none());
        // the export-time queries are all read-only for the AT guard
        for q in RADIO_QUERIES {
            assert_eq!(crate::atguard::classify(q).unwrap().class, crate::atguard::AtClass::Read, "{q}");
        }
    }

    #[test]
    fn dry_run_diff_lists_changes_and_defaults() {
        let wanted = sample();
        let mut current = sample();
        current.preferences.measurement_unit = "mi".into();
        current.radio.as_mut().unwrap().lte_bands = vec!["2".into(), "4".into(), "66".into()];
        current.profiles.clear();
        let p = preview(&current, &wanted);
        assert_eq!(p.iter().map(|i| i.id).collect::<Vec<_>>(), APPLY_ORDER.iter().map(|i| i.id()).collect::<Vec<_>>());
        let pref = p.iter().find(|i| i.id == "preferences").unwrap();
        assert_eq!(pref.changes, vec![Change { field: "measurementUnit".into(), from: json!("mi"), to: json!("km") }]);
        assert!(pref.default_selected && !pref.radio);
        let lat = p.iter().find(|i| i.id == "latency").unwrap();
        assert!(lat.changes.is_empty() && !lat.default_selected, "no change -> not preselected");
        let bands = p.iter().find(|i| i.id == "radio.bands").unwrap();
        assert!(bands.radio && !bands.default_selected, "radio items are off by default");
        assert_eq!(bands.changes[0].field, "lte");
        let prof = p.iter().find(|i| i.id == "profiles").unwrap();
        assert!(prof.note.as_deref().unwrap_or("").contains("skipped"), "{:?}", prof.note);
        assert!(prof.changes.iter().any(|c| c.field.starts_with("T-Mobile")));
        let maint = p.iter().find(|i| i.id == "maintenance").unwrap();
        assert!(maint.note.is_none(), "smtp configured on both sides");
        // no radio section in the bundle
        let mut nr = sample();
        nr.radio = None;
        let p2 = preview(&current, &nr);
        let m = p2.iter().find(|i| i.id == "radio.mode").unwrap();
        assert!(!m.applicable && m.changes.is_empty());
    }

    struct Recorder {
        log: Mutex<Vec<Item>>,
        fail: Option<Item>,
    }
    impl Applier for Recorder {
        async fn apply(&self, item: Item, _b: &Bundle) -> Result<String, String> {
            self.log.lock().unwrap().push(item);
            if self.fail == Some(item) { Err("boom".into()) } else { Ok("ok".into()) }
        }
    }
    struct Failover(std::sync::atomic::AtomicUsize, usize);
    impl FailoverGuard for Failover {
        /// active from the n-th check on
        fn failover_active(&self) -> bool {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= self.1
        }
    }

    #[tokio::test]
    async fn apply_runs_non_radio_first_and_radio_last() {
        let b = sample();
        let rec = Recorder { log: Mutex::new(Vec::new()), fail: None };
        let sel = [Item::RadioCellLock, Item::Policy, Item::RadioBands, Item::Preferences, Item::Profiles, Item::Preferences];
        let res = run_restore(&rec, &Failover(Default::default(), usize::MAX), &b, &sel).await.unwrap();
        let order = rec.log.lock().unwrap().clone();
        assert_eq!(order, vec![Item::Preferences, Item::Policy, Item::Profiles, Item::RadioBands, Item::RadioCellLock]);
        assert!(res.iter().all(|r| r.ok));
        let first_radio = order.iter().position(|i| i.is_radio()).unwrap();
        assert!(order[first_radio..].iter().all(|i| i.is_radio()));
        assert!(order[..first_radio].iter().all(|i| !i.is_radio()));
    }

    #[tokio::test]
    async fn radio_failure_stops_later_radio_items() {
        let b = sample();
        let rec = Recorder { log: Mutex::new(Vec::new()), fail: Some(Item::RadioMode) };
        let res = run_restore(&rec, &Failover(Default::default(), usize::MAX), &b, &[Item::RadioMode, Item::RadioBands, Item::Latency]).await.unwrap();
        assert_eq!(rec.log.lock().unwrap().clone(), vec![Item::Latency, Item::RadioMode]);
        assert_eq!(res.iter().map(|r| r.ok).collect::<Vec<_>>(), vec![true, false, false]);
        assert!(res[2].message.contains("skipped"));
    }

    #[tokio::test]
    async fn refused_while_failover_is_active() {
        let b = sample();
        let rec = Recorder { log: Mutex::new(Vec::new()), fail: None };
        let always = Failover(Default::default(), 0);
        assert_eq!(run_restore(&rec, &always, &b, &[Item::Preferences]).await, Err(RestoreError::FailoverActive));
        assert!(rec.log.lock().unwrap().is_empty());
        // failover starting mid-restore stops the radio part
        let later = Failover(Default::default(), 1);
        let res = run_restore(&rec, &later, &b, &[Item::Preferences, Item::RadioBands]).await.unwrap();
        assert_eq!(rec.log.lock().unwrap().clone(), vec![Item::Preferences]);
        assert!(!res[1].ok);
        // the production guard reads the observability failover state
        assert_eq!(ObsFailover.failover_active(), crate::obs::failover::is_active());
    }

    #[test]
    fn item_ids_roundtrip() {
        for i in APPLY_ORDER {
            assert_eq!(Item::from_id(i.id()), Some(i));
        }
        assert_eq!(Item::from_id("radio.everything"), None);
        assert_eq!(plan(&[Item::RadioCellLock, Item::Preferences]), vec![Item::Preferences, Item::RadioCellLock]);
    }

    #[test]
    fn identifiers_flag_fails_closed() {
        let q = |v: Option<&str>| ExportQuery { identifiers: v.map(str::to_string) };
        for on in ["1", "true", "TRUE", "yes", "on", " 1", "2"] {
            assert!(export_wants_identifiers(&q(Some(on))), "{on:?}");
        }
        for off in ["", "0", "false", "False", "no", "off"] {
            assert!(!export_wants_identifiers(&q(Some(off))), "{off:?}");
        }
        assert!(!export_wants_identifiers(&q(None)));
    }

    #[test]
    fn legacy_bundle_without_dataplane_or_radio_tuning_parses_and_previews() {
        let b = sample();
        let mut v = serde_json::to_value(&b).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("dataplane");
        obj.remove("radioTuning");
        let parsed = reparse(v).unwrap();
        assert!(parsed.dataplane.is_none());
        assert!(parsed.radio_tuning.is_none());

        let mut cur = sample();
        cur.dataplane = Some(crate::dataplane::DataplaneConfig::default());
        let items = preview(&cur, &parsed);
        let dp_item = items.iter().find(|i| i.id == "dataplane").unwrap();
        assert!(!dp_item.applicable && !dp_item.default_selected);
        assert!(dp_item.note.as_deref().unwrap_or("").contains("legacy"));
        let rt_item = items.iter().find(|i| i.id == "radioTuning").unwrap();
        assert!(!rt_item.applicable && !rt_item.default_selected);
    }

    #[test]
    fn dataplane_and_radio_tuning_roundtrip_and_validate() {
        let mut wanted = sample();
        let dp = crate::dataplane::DataplaneConfig {
            mode: crate::dataplane::DataplaneMode::Native,
            iface: "rmnet_data1".into(),
            kernel_tuning: crate::dataplane::KernelTuningProfile::HighThroughput,
            ..Default::default()
        };
        wanted.dataplane = Some(dp);
        wanted.radio_tuning = Some(crate::radio_tuning::RadioTuningState {
            lte_ca_enabled: Some(true),
            nr_ca_enabled: Some(true),
            nr_cdrx_enabled: Some(false),
            rat_acq_order: Some("NR5G:LTE:WCDMA".into()),
            lte_band_priority: vec!["66".into(), "2".into()],
            ..Default::default()
        });
        let raw = serde_json::to_value(&wanted).unwrap();
        assert_eq!(reparse(raw).unwrap(), wanted);

        let cur = sample();
        let items = preview(&cur, &wanted);
        let dp_item = items.iter().find(|i| i.id == "dataplane").unwrap();
        assert!(dp_item.applicable && dp_item.radio && !dp_item.default_selected);
        assert!(dp_item.changes.iter().any(|c| c.field == "mode"));

        let mut bad_dp = wanted.clone();
        bad_dp.dataplane.as_mut().unwrap().mux_id = 0;
        assert!(validate(&bad_dp).is_err());

        let mut bad_rt = wanted.clone();
        bad_rt.radio_tuning.as_mut().unwrap().rat_acq_order = Some("GSM".into());
        assert!(validate(&bad_rt).is_err());
    }
}

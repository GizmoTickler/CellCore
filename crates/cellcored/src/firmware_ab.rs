//! Native, zero-USB, inactive-slot A/B firmware flasher for Quectel RM551E-GL / SDX75
//! dual-slot NAND (`R02A02+`, 58-partition `/proc/mtd`).
//!
//! Safety invariants enforced unconditionally:
//! - Never writes to the active boot slot (`target_slot == active_slot.other()`).
//! - Never writes to any non-A/B partition (`efs2`, `mibib`, `usrdata`, `misc`, `recoveryinfo`, etc.).
//! - Only writes to the explicit 22-partition A/B allowlist, verified against `/proc/mtd`.
//! - Refuses to touch any MTD currently UBI-attached in `/sys/class/ubi/ubi*/mtd_num`.
//! - Streams/extracts ONE image at a time from a `.zip` package to stay well within `/tmp` tmpfs.
//! - Verifies MD5 against `md5.txt` before flashing (fail-closed unless explicitly overridden),
//!   verifies UBI attachability for `.ubi` images, and verifies SHA-256 read-back for raw MTD images.
//! - Never marks the previous slot unbootable so 1-command rollback remains intact.

use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt as _;
use md5::Digest as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    io::AsyncWriteExt as _,
    sync::{Mutex, RwLock},
};

use crate::{http::HttpCtx, state::AppState};

pub const AB_STATE_PATH: &str = "/etc/cellcore/ab-flash-state.json";
pub const AB_LOCK_PATH: &str = "/var/run/cellcore-ab-flash.lock";
pub const STAGE_DIR: &str = "/tmp/cellcore-ab-stage";
pub const SYSMNT_DIR: &str = "/tmp/cellcore-ab-sysmnt";
pub const UPLOAD_CACHE_DIR: &str = "/usrdata/cache";
pub const MIN_STAGE_FREE_MIB: u64 = 128;
pub const FLASH_SPACE_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_UPLOAD_ZIP_BYTES: u64 = 250 * 1024 * 1024;
pub const UPLOAD_MIN_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;
const UNZIP_STREAM_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_CONFIRM_DELAY_SECS: u64 = 90;
const MAX_STAGED_ENTRIES: usize = 50;
const MAX_LOG_LINES: usize = 200;

/// Rootfs scope A/B partition bases (2).
pub const ROOTFS_BASES: &[&str] = &["boot", "system"];

/// Baseband / TrustZone / DSP scope A/B partition bases (15).
pub const BASEBAND_BASES: &[&str] = &[
    "modem",
    "ipa_fw",
    "tz",
    "tz_devcfg",
    "cmnlib64",
    "keymaster",
    "apdp",
    "multi_oem",
    "multi_qti",
    "aop",
    "aop_devcfg",
    "qhee",
    "qupfw",
    "shrm",
    "cpucpfw",
];

/// Bootloader scope A/B partition bases (5, included in `full` scope; `sbl` written last).
pub const BOOTLOADER_BASES: &[&str] = &["sbl", "xbl_config", "xbl_ramdump", "abl", "uefi"];

/// Non-A/B critical partitions that MUST NEVER be erased or written by this module.
pub const NEVER_TOUCH_PARTITIONS: &[&str] = &[
    "mibib",
    "efs2",
    "rawdata",
    "sys_rev",
    "cdt",
    "ddr",
    "sec",
    "recoveryinfo",
    "misc",
    "quest",
    "devinfo",
    "fota",
    "usb_qti",
    "usrdata",
];

const OVERLAY_INIT_03: &str = "\
#!/bin/sh /etc/rc.common
START=03
start() {
    [ -x /usrdata/bin/cellcored ] && /usrdata/bin/cellcored overlay pivot
}
";

const OVERLAY_INIT_13: &str = "\
#!/bin/sh /etc/rc.common
START=13
start() {
    [ -x /usrdata/bin/cellcored ] && /usrdata/bin/cellcored overlay remount-rw
}
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Slot {
    #[serde(rename = "_a", alias = "a", alias = "A", alias = "0")]
    A,
    #[serde(rename = "_b", alias = "b", alias = "B", alias = "1")]
    B,
}

impl Slot {
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::A => "_a",
            Self::B => "_b",
        }
    }

    pub const fn index(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    pub fn partition_name(self, base: &str) -> String {
        match self {
            Self::A => base.to_string(),
            Self::B => format!("{base}_b"),
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "a" | "_a" | "0" => Some(Self::A),
            "b" | "_b" | "1" => Some(Self::B),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FlashScope {
    #[default]
    Rootfs,
    Baseband,
    Full,
}

impl FlashScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rootfs => "rootfs",
            Self::Baseband => "baseband",
            Self::Full => "full",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "rootfs" => Some(Self::Rootfs),
            "baseband" => Some(Self::Baseband),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn allowed_bases(self) -> Vec<&'static str> {
        match self {
            Self::Rootfs => ROOTFS_BASES.to_vec(),
            Self::Baseband => BASEBAND_BASES.to_vec(),
            Self::Full => {
                let mut v = Vec::with_capacity(
                    ROOTFS_BASES.len() + BASEBAND_BASES.len() + BOOTLOADER_BASES.len(),
                );
                v.extend_from_slice(ROOTFS_BASES);
                v.extend_from_slice(BASEBAND_BASES);
                v.extend_from_slice(BOOTLOADER_BASES);
                v
            }
        }
    }
}

pub fn is_known_ab_base(base: &str) -> bool {
    ROOTFS_BASES.contains(&base) || BASEBAND_BASES.contains(&base) || BOOTLOADER_BASES.contains(&base)
}

pub fn is_never_touch_partition(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let stripped = lower.strip_suffix("_b").unwrap_or(&lower);
    NEVER_TOUCH_PARTITIONS.contains(&lower.as_str()) || NEVER_TOUCH_PARTITIONS.contains(&stripped)
}

fn write_order_rank(base: &str) -> usize {
    match base {
        "boot" => 0,
        "modem" => 1,
        "system" => 2,
        "sbl" => 999,
        other => {
            if let Some(pos) = BASEBAND_BASES.iter().position(|&b| b == other) {
                10 + pos
            } else if let Some(pos) = BOOTLOADER_BASES.iter().position(|&b| b == other) {
                100 + pos
            } else {
                500
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtdPartition {
    pub num: u32,
    pub size: u64,
    pub erasesize: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbLayout {
    pub partitions: HashMap<String, MtdPartition>,
    pub total_mtds: usize,
    pub ab_bases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RciInfo {
    pub selected_set: Option<u32>,
    pub trial_boot_enable: Option<u32>,
    pub trial_boot_max_attempts: Option<u32>,
    pub trial_boot_failed_attempts: Option<u32>,
    pub image_set_to_boot: Option<u32>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawProgramEntry {
    pub base_label: String,
    pub zip_relpath: String,
    pub is_ubi: bool,
    pub num_partition_sectors: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawProgramManifest {
    pub project_name: Option<String>,
    pub entries: Vec<RawProgramEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedPartition {
    pub base_label: String,
    pub target_partition: String,
    pub mtd_num: u32,
    pub mtd_size: u64,
    pub erasesize: u64,
    pub zip_relpath: String,
    pub expected_md5: Option<String>,
    pub is_ubi: bool,
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlashPlan {
    pub active_slot: Slot,
    pub target_slot: Slot,
    pub scope: FlashScope,
    pub project_name: Option<String>,
    pub device_project_name: Option<String>,
    pub device_project_rev: Option<String>,
    pub partitions: Vec<PlannedPartition>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectReport {
    pub source_path: String,
    pub source_kind: String,
    pub rawprogram_file: String,
    pub md5_entries: usize,
    pub tmp_avail_mib: Option<u64>,
    pub tmp_space_ok: bool,
    pub plan: FlashPlan,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlashOptions {
    pub dry_run: bool,
    pub preserve_cellcore: bool,
    pub activate_slot: bool,
    pub reboot: bool,
    pub verify_readback: bool,
}

impl Default for FlashOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            preserve_cellcore: true,
            activate_slot: false,
            reboot: false,
            verify_readback: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PersistedAbFlashState {
    pub status: String,
    pub last_flash_ts: Option<u64>,
    pub previous_slot: Option<Slot>,
    pub target_slot: Option<Slot>,
    pub scope: Option<FlashScope>,
    pub source_name: Option<String>,
    pub project_name: Option<String>,
    pub partitions_flashed: Vec<String>,
    pub verified_on_boot: bool,
    pub message: Option<String>,
    pub log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AbJobProgress {
    pub running: bool,
    pub dry_run: bool,
    pub phase: String,
    pub current_partition: Option<String>,
    pub completed: usize,
    pub total: usize,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub ok: Option<bool>,
    pub error: Option<String>,
    pub log: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbStatusResponse {
    pub supported: bool,
    pub unsupported_reason: Option<String>,
    pub total_mtds: usize,
    pub ab_base_count: usize,
    pub active_slot: Option<Slot>,
    pub inactive_slot: Option<Slot>,
    pub slot_a_unbootable: Option<bool>,
    pub slot_b_unbootable: Option<bool>,
    pub trial_boot_active: Option<bool>,
    pub rci: Option<RciInfo>,
    pub project_name: Option<String>,
    pub project_rev: Option<String>,
    pub tmp_avail_mib: Option<u64>,
    pub ab_updater_enabled: bool,
    pub mirror_copy_enabled: bool,
    pub job: AbJobProgress,
    pub last_state: PersistedAbFlashState,
}

pub struct AbFlashState {
    pub op_lock: Arc<Mutex<()>>,
    pub job: RwLock<AbJobProgress>,
}

impl Default for AbFlashState {
    fn default() -> Self {
        Self::new()
    }
}

impl AbFlashState {
    pub fn new() -> Self {
        Self {
            op_lock: Arc::new(Mutex::new(())),
            job: RwLock::new(AbJobProgress {
                phase: "idle".into(),
                ..Default::default()
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure Parsers & Planners (100% unit-testable without real MTD hardware)
// ---------------------------------------------------------------------------

/// Parse `/proc/mtd` lines (`mtd55: 07380000 00040000 "system"`).
pub fn parse_proc_mtd(content: &str) -> Vec<MtdPartition> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("mtd") else {
            continue;
        };
        let Some((num_str, tail)) = rest.split_once(':') else {
            continue;
        };
        let Ok(num) = num_str.trim().parse::<u32>() else {
            continue;
        };
        let Some(q1) = tail.find('"') else {
            continue;
        };
        let Some(q2_rel) = tail[q1 + 1..].find('"') else {
            continue;
        };
        let name = tail[q1 + 1..q1 + 1 + q2_rel].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let mut nums = tail[..q1].split_whitespace();
        let (Some(size_hex), Some(erase_hex)) = (nums.next(), nums.next()) else {
            continue;
        };
        let (Ok(size), Ok(erasesize)) = (
            u64::from_str_radix(size_hex, 16),
            u64::from_str_radix(erase_hex, 16),
        ) else {
            continue;
        };
        out.push(MtdPartition {
            num,
            size,
            erasesize,
            name,
        });
    }
    out
}

/// Verify dual-slot A/B MTD layout (requires `boot`/`boot_b`, `system`/`system_b`, `modem`/`modem_b`).
pub fn detect_ab_layout(mtds: &[MtdPartition]) -> Result<AbLayout, String> {
    let mut partitions = HashMap::with_capacity(mtds.len());
    for m in mtds {
        partitions.insert(m.name.clone(), m.clone());
    }
    let required = ["boot", "boot_b", "system", "system_b", "modem", "modem_b"];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| !partitions.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "Dual-slot A/B NAND layout not detected ({} MTD partitions, missing {}). Legacy single-slot firmware (e.g. R01A04) requires USB firehose upgrade to R02A02+ first.",
            mtds.len(),
            missing.join(", ")
        ));
    }
    let mut ab_bases = Vec::new();
    for &base in ROOTFS_BASES
        .iter()
        .chain(BASEBAND_BASES.iter())
        .chain(BOOTLOADER_BASES.iter())
    {
        if partitions.contains_key(base) && partitions.contains_key(&format!("{base}_b")) {
            ab_bases.push(base.to_string());
        }
    }
    Ok(AbLayout {
        partitions,
        total_mtds: mtds.len(),
        ab_bases,
    })
}

/// Parse active slot from `/proc/cmdline` (`SLOT_SUFFIX=_a`, `systemd.setenv="SLOT_SUFFIX=_a"`, etc.).
pub fn parse_cmdline_slot(cmdline: &str) -> Option<Slot> {
    for tok in cmdline.split_whitespace() {
        let unwrapped = tok
            .strip_prefix("systemd.setenv=")
            .unwrap_or(tok)
            .trim_matches('"')
            .trim_matches('\'');
        if let Some(val) = unwrapped
            .strip_prefix("SLOT_SUFFIX=")
            .or_else(|| unwrapped.strip_prefix("slot_suffix="))
            .or_else(|| unwrapped.strip_prefix("androidboot.slot_suffix="))
            && let Some(slot) = Slot::parse(val.trim_matches('"').trim_matches('\''))
        {
            return Some(slot);
        }
    }
    None
}

/// Parse `/sbin/abctl --print_rci` output into structured fields.
pub fn parse_rci_output(stdout: &str) -> RciInfo {
    let mut info = RciInfo {
        raw: stdout.trim().to_string(),
        ..Default::default()
    };
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k_raw, v_raw) = if let Some((k, v)) = trimmed.split_once(':') {
            (k, v)
        } else if let Some((k, v)) = trimmed.split_once('=') {
            (k, v)
        } else {
            let mut parts = trimmed.split_whitespace();
            let Some(k) = parts.next() else { continue };
            let Some(v) = parts.next() else { continue };
            (k, v)
        };
        let leaf = k_raw.trim().rsplit('.').next().unwrap_or(k_raw.trim());
        let key: String = leaf
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let val_tok = v_raw.split_whitespace().next().unwrap_or("");
        let parsed = if let Some(hex_s) = val_tok.strip_prefix("0x").or_else(|| val_tok.strip_prefix("0X")) {
            u32::from_str_radix(hex_s, 16).ok()
        } else {
            val_tok.parse::<u32>().ok()
        };
        let Some(num) = parsed else { continue };
        match key.trim_matches('_') {
            "selected_set" => info.selected_set = Some(num),
            "trial_boot_enable" => info.trial_boot_enable = Some(num),
            "trial_boot_max_attempts" => info.trial_boot_max_attempts = Some(num),
            "trial_boot_failed_attempts" => info.trial_boot_failed_attempts = Some(num),
            "image_set_to_boot" => info.image_set_to_boot = Some(num),
            _ => {}
        }
    }
    info
}

/// Parse Quectel `md5.txt` (`FILE:\update\boot.img:C3B4...`, CRLF + Windows `\`).
pub fn parse_md5_txt(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        let Some(rest) = line.strip_prefix("FILE:") else {
            continue;
        };
        let Some((path_raw, hex_raw)) = rest.rsplit_once(':') else {
            continue;
        };
        let digest = hex_raw.trim().to_ascii_lowercase();
        if digest.len() != 32 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let norm = normalize_rel_path(path_raw);
        if !norm.is_empty() {
            map.insert(norm, digest);
        }
    }
    map
}

fn normalize_rel_path(raw: &str) -> String {
    raw.trim()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

/// Resolve a `rawprogram` `filename` relative to `update/firehose/`, rejecting any traversal
/// escaping outside the firmware package root.
fn resolve_firehose_relpath(raw_filename: &str) -> Result<String, String> {
    let trimmed = raw_filename.trim();
    if trimmed.is_empty() {
        return Err("empty filename".into());
    }
    if trimmed.contains('\0') {
        return Err("filename contains NUL byte".into());
    }
    let slash = trimmed.replace('\\', "/");
    if slash.starts_with('/') || slash.contains(':') {
        return Err(format!("absolute or drive-qualified filename rejected: {trimmed}"));
    }
    let mut stack: Vec<&str> = vec!["update", "firehose"];
    for seg in slash.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(format!("path escapes firmware package root: {trimmed}"));
                }
            }
            part => stack.push(part),
        }
    }
    if stack.is_empty() {
        return Err(format!("filename resolves to package root: {trimmed}"));
    }
    Ok(stack.join("/"))
}

fn xml_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let mut search = tag;
    while let Some(idx) = search.find(&needle) {
        let boundary_ok = idx == 0
            || search.as_bytes()[idx - 1].is_ascii_whitespace()
            || search.as_bytes()[idx - 1] == b'<';
        let after = &search[idx + needle.len()..];
        if boundary_ok {
            let end = after.find('"')?;
            return Some(&after[..end]);
        }
        search = after;
    }
    None
}

/// Parse `update/firehose/rawprogram_nand_p4K_b256K_update.xml`.
pub fn parse_rawprogram_xml(content: &str) -> Result<RawProgramManifest, String> {
    let mut project_name: Option<String> = None;
    let mut entries: Vec<RawProgramEntry> = Vec::new();
    let mut seen_bases: HashSet<String> = HashSet::new();

    let mut rest = content;
    while let Some(start) = rest.find('<') {
        let after_lt = &rest[start + 1..];
        let Some(end) = after_lt.find('>') else {
            break;
        };
        let tag = &after_lt[..end];
        rest = &after_lt[end + 1..];

        let tag_trim = tag.trim();
        if tag_trim.starts_with('!') || tag_trim.starts_with('?') || tag_trim.starts_with('/') {
            continue;
        }
        let tag_name = tag_trim.split_whitespace().next().unwrap_or("");
        if project_name.is_none()
            && let Some(pn) = xml_attr(tag_trim, "c_project_name")
        {
            let clean = pn.trim();
            if !clean.is_empty() {
                project_name = Some(clean.to_string());
            }
        }
        if tag_name != "program" {
            continue;
        }
        let Some(filename_raw) = xml_attr(tag_trim, "filename") else {
            continue;
        };
        if filename_raw.trim().is_empty() {
            continue;
        }
        let Some(label_raw) = xml_attr(tag_trim, "label") else {
            continue;
        };
        let label = label_raw.trim();
        if label.is_empty() {
            continue;
        }
        let zip_relpath = resolve_firehose_relpath(filename_raw)?;
        let base_label = label.strip_suffix("_b").unwrap_or(label).to_string();
        if !seen_bases.insert(base_label.clone()) {
            continue;
        }
        let num_partition_sectors = xml_attr(tag_trim, "num_partition_sectors")
            .and_then(|s| s.trim().parse::<u64>().ok());
        let is_ubi = zip_relpath.to_ascii_lowercase().ends_with(".ubi");
        entries.push(RawProgramEntry {
            base_label,
            zip_relpath,
            is_ubi,
            num_partition_sectors,
        });
    }

    if entries.is_empty() {
        return Err("rawprogram XML contained no flashable <program> entries".into());
    }
    Ok(RawProgramManifest {
        project_name,
        entries,
    })
}

pub fn parse_project_version_file(content: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut rev = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if val.is_empty() {
                continue;
            }
            if key == "project name" {
                name = Some(val.to_string());
            } else if key == "project rev" {
                rev = Some(val.to_string());
            }
        }
    }
    (name, rev)
}

fn lookup_md5(md5s: &HashMap<String, String>, relpath: &str) -> Option<String> {
    if let Some(v) = md5s.get(relpath) {
        return Some(v.clone());
    }
    let lower = relpath.to_ascii_lowercase();
    md5s.iter()
        .find(|(k, _)| k.to_ascii_lowercase() == lower)
        .map(|(_, v)| v.clone())
}

#[allow(clippy::too_many_arguments)]
pub fn build_flash_plan(
    layout: &AbLayout,
    active_slot: Slot,
    scope: FlashScope,
    manifest: &RawProgramManifest,
    md5s: &HashMap<String, String>,
    attached_mtds: &HashSet<u32>,
    allow_no_manifest: bool,
    current_project: Option<&str>,
    current_rev: Option<&str>,
    allow_project_mismatch: bool,
) -> Result<FlashPlan, String> {
    let target_slot = active_slot.other();
    if target_slot == active_slot {
        return Err("safety abort: target slot equals active slot".into());
    }

    let mut warnings = Vec::new();
    if let (Some(pkg_proj), Some(dev_proj)) = (manifest.project_name.as_deref(), current_project)
        && !pkg_proj.eq_ignore_ascii_case(dev_proj)
    {
        if !allow_project_mismatch {
            return Err(format!(
                "firmware project mismatch: package is '{pkg_proj}', device is '{dev_proj}' (pass allowProjectMismatch / --allow-project-mismatch to override)"
            ));
        }
        warnings.push(format!(
            "Project mismatch overridden: package '{pkg_proj}' vs device '{dev_proj}'"
        ));
    }

    let scope_bases = scope.allowed_bases();
    let mut planned = Vec::new();

    for entry in &manifest.entries {
        if is_never_touch_partition(&entry.base_label) {
            continue;
        }
        if !scope_bases.contains(&entry.base_label.as_str()) {
            continue;
        }
        if !is_known_ab_base(&entry.base_label) {
            return Err(format!(
                "safety abort: partition base '{}' is not in the 22-partition A/B allowlist",
                entry.base_label
            ));
        }

        let active_name = active_slot.partition_name(&entry.base_label);
        let target_name = target_slot.partition_name(&entry.base_label);
        if target_name == active_name {
            return Err(format!(
                "safety abort: target partition '{target_name}' matches active slot partition"
            ));
        }
        if is_never_touch_partition(&target_name) {
            return Err(format!(
                "safety abort: target partition '{target_name}' is on the NEVER-TOUCH denylist"
            ));
        }

        let mtd = layout.partitions.get(&target_name).ok_or_else(|| {
            format!(
                "target inactive partition '{target_name}' not found in /proc/mtd"
            )
        })?;

        if attached_mtds.contains(&mtd.num) {
            return Err(format!(
                "safety abort: target /dev/mtd{} ('{target_name}') is currently UBI-attached!",
                mtd.num
            ));
        }

        let expected_md5 = lookup_md5(md5s, &entry.zip_relpath);
        if expected_md5.is_none() {
            if !allow_no_manifest {
                return Err(format!(
                    "MD5 checksum missing in md5.txt for '{}' (partition '{target_name}')",
                    entry.zip_relpath
                ));
            }
            warnings.push(format!(
                "No MD5 entry in md5.txt for '{}' (manifest check overridden)",
                entry.zip_relpath
            ));
        }

        planned.push(PlannedPartition {
            base_label: entry.base_label.clone(),
            target_partition: target_name,
            mtd_num: mtd.num,
            mtd_size: mtd.size,
            erasesize: mtd.erasesize,
            zip_relpath: entry.zip_relpath.clone(),
            expected_md5,
            is_ubi: entry.is_ubi,
            file_size: None,
        });
    }

    if planned.is_empty() {
        return Err(format!(
            "firmware package contained no matching partitions for scope '{}'",
            scope.as_str()
        ));
    }

    planned.sort_by_key(|p| write_order_rank(&p.base_label));

    Ok(FlashPlan {
        active_slot,
        target_slot,
        scope,
        project_name: manifest.project_name.clone(),
        device_project_name: current_project.map(str::to_string),
        device_project_rev: current_rev.map(str::to_string),
        partitions: planned,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Hardware & Filesystem Probing
// ---------------------------------------------------------------------------

pub fn read_proc_mtd() -> Result<Vec<MtdPartition>, String> {
    let raw = fs::read_to_string(crate::paths::p("/proc/mtd"))
        .map_err(|e| format!("read /proc/mtd: {e}"))?;
    Ok(parse_proc_mtd(&raw))
}

pub fn read_attached_ubi_mtds() -> HashSet<u32> {
    let mut set = HashSet::new();
    let dir = crate::paths::p("/sys/class/ubi");
    let Ok(entries) = fs::read_dir(&dir) else {
        return set;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with("ubi") || name.contains('_') {
            continue;
        }
        let mtd_file = e.path().join("mtd_num");
        if let Ok(s) = fs::read_to_string(&mtd_file)
            && let Ok(num) = s.trim().parse::<u32>()
        {
            set.insert(num);
        }
    }
    set
}

pub fn read_device_project_info() -> (Option<String>, Option<String>) {
    fs::read_to_string(crate::paths::p("/etc/quectel-project-version"))
        .map(|s| parse_project_version_file(&s))
        .unwrap_or((None, None))
}

fn run_tool_timeout(prog: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let resolved = crate::paths::program(prog);
    let mut child = Command::new(&resolved)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("exec {prog}: {e}"))?;

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("wait {prog}: {e}")),
        }
    };

    let stdout = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).to_string();

    match status {
        None => Err(format!("{prog} timed out after {}s", timeout.as_secs())),
        Some(st) if st.success() => Ok(stdout),
        Some(st) => {
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            Err(format!("{prog} exited {:?}: {detail}", st.code()))
        }
    }
}

pub fn detect_active_slot() -> Result<Slot, String> {
    let from_abctl = run_tool_timeout("/sbin/abctl", &["--boot_slot"], Duration::from_secs(5))
        .ok()
        .and_then(|s| Slot::parse(&s));
    let from_cmdline = fs::read_to_string(crate::paths::p("/proc/cmdline"))
        .ok()
        .and_then(|s| parse_cmdline_slot(&s));

    match (from_abctl, from_cmdline) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "active slot disagreement: abctl reports {} while /proc/cmdline reports {}",
            a.suffix(),
            b.suffix()
        )),
        (Some(a), _) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(
            "unable to determine active boot slot from /sbin/abctl --boot_slot or /proc/cmdline"
                .into(),
        ),
    }
}

pub fn read_ab_unbootable(slot: Slot) -> Option<bool> {
    let idx = slot.index().to_string();
    let out = run_tool_timeout("/sbin/abctl", &["--get_unbootable", &idx], Duration::from_secs(5)).ok()?;
    match out.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub fn read_trialboot_status() -> Option<bool> {
    let out = run_tool_timeout("/sbin/abctl", &["--get_trialboot_status"], Duration::from_secs(5)).ok()?;
    match out.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub fn read_rci_info() -> Option<RciInfo> {
    let out = run_tool_timeout("/sbin/abctl", &["--print_rci"], Duration::from_secs(5)).ok()?;
    Some(parse_rci_output(&out))
}

fn statvfs_avail_bytes(path: &str) -> Option<u64> {
    let mapped = crate::paths::p(path);
    let c = CString::new(Path::new(&mapped).as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    let bytes = (st.f_bavail as u128).saturating_mul(st.f_frsize as u128);
    Some(bytes.min(u64::MAX as u128) as u64)
}

fn statvfs_avail_mib(path: &str) -> Option<u64> {
    statvfs_avail_bytes(path).map(|b| b / (1024 * 1024))
}

fn detect_vendor_ab_init_enabled() -> (bool, bool) {
    let dir = crate::paths::p("/etc/rc.d");
    let Ok(entries) = fs::read_dir(&dir) else {
        return (false, false);
    };
    let mut ab_updater = false;
    let mut mirror_copy = false;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with('S') {
            continue;
        }
        if name.contains("ab-updater") {
            ab_updater = true;
        }
        if name.contains("mirror_copy") {
            mirror_copy = true;
        }
    }
    (ab_updater, mirror_copy)
}

pub fn detect_conflicting_vendor_ab_procs() -> Vec<String> {
    let mut found = Vec::new();
    let proc_dir = crate::paths::p("/proc");
    let Ok(entries) = fs::read_dir(&proc_dir) else {
        return found;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = fs::read_to_string(e.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline_raw = fs::read(e.path().join("cmdline")).unwrap_or_default();
        let argv0 = cmdline_raw
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).to_string())
            .unwrap_or_default();
        let argv0_base = Path::new(&argv0)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        for target in ["mirror_copy", "ab-updater"] {
            if comm == target || argv0_base == target {
                found.push(format!("{target} (pid {name})"));
                break;
            }
        }
    }
    found.sort();
    found
}

pub fn load_persisted_state() -> PersistedAbFlashState {
    crate::state::load_json_or_default(AB_STATE_PATH)
}

pub fn save_persisted_state(st: &PersistedAbFlashState) -> Result<(), String> {
    crate::state::save_json_atomic(AB_STATE_PATH, st, 0o600)
}

pub fn probe_ab_status(job: AbJobProgress) -> AbStatusResponse {
    let (project_name, project_rev) = read_device_project_info();
    let tmp_avail_mib = statvfs_avail_mib("/tmp");
    let (ab_updater_enabled, mirror_copy_enabled) = detect_vendor_ab_init_enabled();
    let last_state = load_persisted_state();

    let mtds = match read_proc_mtd() {
        Ok(m) => m,
        Err(e) => {
            return AbStatusResponse {
                supported: false,
                unsupported_reason: Some(e),
                total_mtds: 0,
                ab_base_count: 0,
                active_slot: detect_active_slot().ok(),
                inactive_slot: None,
                slot_a_unbootable: None,
                slot_b_unbootable: None,
                trial_boot_active: None,
                rci: None,
                project_name,
                project_rev,
                tmp_avail_mib,
                ab_updater_enabled,
                mirror_copy_enabled,
                job,
                last_state,
            };
        }
    };

    let layout = match detect_ab_layout(&mtds) {
        Ok(l) => l,
        Err(reason) => {
            let active = detect_active_slot().ok();
            return AbStatusResponse {
                supported: false,
                unsupported_reason: Some(reason),
                total_mtds: mtds.len(),
                ab_base_count: 0,
                active_slot: active,
                inactive_slot: active.map(Slot::other),
                slot_a_unbootable: read_ab_unbootable(Slot::A),
                slot_b_unbootable: read_ab_unbootable(Slot::B),
                trial_boot_active: read_trialboot_status(),
                rci: read_rci_info(),
                project_name,
                project_rev,
                tmp_avail_mib,
                ab_updater_enabled,
                mirror_copy_enabled,
                job,
                last_state,
            };
        }
    };

    let active_slot = detect_active_slot().ok();
    AbStatusResponse {
        supported: true,
        unsupported_reason: None,
        total_mtds: layout.total_mtds,
        ab_base_count: layout.ab_bases.len(),
        active_slot,
        inactive_slot: active_slot.map(Slot::other),
        slot_a_unbootable: read_ab_unbootable(Slot::A),
        slot_b_unbootable: read_ab_unbootable(Slot::B),
        trial_boot_active: read_trialboot_status(),
        rci: read_rci_info(),
        project_name,
        project_rev,
        tmp_avail_mib,
        ab_updater_enabled,
        mirror_copy_enabled,
        job,
        last_state,
    }
}

// ---------------------------------------------------------------------------
// Package Inspection (Zip or Unpacked Directory, 100% Read-Only)
// ---------------------------------------------------------------------------

enum PackageSource {
    Zip {
        path: PathBuf,
        /// Lowercase normalized path -> exact entry name inside zip + uncompressed size.
        entries: HashMap<String, (String, u64)>,
    },
    Dir(PathBuf),
}

pub fn validate_source_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("firmware package path is required".into());
    }
    if trimmed.contains('\0') {
        return Err("firmware package path contains NUL byte".into());
    }
    let path = PathBuf::from(trimmed);
    for c in path.components() {
        if matches!(c, Component::ParentDir) {
            return Err("firmware package path must not contain '..' traversal".into());
        }
    }
    if !path.exists() {
        return Err(format!("firmware package path not found: {}", path.display()));
    }
    Ok(path)
}

/// Strict path confinement for HTTP API endpoints (`inspect` and `flash`):
/// rejects symlinks, non-regular/non-dir files (device nodes, FIFOs), and any
/// canonical path outside `/tmp/` or `/usrdata/` (respecting `crate::paths::p`).
pub fn validate_http_source_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("firmware package path is required".into());
    }
    if trimmed.contains('\0') {
        return Err("firmware package path contains NUL byte".into());
    }
    if !trimmed.starts_with('/') {
        return Err("firmware package path must be an absolute path under /tmp/ or /usrdata/".into());
    }
    let raw_path = PathBuf::from(trimmed);
    for c in raw_path.components() {
        if matches!(c, Component::ParentDir) {
            return Err("firmware package path must not contain '..' traversal".into());
        }
    }

    let mapped = PathBuf::from(crate::paths::p(trimmed));
    let sym_meta = fs::symlink_metadata(&mapped)
        .map_err(|_| format!("firmware package path not found: {trimmed}"))?;
    if sym_meta.file_type().is_symlink() {
        return Err("firmware package path must not be a symlink".into());
    }
    if !(sym_meta.file_type().is_file() || sym_meta.file_type().is_dir()) {
        return Err("firmware package path must be a regular file or directory".into());
    }

    let canon = fs::canonicalize(&mapped)
        .map_err(|e| format!("failed to canonicalize firmware package path: {e}"))?;
    let canon_meta = fs::metadata(&canon)
        .map_err(|e| format!("failed to stat firmware package path: {e}"))?;
    if !(canon_meta.is_file() || canon_meta.is_dir()) {
        return Err("firmware package path must be a regular file or directory".into());
    }

    let allowed_roots: Vec<PathBuf> = ["/tmp", "/usrdata"]
        .into_iter()
        .map(|root| {
            let p = PathBuf::from(crate::paths::p(root));
            fs::canonicalize(&p).unwrap_or(p)
        })
        .collect();

    if !allowed_roots
        .iter()
        .any(|root| canon.starts_with(root) && canon != *root)
    {
        return Err(
            "firmware package path must reside strictly inside /tmp/ or /usrdata/".into(),
        );
    }

    Ok(canon)
}

fn parse_unzip_list(stdout: &str) -> HashMap<String, (String, u64)> {
    let mut map = HashMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Archive:")
            || trimmed.starts_with("Length")
            || trimmed.starts_with("---")
        {
            continue;
        }
        // Info-ZIP `unzip -l` format: `<len>  <date> <time>   <name>`
        let mut parts = trimmed.splitn(4, char::is_whitespace);
        let Some(len_s) = parts.next() else { continue };
        let Ok(len) = len_s.parse::<u64>() else { continue };
        let rest = parts.collect::<Vec<_>>().join(" ");
        let mut rest_parts = rest.trim_start().splitn(3, char::is_whitespace);
        let Some(_date) = rest_parts.next() else { continue };
        let Some(_time) = rest_parts.next() else { continue };
        let Some(name_raw) = rest_parts.next() else { continue };
        let name = name_raw.trim_start();
        if name.is_empty() || name.ends_with('/') {
            continue;
        }
        let norm = normalize_rel_path(name).to_ascii_lowercase();
        map.insert(norm, (name.to_string(), len));
    }
    map
}

impl PackageSource {
    fn open(path: &Path) -> Result<Self, String> {
        if path.is_dir() {
            return Ok(Self::Dir(path.to_path_buf()));
        }
        let p_str = path
            .to_str()
            .ok_or_else(|| "firmware package path is not valid UTF-8".to_string())?;
        let listing = run_tool_timeout("/usr/bin/unzip", &["-l", p_str], Duration::from_secs(30))
            .map_err(|e| format!("failed to list zip archive {}: {e}", path.display()))?;
        let entries = parse_unzip_list(&listing);
        if entries.is_empty() {
            return Err(format!("zip archive {} contains no files", path.display()));
        }
        Ok(Self::Zip {
            path: path.to_path_buf(),
            entries,
        })
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Zip { .. } => "zip",
            Self::Dir(_) => "directory",
        }
    }

    /// Detect optional top-level directory prefix inside a zip or unpacked folder (e.g. `RM551EGL.../md5.txt`).
    fn find_entry_by_suffix(&self, suffix_lower: &str) -> Option<(String, String)> {
        match self {
            Self::Zip { entries, .. } => {
                // Exact match first
                if let Some((orig, _)) = entries.get(suffix_lower) {
                    return Some((String::new(), orig.clone()));
                }
                // One top-level folder prefix `<prefix>/<suffix>`
                let needle = format!("/{suffix_lower}");
                for (norm, (orig, _)) in entries {
                    if let Some(prefix) = norm.strip_suffix(&needle)
                        && !prefix.contains('/')
                    {
                        return Some((format!("{prefix}/"), orig.clone()));
                    }
                }
                None
            }
            Self::Dir(root) => {
                let direct = root.join(suffix_lower);
                if direct.is_file() {
                    return Some((String::new(), suffix_lower.to_string()));
                }
                // Check one level of nested subfolder
                if let Ok(rd) = fs::read_dir(root) {
                    for e in rd.flatten() {
                        if e.path().is_dir() {
                            let cand = e.path().join(suffix_lower);
                            if cand.is_file() {
                                let pfx = format!("{}/", e.file_name().to_string_lossy());
                                return Some((pfx.clone(), format!("{pfx}{suffix_lower}")));
                            }
                        }
                    }
                }
                None
            }
        }
    }

    fn find_rawprogram(&self) -> Result<(String, String), String> {
        match self {
            Self::Zip { entries, .. } => {
                let mut candidates: Vec<(String, String)> = Vec::new();
                for (norm, (orig, _)) in entries {
                    let fname = norm.rsplit('/').next().unwrap_or("");
                    if fname.starts_with("rawprogram_nand_") && fname.ends_with("_update.xml") {
                        let prefix = norm
                            .split_once("update/firehose/")
                            .map(|(p, _)| p.to_string())
                            .unwrap_or_default();
                        candidates.push((prefix, orig.clone()));
                    }
                }
                candidates.sort_by(|a, b| a.1.cmp(&b.1));
                candidates
                    .into_iter()
                    .find(|(_, orig)| orig.to_ascii_lowercase().contains("p4k_b256k"))
                    .or_else(|| {
                        entries
                            .iter()
                            .find(|(n, _)| {
                                let f = n.rsplit('/').next().unwrap_or("");
                                f.starts_with("rawprogram_nand_") && f.ends_with("_update.xml")
                            })
                            .map(|(n, (orig, _))| {
                                let pfx = n
                                    .split_once("update/firehose/")
                                    .map(|(p, _)| p.to_string())
                                    .unwrap_or_default();
                                (pfx, orig.clone())
                            })
                    })
                    .ok_or_else(|| {
                        "could not find update/firehose/rawprogram_nand_*_update.xml in zip archive"
                            .into()
                    })
            }
            Self::Dir(root) => {
                let mut search_roots = vec![(String::new(), root.clone())];
                if let Ok(rd) = fs::read_dir(root) {
                    for e in rd.flatten() {
                        if e.path().is_dir() {
                            let pfx = format!("{}/", e.file_name().to_string_lossy());
                            search_roots.push((pfx, e.path()));
                        }
                    }
                }
                for (pfx, base) in search_roots {
                    let fh = base.join("update/firehose");
                    let Ok(rd) = fs::read_dir(&fh) else { continue };
                    let mut matches: Vec<String> = rd
                        .flatten()
                        .filter_map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let low = name.to_ascii_lowercase();
                            if low.starts_with("rawprogram_nand_") && low.ends_with("_update.xml") {
                                Some(name)
                            } else {
                                None
                            }
                        })
                        .collect();
                    matches.sort();
                    if let Some(chosen) = matches
                        .iter()
                        .find(|m| m.to_ascii_lowercase().contains("p4k_b256k"))
                        .or_else(|| matches.first())
                    {
                        return Ok((pfx.clone(), format!("{pfx}update/firehose/{chosen}")));
                    }
                }
                Err("could not find update/firehose/rawprogram_nand_*_update.xml in firmware directory".into())
            }
        }
    }

    fn read_text(&self, rel: &str) -> Result<String, String> {
        match self {
            Self::Zip { path, .. } => {
                let p_str = path.to_str().ok_or("non-UTF-8 zip path")?;
                run_tool_timeout("/usr/bin/unzip", &["-p", p_str, rel], Duration::from_secs(30))
            }
            Self::Dir(root) => fs::read_to_string(root.join(rel))
                .map_err(|e| format!("read {}: {e}", root.join(rel).display())),
        }
    }

    fn resolve_image_entry(&self, prefix: &str, relpath: &str) -> Result<(String, Option<u64>), String> {
        let joined = format!("{prefix}{relpath}");
        match self {
            Self::Zip { entries, .. } => {
                let key = joined.to_ascii_lowercase();
                if let Some((orig, sz)) = entries.get(&key) {
                    return Ok((orig.clone(), Some(*sz)));
                }
                Err(format!("image '{joined}' missing from zip archive"))
            }
            Self::Dir(root) => {
                let full = root.join(&joined);
                if full.is_file() {
                    let sz = fs::metadata(&full).ok().map(|m| m.len());
                    return Ok((joined, sz));
                }
                // Case-insensitive lookup inside parent dir (e.g. NON-HLOS.ubi)
                if let (Some(parent), Some(fname)) = (full.parent(), full.file_name())
                    && let Ok(rd) = fs::read_dir(parent)
                {
                    let want = fname.to_string_lossy().to_ascii_lowercase();
                    for e in rd.flatten() {
                        if e.file_name().to_string_lossy().to_ascii_lowercase() == want
                            && e.path().is_file()
                        {
                            let rel_found = e
                                .path()
                                .strip_prefix(root)
                                .ok()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or(joined);
                            let sz = e.metadata().ok().map(|m| m.len());
                            return Ok((rel_found, sz));
                        }
                    }
                }
                Err(format!("image '{}' missing from firmware directory", full.display()))
            }
        }
    }
}

pub fn inspect_package(
    source_path: &Path,
    scope: FlashScope,
    allow_project_mismatch: bool,
    allow_no_manifest: bool,
) -> Result<InspectReport, String> {
    let mtds = read_proc_mtd()?;
    let layout = detect_ab_layout(&mtds)?;
    let active_slot = detect_active_slot()?;
    let attached_mtds = read_attached_ubi_mtds();
    let (dev_proj, dev_rev) = read_device_project_info();

    let pkg = PackageSource::open(source_path)?;
    let (prefix, rawprogram_file) = pkg.find_rawprogram()?;
    let raw_xml = pkg.read_text(&rawprogram_file)?;
    let manifest = parse_rawprogram_xml(&raw_xml)?;

    let md5s = if let Some((_, md5_entry)) = pkg.find_entry_by_suffix("md5.txt") {
        let txt = pkg.read_text(&md5_entry)?;
        parse_md5_txt(&txt)
    } else {
        HashMap::new()
    };

    let mut plan = build_flash_plan(
        &layout,
        active_slot,
        scope,
        &manifest,
        &md5s,
        &attached_mtds,
        allow_no_manifest,
        dev_proj.as_deref(),
        dev_rev.as_deref(),
        allow_project_mismatch,
    )?;

    // Resolve each image entry in the package and check uncompressed size <= mtd.size
    for part in &mut plan.partitions {
        let (_, sz) = pkg.resolve_image_entry(&prefix, &part.zip_relpath)?;
        if let Some(bytes) = sz
            && bytes > part.mtd_size
        {
            return Err(format!(
                "image '{}' ({bytes} bytes) exceeds target partition '{}' size ({} bytes)",
                part.zip_relpath, part.target_partition, part.mtd_size
            ));
        }
        part.file_size = sz;
    }

    let tmp_avail_mib = statvfs_avail_mib("/tmp");
    let tmp_space_ok = match &pkg {
        PackageSource::Dir(_) => true,
        PackageSource::Zip { .. } => tmp_avail_mib.is_none_or(|m| m >= MIN_STAGE_FREE_MIB),
    };
    if !tmp_space_ok {
        plan.warnings.push(format!(
            "/tmp has {} MiB free (recommended >= {MIN_STAGE_FREE_MIB} MiB for single-image zip staging)",
            tmp_avail_mib.unwrap_or(0)
        ));
    }

    Ok(InspectReport {
        source_path: source_path.display().to_string(),
        source_kind: pkg.kind_label().to_string(),
        rawprogram_file,
        md5_entries: md5s.len(),
        tmp_avail_mib,
        tmp_space_ok,
        plan,
    })
}

// ---------------------------------------------------------------------------
// Exclusive Process Lock & Cleanup Guards
// ---------------------------------------------------------------------------

struct AbFlockGuard {
    file: fs::File,
}

impl Drop for AbFlockGuard {
    fn drop(&mut self) {
        // Explicitly unlock before closing: in a multi-threaded daemon (or
        // parallel test suite) another thread may be mid-fork() before
        // O_CLOEXEC takes effect, keeping the open file description alive
        // briefly after close(2). LOCK_UN releases the lock immediately.
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn acquire_ab_flock() -> Result<AbFlockGuard, String> {
    let lock_path = crate::paths::p(AB_LOCK_PATH);
    if let Some(parent) = Path::new(&lock_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|e| format!("open {lock_path}: {e}"))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Err("another A/B firmware flash or slot switch is already in progress".into());
        }
        return Err(format!("flock {lock_path}: {err}"));
    }
    Ok(AbFlockGuard { file })
}

struct RemoveFileGuard(Option<PathBuf>);
impl Drop for RemoveFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

struct RemoveDirGuard(PathBuf);
impl Drop for RemoveDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct UbiDetachGuard(Option<u32>);
impl Drop for UbiDetachGuard {
    fn drop(&mut self) {
        if let Some(dev) = self.0.take() {
            let d = dev.to_string();
            let _ = run_tool_timeout("/usr/sbin/ubidetach", &["-d", &d], Duration::from_secs(15));
        }
    }
}

struct UmountGuard(Option<String>);
impl Drop for UmountGuard {
    fn drop(&mut self) {
        if let Some(mnt) = self.0.take() {
            let _ = run_tool_timeout("sync", &[], Duration::from_secs(10));
            for _ in 0..3 {
                if run_tool_timeout("umount", &[&mnt], Duration::from_secs(15)).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let _ = run_tool_timeout("umount", &["-l", &mnt], Duration::from_secs(10));
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming Extraction, Hashing, Flashing & Verification
// ---------------------------------------------------------------------------

struct StreamedImage {
    /// Path on disk when staged (None for zip dry-run).
    disk_path: Option<PathBuf>,
    /// True if `disk_path` is a temporary extracted file that must be deleted after use.
    is_staged_temp: bool,
    size: u64,
    md5_hex: String,
    sha256_hex: String,
    magic4: [u8; 4],
}

fn stream_hash_and_maybe_stage<R: Read>(
    reader: &mut R,
    out_file: Option<&mut fs::File>,
    max_bytes: u64,
    deadline: Option<(std::os::fd::RawFd, std::time::Instant)>,
) -> Result<(u64, String, String, [u8; 4]), String> {
    let mut md5 = md5::Md5::new();
    let mut sha = Sha256::new();
    let mut magic4 = [0u8; 4];
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    let mut out = out_file;

    loop {
        if let Some((fd, dl)) = deadline {
            loop {
                let now = std::time::Instant::now();
                if now >= dl {
                    return Err(format!(
                        "unzip stream timed out after {}s",
                        UNZIP_STREAM_TIMEOUT.as_secs()
                    ));
                }
                let rem_ms = dl
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(500) as libc::c_int;
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd, 1, rem_ms.max(1)) };
                if rc > 0 {
                    break;
                }
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(format!("poll image stream: {err}"));
                }
            }
        }
        let n = reader.read(&mut buf).map_err(|e| format!("read image stream: {e}"))?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if total < 4 {
            let need = (4 - total) as usize;
            let take = need.min(n);
            magic4[total as usize..total as usize + take].copy_from_slice(&chunk[..take]);
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(format!(
                "image stream exceeded target MTD capacity ({max_bytes} bytes)"
            ));
        }
        md5.update(chunk);
        sha.update(chunk);
        if let Some(f) = out.as_deref_mut() {
            f.write_all(chunk).map_err(|e| format!("write staged image: {e}"))?;
        }
    }
    if let Some(f) = out {
        f.flush().map_err(|e| format!("flush staged image: {e}"))?;
    }
    if total == 0 {
        return Err("image file is empty (0 bytes)".into());
    }
    Ok((
        total,
        hex::encode(md5.finalize()),
        hex::encode(sha.finalize()),
        magic4,
    ))
}

fn prepare_single_image(
    pkg: &PackageSource,
    entry_name: &str,
    stage_dir: &Path,
    part: &PlannedPartition,
    need_disk_file: bool,
) -> Result<StreamedImage, String> {
    match pkg {
        PackageSource::Dir(root) => {
            let full = root.join(entry_name);
            let mut f = fs::File::open(&full)
                .map_err(|e| format!("open {}: {e}", full.display()))?;
            let (size, md5_hex, sha256_hex, magic4) =
                stream_hash_and_maybe_stage(&mut f, None, part.mtd_size, None)?;
            Ok(StreamedImage {
                disk_path: Some(full),
                is_staged_temp: false,
                size,
                md5_hex,
                sha256_hex,
                magic4,
            })
        }
        PackageSource::Zip { path, .. } => {
            let p_str = path.to_str().ok_or("non-UTF-8 zip path")?;
            let mut child = Command::new(crate::paths::program("/usr/bin/unzip"))
                .args(["-p", p_str, entry_name])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn unzip -p for {entry_name}: {e}"))?;

            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| "unzip -p missing stdout pipe".to_string())?;
            let mut stderr = child.stderr.take();
            let err_thread = std::thread::spawn(move || {
                let mut s = Vec::new();
                if let Some(p) = stderr.as_mut() {
                    let _ = p.read_to_end(&mut s);
                }
                s
            });

            let staged_path = if need_disk_file {
                Some(stage_dir.join(format!("{}.img", part.target_partition)))
            } else {
                None
            };
            let mut tmp_file = match &staged_path {
                Some(sp) => {
                    let _ = fs::remove_file(sp);
                    match crate::state::create_private_tmp(sp, 0o600) {
                        Ok(f) => Some(f),
                        Err(e) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            drop(stdout);
                            let _ = err_thread.join();
                            return Err(format!("create staged file {}: {e}", sp.display()));
                        }
                    }
                }
                None => None,
            };

            let deadline = std::time::Instant::now() + UNZIP_STREAM_TIMEOUT;
            let stdout_fd = stdout.as_raw_fd();
            let stream_res = stream_hash_and_maybe_stage(
                &mut stdout,
                tmp_file.as_mut(),
                part.mtd_size,
                Some((stdout_fd, deadline)),
            );
            drop(tmp_file);
            drop(stdout);

            if let Err(e) = stream_res {
                let _ = child.kill();
                let _ = child.wait();
                let _ = err_thread.join();
                if let Some(sp) = &staged_path {
                    let _ = fs::remove_file(sp);
                }
                return Err(e);
            }

            let status = loop {
                match child.try_wait() {
                    Ok(Some(st)) => break Some(st),
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = err_thread.join();
                        if let Some(sp) = &staged_path {
                            let _ = fs::remove_file(sp);
                        }
                        return Err(format!("wait unzip -p: {e}"));
                    }
                }
            };
            let err_bytes = err_thread.join().unwrap_or_default();

            let (size, md5_hex, sha256_hex, magic4) = stream_res.unwrap();
            let Some(status) = status else {
                if let Some(sp) = &staged_path {
                    let _ = fs::remove_file(sp);
                }
                return Err(format!(
                    "unzip -p {entry_name} timed out after {}s",
                    UNZIP_STREAM_TIMEOUT.as_secs()
                ));
            };
            if !status.success() {
                if let Some(sp) = &staged_path {
                    let _ = fs::remove_file(sp);
                }
                return Err(format!(
                    "unzip -p {entry_name} failed ({:?}): {}",
                    status.code(),
                    String::from_utf8_lossy(&err_bytes).trim()
                ));
            }
            Ok(StreamedImage {
                disk_path: staged_path,
                is_staged_temp: need_disk_file,
                size,
                md5_hex,
                sha256_hex,
                magic4,
            })
        }
    }
}

fn sha256_first_n_bytes(path: &Path, limit: u64) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("open {} for verify: {e}", path.display()))?;
    let mut sha = Sha256::new();
    let mut remaining = limit;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = (remaining as usize).min(buf.len());
        let n = f
            .read(&mut buf[..want])
            .map_err(|e| format!("read {} for verify: {e}", path.display()))?;
        if n == 0 {
            return Err(format!(
                "short read-back on {}: expected {limit} bytes, got {}",
                path.display(),
                limit - remaining
            ));
        }
        sha.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hex::encode(sha.finalize()))
}

fn pick_unused_ubi_dev() -> u32 {
    let sys_ubi = crate::paths::p("/sys/class/ubi");
    for cand in 7u32..=15 {
        let sys_p = PathBuf::from(&sys_ubi).join(format!("ubi{cand}"));
        let dev_p = PathBuf::from(crate::paths::p(&format!("/dev/ubi{cand}")));
        if !sys_p.exists() && !dev_p.exists() {
            return cand;
        }
    }
    7
}

fn check_usrdata_space_for_cellcored() -> Result<u64, String> {
    let src_path = PathBuf::from(crate::paths::p("/usr/sbin/cellcored"));
    let src_meta = fs::metadata(&src_path).map_err(|_| {
        format!(
            "cannot preserve CellCore: {} does not exist",
            src_path.display()
        )
    })?;
    if !src_meta.is_file() {
        return Err(format!(
            "cannot preserve CellCore: {} is not a regular file",
            src_path.display()
        ));
    }
    let cellcored_size = src_meta.len();
    let need = cellcored_size.saturating_add(FLASH_SPACE_HEADROOM_BYTES);
    let usrdata_dir = PathBuf::from(crate::paths::p("/usrdata"));
    let avail = statvfs_avail_bytes("/usrdata").ok_or_else(|| {
        format!(
            "cannot preserve CellCore: unable to check available space on {}",
            usrdata_dir.display()
        )
    })?;
    if avail < need {
        return Err(format!(
            "insufficient /usrdata space to preserve CellCore: {} bytes available, need at least {} bytes (cellcored {} + 16 MiB headroom)",
            avail, need, cellcored_size
        ));
    }
    Ok(cellcored_size)
}

fn stage_cellcored_to_usrdata(log: &mut impl FnMut(&str)) -> Result<(), String> {
    let _ = check_usrdata_space_for_cellcored()?;
    let src_path = PathBuf::from(crate::paths::p("/usr/sbin/cellcored"));
    let dst_dir = PathBuf::from(crate::paths::p("/usrdata/bin"));
    fs::create_dir_all(&dst_dir).map_err(|e| format!("mkdir {}: {e}", dst_dir.display()))?;
    let dst_path = dst_dir.join("cellcored");
    let tmp_path = dst_dir.join(format!(".cellcored.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp_path);

    let mut src_f = fs::File::open(&src_path).map_err(|e| format!("open {}: {e}", src_path.display()))?;
    let mut tmp_f = crate::state::create_private_tmp(&tmp_path, 0o755)
        .map_err(|e| format!("create {}: {e}", tmp_path.display()))?;
    let mut guard = RemoveFileGuard(Some(tmp_path.clone()));

    let mut src_sha = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let n = src_f.read(&mut buf).map_err(|e| format!("read cellcored: {e}"))?;
        if n == 0 {
            break;
        }
        src_sha.update(&buf[..n]);
        tmp_f
            .write_all(&buf[..n])
            .map_err(|e| format!("write staged /usrdata/bin/cellcored: {e}"))?;
        copied += n as u64;
    }
    tmp_f.sync_all().map_err(|e| format!("sync staged cellcored: {e}"))?;
    drop(tmp_f);

    let expected = hex::encode(src_sha.finalize());
    let actual = sha256_first_n_bytes(&tmp_path, copied)?;
    if actual != expected {
        return Err("SHA-256 mismatch while staging /usrdata/bin/cellcored".into());
    }
    crate::state::atomic_rename_file(&tmp_path, &dst_path)?;
    guard.0 = None;
    log(&format!(
        "Staged verified /usrdata/bin/cellcored ({copied} bytes, sha256={}…)",
        &actual[..12]
    ));
    Ok(())
}

fn inject_overlay_hooks_into_mounted_rootfs(
    mnt: &Path,
    log: &mut impl FnMut(&str),
) -> Result<(), String> {
    let rcd_03 = mnt.join("etc/rc.d/S03cellcore-overlay");
    let legacy_13 = mnt.join("etc/rc.d/S13mount-fix-final");
    if rcd_03.exists() || rcd_03.symlink_metadata().is_ok() || legacy_13.exists() {
        log("Inactive rootfs already contains overlay hooks; preserving as-is");
        return Ok(());
    }
    stage_cellcored_to_usrdata(log)?;

    let init03 = mnt.join("etc/init.d/cellcore-overlay");
    let init13 = mnt.join("etc/init.d/cellcore-overlay-rw");
    let rcd13 = mnt.join("etc/rc.d/S13cellcore-overlay-rw");

    if let Some(parent) = init03.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    if let Some(parent) = rcd_03.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }

    crate::state::atomic_write(&init03, OVERLAY_INIT_03.as_bytes(), 0o755)?;
    crate::state::atomic_write(&init13, OVERLAY_INIT_13.as_bytes(), 0o755)?;

    let _ = fs::remove_file(&rcd_03);
    let _ = fs::remove_file(&rcd13);
    std::os::unix::fs::symlink("../init.d/cellcore-overlay", &rcd_03)
        .map_err(|e| format!("symlink {}: {e}", rcd_03.display()))?;
    std::os::unix::fs::symlink("../init.d/cellcore-overlay-rw", &rcd13)
        .map_err(|e| format!("symlink {}: {e}", rcd13.display()))?;

    log("Injected clean-room CellCore overlay hooks into stock inactive rootfs");
    Ok(())
}

fn flash_ubi_partition(
    part: &PlannedPartition,
    img_path: &Path,
    preserve_cellcore: bool,
    log: &mut impl FnMut(&str),
) -> Result<(), String> {
    let mtd_dev = crate::paths::p(&format!("/dev/mtd{}", part.mtd_num));
    let img_str = img_path.to_str().ok_or("non-UTF-8 image path")?;

    log(&format!(
        "Running ubiformat {mtd_dev} -y -f {} ({})...",
        img_path.file_name().unwrap_or_default().to_string_lossy(),
        part.target_partition
    ));
    run_tool_timeout(
        "/usr/sbin/ubiformat",
        &[&mtd_dev, "-y", "-f", img_str],
        Duration::from_secs(600),
    )?;

    let ubi_dev = pick_unused_ubi_dev();
    let mtd_num_s = part.mtd_num.to_string();
    let ubi_dev_s = ubi_dev.to_string();
    let ubi_ctrl = crate::paths::p("/dev/ubi_ctrl");

    log(&format!(
        "Verifying UBI volume on mtd{} via ubiattach (ubi{ubi_dev})...",
        part.mtd_num
    ));
    run_tool_timeout(
        "/usr/sbin/ubiattach",
        &["-m", &mtd_num_s, "-d", &ubi_dev_s, "-b", "10", &ubi_ctrl],
        Duration::from_secs(60),
    )?;
    let mut detach_guard = UbiDetachGuard(Some(ubi_dev));

    run_tool_timeout("/usr/sbin/ubinfo", &["-d", &ubi_dev_s], Duration::from_secs(15))
        .map_err(|e| format!("ubinfo verification failed on mtd{}: {e}", part.mtd_num))?;

    if part.base_label == "system" && preserve_cellcore {
        let mnt_str = crate::paths::p(SYSMNT_DIR);
        fs::create_dir_all(&mnt_str).map_err(|e| format!("mkdir {mnt_str}: {e}"))?;
        let ubi_vol = crate::paths::p(&format!("/dev/ubi{ubi_dev}_0"));
        run_tool_timeout(
            "mount",
            &["-t", "ubifs", &ubi_vol, &mnt_str],
            Duration::from_secs(30),
        )?;
        let mut umount_guard = UmountGuard(Some(mnt_str.clone()));
        let inject_res = inject_overlay_hooks_into_mounted_rootfs(Path::new(&mnt_str), log);
        // Explicitly sync + umount before checking result so mount is always released cleanly.
        let _ = run_tool_timeout("sync", &[], Duration::from_secs(10));
        let mut unmounted = false;
        for _ in 0..3 {
            if run_tool_timeout("umount", &[&mnt_str], Duration::from_secs(15)).is_ok() {
                unmounted = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if unmounted {
            umount_guard.0 = None;
        }
        drop(umount_guard);
        let _ = fs::remove_dir(&mnt_str);
        inject_res?;
    }

    run_tool_timeout("/usr/sbin/ubidetach", &["-d", &ubi_dev_s], Duration::from_secs(20))?;
    detach_guard.0 = None;
    log(&format!("Verified UBI partition '{}' (mtd{})", part.target_partition, part.mtd_num));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flash_raw_mtd_partition(
    part: &PlannedPartition,
    img_path: &Path,
    img_size: u64,
    expected_sha256: &str,
    stage_dir: &Path,
    verify_readback: bool,
    remove_img_after_flash: bool,
    log: &mut impl FnMut(&str),
) -> Result<(), String> {
    let mtd_dev = crate::paths::p(&format!("/dev/mtd{}", part.mtd_num));
    let img_str = img_path.to_str().ok_or("non-UTF-8 image path")?;
    let mtdimg_bin = crate::paths::program("/usr/bin/mtdimg");

    if Path::new(&mtdimg_bin).exists() {
        log(&format!(
            "Flashing '{}' (mtd{}) via mtdimg ({img_size} bytes)...",
            part.target_partition, part.mtd_num
        ));
        run_tool_timeout(
            "/usr/bin/mtdimg",
            &["--flash", &part.target_partition, img_str],
            Duration::from_secs(300),
        )?;
    } else {
        log(&format!(
            "Flashing '{}' (mtd{}) via flash_erase + nandwrite ({img_size} bytes)...",
            part.target_partition, part.mtd_num
        ));
        run_tool_timeout(
            "/usr/sbin/flash_erase",
            &[&mtd_dev, "0", "0"],
            Duration::from_secs(180),
        )?;
        run_tool_timeout(
            "/usr/sbin/nandwrite",
            &["-p", &mtd_dev, img_str],
            Duration::from_secs(300),
        )?;
    }

    // Free the staged zip temp file BEFORE reading back from NAND so peak /tmp
    // tmpfs usage stays at 1x image size instead of 2x (never delete source files
    // when flashing from an unpacked directory!).
    if remove_img_after_flash {
        let _ = fs::remove_file(img_path);
    }

    if verify_readback {
        let verify_path = stage_dir.join(format!(".verify.{}", part.target_partition));
        let _ = fs::remove_file(&verify_path);
        let _verify_guard = RemoveFileGuard(Some(verify_path.clone()));
        let v_str = verify_path.to_str().ok_or("non-UTF-8 verify path")?;
        let len_s = img_size.to_string();
        // Prefer Quectel's native `/usr/bin/mtdimg --read` (256 KiB bulk reads, ~24x faster
        // on Qualcomm QPIC NAND than `nanddump`'s 4 KiB page-by-page reads).
        if Path::new(&mtdimg_bin).exists() {
            run_tool_timeout(
                "/usr/bin/mtdimg",
                &["-n", &len_s, "--read", &part.target_partition, v_str],
                Duration::from_secs(300),
            )?;
        } else {
            run_tool_timeout(
                "/usr/sbin/nanddump",
                &["-q", "--bb=skipbad", "-l", &len_s, "-f", v_str, &mtd_dev],
                Duration::from_secs(600),
            )?;
        }

        let got_sha = sha256_first_n_bytes(&verify_path, img_size)?;
        if got_sha != expected_sha256 {
            return Err(format!(
                "SHA-256 read-back mismatch on '{}' (mtd{}): expected {expected_sha256}, got {got_sha}",
                part.target_partition, part.mtd_num
            ));
        }
        log(&format!(
            "Verified read-back SHA-256 on '{}' ({}…)",
            part.target_partition,
            &got_sha[..12]
        ));
    }
    Ok(())
}

pub fn execute_flash<F>(
    plan: &FlashPlan,
    source_path: &Path,
    opts: FlashOptions,
    mut on_progress: F,
) -> Result<PersistedAbFlashState, String>
where
    F: FnMut(&str, Option<&str>, usize, usize),
{
    let _flock = acquire_ab_flock()?;
    let pkg = PackageSource::open(source_path)?;
    let (prefix, _) = pkg.find_rawprogram()?;
    let total = plan.partitions.len();
    let mut logs: Vec<String> = Vec::new();
    let mut push_log = |msg: &str, current: Option<&str>, done: usize| {
        let line = format!("[{}] {msg}", crate::state::format_now_hms());
        logs.push(line.clone());
        if logs.len() > MAX_LOG_LINES {
            logs.drain(0..logs.len() - MAX_LOG_LINES);
        }
        on_progress(&line, current, done, total);
    };

    // Re-verify active slot immediately before touching anything
    let live_active = detect_active_slot()?;
    if live_active != plan.active_slot || live_active == plan.target_slot {
        return Err(format!(
            "safety abort: active slot changed before flash (expected {}, live {})",
            plan.active_slot.suffix(),
            live_active.suffix()
        ));
    }

    let source_name = source_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| source_path.display().to_string());

    if !opts.dry_run {
        let conflicts = detect_conflicting_vendor_ab_procs();
        if !conflicts.is_empty() {
            return Err(format!(
                "refusing A/B flash while conflicting vendor updater process is running: {}",
                conflicts.join(", ")
            ));
        }

        let max_planned_img_bytes = plan
            .partitions
            .iter()
            .filter_map(|p| p.file_size)
            .max()
            .unwrap_or(0);
        if matches!(pkg, PackageSource::Zip { .. }) || opts.verify_readback {
            let tmp_root = PathBuf::from(crate::paths::p("/tmp"));
            let _ = fs::create_dir_all(&tmp_root);
            let need_tmp = max_planned_img_bytes.saturating_add(FLASH_SPACE_HEADROOM_BYTES);
            let avail_tmp = statvfs_avail_bytes("/tmp")
                .ok_or_else(|| "cannot check available /tmp space before flash".to_string())?;
            if avail_tmp < need_tmp {
                return Err(format!(
                    "insufficient /tmp space for flash staging/verify: {} bytes available, need at least {} bytes (max image {} + 16 MiB headroom)",
                    avail_tmp, need_tmp, max_planned_img_bytes
                ));
            }
        }

        if opts.preserve_cellcore && plan.partitions.iter().any(|p| p.base_label == "system") {
            let _ = check_usrdata_space_for_cellcored()?;
        }
    }

    push_log(
        &format!(
            "{} A/B flash: active={} -> target={} scope={} ({total} partitions)",
            if opts.dry_run { "Starting DRY-RUN" } else { "Starting" },
            plan.active_slot.suffix(),
            plan.target_slot.suffix(),
            plan.scope.as_str(),
        ),
        None,
        0,
    );

    let stage_dir = PathBuf::from(crate::paths::p(STAGE_DIR));
    let _stage_guard = if !opts.dry_run {
        let _ = fs::remove_dir_all(&stage_dir);
        fs::create_dir_all(&stage_dir).map_err(|e| format!("mkdir {}: {e}", stage_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700));
        }
        Some(RemoveDirGuard(stage_dir.clone()))
    } else {
        None
    };

    let mut flashed_names = Vec::with_capacity(total);
    let mut dirty_state_persisted = false;

    for (idx, part) in plan.partitions.iter().enumerate() {
        let part_res: Result<(), String> = (|| {
            // Re-assert safety invariants per partition
            if is_never_touch_partition(&part.base_label)
                || is_never_touch_partition(&part.target_partition)
                || !is_known_ab_base(&part.base_label)
                || part.target_partition == plan.active_slot.partition_name(&part.base_label)
            {
                return Err(format!(
                    "safety abort: refused unsafe partition '{}'",
                    part.target_partition
                ));
            }
            let attached = read_attached_ubi_mtds();
            if attached.contains(&part.mtd_num) {
                return Err(format!(
                    "safety abort: /dev/mtd{} ('{}') is currently UBI-attached!",
                    part.mtd_num, part.target_partition
                ));
            }

            let (entry_name, _) = pkg.resolve_image_entry(&prefix, &part.zip_relpath)?;
            push_log(
                &format!(
                    "[{}/{}] Verifying {} -> {} (mtd{})",
                    idx + 1,
                    total,
                    part.zip_relpath,
                    part.target_partition,
                    part.mtd_num
                ),
                Some(&part.target_partition),
                idx,
            );

            let streamed = prepare_single_image(&pkg, &entry_name, &stage_dir, part, !opts.dry_run)?;
            let mut temp_guard = if streamed.is_staged_temp {
                RemoveFileGuard(streamed.disk_path.clone())
            } else {
                RemoveFileGuard(None)
            };

            if let Some(expected_md5) = part.expected_md5.as_deref() {
                if !streamed.md5_hex.eq_ignore_ascii_case(expected_md5) {
                    return Err(format!(
                        "MD5 mismatch for '{}': expected {expected_md5}, got {}",
                        part.zip_relpath, streamed.md5_hex
                    ));
                }
                push_log(
                    &format!(
                        "MD5 OK for {} ({} bytes, md5={}…)",
                        part.target_partition,
                        streamed.size,
                        &streamed.md5_hex[..12]
                    ),
                    Some(&part.target_partition),
                    idx,
                );
            } else {
                push_log(
                    &format!(
                        "No expected MD5 for {} ({} bytes, sha256={}…)",
                        part.target_partition,
                        streamed.size,
                        &streamed.sha256_hex[..12]
                    ),
                    Some(&part.target_partition),
                    idx,
                );
            }

            if part.is_ubi && &streamed.magic4 != b"UBI#" {
                return Err(format!(
                    "invalid UBI magic on '{}' (expected 'UBI#', got {:02x?})",
                    part.zip_relpath, streamed.magic4
                ));
            }

            if opts.dry_run {
                push_log(
                    &format!(
                        "[dry-run] Would flash {} -> /dev/mtd{} ('{}', {} bytes, {})",
                        part.zip_relpath,
                        part.mtd_num,
                        part.target_partition,
                        streamed.size,
                        if part.is_ubi { "ubiformat+verify" } else { "mtdimg+sha256" }
                    ),
                    Some(&part.target_partition),
                    idx + 1,
                );
                flashed_names.push(part.target_partition.clone());
                return Ok(());
            }

            // Persist flashing_in_progress BEFORE erasing the very first NAND partition
            // so a crash or mid-flash failure marks the target slot dirty.
            if !dirty_state_persisted {
                let in_prog = PersistedAbFlashState {
                    status: "flashing_in_progress".into(),
                    last_flash_ts: Some(crate::auth::now_secs()),
                    previous_slot: Some(plan.active_slot),
                    target_slot: Some(plan.target_slot),
                    scope: Some(plan.scope),
                    source_name: Some(source_name.clone()),
                    project_name: plan.project_name.clone(),
                    partitions_flashed: Vec::new(),
                    verified_on_boot: false,
                    message: Some(format!(
                        "Flashing {total} partitions to inactive slot {}...",
                        plan.target_slot.suffix()
                    )),
                    log: Vec::new(),
                };
                save_persisted_state(&in_prog)?;
                dirty_state_persisted = true;
            }

            let disk_path = streamed
                .disk_path
                .as_deref()
                .ok_or("missing staged image path")?;

            let mut step_log = |m: &str| {
                push_log(m, Some(&part.target_partition), idx);
            };
            if part.is_ubi {
                flash_ubi_partition(part, disk_path, opts.preserve_cellcore, &mut step_log)?;
            } else {
                flash_raw_mtd_partition(
                    part,
                    disk_path,
                    streamed.size,
                    &streamed.sha256_hex,
                    &stage_dir,
                    opts.verify_readback,
                    streamed.is_staged_temp,
                    &mut step_log,
                )?;
                if streamed.is_staged_temp {
                    temp_guard.0 = None;
                }
            }

            // Delete the single extracted file immediately before next partition
            drop(temp_guard);
            flashed_names.push(part.target_partition.clone());
            push_log(
                &format!(
                    "Completed [{}/{}] '{}'",
                    idx + 1,
                    total,
                    part.target_partition
                ),
                Some(&part.target_partition),
                idx + 1,
            );
            Ok(())
        })();

        if let Err(err) = part_res {
            if !opts.dry_run && dirty_state_persisted {
                drop(push_log);
                let failed = PersistedAbFlashState {
                    status: "failed".into(),
                    last_flash_ts: Some(crate::auth::now_secs()),
                    previous_slot: Some(plan.active_slot),
                    target_slot: Some(plan.target_slot),
                    scope: Some(plan.scope),
                    source_name: Some(source_name),
                    project_name: plan.project_name.clone(),
                    partitions_flashed: flashed_names,
                    verified_on_boot: false,
                    message: Some(err.clone()),
                    log: logs,
                };
                let _ = save_persisted_state(&failed);
            }
            return Err(err);
        }
    }

    if opts.dry_run {
        push_log(
            &format!(
                "DRY-RUN complete: all {total} images verified cleanly; zero NAND writes performed"
            ),
            None,
            total,
        );
        drop(push_log);
        return Ok(PersistedAbFlashState {
            status: "dry_run_ok".into(),
            last_flash_ts: Some(crate::auth::now_secs()),
            previous_slot: Some(plan.active_slot),
            target_slot: Some(plan.target_slot),
            scope: Some(plan.scope),
            source_name: Some(source_name),
            project_name: plan.project_name.clone(),
            partitions_flashed: flashed_names,
            verified_on_boot: false,
            message: Some("Dry-run passed cleanly; zero NAND writes performed".into()),
            log: logs,
        });
    }

    drop(push_log);
    let mut persisted = PersistedAbFlashState {
        status: "flashed".into(),
        last_flash_ts: Some(crate::auth::now_secs()),
        previous_slot: Some(plan.active_slot),
        target_slot: Some(plan.target_slot),
        scope: Some(plan.scope),
        source_name: Some(source_name),
        project_name: plan.project_name.clone(),
        partitions_flashed: flashed_names,
        verified_on_boot: false,
        message: Some(format!(
            "Flashed {total} partitions to inactive slot {}",
            plan.target_slot.suffix()
        )),
        log: logs.clone(),
    };
    save_persisted_state(&persisted)?;

    if opts.activate_slot {
        let target_idx = plan.target_slot.index().to_string();
        run_tool_timeout("/sbin/abctl", &["--set_active", &target_idx], Duration::from_secs(10))?;
        let act_line = format!(
            "[{}] Activated slot {} (index {target_idx}) via abctl --set_active (previous slot {} kept intact for rollback)",
            crate::state::format_now_hms(),
            plan.target_slot.suffix(),
            plan.active_slot.suffix()
        );
        logs.push(act_line.clone());
        if logs.len() > MAX_LOG_LINES {
            logs.drain(0..logs.len() - MAX_LOG_LINES);
        }
        on_progress(&act_line, None, total, total);
        persisted.status = "activated".into();
        persisted.message = Some(format!(
            "Slot {} flashed and activated; reboot to trial-boot into new firmware",
            plan.target_slot.suffix()
        ));
        persisted.log = logs;
        save_persisted_state(&persisted)?;
    }

    Ok(persisted)
}

pub fn switch_slot(
    target: Option<Slot>,
    reboot_now: bool,
    force: bool,
) -> Result<PersistedAbFlashState, String> {
    let _flock = acquire_ab_flock()?;
    let mtds = read_proc_mtd()?;
    let _ = detect_ab_layout(&mtds)?;
    let current = detect_active_slot()?;
    let dest = target.unwrap_or_else(|| current.other());

    if dest == current {
        return Err(format!(
            "target slot {} is already the active boot slot",
            dest.suffix()
        ));
    }
    let last_state = load_persisted_state();
    if !force
        && last_state.target_slot == Some(dest)
        && matches!(
            last_state.status.as_str(),
            "flashing_in_progress" | "failed"
        )
    {
        return Err(format!(
            "refusing to activate dirty/half-flashed slot {} (last flash status='{}'{}); cleanly flash slot {} before activating (or pass force/--force to override)",
            dest.suffix(),
            last_state.status,
            last_state
                .message
                .as_deref()
                .map(|m| format!(": {m}"))
                .unwrap_or_default(),
            dest.suffix(),
        ));
    }
    match read_ab_unbootable(dest) {
        Some(false) => {}
        Some(true) => {
            return Err(format!(
                "refusing to switch to slot {}: abctl reports it is marked unbootable",
                dest.suffix()
            ));
        }
        None => {
            return Err(format!(
                "refusing to switch to slot {}: could not verify bootability via /sbin/abctl --get_unbootable",
                dest.suffix()
            ));
        }
    }

    let idx = dest.index().to_string();
    run_tool_timeout("/sbin/abctl", &["--set_active", &idx], Duration::from_secs(10))?;

    let mut st = last_state;
    st.status = "switched".into();
    st.last_flash_ts = Some(crate::auth::now_secs());
    st.previous_slot = Some(current);
    st.target_slot = Some(dest);
    st.verified_on_boot = false;
    let msg = format!(
        "Switched next boot slot from {} to {} (slot {} remains intact)",
        current.suffix(),
        dest.suffix(),
        current.suffix()
    );
    st.message = Some(msg.clone());
    st.log
        .push(format!("[{}] {msg}", crate::state::format_now_hms()));
    if st.log.len() > MAX_LOG_LINES {
        st.log.drain(0..st.log.len() - MAX_LOG_LINES);
    }
    save_persisted_state(&st)?;

    if reboot_now {
        let _ = run_tool_timeout("sync", &[], Duration::from_secs(10));
        let _ = run_tool_timeout("/sbin/reboot", &[], Duration::from_secs(10));
    }
    Ok(st)
}

pub fn confirm_current_slot() -> Result<PersistedAbFlashState, String> {
    let _flock = acquire_ab_flock()?;
    let current = detect_active_slot()?;
    run_tool_timeout("/sbin/abctl", &["--set_success"], Duration::from_secs(10))?;

    let mut st = load_persisted_state();
    st.verified_on_boot = true;
    if matches!(st.status.as_str(), "flashed" | "activated" | "switched" | "") {
        st.status = "confirmed".into();
    }
    let msg = format!("Confirmed active slot {} as boot-successful", current.suffix());
    st.message = Some(msg.clone());
    st.log
        .push(format!("[{}] {msg}", crate::state::format_now_hms()));
    if st.log.len() > MAX_LOG_LINES {
        st.log.drain(0..st.log.len() - MAX_LOG_LINES);
    }
    save_persisted_state(&st)?;
    Ok(st)
}

/// Probation-gated boot auto-confirm for a newly booted A/B target slot.
/// Waits until daemon/device uptime reaches `CELLCORE_AB_CONFIRM_DELAY_SECS`
/// (default 90 s, polling every 5 s) and verifies SMD AT (`AT+CFUN?`),
/// QRTR/dataplane health, and HTTP listener liveness before calling
/// `/sbin/abctl --set_success`. If health checks fail, leaves trial-boot active
/// so the bootloader can fall back cleanly instead of locking in a broken slot.
pub fn spawn_boot_auto_confirm(state: AppState) {
    tokio::spawn(async move {
        let check = crate::paths::spawn_blocking(|| -> Option<Slot> {
            let st = load_persisted_state();
            if st.verified_on_boot {
                return None;
            }
            if matches!(st.status.as_str(), "failed" | "flashing_in_progress") {
                return None;
            }
            let target = st.target_slot?;
            let current = detect_active_slot().ok()?;
            (current == target).then_some(current)
        })
        .await;

        let Ok(Some(current_slot)) = check else {
            return;
        };

        let delay_secs = std::env::var("CELLCORE_AB_CONFIRM_DELAY_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_CONFIRM_DELAY_SECS);
        let started = tokio::time::Instant::now();

        state.push_daemon_log(format!(
            "firmware-ab: slot {} trial-boot probation started (waiting {}s before health verification)",
            current_slot.suffix(),
            delay_secs
        ));

        while started.elapsed() < Duration::from_secs(delay_secs) {
            let rem = Duration::from_secs(delay_secs).saturating_sub(started.elapsed());
            tokio::time::sleep(rem.min(Duration::from_secs(5))).await;
        }

        // Verify health checks with a short retry window (up to 6 checks @ 5s = 30s)
        let mut at_ok = false;
        let mut dp_ok = false;
        let mut http_ok = false;
        for attempt in 0..6 {
            at_ok = state.smd.is_healthy()
                && state
                    .smd
                    .exec("AT+CFUN?", crate::smd::Priority::Background, Duration::from_secs(5))
                    .await
                    .is_ok_and(|r| r.ok);
            dp_ok = !crate::dataplane::is_native_mode() || crate::dataplane::is_wds_connected();
            http_ok = state.hb_http_ms.load(std::sync::atomic::Ordering::Acquire) > 0;
            if at_ok && dp_ok && http_ok {
                break;
            }
            if attempt == 0 {
                state.push_daemon_log(format!(
                    "firmware-ab: slot {} probation waiting for healthy subsystem state (at_ok={at_ok}, dp_ok={dp_ok}, http_ok={http_ok})",
                    current_slot.suffix()
                ));
            }
            if attempt < 5 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }

        if !(at_ok && dp_ok && http_ok) {
            state.push_daemon_log(format!(
                "firmware-ab: probation health check FAILED for slot {} (at_ok={at_ok}, dp_ok={dp_ok}, http_ok={http_ok}); leaving trial-boot active without confirming",
                current_slot.suffix()
            ));
            return;
        }

        let _op_guard = state.ab_flash.op_lock.lock().await;
        let res = crate::paths::spawn_blocking(move || -> Result<Option<String>, String> {
            let st = load_persisted_state();
            if st.verified_on_boot || st.target_slot != Some(current_slot) {
                return Ok(None);
            }
            let updated = confirm_current_slot()?;
            Ok(updated.message)
        })
        .await;
        match res {
            Ok(Ok(Some(msg))) => state.push_daemon_log(format!("firmware-ab: {msg}")),
            Ok(Err(e)) => state.push_daemon_log(format!(
                "firmware-ab: probation confirm failed for slot {}: {e}",
                current_slot.suffix()
            )),
            _ => {}
        }
    });
}

// ---------------------------------------------------------------------------
// HTTP API Handlers
// ---------------------------------------------------------------------------

fn err_resp(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "status": "error", "error": msg.into() })),
    )
        .into_response()
}

pub async fn get_firmware_ab(State(ctx): State<HttpCtx>) -> Response {
    let job = ctx.app.ab_flash.job.read().await.clone();
    match crate::paths::spawn_blocking(move || probe_ab_status(job)).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("probe task failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectBody {
    pub path: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub allow_project_mismatch: bool,
    #[serde(default)]
    pub allow_no_manifest: bool,
}

pub async fn post_firmware_ab_inspect(Json(body): Json<InspectBody>) -> Response {
    let source = match validate_http_source_path(&body.path) {
        Ok(p) => p,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
    };
    let scope = match body.scope.as_deref() {
        None => FlashScope::Rootfs,
        Some(s) => match FlashScope::parse(s) {
            Some(sc) => sc,
            None => {
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("invalid scope '{s}' (expected rootfs, baseband, or full)"),
                );
            }
        },
    };
    let allow_pm = body.allow_project_mismatch;
    let allow_nm = body.allow_no_manifest;
    match crate::paths::spawn_blocking(move || inspect_package(&source, scope, allow_pm, allow_nm))
        .await
    {
        Ok(Ok(report)) => (StatusCode::OK, Json(report)).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::BAD_REQUEST, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("inspect task failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlashBody {
    pub path: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_true")]
    pub preserve_cellcore: bool,
    #[serde(default = "default_true")]
    pub verify_readback: bool,
    #[serde(default)]
    pub activate_slot: bool,
    #[serde(default)]
    pub reboot: bool,
    #[serde(default)]
    pub allow_project_mismatch: bool,
    #[serde(default)]
    pub allow_no_manifest: bool,
}

fn broadcast_ab_flash_progress(app: &crate::state::AppState, j: &AbJobProgress) {
    app.broadcast_json(&serde_json::json!({
        "channel": "ab_flash",
        "running": j.running,
        "phase": j.phase,
        "currentPartition": j.current_partition,
        "completed": j.completed,
        "total": j.total,
        "ok": j.ok,
        "error": j.error,
    }));
}

fn default_true() -> bool {
    true
}

pub async fn post_firmware_ab_flash(
    State(ctx): State<HttpCtx>,
    Json(body): Json<FlashBody>,
) -> Response {
    let source = match validate_http_source_path(&body.path) {
        Ok(p) => p,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
    };
    let scope = match body.scope.as_deref() {
        None => FlashScope::Rootfs,
        Some(s) => match FlashScope::parse(s) {
            Some(sc) => sc,
            None => {
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("invalid scope '{s}' (expected rootfs, baseband, or full)"),
                );
            }
        },
    };
    if body.reboot && !body.activate_slot {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "reboot requires activateSlot: true",
        );
    }

    let Ok(guard) = Arc::clone(&ctx.app.ab_flash.op_lock).try_lock_owned() else {
        return err_resp(
            StatusCode::CONFLICT,
            "An A/B firmware operation is already running",
        );
    };

    let source_inspect = source.clone();
    let allow_pm = body.allow_project_mismatch;
    let allow_nm = body.allow_no_manifest;
    let inspect = match crate::paths::spawn_blocking(move || {
        inspect_package(&source_inspect, scope, allow_pm, allow_nm)
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, e),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("inspect task failed: {e}")),
    };

    let total = inspect.plan.partitions.len();
    let started = crate::auth::now_secs();
    let initial_snap = {
        let mut j = ctx.app.ab_flash.job.write().await;
        *j = AbJobProgress {
            running: true,
            dry_run: body.dry_run,
            phase: if body.dry_run { "dry-run".into() } else { "flashing".into() },
            current_partition: None,
            completed: 0,
            total,
            started_at: Some(started),
            finished_at: None,
            ok: None,
            error: None,
            log: vec![format!(
                "[{}] Queued {} ({total} partitions -> slot {})",
                crate::state::format_now_hms(),
                if body.dry_run { "dry-run" } else { "A/B flash" },
                inspect.plan.target_slot.suffix()
            )],
        };
        j.clone()
    };
    broadcast_ab_flash_progress(&ctx.app, &initial_snap);

    let opts = FlashOptions {
        dry_run: body.dry_run,
        preserve_cellcore: body.preserve_cellcore,
        activate_slot: body.activate_slot,
        reboot: body.reboot,
        verify_readback: body.verify_readback,
    };
    let app = ctx.app.clone();
    let plan = inspect.plan.clone();
    tokio::spawn(async move {
        let _lock = guard;
        let app_cb = app.clone();
        let plan_run = plan.clone();
        let res = crate::paths::spawn_blocking(move || {
            execute_flash(&plan_run, &source, opts, |line, cur, done, tot| {
                let snap = {
                    let mut j = app_cb.ab_flash.job.blocking_write();
                    j.current_partition = cur.map(str::to_string);
                    j.completed = done;
                    j.total = tot;
                    j.log.push(line.to_string());
                    if j.log.len() > MAX_LOG_LINES {
                        let drop_n = j.log.len() - MAX_LOG_LINES;
                        j.log.drain(0..drop_n);
                    }
                    j.clone()
                };
                broadcast_ab_flash_progress(&app_cb, &snap);
            })
        })
        .await;

        let finished = crate::auth::now_secs();
        match res {
            Ok(Ok(st)) => {
                let final_snap = {
                    let mut j = app.ab_flash.job.write().await;
                    j.running = false;
                    j.phase = st.status.clone();
                    j.current_partition = None;
                    j.completed = total;
                    j.finished_at = Some(finished);
                    j.ok = Some(true);
                    j.error = None;
                    j.clone()
                };
                broadcast_ab_flash_progress(&app, &final_snap);
                app.push_daemon_log(format!(
                    "firmware-ab: {}",
                    st.message.as_deref().unwrap_or("completed")
                ));
                if !opts.dry_run && opts.activate_slot && opts.reboot {
                    app.push_daemon_log("firmware-ab: rebooting into activated slot in 1s");
                    crate::telemetry::flush_persistent_state(&app).await;
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    let _ = crate::uci::run_cmd("sync", &[], Duration::from_secs(10)).await;
                    let _ = crate::uci::run_cmd("/sbin/reboot", &[], Duration::from_secs(10)).await;
                }
            }
            Ok(Err(e)) => {
                let final_snap = {
                    let mut j = app.ab_flash.job.write().await;
                    j.running = false;
                    j.phase = "failed".into();
                    j.finished_at = Some(finished);
                    j.ok = Some(false);
                    j.error = Some(e.clone());
                    j.log.push(format!("[{}] ERROR: {e}", crate::state::format_now_hms()));
                    j.clone()
                };
                broadcast_ab_flash_progress(&app, &final_snap);
                app.push_daemon_log(format!("firmware-ab failed: {e}"));
            }
            Err(e) => {
                let msg = format!("flash worker panicked: {e}");
                let final_snap = {
                    let mut j = app.ab_flash.job.write().await;
                    j.running = false;
                    j.phase = "failed".into();
                    j.finished_at = Some(finished);
                    j.ok = Some(false);
                    j.error = Some(msg);
                    j.clone()
                };
                broadcast_ab_flash_progress(&app, &final_snap);
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ok": true,
            "started": true,
            "status": if body.dry_run { "dry-run" } else { "flashing" },
            "targetSlot": inspect.plan.target_slot,
            "partitions": total,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SwitchBody {
    pub slot: Option<String>,
    pub reboot: bool,
    pub force: bool,
}

pub async fn post_firmware_ab_switch(
    State(ctx): State<HttpCtx>,
    Json(body): Json<SwitchBody>,
) -> Response {
    let target = match body.slot.as_deref() {
        None => None,
        Some(raw) => match Slot::parse(raw) {
            Some(s) => Some(s),
            None => {
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("invalid slot '{raw}' (expected a, b, _a, or _b)"),
                );
            }
        },
    };
    let Ok(_guard) = ctx.app.ab_flash.op_lock.try_lock() else {
        return err_resp(
            StatusCode::CONFLICT,
            "An A/B firmware operation is already running",
        );
    };

    let force = body.force;
    match crate::paths::spawn_blocking(move || switch_slot(target, false, force)).await {
        Ok(Ok(st)) => {
            ctx.app.push_daemon_log(format!(
                "firmware-ab: {}",
                st.message.as_deref().unwrap_or("slot switched")
            ));
            if body.reboot {
                let app = ctx.app.clone();
                tokio::spawn(async move {
                    crate::telemetry::flush_persistent_state(&app).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = crate::uci::run_cmd("sync", &[], Duration::from_secs(10)).await;
                    let _ = crate::uci::run_cmd("/sbin/reboot", &[], Duration::from_secs(10)).await;
                });
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "rebooting": body.reboot,
                    "state": st,
                })),
            )
                .into_response()
        }
        Ok(Err(e)) => err_resp(StatusCode::CONFLICT, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("switch task failed: {e}")),
    }
}

pub async fn post_firmware_ab_confirm(State(ctx): State<HttpCtx>) -> Response {
    let Ok(_guard) = ctx.app.ab_flash.op_lock.try_lock() else {
        return err_resp(
            StatusCode::CONFLICT,
            "An A/B firmware operation is already running",
        );
    };
    match crate::paths::spawn_blocking(confirm_current_slot).await {
        Ok(Ok(st)) => {
            ctx.app.push_daemon_log(format!(
                "firmware-ab: {}",
                st.message.as_deref().unwrap_or("slot confirmed")
            ));
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "state": st,
                })),
            )
                .into_response()
        }
        Ok(Err(e)) => err_resp(StatusCode::BAD_REQUEST, e),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("confirm task failed: {e}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedFirmwareFile {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub mtime_secs: u64,
}

/// Scan `/tmp` and `/usrdata/cache` (non-recursive, capped at 50 entries) for
/// regular `.zip` files >= `min_bytes`, sorted newest first.
pub fn scan_staged_firmware_zips(min_bytes: u64) -> Vec<StagedFirmwareFile> {
    let mut files = Vec::new();
    for dir_virt in ["/tmp", UPLOAD_CACHE_DIR] {
        let dir_real = PathBuf::from(crate::paths::p(dir_virt));
        let Ok(rd) = fs::read_dir(&dir_real) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || !name.to_ascii_lowercase().ends_with(".zip") {
                continue;
            }
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let size_bytes = meta.len();
            if size_bytes < min_bytes {
                continue;
            }
            let mtime_secs = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            files.push(StagedFirmwareFile {
                path: format!("{dir_virt}/{name}"),
                name,
                size_bytes,
                mtime_secs,
            });
        }
    }
    files.sort_by(|a, b| {
        b.mtime_secs
            .cmp(&a.mtime_secs)
            .then_with(|| a.name.cmp(&b.name))
    });
    files.truncate(MAX_STAGED_ENTRIES);
    files
}

pub async fn get_firmware_ab_staged() -> Response {
    let min_bytes = if cfg!(test) { 1 } else { 1024 * 1024 + 1 };
    match crate::paths::spawn_blocking(move || scan_staged_firmware_zips(min_bytes)).await {
        Ok(files) => (StatusCode::OK, Json(serde_json::json!({ "files": files }))).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("staged scan failed: {e}")),
    }
}

pub fn sanitize_upload_filename(raw: Option<&str>) -> Result<String, String> {
    let name = raw.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("firmware-upload.zip");
    if name.len() > 128 {
        return Err("filename exceeds 128 characters".into());
    }
    if name.starts_with('.') || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("invalid firmware filename".into());
    }
    if !name.ends_with(".zip") || name.len() <= 4 {
        return Err("firmware filename must match [A-Za-z0-9._-]+\\.zip".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("firmware filename must match [A-Za-z0-9._-]+\\.zip".into());
    }
    Ok(name.to_string())
}

pub async fn post_firmware_ab_upload(
    State(ctx): State<HttpCtx>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(ct) = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if !mime.is_empty()
            && !matches!(
                mime.as_str(),
                "application/octet-stream" | "application/zip" | "application/x-zip-compressed"
            )
        {
            return err_resp(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("unsupported Content-Type '{mime}' (expected application/octet-stream or application/zip)"),
            );
        }
    }

    let raw_name = headers
        .get("x-firmware-filename")
        .and_then(|v| v.to_str().ok());
    let filename = match sanitize_upload_filename(raw_name) {
        Ok(n) => n,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, e),
    };

    let content_length = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(cl) = content_length
        && cl > MAX_UPLOAD_ZIP_BYTES
    {
        return err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("upload exceeds maximum allowed size ({MAX_UPLOAD_ZIP_BYTES} bytes)"),
        );
    }

    let cache_dir = PathBuf::from(crate::paths::p(UPLOAD_CACHE_DIR));
    if let Err(e) = fs::create_dir_all(&cache_dir) {
        return err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create {}: {e}", cache_dir.display()),
        );
    }

    let avail_bytes = match statvfs_avail_bytes("/usrdata").or_else(|| statvfs_avail_bytes(UPLOAD_CACHE_DIR)) {
        Some(b) => b,
        None => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to verify /usrdata available space",
            );
        }
    };
    let required_start = content_length
        .unwrap_or(0)
        .saturating_add(UPLOAD_MIN_HEADROOM_BYTES);
    if avail_bytes < required_start {
        return err_resp(
            StatusCode::INSUFFICIENT_STORAGE,
            format!(
                "insufficient /usrdata space: {} bytes available, need at least {} bytes (32 MiB headroom)",
                avail_bytes, required_start
            ),
        );
    }

    let tmp_name = format!(".{filename}.upload.{}.{}", std::process::id(), crate::state::mono_ms());
    let tmp_path = cache_dir.join(&tmp_name);
    let final_path = cache_dir.join(&filename);
    let std_file = match crate::state::create_private_tmp(&tmp_path, 0o600) {
        Ok(f) => f,
        Err(e) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("create upload temp file: {e}"),
            );
        }
    };
    let mut tmp_guard = RemoveFileGuard(Some(tmp_path.clone()));
    let mut async_file = tokio::fs::File::from_std(std_file);

    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut magic4 = [0u8; 4];
    let mut magic_checked = false;
    let mut last_space_check: u64 = 0;

    while let Some(next_chunk) = stream.next().await {
        let chunk = match next_chunk {
            Ok(c) => c,
            Err(e) => return err_resp(StatusCode::BAD_REQUEST, format!("upload stream error: {e}")),
        };
        if chunk.is_empty() {
            continue;
        }
        if total < 4 {
            let need = (4 - total) as usize;
            let take = need.min(chunk.len());
            magic4[total as usize..total as usize + take].copy_from_slice(&chunk[..take]);
        }
        total = total.saturating_add(chunk.len() as u64);
        if total > MAX_UPLOAD_ZIP_BYTES {
            return err_resp(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("upload exceeded maximum allowed size ({MAX_UPLOAD_ZIP_BYTES} bytes)"),
            );
        }
        if !magic_checked && total >= 4 {
            if &magic4 != b"PK\x03\x04" {
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    "invalid firmware upload: missing ZIP magic header (PK\\x03\\x04)",
                );
            }
            magic_checked = true;
        }
        if total.saturating_sub(last_space_check) >= 16 * 1024 * 1024 {
            last_space_check = total;
            if statvfs_avail_bytes("/usrdata")
                .or_else(|| statvfs_avail_bytes(UPLOAD_CACHE_DIR))
                .is_none_or(|b| b < UPLOAD_MIN_HEADROOM_BYTES)
            {
                return err_resp(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "aborted upload: /usrdata free space dropped below 32 MiB headroom",
                );
            }
        }
        hasher.update(&chunk);
        if let Err(e) = async_file.write_all(&chunk).await {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("write upload temp file: {e}"),
            );
        }
    }

    if total < 4 || !magic_checked {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid firmware upload: file is empty or missing ZIP magic header",
        );
    }
    if let Err(e) = async_file.flush().await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("flush upload: {e}"));
    }
    if let Err(e) = async_file.sync_all().await {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("sync upload: {e}"));
    }
    drop(async_file);

    let tmp_mv = tmp_path.clone();
    let dst_mv = final_path.clone();
    match crate::paths::spawn_blocking(move || crate::state::atomic_rename_file(&tmp_mv, &dst_mv)).await {
        Ok(Ok(())) => {
            tmp_guard.0 = None;
        }
        Ok(Err(e)) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("install upload: {e}")),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("install task failed: {e}")),
    }

    let sha256 = hex::encode(hasher.finalize());
    let reported_path = format!("{UPLOAD_CACHE_DIR}/{filename}");
    ctx.app.push_daemon_log(format!(
        "firmware-ab: uploaded {reported_path} ({total} bytes, sha256={}…)",
        &sha256[..12]
    ));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "path": reported_path,
            "sizeBytes": total,
            "sha256": sha256,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// CLI Entrypoint (`cellctl firmware-flash ...` / `cellcored firmware-flash ...`)
// ---------------------------------------------------------------------------

fn print_cli_usage() {
    eprintln!(
        "\
Usage: cellctl firmware-flash <subcommand> [options]

Subcommands:
  status [--json]
  inspect <zip-or-dir> [--scope rootfs|baseband|full] [--allow-project-mismatch] [--allow-no-manifest] [--json]
  flash <zip-or-dir> [--scope rootfs|baseband|full] [--dry-run] [--yes] [--activate] [--reboot]
                     [--no-preserve-cellcore] [--no-verify] [--allow-project-mismatch] [--allow-no-manifest]
  switch [--slot a|b] [--reboot] --yes
  rollback [--reboot] --yes
  confirm"
    );
}

pub fn run_cli(args: &[String]) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    match sub {
        "status" => {
            let want_json = args.iter().any(|a| a == "--json");
            let st = probe_ab_status(AbJobProgress {
                phase: "idle".into(),
                ..Default::default()
            });
            if want_json {
                println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
                return 0;
            }
            println!(
                "supported={} total_mtds={} ab_bases={} active_slot={} inactive_slot={}",
                if st.supported { 1 } else { 0 },
                st.total_mtds,
                st.ab_base_count,
                st.active_slot.map(Slot::suffix).unwrap_or("unknown"),
                st.inactive_slot.map(Slot::suffix).unwrap_or("unknown"),
            );
            println!(
                "slot_a_unbootable={} slot_b_unbootable={} trial_boot={} tmp_avail_mib={}",
                st.slot_a_unbootable.map(|b| if b { "1" } else { "0" }).unwrap_or("unknown"),
                st.slot_b_unbootable.map(|b| if b { "1" } else { "0" }).unwrap_or("unknown"),
                st.trial_boot_active.map(|b| if b { "1" } else { "0" }).unwrap_or("unknown"),
                st.tmp_avail_mib.unwrap_or(0),
            );
            if let Some(proj) = st.project_name.as_deref() {
                println!(
                    "project_name={proj} project_rev={}",
                    st.project_rev.as_deref().unwrap_or("unknown")
                );
            }
            if let Some(rci) = &st.rci {
                println!(
                    "rci selected_set={:?} trial_boot_enable={:?} failed_attempts={:?}/{:?}",
                    rci.selected_set,
                    rci.trial_boot_enable,
                    rci.trial_boot_failed_attempts,
                    rci.trial_boot_max_attempts,
                );
            }
            if let Some(reason) = st.unsupported_reason.as_deref() {
                println!("reason={reason}");
            }
            if !st.last_state.status.is_empty() {
                println!(
                    "last_flash status={} target={} verified_on_boot={}",
                    st.last_state.status,
                    st.last_state.target_slot.map(Slot::suffix).unwrap_or("none"),
                    if st.last_state.verified_on_boot { 1 } else { 0 },
                );
            }
            0
        }
        "inspect" => run_cli_inspect(&args[1..]),
        "flash" => run_cli_flash(&args[1..]),
        "switch" => run_cli_switch(&args[1..], false),
        "rollback" => run_cli_switch(&args[1..], true),
        "confirm" => match confirm_current_slot() {
            Ok(st) => {
                println!("{}", st.message.unwrap_or_else(|| "slot confirmed".into()));
                0
            }
            Err(e) => {
                eprintln!("firmware-flash confirm: {e}");
                1
            }
        },
        _ => {
            print_cli_usage();
            2
        }
    }
}

fn run_cli_inspect(args: &[String]) -> i32 {
    let mut path_arg: Option<String> = None;
    let mut scope = FlashScope::Rootfs;
    let mut allow_pm = false;
    let mut allow_nm = false;
    let mut want_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--scope" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--scope requires rootfs|baseband|full");
                    return 2;
                };
                let Some(sc) = FlashScope::parse(v) else {
                    eprintln!("invalid --scope '{v}'");
                    return 2;
                };
                scope = sc;
                i += 2;
            }
            "--allow-project-mismatch" => {
                allow_pm = true;
                i += 1;
            }
            "--allow-no-manifest" => {
                allow_nm = true;
                i += 1;
            }
            "--json" => {
                want_json = true;
                i += 1;
            }
            s if s.starts_with('-') => {
                eprintln!("unknown flag: {s}");
                return 2;
            }
            s => {
                path_arg = Some(s.to_string());
                i += 1;
            }
        }
    }
    let Some(raw) = path_arg else {
        print_cli_usage();
        return 2;
    };
    let source = match validate_source_path(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("firmware-flash inspect: {e}");
            return 1;
        }
    };
    match inspect_package(&source, scope, allow_pm, allow_nm) {
        Ok(rep) => {
            if want_json {
                println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            } else {
                println!(
                    "source={} ({}) active={} target={} scope={} project={} tmp_avail_mib={}",
                    rep.source_path,
                    rep.source_kind,
                    rep.plan.active_slot.suffix(),
                    rep.plan.target_slot.suffix(),
                    rep.plan.scope.as_str(),
                    rep.plan.project_name.as_deref().unwrap_or("unknown"),
                    rep.tmp_avail_mib.unwrap_or(0),
                );
                for p in &rep.plan.partitions {
                    println!(
                        "  mtd{:<2} {:<14} {:<6} size={:<10} mtd_max={:<10} md5={} file={}",
                        p.mtd_num,
                        p.target_partition,
                        if p.is_ubi { "ubi" } else { "raw" },
                        p.file_size.unwrap_or(0),
                        p.mtd_size,
                        p.expected_md5.as_deref().map(|m| &m[..8]).unwrap_or("MISSING"),
                        p.zip_relpath,
                    );
                }
                for w in &rep.plan.warnings {
                    println!("warning: {w}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("firmware-flash inspect: {e}");
            1
        }
    }
}

fn run_cli_flash(args: &[String]) -> i32 {
    let mut path_arg: Option<String> = None;
    let mut scope = FlashScope::Rootfs;
    let mut dry_run = false;
    let mut yes = false;
    let mut activate = false;
    let mut reboot = false;
    let mut preserve_cellcore = true;
    let mut verify_readback = true;
    let mut allow_pm = false;
    let mut allow_nm = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--scope" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--scope requires rootfs|baseband|full");
                    return 2;
                };
                let Some(sc) = FlashScope::parse(v) else {
                    eprintln!("invalid --scope '{v}'");
                    return 2;
                };
                scope = sc;
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--yes" | "-y" => {
                yes = true;
                i += 1;
            }
            "--activate" => {
                activate = true;
                i += 1;
            }
            "--reboot" => {
                reboot = true;
                i += 1;
            }
            "--no-preserve-cellcore" => {
                preserve_cellcore = false;
                i += 1;
            }
            "--no-verify" => {
                verify_readback = false;
                i += 1;
            }
            "--allow-project-mismatch" => {
                allow_pm = true;
                i += 1;
            }
            "--allow-no-manifest" => {
                allow_nm = true;
                i += 1;
            }
            s if s.starts_with('-') => {
                eprintln!("unknown flag: {s}");
                return 2;
            }
            s => {
                path_arg = Some(s.to_string());
                i += 1;
            }
        }
    }
    let Some(raw) = path_arg else {
        print_cli_usage();
        return 2;
    };
    if !dry_run && !yes {
        eprintln!("Refusing to flash NAND without --yes (or pass --dry-run to verify without writing).");
        return 2;
    }
    if reboot && !activate {
        eprintln!("--reboot requires --activate.");
        return 2;
    }
    let source = match validate_source_path(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("firmware-flash: {e}");
            return 1;
        }
    };
    let report = match inspect_package(&source, scope, allow_pm, allow_nm) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("firmware-flash: {e}");
            return 1;
        }
    };
    let opts = FlashOptions {
        dry_run,
        preserve_cellcore,
        activate_slot: activate,
        reboot,
        verify_readback,
    };
    match execute_flash(&report.plan, &source, opts, |line, _, _, _| {
        println!("{line}");
    }) {
        Ok(st) => {
            println!("ok=1 status={}", st.status);
            if !dry_run && activate && reboot {
                let _ = run_tool_timeout("sync", &[], Duration::from_secs(10));
                let _ = run_tool_timeout("/sbin/reboot", &[], Duration::from_secs(10));
            }
            0
        }
        Err(e) => {
            eprintln!("firmware-flash failed: {e}");
            1
        }
    }
}

fn run_cli_switch(args: &[String], force_other: bool) -> i32 {
    let mut slot: Option<Slot> = None;
    let mut reboot = false;
    let mut yes = false;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--slot" if !force_other => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--slot requires a or b");
                    return 2;
                };
                let Some(s) = Slot::parse(v) else {
                    eprintln!("invalid --slot '{v}'");
                    return 2;
                };
                slot = Some(s);
                i += 2;
            }
            "--reboot" => {
                reboot = true;
                i += 1;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            "--yes" | "-y" => {
                yes = true;
                i += 1;
            }
            other => {
                eprintln!("unknown flag: {other}");
                return 2;
            }
        }
    }
    if !yes {
        eprintln!("Refusing to switch active boot slot without --yes.");
        return 2;
    }
    match switch_slot(slot, reboot, force) {
        Ok(st) => {
            println!("{}", st.message.unwrap_or_else(|| "slot switched".into()));
            0
        }
        Err(e) => {
            eprintln!("firmware-flash switch: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real 58-partition R02A02 Dual-Slot A/B NAND layout verified on SDX75.
    const PROC_MTD_R02A02: &str = r#"dev:    size   erasesize  name
mtd0: 00140000 00040000 "sbl"
mtd1: 00140000 00040000 "sbl_b"
mtd2: 00140000 00040000 "mibib"
mtd3: 00600000 00040000 "efs2"
mtd4: 00100000 00040000 "tz"
mtd5: 00100000 00040000 "tz_b"
mtd6: 00040000 00040000 "tz_devcfg"
mtd7: 00040000 00040000 "tz_devcfg_b"
mtd8: 00080000 00040000 "ddr"
mtd9: 00080000 00040000 "aop"
mtd10: 00080000 00040000 "aop_b"
mtd11: 00040000 00040000 "aop_devcfg"
mtd12: 00040000 00040000 "aop_devcfg_b"
mtd13: 00140000 00040000 "qhee"
mtd14: 00140000 00040000 "qhee_b"
mtd15: 00040000 00040000 "qupfw"
mtd16: 00040000 00040000 "qupfw_b"
mtd17: 00040000 00040000 "shrm"
mtd18: 00040000 00040000 "shrm_b"
mtd19: 00080000 00040000 "cpucpfw"
mtd20: 00080000 00040000 "cpucpfw_b"
mtd21: 000c0000 00040000 "xbl_config"
mtd22: 000c0000 00040000 "xbl_config_b"
mtd23: 00100000 00040000 "xbl_ramdump"
mtd24: 00100000 00040000 "xbl_ramdump_b"
mtd25: 00100000 00040000 "abl"
mtd26: 00100000 00040000 "abl_b"
mtd27: 00300000 00040000 "uefi"
mtd28: 00300000 00040000 "uefi_b"
mtd29: 000c0000 00040000 "cmnlib64"
mtd30: 000c0000 00040000 "cmnlib64_b"
mtd31: 000c0000 00040000 "keymaster"
mtd32: 000c0000 00040000 "keymaster_b"
mtd33: 00040000 00040000 "apdp"
mtd34: 00040000 00040000 "apdp_b"
mtd35: 00040000 00040000 "multi_oem"
mtd36: 00040000 00040000 "multi_oem_b"
mtd37: 00040000 00040000 "multi_qti"
mtd38: 00040000 00040000 "multi_qti_b"
mtd39: 00100000 00040000 "ipa_fw"
mtd40: 00100000 00040000 "ipa_fw_b"
mtd41: 00100000 00040000 "rawdata"
mtd42: 00040000 00040000 "sys_rev"
mtd43: 00040000 00040000 "cdt"
mtd44: 00040000 00040000 "sec"
mtd45: 000c0000 00040000 "recoveryinfo"
mtd46: 000c0000 00040000 "misc"
mtd47: 00040000 00040000 "quest"
mtd48: 00040000 00040000 "devinfo"
mtd49: 00200000 00040000 "fota"
mtd50: 00040000 00040000 "usb_qti"
mtd51: 03c00000 00040000 "boot"
mtd52: 03c00000 00040000 "boot_b"
mtd53: 07800000 00040000 "modem"
mtd54: 07800000 00040000 "modem_b"
mtd55: 07380000 00040000 "system"
mtd56: 07380000 00040000 "system_b"
mtd57: 11200000 00040000 "usrdata"
"#;

    const PROC_MTD_R01A04_SINGLE_SLOT: &str = r#"dev:    size   erasesize  name
mtd0: 00140000 00040000 "sbl"
mtd1: 00140000 00040000 "mibib"
mtd2: 00600000 00040000 "efs2"
mtd33: 03c00000 00040000 "boot"
mtd34: 07800000 00040000 "modem"
mtd35: 07380000 00040000 "system"
mtd36: 11200000 00040000 "usrdata"
"#;

    const SAMPLE_RAWPROGRAM_XML: &str = r#"<?xml version="1.0" ?>
<data>
  <erase c_project_name="RM551EGL00AAA_VA" label="mibib" />
  <program filename="..\sbl1.mbn" label="sbl" num_partition_sectors="320" />
  <program filename="..\sbl1.mbn" label="sbl_b" num_partition_sectors="320" />
  <program filename="..\xbl_config.elf" label="xbl_config" num_partition_sectors="64" />
  <program filename="..\xbl_ramdump.elf" label="xbl_ramdump" num_partition_sectors="64" />
  <program filename="..\abl.elf" label="abl" num_partition_sectors="128" />
  <program filename="..\uefi.elf" label="uefi" num_partition_sectors="512" />
  <program filename="..\tz.mbn" label="tz" num_partition_sectors="256" />
  <program filename="..\devcfg.mbn" label="tz_devcfg" num_partition_sectors="32" />
  <program filename="..\cmnlib64.mbn" label="cmnlib64" num_partition_sectors="128" />
  <program filename="..\km41.mbn" label="keymaster" num_partition_sectors="128" />
  <program filename="..\apdp.mbn" label="apdp" num_partition_sectors="16" />
  <program filename="..\multi_image.mbn" label="multi_oem" num_partition_sectors="16" />
  <program filename="..\multi_image_qti.mbn" label="multi_qti" num_partition_sectors="16" />
  <program filename="..\aop.mbn" label="aop" num_partition_sectors="64" />
  <program filename="..\aop_devcfg.mbn" label="aop_devcfg" num_partition_sectors="16" />
  <program filename="..\qhee.mbn" label="qhee" num_partition_sectors="256" />
  <program filename="..\qupv3fw.elf" label="qupfw" num_partition_sectors="16" />
  <program filename="..\shrm.elf" label="shrm" num_partition_sectors="16" />
  <program filename="..\cpucp.elf" label="cpucpfw" num_partition_sectors="32" />
  <program filename="..\ipa_fws.elf" label="ipa_fw" num_partition_sectors="64" />
  <program filename="..\NON-HLOS.ubi" label="modem" num_partition_sectors="24000" />
  <program filename="..\NON-HLOS.ubi" label="modem_b" num_partition_sectors="24000" />
  <program filename="..\boot.img" label="boot" num_partition_sectors="15616" />
  <program filename="..\boot.img" label="boot_b" num_partition_sectors="15616" />
  <program filename="..\sysfs.ubi" label="system" num_partition_sectors="22000" />
  <program filename="..\sysfs.ubi" label="system_b" num_partition_sectors="22000" />
  <program filename="..\efs2.bin" label="efs2" num_partition_sectors="100" />
  <program filename="..\usrdata.ubi" label="usrdata" num_partition_sectors="1000" />
  <program filename="..\partition_nand.xml" label="mibib" num_partition_sectors="10" />
  <program filename="" label="misc" num_partition_sectors="10" />
</data>
"#;

    fn sample_md5s() -> HashMap<String, String> {
        let mut txt = String::new();
        for f in [
            "sbl1.mbn", "xbl_config.elf", "xbl_ramdump.elf", "abl.elf", "uefi.elf",
            "tz.mbn", "devcfg.mbn", "cmnlib64.mbn", "km41.mbn", "apdp.mbn",
            "multi_image.mbn", "multi_image_qti.mbn", "aop.mbn", "aop_devcfg.mbn",
            "qhee.mbn", "qupv3fw.elf", "shrm.elf", "cpucp.elf", "ipa_fws.elf",
            "NON-HLOS.ubi", "boot.img", "sysfs.ubi",
        ] {
            txt.push_str(&format!("FILE:\\update\\{f}:0123456789ABCDEF0123456789ABCDEF\r\n"));
        }
        parse_md5_txt(&txt)
    }

    #[test]
    fn parses_58_partition_r02_and_rejects_single_slot_r01() {
        let mtds = parse_proc_mtd(PROC_MTD_R02A02);
        assert_eq!(mtds.len(), 58);
        let layout = detect_ab_layout(&mtds).expect("58-part A/B layout");
        assert_eq!(layout.ab_bases.len(), 22);
        assert_eq!(layout.partitions["system"].num, 55);
        assert_eq!(layout.partitions["system_b"].num, 56);

        let legacy = parse_proc_mtd(PROC_MTD_R01A04_SINGLE_SLOT);
        let err = detect_ab_layout(&legacy).unwrap_err();
        assert!(err.contains("boot_b") && err.contains("R02A02+"), "{err}");
    }

    #[test]
    fn parses_windows_md5_txt_and_rawprogram_xml() {
        let md5s = parse_md5_txt(
            "\u{feff}FILE:\\update\\boot.img:C3B4C2CDD29892C1F9BF7A73F9A818F5\r\n\
             FILE:\\update\\NON-HLOS.ubi:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
             FILE:\\update\\bad.bin:not-hex\r\n",
        );
        assert_eq!(
            md5s.get("update/boot.img").map(String::as_str),
            Some("c3b4c2cdd29892c1f9bf7a73f9a818f5")
        );
        assert_eq!(
            md5s.get("update/NON-HLOS.ubi").map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(!md5s.contains_key("update/bad.bin"));

        let manifest = parse_rawprogram_xml(SAMPLE_RAWPROGRAM_XML).expect("rawprogram");
        assert_eq!(manifest.project_name.as_deref(), Some("RM551EGL00AAA_VA"));
        let boot = manifest.entries.iter().find(|e| e.base_label == "boot").unwrap();
        assert_eq!(boot.zip_relpath, "update/boot.img");
        assert!(!boot.is_ubi);
        let sys = manifest.entries.iter().find(|e| e.base_label == "system").unwrap();
        assert_eq!(sys.zip_relpath, "update/sysfs.ubi");
        assert!(sys.is_ubi);

        // Path traversal escaping above package root is rejected
        let evil = r#"<data><program filename="..\..\..\etc\shadow" label="boot" /></data>"#;
        let err = parse_rawprogram_xml(evil).unwrap_err();
        assert!(err.contains("escapes"), "{err}");

        let abs = r#"<data><program filename="/etc/passwd" label="boot" /></data>"#;
        assert!(parse_rawprogram_xml(abs).is_err());
    }

    #[test]
    fn build_flash_plan_enforces_inactive_slot_never_touch_and_ubi_attached() {
        let mtds = parse_proc_mtd(PROC_MTD_R02A02);
        let layout = detect_ab_layout(&mtds).unwrap();
        let manifest = parse_rawprogram_xml(SAMPLE_RAWPROGRAM_XML).unwrap();
        let md5s = sample_md5s();
        // Active slot A has system (55) and usrdata (57) attached
        let mut attached = HashSet::from([55u32, 57u32]);

        // Rootfs from Slot A -> flashes boot_b (52), system_b (56)
        let plan_a_root = build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &md5s, &attached,
            false, Some("RM551EGL00AAA_VA"), Some("R02A02"), false,
        ).unwrap();
        assert_eq!(plan_a_root.target_slot, Slot::B);
        let names: Vec<&str> = plan_a_root.partitions.iter().map(|p| p.target_partition.as_str()).collect();
        assert_eq!(names, vec!["boot_b", "system_b"]);

        // Full from Slot A -> all 22 _b partitions, sbl_b LAST, ZERO NEVER-TOUCH or active-slot parts
        let plan_a_full = build_flash_plan(
            &layout, Slot::A, FlashScope::Full, &manifest, &md5s, &attached,
            false, Some("RM551EGL00AAA_VA"), None, false,
        ).unwrap();
        assert_eq!(plan_a_full.partitions.len(), 22);
        assert_eq!(plan_a_full.partitions.first().unwrap().target_partition, "boot_b");
        assert_eq!(plan_a_full.partitions.last().unwrap().target_partition, "sbl_b");
        for p in &plan_a_full.partitions {
            assert!(p.target_partition.ends_with("_b"), "{}", p.target_partition);
            assert!(!is_never_touch_partition(&p.target_partition));
            assert!(!is_never_touch_partition(&p.base_label));
        }

        // Baseband from Slot B -> 15 bare (Slot A) partitions, modem FIRST
        let attached_b = HashSet::from([56u32, 57u32]);
        let plan_b_bb = build_flash_plan(
            &layout, Slot::B, FlashScope::Baseband, &manifest, &md5s, &attached_b,
            false, Some("RM551EGL00AAA_VA"), None, false,
        ).unwrap();
        assert_eq!(plan_b_bb.target_slot, Slot::A);
        assert_eq!(plan_b_bb.partitions.len(), 15);
        assert_eq!(plan_b_bb.partitions.first().unwrap().target_partition, "modem");
        for p in &plan_b_bb.partitions {
            assert!(!p.target_partition.ends_with("_b"), "{}", p.target_partition);
        }

        // Project mismatch fails closed unless overridden
        assert!(build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &md5s, &attached,
            false, Some("OTHER_PROJECT"), None, false,
        ).is_err());
        assert!(build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &md5s, &attached,
            false, Some("OTHER_PROJECT"), None, true,
        ).is_ok());

        // Missing MD5 fails closed unless allow_no_manifest
        assert!(build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &HashMap::new(), &attached,
            false, Some("RM551EGL00AAA_VA"), None, false,
        ).is_err());
        assert!(build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &HashMap::new(), &attached,
            true, Some("RM551EGL00AAA_VA"), None, false,
        ).is_ok());

        // Attached target MTD (system_b = 56) is hard-blocked!
        attached.insert(56);
        let err = build_flash_plan(
            &layout, Slot::A, FlashScope::Rootfs, &manifest, &md5s, &attached,
            false, Some("RM551EGL00AAA_VA"), None, false,
        ).unwrap_err();
        assert!(err.contains("UBI-attached"), "{err}");
    }

    #[test]
    fn parses_cmdline_slot_and_rci_output() {
        assert_eq!(
            parse_cmdline_slot("console=ttyMSM0,115200 ubi.mtd=55 SLOT_SUFFIX=_a root=ubi0:rootfs"),
            Some(Slot::A)
        );
        assert_eq!(
            parse_cmdline_slot("ubi.mtd=56 SLOT_SUFFIX=_b quiet"),
            Some(Slot::B)
        );
        assert_eq!(parse_cmdline_slot("root=ubi0:rootfs"), None);

        let rci = parse_rci_output(
            "selected_set: 1\n\
             trial_boot_enable: 1\n\
             trial_boot_max_attempts: 3\n\
             trial_boot_failed_attempts: 0\n\
             image_set_to_boot: 1\n",
        );
        assert_eq!(rci.selected_set, Some(1));
        assert_eq!(rci.trial_boot_enable, Some(1));
        assert_eq!(rci.trial_boot_max_attempts, Some(3));
        assert_eq!(rci.trial_boot_failed_attempts, Some(0));
        assert_eq!(rci.image_set_to_boot, Some(1));
    }

    // Serialize unit tests that acquire the process-wide A/B OPERATION_LOCK.
    static TEST_OP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn end_to_end_dry_run_against_synthetic_firmware_dir() {
        let _op_guard = TEST_OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sbx = crate::paths::TestSandbox::new("fw-ab-dryrun");
        sbx.write("/proc/mtd", PROC_MTD_R02A02);
        sbx.write("/proc/cmdline", "ubi.mtd=55 SLOT_SUFFIX=_a root=ubi0:rootfs\n");
        sbx.write(
            "/etc/quectel-project-version",
            "Project Name: RM551EGL00AAA_VA\nProject Rev : RM551EGL00AAR02A02M8G_01.001\n",
        );
        sbx.write("/sys/class/ubi/ubi0/mtd_num", "55\n");
        sbx.write("/sys/class/ubi/ubi2/mtd_num", "57\n");
        sbx.write_exec(
            "/sbin/abctl",
            "#!/bin/sh\ncase \"$1\" in\n--boot_slot) echo _a ;;\n--get_unbootable) echo 0 ;;\n--get_trialboot_status) echo 0 ;;\n*) exit 0 ;;\nesac\n",
        );

        let fw_dir = sbx.root.join("pkg");
        let boot_bytes = b"ANDROID!synthetic-boot-image-data-for-test";
        let mut sys_bytes = b"UBI#".to_vec();
        sys_bytes.extend_from_slice(&[0x55u8; 4096]);
        let boot_md5 = hex::encode(md5::Md5::digest(boot_bytes));
        let sys_md5 = hex::encode(md5::Md5::digest(&sys_bytes));

        fs::create_dir_all(fw_dir.join("update/firehose")).unwrap();
        fs::write(fw_dir.join("update/boot.img"), boot_bytes).unwrap();
        fs::write(fw_dir.join("update/sysfs.ubi"), &sys_bytes).unwrap();
        fs::write(
            fw_dir.join("update/firehose/rawprogram_nand_p4K_b256K_update.xml"),
            r#"<?xml version="1.0" ?>
<data>
  <erase c_project_name="RM551EGL00AAA_VA" />
  <program filename="..\boot.img" label="boot" num_partition_sectors="100" />
  <program filename="..\sysfs.ubi" label="system" num_partition_sectors="200" />
  <program filename="..\efs2.bin" label="efs2" num_partition_sectors="50" />
</data>
"#,
        )
        .unwrap();
        fs::write(
            fw_dir.join("md5.txt"),
            format!(
                "FILE:\\update\\boot.img:{}\r\nFILE:\\update\\sysfs.ubi:{}\r\n",
                boot_md5.to_uppercase(),
                sys_md5.to_uppercase()
            ),
        )
        .unwrap();

        let report = inspect_package(&fw_dir, FlashScope::Rootfs, false, false).expect("inspect");
        assert_eq!(report.plan.active_slot, Slot::A);
        assert_eq!(report.plan.target_slot, Slot::B);
        assert_eq!(report.plan.partitions.len(), 2);
        assert_eq!(report.plan.partitions[0].target_partition, "boot_b");
        assert_eq!(report.plan.partitions[1].target_partition, "system_b");

        let mut seen = Vec::new();
        let st = execute_flash(
            &report.plan,
            &fw_dir,
            FlashOptions {
                dry_run: true,
                ..Default::default()
            },
            |line, _, _, _| seen.push(line.to_string()),
        )
        .expect("dry run");
        assert_eq!(st.status, "dry_run_ok");
        assert_eq!(st.partitions_flashed, vec!["boot_b", "system_b"]);
        assert!(seen.iter().any(|l| l.contains("DRY-RUN complete")));

        // Corrupt boot.img -> dry_run fails closed on MD5 mismatch
        fs::write(fw_dir.join("update/boot.img"), b"corrupted").unwrap();
        let err = execute_flash(
            &report.plan,
            &fw_dir,
            FlashOptions {
                dry_run: true,
                ..Default::default()
            },
            |_, _, _, _| {},
        )
        .unwrap_err();
        assert!(err.contains("MD5 mismatch"), "{err}");

        // Restore boot.img, corrupt UBI magic on sysfs.ubi (updating md5.txt to match) -> fails on UBI# magic!
        fs::write(fw_dir.join("update/boot.img"), boot_bytes).unwrap();
        let bad_ubi = b"NOPEnot-a-ubi-image";
        let bad_md5 = hex::encode(md5::Md5::digest(bad_ubi));
        fs::write(fw_dir.join("update/sysfs.ubi"), bad_ubi).unwrap();
        fs::write(
            fw_dir.join("md5.txt"),
            format!("FILE:\\update\\boot.img:{boot_md5}\r\nFILE:\\update\\sysfs.ubi:{bad_md5}\r\n"),
        )
        .unwrap();
        let report2 = inspect_package(&fw_dir, FlashScope::Rootfs, false, false).unwrap();
        let err2 = execute_flash(
            &report2.plan,
            &fw_dir,
            FlashOptions {
                dry_run: true,
                ..Default::default()
            },
            |_, _, _, _| {},
        )
        .unwrap_err();
        assert!(err2.contains("invalid UBI magic"), "{err2}");
    }

    #[test]
    fn switch_slot_refuses_dirty_target_slot_unless_forced() {
        let _op_guard = TEST_OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sbx = crate::paths::TestSandbox::new("fw-ab-dirty-slot");
        sbx.write("/proc/mtd", PROC_MTD_R02A02);
        sbx.write("/proc/cmdline", "ubi.mtd=55 SLOT_SUFFIX=_a root=ubi0:rootfs\n");
        sbx.write_exec(
            "/sbin/abctl",
            "#!/bin/sh\ncase \"$1\" in\n--boot_slot) echo _a ;;\n--get_unbootable) echo 0 ;;\n--set_active) exit 0 ;;\n*) exit 0 ;;\nesac\n",
        );

        for dirty_status in ["flashing_in_progress", "failed"] {
            save_persisted_state(&PersistedAbFlashState {
                status: dirty_status.into(),
                target_slot: Some(Slot::B),
                previous_slot: Some(Slot::A),
                partitions_flashed: vec!["boot_b".into()],
                message: Some("simulated partial failure".into()),
                ..Default::default()
            })
            .unwrap();

            let err = switch_slot(Some(Slot::B), false, false).unwrap_err();
            assert!(
                err.contains("dirty") && err.contains(dirty_status),
                "expected dirty-slot refusal for {dirty_status}, got: {err}"
            );
        }

        // Explicit force=true overrides the dirty-slot guard
        let forced = switch_slot(Some(Slot::B), false, true).expect("forced switch");
        assert_eq!(forced.status, "switched");
        assert_eq!(forced.target_slot, Some(Slot::B));
    }

    #[test]
    fn http_source_path_enforces_tmp_and_usrdata_confinement() {
        let sbx = crate::paths::TestSandbox::new("fw-ab-path-confine");
        sbx.write("/tmp/good.zip", "PK\x03\x04test");
        sbx.write("/usrdata/cache/good2.zip", "PK\x03\x04test");
        sbx.write("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n");

        // Regular files inside /tmp and /usrdata pass
        assert!(validate_http_source_path("/tmp/good.zip").is_ok());
        assert!(validate_http_source_path("/usrdata/cache/good2.zip").is_ok());

        // Paths outside /tmp and /usrdata are rejected
        assert!(validate_http_source_path("/etc/passwd").is_err());
        assert!(validate_http_source_path("/tmp/../etc/passwd").is_err());
        assert!(validate_http_source_path("relative/fw.zip").is_err());
        assert!(validate_http_source_path("/tmp").is_err());

        // Symlinks are rejected even when inside /tmp
        let sym_escape = sbx.root.join("tmp/escape.zip");
        std::os::unix::fs::symlink(sbx.root.join("etc/passwd"), &sym_escape).unwrap();
        assert!(validate_http_source_path("/tmp/escape.zip").is_err());

        let sym_local = sbx.root.join("tmp/alias.zip");
        std::os::unix::fs::symlink(sbx.root.join("tmp/good.zip"), &sym_local).unwrap();
        assert!(validate_http_source_path("/tmp/alias.zip").is_err());

        // FIFOs are rejected
        let fifo_path = sbx.root.join("tmp/pipe.zip");
        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        assert!(validate_http_source_path("/tmp/pipe.zip").is_err());
    }

    #[test]
    fn scans_staged_firmware_zips_and_detects_vendor_init_conflicts() {
        let sbx = crate::paths::TestSandbox::new("fw-ab-staged-scan");
        sbx.write("/tmp/older.zip", "PK\x03\x04older");
        sbx.write("/usrdata/cache/newer.zip", "PK\x03\x04newer-payload");
        sbx.write("/tmp/not-a-zip.txt", "ignore me");
        sbx.write("/tmp/.hidden.zip", "PK\x03\x04hidden");
        fs::create_dir_all(sbx.root.join("tmp/dir.zip")).unwrap();
        std::os::unix::fs::symlink(
            sbx.root.join("tmp/older.zip"),
            sbx.root.join("tmp/symlink.zip"),
        )
        .unwrap();

        // Set explicit mtimes so sorting is deterministic (newer.zip > older.zip)
        let older_p = CString::new(sbx.root.join("tmp/older.zip").as_os_str().as_bytes()).unwrap();
        let newer_p = CString::new(
            sbx.root
                .join("usrdata/cache/newer.zip")
                .as_os_str()
                .as_bytes(),
        )
        .unwrap();
        let old_tv = [
            libc::timeval { tv_sec: 1_700_000_100, tv_usec: 0 },
            libc::timeval { tv_sec: 1_700_000_100, tv_usec: 0 },
        ];
        let new_tv = [
            libc::timeval { tv_sec: 1_700_000_200, tv_usec: 0 },
            libc::timeval { tv_sec: 1_700_000_200, tv_usec: 0 },
        ];
        unsafe {
            libc::utimes(older_p.as_ptr(), old_tv.as_ptr());
            libc::utimes(newer_p.as_ptr(), new_tv.as_ptr());
        }

        let files = scan_staged_firmware_zips(1);
        assert_eq!(files.len(), 2, "{files:?}");
        assert_eq!(files[0].name, "newer.zip");
        assert_eq!(files[0].path, "/usrdata/cache/newer.zip");
        assert_eq!(files[1].name, "older.zip");
        assert_eq!(files[1].path, "/tmp/older.zip");

        // Filename sanitization
        assert_eq!(sanitize_upload_filename(None).unwrap(), "firmware-upload.zip");
        assert_eq!(
            sanitize_upload_filename(Some("RM551E_R02A02-test.zip")).unwrap(),
            "RM551E_R02A02-test.zip"
        );
        assert!(sanitize_upload_filename(Some("../evil.zip")).is_err());
        assert!(sanitize_upload_filename(Some("bad name.zip")).is_err());
        assert!(sanitize_upload_filename(Some("notzip.bin")).is_err());

        // Vendor init & proc detection
        sbx.write("/etc/rc.d/S90ab-updater", "");
        sbx.write("/etc/rc.d/S95mirror_copy", "");
        assert_eq!(detect_vendor_ab_init_enabled(), (true, true));
        sbx.write("/proc/4321/comm", "mirror_copy\n");
        let procs = detect_conflicting_vendor_ab_procs();
        assert_eq!(procs, vec!["mirror_copy (pid 4321)".to_string()]);
    }
}

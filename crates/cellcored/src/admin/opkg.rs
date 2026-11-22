//! Software › opkg: installed / available (search) / info, update lists, install,
//! remove. Removal of packages CellCore or the platform depends on needs a
//! typed confirmation; CellCore's own package cannot be removed here.

use std::{
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};

use super::{
    audit, bad, conflict, exec::{ExecOpts, KIB, MIB, run}, forbidden, mutate_lock, ok, require_confirm, server,
    validate::is_safe_name,
};
use crate::http::HttpCtx;

const QM_PACKAGE_PREFIX: &str = "sdxpinn-cellcore";
pub const QM_PACKAGE_DEFAULT: &str = "sdxpinn-cellcore";
pub const MIN_SELF_UPGRADE_BYTES: u64 = 15 * 1024 * 1024;
pub const SELF_UPGRADE_STATE_PATH: &str = "/tmp/cellcore/self-upgrade.json";
pub const SELF_UPGRADE_LOG_PATH: &str = "/tmp/cellcore/self-upgrade.log";
const SELF_UPGRADE_SCRIPT_PATH: &str = "/tmp/cellcore/self-upgrade.sh";
const OPKG_STATUS_PATH: &str = "/usr/lib/opkg/status";
const CUSTOM_FEEDS_PATH: &str = "/etc/opkg/customfeeds.conf";
const DIST_FEEDS_PATH: &str = "/etc/opkg/distfeeds.conf";
const FEEDS_MAX_BYTES: usize = 16 * 1024;
const LIST_CACHE_TTL: Duration = Duration::from_secs(600);

/// Packages whose removal breaks the platform, networking or access.
const CORE_PACKAGES: &[&str] = &[
    "base-files", "busybox", "libc", "procd", "ubus", "ubusd", "uci", "libuci20130104", "netifd", "firewall4", "nftables",
    "nftables-json", "dnsmasq", "dropbear", "opkg", "uhttpd", "mwan3", "odhcpd", "odhcpd-ipv6only", "rpcd", "jshn",
    "jsonfilter", "libubox20230523", "ca-bundle", "ca-certificates", "kernel", "fstools", "logd", "urandom-seed",
];
const CORE_PREFIXES: &[&str] = &["QCMAP", "kmod-", "libqcmap", "sdxpinn-", "ql-", "quectel"];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// `opkg list-installed` / `opkg list` lines: `name - version[ - description]`.
/// Noise lines (warnings, "Multiple packages …") are skipped.
pub fn parse_pkg_lines(text: &str) -> Vec<Pkg> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.splitn(3, " - ");
            let name = it.next()?.trim();
            let version = it.next()?.trim();
            let description = it.next().unwrap_or("").trim();
            if !is_safe_name(name, 128) || version.is_empty() || version.contains(' ') {
                return None;
            }
            Some(Pkg { name: name.into(), version: version.into(), description: description.into() })
        })
        .collect()
}

/// `opkg info` / `opkg status` output: blank-line separated stanzas of
/// `Key: value`, with indented continuation lines.
pub fn parse_info(text: &str) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    for l in text.lines() {
        if l.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if l.starts_with(' ') || l.starts_with('\t') {
            if let Some(last) = cur.last_mut() {
                if !last.1.is_empty() {
                    last.1.push('\n');
                }
                last.1.push_str(l.trim());
            }
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            cur.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn field<'a>(stanza: &'a [(String, String)], key: &str) -> Option<&'a str> {
    stanza.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Package names from a `Depends:` field: "libc, uci, foo (>= 1.2)".
pub fn parse_depends(dep: &str) -> Vec<String> {
    dep.split(',')
        .filter_map(|d| {
            let n = d.trim().split(|c: char| c.is_whitespace() || c == '(').next()?.trim();
            (!n.is_empty()).then(|| n.to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PkgGuard {
    None,
    Protected,
    Blocked,
}

pub fn guard_for(name: &str, qm_depends: &[String]) -> PkgGuard {
    if name.starts_with(QM_PACKAGE_PREFIX) {
        return PkgGuard::Blocked;
    }
    if CORE_PACKAGES.contains(&name) || CORE_PREFIXES.iter().any(|p| name.starts_with(p)) || qm_depends.iter().any(|d| d == name) {
        return PkgGuard::Protected;
    }
    PkgGuard::None
}

fn opkg_busy(out: &str) -> bool {
    out.contains("Could not lock") || out.contains("opkg.lock")
}

/// Free bytes on the overlay root mount (non-root `f_bavail`).
pub(crate) fn overlay_free_bytes() -> Option<u64> {
    let path = c"/";
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and a properly sized out-struct.
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Free space of the overlay (the root mount on this build).
fn overlay_space() -> serde_json::Value {
    let path = c"/";
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and a properly sized out-struct.
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return serde_json::Value::Null;
    }
    let bs = st.f_frsize as u64;
    serde_json::json!({
        "totalKb": st.f_blocks as u64 * bs / 1024,
        "freeKb": st.f_bavail as u64 * bs / 1024,
    })
}

fn ver_char_weight(b: u8) -> i32 {
    if b == b'~' {
        -1
    } else if b.is_ascii_alphabetic() {
        i32::from(b)
    } else {
        i32::from(b) + 256
    }
}

fn cmp_ver_segment(mut a: &[u8], mut b: &[u8]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    while !a.is_empty() || !b.is_empty() {
        let a_non = a.iter().position(|c| c.is_ascii_digit()).unwrap_or(a.len());
        let b_non = b.iter().position(|c| c.is_ascii_digit()).unwrap_or(b.len());
        let (an, rest_a) = a.split_at(a_non);
        let (bn, rest_b) = b.split_at(b_non);
        let max_non = an.len().max(bn.len());
        for i in 0..max_non {
            let aw = an.get(i).copied().map(ver_char_weight).unwrap_or(0);
            let bw = bn.get(i).copied().map(ver_char_weight).unwrap_or(0);
            match aw.cmp(&bw) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        a = rest_a;
        b = rest_b;

        let a_dig = a.iter().position(|c| !c.is_ascii_digit()).unwrap_or(a.len());
        let b_dig = b.iter().position(|c| !c.is_ascii_digit()).unwrap_or(b.len());
        let (ad, rest_a2) = a.split_at(a_dig);
        let (bd, rest_b2) = b.split_at(b_dig);
        let atrim = &ad[ad.iter().position(|&c| c != b'0').unwrap_or(ad.len())..];
        let btrim = &bd[bd.iter().position(|&c| c != b'0').unwrap_or(bd.len())..];
        match atrim.len().cmp(&btrim.len()).then_with(|| atrim.cmp(btrim)) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        a = rest_a2;
        b = rest_b2;
    }
    Ordering::Equal
}

fn split_opkg_version(v: &str) -> (u64, &str, &str) {
    let s = v.trim();
    let (epoch, after_epoch) = match s.split_once(':') {
        Some((ep, rest)) if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) => {
            (ep.parse::<u64>().unwrap_or(0), rest)
        }
        _ => (0, s),
    };
    match after_epoch.rsplit_once('-') {
        Some((up, rev)) => (epoch, up, rev),
        None => (epoch, after_epoch, ""),
    }
}

/// Compare two opkg/ipk version strings using epoch, upstream, and `-revision` rules.
pub fn compare_opkg_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (ea, ua, ra) = split_opkg_version(a);
    let (eb, ub, rb) = split_opkg_version(b);
    ea.cmp(&eb)
        .then_with(|| cmp_ver_segment(ua.as_bytes(), ub.as_bytes()))
        .then_with(|| cmp_ver_segment(ra.as_bytes(), rb.as_bytes()))
}

pub(crate) fn find_qm_package_status() -> (String, Option<String>) {
    if let Some((pkgs, _)) = read_installed_from_status()
        && let Some(p) = pkgs
            .iter()
            .find(|p| p.name == QM_PACKAGE_DEFAULT)
            .or_else(|| pkgs.iter().find(|p| p.name.starts_with(QM_PACKAGE_PREFIX)))
    {
        return (p.name.clone(), Some(p.version.clone()));
    }
    (QM_PACKAGE_DEFAULT.to_string(), None)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SelfUpgradeState {
    pub active: bool,
    pub phase: String,
    pub package: String,
    pub from_version: Option<String>,
    pub target_version: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
    pub pid: Option<u32>,
    pub error: Option<String>,
    pub rolled_back: bool,
}

impl SelfUpgradeState {
    fn idle() -> Self {
        Self {
            active: false,
            phase: "idle".into(),
            ..Self::default()
        }
    }
}

pub(crate) fn read_self_upgrade_state() -> SelfUpgradeState {
    let path = crate::paths::p(SELF_UPGRADE_STATE_PATH);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<SelfUpgradeState>(&s).ok())
        .unwrap_or_else(SelfUpgradeState::idle)
}

fn tail_log_lines(path: &str, limit: usize) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(crate::paths::p(path)) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(limit);
    lines[start..].iter().map(|s| (*s).to_string()).collect()
}

fn safe_script_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'~' | b':'))
}

pub(crate) fn build_self_upgrade_script(
    pkg: &str,
    from_ver: &str,
    target_ver: &str,
    state_path: &str,
    log_path: &str,
) -> String {
    format!(
        r#"#!/bin/sh
set -u
PKG='{pkg}'
FROM_VER='{from_ver}'
TARGET_VER='{target_ver}'
STATE='{state_path}'
LOG='{log_path}'
RB='/tmp/qm-rollback'
mkdir -p /tmp/cellcore
exec >> "$LOG" 2>&1
STARTED_AT=$(date +%s 2>/dev/null || echo 0)
write_state() {{
  now=$(date +%s 2>/dev/null || echo 0)
  err_esc=$(printf '%s' "${{4:-}}" | tr '\r\n"' '   ')
  tmp="${{STATE}}.tmp.$$"
  if [ -n "$err_esc" ]; then
    err_json="\"$err_esc\""
  else
    err_json="null"
  fi
  printf '{{"active":%s,"phase":"%s","package":"%s","fromVersion":"%s","targetVersion":"%s","startedAt":%s,"updatedAt":%s,"pid":%s,"error":%s,"rolledBack":%s}}\n' \
    "$1" "$2" "$PKG" "$FROM_VER" "$TARGET_VER" "$STARTED_AT" "$now" "$$" "$err_json" "$3" > "$tmp" && mv -f "$tmp" "$STATE"
}}
echo "=== CellCore self-upgrade started ($PKG $FROM_VER -> $TARGET_VER) ==="
write_state true "snapshotting" false ""
rm -rf "$RB"
mkdir -p "$RB/etc" "$RB/opkg-info"
[ -x /usr/sbin/cellcored ] && cp -a /usr/sbin/cellcored "$RB/cellcored"
[ -d /www ] && cp -a /www "$RB/www"
[ -f /etc/init.d/cellcored ] && cp -a /etc/init.d/cellcored "$RB/init.d-cellcored"
[ -f /etc/init.d/dropbear-lan-watchdog ] && cp -a /etc/init.d/dropbear-lan-watchdog "$RB/init.d-dropbear-lan-watchdog"
[ -d /etc/cellcore ] && cp -a /etc/cellcore "$RB/etc/cellcore"
[ -f /usr/lib/opkg/status ] && cp -a /usr/lib/opkg/status "$RB/opkg-status"
cp -a /usr/lib/opkg/info/sdxpinn-cellcore.* "$RB/opkg-info/" 2>/dev/null || true
rollback() {{
  reason="$1"
  echo "ERROR: $reason -- rolling back"
  write_state true "rolling_back" true "$reason"
  [ -x "$RB/cellcored" ] && cp -af "$RB/cellcored" /usr/sbin/cellcored
  if [ -d "$RB/www" ]; then
    rm -rf /www
    cp -a "$RB/www" /www
  fi
  [ -f "$RB/init.d-cellcored" ] && cp -af "$RB/init.d-cellcored" /etc/init.d/cellcored
  [ -f "$RB/init.d-dropbear-lan-watchdog" ] && cp -af "$RB/init.d-dropbear-lan-watchdog" /etc/init.d/dropbear-lan-watchdog
  if [ -d "$RB/etc/cellcore" ]; then
    mkdir -p /etc/cellcore
    cp -af "$RB/etc/cellcore/." /etc/cellcore/
  fi
  [ -f "$RB/opkg-status" ] && cp -af "$RB/opkg-status" /usr/lib/opkg/status
  if [ -d "$RB/opkg-info" ]; then
    rm -f /usr/lib/opkg/info/sdxpinn-cellcore.* 2>/dev/null || true
    cp -af "$RB/opkg-info/." /usr/lib/opkg/info/ 2>/dev/null || true
  fi
  /etc/init.d/cellcored restart >/dev/null 2>&1 || /etc/init.d/cellcored start >/dev/null 2>&1 || true
  sleep 2
  write_state false "rolled_back" true "$reason"
  exit 1
}}
write_state true "updating_feeds" false ""
if ! opkg update; then
  rollback "opkg update failed"
fi
write_state true "upgrading" false ""
if ! opkg upgrade "$PKG"; then
  rollback "opkg upgrade $PKG failed"
fi
write_state true "verifying" false ""
i=0
verified=0
while [ "$i" -lt 45 ]; do
  if /usr/sbin/cellcored verify --expect-wan 0 >/dev/null 2>&1; then
    verified=1
    break
  fi
  sleep 1
  i=$((i + 1))
done
if [ "$verified" -ne 1 ]; then
  rollback "cellcored verify timed out after 45s"
fi
RESCUE_DL="/tmp/qm-rescue-dl.$$"
mkdir -p "$RESCUE_DL" /etc/cellcore-rescue
if (cd "$RESCUE_DL" && opkg download "$PKG" >/dev/null 2>&1); then
  ipk_f=$(ls -1 "$RESCUE_DL"/"${{PKG}}"_*.ipk "$RESCUE_DL"/*.ipk 2>/dev/null | head -n 1)
  if [ -n "$ipk_f" ] && [ -f "$ipk_f" ]; then
    cp -f "$ipk_f" /etc/cellcore-rescue/cellcore.ipk.tmp && mv -f /etc/cellcore-rescue/cellcore.ipk.tmp /etc/cellcore-rescue/cellcore.ipk
    echo "Staged verified rescue package -> /etc/cellcore-rescue/cellcore.ipk"
  fi
fi
rm -rf "$RESCUE_DL"
rm -rf "$RB"
echo "=== CellCore self-upgrade succeeded ($PKG -> $TARGET_VER) ==="
write_state false "succeeded" false ""
"#
    )
}

/// Parse installed packages and CellCore's `Depends` directly from `/usr/lib/opkg/status`
/// without forking `opkg`.
pub fn parse_installed_from_status(text: &str) -> (Vec<Pkg>, Vec<String>) {
    let mut pkgs = Vec::new();
    let mut qm_deps = Vec::new();
    for stanza in parse_info(text) {
        let Some(status) = field(&stanza, "Status") else {
            continue;
        };
        if !status.contains("installed") || status.contains("not-installed") || status.contains("deinstall") {
            continue;
        }
        let Some(name) = field(&stanza, "Package") else {
            continue;
        };
        let Some(version) = field(&stanza, "Version") else {
            continue;
        };
        if !is_safe_name(name, 128) || version.trim().is_empty() {
            continue;
        }
        if name.starts_with(QM_PACKAGE_PREFIX)
            && let Some(dep) = field(&stanza, "Depends")
        {
            qm_deps = parse_depends(dep);
        }
        pkgs.push(Pkg {
            name: name.to_string(),
            version: version.trim().to_string(),
            description: String::new(),
        });
    }
    pkgs.sort_by_key(|a| a.name.to_ascii_lowercase());
    (pkgs, qm_deps)
}

fn read_installed_from_status() -> Option<(Vec<Pkg>, Vec<String>)> {
    let text = std::fs::read_to_string(crate::paths::p(OPKG_STATUS_PATH)).ok()?;
    Some(parse_installed_from_status(&text))
}

async fn qm_depends() -> Vec<String> {
    if let Some((_, deps)) = read_installed_from_status() {
        return deps;
    }
    let Ok(out) = run("opkg", &["status", "sdxpinn-cellcore"], ExecOpts::new(20, 64 * KIB)).await else {
        return Vec::new();
    };
    parse_info(&out.stdout_str())
        .first()
        .and_then(|s| field(s, "Depends"))
        .map(parse_depends)
        .unwrap_or_default()
}

fn lists_age_secs() -> Option<u64> {
    let rd = std::fs::read_dir(crate::paths::p("/var/opkg-lists")).ok()?;
    rd.flatten()
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
}

pub async fn get_software() -> Response {
    let (pkgs, deps) = match read_installed_from_status() {
        Some(pair) => pair,
        None => {
            let out = match run("opkg", &["list-installed"], ExecOpts::new(30, 4 * MIB)).await {
                Ok(o) => o,
                Err(e) => return server(e),
            };
            if !out.ok() && opkg_busy(&out.log()) {
                return conflict("opkg is busy (another install or update is running); try again shortly");
            }
            (parse_pkg_lines(&out.stdout_str()), qm_depends().await)
        }
    };
    let installed: Vec<serde_json::Value> = pkgs
        .into_iter()
        .map(|p| serde_json::json!({ "name": p.name, "version": p.version, "guard": guard_for(&p.name, &deps) }))
        .collect();
    ok(serde_json::json!({
        "installed": installed,
        "space": overlay_space(),
        "listsAgeSecs": lists_age_secs(),
        "quecmanagerDepends": deps,
    }))
}

type ListCache = Mutex<Option<(Instant, Vec<Pkg>)>>;
static LIST_CACHE: OnceLock<ListCache> = OnceLock::new();

fn invalidate_cache() {
    if let Ok(mut c) = LIST_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *c = None;
    }
}

async fn available() -> Result<Vec<Pkg>, String> {
    if let Ok(c) = LIST_CACHE.get_or_init(|| Mutex::new(None)).lock()
        && let Some((t, v)) = c.as_ref()
        && t.elapsed() < LIST_CACHE_TTL
    {
        return Ok(v.clone());
    }
    let out = run("opkg", &["list"], ExecOpts::new(60, 8 * MIB)).await?;
    if !out.ok() {
        let log = out.log();
        return Err(if opkg_busy(&log) { "opkg is busy; try again shortly".into() } else { out.err_summary("opkg list") });
    }
    let v = parse_pkg_lines(&out.stdout_str());
    if let Ok(mut c) = LIST_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *c = Some((Instant::now(), v.clone()));
    }
    Ok(v)
}

#[derive(Deserialize)]
pub struct SearchQ {
    #[serde(default)]
    q: String,
}

pub fn search(pkgs: &[Pkg], q: &str, limit: usize) -> (Vec<Pkg>, usize) {
    let q = q.trim().to_ascii_lowercase();
    let mut hits: Vec<&Pkg> = pkgs
        .iter()
        .filter(|p| p.name.to_ascii_lowercase().contains(&q) || p.description.to_ascii_lowercase().contains(&q))
        .collect();
    // Name matches first, then exact/prefix, then alphabetical.
    hits.sort_by_key(|p| {
        let n = p.name.to_ascii_lowercase();
        (n != q, !n.starts_with(&q), !n.contains(&q), n)
    });
    let total = hits.len();
    (hits.into_iter().take(limit).cloned().collect(), total)
}

pub async fn get_available(Query(q): Query<SearchQ>) -> Response {
    let term = q.q.trim();
    if term.chars().count() < 2 || term.len() > 64 || term.chars().any(char::is_control) {
        return bad("Type at least 2 characters to search");
    }
    match available().await {
        Ok(all) => {
            let (results, total) = search(&all, term, 200);
            ok(serde_json::json!({ "results": results, "total": total }))
        }
        Err(e) => server(e),
    }
}

#[derive(Deserialize)]
pub struct NameQ {
    name: String,
}

pub async fn get_info(Query(q): Query<NameQ>) -> Response {
    if !is_safe_name(&q.name, 128) {
        return bad("Invalid package name");
    }
    let mut parsed_stanzas: Vec<Vec<(String, String)>> = std::fs::read_to_string(crate::paths::p(OPKG_STATUS_PATH))
        .map(|txt| {
            parse_info(&txt)
                .into_iter()
                .filter(|s| field(s, "Package") == Some(q.name.as_str()))
                .collect()
        })
        .unwrap_or_default();
    if parsed_stanzas.is_empty() {
        let out = match run("opkg", &["info", &q.name], ExecOpts::new(30, MIB)).await {
            Ok(o) => o,
            Err(e) => return server(e),
        };
        parsed_stanzas = parse_info(&out.stdout_str());
    }
    let stanzas: Vec<serde_json::Value> = parsed_stanzas
        .into_iter()
        .map(|s| serde_json::Value::Object(s.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect()))
        .collect();
    let deps = qm_depends().await;
    ok(serde_json::json!({ "name": q.name, "stanzas": stanzas, "guard": guard_for(&q.name, &deps) }))
}

pub fn validate_feeds(content: &str) -> Result<String, String> {
    if content.len() > FEEDS_MAX_BYTES {
        return Err(format!("Feeds file exceeds {FEEDS_MAX_BYTES} bytes"));
    }
    if content
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("Control characters are not allowed in opkg feeds".into());
    }
    let mut normalized = content.replace("\r\n", "\n");
    for (idx, raw) in normalized.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(format!("Line {}: expected '<src|src/gz> <name> <url>'", idx + 1));
        }
        if !matches!(parts[0], "src" | "src/gz") {
            return Err(format!("Line {}: type must be 'src' or 'src/gz'", idx + 1));
        }
        if !is_safe_name(parts[1], 64) {
            return Err(format!("Line {}: invalid feed name '{}'", idx + 1, parts[1]));
        }
        let url = parts[2];
        if (!url.starts_with("http://") && !url.starts_with("https://"))
            || url.len() > 512
            || url.bytes().any(|b| b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'\'' | b'`'))
        {
            return Err(format!("Line {}: URL must be http:// or https:// without spaces or quotes", idx + 1));
        }
    }
    if !normalized.is_empty() && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    Ok(normalized)
}

pub async fn get_feeds() -> Response {
    let custom = std::fs::read_to_string(crate::paths::p(CUSTOM_FEEDS_PATH)).unwrap_or_default();
    let dist = std::fs::read_to_string(crate::paths::p(DIST_FEEDS_PATH)).unwrap_or_default();
    ok(serde_json::json!({
        "customPath": CUSTOM_FEEDS_PATH,
        "custom": custom,
        "distPath": DIST_FEEDS_PATH,
        "dist": dist,
    }))
}

#[derive(Deserialize)]
pub struct FeedsReq {
    content: String,
}

pub async fn put_feeds(State(ctx): State<HttpCtx>, Json(req): Json<FeedsReq>) -> Response {
    let normalized = match validate_feeds(&req.content) {
        Ok(s) => s,
        Err(e) => return bad(e),
    };
    let _g = mutate_lock().await;
    if let Err(e) = crate::state::atomic_write(Path::new(CUSTOM_FEEDS_PATH), normalized.as_bytes(), 0o644) {
        return server(e);
    }
    invalidate_cache();
    audit(&ctx, format!("updated {} ({} bytes)", CUSTOM_FEEDS_PATH, normalized.len()));
    ok(serde_json::json!({ "status": "ok" }))
}

fn op_result(ctx: &HttpCtx, what: &str, out: super::exec::ExecOut) -> Response {
    let log = out.log();
    audit(ctx, format!("opkg {what} -> {:?}", out.code));
    if out.ok() {
        ok(serde_json::json!({ "status": "ok", "log": super::exec::tail_chars(&log, 32 * 1024) }))
    } else if opkg_busy(&log) {
        conflict("opkg is busy (another install or update is running); try again shortly")
    } else {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "error": format!("opkg {what} failed"), "log": super::exec::tail_chars(&log, 32 * 1024) })),
        )
            .into_response()
    }
}

use axum::response::IntoResponse;

async fn run_opkg_with_retry(args: &[&str], timeout_secs: u64) -> Result<super::exec::ExecOut, String> {
    for attempt in 1..=3 {
        let out = run("opkg", args, ExecOpts::new(timeout_secs, 256 * KIB)).await?;
        let log = out.log();
        if out.ok() || opkg_busy(&log) || !log.contains("Failed to download") || attempt == 3 {
            return Ok(out);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    unreachable!()
}

pub async fn post_update(State(ctx): State<HttpCtx>) -> Response {
    let _g = mutate_lock().await;
    invalidate_cache();
    match run_opkg_with_retry(&["update"], 180).await {
        Ok(out) => op_result(&ctx, "update", out),
        Err(e) => server(e),
    }
}

#[derive(Deserialize)]
pub struct PkgReq {
    name: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_install(State(ctx): State<HttpCtx>, Json(req): Json<PkgReq>) -> Response {
    if !is_safe_name(&req.name, 128) {
        return bad("Invalid package name");
    }
    let space = overlay_space();
    if space["freeKb"].as_u64().is_some_and(|f| f < 2048) {
        return conflict("Less than 2 MiB free on the overlay; free some space first");
    }
    let _g = mutate_lock().await;
    invalidate_cache();
    if lists_age_secs().is_none() {
        match run_opkg_with_retry(&["update"], 180).await {
            Ok(up) if up.ok() => {}
            Ok(up) => return op_result(&ctx, "update", up),
            Err(e) => return server(e),
        }
    }
    match run_opkg_with_retry(&["install", &req.name], 300).await {
        Ok(out) => op_result(&ctx, &format!("install {}", req.name), out),
        Err(e) => server(e),
    }
}

pub async fn post_remove(State(ctx): State<HttpCtx>, Json(req): Json<PkgReq>) -> Response {
    if !is_safe_name(&req.name, 128) {
        return bad("Invalid package name");
    }
    let deps = qm_depends().await;
    match guard_for(&req.name, &deps) {
        PkgGuard::Blocked => return forbidden("CellCore cannot uninstall itself from its own UI"),
        PkgGuard::Protected => {
            if let Err(r) = require_confirm(
                req.confirm.as_deref(),
                &req.name,
                &format!("{} is needed by CellCore or the platform; removing it can break the UI, networking or SSH. Type the package name to remove it anyway.", req.name),
            ) {
                return r;
            }
        }
        PkgGuard::None => {}
    }
    let _g = mutate_lock().await;
    invalidate_cache();
    match run("opkg", &["remove", &req.name], ExecOpts::new(120, 256 * KIB)).await {
        Ok(out) => op_result(&ctx, &format!("remove {}", req.name), out),
        Err(e) => server(e),
    }
}

#[derive(Deserialize, Default)]
pub struct UpdateCheckQ {
    #[serde(default)]
    refresh: Option<String>,
}

pub async fn get_update_check(Query(q): Query<UpdateCheckQ>) -> Response {
    if matches!(q.refresh.as_deref(), Some("1" | "true" | "yes")) {
        let _g = mutate_lock().await;
        invalidate_cache();
        match run_opkg_with_retry(&["update"], 180).await {
            Ok(out) if out.ok() => {}
            Ok(out) => {
                let log = out.log();
                if opkg_busy(&log) {
                    return conflict("opkg is busy (another install or update is running); try again shortly");
                }
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "status": "error",
                        "error": "opkg update failed",
                        "log": super::exec::tail_chars(&log, 16 * 1024),
                    })),
                )
                    .into_response();
            }
            Err(e) => return server(e),
        }
    }

    let (pkg, installed_version) = find_qm_package_status();
    let avail_list = match available().await {
        Ok(v) => v,
        Err(e) => {
            return ok(serde_json::json!({
                "status": "ok",
                "package": pkg,
                "installedVersion": installed_version,
                "availableVersion": serde_json::Value::Null,
                "updateAvailable": false,
                "listsAgeSecs": lists_age_secs(),
                "overlayFreeBytes": overlay_free_bytes(),
                "minOverlayBytes": MIN_SELF_UPGRADE_BYTES,
                "state": read_self_upgrade_state(),
                "warning": e,
            }));
        }
    };
    let available_version = avail_list
        .into_iter()
        .filter(|p| p.name == pkg)
        .max_by(|a, b| compare_opkg_versions(&a.version, &b.version))
        .map(|p| p.version);
    let update_available = available_version.as_deref().is_some_and(|avail| {
        installed_version
            .as_deref()
            .is_none_or(|inst| compare_opkg_versions(avail, inst) == std::cmp::Ordering::Greater)
    });
    ok(serde_json::json!({
        "status": "ok",
        "package": pkg,
        "installedVersion": installed_version,
        "availableVersion": available_version,
        "updateAvailable": update_available,
        "listsAgeSecs": lists_age_secs(),
        "overlayFreeBytes": overlay_free_bytes(),
        "minOverlayBytes": MIN_SELF_UPGRADE_BYTES,
        "state": read_self_upgrade_state(),
    }))
}

pub async fn get_self_upgrade_status() -> Response {
    let mut st = read_self_upgrade_state();
    let now = crate::auth::now_secs();
    if st.active && now.saturating_sub(st.updated_at.max(st.started_at)) > 300 {
        st.active = false;
        if st.error.is_none() {
            st.error = Some("Upgrade worker timed out or exited unexpectedly".into());
        }
    }
    ok(serde_json::json!({
        "status": "ok",
        "state": st,
        "log": tail_log_lines(SELF_UPGRADE_LOG_PATH, 100),
    }))
}

#[derive(Deserialize, Default)]
pub struct UpgradeReq {
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_self_upgrade(State(ctx): State<HttpCtx>, Json(req): Json<UpgradeReq>) -> Response {
    let why = "Upgrades CellCore from the opkg feed, restarts cellcored briefly, and auto-rolls back if verification fails within 45s. Type UPGRADE to continue.";
    if let Err(resp) = require_confirm(req.confirm.as_deref(), "UPGRADE", why) {
        return resp;
    }
    if let Some(free) = overlay_free_bytes()
        && free < MIN_SELF_UPGRADE_BYTES
    {
        return bad(format!(
            "Insufficient overlay space: {} MiB free, at least 15 MiB required",
            free / (1024 * 1024)
        ));
    }
    let cur = read_self_upgrade_state();
    let now = crate::auth::now_secs();
    if cur.active && now.saturating_sub(cur.updated_at.max(cur.started_at)) < 300 {
        return conflict("A CellCore self-upgrade is already in progress");
    }

    let (pkg, from_ver_opt) = find_qm_package_status();
    if !safe_script_token(&pkg) {
        return bad("Invalid CellCore package name");
    }
    let from_ver = from_ver_opt
        .filter(|v| safe_script_token(v))
        .unwrap_or_else(|| "unknown".into());
    let avail_ver = available()
        .await
        .ok()
        .and_then(|list| {
            list.into_iter()
                .filter(|p| p.name == pkg)
                .max_by(|a, b| compare_opkg_versions(&a.version, &b.version))
                .map(|p| p.version)
        })
        .filter(|v| safe_script_token(v))
        .unwrap_or_else(|| "latest".into());

    let state_path = crate::paths::p(SELF_UPGRADE_STATE_PATH);
    let log_path = crate::paths::p(SELF_UPGRADE_LOG_PATH);
    let script_path = crate::paths::p(SELF_UPGRADE_SCRIPT_PATH);

    let init_state = SelfUpgradeState {
        active: true,
        phase: "starting".into(),
        package: pkg.clone(),
        from_version: Some(from_ver.clone()),
        target_version: Some(avail_ver.clone()),
        started_at: now,
        updated_at: now,
        pid: None,
        error: None,
        rolled_back: false,
    };
    if let Err(e) = crate::state::save_json_atomic(SELF_UPGRADE_STATE_PATH, &init_state, 0o600) {
        return server(format!("save self-upgrade state: {e}"));
    }

    let script = build_self_upgrade_script(&pkg, &from_ver, &avail_ver, &state_path, &log_path);
    if let Some(parent) = Path::new(&script_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&script_path, script.as_bytes()) {
        return server(format!("write self-upgrade script: {e}"));
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700));

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg(&script_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Detach from cellcored's process group/session so CONTROL/preinst stopping
    // cellcored cannot kill the upgrade watcher before postinst/verify finish.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(_) => {
            audit(
                &ctx,
                format!("started detached self-upgrade for {pkg} ({from_ver} -> {avail_ver})"),
            );
            (
                axum::http::StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "accepted",
                    "phase": "starting",
                    "package": pkg,
                    "fromVersion": from_ver,
                    "targetVersion": avail_ver,
                    "logPath": SELF_UPGRADE_LOG_PATH,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let _ = std::fs::remove_file(&state_path);
            server(format!("spawn self-upgrade script: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_list() {
        let v = parse_pkg_lines(include_str!("fixtures/opkg_installed.txt"));
        assert!(v.len() > 600);
        let d = v.iter().find(|p| p.name == "dropbear").unwrap();
        assert_eq!(d.version, "2022.82-6");
        assert!(v.iter().any(|p| p.name == "luci-app-firewall"));
        assert!(v.iter().any(|p| p.name == "QCMAP_ConnectionManager" && p.version == "1-1"));
    }

    #[test]
    fn parses_available_list_with_descriptions() {
        let v = parse_pkg_lines(include_str!("fixtures/opkg_list.txt"));
        assert_eq!(v.len(), 80);
        let a = v.iter().find(|p| p.name == "aardvark-dns").unwrap();
        assert_eq!(a.version, "1.11.0-1");
        assert!(a.description.starts_with("Aardvark-dns is an authoritative"));
        let x = v.iter().find(|p| p.name == "464xlat").unwrap();
        assert!(x.description.contains("RFC6877"));
        // noise lines are ignored
        assert!(parse_pkg_lines("Multiple packages (libatomic1 and libatomic1) providing same name marked HOLD or PREFER. Using latest.\n").is_empty());
        // list-upgradable form: name - old - new (new lands in description; still parses)
        assert_eq!(parse_pkg_lines("luci-lib-base - git-22.308 - git-25.222\n")[0].name, "luci-lib-base");
    }

    #[test]
    fn parses_info_and_depends() {
        let s = parse_info(include_str!("fixtures/opkg_info_qm.txt"));
        assert_eq!(s.len(), 2);
        assert_eq!(field(&s[0], "Version"), Some("4.1.0-1"));
        assert!(field(&s[0], "Status").unwrap().contains("installed"));
        let deps = parse_depends(field(&s[0], "Depends").unwrap());
        assert_eq!(deps, vec!["libc", "uci", "ubus", "uhttpd", "ookla-speedtest", "msmtp", "ca-bundle", "ca-certificates"]);
        let old = parse_depends(field(&s[1], "Depends").unwrap());
        assert_eq!(old[0], "sdxpinn-patch");
        assert!(old.contains(&"sms-tool".to_string()));

        let d = parse_info(include_str!("fixtures/opkg_info_dropbear.txt"));
        assert_eq!(d.len(), 1);
        let conf = field(&d[0], "Conffiles").unwrap();
        assert!(conf.contains("/etc/config/dropbear"));
        assert_eq!(conf.lines().count(), 3);
    }

    #[test]
    fn guards_packages() {
        let deps = vec!["ookla-speedtest".to_string(), "msmtp".to_string()];
        assert_eq!(guard_for("sdxpinn-cellcore", &deps), PkgGuard::Blocked);
        assert_eq!(guard_for("dropbear", &deps), PkgGuard::Protected);
        assert_eq!(guard_for("kmod-nft-core", &deps), PkgGuard::Protected);
        assert_eq!(guard_for("QCMAP_CLI", &deps), PkgGuard::Protected);
        assert_eq!(guard_for("msmtp", &deps), PkgGuard::Protected);
        assert_eq!(guard_for("tcpdump", &deps), PkgGuard::None);
        assert_eq!(guard_for("luci-app-firewall", &deps), PkgGuard::None);
    }

    #[test]
    fn search_ranks_name_matches() {
        let v = parse_pkg_lines(include_str!("fixtures/opkg_list.txt"));
        let (hits, total) = search(&v, "acme", 5);
        assert!(total >= 2);
        assert_eq!(hits[0].name, "acme");
        let (none, t) = search(&v, "zzzz-nothing", 5);
        assert!(none.is_empty() && t == 0);
    }

    #[test]
    fn detects_lock_contention() {
        assert!(opkg_busy(" * opkg_conf_load: Could not lock /var/lock/opkg.lock: Resource temporarily unavailable."));
        assert!(!opkg_busy("Installing tcpdump"));
    }

    #[test]
    fn parses_status_file_and_validates_feeds() {
        let status = "\
Package: dropbear
Version: 2022.82-6
Depends: libc
Status: install user installed

Package: stale-pkg
Version: 0.1
Status: unknown ok not-installed

Package: deinst-pkg
Version: 0.2
Status: deinstall ok config-files

Package: sdxpinn-cellcore
Version: 4.2.0
Depends: libc, uci, ubus, msmtp
Status: install user installed
";
        let (pkgs, deps) = parse_installed_from_status(status);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "dropbear");
        assert_eq!(pkgs[1].name, "sdxpinn-cellcore");
        assert_eq!(deps, vec!["libc", "uci", "ubus", "msmtp"]);

        let valid = "# comment\nsrc/gz custom_feed https://example.com/feed\r\nsrc raw http://127.0.0.1:8000/pkgs";
        assert_eq!(
            validate_feeds(valid).unwrap(),
            "# comment\nsrc/gz custom_feed https://example.com/feed\nsrc raw http://127.0.0.1:8000/pkgs\n"
        );
        assert!(validate_feeds("src/gz bad;name https://example.com/a").is_err());
        assert!(validate_feeds("ftp custom ftp://example.com/a").is_err());
        assert!(validate_feeds("src custom file:///etc/passwd").is_err());
        assert!(validate_feeds("src custom https://example.com/a extra").is_err());
    }

    #[test]
    fn compares_opkg_versions_accurately() {
        use std::cmp::Ordering;
        assert_eq!(compare_opkg_versions("4.2.0-5", "4.2.1-1"), Ordering::Less);
        assert_eq!(compare_opkg_versions("4.2.9-1", "4.2.10-1"), Ordering::Less);
        assert_eq!(compare_opkg_versions("4.2.1-1", "4.2.1-1"), Ordering::Equal);
        assert_eq!(compare_opkg_versions("4.2.1-2", "4.2.1-10"), Ordering::Less);
        assert_eq!(compare_opkg_versions("1:4.2.0-1", "4.2.9-1"), Ordering::Greater);
        assert_eq!(compare_opkg_versions("4.2.1~rc1-1", "4.2.1-1"), Ordering::Less);
    }

    #[test]
    fn self_upgrade_script_snapshots_opkg_metadata_watchdog_and_stages_rescue_ipk() {
        let s = build_self_upgrade_script(
            "sdxpinn-cellcore",
            "1.5.0-1",
            "1.6.0-1",
            "/tmp/cellcore/self-upgrade.json",
            "/tmp/cellcore/self-upgrade.log",
        );
        assert!(s.contains("/usr/lib/opkg/status"));
        assert!(s.contains("/usr/lib/opkg/info/sdxpinn-cellcore.*"));
        assert!(s.contains("/etc/init.d/dropbear-lan-watchdog"));
        assert!(s.contains("/etc/cellcore-rescue/cellcore.ipk"));
        assert!(s.contains("cellcored verify --expect-wan 0"));
    }
}

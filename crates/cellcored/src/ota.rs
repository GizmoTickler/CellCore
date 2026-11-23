//! OTA update check / install for the CellCore package.
//!
//! * Check refreshes **only** the signed CellCore feed (a temporary opkg
//!   config with the base settings plus that one `src` line), with a
//!   generous timeout and the child killed on timeout.
//! * Versions are ordered exactly like opkg (epoch, upstream, revision with
//!   dpkg-style `~`/digit/alpha rules).
//! * Install runs `opkg upgrade` detached from the daemon (new session, own
//!   log) because the package's postinst restarts cellcored. Progress is
//!   kept in files under /tmp so it is still readable after the restart.
//!   Downgrades are refused.

use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    admin::exec::{ExecOpts, KIB, run as exec_run},
    auth::now_secs,
    state::atomic_write,
    uci::run_cmd,
};

pub const FEED_NAME: &str = "CellCore-repo";
pub const OPKG_CONF: &str = "/etc/opkg.conf";
pub const CUSTOM_FEEDS: &str = "/etc/opkg/customfeeds.conf";
pub const FEED_CONF_TMP: &str = "/tmp/cellcore/opkg-feed.conf";
pub const CHECK_STATE_PATH: &str = "/tmp/cellcore/ota-check.json";
pub const UPGRADE_STATUS_PATH: &str = "/tmp/cellcore/ota-upgrade.json";
pub const UPGRADE_LOG_PATH: &str = "/tmp/cellcore/ota-upgrade.log";
#[allow(dead_code)]
pub const RESCUE_IPK_PATH: &str = "/etc/cellcore-rescue/cellcore.ipk";
const DEFAULT_LISTS_DIR: &str = "/var/opkg-lists";
const FEED_UPDATE_TIMEOUT: Duration = Duration::from_secs(90);
const LOG_TAIL_LINES: usize = 40;

// ---------------------------------------------------------------------------
// opkg version ordering
// ---------------------------------------------------------------------------

fn order(c: u8) -> i32 {
    match c {
        b'~' => -1,
        0 => 0,
        c if c.is_ascii_digit() => 0,
        c if c.is_ascii_alphabetic() => c as i32,
        c => c as i32 + 256,
    }
}

/// dpkg/opkg `verrevcmp`.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() || j < b.len() {
        while (at(a, i) != 0 && !at(a, i).is_ascii_digit()) || (at(b, j) != 0 && !at(b, j).is_ascii_digit()) {
            let (ac, bc) = (order(at(a, i)), order(at(b, j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while at(a, i) == b'0' {
            i += 1;
        }
        while at(b, j) == b'0' {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while at(a, i).is_ascii_digit() && at(b, j).is_ascii_digit() {
            if first_diff == Ordering::Equal {
                first_diff = at(a, i).cmp(&at(b, j));
            }
            i += 1;
            j += 1;
        }
        if at(a, i).is_ascii_digit() {
            return Ordering::Greater;
        }
        if at(b, j).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

fn split_version(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e.parse().unwrap_or(0), r),
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((up, rev)) => (epoch, up, rev),
        None => (epoch, rest, ""),
    }
}

/// opkg `pkg_compare_versions`: epoch, then upstream, then revision.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split_version(a);
    let (eb, ub, rb) = split_version(b);
    ea.cmp(&eb).then_with(|| verrevcmp(ua, ub)).then_with(|| verrevcmp(ra, rb))
}

// ---------------------------------------------------------------------------
// Feed-only opkg config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedConf {
    pub conf: String,
    pub lists_dir: String,
    pub feed_line: String,
    pub feed_url: String,
    pub check_signature: bool,
}

fn feed_src_line<'a>(text: &'a str, feed: &str) -> Option<&'a str> {
    text.lines().map(str::trim).find(|l| {
        let mut it = l.split_whitespace();
        matches!(it.next(), Some("src") | Some("src/gz")) && it.next() == Some(feed) && it.next().is_some()
    })
}

/// Base settings (`dest`, `lists_dir`, `option`, `arch`) from opkg.conf plus
/// only the CellCore feed's `src` line (read from customfeeds.conf, or
/// opkg.conf as a fallback) — never a hard-coded URL. Always enforces
/// `option check_signature` so feed verification fails closed.
pub fn build_feed_conf(opkg_conf: &str, custom_feeds: &str, feed: &str) -> Result<FeedConf, String> {
    let mut out = Vec::new();
    let mut lists_dir = crate::paths::p(DEFAULT_LISTS_DIR);
    let mut has_check_signature = false;
    for line in opkg_conf.lines().map(str::trim) {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("dest") | Some("arch") => out.push(line.to_string()),
            Some("option") => {
                if it.clone().next() == Some("check_signature") {
                    let arg = it.nth(1);
                    if matches!(arg, Some("0") | Some("false") | Some("no")) {
                        // Never honour disabled signature checking for OTA.
                        continue;
                    }
                    has_check_signature = true;
                }
                out.push(line.to_string());
            }
            Some("lists_dir") => {
                if let Some(dir) = it.nth(1) {
                    lists_dir = dir.to_string();
                }
                out.push(line.to_string());
            }
            _ => {}
        }
    }
    let feed_line = feed_src_line(custom_feeds, feed)
        .or_else(|| feed_src_line(opkg_conf, feed))
        .ok_or_else(|| format!("Feed {feed} is not configured in {CUSTOM_FEEDS}"))?
        .to_string();
    let feed_url = feed_line
        .split_whitespace()
        .nth(2)
        .ok_or_else(|| format!("Feed {feed} has no URL"))?
        .to_string();
    if !(feed_url.starts_with("https://") || feed_url.starts_with("http://")) {
        return Err(format!("Feed {feed} URL must use https:// or http:// (got {feed_url})"));
    }
    if !has_check_signature {
        out.push("option check_signature".to_string());
    }
    if !out.iter().any(|l| l.starts_with("lists_dir")) {
        out.push(format!("lists_dir ext {lists_dir}"));
    }
    out.push(feed_line.clone());
    Ok(FeedConf {
        conf: format!("{}\n", out.join("\n")),
        lists_dir,
        feed_line,
        feed_url,
        check_signature: true,
    })
}

fn load_feed_conf() -> Result<FeedConf, String> {
    let base = fs::read_to_string(crate::paths::p(OPKG_CONF)).map_err(|e| format!("read {OPKG_CONF}: {e}"))?;
    let custom = fs::read_to_string(crate::paths::p(CUSTOM_FEEDS)).unwrap_or_default();
    let fc = build_feed_conf(&base, &custom, FEED_NAME)?;
    atomic_write(Path::new(&crate::paths::p(FEED_CONF_TMP)), fc.conf.as_bytes(), 0o600)?;
    Ok(fc)
}

/// Fail-closed signature verdict for `opkg update` output. Only returns
/// `Ok(true)` when signature checking is active AND `opkg` explicitly confirms
/// `"Signature check passed"`. Never treats missing confirmation as OK.
pub fn evaluate_feed_update_signature(check_signature_enabled: bool, output: &str) -> Result<bool, String> {
    if !check_signature_enabled {
        return Err("Feed signature checking (option check_signature) is not enabled".into());
    }
    let lower = output.to_ascii_lowercase();
    if lower.contains("signature check failed")
        || lower.contains("signature verification failed")
        || lower.contains("no signature")
    {
        return Err("Feed signature check failed".into());
    }
    if !lower.contains("signature check passed") {
        return Err("Feed signature verification was not confirmed by opkg".into());
    }
    Ok(true)
}

/// Gate an upgrade on a verified feed check: fail closed unless
/// `check.ok && check.signature_verified == Some(true)`.
pub fn require_verified_check(check: Option<&CheckRecord>) -> Result<(), String> {
    match check {
        Some(c) if c.ok && c.signature_verified == Some(true) => Ok(()),
        Some(c) if c.signature_verified == Some(false) => {
            Err("Refusing upgrade: last feed signature check failed".into())
        }
        _ => Err("Refusing upgrade: feed signature has not been verified (run a signed check first)".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPkgMeta {
    pub package: String,
    pub version: String,
    pub filename: String,
    pub sha256: String,
}

fn is_safe_ipk_filename(name: &str) -> bool {
    !name.is_empty()
        && name.ends_with(".ipk")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'~'))
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse `opkg info <pkg>` (or `Packages` index) output from the signed
/// CellCore feed and extract the exact `.ipk` `Filename` and `SHA256sum` for
/// `(pkg, target_version)`. Fails closed if missing or malformed.
pub fn parse_pkg_metadata(stanzas: &str, pkg: &str, target_version: &str) -> Result<VerifiedPkgMeta, String> {
    let mut cur_pkg = String::new();
    let mut cur_ver = String::new();
    let mut cur_file = String::new();
    let mut cur_sha = String::new();

    let flush = |cur_pkg: &str, cur_ver: &str, cur_file: &str, cur_sha: &str| -> Result<Option<VerifiedPkgMeta>, String> {
        if cur_pkg == pkg && !cur_ver.is_empty() && compare_versions(cur_ver, target_version) == Ordering::Equal {
            // Skip installed-status stanzas which carry no Filename/SHA256sum.
            if cur_file.is_empty() && cur_sha.is_empty() {
                return Ok(None);
            }
            if !is_safe_ipk_filename(cur_file) {
                return Err(format!("Unsafe or missing Filename for {pkg} {target_version}: {cur_file:?}"));
            }
            if !is_valid_sha256_hex(cur_sha) {
                return Err(format!("Invalid or missing SHA256sum for {pkg} {target_version}"));
            }
            return Ok(Some(VerifiedPkgMeta {
                package: cur_pkg.to_string(),
                version: cur_ver.to_string(),
                filename: cur_file.to_string(),
                sha256: cur_sha.to_ascii_lowercase(),
            }));
        }
        Ok(None)
    };

    for raw in stanzas.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            if let Some(meta) = flush(&cur_pkg, &cur_ver, &cur_file, &cur_sha)? {
                return Ok(meta);
            }
            cur_pkg.clear();
            cur_ver.clear();
            cur_file.clear();
            cur_sha.clear();
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let val = v.trim();
            match k.trim() {
                "Package" => cur_pkg = val.to_string(),
                "Version" => cur_ver = val.to_string(),
                "Filename" => cur_file = val.to_string(),
                "SHA256sum" => cur_sha = val.to_string(),
                _ => {}
            }
        }
    }
    if let Some(meta) = flush(&cur_pkg, &cur_ver, &cur_file, &cur_sha)? {
        return Ok(meta);
    }
    Err(format!(
        "Verified feed metadata (Filename + SHA256sum) not found for {pkg} {target_version}"
    ))
}

/// Verify raw bytes against an expected lowercase/uppercase hex SHA-256 digest.
pub fn verify_sha256_bytes(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let expected = expected_hex.trim().to_ascii_lowercase();
    if !is_valid_sha256_hex(&expected) {
        return Err("Invalid expected SHA-256 digest".into());
    }
    let actual = hex::encode(Sha256::digest(bytes));
    if !crate::auth::constant_time_eq(&actual, &expected) {
        return Err(format!("SHA-256 mismatch (expected {expected}, got {actual})"));
    }
    Ok(())
}

/// Verify an on-disk `.ipk` file against an expected SHA-256 digest.
#[allow(dead_code)]
pub fn verify_file_sha256(path: &Path, expected_hex: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    verify_sha256_bytes(&bytes, expected_hex)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OtaState {
    UpToDate,
    UpdateAvailable,
    FeedOlder,
    Unknown,
}

pub fn classify(installed: Option<&str>, available: Option<&str>) -> OtaState {
    match (installed, available) {
        (Some(i), Some(a)) => match compare_versions(a, i) {
            Ordering::Greater => OtaState::UpdateAvailable,
            Ordering::Equal => OtaState::UpToDate,
            Ordering::Less => OtaState::FeedOlder,
        },
        _ => OtaState::Unknown,
    }
}

/// Versions of `pkg` in `opkg list`/`list-installed` output (`name - ver[ - desc]`).
pub fn parse_opkg_versions(out: &str, pkg: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, " - ");
            (parts.next()?.trim() == pkg).then(|| parts.next().map(|v| v.trim().to_string()))?
        })
        .filter(|v| !v.is_empty())
        .collect()
}

pub fn newest(versions: &[String]) -> Option<String> {
    versions.iter().max_by(|a, b| compare_versions(a, b)).cloned()
}

/// Refuse anything that is not strictly newer than what is installed.
pub fn decide_upgrade(installed: Option<&str>, available: Option<&str>, requested: Option<&str>) -> Result<String, String> {
    let installed = installed.ok_or("Installed version is unknown; refusing to upgrade")?;
    let available = available.ok_or("The feed does not offer this package; run a check first")?;
    if let Some(req) = requested
        && compare_versions(req, available) != Ordering::Equal
    {
        return Err(format!("Requested {req} but the signed feed offers {available}; check again"));
    }
    if compare_versions(available, installed) != Ordering::Greater {
        return Err(format!("Refusing to install {available}: it is not newer than the installed {installed}"));
    }
    Ok(available.to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct CheckRecord {
    pub checked_at: u64,
    pub ok: bool,
    pub signature_verified: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct UpgradeStatus {
    /// idle | running | succeeded | failed
    pub state: String,
    pub target: String,
    pub from: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    pub installed_after: Option<String>,
    pub message: Option<String>,
}

fn pid_alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !stat.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'),
        Err(_) => false,
    }
}

/// Resolve what the UI should see. A `running` record whose installer is
/// gone (e.g. killed with the old daemon, or a reboot) is settled from the
/// installed version instead of spinning forever.
pub fn effective_upgrade_status(rec: Option<UpgradeStatus>, alive: impl Fn(u32) -> bool, installed: Option<&str>) -> UpgradeStatus {
    let Some(mut st) = rec else {
        return UpgradeStatus {
            state: "idle".into(),
            ..Default::default()
        };
    };
    if st.state == "running" && !st.pid.is_some_and(&alive) {
        let reached = installed.is_some_and(|i| compare_versions(i, &st.target) == Ordering::Equal);
        st.state = if reached { "succeeded" } else { "failed" }.into();
        if !reached {
            st.message = Some("Installer stopped before reporting a result".into());
        }
        st.installed_after = installed.map(str::to_string);
    }
    st
}

pub fn read_upgrade_status() -> Option<UpgradeStatus> {
    serde_json::from_slice(&fs::read(crate::paths::p(UPGRADE_STATUS_PATH)).ok()?).ok()
}

fn log_tail(path: &str, n: usize) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].iter().map(|s| s.to_string()).collect()
}

fn list_mtime(dir: &str) -> Option<u64> {
    fs::metadata(PathBuf::from(crate::paths::p(dir)).join(FEED_NAME))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

pub async fn installed_version(pkg: &str) -> Result<Option<String>, String> {
    let out = run_cmd("opkg", &["list-installed", pkg], Duration::from_secs(10)).await?;
    Ok(newest(&parse_opkg_versions(&out, pkg)))
}

async fn feed_version(pkg: &str) -> Result<Option<String>, String> {
    let out = run_cmd("opkg", &["-f", &crate::paths::p(FEED_CONF_TMP), "list", pkg], Duration::from_secs(10)).await?;
    Ok(newest(&parse_opkg_versions(&out, pkg)))
}

/// Everything the OTA view needs. Existing fields are kept; the rest are
/// additive.
pub async fn ota_info(pkg: &str, daemon_version: &str) -> serde_json::Value {
    let mut errors: Vec<String> = Vec::new();
    let installed = installed_version(pkg).await.unwrap_or_else(|e| {
        errors.push(format!("installed version: {e}"));
        None
    });
    let feed = load_feed_conf();
    let (available, lists_dir) = match &feed {
        Ok(fc) => (
            feed_version(pkg).await.unwrap_or_else(|e| {
                errors.push(format!("feed version: {e}"));
                None
            }),
            fc.lists_dir.clone(),
        ),
        Err(e) => {
            errors.push(e.clone());
            (None, crate::paths::p(DEFAULT_LISTS_DIR))
        }
    };
    let state = classify(installed.as_deref(), available.as_deref());
    let check: Option<CheckRecord> = fs::read(crate::paths::p(CHECK_STATE_PATH)).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let upgrade = effective_upgrade_status(read_upgrade_status(), pid_alive, installed.as_deref());
    serde_json::json!({
        "package": pkg,
        "installedVersion": installed,
        "availableVersion": available,
        "updateAvailable": state == OtaState::UpdateAvailable,
        "state": state,
        "lastChecked": list_mtime(&lists_dir),
        "signatureVerified": check.as_ref().and_then(|c| c.signature_verified),
        "lastCheck": check,
        "daemonVersion": daemon_version,
        "errors": errors,
        "upgrade": upgrade,
        "upgradeLog": log_tail(&crate::paths::p(UPGRADE_LOG_PATH), LOG_TAIL_LINES),
    })
}

pub fn upgrade_running() -> bool {
    read_upgrade_status().is_some_and(|s| s.state == "running" && s.pid.is_some_and(pid_alive))
}

/// Refresh only the signed CellCore feed. Fails closed unless `opkg update`
/// succeeds with `option check_signature` enabled AND explicitly confirms
/// `"Signature check passed"`.
pub async fn check_feed() -> CheckRecord {
    let mut rec = CheckRecord {
        checked_at: now_secs(),
        signature_verified: Some(false),
        ..Default::default()
    };
    match load_feed_conf() {
        Err(e) => rec.error = Some(e),
        Ok(fc) => match exec_run(
            "opkg",
            &["-f", &crate::paths::p(FEED_CONF_TMP), "update"],
            ExecOpts::new(FEED_UPDATE_TIMEOUT.as_secs(), 512 * KIB),
        )
        .await
        {
            Ok(out) => {
                let combined = format!("{}\n{}", out.stdout_str(), out.stderr);
                if !out.ok() {
                    rec.ok = false;
                    rec.signature_verified = Some(false);
                    rec.error = Some(out.err_summary("opkg update"));
                } else {
                    match evaluate_feed_update_signature(fc.check_signature, &combined) {
                        Ok(true) => {
                            rec.ok = true;
                            rec.signature_verified = Some(true);
                        }
                        Ok(false) => {
                            rec.ok = false;
                            rec.signature_verified = Some(false);
                            rec.error = Some("Feed signature check failed".into());
                        }
                        Err(e) => {
                            rec.ok = false;
                            rec.signature_verified = Some(false);
                            rec.error = Some(e);
                        }
                    }
                }
            }
            Err(e) => {
                rec.ok = false;
                rec.signature_verified = Some(false);
                rec.error = Some(e);
            }
        },
    }
    if let Ok(json) = serde_json::to_vec(&rec) {
        let _ = atomic_write(Path::new(&crate::paths::p(CHECK_STATE_PATH)), &json, 0o644);
    }
    rec
}

/// Installer run in its own session. Downloads the exact pinned `.ipk` from the
/// verified CellCore feed URL, verifies its SHA-256 against the signed index,
/// installs that exact `.ipk` with `opkg install`, and stages it as the rescue
/// package after post-install verification succeeds.
const INSTALL_SCRIPT: &str = r#"
status="$1"; pkg="$2"; target="$3"; from="$4"; started="$5"; feed_conf="$6"; ipk_url="$7"; expected_sha="$8"; ipk_name="$9"
dl="/tmp/cellcore-ota-dl.$$"
ipk_path="$dl/$ipk_name"
mkdir -p "$dl"
echo "[$(date)] pinned OTA download $pkg $target from verified feed ($ipk_url)"
dl_ok=0
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --connect-timeout 20 --max-time 180 -o "$ipk_path" "$ipk_url" && dl_ok=1
elif command -v uclient-fetch >/dev/null 2>&1; then
  uclient-fetch -q -O "$ipk_path" "$ipk_url" && dl_ok=1
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$ipk_path" "$ipk_url" && dl_ok=1
else
  echo "[$(date)] ERROR: no HTTP downloader (curl/uclient-fetch/wget) available"
fi
rc=1
if [ "$dl_ok" -eq 1 ] && [ -f "$ipk_path" ]; then
  actual_sha=$(sha256sum "$ipk_path" 2>/dev/null | awk '{print $1}' | tr 'A-Z' 'a-z')
  if [ -n "$actual_sha" ] && [ "$actual_sha" = "$expected_sha" ]; then
    echo "[$(date)] verified SHA-256 ($actual_sha); running opkg install $ipk_path"
    opkg -f "$feed_conf" install "$ipk_path"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "[$(date)] feed-only opkg install exited $rc; retrying verified local ipk with system dependency resolution"
      opkg install "$ipk_path"
      rc=$?
    fi
  else
    echo "[$(date)] ERROR: SHA-256 mismatch for $ipk_name (expected $expected_sha, got ${actual_sha:-missing})"
    rc=1
  fi
else
  echo "[$(date)] ERROR: failed to download $ipk_url"
  rc=1
fi
inst=$(opkg list-installed "$pkg" | sed -n "s/^$pkg - \([^ ]*\).*/\1/p" | head -n 1)
if [ "$rc" -eq 0 ] && [ "$inst" = "$target" ]; then
  st=succeeded
  vi=0
  vok=0
  while [ "$vi" -lt 30 ]; do
    if /usr/sbin/cellcored verify --expect-wan 0 >/dev/null 2>&1; then
      vok=1
      break
    fi
    sleep 1
    vi=$((vi + 1))
  done
  if [ "$vok" -eq 1 ] && [ -f "$ipk_path" ]; then
    mkdir -p /etc/cellcore-rescue
    cp -f "$ipk_path" /etc/cellcore-rescue/cellcore.ipk.tmp && mv -f /etc/cellcore-rescue/cellcore.ipk.tmp /etc/cellcore-rescue/cellcore.ipk
    echo "[$(date)] staged verified rescue package -> /etc/cellcore-rescue/cellcore.ipk"
  fi
else
  st=failed
fi
rm -rf "$dl"
echo "[$(date)] opkg exited $rc; installed now: ${inst:-unknown} -> $st"
printf '{"state":"%s","target":"%s","from":"%s","startedAt":%s,"finishedAt":%s,"exitCode":%s,"installedAfter":"%s"}\n' \
  "$st" "$target" "$from" "$started" "$(date +%s)" "$rc" "$inst" > "$status.tmp" && mv "$status.tmp" "$status"
"#;

/// Spawn `/bin/sh -c script _ args...` detached: new session, stdin closed,
/// stdout/stderr appended to `log`. Returns the pid.
pub fn spawn_detached(script: &str, args: &[&str], log: &Path) -> Result<u32, String> {
    use std::os::unix::process::CommandExt;
    if let Some(parent) = log.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let out = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| format!("open {}: {e}", log.display()))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(crate::paths::p("/bin/sh"));
    cmd.arg("-c").arg(script).arg("qm-ota").args(args);
    cmd.stdin(Stdio::null()).stdout(out).stderr(err);
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn installer: {e}"))?;
    let pid = child.id();
    // Reap it if it finishes while we are still running (no zombie).
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

pub async fn start_upgrade(pkg: &str, requested: Option<&str>) -> Result<UpgradeStatus, String> {
    if upgrade_running() {
        return Err("An upgrade is already running".into());
    }
    let check: Option<CheckRecord> = fs::read(crate::paths::p(CHECK_STATE_PATH))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    require_verified_check(check.as_ref())?;
    let installed = installed_version(pkg).await?;
    let fc = load_feed_conf()?;
    let available = feed_version(pkg).await?;
    let target = decide_upgrade(installed.as_deref(), available.as_deref(), requested)?;
    let info_out = run_cmd(
        "opkg",
        &["-f", &crate::paths::p(FEED_CONF_TMP), "info", pkg],
        Duration::from_secs(15),
    )
    .await?;
    let meta = parse_pkg_metadata(&info_out, pkg, &target)?;
    let ipk_url = format!("{}/{}", fc.feed_url.trim_end_matches('/'), meta.filename);
    let from = installed.unwrap_or_default();
    let started = now_secs();
    let _ = fs::write(crate::paths::p(UPGRADE_LOG_PATH), b"");
    let mut st = UpgradeStatus {
        state: "running".into(),
        target: target.clone(),
        from: from.clone(),
        started_at: started,
        ..Default::default()
    };
    let status_path = crate::paths::p(UPGRADE_STATUS_PATH);
    let feed_conf_path = crate::paths::p(FEED_CONF_TMP);
    // Record "running" before launching so a fast installer's final write wins.
    let _ = atomic_write(Path::new(&status_path), &serde_json::to_vec(&st).unwrap_or_default(), 0o644);
    let started_s = started.to_string();
    let pid = spawn_detached(
        INSTALL_SCRIPT,
        &[
            &status_path,
            pkg,
            &target,
            &from,
            &started_s,
            &feed_conf_path,
            &ipk_url,
            &meta.sha256,
            &meta.filename,
        ],
        Path::new(&crate::paths::p(UPGRADE_LOG_PATH)),
    )
    .inspect_err(|e| {
        let failed = UpgradeStatus {
            state: "failed".into(),
            message: Some(e.clone()),
            finished_at: Some(now_secs()),
            ..st.clone()
        };
        let _ = atomic_write(Path::new(&status_path), &serde_json::to_vec(&failed).unwrap_or_default(), 0o644);
    })?;
    st.pid = Some(pid);
    // Only add the pid if the installer has not already finished and
    // written its own result.
    if read_upgrade_status().is_some_and(|s| s.state == "running") {
        let _ = atomic_write(Path::new(&status_path), &serde_json::to_vec(&st).unwrap_or_default(), 0o644);
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opkg_version_ordering() {
        use Ordering::*;
        let cases = [
            ("4.1.0-1", "4.0.0-1", Greater),
            ("4.0.0-1", "4.1.0-1", Less),
            ("3.2.0-1", "4.1.0-1", Less),
            ("4.1.1-1", "4.1.0-1", Greater),
            ("4.10.0-1", "4.9.0-1", Greater),
            ("4.1.0-2", "4.1.0-1", Greater),
            ("4.1.0-01", "4.1.0-1", Equal),
            ("1.0-r10", "1.0-r2", Greater),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~~", "1.0~", Less),
            ("1:1.0-1", "2.0-1", Greater),
            ("0:2.0", "2.0", Equal),
            ("2:0.1", "1:9.9", Greater),
            ("1.0a", "1.0", Greater),
            ("1.0.", "1.0", Greater),
            ("1.0+b1", "1.0a", Greater),
            ("4.1.0", "4.1.0-1", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(compare_versions(a, b), want, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn feed_conf_keeps_base_settings_enforces_check_signature_and_only_our_feed() {
        let base = "dest root /\ndest ram /tmp\nlists_dir ext /var/opkg-lists\noption overlay_root /overlay\noption check_signature\narch all 1\narch aarch64_cortex-a53 10\nsrc/gz openwrt_core https://downloads.openwrt.org/x\n";
        let custom = "# comment\n# src/gz CellCore-repo https://old.example/disabled\nsrc/gz other https://other.example\nsrc/gz CellCore-repo https://feed.example/sdxpinn\n";
        let fc = build_feed_conf(base, custom, FEED_NAME).unwrap();
        assert_eq!(
            fc.conf,
            "dest root /\ndest ram /tmp\nlists_dir ext /var/opkg-lists\noption overlay_root /overlay\noption check_signature\narch all 1\narch aarch64_cortex-a53 10\nsrc/gz CellCore-repo https://feed.example/sdxpinn\n"
        );
        assert_eq!(fc.lists_dir, "/var/opkg-lists");
        assert_eq!(fc.feed_url, "https://feed.example/sdxpinn");
        assert!(fc.check_signature);
        assert!(!fc.conf.contains("openwrt_core") && !fc.conf.contains("other"));
        assert!(build_feed_conf(base, "src/gz other https://x\n", FEED_NAME).is_err());

        // Base config lacking `option check_signature` or explicitly disabling it
        // must still produce a feed config with `option check_signature` enabled.
        let fc2 = build_feed_conf("dest root /\noption check_signature 0\n", custom, FEED_NAME).unwrap();
        assert!(fc2.conf.contains("lists_dir ext /var/opkg-lists\n"));
        assert!(fc2.conf.contains("option check_signature\n"));
        assert!(!fc2.conf.contains("check_signature 0"));
        assert!(fc2.check_signature);
    }

    #[test]
    fn signature_verification_fails_closed() {
        // opkg output evaluation
        assert_eq!(
            evaluate_feed_update_signature(true, "Downloading ...\nSignature check passed.\n"),
            Ok(true)
        );
        assert!(evaluate_feed_update_signature(false, "Signature check passed.\n").is_err());
        assert!(evaluate_feed_update_signature(true, "Updated list of available packages\n").is_err());
        assert!(evaluate_feed_update_signature(true, "Signature check failed.\n").is_err());
        assert!(evaluate_feed_update_signature(true, "Signature check passed.\nSignature check failed.\n").is_err());

        // CheckRecord gating: None / Some(false) / ok=false MUST fail closed
        assert!(require_verified_check(None).is_err());
        assert!(
            require_verified_check(Some(&CheckRecord {
                checked_at: 100,
                ok: true,
                signature_verified: None,
                error: None,
            }))
            .is_err()
        );
        assert!(
            require_verified_check(Some(&CheckRecord {
                checked_at: 100,
                ok: true,
                signature_verified: Some(false),
                error: None,
            }))
            .is_err()
        );
        assert!(
            require_verified_check(Some(&CheckRecord {
                checked_at: 100,
                ok: false,
                signature_verified: Some(true),
                error: Some("err".into()),
            }))
            .is_err()
        );
        assert!(
            require_verified_check(Some(&CheckRecord {
                checked_at: 100,
                ok: true,
                signature_verified: Some(true),
                error: None,
            }))
            .is_ok()
        );
    }

    #[test]
    fn parses_verified_pkg_metadata_and_verifies_sha256() {
        let sha = "d9ea545c92bcef89618148e8fbb3d49c5a942ba4fc0405859f1fbf3128a4931e";
        let stanzas = format!(
            "Package: sdxpinn-cellcore\n\
             Version: 1.7.0-1\n\
             Status: install user installed\n\
             \n\
             Package: sdxpinn-cellcore\n\
             Version: 1.8.0-1\n\
             Filename: sdxpinn-cellcore_1.8.0-1_sdxpinn.ipk\n\
             SHA256sum: {sha}\n"
        );
        let meta = parse_pkg_metadata(&stanzas, "sdxpinn-cellcore", "1.8.0-1").unwrap();
        assert_eq!(meta.filename, "sdxpinn-cellcore_1.8.0-1_sdxpinn.ipk");
        assert_eq!(meta.sha256, sha);

        // Missing version / unsafe filename / bad sha256 must fail closed
        assert!(parse_pkg_metadata(&stanzas, "sdxpinn-cellcore", "1.9.0-1").is_err());
        let bad_fn = format!(
            "Package: sdxpinn-cellcore\nVersion: 1.8.0-1\nFilename: ../evil.ipk\nSHA256sum: {sha}\n"
        );
        assert!(parse_pkg_metadata(&bad_fn, "sdxpinn-cellcore", "1.8.0-1").is_err());
        let bad_sha = "Package: sdxpinn-cellcore\nVersion: 1.8.0-1\nFilename: ok.ipk\nSHA256sum: nothex\n";
        assert!(parse_pkg_metadata(bad_sha, "sdxpinn-cellcore", "1.8.0-1").is_err());

        // Byte & file SHA-256 verification
        let payload = b"verified-ipk-payload";
        let expected = hex::encode(Sha256::digest(payload));
        assert!(verify_sha256_bytes(payload, &expected).is_ok());
        assert!(verify_sha256_bytes(payload, &expected.to_ascii_uppercase()).is_ok());
        assert!(verify_sha256_bytes(b"tampered", &expected).is_err());
        assert!(verify_sha256_bytes(payload, "short").is_err());

        let tmp = std::env::temp_dir().join(format!("qm-ota-sha-{}.ipk", std::process::id()));
        fs::write(&tmp, payload).unwrap();
        assert!(verify_file_sha256(&tmp, &expected).is_ok());
        assert!(verify_file_sha256(&tmp, &"0".repeat(64)).is_err());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn state_and_upgrade_decisions() {
        assert_eq!(classify(Some("4.1.0-1"), Some("4.1.1-1")), OtaState::UpdateAvailable);
        assert_eq!(classify(Some("4.1.0-1"), Some("4.1.0-1")), OtaState::UpToDate);
        assert_eq!(classify(Some("4.1.0-1"), Some("3.2.0-1")), OtaState::FeedOlder);
        assert_eq!(classify(None, Some("3.2.0-1")), OtaState::Unknown);
        assert_eq!(classify(Some("4.1.0-1"), None), OtaState::Unknown);

        assert_eq!(decide_upgrade(Some("4.1.0-1"), Some("4.1.1-1"), None), Ok("4.1.1-1".into()));
        assert!(decide_upgrade(Some("4.1.0-1"), Some("3.2.0-1"), None).unwrap_err().contains("not newer"));
        assert!(decide_upgrade(Some("4.1.0-1"), Some("4.1.0-1"), None).is_err());
        assert!(decide_upgrade(None, Some("4.1.1-1"), None).is_err());
        assert!(decide_upgrade(Some("4.1.0-1"), Some("4.1.1-1"), Some("4.1.2-1")).is_err());
        assert!(decide_upgrade(Some("4.1.0-1"), Some("4.1.1-1"), Some("4.1.1-1")).is_ok());
    }

    #[test]
    fn opkg_list_parsing() {
        let out = "sdxpinn-cellcore - 4.1.0-1 - CellCore\nsdxpinn-cellcore-extra - 9.9 - x\nsdxpinn-cellcore - 4.1.1-1\n";
        let v = parse_opkg_versions(out, "sdxpinn-cellcore");
        assert_eq!(v, vec!["4.1.0-1".to_string(), "4.1.1-1".to_string()]);
        assert_eq!(newest(&v).as_deref(), Some("4.1.1-1"));
        assert!(parse_opkg_versions("", "x").is_empty());
    }

    #[test]
    fn upgrade_state_machine() {
        assert_eq!(effective_upgrade_status(None, |_| true, None).state, "idle");
        let running = UpgradeStatus {
            state: "running".into(),
            target: "4.1.1-1".into(),
            from: "4.1.0-1".into(),
            pid: Some(4242),
            ..Default::default()
        };
        // installer alive -> still running
        assert_eq!(effective_upgrade_status(Some(running.clone()), |_| true, Some("4.1.0-1")).state, "running");
        // installer gone and target installed (daemon restarted mid-way) -> succeeded
        let s = effective_upgrade_status(Some(running.clone()), |_| false, Some("4.1.1-1"));
        assert_eq!(s.state, "succeeded");
        // installer gone, version unchanged -> failed, not "running" forever
        let f = effective_upgrade_status(Some(running), |_| false, Some("4.1.0-1"));
        assert_eq!(f.state, "failed");
        assert!(f.message.is_some());
        // a final record written by the installer is reported as-is
        let done = UpgradeStatus { state: "failed".into(), exit_code: Some(255), ..Default::default() };
        assert_eq!(effective_upgrade_status(Some(done.clone()), |_| false, None), done);
    }

    #[test]
    fn installer_runs_detached_in_its_own_session() {
        let dir = std::env::temp_dir().join(format!("qm-ota-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log");
        let marker = dir.join("sid");
        let script = r#"echo "$$ $(cut -d' ' -f6 /proc/$$/stat)" > "$1"; echo hello"#;
        let pid = spawn_detached(script, &[marker.to_str().unwrap()], &log).unwrap();
        for _ in 0..100 {
            if fs::read_to_string(&marker).is_ok_and(|s| !s.trim().is_empty()) && fs::read_to_string(&log).is_ok_and(|s| s.contains("hello")) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = fs::read_to_string(&marker).unwrap();
        let mut it = text.split_whitespace();
        let (p, sid) = (it.next().unwrap(), it.next().unwrap());
        assert_eq!(p, pid.to_string());
        assert_eq!(sid, pid.to_string(), "installer must lead its own session");
        assert!(fs::read_to_string(&log).unwrap().contains("hello"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_script_uses_pinned_download_sha256_and_stages_rescue_ipk_after_verify() {
        assert!(!INSTALL_SCRIPT.contains("opkg upgrade"), "must never run blanket opkg upgrade");
        assert!(INSTALL_SCRIPT.contains("sha256sum"));
        assert!(INSTALL_SCRIPT.contains("opkg -f \"$feed_conf\" install \"$ipk_path\""));
        assert!(INSTALL_SCRIPT.contains("/usr/sbin/cellcored verify --expect-wan 0"));
        assert!(INSTALL_SCRIPT.contains(RESCUE_IPK_PATH));
    }

    #[tokio::test]
    async fn start_upgrade_refuses_unverified_feed_check() {
        let env = crate::paths::TestSandbox::new("ota-fail-closed");
        // Write a check record with signatureVerified: null
        env.write(
            CHECK_STATE_PATH,
            r#"{"checkedAt":1700000000,"ok":true,"signatureVerified":null,"error":null}"#,
        );
        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let err = start_upgrade("sdxpinn-cellcore", None).await.unwrap_err();
                assert!(err.contains("signature"), "{err}");
            })
            .await;
    }
}

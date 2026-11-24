//! Clean-room, idempotent, reversible rootfs overlay bootstrap for Quectel SDX75 (sdxpinn) modems.
//!
//! Stock RM551E-GL firmware mounts `ubi0:rootfs` read-only at `/` while providing a large
//! writable UBIFS partition at `/usrdata` (~260 MiB). This module inspects `/proc/mounts`
//! deterministically and provides four subcommands via `cellcored overlay <cmd>` /
//! `cellctl overlay <cmd>`:
//!
//! * `status [--json]` — Read-only mount/space inspection and pivot readiness report.
//! * `pivot [--dry-run]` — Idempotent early-boot (`START=03`) overlayfs + `pivot_root`
//!   backed by `/usrdata/cellcore-rootfs` (or existing `/usrdata/rootfs`).
//! * `remount-rw` — Late-boot (`START=13`) `MS_REMOUNT` read-write guard on `/` and `/etc/rc.d`.
//! * `revert [--yes] [--purge]` — Disables the early-boot overlay init scripts on `/real_rootfs`
//!   (and optionally purges the overlay upperdir) so one reboot cleanly
//!   restores 100% stock factory rootfs.

use std::{
    ffi::CString,
    fs,
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use serde::Serialize;

pub const OVERLAY_LOG_PATH: &str = "/tmp/cellcore-overlay.log";
pub const OVERLAY_LOG_MAX_BYTES: u64 = 64 * 1024;
pub const REAL_ROOTFS: &str = "/real_rootfs";
pub const NEW_ROOTFS: &str = "/rootfs";
pub const MIN_BACKING_FREE_MIB: u64 = 32;
pub const PENDING_PURGE_MARKER: &str = ".cellcore-overlay-purge-pending";

/// Platform/virtual mountpoints moved across `pivot_root` when present in `/proc/mounts`.
const MOVE_MOUNTS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/tmp",
    "/firmware",
    "/usrdata",
    "/etc",
    "/data",
    "/cache",
    "/systemrw",
    "/persist",
];

/// Optional platform mounts whose move failure warns instead of aborting the pivot.
/// Critical mounts (`/proc`, `/sys`, `/dev`, `/tmp`, `/usrdata`, `/etc`, etc.) remain fail-closed.
const OPTIONAL_MOVE_MOUNTS: &[&str] = &["/cache", "/persist", "/systemrw"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
}

impl MountEntry {
    pub fn is_rw(&self) -> bool {
        self.options.split(',').any(|o| o == "rw")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayScenario {
    AlreadyPivoted,
    UsrdataR02,
    UsrdataR01,
    LegacyOverlay,
    Unsupported,
}

impl OverlayScenario {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyPivoted => "already-pivoted",
            Self::UsrdataR02 => "usrdata-r02",
            Self::UsrdataR01 => "usrdata-r01",
            Self::LegacyOverlay => "legacy-overlay",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayStatus {
    pub scenario: OverlayScenario,
    pub pivoted: bool,
    pub root_writable: bool,
    pub root_fstype: String,
    pub backing_dir: Option<String>,
    pub upper_dir: Option<String>,
    pub work_dir: Option<String>,
    pub backing_avail_mib: Option<u64>,
    pub etc_mount_count: usize,
    pub safe_to_pivot: bool,
    pub reason: String,
}

pub fn parse_proc_mounts(content: &str) -> Vec<MountEntry> {
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let source = it.next()?.to_string();
            let target = it.next()?.to_string();
            let fstype = it.next()?.to_string();
            let options = it.next()?.to_string();
            Some(MountEntry {
                source,
                target,
                fstype,
                options,
            })
        })
        .collect()
}

fn active_mount_at<'a>(mounts: &'a [MountEntry], target: &str) -> Option<&'a MountEntry> {
    mounts.iter().rev().find(|m| m.target == target)
}

fn pick_upper_work_dirs(backing: &str, existing_check: impl Fn(&str) -> bool) -> (String, String) {
    let legacy_upper = format!("{backing}/rootfs");
    let legacy_work = format!("{backing}/rootfs-workdir");
    if existing_check(&legacy_upper) {
        return (legacy_upper, legacy_work);
    }
    (
        format!("{backing}/cellcore-rootfs"),
        format!("{backing}/cellcore-rootfs-work"),
    )
}

pub fn analyze_mounts(
    mounts: &[MountEntry],
    avail_mib_fn: impl Fn(&str) -> Option<u64>,
    path_exists_fn: impl Fn(&str) -> bool,
) -> OverlayStatus {
    let pivoted = mounts.iter().any(|m| m.target == REAL_ROOTFS);
    let root = active_mount_at(mounts, "/");
    let root_writable = root.is_some_and(MountEntry::is_rw);
    let root_fstype = root.map(|m| m.fstype.clone()).unwrap_or_else(|| "unknown".into());
    let etc_mount_count = mounts.iter().filter(|m| m.target == "/etc").count();
    let usrdata = active_mount_at(mounts, "/usrdata");
    let data = active_mount_at(mounts, "/data");
    let legacy_overlay = active_mount_at(mounts, "/overlay");

    if pivoted {
        let backing = usrdata
            .map(|_| "/usrdata")
            .or_else(|| data.map(|_| "/data"));
        let backing_avail_mib = backing.and_then(&avail_mib_fn);
        let (upper, work) = match backing {
            Some(b) => {
                let (u, w) = pick_upper_work_dirs(b, &path_exists_fn);
                (Some(u), Some(w))
            }
            None => (None, None),
        };
        return OverlayStatus {
            scenario: OverlayScenario::AlreadyPivoted,
            pivoted: true,
            root_writable,
            root_fstype,
            backing_dir: backing.map(str::to_string),
            upper_dir: upper,
            work_dir: work,
            backing_avail_mib,
            etc_mount_count,
            safe_to_pivot: false,
            reason: if root_writable {
                "Overlay already active and root filesystem is writable".into()
            } else {
                "Overlay is pivoted at /real_rootfs but / is read-only; run `cellcored overlay remount-rw`".into()
            },
        };
    }

    let (scenario, backing) = if let Some(u) = usrdata {
        if !u.is_rw() {
            return OverlayStatus {
                scenario: OverlayScenario::Unsupported,
                pivoted: false,
                root_writable,
                root_fstype,
                backing_dir: Some("/usrdata".into()),
                upper_dir: None,
                work_dir: None,
                backing_avail_mib: avail_mib_fn("/usrdata"),
                etc_mount_count,
                safe_to_pivot: false,
                reason: "/usrdata is mounted read-only; cannot host overlay upperdir".into(),
            };
        }
        let sc = if etc_mount_count >= 2 {
            OverlayScenario::UsrdataR01
        } else {
            OverlayScenario::UsrdataR02
        };
        (sc, "/usrdata")
    } else if legacy_overlay.is_some() && data.is_some_and(MountEntry::is_rw) {
        (OverlayScenario::LegacyOverlay, "/data")
    } else {
        return OverlayStatus {
            scenario: OverlayScenario::Unsupported,
            pivoted: false,
            root_writable,
            root_fstype,
            backing_dir: None,
            upper_dir: None,
            work_dir: None,
            backing_avail_mib: None,
            etc_mount_count,
            safe_to_pivot: false,
            reason: if root_writable {
                "Root filesystem is already writable without needing an SDX75 overlay pivot".into()
            } else {
                "Neither writable /usrdata nor writable /data backing partition was found".into()
            },
        };
    };

    let avail = avail_mib_fn(backing);
    let (upper, work) = pick_upper_work_dirs(backing, &path_exists_fn);
    let enough_space = avail.is_some_and(|m| m >= MIN_BACKING_FREE_MIB);
    let reason = if !enough_space {
        format!(
            "Backing partition {backing} has {} MiB free (need at least {MIN_BACKING_FREE_MIB} MiB)",
            avail.unwrap_or(0)
        )
    } else {
        format!(
            "Ready to pivot ({}) using {backing} ({} MiB free)",
            scenario.as_str(),
            avail.unwrap_or(0)
        )
    };

    OverlayStatus {
        scenario,
        pivoted: false,
        root_writable,
        root_fstype,
        backing_dir: Some(backing.into()),
        upper_dir: Some(upper),
        work_dir: Some(work),
        backing_avail_mib: avail,
        etc_mount_count,
        safe_to_pivot: enough_space,
        reason,
    }
}

fn statvfs_avail_mib(path: &str) -> Option<u64> {
    let c = CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    let bytes = (st.f_bavail as u128).saturating_mul(st.f_frsize as u128);
    Some((bytes / (1024 * 1024)) as u64)
}

pub fn probe_status() -> Result<OverlayStatus, String> {
    let raw = fs::read_to_string(crate::paths::p("/proc/mounts"))
        .map_err(|e| format!("read /proc/mounts: {e}"))?;
    let mounts = parse_proc_mounts(&raw);
    Ok(analyze_mounts(
        &mounts,
        statvfs_avail_mib,
        |p| Path::new(&crate::paths::p(p)).exists(),
    ))
}

pub(crate) fn append_overlay_log_at(log_path: &Path, msg: &str) {
    if let Ok(meta) = fs::metadata(log_path)
        && meta.len() > OVERLAY_LOG_MAX_BYTES
    {
        let keep_target = (OVERLAY_LOG_MAX_BYTES / 2) as usize;
        let kept = match fs::read(log_path) {
            Ok(bytes) if bytes.len() > keep_target => {
                let slice = &bytes[bytes.len() - keep_target..];
                match slice.iter().position(|&b| b == b'\n') {
                    Some(nl) => slice[nl + 1..].to_vec(),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        let _ = crate::state::atomic_write(log_path, &kept, 0o644);
    }
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(f, "{msg}");
    }
}

fn log_line(msg: &str) {
    eprintln!("cellcore-overlay: {msg}");
    append_overlay_log_at(Path::new(&crate::paths::p(OVERLAY_LOG_PATH)), msg);
}

fn cstr_path(p: &str) -> Result<CString, String> {
    CString::new(Path::new(p).as_os_str().as_bytes())
        .map_err(|_| format!("invalid NUL byte in path: {p}"))
}

fn sys_mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let src_c = source.map(cstr_path).transpose()?;
    let tgt_c = cstr_path(target)?;
    let fst_c = fstype.map(cstr_path).transpose()?;
    let dat_c = data.map(cstr_path).transpose()?;
    let rc = unsafe {
        libc::mount(
            src_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            tgt_c.as_ptr(),
            fst_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags,
            dat_c
                .as_ref()
                .map_or(std::ptr::null(), |c| c.as_ptr() as *const libc::c_void),
        )
    };
    if rc != 0 {
        return Err(format!(
            "mount(target={target}, flags=0x{flags:x}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn sys_umount_detach(target: &str) -> Result<(), String> {
    let tgt_c = cstr_path(target)?;
    let rc = unsafe { libc::umount2(tgt_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        return Err(format!(
            "umount2({target}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn sys_pivot_root(new_root: &str, put_old: &str) -> Result<(), String> {
    let new_c = cstr_path(new_root)?;
    let old_c = cstr_path(put_old)?;
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, new_c.as_ptr(), old_c.as_ptr()) };
    if rc != 0 {
        return Err(format!(
            "pivot_root({new_root}, {put_old}): {}",
            std::io::Error::last_os_error()
        ));
    }
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    Ok(())
}

pub(crate) fn move_mounts_with<F>(targets: &[&str], mut mover: F) -> Result<(), String>
where
    F: FnMut(&str, &str) -> Result<(), String>,
{
    for &target in targets {
        let src = format!("{REAL_ROOTFS}{target}");
        if let Err(e) = mover(&src, target) {
            let msg = format!("mount --move {src} -> {target} failed: {e}");
            if OPTIONAL_MOVE_MOUNTS.contains(&target) {
                log_line(&format!("warn: optional {msg}; continuing"));
                continue;
            }
            log_line(&format!("error: {msg}"));
            return Err(msg);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevertPlan {
    pub base_root: PathBuf,
    pub hook_paths: Vec<PathBuf>,
    pub extra_rcd_hooks: Vec<PathBuf>,
    /// Unmounted directories safe to delete immediately.
    pub immediate_purge_dirs: Vec<PathBuf>,
    /// Live mounted overlayfs upperdir/workdir that MUST NOT be deleted in place;
    /// staged via `purge_marker_path` for clean removal after reboot into stock rootfs.
    pub deferred_purge_dirs: Vec<PathBuf>,
    pub purge_marker_path: Option<PathBuf>,
    pub needs_real_rootfs_remount: bool,
}

pub fn plan_revert(st: &OverlayStatus, purge: bool) -> RevertPlan {
    let base_root = if st.pivoted {
        PathBuf::from(REAL_ROOTFS)
    } else {
        PathBuf::from("/")
    };
    let hook_paths = vec![
        base_root.join("etc/rc.d/S03cellcore-overlay"),
        base_root.join("etc/rc.d/S13cellcore-overlay-rw"),
        base_root.join("etc/init.d/cellcore-overlay"),
        base_root.join("etc/init.d/cellcore-overlay-rw"),
    ];
    let extra_rcd_hooks = if st.pivoted {
        vec![
            PathBuf::from("/etc/rc.d/S03cellcore-overlay"),
            PathBuf::from("/etc/rc.d/S13cellcore-overlay-rw"),
        ]
    } else {
        Vec::new()
    };

    let mut candidate_dirs: Vec<PathBuf> = Vec::new();
    if purge {
        if let Some(u) = st.upper_dir.as_deref() {
            candidate_dirs.push(PathBuf::from(u));
        }
        if let Some(w) = st.work_dir.as_deref() {
            let wp = PathBuf::from(w);
            if !candidate_dirs.contains(&wp) {
                candidate_dirs.push(wp);
            }
        }
        if let Some(backing) = st.backing_dir.as_deref() {
            for name in ["cellcore-rootfs", "cellcore-rootfs-work"] {
                let p = PathBuf::from(format!("{backing}/{name}"));
                if !candidate_dirs.contains(&p) {
                    candidate_dirs.push(p);
                }
            }
        }
    }

    let (immediate_purge_dirs, deferred_purge_dirs) = if st.pivoted {
        // NEVER rm -rf a live mounted overlayfs upperdir/workdir in place!
        (Vec::new(), candidate_dirs)
    } else {
        (candidate_dirs, Vec::new())
    };
    let purge_marker_path = st
        .backing_dir
        .as_deref()
        .map(|b| PathBuf::from(format!("{b}/{PENDING_PURGE_MARKER}")));

    RevertPlan {
        base_root,
        hook_paths,
        extra_rcd_hooks,
        immediate_purge_dirs,
        deferred_purge_dirs,
        purge_marker_path,
        needs_real_rootfs_remount: st.pivoted,
    }
}

pub fn execute_revert_plan(plan: &RevertPlan) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    for t in plan.hook_paths.iter().chain(plan.extra_rcd_hooks.iter()) {
        if t.exists() || t.symlink_metadata().is_ok() {
            fs::remove_file(t).map_err(|e| format!("remove {}: {e}", t.display()))?;
            actions.push(format!("removed {}", t.display()));
        }
    }
    for dir in &plan.immediate_purge_dirs {
        if dir.exists() {
            fs::remove_dir_all(dir).map_err(|e| format!("purge {}: {e}", dir.display()))?;
            actions.push(format!("purged {}", dir.display()));
        }
    }
    if !plan.deferred_purge_dirs.is_empty() {
        if let Some(marker) = &plan.purge_marker_path {
            let mut body = String::from("# CellCore overlay purge staged (live upperdir not deleted in place)\n");
            for d in &plan.deferred_purge_dirs {
                body.push_str(&d.display().to_string());
                body.push('\n');
            }
            crate::state::atomic_write(marker, body.as_bytes(), 0o600)?;
            actions.push(format!(
                "staged deferred purge marker {} (reboot into stock rootfs before removing live upperdir)",
                marker.display()
            ));
        }
    } else if let Some(marker) = &plan.purge_marker_path
        && marker.exists()
    {
        let _ = fs::remove_file(marker);
        actions.push(format!("cleared purge marker {}", marker.display()));
    }
    Ok(actions)
}

/// Execute idempotent overlayfs + pivot_root (or dry-run plan).
pub fn run_pivot(dry_run: bool) -> Result<(), String> {
    let raw = fs::read_to_string(crate::paths::p("/proc/mounts"))
        .map_err(|e| format!("read /proc/mounts: {e}"))?;
    let mounts = parse_proc_mounts(&raw);
    let st = analyze_mounts(
        &mounts,
        statvfs_avail_mib,
        |p| Path::new(&crate::paths::p(p)).exists(),
    );

    if st.pivoted {
        log_line("already pivoted (/real_rootfs active); nothing to do");
        return Ok(());
    }
    if let Some(backing) = st.backing_dir.as_deref() {
        let marker = PathBuf::from(crate::paths::p(&format!("{backing}/{PENDING_PURGE_MARKER}")));
        if marker.exists() {
            return Err(format!(
                "refusing to pivot while revert purge marker {} is pending; run `cellctl overlay revert --yes --purge` in stock rootfs to finish cleanup",
                marker.display()
            ));
        }
    }
    if !st.safe_to_pivot {
        return Err(format!("refusing to pivot: {}", st.reason));
    }

    let upper = st.upper_dir.as_deref().ok_or("missing upperdir")?;
    let work = st.work_dir.as_deref().ok_or("missing workdir")?;
    let active_move_targets: Vec<&str> = MOVE_MOUNTS
        .iter()
        .copied()
        .filter(|t| mounts.iter().any(|m| m.target == *t))
        .collect();

    if dry_run {
        println!("dry_run=1");
        println!("scenario={}", st.scenario.as_str());
        println!("upperdir={upper}");
        println!("workdir={work}");
        println!("backing_avail_mib={}", st.backing_avail_mib.unwrap_or(0));
        println!("move_mounts={}", active_move_targets.join(","));
        return Ok(());
    }

    log_line(&format!(
        "starting overlay pivot scenario={} upper={upper} work={work}",
        st.scenario.as_str()
    ));

    // Create upper/work directories on writable backing partition first.
    fs::create_dir_all(upper).map_err(|e| format!("mkdir {upper}: {e}"))?;
    fs::create_dir_all(work).map_err(|e| format!("mkdir {work}: {e}"))?;

    // Ensure /rootfs mountpoint exists on the base rootfs (temporarily remounting / rw if needed).
    let remounted_base_rw = if !Path::new(NEW_ROOTFS).exists() {
        sys_mount(None, "/", None, libc::MS_REMOUNT, None)?;
        fs::create_dir_all(NEW_ROOTFS).map_err(|e| format!("mkdir {NEW_ROOTFS}: {e}"))?;
        true
    } else {
        false
    };

    let ovl_opts = format!("lowerdir=/,upperdir={upper},workdir={work}");
    if let Err(e) = sys_mount(Some("overlay"), NEW_ROOTFS, Some("overlay"), 0, Some(&ovl_opts)) {
        if remounted_base_rw {
            let _ = sys_mount(None, "/", None, libc::MS_REMOUNT | libc::MS_RDONLY, None);
        }
        return Err(e);
    }

    let put_old = format!("{NEW_ROOTFS}{REAL_ROOTFS}");
    if let Err(e) = fs::create_dir_all(&put_old) {
        let _ = sys_umount_detach(NEW_ROOTFS);
        if remounted_base_rw {
            let _ = sys_mount(None, "/", None, libc::MS_REMOUNT | libc::MS_RDONLY, None);
        }
        return Err(format!("mkdir {put_old}: {e}"));
    }

    if let Err(e) = sys_pivot_root(NEW_ROOTFS, &put_old) {
        let _ = sys_umount_detach(NEW_ROOTFS);
        if remounted_base_rw {
            let _ = sys_mount(None, "/", None, libc::MS_REMOUNT | libc::MS_RDONLY, None);
        }
        return Err(e);
    }

    move_mounts_with(&active_move_targets, |src, target| {
        fs::create_dir_all(target).map_err(|e| format!("mkdir {target}: {e}"))?;
        sys_mount(Some(src), target, None, libc::MS_MOVE, None)
    })?;

    // Bind original /etc/rc.d so init script enable/disable state persists on the base root.
    let old_rcd = format!("{REAL_ROOTFS}/etc/rc.d");
    if Path::new(&old_rcd).is_dir() {
        fs::create_dir_all("/etc/rc.d").map_err(|e| format!("mkdir /etc/rc.d: {e}"))?;
        sys_mount(Some(&old_rcd), "/etc/rc.d", None, libc::MS_BIND, None)
            .map_err(|e| {
                let msg = format!("bind {old_rcd} -> /etc/rc.d failed: {e}");
                log_line(&format!("error: {msg}"));
                msg
            })?;
        let _ = sys_mount(None, "/etc/rc.d", None, libc::MS_REMOUNT | libc::MS_BIND, None);
    }

    // Keep base factory root read-only to protect factory UBIFS integrity.
    let _ = sys_mount(
        None,
        REAL_ROOTFS,
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY,
        None,
    );

    log_line("overlay pivot completed cleanly");
    Ok(())
}

/// Late-boot (`START=13`) safeguard: ensure `/` and `/etc/rc.d` remain read-write.
pub fn run_remount_rw() -> Result<(), String> {
    sys_mount(None, "/", None, libc::MS_REMOUNT, None)?;
    if Path::new("/etc/rc.d").is_dir() {
        let _ = sys_mount(None, "/etc/rc.d", None, libc::MS_REMOUNT | libc::MS_BIND, None);
    }
    log_line("remounted / and /etc/rc.d read-write");
    Ok(())
}

/// Cleanly disable the CellCore early-boot overlay hooks so the next reboot restores
/// 100% stock factory rootfs without touching any factory binaries.
#[cfg(test)]
pub fn disable_overlay_hooks_in(base_root: &Path, purge_dirs: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    let targets = [
        base_root.join("etc/rc.d/S03cellcore-overlay"),
        base_root.join("etc/rc.d/S13cellcore-overlay-rw"),
        base_root.join("etc/init.d/cellcore-overlay"),
        base_root.join("etc/init.d/cellcore-overlay-rw"),
    ];
    for t in &targets {
        if t.exists() || t.symlink_metadata().is_ok() {
            fs::remove_file(t).map_err(|e| format!("remove {}: {e}", t.display()))?;
            actions.push(format!("removed {}", t.display()));
        }
    }
    for dir in purge_dirs {
        if dir.exists() {
            fs::remove_dir_all(dir).map_err(|e| format!("purge {}: {e}", dir.display()))?;
            actions.push(format!("purged {}", dir.display()));
        }
    }
    Ok(actions)
}

pub fn run_revert(yes: bool, purge: bool) -> Result<(), String> {
    if !yes {
        return Err(
            "Refusing to revert overlay without --yes. Re-run `cellctl overlay revert --yes [--purge]` and reboot to restore factory rootfs."
                .into(),
        );
    }
    let st = probe_status()?;
    let plan = plan_revert(&st, purge);
    if plan.needs_real_rootfs_remount {
        // Temporarily remount /real_rootfs rw to remove only our two init scripts/symlinks.
        sys_mount(None, REAL_ROOTFS, None, libc::MS_REMOUNT, None)?;
    } else {
        let _ = sys_mount(None, "/", None, libc::MS_REMOUNT, None);
    }

    let res = execute_revert_plan(&plan);
    if plan.needs_real_rootfs_remount {
        let _ = sys_mount(
            None,
            REAL_ROOTFS,
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY,
            None,
        );
    }
    let actions = res?;
    if actions.is_empty() {
        println!("No CellCore overlay hooks found; already reverted.");
    } else {
        for a in actions {
            println!("ok: {a}");
        }
    }
    if !plan.deferred_purge_dirs.is_empty() {
        println!(
            "Revert staged cleanly without deleting the live mounted overlay upperdir. Reboot into stock factory rootfs, then re-run `cellctl overlay revert --yes --purge` to reclaim backing space."
        );
    } else {
        println!("Revert staged cleanly. Run `reboot` to boot back into stock factory rootfs.");
    }
    Ok(())
}

pub fn run_cli(args: &[String]) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    match sub {
        "status" => {
            let want_json = args.iter().any(|a| a == "--json");
            match probe_status() {
                Ok(st) => {
                    if want_json {
                        println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
                    } else {
                        println!(
                            "scenario={} pivoted={} root_writable={} root_fstype={} backing={} avail_mib={} safe_to_pivot={}",
                            st.scenario.as_str(),
                            if st.pivoted { 1 } else { 0 },
                            if st.root_writable { 1 } else { 0 },
                            st.root_fstype,
                            st.backing_dir.as_deref().unwrap_or("none"),
                            st.backing_avail_mib.unwrap_or(0),
                            if st.safe_to_pivot { 1 } else { 0 },
                        );
                        println!("reason={}", st.reason);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("cellcore-overlay: {e}");
                    1
                }
            }
        }
        "pivot" => {
            let dry_run = args.iter().any(|a| a == "--dry-run");
            match run_pivot(dry_run) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("cellcore-overlay: {e}");
                    1
                }
            }
        }
        "remount-rw" => match run_remount_rw() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("cellcore-overlay: {e}");
                1
            }
        },
        "revert" => {
            let yes = args.iter().any(|a| a == "--yes");
            let purge = args.iter().any(|a| a == "--purge");
            match run_revert(yes, purge) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("cellcore-overlay: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("Usage: cellctl overlay <status [--json] | pivot [--dry-run] | remount-rw | revert --yes [--purge]>");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS_ALREADY_PIVOTED: &str = "\
ubi0:rootfs /real_rootfs ubifs ro,relatime,ubi=0,vol=0 0 0
proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0
/dev/ubi2_0 /usrdata ubifs rw,relatime,ubi=2,vol=0 0 0
/dev/ubi2_0 /etc ubifs rw,relatime,ubi=2,vol=0 0 0
overlay / overlay rw,relatime,lowerdir=/,upperdir=/usrdata/rootfs,workdir=/usrdata/rootfs-workdir 0 0
";

    const MOUNTS_STOCK_R02: &str = "\
ubi0:rootfs / ubifs ro,relatime,ubi=0,vol=0 0 0
proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0
sysfs /sys sysfs rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0
/dev/ubi2_0 /usrdata ubifs rw,relatime,ubi=2,vol=0 0 0
/dev/ubi2_0 /etc ubifs rw,relatime,ubi=2,vol=0 0 0
";

    const MOUNTS_STOCK_R01: &str = "\
ubi0:rootfs / ubifs ro,relatime,ubi=0,vol=0 0 0
/dev/ubi2_0 /usrdata ubifs rw,relatime,ubi=2,vol=0 0 0
/dev/ubi2_0 /etc ubifs rw,relatime,ubi=2,vol=0 0 0
overlay /etc overlay rw,relatime 0 0
";

    #[test]
    fn detects_already_pivoted_sdx75() {
        let m = parse_proc_mounts(MOUNTS_ALREADY_PIVOTED);
        let st = analyze_mounts(&m, |_| Some(240), |p| p == "/usrdata/rootfs");
        assert_eq!(st.scenario, OverlayScenario::AlreadyPivoted);
        assert!(st.pivoted);
        assert!(st.root_writable);
        assert!(!st.safe_to_pivot);
        assert_eq!(st.upper_dir.as_deref(), Some("/usrdata/rootfs"));
    }

    #[test]
    fn detects_stock_r02_and_refuses_low_space() {
        let m = parse_proc_mounts(MOUNTS_STOCK_R02);
        let ok = analyze_mounts(&m, |_| Some(250), |_| false);
        assert_eq!(ok.scenario, OverlayScenario::UsrdataR02);
        assert!(!ok.pivoted);
        assert!(!ok.root_writable);
        assert!(ok.safe_to_pivot);
        assert_eq!(ok.upper_dir.as_deref(), Some("/usrdata/cellcore-rootfs"));

        let low = analyze_mounts(&m, |_| Some(12), |_| false);
        assert!(!low.safe_to_pivot);
        assert!(low.reason.contains("12 MiB"));
    }

    #[test]
    fn detects_stock_r01_two_etc_mounts() {
        let m = parse_proc_mounts(MOUNTS_STOCK_R01);
        let st = analyze_mounts(&m, |_| Some(180), |_| false);
        assert_eq!(st.scenario, OverlayScenario::UsrdataR01);
        assert_eq!(st.etc_mount_count, 2);
        assert!(st.safe_to_pivot);
    }

    #[test]
    fn revert_cleans_only_cellcore_overlay_hooks_and_optional_purge() {
        let sbx = crate::paths::TestSandbox::new("overlay-revert");
        let base = sbx.root.join("real_rootfs");
        fs::create_dir_all(base.join("etc/init.d")).unwrap();
        fs::create_dir_all(base.join("etc/rc.d")).unwrap();
        fs::write(base.join("etc/init.d/cellcore-overlay"), b"#!/bin/sh\n").unwrap();
        fs::write(base.join("etc/init.d/cellcore-overlay-rw"), b"#!/bin/sh\n").unwrap();
        fs::write(base.join("etc/init.d/dropbear"), b"keep me").unwrap();
        std::os::unix::fs::symlink(
            "../init.d/cellcore-overlay",
            base.join("etc/rc.d/S03cellcore-overlay"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../init.d/cellcore-overlay-rw",
            base.join("etc/rc.d/S13cellcore-overlay-rw"),
        )
        .unwrap();

        let upper = sbx.root.join("usrdata/cellcore-rootfs");
        fs::create_dir_all(&upper).unwrap();
        fs::write(upper.join("marker"), b"ok").unwrap();

        let actions = disable_overlay_hooks_in(&base, std::slice::from_ref(&upper)).unwrap();
        assert_eq!(actions.len(), 5);
        assert!(!base.join("etc/init.d/cellcore-overlay").exists());
        assert!(!base.join("etc/rc.d/S03cellcore-overlay").exists());
        assert!(base.join("etc/init.d/dropbear").exists());
        assert!(!upper.exists());
    }

    #[test]
    fn overlay_log_truncates_when_exceeding_64_kib() {
        let sbx = crate::paths::TestSandbox::new("overlay-log-cap");
        let log_path = sbx.root.join("tmp/cellcore-overlay.log");
        fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        let big = format!("{}\n", "A".repeat(OVERLAY_LOG_MAX_BYTES as usize + 4096));
        fs::write(&log_path, big.as_bytes()).unwrap();

        append_overlay_log_at(&log_path, "fresh-entry-after-rotate");
        let after = fs::read_to_string(&log_path).unwrap();
        assert!(after.len() < OVERLAY_LOG_MAX_BYTES as usize);
        assert!(after.contains("fresh-entry-after-rotate"));
    }

    #[test]
    fn move_mounts_fails_closed_when_any_mount_move_fails() {
        let mut seen = Vec::new();
        let err = move_mounts_with(&["/proc", "/sys", "/dev"], |src, tgt| {
            seen.push((src.to_string(), tgt.to_string()));
            if tgt == "/sys" {
                Err("EBUSY".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(err.contains("mount --move /real_rootfs/sys -> /sys failed: EBUSY"), "{err}");
        assert_eq!(seen.len(), 2, "must stop immediately on first failed move");
    }

    #[test]
    fn move_mounts_treats_optional_platform_mounts_as_best_effort() {
        let mut seen = Vec::new();
        move_mounts_with(&["/proc", "/cache", "/persist", "/systemrw", "/etc"], |src, tgt| {
            seen.push((src.to_string(), tgt.to_string()));
            if matches!(tgt, "/cache" | "/persist" | "/systemrw") {
                Err("ENOENT".into())
            } else {
                Ok(())
            }
        })
        .expect("optional mount move failures should warn and continue");
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn revert_plan_defers_live_upperdir_purge_when_pivoted_and_purges_when_unpivoted() {
        let sbx = crate::paths::TestSandbox::new("overlay-revert-plan");

        // Case 1: Pivoted (live overlayfs mounted) with --purge -> NEVER deletes live upperdir in place!
        let m_pivoted = parse_proc_mounts(MOUNTS_ALREADY_PIVOTED);
        let st_pivoted = analyze_mounts(&m_pivoted, |_| Some(200), |p| p == "/usrdata/rootfs");
        let plan_piv = plan_revert(&st_pivoted, true);
        assert!(plan_piv.needs_real_rootfs_remount);
        assert!(
            plan_piv.immediate_purge_dirs.is_empty(),
            "live mounted overlayfs upperdir must NEVER be in immediate_purge_dirs: {:?}",
            plan_piv.immediate_purge_dirs
        );
        assert!(plan_piv.deferred_purge_dirs.contains(&PathBuf::from("/usrdata/rootfs")));
        assert!(plan_piv.deferred_purge_dirs.contains(&PathBuf::from("/usrdata/rootfs-workdir")));
        assert_eq!(
            plan_piv.purge_marker_path,
            Some(PathBuf::from(format!("/usrdata/{PENDING_PURGE_MARKER}")))
        );
        assert!(plan_piv.extra_rcd_hooks.contains(&PathBuf::from("/etc/rc.d/S03cellcore-overlay")));

        // Execute pivoted revert plan against sandboxed paths and confirm upperdir survives + marker written!
        let real_root = sbx.root.join("real_rootfs");
        let live_rcd = sbx.root.join("live_etc_rcd");
        let upper = sbx.root.join("usrdata/cellcore-rootfs");
        let work = sbx.root.join("usrdata/cellcore-rootfs-work");
        let marker = sbx.root.join(format!("usrdata/{PENDING_PURGE_MARKER}"));
        fs::create_dir_all(real_root.join("etc/init.d")).unwrap();
        fs::create_dir_all(real_root.join("etc/rc.d")).unwrap();
        fs::create_dir_all(&live_rcd).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(real_root.join("etc/init.d/cellcore-overlay"), b"#!/bin/sh\n").unwrap();
        fs::write(real_root.join("etc/rc.d/S03cellcore-overlay"), b"link").unwrap();
        fs::write(live_rcd.join("S03cellcore-overlay"), b"link").unwrap();
        fs::write(upper.join("live-file"), b"still mounted").unwrap();

        let sbx_piv_plan = RevertPlan {
            base_root: real_root.clone(),
            hook_paths: vec![
                real_root.join("etc/rc.d/S03cellcore-overlay"),
                real_root.join("etc/init.d/cellcore-overlay"),
            ],
            extra_rcd_hooks: vec![live_rcd.join("S03cellcore-overlay")],
            immediate_purge_dirs: Vec::new(),
            deferred_purge_dirs: vec![upper.clone(), work.clone()],
            purge_marker_path: Some(marker.clone()),
            needs_real_rootfs_remount: true,
        };
        let actions = execute_revert_plan(&sbx_piv_plan).unwrap();
        assert!(actions.iter().any(|a| a.contains("staged deferred purge marker")), "{actions:?}");
        assert!(!real_root.join("etc/rc.d/S03cellcore-overlay").exists());
        assert!(!live_rcd.join("S03cellcore-overlay").exists());
        assert!(upper.join("live-file").exists(), "live upperdir MUST NOT be deleted in place!");
        assert!(marker.exists(), "deferred purge marker must be written");

        // Case 2: Unpivoted (stock rootfs after reboot) with --purge -> safe to purge immediately & clear marker!
        let m_stock = parse_proc_mounts(MOUNTS_STOCK_R02);
        let st_stock = analyze_mounts(&m_stock, |_| Some(200), |_| false);
        let plan_stock = plan_revert(&st_stock, true);
        assert!(!plan_stock.needs_real_rootfs_remount);
        assert!(plan_stock.deferred_purge_dirs.is_empty());
        assert!(plan_stock.immediate_purge_dirs.contains(&PathBuf::from("/usrdata/cellcore-rootfs")));
        assert!(plan_stock.immediate_purge_dirs.contains(&PathBuf::from("/usrdata/cellcore-rootfs-work")));

        let sbx_stock_plan = RevertPlan {
            base_root: real_root.clone(),
            hook_paths: Vec::new(),
            extra_rcd_hooks: Vec::new(),
            immediate_purge_dirs: vec![upper.clone(), work.clone()],
            deferred_purge_dirs: Vec::new(),
            purge_marker_path: Some(marker.clone()),
            needs_real_rootfs_remount: false,
        };
        let actions2 = execute_revert_plan(&sbx_stock_plan).unwrap();
        assert!(actions2.iter().any(|a| a.contains("purged")), "{actions2:?}");
        assert!(!upper.exists(), "unmounted upperdir must be purged cleanly");
        assert!(!work.exists(), "unmounted workdir must be purged cleanly");
        assert!(!marker.exists(), "purge marker must be cleared after purge");
    }
}

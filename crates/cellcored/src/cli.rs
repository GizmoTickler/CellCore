use std::{
    env,
    fs,
    io::{BufRead, BufReader, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    process,
    time::{Duration, Instant},
};

use crate::{
    ipc::{IpcRequest, IpcResponse, detect_first_up_rmnet, format_r10_status_lines, ipc_socket_path, read_proc_uptime_secs},
    reconcile::run_boot_reconcile,
    smd::DirectSession,
    uci::{run_cmd_blocking, run_cmd_blocking_timeout},
};

pub const DAEMON_LOCK_PATH: &str = "/var/run/cellcored.lock";

/// Route10 kills its SSH session after 25 s; everything the CLI does for a
/// Route10 command must finish before this.
const R10_CLI_BUDGET: Duration = Duration::from_secs(23);
/// IPC read timeout for `status` (daemon answers within 18 s).
const IPC_STATUS_TIMEOUT: Duration = Duration::from_secs(20);
/// IPC read timeout for recovery actions (daemon answers within 20 s).
const IPC_ACTION_TIMEOUT: Duration = Duration::from_secs(22);
/// `metrics` and `role` are answered from memory; never block Route10 long.
const IPC_QUICK_TIMEOUT: Duration = Duration::from_secs(8);

pub fn daemon_lock_path() -> String {
    env::var("QM_LOCK_PATH").unwrap_or_else(|_| crate::paths::p(DAEMON_LOCK_PATH))
}

fn smd_device() -> String {
    crate::paths::smd_device()
}

/// Exclusive ownership of the AT device. The daemon holds it for its whole
/// lifetime; the CLI may only open the device directly while holding it.
/// The kernel drops the lock when the holder dies, so it can never go stale.
pub struct DeviceLock {
    _file: fs::File,
}

fn flock_file(path: &str, blocking: bool) -> Result<Option<DeviceLock>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    let op = if blocking { libc::LOCK_EX } else { libc::LOCK_EX | libc::LOCK_NB };
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
        if rc == 0 {
            return Ok(Some(DeviceLock { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(format!("flock {path}: {err}")),
        }
    }
}

/// Daemon side: block until the device lock is ours (a CLI fallback that is
/// mid-sequence finishes first).
pub fn acquire_daemon_lock(path: &str) -> Result<DeviceLock, String> {
    flock_file(path, true)?.ok_or_else(|| "lock unavailable".to_string())
}

/// Any other process running as `cellcored` (covers daemons from older
/// builds that do not take the lock).
fn other_daemon_process_alive() -> bool {
    let me = process::id().to_string();
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.bytes().all(|b| b.is_ascii_digit())
            && name != me
            && fs::read_to_string(e.path().join("comm")).is_ok_and(|c| c.trim() == "cellcored")
    })
}

/// Direct /dev/smd access is allowed only when no daemon is alive: we must
/// get the lock *and* see no cellcored process. Holding the returned lock
/// also serialises concurrent CLI fallbacks.
pub fn try_direct_access(lock_path: &str, check_procs: bool) -> Option<DeviceLock> {
    if check_procs && other_daemon_process_alive() {
        return None;
    }
    let lock = flock_file(lock_path, false).ok().flatten()?;
    if check_procs && other_daemon_process_alive() {
        return None;
    }
    Some(lock)
}

/// Write to stdout without panicking if Route10 already hung up (panic=abort
/// would otherwise kill us mid recovery sequence).
fn out(text: &str) {
    let mut so = std::io::stdout();
    let _ = so.write_all(text.as_bytes());
    let _ = so.flush();
}

pub fn call_daemon_sync(req: &IpcRequest) -> Result<IpcResponse, String> {
    call_daemon_sync_timeout(req, IPC_ACTION_TIMEOUT)
}

pub fn call_daemon_sync_timeout(req: &IpcRequest, read_timeout: Duration) -> Result<IpcResponse, String> {
    let sock_path = ipc_socket_path();
    let mut stream = UnixStream::connect(&sock_path)
        .map_err(|e| format!("connect {sock_path}: {e}"))?;
    let _ = stream.set_read_timeout(Some(read_timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write ipc: {e}"))?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read ipc: {e}"))?;
    serde_json::from_str::<IpcResponse>(line.trim()).map_err(|e| format!("parse ipc: {e}"))
}

fn resolve_r10_command(ssh_orig: Option<&str>, args: &[String]) -> Option<String> {
    if let Some(cmd) = ssh_orig.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(cmd.to_string());
    }
    if args.is_empty() || args.iter().any(|a| a.trim().is_empty()) {
        return None;
    }
    Some(args.join(" ").trim().to_string())
}

pub fn run_r10_modem_ctl(args: &[String]) -> i32 {
    let ssh_orig = env::var("SSH_ORIGINAL_COMMAND").ok();
    let Some(cmd) = resolve_r10_command(ssh_orig.as_deref(), args) else {
        out("error=rejected_command\n");
        return 2;
    };
    let cmd = cmd.as_str();
    let started = Instant::now();

    match cmd {
        "status" => {
            if let Ok(resp) = call_daemon_sync_timeout(&IpcRequest::R10Status, IPC_STATUS_TIMEOUT)
                && resp.ok
            {
                out(&resp.output);
                return 0;
            }
            // Never open the device while a daemon is alive: if it is up but
            // did not answer, report the AT channel as not OK.
            let text = match try_direct_access(&daemon_lock_path(), true) {
                Some(_lock) => direct_r10_status_fallback(started),
                None => r10_status_without_at(started),
            };
            out(&text);
            0
        }
        "wan-restart" | "modem-reset" => {
            let req = if cmd == "wan-restart" { IpcRequest::R10WanRestart } else { IpcRequest::R10ModemReset };
            if let Ok(resp) = call_daemon_sync_timeout(&req, IPC_ACTION_TIMEOUT)
                && resp.ok
            {
                out(&resp.output);
                return 0;
            }
            match try_direct_access(&daemon_lock_path(), true) {
                Some(_lock) => {
                    // Daemon not running. Finish the sequence even if Route10
                    // hangs up: a CFUN=0 must always be followed by CFUN=1.
                    unsafe {
                        libc::signal(libc::SIGHUP, libc::SIG_IGN);
                        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                    }
                    if cmd == "wan-restart" {
                        direct_wan_restart();
                    } else {
                        direct_modem_reset();
                    }
                    out(&format!("result=ok action={cmd}\n"));
                    0
                }
                None => {
                    // Daemon alive (or another fallback running): it owns the
                    // sequence; do not run it a second time.
                    out(&format!("result=ok action={cmd} state=in_progress running=daemon\n"));
                    0
                }
            }
        }
        "reboot" => {
            if let Ok(resp) = call_daemon_sync(&IpcRequest::R10Reboot)
                && resp.ok
            {
                out(&resp.output);
                return 0;
            }
            let _ = run_cmd_blocking("sync", &[]);
            let _ = run_cmd_blocking("/sbin/reboot", &[]);
            out("result=ok action=reboot\n");
            0
        }
        "metrics" => match call_daemon_sync_timeout(&IpcRequest::Metrics, IPC_QUICK_TIMEOUT) {
            Ok(resp) if resp.ok => {
                out(&resp.output);
                0
            }
            // Nothing on stdout: a caller writing a .prom file must not get
            // an error string as exposition text.
            Ok(resp) => err_line(&format!("error=metrics_failed {}", resp.error.unwrap_or_default())),
            Err(e) => err_line(&format!("error=daemon_unavailable {e}")),
        },
        c if c.split_whitespace().next() == Some("role") => {
            let words: Vec<&str> = c.split_whitespace().collect();
            let Some(role) = words.get(1).filter(|_| words.len() == 2).filter(|r| matches!(**r, "active" | "standby")) else {
                out("error=rejected_command\n");
                return 2;
            };
            match call_daemon_sync_timeout(&IpcRequest::Role { role: (*role).to_string() }, IPC_QUICK_TIMEOUT) {
                Ok(resp) if resp.ok => {
                    out(&resp.output);
                    0
                }
                Ok(resp) => {
                    out(&format!("error=role_failed {}\n", resp.error.unwrap_or_default()));
                    1
                }
                Err(_) => {
                    out("error=daemon_unavailable\n");
                    1
                }
            }
        }
        _ => {
            out("error=rejected_command\n");
            2
        }
    }
}

fn err_line(text: &str) -> i32 {
    let mut se = std::io::stderr();
    let _ = writeln!(se, "{text}");
    1
}

fn remaining(started: Instant, cap: Duration) -> Duration {
    R10_CLI_BUDGET.saturating_sub(started.elapsed()).min(cap)
}

fn wan_status_blocking(started: Instant) -> (u8, u64, String) {
    let (mut wan_up, mut wan_uptime, mut l3_device) = (0u8, 0u64, String::from("none"));
    for iface in ["network.interface.wan", "network.interface.wan_v6"] {
        let budget = remaining(started, Duration::from_secs(2));
        if budget.is_zero() {
            break;
        }
        if let Ok(out) = run_cmd_blocking_timeout("ubus", &["call", iface, "status"], budget)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&out)
            && v.get("up").and_then(|x| x.as_bool()) == Some(true)
        {
            wan_up = 1;
            if wan_uptime == 0 {
                wan_uptime = v.get("uptime").and_then(|x| x.as_u64()).unwrap_or(0);
            }
            if l3_device == "none"
                && let Some(dev) = v.get("l3_device").and_then(|x| x.as_str())
                && !dev.is_empty()
            {
                l3_device = dev.to_string();
            }
        }
    }
    if wan_up == 0
        && let Some(dev) = crate::netlink::detect_active_rmnet_wan_live()
    {
        wan_up = 1;
        l3_device = dev;
        wan_uptime = read_proc_uptime_secs().max(1);
    }
    if l3_device == "none" {
        l3_device = detect_first_up_rmnet();
    }
    (wan_up, wan_uptime, l3_device)
}

/// Same 17 keys, AT fields empty (at_token_ok=0, cfun=-1).
fn r10_status_without_at(started: Instant) -> String {
    let (wan_up, wan_uptime, l3_device) = wan_status_blocking(started);
    format_r10_status_lines(wan_up, wan_uptime, &l3_device, read_proc_uptime_secs(), "", "", "", "")
}

fn run_direct_r10_queries<F>(mut opener: F, started: Instant) -> [String; 4]
where
    F: FnMut() -> Result<DirectSession, String>,
{
    const CMDS: [&str; 4] = [
        "AT+CFUN?",
        "AT+QENG=\"servingcell\"",
        "AT+QRSRP",
        "AT+QNWINFO",
    ];
    let mut bodies: [String; 4] = Default::default();
    let Ok(mut session) = opener() else {
        return bodies;
    };
    for (i, cmd) in CMDS.iter().enumerate() {
        let budget = remaining(started, Duration::from_secs(4));
        if budget.is_zero() {
            break;
        }
        match session.exec(cmd, budget) {
            Ok(r) => {
                if i == 0
                    && crate::parsers::parse_scalar_at_value(&r.body, "+CFUN:")
                        .parse::<i32>()
                        .is_err()
                {
                    let retry_budget = remaining(started, Duration::from_secs(4));
                    if !retry_budget.is_zero()
                        && let Ok(r2) = session.exec(cmd, retry_budget)
                    {
                        bodies[i] = r2.body;
                        continue;
                    }
                }
                bodies[i] = r.body;
            }
            Err(e) if i == 0 && !e.starts_with("Direct SMD AT timed out") => {
                let retry_budget = remaining(started, Duration::from_secs(4));
                if !retry_budget.is_zero()
                    && let Ok(mut reopened) = opener()
                {
                    if let Ok(r2) = reopened.exec(cmd, retry_budget) {
                        bodies[i] = r2.body;
                    }
                    session = reopened;
                }
            }
            Err(_) => {}
        }
    }
    bodies
}

fn direct_r10_status_fallback(started: Instant) -> String {
    let (wan_up, wan_uptime, l3_device) = wan_status_blocking(started);
    let modem_uptime_s = read_proc_uptime_secs();
    let bodies = run_direct_r10_queries(|| DirectSession::open(&smd_device()), started);
    format_r10_status_lines(
        wan_up,
        wan_uptime,
        &l3_device,
        modem_uptime_s,
        &bodies[0],
        &bodies[1],
        &bodies[2],
        &bodies[3],
    )
}

fn direct_wan_restart() {
    if let Ok(mut s) = DirectSession::open(&smd_device()) {
        let cfun = s.exec("AT+CFUN?", Duration::from_secs(5)).map(|r| r.body).unwrap_or_default();
        if crate::parsers::parse_scalar_at_value(&cfun, "+CFUN:").trim() != "1" {
            let _ = s.exec("AT+CFUN=1", Duration::from_secs(10));
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let _ = run_cmd_blocking_timeout("ubus", &["call", "network.interface.wan", "down"], Duration::from_secs(3));
    std::thread::sleep(Duration::from_secs(2));
    let _ = run_cmd_blocking_timeout("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3));
    let _ = run_cmd_blocking_timeout("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3));
}

fn direct_modem_reset() {
    if let Ok(mut s) = DirectSession::open(&smd_device()) {
        let _ = s.exec("AT+CFUN=0", Duration::from_secs(10));
        std::thread::sleep(Duration::from_secs(3));
        let _ = s.exec("AT+CFUN=1", Duration::from_secs(15));
    }
    std::thread::sleep(Duration::from_secs(5));
    let _ = run_cmd_blocking_timeout("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3));
    let _ = run_cmd_blocking_timeout("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3));
}

/// Direct AT only when no daemon is alive; `None` = refused.
fn direct_exec(cmd: &str, timeout: Duration) -> Option<Result<crate::smd::AtResponse, String>> {
    let _lock = try_direct_access(&daemon_lock_path(), true)?;
    Some(DirectSession::open(&smd_device()).and_then(|mut s| s.exec(cmd, timeout)))
}

pub fn run_cellctl(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "version" | "--version" | "-V" => {
            println!("cellcored {} (RM551E-GL SDX75)", env!("CARGO_PKG_VERSION"));
            0
        }
        "overlay" => crate::overlay::run_cli(&args[1..]),
        "reconcile" => {
            if let Ok(resp) = call_daemon_sync(&IpcRequest::Reconcile)
                && resp.ok
            {
                println!("{}", resp.output);
                return 0;
            }
            let r = run_boot_reconcile(false);
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            0
        }
        "status" => match call_daemon_sync(&IpcRequest::QuectelStatus) {
            Ok(resp) if resp.ok => {
                print!("{}", resp.output);
                0
            }
            Ok(resp) => {
                eprintln!("{}", resp.error.unwrap_or_else(|| "status failed".into()));
                1
            }
            Err(_) => {
                let started = Instant::now();
                let text = match try_direct_access(&daemon_lock_path(), true) {
                    Some(_lock) => direct_r10_status_fallback(started),
                    None => r10_status_without_at(started),
                };
                print!("{text}");
                0
            }
        },
        "at" => {
            let cmd = args[1..].join(" ");
            if cmd.trim().is_empty() {
                eprintln!("Usage: cellctl at <AT_COMMAND>");
                return 2;
            }
            match call_daemon_sync(&IpcRequest::QuectelAt {
                command: cmd.clone(),
                timeout_secs: Some(12),
            }) {
                Ok(resp) => {
                    println!("{}", resp.output);
                    if resp.ok { 0 } else { 1 }
                }
                Err(ipc_err) => match direct_exec(&cmd, Duration::from_secs(12)) {
                    Some(Ok(r)) => {
                        println!("{}", r.body);
                        if r.ok { 0 } else { 1 }
                    }
                    Some(Err(e)) => {
                        eprintln!("AT error: {e}");
                        1
                    }
                    None => {
                        eprintln!("cellcored is running but did not answer ({ipc_err}); not opening the AT device directly");
                        1
                    }
                },
            }
        }
        "speedtest" => {
            let status = process::Command::new(crate::paths::p("/usr/bin/speedtest"))
                .env("HOME", crate::paths::p("/tmp/cellcore"))
                .args(["--accept-license", "--accept-gdpr"])
                .status();
            status.map(|s| s.code().unwrap_or(1)).unwrap_or(1)
        }
        "lan" => {
            let req = IpcRequest::QuectelAt {
                command: "AT+QMAP=\"LANIP\"".into(),
                timeout_secs: Some(4),
            };
            let lanip = match call_daemon_sync(&req) {
                Ok(resp) => resp.output,
                Err(_) => direct_exec("AT+QMAP=\"LANIP\"", Duration::from_secs(4))
                    .and_then(|r| r.ok())
                    .map(|r| r.body)
                    .unwrap_or_default(),
            };
            println!("{lanip}");
            0
        }
        "verify" => run_verify(&args[1..]),
        "upgrade" => run_upgrade(&args[1..]),
        "acme" => crate::acme::run_cli(&args[1..]),
        "security" => crate::hardening::run_cli(&args[1..]),
        "dataplane-restore" => crate::dataplane::run_dataplane_restore_cli(),
        _ => {
            eprintln!("Usage: cellctl <status|at <CMD>|reconcile|dataplane-restore|verify [--expect-wan 0|1]|upgrade [--check|--yes]|acme <status|config|issue|reset>|security <audit|harden>|overlay <status|pivot|remount-rw|revert>|speedtest|lan>");
            2
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifyArgs {
    expect_wan: bool,
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    let mut expect_wan = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(val) = a.strip_prefix("--expect-wan=") {
            expect_wan = match val {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => return Err(format!("invalid --expect-wan value {val:?} (expected 0 or 1)")),
            };
        } else if a == "--expect-wan" {
            let Some(val) = args.get(i + 1) else {
                return Err("--expect-wan requires 0 or 1".into());
            };
            expect_wan = match val.as_str() {
                "1" | "true" => true,
                "0" | "false" => false,
                _ => return Err(format!("invalid --expect-wan value {val:?} (expected 0 or 1)")),
            };
            i += 1;
        } else {
            return Err(format!("unknown verify flag: {a}"));
        }
        i += 1;
    }
    Ok(VerifyArgs { expect_wan })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpgradeArgs {
    check: bool,
    yes: bool,
}

fn parse_upgrade_args(args: &[String]) -> Result<UpgradeArgs, String> {
    let mut check = false;
    let mut yes = false;
    for a in args {
        match a.as_str() {
            "--check" => check = true,
            "--yes" | "-y" => yes = true,
            other => return Err(format!("unknown upgrade flag: {other}")),
        }
    }
    Ok(UpgradeArgs { check, yes })
}

fn run_verify(args: &[String]) -> i32 {
    let parsed = match parse_verify_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error=invalid_args detail={e}");
            return 2;
        }
    };
    let status_resp = match call_daemon_sync_timeout(&IpcRequest::QuectelStatus, Duration::from_secs(6)) {
        Ok(r) if r.ok => r,
        Ok(r) => {
            eprintln!("error=ipc_failed detail={}", r.error.unwrap_or_default());
            return 1;
        }
        Err(e) => {
            eprintln!("error=daemon_unavailable detail={e}");
            return 1;
        }
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&status_resp.output) else {
        eprintln!("error=invalid_status_json");
        return 1;
    };
    let version = v.get("version").and_then(|x| x.as_str()).unwrap_or("").trim();
    if version.is_empty() {
        eprintln!("error=missing_version");
        return 1;
    }
    let active_rmnet = crate::netlink::detect_active_rmnet_wan_live();
    let wan_up = if active_rmnet.is_some() { 1 } else { 0 };
    if parsed.expect_wan && wan_up == 0 {
        eprintln!("error=wan_down version={version} wan_up=0");
        return 1;
    }
    println!(
        "ok=1 version={version} wan_up={wan_up} iface={}",
        active_rmnet.as_deref().unwrap_or("none")
    );
    0
}

fn run_upgrade(args: &[String]) -> i32 {
    let parsed = match parse_upgrade_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error=invalid_args detail={e}");
            return 2;
        }
    };
    let (pkg, installed) = crate::admin::opkg::find_qm_package_status();
    if parsed.check {
        let _ = run_cmd_blocking_timeout("opkg", &["update"], Duration::from_secs(120));
        let avail = run_cmd_blocking_timeout("opkg", &["list", &pkg], Duration::from_secs(30))
            .ok()
            .and_then(|out| {
                crate::admin::opkg::parse_pkg_lines(&out)
                    .into_iter()
                    .filter(|p| p.name == pkg)
                    .max_by(|a, b| crate::admin::opkg::compare_opkg_versions(&a.version, &b.version))
                    .map(|p| p.version)
            });
        let update_available = avail.as_deref().is_some_and(|av| {
            installed
                .as_deref()
                .is_none_or(|inst| crate::admin::opkg::compare_opkg_versions(av, inst) == std::cmp::Ordering::Greater)
        });
        println!(
            "package={pkg} installed={} available={} update_available={}",
            installed.as_deref().unwrap_or("none"),
            avail.as_deref().unwrap_or("none"),
            if update_available { 1 } else { 0 }
        );
        return 0;
    }
    if !parsed.yes {
        eprintln!("Usage: cellctl upgrade [--check] | cellctl upgrade --yes");
        return 2;
    }
    if let Some(free) = crate::admin::opkg::overlay_free_bytes()
        && free < crate::admin::opkg::MIN_SELF_UPGRADE_BYTES
    {
        eprintln!(
            "error=insufficient_overlay_space free_bytes={free} required_bytes={}",
            crate::admin::opkg::MIN_SELF_UPGRADE_BYTES
        );
        return 1;
    }
    let from_ver = installed.as_deref().unwrap_or("unknown");
    let script = crate::admin::opkg::build_self_upgrade_script(
        &pkg,
        from_ver,
        "latest",
        crate::admin::opkg::SELF_UPGRADE_STATE_PATH,
        crate::admin::opkg::SELF_UPGRADE_LOG_PATH,
    );
    let script_path = "/tmp/cellcore/self-upgrade.sh";
    let _ = fs::create_dir_all("/tmp/cellcore");
    if let Err(e) = fs::write(script_path, script.as_bytes()) {
        eprintln!("error=write_script detail={e}");
        return 1;
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(script_path, fs::Permissions::from_mode(0o700));
    match process::Command::new("/bin/sh").arg(script_path).status() {
        Ok(s) if s.success() => {
            println!("ok=1 package={pkg} upgraded_from={from_ver}");
            0
        }
        Ok(s) => {
            eprintln!("error=upgrade_failed code={:?}", s.code());
            1
        }
        Err(e) => {
            eprintln!("error=exec_failed detail={e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_access_refused_while_lock_is_held() {
        let path = std::env::temp_dir().join(format!("qm-lock-{}", process::id()));
        let path = path.to_str().unwrap().to_string();
        // The "daemon" holds the device lock (flock is per open file
        // description, so a second open in this process contends as a
        // separate process would).
        let daemon = acquire_daemon_lock(&path).expect("daemon lock");
        assert!(try_direct_access(&path, false).is_none(), "CLI must not open smd while the daemon is alive");
        drop(daemon);
        let cli = try_direct_access(&path, false).expect("daemon gone: direct allowed");
        // a second concurrent CLI fallback is refused too
        assert!(try_direct_access(&path, false).is_none());
        drop(cli);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn r10_command_resolution_accepts_multi_arg_argv_and_rejects_empty() {
        assert_eq!(
            resolve_r10_command(None, &["role".into(), "active".into()]),
            Some("role active".into())
        );
        assert_eq!(
            resolve_r10_command(None, &["status".into()]),
            Some("status".into())
        );
        assert_eq!(
            resolve_r10_command(Some("role standby"), &["status".into()]),
            Some("role standby".into())
        );
        assert_eq!(resolve_r10_command(None, &[]), None);
        assert_eq!(resolve_r10_command(None, &["role".into(), " ".into()]), None);
        assert_eq!(run_r10_modem_ctl(&[]), 2);
        assert_eq!(run_r10_modem_ctl(&["role".into(), "".into()]), 2);
    }

    fn spawn_mock_smd<F>(handler: F) -> DirectSession
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        use std::os::fd::FromRawFd;
        let mut fds = [-1i32; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) }, 0);
        let peer = unsafe { UnixStream::from_raw_fd(fds[1]) };
        std::thread::spawn(move || handler(peer));
        DirectSession::from_fd(fds[0])
    }

    #[test]
    fn direct_r10_queries_reopen_once_on_eof_and_recover_cfun() {
        let mut attempt = 0u32;
        let bodies = run_direct_r10_queries(
            || {
                attempt += 1;
                if attempt == 1 {
                    Ok(spawn_mock_smd(|peer| {
                        // Drop immediately on read/write -> EOF on first session
                        drop(peer);
                    }))
                } else {
                    Ok(spawn_mock_smd(|mut peer| {
                        let mut reader = BufReader::new(peer.try_clone().unwrap());
                        let mut line = String::new();
                        while reader.read_line(&mut line).unwrap_or(0) > 0 {
                            let reply = if line.contains("CFUN?") {
                                "+CFUN: 1\r\nOK\r\n"
                            } else {
                                "OK\r\n"
                            };
                            let _ = peer.write_all(reply.as_bytes());
                            line.clear();
                        }
                    }))
                }
            },
            Instant::now(),
        );
        assert_eq!(attempt, 2);
        assert!(bodies[0].contains("+CFUN: 1"), "{:?}", bodies);
    }

    #[test]
    fn direct_r10_queries_retry_stale_cfun_terminator_and_report_error_cleanly() {
        // Case A: first AT+CFUN? receives stale "OK\r\n" without "+CFUN:", second returns "+CFUN: 1\r\nOK\r\n"
        let bodies_stale = run_direct_r10_queries(
            || {
                Ok(spawn_mock_smd(|mut peer| {
                    let mut reader = BufReader::new(peer.try_clone().unwrap());
                    let mut line = String::new();
                    let mut cfun_calls = 0;
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        if line.contains("CFUN?") {
                            cfun_calls += 1;
                            if cfun_calls == 1 {
                                let _ = peer.write_all(b"OK\r\n");
                            } else {
                                let _ = peer.write_all(b"+CFUN: 1\r\nOK\r\n");
                            }
                        } else {
                            let _ = peer.write_all(b"OK\r\n");
                        }
                        line.clear();
                    }
                }))
            },
            Instant::now(),
        );
        assert!(bodies_stale[0].contains("+CFUN: 1"), "{:?}", bodies_stale);

        // Case B: modem answers ERROR to both -> formatted status reports at_token_ok=0 without hanging
        let bodies_err = run_direct_r10_queries(
            || {
                Ok(spawn_mock_smd(|mut peer| {
                    let mut reader = BufReader::new(peer.try_clone().unwrap());
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let _ = peer.write_all(b"ERROR\r\n");
                        line.clear();
                    }
                }))
            },
            Instant::now(),
        );
        let formatted = format_r10_status_lines(1, 10, "rmnet_data0", 20, &bodies_err[0], &bodies_err[1], &bodies_err[2], &bodies_err[3]);
        assert!(formatted.contains("at_token_ok=0\n"), "{formatted}");
    }

    #[test]
    fn parses_verify_and_upgrade_cli_args() {
        assert_eq!(parse_verify_args(&[]).unwrap(), VerifyArgs { expect_wan: false });
        assert_eq!(
            parse_verify_args(&["--expect-wan".into(), "1".into()]).unwrap(),
            VerifyArgs { expect_wan: true }
        );
        assert_eq!(
            parse_verify_args(&["--expect-wan=0".into()]).unwrap(),
            VerifyArgs { expect_wan: false }
        );
        assert!(parse_verify_args(&["--expect-wan".into(), "maybe".into()]).is_err());
        assert!(parse_verify_args(&["--bogus".into()]).is_err());

        assert_eq!(
            parse_upgrade_args(&["--check".into()]).unwrap(),
            UpgradeArgs { check: true, yes: false }
        );
        assert_eq!(
            parse_upgrade_args(&["--yes".into()]).unwrap(),
            UpgradeArgs { check: false, yes: true }
        );
        assert!(parse_upgrade_args(&["--unknown".into()]).is_err());
    }
}

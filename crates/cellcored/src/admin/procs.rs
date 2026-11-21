//! Processes › list with CPU / memory (from /proc, sampled twice), and signals.
//!
//! PID 1, kernel threads and this daemon are never signalled. Platform-critical
//! processes need a typed confirmation. The caller's `starttime` must match the
//! live process so a recycled PID is never hit.

use std::{collections::HashMap, time::Duration};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};

use super::{audit, bad, conflict, forbidden, ok, require_confirm, server};
use crate::http::HttpCtx;

const PF_KTHREAD: u64 = 0x0020_0000;
const MAX_PROCS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub flags: u64,
    pub utime: u64,
    pub stime: u64,
    pub nice: i64,
    pub threads: i64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss_pages: i64,
}

impl ProcStat {
    pub fn is_kthread(&self) -> bool {
        self.flags & PF_KTHREAD != 0 || self.pid == 2 || self.ppid == 2
    }
}

/// Parse `/proc/<pid>/stat`. The comm field may contain spaces and parentheses,
/// so split at the last ')'.
pub fn parse_proc_stat(s: &str) -> Option<ProcStat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let pid: i32 = s[..open].trim().parse().ok()?;
    let comm = s[open + 1..close].to_string();
    let f: Vec<&str> = s[close + 1..].split_whitespace().collect();
    if f.len() < 22 {
        return None;
    }
    Some(ProcStat {
        pid,
        comm,
        state: f[0].chars().next()?,
        ppid: f[1].parse().ok()?,
        flags: f[6].parse().ok()?,
        utime: f[11].parse().ok()?,
        stime: f[12].parse().ok()?,
        nice: f[16].parse().ok()?,
        threads: f[17].parse().ok()?,
        starttime: f[19].parse().ok()?,
        vsize: f[20].parse().ok()?,
        rss_pages: f[21].parse().ok()?,
    })
}

/// Sum of all jiffies on the aggregate `cpu` line of /proc/stat, and CPU count.
pub fn parse_cpu_total(s: &str) -> (u64, usize) {
    let mut total = 0;
    let mut cpus = 0;
    for l in s.lines() {
        if let Some(rest) = l.strip_prefix("cpu ") {
            total = rest.split_whitespace().filter_map(|x| x.parse::<u64>().ok()).sum();
        } else if l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit) {
            cpus += 1;
        }
    }
    (total, cpus.max(1))
}

pub fn parse_meminfo_kb(s: &str, key: &str) -> Option<u64> {
    s.lines().find_map(|l| {
        let rest = l.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// uid → name from /etc/passwd content.
pub fn parse_passwd(s: &str) -> HashMap<u32, String> {
    s.lines()
        .filter_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?;
            let _pw = it.next()?;
            let uid = it.next()?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

fn status_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|l| l.strip_prefix("Uid:")?.split_whitespace().next()?.parse().ok())
}

/// Process names whose loss takes down the modem, the data path, the LAN or this
/// UI. Matched against comm (≤15 chars, so prefixes).
const CRITICAL_COMM: &[&str] = &[
    "procd", "ubusd", "netifd", "rpcd", "logd", "QCMAP_", "netmgrd", "ipacm", "cellular_device", "cellcored",
    "dnsmasq", "odhcpd", "dropbear", "uhttpd", "ql_", "quectel", "qrtr", "rmt_storage", "qseecomd", "atfwd",
    "time_daemon", "servicemanager", "diag",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcGuard {
    None,
    Critical,
    Blocked,
}

pub fn guard_for(p: &ProcStat, self_pid: i32) -> ProcGuard {
    if p.pid <= 1 || p.is_kthread() || p.pid == self_pid {
        return ProcGuard::Blocked;
    }
    if CRITICAL_COMM.iter().any(|c| p.comm.starts_with(c)) {
        return ProcGuard::Critical;
    }
    ProcGuard::None
}

pub fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        _ => return None,
    })
}

struct Snapshot {
    procs: HashMap<i32, ProcStat>,
    cpu_total: u64,
}

fn snapshot() -> Snapshot {
    let mut procs = HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten().take(MAX_PROCS * 4) {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                && let Some(p) = parse_proc_stat(&s)
            {
                procs.insert(pid, p);
                if procs.len() >= MAX_PROCS {
                    break;
                }
            }
        }
    }
    let (cpu_total, _) = parse_cpu_total(&std::fs::read_to_string("/proc/stat").unwrap_or_default());
    Snapshot { procs, cpu_total }
}

fn cmdline(pid: i32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            let s: String = b[..b.len().min(512)]
                .split(|&c| c == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            s
        })
        .unwrap_or_default()
}

pub async fn get_processes() -> Response {
    let a = tokio::task::spawn_blocking(snapshot).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = tokio::task::spawn_blocking(snapshot).await;
    let (Ok(a), Ok(b)) = (a, b) else {
        return server("failed to read /proc");
    };
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_total_kb = parse_meminfo_kb(&meminfo, "MemTotal").unwrap_or(1).max(1);
    let mem_avail_kb = parse_meminfo_kb(&meminfo, "MemAvailable").unwrap_or(0);
    let (_, ncpu) = parse_cpu_total(&std::fs::read_to_string("/proc/stat").unwrap_or_default());
    let page_kb = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) / 1024) as i64;
    let users = parse_passwd(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
    let self_pid = std::process::id() as i32;
    let dt = b.cpu_total.saturating_sub(a.cpu_total).max(1) as f64;

    let mut rows: Vec<serde_json::Value> = b
        .procs
        .values()
        .map(|p| {
            let prev = a.procs.get(&p.pid).filter(|x| x.starttime == p.starttime);
            let used = prev.map(|x| (p.utime + p.stime).saturating_sub(x.utime + x.stime)).unwrap_or(0);
            let cpu = (used as f64 / dt) * 100.0;
            let rss_kb = (p.rss_pages.max(0) * page_kb) as u64;
            let uid = std::fs::read_to_string(format!("/proc/{}/status", p.pid)).ok().and_then(|s| status_uid(&s));
            serde_json::json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.comm,
                "cmd": if p.is_kthread() { format!("[{}]", p.comm) } else { cmdline(p.pid) },
                "user": uid.map(|u| users.get(&u).cloned().unwrap_or_else(|| u.to_string())),
                "state": p.state.to_string(),
                "threads": p.threads,
                "cpu": (cpu * 10.0).round() / 10.0,
                "rssKb": rss_kb,
                "mem": ((rss_kb as f64 / mem_total_kb as f64) * 1000.0).round() / 10.0,
                "starttime": p.starttime,
                "kernel": p.is_kthread(),
                "guard": guard_for(p, self_pid),
            })
        })
        .collect();
    rows.sort_by(|x, y| {
        let cx = x["cpu"].as_f64().unwrap_or(0.0);
        let cy = y["cpu"].as_f64().unwrap_or(0.0);
        cy.partial_cmp(&cx)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| y["rssKb"].as_u64().cmp(&x["rssKb"].as_u64()))
    });
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    ok(serde_json::json!({
        "processes": rows,
        "cpus": ncpu,
        "memTotalKb": mem_total_kb,
        "memAvailableKb": mem_avail_kb,
        "load": load.split_whitespace().take(3).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
pub struct SignalReq {
    pid: i32,
    signal: String,
    starttime: u64,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_signal(State(ctx): State<HttpCtx>, Json(req): Json<SignalReq>) -> Response {
    let Some(sig) = signal_number(&req.signal) else {
        return bad("Unsupported signal");
    };
    if req.pid <= 1 {
        return forbidden("Refusing to signal PID 0/1");
    }
    let Some(p) = std::fs::read_to_string(format!("/proc/{}/stat", req.pid)).ok().and_then(|s| parse_proc_stat(&s)) else {
        return conflict("That process has already exited");
    };
    if p.starttime != req.starttime {
        return conflict("That PID now belongs to a different process; refresh the list");
    }
    match guard_for(&p, std::process::id() as i32) {
        ProcGuard::Blocked => return forbidden("Kernel threads, PID 1 and CellCore itself cannot be signalled"),
        ProcGuard::Critical => {
            if let Err(r) = require_confirm(
                req.confirm.as_deref(),
                &p.comm,
                &format!("{} is a platform-critical process; signalling it can drop the cellular link or this UI. Type its name to continue.", p.comm),
            ) {
                return r;
            }
        }
        ProcGuard::None => {}
    }
    // SAFETY: plain syscall with validated pid/signal; no memory is shared.
    let rc = unsafe { libc::kill(req.pid, sig) };
    if rc != 0 {
        return server(format!("kill failed: {}", std::io::Error::last_os_error()));
    }
    audit(&ctx, format!("signal {} -> pid {} ({})", req.signal, req.pid, p.comm));
    ok(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_proc_stat() {
        let p = parse_proc_stat(include_str!("fixtures/proc_pid_stat_user.txt")).unwrap();
        assert_eq!(p.pid, 2879);
        assert_eq!(p.comm, "QCMAP_Connectio");
        assert_eq!(p.state, 'S');
        assert_eq!(p.ppid, 1);
        assert_eq!(p.threads, 1);
        assert_eq!(p.starttime, 1771);
        assert_eq!(p.vsize, 2_846_720);
        assert_eq!(p.rss_pages, 200);
        assert!(!p.is_kthread());
        assert_eq!(guard_for(&p, 999), ProcGuard::Critical);

        let k = parse_proc_stat(include_str!("fixtures/proc_pid_stat_kthread.txt")).unwrap();
        assert_eq!(k.comm, "kthreadd");
        assert!(k.is_kthread());
        assert_eq!(guard_for(&k, 999), ProcGuard::Blocked);
    }

    #[test]
    fn comm_with_parens_and_spaces() {
        let s = "42 (a (b) c) R 1 42 42 0 -1 4194560 1 0 0 0 7 3 0 0 20 0 2 0 555 1000 10 0";
        let p = parse_proc_stat(s).unwrap();
        assert_eq!(p.comm, "a (b) c");
        assert_eq!(p.utime, 7);
        assert_eq!(p.stime, 3);
        assert_eq!(p.starttime, 555);
        assert_eq!(guard_for(&p, 999), ProcGuard::None);
        assert_eq!(guard_for(&p, 42), ProcGuard::Blocked);
        assert!(parse_proc_stat("garbage").is_none());
    }

    #[test]
    fn parses_cpu_and_meminfo() {
        let (total, cpus) = parse_cpu_total(include_str!("fixtures/proc_stat.txt"));
        assert!(total > 0);
        assert_eq!(cpus, 4);
        let mi = include_str!("fixtures/meminfo.txt");
        assert!(parse_meminfo_kb(mi, "MemTotal").unwrap() > 500_000);
        assert!(parse_meminfo_kb(mi, "MemAvailable").is_some());
        assert!(parse_meminfo_kb(mi, "Nope").is_none());
    }

    #[test]
    fn passwd_and_signals() {
        let m = parse_passwd("root:x:0:0:root:/root:/bin/ash\nntp:x:123:123:ntp:/var/run/ntp:/bin/false\n");
        assert_eq!(m.get(&0).map(String::as_str), Some("root"));
        assert_eq!(m.get(&123).map(String::as_str), Some("ntp"));
        assert_eq!(signal_number("TERM"), Some(libc::SIGTERM));
        assert_eq!(signal_number("SEGV"), None);
        assert_eq!(signal_number("9"), None);
    }
}

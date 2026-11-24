//! Diagnostics › ping / traceroute / nslookup as async jobs whose output is
//! polled incrementally. Hosts are validated strictly (no shell, never a flag);
//! runtime, output size and concurrency are bounded.

use std::{
    collections::HashMap,
    process::Stdio,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path, Query},
    response::Response,
};
use serde::Deserialize;
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Semaphore, oneshot},
};

use super::{bad, conflict, fail, ok, server, validate::is_net_target};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_RUNTIME: Duration = Duration::from_secs(45);
const MAX_RUNNING: usize = 2;
const KEEP_JOBS: usize = 8;
const JOB_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReq {
    pub tool: String,
    pub host: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub server: Option<String>,
}

/// Build the argv for a diagnostic, or explain why not.
pub fn build_argv(r: &RunReq) -> Result<(String, Vec<String>), String> {
    let host = r.host.trim();
    if !is_net_target(host) {
        return Err("Enter a host name or IP address".into());
    }
    let v6 = match r.family.as_str() {
        "" | "auto" => host.contains(':'),
        "ipv4" if host.contains(':') => return Err("That is an IPv6 address".into()),
        "ipv4" => false,
        "ipv6" => true,
        _ => return Err("Family must be auto, ipv4 or ipv6".into()),
    };
    match r.tool.as_str() {
        "ping" => {
            let count = r.count.unwrap_or(4).clamp(1, 10);
            let prog = if v6 { "ping6" } else { "ping" };
            // `--`: the host is always an operand, never an option.
            Ok((prog.into(), vec!["-c".into(), count.to_string(), "-W".into(), "2".into(), "--".into(), host.into()]))
        }
        "traceroute" => {
            let prog = if v6 { "traceroute6" } else { "traceroute" };
            Ok((prog.into(), vec!["-n".into(), "-w".into(), "2".into(), "-q".into(), "1".into(), "-m".into(), "20".into(), "--".into(), host.into()]))
        }
        "nslookup" => {
            let mut a = vec![host.to_string()];
            if let Some(s) = r.server.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                if !is_net_target(s) {
                    return Err("DNS server must be a host name or IP address".into());
                }
                a.push(s.to_string());
            }
            Ok(("nslookup".into(), a))
        }
        _ => Err("Tool must be ping, traceroute or nslookup".into()),
    }
}

fn resolve(prog: &str) -> String {
    #[cfg(test)]
    {
        let mapped = crate::paths::program(prog);
        if std::path::Path::new(&mapped).is_file() {
            return mapped;
        }
    }
    for dir in ["/bin", "/usr/bin", "/sbin", "/usr/sbin"] {
        let p = format!("{dir}/{prog}");
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }
    prog.to_string()
}

struct Job {
    tool: String,
    host: String,
    started: Instant,
    output: Vec<u8>,
    truncated: bool,
    done: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    cancelled: bool,
    cancel: Option<oneshot::Sender<()>>,
}

type Jobs = Mutex<HashMap<u64, Arc<Mutex<Job>>>>;
static JOBS: OnceLock<Jobs> = OnceLock::new();
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
/// Independent process-slot semaphore so deleting a job record can never bypass
/// `MAX_RUNNING`: a permit is held until the child process actually exits or is
/// killed and reaped.
static ACTIVE_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn jobs() -> &'static Jobs {
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn active_slots() -> &'static Arc<Semaphore> {
    ACTIVE_SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_RUNNING)))
}

fn prune(map: &mut HashMap<u64, Arc<Mutex<Job>>>) {
    map.retain(|_, j| j.lock().map(|j| !(j.done && j.started.elapsed() > JOB_TTL)).unwrap_or(false));
    while map.len() > KEEP_JOBS {
        let oldest_done = map
            .iter()
            .filter(|(_, j)| j.lock().map(|j| j.done).unwrap_or(true))
            .min_by_key(|(id, _)| **id)
            .map(|(id, _)| *id);
        match oldest_done {
            Some(id) => {
                map.remove(&id);
            }
            None => break,
        }
    }
}

pub async fn post_run(Json(req): Json<RunReq>) -> Response {
    let (prog, args) = match build_argv(&req) {
        Ok(x) => x,
        Err(e) => return bad(e),
    };
    let Ok(permit) = active_slots().clone().try_acquire_owned() else {
        return conflict("Two diagnostics are already running; wait for one to finish");
    };
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let job = Arc::new(Mutex::new(Job {
        tool: req.tool.clone(),
        host: req.host.trim().to_string(),
        started: Instant::now(),
        output: Vec::new(),
        truncated: false,
        done: false,
        exit_code: None,
        timed_out: false,
        cancelled: false,
        cancel: Some(cancel_tx),
    }));
    let id = {
        let Ok(mut map) = jobs().lock() else { return server("lock poisoned") };
        prune(&mut map);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        map.insert(id, Arc::clone(&job));
        id
    };

    let mut cmd = Command::new(resolve(&prog));
    cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = {
        let mut attempt = 0u8;
        loop {
            match cmd.spawn() {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 5 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    if let Ok(mut j) = job.lock() {
                        j.done = true;
                        j.cancel = None;
                        j.output = format!("failed to start {prog}: {e}").into_bytes();
                    }
                    drop(permit);
                    return server(format!("failed to start {prog}"));
                }
            }
        }
    };
    let pump = |mut r: Box<dyn tokio::io::AsyncRead + Unpin + Send>, job: Arc<Mutex<Job>>| async move {
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut j) = job.lock() {
                        let room = MAX_OUTPUT.saturating_sub(j.output.len());
                        let take = n.min(room);
                        j.output.extend_from_slice(&buf[..take]);
                        if take < n {
                            j.truncated = true;
                        }
                    }
                }
            }
        }
    };
    let so = child.stdout.take().map(|s| tokio::spawn(pump(Box::new(s), Arc::clone(&job))));
    let se = child.stderr.take().map(|s| tokio::spawn(pump(Box::new(s), Arc::clone(&job))));
    let job2 = Arc::clone(&job);
    tokio::spawn(async move {
        let _permit = permit;
        let (code, timed_out, cancelled) = tokio::select! {
            res = tokio::time::timeout(MAX_RUNTIME, child.wait()) => {
                match res {
                    Ok(Ok(st)) => (st.code(), false, false),
                    Ok(Err(_)) => (None, false, false),
                    Err(_) => {
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        (None, true, false)
                    }
                }
            }
            _ = cancel_rx => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                (None, false, true)
            }
        };
        for h in [so, se].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
        }
        if let Ok(mut j) = job2.lock() {
            j.done = true;
            j.exit_code = code;
            j.timed_out = timed_out;
            j.cancelled |= cancelled;
            j.cancel = None;
        }
        // `_permit` is dropped here only after the child is dead and reaped.
    });
    ok(serde_json::json!({ "id": id, "argv": std::iter::once(prog).chain(args).collect::<Vec<_>>() }))
}

#[derive(Deserialize)]
pub struct OffsetQ {
    #[serde(default)]
    offset: usize,
}

pub async fn get_job(Path(id): Path<u64>, Query(q): Query<OffsetQ>) -> Response {
    let job = jobs().lock().ok().and_then(|m| m.get(&id).cloned());
    let Some(job) = job else {
        return fail(axum::http::StatusCode::NOT_FOUND, "No such job");
    };
    let Ok(j) = job.lock() else { return server("lock poisoned") };
    let start = q.offset.min(j.output.len());
    ok(serde_json::json!({
        "id": id,
        "tool": j.tool,
        "host": j.host,
        "chunk": String::from_utf8_lossy(&j.output[start..]),
        "offset": j.output.len(),
        "done": j.done,
        "exitCode": j.exit_code,
        "timedOut": j.timed_out,
        "cancelled": j.cancelled,
        "truncated": j.truncated,
        "elapsedMs": j.started.elapsed().as_millis() as u64,
    }))
}

/// Remove a job record and immediately kill any still-running child process.
/// The concurrency slot stays held until the child is actually reaped.
pub async fn delete_job(Path(id): Path<u64>) -> Response {
    let removed = jobs().lock().ok().and_then(|mut m| m.remove(&id));
    if let Some(job) = removed
        && let Ok(mut j) = job.lock()
        && let Some(tx) = j.cancel.take()
    {
        j.cancelled = true;
        let _ = tx.send(());
    }
    ok(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tool: &str, host: &str, family: &str) -> RunReq {
        RunReq { tool: tool.into(), host: host.into(), family: family.into(), count: None, server: None }
    }

    #[test]
    fn builds_bounded_argv() {
        let (p, a) = build_argv(&req("ping", "1.1.1.1", "")).unwrap();
        assert_eq!(p, "ping");
        assert_eq!(a, vec!["-c", "4", "-W", "2", "--", "1.1.1.1"]);
        let (p, _) = build_argv(&req("ping", "2001:4860:4860::8888", "")).unwrap();
        assert_eq!(p, "ping6");
        let (p, a) = build_argv(&req("traceroute", "example.com", "ipv6")).unwrap();
        assert_eq!(p, "traceroute6");
        assert!(a.contains(&"-m".to_string()));
        let mut many = req("ping", "example.com", "");
        many.count = Some(10_000);
        assert_eq!(build_argv(&many).unwrap().1[1], "10");
        let mut ns = req("nslookup", "example.com", "");
        ns.server = Some("9.9.9.9".into());
        assert_eq!(build_argv(&ns).unwrap().1, vec!["example.com", "9.9.9.9"]);
    }

    #[test]
    fn rejects_injection_and_flags() {
        for h in ["-f", "--help", "1.1.1.1 -s 65000", "$(id)", "a;b", "a|b", "", "x\ny"] {
            assert!(build_argv(&req("ping", h, "")).is_err(), "{h:?}");
        }
        assert!(build_argv(&req("rm", "1.1.1.1", "")).is_err());
        assert!(build_argv(&req("ping", "::1", "ipv4")).is_err());
        assert!(build_argv(&req("ping", "1.1.1.1", "ipx")).is_err());
        let mut ns = req("nslookup", "example.com", "");
        ns.server = Some("-port=1".into());
        assert!(build_argv(&ns).is_err());
    }

    fn pid_alive(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'),
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn deleting_running_job_kills_child_and_enforces_process_cap() {
        let env = crate::paths::TestSandbox::new("diag-cap");
        let pids_file = env.root.join("pids");
        env.write_exec(
            "/bin/ping",
            &format!("#!/bin/sh\necho $$ >> {}\nexec sleep 30\n", pids_file.display()),
        );

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let r1 = post_run(Json(req("ping", "1.1.1.1", "ipv4"))).await;
                assert_eq!(r1.status(), axum::http::StatusCode::OK);
                let b1: serde_json::Value =
                    serde_json::from_slice(&axum::body::to_bytes(r1.into_body(), 4096).await.unwrap()).unwrap();
                let id1 = b1["id"].as_u64().unwrap();

                let r2 = post_run(Json(req("ping", "1.0.0.1", "ipv4"))).await;
                assert_eq!(r2.status(), axum::http::StatusCode::OK);
                let b2: serde_json::Value =
                    serde_json::from_slice(&axum::body::to_bytes(r2.into_body(), 4096).await.unwrap()).unwrap();
                let id2 = b2["id"].as_u64().unwrap();

                // Cap reached: 3rd job must be rejected with 409 Conflict.
                let r3 = post_run(Json(req("ping", "8.8.8.8", "ipv4"))).await;
                assert_eq!(r3.status(), axum::http::StatusCode::CONFLICT);
                assert_eq!(active_slots().available_permits(), 0);

                // Wait until both mock children have recorded their PIDs.
                let mut pids = Vec::new();
                for _ in 0..100 {
                    if let Ok(s) = std::fs::read_to_string(&pids_file) {
                        pids = s.lines().filter_map(|l| l.trim().parse::<u32>().ok()).collect();
                        if pids.len() >= 2 {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(pids.len(), 2, "expected 2 spawned child PIDs");

                // Simulate direct map removal without killing (the old bypass): the independent
                // semaphore MUST still block spawning a 3rd child while both processes live.
                let saved1 = jobs().lock().unwrap().remove(&id1).unwrap();
                let r_bypass = post_run(Json(req("ping", "8.8.4.4", "ipv4"))).await;
                assert_eq!(r_bypass.status(), axum::http::StatusCode::CONFLICT);
                jobs().lock().unwrap().insert(id1, saved1);

                // Deleting both running jobs must kill and reap their child processes and
                // release both semaphore permits.
                assert_eq!(delete_job(Path(id1)).await.status(), axum::http::StatusCode::OK);
                assert_eq!(delete_job(Path(id2)).await.status(), axum::http::StatusCode::OK);

                for _ in 0..100 {
                    if active_slots().available_permits() == MAX_RUNNING && pids.iter().all(|&p| !pid_alive(p)) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(active_slots().available_permits(), MAX_RUNNING);
                for p in pids {
                    assert!(!pid_alive(p), "child pid {p} was not killed on delete_job");
                }
            })
            .await;
    }
}

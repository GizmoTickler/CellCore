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
use tokio::{io::AsyncReadExt, process::Command};

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
}

type Jobs = Mutex<HashMap<u64, Arc<Mutex<Job>>>>;
static JOBS: OnceLock<Jobs> = OnceLock::new();
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn jobs() -> &'static Jobs {
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
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
    let job = Arc::new(Mutex::new(Job {
        tool: req.tool.clone(),
        host: req.host.trim().to_string(),
        started: Instant::now(),
        output: Vec::new(),
        truncated: false,
        done: false,
        exit_code: None,
        timed_out: false,
    }));
    let id = {
        let Ok(mut map) = jobs().lock() else { return server("lock poisoned") };
        prune(&mut map);
        let running = map.values().filter(|j| j.lock().map(|j| !j.done).unwrap_or(false)).count();
        if running >= MAX_RUNNING {
            return conflict("Two diagnostics are already running; wait for one to finish");
        }
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        map.insert(id, Arc::clone(&job));
        id
    };

    let mut cmd = Command::new(resolve(&prog));
    cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Ok(mut j) = job.lock() {
                j.done = true;
                j.output = format!("failed to start {prog}: {e}").into_bytes();
            }
            return server(format!("failed to start {prog}"));
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
        let res = tokio::time::timeout(MAX_RUNTIME, child.wait()).await;
        let (code, timed_out) = match res {
            Ok(Ok(st)) => (st.code(), false),
            Ok(Err(_)) => (None, false),
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                (None, true)
            }
        };
        for h in [so, se].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
        }
        if let Ok(mut j) = job2.lock() {
            j.done = true;
            j.exit_code = code;
            j.timed_out = timed_out;
        }
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
        "truncated": j.truncated,
        "elapsedMs": j.started.elapsed().as_millis() as u64,
    }))
}

/// Forget a job's output. A still-running process keeps its runtime bound and
/// is reaped by its waiter task.
pub async fn delete_job(Path(id): Path<u64>) -> Response {
    if let Ok(mut m) = jobs().lock() {
        m.remove(&id);
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
}

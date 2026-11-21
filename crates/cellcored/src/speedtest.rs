use std::{
    process::Stdio,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use crate::{
    auth::now_secs,
    state::{AppState, SpeedtestLiveState, SpeedtestRun, SpeedtestSample, format_now_hms, save_json_atomic},
};

pub const SPEEDTEST_HISTORY_PATH: &str = "/etc/cellcore/speedtest_history.json";
/// A full run normally takes 30-60 s; anything past this is hung.
pub const SPEEDTEST_MAX_RUNTIME: std::time::Duration = std::time::Duration::from_secs(180);
const STDERR_TAIL_BYTES: usize = 2048;

/// Read a pipe to EOF keeping only the last `max` bytes, so the child can
/// never block on a full stderr pipe.
pub async fn drain_tail<R: tokio::io::AsyncRead + Unpin>(mut r: R, max: usize) -> String {
    use tokio::io::AsyncReadExt;
    let mut tail: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > max {
                    let cut = tail.len() - max;
                    tail.drain(..cut);
                }
            }
        }
    }
    String::from_utf8_lossy(&tail).trim().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedtestServerOption {
    pub id: i64,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub location: String,
    pub country: String,
}

pub fn compute_bufferbloat_grade(
    idle_ping: Option<f64>,
    dl_iqm: Option<f64>,
    ul_iqm: Option<f64>,
) -> String {
    let Some(idle) = idle_ping.filter(|&v| v > 0.0 && v.is_finite()) else {
        return "--".into();
    };
    let dl_delta = dl_iqm.map(|v| (v - idle).max(0.0)).unwrap_or(0.0);
    let ul_delta = ul_iqm.map(|v| (v - idle).max(0.0)).unwrap_or(0.0);
    let worst = dl_delta.max(ul_delta);
    if worst < 5.0 {
        "A+".into()
    } else if worst < 15.0 {
        "A".into()
    } else if worst < 30.0 {
        "B".into()
    } else if worst < 60.0 {
        "C".into()
    } else if worst < 150.0 {
        "D".into()
    } else {
        "F".into()
    }
}

pub async fn list_nearby_servers() -> Result<Vec<SpeedtestServerOption>, String> {
    let child = Command::new(crate::paths::p("/usr/bin/speedtest"))
        .env("HOME", crate::paths::p("/tmp/cellcore"))
        .args(["--accept-license", "--accept-gdpr", "-f", "json", "-L"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to launch speedtest: {e}"))?;

    let out = tokio::time::timeout(Duration::from_secs(12), child.wait_with_output())
        .await
        .map_err(|_| "Timed out listing speedtest servers".to_string())?
        .map_err(|e| format!("Speedtest wait failed: {e}"))?;

    if !out.status.success() {
        return Err("Speedtest server discovery failed".into());
    }
    let val: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("Invalid server list JSON: {e}"))?;
    let mut servers = Vec::new();
    if let Some(arr) = val.get("servers").and_then(|v| v.as_array()) {
        for s in arr.iter().take(15) {
            servers.push(SpeedtestServerOption {
                id: s.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                host: s.get("host").and_then(|v| v.as_str()).unwrap_or("").into(),
                port: s.get("port").and_then(|v| v.as_u64()).unwrap_or(8080) as u16,
                name: s.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown").into(),
                location: s.get("location").and_then(|v| v.as_str()).unwrap_or("").into(),
                country: s.get("country").and_then(|v| v.as_str()).unwrap_or("").into(),
            });
        }
    }
    Ok(servers)
}

const SERVER_LIST_TTL: Duration = Duration::from_secs(600);
const SERVER_LIST_ERR_TTL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct ServerListCacheState {
    ok: Option<(Instant, Vec<SpeedtestServerOption>)>,
    last_err: Option<(Instant, String)>,
}

type ServerListCache = Mutex<ServerListCacheState>;
static SERVER_LIST_CACHE: OnceLock<ServerListCache> = OnceLock::new();
static SERVER_LIST_FLIGHT: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn server_cache() -> &'static ServerListCache {
    SERVER_LIST_CACHE.get_or_init(|| Mutex::new(ServerListCacheState::default()))
}

/// Return cached nearby Ookla servers within `SERVER_LIST_TTL`, collapsing
/// concurrent cache misses onto one `speedtest -L` subprocess and falling back
/// to stale data (or an empty list) with a warning string on transient failure.
pub async fn list_nearby_servers_cached() -> (Vec<SpeedtestServerOption>, Option<String>) {
    if let Ok(g) = server_cache().lock() {
        if let Some((ts, list)) = g.ok.as_ref()
            && ts.elapsed() < SERVER_LIST_TTL
        {
            return (list.clone(), None);
        }
        if let Some((ts, msg)) = g.last_err.as_ref()
            && ts.elapsed() < SERVER_LIST_ERR_TTL
        {
            let stale = g.ok.as_ref().map(|(_, list)| list.clone()).unwrap_or_default();
            return (stale, Some(msg.clone()));
        }
    }
    let _flight = SERVER_LIST_FLIGHT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    if let Ok(g) = server_cache().lock() {
        if let Some((ts, list)) = g.ok.as_ref()
            && ts.elapsed() < SERVER_LIST_TTL
        {
            return (list.clone(), None);
        }
        if let Some((ts, msg)) = g.last_err.as_ref()
            && ts.elapsed() < SERVER_LIST_ERR_TTL
        {
            let stale = g.ok.as_ref().map(|(_, list)| list.clone()).unwrap_or_default();
            return (stale, Some(msg.clone()));
        }
    }
    match list_nearby_servers().await {
        Ok(servers) => {
            if let Ok(mut g) = server_cache().lock() {
                g.ok = Some((Instant::now(), servers.clone()));
                g.last_err = None;
            }
            (servers, None)
        }
        Err(e) => {
            let stale = if let Ok(mut g) = server_cache().lock() {
                g.last_err = Some((Instant::now(), e.clone()));
                g.ok.as_ref().map(|(_, list)| list.clone()).unwrap_or_default()
            } else {
                Vec::new()
            };
            (stale, Some(e))
        }
    }
}

fn build_speedtest_args(server_id: Option<i64>) -> Vec<String> {
    let mut args = vec![
        "--accept-license".to_string(),
        "--accept-gdpr".to_string(),
        "-f".to_string(),
        "json".to_string(),
        "-p".to_string(),
        "yes".to_string(),
        "--progress-update-interval=100".to_string(),
    ];
    if let Some(id) = server_id.filter(|&x| x > 0) {
        args.push("--server-id".into());
        args.push(id.to_string());
    }
    // Measure the cellular link, not the WARP tunnel, while WARP steers
    // modem traffic (no-op otherwise).
    if let Some(dev) = crate::vpn::bypass_iface() {
        args.push(format!("--interface={dev}"));
    }
    args
}

fn pick_retry_server_id() -> Option<i64> {
    let g = server_cache().lock().ok()?;
    let (_, list) = g.ok.as_ref()?;
    list.get(1)
        .or_else(|| list.first())
        .map(|s| s.id)
        .filter(|&id| id > 0)
}

fn spawn_speedtest_child(bin: &str, home: &str, args: &[String]) -> Result<tokio::process::Child, String> {
    Command::new(bin)
        .env("HOME", home)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to start speedtest binary: {e}"))
}

async fn finish_speedtest_slot(state: &AppState) {
    let mut pid_guard = state.speedtest_pid.lock().await;
    *pid_guard = None;
}

pub async fn start_speedtest(state: AppState, server_id: Option<i64>) -> Result<(), String> {
    let mut pid_guard = state.speedtest_pid.lock().await;
    if pid_guard.is_some() {
        return Err("Speedtest is already running".into());
    }

    let bin_path = crate::paths::p("/usr/bin/speedtest");
    let home_path = crate::paths::p("/tmp/cellcore");
    let hist_path = crate::paths::p(SPEEDTEST_HISTORY_PATH);

    let first_args = build_speedtest_args(server_id);
    let first_child = spawn_speedtest_child(&bin_path, &home_path, &first_args)?;

    let child_pid = first_child.id().unwrap_or(0);
    *pid_guard = Some(child_pid);
    drop(pid_guard);

    {
        let mut live = state.speedtest_live.write().await;
        *live = SpeedtestLiveState {
            running: true,
            phase: "starting".into(),
            progress: 4,
            ..Default::default()
        };
        broadcast_speedtest(&state, &live);
    }

    let max_attempts: usize = if server_id.is_none() { 2 } else { 1 };
    let attempt_timeout = if max_attempts > 1 {
        Duration::from_secs(90)
    } else {
        SPEEDTEST_MAX_RUNTIME
    };

    tokio::spawn(async move {
        let mut child_opt = Some(first_child);
        for attempt in 1..=max_attempts {
            let mut child = match child_opt.take() {
                Some(c) => c,
                None => {
                    let retry_args = build_speedtest_args(pick_retry_server_id());
                    match spawn_speedtest_child(&bin_path, &home_path, &retry_args) {
                        Ok(c) => {
                            let new_pid = c.id().unwrap_or(0);
                            let mut pid_guard = state.speedtest_pid.lock().await;
                            if pid_guard.is_none() {
                                return;
                            }
                            *pid_guard = Some(new_pid);
                            drop(pid_guard);
                            let mut live = state.speedtest_live.write().await;
                            if !live.running || live.phase == "stopped" {
                                finish_speedtest_slot(&state).await;
                                return;
                            }
                            live.phase = "starting".into();
                            live.progress = 4;
                            broadcast_speedtest(&state, &live);
                            c
                        }
                        Err(msg) => {
                            finish_speedtest_slot(&state).await;
                            let mut live = state.speedtest_live.write().await;
                            if live.running {
                                live.running = false;
                                if live.phase != "stopped" {
                                    live.phase = "error".into();
                                    live.error = Some(msg);
                                }
                                broadcast_speedtest(&state, &live);
                            }
                            return;
                        }
                    }
                }
            };

            let stdout = child.stdout.take();
            let stderr_task = child.stderr.take().map(|e| tokio::spawn(drain_tail(e, STDERR_TAIL_BYTES)));
            let mut last_dl_iqm: Option<f64> = None;
            let mut last_ul_iqm: Option<f64> = None;

            let reading = async {
                if let Some(out) = stdout {
                    let mut reader = BufReader::new(out).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        let trimmed = line.trim();
                        if !trimmed.starts_with('{') {
                            continue;
                        }
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                            continue;
                        };
                        let ev = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
                        let mut live = state.speedtest_live.write().await;
                        let now_ms = now_secs() * 1000;
                        match ev {
                            "testStart" => {
                                live.phase = "ping".into();
                                live.progress = 8;
                                live.isp = v.get("isp").and_then(|x| x.as_str()).map(|s| s.to_string());
                                if let Some(srv) = v.get("server") {
                                    live.server_name = srv.get("name").and_then(|x| x.as_str()).map(|s| s.to_string());
                                    live.server_location = srv.get("location").and_then(|x| x.as_str()).map(|s| s.to_string());
                                }
                            }
                            "ping" => {
                                live.phase = "ping".into();
                                if let Some(p) = v.get("ping") {
                                    live.ping_ms = p.get("latency").and_then(|x| x.as_f64()).map(round2);
                                    live.jitter_ms = p.get("jitter").and_then(|x| x.as_f64()).map(round2);
                                    let prog = p.get("progress").and_then(|x| x.as_f64()).unwrap_or(0.0);
                                    live.progress = (prog * 20.0).round().clamp(5.0, 20.0) as u8;
                                }
                            }
                            "download" => {
                                live.phase = "download".into();
                                if let Some(d) = v.get("download") {
                                    let bw = d.get("bandwidth").and_then(|x| x.as_f64()).unwrap_or(0.0);
                                    let mbps = round2((bw * 8.0) / 1_000_000.0);
                                    live.download_mbps = Some(mbps);
                                    if let Some(iqm) = d.get("latency").and_then(|l| l.get("iqm")).and_then(|x| x.as_f64()) {
                                        let rounded = round2(iqm);
                                        live.dl_latency_iqm = Some(rounded);
                                        last_dl_iqm = Some(rounded);
                                    }
                                    let prog = d.get("progress").and_then(|x| x.as_f64()).unwrap_or(0.0);
                                    live.progress = 20 + (prog * 40.0).round().clamp(0.0, 40.0) as u8;
                                    let dl_iqm_copy = live.dl_latency_iqm;
                                    live.samples.push(SpeedtestSample {
                                        ts: now_ms,
                                        phase: "download".into(),
                                        mbps,
                                        latency_iqm: dl_iqm_copy,
                                    });
                                    if live.samples.len() > 160 {
                                        live.samples.remove(0);
                                    }
                                }
                            }
                            "upload" => {
                                live.phase = "upload".into();
                                if let Some(u) = v.get("upload") {
                                    let bw = u.get("bandwidth").and_then(|x| x.as_f64()).unwrap_or(0.0);
                                    let mbps = round2((bw * 8.0) / 1_000_000.0);
                                    live.upload_mbps = Some(mbps);
                                    if let Some(iqm) = u.get("latency").and_then(|l| l.get("iqm")).and_then(|x| x.as_f64()) {
                                        let rounded = round2(iqm);
                                        live.ul_latency_iqm = Some(rounded);
                                        last_ul_iqm = Some(rounded);
                                    }
                                    let prog = u.get("progress").and_then(|x| x.as_f64()).unwrap_or(0.0);
                                    live.progress = 60 + (prog * 40.0).round().clamp(0.0, 40.0) as u8;
                                    let ul_iqm_copy = live.ul_latency_iqm;
                                    live.samples.push(SpeedtestSample {
                                        ts: now_ms,
                                        phase: "upload".into(),
                                        mbps,
                                        latency_iqm: ul_iqm_copy,
                                    });
                                    if live.samples.len() > 160 {
                                        live.samples.remove(0);
                                    }
                                }
                            }
                            "result" => {
                                let ping_ms = v.get("ping").and_then(|p| p.get("latency")).and_then(|x| x.as_f64()).map(round2);
                                let jitter_ms = v.get("ping").and_then(|p| p.get("jitter")).and_then(|x| x.as_f64()).map(round2);
                                let dl_mbps = v
                                    .get("download")
                                    .and_then(|d| d.get("bandwidth"))
                                    .and_then(|x| x.as_f64())
                                    .map(|bw| round2((bw * 8.0) / 1_000_000.0));
                                let ul_mbps = v
                                    .get("upload")
                                    .and_then(|u| u.get("bandwidth"))
                                    .and_then(|x| x.as_f64())
                                    .map(|bw| round2((bw * 8.0) / 1_000_000.0));
                                let dl_iqm = v
                                    .get("download")
                                    .and_then(|d| d.get("latency"))
                                    .and_then(|l| l.get("iqm"))
                                    .and_then(|x| x.as_f64())
                                    .map(round2)
                                    .or(last_dl_iqm);
                                let ul_iqm = v
                                    .get("upload")
                                    .and_then(|u| u.get("latency"))
                                    .and_then(|l| l.get("iqm"))
                                    .and_then(|x| x.as_f64())
                                    .map(round2)
                                    .or(last_ul_iqm);
                                let grade = compute_bufferbloat_grade(ping_ms, dl_iqm, ul_iqm);

                                live.running = false;
                                live.phase = "complete".into();
                                live.progress = 100;
                                live.ping_ms = ping_ms;
                                live.jitter_ms = jitter_ms;
                                live.download_mbps = dl_mbps;
                                live.upload_mbps = ul_mbps;
                                live.dl_latency_iqm = dl_iqm;
                                live.ul_latency_iqm = ul_iqm;
                                live.bufferbloat_grade = Some(grade.clone());
                                live.packet_loss = v.get("packetLoss").and_then(|x| x.as_f64()).map(round2);
                                live.isp = v
                                    .get("isp")
                                    .and_then(|x| x.as_str())
                                    .or_else(|| v.get("server").and_then(|s| s.get("isp")).and_then(|x| x.as_str()))
                                    .map(|s| s.to_string())
                                    .or_else(|| live.isp.clone());
                                live.server_name = v
                                    .get("server")
                                    .and_then(|s| s.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string())
                                    .or_else(|| live.server_name.clone());
                                live.server_location = v
                                    .get("server")
                                    .and_then(|s| s.get("location"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string())
                                    .or_else(|| live.server_location.clone());
                                live.external_ip = v
                                    .get("interface")
                                    .and_then(|i| i.get("externalIp"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                live.result_url = v
                                    .get("result")
                                    .and_then(|r| r.get("url"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());

                                let ts = now_secs();
                                let run = SpeedtestRun {
                                    id: format!("st-{ts}"),
                                    timestamp: format_now_hms(),
                                    ts,
                                    download_mbps: dl_mbps.unwrap_or(0.0),
                                    upload_mbps: ul_mbps.unwrap_or(0.0),
                                    ping_ms: ping_ms.unwrap_or(0.0),
                                    jitter_ms: jitter_ms.unwrap_or(0.0),
                                    packet_loss: live.packet_loss,
                                    dl_latency_iqm: dl_iqm,
                                    ul_latency_iqm: ul_iqm,
                                    bufferbloat_grade: grade,
                                    isp: live.isp.clone(),
                                    server_id: v.get("server").and_then(|s| s.get("id")).and_then(|x| x.as_i64()),
                                    server_name: live.server_name.clone(),
                                    server_location: live.server_location.clone(),
                                    external_ip: live.external_ip.clone(),
                                    result_url: live.result_url.clone(),
                                };
                                drop(live);
                                let mut hist = state.speedtest_history.write().await;
                                hist.insert(0, run);
                                hist.truncate(50);
                                let _ = save_json_atomic(&hist_path, &*hist, 0o600);
                                let live_after = state.speedtest_live.read().await;
                                broadcast_speedtest(&state, &live_after);
                                continue;
                            }
                            _ => {}
                        }
                        broadcast_speedtest(&state, &live);
                    }
                }
            };
            let timed_out = tokio::time::timeout(attempt_timeout, reading).await.is_err();
            if timed_out {
                let _ = child.start_kill();
            }

            let status = child.wait().await;
            let stderr_tail = match stderr_task {
                Some(t) => tokio::time::timeout(Duration::from_secs(2), t)
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or_default(),
                None => String::new(),
            };

            let completed_or_stopped = {
                let live = state.speedtest_live.read().await;
                let has_pid = state.speedtest_pid.lock().await.is_some();
                !live.running || live.phase == "stopped" || !has_pid
            };
            if completed_or_stopped {
                finish_speedtest_slot(&state).await;
                return;
            }

            let rate_limited = status.as_ref().ok().and_then(|st| st.code()) == Some(173)
                || stderr_tail.to_ascii_lowercase().contains("too many requests");
            if attempt < max_attempts && !rate_limited {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let still_active = {
                    let has_pid = state.speedtest_pid.lock().await.is_some();
                    let live = state.speedtest_live.read().await;
                    has_pid && live.running && live.phase != "stopped"
                };
                if still_active {
                    continue;
                }
                finish_speedtest_slot(&state).await;
                return;
            }

            finish_speedtest_slot(&state).await;
            let mut live = state.speedtest_live.write().await;
            if live.running {
                live.running = false;
                if live.phase != "stopped" {
                    live.phase = "error".into();
                    let mut msg = if timed_out {
                        format!("Speedtest timed out after {} s", attempt_timeout.as_secs())
                    } else {
                        match status {
                            Ok(st) => format!("Speedtest exited with code {:?}", st.code()),
                            Err(e) => format!("Speedtest failed: {e}"),
                        }
                    };
                    if let Some(last) = stderr_tail.lines().last().filter(|l| !l.trim().is_empty()) {
                        msg.push_str(&format!(": {}", last.trim()));
                    }
                    live.error = Some(msg);
                }
                broadcast_speedtest(&state, &live);
            }
            return;
        }
    });

    Ok(())
}

pub async fn stop_speedtest(state: &AppState) -> Result<(), String> {
    let pid_opt = {
        let mut guard = state.speedtest_pid.lock().await;
        guard.take()
    };
    if let Some(pid) = pid_opt
        && pid > 0
    {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    let mut live = state.speedtest_live.write().await;
    live.running = false;
    live.phase = "stopped".into();
    broadcast_speedtest(state, &live);
    Ok(())
}

fn broadcast_speedtest(state: &AppState, live: &SpeedtestLiveState) {
    if let Ok(payload) = serde_json::to_value(live) {
        let mut obj = payload;
        if let Some(map) = obj.as_object_mut() {
            map.insert("channel".into(), serde_json::Value::String("speedtest".into()));
        }
        state.broadcast_json(&obj);
    }
}

fn round2(n: f64) -> f64 {
    (n * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stderr_is_drained_so_a_chatty_child_cannot_block() {
        // 256 KiB on stderr is far beyond the pipe buffer: an undrained pipe
        // would block the child forever before it writes its stdout line.
        let mut child = Command::new("sh")
            .args(["-c", "head -c 262144 /dev/zero | tr '\\0' 'e' >&2; echo 'last error line' >&2; echo done"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let err = tokio::spawn(drain_tail(child.stderr.take().unwrap(), 64));
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await;
        assert_eq!(first.expect("child blocked on stderr").unwrap().as_deref(), Some("done"));
        let tail = err.await.unwrap();
        assert!(tail.ends_with("last error line") && tail.len() <= 64, "{tail:?}");
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn auto_speedtest_retries_once_on_transient_failure_while_explicit_server_does_not() {
        let env = crate::paths::TestSandbox::new("speedtest-retry");
        let counter = env.root.join("calls.cnt");
        std::fs::write(&counter, "0\n").unwrap();
        env.write_exec(
            "/usr/bin/speedtest",
            &format!(
                "#!/bin/sh\n\
                 cnt=$(cat {c})\n\
                 cnt=$((cnt + 1))\n\
                 printf '%s\\n' \"$cnt\" > {c}\n\
                 if [ \"$cnt\" -eq 1 ]; then\n\
                   echo 'Socket error' >&2\n\
                   exit 2\n\
                 fi\n\
                 printf '%s\\n' '{{\"type\":\"result\",\"ping\":{{\"latency\":12.0,\"jitter\":0.5}},\"download\":{{\"bandwidth\":12500000,\"latency\":{{\"iqm\":20.0}}}},\"upload\":{{\"bandwidth\":12500000,\"latency\":{{\"iqm\":18.0}}}},\"server\":{{\"id\":100,\"name\":\"TestSrv\",\"location\":\"City\"}}}}'\n",
                c = counter.display(),
            ),
        );

        let auth = crate::auth::AuthStore::new(env.root.join("sessions"));
        let app = AppState::for_tests(env.root.clone(), auth);

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // Explicit serverId must NOT retry on failure.
                start_speedtest(app.clone(), Some(999999999)).await.unwrap();
                for _ in 0..80 {
                    if !app.speedtest_live.read().await.running && app.speedtest_pid.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "1");
                assert_eq!(app.speedtest_live.read().await.phase, "error");
                assert!(app.speedtest_pid.lock().await.is_none());

                // Automatic selection (server_id: None) retries once after transient failure.
                std::fs::write(&counter, "0\n").unwrap();
                start_speedtest(app.clone(), None).await.unwrap();
                for _ in 0..160 {
                    if !app.speedtest_live.read().await.running && app.speedtest_pid.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "2");
                let live = app.speedtest_live.read().await.clone();
                assert_eq!(live.phase, "complete");
                assert!(!live.running);
                assert!(app.speedtest_pid.lock().await.is_none());
                let hist = app.speedtest_history.read().await;
                assert_eq!(hist.len(), 1);
                assert_eq!(hist[0].download_mbps, 100.0);
            })
            .await;
    }

    #[tokio::test]
    async fn auto_speedtest_does_not_retry_on_rate_limit_exit_173() {
        let env = crate::paths::TestSandbox::new("speedtest-ratelimit");
        let counter = env.root.join("calls.cnt");
        std::fs::write(&counter, "0\n").unwrap();
        env.write_exec(
            "/usr/bin/speedtest",
            &format!(
                "#!/bin/sh\n\
                 cnt=$(cat {c})\n\
                 cnt=$((cnt + 1))\n\
                 printf '%s\\n' \"$cnt\" > {c}\n\
                 echo 'Too many requests received.' >&2\n\
                 exit 173\n",
                c = counter.display(),
            ),
        );

        let auth = crate::auth::AuthStore::new(env.root.join("sessions"));
        let app = AppState::for_tests(env.root.clone(), auth);

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                start_speedtest(app.clone(), None).await.unwrap();
                for _ in 0..80 {
                    if !app.speedtest_live.read().await.running && app.speedtest_pid.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "1");
                let live = app.speedtest_live.read().await.clone();
                assert_eq!(live.phase, "error");
                assert!(!live.running);
                let err = live.error.unwrap_or_default();
                assert!(err.contains("173"), "{err}");
                assert!(err.contains("Too many requests"), "{err}");
                assert!(app.speedtest_pid.lock().await.is_none());
            })
            .await;
    }
}

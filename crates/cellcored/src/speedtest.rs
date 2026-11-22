use std::{
    net::SocketAddr,
    os::fd::AsRawFd,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    process::Command,
    sync::watch,
};

use crate::{
    auth::now_secs,
    state::{
        AppState, SpeedtestLiveState, SpeedtestRun, SpeedtestSample, format_now_hms,
        save_json_atomic_async,
    },
};

pub const SPEEDTEST_HISTORY_PATH: &str = "/etc/cellcore/speedtest_history.json";
/// A full run normally takes 30-60 s; anything past this is hung.
pub const SPEEDTEST_MAX_RUNTIME: std::time::Duration = std::time::Duration::from_secs(180);
const STDERR_TAIL_BYTES: usize = 2048;

const NATIVE_DEFAULT_HOST: &str = "speed.cloudflare.com";
const NATIVE_DEFAULT_PORT: u16 = 80;
const NATIVE_DL_STREAMS: usize = 8;
const NATIVE_UL_STREAMS: usize = 6;
const NATIVE_DL_CHUNK_BYTES: usize = 90_000_000;
const NATIVE_UL_CHUNK_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_DL_SECS: u64 = 10;
const NATIVE_UL_SECS: u64 = 8;
const NATIVE_WARMUP_SECS: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedtestEngine {
    #[default]
    Auto,
    Ookla,
    Native,
}

/// Read a pipe to EOF keeping only the last `max` bytes, so the child can
/// never block on a full stderr pipe.
pub async fn drain_tail<R: tokio::io::AsyncRead + Unpin>(mut r: R, max: usize) -> String {
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

/// Interquartile mean (IQM) of positive finite latency samples — robust against
/// single-packet spikes, matching Ookla/Cloudflare loaded-latency reporting.
pub fn compute_iqm(samples: &[f64]) -> Option<f64> {
    let mut vals: Vec<f64> = samples
        .iter()
        .copied()
        .filter(|v| v.is_finite() && *v > 0.0)
        .collect();
    if vals.is_empty() {
        return None;
    }
    vals.sort_by(|a, b| a.total_cmp(b));
    if vals.len() < 4 {
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        return Some(round2(mean));
    }
    let lo = vals.len() / 4;
    let hi = vals.len() - lo;
    let slice = &vals[lo..hi];
    let mean = slice.iter().sum::<f64>() / slice.len() as f64;
    Some(round2(mean))
}

/// Compute jitter as the mean absolute difference between consecutive RTT samples.
pub fn compute_jitter(samples: &[f64]) -> Option<f64> {
    if samples.len() < 2 {
        return Some(0.0);
    }
    let mut sum = 0.0;
    let mut count = 0usize;
    for w in samples.windows(2) {
        if w[0].is_finite() && w[1].is_finite() {
            sum += (w[1] - w[0]).abs();
            count += 1;
        }
    }
    (count > 0).then(|| round2(sum / count as f64))
}

/// Parse Cloudflare edge headers (`cf-meta-ip` and `cf-ray` PoP code) from a raw HTTP header block.
pub fn parse_cf_meta_headers(headers_text: &str) -> (Option<String>, Option<String>) {
    let mut ext_ip = None;
    let mut colo = None;
    for line in headers_text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "cf-meta-ip" && !val.is_empty() {
                ext_ip = Some(val.to_string());
            } else if key == "cf-ray"
                && let Some((_, pop)) = val.rsplit_once('-')
                && pop.len() == 3
                && pop.bytes().all(|b| b.is_ascii_alphabetic())
            {
                colo = Some(pop.to_ascii_uppercase());
            }
        }
    }
    (ext_ip, colo)
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
    *state.speedtest_pid.lock().await = None;
    *state.speedtest_cancel.lock().await = None;
}

#[cfg(test)]
pub async fn start_speedtest(state: AppState, server_id: Option<i64>) -> Result<(), String> {
    start_speedtest_with_engine(state, server_id, SpeedtestEngine::Auto).await
}

pub async fn start_speedtest_with_engine(
    state: AppState,
    server_id: Option<i64>,
    engine: SpeedtestEngine,
) -> Result<(), String> {
    let bin_path = crate::paths::p("/usr/bin/speedtest");
    let use_native = match engine {
        SpeedtestEngine::Native => true,
        SpeedtestEngine::Ookla => false,
        SpeedtestEngine::Auto => !Path::new(&bin_path).exists(),
    };
    if use_native {
        return start_native_speedtest(state, NATIVE_DEFAULT_HOST.to_string(), NATIVE_DEFAULT_PORT, None).await;
    }

    let mut pid_guard = state.speedtest_pid.lock().await;
    if pid_guard.is_some() {
        return Err("Speedtest is already running".into());
    }

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
            engine: Some("ookla".into()),
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
                                    engine: Some("ookla".into()),
                                };
                                drop(live);
                                let hist_snap = {
                                    let mut hist = state.speedtest_history.write().await;
                                    hist.insert(0, run);
                                    hist.truncate(50);
                                    hist.clone()
                                };
                                let _ = save_json_atomic_async(&hist_path, hist_snap, 0o600).await;
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

// ---------------------------------------------------------------------------
// Pure-Rust Native Multi-Stream Speedtest & Loaded Bufferbloat Engine
// ---------------------------------------------------------------------------

async fn connect_native_socket(
    addr: SocketAddr,
    bypass_dev: Option<&str>,
    rcvbuf: Option<i32>,
    sndbuf: Option<i32>,
) -> Result<TcpStream, String> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|e| format!("socket: {e}"))?;

    unsafe {
        if let Some(sz) = rcvbuf {
            let _ = libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&sz as *const i32) as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
        if let Some(sz) = sndbuf {
            let _ = libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&sz as *const i32) as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
        if let Some(dev) = bypass_dev {
            let mut ifname = dev.as_bytes().to_vec();
            ifname.push(0);
            let _ = libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname.as_ptr() as *const libc::c_void,
                ifname.len() as libc::socklen_t,
            );
        }
    }
    let stream = tokio::time::timeout(Duration::from_secs(5), sock.connect(addr))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn parse_http_status(headers: &str) -> u16 {
    headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

async fn read_http_headers(stream: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut tmp))
            .await
            .map_err(|_| "header timeout".to_string())?
            .map_err(|e| format!("header read: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF reading HTTP headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let hdr = String::from_utf8_lossy(&buf[..pos]).to_string();
            let rest = buf[pos + 4..].to_vec();
            return Ok((hdr, rest));
        }
        if buf.len() > 16384 {
            return Err("HTTP response headers too large".into());
        }
    }
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().ok();
        }
    }
    None
}

async fn probe_http_rtt(
    stream: &mut TcpStream,
    host: &str,
    meas_id: u64,
) -> Result<(f64, String), String> {
    let req = format!(
        "GET /__down?measId={meas_id}&bytes=0 HTTP/1.1\r\nHost: {host}\r\nReferer: https://speed.cloudflare.com/\r\nUser-Agent: CellCore-NativeSpeedtest/1.2\r\nConnection: keep-alive\r\n\r\n"
    );
    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(3), stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "probe write timeout".to_string())?
        .map_err(|e| format!("probe write: {e}"))?;
    let (hdr, rest) = read_http_headers(stream).await?;
    let rtt_ms = t0.elapsed().as_secs_f64() * 1000.0;
    if let Some(cl) = parse_content_length(&hdr)
        && cl > rest.len()
    {
        let mut rem = cl - rest.len();
        let mut sink = [0u8; 2048];
        while rem > 0 {
            let take = rem.min(sink.len());
            let n = stream.read(&mut sink[..take]).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            rem -= n;
        }
    }
    Ok((rtt_ms, hdr))
}

async fn native_dl_worker(
    addr: SocketAddr,
    host: String,
    meas_id: u64,
    bypass_dev: Option<String>,
    bytes_total: Arc<AtomicU64>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let req = format!(
        "GET /__down?measId={meas_id}&bytes={NATIVE_DL_CHUNK_BYTES} HTTP/1.1\r\nHost: {host}\r\nReferer: https://speed.cloudflare.com/\r\nUser-Agent: CellCore-NativeSpeedtest/1.2\r\nConnection: keep-alive\r\n\r\n"
    );
    let mut buf = vec![0u8; 256 * 1024];
    while !*stop_rx.borrow() {
        let Ok(mut stream) = connect_native_socket(addr, bypass_dev.as_deref(), Some(2 * 1024 * 1024), None).await else {
            tokio::time::sleep(Duration::from_millis(120)).await;
            continue;
        };
        while !*stop_rx.borrow() {
            if stream.write_all(req.as_bytes()).await.is_err() {
                break;
            }
            let Ok((hdr, rest)) = read_http_headers(&mut stream).await else {
                break;
            };
            let status = parse_http_status(&hdr);
            if status == 429 {
                tokio::time::sleep(Duration::from_millis(400)).await;
                break;
            }
            if !(200..300).contains(&status) {
                tokio::time::sleep(Duration::from_millis(250)).await;
                break;
            }
            let target = parse_content_length(&hdr).unwrap_or(NATIVE_DL_CHUNK_BYTES);
            let mut got = rest.len();
            bytes_total.fetch_add(got as u64, Ordering::Relaxed);
            let mut eof = false;
            while got < target && !*stop_rx.borrow() {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    res = stream.read(&mut buf) => {
                        match res {
                            Ok(0) | Err(_) => {
                                eof = true;
                                break;
                            }
                            Ok(n) => {
                                got += n;
                                bytes_total.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            if eof {
                break;
            }
        }
    }
}

static NATIVE_UL_PAYLOAD: OnceLock<Vec<u8>> = OnceLock::new();

fn native_ul_payload() -> &'static [u8] {
    NATIVE_UL_PAYLOAD.get_or_init(|| vec![0x5Au8; 128 * 1024])
}

#[cfg(target_os = "linux")]
fn read_tcp_bytes_acked(fd: std::os::fd::RawFd) -> Option<u64> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast::<libc::c_void>(),
            &mut len,
        )
    };
    let needed = std::mem::offset_of!(libc::tcp_info, tcpi_bytes_acked) + std::mem::size_of::<u64>();
    if rc == 0 && (len as usize) >= needed {
        Some(info.tcpi_bytes_acked)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn read_tcp_bytes_acked(_fd: std::os::fd::RawFd) -> Option<u64> {
    None
}

pub fn compute_probe_loss_pct(sent: u64, failed: u64) -> Option<f64> {
    if sent == 0 {
        return None;
    }
    Some(round2(((failed.min(sent) as f64) / (sent as f64)) * 100.0))
}

async fn native_ul_worker(
    addr: SocketAddr,
    host: String,
    meas_id: u64,
    bypass_dev: Option<String>,
    bytes_total: Arc<AtomicU64>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let header = format!(
        "POST /__up?measId={meas_id} HTTP/1.1\r\nHost: {host}\r\nReferer: https://speed.cloudflare.com/\r\nUser-Agent: CellCore-NativeSpeedtest/1.2\r\nContent-Type: application/octet-stream\r\nContent-Length: {NATIVE_UL_CHUNK_BYTES}\r\nConnection: keep-alive\r\n\r\n"
    );
    let payload = native_ul_payload();
    while !*stop_rx.borrow() {
        // Keep SO_SNDBUF bounded (128 KiB per stream) so cellular uploads don't
        // experience fake initial buffer-fill spikes followed by drain stalls.
        let Ok(mut stream) = connect_native_socket(addr, bypass_dev.as_deref(), None, Some(128 * 1024)).await else {
            tokio::time::sleep(Duration::from_millis(120)).await;
            continue;
        };
        let mut last_acked: u64 = 0;
        let mut use_tcp_info = read_tcp_bytes_acked(stream.as_raw_fd()).is_some();
        while !*stop_rx.borrow() {
            if stream.write_all(header.as_bytes()).await.is_err() {
                break;
            }
            let mut sent = 0usize;
            let mut failed = false;
            while sent < NATIVE_UL_CHUNK_BYTES && !*stop_rx.borrow() {
                let to_send = (NATIVE_UL_CHUNK_BYTES - sent).min(payload.len());
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    res = stream.write_all(&payload[..to_send]) => {
                        if res.is_err() {
                            failed = true;
                            break;
                        }
                        sent += to_send;
                        if use_tcp_info {
                            if let Some(acked) = read_tcp_bytes_acked(stream.as_raw_fd()) {
                                let delta = acked.saturating_sub(last_acked);
                                if delta > 0 {
                                    bytes_total.fetch_add(delta, Ordering::Relaxed);
                                    last_acked = acked;
                                }
                            } else {
                                use_tcp_info = false;
                                bytes_total.fetch_add(to_send as u64, Ordering::Relaxed);
                            }
                        } else {
                            bytes_total.fetch_add(to_send as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
            if use_tcp_info
                && let Some(acked) = read_tcp_bytes_acked(stream.as_raw_fd())
            {
                let delta = acked.saturating_sub(last_acked);
                if delta > 0 {
                    bytes_total.fetch_add(delta, Ordering::Relaxed);
                    last_acked = acked;
                }
            }
            if failed || *stop_rx.borrow() {
                break;
            }
            // Drain the short 200 OK response before reusing keep-alive socket.
            let Ok((hdr, rest)) = read_http_headers(&mut stream).await else {
                break;
            };
            let status = parse_http_status(&hdr);
            if status == 429 {
                tokio::time::sleep(Duration::from_millis(400)).await;
                break;
            }
            if let Some(cl) = parse_content_length(&hdr)
                && cl > rest.len()
            {
                let mut rem = cl - rest.len();
                let mut sink = [0u8; 512];
                while rem > 0 {
                    let n = stream.read(&mut sink).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    rem = rem.saturating_sub(n);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn native_loaded_ping_worker(
    addr: SocketAddr,
    host: String,
    meas_id: u64,
    bypass_dev: Option<String>,
    samples: Arc<Mutex<Vec<f64>>>,
    probes_sent: Arc<AtomicU64>,
    probes_failed: Arc<AtomicU64>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut stream_opt: Option<TcpStream> = None;
    while !*stop_rx.borrow() {
        if stream_opt.is_none() {
            stream_opt = connect_native_socket(addr, bypass_dev.as_deref(), None, None).await.ok();
        }
        probes_sent.fetch_add(1, Ordering::Relaxed);
        if let Some(s) = stream_opt.as_mut() {
            match probe_http_rtt(s, &host, meas_id).await {
                Ok((rtt, _)) => {
                    if let Ok(mut g) = samples.lock() {
                        g.push(rtt);
                    }
                }
                Err(_) => {
                    probes_failed.fetch_add(1, Ordering::Relaxed);
                    stream_opt = None;
                }
            }
        } else {
            probes_failed.fetch_add(1, Ordering::Relaxed);
        }
        tokio::select! {
            _ = stop_rx.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

#[derive(Clone, Copy)]
struct NativePhaseDurations {
    dl_secs: u64,
    ul_secs: u64,
    warmup_secs: f64,
}

impl Default for NativePhaseDurations {
    fn default() -> Self {
        Self {
            dl_secs: NATIVE_DL_SECS,
            ul_secs: NATIVE_UL_SECS,
            warmup_secs: NATIVE_WARMUP_SECS,
        }
    }
}

async fn start_native_speedtest(
    state: AppState,
    host: String,
    port: u16,
    custom_durations: Option<NativePhaseDurations>,
) -> Result<(), String> {
    let mut pid_guard = state.speedtest_pid.lock().await;
    if pid_guard.is_some() {
        return Err("Speedtest is already running".into());
    }
    let (cancel_tx, cancel_rx) = watch::channel(false);
    *pid_guard = Some(0);
    drop(pid_guard);
    *state.speedtest_cancel.lock().await = Some(cancel_tx);

    let hist_path = crate::paths::p(SPEEDTEST_HISTORY_PATH);
    let durs = custom_durations.unwrap_or_default();

    {
        let mut live = state.speedtest_live.write().await;
        *live = SpeedtestLiveState {
            running: true,
            phase: "starting".into(),
            progress: 4,
            engine: Some("native".into()),
            server_name: Some("Cloudflare Edge (Native Rust)".into()),
            isp: Some("Cloudflare Anycast".into()),
            ..Default::default()
        };
        broadcast_speedtest(&state, &live);
    }

    tokio::spawn(async move {
        let res = run_native_pipeline(&state, &host, port, &hist_path, durs, cancel_rx).await;
        finish_speedtest_slot(&state).await;
        if let Err(msg) = res {
            let mut live = state.speedtest_live.write().await;
            if live.running && live.phase != "stopped" {
                live.running = false;
                live.phase = "error".into();
                live.error = Some(msg);
                broadcast_speedtest(&state, &live);
            }
        }
    });

    Ok(())
}

async fn run_native_pipeline(
    state: &AppState,
    host: &str,
    port: u16,
    hist_path: &str,
    durs: NativePhaseDurations,
    cancel_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| format!("DNS lookup timed out for {host}"))?
    .map_err(|e| format!("DNS lookup failed for {host}: {e}"))?
    .collect();
    if addrs.is_empty() {
        return Err(format!("No IP address resolved for {host}"));
    }

    // Iterate all resolved SocketAddrs (IPv4 + IPv6) until one connects cleanly.
    let mut connected: Option<(SocketAddr, Option<String>, TcpStream)> = None;
    let mut last_err = format!("Failed to connect to {host}");
    for cand in addrs {
        let bypass_dev = if cand.ip().is_loopback() {
            None
        } else {
            crate::vpn::bypass_iface()
        };
        match connect_native_socket(cand, bypass_dev.as_deref(), None, None).await {
            Ok(stream) => {
                connected = Some((cand, bypass_dev, stream));
                break;
            }
            Err(e) => {
                last_err = format!("connect {cand}: {e}");
            }
        }
    }
    let (addr, bypass_dev, mut ping_stream) = connected.ok_or(last_err)?;

    // --- Phase 1: Idle Latency & Edge Discovery ---
    let meas_id = now_secs()
        .wrapping_mul(1_000_003)
        .wrapping_add(u64::from(std::process::id()));
    let mut idle_rtts: Vec<f64> = Vec::with_capacity(9);
    let mut ext_ip: Option<String> = None;
    let mut colo: Option<String> = None;
    let probes_sent = Arc::new(AtomicU64::new(0));
    let probes_failed = Arc::new(AtomicU64::new(0));

    for i in 0..10 {
        if *cancel_rx.borrow() {
            return Ok(());
        }
        if i == 0 {
            let (_rtt, hdr) = probe_http_rtt(&mut ping_stream, host, meas_id).await?;
            let (ip, c) = parse_cf_meta_headers(&hdr);
            ext_ip = ip;
            colo = c;
            let mut live = state.speedtest_live.write().await;
            live.phase = "ping".into();
            live.progress = 8;
            if let Some(pop) = colo.as_deref() {
                live.server_location = Some(format!("PoP {pop}"));
            }
            live.external_ip = ext_ip.clone();
            broadcast_speedtest(state, &live);
            continue;
        }
        probes_sent.fetch_add(1, Ordering::Relaxed);
        match probe_http_rtt(&mut ping_stream, host, meas_id).await {
            Ok((rtt, _hdr)) => {
                idle_rtts.push(rtt);
            }
            Err(_) => {
                probes_failed.fetch_add(1, Ordering::Relaxed);
                if let Ok(reconn) = connect_native_socket(addr, bypass_dev.as_deref(), None, None).await {
                    ping_stream = reconn;
                }
            }
        }
        let cur_ping = compute_iqm(&idle_rtts);
        let cur_jit = compute_jitter(&idle_rtts);
        let mut live = state.speedtest_live.write().await;
        live.phase = "ping".into();
        live.ping_ms = cur_ping;
        live.jitter_ms = cur_jit;
        live.progress = 8 + (((i as f64) / 9.0) * 12.0).round() as u8;
        broadcast_speedtest(state, &live);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    drop(ping_stream);

    let idle_ping = compute_iqm(&idle_rtts);
    let idle_jitter = compute_jitter(&idle_rtts);

    // --- Phase 2: Multi-Stream Download + Loaded Latency ---
    let (dl_mbps, dl_iqm) = run_native_transfer_phase(
        state,
        addr,
        host,
        meas_id,
        bypass_dev.clone(),
        "download",
        20,
        40,
        durs.dl_secs,
        durs.warmup_secs,
        Arc::clone(&probes_sent),
        Arc::clone(&probes_failed),
        cancel_rx.clone(),
    )
    .await?;
    if *cancel_rx.borrow() {
        return Ok(());
    }

    // Brief 400ms pause to let buffers drain before upload phase
    tokio::time::sleep(Duration::from_millis(400)).await;

    // --- Phase 3: Multi-Stream Upload + Loaded Latency ---
    let (ul_mbps, ul_iqm) = run_native_transfer_phase(
        state,
        addr,
        host,
        meas_id,
        bypass_dev,
        "upload",
        60,
        38,
        durs.ul_secs,
        durs.warmup_secs,
        Arc::clone(&probes_sent),
        Arc::clone(&probes_failed),
        cancel_rx.clone(),
    )
    .await?;
    if *cancel_rx.borrow() {
        return Ok(());
    }

    // --- Phase 4: Finalize & Persist ---
    let grade = compute_bufferbloat_grade(idle_ping, dl_iqm, ul_iqm);
    let packet_loss = compute_probe_loss_pct(
        probes_sent.load(Ordering::Relaxed),
        probes_failed.load(Ordering::Relaxed),
    );
    let server_name = Some("Cloudflare Edge (Native Rust)".to_string());
    let server_loc = colo.map(|c| format!("PoP {c}")).or_else(|| Some("Anycast Edge".into()));
    let ts = now_secs();

    {
        let mut live = state.speedtest_live.write().await;
        live.running = false;
        live.phase = "complete".into();
        live.progress = 100;
        live.ping_ms = idle_ping;
        live.jitter_ms = idle_jitter;
        live.download_mbps = Some(dl_mbps);
        live.upload_mbps = Some(ul_mbps);
        live.dl_latency_iqm = dl_iqm;
        live.ul_latency_iqm = ul_iqm;
        live.bufferbloat_grade = Some(grade.clone());
        live.packet_loss = packet_loss;
        live.server_name = server_name.clone();
        live.server_location = server_loc.clone();
        live.external_ip = ext_ip.clone();
        live.engine = Some("native".into());
        broadcast_speedtest(state, &live);
    }

    let run = SpeedtestRun {
        id: format!("st-{ts}"),
        timestamp: format_now_hms(),
        ts,
        download_mbps: dl_mbps,
        upload_mbps: ul_mbps,
        ping_ms: idle_ping.unwrap_or(0.0),
        jitter_ms: idle_jitter.unwrap_or(0.0),
        packet_loss,
        dl_latency_iqm: dl_iqm,
        ul_latency_iqm: ul_iqm,
        bufferbloat_grade: grade,
        isp: Some("Cloudflare Anycast".into()),
        server_id: None,
        server_name,
        server_location: server_loc,
        external_ip: ext_ip,
        result_url: None,
        engine: Some("native".into()),
    };

    let hist_snap = {
        let mut hist = state.speedtest_history.write().await;
        hist.insert(0, run);
        hist.truncate(50);
        hist.clone()
    };
    let _ = save_json_atomic_async(hist_path, hist_snap, 0o600).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_native_transfer_phase(
    state: &AppState,
    addr: SocketAddr,
    host: &str,
    meas_id: u64,
    bypass_dev: Option<String>,
    phase: &str,
    prog_base: u8,
    prog_span: u8,
    duration_secs: u64,
    warmup_secs: f64,
    probes_sent: Arc<AtomicU64>,
    probes_failed: Arc<AtomicU64>,
    mut cancel_rx: watch::Receiver<bool>,
) -> Result<(f64, Option<f64>), String> {
    let (phase_stop_tx, phase_stop_rx) = watch::channel(false);
    let bytes_total = Arc::new(AtomicU64::new(0));
    let rtt_samples = Arc::new(Mutex::new(Vec::<f64>::new()));

    let streams = if phase == "download" {
        NATIVE_DL_STREAMS
    } else {
        NATIVE_UL_STREAMS
    };
    let mut handles = Vec::with_capacity(streams + 1);
    for _ in 0..streams {
        let b = Arc::clone(&bytes_total);
        let rx = phase_stop_rx.clone();
        let h = host.to_string();
        let dev = bypass_dev.clone();
        if phase == "download" {
            handles.push(tokio::spawn(native_dl_worker(addr, h, meas_id, dev, b, rx)));
        } else {
            handles.push(tokio::spawn(native_ul_worker(addr, h, meas_id, dev, b, rx)));
        }
    }
    handles.push(tokio::spawn(native_loaded_ping_worker(
        addr,
        host.to_string(),
        meas_id,
        bypass_dev,
        Arc::clone(&rtt_samples),
        probes_sent,
        probes_failed,
        phase_stop_rx,
    )));

    let start = Instant::now();
    let total_dur = Duration::from_secs(duration_secs.max(1));
    let mut window: std::collections::VecDeque<(Instant, u64)> = std::collections::VecDeque::with_capacity(8);
    window.push_back((start, 0));
    let mut warmup_mark: Option<(Instant, u64)> = None;

    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    let _ = phase_stop_tx.send(true);
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }

        let now = Instant::now();
        let elapsed = now.duration_since(start);
        let cur_bytes = bytes_total.load(Ordering::Relaxed);
        window.push_back((now, cur_bytes));
        // 1.0-second rolling sliding window eliminates 250 ms cellular TDD/HARQ sawtooth noise
        while window.len() > 2
            && window
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) > Duration::from_millis(1050))
        {
            window.pop_front();
        }
        let (win_t, win_b) = window.front().copied().unwrap_or((start, 0));
        let dt = now.duration_since(win_t).as_secs_f64().max(0.1);
        let smooth_mbps = round2(((cur_bytes.saturating_sub(win_b) as f64) * 8.0) / (dt * 1_000_000.0));

        if warmup_mark.is_none() && elapsed.as_secs_f64() >= warmup_secs {
            warmup_mark = Some((now, cur_bytes));
        }

        let iqm = rtt_samples.lock().ok().and_then(|g| compute_iqm(&g));
        let frac = (elapsed.as_secs_f64() / total_dur.as_secs_f64()).clamp(0.0, 1.0);
        let progress = prog_base + (frac * f64::from(prog_span)).round() as u8;

        {
            let mut live = state.speedtest_live.write().await;
            live.phase = phase.into();
            live.progress = progress;
            if phase == "download" {
                live.download_mbps = Some(smooth_mbps);
                live.dl_latency_iqm = iqm;
            } else {
                live.upload_mbps = Some(smooth_mbps);
                live.ul_latency_iqm = iqm;
            }
            live.samples.push(SpeedtestSample {
                ts: now_secs() * 1000,
                phase: phase.into(),
                mbps: smooth_mbps,
                latency_iqm: iqm,
            });
            if live.samples.len() > 160 {
                live.samples.remove(0);
            }
            broadcast_speedtest(state, &live);
        }

        if elapsed >= total_dur {
            break;
        }
    }

    let _ = phase_stop_tx.send(true);
    let end = Instant::now();
    let final_bytes = bytes_total.load(Ordering::Relaxed);
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
    }

    let steady_mbps = match warmup_mark {
        Some((t0, b0)) if end.duration_since(t0).as_secs_f64() >= 0.5 => {
            let secs = end.duration_since(t0).as_secs_f64();
            round2(((final_bytes.saturating_sub(b0) as f64) * 8.0) / (secs * 1_000_000.0))
        }
        _ => {
            let secs = end.duration_since(start).as_secs_f64().max(0.1);
            round2(((final_bytes as f64) * 8.0) / (secs * 1_000_000.0))
        }
    };
    let final_iqm = rtt_samples.lock().ok().and_then(|g| compute_iqm(&g));
    Ok((steady_mbps, final_iqm))
}

pub async fn stop_speedtest(state: &AppState) -> Result<(), String> {
    if let Some(cancel) = state.speedtest_cancel.lock().await.take() {
        let _ = cancel.send(true);
    }
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
    if state.ws_tx.receiver_count() == 0 {
        return;
    }
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
    use tokio::net::TcpListener;

    #[test]
    fn computes_iqm_jitter_and_cf_headers() {
        assert_eq!(compute_iqm(&[10.0, 20.0, 22.0, 24.0, 26.0, 28.0, 30.0, 500.0]), Some(25.0));
        assert_eq!(compute_iqm(&[]), None);
        assert_eq!(compute_jitter(&[20.0, 24.0, 22.0, 26.0]), Some(3.33));
        let hdr = "HTTP/1.1 200 OK\r\ncf-meta-ip: 203.0.113.42\r\ncf-ray: 8a1b2c3d4e5f-IAD\r\n";
        assert_eq!(
            parse_cf_meta_headers(hdr),
            (Some("203.0.113.42".into()), Some("IAD".into()))
        );
    }

    #[tokio::test]
    async fn native_speedtest_runs_end_to_end_against_local_http_server() {
        let env = crate::paths::TestSandbox::new("speedtest-native");
        let auth = crate::auth::AuthStore::new(env.root.join("sessions"));
        let app = AppState::for_tests(env.root.clone(), auth);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let chunk = vec![b'A'; 65536];
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let chunk = chunk.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let Ok((hdr, rest)) = read_http_headers(&mut sock).await else {
                            break;
                        };
                        let first = hdr.lines().next().unwrap_or("");
                        if first.contains("bytes=0") {
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncf-meta-ip: 198.51.100.7\r\ncf-ray: abcdef123456-IAD\r\nConnection: keep-alive\r\n\r\n";
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                        } else if first.starts_with("GET /__down") {
                            let body_len = 512 * 1024;
                            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: keep-alive\r\n\r\n");
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                            let mut rem = body_len;
                            while rem > 0 {
                                let take = rem.min(chunk.len());
                                if sock.write_all(&chunk[..take]).await.is_err() {
                                    return;
                                }
                                rem -= take;
                            }
                        } else if first.starts_with("POST /__up") {
                            let cl = parse_content_length(&hdr).unwrap_or(0);
                            let mut rem = cl.saturating_sub(rest.len());
                            while rem > 0 {
                                let take = rem.min(buf.len());
                                match sock.read(&mut buf[..take]).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => rem -= n,
                                }
                            }
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                });
            }
        });

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                let durs = NativePhaseDurations {
                    dl_secs: 1,
                    ul_secs: 1,
                    warmup_secs: 0.1,
                };
                start_native_speedtest(app.clone(), "127.0.0.1".into(), addr.port(), Some(durs))
                    .await
                    .unwrap();
                for _ in 0..160 {
                    if !app.speedtest_live.read().await.running && app.speedtest_pid.lock().await.is_none() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let live = app.speedtest_live.read().await.clone();
                assert_eq!(live.phase, "complete", "{live:?}");
                assert!(!live.running);
                assert_eq!(live.engine.as_deref(), Some("native"));
                assert_eq!(live.server_location.as_deref(), Some("PoP IAD"));
                assert_eq!(live.external_ip.as_deref(), Some("198.51.100.7"));
                assert!(live.download_mbps.unwrap_or(0.0) > 1.0, "{live:?}");
                assert!(live.upload_mbps.unwrap_or(0.0) > 1.0, "{live:?}");
                let hist = app.speedtest_history.read().await;
                assert_eq!(hist.len(), 1);
                assert_eq!(hist[0].engine.as_deref(), Some("native"));
            })
            .await;
        server.abort();
    }

    #[tokio::test]
    async fn stderr_is_drained_so_a_chatty_child_cannot_block() {
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

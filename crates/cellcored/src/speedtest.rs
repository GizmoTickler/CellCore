use std::{
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::watch,
};

use crate::{
    auth::now_secs,
    state::{
        AppState, SpeedtestLiveState, SpeedtestRun, SpeedtestSample, format_now_hms, mono_ms,
        save_json_atomic_async,
    },
};

pub const SPEEDTEST_HISTORY_PATH: &str = "/etc/cellcore/speedtest_history.json";

const NATIVE_DEFAULT_HOST: &str = "speed.cloudflare.com";
const NATIVE_DEFAULT_PORT: u16 = 80;
const NATIVE_DL_STREAMS: usize = 8;
const NATIVE_UL_STREAMS: usize = 6;
const NATIVE_DL_CHUNK_BYTES: usize = 90_000_000;
const NATIVE_UL_CHUNK_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_DL_SECS: u64 = 10;
const NATIVE_UL_SECS: u64 = 8;
const NATIVE_WARMUP_SECS: f64 = 2.0;

/// Grace period after a local speedtest ends during which rmnet byte deltas
/// are still draining and must not falsely trip failover or standby-leak alerts.
const SELF_TRAFFIC_SETTLE_MS: u64 = 10_000;

static LAST_SPEEDTEST_END_MONO_MS: AtomicU64 = AtomicU64::new(0);

/// Returns true while CellCore's own speedtest is running (or within
/// `SELF_TRAFFIC_SETTLE_MS` after it finished) so the failover throughput
/// heuristic and standby-leak detector ignore self-generated test traffic.
pub async fn is_self_traffic_active(state: &AppState) -> bool {
    if state.speedtest_live.read().await.running {
        return true;
    }
    let ended = LAST_SPEEDTEST_END_MONO_MS.load(Ordering::Relaxed);
    ended != 0 && mono_ms().saturating_sub(ended) < SELF_TRAFFIC_SETTLE_MS
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
/// single-packet spikes, matching Cloudflare loaded-latency reporting.
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

/// Check whether HTTP response headers request closing the keep-alive connection.
fn header_requests_close(headers_text: &str) -> bool {
    for line in headers_text.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("connection")
            && v.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("close"))
        {
            return true;
        }
    }
    false
}

async fn finish_speedtest_slot(state: &AppState) {
    LAST_SPEEDTEST_END_MONO_MS.store(mono_ms(), Ordering::Relaxed);
    *state.speedtest_pid.lock().await = None;
    *state.speedtest_cancel.lock().await = None;
}

pub async fn start_speedtest(state: AppState) -> Result<(), String> {
    start_native_speedtest(state, NATIVE_DEFAULT_HOST.to_string(), NATIVE_DEFAULT_PORT, None).await
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

#[derive(Debug)]
enum ProbeErr {
    /// Clean keep-alive socket recycle by the remote edge (EOF / reset on reused socket)
    /// — NOT network packet loss; caller should transparently reconnect once.
    KeepAliveClosed,
    /// Genuine probe timeout or transport error.
    Transport(String),
}

async fn read_http_headers_typed(stream: &mut TcpStream) -> Result<(String, Vec<u8>), ProbeErr> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut tmp))
            .await
            .map_err(|_| ProbeErr::Transport("header timeout".to_string()))?
            .map_err(|e| {
                if buf.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    )
                {
                    ProbeErr::KeepAliveClosed
                } else {
                    ProbeErr::Transport(format!("header read: {e}"))
                }
            })?;
        if n == 0 {
            if buf.is_empty() {
                return Err(ProbeErr::KeepAliveClosed);
            }
            return Err(ProbeErr::Transport("unexpected EOF reading HTTP headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let hdr = String::from_utf8_lossy(&buf[..pos]).to_string();
            let rest = buf[pos + 4..].to_vec();
            return Ok((hdr, rest));
        }
        if buf.len() > 16384 {
            return Err(ProbeErr::Transport("HTTP response headers too large".into()));
        }
    }
}

async fn read_http_headers(stream: &mut TcpStream) -> Result<(String, Vec<u8>), String> {
    read_http_headers_typed(stream).await.map_err(|e| match e {
        ProbeErr::KeepAliveClosed => "keep-alive closed".into(),
        ProbeErr::Transport(s) => s,
    })
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

async fn probe_http_rtt_typed(
    stream: &mut TcpStream,
    host: &str,
    meas_id: u64,
) -> Result<(f64, String), ProbeErr> {
    let req = format!(
        "GET /__down?measId={meas_id}&bytes=0 HTTP/1.1\r\nHost: {host}\r\nReferer: https://speed.cloudflare.com/\r\nUser-Agent: CellCore-NativeSpeedtest/1.2\r\nConnection: keep-alive\r\n\r\n"
    );
    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(3), stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| ProbeErr::Transport("probe write timeout".to_string()))?
        .map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) {
                ProbeErr::KeepAliveClosed
            } else {
                ProbeErr::Transport(format!("probe write: {e}"))
            }
        })?;
    let (hdr, rest) = read_http_headers_typed(stream).await?;
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

async fn probe_http_rtt(
    stream: &mut TcpStream,
    host: &str,
    meas_id: u64,
) -> Result<(f64, String), String> {
    probe_http_rtt_typed(stream, host, meas_id)
        .await
        .map_err(|e| match e {
            ProbeErr::KeepAliveClosed => "keep-alive closed".into(),
            ProbeErr::Transport(s) => s,
        })
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
        // 1 MiB SO_RCVBUF per stream × 8 streams = 8 MiB aggregate window (saturates 1.5+ Gbps
        // without over-filling carrier RLC queues and spiking loaded latency).
        let Ok(mut stream) = connect_native_socket(addr, bypass_dev.as_deref(), Some(1024 * 1024), None).await else {
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
            if eof || header_requests_close(&hdr) {
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
            if header_requests_close(&hdr) {
                break;
            }
        }
    }
}

/// Probe a single loaded HTTP RTT, transparently reconnecting once when the
/// remote server closes an idle/max-requests keep-alive socket so normal
/// keep-alive recycles are never miscounted as packet loss.
async fn probe_once_with_keepalive_retry(
    stream_opt: &mut Option<TcpStream>,
    addr: SocketAddr,
    host: &str,
    meas_id: u64,
    bypass_dev: Option<&str>,
) -> Result<f64, ()> {
    let mut reused = stream_opt.is_some();
    for _attempt in 0..2 {
        if stream_opt.is_none() {
            match connect_native_socket(addr, bypass_dev, None, None).await {
                Ok(s) => {
                    *stream_opt = Some(s);
                    reused = false;
                }
                Err(_) => return Err(()),
            }
        }
        let s = stream_opt.as_mut().expect("stream populated");
        match probe_http_rtt_typed(s, host, meas_id).await {
            Ok((rtt, hdr)) => {
                if header_requests_close(&hdr) {
                    *stream_opt = None;
                }
                return Ok(rtt);
            }
            Err(ProbeErr::KeepAliveClosed) if reused => {
                *stream_opt = None;
                reused = false;
                continue;
            }
            Err(_) => {
                *stream_opt = None;
                return Err(());
            }
        }
    }
    Err(())
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
        let res = tokio::select! {
            _ = stop_rx.changed() => break,
            r = probe_once_with_keepalive_retry(
                &mut stream_opt,
                addr,
                &host,
                meas_id,
                bypass_dev.as_deref(),
            ) => r,
        };
        if *stop_rx.borrow() {
            break;
        }
        probes_sent.fetch_add(1, Ordering::Relaxed);
        match res {
            Ok(rtt) => {
                if let Ok(mut g) = samples.lock() {
                    g.push(rtt);
                }
            }
            Err(()) => {
                probes_failed.fetch_add(1, Ordering::Relaxed);
            }
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
    let (addr, bypass_dev, ping_stream) = connected.ok_or(last_err)?;

    // --- Phase 1: Idle Latency & Edge Discovery ---
    let meas_id = now_secs()
        .wrapping_mul(1_000_003)
        .wrapping_add(u64::from(std::process::id()));
    let mut idle_rtts: Vec<f64> = Vec::with_capacity(9);
    let mut ext_ip: Option<String> = None;
    let mut colo: Option<String> = None;
    let probes_sent = Arc::new(AtomicU64::new(0));
    let probes_failed = Arc::new(AtomicU64::new(0));

    let mut ping_opt: Option<TcpStream> = Some(ping_stream);
    for i in 0..10 {
        if *cancel_rx.borrow() {
            return Ok(());
        }
        if i == 0 {
            let s = ping_opt.as_mut().expect("initial stream");
            let (_rtt, hdr) = probe_http_rtt(s, host, meas_id).await?;
            if header_requests_close(&hdr) {
                ping_opt = None;
            }
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
        match probe_once_with_keepalive_retry(
            &mut ping_opt,
            addr,
            host,
            meas_id,
            bypass_dev.as_deref(),
        )
        .await
        {
            Ok(rtt) => {
                idle_rtts.push(rtt);
            }
            Err(()) => {
                probes_failed.fetch_add(1, Ordering::Relaxed);
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
    drop(ping_opt);

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
    *state.speedtest_pid.lock().await = None;
    LAST_SPEEDTEST_END_MONO_MS.store(mono_ms(), Ordering::Relaxed);
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
    fn computes_iqm_jitter_cf_headers_and_connection_close() {
        assert_eq!(compute_iqm(&[10.0, 20.0, 22.0, 24.0, 26.0, 28.0, 30.0, 500.0]), Some(25.0));
        assert_eq!(compute_iqm(&[]), None);
        assert_eq!(compute_jitter(&[20.0, 24.0, 22.0, 26.0]), Some(3.33));
        let hdr = "HTTP/1.1 200 OK\r\ncf-meta-ip: 203.0.113.42\r\ncf-ray: 8a1b2c3d4e5f-IAD\r\nConnection: close\r\n";
        assert_eq!(
            parse_cf_meta_headers(hdr),
            (Some("203.0.113.42".into()), Some("IAD".into()))
        );
        assert!(header_requests_close(hdr));
        assert!(!header_requests_close("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n"));
    }

    #[tokio::test]
    async fn keepalive_eof_and_connection_close_do_not_report_false_packet_loss() {
        // Server closes the TCP connection after every single probe (simulating
        // Cloudflare edge keep-alive recycle / Connection: close).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut count = 0usize;
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                count += 1;
                let announce_close = count % 2 == 1;
                tokio::spawn(async move {
                    if read_http_headers(&mut sock).await.is_ok() {
                        let resp = if announce_close {
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            // Claim keep-alive then close socket immediately (EOF on next probe)
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        };
                        let _ = sock.write_all(resp.as_bytes()).await;
                    }
                });
            }
        });

        let mut stream_opt: Option<TcpStream> = None;
        for _ in 0..6 {
            let rtt = probe_once_with_keepalive_retry(&mut stream_opt, addr, "127.0.0.1", 42, None)
                .await
                .expect("keep-alive close/EOF must reconnect transparently without loss");
            assert!(rtt >= 0.0);
        }
        server.abort();
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
                assert!(is_self_traffic_active(&app).await);
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
                assert_eq!(live.packet_loss, Some(0.0), "{live:?}");
                assert!(live.download_mbps.unwrap_or(0.0) > 1.0, "{live:?}");
                assert!(live.upload_mbps.unwrap_or(0.0) > 1.0, "{live:?}");
                let hist = app.speedtest_history.read().await;
                assert_eq!(hist.len(), 1);
                assert_eq!(hist[0].engine.as_deref(), Some("native"));
                // Immediately after completion, settle window keeps self-traffic active
                assert!(is_self_traffic_active(&app).await);
            })
            .await;
        server.abort();
    }
}

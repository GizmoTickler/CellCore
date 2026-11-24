use std::{
    fs,
    future::Future,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

use crate::{
    parsers::{clean_at_lines, parse_carrier_aggregation, parse_scalar_at_value, parse_serving_cell, split_csv_fields, unquote},
    reconcile::run_boot_reconcile,
    smd::Priority,
    state::AppState,
    uci::run_cmd,
};

pub const IPC_SOCKET_PATH: &str = "/var/run/cellcored.sock";
const IPC_READ_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Route10's watchdog kills the SSH session after 25 s. The daemon answers
/// `status` within this budget (the CLI adds connect/print overhead).
pub const R10_STATUS_BUDGET: Duration = Duration::from_secs(18);
/// wan-restart / modem-reset reply after at most this long; a sequence that
/// is still running keeps going in the background and is reported as
/// `state=in_progress`.
pub const R10_ACTION_REPLY_BUDGET: Duration = Duration::from_secs(20);
/// A gate older than this is considered wedged and may be re-taken.
const R10_ACTION_MAX_AGE: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R10Action {
    WanRestart,
    ModemReset,
}

impl R10Action {
    pub fn name(self) -> &'static str {
        match self {
            R10Action::WanRestart => "wan-restart",
            R10Action::ModemReset => "modem-reset",
        }
    }
}

/// At most one recovery action (wan-restart / modem-reset) runs at a time;
/// a request arriving while one is running is reported, not re-run.
#[derive(Default)]
pub struct ActionGate {
    running: Mutex<Option<(R10Action, Instant)>>,
}

pub struct ActionToken {
    gate: Arc<ActionGate>,
}

impl Drop for ActionToken {
    fn drop(&mut self) {
        if let Ok(mut g) = self.gate.running.lock() {
            *g = None;
        }
    }
}

impl ActionGate {
    pub fn try_start(gate: &Arc<ActionGate>, action: R10Action) -> Result<ActionToken, (R10Action, Duration)> {
        let mut g = gate.running.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((running, since)) = *g
            && since.elapsed() < R10_ACTION_MAX_AGE
        {
            return Err((running, since.elapsed()));
        }
        *g = Some((action, Instant::now()));
        Ok(ActionToken { gate: Arc::clone(gate) })
    }
}

static R10_GATE: LazyLock<Arc<ActionGate>> = LazyLock::new(|| Arc::new(ActionGate::default()));

/// Run `work` under `gate`, replying within `budget`. The work itself is
/// spawned, so it completes even if the Route10 client disconnects.
///
/// `on_start` runs only when this request actually starts the action (it is
/// where the caller records the execution: daemon log, event, audit), so a
/// request answered `state=in_progress` never looks like a second run.
/// `on_busy` runs instead when the request is refused.
pub async fn run_gated_action<F, S, B>(gate: &Arc<ActionGate>, action: R10Action, budget: Duration, on_start: S, on_busy: B, work: F) -> String
where
    F: Future<Output = ()> + Send + 'static,
    S: FnOnce(),
    B: FnOnce(R10Action, Duration),
{
    match ActionGate::try_start(gate, action) {
        Err((running, elapsed)) => {
            on_busy(running, elapsed);
            format!(
                "result=ok action={} state=in_progress running={} elapsed_s={}\n",
                action.name(),
                running.name(),
                elapsed.as_secs()
            )
        }
        Ok(token) => {
            on_start();
            let handle = tokio::spawn(async move {
                let _token = token;
                work.await;
            });
            match tokio::time::timeout(budget, handle).await {
                Ok(_) => format!("result=ok action={}\n", action.name()),
                Err(_) => format!("result=ok action={}\nstate=in_progress\n", action.name()),
            }
        }
    }
}

/// A reboot is issued at most once: a retried / concurrent `reboot` while
/// one is already under way is reported, not re-issued. The gate is never
/// released (the device is going down); it only expires after
/// `R10_ACTION_MAX_AGE`, in case the reboot command itself failed.
#[derive(Default)]
pub struct RebootGate {
    started: Mutex<Option<Instant>>,
}

impl RebootGate {
    /// `Ok` = this request issues the reboot; `Err(elapsed)` = one is under way.
    pub fn try_start(&self) -> Result<(), Duration> {
        let mut g = self.started.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(since) = *g
            && since.elapsed() < R10_ACTION_MAX_AGE
        {
            return Err(since.elapsed());
        }
        *g = Some(Instant::now());
        Ok(())
    }
}

static R10_REBOOT_GATE: LazyLock<RebootGate> = LazyLock::new(RebootGate::default);

async fn wan_restart_sequence(state: AppState) {
    {
        let guard = crate::radio::lock_bounded(&state, Duration::from_secs(5)).await;
        if guard.is_none() {
            state.push_daemon_log("r10-modem-ctl: radio_lock busy for 5s; continuing wan-restart recovery");
        }
        let mut reset_cfun = false;
        if let Ok(cfun_res) = state
            .smd
            .exec("AT+CFUN?", Priority::Emergency, Duration::from_secs(5))
            .await
        {
            let cfun_str = parse_scalar_at_value(&cfun_res.body, "+CFUN:");
            if cfun_str.trim() != "1" {
                let _ = crate::telemetry::ensure_cfun_one_with_retries(&state, Duration::from_secs(10)).await;
                crate::handlers::forget_radio_mode(&state);
                reset_cfun = true;
            }
        }
        drop(guard);
        if reset_cfun {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    if !crate::dataplane::trigger_native_reconnect_if_active().await {
        let _ = run_cmd("ubus", &["call", "network.interface.wan", "down"], Duration::from_secs(3)).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = run_cmd("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3)).await;
        let _ = run_cmd("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3)).await;
    }
}

async fn modem_reset_sequence(state: AppState) {
    {
        let guard = crate::radio::lock_bounded(&state, Duration::from_secs(5)).await;
        if guard.is_none() {
            state.push_daemon_log("r10-modem-ctl: radio_lock busy for 5s; continuing modem-reset recovery");
        }
        let _ = state
            .smd
            .exec("AT+CFUN=0", Priority::Emergency, Duration::from_secs(10))
            .await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let _ = crate::telemetry::ensure_cfun_one_with_retries(&state, Duration::from_secs(15)).await;
        crate::handlers::forget_radio_mode(&state);
        drop(guard);
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    if !crate::dataplane::trigger_native_reconnect_if_active().await {
        let _ = run_cmd("ubus", &["call", "network.interface.wan", "up"], Duration::from_secs(3)).await;
        let _ = run_cmd("ubus", &["call", "network.interface.wan_v6", "up"], Duration::from_secs(3)).await;
    }
}

pub fn ipc_socket_path() -> String {
    crate::paths::ipc_socket()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum IpcRequest {
    R10Status,
    R10WanRestart,
    R10ModemReset,
    R10Reboot,
    QuectelAt { command: String, timeout_secs: Option<u64> },
    QuectelStatus,
    Reconcile,
    /// Prometheus text from cached state (no AT).
    Metrics,
    /// Route10's failover hint: "active" | "standby".
    Role { role: String },
    /// Trigger ACME certificate issuance inside the running daemon (supports both HTTP-01 and DNS-01).
    AcmeIssue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub ok: bool,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn spawn_ipc_server(state: AppState, enforce_uhttpd_loopback: bool) {
    tokio::spawn(async move {
        let sock_path = ipc_socket_path();
        let sock = Path::new(&sock_path);
        if let Some(parent) = sock.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if sock.exists() {
            let _ = fs::remove_file(sock);
        }
        let Ok(listener) = UnixListener::bind(sock) else {
            state.push_daemon_log(format!("Failed to bind {sock_path}"));
            return;
        };
        let _ = fs::set_permissions(sock, fs::Permissions::from_mode(0o600));

        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(_) => {
                    // EMFILE/ENFILE etc.: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let st = state.clone();
            tokio::spawn(async move {
                handle_ipc_client(st, stream, enforce_uhttpd_loopback).await;
            });
        }
    });
}

async fn handle_ipc_client(
    state: AppState,
    stream: UnixStream,
    enforce_uhttpd_loopback: bool,
) {
    use tokio::io::AsyncReadExt;
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r.take(IPC_MAX_REQUEST_BYTES));
    let mut line = String::new();
    match tokio::time::timeout(IPC_READ_TIMEOUT, reader.read_line(&mut line)).await {
        Ok(Ok(_)) if !line.trim().is_empty() => {}
        _ => return,
    }
    let resp = match serde_json::from_str::<IpcRequest>(line.trim()) {
        Ok(req) => dispatch_ipc(state, req, enforce_uhttpd_loopback).await,
        Err(e) => IpcResponse {
            ok: false,
            output: String::new(),
            error: Some(format!("Invalid IPC JSON: {e}")),
        },
    };
    if let Ok(mut out) = serde_json::to_string(&resp) {
        out.push('\n');
        let _ = w.write_all(out.as_bytes()).await;
    }
}

pub(crate) async fn dispatch_ipc(
    state: AppState,
    req: IpcRequest,
    enforce_uhttpd_loopback: bool,
) -> IpcResponse {
    match req {
        IpcRequest::R10Status => {
            let text = build_r10_status_text_async(&state).await;
            IpcResponse {
                ok: true,
                output: text,
                error: None,
            }
        }
        IpcRequest::R10WanRestart => {
            let st = state.clone();
            let output = run_gated_action(
                &R10_GATE,
                R10Action::WanRestart,
                R10_ACTION_REPLY_BUDGET,
                || {
                    state.push_daemon_log("modem-ctl: Stage 1 wan-restart");
                    crate::obs::events::r10_action("wan-restart");
                    state.audit.event("ipc", "r10/wan-restart", "External recovery stage 1: WAN restart");
                },
                |running, elapsed| log_r10_busy(&state, R10Action::WanRestart, running, elapsed),
                wan_restart_sequence(st),
            )
            .await;
            IpcResponse {
                ok: true,
                output,
                error: None,
            }
        }
        IpcRequest::R10ModemReset => {
            let st = state.clone();
            let output = run_gated_action(
                &R10_GATE,
                R10Action::ModemReset,
                R10_ACTION_REPLY_BUDGET,
                || {
                    state.push_daemon_log("modem-ctl: Stage 2 modem-reset (CFUN=0 -> CFUN=1)");
                    crate::obs::events::r10_action("modem-reset");
                    state.audit.event("ipc", "r10/modem-reset", "External recovery stage 2: modem reset (CFUN=0 -> CFUN=1)");
                },
                |running, elapsed| log_r10_busy(&state, R10Action::ModemReset, running, elapsed),
                modem_reset_sequence(st),
            )
            .await;
            IpcResponse {
                ok: true,
                output,
                error: None,
            }
        }
        IpcRequest::R10Reboot => {
            if let Err(elapsed) = R10_REBOOT_GATE.try_start() {
                state.push_daemon_log(format!(
                    "r10-modem-ctl: reboot already under way ({}s ago); not issued again",
                    elapsed.as_secs()
                ));
                return IpcResponse {
                    ok: true,
                    output: format!("result=ok action=reboot state=in_progress elapsed_s={}\n", elapsed.as_secs()),
                    error: None,
                };
            }
            state.push_daemon_log("modem-ctl: Stage 3 reboot requested via IPC");
            crate::obs::events::r10_action("reboot");
            crate::obs::set_boot_reason("reboot requested via IPC");
            state.audit.event("ipc", "r10/reboot", "External recovery stage 3: reboot");
            // Reply first, then persist and reboot: the reply must never wait
            // on the flushes, or a slow flush outlasts the CLI's IPC read and
            // the CLI's own fallback reboots a second time.
            let st = state.clone();
            tokio::spawn(async move {
                st.audit.flush_now();
                crate::telemetry::flush_persistent_state(&st).await;
                let _ = run_cmd("sync", &[], Duration::from_secs(3)).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = run_cmd("/sbin/reboot", &[], Duration::from_secs(3)).await;
            });
            IpcResponse {
                ok: true,
                output: "result=ok action=reboot\n".into(),
                error: None,
            }
        }
        IpcRequest::QuectelAt {
            command,
            timeout_secs,
        } => {
            let dur = Duration::from_secs(timeout_secs.unwrap_or(10).clamp(1, 180));
            let deadline = tokio::time::Instant::now() + dur;
            // cellctl / menu / r10-modem-ctl may change the network mode
            // behind the band-lock checks' back; a radio write waits for (and
            // holds off) the radio endpoints' read-plan-write.
            let _radio = if crate::radio::is_radio_write(&command) {
                match tokio::time::timeout_at(deadline, crate::radio::lock(&state)).await {
                    Ok(g) => Some(g),
                    Err(_) => {
                        return IpcResponse {
                            ok: false,
                            output: String::new(),
                            error: Some(format!("AT command timed out ({command}): radio busy")),
                        };
                    }
                }
            } else {
                None
            };
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                return IpcResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(format!("AT command timed out ({command}): radio busy")),
                };
            }
            crate::handlers::note_raw_at_command(&state, &command);
            let exec = state.smd.exec(command.clone(), Priority::Interactive, rem).await;
            crate::handlers::note_raw_at_command(&state, &command);
            match exec {
                Ok(r) => IpcResponse {
                    ok: r.ok,
                    output: r.body,
                    error: if r.ok { None } else { Some("AT ERROR".into()) },
                },
                Err(e) => IpcResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(e),
                },
            }
        }
        IpcRequest::QuectelStatus => {
            let modem = state.modem.read().await.clone();
            let internals = state.internals.read().await.clone();
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "version": state.version,
                "operator": modem.operator,
                "serving": modem.serving,
                "carriers": modem.carriers,
                "mimo": modem.mimo,
                "bearers": modem.bearers,
                "internals": internals,
            }))
            .unwrap_or_default();
            IpcResponse {
                ok: true,
                output: format!("{json}\n"),
                error: None,
            }
        }
        IpcRequest::Metrics => IpcResponse {
            ok: true,
            output: crate::obs::metrics::render_state(&state).await,
            error: None,
        },
        IpcRequest::Role { role } => match crate::obs::failover::Role::parse(&role) {
            Some(r) => IpcResponse {
                ok: true,
                output: crate::obs::failover::set_hint(r),
                error: None,
            },
            None => IpcResponse {
                ok: false,
                output: String::new(),
                error: Some("role must be active or standby".into()),
            },
        },
        IpcRequest::AcmeIssue => {
            let cfg = crate::acme::load_config();
            if cfg.domains.is_empty() {
                return IpcResponse {
                    ok: false,
                    output: String::new(),
                    error: Some("No ACME domains configured. Run `cellctl acme config --domains ...` first.".into()),
                };
            }
            state.audit.event("ipc", "acme-issue", "ACME issuance requested over IPC");
            match crate::acme::issue_certificate(cfg).await {
                Ok(msg) => {
                    state.push_daemon_log(format!("ACME (CLI): {msg}"));
                    IpcResponse {
                        ok: true,
                        output: format!("{msg}\n"),
                        error: None,
                    }
                }
                Err(e) => {
                    state.push_daemon_log(format!("ACME (CLI) failed: {e}"));
                    IpcResponse {
                        ok: false,
                        output: String::new(),
                        error: Some(e),
                    }
                }
            }
        }
        IpcRequest::Reconcile => {
            state.audit.event("ipc", "reconcile", "boot reconcile requested over IPC");
            let report = tokio::task::spawn_blocking(move || run_boot_reconcile(enforce_uhttpd_loopback))
                .await
                .unwrap_or_default();
            state.internals.write().await.last_reconcile = Some(report.clone());
            IpcResponse {
                ok: true,
                output: serde_json::to_string_pretty(&report).unwrap_or_default(),
                error: None,
            }
        }
    }
}

fn log_r10_busy(state: &AppState, requested: R10Action, running: R10Action, elapsed: Duration) {
    state.push_daemon_log(format!(
        "r10-modem-ctl: {} requested while {} is in progress ({}s); not re-run",
        requested.name(),
        running.name(),
        elapsed.as_secs()
    ));
}

async fn build_r10_status_text_async(state: &AppState) -> String {
    // Fresh AT commands on every call (never a cached snapshot), at the
    // highest priority so UI/telemetry work cannot starve Route10. ubus runs
    // concurrently; the whole thing is capped so Route10's 25 s kill never
    // fires. On the cap the AT fields are reported empty (at_token_ok=0).
    let cmds = vec![
        ("AT+CFUN?".into(), Duration::from_secs(4)),
        ("AT+QENG=\"servingcell\"".into(), Duration::from_secs(4)),
        ("AT+QRSRP".into(), Duration::from_secs(4)),
        ("AT+QNWINFO".into(), Duration::from_secs(4)),
    ];
    let at_fut = async {
        tokio::time::timeout(R10_STATUS_BUDGET, state.smd.exec_batch(cmds, Priority::Emergency))
            .await
            .ok()
            .and_then(|r| r.ok())
    };
    let ubus_fut = async {
        tokio::time::timeout(R10_STATUS_BUDGET, query_wan_ubus_async())
            .await
            .unwrap_or((0, 0, detect_first_up_rmnet()))
    };
    let (res, (wan_up, wan_uptime, l3_device)) = tokio::join!(at_fut, ubus_fut);
    let modem_uptime_s = read_proc_uptime_secs();
    let maintenance_pause = is_maintenance_pause_active(state).await;
    let get_b = |idx: usize| -> String {
        res.as_ref()
            .and_then(|v| v.get(idx))
            .and_then(|r| r.as_ref().ok())
            .map(|r| r.body.clone())
            .unwrap_or_default()
    };

    let mut text = format_r10_status_lines(
        wan_up,
        wan_uptime,
        &l3_device,
        modem_uptime_s,
        &get_b(0),
        &get_b(1),
        &get_b(2),
        &get_b(3),
    );
    if maintenance_pause {
        text.push_str("maintenance_pause=1\n");
    }
    let (wan_v4_usable, wan_v6_usable) = resolve_wan_family_usable(
        crate::dataplane::wds_v4_usable(),
        crate::dataplane::wds_v6_usable(),
        crate::dataplane::is_native_mode(),
        crate::dataplane::is_wds_v4_connected(),
        crate::dataplane::is_wds_v6_connected(),
        wan_up,
    );
    text.push_str(&format!(
        "wan_v4_usable={wan_v4_usable}\nwan_v6_usable={wan_v6_usable}\n"
    ));
    text
}

pub(crate) fn resolve_wan_family_usable(
    v4_usable: Option<bool>,
    v6_usable: Option<bool>,
    native_mode: bool,
    v4_wds_connected: bool,
    v6_wds_connected: bool,
    wan_up: u8,
) -> (u8, u8) {
    let map_fam = |probe: Option<bool>, wds_conn: bool| -> u8 {
        match probe {
            Some(true) => 1,
            Some(false) => 0,
            None => {
                if native_mode {
                    u8::from(wds_conn)
                } else {
                    u8::from(wan_up == 1)
                }
            }
        }
    };
    (
        map_fam(v4_usable, v4_wds_connected),
        map_fam(v6_usable, v6_wds_connected),
    )
}

pub(crate) async fn is_maintenance_pause_active(state: &AppState) -> bool {
    if state
        .recovery_in_progress
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return true;
    }
    if state.antenna_align.read().await.active {
        return true;
    }
    state.quecwatch.read().await.status == "recovering"
}

/// Combine netlink rmnet liveness with native QMI WDS bearer state so Route10
/// never receives a false `wan_up=1` after a PDN drop while stale addresses linger.
pub(crate) fn resolve_native_wan_up(
    native_mode: bool,
    wds_connected: bool,
    netlink_dev: Option<String>,
    native_uptime: Option<u64>,
    proc_uptime: u64,
) -> (u8, u64, String) {
    if native_mode && !wds_connected {
        return (0, 0, String::from("none"));
    }
    if let Some(dev) = netlink_dev {
        let up = native_uptime.unwrap_or_else(|| proc_uptime.max(1));
        return (1, up, dev);
    }
    (0, 0, String::from("none"))
}

pub async fn query_wan_ubus_async() -> (u8, u64, String) {
    let mut wan_up = 0u8;
    let mut wan_uptime = 0u64;
    let mut l3_device = String::from("none");
    let native_mode = crate::dataplane::is_native_mode();
    if !native_mode {
        for iface in ["network.interface.wan", "network.interface.wan_v6"] {
            if let Ok(out) = run_cmd("ubus", &["call", iface, "status"], Duration::from_secs(2)).await
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
    }
    if wan_up == 0 {
        let wds_connected = crate::dataplane::is_wds_connected();
        let netlink_dev = if !native_mode || wds_connected {
            tokio::task::spawn_blocking(crate::netlink::detect_active_rmnet_wan_live)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let (up, uptime, dev) = resolve_native_wan_up(
            native_mode,
            wds_connected,
            netlink_dev,
            crate::dataplane::native_wan_uptime_secs(),
            read_proc_uptime_secs(),
        );
        wan_up = up;
        wan_uptime = uptime;
        if dev != "none" {
            l3_device = dev;
        }
    }
    if l3_device == "none" {
        l3_device = detect_first_up_rmnet();
    }
    (wan_up, wan_uptime, l3_device)
}

pub fn read_proc_uptime_secs() -> u64 {
    fs::read_to_string(crate::paths::p("/proc/uptime"))
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

pub fn detect_first_up_rmnet() -> String {
    if let Ok(entries) = fs::read_dir(crate::paths::p("/sys/class/net")) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("rmnet_data"))
            .collect();
        names.sort();
        for name in &names {
            let up = fs::read_to_string(crate::paths::p(&format!("/sys/class/net/{name}/operstate")))
                .unwrap_or_default();
            if up.trim() == "up" {
                return name.clone();
            }
        }
        if let Some(first) = names.into_iter().next() {
            return first;
        }
    }
    "none".into()
}

#[allow(clippy::too_many_arguments)]
pub fn format_r10_status_lines(
    wan_up: u8,
    wan_uptime: u64,
    l3_device: &str,
    modem_uptime_s: u64,
    cfun_out: &str,
    qeng_out: &str,
    qrsrp_out: &str,
    qnwinfo_out: &str,
) -> String {
    let cfun = parse_scalar_at_value(cfun_out, "+CFUN:")
        .parse::<i32>()
        .unwrap_or(-1);
    let at_token_ok = if cfun != -1 { 1 } else { 0 };

    let serving = parse_serving_cell(qeng_out, &parse_carrier_aggregation(""));
    let mut mode = String::new();
    let mut lte_band = String::new();
    let mut lte_rsrp = String::new();
    let mut lte_rsrq = String::new();
    let mut nr_band = String::new();
    let mut nr_rsrp = String::new();
    let mut nr_sinr = String::new();
    let mut nr_rsrq = String::new();

    if let Some(sc) = serving {
        if sc.rat == "NR5G-SA" {
            mode = "NR5G-SA".into();
            if sc.band != "-" {
                nr_band = sc.band;
            }
            if let Some(v) = sc.rsrp.filter(|&v| v > -140.0 && v < 0.0) {
                nr_rsrp = format!("{}", v.round() as i64);
            }
            if let Some(v) = sc.rsrq.filter(|&v| (-40.0..=5.0).contains(&v)) {
                nr_rsrq = format!("{}", v.round() as i64);
            }
            if let Some(v) = sc.sinr.filter(|&v| (-30.0..=60.0).contains(&v)) {
                nr_sinr = format!("{}", v.round() as i64);
            }
        } else if sc.rat.starts_with("LTE") {
            mode = "LTE".into();
            if sc.band != "-" {
                lte_band = sc.band;
            }
            if let Some(v) = sc.rsrp.filter(|&v| v > -140.0 && v < 0.0) {
                lte_rsrp = format!("{}", v.round() as i64);
            }
            if let Some(v) = sc.rsrq.filter(|&v| (-40.0..=5.0).contains(&v)) {
                lte_rsrq = format!("{}", v.round() as i64);
            }
        }
    }

    // Parse NR5G-NSA secondary line if present
    for line in clean_at_lines(qeng_out) {
        if let Some(body) = line.strip_prefix("+QENG:") {
            let f = split_csv_fields(body);
            if unquote(f.first().map(|s| s.as_str())) == "NR5G-NSA" {
                mode = "NR5G-NSA".into();
                if let Some(v) = f.get(4).and_then(|s| unquote(Some(s)).parse::<i64>().ok())
                    && (-139..0).contains(&v)
                {
                    nr_rsrp = v.to_string();
                }
                if let Some(v) = f.get(5).and_then(|s| unquote(Some(s)).parse::<i64>().ok())
                    && (-30..=60).contains(&v)
                {
                    nr_sinr = v.to_string();
                }
                if let Some(v) = f.get(6).and_then(|s| unquote(Some(s)).parse::<i64>().ok())
                    && (-40..=5).contains(&v)
                {
                    nr_rsrq = v.to_string();
                }
                let b = unquote(f.get(8).map(|s| s.as_str()));
                if !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()) {
                    nr_band = format!("n{b}");
                }
            }
        }
    }

    let mut rat = String::new();
    let mut qrsrp_val = String::new();
    for line in clean_at_lines(qrsrp_out) {
        if let Some(rest) = line.strip_prefix("+QRSRP:") {
            let f = split_csv_fields(rest);
            if let Some(v) = f.first().and_then(|s| unquote(Some(s)).parse::<i64>().ok())
                && (-139..0).contains(&v)
            {
                qrsrp_val = v.to_string();
            }
            let raw_rat = unquote(f.last().map(|s| s.as_str())).to_ascii_uppercase();
            if matches!(raw_rat.as_str(), "LTE" | "NR5G") {
                rat = raw_rat;
            }
            break;
        }
    }

    let rsrp_dbm = if !nr_rsrp.is_empty() {
        nr_rsrp.clone()
    } else if !lte_rsrp.is_empty() {
        lte_rsrp.clone()
    } else {
        qrsrp_val
    };
    if mode.is_empty() && rat == "LTE" {
        mode = "LTE".into();
    }

    let band = clean_at_lines(qnwinfo_out)
        .into_iter()
        .find_map(|l| {
            l.strip_prefix("+QNWINFO:")
                .map(|r| r.trim().replace('"', ""))
        })
        .filter(|b| {
            !b.is_empty()
                && b != "-"
                && !b.eq_ignore_ascii_case("No Service")
                && !b.eq_ignore_ascii_case("NONE")
        })
        .unwrap_or_default();

    format!(
        "wan_up={wan_up}\n\
wan_uptime={wan_uptime}\n\
l3_device={l3_device}\n\
modem_uptime_s={modem_uptime_s}\n\
at_token_ok={at_token_ok}\n\
cfun={cfun}\n\
rsrp_dbm={rsrp_dbm}\n\
rat={rat}\n\
band={band}\n\
mode={mode}\n\
lte_band={lte_band}\n\
lte_rsrp_dbm={lte_rsrp}\n\
lte_rsrq_db={lte_rsrq}\n\
nr_band={nr_band}\n\
nr_rsrp_dbm={nr_rsrp}\n\
nr_sinr_db={nr_sinr}\n\
nr_rsrq_db={nr_rsrq}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_r10_status_from_live_sdx75_outputs() {
        let qeng = r#"+QENG: "servingcell","NOCONN","NR5G-SA","TDD",310,260,1060F4137,258,B0FB00,521310,41,14,-101,-11,9,1,-"#;
        let qrsrp = "+QRSRP: -102,-106,-140,-140,NR5G";
        let qnwinfo = r#"+QNWINFO: "TDD NR5G","310260","NR5G BAND 41",521310"#;
        let out = format_r10_status_lines(1, 15261, "rmnet_data1", 21534, "+CFUN: 1", qeng, qrsrp, qnwinfo);
        assert!(out.contains("at_token_ok=1\n"));
        assert!(out.contains("cfun=1\n"));
        assert!(out.contains("rsrp_dbm=-101\n"));
        assert!(out.contains("rat=NR5G\n"));
        assert!(out.contains("band=TDD NR5G,310260,NR5G BAND 41,521310\n"));
        assert!(out.contains("mode=NR5G-SA\n"));
        assert!(out.contains("nr_band=n41\n"));
        assert!(out.contains("nr_rsrp_dbm=-101\n"));
        assert!(out.contains("nr_sinr_db=9\n"));
        assert!(out.contains("nr_rsrq_db=-11\n"));
        assert_eq!(out.lines().count(), 17);
    }

    #[test]
    fn status_format_is_byte_for_byte_stable() {
        let qeng = r#"+QENG: "servingcell","NOCONN","NR5G-SA","TDD",310,260,1060F4137,258,B0FB00,521310,41,14,-101,-11,9,1,-"#;
        let out = format_r10_status_lines(
            1,
            15261,
            "rmnet_data1",
            21534,
            "+CFUN: 1",
            qeng,
            "+QRSRP: -102,-106,-140,-140,NR5G",
            r#"+QNWINFO: "TDD NR5G","310260","NR5G BAND 41",521310"#,
        );
        assert_eq!(
            out,
            "wan_up=1\nwan_uptime=15261\nl3_device=rmnet_data1\nmodem_uptime_s=21534\nat_token_ok=1\ncfun=1\n\
rsrp_dbm=-101\nrat=NR5G\nband=TDD NR5G,310260,NR5G BAND 41,521310\nmode=NR5G-SA\nlte_band=\nlte_rsrp_dbm=\n\
lte_rsrq_db=\nnr_band=n41\nnr_rsrp_dbm=-101\nnr_sinr_db=9\nnr_rsrq_db=-11\n"
        );
        // AT channel unavailable: same 17 keys, at_token_ok=0, cfun=-1
        let dead = format_r10_status_lines(0, 0, "none", 5, "", "", "", "");
        assert_eq!(dead.lines().count(), 17);
        assert!(dead.contains("\nat_token_ok=0\ncfun=-1\n"));
    }

    #[test]
    fn searching_and_none_states_keep_rat_and_mode_clean() {
        let out = format_r10_status_lines(
            0,
            0,
            "none",
            100,
            "+CFUN: 1",
            r#"+QENG: "servingcell","SEARCH""#,
            "+QRSRP: -140,-140,-140,-140,NONE",
            "+QNWINFO: \"No Service\"",
        );
        assert!(out.contains("rat=\n"), "{out}");
        assert!(out.contains("band=\n"), "{out}");
        assert!(out.contains("mode=\n"), "{out}");
        assert!(!out.contains("UNKNOWN"), "{out}");
        assert!(!out.contains("NONE"), "{out}");
        assert!(!out.contains("=-"), "{out}");

        // NR5G QRSRP without QENG serving cell keeps rat=NR5G and mode=""
        let nr_only = format_r10_status_lines(
            0,
            0,
            "none",
            100,
            "+CFUN: 1",
            r#"+QENG: "servingcell","LIMSRV","UNKNOWN","-""#,
            "+QRSRP: -95,-96,-140,-140,NR5G",
            "+QNWINFO: \"-\"",
        );
        assert!(nr_only.contains("rat=NR5G\n"), "{nr_only}");
        assert!(nr_only.contains("mode=\n"), "{nr_only}");
        assert!(nr_only.contains("band=\n"), "{nr_only}");

        let nsa = "+QENG: \"servingcell\",\"NOCONN\"\r\n\
                   +QENG: \"LTE\",\"FDD\",310,260,1A2B3C,100,1950,4,5,5,A1B2,-90,-10,-62,15\r\n\
                   +QENG: \"NR5G-NSA\",310,260,589,-93,14,-10,521310,41,12";
        let nsa_out = format_r10_status_lines(
            1,
            100,
            "rmnet_data1",
            200,
            "+CFUN: 1",
            nsa,
            "+QRSRP: -93,-104,-140,-140,NR5G",
            "",
        );
        assert!(nsa_out.contains("mode=NR5G-NSA\n"), "{nsa_out}");
        assert!(nsa_out.contains("lte_band=B4\n"), "{nsa_out}");
        assert!(nsa_out.contains("nr_band=n41\n"), "{nsa_out}");
    }

    #[test]
    fn metrics_and_role_ops_wire_names() {
        assert_eq!(serde_json::to_string(&IpcRequest::Metrics).unwrap(), r#"{"op":"metrics"}"#);
        let r: IpcRequest = serde_json::from_str(r#"{"op":"role","role":"active"}"#).unwrap();
        assert!(matches!(r, IpcRequest::Role { ref role } if role == "active"));
        // existing ops keep their names
        assert_eq!(serde_json::to_string(&IpcRequest::R10Status).unwrap(), r#"{"op":"r10-status"}"#);
    }

    #[tokio::test]
    async fn recovery_action_in_progress_is_reported_not_rerun() {
        let gate = Arc::new(ActionGate::default());
        let runs = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let r1 = Arc::clone(&runs);
        let t0 = Instant::now();
        let first = run_gated_action(&gate, R10Action::ModemReset, Duration::from_millis(100), || {}, |_, _| {}, async move {
            r1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(600)).await;
        })
        .await;
        assert!(t0.elapsed() < Duration::from_millis(400), "reply must respect the budget");
        assert_eq!(first, "result=ok action=modem-reset\nstate=in_progress\n");
        let r2 = Arc::clone(&runs);
        let second = run_gated_action(&gate, R10Action::ModemReset, Duration::from_secs(1), || {}, |_, _| {}, async move {
            r2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert!(second.starts_with("result=ok action=modem-reset state=in_progress running=modem-reset"));
        let r3 = Arc::clone(&runs);
        let third = run_gated_action(&gate, R10Action::WanRestart, Duration::from_secs(1), || {}, |_, _| {}, async move {
            r3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert!(third.contains("state=in_progress running=modem-reset"));
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
        // the background sequence finishes even though the caller stopped waiting
        tokio::time::sleep(Duration::from_millis(700)).await;
        let r4 = Arc::clone(&runs);
        let fourth = run_gated_action(&gate, R10Action::WanRestart, Duration::from_secs(1), || {}, |_, _| {}, async move {
            r4.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert_eq!(fourth, "result=ok action=wan-restart\n");
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
    /// HARD-05: the execution ledger (daemon log / event / audit) is written
    /// only by the request that actually starts the action. A Route10 retry
    /// queued behind a killed client, or two parallel calls, must leave
    /// exactly one "Stage 1 wan-restart" record and one execution.
    #[tokio::test]
    async fn ledger_records_one_start_for_retried_and_parallel_wan_restart() {
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        let gate = Arc::new(ActionGate::default());
        let runs = Arc::new(AtomicU32::new(0));
        let starts = Arc::new(AtomicU32::new(0));
        let busy = Arc::new(AtomicU32::new(0));
        let call = |gate: Arc<ActionGate>, runs: Arc<AtomicU32>, starts: Arc<AtomicU32>, busy: Arc<AtomicU32>, budget: Duration| async move {
            run_gated_action(
                &gate,
                R10Action::WanRestart,
                budget,
                || {
                    starts.fetch_add(1, SeqCst);
                },
                |running, _| {
                    assert_eq!(running, R10Action::WanRestart);
                    busy.fetch_add(1, SeqCst);
                },
                async move {
                    runs.fetch_add(1, SeqCst);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                },
            )
            .await
        };
        // first client "killed" early: its request future is dropped mid-wait
        let first = tokio::spawn(call(gate.clone(), runs.clone(), starts.clone(), busy.clone(), Duration::from_secs(5)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.abort();
        // the Route10 retry and a parallel duplicate
        let (a, b) = tokio::join!(
            call(gate.clone(), runs.clone(), starts.clone(), busy.clone(), Duration::from_secs(5)),
            call(gate.clone(), runs.clone(), starts.clone(), busy.clone(), Duration::from_secs(5)),
        );
        for out in [&a, &b] {
            assert!(out.contains("state=in_progress running=wan-restart"), "{out}");
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(runs.load(SeqCst), 1, "executions");
        assert_eq!(starts.load(SeqCst), 1, "ledger records a single start");
        assert_eq!(busy.load(SeqCst), 2, "the two duplicates are logged as refused");
    }

    #[test]
    fn reboot_is_issued_once_while_one_is_under_way() {
        let gate = RebootGate::default();
        assert!(gate.try_start().is_ok());
        assert!(gate.try_start().is_err(), "a retried reboot must not be issued again");
        assert!(gate.try_start().is_err());
        // a reboot that never happened (wedged command) may be retried later
        *gate.started.lock().unwrap() = Some(Instant::now() - R10_ACTION_MAX_AGE - Duration::from_secs(1));
        assert!(gate.try_start().is_ok());
    }

    #[tokio::test]
    async fn maintenance_pause_tracks_align_linkwatch_and_recovery_state() {
        let sbx = crate::paths::TestSandbox::new("ipc-maint-pause");
        let auth = crate::auth::AuthStore::new(sbx.root.join("sessions"));
        let app = AppState::for_tests(sbx.root.clone(), auth);

        assert!(!is_maintenance_pause_active(&app).await);

        app.antenna_align.write().await.active = true;
        assert!(is_maintenance_pause_active(&app).await);
        app.antenna_align.write().await.active = false;
        assert!(!is_maintenance_pause_active(&app).await);

        app.quecwatch.write().await.status = "recovering".into();
        assert!(is_maintenance_pause_active(&app).await);
        app.quecwatch.write().await.status = "healthy".into();
        assert!(!is_maintenance_pause_active(&app).await);

        app.recovery_in_progress
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(is_maintenance_pause_active(&app).await);
        app.recovery_in_progress
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(!is_maintenance_pause_active(&app).await);
    }

    #[test]
    fn native_wan_up_requires_both_netlink_and_wds_connected() {
        // PDN dropped (WDS disconnected) while stale rmnet IP still lingers -> MUST report wan_up=0!
        assert_eq!(
            resolve_native_wan_up(true, false, Some("rmnet_data0".into()), Some(120), 500),
            (0, 0, "none".into())
        );
        // WDS connected but netlink has no IP/UP -> MUST report wan_up=0!
        assert_eq!(
            resolve_native_wan_up(true, true, None, Some(120), 500),
            (0, 0, "none".into())
        );
        // Both WDS connected AND netlink UP -> wan_up=1 with native uptime.
        assert_eq!(
            resolve_native_wan_up(true, true, Some("rmnet_data1".into()), Some(42), 500),
            (1, 42, "rmnet_data1".into())
        );
        // Coexist mode (native_mode=false) relies on netlink liveness when ubus is absent.
        assert_eq!(
            resolve_native_wan_up(false, false, Some("rmnet_data0".into()), None, 500),
            (1, 500, "rmnet_data0".into())
        );
    }

    #[test]
    fn resolves_per_family_wan_usable_flags() {
        assert_eq!(resolve_wan_family_usable(Some(true), Some(false), true, true, true, 1), (1, 0));
        assert_eq!(resolve_wan_family_usable(Some(false), Some(true), true, true, true, 1), (0, 1));
        assert_eq!(resolve_wan_family_usable(None, None, true, true, false, 1), (1, 0));
        assert_eq!(resolve_wan_family_usable(None, None, false, false, false, 1), (1, 1));
        assert_eq!(resolve_wan_family_usable(None, None, false, false, false, 0), (0, 0));
    }
}

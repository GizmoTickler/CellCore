mod admin;
mod appbackup;
mod atguard;
mod audit;
mod auth;
mod cli;
mod dataplane;
mod handlers;
mod http;
mod ipc;
mod netlink;
mod obs;
mod ota;
mod parsers;
mod paths;
mod profiles;
mod qmi;
mod reconcile;
mod secroutes;
mod smd;
mod sms;
mod speedtest;
mod state;
mod telemetry;
mod tokens;
mod tower_finder;
mod tz;
mod uci;
#[cfg(test)]
mod fakeat;
mod radio;
mod radio_tuning;
#[cfg(test)]
mod validation_tests;
mod vpn;

use std::{
    collections::VecDeque,
    env,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use tokio::sync::{Mutex, RwLock, broadcast, mpsc};

use crate::{
    auth::{AuthStore, SESSION_DIR},
    reconcile::run_boot_reconcile,
    smd::SmdClient,
    speedtest::SPEEDTEST_HISTORY_PATH,
    state::{
        AntennaAlignState, AppState, DataUsageState, ETC_QM_DIR, MemoryTelemetry, ModemSecrets,
        ModemSnapshot, LinkWatchRuntime, SystemInternals, TMP_QM_DIR, TrafficRuntime,
        UptimeTelemetry, load_json_or_default, load_settings_from_uci_and_disk,
    },
    telemetry::{DATA_USAGE_PATH, flush_persistent_state, spawn_background_tasks},
};

fn parse_addrs(raw: &str) -> Vec<SocketAddr> {
    raw.split(',')
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

fn format_listen_addrs(primary: Option<std::net::Ipv4Addr>, port: u16) -> Vec<SocketAddr> {
    match primary {
        Some(ip) if !ip.is_loopback() && !ip.is_unspecified() => vec![
            SocketAddr::from((ip, port)),
            SocketAddr::from(([127, 0, 0, 1], port)),
        ],
        _ => vec![SocketAddr::from(([0, 0, 0, 0], port))],
    }
}

fn detect_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    netlink::get_iface_ipv4("br-lan").or_else(|| {
        uci::uci_get_blocking("network.lan.ipaddr")
            .and_then(|s| s.trim().parse::<std::net::Ipv4Addr>().ok())
    })
}

fn resolve_listen_addrs(env_key: &str, detected_lan: Option<std::net::Ipv4Addr>, port: u16) -> Vec<SocketAddr> {
    if let Ok(raw) = env::var(env_key) {
        let parsed = parse_addrs(&raw);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    format_listen_addrs(detected_lan, port)
}

fn main() {
    let _ = rustls_rustcrypto::provider().install_default();

    let args: Vec<String> = env::args().collect();
    let bin_name = args
        .first()
        .and_then(|p| Path::new(p).file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("cellcored");

    if bin_name == "r10-modem-ctl" || bin_name == "modem-ctl" {
        let code = cli::run_r10_modem_ctl(&args[1..]);
        process::exit(code);
    }
    if bin_name == "cellctl" || bin_name == "quecctl" || bin_name == "menu" {
        let code = cli::run_cellctl(&args[1..]);
        process::exit(code);
    }
    match args.get(1).map(|s| s.as_str()) {
        Some("--version" | "-V" | "version") => {
            println!("cellcored {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("verify" | "upgrade") => {
            let code = cli::run_cellctl(&args[1..]);
            process::exit(code);
        }
        Some("reconcile") => {
            let report = run_boot_reconcile(true);
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            return;
        }
        _ => {}
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async_main());
}

async fn async_main() {
    let _ = fs::create_dir_all(paths::p(ETC_QM_DIR));
    let _ = fs::create_dir_all(paths::p(TMP_QM_DIR));
    let _ = fs::create_dir_all(paths::p(&format!("{TMP_QM_DIR}/signal_graphs")));

    let detected_lan = if env::var_os("QM_HTTPS_ADDR").is_some() && env::var_os("QM_HTTP_ADDR").is_some() {
        None
    } else {
        tokio::task::spawn_blocking(detect_lan_ipv4).await.ok().flatten()
    };
    let https_addrs = resolve_listen_addrs("QM_HTTPS_ADDR", detected_lan, 443);
    let http_addrs = resolve_listen_addrs("QM_HTTP_ADDR", detected_lan, 80);
    let enforce_uhttpd_loopback = https_addrs.iter().any(|a| a.port() == 443);

    let report = tokio::task::spawn_blocking(move || run_boot_reconcile(enforce_uhttpd_loopback))
        .await
        .unwrap_or_default();
    let _ = handlers::repair_qcmap_wwan_uci_for_existing_xml_profiles().await;

    let smd_dev = paths::smd_device();
    let www_dir = PathBuf::from(env::var("QM_WWW_DIR").unwrap_or_else(|_| paths::p("/www")));

    // Own the AT device for the daemon's whole lifetime; `r10-modem-ctl` /
    // `cellctl` only open it directly when they can take this lock.
    let lock_path = cli::daemon_lock_path();
    let device_lock = tokio::task::spawn_blocking(move || cli::acquire_daemon_lock(&lock_path))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    if let Err(e) = &device_lock {
        eprintln!("cellcored: device lock unavailable ({e}); CLI falls back to process detection");
    }
    let smd = SmdClient::spawn(smd_dev);
    let auth = AuthStore::new(paths::p(SESSION_DIR));
    auth.ensure_dir();

    let (ws_tx, _) = broadcast::channel(64);
    let (rf_refresh_tx, rf_refresh_rx) = mpsc::channel(4);

    let data_usage = load_json_or_default::<DataUsageState>(DATA_USAGE_PATH);
    let speedtest_history = load_json_or_default(SPEEDTEST_HISTORY_PATH);
    let settings = load_settings_from_uci_and_disk();

    let internals = SystemInternals {
        last_reconcile: Some(report),
        ..Default::default()
    };

    let state = AppState {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_package: "sdxpinn-cellcore".to_string(),
        www_dir,
        smd,
        auth,
        ws_tx,
        rf_refresh_tx,
        modem: Arc::new(RwLock::new(ModemSnapshot::default())),
        secrets: Arc::new(RwLock::new(ModemSecrets::default())),
        rsrp_hist: Arc::new(RwLock::new(VecDeque::with_capacity(180))),
        rsrq_hist: Arc::new(RwLock::new(VecDeque::with_capacity(180))),
        sinr_hist: Arc::new(RwLock::new(VecDeque::with_capacity(180))),
        traffic: Arc::new(RwLock::new(TrafficRuntime::default())),
        data_usage: Arc::new(RwLock::new(data_usage)),
        ping_realtime: Arc::new(RwLock::new(VecDeque::with_capacity(180))),
        ping_hourly: Arc::new(RwLock::new(VecDeque::with_capacity(120))),
        ping_twelvehour: Arc::new(RwLock::new(VecDeque::with_capacity(144))),
        ping_daily: Arc::new(RwLock::new(VecDeque::with_capacity(144))),
        memory: Arc::new(RwLock::new(MemoryTelemetry::default())),
        device_uptime: Arc::new(RwLock::new(UptimeTelemetry::default())),
        session_uptime: Arc::new(RwLock::new(UptimeTelemetry::disconnected(0, String::new()))),
        internals: Arc::new(RwLock::new(internals)),
        speedtest_live: Arc::new(RwLock::new(Default::default())),
        speedtest_history: Arc::new(RwLock::new(speedtest_history)),
        speedtest_pid: Arc::new(Mutex::new(None)),
        antenna_align: Arc::new(RwLock::new(AntennaAlignState::default())),
        align_notify: Arc::new(tokio::sync::Notify::new()),
        settings: Arc::new(RwLock::new(settings)),
        quecwatch: Arc::new(RwLock::new(LinkWatchRuntime {
            status: "idle".into(),
            message: "LinkWatch ready".into(),
            ..Default::default()
        })),
        alerts: Arc::new(RwLock::new(VecDeque::with_capacity(24))),
        qscan_running: Arc::new(Mutex::new(None)),
        qscan_last: Arc::new(RwLock::new(None)),
        daemon_logs: Arc::new(RwLock::new(VecDeque::with_capacity(250))),
        audit: audit::AuditLog::new(Some(PathBuf::from(crate::paths::p(audit::AUDIT_DIR))), true),
        tokens: tokens::TokenStore::new(Some(PathBuf::from(crate::paths::p(tokens::TOKENS_PATH)))),
        radio: Default::default(),
        radio_lock: Default::default(),
    };
    state.audit.spawn_flusher();

    state.push_daemon_log(format!("cellcored v{} started", state.version));
    obs::start(&state);
    vpn::start(&state);
    dataplane::start(&state);
    spawn_background_tasks(state.clone(), rf_refresh_rx);
    ipc::spawn_ipc_server(state.clone(), enforce_uhttpd_loopback);

    if let Err(e) =
        http::serve_http_and_https(state.clone(), https_addrs, http_addrs, enforce_uhttpd_loopback)
            .await
    {
        eprintln!("cellcored HTTP/TLS init failed: {e}");
        process::exit(1);
    }

    // Wait for SIGTERM or SIGINT and flush persistent counters
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
    }
    flush_persistent_state(&state).await;
    state.audit.flush_now();
    state.push_daemon_log("cellcored shutting down cleanly");
    drop(device_lock);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_script_respawns_forever() {
        // procd: respawn <threshold> <timeout> <retry>; retry 0 = unlimited.
        // With "3600 5 5" five crashes inside an hour left the backup-WAN
        // modem's daemon dead until the next reboot.
        let init = include_str!("../../../scripts/etc/init.d/cellcored");
        let line = init.lines().find(|l| l.contains("procd_set_param respawn")).expect("respawn line");
        let retry = line.split_whitespace().last().unwrap();
        assert!(retry == "0" || retry.ends_with(":-0}"), "{line}");
    }

    #[test]
    fn crate_version_matches_package() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.0");
    }

    #[test]
    fn dynamic_listen_addrs_formats_detected_or_wildcard() {
        use std::net::{Ipv4Addr, SocketAddr};
        assert_eq!(
            super::format_listen_addrs(Some(Ipv4Addr::new(192, 168, 1, 1)), 443),
            vec![
                SocketAddr::from(([192, 168, 1, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ]
        );
        assert_eq!(
            super::format_listen_addrs(None, 443),
            vec![SocketAddr::from(([0, 0, 0, 0], 443))]
        );
        assert_eq!(
            super::format_listen_addrs(Some(Ipv4Addr::new(127, 0, 0, 1)), 80),
            vec![SocketAddr::from(([0, 0, 0, 0], 80))]
        );
    }
}

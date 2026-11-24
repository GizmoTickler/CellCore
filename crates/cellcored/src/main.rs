mod acme;
mod admin;
mod appbackup;
mod atguard;
mod audit;
mod auth;
mod cli;
mod dataplane;
mod firmware_ab;
mod handlers;
mod hardening;
mod http;
mod ipc;
mod netlink;
mod obs;
mod ota;
mod overlay;
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
        AntennaAlignState, AppState, ETC_QM_DIR, LinkWatchRuntime, MemoryTelemetry, ModemSecrets,
        ModemSnapshot, SystemInternals, TMP_QM_DIR, TrafficRuntime, UptimeTelemetry,
        load_json_or_default, load_settings_from_uci_and_disk,
    },
    telemetry::{
        flush_persistent_state, load_initial_cell_lock_bypass, load_initial_data_usage,
        spawn_background_tasks, spawn_liveness_watchdog,
    },
};

fn parse_addrs(raw: &str) -> Vec<SocketAddr> {
    raw.split(',')
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

fn format_listen_addrs_with_extra(
    primary: Option<std::net::Ipv4Addr>,
    extra: &[std::net::Ipv4Addr],
    port: u16,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Some(ip) = primary
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        out.push(SocketAddr::from((ip, port)));
    }
    let lo = SocketAddr::from(([127, 0, 0, 1], port));
    if !out.contains(&lo) {
        out.push(lo);
    }
    for &e in extra {
        let sa = SocketAddr::from((e, port));
        if !e.is_unspecified() && !out.contains(&sa) {
            out.push(sa);
        }
    }
    out
}

fn detect_lan_ipv4_with_retry<F>(
    mut detect: F,
    max_attempts: usize,
    delay: std::time::Duration,
) -> Option<std::net::Ipv4Addr>
where
    F: FnMut() -> Option<std::net::Ipv4Addr>,
{
    let attempts = max_attempts.max(1);
    for i in 0..attempts {
        if let Some(ip) = detect()
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            return Some(ip);
        }
        if i + 1 < attempts {
            std::thread::sleep(delay);
        }
    }
    None
}

#[cfg(test)]
fn format_listen_addrs(primary: Option<std::net::Ipv4Addr>, port: u16) -> Vec<SocketAddr> {
    format_listen_addrs_with_extra(primary, &[], port)
}

fn extract_loopback_mgmt_ipv4s(
    links: &[netlink::NetlinkLink],
    addrs: &[netlink::NetlinkAddr],
) -> Vec<std::net::Ipv4Addr> {
    let Some(lo_idx) = links.iter().find(|l| l.name == "lo").map(|l| l.ifindex) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in addrs {
        if a.ifindex != lo_idx || a.family != libc::AF_INET as u8 || a.prefix_len != 32 {
            continue;
        }
        if let Ok(ip) = a.address.parse::<std::net::Ipv4Addr>() {
            let [o0, o1, _, _] = ip.octets();
            if o0 == 10 && o1 == 254 && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out.sort();
    out
}

fn detect_loopback_mgmt_ipv4s() -> Vec<std::net::Ipv4Addr> {
    let (Ok(links), Ok(addrs)) = (netlink::list_links(), netlink::list_addrs()) else {
        return Vec::new();
    };
    extract_loopback_mgmt_ipv4s(&links, &addrs)
}

fn detect_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    netlink::get_iface_ipv4("br-lan").or_else(|| {
        uci::uci_get_blocking("network.lan.ipaddr")
            .and_then(|s| s.trim().parse::<std::net::Ipv4Addr>().ok())
    })
}

fn resolve_listen_addrs(
    env_key: &str,
    detected_lan: Option<std::net::Ipv4Addr>,
    loopback_mgmt: &[std::net::Ipv4Addr],
    port: u16,
) -> Vec<SocketAddr> {
    if let Ok(raw) = env::var(env_key) {
        let parsed = parse_addrs(&raw);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    format_listen_addrs_with_extra(detected_lan, loopback_mgmt, port)
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
        Some("overlay") => {
            let code = overlay::run_cli(&args[2..]);
            process::exit(code);
        }
        Some("firmware-flash") => {
            let code = firmware_ab::run_cli(&args[2..]);
            process::exit(code);
        }
        Some("acme") => {
            let code = acme::run_cli(&args[2..]);
            process::exit(code);
        }
        Some("security") => {
            let code = hardening::run_cli(&args[2..]);
            process::exit(code);
        }
        Some("reconcile") => {
            let report = run_boot_reconcile(true);
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            return;
        }
        Some("dataplane-restore") => {
            let code = dataplane::run_dataplane_restore_cli();
            process::exit(code);
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

    let (detected_lan, loopback_mgmt) =
        if env::var_os("QM_HTTPS_ADDR").is_some() && env::var_os("QM_HTTP_ADDR").is_some() {
            (None, Vec::new())
        } else {
            tokio::task::spawn_blocking(|| {
                let lan = detect_lan_ipv4_with_retry(
                    detect_lan_ipv4,
                    10,
                    std::time::Duration::from_millis(500),
                );
                let lo_mgmt = detect_loopback_mgmt_ipv4s();
                if lan.is_none() {
                    eprintln!(
                        "cellcored: br-lan IPv4 unavailable after boot wait; binding loopback/mgmt only (never 0.0.0.0)"
                    );
                }
                (lan, lo_mgmt)
            })
            .await
            .unwrap_or((None, Vec::new()))
        };
    let https_addrs = resolve_listen_addrs("QM_HTTPS_ADDR", detected_lan, &loopback_mgmt, 443);
    let http_addrs = resolve_listen_addrs("QM_HTTP_ADDR", detected_lan, &loopback_mgmt, 80);
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

    let data_usage = load_initial_data_usage();
    let speedtest_history = load_json_or_default(SPEEDTEST_HISTORY_PATH);
    let settings = load_settings_from_uci_and_disk();
    let initial_https_redirect = settings.https_redirect;
    let (init_bypassed, init_bypass_reason) = load_initial_cell_lock_bypass();

    let internals = SystemInternals {
        last_reconcile: Some(report),
        ..Default::default()
    };

    let init_hb = state::mono_ms();
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
        speedtest_cancel: Arc::new(Mutex::new(None)),
        antenna_align: Arc::new(RwLock::new(AntennaAlignState::default())),
        align_notify: Arc::new(tokio::sync::Notify::new()),
        phy_diag: Arc::new(RwLock::new(Default::default())),
        dsp_telemetry: Arc::new(RwLock::new(Default::default())),
        tls_cert_info: Arc::new(RwLock::new(Default::default())),
        tuning_cache: Arc::new(RwLock::new(None)),
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
        cell_lock_bypassed: Arc::new(std::sync::atomic::AtomicBool::new(init_bypassed)),
        cell_lock_bypass_reason: Arc::new(std::sync::atomic::AtomicU8::new(init_bypass_reason.to_u8())),
        recovery_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        https_redirect_cached: Arc::new(std::sync::atomic::AtomicBool::new(initial_https_redirect)),
        hb_rf_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
        hb_net_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
        hb_linkwatch_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
        hb_http_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_hb)),
        qscan_started_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        phy_diag_updated_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        dsp_telemetry_updated_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        process_rss_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        process_open_fds: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        last_sim_slot: Arc::new(std::sync::atomic::AtomicI32::new(0)),
        sim_switched_at_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sched_boot_checked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        spn_cache: Arc::new(RwLock::new((String::new(), String::new(), String::new()))),
        ab_flash: Arc::new(firmware_ab::AbFlashState::new()),
    };
    state.audit.spawn_flusher();

    state.push_daemon_log(format!("cellcored v{} started", state.version));
    obs::start(&state);
    vpn::start(&state);
    dataplane::start(&state);
    acme::spawn_renewal_task();
    firmware_ab::spawn_boot_auto_confirm(state.clone());
    hardening::spawn_dropbear_boot_watchdog(state.clone());
    spawn_background_tasks(state.clone(), rf_refresh_rx);
    spawn_liveness_watchdog(&state);
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
    dataplane::shutdown_cleanly(&state).await;
    flush_persistent_state(&state).await;
    state.push_daemon_log("cellcored shutting down cleanly");
    state.audit.flush_now();
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
        assert_eq!(env!("CARGO_PKG_VERSION"), "1.9.1");
    }

    #[test]
    fn dynamic_listen_addrs_never_falls_back_to_wildcard() {
        use std::net::{Ipv4Addr, SocketAddr};
        assert_eq!(
            super::format_listen_addrs(Some(Ipv4Addr::new(192, 168, 1, 1)), 443),
            vec![
                SocketAddr::from(([192, 168, 1, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ]
        );
        // When br-lan is unavailable (None, loopback, or 0.0.0.0), bind ONLY loopback/mgmt, NEVER 0.0.0.0.
        assert_eq!(
            super::format_listen_addrs(None, 443),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))]
        );
        assert_eq!(
            super::format_listen_addrs(Some(Ipv4Addr::new(127, 0, 0, 1)), 80),
            vec![SocketAddr::from(([127, 0, 0, 1], 80))]
        );
        assert_eq!(
            super::format_listen_addrs(Some(Ipv4Addr::UNSPECIFIED), 443),
            vec![SocketAddr::from(([127, 0, 0, 1], 443))]
        );
        assert_eq!(
            super::format_listen_addrs_with_extra(
                None,
                &[Ipv4Addr::new(10, 254, 224, 1), Ipv4Addr::UNSPECIFIED],
                443,
            ),
            vec![
                SocketAddr::from(([127, 0, 0, 1], 443)),
                SocketAddr::from(([10, 254, 224, 1], 443)),
            ]
        );
        assert_eq!(
            super::format_listen_addrs_with_extra(
                Some(Ipv4Addr::new(192, 168, 224, 1)),
                &[Ipv4Addr::new(10, 254, 224, 1), Ipv4Addr::new(10, 254, 228, 1)],
                443,
            ),
            vec![
                SocketAddr::from(([192, 168, 224, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
                SocketAddr::from(([10, 254, 224, 1], 443)),
                SocketAddr::from(([10, 254, 228, 1], 443)),
            ]
        );
    }

    #[test]
    fn detect_lan_ipv4_retries_briefly_until_available() {
        use std::net::Ipv4Addr;
        let mut calls = 0usize;
        let ip = super::detect_lan_ipv4_with_retry(
            || {
                calls += 1;
                if calls < 3 {
                    None
                } else {
                    Some(Ipv4Addr::new(192, 168, 224, 1))
                }
            },
            5,
            std::time::Duration::from_millis(1),
        );
        assert_eq!(ip, Some(Ipv4Addr::new(192, 168, 224, 1)));
        assert_eq!(calls, 3);

        let mut miss_calls = 0usize;
        let none = super::detect_lan_ipv4_with_retry(
            || {
                miss_calls += 1;
                Some(Ipv4Addr::UNSPECIFIED)
            },
            3,
            std::time::Duration::from_millis(1),
        );
        assert_eq!(none, None);
        assert_eq!(miss_calls, 3);
    }

    #[test]
    fn extracts_only_10_254_slash_32_loopback_mgmt_ips() {
        use std::net::Ipv4Addr;
        let links = vec![
            crate::netlink::NetlinkLink {
                ifindex: 1,
                name: "lo".into(),
                up: true,
                lower_up: true,
                mtu: 65536,
                kind: None,
                rmnet_mux_id: None,
                master_index: None,
            },
            crate::netlink::NetlinkLink {
                ifindex: 2,
                name: "br-lan".into(),
                up: true,
                lower_up: true,
                mtu: 1500,
                kind: None,
                rmnet_mux_id: None,
                master_index: None,
            },
        ];
        let addrs = vec![
            crate::netlink::NetlinkAddr {
                ifindex: 1,
                family: libc::AF_INET as u8,
                address: "127.0.0.1".into(),
                prefix_len: 8,
                scope: 254,
            },
            crate::netlink::NetlinkAddr {
                ifindex: 1,
                family: libc::AF_INET as u8,
                address: "10.254.228.1".into(),
                prefix_len: 32,
                scope: 0,
            },
            crate::netlink::NetlinkAddr {
                ifindex: 1,
                family: libc::AF_INET as u8,
                address: "10.254.224.1".into(),
                prefix_len: 32,
                scope: 0,
            },
            crate::netlink::NetlinkAddr {
                ifindex: 1,
                family: libc::AF_INET as u8,
                address: "10.254.1.1".into(),
                prefix_len: 24,
                scope: 0,
            },
            crate::netlink::NetlinkAddr {
                ifindex: 2,
                family: libc::AF_INET as u8,
                address: "10.254.99.1".into(),
                prefix_len: 32,
                scope: 0,
            },
        ];
        assert_eq!(
            super::extract_loopback_mgmt_ipv4s(&links, &addrs),
            vec![Ipv4Addr::new(10, 254, 224, 1), Ipv4Addr::new(10, 254, 228, 1)]
        );
    }
}

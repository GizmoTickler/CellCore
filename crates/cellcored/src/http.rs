use std::{
    fs,
    io::BufReader,
    net::SocketAddr,
    os::fd::FromRawFd,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        ConnectInfo, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    net::TcpListener,
    sync::RwLock,
};
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::services::{ServeDir, ServeFile};

use crate::{handlers, state::AppState};

pub type ProxyClient = Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct HttpCtx {
    pub app: AppState,
    pub proxy: ProxyClient,
    pub enforce_uhttpd_loopback: bool,
}

pub async fn serve_http_and_https(
    state: AppState,
    https_addrs: Vec<SocketAddr>,
    http_addrs: Vec<SocketAddr>,
    enforce_uhttpd_loopback: bool,
) -> Result<(), String> {
    let proxy: ProxyClient = Client::builder(TokioExecutor::new()).build_http();
    let ctx = HttpCtx {
        app: state.clone(),
        proxy,
        enforce_uhttpd_loopback,
    };

    let lan_ip_str = https_addrs
        .iter()
        .find(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())
        .map(|a| a.ip().to_string());
    let (cert_path, key_path) = ensure_tls_pair(&TLS_SOURCES, lan_ip_str.as_deref())?;
    let tls_cfg = Arc::new(RwLock::new(Arc::new(load_tls_config(&cert_path, &key_path)?)));

    // Hot-reload TLS on ACME renewal: re-resolve the pair every tick (so an
    // ACME cert issued after boot is picked up) and reload when the chosen
    // pair or either file's mtime/size changes (key-only rotations too).
    // Also heals a pre-NTP 1970 self-signed certificate once wall clock syncs.
    let tls_watch = Arc::clone(&tls_cfg);
    let hb_http_watch = Arc::clone(&state.hb_http_ms);
    let lan_ip_watch = lan_ip_str.clone();
    tokio::spawn(async move {
        let mut last = tls_fingerprint(&cert_path, &key_path);
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            hb_http_watch.store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
            let lan_clone = lan_ip_watch.clone();
            let _ = tokio::task::spawn_blocking(move || {
                check_and_heal_self_signed_cert(
                    &TLS_SOURCES,
                    crate::auth::now_secs(),
                    lan_clone.as_deref(),
                )
            })
            .await;
            let (cp, kp) = resolve_tls_pair(&TLS_SOURCES);
            let cur = tls_fingerprint(&cp, &kp);
            if cur != last {
                match load_tls_config(&cp, &kp) {
                    Ok(new_cfg) => {
                        *tls_watch.write().await = Arc::new(new_cfg);
                        last = cur;
                    }
                    Err(e) => {
                        eprintln!(
                            "cellcored: TLS pair ({}, {}) invalid/mismatched ({e}); falling back to self-signed",
                            cp.display(),
                            kp.display()
                        );
                        let lan_fb = lan_ip_watch.clone();
                        let fb_res = tokio::task::spawn_blocking(move || {
                            ensure_self_signed_fallback(&TLS_SOURCES, lan_fb.as_deref())
                        })
                        .await;
                        if let Ok(Ok((fb_c, fb_k))) = fb_res
                            && let Ok(fb_cfg) = load_tls_config(&fb_c, &fb_k)
                        {
                            *tls_watch.write().await = Arc::new(fb_cfg);
                            last = cur;
                        }
                    }
                }
            }
        }
    });

    // Periodically prune expired auth sessions
    let auth_prune = state.auth.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(120)).await;
            auth_prune.prune_expired().await;
        }
    });

    let router = build_router(ctx.clone());

    let limits = ConnLimits::default();
    let slots = Arc::new(ConnTracker::new(limits));
    let fallback_host = Arc::new(
        https_addrs
            .iter()
            .find(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "localhost".to_string()),
    );

    for addr in https_addrs {
        let listener = bind_tcp_freebind(addr)?;
        let r = router.clone();
        let tls_ref = Arc::clone(&tls_cfg);
        let slots = Arc::clone(&slots);
        tokio::spawn(accept_loop(listener, slots, move |stream, peer, permit| {
            let srv = r.clone();
            let tls_ref = Arc::clone(&tls_ref);
            async move {
                let _permit = permit;
                let acceptor = TlsAcceptor::from(Arc::clone(&*tls_ref.read().await));
                if let Ok(Ok(tls_stream)) = tokio::time::timeout(limits.handshake, acceptor.accept(stream)).await {
                    let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    serve_connection_with(tls_stream, srv, peer, limits, is_h2).await;
                }
            }
        }));
    }

    let redirect_router = {
        let fb = Arc::clone(&fallback_host);
        Router::new()
            .route("/.well-known/acme-challenge/{token}", get(acme_http01_handler))
            .fallback(move |req: Request| {
                let fb = Arc::clone(&fb);
                async move { http_redirect_handler(req, &fb).await }
            })
    };

    for addr in http_addrs {
        let listener = bind_tcp_freebind(addr)?;
        let redir_flag = Arc::clone(&state.https_redirect_cached);
        let r_redir = redirect_router.clone();
        let srv_fallback = router.clone();
        let slots = Arc::clone(&slots);
        tokio::spawn(accept_loop(listener, slots, move |stream, peer, permit| {
            let redir_flag = Arc::clone(&redir_flag);
            let r_redir = r_redir.clone();
            let r_fb = srv_fallback.clone();
            async move {
                let _permit = permit;
                if redir_flag.load(std::sync::atomic::Ordering::Acquire) {
                    serve_connection_with(stream, r_redir, peer, limits, false).await;
                } else {
                    serve_connection_with(stream, r_fb, peer, limits, false).await;
                }
            }
        }));
    }

    Ok(())
}

/// Bounds that keep idle or slow clients from exhausting file descriptors.
#[derive(Clone, Copy, Debug)]
pub struct ConnLimits {
    /// Concurrent client connections across all listeners.
    pub max_conns: usize,
    /// Concurrent connections from one client IP.
    pub max_per_ip: usize,
    /// The last `reserved` global slots only go to IPs holding fewer than
    /// `light_client` connections, so a browser can still reach the UI while
    /// heavy clients have filled the rest.
    pub reserved: usize,
    pub light_client: usize,
    /// TLS handshake must complete within this.
    pub handshake: Duration,
    /// Request headers (incl. on idle keep-alive connections) within this.
    pub header_read: Duration,
    /// HTTP/2 PING keepalive interval.
    pub h2_keep_alive_interval: Duration,
    /// HTTP/2 PING ack timeout before closing dead peers.
    pub h2_keep_alive_timeout: Duration,
    /// Maximum time an HTTP/2 connection may sit with zero in-flight requests.
    pub h2_idle_timeout: Duration,
    /// Maximum concurrent HTTP/2 streams per connection.
    pub h2_max_concurrent_streams: u32,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            max_conns: 192,
            max_per_ip: 32,
            reserved: 24,
            light_client: 4,
            handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(15),
            h2_keep_alive_interval: Duration::from_secs(20),
            h2_keep_alive_timeout: Duration::from_secs(10),
            h2_idle_timeout: Duration::from_secs(60),
            h2_max_concurrent_streams: 64,
        }
    }
}

/// Global + per-IP connection accounting with reserved slots for light clients.
pub struct ConnTracker {
    limits: ConnLimits,
    inner: std::sync::Mutex<(usize, std::collections::HashMap<std::net::IpAddr, usize>)>,
}

pub struct ConnGuard {
    tracker: Arc<ConnTracker>,
    ip: std::net::IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut g = self.tracker.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 = g.0.saturating_sub(1);
        if let Some(c) = g.1.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                g.1.remove(&self.ip);
            }
        }
    }
}

impl ConnTracker {
    pub fn new(limits: ConnLimits) -> Self {
        Self {
            limits,
            inner: std::sync::Mutex::new((0, std::collections::HashMap::new())),
        }
    }

    pub fn try_admit(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<ConnGuard> {
        let l = self.limits;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mine = g.1.get(&ip).copied().unwrap_or(0);
        if g.0 >= l.max_conns || mine >= l.max_per_ip {
            return None;
        }
        if g.0 >= l.max_conns.saturating_sub(l.reserved) && mine >= l.light_client {
            return None;
        }
        g.0 += 1;
        *g.1.entry(ip).or_insert(0) += 1;
        Some(ConnGuard {
            tracker: Arc::clone(self),
            ip,
        })
    }
}

/// Accept connections under the global/per-IP caps (refused connections are
/// closed at once) and back off on accept errors such as EMFILE instead of
/// spinning.
pub async fn accept_loop<F, Fut>(listener: TcpListener, slots: Arc<ConnTracker>, handle: F)
where
    F: Fn(tokio::net::TcpStream, SocketAddr, ConnGuard) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                match slots.try_admit(peer.ip()) {
                    Some(guard) => {
                        tokio::spawn(handle(stream, peer, guard));
                    }
                    None => drop(stream),
                }
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn serve_connection_with<S>(io: S, router: Router, peer: SocketAddr, limits: ConnLimits, h2: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let hyper_io = TokioIo::new(io);
    if h2 {
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(crate::state::mono_ms()));
        struct InFlightGuard {
            in_flight: Arc<std::sync::atomic::AtomicUsize>,
            last_activity: Arc<std::sync::atomic::AtomicU64>,
        }
        impl Drop for InFlightGuard {
            fn drop(&mut self) {
                self.last_activity
                    .store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
                self.in_flight.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let in_flight_svc = Arc::clone(&in_flight);
        let last_act_svc = Arc::clone(&last_activity);
        let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            let mut r = router.clone();
            in_flight_svc.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            last_act_svc.store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
            let guard = InFlightGuard {
                in_flight: Arc::clone(&in_flight_svc),
                last_activity: Arc::clone(&last_act_svc),
            };
            async move {
                let _guard = guard;
                let axum_req = req.map(Body::new);
                r.call(axum_req).await
            }
        });
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(limits.h2_keep_alive_interval))
            .keep_alive_timeout(limits.h2_keep_alive_timeout)
            .max_concurrent_streams(limits.h2_max_concurrent_streams);
        let mut conn = std::pin::pin!(builder.serve_connection(hyper_io, svc));
        let idle_ms = limits.h2_idle_timeout.as_millis() as u64;
        let tick_dur = (limits.h2_idle_timeout / 2).clamp(Duration::from_millis(50), Duration::from_secs(5));
        let mut tick = tokio::time::interval(tick_dur);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = conn.as_mut() => break,
                _ = tick.tick() => {
                    if in_flight.load(std::sync::atomic::Ordering::Acquire) == 0
                        && crate::state::mono_ms()
                            .saturating_sub(last_activity.load(std::sync::atomic::Ordering::Acquire))
                            >= idle_ms
                    {
                        conn.as_mut().graceful_shutdown();
                        let _ = tokio::time::timeout(Duration::from_secs(2), conn.as_mut()).await;
                        break;
                    }
                }
            }
        }
    } else {
        let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            let mut r = router.clone();
            async move {
                let axum_req = req.map(Body::new);
                r.call(axum_req).await
            }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder.timer(TokioTimer::new()).header_read_timeout(limits.header_read);
        let _ = builder.serve_connection(hyper_io, svc).with_upgrades().await;
    }
}

async fn acme_http01_handler(axum::extract::Path(token): axum::extract::Path<String>) -> Response {
    match crate::acme::lookup_http01_token(&token).await {
        Some(key_auth) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            key_auth,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Extract and validate the host component (without port) from an HTTP `Host`
/// header or URI authority for HTTPS redirect construction. Handles bracketed
/// IPv6 literals (`[fd00::1]:80` -> `[fd00::1]`) and rejects `@`, path,
/// whitespace, control, or malformed-port injections by falling back safely.
pub(crate) fn sanitize_redirect_host(raw: Option<&str>, fallback_host: &str) -> String {
    let fallback = || {
        if fallback_host.contains(':') && !fallback_host.starts_with('[') {
            format!("[{fallback_host}]")
        } else {
            fallback_host.to_string()
        }
    };
    let Some(host) = raw else {
        return fallback();
    };
    if host.is_empty()
        || host.len() > 260
        || host
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#'))
    {
        return fallback();
    }
    if host.starts_with('[') {
        let Some(close) = host.find(']') else {
            return fallback();
        };
        let inner = &host[1..close];
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return fallback();
        }
        let rest = &host[close + 1..];
        if !rest.is_empty() {
            let Some(port_s) = rest.strip_prefix(':') else {
                return fallback();
            };
            if port_s.is_empty()
                || !port_s.bytes().all(|b| b.is_ascii_digit())
                || port_s.parse::<u16>().is_err()
            {
                return fallback();
            }
        }
        return host[..=close].to_string();
    }
    let (h, port_opt) = match host.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host, None),
    };
    if let Some(p) = port_opt
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err())
    {
        return fallback();
    }
    if h.is_empty()
        || h.len() > 253
        || h.starts_with(['.', '-'])
        || h.ends_with(['.', '-'])
        || h.contains("..")
        || !h
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return fallback();
    }
    h.to_string()
}

async fn http_redirect_handler(req: Request, fallback_host: &str) -> Response {
    let raw_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()));
    let safe_host = sanitize_redirect_host(raw_host, fallback_host);
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .filter(|p| p.starts_with('/') && !p.bytes().any(|b| b.is_ascii_control()))
        .unwrap_or("/");
    let target = format!("https://{safe_host}{path_q}");
    let safe_fb = sanitize_redirect_host(None, fallback_host);
    let fallback_url = HeaderValue::from_str(&format!("https://{safe_fb}/"))
        .unwrap_or_else(|_| HeaderValue::from_static("https://localhost/"));
    (
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, HeaderValue::from_str(&target).unwrap_or(fallback_url))],
        "",
    )
        .into_response()
}

pub(crate) fn build_router(ctx: HttpCtx) -> Router {
    let www = &ctx.app.www_dir;
    let index_file = if www.join("index.html").exists() {
        www.join("index.html")
    } else {
        www.join("login.html")
    };

    let protected = Router::new()
        .route("/api/v1/bootstrap", get(handlers::get_bootstrap))
        .route("/api/v1/ws", get(ws_upgrade_handler))
        .route("/api/v1/modem/refresh", post(handlers::post_modem_refresh))
        .route("/api/v1/modem/at", post(handlers::post_modem_at))
        .route("/api/v1/modem/secrets", get(handlers::get_modem_secrets))
        .route("/api/v1/modem/imei", post(handlers::post_modem_imei))
        .route("/api/v1/cellular/profiles", get(handlers::get_profiles).post(handlers::post_profile).delete(handlers::delete_profile))
        .route("/api/v1/cellular/profiles/pause", post(handlers::post_profile_pause))
        .route("/api/v1/cellular/mbn", post(handlers::post_mbn))
        .route("/api/v1/cellular/bands", get(handlers::get_bands).post(handlers::post_bands))
        .route("/api/v1/cellular/mode", get(handlers::get_mode).post(handlers::post_mode))
        .route("/api/v1/cellular/cell-lock", get(handlers::get_cell_lock).post(handlers::post_cell_lock).delete(handlers::delete_cell_lock))
        .route("/api/v1/cellular/scan", get(handlers::get_cell_scan).post(handlers::post_cell_scan).delete(handlers::delete_cell_scan))
        .route("/api/v1/cellular/align", get(handlers::get_antenna_align).post(handlers::post_antenna_align))
        .route("/api/v1/cellular/tower-finder", get(crate::tower_finder::get_tower_finder).put(crate::tower_finder::put_tower_finder))
        .route("/api/v1/cellular/tower-finder/lookup", post(crate::tower_finder::post_tower_lookup))
        .route("/api/v1/cellular/tuning", get(crate::radio_tuning::get_tuning).post(crate::radio_tuning::post_tuning))
        .route("/api/v1/cellular/dsp", get(crate::qmi::dsp::get_dsp_telemetry))
        .route("/api/v1/network/lan", get(handlers::get_network_lan).post(handlers::post_network_lan))
        .route("/api/v1/network/data-usage", get(handlers::get_data_usage).post(handlers::post_data_usage).delete(handlers::delete_data_usage))
        .route("/api/v1/diagnostics/health", get(handlers::get_health))
        .route("/api/v1/diagnostics/linkwatch", get(handlers::get_quecwatch).post(handlers::post_quecwatch))
        .route("/api/v1/diagnostics/quecwatch", get(handlers::get_quecwatch).post(handlers::post_quecwatch))
        .route("/api/v1/diagnostics/latency", get(handlers::get_latency).post(handlers::post_latency))
        .route("/api/v1/speedtest/servers", get(handlers::get_speedtest_servers))
        .route("/api/v1/speedtest/start", post(handlers::post_speedtest_start))
        .route("/api/v1/speedtest/stop", post(handlers::post_speedtest_stop))
        .route("/api/v1/speedtest/history", get(handlers::get_speedtest_history).delete(handlers::delete_speedtest_history))
        .route("/api/v1/sms", get(handlers::get_sms_inbox).post(handlers::post_sms_send).delete(handlers::delete_sms))
        .route("/api/v1/system/internals", get(handlers::get_system_internals))
        .route("/api/v1/system/usb-gadget", post(handlers::post_usb_gadget))
        .route("/api/v1/system/reconcile", post(handlers::post_reconcile))
        .route("/api/v1/system/logs", get(handlers::get_logs))
        .route("/api/v1/system/maintenance", get(handlers::get_maintenance).post(handlers::post_maintenance))
        .route("/api/v1/system/reboot", post(handlers::post_reboot))
        .route("/api/v1/system/ota", get(handlers::get_ota).post(handlers::post_ota))
        .route("/api/v1/system/firmware-ab", get(crate::firmware_ab::get_firmware_ab))
        .route("/api/v1/system/firmware-ab/staged", get(crate::firmware_ab::get_firmware_ab_staged))
        .route(
            "/api/v1/system/firmware-ab/upload",
            post(crate::firmware_ab::post_firmware_ab_upload)
                .layer(axum::extract::DefaultBodyLimit::max(260 * 1024 * 1024)),
        )
        .route("/api/v1/system/firmware-ab/inspect", post(crate::firmware_ab::post_firmware_ab_inspect))
        .route("/api/v1/system/firmware-ab/flash", post(crate::firmware_ab::post_firmware_ab_flash))
        .route("/api/v1/system/firmware-ab/switch", post(crate::firmware_ab::post_firmware_ab_switch))
        .route("/api/v1/system/firmware-ab/confirm", post(crate::firmware_ab::post_firmware_ab_confirm))
        .route("/api/v1/system/settings", get(handlers::get_settings).post(handlers::post_settings))
        .route("/api/v1/system/acme", get(crate::acme::get_acme).put(crate::acme::put_acme).delete(crate::acme::delete_acme))
        .route("/api/v1/system/acme/issue", post(crate::acme::post_acme_issue))
        .route("/api/v1/security/audit", get(crate::hardening::get_security_audit))
        .route("/api/v1/security/harden", post(crate::hardening::post_security_harden))
        .route("/api/v1/system/password", post(handlers::post_change_password))
        .route("/api/v1/auth/logout", post(handlers::post_logout))
        .merge(crate::admin::routes())
        .merge(crate::secroutes::routes())
        .merge(crate::vpn::routes())
        .merge(crate::dataplane::routes())
        .merge(crate::obs::routes())
        .merge(crate::obs::metrics_routes())
        // order (outer -> inner): auth -> audit -> failover guard -> handler.
        // The guard is inside auth: disruptive calls need force:true while
        // carrying failover traffic; the audit layer records its refusals too.
        .route_layer(middleware::from_fn(crate::obs::failover::guard_middleware))
        .route_layer(middleware::from_fn_with_state(ctx.clone(), audit_middleware))
        .route_layer(middleware::from_fn_with_state(ctx.clone(), auth_middleware));

    let public = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_http01_handler))
        .route(
            "/api/v1/auth/status",
            get(handlers::get_auth_status).layer(middleware::from_fn(auth_status_origin_guard)),
        )
        .route(
            "/api/v1/auth/login",
            post(handlers::post_login).layer(axum::extract::DefaultBodyLimit::max(LOGIN_MAX_BODY)),
        )
        .route("/api/v1/public/preview", get(handlers::get_public_preview));

    let proxy_routes = Router::new()
        .route("/cgi-bin/luci", axum::routing::any(luci_proxy_handler))
        .route("/cgi-bin/luci/", axum::routing::any(luci_proxy_handler))
        .route("/ubus/", axum::routing::any(luci_proxy_handler))
        .route("/cgi-bin/luci/{*rest}", axum::routing::any(luci_proxy_handler))
        .route("/luci-static/{*rest}", axum::routing::any(luci_proxy_handler))
        .route("/ubus", axum::routing::any(luci_proxy_handler))
        .route("/ubus/{*rest}", axum::routing::any(luci_proxy_handler))
        // LuCI/rpcd are only reachable through a CellCore session: the
        // throttled QM login is the single front door to the root password.
        .route_layer(middleware::from_fn_with_state(ctx.clone(), proxy_auth_middleware));

    let static_svc = tower::ServiceBuilder::new()
        .layer(middleware::from_fn(static_path_guard))
        .service(
            ServeDir::new(www)
                .precompressed_br()
                .precompressed_gzip()
                .not_found_service(ServeFile::new(index_file)),
        );

    Router::new()
        .merge(public)
        .merge(protected)
        .merge(proxy_routes)
        .fallback_service(static_svc)
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(middleware::from_fn(body_deadline_middleware))
        .layer(middleware::from_fn_with_state(ctx.clone(), security_headers_middleware))
        .with_state(ctx)
}

async fn security_headers_middleware(State(ctx): State<HttpCtx>, req: Request, next: Next) -> Response {
    ctx.app
        .hb_http_ms
        .store(crate::state::mono_ms(), std::sync::atomic::Ordering::Release);
    let path = req.uri().path().to_string();
    let hsts = ctx
        .app
        .https_redirect_cached
        .load(std::sync::atomic::Ordering::Acquire);
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if path.starts_with("/cgi-bin/luci") || path.starts_with("/luci-static/") {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        headers.insert(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            ),
        );
    } else {
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://server.arcgisonline.com https://services.arcgisonline.com; font-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            ),
        );
    }
    if hsts {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if path.starts_with("/assets/") {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else if !path.starts_with("/luci-static/") {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
    }
    resp
}

pub fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let t = auth_val.trim();
        let tok = t
            .strip_prefix("Bearer ")
            .or_else(|| t.strip_prefix("bearer "))
            .unwrap_or(t)
            .trim();
        if crate::auth::is_valid_token_syntax(tok) {
            return Some(tok.to_string());
        }
    }
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            let trimmed = part.trim();
            if let Some(val) = trimmed.strip_prefix("qm_session=") {
                let tok = val.trim();
                if crate::auth::is_valid_token_syntax(tok) {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

/// Who made an authenticated request; inserted into the request extensions
/// by `auth_middleware` (read by the audit layer and by handlers).
#[derive(Debug, Clone)]
pub struct AuthCtx {
    /// `None` = interactive session, `Some` = API token.
    pub token: Option<crate::tokens::TokenAuth>,
    pub peer: Option<std::net::IpAddr>,
}

impl AuthCtx {
    pub fn kind(&self) -> &'static str {
        if self.token.is_some() { "token" } else { "session" }
    }
}

/// The raw `Authorization: Bearer` value, if any.
fn bearer_value(headers: &axum::http::HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    Some(v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")).unwrap_or(v).trim())
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "status": "error", "error": msg }))).into_response()
}

fn peer_ip(req: &Request) -> Option<std::net::IpAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())
}

fn is_mutating(m: &Method) -> bool {
    matches!(*m, Method::POST | Method::PUT | Method::DELETE | Method::PATCH)
}

async fn auth_middleware(State(ctx): State<HttpCtx>, mut req: Request, next: Next) -> Response {
    let peer = peer_ip(&req);

    // API token: `Authorization: Bearer qmt_...`. Decided by the prefix alone,
    // so a token never falls back to (or is mistaken for) a session.
    if let Some(b) = bearer_value(req.headers())
        && b.starts_with(crate::tokens::TOKEN_PREFIX)
    {
        let ip = peer.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let route = req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| req.uri().path().to_string());
        let auth = match ctx.app.tokens.authenticate(b, ip) {
            Ok(a) => a,
            Err(crate::tokens::TokenError::RateLimited) => {
                return json_err(StatusCode::TOO_MANY_REQUESTS, "Too many failed token attempts. Retry in 60s.");
            }
            Err(e) => {
                // Aggregated per peer, outside the entry ring: unauthenticated
                // traffic cannot flush real audit records.
                ctx.app.audit.auth_failure(&ip.to_string(), &route);
                return json_err(
                    StatusCode::UNAUTHORIZED,
                    if e == crate::tokens::TokenError::Expired { "API token expired" } else { "Invalid API token" },
                );
            }
        };
        // Typed confirmations and the failover guard's force:true apply to
        // tokens exactly as to a browser (they are payload fields).
        if let Err(why) = crate::tokens::token_may_access(auth.kind, req.method(), &route, req.uri().query()) {
            return json_err(StatusCode::FORBIDDEN, why);
        }
        // Not cookie-borne, so no CSRF header is required.
        req.extensions_mut().insert(AuthCtx { token: Some(auth), peer });
        return next.run(req).await;
    }

    let ws_query_tok = if req.uri().path() == "/api/v1/ws" {
        ws_query_token(req.uri())
    } else {
        None
    };

    let Some(token) = extract_session_token(req.headers()).or(ws_query_tok) else {
        return json_err(StatusCode::UNAUTHORIZED, "Unauthorized");
    };
    let Some(session) = ctx.app.auth.validate_token(&token, true).await else {
        return json_err(StatusCode::UNAUTHORIZED, "Session expired");
    };

    // CSRF on state-changing requests unless the session token itself was
    // sent in the Authorization header (which a cross-site page cannot set).
    let header_borne = bearer_value(req.headers()).is_some_and(|b| b == token);
    if is_mutating(req.method()) && !header_borne {
        let csrf = req
            .headers()
            .get("x-qm-csrf")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !crate::auth::constant_time_eq(csrf, &session.csrf_token) {
            return json_err(StatusCode::FORBIDDEN, "CSRF check failed");
        }
    }

    req.extensions_mut().insert(AuthCtx { token: None, peer });
    next.run(req).await
}

/// Records every mutating request on the protected router (inside auth, so
/// the caller is known). The JSON body is read (bounded), summarised with
/// redaction and handed on unchanged.
async fn audit_middleware(State(ctx): State<HttpCtx>, req: Request, next: Next) -> Response {
    if !is_mutating(req.method()) {
        // Token reads are audited as per-token counters (a monitoring token
        // polling every few seconds must not flood the entry ring).
        let tok = req.extensions().get::<AuthCtx>().and_then(|a| a.token.as_ref().map(|t| (t.name.clone(), a.peer)));
        let route = req.extensions().get::<axum::extract::MatchedPath>().map(|m| m.as_str().to_string());
        let resp = next.run(req).await;
        if let (Some((name, peer)), Some(route)) = (tok, route) {
            let peer = peer.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
            ctx.app.audit.token_read(&name, &route, &peer, resp.status().as_u16());
        }
        return resp;
    }
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".into());
    let who = req.extensions().get::<AuthCtx>().cloned();
    let peer = who
        .as_ref()
        .and_then(|a| a.peer)
        .or_else(|| peer_ip(&req))
        .map(|i| i.to_string())
        .unwrap_or_else(|| "-".into());
    let query = req.uri().query().map(crate::audit::summarize_query).unwrap_or_default();
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let capture = ct.as_deref().is_some_and(|c| c.to_ascii_lowercase().contains("json"))
        && declared.is_some_and(|n| n as usize <= crate::audit::MAX_CAPTURE);
    let (parts, body) = req.into_parts();
    let (body_summary, body) = if capture {
        match axum::body::to_bytes(body, crate::audit::MAX_CAPTURE).await {
            Ok(b) => (crate::audit::summarize_body(ct.as_deref(), Some(&b), declared), Body::from(b)),
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "Request body unreadable or too slow"),
        }
    } else {
        (crate::audit::summarize_body(ct.as_deref(), None, declared), body)
    };
    let resp = next.run(Request::from_parts(parts, body)).await;
    let note = resp.extensions().get::<crate::audit::AuditNote>().map(|n| n.0.clone());
    let mut summary = [query, body_summary, note.unwrap_or_default()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if summary.is_empty() {
        summary.push('-');
    }
    ctx.app.audit.record(crate::audit::NewEntry {
        kind: "http",
        method: &method,
        route: &route,
        status: resp.status().as_u16(),
        peer: &peer,
        auth: who.as_ref().map(|a| a.kind()).unwrap_or("session"),
        token_name: who.as_ref().and_then(|a| a.token.as_ref()).map(|t| t.name.as_str()),
        summary,
    });
    resp
}

fn ws_query_token(uri: &Uri) -> Option<String> {
    uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == "token" && crate::auth::is_valid_token_syntax(v) {
                Some(v.to_string())
            } else {
                None
            }
        })
    })
}

const WS_MAX_MESSAGE_SIZE: usize = 64 * 1024;
const WS_MAX_FRAME_SIZE: usize = 64 * 1024;

async fn ws_upgrade_handler(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    uri: Uri,
    ws: WebSocketUpgrade,
) -> Response {
    let token = extract_session_token(&headers).or_else(|| ws_query_token(&uri)).unwrap_or_default();
    ws.max_message_size(WS_MAX_MESSAGE_SIZE)
        .max_frame_size(WS_MAX_FRAME_SIZE)
        .on_upgrade(move |socket| handle_ws_socket(ctx.app, socket, token))
}

/// True while the WebSocket's session is still valid (not logged out,
/// revoked by a password change, or expired).
async fn ws_session_alive(state: &AppState, token: &str) -> bool {
    state.auth.validate_token(token, false).await.is_some()
}

const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_PONG_TIMEOUT: Duration = Duration::from_secs(90);

async fn handle_ws_socket(state: AppState, mut socket: WebSocket, token: String) {
    let mut rx = state.ws_tx.subscribe();
    let mut revoked = state.auth.subscribe_revocations();
    let mut expiry_check = tokio::time::interval(Duration::from_secs(60));
    expiry_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    expiry_check.tick().await;
    let mut ping_check = tokio::time::interval(WS_PING_INTERVAL);
    ping_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_check.tick().await;
    let mut last_pong = std::time::Instant::now();

    // Send immediate initial burst so client sees live state instantly
    let init_ping = state.ping_realtime.read().await.back().cloned();
    if let Some(p) = init_ping {
        let _ = socket
            .send(Message::Text(
                serde_json::json!({
                    "channel": "ping",
                    "timestamp": p.timestamp,
                    "host": p.host,
                    "latency": p.latency,
                    "packet_loss": p.packet_loss,
                    "ok": p.ok,
                })
                .to_string()
                .into(),
            ))
            .await;
    }

    loop {
        tokio::select! {
            _ = revoked.changed() => {
                if !ws_session_alive(&state, &token).await {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = expiry_check.tick() => {
                if !ws_session_alive(&state, &token).await {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = ping_check.tick() => {
                if last_pong.elapsed() >= WS_PONG_TIMEOUT {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                if socket.send(Message::Ping(axum::body::Bytes::new())).await.is_err() {
                    break;
                }
            }
            msg = rx.recv() => {
                match msg {
                    Ok(txt) => {
                        if socket.send(Message::Text(txt)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Text(txt))) => {
                        last_pong = std::time::Instant::now();
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt)
                            && v.get("action").and_then(|a| a.as_str()) == Some("set_fast_rf")
                        {
                            let en = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
                            let snap = {
                                let mut a = state.antenna_align.write().await;
                                a.active = en;
                                if en {
                                    a.expires_at = crate::auth::now_secs() + 300;
                                } else {
                                    a.keep_awake = false;
                                }
                                a.clone()
                            };
                            state.align_notify.notify_one();
                            state.broadcast_with(|| serde_json::json!({
                                "channel": "antenna_align",
                                "align": snap,
                            }));
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        last_pong = std::time::Instant::now();
                        let _ = socket.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {
                        last_pong = std::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                }
            }
        }
    }
}

/// Percent-decode each path segment. `None` for malformed escapes, NUL,
/// or a segment that decodes to `.`/`..` or contains a separator — i.e.
/// anything a downstream server might normalise into a different path.
pub fn safe_path_segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix('/')?;
    let mut out = Vec::new();
    for raw in rest.split('/') {
        let bytes = raw.as_bytes();
        let mut dec = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                dec.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            } else {
                dec.push(bytes[i]);
                i += 1;
            }
        }
        let seg = String::from_utf8(dec).ok()?;
        if seg == "." || seg == ".." || seg.contains(['/', '\\', '\0']) {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

/// Only the LuCI/ubus entry points may be proxied, and only via a clean path.
pub fn proxy_path_allowed(path: &str) -> bool {
    let Some(segs) = safe_path_segments(path) else {
        return false;
    };
    // empty interior segments ("//") are refused; a single trailing "/" is ok
    let interior = &segs[..segs.len().saturating_sub(1)];
    if interior.iter().any(|s| s.is_empty()) {
        return false;
    }
    match segs.as_slice() {
        [a, ..] if a == "ubus" => true,
        [a, b, ..] if a == "cgi-bin" && b == "luci" => true,
        [a, _, ..] if a == "luci-static" => true,
        _ => false,
    }
}

/// Static files: never serve anything under /cgi-bin (raw CGI sources) and
/// never anything with ambiguous/encoded traversal.
pub fn static_path_allowed(path: &str) -> bool {
    match safe_path_segments(path) {
        Some(segs) => !segs.first().is_some_and(|s| s.eq_ignore_ascii_case("cgi-bin")),
        None => false,
    }
}

/// Longest request path the static file service is asked about. The UI's own
/// paths are far shorter; anything longer is refused before the filesystem
/// sees it (ENAMETOOLONG would otherwise surface as a 500).
const STATIC_MAX_PATH: usize = 1024;
/// NAME_MAX: no file on the device can have a longer path component.
const STATIC_MAX_SEGMENT: usize = 255;

async fn static_path_guard(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.len() > STATIC_MAX_PATH {
        return StatusCode::URI_TOO_LONG.into_response();
    }
    if !static_path_allowed(path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if safe_path_segments(path).is_some_and(|segs| segs.iter().any(|s| s.len() > STATIC_MAX_SEGMENT)) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

/// Proxied /ubus JSON-RPC bodies are read up to this (after QM auth).
const UBUS_MAX_BODY: usize = 64 * 1024;
/// LuCI posts above this (sysupgrade images) are streamed with a longer deadline.
const LUCI_MAX_BUFFERED_BODY: usize = 64 * 1024;
const LUCI_MAX_STREAMED_BODY: u64 = 64 * 1024 * 1024;
/// /api/v1/auth/login only carries a password.
pub const LOGIN_MAX_BODY: usize = 4 * 1024;
const PROXY_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_DEADLINE: Duration = Duration::from_secs(15);
const BODY_DEADLINE_LARGE: Duration = Duration::from_secs(300);
const LUCI_UPSTREAM: &str = "127.0.0.1:8080";

#[cfg(test)]
static LUCI_UPSTREAM_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn luci_upstream() -> &'static str {
    #[cfg(test)]
    {
        if let Some(u) = LUCI_UPSTREAM_OVERRIDE.get() {
            return u.as_str();
        }
        static SEAM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        SEAM.get_or_init(|| std::env::var("QM_LUCI_UPSTREAM").unwrap_or_else(|_| LUCI_UPSTREAM.to_string()))
    }
    #[cfg(not(test))]
    {
        LUCI_UPSTREAM
    }
}

/// The CellCore session cookie only. An Authorization header on a proxied
/// request belongs to LuCI/ubus, so it is ignored here.
fn qm_cookie_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
        .find_map(|kv| {
            let v = kv.trim().strip_prefix("qm_session=")?.trim();
            crate::auth::is_valid_token_syntax(v).then(|| v.to_string())
        })
}

fn authority_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

/// CSRF for the proxy: LuCI's own requests cannot carry X-QM-CSRF, so
/// state-changing requests must come from this origin (Origin, else
/// Referer, must name the Host or HTTP/2 `:authority`). The QM cookie is
/// also SameSite=Strict.
pub fn same_origin_for(headers: &axum::http::HeaderMap, uri_authority: Option<&str>) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or(uri_authority)
    else {
        return false;
    };
    let src = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    src.and_then(authority_of).is_some_and(|a| a.eq_ignore_ascii_case(host))
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn same_origin_request(headers: &axum::http::HeaderMap) -> bool {
    same_origin_for(headers, None)
}

#[cfg(test)]
tokio::task_local! {
    static LUCI_PROXY_ENABLED_TEST_OVERRIDE: bool;
}

/// Same-origin LuCI reverse proxying is disabled by default to preserve strict
/// origin isolation between LuCI and the CellCore API/CSRF surface. Operators
/// who explicitly need legacy LuCI may opt in with `CELLCORE_ENABLE_LUCI_PROXY=1`.
pub fn luci_proxy_enabled() -> bool {
    #[cfg(test)]
    if let Ok(v) = LUCI_PROXY_ENABLED_TEST_OVERRIDE.try_with(|b| *b) {
        return v;
    }
    std::env::var("CELLCORE_ENABLE_LUCI_PROXY")
        .ok()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

/// Block requests to `/api/v1/auth/status` originating from proxied LuCI pages
/// so even when `CELLCORE_ENABLE_LUCI_PROXY=1` is opted in, LuCI-origin scripts
/// cannot harvest the CellCore CSRF token.
async fn auth_status_origin_guard(req: Request, next: Next) -> Response {
    if let Some(referer) = req.headers().get(header::REFERER).and_then(|v| v.to_str().ok()) {
        let lower = referer.to_ascii_lowercase();
        if lower.contains("/cgi-bin/luci") || lower.contains("/luci-static/") {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "LuCI origin may not access CellCore auth status"
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

async fn proxy_auth_middleware(State(ctx): State<HttpCtx>, req: Request, next: Next) -> Response {
    if !luci_proxy_enabled() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "status": "error",
                "error": "Same-origin LuCI proxy is disabled by default for origin isolation. Set CELLCORE_ENABLE_LUCI_PROXY=1 to enable."
            })),
        )
            .into_response();
    }
    let authed = match qm_cookie_token(req.headers()) {
        Some(tok) => ctx.app.auth.validate_token(&tok, true).await.is_some(),
        None => false,
    };
    if !authed {
        if req.method() == Method::GET && req.uri().path().starts_with("/cgi-bin/luci") {
            return (StatusCode::FOUND, [(header::LOCATION, HeaderValue::from_static("/#/login"))]).into_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "status": "error", "error": "CellCore login required" })),
        )
            .into_response();
    }
    let state_changing = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let uri_auth = req.uri().authority().map(|a| a.as_str().to_string());
    if state_changing && !same_origin_for(req.headers(), uri_auth.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "status": "error", "error": "Cross-origin request refused" })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Re-serialise a /ubus JSON body so rpcd executes exactly the value we
/// parsed (duplicate keys collapsed, one canonical encoding). Strings with
/// NUL are refused: C consumers would truncate them.
pub fn canonical_ubus_body(body: &[u8]) -> Result<Vec<u8>, &'static str> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| "Invalid JSON-RPC body")?;
    if !(v.is_object() || v.is_array()) {
        return Err("Invalid JSON-RPC body");
    }
    let out = serde_json::to_vec(&v).map_err(|_| "Invalid JSON-RPC body")?;
    if out.windows(6).any(|w| w == b"\\u0000") {
        return Err("NUL in JSON string");
    }
    Ok(out)
}

/// Wrap a request body so that reading it fails once `deadline` passes.
/// Nothing is buffered here; whoever reads the body (extractor, proxy) gets
/// an error instead of waiting on a slow client forever.
#[cfg(test)]
pub fn body_with_deadline(body: Body, deadline: tokio::time::Instant) -> Body {
    body_with_deadline_cell(body, BodyDeadline::new(deadline))
}

/// The body deadline of one request. It starts at the generic deadline and
/// can only be extended by a route layer that runs after authentication
/// (see [`upload_deadline_middleware`]).
#[derive(Clone)]
pub struct BodyDeadline {
    started: tokio::time::Instant,
    at: Arc<std::sync::Mutex<tokio::time::Instant>>,
}

impl BodyDeadline {
    pub fn new(at: tokio::time::Instant) -> Self {
        Self { started: tokio::time::Instant::now(), at: Arc::new(std::sync::Mutex::new(at)) }
    }
    pub fn get(&self) -> tokio::time::Instant {
        *self.at.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Move the deadline to `started + total` if that is later (never shortens it).
    pub fn extend_to(&self, total: Duration) {
        let want = self.started + total;
        let mut g = self.at.lock().unwrap_or_else(|p| p.into_inner());
        if want > *g {
            *g = want;
        }
    }
}

fn body_with_deadline_cell(body: Body, deadline: BodyDeadline) -> Body {
    let stream = futures_util::stream::unfold(Some(body.into_data_stream()), move |state| {
        let deadline = deadline.clone();
        async move {
            let mut s = state?;
            // Re-read per chunk: an authenticated upload route may have extended it.
            match tokio::time::timeout_at(deadline.get(), s.next()).await {
                Ok(Some(item)) => Some((item.map_err(axum::BoxError::from), Some(s))),
                Ok(None) => None,
                Err(_) => Some((Err(axum::BoxError::from("request body deadline exceeded")), None)),
            }
        }
    });
    Body::from_stream(stream)
}

/// Slowest upload rate a large-upload route must tolerate (~1 Mbit/s).
pub const UPLOAD_MIN_RATE_BYTES_PER_SEC: u64 = 128 * 1024;

/// Body deadline for an upload of `bytes`: the generic deadline plus the time
/// the body takes at [`UPLOAD_MIN_RATE_BYTES_PER_SEC`], capped at the large-upload deadline.
pub fn upload_body_deadline(bytes: u64) -> Duration {
    let transfer = Duration::from_secs(bytes.div_ceil(UPLOAD_MIN_RATE_BYTES_PER_SEC));
    (BODY_DEADLINE + transfer).min(BODY_DEADLINE_LARGE)
}

/// Route layer for authenticated upload routes (admin backup inspect/restore):
/// extends this request's body deadline to fit its declared size, up to `max`
/// bytes. Mounted per route, inside the auth layer, so it never runs for an
/// unauthenticated request and no other route gets a longer deadline.
pub async fn upload_deadline_middleware(max: u64, req: Request, next: Next) -> Response {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max) {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
    }
    if let Some(d) = req.extensions().get::<BodyDeadline>() {
        d.extend_to(upload_body_deadline(declared.unwrap_or(max)));
    }
    next.run(req).await
}

/// Every request body must arrive within a deadline (slow-body DoS). The
/// body is wrapped, not pre-buffered; size limits are enforced by whoever
/// reads it (small ones before authentication).
async fn body_deadline_middleware(mut req: Request, next: Next) -> Response {
    let has_body = matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
    if !has_body {
        return next.run(req).await;
    }
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let large_upload = req.uri().path().starts_with("/cgi-bin/luci") && declared.is_some_and(|n| n as usize > LUCI_MAX_BUFFERED_BODY);
    if large_upload && declared.is_some_and(|n| n > LUCI_MAX_STREAMED_BODY) {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
    }
    let deadline = BodyDeadline::new(tokio::time::Instant::now() + if large_upload { BODY_DEADLINE_LARGE } else { BODY_DEADLINE });
    req.extensions_mut().insert(deadline.clone());
    let (parts, body) = req.into_parts();
    // Only the body is bounded: handlers such as the AT console (180 s) or
    // the OTA feed check legitimately run longer than the body deadline.
    next.run(Request::from_parts(parts, body_with_deadline_cell(body, deadline))).await
}

async fn luci_proxy_handler(State(ctx): State<HttpCtx>, mut req: Request) -> Response {
    let path = req.uri().path().to_string();
    if !proxy_path_allowed(&path) {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::POST | Method::OPTIONS) {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
    }
    let upstream = luci_upstream();
    let path_q = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/cgi-bin/luci".into());
    let target_uri: Uri = match format!("http://{upstream}{path_q}").parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid URI").into_response(),
    };

    if req.method() == Method::POST && path.starts_with("/ubus") {
        let (mut parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, UBUS_MAX_BODY).await {
            Ok(b) => b,
            Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large or too slow").into_response(),
        };
        let canonical = match canonical_ubus_body(&bytes) {
            Ok(c) => c,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        };
        parts.headers.remove(header::TRANSFER_ENCODING);
        parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(canonical.len()));
        req = Request::from_parts(parts, Body::from(canonical));
    }

    // Our own credentials stay with us.
    let other_cookies: Vec<String> = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
        .map(str::trim)
        .filter(|kv| !kv.is_empty() && !kv.starts_with("qm_session="))
        .map(str::to_string)
        .collect();
    let headers = req.headers_mut();
    headers.remove(header::COOKIE);
    if !other_cookies.is_empty()
        && let Ok(v) = HeaderValue::from_str(&other_cookies.join("; "))
    {
        headers.insert(header::COOKIE, v);
    }
    headers.remove("x-qm-csrf");
    headers.insert(header::HOST, HeaderValue::from_static(LUCI_UPSTREAM));
    *req.version_mut() = axum::http::Version::HTTP_11;
    *req.uri_mut() = target_uri;

    match tokio::time::timeout(PROXY_UPSTREAM_TIMEOUT, ctx.proxy.request(req)).await {
        Ok(Ok(mut resp)) => {
            let prefix = format!("http://{upstream}");
            if let Some(loc) = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok())
                && let Some(stripped) = loc.strip_prefix(prefix.as_str())
                && let Ok(hv) = HeaderValue::from_str(stripped)
            {
                resp.headers_mut().insert(header::LOCATION, hv);
            }
            resp.map(Body::new)
        }
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, format!("LuCI upstream unavailable: {e}")).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "LuCI upstream timed out").into_response(),
    }
}

pub struct TlsSources<'a> {
    pub acme_cert: &'a str,
    pub acme_key: &'a str,
    pub self_cert: &'a str,
    pub self_key: &'a str,
    pub fallback_cert: &'a str,
    pub fallback_key: &'a str,
}

const TLS_SOURCES: TlsSources<'static> = TlsSources {
    acme_cert: "/etc/ssl/acme/fullchain.pem",
    acme_key: "/etc/ssl/acme/privkey.pem",
    self_cert: "/etc/cellcore/tls/cert.pem",
    self_key: "/etc/cellcore/tls/key.pem",
    fallback_cert: "/etc/uhttpd.crt",
    fallback_key: "/etc/uhttpd.key",
};

/// Resolve the active TLS certificate/key pair in priority order:
/// 1. Trusted ACME pair (`/etc/ssl/acme/{fullchain,privkey}.pem`)
/// 2. CellCore-managed self-signed ECDSA pair (`/etc/cellcore/tls/{cert,key}.pem`)
/// 3. Existing OpenWrt `uhttpd` self-signed pair (`/etc/uhttpd.{crt,key}`)
///
/// Both halves must exist so cert and key always match.
pub fn resolve_tls_pair(src: &TlsSources) -> (PathBuf, PathBuf) {
    let p = crate::paths::p;
    for (c, k) in [
        (src.acme_cert, src.acme_key),
        (src.self_cert, src.self_key),
        (src.fallback_cert, src.fallback_key),
    ] {
        if c.is_empty() || k.is_empty() {
            continue;
        }
        let (cp, kp) = (p(c), p(k));
        if Path::new(&cp).exists() && Path::new(&kp).exists() {
            return (PathBuf::from(cp), PathBuf::from(kp));
        }
    }
    let target_c = if !src.self_cert.is_empty() { src.self_cert } else { src.fallback_cert };
    let target_k = if !src.self_key.is_empty() { src.self_key } else { src.fallback_key };
    (PathBuf::from(p(target_c)), PathBuf::from(p(target_k)))
}

/// Generate a fresh 10-year ECDSA P-256 self-signed cert/key pair using `openssl`.
pub fn generate_self_signed_cert(cert_path: &Path, key_path: &Path, lan_ip: Option<&str>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }

    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'))
        .unwrap_or_else(|| "cellcore".into());

    let mut san = format!("DNS:{hostname},DNS:cellcore.local,IP:127.0.0.1");
    if let Some(ip) = lan_ip
        && ip.parse::<std::net::IpAddr>().is_ok()
    {
        san.push_str(&format!(",IP:{ip}"));
    }

    let tmp_cert = cert_path.with_extension("pem.tmp");
    let tmp_key = key_path.with_extension("pem.tmp");
    let _ = fs::remove_file(&tmp_cert);
    let _ = fs::remove_file(&tmp_key);

    let subj = format!("/CN={hostname}");
    let san_arg = format!("subjectAltName={san}");
    let run_openssl = |with_san: bool| -> Result<std::process::Output, String> {
        let mut cmd = std::process::Command::new("openssl");
        cmd.args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "3650",
            "-keyout",
        ])
        .arg(&tmp_key)
        .arg("-out")
        .arg(&tmp_cert)
        .args(["-subj", &subj]);
        if with_san {
            cmd.args(["-addext", &san_arg]);
        }
        cmd.output().map_err(|e| format!("spawn openssl: {e}"))
    };

    let out = match run_openssl(true) {
        Ok(o) if o.status.success() => o,
        _ => run_openssl(false)?,
    };
    if !out.status.success() {
        let _ = fs::remove_file(&tmp_cert);
        let _ = fs::remove_file(&tmp_key);
        return Err(format!(
            "openssl self-signed cert failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let key_bytes = fs::read(&tmp_key).map_err(|e| format!("read {}: {e}", tmp_key.display()))?;
    let cert_bytes = fs::read(&tmp_cert).map_err(|e| format!("read {}: {e}", tmp_cert.display()))?;
    let _ = fs::remove_file(&tmp_key);
    let _ = fs::remove_file(&tmp_cert);
    crate::state::atomic_write(key_path, &key_bytes, 0o600)?;
    crate::state::atomic_write(cert_path, &cert_bytes, 0o644)?;
    eprintln!(
        "cellcored: generated self-signed ECDSA P-256 TLS certificate at {}",
        cert_path.display()
    );
    Ok(())
}

/// Ensure a valid self-signed fallback pair exists and loads cleanly in rustls.
fn ensure_self_signed_fallback(src: &TlsSources, lan_ip: Option<&str>) -> Result<(PathBuf, PathBuf), String> {
    let p = crate::paths::p;
    let target_c = PathBuf::from(p(if !src.self_cert.is_empty() {
        src.self_cert
    } else {
        src.fallback_cert
    }));
    let target_k = PathBuf::from(p(if !src.self_key.is_empty() {
        src.self_key
    } else {
        src.fallback_key
    }));
    if target_c.exists() && target_k.exists() && load_tls_config(&target_c, &target_k).is_ok() {
        return Ok((target_c, target_k));
    }
    generate_self_signed_cert(&target_c, &target_k, lan_ip)?;
    Ok((target_c, target_k))
}

/// Ensure a valid, loadable TLS pair exists (auto-generating a self-signed ECDSA P-256
/// cert under `/etc/cellcore/tls/` on factory modems that have no cert yet, or falling
/// back to self-signed if the ACME pair has a mismatched/corrupt key).
pub fn ensure_tls_pair(src: &TlsSources, lan_ip: Option<&str>) -> Result<(PathBuf, PathBuf), String> {
    let (cp, kp) = resolve_tls_pair(src);
    if cp.exists() && kp.exists() && load_tls_config(&cp, &kp).is_ok() {
        return Ok((cp, kp));
    }
    ensure_self_signed_fallback(src, lan_ip)
}

fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let &tag = input.first()?;
    let &len_b = input.get(1)?;
    let (len, hdr_len) = if (len_b & 0x80) == 0 {
        (usize::from(len_b), 2usize)
    } else {
        let count = usize::from(len_b & 0x7f);
        if count == 0 || count > 4 || input.len() < 2 + count {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[2..2 + count] {
            l = (l << 8) | usize::from(b);
        }
        (l, 2 + count)
    };
    let end = hdr_len.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((tag, &input[hdr_len..end], &input[end..]))
}

fn parse_asn1_time_unix(tag: u8, bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ (RFC 5280: >=50 -> 19xx, <50 -> 20xx)
            if s.len() < 12 {
                return None;
            }
            let yy: i32 = s[0..2].parse().ok()?;
            let yr = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (yr, &s[2..])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() < 14 {
                return None;
            }
            let yr: i32 = s[0..4].parse().ok()?;
            (yr, &s[4..])
        }
        _ => return None,
    };
    let month: u32 = rest[0..2].parse().ok()?;
    let day: u32 = rest[2..4].parse().ok()?;
    let hour: i64 = rest[4..6].parse().ok()?;
    let min: i64 = rest[6..8].parse().ok()?;
    let sec: i64 = rest[8..10].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour >= 24 || min >= 60 || sec >= 60 {
        return None;
    }
    let days = crate::obs::usage_cycle::Civil::new(year, month, day).days();
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Extract the leaf certificate's `notAfter` Unix timestamp directly in-process
/// from PEM bytes (zero `openssl` subprocess forks).
pub fn parse_pem_leaf_not_after_unix(pem_bytes: &[u8]) -> Result<i64, String> {
    let mut rd = std::io::Cursor::new(pem_bytes);
    let cert = rustls_pemfile::certs(&mut rd)
        .next()
        .ok_or_else(|| "no PEM certificate found".to_string())?
        .map_err(|e| format!("invalid PEM cert: {e}"))?;
    let (tag, cert_seq, _) = der_read_tlv(cert.as_ref()).ok_or("malformed DER cert")?;
    if tag != 0x30 {
        return Err("expected SEQUENCE at cert root".into());
    }
    let (tbs_tag, mut tbs, _) = der_read_tlv(cert_seq).ok_or("malformed TBSCertificate")?;
    if tbs_tag != 0x30 {
        return Err("expected SEQUENCE for TBSCertificate".into());
    }
    // Optional [0] EXPLICIT version
    if tbs.first() == Some(&0xA0) {
        let (_, _, rem) = der_read_tlv(tbs).ok_or("malformed TBS version")?;
        tbs = rem;
    }
    // Skip serialNumber, signature AlgorithmIdentifier, issuer Name
    for _ in 0..3 {
        let (_, _, rem) = der_read_tlv(tbs).ok_or("malformed TBS prefix")?;
        tbs = rem;
    }
    let (val_tag, validity, _) = der_read_tlv(tbs).ok_or("malformed TBS validity")?;
    if val_tag != 0x30 {
        return Err("expected SEQUENCE for validity".into());
    }
    // Skip notBefore, read notAfter
    let (_, _, after_nb) = der_read_tlv(validity).ok_or("malformed notBefore")?;
    let (na_tag, na_val, _) = der_read_tlv(after_nb).ok_or("malformed notAfter")?;
    parse_asn1_time_unix(na_tag, na_val).ok_or_else(|| "invalid notAfter timestamp".into())
}

type CertExpiryCacheEntry = (PathBuf, Option<(i64, i64, u64, u64)>, i64);
static SELF_CERT_EXPIRY_CACHE: std::sync::Mutex<Option<CertExpiryCacheEntry>> =
    std::sync::Mutex::new(None);

fn cached_cert_not_after_unix(cert_path: &Path) -> Result<i64, String> {
    let stamp = file_stamp(cert_path);
    if let Ok(g) = SELF_CERT_EXPIRY_CACHE.lock()
        && let Some((ref p, cached_stamp, exp)) = *g
        && p == cert_path
        && cached_stamp == stamp
    {
        return Ok(exp);
    }
    let pem = fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    let exp = parse_pem_leaf_not_after_unix(&pem)?;
    if let Ok(mut g) = SELF_CERT_EXPIRY_CACHE.lock() {
        *g = Some((cert_path.to_path_buf(), stamp, exp));
    }
    Ok(exp)
}

/// If the active TLS certificate is the CellCore self-signed fallback (`/etc/cellcore/tls/cert.pem`)
/// and the wall clock has synced (`>= 2025-01-01`), check cached in-process DER `notAfter`
/// (re-parsing only when the file's mtime/size/ino stamp changes — zero `openssl` forks!).
/// If expired/corrupt (e.g. generated at `1970` pre-NTP!), regenerate a fresh 10-year ECDSA P-256
/// pair so the TLS watcher hot-reloads it automatically. Returns `Ok(true)` when regenerated.
pub fn check_and_heal_self_signed_cert(
    src: &TlsSources,
    wall_now_secs: u64,
    lan_ip: Option<&str>,
) -> Result<bool, String> {
    if wall_now_secs < crate::state::MIN_VALID_WALL_CLOCK_SECS || src.self_cert.is_empty() {
        return Ok(false);
    }
    let (cp, kp) = resolve_tls_pair(src);
    let self_cp = PathBuf::from(crate::paths::p(src.self_cert));
    if cp != self_cp || !cp.exists() {
        return Ok(false);
    }
    let check_ok = cached_cert_not_after_unix(&cp)
        .is_ok_and(|not_after| not_after > wall_now_secs as i64);
    if check_ok {
        return Ok(false);
    }
    eprintln!(
        "cellcored: self-signed TLS cert {} is expired (likely pre-NTP 1970 boot); regenerating 10-year cert",
        cp.display()
    );
    generate_self_signed_cert(&cp, &kp, lan_ip)?;
    if let Ok(mut g) = SELF_CERT_EXPIRY_CACHE.lock() {
        *g = None;
    }
    Ok(true)
}

fn file_stamp(path: &Path) -> Option<(i64, i64, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).ok()?;
    Some((m.mtime(), m.mtime_nsec(), m.size(), m.ino()))
}

pub type TlsFingerprint = (PathBuf, PathBuf, Option<(i64, i64, u64, u64)>, Option<(i64, i64, u64, u64)>);

pub fn tls_fingerprint(cert: &Path, key: &Path) -> TlsFingerprint {
    (cert.to_path_buf(), key.to_path_buf(), file_stamp(cert), file_stamp(key))
}

fn extract_cert_public_key_bytes(cert_der: &[u8]) -> Result<&[u8], String> {
    let (tag, cert_seq, _) = der_read_tlv(cert_der).ok_or("malformed DER cert")?;
    if tag != 0x30 {
        return Err("expected SEQUENCE at cert root".into());
    }
    let (tbs_tag, mut tbs, _) = der_read_tlv(cert_seq).ok_or("malformed TBSCertificate")?;
    if tbs_tag != 0x30 {
        return Err("expected SEQUENCE for TBSCertificate".into());
    }
    // Optional [0] EXPLICIT version
    if tbs.first() == Some(&0xA0) {
        let (_, _, rem) = der_read_tlv(tbs).ok_or("malformed TBS version")?;
        tbs = rem;
    }
    // Skip serialNumber, signature AlgorithmIdentifier, issuer Name, validity, subject Name
    for _ in 0..5 {
        let (_, _, rem) = der_read_tlv(tbs).ok_or("malformed TBS field before SPKI")?;
        tbs = rem;
    }
    let (spki_tag, spki_body, _) = der_read_tlv(tbs).ok_or("malformed SubjectPublicKeyInfo")?;
    if spki_tag != 0x30 {
        return Err("expected SEQUENCE for SubjectPublicKeyInfo".into());
    }
    let (_, _, spki_rem) = der_read_tlv(spki_body).ok_or("malformed SPKI algorithm")?;
    let (bs_tag, bs_body, _) = der_read_tlv(spki_rem).ok_or("malformed SPKI BIT STRING")?;
    if bs_tag != 0x03 || bs_body.is_empty() || bs_body[0] != 0 {
        return Err("unexpected SPKI BIT STRING encoding".into());
    }
    Ok(&bs_body[1..])
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig, String> {
    let cert_file = fs::File::open(cert_path)
        .map_err(|e| format!("open {}: {e}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs {}: {e}", cert_path.display()))?;
    if certs.is_empty() {
        return Err(format!("No certificates in {}", cert_path.display()));
    }

    let key_file = fs::File::open(key_path)
        .map_err(|e| format!("open {}: {e}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse key {}: {e}", key_path.display()))?
        .ok_or_else(|| format!("No private key in {}", key_path.display()))?;

    // Validate that the private key actually matches the leaf certificate's public key
    // (ServerConfig::with_single_cert only checks algorithm compatibility, not key equality).
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls_rustcrypto::provider()));
    let signing_key = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| format!("load private key {}: {e}", key_path.display()))?;
    let ck = rustls::sign::CertifiedKey::new(certs.clone(), signing_key);
    match ck.keys_match() {
        Ok(()) => {}
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
            // Provider did not expose raw SPKI on SigningKey; verify a live signature against
            // the leaf certificate's public key using the provider's verification algorithms.
            let pub_key_bytes = extract_cert_public_key_bytes(certs[0].as_ref())?;
            let probe = b"cellcore-tls-key-cert-match-probe";
            let schemes = [
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ];
            let signer = ck
                .key
                .choose_scheme(&schemes)
                .ok_or_else(|| "TLS private key has no supported signature scheme".to_string())?;
            let scheme = signer.scheme();
            let sig = signer
                .sign(probe)
                .map_err(|e| format!("TLS key probe sign failed: {e}"))?;
            let verifiers = provider
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(s, _)| *s == scheme)
                .map(|(_, algs)| *algs)
                .ok_or_else(|| format!("no verifier for TLS signature scheme {scheme:?}"))?;
            if !verifiers
                .iter()
                .any(|alg| alg.verify_signature(pub_key_bytes, probe, &sig).is_ok())
            {
                return Err("TLS certificate and private key mismatch".into());
            }
        }
        Err(e) => {
            return Err(format!("TLS certificate and private key mismatch: {e}"));
        }
    }

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("rustls config error: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

fn bind_tcp_freebind(addr: SocketAddr) -> Result<TcpListener, String> {
    let std_listener = match addr {
        SocketAddr::V4(v4) => {
            let fd = unsafe {
                libc::socket(
                    libc::AF_INET,
                    libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err(format!("socket v4 {addr}: {}", std::io::Error::last_os_error()));
            }
            let one: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_FREEBIND,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            let rc = unsafe {
                libc::bind(
                    fd,
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd); }
                return Err(format!("bind {addr}: {err}"));
            }
            if unsafe { libc::listen(fd, 128) } != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd); }
                return Err(format!("listen {addr}: {err}"));
            }
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
        SocketAddr::V6(_) => std::net::TcpListener::bind(addr)
            .map_err(|e| format!("bind v6 {addr}: {e}"))?,
    };
    let _ = std_listener.set_nonblocking(true);
    TcpListener::from_std(std_listener).map_err(|e| format!("tokio listener {addr}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn proxy_rejects_traversal_and_foreign_paths() {
        for ok in ["/ubus", "/ubus/", "/cgi-bin/luci", "/cgi-bin/luci/admin/status", "/luci-static/bootstrap/cascade.css"] {
            assert!(proxy_path_allowed(ok), "{ok}");
        }
        for bad in [
            "/luci-static/../cgi-bin/cgi-exec",
            "/luci-static/%2e%2e/cgi-bin/cgi-exec",
            "/luci-static/%2E%2e/cgi-bin/x",
            "/cgi-bin/luci/../cgi-backup",
            "/cgi-bin/luci/%2e%2e%2fcgi-download",
            "/cgi-bin/luci/./admin",
            "/cgi-bin/luci//admin",
            "/luci-static/a%5c..%5cb",
            "/luci-static/bad%zz",
            "/luci-static/%00",
            "/cgi-bin/cgi-exec",
            "/ubusx",
        ] {
            assert!(!proxy_path_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn static_never_serves_cgi_sources() {
        assert!(static_path_allowed("/assets/index-abc.js"));
        assert!(static_path_allowed("/"));
        assert!(!static_path_allowed("/cgi-bin/quecmanager/at_cmd.sh"));
        assert!(!static_path_allowed("/CGI-BIN/luci"));
        assert!(!static_path_allowed("/cgi%2dbin/quecmanager/x.sh"));
        assert!(!static_path_allowed("/assets/%2e%2e/cgi-bin/x"));
    }

    #[test]
    fn per_ip_cap_and_reserved_slots() {
        let limits = ConnLimits { max_conns: 10, max_per_ip: 6, reserved: 4, light_client: 2, ..ConnLimits::default() };
        let t = Arc::new(ConnTracker::new(limits));
        let attacker: std::net::IpAddr = "192.168.224.50".parse().unwrap();
        let owner: std::net::IpAddr = "192.168.224.10".parse().unwrap();
        let mut held: Vec<ConnGuard> = (0..6).filter_map(|_| t.try_admit(attacker)).collect();
        assert_eq!(held.len(), 6, "attacker reaches only the reserve boundary / per-IP cap");
        assert!(t.try_admit(attacker).is_none(), "per-IP cap");
        let second: std::net::IpAddr = "192.168.224.51".parse().unwrap();
        held.extend((0..6).filter_map(|_| t.try_admit(second)));
        // second heavy client is held out of the reserved slots
        assert_eq!(held.len(), 6 + 2);
        // the owner still gets in on a reserved slot
        let o1 = t.try_admit(owner).expect("owner admitted");
        let o2 = t.try_admit(owner).expect("owner admitted");
        assert!(t.try_admit(owner).is_none(), "global cap");
        drop((o1, o2));
        held.clear();
        assert!(t.try_admit(attacker).is_some(), "slots released on drop");
    }

    #[test]
    fn tls_pair_switches_to_acme_and_tracks_key_changes() {
        let dir = std::env::temp_dir().join(format!("qm-tls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let (ac, ak, sc, sk, fc, fk) = (
            p("fullchain.pem"),
            p("privkey.pem"),
            p("cellcore.pem"),
            p("cellcore.key"),
            p("uhttpd.crt"),
            p("uhttpd.key"),
        );
        let src = TlsSources {
            acme_cert: &ac,
            acme_key: &ak,
            self_cert: &sc,
            self_key: &sk,
            fallback_cert: &fc,
            fallback_key: &fk,
        };
        fs::write(&fc, "c").unwrap();
        fs::write(&fk, "k").unwrap();
        let (c0, k0) = resolve_tls_pair(&src);
        assert_eq!(c0, PathBuf::from(&fc));
        let fp0 = tls_fingerprint(&c0, &k0);
        // ACME cert alone (key not yet written) must not produce a mismatched pair
        fs::write(&ac, "acme").unwrap();
        assert_eq!(resolve_tls_pair(&src).0, PathBuf::from(&fc));
        fs::write(&ak, "acmekey").unwrap();
        let (c1, k1) = resolve_tls_pair(&src);
        assert_eq!((c1.clone(), k1.clone()), (PathBuf::from(&ac), PathBuf::from(&ak)));
        let fp1 = tls_fingerprint(&c1, &k1);
        assert_ne!(fp0, fp1);
        // key-only rotation changes the fingerprint
        fs::write(&ak, "acmekey-rotated-longer").unwrap();
        assert_ne!(fp1, tls_fingerprint(&c1, &k1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_tls_pair_generates_valid_ecdsa_self_signed_cert() {
        let _ = rustls_rustcrypto::provider().install_default();
        let dir = std::env::temp_dir().join(format!("cc-tls-gen-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let (ac, ak, sc, sk, fc, fk) = (
            p("acme/fullchain.pem"),
            p("acme/privkey.pem"),
            p("tls/cert.pem"),
            p("tls/key.pem"),
            p("uhttpd.crt"),
            p("uhttpd.key"),
        );
        let src = TlsSources {
            acme_cert: &ac,
            acme_key: &ak,
            self_cert: &sc,
            self_key: &sk,
            fallback_cert: &fc,
            fallback_key: &fk,
        };
        let (cert, key) = ensure_tls_pair(&src, Some("192.168.225.1")).expect("generate self-signed cert");
        assert_eq!(cert, PathBuf::from(&sc));
        assert_eq!(key, PathBuf::from(&sk));
        assert!(load_tls_config(&cert, &key).is_ok(), "generated cert must load in rustls");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    async fn spawn_test_server(limits: ConnLimits) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .route("/echo", post(|body: String| async move { body }))
            .layer(middleware::from_fn(body_deadline_middleware));
        let slots = Arc::new(ConnTracker::new(limits));
        tokio::spawn(accept_loop(listener, slots, move |stream, peer, permit| {
            let r = router.clone();
            async move {
                let _p = permit;
                serve_connection_with(stream, r, peer, limits, false).await;
            }
        }));
        addr
    }

    async fn closed_within(s: &mut tokio::net::TcpStream, within: Duration) -> bool {
        let mut b = [0u8; 64];
        matches!(tokio::time::timeout(within, s.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_)))
    }

    #[tokio::test]
    async fn idle_connections_are_closed_and_capped() {
        let limits = ConnLimits {
            max_conns: 2,
            max_per_ip: 2,
            reserved: 0,
            handshake: Duration::from_millis(300),
            header_read: Duration::from_millis(300),
            ..ConnLimits::default()
        };
        let addr = spawn_test_server(limits).await;
        let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // over the cap: closed immediately
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(closed_within(&mut c, Duration::from_millis(200)).await, "connection over cap not closed");
        // idle connections that never send headers are closed by the timeout
        assert!(closed_within(&mut a, Duration::from_secs(3)).await, "idle connection held open");
        assert!(closed_within(&mut b, Duration::from_secs(3)).await, "idle connection held open");
        // slots are released: a real request now works
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut d = tokio::net::TcpStream::connect(addr).await.unwrap();
        d.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        tokio::time::timeout(Duration::from_secs(3), d.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert!(resp.starts_with("HTTP/1.1 200") && resp.ends_with("pong"), "{resp}");
    }

    #[tokio::test]
    async fn slow_request_body_is_cut_off() {
        let addr = spawn_test_server(ConnLimits::default()).await;
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc").await.unwrap();
        // trickle nothing more: the streamed body hits its deadline, the
        // handler fails and the connection slot is released
        let mut resp = String::new();
        let t0 = std::time::Instant::now();
        let _ = tokio::time::timeout(Duration::from_secs(25), s.read_to_string(&mut resp)).await;
        assert!(t0.elapsed() < Duration::from_secs(20), "slow body held the connection {:?}", t0.elapsed());
        assert!(!resp.starts_with("HTTP/1.1 200"), "{resp:?}");
    }

    #[test]
    fn upload_deadline_scales_with_size_and_is_capped() {
        assert_eq!(upload_body_deadline(0), BODY_DEADLINE);
        // 32 MiB at the minimum rate: 256 s on top of the generic deadline
        assert_eq!(upload_body_deadline(32 * 1024 * 1024), Duration::from_secs(15 + 256));
        assert_eq!(upload_body_deadline(u64::MAX / 2), BODY_DEADLINE_LARGE);
        // the 4.1.1 failure: 32 MiB in 15 s needed >= 18 Mbit/s
        assert!(upload_body_deadline(32 * 1024 * 1024) > Duration::from_secs(250));
    }

    #[tokio::test]
    async fn deadline_body_passes_data_and_errors_after_deadline() {
        let ok = body_with_deadline(Body::from("hello"), tokio::time::Instant::now() + Duration::from_secs(5));
        assert_eq!(axum::body::to_bytes(ok, 100).await.unwrap(), "hello");
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
        let slow = Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|v| (v, rx)) }));
        let wrapped = body_with_deadline(slow, tokio::time::Instant::now() + Duration::from_millis(100));
        tx.send(Ok("a".into())).await.unwrap();
        let t0 = std::time::Instant::now();
        assert!(axum::body::to_bytes(wrapped, 100).await.is_err());
        assert!(t0.elapsed() < Duration::from_secs(1));
        drop(tx);
    }

    // ---------- LuCI/ubus proxy behind QM auth (mock upstream) ----------

    struct MockUpstream {
        hits: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    }

    async fn mock_upstream() -> MockUpstream {
        let hits: Arc<std::sync::Mutex<Vec<(String, String, String)>>> = Default::default();
        let h = Arc::clone(&hits);
        let app = Router::new().fallback(move |req: Request| {
            let h = Arc::clone(&h);
            async move {
                let path = req.uri().path().to_string();
                let cookie = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                h.lock().unwrap().push((path, String::from_utf8_lossy(&body).into_owned(), cookie));
                "upstream-ok"
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _ = LUCI_UPSTREAM_OVERRIDE.set(addr.to_string());
        assert_eq!(LUCI_UPSTREAM_OVERRIDE.get(), Some(&addr.to_string()), "one mock upstream per test binary");
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        MockUpstream { hits }
    }

    fn test_router() -> (Router, crate::auth::AuthStore) {
        let dir = std::env::temp_dir().join(format!("qm-proxy-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let auth = crate::auth::AuthStore::new(dir.join("sessions"));
        let app = AppState::for_tests(dir, auth.clone());
        let ctx = HttpCtx {
            app,
            proxy: Client::builder(TokioExecutor::new()).build_http(),
            enforce_uhttpd_loopback: true,
        };
        (build_router(ctx), auth)
    }

    async fn send(router: &Router, method: Method, uri: &str, headers: &[(&str, &str)], body: &str) -> Response {
        let mut b = axum::http::Request::builder().method(method).uri(uri).header(header::HOST, "192.168.224.1");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from(([192, 168, 224, 50], 40000))));
        tower::ServiceExt::oneshot(router.clone(), req).await.unwrap()
    }

    #[tokio::test]
    async fn over_long_static_paths_are_4xx_not_500() {
        let (router, _auth) = test_router();
        for uri in [
            format!("/{}", "a/".repeat(5000)),
            format!("/{}", "a/".repeat(600)),
            format!("/{}", "b".repeat(300)),
            format!("/assets/{}.js", "c".repeat(1000)),
        ] {
            let st = send(&router, Method::GET, &uri, &[], "").await.status();
            assert!(
                st == StatusCode::NOT_FOUND || st == StatusCode::URI_TOO_LONG,
                "GET of a {}-byte path: {st}",
                uri.len()
            );
        }
    }

    #[tokio::test]
    async fn luci_proxy_disabled_by_default() {
        let (router, auth) = test_router();
        let sess = auth.create_session().await.unwrap();
        let qm = format!("qm_session={}", sess.token);
        for (m, uri) in [
            (Method::GET, "/cgi-bin/luci"),
            (Method::GET, "/cgi-bin/luci/"),
            (Method::GET, "/luci-static/bootstrap/cascade.css"),
            (Method::POST, "/ubus"),
        ] {
            // Unauthenticated
            let r = send(&router, m.clone(), uri, &[], "").await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "unauth {m} {uri}");
            // Even authenticated
            let r = send(&router, m.clone(), uri, &[("cookie", qm.as_str())], "").await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "auth {m} {uri}");
        }
    }

    #[tokio::test]
    async fn auth_status_rejects_luci_referer_and_allows_spa() {
        let (router, auth) = test_router();
        let sess = auth.create_session().await.unwrap();
        let qm = format!("qm_session={}", sess.token);

        // Normal CellCore SPA request succeeds and returns csrfToken
        let ok_resp = send(
            &router,
            Method::GET,
            "/api/v1/auth/status",
            &[("cookie", qm.as_str()), ("referer", "https://192.168.224.1/")],
            "",
        )
        .await;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        let ok_body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(ok_resp.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(ok_body["authenticated"], true);
        assert!(ok_body["csrfToken"].as_str().is_some());

        // Referer from LuCI is refused with 403
        for bad_ref in [
            "https://192.168.224.1/cgi-bin/luci",
            "https://192.168.224.1/cgi-bin/luci/admin/status",
            "https://192.168.224.1/CGI-BIN/LUCI/",
            "https://192.168.224.1/luci-static/bootstrap/x.html",
        ] {
            let r = send(
                &router,
                Method::GET,
                "/api/v1/auth/status",
                &[("cookie", qm.as_str()), ("referer", bad_ref)],
                "",
            )
            .await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "referer={bad_ref}");
        }
    }

    #[tokio::test]
    async fn h2_idle_connection_is_closed_after_idle_timeout() {
        let limits = ConnLimits {
            max_conns: 2,
            max_per_ip: 2,
            reserved: 0,
            h2_keep_alive_interval: Duration::from_secs(10),
            h2_keep_alive_timeout: Duration::from_secs(5),
            h2_idle_timeout: Duration::from_millis(200),
            ..ConnLimits::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let slots = Arc::new(ConnTracker::new(limits));
        let slots_srv = Arc::clone(&slots);
        tokio::spawn(accept_loop(listener, slots_srv, move |stream, peer, permit| {
            let r = router.clone();
            async move {
                let _p = permit;
                serve_connection_with(stream, r, peer, limits, true).await;
            }
        }));

        // Connect and send the HTTP/2 client connection preface + empty SETTINGS frame,
        // then sit idle without sending any requests.
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        s.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap(); // empty SETTINGS frame

        // Drain server frames until EOF; the idle watchdog must close the H2 connection.
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            let mut buf = [0u8; 256];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return true,
                    Ok(_) => continue,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(closed, "idle HTTP/2 connection was not closed after h2_idle_timeout");
    }

    #[tokio::test]
    async fn luci_and_ubus_require_a_cellcore_session() {
        LUCI_PROXY_ENABLED_TEST_OVERRIDE
            .scope(true, async {
                let up = mock_upstream().await;
                let (router, auth) = test_router();
                let login = r#"{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","session","login",{"username":"root","password":"x"}]}"#;
                let batch = format!("[{login},{login}]");
                let dup = r#"{"method":"call","params":["0123456789abcdef0123456789abcdef","uci","get",{}],"params":["00000000000000000000000000000000","session","login",{}]}"#;
                let nul = r#"{"method":"call","params":["00000000000000000000000000000000","session","login",{"username":"root\u0000x","password":"x"}]}"#;
                const FAKE_LUCI: &[(&str, &str)] = &[("cookie", "sysauth_https=0123456789abcdef0123456789abcdef")];
                type Case<'a> = (Method, &'a str, &'a [(&'a str, &'a str)], String);
                let cases: Vec<Case> = vec![
                    (Method::POST, "/ubus", &[], login.to_string()),
                    (Method::POST, "/ubus", &[], batch.clone()),
                    (Method::POST, "/ubus", &[], dup.to_string()),
                    (Method::POST, "/ubus", &[], nul.to_string()),
                    (Method::POST, "/ubus/call/session/login", &[], r#"{"username":"root","password":"x"}"#.into()),
                    (Method::GET, "/ubus/list", &[], String::new()),
                    (Method::GET, "/cgi-bin/luci/?luci_username=root&luci_password=x", &[], String::new()),
                    (Method::POST, "/cgi-bin/luci/", FAKE_LUCI, "luci_username=root&luci_password=x".into()),
                    (Method::PUT, "/cgi-bin/luci/", &[], "luci_password=x".into()),
                    (Method::GET, "/luci-static/bootstrap/cascade.css", &[], String::new()),
                    (Method::POST, "/ubus", &[("authorization", "Bearer 0123456789abcdef0123456789abcdef")], login.to_string()),
                    (Method::POST, "/ubus", &[("cookie", "qm_session=0123456789abcdef0123456789abcdef")], login.to_string()),
                ];
                for (m, uri, h, body) in cases {
                    let r = send(&router, m.clone(), uri, h, &body).await;
                    let s = r.status();
                    assert!(
                        s == StatusCode::UNAUTHORIZED || (m == Method::GET && uri.starts_with("/cgi-bin/luci") && s == StatusCode::FOUND),
                        "{m} {uri} -> {s}"
                    );
                }
                assert!(up.hits.lock().unwrap().is_empty(), "unauthenticated request reached uhttpd/rpcd");

                // after CellCore login
                let sess = auth.create_session().await.unwrap();
                let qm = format!("qm_session={}; sysauth_https=abcdef", sess.token);
                let same_origin: &[(&str, &str)] = &[("cookie", qm.as_str()), ("origin", "https://192.168.224.1")];
                let r = send(&router, Method::GET, "/luci-static/bootstrap/cascade.css", &[("cookie", qm.as_str())], "").await;
                assert_eq!(r.status(), StatusCode::OK, "LuCI static assets load after QM login");
                let r = send(&router, Method::GET, "/cgi-bin/luci/", &[("cookie", qm.as_str())], "").await;
                assert_eq!(r.status(), StatusCode::OK);
                assert_eq!(
                    r.headers().get("x-frame-options").and_then(|v| v.to_str().ok()),
                    Some("DENY"),
                    "proxied LuCI responses must enforce X-Frame-Options: DENY"
                );
                let csp = r
                    .headers()
                    .get("content-security-policy")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert!(
                    csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self'"),
                    "proxied LuCI responses must enforce strict CSP, got: {csp}"
                );
                let r = send(&router, Method::POST, "/ubus", same_origin, dup).await;
                assert_eq!(r.status(), StatusCode::OK);
                // NUL is refused even when authenticated; malformed JSON too
                assert_eq!(send(&router, Method::POST, "/ubus", same_origin, nul).await.status(), StatusCode::BAD_REQUEST);
                assert_eq!(send(&router, Method::POST, "/ubus", same_origin, "{\"a\":").await.status(), StatusCode::BAD_REQUEST);
                // cross-origin state change with a valid cookie: refused
                let cross: &[(&str, &str)] = &[("cookie", qm.as_str()), ("origin", "https://evil.example")];
                assert_eq!(send(&router, Method::POST, "/ubus", cross, login).await.status(), StatusCode::FORBIDDEN);
                let no_origin: &[(&str, &str)] = &[("cookie", qm.as_str())];
                assert_eq!(send(&router, Method::POST, "/ubus", no_origin, login).await.status(), StatusCode::FORBIDDEN);

                let hits = up.hits.lock().unwrap().clone();
                assert_eq!(hits.len(), 3, "{hits:?}");
                // canonical body: rpcd sees the single value we parsed
                let (path, body, cookie) = &hits[2];
                assert_eq!(path, "/ubus");
                let v: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(v["params"][1], "session");
                assert_eq!(body.matches("\"params\"").count(), 1);
                // the CellCore session cookie is not forwarded, LuCI's is
                assert!(!cookie.contains("qm_session") && cookie.contains("sysauth_https=abcdef"), "{cookie}");
            })
            .await;
    }

    #[test]
    fn same_origin_check() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = axum::http::HeaderMap::new();
            for (k, v) in pairs {
                m.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
            }
            m
        };
        assert!(same_origin_request(&h(&[("host", "192.168.224.1"), ("origin", "https://192.168.224.1")])));
        assert!(same_origin_request(&h(&[("host", "192.168.224.1"), ("referer", "https://192.168.224.1/cgi-bin/luci/admin")])));
        assert!(!same_origin_request(&h(&[("host", "192.168.224.1"), ("origin", "https://192.168.224.1.evil.example")])));
        assert!(!same_origin_request(&h(&[("host", "192.168.224.1"), ("origin", "null")])));
        assert!(!same_origin_request(&h(&[("host", "192.168.224.1")])));
        // HTTP/2 requests send :authority instead of Host header
        assert!(same_origin_for(&h(&[("origin", "https://192.168.228.1")]), Some("192.168.228.1")));
        assert!(!same_origin_for(&h(&[("origin", "https://evil.example")]), Some("192.168.228.1")));
    }

    #[test]
    fn expired_1970_self_signed_cert_is_regenerated_once_wall_clock_syncs() {
        let dir = std::env::temp_dir().join(format!("qm-tls-1970-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let acme_c = dir.join("acme/fullchain.pem").display().to_string();
        let acme_k = dir.join("acme/privkey.pem").display().to_string();
        let self_c_path = dir.join("tls/cert.pem");
        let self_k_path = dir.join("tls/key.pem");
        let self_c = self_c_path.display().to_string();
        let self_k = self_k_path.display().to_string();
        let fb_c = dir.join("uhttpd.crt").display().to_string();
        let fb_k = dir.join("uhttpd.key").display().to_string();
        let sources = TlsSources {
            acme_cert: &acme_c,
            acme_key: &acme_k,
            self_cert: &self_c,
            self_key: &self_k,
            fallback_cert: &fb_c,
            fallback_key: &fb_k,
        };
        fs::create_dir_all(self_c_path.parent().unwrap()).unwrap();
        // Write an invalid/expired PEM simulating a 1970 pre-NTP certificate that fails -checkend 0.
        fs::write(&self_k_path, b"-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n").unwrap();
        fs::write(&self_c_path, b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n").unwrap();

        // Pre-NTP wall clock (< 2025-01-01): must NOT regenerate yet.
        assert_eq!(
            check_and_heal_self_signed_cert(&sources, 100, Some("192.168.225.1")),
            Ok(false)
        );

        // Post-NTP wall clock: detects checkend failure and regenerates a valid 10-year cert.
        assert_eq!(
            check_and_heal_self_signed_cert(
                &sources,
                crate::state::MIN_VALID_WALL_CLOCK_SECS + 60,
                Some("192.168.225.1")
            ),
            Ok(true)
        );
        let ok = std::process::Command::new("openssl")
            .args(["x509", "-checkend", "86400", "-noout", "-in", &self_c])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "regenerated self-signed cert must be valid");
        // Subsequent check sees valid cert and returns Ok(false) (no churn).
        assert_eq!(
            check_and_heal_self_signed_cert(
                &sources,
                crate::state::MIN_VALID_WALL_CLOCK_SECS + 120,
                Some("192.168.225.1")
            ),
            Ok(false)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn compression_layer_serves_gzip_when_accepted() {
        let (router, auth) = test_router();
        let sess = auth.create_session().await.unwrap();
        let cookie = format!("qm_session={}", sess.token);
        let resp = send(
            &router,
            Method::GET,
            "/api/v1/metrics",
            &[("cookie", cookie.as_str()), ("accept-encoding", "gzip")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "CompressionLayer must gzip compressible API responses"
        );
    }

    #[test]
    fn mismatched_acme_key_and_cert_falls_back_to_self_signed() {
        let _ = rustls_rustcrypto::provider().install_default();
        let dir = std::env::temp_dir().join(format!("cc-tls-mismatch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("acme")).unwrap();
        fs::create_dir_all(dir.join("tls")).unwrap();
        let ac = dir.join("acme/fullchain.pem");
        let ak = dir.join("acme/privkey.pem");
        let sc = dir.join("tls/cert.pem");
        let sk = dir.join("tls/key.pem");
        // Generate two unrelated keypairs and cross-wire ACME cert + other key.
        generate_self_signed_cert(&ac, &dir.join("acme/orig.key"), None).unwrap();
        generate_self_signed_cert(&dir.join("acme/other.crt"), &ak, None).unwrap();
        assert!(load_tls_config(&ac, &ak).is_err(), "mismatched cert/key must fail rustls validation");

        let ac_s = ac.display().to_string();
        let ak_s = ak.display().to_string();
        let sc_s = sc.display().to_string();
        let sk_s = sk.display().to_string();
        let src = TlsSources {
            acme_cert: &ac_s,
            acme_key: &ak_s,
            self_cert: &sc_s,
            self_key: &sk_s,
            fallback_cert: "",
            fallback_key: "",
        };
        let (chosen_c, chosen_k) = ensure_tls_pair(&src, Some("192.168.225.1")).unwrap();
        assert_eq!(chosen_c, sc);
        assert_eq!(chosen_k, sk);
        assert!(load_tls_config(&chosen_c, &chosen_k).is_ok());
        // Verify in-process DER notAfter parser reads our freshly generated 10-year cert.
        let exp = parse_pem_leaf_not_after_unix(&fs::read(&chosen_c).unwrap()).unwrap();
        assert!(exp > crate::auth::now_secs() as i64 + 86_400 * 3000, "exp={exp}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_redirect_handles_ipv6_and_rejects_host_injection() {
        assert_eq!(sanitize_redirect_host(Some("192.168.228.1:80"), "192.168.228.1"), "192.168.228.1");
        assert_eq!(sanitize_redirect_host(Some("modem.local:8080"), "192.168.228.1"), "modem.local");
        assert_eq!(sanitize_redirect_host(Some("[fd00::1]:80"), "192.168.228.1"), "[fd00::1]");
        assert_eq!(sanitize_redirect_host(Some("[fd00::1]"), "192.168.228.1"), "[fd00::1]");
        assert_eq!(sanitize_redirect_host(Some("[::1]:8080"), "192.168.228.1"), "[::1]");
        for bad in [
            "evil.example@192.168.228.1",
            "192.168.228.1/evil",
            "192.168.228.1\\evil",
            "192.168.228.1 evil",
            "192.168.228.1:99999",
            "192.168.228.1:abc",
            "[not-ipv6]:80",
            "[fd00::1]:99999",
            "fd00::1",
            "",
        ] {
            assert_eq!(
                sanitize_redirect_host(Some(bad), "192.168.228.1"),
                "192.168.228.1",
                "malicious/invalid Host {bad:?} must fall back"
            );
        }

        let req_v6 = Request::builder()
            .uri("/dashboard?tab=rf")
            .header(header::HOST, "[fd00::1]:80")
            .body(Body::empty())
            .unwrap();
        let resp_v6 = http_redirect_handler(req_v6, "192.168.228.1").await;
        assert_eq!(resp_v6.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp_v6.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("https://[fd00::1]/dashboard?tab=rf")
        );

        let req_inj = Request::builder()
            .uri("/login")
            .header(header::HOST, "evil.example@192.168.228.1")
            .body(Body::empty())
            .unwrap();
        let resp_inj = http_redirect_handler(req_inj, "192.168.228.1").await;
        assert_eq!(resp_inj.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp_inj.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("https://192.168.228.1/login")
        );
    }

    impl super::HttpCtx {
        pub fn for_tests(dir: &Path) -> Self {
            let auth = crate::auth::AuthStore::new(dir.join("sessions"));
            let app = AppState::for_tests(dir.to_path_buf(), auth);
            Self {
                app,
                proxy: Client::builder(TokioExecutor::new()).build_http(),
                enforce_uhttpd_loopback: true,
            }
        }
    }
}

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
    let tls_watch = Arc::clone(&tls_cfg);
    tokio::spawn(async move {
        let mut last = tls_fingerprint(&cert_path, &key_path);
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let (cp, kp) = resolve_tls_pair(&TLS_SOURCES);
            let cur = tls_fingerprint(&cp, &kp);
            if cur != last
                && let Ok(new_cfg) = load_tls_config(&cp, &kp)
            {
                *tls_watch.write().await = Arc::new(new_cfg);
                last = cur;
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

    for addr in http_addrs {
        let listener = bind_tcp_freebind(addr)?;
        let app_http = state.clone();
        let srv_fallback = router.clone();
        let slots = Arc::clone(&slots);
        let fb = Arc::clone(&fallback_host);
        tokio::spawn(accept_loop(listener, slots, move |stream, peer, permit| {
            let st = app_http.clone();
            let r_fb = srv_fallback.clone();
            let fb = Arc::clone(&fb);
            async move {
                let _permit = permit;
                let redir = st.settings.read().await.https_redirect;
                if redir {
                    let redirect_svc = Router::new()
                        .route("/.well-known/acme-challenge/{token}", get(acme_http01_handler))
                        .fallback(move |req: Request| {
                            let fb = Arc::clone(&fb);
                            async move { http_redirect_handler(req, &fb).await }
                        });
                    serve_connection_with(stream, redirect_svc, peer, limits, false).await;
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
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        let mut r = router.clone();
        async move {
            let axum_req = req.map(Body::new);
            r.call(axum_req).await
        }
    });
    if h2 {
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10));
        let _ = builder.serve_connection(hyper_io, svc).await;
    } else {
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

async fn http_redirect_handler(req: Request, fallback_host: &str) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or(fallback_host);
    let host_no_port = host.split(':').next().unwrap_or(host);
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target = format!("https://{host_no_port}{path_q}");
    let fallback_url = HeaderValue::from_str(&format!("https://{fallback_host}/"))
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
        .route("/api/v1/system/settings", get(handlers::get_settings).post(handlers::post_settings))
        .route("/api/v1/system/acme", get(crate::acme::get_acme).put(crate::acme::put_acme))
        .route("/api/v1/system/acme/issue", post(crate::acme::post_acme_issue))
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
        .route("/api/v1/auth/status", get(handlers::get_auth_status))
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
        .layer(middleware::from_fn(body_deadline_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(ctx)
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
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

async fn ws_upgrade_handler(
    State(ctx): State<HttpCtx>,
    headers: axum::http::HeaderMap,
    uri: Uri,
    ws: WebSocketUpgrade,
) -> Response {
    let token = extract_session_token(&headers).or_else(|| ws_query_token(&uri)).unwrap_or_default();
    ws.on_upgrade(move |socket| handle_ws_socket(ctx.app, socket, token))
}

/// True while the WebSocket's session is still valid (not logged out,
/// revoked by a password change, or expired).
async fn ws_session_alive(state: &AppState, token: &str) -> bool {
    state.auth.validate_token(token, false).await.is_some()
}

async fn handle_ws_socket(state: AppState, mut socket: WebSocket, token: String) {
    let mut rx = state.ws_tx.subscribe();
    let mut revoked = state.auth.subscribe_revocations();
    let mut expiry_check = tokio::time::interval(Duration::from_secs(60));
    expiry_check.tick().await;

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
            msg = rx.recv() => {
                match msg {
                    Ok(txt) => {
                        if socket.send(Message::Text(txt.into())).await.is_err() {
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
                        let _ = socket.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
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

async fn proxy_auth_middleware(State(ctx): State<HttpCtx>, req: Request, next: Next) -> Response {
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

/// Ensure a valid, loadable TLS pair exists (auto-generating a self-signed ECDSA P-256
/// cert under `/etc/cellcore/tls/` on factory modems that have no cert yet).
pub fn ensure_tls_pair(src: &TlsSources, lan_ip: Option<&str>) -> Result<(PathBuf, PathBuf), String> {
    let (cp, kp) = resolve_tls_pair(src);
    if cp.exists() && kp.exists() && load_tls_config(&cp, &kp).is_ok() {
        return Ok((cp, kp));
    }
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
    generate_self_signed_cert(&target_c, &target_k, lan_ip)?;
    Ok((target_c, target_k))
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
    async fn luci_and_ubus_require_a_cellcore_session() {
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

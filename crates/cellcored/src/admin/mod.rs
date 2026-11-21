//! Native replacements for the LuCI functions this gateway uses, served under
//! `/api/v1/admin/...` behind the normal session + CSRF middleware.
//!
//! Ground rules for every module here:
//! - argv-only process spawning through [`exec::run`] (bounded time and output);
//! - every input validated before it reaches an argv slot or a UCI value;
//! - configuration changes go through `uci` + commit + the service's reload;
//! - mutations are serialized by one lock and recorded in the daemon log;
//! - actions that can cut the owner off need a typed confirmation (HTTP 428 until given).

pub mod exec;
pub mod ucicfg;
pub mod validate;

mod access;
mod backup;
mod cron;
mod dhcp;
mod diag;
pub mod firewall;
mod mwan3;
mod netstat;
pub mod opkg;
mod procs;
mod services;
pub mod system;

use std::sync::OnceLock;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::Value;
use tokio::sync::{Mutex, MutexGuard};

use crate::http::HttpCtx;

pub fn ok(v: Value) -> Response {
    Json(v).into_response()
}

pub fn fail(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "status": "error", "error": msg.into() }))).into_response()
}

pub fn bad(msg: impl Into<String>) -> Response {
    fail(StatusCode::BAD_REQUEST, msg)
}

pub fn server(msg: impl Into<String>) -> Response {
    fail(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

pub fn conflict(msg: impl Into<String>) -> Response {
    fail(StatusCode::CONFLICT, msg)
}

pub fn forbidden(msg: impl Into<String>) -> Response {
    fail(StatusCode::FORBIDDEN, msg)
}

/// Typed confirmation gate. The client must echo `expected` in its `confirm` field;
/// until it does the request is answered with 428 and the phrase to type.
#[allow(clippy::result_large_err)] // early-return Response, idiomatic for handlers
pub fn require_confirm(given: Option<&str>, expected: &str, why: &str) -> Result<(), Response> {
    if given.map(str::trim) == Some(expected) {
        return Ok(());
    }
    Err((
        StatusCode::PRECONDITION_REQUIRED,
        Json(serde_json::json!({
            "status": "error",
            "error": why,
            "confirm": expected,
        })),
    )
        .into_response())
}

static MUTATE: OnceLock<Mutex<()>> = OnceLock::new();

/// Serializes every admin mutation (UCI edits, service actions, opkg, restore).
pub async fn mutate_lock() -> MutexGuard<'static, ()> {
    MUTATE.get_or_init(|| Mutex::new(())).lock().await
}

pub fn audit(ctx: &HttpCtx, msg: impl AsRef<str>) {
    ctx.app.push_daemon_log(format!("admin: {}", msg.as_ref()));
    // Also in the audit log: covers out-of-band actions such as the firewall
    // auto-rollback that no request is behind.
    ctx.app.audit.event("system", "admin", msg.as_ref());
}

/// All `/api/v1/admin` routes; merged into the protected router in `http.rs`.
pub fn routes() -> Router<HttpCtx> {
    const P: &str = "/api/v1/admin";
    let r = |p: &str| format!("{P}{p}");
    Router::new()
        // System
        .route(&r("/system"), get(system::get_system).post(system::post_system))
        .route(&r("/system/timezones"), get(system::get_timezones))
        // Access
        .route(&r("/access"), get(access::get_access))
        .route(&r("/access/dropbear"), post(access::post_dropbear))
        .route(&r("/access/keys"), post(access::post_key).delete(access::delete_key))
        // Services
        .route(&r("/services"), get(services::get_services))
        .route(&r("/services/action"), post(services::post_action))
        .route(&r("/services/rc-local"), get(services::get_rc_local).put(services::put_rc_local))
        // Scheduled tasks
        .route(&r("/cron"), get(cron::get_cron).put(cron::put_cron))
        .route(&r("/cron/validate"), post(cron::post_validate))
        // Processes
        .route(&r("/processes"), get(procs::get_processes))
        .route(&r("/processes/signal"), post(procs::post_signal))
        // Software
        .route(&r("/software"), get(opkg::get_software))
        .route(&r("/software/available"), get(opkg::get_available))
        .route(&r("/software/info"), get(opkg::get_info))
        .route(&r("/software/feeds"), get(opkg::get_feeds).put(opkg::put_feeds))
        .route(&r("/software/update"), post(opkg::post_update))
        .route(&r("/software/update-check"), get(opkg::get_update_check))
        .route(&r("/software/self-upgrade"), get(opkg::get_self_upgrade_status).post(opkg::post_self_upgrade))
        .route(&r("/software/install"), post(opkg::post_install))
        .route(&r("/software/remove"), post(opkg::post_remove))
        // Firewall
        .route(&r("/firewall"), get(firewall::get_firewall))
        .route(&r("/firewall/zone"), post(firewall::post_zone))
        .route(&r("/firewall/forwarding"), post(firewall::post_forwarding).delete(firewall::delete_forwarding))
        .route(&r("/firewall/redirect"), post(firewall::post_redirect).delete(firewall::delete_redirect))
        .route(&r("/firewall/rule"), post(firewall::post_rule).delete(firewall::delete_rule))
        .route(&r("/firewall/confirm"), post(firewall::post_confirm))
        .route(&r("/firewall/revert"), post(firewall::post_revert))
        // Multi-WAN
        .route(&r("/mwan3"), get(mwan3::get_mwan3))
        // Network status
        .route(&r("/network/interfaces"), get(netstat::get_interfaces))
        .route(&r("/network/interfaces/action"), post(netstat::post_interface_action))
        .route(&r("/network/routes"), get(netstat::get_routes))
        .route(&r("/network/static-routes"), get(netstat::get_static_routes))
        .route(&r("/network/static-route"), post(netstat::post_static_route).delete(netstat::delete_static_route))
        .route(&r("/network/neighbours"), get(netstat::get_neighbours))
        .route(&r("/network/connections"), get(netstat::get_connections))
        // DHCP / DNS
        .route(&r("/dhcp"), get(dhcp::get_dhcp))
        .route(&r("/dhcp/host"), post(dhcp::post_host).delete(dhcp::delete_host))
        .route(&r("/dhcp/domain"), post(dhcp::post_domain).delete(dhcp::delete_domain))
        .route(&r("/dhcp/dnsmasq"), post(dhcp::post_dnsmasq))
        // Diagnostics
        .route(&r("/diag/run"), post(diag::post_run))
        .route(&r("/diag/jobs/{id}"), get(diag::get_job).delete(diag::delete_job))
        // Backup
        .route(&r("/backup"), get(backup::get_backup))
        .route(&r("/backup/download"), get(backup::get_download))
        // Archive uploads (up to 32 MiB) get a body deadline sized to the upload;
        // this layer sits inside the auth layer, so only authenticated requests to
        // these two routes get more than the generic 15 s.
        .route(
            &r("/backup/inspect"),
            post(backup::post_inspect)
                .layer(DefaultBodyLimit::max(backup::MAX_ARCHIVE))
                .layer(axum::middleware::from_fn(archive_upload_deadline)),
        )
        .route(
            &r("/backup/restore"),
            post(backup::post_restore)
                .layer(DefaultBodyLimit::max(backup::MAX_ARCHIVE))
                .layer(axum::middleware::from_fn(archive_upload_deadline)),
        )
}

async fn archive_upload_deadline(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    crate::http::upload_deadline_middleware(backup::MAX_ARCHIVE as u64, req, next).await
}

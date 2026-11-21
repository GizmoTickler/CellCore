//! HTTP endpoints for the observability features. All of them sit behind
//! the normal session + CSRF middleware (merged into the protected router in
//! `http.rs`).

use std::collections::BTreeMap;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;

use super::{
    config::{self, Header, WebhookFormat},
    events::EventKind,
    failover, lock, metrics, notify, obs, save_config, usage_cycle,
};
use crate::{
    admin::{bad, ok, server},
    http::HttpCtx,
};

/// `GET /api/v1/metrics` (Prometheus text).
///
/// Merged into the protected router: a browser session, or a `read` or `rw`
/// API token (see `tokens::token_may_access`). The renderer itself is
/// `metrics::render_state` and is shared with the IPC `metrics` op.
pub fn metrics_routes() -> Router<HttpCtx> {
    Router::new().route("/api/v1/metrics", get(get_metrics))
}

pub fn routes() -> Router<HttpCtx> {
    Router::new()
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/failover", get(get_failover))
        .route("/api/v1/failover/config", post(post_failover_config))
        .route("/api/v1/network/data-usage/cycle", get(get_cycle))
        .route("/api/v1/network/data-usage/alerts", post(post_usage_alerts))
        .route("/api/v1/notify", get(get_notify).post(post_notify))
        .route("/api/v1/notify/test", post(post_notify_test))
}

async fn get_metrics(State(ctx): State<HttpCtx>) -> Response {
    let text = metrics::render_state(&ctx.app).await;
    ([(header::CONTENT_TYPE, metrics::CONTENT_TYPE)], text).into_response()
}

#[derive(Deserialize, Default)]
pub struct EventsQuery {
    since: Option<u64>,
    #[serde(rename = "type")]
    kind: Option<String>,
    limit: Option<usize>,
}

/// Parse a comma-separated type filter; unknown names are an error so a
/// typo does not silently return everything.
pub fn parse_kinds(raw: Option<&str>) -> Result<Vec<EventKind>, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|s| EventKind::parse(s.trim()).ok_or_else(|| format!("Unknown event type {:?}", s.trim())))
        .collect()
}

async fn get_events(Query(q): Query<EventsQuery>) -> Response {
    let kinds = match parse_kinds(q.kind.as_deref()) {
        Ok(k) => k,
        Err(e) => return bad(e),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, super::events::RING_CAP);
    let (events, counts, stored) = {
        let st = lock(&obs().events);
        (st.query(q.since, &kinds, limit), st.counts.clone(), st.len())
    };
    let counts: BTreeMap<&str, u64> = EventKind::ALL.iter().map(|k| (k.as_str(), counts.get(k).copied().unwrap_or(0))).collect();
    ok(serde_json::json!({
        "events": events,
        "stored": stored,
        "countsSinceStart": counts,
        "types": EventKind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
    }))
}

async fn get_failover() -> Response {
    ok(failover::status_json())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailoverCfgReq {
    throughput_detect: Option<bool>,
    baseline_bps: Option<u64>,
    sustain_secs: Option<u64>,
    release_secs: Option<u64>,
    hint_ttl_secs: Option<u64>,
}

fn in_range(v: Option<u64>, lo: u64, hi: u64, what: &str) -> Result<Option<u64>, String> {
    match v {
        Some(x) if !(lo..=hi).contains(&x) => Err(format!("{what} must be between {lo} and {hi}")),
        other => Ok(other),
    }
}

async fn post_failover_config(Json(b): Json<FailoverCfgReq>) -> Response {
    let checked = (|| -> Result<_, String> {
        Ok((
            in_range(b.baseline_bps, 64_000, 10_000_000_000, "baselineBps")?,
            in_range(b.sustain_secs, 10, 3600, "sustainSecs")?,
            in_range(b.release_secs, 30, 86_400, "releaseSecs")?,
            in_range(b.hint_ttl_secs, 60, 3600, "hintTtlSecs")?,
        ))
    })();
    let (base, sustain, release, ttl) = match checked {
        Ok(v) => v,
        Err(e) => return bad(e),
    };
    {
        let mut c = lock(&obs().config);
        let f = &mut c.failover;
        if let Some(v) = b.throughput_detect {
            f.throughput_detect = v;
        }
        if let Some(v) = base {
            f.baseline_bps = v;
        }
        if let Some(v) = sustain {
            f.sustain_secs = v;
        }
        if let Some(v) = release {
            f.release_secs = v;
        }
        if let Some(v) = ttl {
            f.hint_ttl_secs = v;
        }
    }
    if let Err(e) = save_config() {
        return server(e);
    }
    ok(failover::status_json())
}

async fn get_cycle(State(ctx): State<HttpCtx>) -> Response {
    let u = ctx.app.data_usage.read().await.clone();
    ok(usage_cycle::cycle_report(&u))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageAlertsReq {
    thresholds_enabled: Option<bool>,
    standby_floor_bytes: Option<u64>,
}

async fn post_usage_alerts(State(ctx): State<HttpCtx>, Json(b): Json<UsageAlertsReq>) -> Response {
    if let Some(f) = b.standby_floor_bytes
        && f != 0
        && !(1024 * 1024..=1024u64.pow(4)).contains(&f)
    {
        return bad("standbyFloorBytes must be 0 (off) or between 1 MiB and 1 TiB");
    }
    {
        let mut c = lock(&obs().config);
        if let Some(v) = b.thresholds_enabled {
            c.usage.thresholds_enabled = v;
        }
        if let Some(v) = b.standby_floor_bytes {
            c.usage.standby_floor_bytes = v;
        }
    }
    if let Err(e) = save_config() {
        return server(e);
    }
    get_cycle(State(ctx)).await
}

async fn get_notify() -> Response {
    let view = lock(&obs().config).public_view();
    ok(serde_json::json!({
        "config": view["notify"],
        "status": notify::status_json(),
        "types": EventKind::ALL.iter().map(|k| serde_json::json!({
            "type": k.as_str(),
            "default": k.notify_default(),
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct QuietReq {
    enabled: Option<bool>,
    start: Option<String>,
    end: Option<String>,
    allow_critical: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderReq {
    name: String,
    /// Absent = keep the stored value for this header name (write-only).
    value: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct WebhookReq {
    enabled: Option<bool>,
    url: Option<String>,
    format: Option<WebhookFormat>,
    headers: Option<Vec<HeaderReq>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct NtfyReq {
    enabled: Option<bool>,
    url: Option<String>,
    /// Absent = keep, "" = clear, value = set (never echoed back).
    token: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SmsReq {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct EnabledReq {
    enabled: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct NotifyReq {
    enabled: Option<bool>,
    kinds: Option<BTreeMap<String, bool>>,
    dedupe_secs: Option<u64>,
    rate_per_hour: Option<u32>,
    quiet: Option<QuietReq>,
    email: Option<EnabledReq>,
    webhook: Option<WebhookReq>,
    ntfy: Option<NtfyReq>,
    sms_forward: Option<SmsReq>,
}

/// Apply a notify update to a copy of the config; nothing is stored unless
/// the whole request validates.
pub fn apply_notify(cur: &config::NotifyConfig, b: NotifyReq) -> Result<config::NotifyConfig, String> {
    let mut n = cur.clone();
    if let Some(v) = b.enabled {
        n.enabled = v;
    }
    if let Some(k) = b.kinds {
        for (name, on) in k {
            EventKind::parse(&name).ok_or_else(|| format!("Unknown event type {name:?}"))?;
            n.kinds.insert(name, on);
        }
    }
    if let Some(v) = b.dedupe_secs {
        if v > 86_400 {
            return Err("dedupeSecs must be at most 86400".into());
        }
        n.dedupe_secs = v;
    }
    if let Some(v) = b.rate_per_hour {
        if !(1..=120).contains(&v) {
            return Err("ratePerHour must be between 1 and 120".into());
        }
        n.rate_per_hour = v;
    }
    if let Some(q) = b.quiet {
        if let Some(v) = q.enabled {
            n.quiet.enabled = v;
        }
        if let Some(s) = q.start {
            n.quiet.start = config::validate_hhmm(&s)?;
        }
        if let Some(s) = q.end {
            n.quiet.end = config::validate_hhmm(&s)?;
        }
        if let Some(v) = q.allow_critical {
            n.quiet.allow_critical = v;
        }
    }
    if let Some(e) = b.email
        && let Some(v) = e.enabled
    {
        n.email.enabled = v;
    }
    if let Some(w) = b.webhook {
        if let Some(v) = w.enabled {
            n.webhook.enabled = v;
        }
        if let Some(u) = w.url {
            n.webhook.url = if u.trim().is_empty() { String::new() } else { config::validate_url(&u)? };
        }
        if let Some(f) = w.format {
            n.webhook.format = f;
        }
        if let Some(hs) = w.headers {
            if hs.len() > config::MAX_HEADERS {
                return Err(format!("At most {} headers", config::MAX_HEADERS));
            }
            let mut out: Vec<Header> = Vec::with_capacity(hs.len());
            for h in hs {
                let name = config::validate_header_name(&h.name)?;
                if out.iter().any(|o| o.name.eq_ignore_ascii_case(&name)) {
                    return Err(format!("Header {name} is listed twice"));
                }
                let value = match h.value {
                    Some(v) => config::validate_header_value(&v)?,
                    None => cur
                        .webhook
                        .headers
                        .iter()
                        .find(|o| o.name.eq_ignore_ascii_case(&name))
                        .map(|o| o.value.clone())
                        .ok_or_else(|| format!("Header {name} needs a value"))?,
                };
                out.push(Header { name, value });
            }
            n.webhook.headers = out;
        }
        if n.webhook.enabled && n.webhook.url.is_empty() {
            return Err("Set a webhook URL before enabling it".into());
        }
    }
    if let Some(t) = b.ntfy {
        if let Some(v) = t.enabled {
            n.ntfy.enabled = v;
        }
        if let Some(u) = t.url {
            n.ntfy.url = if u.trim().is_empty() {
                String::new()
            } else {
                let u = config::validate_url(&u)?;
                notify::ntfy_target(&u)?;
                u
            };
        }
        if let Some(tok) = t.token {
            n.ntfy.token = if tok.trim().is_empty() { String::new() } else { config::validate_token(&tok)? };
        }
        if n.ntfy.enabled && n.ntfy.url.is_empty() {
            return Err("Set an ntfy topic URL before enabling it".into());
        }
    }
    if let Some(s) = b.sms_forward {
        if let Some(v) = s.enabled {
            n.sms_forward.enabled = v;
        }
        if let Some(i) = s.interval_secs {
            if !(notify::SMS_MIN_INTERVAL_SECS..=86_400).contains(&i) {
                return Err(format!("SMS poll interval must be between {} and 86400 seconds", notify::SMS_MIN_INTERVAL_SECS));
            }
            n.sms_forward.interval_secs = i;
        }
    }
    Ok(n)
}

async fn post_notify(Json(b): Json<NotifyReq>) -> Response {
    let cur = lock(&obs().config).notify.clone();
    let next = match apply_notify(&cur, b) {
        Ok(n) => n,
        Err(e) => return bad(e),
    };
    if next.sms_forward.enabled && !cur.sms_forward.enabled {
        notify::sms_forward_enabled_changed(true);
    }
    lock(&obs().config).notify = next;
    if let Err(e) = save_config() {
        return server(e);
    }
    get_notify().await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TestReq {
    sink: Option<String>,
}

async fn post_notify_test(Json(b): Json<TestReq>) -> Response {
    let only = match b.sink.as_deref() {
        None | Some("") | Some("all") => None,
        Some(s) if notify::SINKS.contains(&s) => Some(s),
        Some(s) => return bad(format!("Unknown sink {s:?}")),
    };
    let res = notify::send_test(only).await;
    let empty = res["results"].as_array().is_none_or(|a| a.is_empty());
    if empty {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "error": "No notification channel is enabled" })),
        )
            .into_response();
    }
    ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(v: serde_json::Value) -> NotifyReq {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn kinds_filter() {
        assert_eq!(parse_kinds(None).unwrap(), vec![]);
        assert_eq!(parse_kinds(Some("handover, ca_change")).unwrap(), vec![EventKind::Handover, EventKind::CaChange]);
        assert!(parse_kinds(Some("handover,bogus")).is_err());
    }

    #[test]
    fn secrets_are_write_only_and_kept_when_omitted() {
        let mut cur = config::NotifyConfig::default();
        cur.webhook.headers.push(Header { name: "Authorization".into(), value: "Bearer s3cret".into() });
        cur.ntfy.token = "tok".into();
        // headers re-sent without values keep theirs; token absent keeps it
        let n = apply_notify(
            &cur,
            req(serde_json::json!({
                "webhook": { "url": "https://h.example/x", "headers": [{ "name": "authorization" }, { "name": "X-Extra", "value": "1" }] },
                "ntfy": { "url": "https://ntfy.sh/t" }
            })),
        )
        .unwrap();
        assert_eq!(n.webhook.headers[0].value, "Bearer s3cret");
        assert_eq!(n.webhook.headers[1].value, "1");
        assert_eq!(n.ntfy.token, "tok");
        // empty string clears
        let n2 = apply_notify(&n, req(serde_json::json!({ "ntfy": { "token": "" } }))).unwrap();
        assert!(n2.ntfy.token.is_empty());
        // a new header without a value is refused
        assert!(apply_notify(&cur, req(serde_json::json!({ "webhook": { "headers": [{ "name": "X-New" }] } }))).is_err());
    }

    #[test]
    fn invalid_input_is_refused_atomically() {
        let cur = config::NotifyConfig::default();
        for bad in [
            serde_json::json!({ "webhook": { "url": "file:///etc/passwd" } }),
            serde_json::json!({ "webhook": { "url": "https://h/x", "headers": [{ "name": "Host", "value": "x" }] } }),
            serde_json::json!({ "webhook": { "url": "https://h/x", "headers": [{ "name": "X", "value": "a\r\nB: c" }] } }),
            serde_json::json!({ "webhook": { "enabled": true } }),
            serde_json::json!({ "ntfy": { "url": "https://ntfy.sh/" } }),
            serde_json::json!({ "ntfy": { "token": "a b" } }),
            serde_json::json!({ "kinds": { "nope": true } }),
            serde_json::json!({ "ratePerHour": 0 }),
            serde_json::json!({ "quiet": { "start": "25:00" } }),
            serde_json::json!({ "smsForward": { "intervalSecs": 5 } }),
            serde_json::json!({ "enabled": true, "webhook": { "url": "https://ok/x", "headers": [{ "name": "A", "value": "1" }, { "name": "a", "value": "2" }] } }),
        ] {
            assert!(apply_notify(&cur, req(bad.clone())).is_err(), "accepted {bad}");
        }
        let good = apply_notify(
            &cur,
            req(serde_json::json!({
                "enabled": true,
                "kinds": { "handover": true },
                "quiet": { "enabled": true, "start": "7:30", "end": "06:00" },
                "webhook": { "enabled": true, "url": "http://192.168.120.10:9093/api/v2/alerts", "format": "alertmanager" },
            })),
        )
        .unwrap();
        assert!(good.enabled && good.webhook.enabled);
        assert_eq!(good.quiet.start, "07:30");
        assert_eq!(good.webhook.format, WebhookFormat::Alertmanager);
    }
}

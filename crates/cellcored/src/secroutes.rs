//! Security/admin endpoints: audit log, API tokens, AT classification and the
//! CellCore config backup. Merged into the protected router in `http.rs`.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde::Deserialize;

use crate::{audit::AuditFilter, http::HttpCtx, tokens::TokenKind};

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "status": "error", "error": msg.into() }))).into_response()
}

async fn get_audit(State(ctx): State<HttpCtx>, Query(f): Query<AuditFilter>) -> Response {
    let entries = ctx.app.audit.query(&f);
    let (failures, overflow) = ctx.app.audit.auth_failures();
    Json(serde_json::json!({
        "entries": entries,
        "retained": ctx.app.audit.len(),
        "authFailures": failures,
        "tokenReads": ctx.app.audit.token_reads(),
        "authFailuresOther": overflow,
    }))
    .into_response()
}

async fn get_tokens(State(ctx): State<HttpCtx>) -> Response {
    Json(serde_json::json!({ "tokens": ctx.app.tokens.list() })).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateTokenReq {
    name: String,
    kind: TokenKind,
    #[serde(default, alias = "expiresDays")]
    expires_in_days: Option<u32>,
}

async fn post_token(State(ctx): State<HttpCtx>, Json(req): Json<CreateTokenReq>) -> Response {
    match ctx.app.tokens.create(&req.name, req.kind, req.expires_in_days) {
        Ok((info, token)) => {
            ctx.app.push_daemon_log(format!("API token created: {} ({})", info.name, info.kind.as_str()));
            Json(serde_json::json!({ "status": "success", "token": token, "info": info })).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

async fn delete_token(State(ctx): State<HttpCtx>, Path(id): Path<String>) -> Response {
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return err(StatusCode::BAD_REQUEST, "Invalid token id");
    }
    match ctx.app.tokens.revoke(&id) {
        Ok(Some(name)) => {
            ctx.app.push_daemon_log(format!("API token revoked: {name}"));
            Json(serde_json::json!({ "status": "success" })).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "No such token"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Deserialize)]
struct ClassifyQuery {
    command: String,
}

async fn get_at_classify(Query(q): Query<ClassifyQuery>) -> Response {
    match crate::atguard::classify(&q.command) {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

pub fn routes() -> Router<HttpCtx> {
    Router::new()
        .route("/api/v1/audit", get(get_audit))
        .route("/api/v1/security/tokens", get(get_tokens).post(post_token))
        .route("/api/v1/security/tokens/{id}", delete(delete_token))
        .route("/api/v1/modem/at/classify", get(get_at_classify))
        .merge(crate::appbackup::routes())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Method, Request, StatusCode, header},
    };
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};

    use crate::{
        auth::AuthStore,
        http::{HttpCtx, build_router},
        state::AppState,
        tokens::TokenKind,
    };

    struct T {
        router: axum::Router,
        app: AppState,
        auth: AuthStore,
    }

    fn setup(tag: &str) -> T {
        let dir = std::env::temp_dir().join(format!("qm-sec-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let auth = AuthStore::new(dir.join("sessions"));
        let app = AppState::for_tests(dir, auth.clone());
        let ctx = HttpCtx {
            app: app.clone(),
            proxy: Client::builder(TokioExecutor::new()).build_http(),
            enforce_uhttpd_loopback: true,
        };
        T { router: build_router(ctx), app, auth }
    }

    async fn send(t: &T, method: Method, uri: &str, headers: &[(&str, &str)], body: &str, peer: [u8; 4]) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder().method(method).uri(uri).header(header::HOST, "192.168.224.1");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/json").header(header::CONTENT_LENGTH, body.len());
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::from((peer, 40000))));
        let resp = tower::ServiceExt::oneshot(t.router.clone(), req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    const PEER: [u8; 4] = [192, 168, 224, 50];

    #[tokio::test]
    async fn token_lifecycle_scopes_and_csrf() {
        let t = setup("life");
        let sess = t.auth.create_session().await.unwrap();
        let cookie = format!("qm_session={}", sess.token);

        // session (cookie) creates a token; CSRF is required for the cookie
        let body = r#"{"name":"ci","kind":"rw","expiresInDays":30}"#;
        let (s, _) = send(&t, Method::POST, "/api/v1/security/tokens", &[("cookie", &cookie)], body, PEER).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "cookie session without CSRF");
        let (s, v) = send(&t, Method::POST, "/api/v1/security/tokens", &[("cookie", &cookie), ("x-qm-csrf", &sess.csrf_token)], body, PEER).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let tok = v["token"].as_str().unwrap().to_string();
        let id = v["info"]["id"].as_str().unwrap().to_string();
        assert!(tok.starts_with("qmt_"));
        // the list never shows the secret or the hash
        let (_, l) = send(&t, Method::GET, "/api/v1/security/tokens", &[("cookie", &cookie)], "", PEER).await;
        let ls = l.to_string();
        assert!(!ls.contains(&tok[21..]) && !ls.contains(&crate::tokens::hash_token(&tok)), "{ls}");

        let bearer = format!("Bearer {tok}");
        // rw: GET and POST work without any CSRF header
        let (s, _) = send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &bearer)], "", PEER).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = send(&t, Method::POST, "/api/v1/modem/refresh", &[("authorization", &bearer)], "", PEER).await;
        assert_eq!(s, StatusCode::OK);
        // rw reaches the AT console (no modem in tests -> 502); dangerous lines still need confirm
        let (s, _) = send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &bearer)], r#"{"command":"AT+CSQ"}"#, PEER).await;
        assert_eq!(s, StatusCode::BAD_GATEWAY);
        let (s, v) = send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &bearer)], r#"{"command":"AT+CFUN=0"}"#, PEER).await;
        assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
        let (s, _) = send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &bearer)], r#"{"command":"AT+CFUN=0","confirm":true}"#, PEER).await;
        assert_eq!(s, StatusCode::BAD_GATEWAY, "confirmed dangerous command reaches the modem queue");
        // the two session-only flows are refused even for rw
        for (m, p) in [
            (Method::POST, "/api/v1/system/password"),
            (Method::GET, "/api/v1/security/tokens"),
            (Method::POST, "/api/v1/security/tokens"),
        ] {
            let (s, _) = send(&t, m.clone(), p, &[("authorization", &bearer)], "{}", PEER).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{m} {p}");
        }
        let del = format!("/api/v1/security/tokens/{id}");
        let (s, _) = send(&t, Method::DELETE, &del, &[("authorization", &bearer)], "", PEER).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "a token cannot revoke tokens");

        // audit: the token request is recorded with its name, the session one as session
        let (_, a) = send(&t, Method::GET, "/api/v1/audit?auth=token", &[("cookie", &cookie)], "", PEER).await;
        let entries = a["entries"].as_array().unwrap();
        assert!(entries.iter().any(|e| e["route"] == "/api/v1/modem/refresh" && e["tokenName"] == "ci" && e["status"] == 200));
        assert!(entries.iter().any(|e| e["route"] == "/api/v1/modem/at"
            && e["tokenName"] == "ci"
            && e["summary"].as_str().unwrap().contains("at_class=dangerous at_cmds=+CFUN=0")));
        // token reads are counted per token
        let reads = a["tokenReads"].as_array().unwrap();
        assert!(reads.iter().any(|r| r["tokenName"] == "ci" && r["count"].as_u64().unwrap() >= 1), "{reads:?}");
        assert!(entries.iter().all(|e| e["auth"] == "token"));
        let (_, a) = send(&t, Method::GET, "/api/v1/audit?route=security/tokens&method=POST", &[("cookie", &cookie)], "", PEER).await;
        let e0 = &a["entries"].as_array().unwrap()[0];
        assert_eq!(e0["auth"], "session");
        assert_eq!(e0["peer"], "192.168.224.50");
        assert!(e0["summary"].as_str().unwrap().contains("name=\"ci\""));

        // revoke via session -> the token stops working
        let (s, _) = send(&t, Method::DELETE, &del, &[("cookie", &cookie), ("x-qm-csrf", &sess.csrf_token)], "", PEER).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &bearer)], "", PEER).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("qm-sec-life-{}", std::process::id())));
    }

    /// Every (method, route template) the real routers declare, read from the
    /// sources so a route added anywhere is covered automatically.
    fn declared_routes() -> Vec<(Method, String)> {
        let sources = [
            ("", include_str!("http.rs")),
            ("/api/v1/admin", include_str!("admin/mod.rs")),
            ("", include_str!("secroutes.rs")),
            ("", include_str!("obs/api.rs")),
            ("/api/v1/system/config-backup", include_str!("appbackup.rs")),
            ("", include_str!("vpn/mod.rs")),
            ("", include_str!("dataplane.rs")),
        ];
        let mut out = Vec::new();
        for (prefix, src) in sources {
            // only the non-test part of the file
            let code = src.split("#[cfg(test)]").next().unwrap_or("");
            for chunk in code.split(".route(").skip(1) {
                let Some(q0) = chunk.find('"') else { continue };
                let rest = &chunk[q0 + 1..];
                let Some(q1) = rest.find('"') else { continue };
                let raw = &rest[..q1];
                let path = if raw.starts_with("/api/") {
                    raw.to_string()
                } else if let Some(r) = raw.strip_prefix("{P}") {
                    format!("{prefix}{r}")
                } else if raw.starts_with('/') && chunk[..q0].contains("r(") {
                    format!("{prefix}{raw}")
                } else {
                    continue; // LuCI proxy, static
                };
                let body = chunk.split(".route(").next().unwrap_or(chunk);
                let body = body.split("\n        .").next().unwrap_or(body);
                for (needle, m) in [("get(", Method::GET), ("post(", Method::POST), ("put(", Method::PUT), ("delete(", Method::DELETE)] {
                    let hit = body.match_indices(needle).any(|(i, _)| i == 0 || !body.as_bytes()[i - 1].is_ascii_alphanumeric() && body.as_bytes()[i - 1] != b'_');
                    if hit {
                        out.push((m, path.clone()));
                    }
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn every_declared_route_follows_the_token_type_rules() {
        use crate::tokens::{READ_DENY, is_session_only, token_may_access};
        let routes = declared_routes();
        assert!(routes.len() > 80, "route scan found only {}", routes.len());
        for must in ["/api/v1/metrics", "/api/v1/notify", "/api/v1/failover/config", "/api/v1/admin/cron", "/api/v1/admin/software/install", "/api/v1/modem/at", "/api/v1/system/config-backup/apply", "/api/v1/security/tokens/{id}", "/api/v1/system/password", "/api/v1/vpn/warp", "/api/v1/vpn/warp/teams", "/api/v1/vpn/warp/policy", "/api/v1/vpn/tailscale/settings", "/api/v1/vpn/packages"] {
            assert!(routes.iter().any(|(_, p)| p == must), "scan missed {must}");
        }
        for p in READ_DENY {
            assert!(routes.iter().any(|(m, rp)| *m == Method::GET && rp == p), "denylisted {p} is not a real GET route");
        }
        let public = ["/api/v1/auth/status", "/api/v1/auth/login", "/api/v1/public/preview"];
        let protected: Vec<&(Method, String)> = routes.iter().filter(|(_, p)| !public.contains(&p.as_str())).collect();

        // decisions for every declared route
        for (m, p) in &protected {
            let get = *m == Method::GET;
            let hard = is_session_only(p) || p == "/api/v1/ws";
            let rw = token_may_access(TokenKind::Rw, m, p, None).is_ok();
            let read = token_may_access(TokenKind::Read, m, p, None).is_ok();
            assert_eq!(rw, !hard, "rw {m} {p}");
            assert_eq!(read, get && !hard && !READ_DENY.contains(&p.as_str()), "read {m} {p}");
        }

        // and through the real router where it has no side effects: every
        // mutation with a read token, every denylisted GET with a read token,
        // and the session-only pair with an rw token are refused before any handler
        let t = setup("enum");
        let (_, rd) = t.app.tokens.create("reader", TokenKind::Read, None).unwrap();
        let (_, rw) = t.app.tokens.create("writer", TokenKind::Rw, None).unwrap();
        let (hr, hw) = (format!("Bearer {rd}"), format!("Bearer {rw}"));
        let mut checked = 0;
        for (m, p) in &protected {
            let uri = p.replace("{id}", "0123456789abcdef");
            if *m != Method::GET || READ_DENY.contains(&p.as_str()) || p == "/api/v1/ws" {
                let (s, v) = send(&t, m.clone(), &uri, &[("authorization", &hr)], "{}", PEER).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "read token reached {m} {p}: {v}");
                checked += 1;
            }
            if is_session_only(p) {
                let (s, v) = send(&t, m.clone(), &uri, &[("authorization", &hw)], "{}", PEER).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "rw token reached {m} {p}: {v}");
                checked += 1;
            }
        }
        assert!(checked > 50, "{checked}");
        assert_eq!(t.app.audit.len(), 0, "refused token requests never reach a handler");
        // export with identifiers: read refused, decided on the query too
        let (s, _) = send(&t, Method::GET, "/api/v1/system/config-backup/export?identifiers=1", &[("authorization", &hr)], "", PEER).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn read_tokens_read_and_rw_tokens_operate() {
        let t = setup("types");
        let (_, read) = t.app.tokens.create("r", TokenKind::Read, None).unwrap();
        let (_, rw) = t.app.tokens.create("w", TokenKind::Rw, None).unwrap();
        let h = |t: &str| format!("Bearer {t}");
        let at = r#"{"command":"AT+CSQ"}"#;
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &h(&read))], at, PEER).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &h(&rw))], at, PEER).await.0, StatusCode::BAD_GATEWAY);
        for p in [
            "/api/v1/bootstrap",
            "/api/v1/metrics",
            "/api/v1/failover",
            "/api/v1/cellular/tower-finder",
            "/api/v1/vpn/cloudflared",
            "/api/v1/modem/at/classify?command=AT%2BCSQ",
        ] {
            assert_eq!(send(&t, Method::GET, p, &[("authorization", &h(&read))], "", PEER).await.0, StatusCode::OK, "{p}");
        }
        for denied in [
            "/api/v1/audit",
            "/api/v1/modem/secrets",
            "/api/v1/events",
            "/api/v1/notify",
            "/api/v1/admin/services/rc-local",
            "/api/v1/admin/software/feeds",
            "/api/v1/system/ota",
        ] {
            assert_eq!(
                send(&t, Method::GET, denied, &[("authorization", &h(&read))], "", PEER).await.0,
                StatusCode::FORBIDDEN,
                "read token must be denied {denied}"
            );
        }
        assert_eq!(send(&t, Method::GET, "/api/v1/audit", &[("authorization", &h(&rw))], "", PEER).await.0, StatusCode::OK);
        assert_eq!(send(&t, Method::GET, "/api/v1/modem/secrets", &[("authorization", &h(&rw))], "", PEER).await.0, StatusCode::OK);
        assert_eq!(send(&t, Method::GET, "/api/v1/events", &[("authorization", &h(&rw))], "", PEER).await.0, StatusCode::OK);
        assert_eq!(send(&t, Method::GET, "/api/v1/notify", &[("authorization", &h(&rw))], "", PEER).await.0, StatusCode::OK);

        // Creating an rw token without expiresInDays via HTTP defaults to 90 days.
        let sess = t.auth.create_session().await.unwrap();
        let cookie = format!("qm_session={}", sess.token);
        let (s, v) = send(
            &t,
            Method::POST,
            "/api/v1/security/tokens",
            &[("cookie", &cookie), ("x-qm-csrf", &sess.csrf_token)],
            r#"{"name":"rw-default","kind":"rw"}"#,
            PEER,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let created_at = v["info"]["createdAt"].as_u64().unwrap();
        let expires_at = v["info"]["expiresAt"].as_u64().expect("rw token must default to 90d expiry");
        assert_eq!(expires_at - created_at, u64::from(crate::tokens::DEFAULT_RW_EXPIRY_DAYS) * 86_400);
    }

    #[tokio::test]
    async fn sessions_and_tokens_are_not_confusable() {
        let t = setup("confuse");
        let sess = t.auth.create_session().await.unwrap();
        let (_, tok) = t.app.tokens.create("x", TokenKind::Rw, None).unwrap();
        // an API token in the session cookie is not a session
        let c = format!("qm_session={tok}");
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("cookie", &c)], "", PEER).await.0, StatusCode::UNAUTHORIZED);
        // a session token dressed as an API token is not a token
        let fake = format!("Bearer qmt_{}", &sess.token[..16]);
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &fake)], "", PEER).await.0, StatusCode::UNAUTHORIZED);
        // a bad API token does not fall back to a valid session cookie
        let bad = format!("Bearer qmt_{}_{}", "0".repeat(16), "0".repeat(64));
        let sc = format!("qm_session={}", sess.token);
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &bad), ("cookie", &sc)], "", PEER).await.0, StatusCode::UNAUTHORIZED);
        // session bearer in the Authorization header keeps working (and, being
        // header-borne, needs no CSRF); with only a cookie it needs CSRF
        let sb = format!("Bearer {}", sess.token);
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &sb)], "", PEER).await.0, StatusCode::OK);
        let at = r#"{"command":"AT+CSQ"}"#;
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &sb)], at, PEER).await.0, StatusCode::BAD_GATEWAY);
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("cookie", &sc)], at, PEER).await.0, StatusCode::FORBIDDEN);
        // garbage in Authorization does not exempt a cookie session from CSRF
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("cookie", &sc), ("authorization", "Bearer nope")], at, PEER).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&t, Method::POST, "/api/v1/modem/at", &[("cookie", &sc), ("x-qm-csrf", &sess.csrf_token)], at, PEER).await.0, StatusCode::BAD_GATEWAY);
        // a valid token is accepted
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &format!("Bearer {tok}"))], "", PEER).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_token_auth_is_rate_limited_and_audited() {
        let t = setup("rl");
        let (_, tok) = t.app.tokens.create("x", TokenKind::Read, None).unwrap();
        let bad = format!("Bearer qmt_{}_{}", "1".repeat(16), "2".repeat(64));
        let attacker = [192, 168, 224, 77];
        let mut statuses = Vec::new();
        for _ in 0..12 {
            statuses.push(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &bad)], "", attacker).await.0);
        }
        assert!(statuses[..10].iter().all(|s| *s == StatusCode::UNAUTHORIZED), "{statuses:?}");
        assert_eq!(statuses[11], StatusCode::TOO_MANY_REQUESTS);
        let good = format!("Bearer {tok}");
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &good)], "", attacker).await.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(send(&t, Method::GET, "/api/v1/bootstrap", &[("authorization", &good)], "", PEER).await.0, StatusCode::OK);
        let (failed, _) = t.app.audit.auth_failures();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].peer, "192.168.224.77");
        assert!(failed[0].count >= 10);
        assert_eq!(t.app.audit.len(), 0, "auth failures never enter the entry ring");
        assert!(!format!("{failed:?}").contains("2222222222"), "presented token never logged");
    }

    #[tokio::test]
    async fn audit_redacts_secret_bodies_end_to_end() {
        let t = setup("redact");
        let sess = t.auth.create_session().await.unwrap();
        let sb = format!("Bearer {}", sess.token);
        let body = r#"{"currentPassword":"Sup3rSecret!","newPassword":"An0therSecret!"}"#;
        let _ = send(&t, Method::POST, "/api/v1/system/password", &[("authorization", &sb)], body, PEER).await;
        let imei = r#"{"imei":"356938035643809","password":"Sup3rSecret!","applyNow":false}"#;
        let _ = send(&t, Method::POST, "/api/v1/modem/imei", &[("authorization", &sb)], imei, PEER).await;
        let smtp = r#"{"smtpSender":"a@example.com","smtpPassword":"gmail-app-pass","smtpRecipient":"b@example.com"}"#;
        // a malformed body (unknown shape) still gets logged redacted; no fs side effect when the handler rejects it
        let _ = send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &sb)], &format!("{{\"command\":\"AT+EGMR=1,7,\\\"356938035643809\\\"\",\"x\":{smtp}}}"), PEER).await;
        // dangerous AT from a session: 428 without confirm; the log keeps names/class, not arguments
        let (s, v) = send(&t, Method::POST, "/api/v1/modem/at", &[("authorization", &sb)], r#"{"command":"AT+CPIN=\"4321\";+CFUN=0"}"#, PEER).await;
        assert_eq!(s, StatusCode::PRECONDITION_REQUIRED, "{v}");
        assert_eq!(v["classification"]["class"], "dangerous");
        let all = serde_json::to_string(&t.app.audit.query(&Default::default())).unwrap();
        assert!(all.contains("at_cmds=+CPIN=<redacted>;+CFUN=0"), "{all}");
        assert!(!all.contains("4321"), "{all}");
        for secret in ["Sup3rSecret", "An0therSecret", "356938035643809", "gmail-app-pass", &sess.token[..], &sess.csrf_token[..]] {
            assert!(!all.contains(secret), "{secret} leaked: {all}");
        }
        assert!(all.contains("/api/v1/system/password") && all.contains("/api/v1/modem/imei"));
    }
}

//! Firewall › zones / forwardings / rules (read), port forwards and traffic rules
//! (create / edit / delete through uci + `fw4 reload`).
//!
//! Every change is commit-confirm: the previous config is snapshotted, the change
//! is committed and fw4 reloaded, and unless the UI confirms within
//! [`CONFIRM_SECS`] (proving the browser can still reach the box) the snapshot is
//! restored automatically. Only `redirect` and `rule` sections are ever written;
//! the owner's nftables.d / firewall.user* files are shown read-only and never
//! written.

use std::{
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};

use super::{
    audit, bad, conflict, exec::{KIB, run}, mutate_lock, ok, require_confirm, server,
    ucicfg::{self, Op, UciSection, of_type},
    validate::{is_ip_or_cidr, is_label, is_port_spec, parse_ipv4},
};
use crate::http::HttpCtx;

pub const CONFIRM_SECS: u64 = 90;
const MAX_FILE: usize = 64 * 1024;

// ── read model ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub networks: Vec<String>,
    pub input: String,
    pub output: String,
    pub forward: String,
    pub masq: bool,
    pub mtu_fix: bool,
}

pub fn zones(sections: &[UciSection]) -> Vec<Zone> {
    of_type(sections, "zone")
        .into_iter()
        .map(|z| Zone {
            id: z.id.clone(),
            name: z.get_or("name", "").to_string(),
            networks: z.list("network"),
            input: z.get_or("input", "ACCEPT").to_string(),
            output: z.get_or("output", "ACCEPT").to_string(),
            forward: z.get_or("forward", "REJECT").to_string(),
            masq: z.flag("masq", false),
            mtu_fix: z.flag("mtu_fix", false),
        })
        .collect()
}

/// Options listed for a rule/redirect in the UI (anything else is preserved).
const RULE_KEYS: &[&str] = &["name", "src", "dest", "proto", "src_ip", "src_port", "dest_ip", "dest_port", "family", "target", "icmp_type"];
const REDIRECT_KEYS: &[&str] = &["name", "src", "dest", "proto", "src_ip", "src_dport", "dest_ip", "dest_port", "target", "reflection", "family"];

fn entry_json(s: &UciSection, keys: &[&str]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("id".into(), s.id.clone().into());
    m.insert("index".into(), s.index.into());
    m.insert("enabled".into(), s.flag("enabled", true).into());
    for k in keys {
        if let Some(v) = s.options.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.items().join(" ")) {
            m.insert((*k).into(), v.into());
        }
    }
    m.insert("all".into(), s.options_json());
    serde_json::Value::Object(m)
}

/// A redirect with no source port and proto all forwards every port of the WAN
/// address to one host (DMZ / IP passthrough): removing or changing it can cut
/// the downstream router off.
pub fn is_passthrough(s: &UciSection) -> bool {
    let proto = s.get_or("proto", "tcp udp");
    s.get("src_dport").is_none() && (proto == "all" || proto.is_empty())
}

/// Files the owner maintains by hand; shown read-only.
fn hardening_files() -> Vec<serde_json::Value> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/etc/nftables.d") {
        paths.extend(rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "nft")));
    }
    if let Ok(rd) = std::fs::read_dir("/etc") {
        paths.extend(
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("firewall.user"))),
        );
    }
    paths.sort();
    paths
        .into_iter()
        .filter(|p| p.is_file())
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap_or_default();
            let truncated = bytes.len() > MAX_FILE;
            serde_json::json!({
                "path": p.display().to_string(),
                "size": bytes.len(),
                "content": String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_FILE)]),
                "truncated": truncated,
            })
        })
        .collect()
}

// ── pending commit-confirm ──────────────────────────────────────────────────

struct Pending {
    token: String,
    deadline: Instant,
    snapshot: String,
    summary: String,
}

static PENDING: OnceLock<Mutex<Option<Pending>>> = OnceLock::new();

fn pending() -> &'static Mutex<Option<Pending>> {
    PENDING.get_or_init(|| Mutex::new(None))
}

/// A firewall change is waiting for commit-confirm. Other writers of
/// /etc/config/firewall (the VPN module) refuse meanwhile: the pending
/// rollback restores a snapshot and would silently drop their sections.
pub fn change_pending() -> bool {
    pending().lock().map(|p| p.is_some()).unwrap_or(true)
}

fn pending_json() -> serde_json::Value {
    match pending().lock().ok().as_deref() {
        Some(Some(p)) => serde_json::json!({
            "token": p.token,
            "secondsLeft": p.deadline.saturating_duration_since(Instant::now()).as_secs(),
            "summary": p.summary,
        }),
        _ => serde_json::Value::Null,
    }
}

fn new_token() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    hex::encode(b)
}

pub fn detect_firewall_bin() -> &'static str {
    if std::path::Path::new(&crate::paths::p("/sbin/fw4")).exists()
        || std::path::Path::new(&crate::paths::p("/usr/sbin/fw4")).exists()
    {
        "fw4"
    } else {
        "fw3"
    }
}

async fn fw_reload(fw: &str) -> Result<(), String> {
    let out = run(fw, &["reload"], super::exec::ExecOpts::new(60, 64 * KIB)).await?;
    if out.ok() { Ok(()) } else { Err(out.err_summary(&format!("{fw} reload"))) }
}

/// Restore the snapshot behind `token` (if it is still pending).
async fn rollback(ctx: &HttpCtx, token: &str, why: &str) -> Result<bool, String> {
    let _g = mutate_lock().await;
    let p = {
        let mut guard = pending().lock().map_err(|_| "lock poisoned")?;
        match guard.as_ref() {
            Some(p) if p.token == token => guard.take(),
            _ => None,
        }
    };
    let Some(p) = p else { return Ok(false) };
    ucicfg::restore_snapshot("firewall", &p.snapshot).await?;
    let fw = detect_firewall_bin();
    let r = fw_reload(fw).await;
    audit(ctx, format!("firewall change rolled back via {fw} ({why}): {}", p.summary));
    r.map(|_| true)
}

/// Commit `ops` on firewall, reload the firewall backend (fw4 or fw3) and arm the auto-rollback.
async fn apply_with_confirm(ctx: &HttpCtx, new_type: Option<&str>, ops: Vec<Op>, summary: String) -> Response {
    let _g = mutate_lock().await;
    if pending().lock().map(|p| p.is_some()).unwrap_or(true) {
        return conflict("A previous firewall change is still waiting for confirmation; confirm or revert it first");
    }
    let snapshot = match ucicfg::export("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let new_id = match ucicfg::apply("firewall", new_type, ops).await {
        Ok(id) => id,
        Err(e) => return server(e),
    };
    let fw = detect_firewall_bin();
    if let Err(e) = fw_reload(fw).await {
        let rb = ucicfg::restore_snapshot("firewall", &snapshot).await;
        let _ = fw_reload(fw).await;
        audit(ctx, format!("firewall change rejected by {fw}, restored ({:?}): {summary}", rb.is_ok()));
        return server(format!("{fw} rejected the change, previous rules restored: {e}"));
    }
    let token = new_token();
    if let Ok(mut p) = pending().lock() {
        *p = Some(Pending {
            token: token.clone(),
            deadline: Instant::now() + Duration::from_secs(CONFIRM_SECS),
            snapshot,
            summary: summary.clone(),
        });
    }
    let (ctx2, tok2) = (ctx.clone(), token.clone());
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(CONFIRM_SECS)).await;
        let _ = rollback(&ctx2, &tok2, "not confirmed in time").await;
    });
    audit(ctx, format!("firewall change applied, awaiting confirmation: {summary}"));
    ok(serde_json::json!({
        "status": "pending",
        "id": new_id,
        "pending": { "token": token, "secondsLeft": CONFIRM_SECS, "summary": summary },
    }))
}

#[derive(Deserialize)]
pub struct TokenReq {
    token: String,
}

pub async fn post_confirm(State(ctx): State<HttpCtx>, Json(req): Json<TokenReq>) -> Response {
    let mut g = match pending().lock() {
        Ok(g) => g,
        Err(_) => return server("lock poisoned"),
    };
    match g.as_ref() {
        Some(p) if p.token == req.token => {
            let s = g.take().map(|p| p.summary).unwrap_or_default();
            drop(g);
            audit(&ctx, format!("firewall change confirmed: {s}"));
            ok(serde_json::json!({ "status": "ok" }))
        }
        _ => conflict("Nothing to confirm (it may already have been rolled back)"),
    }
}

pub async fn post_revert(State(ctx): State<HttpCtx>, Json(req): Json<TokenReq>) -> Response {
    match rollback(&ctx, &req.token, "reverted by user").await {
        Ok(true) => ok(serde_json::json!({ "status": "ok" })),
        Ok(false) => conflict("Nothing to revert"),
        Err(e) => server(e),
    }
}

// ── GET ─────────────────────────────────────────────────────────────────────

pub async fn get_firewall() -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let defaults = of_type(&s, "defaults").first().map(|d| d.options_json()).unwrap_or_default();
    let fwd: Vec<serde_json::Value> = of_type(&s, "forwarding")
        .into_iter()
        .map(|f| serde_json::json!({ "id": f.id, "src": f.get_or("src", ""), "dest": f.get_or("dest", ""), "enabled": f.flag("enabled", true) }))
        .collect();
    let rules: Vec<serde_json::Value> = of_type(&s, "rule").into_iter().map(|r| entry_json(r, RULE_KEYS)).collect();
    let redirects: Vec<serde_json::Value> = of_type(&s, "redirect")
        .into_iter()
        .map(|r| {
            let mut v = entry_json(r, REDIRECT_KEYS);
            v["passthrough"] = is_passthrough(r).into();
            v
        })
        .collect();
    let includes: Vec<serde_json::Value> = of_type(&s, "include")
        .into_iter()
        .map(|i| serde_json::json!({ "id": i.id, "path": i.get_or("path", ""), "type": i.get_or("type", "script"), "enabled": i.flag("enabled", true) }))
        .collect();
    ok(serde_json::json!({
        "defaults": defaults,
        "zones": zones(&s),
        "forwardings": fwd,
        "rules": rules,
        "redirects": redirects,
        "includes": includes,
        "hardening": hardening_files(),
        "pending": pending_json(),
        "confirmSecs": CONFIRM_SECS,
    }))
}

// ── validation ──────────────────────────────────────────────────────────────

const PROTOS: &[&str] = &["tcp", "udp", "icmp", "icmpv6", "all", "esp", "ah", "gre", "sctp", "udplite"];

fn validate_proto(proto: &str) -> Result<(Vec<&str>, bool), String> {
    let toks: Vec<&str> = proto.split_whitespace().collect();
    if toks.is_empty() {
        return Err("Choose a protocol".into());
    }
    if let Some(t) = toks.iter().find(|t| !PROTOS.contains(t)) {
        return Err(format!("Unknown protocol {t}"));
    }
    if toks.contains(&"all") && toks.len() > 1 {
        return Err("'all' cannot be combined with other protocols".into());
    }
    let ports_ok = toks.iter().all(|t| matches!(*t, "tcp" | "udp" | "sctp" | "udplite"));
    Ok((toks, ports_ok))
}

fn opt_port(label: &str, v: &str, ports_ok: bool) -> Result<(), String> {
    if v.is_empty() {
        return Ok(());
    }
    if !ports_ok {
        return Err(format!("{label} needs protocol TCP and/or UDP"));
    }
    if !is_port_spec(v) {
        return Err(format!("{label} must be a port (1–65535) or range like 8000-8100"));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct RedirectReq {
    pub id: Option<String>,
    pub name: String,
    pub src: String,
    pub src_ip: String,
    pub src_dport: String,
    pub dest: String,
    pub dest_ip: String,
    pub dest_port: String,
    pub proto: String,
    pub enabled: bool,
    pub reflection: bool,
    pub confirm: Option<String>,
}

/// Validate a port forward; returns the UCI ops (section id "" = the new section).
pub fn redirect_ops(r: &RedirectReq, zone_names: &[String], sid: &str) -> Result<Vec<Op>, String> {
    let r = RedirectReq {
        name: r.name.trim().into(),
        src_ip: r.src_ip.trim().into(),
        src_dport: r.src_dport.trim().into(),
        dest_ip: r.dest_ip.trim().into(),
        dest_port: r.dest_port.trim().into(),
        ..r.clone()
    };
    if !is_label(&r.name) {
        return Err("Name: 1–64 printable characters, no quotes".into());
    }
    if !zone_names.contains(&r.src) {
        return Err("Source zone must be an existing zone".into());
    }
    let dest = if r.dest.is_empty() { "lan".to_string() } else { r.dest.clone() };
    if !zone_names.contains(&dest) {
        return Err("Destination zone must be an existing zone".into());
    }
    let (_, ports_ok) = validate_proto(&r.proto)?;
    opt_port("External port", &r.src_dport, ports_ok)?;
    opt_port("Internal port", &r.dest_port, ports_ok)?;
    if !r.dest_ip.is_empty() && parse_ipv4(&r.dest_ip).is_none() {
        return Err("Internal IP must be an IPv4 address".into());
    }
    if !r.src_ip.is_empty() && !is_ip_or_cidr(&r.src_ip) {
        return Err("Source IP must be an address or CIDR".into());
    }
    if r.src_dport.is_empty() && r.dest_ip.is_empty() {
        return Err("Set an external port or an internal IP".into());
    }
    if !r.dest_port.is_empty() && r.dest_ip.is_empty() && r.src_dport.is_empty() {
        return Err("An internal port needs an external port".into());
    }
    Ok(vec![
        Op::set(sid, "name", &r.name),
        Op::set(sid, "target", "DNAT"),
        Op::set(sid, "src", &r.src),
        Op::set(sid, "dest", &dest),
        Op::set(sid, "proto", r.proto.split_whitespace().collect::<Vec<_>>().join(" ")),
        Op::set_or_clear(sid, "src_ip", &r.src_ip),
        Op::set_or_clear(sid, "src_dport", &r.src_dport),
        Op::set_or_clear(sid, "dest_ip", &r.dest_ip),
        Op::set_or_clear(sid, "dest_port", &r.dest_port),
        Op::set(sid, "reflection", if r.reflection { "1" } else { "0" }),
        Op::set(sid, "enabled", if r.enabled { "1" } else { "0" }),
    ])
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct RuleReq {
    pub id: Option<String>,
    pub name: String,
    pub src: String,
    pub dest: String,
    pub proto: String,
    pub src_ip: String,
    pub src_port: String,
    pub dest_ip: String,
    pub dest_port: String,
    pub family: String,
    pub target: String,
    pub enabled: bool,
    pub confirm: Option<String>,
}

pub fn rule_ops(r: &RuleReq, zone_names: &[String], sid: &str) -> Result<Vec<Op>, String> {
    let name = r.name.trim();
    if !is_label(name) {
        return Err("Name: 1–64 printable characters, no quotes".into());
    }
    let zone_ok = |z: &str| z == "*" || zone_names.iter().any(|n| n == z);
    if !zone_ok(&r.src) {
        return Err("Source zone must be an existing zone or *".into());
    }
    if !r.dest.is_empty() && !zone_ok(&r.dest) {
        return Err("Destination zone must be empty (this device), an existing zone, or *".into());
    }
    let (_, ports_ok) = validate_proto(&r.proto)?;
    opt_port("Source port", r.src_port.trim(), ports_ok)?;
    opt_port("Destination port", r.dest_port.trim(), ports_ok)?;
    for (label, v) in [("Source IP", r.src_ip.trim()), ("Destination IP", r.dest_ip.trim())] {
        if !v.is_empty() && !is_ip_or_cidr(v) {
            return Err(format!("{label} must be an address or CIDR"));
        }
    }
    if !matches!(r.family.as_str(), "" | "any" | "ipv4" | "ipv6") {
        return Err("Family must be any, ipv4 or ipv6".into());
    }
    if !matches!(r.target.as_str(), "ACCEPT" | "REJECT" | "DROP") {
        return Err("Action must be ACCEPT, REJECT or DROP".into());
    }
    let family = if r.family == "any" { "" } else { r.family.as_str() };
    Ok(vec![
        Op::set(sid, "name", name),
        Op::set(sid, "src", &r.src),
        Op::set_or_clear(sid, "dest", &r.dest),
        Op::set(sid, "proto", r.proto.split_whitespace().collect::<Vec<_>>().join(" ")),
        Op::set_or_clear(sid, "src_ip", r.src_ip.trim()),
        Op::set_or_clear(sid, "src_port", r.src_port.trim()),
        Op::set_or_clear(sid, "dest_ip", r.dest_ip.trim()),
        Op::set_or_clear(sid, "dest_port", r.dest_port.trim()),
        Op::set_or_clear(sid, "family", family),
        Op::set(sid, "target", &r.target),
        Op::set(sid, "enabled", if r.enabled { "1" } else { "0" }),
    ])
}

/// A REJECT/DROP rule on traffic *to this device* from a LAN-side zone (or any
/// zone) can block the UI and SSH.
pub fn rule_can_lock_out(r: &RuleReq, zones: &[Zone]) -> bool {
    if r.target == "ACCEPT" || !r.enabled || !r.dest.is_empty() {
        return false;
    }
    if r.src == "*" {
        return true;
    }
    zones
        .iter()
        .find(|z| z.name == r.src)
        .is_some_and(|z| z.networks.iter().any(|n| n == "lan" || n.starts_with("lan")))
}

/// Return the first declared zone sharing `src`'s network list so fw3/fw4
/// rules target the active chain (on SDX75, `lan_wan` precedes `lan` for
/// network `lan` and would otherwise shadow rules on `src='lan'`).
pub fn effective_rule_src<'a>(src: &'a str, zones: &'a [Zone]) -> &'a str {
    if src == "*" {
        return src;
    }
    let Some((idx, chosen)) = zones.iter().enumerate().find(|(_, z)| z.name == src) else {
        return src;
    };
    if chosen.networks.is_empty() {
        return src;
    }
    zones[..idx]
        .iter()
        .find(|z| z.networks == chosen.networks)
        .map(|z| z.name.as_str())
        .unwrap_or(src)
}

fn zone_names(s: &[UciSection]) -> Vec<String> {
    zones(s).into_iter().map(|z| z.name).filter(|n| !n.is_empty()).collect()
}

#[allow(clippy::result_large_err)]
fn find_section<'a>(s: &'a [UciSection], id: &str, stype: &str) -> Result<&'a UciSection, Response> {
    s.iter()
        .find(|x| x.id == id)
        .filter(|x| x.stype == stype)
        .ok_or_else(|| bad(format!("No {stype} section {id}")))
}

// ── mutations ───────────────────────────────────────────────────────────────

pub async fn post_redirect(State(ctx): State<HttpCtx>, Json(req): Json<RedirectReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let names = zone_names(&s);
    let sid = req.id.clone().unwrap_or_default();
    if !sid.is_empty() {
        let existing = match find_section(&s, &sid, "redirect") {
            Ok(x) => x,
            Err(r) => return r,
        };
        if is_passthrough(existing)
            && let Err(r) = require_confirm(
                req.confirm.as_deref(),
                "PASSTHROUGH",
                &format!(
                    "This forward sends every WAN port to {}; it is how the downstream router gets its WAN. Type PASSTHROUGH to change it.",
                    existing.get_or("dest_ip", "a LAN host")
                ),
            )
        {
            return r;
        }
    }
    let ops = match redirect_ops(&req, &names, &sid) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    let new_type = sid.is_empty().then_some("redirect");
    let what = if sid.is_empty() { "add" } else { "edit" };
    apply_with_confirm(&ctx, new_type, ops, format!("{what} port forward '{}'", req.name.trim())).await
}

#[derive(Deserialize)]
pub struct DeleteReq {
    id: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn delete_redirect(State(ctx): State<HttpCtx>, Json(req): Json<DeleteReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sec = match find_section(&s, &req.id, "redirect") {
        Ok(x) => x,
        Err(r) => return r,
    };
    if is_passthrough(sec)
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "PASSTHROUGH",
            &format!(
                "Deleting this forward stops passing WAN traffic to {}; the downstream router loses its backup WAN. Type PASSTHROUGH to delete it.",
                sec.get_or("dest_ip", "a LAN host")
            ),
        )
    {
        return r;
    }
    let summary = format!("delete port forward '{}'", sec.get_or("name", &req.id));
    apply_with_confirm(&ctx, None, vec![Op::Delete { section: req.id.clone(), option: None }], summary).await
}

pub async fn post_rule(State(ctx): State<HttpCtx>, Json(req): Json<RuleReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sid = req.id.clone().unwrap_or_default();
    if !sid.is_empty()
        && let Err(r) = find_section(&s, &sid, "rule")
    {
        return r;
    }
    let all_zones = zones(&s);
    let mut eff_req = req.clone();
    eff_req.src = effective_rule_src(&req.src, &all_zones).to_string();
    let ops = match rule_ops(&eff_req, &zone_names(&s), &sid) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    if rule_can_lock_out(&eff_req, &all_zones)
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "BLOCK",
            "This rule rejects traffic from the LAN to the gateway itself and can block this page and SSH. If you lose access, the change reverts automatically. Type BLOCK to apply.",
        )
    {
        return r;
    }
    let new_type = sid.is_empty().then_some("rule");
    let what = if sid.is_empty() { "add" } else { "edit" };
    apply_with_confirm(&ctx, new_type, ops, format!("{what} traffic rule '{}'", eff_req.name.trim())).await
}

pub async fn delete_rule(State(ctx): State<HttpCtx>, Json(req): Json<DeleteReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sec = match find_section(&s, &req.id, "rule") {
        Ok(x) => x,
        Err(r) => return r,
    };
    let summary = format!("delete traffic rule '{}'", sec.get_or("name", &req.id));
    apply_with_confirm(&ctx, None, vec![Op::Delete { section: req.id.clone(), option: None }], summary).await
}

const ZONE_POLICIES: &[&str] = &["ACCEPT", "REJECT", "DROP"];

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ZoneReq {
    pub id: String,
    pub input: String,
    pub output: String,
    pub forward: String,
    pub masq: bool,
    pub mtu_fix: bool,
    pub confirm: Option<String>,
}

pub fn zone_ops(r: &ZoneReq) -> Result<Vec<Op>, String> {
    let id = r.id.trim();
    if id.is_empty() {
        return Err("Missing zone id".into());
    }
    let inp = r.input.trim();
    let out = r.output.trim();
    let fwd = r.forward.trim();
    for (label, val) in [("Input", inp), ("Output", out), ("Forward", fwd)] {
        if !ZONE_POLICIES.contains(&val) {
            return Err(format!("{label} policy must be ACCEPT, REJECT, or DROP"));
        }
    }
    Ok(vec![
        Op::set(id, "input", inp),
        Op::set(id, "output", out),
        Op::set(id, "forward", fwd),
        Op::set(id, "masq", if r.masq { "1" } else { "0" }),
        Op::set(id, "mtu_fix", if r.mtu_fix { "1" } else { "0" }),
    ])
}

pub async fn post_zone(State(ctx): State<HttpCtx>, Json(req): Json<ZoneReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sec = match find_section(&s, req.id.trim(), "zone") {
        Ok(x) => x,
        Err(r) => return r,
    };
    let zname = sec.get_or("name", &req.id).to_string();
    let ops = match zone_ops(&req) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    if zname == "lan"
        && (req.input.trim() != "ACCEPT" || req.output.trim() != "ACCEPT")
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "LOCKOUT",
            "Changing LAN input or output policy away from ACCEPT can cut access to this UI and SSH. Type LOCKOUT to apply (auto-reverts if unconfirmed).",
        )
    {
        return r;
    }
    apply_with_confirm(&ctx, None, ops, format!("update firewall zone '{zname}'")).await
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ForwardingReq {
    pub src: String,
    pub dest: String,
    pub enabled: Option<bool>,
}

pub fn forwarding_ops(
    r: &ForwardingReq,
    zone_names: &[String],
    existing: &[(String, String)],
) -> Result<Vec<Op>, String> {
    let src = r.src.trim();
    let dest = r.dest.trim();
    if !zone_names.iter().any(|z| z == src) {
        return Err(format!("Unknown source zone '{src}'"));
    }
    if !zone_names.iter().any(|z| z == dest) {
        return Err(format!("Unknown destination zone '{dest}'"));
    }
    if src == dest {
        return Err("Source and destination zones must be different".into());
    }
    if existing.iter().any(|(s, d)| s == src && d == dest) {
        return Err(format!("Forwarding {src} -> {dest} already exists"));
    }
    Ok(vec![
        Op::set("", "src", src),
        Op::set("", "dest", dest),
        Op::set("", "enabled", if r.enabled.unwrap_or(true) { "1" } else { "0" }),
    ])
}

pub async fn post_forwarding(State(ctx): State<HttpCtx>, Json(req): Json<ForwardingReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let existing: Vec<(String, String)> = of_type(&s, "forwarding")
        .into_iter()
        .map(|f| (f.get_or("src", "").to_string(), f.get_or("dest", "").to_string()))
        .collect();
    let ops = match forwarding_ops(&req, &zone_names(&s), &existing) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    apply_with_confirm(
        &ctx,
        Some("forwarding"),
        ops,
        format!("add forwarding {} -> {}", req.src.trim(), req.dest.trim()),
    )
    .await
}

pub async fn delete_forwarding(State(ctx): State<HttpCtx>, Json(req): Json<DeleteReq>) -> Response {
    let s = match ucicfg::show("firewall").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let sec = match find_section(&s, &req.id, "forwarding") {
        Ok(x) => x,
        Err(r) => return r,
    };
    let src = sec.get_or("src", "");
    let dest = sec.get_or("dest", "");
    if src == "lan"
        && dest == "wan"
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "DELETE",
            "Removing lan -> wan forwarding cuts outbound internet access for LAN clients. Type DELETE to remove (auto-reverts if unconfirmed).",
        )
    {
        return r;
    }
    let summary = format!("delete forwarding {src} -> {dest}");
    apply_with_confirm(&ctx, None, vec![Op::Delete { section: req.id.clone(), option: None }], summary).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<UciSection> {
        ucicfg::parse_uci_show("firewall", include_str!("fixtures/uci_firewall.txt"))
    }

    fn names() -> Vec<String> {
        zone_names(&fixture())
    }

    fn ops_kv(ops: &[Op]) -> Vec<(String, String)> {
        ops.iter()
            .filter_map(|o| match o {
                Op::Set { option, value, .. } => Some((option.clone(), value.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn reads_real_zones_and_passthrough() {
        let s = fixture();
        let z = zones(&s);
        assert_eq!(names(), vec!["lan_wan", "lan", "wan_all", "wan", "swip"]);
        let wan = z.iter().find(|x| x.name == "wan").unwrap();
        assert!(wan.masq);
        assert_eq!(wan.input, "REJECT");
        let red = of_type(&s, "redirect")[0];
        assert!(is_passthrough(red));
        assert_eq!(red.get("dest_ip"), Some("192.168.224.2"));
    }

    #[test]
    fn validates_port_forward() {
        let ok = RedirectReq {
            name: "Web".into(),
            src: "wan".into(),
            src_dport: "8443".into(),
            dest_ip: "192.168.224.10".into(),
            dest_port: "443".into(),
            proto: "tcp".into(),
            enabled: true,
            ..Default::default()
        };
        let ops = redirect_ops(&ok, &names(), "").unwrap();
        let kv = ops_kv(&ops);
        assert!(kv.contains(&("dest".into(), "lan".into())));
        assert!(kv.contains(&("target".into(), "DNAT".into())));
        assert!(kv.contains(&("src_dport".into(), "8443".into())));

        let tcpudp = RedirectReq { proto: "tcp  udp".into(), ..ok.clone() };
        assert!(ops_kv(&redirect_ops(&tcpudp, &names(), "x").unwrap()).contains(&("proto".into(), "tcp udp".into())));

        for (bad, why) in [
            (RedirectReq { src: "internet".into(), ..ok.clone() }, "unknown zone"),
            (RedirectReq { src_dport: "0".into(), ..ok.clone() }, "port 0"),
            (RedirectReq { src_dport: "22;reboot".into(), ..ok.clone() }, "injection"),
            (RedirectReq { dest_ip: "192.168.224.300".into(), ..ok.clone() }, "bad ip"),
            (RedirectReq { proto: "icmp".into(), ..ok.clone() }, "ports with icmp"),
            (RedirectReq { proto: "all tcp".into(), ..ok.clone() }, "all + tcp"),
            (RedirectReq { name: "x'y".into(), ..ok.clone() }, "quote in name"),
            (RedirectReq { src_dport: "".into(), dest_ip: "".into(), ..ok.clone() }, "nothing to forward"),
            (RedirectReq { src_ip: "1.2.3.4/40".into(), ..ok.clone() }, "bad cidr"),
        ] {
            assert!(redirect_ops(&bad, &names(), "").is_err(), "{why}");
        }
        // Passthrough style (proto all, no ports) is valid but flagged elsewhere.
        let dmz = RedirectReq { proto: "all".into(), src_dport: "".into(), dest_port: "".into(), ..ok.clone() };
        assert!(redirect_ops(&dmz, &names(), "").is_ok());
    }

    #[test]
    fn validates_rules_and_lockout() {
        let s = fixture();
        let z = zones(&s);
        let allow = RuleReq {
            name: "Allow SSH from WAN".into(),
            src: "wan".into(),
            proto: "tcp".into(),
            dest_port: "22".into(),
            family: "ipv4".into(),
            target: "ACCEPT".into(),
            enabled: true,
            ..Default::default()
        };
        let kv = ops_kv(&rule_ops(&allow, &names(), "").unwrap());
        assert!(kv.contains(&("target".into(), "ACCEPT".into())));
        assert!(!rule_can_lock_out(&allow, &z));

        let block_lan = RuleReq { src: "lan".into(), target: "REJECT".into(), dest_port: "".into(), ..allow.clone() };
        assert!(rule_ops(&block_lan, &names(), "").is_ok());
        assert!(rule_can_lock_out(&block_lan, &z));
        let block_any = RuleReq { src: "*".into(), target: "DROP".into(), ..allow.clone() };
        assert!(rule_can_lock_out(&block_any, &z));
        let forward_block = RuleReq { dest: "wan".into(), ..block_lan.clone() };
        assert!(!rule_can_lock_out(&forward_block, &z));
        let disabled = RuleReq { enabled: false, ..block_lan.clone() };
        assert!(!rule_can_lock_out(&disabled, &z));

        assert_eq!(effective_rule_src("lan", &z), "lan_wan");
        assert_eq!(effective_rule_src("wan", &z), "wan");
        assert_eq!(effective_rule_src("*", &z), "*");

        for bad in [
            RuleReq { target: "MASQUERADE".into(), ..allow.clone() },
            RuleReq { family: "ipv5".into(), ..allow.clone() },
            RuleReq { src: "nope".into(), ..allow.clone() },
            RuleReq { dest_ip: "not-an-ip".into(), ..allow.clone() },
            RuleReq { proto: "icmp".into(), ..allow.clone() },
        ] {
            assert!(rule_ops(&bad, &names(), "").is_err());
        }
    }

    #[test]
    fn detects_fw4_or_falls_back_to_fw3() {
        {
            let env = crate::paths::TestSandbox::new("fw-detect");
            assert_eq!(detect_firewall_bin(), "fw3");
            env.write("/sbin/fw4", "");
            assert_eq!(detect_firewall_bin(), "fw4");
        }
        let env2 = crate::paths::TestSandbox::new("fw-detect-usr");
        assert_eq!(detect_firewall_bin(), "fw3");
        env2.write("/usr/sbin/fw4", "");
        assert_eq!(detect_firewall_bin(), "fw4");
    }

    #[tokio::test]
    async fn apply_and_rollback_use_detected_firewall_bin() {
        let env = crate::paths::TestSandbox::new("fw-apply");
        let log = env.root.join("fw.log");
        env.write_exec(
            "/bin/uci",
            "#!/bin/sh\ncase \"$1\" in\n  export) echo \"package firewall\" ;;\n  add) echo \"cfg010203\" ;;\nesac\nexit 0\n",
        );
        env.write_exec(
            "/bin/fw3",
            &format!("#!/bin/sh\necho \"fw3 $*\" >> {}\necho \"bad nft rule\" >&2\nexit 1\n", log.display()),
        );
        env.write_exec(
            "/bin/fw4",
            &format!("#!/bin/sh\necho \"fw4 $*\" >> {}\nexit 0\n", log.display()),
        );
        let ctx = HttpCtx::for_tests(&env.root);

        crate::paths::TEST_ENV
            .scope(env.env(), async {
                // Absent /sbin/fw4 -> uses fw3, interpolates fw3 into error & audit
                let resp = apply_with_confirm(
                    &ctx,
                    Some("rule"),
                    vec![Op::set("", "name", "test")],
                    "add test rule".into(),
                )
                .await;
                assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let err = v["error"].as_str().unwrap();
                assert!(err.contains("fw3 rejected the change"), "{err}");
                assert!(err.contains("fw3 reload"), "{err}");
                let calls = std::fs::read_to_string(&log).unwrap();
                assert_eq!(calls.lines().collect::<Vec<_>>(), vec!["fw3 reload", "fw3 reload"]);
                let dlogs = ctx.app.daemon_logs.read().await;
                assert!(dlogs.iter().any(|l| l.contains("rejected by fw3")), "{dlogs:?}");
                drop(dlogs);

                // Present /sbin/fw4 -> uses fw4 for apply and rollback
                std::fs::write(&log, "").unwrap();
                env.write("/sbin/fw4", "");
                let resp2 = apply_with_confirm(
                    &ctx,
                    Some("rule"),
                    vec![Op::set("", "name", "test2")],
                    "add fw4 rule".into(),
                )
                .await;
                assert_eq!(resp2.status(), axum::http::StatusCode::OK);
                let body2 = axum::body::to_bytes(resp2.into_body(), 8192).await.unwrap();
                let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
                let tok = v2["pending"]["token"].as_str().unwrap().to_string();
                assert!(rollback(&ctx, &tok, "test revert").await.unwrap());
                let calls2 = std::fs::read_to_string(&log).unwrap();
                assert_eq!(calls2.lines().collect::<Vec<_>>(), vec!["fw4 reload", "fw4 reload"]);
                let dlogs2 = ctx.app.daemon_logs.read().await;
                assert!(dlogs2.iter().any(|l| l.contains("rolled back via fw4")), "{dlogs2:?}");
            })
            .await;
    }

    #[test]
    fn validates_zones_and_forwardings() {
        let ok_z = ZoneReq {
            id: "cfg01".into(),
            input: "DROP".into(),
            output: "ACCEPT".into(),
            forward: "REJECT".into(),
            masq: true,
            mtu_fix: true,
            confirm: None,
        };
        let kv = ops_kv(&zone_ops(&ok_z).unwrap());
        assert!(kv.contains(&("input".into(), "DROP".into())));
        assert!(kv.contains(&("mtu_fix".into(), "1".into())));

        assert!(zone_ops(&ZoneReq { input: "ALLOW".into(), ..ok_z.clone() }).is_err());
        assert!(zone_ops(&ZoneReq { id: "".into(), ..ok_z }).is_err());

        let existing = vec![("lan".into(), "wan".into())];
        let add = ForwardingReq { src: "lan".into(), dest: "swip".into(), enabled: Some(true) };
        let fkv = ops_kv(&forwarding_ops(&add, &names(), &existing).unwrap());
        assert!(fkv.contains(&("src".into(), "lan".into())));
        assert!(fkv.contains(&("dest".into(), "swip".into())));

        assert!(forwarding_ops(&ForwardingReq { src: "lan".into(), dest: "wan".into(), enabled: None }, &names(), &existing).is_err());
        assert!(forwarding_ops(&ForwardingReq { src: "lan".into(), dest: "lan".into(), enabled: None }, &names(), &existing).is_err());
        assert!(forwarding_ops(&ForwardingReq { src: "nope".into(), dest: "wan".into(), enabled: None }, &names(), &existing).is_err());
    }
}

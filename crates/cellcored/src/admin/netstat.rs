//! Network status › interfaces (`ubus call network.interface dump` + sysfs
//! counters), routing tables (`ip route show table all`), neighbours (`ip neigh`)
//! and connection tracking (`/proc/net/nf_conntrack`, fallback `conntrack -L`).

use std::{collections::HashMap, net::Ipv6Addr};

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    audit, bad, conflict,
    exec::{ExecOpts, KIB, MIB, run, run_ok},
    forbidden, mutate_lock, ok, require_confirm, server,
    ucicfg::{self, Op, UciSection},
    validate::{is_ip_or_cidr, is_ipv4_cidr, is_safe_name, parse_ipv4},
};
use crate::http::HttpCtx;

const MAX_CONNTRACK_BYTES: usize = 4 * MIB;
const MAX_CONN_ROWS: usize = 300;

// ── interfaces ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Iface {
    pub name: String,
    pub up: bool,
    pub proto: String,
    pub device: String,
    pub l3_device: String,
    pub uptime: u64,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dns: Vec<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_packets: Option<u64>,
    pub tx_packets: Option<u64>,
}

fn addrs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    let addr = x.get("address")?.as_str()?;
                    let mask = x.get("mask").and_then(Value::as_u64);
                    Some(match mask {
                        Some(m) => format!("{addr}/{m}"),
                        None => addr.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_iface_dump(json: &str) -> Vec<Iface> {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return Vec::new() };
    let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    v.get("interface")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|i| {
                    let mut ipv6 = addrs(i, "ipv6-address");
                    // Delegated prefixes assigned to this interface carry its global address.
                    if let Some(a) = i.get("ipv6-prefix-assignment").and_then(Value::as_array) {
                        for p in a {
                            if let Some(la) = p.get("local-address")
                                && let Some(addr) = la.get("address").and_then(Value::as_str)
                            {
                                let m = la.get("mask").and_then(Value::as_u64).unwrap_or(64);
                                ipv6.push(format!("{addr}/{m}"));
                            }
                        }
                    }
                    Iface {
                        name: s(i, "interface"),
                        up: i.get("up").and_then(Value::as_bool).unwrap_or(false),
                        proto: s(i, "proto"),
                        device: s(i, "device"),
                        l3_device: s(i, "l3_device"),
                        uptime: i.get("uptime").and_then(Value::as_u64).unwrap_or(0),
                        ipv4: addrs(i, "ipv4-address"),
                        ipv6,
                        dns: i
                            .get("dns-server")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                            .unwrap_or_default(),
                        rx_bytes: None,
                        tx_bytes: None,
                        rx_packets: None,
                        tx_packets: None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn sysfs_stat(dev: &str, name: &str) -> Option<u64> {
    if dev.is_empty() || dev.contains('/') || dev.starts_with('.') {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{dev}/statistics/{name}")).ok()?.trim().parse().ok()
}

pub async fn get_interfaces() -> Response {
    let out = match run_ok("ubus", &["call", "network.interface", "dump"], 10, 4 * MIB).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    let mut ifaces = parse_iface_dump(&out);
    for i in &mut ifaces {
        let dev = if i.l3_device.is_empty() { i.device.clone() } else { i.l3_device.clone() };
        i.rx_bytes = sysfs_stat(&dev, "rx_bytes");
        i.tx_bytes = sysfs_stat(&dev, "tx_bytes");
        i.rx_packets = sysfs_stat(&dev, "rx_packets");
        i.tx_packets = sysfs_stat(&dev, "tx_packets");
    }
    ok(serde_json::json!({ "interfaces": ifaces }))
}

// ── routes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    /// unicast | local | broadcast | anycast | multicast | unreachable | …
    pub kind: String,
    pub dst: String,
    pub via: Option<String>,
    pub dev: Option<String>,
    pub table: String,
    pub proto: Option<String>,
    pub scope: Option<String>,
    pub src: Option<String>,
    pub metric: Option<u32>,
    pub mtu: Option<String>,
    pub flags: Vec<String>,
}

const ROUTE_TYPES: &[&str] = &["unicast", "local", "broadcast", "anycast", "multicast", "unreachable", "blackhole", "prohibit", "throw", "nat"];

/// Parse `ip [-6] route show table all` text.
pub fn parse_routes(text: &str) -> Vec<Route> {
    text.lines()
        .filter_map(|l| {
            let mut t = l.split_whitespace().peekable();
            let mut r = Route { kind: "unicast".into(), table: "main".into(), ..Default::default() };
            let first = *t.peek()?;
            if ROUTE_TYPES.contains(&first) {
                r.kind = first.to_string();
                t.next();
            }
            r.dst = t.next()?.to_string();
            while let Some(tok) = t.next() {
                match tok {
                    "via" => r.via = t.next().map(str::to_string),
                    "dev" => r.dev = t.next().map(str::to_string),
                    "table" => r.table = t.next().unwrap_or("").to_string(),
                    "proto" => r.proto = t.next().map(str::to_string),
                    "scope" => r.scope = t.next().map(str::to_string),
                    "src" => r.src = t.next().map(str::to_string),
                    "metric" => r.metric = t.next().and_then(|x| x.parse().ok()),
                    "mtu" => {
                        let mut v = t.next().unwrap_or("").to_string();
                        if v == "lock" {
                            v = format!("{} (locked)", t.next().unwrap_or(""));
                        }
                        r.mtu = Some(v);
                    }
                    "pref" | "expires" | "error" | "hoplimit" | "advmss" | "weight" | "realm" => {
                        t.next();
                    }
                    "linkdown" | "onlink" | "dead" | "pervasive" | "offload" | "trap" => r.flags.push(tok.to_string()),
                    _ => {}
                }
            }
            Some(r)
        })
        .collect()
}

pub async fn get_routes() -> Response {
    let v4 = run_ok("ip", &["-4", "route", "show", "table", "all"], 10, 2 * MIB).await;
    let v6 = run_ok("ip", &["-6", "route", "show", "table", "all"], 10, 2 * MIB).await;
    let rules = run_ok("ip", &["rule", "show"], 10, MIB).await.unwrap_or_default();
    match (v4, v6) {
        (Ok(a), Ok(b)) => ok(serde_json::json!({
            "ipv4": parse_routes(&a),
            "ipv6": parse_routes(&b),
            "rules": rules.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>(),
        })),
        (Err(e), _) | (_, Err(e)) => server(e),
    }
}

// ── neighbours ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Neighbour {
    pub address: String,
    pub dev: String,
    pub lladdr: Option<String>,
    pub state: String,
    pub router: bool,
    pub family: &'static str,
}

/// Parse `ip neigh show`: `ADDR dev DEV [lladdr MAC] [router] STATE`.
pub fn parse_neigh(text: &str) -> Vec<Neighbour> {
    text.lines()
        .filter_map(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            let address = (*toks.first()?).to_string();
            let mut n = Neighbour {
                family: if address.contains(':') { "ipv6" } else { "ipv4" },
                address,
                dev: String::new(),
                lladdr: None,
                state: String::new(),
                router: false,
            };
            let mut i = 1;
            while i < toks.len() {
                match toks[i] {
                    "dev" => {
                        n.dev = toks.get(i + 1).unwrap_or(&"").to_string();
                        i += 1;
                    }
                    "lladdr" => {
                        n.lladdr = toks.get(i + 1).map(|s| s.to_string());
                        i += 1;
                    }
                    "router" => n.router = true,
                    "proxy" | "extern_learn" => {}
                    s if s.chars().all(|c| c.is_ascii_uppercase() || c == '_') => n.state = s.to_string(),
                    _ => {}
                }
                i += 1;
            }
            Some(n)
        })
        .collect()
}

pub async fn get_neighbours() -> Response {
    match run_ok("ip", &["neigh", "show"], 10, MIB).await {
        Ok(o) => ok(serde_json::json!({ "neighbours": parse_neigh(&o) })),
        Err(e) => server(e),
    }
}

// ── conntrack ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Conn {
    pub family: &'static str,
    pub proto: String,
    pub state: Option<String>,
    pub ttl: u64,
    pub src: String,
    pub dst: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub reply_src: String,
    pub bytes: u64,
    pub packets: u64,
    pub assured: bool,
}

/// Parse one line of /proc/net/nf_conntrack (`ipv4 2 tcp 6 …`) or `conntrack -L`
/// (`tcp 6 …`). The first `src=`/`dst=` pair is the original direction; byte and
/// packet counters of both directions are summed.
pub fn parse_conntrack_line(line: &str) -> Option<Conn> {
    let mut toks: Vec<&str> = line.split_whitespace().collect();
    let mut family = "ipv4";
    if matches!(toks.first(), Some(&"ipv4") | Some(&"ipv6")) {
        family = if toks[0] == "ipv6" { "ipv6" } else { "ipv4" };
        toks.drain(..2);
    }
    if toks.len() < 4 {
        return None;
    }
    let proto = toks[0].to_string();
    let ttl: u64 = toks[2].parse().ok()?;
    let mut state = None;
    let (mut src, mut dst, mut reply_src) = (None, None, None);
    let (mut sport, mut dport) = (None, None);
    let (mut bytes, mut packets) = (0u64, 0u64);
    let mut assured = false;
    let mut src_seen = 0;
    for t in &toks[3..] {
        if let Some((k, v)) = t.split_once('=') {
            match k {
                "src" => {
                    src_seen += 1;
                    if src_seen == 1 {
                        src = Some(v.to_string());
                    } else if src_seen == 2 {
                        reply_src = Some(v.to_string());
                    }
                }
                "dst" if dst.is_none() => dst = Some(v.to_string()),
                "sport" if sport.is_none() => sport = v.parse().ok(),
                "dport" if dport.is_none() => dport = v.parse().ok(),
                "bytes" => bytes += v.parse::<u64>().unwrap_or(0),
                "packets" => packets += v.parse::<u64>().unwrap_or(0),
                _ => {}
            }
        } else if *t == "[ASSURED]" {
            assured = true;
        } else if t.chars().all(|c| c.is_ascii_uppercase() || c == '_') && state.is_none() && src.is_none() {
            state = Some(t.to_string());
        }
    }
    let src = src?;
    if src.contains(':') {
        family = "ipv6";
    }
    Some(Conn {
        family,
        proto,
        state,
        ttl,
        src: compress_v6(&src),
        dst: compress_v6(&dst.unwrap_or_default()),
        sport,
        dport,
        reply_src: compress_v6(&reply_src.unwrap_or_default()),
        bytes,
        packets,
        assured,
    })
}

/// /proc/net/nf_conntrack prints IPv6 fully expanded; normalise it.
fn compress_v6(s: &str) -> String {
    if s.contains(':') {
        s.parse::<std::net::Ipv6Addr>().map(|a| a.to_string()).unwrap_or_else(|_| s.to_string())
    } else {
        s.to_string()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Talker {
    pub address: String,
    pub flows: usize,
    pub bytes: u64,
}

pub fn top_talkers(conns: &[Conn], n: usize) -> Vec<Talker> {
    let mut m: HashMap<&str, (usize, u64)> = HashMap::new();
    for c in conns {
        let e = m.entry(c.src.as_str()).or_default();
        e.0 += 1;
        e.1 += c.bytes;
    }
    let mut v: Vec<Talker> = m.into_iter().map(|(a, (f, b))| Talker { address: a.to_string(), flows: f, bytes: b }).collect();
    v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(b.flows.cmp(&a.flows)).then(a.address.cmp(&b.address)));
    v.truncate(n);
    v
}

pub async fn get_connections() -> Response {
    let text = match std::fs::File::open("/proc/net/nf_conntrack") {
        Ok(f) => {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = f.take(MAX_CONNTRACK_BYTES as u64).read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        }
        Err(_) => match run("conntrack", &["-L"], ExecOpts::new(15, MAX_CONNTRACK_BYTES)).await {
            Ok(o) => o.stdout_str(),
            Err(e) => return server(e),
        },
    };
    let mut conns: Vec<Conn> = text.lines().filter_map(parse_conntrack_line).collect();
    let count = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(conns.len() as u64);
    let max = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_max").ok().and_then(|s| s.trim().parse::<u64>().ok());
    let mut by_proto: HashMap<String, usize> = HashMap::new();
    for c in &conns {
        *by_proto.entry(c.proto.clone()).or_default() += 1;
    }
    let talkers = top_talkers(&conns, 10);
    conns.sort_by_key(|c| std::cmp::Reverse(c.bytes));
    conns.truncate(MAX_CONN_ROWS);
    ok(serde_json::json!({
        "count": count,
        "max": max,
        "byProto": by_proto,
        "topTalkers": talkers,
        "connections": conns,
        "accounting": conns.iter().any(|c| c.bytes > 0),
    }))
}

// ── static routes (UCI network) + interface actions ─────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaticRoute {
    pub id: String,
    pub family: String,
    pub interface: String,
    pub target: String,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    pub table: Option<u32>,
    pub disabled: bool,
}

pub fn parse_static_routes(sections: &[UciSection]) -> Vec<StaticRoute> {
    sections
        .iter()
        .filter(|s| matches!(s.stype.as_str(), "route" | "route6"))
        .map(|s| StaticRoute {
            id: s.id.clone(),
            family: if s.stype == "route6" { "ipv6" } else { "ipv4" }.to_string(),
            interface: s.get_or("interface", "").to_string(),
            target: s.get_or("target", "").to_string(),
            netmask: s.get("netmask").filter(|x| !x.is_empty()).map(str::to_string),
            gateway: s.get("gateway").filter(|x| !x.is_empty()).map(str::to_string),
            metric: s.get("metric").and_then(|x| x.parse::<u32>().ok()),
            table: s.get("table").and_then(|x| x.parse::<u32>().ok()),
            disabled: s.flag("disabled", false),
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StaticRouteReq {
    pub id: Option<String>,
    pub family: String,
    pub interface: String,
    pub target: String,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    pub table: Option<u32>,
    pub disabled: bool,
    pub confirm: Option<String>,
}

fn is_default_target(family: &str, target: &str, netmask: &str) -> bool {
    if family == "ipv6" {
        matches!(target, "::/0" | "::")
    } else {
        target == "0.0.0.0/0" || (target == "0.0.0.0" && (netmask.is_empty() || netmask == "0.0.0.0"))
    }
}

pub fn static_route_ops(
    r: &StaticRouteReq,
    ifaces: &[String],
    sid: &str,
) -> Result<(Vec<Op>, bool), String> {
    let fam = r.family.trim();
    if !matches!(fam, "ipv4" | "ipv6") {
        return Err("Family must be ipv4 or ipv6".into());
    }
    let iface = r.interface.trim();
    if !is_safe_name(iface, 32) {
        return Err("Invalid interface name".into());
    }
    if !ifaces.is_empty() && !ifaces.iter().any(|i| i == iface) {
        return Err(format!("Unknown interface '{iface}'"));
    }
    let target = r.target.trim();
    let nm = r.netmask.as_deref().unwrap_or("").trim();
    let gw = r.gateway.as_deref().unwrap_or("").trim();

    if fam == "ipv4" {
        if !is_ipv4_cidr(target) {
            return Err("Target must be an IPv4 address or CIDR (e.g. 10.0.0.0/24)".into());
        }
        if !nm.is_empty() {
            if target.contains('/') {
                return Err("Cannot specify both a CIDR prefix on target and a separate netmask".into());
            }
            if parse_ipv4(nm).is_none() {
                return Err("Netmask must be an IPv4 mask like 255.255.255.0".into());
            }
        }
        if !gw.is_empty() && parse_ipv4(gw).is_none() {
            return Err("Gateway must be a valid IPv4 address".into());
        }
    } else {
        if !target.contains(':') || !is_ip_or_cidr(target) {
            return Err("Target must be an IPv6 address or CIDR (e.g. fd00::/64)".into());
        }
        if !nm.is_empty() {
            return Err("IPv6 routes encode the prefix length in target CIDR, not netmask".into());
        }
        if !gw.is_empty() && gw.parse::<Ipv6Addr>().is_err() {
            return Err("Gateway must be a valid IPv6 address".into());
        }
    }

    if let Some(m) = r.metric
        && m > 65535
    {
        return Err("Metric must be between 0 and 65535".into());
    }
    if let Some(t) = r.table
        && (!(1..=65535).contains(&t) || t == 255 || t == 51820)
    {
        return Err("Route table must be 1..65535 (excluding reserved tables 255 and 51820)".into());
    }

    let is_default = is_default_target(fam, target, nm);
    let mut ops = vec![
        Op::set(sid, "interface", iface),
        Op::set(sid, "target", target),
        if fam == "ipv4" {
            Op::set_or_clear(sid, "netmask", nm)
        } else {
            Op::Delete {
                section: sid.into(),
                option: Some("netmask".into()),
            }
        },
        Op::set_or_clear(sid, "gateway", gw),
    ];
    ops.push(match r.metric {
        Some(m) => Op::set(sid, "metric", m.to_string()),
        None => Op::Delete {
            section: sid.into(),
            option: Some("metric".into()),
        },
    });
    ops.push(match r.table {
        Some(t) => Op::set(sid, "table", t.to_string()),
        None => Op::Delete {
            section: sid.into(),
            option: Some("table".into()),
        },
    });
    ops.push(if r.disabled {
        Op::set(sid, "disabled", "1")
    } else {
        Op::Delete {
            section: sid.into(),
            option: Some("disabled".into()),
        }
    });
    Ok((ops, is_default))
}

async fn network_reload() -> Option<String> {
    run_ok("ubus", &["call", "network", "reload"], 10, 16 * KIB).await.err()
}

pub async fn get_static_routes() -> Response {
    match ucicfg::show("network").await {
        Ok(sections) => ok(serde_json::json!({ "routes": parse_static_routes(&sections) })),
        Err(e) => server(e),
    }
}

pub async fn post_static_route(State(ctx): State<HttpCtx>, Json(req): Json<StaticRouteReq>) -> Response {
    let _g = mutate_lock().await;
    let sections = match ucicfg::show("network").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let ifaces: Vec<String> = run_ok("ubus", &["call", "network.interface", "dump"], 10, 4 * MIB)
        .await
        .map(|out| parse_iface_dump(&out).into_iter().map(|i| i.name).collect())
        .unwrap_or_default();

    let sid = req.id.clone().unwrap_or_default();
    let expected_type = if req.family.trim() == "ipv6" { "route6" } else { "route" };
    if !sid.is_empty()
        && !parse_static_routes(&sections)
            .iter()
            .any(|sr| sr.id == sid && (if sr.family == "ipv6" { "route6" } else { "route" }) == expected_type)
    {
        return bad("No such static route section");
    }
    let (ops, is_default) = match static_route_ops(&req, &ifaces, &sid) {
        Ok(x) => x,
        Err(e) => return bad(e),
    };
    if is_default
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "DEFAULT ROUTE",
            "Adding or modifying a default route (0.0.0.0/0 or ::/0) can redirect or drop gateway traffic. Type DEFAULT ROUTE to apply.",
        )
    {
        return r;
    }
    let new_id = match ucicfg::apply("network", sid.is_empty().then_some(expected_type), ops).await {
        Ok(id) => id,
        Err(e) => return if e.contains("uncommitted") { conflict(e) } else { server(e) },
    };
    let note = network_reload().await;
    audit(
        &ctx,
        format!(
            "static route {} {} dev {} -> {}",
            if sid.is_empty() { "added" } else { "updated" },
            req.target.trim(),
            req.interface.trim(),
            req.gateway.as_deref().unwrap_or("-").trim()
        ),
    );
    ok(serde_json::json!({ "status": "ok", "id": new_id.unwrap_or(sid), "note": note }))
}

#[derive(Deserialize)]
pub struct DeleteRouteReq {
    id: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn delete_static_route(State(ctx): State<HttpCtx>, Json(req): Json<DeleteRouteReq>) -> Response {
    let _g = mutate_lock().await;
    let sections = match ucicfg::show("network").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let Some(existing) = parse_static_routes(&sections).into_iter().find(|r| r.id == req.id) else {
        return bad("No such static route");
    };
    let is_def = is_default_target(
        &existing.family,
        &existing.target,
        existing.netmask.as_deref().unwrap_or(""),
    );
    if is_def
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            "DELETE",
            "Deleting a default route can drop internet connectivity. Type DELETE to remove.",
        )
    {
        return r;
    }
    if let Err(e) = ucicfg::apply("network", None, vec![Op::Delete { section: req.id.clone(), option: None }]).await {
        return if e.contains("uncommitted") { conflict(e) } else { server(e) };
    }
    let note = network_reload().await;
    audit(&ctx, format!("static route deleted {} ({})", existing.target, existing.interface));
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

pub fn interface_action_gate(name: &str, action: &str) -> Result<bool, &'static str> {
    if action == "down" && matches!(name, "lan" | "loopback") {
        return Err("Taking the LAN or loopback interface down is blocked to prevent losing access");
    }
    Ok(action == "down" || name == "lan")
}

#[derive(Deserialize)]
pub struct IfaceActionReq {
    name: String,
    action: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub async fn post_interface_action(State(ctx): State<HttpCtx>, Json(req): Json<IfaceActionReq>) -> Response {
    let name = req.name.trim().to_string();
    let action = req.action.trim().to_string();
    if !is_safe_name(&name, 32) {
        return bad("Invalid interface name");
    }
    if !matches!(action.as_str(), "up" | "down" | "renew") {
        return bad("Action must be up, down, or renew");
    }
    let needs_confirm = match interface_action_gate(&name, &action) {
        Ok(c) => c,
        Err(why) => return forbidden(why),
    };
    let dump = match run_ok("ubus", &["call", "network.interface", "dump"], 10, 4 * MIB).await {
        Ok(o) => o,
        Err(e) => return server(e),
    };
    if !parse_iface_dump(&dump).into_iter().any(|i| i.name == name) {
        return bad(format!("No such network interface '{name}'"));
    }
    if needs_confirm
        && let Err(r) = require_confirm(
            req.confirm.as_deref(),
            &name,
            &format!("Running '{action}' on interface '{name}' can interrupt connectivity. Type {name} to continue."),
        )
    {
        return r;
    }
    let _g = mutate_lock().await;
    let obj = format!("network.interface.{name}");
    match run("ubus", &["call", &obj, &action], ExecOpts::new(15, 64 * KIB)).await {
        Ok(o) if o.ok() => {
            audit(&ctx, format!("interface {name} {action}"));
            ok(serde_json::json!({ "status": "ok" }))
        }
        Ok(o) => server(o.err_summary(&format!("ubus call {obj} {action}"))),
        Err(e) => server(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_interface_dump() {
        let v = parse_iface_dump(include_str!("fixtures/iface_dump.json"));
        assert!(v.len() >= 10);
        let wan = v.iter().find(|i| i.name == "wan").unwrap();
        assert!(wan.up);
        assert_eq!(wan.proto, "rmnet");
        assert_eq!(wan.l3_device, "rmnet_data1");
        assert_eq!(wan.ipv4, vec!["192.0.0.2/27"]);
        assert_eq!(wan.dns, vec!["192.0.0.30"]);
        let ecm = v.iter().find(|i| i.name == "ecm").unwrap();
        assert_eq!(ecm.ipv4, vec!["169.254.21.1/24"]);
        assert_eq!(ecm.uptime, 46949);
        assert!(parse_iface_dump("{}").is_empty());
    }

    #[test]
    fn parses_real_routes() {
        let v4 = parse_routes(include_str!("fixtures/ip4_routes.txt"));
        assert_eq!(v4.len(), 26);
        let d = &v4[0];
        assert_eq!(d.dst, "default");
        assert_eq!(d.via.as_deref(), Some("192.0.0.1"));
        assert_eq!(d.dev.as_deref(), Some("rmnet_data1"));
        assert_eq!(d.table, "5");
        assert_eq!(d.metric, Some(256));
        assert_eq!(d.mtu.as_deref(), Some("1472 (locked)"));
        let linkdown = v4.iter().find(|r| r.flags.contains(&"linkdown".to_string())).unwrap();
        assert_eq!(linkdown.dev.as_deref(), Some("ecm0"));
        let main_default = v4.iter().find(|r| r.dst == "default" && r.table == "main").unwrap();
        assert_eq!(main_default.src.as_deref(), Some("192.0.0.2"));
        let local = v4.iter().find(|r| r.kind == "local").unwrap();
        assert_eq!(local.table, "local");
        assert_eq!(local.scope.as_deref(), Some("host"));

        let v6 = parse_routes(include_str!("fixtures/ip6_routes.txt"));
        assert_eq!(v6.len(), 29);
        assert!(v6.iter().any(|r| r.kind == "anycast"));
        assert!(v6.iter().any(|r| r.kind == "multicast" && r.dst == "ff00::/8"));
        let d6 = v6.iter().find(|r| r.dst == "default" && r.table == "main").unwrap();
        assert_eq!(d6.via.as_deref(), Some("fe80::1"));
        assert_eq!(d6.metric, Some(1024));
    }

    #[test]
    fn parses_neighbours() {
        let n = parse_neigh(include_str!("fixtures/ip_neigh.txt"));
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].address, "192.168.224.2");
        assert_eq!(n[0].dev, "br-lan");
        assert_eq!(n[0].lladdr.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(n[0].state, "REACHABLE");
        let v6 = parse_neigh("fe80::1 dev rmnet_data1 lladdr 02:00:00:00:00:02 router STALE\n192.168.1.9 dev br-lan FAILED\n");
        assert!(v6[0].router);
        assert_eq!(v6[0].family, "ipv6");
        assert_eq!(v6[1].state, "FAILED");
        assert!(v6[1].lladdr.is_none());
    }

    #[test]
    fn parses_real_conntrack() {
        let proc: Vec<Conn> = include_str!("fixtures/nf_conntrack.txt").lines().filter_map(parse_conntrack_line).collect();
        assert_eq!(proc.len(), 60);
        let v6: Vec<Conn> = include_str!("fixtures/nf_conntrack_v6.txt").lines().filter_map(parse_conntrack_line).collect();
        assert_eq!(v6.len(), 40);
        let udp6 = v6.iter().find(|c| c.family == "ipv6" && c.proto == "udp").unwrap();
        // /proc prints IPv6 fully expanded; it must come back compressed.
        assert_eq!(udp6.dst, "fd00:976a::10");
        assert_eq!(udp6.dport, Some(53));
        assert!(udp6.bytes > 0 && udp6.packets >= 2);
        let icmp = proc.iter().find(|c| c.proto == "icmp").unwrap();
        assert_eq!(icmp.family, "ipv4");
        assert_eq!(icmp.src, "192.168.224.2");
        assert!(icmp.sport.is_none());

        let cli: Vec<Conn> = include_str!("fixtures/conntrack_list.txt").lines().filter_map(parse_conntrack_line).collect();
        assert_eq!(cli.len(), 20);
        assert_eq!(cli[0].family, "ipv6");
        assert_eq!(cli[2].reply_src, "1.0.0.1");

        let tcp = parse_conntrack_line("ipv4     2 tcp      6 7440 ESTABLISHED src=192.168.224.2 dst=1.1.1.1 sport=5000 dport=443 packets=3 bytes=300 src=1.1.1.1 dst=192.0.0.2 sport=443 dport=5000 packets=2 bytes=200 [ASSURED] mark=0 use=1").unwrap();
        assert_eq!(tcp.state.as_deref(), Some("ESTABLISHED"));
        assert!(tcp.assured);
        assert_eq!(tcp.ttl, 7440);
        assert_eq!(tcp.bytes, 500);
        assert!(parse_conntrack_line("garbage").is_none());

        let top = top_talkers(&proc, 3);
        assert_eq!(top[0].address, "192.168.224.2");
        assert!(top[0].flows > 1);
    }

    #[test]
    fn static_routes_and_interface_action_gates() {
        let uci = "network.@route[0]=route\nnetwork.@route[0].interface='lan'\nnetwork.@route[0].target='198.51.100.0'\nnetwork.@route[0].netmask='255.255.255.0'\nnetwork.@route[0].gateway='192.168.228.254'\nnetwork.@route[0].metric='10'\n\nnetwork.@route6[0]=route6\nnetwork.@route6[0].interface='wan6'\nnetwork.@route6[0].target='fd00:1::/64'\nnetwork.@route6[0].disabled='1'\n";
        let secs = ucicfg::parse_uci_show("network", uci);
        let parsed = parse_static_routes(&secs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].family, "ipv4");
        assert_eq!(parsed[0].metric, Some(10));
        assert_eq!(parsed[1].family, "ipv6");
        assert!(parsed[1].disabled);

        let ifaces = vec!["lan".to_string(), "wan".to_string()];
        let good = StaticRouteReq {
            family: "ipv4".into(),
            interface: "lan".into(),
            target: "198.51.100.42/32".into(),
            gateway: Some("192.168.228.2".into()),
            ..Default::default()
        };
        let (ops, is_def) = static_route_ops(&good, &ifaces, "").unwrap();
        assert!(!ops.is_empty() && !is_def);

        let def_v4 = StaticRouteReq { target: "0.0.0.0/0".into(), ..good.clone() };
        assert!(static_route_ops(&def_v4, &ifaces, "").unwrap().1);
        let def_v6 = StaticRouteReq {
            family: "ipv6".into(),
            interface: "wan".into(),
            target: "::/0".into(),
            ..Default::default()
        };
        assert!(static_route_ops(&def_v6, &ifaces, "").unwrap().1);

        // Forbidden table 51820, bad target, unknown interface
        assert!(static_route_ops(&StaticRouteReq { table: Some(51820), ..good.clone() }, &ifaces, "").is_err());
        assert!(static_route_ops(&StaticRouteReq { table: Some(255), ..good.clone() }, &ifaces, "").is_err());
        assert!(static_route_ops(&StaticRouteReq { target: "not-an-ip".into(), ..good.clone() }, &ifaces, "").is_err());
        assert!(static_route_ops(&StaticRouteReq { interface: "nope".into(), ..good }, &ifaces, "").is_err());

        assert!(interface_action_gate("lan", "down").is_err());
        assert!(interface_action_gate("loopback", "down").is_err());
        assert_eq!(interface_action_gate("lan", "renew"), Ok(true));
        assert_eq!(interface_action_gate("wan", "down"), Ok(true));
        assert_eq!(interface_action_gate("wan", "renew"), Ok(false));
    }
}

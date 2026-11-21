//! DHCP & DNS › static leases (uci `dhcp` host sections), active leases and the
//! key dnsmasq options. LAN addressing stays in Network › LAN (QCMAP owns it).

use std::net::Ipv4Addr;

use axum::{Json, extract::State, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    audit, bad, conflict, exec::{KIB, MIB, run_ok}, mutate_lock, ok, server,
    ucicfg::{self, Op, UciSection, of_type},
    validate::{ipv4_in_subnet, is_host_label, is_hostname, is_leasetime, is_mac, parse_ip, parse_ipv4},
};
use crate::http::HttpCtx;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    pub expires: u64,
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
}

/// dnsmasq lease file: `expiry mac ip hostname clientid` (`*` = unknown).
pub fn parse_leases(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() < 3 {
                return None;
            }
            let star = |s: Option<&&str>| s.filter(|x| **x != "*").map(|x| x.to_string());
            Some(Lease {
                expires: t[0].parse().ok()?,
                mac: t[1].to_ascii_lowercase(),
                ip: t[2].to_string(),
                hostname: star(t.get(3)),
                client_id: star(t.get(4)),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaticHost {
    pub id: String,
    pub name: String,
    pub macs: Vec<String>,
    pub ip: String,
    pub leasetime: String,
    pub dns: bool,
}

pub fn static_hosts(s: &[UciSection]) -> Vec<StaticHost> {
    of_type(s, "host")
        .into_iter()
        .map(|h| StaticHost {
            id: h.id.clone(),
            name: h.get_or("name", "").to_string(),
            macs: h.list("mac").into_iter().map(|m| m.to_ascii_lowercase()).collect(),
            ip: h.get_or("ip", "").to_string(),
            leasetime: h.get_or("leasetime", "").to_string(),
            dns: h.flag("dns", false),
        })
        .collect()
}

/// Lease file path from the dnsmasq section; only accepted under /tmp.
pub fn lease_file(s: &[UciSection]) -> String {
    of_type(s, "dnsmasq")
        .first()
        .and_then(|d| d.get("leasefile"))
        .filter(|p| p.starts_with("/tmp/") && !p.contains(".."))
        .unwrap_or("/tmp/dhcp.leases")
        .to_string()
}

/// dnsmasq options shown (and the boolean/simple ones editable).
const DNSMASQ_SHOWN: &[&str] = &[
    "domain", "local", "domainneeded", "boguspriv", "rebind_protection", "rebind_localhost", "localise_queries",
    "expandhosts", "authoritative", "nonegcache", "localservice", "logqueries", "cachesize", "ednspacket_max",
    "interface", "notinterface", "leasefile", "resolvfile", "server",
];
const DNSMASQ_BOOLS: &[&str] = &[
    "domainneeded", "boguspriv", "rebind_protection", "rebind_localhost", "localise_queries", "expandhosts", "authoritative", "logqueries",
];

fn lan_subnet(status_json: &str) -> Option<(Ipv4Addr, u8)> {
    let v: Value = serde_json::from_str(status_json).ok()?;
    let a = v.get("ipv4-address")?.as_array()?.first()?;
    let ip = parse_ipv4(a.get("address")?.as_str()?)?;
    let mask = u8::try_from(a.get("mask")?.as_u64()?).ok()?;
    Some((ip, mask))
}

async fn lan() -> Option<(Ipv4Addr, u8)> {
    let out = run_ok("ubus", &["call", "network.interface.lan", "status"], 5, MIB).await.ok()?;
    lan_subnet(&out)
}

pub async fn get_dhcp() -> Response {
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let lf = lease_file(&s);
    let leases = std::fs::read(&lf)
        .map(|b| parse_leases(&String::from_utf8_lossy(&b[..b.len().min(256 * KIB)])))
        .unwrap_or_default();
    let dnsmasq: Vec<Value> = of_type(&s, "dnsmasq")
        .into_iter()
        .map(|d| {
            let mut m = serde_json::Map::new();
            for k in DNSMASQ_SHOWN {
                if let Some((_, v)) = d.options.iter().find(|(kk, _)| kk == k) {
                    m.insert((*k).into(), serde_json::to_value(v).unwrap_or(Value::Null));
                }
            }
            serde_json::json!({ "id": d.id, "options": m })
        })
        .collect();
    let pools: Vec<Value> = of_type(&s, "dhcp")
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "interface": p.get_or("interface", ""),
                "ignore": p.flag("ignore", false),
                "start": p.get("start"),
                "limit": p.get("limit"),
                "leasetime": p.get("leasetime"),
            })
        })
        .collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let subnet = lan().await;
    ok(serde_json::json!({
        "hosts": static_hosts(&s),
        "domains": domain_hosts(&s),
        "leases": leases,
        "leaseFile": lf,
        "now": now,
        "dnsmasq": dnsmasq,
        "editableFlags": DNSMASQ_BOOLS,
        "pools": pools,
        "lanSubnet": subnet.map(|(ip, m)| format!("{ip}/{m}")),
    }))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomainHost {
    pub id: String,
    pub name: String,
    pub ip: String,
}

pub fn domain_hosts(s: &[UciSection]) -> Vec<DomainHost> {
    of_type(s, "domain")
        .into_iter()
        .map(|d| DomainHost {
            id: d.id.clone(),
            name: d.get_or("name", "").to_string(),
            ip: d.get_or("ip", "").to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct DomainReq {
    pub id: Option<String>,
    pub name: String,
    pub ip: String,
}

pub fn domain_ops(r: &DomainReq, others: &[DomainHost], sid: &str) -> Result<Vec<Op>, String> {
    let name = r.name.trim();
    if !is_hostname(name) {
        return Err("Hostname must be a valid DNS name (e.g. nas.lan)".into());
    }
    let Some(ip) = parse_ip(r.ip.trim()) else {
        return Err("IP must be a valid IPv4 or IPv6 address".into());
    };
    let ip_str = ip.to_string();
    let lower = name.to_ascii_lowercase();
    if others
        .iter()
        .filter(|o| Some(&o.id) != r.id.as_ref())
        .any(|o| o.name.eq_ignore_ascii_case(&lower) && o.ip == ip_str)
    {
        return Err(format!("{name} -> {ip_str} is already configured"));
    }
    Ok(vec![Op::set(sid, "name", name), Op::set(sid, "ip", ip_str)])
}

pub async fn post_domain(State(ctx): State<HttpCtx>, Json(req): Json<DomainReq>) -> Response {
    let _g = mutate_lock().await;
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let domains = domain_hosts(&s);
    let sid = req.id.clone().unwrap_or_default();
    if !sid.is_empty() && !domains.iter().any(|d| d.id == sid) {
        return bad("No such custom hostname entry");
    }
    let ops = match domain_ops(&req, &domains, &sid) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    if let Err(e) = ucicfg::apply("dhcp", sid.is_empty().then_some("domain"), ops).await {
        return if e.contains("uncommitted") { conflict(e) } else { server(e) };
    }
    let note = reload_dnsmasq().await;
    audit(
        &ctx,
        format!(
            "dhcp custom hostname {} {} -> {}",
            if sid.is_empty() { "added" } else { "updated" },
            req.name.trim(),
            req.ip.trim()
        ),
    );
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

pub async fn delete_domain(State(ctx): State<HttpCtx>, Json(req): Json<IdReq>) -> Response {
    let _g = mutate_lock().await;
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let Some(d) = domain_hosts(&s).into_iter().find(|d| d.id == req.id) else {
        return bad("No such custom hostname entry");
    };
    if let Err(e) = ucicfg::apply("dhcp", None, vec![Op::Delete { section: req.id.clone(), option: None }]).await {
        return if e.contains("uncommitted") { conflict(e) } else { server(e) };
    }
    let note = reload_dnsmasq().await;
    audit(&ctx, format!("dhcp custom hostname removed {} -> {}", d.name, d.ip));
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HostReq {
    pub id: Option<String>,
    pub name: String,
    pub mac: String,
    pub ip: String,
    pub leasetime: String,
    pub dns: bool,
}

/// Validate a static lease against the LAN subnet and the other hosts.
pub fn host_ops(r: &HostReq, others: &[StaticHost], subnet: Option<(Ipv4Addr, u8)>, sid: &str) -> Result<Vec<Op>, String> {
    let name = r.name.trim();
    if !is_host_label(name) {
        return Err("Hostname: letters, digits and hyphens only".into());
    }
    let macs: Vec<String> = r.mac.split([' ', ',']).filter(|m| !m.is_empty()).map(|m| m.to_ascii_lowercase()).collect();
    if macs.is_empty() || macs.len() > 4 || !macs.iter().all(|m| is_mac(m)) {
        return Err("MAC must look like 02:00:00:00:00:01 (up to 4, space separated)".into());
    }
    let Some(ip) = parse_ipv4(r.ip.trim()) else {
        return Err("IP must be an IPv4 address".into());
    };
    if let Some((net, m)) = subnet {
        if !ipv4_in_subnet(ip, net, m) {
            return Err(format!("{ip} is outside the LAN subnet {net}/{m}"));
        }
        if ip == net {
            return Err("That is the gateway's own address".into());
        }
    }
    let lt = r.leasetime.trim();
    if !lt.is_empty() && !is_leasetime(lt) {
        return Err("Lease time like 12h, 30m, 1d or infinite".into());
    }
    for o in others.iter().filter(|o| Some(&o.id) != r.id.as_ref()) {
        if o.ip == ip.to_string() {
            return Err(format!("{ip} is already reserved for {}", o.name));
        }
        if let Some(m) = macs.iter().find(|m| o.macs.contains(m)) {
            return Err(format!("{m} already has a reservation ({})", o.name));
        }
        if o.name.eq_ignore_ascii_case(name) {
            return Err(format!("Hostname {name} is already used"));
        }
    }
    Ok(vec![
        Op::set(sid, "name", name),
        Op::set(sid, "mac", macs.join(" ")),
        Op::set(sid, "ip", ip.to_string()),
        Op::set_or_clear(sid, "leasetime", lt),
        Op::set(sid, "dns", if r.dns { "1" } else { "0" }),
    ])
}

async fn reload_dnsmasq() -> Option<String> {
    run_ok("/etc/init.d/dnsmasq", &["reload"], 30, 16 * KIB).await.err()
}

pub async fn post_host(State(ctx): State<HttpCtx>, Json(req): Json<HostReq>) -> Response {
    let _g = mutate_lock().await;
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let hosts = static_hosts(&s);
    let sid = req.id.clone().unwrap_or_default();
    if !sid.is_empty() && !hosts.iter().any(|h| h.id == sid) {
        return bad("No such static lease");
    }
    let ops = match host_ops(&req, &hosts, lan().await, &sid) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    if let Err(e) = ucicfg::apply("dhcp", sid.is_empty().then_some("host"), ops).await {
        return server(e);
    }
    let note = reload_dnsmasq().await;
    audit(&ctx, format!("dhcp static lease {} {} -> {}", if sid.is_empty() { "added" } else { "updated" }, req.name.trim(), req.ip.trim()));
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

#[derive(Deserialize)]
pub struct IdReq {
    id: String,
}

pub async fn delete_host(State(ctx): State<HttpCtx>, Json(req): Json<IdReq>) -> Response {
    let _g = mutate_lock().await;
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    let Some(h) = static_hosts(&s).into_iter().find(|h| h.id == req.id) else {
        return bad("No such static lease");
    };
    if let Err(e) = ucicfg::apply("dhcp", None, vec![Op::Delete { section: req.id.clone(), option: None }]).await {
        return server(e);
    }
    let note = reload_dnsmasq().await;
    audit(&ctx, format!("dhcp static lease removed {} {}", h.name, h.ip));
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct DnsmasqReq {
    pub id: String,
    pub domain: String,
    pub local: String,
    pub flags: std::collections::BTreeMap<String, bool>,
}

pub fn dnsmasq_ops(r: &DnsmasqReq) -> Result<Vec<Op>, String> {
    let mut ops = Vec::new();
    let d = r.domain.trim();
    if !d.is_empty() && !is_hostname(d) {
        return Err("Local domain must be a DNS name like lan".into());
    }
    ops.push(Op::set_or_clear(&r.id, "domain", d));
    let l = r.local.trim();
    if !l.is_empty() {
        let inner = l.strip_prefix('/').and_then(|x| x.strip_suffix('/')).ok_or("Local server must look like /lan/")?;
        if !is_hostname(inner) {
            return Err("Local server must look like /lan/".into());
        }
    }
    ops.push(Op::set_or_clear(&r.id, "local", l));
    for (k, v) in &r.flags {
        if !DNSMASQ_BOOLS.contains(&k.as_str()) {
            return Err(format!("{k} is not editable here"));
        }
        ops.push(Op::set(&r.id, k, if *v { "1" } else { "0" }));
    }
    Ok(ops)
}

pub async fn post_dnsmasq(State(ctx): State<HttpCtx>, Json(req): Json<DnsmasqReq>) -> Response {
    let _g = mutate_lock().await;
    let s = match ucicfg::show("dhcp").await {
        Ok(s) => s,
        Err(e) => return server(e),
    };
    if !of_type(&s, "dnsmasq").iter().any(|d| d.id == req.id) {
        return bad("No such dnsmasq instance");
    }
    let ops = match dnsmasq_ops(&req) {
        Ok(o) => o,
        Err(e) => return bad(e),
    };
    if let Err(e) = ucicfg::apply("dhcp", None, ops).await {
        return if e.contains("uncommitted") { conflict(e) } else { server(e) };
    }
    let note = reload_dnsmasq().await;
    audit(&ctx, format!("dnsmasq options updated ({})", req.id));
    ok(serde_json::json!({ "status": "ok", "note": note }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<UciSection> {
        ucicfg::parse_uci_show("dhcp", include_str!("fixtures/uci_dhcp.txt"))
    }

    #[test]
    fn parses_real_leases_and_hosts() {
        let l = parse_leases(include_str!("fixtures/dhcp_leases.txt"));
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].ip, "192.168.224.2");
        assert_eq!(l[0].mac, "02:00:00:00:00:01");
        assert_eq!(l[0].hostname.as_deref(), Some("lanhost"));
        assert!(l[0].client_id.is_none());
        assert!(parse_leases("junk\n").is_empty());

        let s = fixture();
        let h = static_hosts(&s);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name, "lanhost");
        assert_eq!(h[0].macs, vec!["02:00:00:00:00:01"]);
        assert!(h[0].dns);
        assert_eq!(lease_file(&s), "/tmp/data/dhcp.leases.lan");
    }

    #[test]
    fn lan_subnet_from_interface_status() {
        let j = r#"{"ipv4-address":[{"address":"192.168.224.1","mask":22}]}"#;
        assert_eq!(lan_subnet(j), Some(("192.168.224.1".parse().unwrap(), 22)));
        assert_eq!(lan_subnet("{}"), None);
    }

    #[test]
    fn validates_static_leases() {
        let hosts = static_hosts(&fixture());
        let subnet = Some(("192.168.224.1".parse().unwrap(), 22));
        let good = HostReq { name: "printer".into(), mac: "02:00:00:00:00:09".into(), ip: "192.168.225.20".into(), leasetime: "12h".into(), ..Default::default() };
        assert!(host_ops(&good, &hosts, subnet, "").is_ok());
        let bad_cases = [
            HostReq { ip: "10.0.0.5".into(), ..good.clone() },
            HostReq { ip: "192.168.224.2".into(), ..good.clone() },
            HostReq { mac: "02:00:00:00:00:01".into(), ..good.clone() },
            HostReq { name: "lanhost".into(), ..good.clone() },
            HostReq { name: "bad name".into(), ..good.clone() },
            HostReq { mac: "zz:00:00:00:00:09".into(), ..good.clone() },
            HostReq { leasetime: "forever".into(), ..good.clone() },
            HostReq { ip: "192.168.224.1".into(), ..good.clone() },
        ];
        for b in bad_cases {
            assert!(host_ops(&b, &hosts, subnet, "").is_err(), "{b:?}");
        }
        // Editing the existing host may keep its own IP/MAC/name.
        let edit = HostReq { id: Some(hosts[0].id.clone()), name: "lanhost".into(), mac: "02:00:00:00:00:01".into(), ip: "192.168.224.2".into(), dns: true, ..Default::default() };
        assert!(host_ops(&edit, &hosts, subnet, &hosts[0].id).is_ok());
    }

    #[test]
    fn validates_dnsmasq_options() {
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("rebind_protection".to_string(), true);
        let r = DnsmasqReq { id: "lan_dns".into(), domain: "lan".into(), local: "/lan/".into(), flags };
        assert_eq!(dnsmasq_ops(&r).unwrap().len(), 3);
        let mut f2 = std::collections::BTreeMap::new();
        f2.insert("dhcpscript".to_string(), true);
        assert!(dnsmasq_ops(&DnsmasqReq { id: "x".into(), flags: f2, ..Default::default() }).is_err());
        assert!(dnsmasq_ops(&DnsmasqReq { id: "x".into(), local: "lan".into(), ..Default::default() }).is_err());
        assert!(dnsmasq_ops(&DnsmasqReq { id: "x".into(), domain: "a b".into(), ..Default::default() }).is_err());
    }

    #[test]
    fn parses_and_validates_custom_domains() {
        let uci = "dhcp.@domain[0]=domain\ndhcp.@domain[0].name='router.lan'\ndhcp.@domain[0].ip='192.168.228.1'\n";
        let secs = ucicfg::parse_uci_show("dhcp", uci);
        let list = domain_hosts(&secs);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "router.lan");
        assert_eq!(list[0].ip, "192.168.228.1");

        let add = DomainReq { id: None, name: "nas.lan".into(), ip: "192.168.228.10".into() };
        assert_eq!(domain_ops(&add, &list, "").unwrap().len(), 2);
        let v6 = DomainReq { id: None, name: "v6host.lan".into(), ip: "fd00::10".into() };
        assert!(domain_ops(&v6, &list, "").is_ok());
        // Duplicate pair rejected
        let dup = DomainReq { id: None, name: "ROUTER.LAN".into(), ip: "192.168.228.1".into() };
        assert!(domain_ops(&dup, &list, "").is_err());
        // Editing self allowed
        let self_edit = DomainReq { id: Some(list[0].id.clone()), name: "router.lan".into(), ip: "192.168.228.1".into() };
        assert!(domain_ops(&self_edit, &list, &list[0].id).is_ok());
        // Bad hostname / IP rejected
        assert!(domain_ops(&DomainReq { id: None, name: "-bad".into(), ip: "1.2.3.4".into() }, &list, "").is_err());
        assert!(domain_ops(&DomainReq { id: None, name: "good.lan".into(), ip: "999.1.1.1".into() }, &list, "").is_err());
    }
}

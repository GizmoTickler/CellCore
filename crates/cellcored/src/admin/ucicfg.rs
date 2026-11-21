//! UCI helpers for the admin API: parse `uci -X show <config>` output, and apply
//! changes transactionally (refuse when foreign changes are staged, revert our
//! staged changes on error, snapshot/restore through `uci export`/`uci import`).

use serde::Serialize;
use serde_json::{Map, Value};

use super::exec::{ExecOpts, KIB, MIB, run, run_ok};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum UciVal {
    One(String),
    List(Vec<String>),
}

impl UciVal {
    pub fn first(&self) -> &str {
        match self {
            UciVal::One(s) => s,
            UciVal::List(v) => v.first().map(String::as_str).unwrap_or(""),
        }
    }

    pub fn items(&self) -> Vec<String> {
        match self {
            UciVal::One(s) => s.split_whitespace().map(str::to_string).collect(),
            UciVal::List(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UciSection {
    /// Section id usable in `uci set config.<id>.opt=…` (cfgXXXXXX for anonymous sections with -X).
    pub id: String,
    #[serde(rename = "type")]
    pub stype: String,
    /// Position among sections of the same type (matches `@type[n]`).
    pub index: usize,
    pub options: Vec<(String, UciVal)>,
}

impl UciSection {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options.iter().find(|(k, _)| k == key).map(|(_, v)| v.first())
    }

    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }

    /// List-valued option; a single scalar is split on whitespace (UCI treats
    /// `option network 'a b'` and `list network 'a'` alike for most consumers).
    pub fn list(&self, key: &str) -> Vec<String> {
        self.options
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.items())
            .unwrap_or_default()
    }

    pub fn flag(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            Some(v) => matches!(v, "1" | "on" | "true" | "yes" | "enabled"),
            None => default,
        }
    }

    pub fn options_json(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in &self.options {
            m.insert(
                k.clone(),
                match v {
                    UciVal::One(s) => Value::String(s.clone()),
                    UciVal::List(l) => Value::Array(l.iter().cloned().map(Value::String).collect()),
                },
            );
        }
        Value::Object(m)
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "type": self.stype,
            "index": self.index,
            "options": self.options_json(),
        })
    }
}

/// Parse a quoted UCI value as printed by `uci show`: `'a'`, `'a' 'b'`, `'it'\''s'`.
/// Unquoted values (older uci) are accepted as a single token.
pub fn parse_uci_value(raw: &str) -> UciVal {
    let s = raw.trim();
    if !s.starts_with('\'') {
        return UciVal::One(s.to_string());
    }
    let b = s.as_bytes();
    let mut items = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] != b'\'' {
            // Malformed: keep the rest verbatim.
            items.push(s[i..].to_string());
            break;
        }
        i += 1;
        let mut tok = Vec::new();
        loop {
            if i >= b.len() {
                break;
            }
            if b[i] == b'\'' {
                // `'\''` is an escaped single quote inside the token.
                if b[i..].starts_with(b"'\\''") {
                    tok.push(b'\'');
                    i += 4;
                    continue;
                }
                i += 1;
                break;
            }
            tok.push(b[i]);
            i += 1;
        }
        items.push(String::from_utf8_lossy(&tok).into_owned());
    }
    if items.len() == 1 {
        UciVal::One(items.remove(0))
    } else {
        UciVal::List(items)
    }
}

/// Parse `uci [-X] show <config>` into sections in file order.
pub fn parse_uci_show(config: &str, text: &str) -> Vec<UciSection> {
    let mut sections: Vec<UciSection> = Vec::new();
    let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let prefix = format!("{config}.");
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(&prefix) else { continue };
        let Some((path, val)) = rest.split_once('=') else { continue };
        match path.split_once('.') {
            None => {
                let stype = val.trim().to_string();
                let n = type_counts.entry(stype.clone()).or_insert(0);
                sections.push(UciSection { id: path.to_string(), stype, index: *n, options: Vec::new() });
                *n += 1;
            }
            Some((sid, opt)) => {
                if let Some(sec) = sections.iter_mut().rev().find(|s| s.id == sid) {
                    sec.options.push((opt.to_string(), parse_uci_value(val)));
                }
            }
        }
    }
    sections
}

pub fn of_type<'a>(sections: &'a [UciSection], stype: &str) -> Vec<&'a UciSection> {
    sections.iter().filter(|s| s.stype == stype).collect()
}

/// Section ids and option names accepted on writes.
pub fn is_uci_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// UCI option values we are willing to write: single line, no control chars.
pub fn is_safe_value(s: &str) -> bool {
    s.len() <= 1024 && !s.chars().any(|c| c.is_control())
}

pub async fn show(config: &str) -> Result<Vec<UciSection>, String> {
    let out = run_ok("uci", &["-X", "show", config], 5, 2 * MIB).await?;
    Ok(parse_uci_show(config, &out))
}

/// Refuse to operate when someone (LuCI, QCMAP, a shell) has uncommitted changes
/// staged for this config: committing would silently publish them.
pub async fn ensure_clean(config: &str) -> Result<(), String> {
    let out = run("uci", &["changes", config], ExecOpts::new(5, 64 * KIB)).await?;
    let pending = out.stdout_str();
    if pending.trim().is_empty() {
        Ok(())
    } else {
        Err(format!(
            "/etc/config/{config} has uncommitted changes from another tool; review them (uci changes {config}) before editing here"
        ))
    }
}

pub async fn export(config: &str) -> Result<String, String> {
    run_ok("uci", &["export", config], 5, 4 * MIB).await
}

/// Replace the whole package with a previously exported snapshot, then commit.
pub async fn restore_snapshot(config: &str, snapshot: &str) -> Result<(), String> {
    let _ = revert(config).await;
    let out = run("uci", &["import", config], ExecOpts::new(10, 64 * KIB).stdin(snapshot.as_bytes().to_vec())).await?;
    if !out.ok() {
        return Err(out.err_summary("uci import"));
    }
    commit(config).await
}

pub async fn revert(config: &str) -> Result<(), String> {
    run_ok("uci", &["revert", config], 5, 64 * KIB).await.map(|_| ())
}

pub async fn commit(config: &str) -> Result<(), String> {
    run_ok("uci", &["commit", config], 10, 64 * KIB).await.map(|_| ())
}

/// One staged change. Paths are built from validated idents only.
#[derive(Debug, Clone)]
pub enum Op {
    Set { section: String, option: String, value: String },
    /// Replace a list option with these items (delete + add_list).
    SetList { section: String, option: String, values: Vec<String> },
    Delete { section: String, option: Option<String> },
    /// Create (or keep) a *named* section: `uci set config.section=type`.
    Section { section: String, stype: String },
}

impl Op {
    pub fn set(section: &str, option: &str, value: impl Into<String>) -> Self {
        Op::Set { section: section.into(), option: option.into(), value: value.into() }
    }

    /// Set when non-empty, delete otherwise.
    pub fn set_or_clear(section: &str, option: &str, value: &str) -> Self {
        if value.trim().is_empty() {
            Op::Delete { section: section.into(), option: Some(option.into()) }
        } else {
            Op::set(section, option, value.trim())
        }
    }
}

/// Stage `ops` on `config` (adding a new section of `new_type` first when given),
/// then commit. Our staged changes are reverted if any step fails. Returns the id of
/// the new section if one was added.
pub async fn apply(config: &str, new_type: Option<&str>, ops: Vec<Op>) -> Result<Option<String>, String> {
    if !is_uci_ident(config) {
        return Err("invalid config name".into());
    }
    ensure_clean(config).await?;
    let res = stage(config, new_type, ops).await;
    match res {
        Ok(new_id) => match commit(config).await {
            Ok(()) => Ok(new_id),
            Err(e) => {
                let _ = revert(config).await;
                Err(e)
            }
        },
        Err(e) => {
            let _ = revert(config).await;
            Err(e)
        }
    }
}

async fn stage(config: &str, new_type: Option<&str>, ops: Vec<Op>) -> Result<Option<String>, String> {
    let mut new_id = None;
    if let Some(t) = new_type {
        if !is_uci_ident(t) {
            return Err("invalid section type".into());
        }
        let id = run_ok("uci", &["add", config, t], 5, KIB).await?.trim().to_string();
        if !is_uci_ident(&id) {
            return Err(format!("uci add returned an unexpected id: {id}"));
        }
        new_id = Some(id);
    }
    for op in ops {
        // A section id of "" refers to the section we just added.
        let resolve = |s: &str| -> Result<String, String> {
            let sid = if s.is_empty() { new_id.clone().ok_or("no section")? } else { s.to_string() };
            if is_uci_ident(&sid) { Ok(sid) } else { Err(format!("invalid section id {sid}")) }
        };
        match op {
            Op::Set { section, option, value } => {
                let sid = resolve(&section)?;
                if !is_uci_ident(&option) || !is_safe_value(&value) {
                    return Err(format!("refusing to write option {option}"));
                }
                let arg = format!("{config}.{sid}.{option}={value}");
                run_ok("uci", &["set", &arg], 5, KIB).await?;
            }
            Op::SetList { section, option, values } => {
                let sid = resolve(&section)?;
                if !is_uci_ident(&option) {
                    return Err(format!("refusing to write option {option}"));
                }
                let path = format!("{config}.{sid}.{option}");
                let _ = run("uci", &["-q", "delete", &path], ExecOpts::new(5, KIB)).await;
                for v in values {
                    if !is_safe_value(&v) {
                        return Err(format!("refusing to write list {option}"));
                    }
                    let arg = format!("{path}={v}");
                    run_ok("uci", &["add_list", &arg], 5, KIB).await?;
                }
            }
            Op::Section { section, stype } => {
                if !is_uci_ident(&section) || !is_uci_ident(&stype) {
                    return Err(format!("invalid section {section}={stype}"));
                }
                let arg = format!("{config}.{section}={stype}");
                run_ok("uci", &["set", &arg], 5, KIB).await?;
            }
            Op::Delete { section, option } => {
                let sid = resolve(&section)?;
                let path = match option {
                    Some(o) if is_uci_ident(&o) => format!("{config}.{sid}.{o}"),
                    Some(o) => return Err(format!("invalid option {o}")),
                    None => format!("{config}.{sid}"),
                };
                // `-q delete` of a missing option is not an error for our purposes.
                let _ = run("uci", &["-q", "delete", &path], ExecOpts::new(5, KIB)).await;
            }
        }
    }
    Ok(new_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREWALL: &str = include_str!("fixtures/uci_firewall.txt");
    const DHCP: &str = include_str!("fixtures/uci_dhcp.txt");
    const MWAN3: &str = include_str!("fixtures/uci_mwan3.txt");

    #[test]
    fn parses_quoted_values() {
        assert_eq!(parse_uci_value("'22'"), UciVal::One("22".into()));
        assert_eq!(parse_uci_value("'a' 'b c'"), UciVal::List(vec!["a".into(), "b c".into()]));
        assert_eq!(parse_uci_value(r"'it'\''s'"), UciVal::One("it's".into()));
        assert_eq!(parse_uci_value("''"), UciVal::One(String::new()));
        assert_eq!(parse_uci_value("bare"), UciVal::One("bare".into()));
    }

    #[test]
    fn parses_real_firewall_show() {
        let s = parse_uci_show("firewall", FIREWALL);
        assert_eq!(of_type(&s, "zone").len(), 5);
        assert_eq!(of_type(&s, "rule").len(), 12);
        assert_eq!(of_type(&s, "redirect").len(), 1);
        assert_eq!(of_type(&s, "include").len(), 2);
        let wan = of_type(&s, "zone").into_iter().find(|z| z.get("name") == Some("wan")).unwrap();
        assert_eq!(wan.list("network"), vec!["waneth", "waneth_v6", "wanwlan", "wanwlan_v6", "wan", "wan_v6"]);
        assert!(wan.flag("masq", false));
        assert!(wan.id.starts_with("cfg"));
        let inc = s.iter().find(|x| x.id == "qcmap_include").unwrap();
        assert_eq!(inc.get("path"), Some("/etc/firewall.user.qcmap"));
        let rule = of_type(&s, "rule")[3];
        assert_eq!(rule.index, 3);
        assert_eq!(rule.get("name"), Some("Allow-ICMPv6-Forward"));
        assert!(!rule.flag("enabled", true));
    }

    #[test]
    fn parses_real_dhcp_and_mwan3() {
        let d = parse_uci_show("dhcp", DHCP);
        let hosts = of_type(&d, "host");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].get("ip"), Some("192.168.224.2"));
        let lan = d.iter().find(|x| x.id == "lan").unwrap();
        assert_eq!(lan.list("dns").len(), 10);
        let dns = of_type(&d, "dnsmasq");
        assert_eq!(dns[0].id, "lan_dns");
        assert_eq!(dns[0].get("leasefile"), Some("/tmp/data/dhcp.leases.lan"));

        let m = parse_uci_show("mwan3", MWAN3);
        let pol = m.iter().find(|x| x.id == "backhaul_pref").unwrap();
        assert_eq!(pol.list("use_member"), vec!["m_waneth", "m_wanusb", "m_wan"]);
        assert_eq!(of_type(&m, "interface").len(), 6);
    }

    #[test]
    fn ignores_foreign_prefixes() {
        let s = parse_uci_show("dhcp", "dhcpx.a=host\ndhcp.a=host\ndhcp.a.ip='1.2.3.4'\n");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].get("ip"), Some("1.2.3.4"));
    }

    #[test]
    fn ident_and_value_guards() {
        assert!(is_uci_ident("cfg0a1b2c"));
        assert!(!is_uci_ident("a.b"));
        assert!(!is_uci_ident(""));
        assert!(!is_uci_ident("x=y"));
        assert!(is_safe_value("tcp udp"));
        assert!(!is_safe_value("a\nb"));
    }
}

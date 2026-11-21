//! Input validators shared by the admin endpoints. Everything that ends up in an
//! argv slot or a UCI value passes through one of these first.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 1123 host name: dot-separated labels of [A-Za-z0-9-], no leading/trailing
/// hyphen, 1–63 chars each, ≤253 total; an optional trailing dot is allowed. Because
/// a label can never start with '-', the result can never be mistaken for a flag.
pub fn is_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// A single label usable as the system hostname or a DHCP host name.
pub fn is_host_label(s: &str) -> bool {
    !s.contains('.') && is_hostname(s)
}

pub fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    // std rejects leading zeros / octal forms, which is what we want.
    s.parse::<Ipv4Addr>().ok()
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    // Reject zone ids ("fe80::1%eth0") and anything else std would not parse.
    s.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// Target of ping/traceroute/nslookup/NTP: a host name or an IP literal.
pub fn is_net_target(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && !s.starts_with('-') && (parse_ip(s).is_some() || is_hostname(s))
}

/// IPv4 address with optional /prefix (0–32).
pub fn is_ipv4_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, p)) => parse_ipv4(a).is_some() && p.parse::<u8>().is_ok_and(|n| n <= 32) && !p.starts_with('+'),
        None => parse_ipv4(s).is_some(),
    }
}

pub fn is_ip_or_cidr(s: &str) -> bool {
    if is_ipv4_cidr(s) {
        return true;
    }
    match s.split_once('/') {
        Some((a, p)) => a.parse::<Ipv6Addr>().is_ok() && p.parse::<u8>().is_ok_and(|n| n <= 128) && !p.starts_with('+'),
        None => s.parse::<Ipv6Addr>().is_ok(),
    }
}

pub fn is_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Port or port range: "443", "8000-8100" (1–65535, low ≤ high).
pub fn is_port_spec(s: &str) -> bool {
    let p = |x: &str| !x.is_empty() && x.len() <= 5 && x.bytes().all(|b| b.is_ascii_digit()) && x.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
    match s.split_once('-') {
        Some((a, b)) => p(a) && p(b) && a.parse::<u32>().unwrap_or(0) <= b.parse::<u32>().unwrap_or(0),
        None => p(s),
    }
}

pub fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p > 0)
}

/// Free-text label stored in UCI (rule names etc.): printable, no quotes or
/// backslashes, 1–64 chars.
pub fn is_label(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= 64
        && s.chars().all(|c| !c.is_control() && c != '\'' && c != '"' && c != '\\' && c != '`')
}

/// Init script / package / process names: conservative charset, cannot start with
/// '-' or '.', and no path separators.
pub fn is_safe_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('-')
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
}

/// DHCP lease time: "12h", "30m", "1d", "3600", or "infinite".
pub fn is_leasetime(s: &str) -> bool {
    if s == "infinite" {
        return true;
    }
    let (num, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], Some(c)),
        _ => (s, None),
    };
    !num.is_empty()
        && num.len() <= 7
        && num.bytes().all(|b| b.is_ascii_digit())
        && matches!(unit, None | Some('s' | 'm' | 'h' | 'd' | 'w'))
}

/// Is `ip` inside `net/prefix`?
pub fn ipv4_in_subnet(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        assert!(is_hostname("gateway-test"));
        assert!(is_hostname("0.openwrt.pool.ntp.org"));
        assert!(is_hostname("example.com."));
        assert!(!is_hostname("-c1"));
        assert!(!is_hostname("a..b"));
        assert!(!is_hostname("bad_host"));
        assert!(!is_hostname("host;reboot"));
        assert!(!is_hostname("a b"));
        assert!(!is_hostname(&"a".repeat(64)));
        assert!(!is_hostname(""));
        assert!(is_host_label("lanhost"));
        assert!(!is_host_label("lan.host"));
    }

    #[test]
    fn diagnostics_target_validator() {
        assert!(is_net_target("1.1.1.1"));
        assert!(is_net_target("2001:4860:4860::8888"));
        assert!(is_net_target("one.one.one.one"));
        for bad in ["-f", "--help", "8.8.8.8 -c 9999", "$(reboot)", "`id`", "a|b", "fe80::1%eth0", "", "1.1.1.1;ls", "a\nb", "host/../x"] {
            assert!(!is_net_target(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ips_and_cidrs() {
        assert!(is_ipv4_cidr("192.168.224.0/22"));
        assert!(is_ipv4_cidr("10.0.0.1"));
        assert!(!is_ipv4_cidr("10.0.0.1/33"));
        assert!(!is_ipv4_cidr("10.0.0.1/+8"));
        assert!(!is_ipv4_cidr("010.0.0.1"));
        assert!(is_ip_or_cidr("2001:db8::/32"));
        assert!(!is_ip_or_cidr("2001:db8::/129"));
        assert!(ipv4_in_subnet("192.168.227.200".parse().unwrap(), "192.168.224.1".parse().unwrap(), 22));
        assert!(!ipv4_in_subnet("192.168.228.1".parse().unwrap(), "192.168.224.1".parse().unwrap(), 22));
    }

    #[test]
    fn macs_ports_labels() {
        assert!(is_mac("02:00:00:00:00:01"));
        assert!(!is_mac("02-00-00-00-00-01"));
        assert!(!is_mac("02:00:00:00:00"));
        assert!(is_port_spec("22"));
        assert!(is_port_spec("8000-8100"));
        assert!(!is_port_spec("0"));
        assert!(!is_port_spec("70000"));
        assert!(!is_port_spec("100-10"));
        assert!(!is_port_spec("1,2"));
        assert_eq!(parse_port("2222"), Some(2222));
        assert_eq!(parse_port("+22"), None);
        assert!(is_label("Allow SSH from LAN"));
        assert!(!is_label("x'; reboot"));
        assert!(is_safe_name("QCMAP_ConnectionManagerd.init", 64));
        assert!(!is_safe_name("../../bin/sh", 64));
        assert!(!is_safe_name("-x", 64));
        assert!(is_leasetime("12h"));
        assert!(is_leasetime("infinite"));
        assert!(!is_leasetime("12x"));
        assert!(!is_leasetime("h"));
    }
}

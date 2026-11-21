//! WARP routing policy for a backup-WAN modem.
//!
//! Design (see docs/WARP.md for the full rationale):
//!
//! * The WireGuard interface is installed with `route_allowed_ips 0`, so
//!   netifd never touches the main table. The `wan` interface, its default
//!   route and everything the Route10 `status` contract reads stay untouched.
//! * Steering is a block of `ip -4 rule`s in a reserved priority range
//!   (`pref .. pref+15`) that point into a dedicated table (`table`):
//!   - `fwmark BYPASS goto END`: the tunnel's own UDP (netifd `fwmark`) and
//!     the daemon's health probes (LinkWatch ICMP) never enter the tunnel;
//!   - `to <private/special> goto END`: LAN, carrier DNS (10/8), CLAT
//!     (192.0.0.0/24), CGNAT/tailnet (100.64/10), link-local, multicast;
//!   - `iif lo lookup TABLE`: modem-originated traffic (mode `modem`, `lan`);
//!   - `iif <lan> lookup TABLE`: forwarded LAN traffic (mode `lan`);
//!   - `nop` at END: the goto target, after which normal processing
//!     (QCMAP tables, mwan3, main) continues exactly as before.
//! * The table holds a single `default dev <wg>` route, present **only while
//!   the tunnel is proven healthy** (a handshake newer than [`STALE_SECS`]).
//!   A lookup that finds no route falls through to the next rule, so a dead
//!   tunnel means traffic takes the cellular path: fail-back, never a
//!   blackhole. There is deliberately no kill switch (`unreachable`) route.
//! * When netifd removes the device the kernel drops the route at once; the
//!   monitor removes it when the peer goes silent while the device is up.

use serde::{Deserialize, Serialize};

/// Mark set on the WireGuard socket and on daemon health probes. Bit 24:
/// outside mwan3's default 0x3F00 mask and tailscale's 0xff0000 mask.
pub const BYPASS_MARK: u32 = 0x0100_0000;
pub const DEFAULT_PREF: u32 = 1400;
pub const DEFAULT_TABLE: u32 = 51820;
/// Range of priorities owned by this module.
pub const PREF_SPAN: u32 = 16;
/// Tunnel considered dead when the newest handshake is older than this.
/// WireGuard rekeys every 120 s while traffic (or keepalive) flows, so a
/// healthy session is never older than ~125-145 s.
pub const STALE_SECS: u64 = 180;
/// ... and healthy again once a handshake is this fresh (hysteresis).
pub const FRESH_SECS: u64 = 150;

/// Destinations that never enter the tunnel.
pub const EXCLUDE_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "127.0.0.0/8",
    "224.0.0.0/3",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Tunnel may be up but nothing is steered into it.
    #[default]
    Off,
    /// Modem-originated traffic only (notifications, OTA, NTP, …).
    Modem,
    /// Modem-originated plus all forwarded LAN traffic (Route10's failover).
    Lan,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Modem => "modem",
            Mode::Lan => "lan",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub pref: u32,
    pub table: u32,
    pub lan_dev: String,
}

impl Plan {
    pub fn end(&self) -> u32 {
        self.pref + PREF_SPAN - 1
    }

    pub fn owns(&self, pref: u32) -> bool {
        (self.pref..self.pref + PREF_SPAN).contains(&pref)
    }

    /// The rules this mode needs, as `(pref, text)` where text is exactly
    /// what `ip -4 rule show` prints after `PREF:` (single-spaced).
    pub fn rules(&self) -> Vec<(u32, String)> {
        if self.mode == Mode::Off {
            return Vec::new();
        }
        let end = self.end();
        let mut v = vec![(self.pref, format!("from all fwmark {m:#x}/{m:#x} goto {end}", m = BYPASS_MARK))];
        for (i, net) in EXCLUDE_V4.iter().enumerate() {
            v.push((self.pref + 1 + i as u32, format!("from all to {net} goto {end}")));
        }
        v.push((self.pref + 10, format!("from all iif lo lookup {}", self.table)));
        if self.mode == Mode::Lan {
            v.push((self.pref + 11, format!("from all iif {} lookup {}", self.lan_dev, self.table)));
        }
        v.push((end, "from all nop".to_string()));
        v
    }

    /// argv for `ip` that adds one planned rule.
    pub fn add_argv(pref: u32, text: &str) -> Vec<String> {
        let mut a = vec!["-4".into(), "rule".into(), "add".into(), "pref".into(), pref.to_string()];
        a.extend(text.trim_start_matches("from all").split_whitespace().map(str::to_string));
        a
    }
}

/// What has to change to go from the live rules to the plan. Only rules in
/// the owned range are ever deleted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleDiff {
    pub delete_prefs: Vec<u32>,
    pub add: Vec<(u32, String)>,
}

impl RuleDiff {
    pub fn is_empty(&self) -> bool {
        self.delete_prefs.is_empty() && self.add.is_empty()
    }
}

pub fn diff_rules(plan: &Plan, live: &[(u32, String)]) -> RuleDiff {
    let want = plan.rules();
    let ours: Vec<&(u32, String)> = live.iter().filter(|(p, _)| plan.owns(*p)).collect();
    let same = ours.len() == want.len() && want.iter().all(|w| ours.iter().any(|o| o.0 == w.0 && o.1 == w.1));
    if same {
        return RuleDiff::default();
    }
    // Rebuild the block: delete every owned rule (one `del pref` per line,
    // duplicates included), then add the plan. Order: goto target first is
    // not required by the kernel, but adding `nop` before the gotos keeps
    // the block valid at every step.
    let delete_prefs = ours.iter().map(|(p, _)| *p).collect();
    let mut add = want;
    add.sort_by_key(|(p, _)| std::cmp::Reverse(*p));
    RuleDiff { delete_prefs, add }
}

/// Tunnel health as seen by the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    pub device_present: bool,
    /// Seconds since the newest handshake; `None` = never.
    pub handshake_age: Option<u64>,
}

/// Should the default route into the tunnel exist? Hysteresis: once usable
/// it stays usable until the handshake is older than STALE_SECS; once not it
/// needs a handshake fresher than FRESH_SECS.
pub fn tunnel_usable(was_usable: bool, h: Health) -> bool {
    if !h.device_present {
        return false;
    }
    match h.handshake_age {
        None => false,
        Some(age) if was_usable => age <= STALE_SECS,
        Some(age) => age <= FRESH_SECS,
    }
}

/// Handshake age from the epoch `wg` reports (0 = never).
pub fn handshake_age(latest: Option<u64>, now: u64) -> Option<u64> {
    latest.filter(|&t| t > 0).map(|t| now.saturating_sub(t))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Keep,
    /// Add `default dev wg table T` (tunnel healthy again / first time).
    Install,
    /// Flush the table: fail back to the cellular path.
    Withdraw,
}

pub fn route_action(mode: Mode, route_present: bool, usable: bool) -> RouteAction {
    let want = mode != Mode::Off && usable;
    match (want, route_present) {
        (true, false) => RouteAction::Install,
        (false, true) => RouteAction::Withdraw,
        _ => RouteAction::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(mode: Mode) -> Plan {
        Plan { mode, pref: DEFAULT_PREF, table: DEFAULT_TABLE, lan_dev: "br-lan".into() }
    }

    #[test]
    fn off_installs_nothing() {
        assert!(plan(Mode::Off).rules().is_empty());
    }

    #[test]
    fn modem_mode_steers_only_local_traffic() {
        let r = plan(Mode::Modem).rules();
        assert_eq!(r.first().unwrap(), &(1400, "from all fwmark 0x1000000/0x1000000 goto 1415".to_string()));
        assert_eq!(r.last().unwrap(), &(1415, "from all nop".to_string()));
        assert!(r.contains(&(1410, "from all iif lo lookup 51820".into())));
        assert!(!r.iter().any(|(_, t)| t.contains("br-lan")), "modem mode never touches forwarded traffic");
        for net in EXCLUDE_V4 {
            assert!(r.iter().any(|(p, t)| *p < 1410 && t == &format!("from all to {net} goto 1415")), "{net}");
        }
        // every goto lands on the nop inside the block
        assert!(r.iter().filter(|(_, t)| t.contains("goto")).all(|(_, t)| t.ends_with("goto 1415")));
        assert!(r.iter().all(|(p, _)| plan(Mode::Modem).owns(*p)));
        // the only lookups point at our table, never at main or an unreachable action
        assert!(r.iter().all(|(_, t)| !t.contains("unreachable") && !t.contains("blackhole") && !t.contains("prohibit")));
    }

    #[test]
    fn lan_mode_adds_forwarded_traffic_after_exclusions() {
        let r = plan(Mode::Lan).rules();
        let lan = r.iter().find(|(_, t)| t == "from all iif br-lan lookup 51820").expect("lan rule");
        let excl_max = r.iter().filter(|(_, t)| t.contains(" to ")).map(|(p, _)| *p).max().unwrap();
        assert!(lan.0 > excl_max, "LAN-to-LAN and LAN-to-modem stay off the tunnel");
        assert!(lan.0 > 1400, "bypass mark first");
        assert_eq!(r.len(), 1 + EXCLUDE_V4.len() + 3);
    }

    #[test]
    fn rules_sit_after_tailscale_and_before_mwan3() {
        let p = plan(Mode::Lan);
        // tailscale-tiny's init script moves its rules to 1310-1370 when mwan3 is active
        assert!(p.pref > 1370);
        // mwan3 fwmark rules start at 2001
        assert!(p.end() < 2001);
    }

    #[test]
    fn add_argv_is_ip_syntax() {
        assert_eq!(
            Plan::add_argv(1410, "from all iif lo lookup 51820"),
            vec!["-4", "rule", "add", "pref", "1410", "iif", "lo", "lookup", "51820"]
        );
        assert_eq!(Plan::add_argv(1415, "from all nop"), vec!["-4", "rule", "add", "pref", "1415", "nop"]);
        assert_eq!(
            Plan::add_argv(1401, "from all to 10.0.0.0/8 goto 1415"),
            vec!["-4", "rule", "add", "pref", "1401", "to", "10.0.0.0/8", "goto", "1415"]
        );
    }

    #[test]
    fn diff_is_idempotent_and_touches_only_owned_prefs() {
        let p = plan(Mode::Modem);
        let mut live: Vec<(u32, String)> = vec![
            (0, "from all lookup local".into()),
            (1310, "from all fwmark 0x80000/0xff0000 lookup main".into()),
            (2001, "from all fwmark 0x100/0x3f00 lookup 1".into()),
            (32766, "from all lookup main".into()),
        ];
        let d = diff_rules(&p, &live);
        assert!(d.delete_prefs.is_empty());
        assert_eq!(d.add.len(), p.rules().len());
        assert_eq!(d.add[0].0, 1415, "nop added first");
        live.extend(p.rules());
        assert!(diff_rules(&p, &live).is_empty(), "already applied: no churn");
        // switching to lan rebuilds only our block
        let d = diff_rules(&plan(Mode::Lan), &live);
        assert_eq!(d.delete_prefs.len(), p.rules().len());
        assert!(d.delete_prefs.iter().all(|x| (1400..1416).contains(x)));
        // off removes our block and nothing else
        let d = diff_rules(&plan(Mode::Off), &live);
        assert_eq!(d.delete_prefs.len(), p.rules().len());
        assert!(d.add.is_empty());
        // a stray duplicate in our range is cleaned up
        let mut dup = live.clone();
        dup.push((1410, "from all iif lo lookup 51820".into()));
        assert_eq!(diff_rules(&p, &dup).delete_prefs.len(), p.rules().len() + 1);
    }

    #[test]
    fn failback_hysteresis() {
        let h = |present, age| Health { device_present: present, handshake_age: age };
        // never handshaked: not usable, route stays out
        assert!(!tunnel_usable(false, h(true, None)));
        assert!(tunnel_usable(false, h(true, Some(5))));
        assert!(tunnel_usable(true, h(true, Some(170))), "healthy session ages up to the rekey");
        assert!(!tunnel_usable(true, h(true, Some(181))), "silent peer: fail back");
        assert!(!tunnel_usable(false, h(true, Some(160))), "needs a fresh handshake to return");
        assert!(tunnel_usable(false, h(true, Some(10))));
        assert!(!tunnel_usable(true, h(false, Some(1))), "device gone: fail back at once");
        assert_eq!(handshake_age(Some(0), 100), None);
        assert_eq!(handshake_age(Some(90), 100), Some(10));
        assert_eq!(handshake_age(None, 100), None);
    }

    #[test]
    fn route_actions() {
        assert_eq!(route_action(Mode::Lan, false, true), RouteAction::Install);
        assert_eq!(route_action(Mode::Lan, true, false), RouteAction::Withdraw);
        assert_eq!(route_action(Mode::Lan, true, true), RouteAction::Keep);
        assert_eq!(route_action(Mode::Off, true, true), RouteAction::Withdraw, "off never leaves a route behind");
        assert_eq!(route_action(Mode::Off, false, true), RouteAction::Keep);
        assert_eq!(route_action(Mode::Modem, false, false), RouteAction::Keep);
    }
}

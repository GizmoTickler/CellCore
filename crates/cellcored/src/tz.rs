//! Pure-Rust thread-safe POSIX `TZ` resolver and evaluator.
//!
//! OpenWrt 22.03 (static musl) has no `/etc/localtime` or `/usr/share/zoneinfo`,
//! and `tzset()` relies on global state. Resolving `TZ` -> `/etc/TZ` -> `/tmp/TZ`
//! -> UCI `/etc/config/system` directly keeps DST boundaries, daily usage
//! buckets, and scheduled actions consistent without spawning subprocesses.

use crate::{
    admin::system::resolve_zone,
    auth::now_secs,
    obs::usage_cycle::{Civil, civil_from_unix, days_in_month, is_leap},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDateTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// `0` = Sunday .. `6` = Saturday.
    pub wday: u8,
    pub secs_of_day: u32,
    pub utc_offset_secs: i64,
}

impl LocalDateTime {
    pub fn civil(self) -> Civil {
        Civil::new(self.year, self.month, self.day)
    }

    pub fn weekday_name(self) -> &'static str {
        match self.wday {
            0 => "sunday",
            1 => "monday",
            2 => "tuesday",
            3 => "wednesday",
            4 => "thursday",
            5 => "friday",
            _ => "saturday",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleDate {
    /// `M m.w.d`: month `1..=12`, week `1..=5` (`5` = last), weekday `0=Sun..=6`.
    MonthWeekDay { month: u32, week: u32, wday: u32 },
    /// `Jn`: 1-based Julian day (`1..=365`), Feb 29 is NOT counted.
    Julian1(u32),
    /// `n`: 0-based Julian day (`0..=365`), Feb 29 IS counted.
    Julian0(u32),
}

impl RuleDate {
    fn to_civil(self, year: i32) -> Civil {
        match self {
            RuleDate::MonthWeekDay { month, week, wday } => {
                if week <= 4 {
                    let first_wday = (Civil::new(year, month, 1).days() + 4).rem_euclid(7) as u32;
                    let delta = (wday + 7 - first_wday) % 7;
                    let day = 1 + delta + (week - 1) * 7;
                    Civil::new(year, month, day.min(days_in_month(year, month)))
                } else {
                    let dim = days_in_month(year, month);
                    let last_wday = (Civil::new(year, month, dim).days() + 4).rem_euclid(7) as u32;
                    let back = (last_wday + 7 - wday) % 7;
                    Civil::new(year, month, dim - back)
                }
            }
            RuleDate::Julian1(n) => {
                let offset = if is_leap(year) && n >= 60 { n } else { n - 1 };
                Civil::new(year, 1, 1).add_days(i64::from(offset))
            }
            RuleDate::Julian0(n) => Civil::new(year, 1, 1).add_days(i64::from(n)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DstRule {
    date: RuleDate,
    /// Seconds from 00:00:00 of `date` (can be negative or >= 86400).
    time_secs: i64,
}

impl DstRule {
    fn transition_epoch(self, year: i32, active_utc_offset: i64) -> i64 {
        let day_start = self.date.to_civil(year).days() * 86_400;
        day_start + self.time_secs - active_utc_offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DstInfo {
    dst_utc_offset: i64,
    start: DstRule,
    end: DstRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTz {
    std_utc_offset: i64,
    dst: Option<DstInfo>,
}

fn parse_tz_name(s: &str) -> Option<&str> {
    if let Some(rest) = s.strip_prefix('<') {
        let end = rest.find('>')?;
        let inner = &rest[..end];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-')
        {
            return None;
        }
        Some(&rest[end + 1..])
    } else {
        let len = s
            .bytes()
            .take_while(|b| b.is_ascii_alphabetic())
            .count();
        (len >= 3).then_some(&s[len..])
    }
}

fn take_uint(s: &str) -> Option<(u32, &str)> {
    let len = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if len == 0 {
        return None;
    }
    let val = s[..len].parse::<u32>().ok()?;
    Some((val, &s[len..]))
}

/// Parse `[+-]?hh[:mm[:ss]]` returning `(signed_seconds, remaining)`.
/// Notice POSIX `TZ` zone offsets use `+` for west of UTC (opposite ISO 8601),
/// while switch times (`/time`) use standard signed wall-clock hours.
fn parse_hms(s: &str, max_hours: u32) -> Option<(i64, &str)> {
    let (sign, mut rest) = if let Some(r) = s.strip_prefix('+') {
        (1i64, r)
    } else if let Some(r) = s.strip_prefix('-') {
        (-1i64, r)
    } else {
        (1i64, s)
    };
    let (hh, r) = take_uint(rest)?;
    if hh > max_hours {
        return None;
    }
    rest = r;
    let mut mm = 0u32;
    let mut ss = 0u32;
    if let Some(after_colon) = rest.strip_prefix(':') {
        let (m, r2) = take_uint(after_colon)?;
        if m > 59 {
            return None;
        }
        mm = m;
        rest = r2;
        if let Some(after_colon2) = rest.strip_prefix(':') {
            let (sec, r3) = take_uint(after_colon2)?;
            if sec > 59 {
                return None;
            }
            ss = sec;
            rest = r3;
        }
    }
    let total = i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss);
    Some((sign * total, rest))
}

fn parse_rule(s: &str) -> Option<(DstRule, &str)> {
    let (date, mut rest) = if let Some(r) = s.strip_prefix(['M', 'm']) {
        let (m, r) = take_uint(r)?;
        let r = r.strip_prefix('.')?;
        let (w, r) = take_uint(r)?;
        let r = r.strip_prefix('.')?;
        let (d, r) = take_uint(r)?;
        if !(1..=12).contains(&m) || !(1..=5).contains(&w) || d > 6 {
            return None;
        }
        (RuleDate::MonthWeekDay { month: m, week: w, wday: d }, r)
    } else if let Some(r) = s.strip_prefix('J') {
        let (n, r) = take_uint(r)?;
        if !(1..=365).contains(&n) {
            return None;
        }
        (RuleDate::Julian1(n), r)
    } else {
        let (n, r) = take_uint(s)?;
        if n > 365 {
            return None;
        }
        (RuleDate::Julian0(n), r)
    };

    let time_secs = if let Some(after_slash) = rest.strip_prefix('/') {
        let (t, r) = parse_hms(after_slash, 167)?;
        rest = r;
        t
    } else {
        2 * 3600
    };

    Some((DstRule { date, time_secs }, rest))
}

fn starts_with_offset(s: &str) -> bool {
    s.as_bytes()
        .first()
        .is_some_and(|&b| matches!(b, b'+' | b'-' | b'0'..=b'9'))
}

impl PosixTz {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        let rest = parse_tz_name(s)?;
        if rest.is_empty() {
            return Some(Self { std_utc_offset: 0, dst: None });
        }
        if !starts_with_offset(rest) {
            return None;
        }
        let (posix_std, rest) = parse_hms(rest, 24)?;
        let std_utc_offset = -posix_std;
        if rest.is_empty() {
            return Some(Self { std_utc_offset, dst: None });
        }

        let rest = parse_tz_name(rest)?;
        let (dst_utc_offset, rest) = if starts_with_offset(rest) {
            let (posix_dst, r) = parse_hms(rest, 24)?;
            (-posix_dst, r)
        } else {
            (std_utc_offset + 3600, rest)
        };

        let (start, end) = if rest.is_empty() {
            (
                DstRule { date: RuleDate::MonthWeekDay { month: 3, week: 2, wday: 0 }, time_secs: 7200 },
                DstRule { date: RuleDate::MonthWeekDay { month: 11, week: 1, wday: 0 }, time_secs: 7200 },
            )
        } else {
            let r = rest.strip_prefix(',')?;
            let (start, r) = parse_rule(r)?;
            let r = r.strip_prefix(',')?;
            let (end, r) = parse_rule(r)?;
            if !r.is_empty() {
                return None;
            }
            (start, end)
        };

        Some(Self {
            std_utc_offset,
            dst: Some(DstInfo { dst_utc_offset, start, end }),
        })
    }

    pub fn utc_offset_secs(&self, ts: i64) -> i64 {
        let Some(ref dst) = self.dst else {
            return self.std_utc_offset;
        };
        let utc_year = Civil::from_days(ts.div_euclid(86_400)).y;
        let mut transitions = [
            (dst.start.transition_epoch(utc_year - 1, self.std_utc_offset), true),
            (dst.end.transition_epoch(utc_year - 1, dst.dst_utc_offset), false),
            (dst.start.transition_epoch(utc_year, self.std_utc_offset), true),
            (dst.end.transition_epoch(utc_year, dst.dst_utc_offset), false),
            (dst.start.transition_epoch(utc_year + 1, self.std_utc_offset), true),
            (dst.end.transition_epoch(utc_year + 1, dst.dst_utc_offset), false),
        ];
        transitions.sort_by_key(|&(epoch, is_dst)| (epoch, is_dst));

        let mut in_dst = false;
        for (epoch, becomes_dst) in transitions {
            if epoch <= ts {
                in_dst = becomes_dst;
            } else {
                break;
            }
        }
        if in_dst { dst.dst_utc_offset } else { self.std_utc_offset }
    }
}

pub fn interpret_tz_spec(raw: &str) -> Option<PosixTz> {
    let s = raw.trim();
    let s = s.strip_prefix(':').unwrap_or(s).trim();
    if s.is_empty() {
        return None;
    }
    if let Some((_, posix)) = resolve_zone(s) {
        return PosixTz::parse(posix);
    }
    PosixTz::parse(s)
}

fn read_tz_file(path: &str) -> Option<PosixTz> {
    let text = std::fs::read_to_string(crate::paths::p(path)).ok()?;
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    interpret_tz_spec(line)
}

fn unquote_uci_scalar(raw: &str) -> String {
    let s = raw.trim();
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        return s[1..s.len() - 1].replace("'\\''", "'");
    }
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

fn parse_uci_system_tz_fields(text: &str) -> (Option<String>, Option<String>) {
    let mut in_system = false;
    let mut timezone = None;
    let mut zonename = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(kw) = words.next() else { continue };
        if kw == "config" {
            let stype = words.next().map(unquote_uci_scalar).unwrap_or_default();
            in_system = stype == "system";
        } else if in_system && kw == "option" {
            let Some(opt) = words.next() else { continue };
            let rest = line
                .strip_prefix("option")
                .map(str::trim_start)
                .and_then(|s| s.strip_prefix(opt))
                .map(str::trim)
                .unwrap_or("");
            let val = unquote_uci_scalar(rest);
            if val.is_empty() {
                continue;
            }
            if opt == "timezone" {
                timezone = Some(val);
            } else if opt == "zonename" {
                zonename = Some(val);
            }
        }
    }
    (timezone, zonename)
}

fn read_uci_system_tz() -> Option<PosixTz> {
    let text = std::fs::read_to_string(crate::paths::p("/etc/config/system")).ok()?;
    let (timezone, zonename) = parse_uci_system_tz_fields(&text);
    timezone
        .as_deref()
        .and_then(interpret_tz_spec)
        .or_else(|| {
            zonename
                .as_deref()
                .and_then(|z| resolve_zone(z).and_then(|(_, p)| PosixTz::parse(p)))
        })
}

#[cfg(test)]
thread_local! {
    static TEST_TZ_ENV: std::cell::RefCell<Option<Option<String>>> = const { std::cell::RefCell::new(None) };
}

pub fn resolve_posix_tz() -> Option<PosixTz> {
    #[cfg(test)]
    if let Some(ov) = TEST_TZ_ENV.with(|cell| cell.borrow().clone()) {
        if let Some(spec) = ov
            && let Some(tz) = interpret_tz_spec(&spec)
        {
            return Some(tz);
        }
        return read_tz_file("/etc/TZ")
            .or_else(|| read_tz_file("/tmp/TZ"))
            .or_else(read_uci_system_tz);
    }
    if let Ok(env_tz) = std::env::var("TZ")
        && let Some(tz) = interpret_tz_spec(&env_tz)
    {
        return Some(tz);
    }
    read_tz_file("/etc/TZ")
        .or_else(|| read_tz_file("/tmp/TZ"))
        .or_else(read_uci_system_tz)
}

#[allow(deprecated)]
fn libc_utc_offset_secs(ts: i64) -> i64 {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = ts as libc::time_t;
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    tm.tm_gmtoff as i64
}

pub fn local_at_offset(ts: i64, utc_offset_secs: i64) -> LocalDateTime {
    let (civil, secs_of_day) = civil_from_unix(ts, utc_offset_secs);
    let hour = (secs_of_day / 3600) as u8;
    let minute = ((secs_of_day % 3600) / 60) as u8;
    let second = (secs_of_day % 60) as u8;
    let wday = (civil.days() + 4).rem_euclid(7) as u8;
    LocalDateTime {
        year: civil.y,
        month: civil.m,
        day: civil.d,
        hour,
        minute,
        second,
        wday,
        secs_of_day,
        utc_offset_secs,
    }
}

pub fn local_at(ts: i64) -> LocalDateTime {
    let offset = resolve_posix_tz()
        .map(|tz| tz.utc_offset_secs(ts))
        .unwrap_or_else(|| libc_utc_offset_secs(ts));
    local_at_offset(ts, offset)
}

pub fn local_now() -> (Civil, u32) {
    let dt = local_at(now_secs() as i64);
    (dt.civil(), dt.secs_of_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_entry_in_zoneinfo_tsv() {
        for zone in crate::admin::system::zone_names() {
            let (_, posix) = resolve_zone(zone).expect("zone in tsv");
            assert!(PosixTz::parse(posix).is_some(), "failed to parse {zone} -> {posix:?}");
        }
    }

    #[test]
    fn parses_utc_and_bracketed_offsets() {
        let utc = interpret_tz_spec("UTC").unwrap();
        assert_eq!(utc.utc_offset_secs(1_700_000_000), 0);

        let utc0 = PosixTz::parse("UTC0").unwrap();
        assert_eq!(utc0.utc_offset_secs(1_700_000_000), 0);

        // Asia/Colombo: <+0530>-5:30 -> UTC+05:30 (+19800 s)
        let ist_colombo = PosixTz::parse("<+0530>-5:30").unwrap();
        assert_eq!(ist_colombo.utc_offset_secs(0), 5 * 3600 + 30 * 60);
        let dt = local_at_offset(0, ist_colombo.utc_offset_secs(0));
        assert_eq!((dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second), (1970, 1, 1, 5, 30, 0));

        // Bare bracketed <+0530> with no offset defaults to 0 per POSIX
        let bare = PosixTz::parse("<+0530>").unwrap();
        assert_eq!(bare.utc_offset_secs(0), 0);
    }

    #[test]
    fn new_york_spring_forward_and_fall_back_edges() {
        let ny = interpret_tz_spec("America/New_York").unwrap();
        assert_eq!(ny, PosixTz::parse("EST5EDT,M3.2.0,M11.1.0").unwrap());
        assert_eq!(interpret_tz_spec("America/New York").unwrap(), ny);

        // Spring forward 2026-03-08 07:00:00Z (01:59:59 EST -> 03:00:00 EDT)
        let spring_edge = 1_772_953_200i64;
        let before_spring = local_at_offset(spring_edge - 1, ny.utc_offset_secs(spring_edge - 1));
        assert_eq!((before_spring.year, before_spring.month, before_spring.day, before_spring.hour, before_spring.minute, before_spring.second), (2026, 3, 8, 1, 59, 59));
        assert_eq!(before_spring.utc_offset_secs, -5 * 3600);

        let at_spring = local_at_offset(spring_edge, ny.utc_offset_secs(spring_edge));
        assert_eq!((at_spring.year, at_spring.month, at_spring.day, at_spring.hour, at_spring.minute, at_spring.second), (2026, 3, 8, 3, 0, 0));
        assert_eq!(at_spring.utc_offset_secs, -4 * 3600);

        // Fall back 2026-11-01 06:00:00Z (01:59:59 EDT -> 01:00:00 EST)
        let fall_edge = 1_793_512_800i64;
        let before_fall = local_at_offset(fall_edge - 1, ny.utc_offset_secs(fall_edge - 1));
        assert_eq!((before_fall.year, before_fall.month, before_fall.day, before_fall.hour, before_fall.minute, before_fall.second), (2026, 11, 1, 1, 59, 59));
        assert_eq!(before_fall.utc_offset_secs, -4 * 3600);

        let at_fall = local_at_offset(fall_edge, ny.utc_offset_secs(fall_edge));
        assert_eq!((at_fall.year, at_fall.month, at_fall.day, at_fall.hour, at_fall.minute, at_fall.second), (2026, 11, 1, 1, 0, 0));
        assert_eq!(at_fall.utc_offset_secs, -5 * 3600);
    }

    #[test]
    fn supports_julian_rules_and_switch_times() {
        // Jn (ignores Feb 29): J60 = Mar 1 in both leap (2024) and non-leap (2026) years
        let j1 = PosixTz::parse("EST5EDT,J60/01:30:00,J305/02:00:00").unwrap();
        // 2024-03-01 06:30:00Z = 01:30:00 EST (after Feb 29, 2024)
        let mar1_2024 = Civil::new(2024, 3, 1).days() * 86_400 + 6 * 3600 + 30 * 60;
        assert_eq!(j1.utc_offset_secs(mar1_2024 - 1), -5 * 3600);
        assert_eq!(j1.utc_offset_secs(mar1_2024), -4 * 3600);

        // 0-based Julian n (counts Feb 29): 59 = Feb 29 in 2024, Mar 1 in 2026
        let j0 = PosixTz::parse("EST5EDT,59/02:00,305").unwrap();
        let feb29_2024 = Civil::new(2024, 2, 29).days() * 86_400 + 7 * 3600;
        assert_eq!(j0.utc_offset_secs(feb29_2024 - 1), -5 * 3600);
        assert_eq!(j0.utc_offset_secs(feb29_2024), -4 * 3600);

        // Negative DST & southern hemisphere: Europe/Dublin and Pacific/Chatham
        let dublin = interpret_tz_spec("Europe/Dublin").unwrap();
        let jan = Civil::new(2026, 1, 15).days() * 86_400;
        let jul = Civil::new(2026, 7, 15).days() * 86_400;
        assert_eq!(dublin.utc_offset_secs(jan), 0);
        assert_eq!(dublin.utc_offset_secs(jul), 3600);

        let chatham = interpret_tz_spec("Pacific/Chatham").unwrap();
        assert_eq!(chatham.utc_offset_secs(jan), 13 * 3600 + 45 * 60);
        assert_eq!(chatham.utc_offset_secs(jul), 12 * 3600 + 45 * 60);
    }

    #[test]
    fn resolves_tz_precedence_with_test_env_and_uci_fallback() {
        let env = crate::paths::TestSandbox::new("tz-precedence");
        TEST_TZ_ENV.with(|cell| *cell.borrow_mut() = Some(None));

        // 1. UCI /etc/config/system zonename fallback when /etc/TZ and /tmp/TZ are absent
        env.write(
            "/etc/config/system",
            "config system\n\toption hostname 'gw'\n\toption zonename 'America/New_York'\n",
        );
        let ts_summer = Civil::new(2026, 7, 15).days() * 86_400 + 16 * 3600; // 12:00 EDT
        let dt = local_at(ts_summer);
        assert_eq!(dt.utc_offset_secs, -4 * 3600);
        assert_eq!(dt.hour, 12);

        // 2. UCI option timezone overrides zonename if both present
        env.write(
            "/etc/config/system",
            "config system\n\toption timezone '<+0530>-5:30'\n\toption zonename 'America/New_York'\n",
        );
        assert_eq!(local_at(ts_summer).utc_offset_secs, 5 * 3600 + 30 * 60);

        // 3. /tmp/TZ overrides UCI /etc/config/system
        env.write("/tmp/TZ", "UTC0\n");
        assert_eq!(local_at(ts_summer).utc_offset_secs, 0);

        // 4. /etc/TZ overrides /tmp/TZ
        env.write("/etc/TZ", "PST8PDT,M3.2.0,M11.1.0\n");
        assert_eq!(local_at(ts_summer).utc_offset_secs, -7 * 3600);

        // 5. TZ env var overrides /etc/TZ (including IANA name mapping via resolve_zone)
        TEST_TZ_ENV.with(|cell| *cell.borrow_mut() = Some(Some("America/New_York".into())));
        assert_eq!(local_at(ts_summer).utc_offset_secs, -4 * 3600);
        TEST_TZ_ENV.with(|cell| *cell.borrow_mut() = None);
    }
}

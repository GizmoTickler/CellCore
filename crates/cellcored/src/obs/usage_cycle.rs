//! Billing-cycle accounting on top of the daemon's per-day usage buckets.
//!
//! The cycle is computed in local *civil dates* (the same local dates the
//! daily buckets use), so a DST change can never move a boundary. A cycle
//! day past the end of a short month starts that month's cycle on its last
//! day (day 31 → Feb 28/29, Apr 30, ...).

use serde::{Deserialize, Serialize};

use super::{
    events::{EventKind, Severity, emit},
    failover::human_bytes,
    lock, obs,
};
use crate::state::{DailyUsageEntry, DataUsageState};

pub const THRESHOLDS: [u8; 4] = [50, 80, 95, 100];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Civil {
    pub y: i32,
    pub m: u32,
    pub d: u32,
}

pub fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

impl Civil {
    pub fn new(y: i32, m: u32, d: u32) -> Self {
        Self { y, m, d }
    }

    /// Days since 1970-01-01 (H. Hinnant's days_from_civil).
    pub fn days(self) -> i64 {
        let y = i64::from(self.y) - i64::from(self.m <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(self.m);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.d) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    pub fn from_days(z: i64) -> Self {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let y = (yoe + era * 400 + i64::from(m <= 2)) as i32;
        Self { y, m, d }
    }

    pub fn add_days(self, n: i64) -> Self {
        Self::from_days(self.days() + n)
    }

    pub fn ymd(self) -> String {
        format!("{:04}-{:02}-{:02}", self.y, self.m, self.d)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.splitn(3, '-');
        let y = it.next()?.parse().ok()?;
        let m: u32 = it.next()?.parse().ok()?;
        let d: u32 = it.next()?.parse().ok()?;
        ((1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m)).then_some(Self { y, m, d })
    }

    fn month_offset(self, delta: i32) -> (i32, u32) {
        let idx = self.y * 12 + self.m as i32 - 1 + delta;
        (idx.div_euclid(12), (idx.rem_euclid(12) + 1) as u32)
    }
}

/// The cycle start in month (y, m) for a cycle day, clamped to the month.
pub fn cycle_start_in(y: i32, m: u32, cycle_day: u8) -> Civil {
    let day = u32::from(cycle_day.clamp(1, 31)).min(days_in_month(y, m));
    Civil::new(y, m, day)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cycle {
    pub start: Civil,
    /// First day of the next cycle (exclusive end).
    pub next_start: Civil,
}

impl Cycle {
    pub fn end(&self) -> Civil {
        self.next_start.add_days(-1)
    }

    pub fn days(&self) -> i64 {
        self.next_start.days() - self.start.days()
    }
}

pub fn cycle_bounds(today: Civil, cycle_day: u8) -> Cycle {
    let this = cycle_start_in(today.y, today.m, cycle_day);
    let start = if today >= this {
        this
    } else {
        let (y, m) = today.month_offset(-1);
        cycle_start_in(y, m, cycle_day)
    };
    let (ny, nm) = start.month_offset(1);
    Cycle { start, next_start: cycle_start_in(ny, nm, cycle_day) }
}

/// Local civil date and seconds into the day for a unix time at a UTC
/// offset (the offset comes from the C library at the time in question,
/// so it already reflects DST).
pub fn civil_from_unix(ts: i64, utc_offset_secs: i64) -> (Civil, u32) {
    let local = ts + utc_offset_secs;
    (Civil::from_days(local.div_euclid(86_400)), local.rem_euclid(86_400) as u32)
}

pub fn local_now() -> (Civil, u32) {
    crate::tz::local_now()
}

/// Sum of the daily buckets with first <= date <= last.
pub fn sum_days(daily: &[DailyUsageEntry], first: Civil, last: Civil) -> (u64, u64) {
    let (a, b) = (first.ymd(), last.ymd());
    daily
        .iter()
        .filter(|e| e.date.as_str() >= a.as_str() && e.date.as_str() <= b.as_str())
        .fold((0u64, 0u64), |(rx, tx), e| (rx.saturating_add(e.rx_bytes), tx.saturating_add(e.tx_bytes)))
}

/// Days into the cycle including the fraction of today, at least one hour.
pub fn elapsed_days(cycle: &Cycle, today: Civil, secs_of_day: u32) -> f64 {
    let whole = (today.days() - cycle.start.days()).max(0) as f64;
    (whole + f64::from(secs_of_day.min(86_399)) / 86_400.0).max(1.0 / 24.0)
}

/// Linear end-of-cycle projection.
pub fn project(total: u64, elapsed: f64, cycle_days: i64) -> u64 {
    let days = cycle_days.max(1) as f64;
    if elapsed >= days {
        return total;
    }
    (total as f64 * days / elapsed.max(1.0 / 24.0)).round() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct ThresholdMemo {
    pub cycle_start: String,
    pub quota: u64,
    pub fired: Vec<u8>,
}

/// The highest threshold newly crossed this cycle (lower ones crossed at
/// the same time are marked fired without their own event). A new cycle
/// or a changed quota starts a fresh memo.
pub fn threshold_to_fire(memo: &mut ThresholdMemo, cycle_start: &str, quota: u64, used: u64) -> Option<u8> {
    if quota == 0 {
        return None;
    }
    if memo.cycle_start != cycle_start || memo.quota != quota {
        *memo = ThresholdMemo { cycle_start: cycle_start.to_string(), quota, fired: Vec::new() };
    }
    let pct = (u128::from(used) * 100 / u128::from(quota)).min(1000) as u8;
    let crossed: Vec<u8> = THRESHOLDS.iter().copied().filter(|t| pct >= *t && !memo.fired.contains(t)).collect();
    let top = crossed.iter().copied().max()?;
    memo.fired.extend(crossed);
    memo.fired.sort_unstable();
    Some(top)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct UsageMemo {
    pub thresholds: ThresholdMemo,
    /// Local date the standby counter belongs to.
    pub standby_day: String,
    pub standby_bytes: u64,
    pub leak_alerted_day: String,
}

/// Mirrors telemetry's delta rules for the primary rmnet counters: an
/// interface switch is a fresh baseline; a counter that went backwards was
/// reset and counts from zero.
#[derive(Debug, Default)]
pub struct DeltaProbe {
    last: Option<(String, u64, u64)>,
}

impl DeltaProbe {
    pub fn observe(&mut self, iface: &str, rx: u64, tx: u64) -> (u64, u64) {
        let out = match self.last.as_ref() {
            Some((i, lrx, ltx)) if i == iface => (
                if rx >= *lrx { rx - lrx } else { rx },
                if tx >= *ltx { tx - ltx } else { tx },
            ),
            _ => (0, 0),
        };
        self.last = Some((iface.to_string(), rx, tx));
        out
    }
}

/// Every second: lifetime counters and the standby-day counter.
pub fn on_bytes(drx: u64, dtx: u64, failover_active: bool) {
    if drx == 0 && dtx == 0 {
        return;
    }
    let mut p = lock(&obs().persisted);
    p.lifetime_rx = p.lifetime_rx.saturating_add(drx);
    p.lifetime_tx = p.lifetime_tx.saturating_add(dtx);
    if !failover_active {
        p.usage.standby_bytes = p.usage.standby_bytes.saturating_add(drx.saturating_add(dtx));
    }
}

/// Every 30 s: seed lifetime once, roll the standby day, fire thresholds and
/// standby-leak alerts using pre-summed scalars without cloning `DataUsageState`.
pub(crate) fn check_alerts_scalars(
    today: Civil,
    secs: u32,
    cycle: Cycle,
    used: u64,
    quota_bytes: Option<u64>,
    monthly_seed: Option<(u64, u64)>,
    _now: u64,
) {
    let cfg = lock(&obs().config).usage.clone();
    let mut fire_pct = None;
    let mut leak = None;
    {
        let mut p = lock(&obs().persisted);
        if !p.lifetime_seeded
            && let Some((m_rx, m_tx)) = monthly_seed
        {
            p.lifetime_rx = m_rx;
            p.lifetime_tx = m_tx;
            p.lifetime_seeded = true;
            obs().mark_state_dirty();
        }
        let day = today.ymd();
        if p.usage.standby_day != day {
            p.usage.standby_day = day.clone();
            p.usage.standby_bytes = 0;
        }
        if cfg.thresholds_enabled
            && let Some(q) = quota_bytes
        {
            let prev_cycle = p.usage.thresholds.cycle_start.clone();
            let prev_len = p.usage.thresholds.fired.len();
            fire_pct = threshold_to_fire(&mut p.usage.thresholds, &cycle.start.ymd(), q, used);
            if p.usage.thresholds.cycle_start != prev_cycle || p.usage.thresholds.fired.len() != prev_len {
                obs().mark_state_dirty();
            }
        }
        if cfg.standby_floor_bytes > 0 && p.usage.standby_bytes > cfg.standby_floor_bytes && p.usage.leak_alerted_day != day {
            p.usage.leak_alerted_day = day;
            leak = Some(p.usage.standby_bytes);
            obs().mark_state_dirty();
        }
    }
    if let (Some(pct), Some(q)) = (fire_pct, quota_bytes) {
        let projected = project(used, elapsed_days(&cycle, today, secs), cycle.days());
        emit(
            EventKind::UsageThreshold,
            if pct >= 95 { Severity::Critical } else { Severity::Warning },
            format!("Data usage reached {pct}% of the cycle quota ({} of {})", human_bytes(used), human_bytes(q)),
            serde_json::json!({
                "percent": pct,
                "usedBytes": used,
                "quotaBytes": q,
                "projectedBytes": projected,
                "cycleStart": cycle.start.ymd(),
                "cycleEnd": cycle.end().ymd(),
            }),
        );
    }
    if let Some(bytes) = leak {
        emit(
            EventKind::StandbyLeak,
            Severity::Warning,
            format!("Standby leak: {} today while not carrying failover traffic", human_bytes(bytes)),
            serde_json::json!({ "bytes": bytes, "floorBytes": cfg.standby_floor_bytes, "day": today.ymd() }),
        );
    }
}

/// `GET /api/v1/network/data-usage/cycle`
pub fn cycle_report(usage: &DataUsageState) -> serde_json::Value {
    let (today, secs) = local_now();
    report_at(usage, today, secs)
}

pub fn report_at(usage: &DataUsageState, today: Civil, secs: u32) -> serde_json::Value {
    let cycle = cycle_bounds(today, usage.billing_cycle_day);
    let (rx, tx) = sum_days(&usage.daily, cycle.start, today);
    let total = rx.saturating_add(tx);
    let elapsed = elapsed_days(&cycle, today, secs);
    let projected = project(total, elapsed, cycle.days());
    let prev = cycle_bounds(cycle.start.add_days(-1), usage.billing_cycle_day);
    let (prx, ptx) = sum_days(&usage.daily, prev.start, prev.end());
    let prev_has_data = usage
        .daily
        .first()
        .and_then(|e| Civil::parse(&e.date))
        .is_some_and(|first| first <= prev.end());
    let (td_rx, td_tx) = sum_days(&usage.daily, today, today);
    let days: Vec<_> = usage
        .daily
        .iter()
        .filter(|e| Civil::parse(&e.date).is_some_and(|d| d >= cycle.start && d <= today))
        .cloned()
        .collect();
    let cfg = lock(&obs().config).usage.clone();
    let p = lock(&obs().persisted).clone();
    let quota = usage.quota_bytes;
    let pct = |v: u64| quota.filter(|q| *q > 0).map(|q| (v as f64 / q as f64 * 1000.0).round() / 10.0);
    let fired = if p.usage.thresholds.cycle_start == cycle.start.ymd() { p.usage.thresholds.fired.clone() } else { Vec::new() };
    serde_json::json!({
        "cycleDay": usage.billing_cycle_day,
        "cycleStart": cycle.start.ymd(),
        "cycleEnd": cycle.end().ymd(),
        "nextCycleStart": cycle.next_start.ymd(),
        "cycleDays": cycle.days(),
        "daysElapsed": (elapsed * 100.0).round() / 100.0,
        "daysRemaining": (cycle.days() as f64 - elapsed).max(0.0).round() as i64,
        "rxBytes": rx,
        "txBytes": tx,
        "totalBytes": total,
        "projectedBytes": projected,
        "quotaBytes": quota,
        "usedPct": pct(total),
        "projectedPct": pct(projected),
        "thresholds": THRESHOLDS,
        "thresholdsFired": fired,
        "today": { "date": today.ymd(), "rxBytes": td_rx, "txBytes": td_tx },
        "daily": days,
        "previousCycle": prev_has_data.then(|| serde_json::json!({
            "start": prev.start.ymd(),
            "end": prev.end().ymd(),
            "rxBytes": prx,
            "txBytes": ptx,
            "totalBytes": prx.saturating_add(ptx),
        })),
        "lifetime": { "rxBytes": p.lifetime_rx, "txBytes": p.lifetime_tx },
        "standby": {
            "todayBytes": if p.usage.standby_day == today.ymd() { p.usage.standby_bytes } else { 0 },
            "floorBytes": cfg.standby_floor_bytes,
            "alertedToday": p.usage.leak_alerted_day == today.ymd(),
        },
        "alerts": cfg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(y: i32, m: u32, d: u32) -> Civil {
        Civil::new(y, m, d)
    }

    fn bounds(today: Civil, day: u8) -> (String, String, i64) {
        let cy = cycle_bounds(today, day);
        (cy.start.ymd(), cy.end().ymd(), cy.days())
    }

    #[test]
    fn civil_roundtrip() {
        for z in [-1000i64, 0, 1, 19_000, 20_513, 60_000] {
            assert_eq!(Civil::from_days(z).days(), z);
        }
        assert_eq!(c(1970, 1, 1).days(), 0);
        assert_eq!(c(2024, 2, 29).add_days(1), c(2024, 3, 1));
        assert_eq!(Civil::parse("2026-02-29"), None);
        assert_eq!(Civil::parse("2028-02-29"), Some(c(2028, 2, 29)));
        assert_eq!(Civil::parse("2026-13-01"), None);
    }

    #[test]
    fn ordinary_cycle_day() {
        assert_eq!(bounds(c(2026, 11, 18), 15), ("2026-11-15".into(), "2026-12-14".into(), 30));
        assert_eq!(bounds(c(2026, 11, 15), 15), ("2026-11-15".into(), "2026-12-14".into(), 30));
        assert_eq!(bounds(c(2026, 11, 14), 15), ("2026-10-15".into(), "2026-11-14".into(), 31));
        assert_eq!(bounds(c(2026, 1, 3), 15), ("2025-12-15".into(), "2026-01-14".into(), 31), "year wrap");
        assert_eq!(bounds(c(2026, 3, 1), 1), ("2026-03-01".into(), "2026-03-31".into(), 31));
    }

    #[test]
    fn day_29_30_31_in_short_months() {
        // day 31: Feb cycle starts on its last day, Mar on the 31st
        assert_eq!(bounds(c(2026, 2, 27), 31), ("2026-01-31".into(), "2026-02-27".into(), 28));
        assert_eq!(bounds(c(2026, 2, 28), 31), ("2026-02-28".into(), "2026-03-30".into(), 31));
        assert_eq!(bounds(c(2026, 3, 15), 31), ("2026-02-28".into(), "2026-03-30".into(), 31));
        assert_eq!(bounds(c(2026, 3, 31), 31), ("2026-03-31".into(), "2026-04-29".into(), 30));
        assert_eq!(bounds(c(2026, 4, 30), 31), ("2026-04-30".into(), "2026-05-30".into(), 31));
        // leap year
        assert_eq!(bounds(c(2028, 2, 29), 31), ("2028-02-29".into(), "2028-03-30".into(), 31));
        assert_eq!(bounds(c(2028, 2, 29), 30), ("2028-02-29".into(), "2028-03-29".into(), 30));
        // day 30 and 29 in a common February
        assert_eq!(bounds(c(2026, 2, 28), 30), ("2026-02-28".into(), "2026-03-29".into(), 30));
        assert_eq!(bounds(c(2026, 3, 29), 30), ("2026-02-28".into(), "2026-03-29".into(), 30));
        assert_eq!(bounds(c(2026, 3, 30), 30), ("2026-03-30".into(), "2026-04-29".into(), 31));
        assert_eq!(bounds(c(2026, 2, 28), 29), ("2026-02-28".into(), "2026-03-28".into(), 29));
        assert_eq!(bounds(c(2026, 3, 29), 29), ("2026-03-29".into(), "2026-04-28".into(), 31));
        // every day of a year belongs to exactly one cycle and cycles tile
        for day in [1u8, 15, 28, 29, 30, 31] {
            let mut d = c(2027, 12, 1);
            let mut prev: Option<Cycle> = None;
            while d < c(2029, 1, 31) {
                let cy = cycle_bounds(d, day);
                assert!(cy.start <= d && d < cy.next_start, "{day} {d:?}");
                if let Some(p) = prev
                    && p != cy
                {
                    assert_eq!(p.next_start, cy.start, "cycles must tile ({day})");
                }
                prev = Some(cy);
                d = d.add_days(1);
            }
        }
    }

    #[test]
    fn dst_does_not_move_the_boundary() {
        // US spring forward 2026-03-08 07:00Z (EST -5h → EDT -4h)
        let before = civil_from_unix(1_772_953_199, -5 * 3600); // 01:59:59 EST
        let after = civil_from_unix(1_772_953_200, -4 * 3600); // 03:00:00 EDT
        assert_eq!(before.0, c(2026, 3, 8));
        assert_eq!(after.0, c(2026, 3, 8));
        assert_eq!(before.1, 7199);
        assert_eq!(after.1, 10_800);
        assert_eq!(cycle_bounds(before.0, 8), cycle_bounds(after.0, 8));
        // fall back 2026-11-01 06:00Z (EDT → EST): 01:30 happens twice, same day
        let first = civil_from_unix(1_793_511_000, -4 * 3600);
        let second = civil_from_unix(1_793_514_600, -5 * 3600);
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
        // midnight local just before a cycle start is still the old cycle
        let eve = civil_from_unix(1_793_595_599, -5 * 3600); // 2026-11-01 23:59:59 EST
        assert_eq!(eve.0, c(2026, 11, 1));
        assert_eq!(cycle_bounds(eve.0, 2).start, c(2026, 10, 2));
        let morn = civil_from_unix(1_793_595_600, -5 * 3600);
        assert_eq!(cycle_bounds(morn.0, 2).start, c(2026, 11, 2));
    }

    #[test]
    fn cycle_day_change_moves_the_window_and_resets_thresholds() {
        let today = c(2026, 11, 18);
        let daily: Vec<DailyUsageEntry> = (1..=18)
            .map(|d| DailyUsageEntry { date: c(2026, 11, d).ymd(), rx_bytes: 100, tx_bytes: 10 })
            .chain((20..=31).map(|d| DailyUsageEntry { date: c(2026, 10, d).ymd(), rx_bytes: 1000, tx_bytes: 0 }))
            .collect();
        let a = cycle_bounds(today, 15);
        assert_eq!(sum_days(&daily, a.start, today), (400, 40));
        let b = cycle_bounds(today, 25);
        assert_eq!(b.start, c(2026, 10, 25));
        assert_eq!(sum_days(&daily, b.start, today), (7000 + 1800, 180));
        let mut memo = ThresholdMemo::default();
        assert_eq!(threshold_to_fire(&mut memo, &a.start.ymd(), 1000, 440), None);
        assert_eq!(threshold_to_fire(&mut memo, &b.start.ymd(), 10_000, 8980), Some(80), "new window: fresh memo");
        assert_eq!(memo.fired, vec![50, 80]);
    }

    #[test]
    fn thresholds_fire_once_highest_only() {
        let mut m = ThresholdMemo::default();
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 499), None);
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 500), Some(50));
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 700), None);
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 990), Some(95), "80 and 95 at once: one event");
        assert_eq!(m.fired, vec![50, 80, 95]);
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 5000), Some(100));
        assert_eq!(threshold_to_fire(&mut m, "2026-11-15", 1000, 9000), None);
        // next cycle starts fresh
        assert_eq!(threshold_to_fire(&mut m, "2026-12-15", 1000, 10), None);
        assert_eq!(threshold_to_fire(&mut m, "2026-12-15", 1000, 600), Some(50));
        // quota raised mid-cycle: fresh memo for the new quota
        assert_eq!(threshold_to_fire(&mut m, "2026-12-15", 2000, 600), None);
        assert_eq!(threshold_to_fire(&mut m, "2026-12-15", 0, 600), None, "no quota, no alerts");
        assert_eq!(threshold_to_fire(&mut m, "2026-12-15", 1, u64::MAX), Some(100), "no overflow");
    }

    #[test]
    fn projection() {
        let cy = cycle_bounds(c(2026, 11, 18), 15); // 30 days
        let e = elapsed_days(&cy, c(2026, 11, 18), 43_200); // 3.5 days
        assert!((e - 3.5).abs() < 1e-9);
        assert_eq!(project(3_500, e, cy.days()), 30_000);
        assert_eq!(project(10, elapsed_days(&cy, c(2026, 11, 15), 0), 30), 7200, "first hour floor");
        assert_eq!(project(77, 31.0, 30), 77, "past the end: actual");
    }

    #[test]
    fn delta_probe_mirrors_telemetry_rules() {
        let mut p = DeltaProbe::default();
        assert_eq!(p.observe("rmnet_data1", 1000, 500), (0, 0), "first sample is a baseline");
        assert_eq!(p.observe("rmnet_data1", 1500, 600), (500, 100));
        assert_eq!(p.observe("rmnet_data1", 200, 50), (200, 50), "counter reset");
        assert_eq!(p.observe("rmnet_data2", 9000, 9000), (0, 0), "iface switch");
        assert_eq!(p.observe("rmnet_data2", 9100, 9000), (100, 0));
    }

    #[test]
    fn report_has_previous_cycle_only_with_history() {
        let mut u = DataUsageState { billing_cycle_day: 31, quota_bytes: Some(10_000), ..Default::default() };
        u.daily = vec![
            DailyUsageEntry { date: "2026-02-27".into(), rx_bytes: 5, tx_bytes: 5 },
            DailyUsageEntry { date: "2026-02-28".into(), rx_bytes: 1000, tx_bytes: 0 },
            DailyUsageEntry { date: "2026-03-01".into(), rx_bytes: 1000, tx_bytes: 0 },
        ];
        let r = report_at(&u, c(2026, 3, 1), 0);
        assert_eq!(r["cycleStart"], "2026-02-28");
        assert_eq!(r["cycleEnd"], "2026-03-30");
        assert_eq!(r["totalBytes"], 2000);
        assert_eq!(r["usedPct"], 20.0);
        assert_eq!(r["previousCycle"]["totalBytes"], 10);
        assert_eq!(r["daily"].as_array().map(|a| a.len()), Some(2));
        u.daily.remove(0);
        let r2 = report_at(&u, c(2026, 3, 1), 0);
        assert!(r2["previousCycle"].is_null());
    }
}

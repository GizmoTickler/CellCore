//! Radio changes (band lists + network mode) that keep the modem usable
//! through failures.
//!
//! A change is a sequence of writes planned so that every intermediate state
//! keeps the invariant ([`RadioConfig::check`]). When a write fails, nothing
//! after it is sent and nothing is assumed about the modem: a write whose reply
//! was lost may have been applied, and a refused write leaves the modem
//! wherever the earlier ones put it. The modem is re-read (bounded retries) and
//! a repair is planned from that real state:
//!
//! * back to the pre-request state, with a plan whose every step keeps the
//!   invariant, as long as that is possible;
//! * otherwise, if the real state breaks the invariant, to the nearest state
//!   that satisfies it (fewest writes, then closest to the pre-request state);
//! * otherwise the modem stays where it is (usable, but not rolled back).
//!
//! After any failed repair write the plan is dropped, the modem re-read and a
//! fresh plan made (a refused command is never planned again), for a bounded
//! number of rounds. The outcome reports the final state as read back, whether
//! it is the pre-request state (`ok`) and whether it satisfies the invariant
//! (`safe`; false whenever it could not be read).

use std::time::Duration;

use crate::{
    handlers::{RadioConfig, RadioStep, parse_mode_pref, parse_nr5g_disable, plan_radio_steps},
    smd::{Priority, never_sent},
    state::AppState,
};

/// The RATs a `mode_pref` value enables: (LTE, NR5G). `AUTO` is both; any
/// ':'-joined combination of LTE, NR5G and WCDMA, in any order or case, each at
/// most once, is the union of its tokens (WCDMA has no band lock here, so it
/// adds neither). `None`: not a value this daemon understands.
pub fn mode_rats(mode: &str) -> Option<(bool, bool)> {
    let up = mode.trim().to_ascii_uppercase();
    if up == "AUTO" {
        return Some((true, true));
    }
    let (mut lte, mut nr, mut wcdma) = (false, false, false);
    for tok in up.split(':') {
        let seen = match tok {
            "LTE" => std::mem::replace(&mut lte, true),
            "NR5G" => std::mem::replace(&mut nr, true),
            "WCDMA" => std::mem::replace(&mut wcdma, true),
            _ => return None,
        };
        if seen {
            return None;
        }
    }
    Some((lte, nr))
}

/// How one AT write ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// The modem answered ERROR / +CME ERROR (body) (normally not applied,
    /// though a buggy modem may still apply before refusing).
    Refused(String),
    /// Sent, but no reply (transport error, timeout): it may have been applied.
    Lost(String),
    /// Never reached the modem.
    NotSent(String),
}

/// What a failed write was trying to set, so a single-key re-read can tell
/// whether it took effect even when other radio keys are unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCheck {
    Radio(RadioStep),
    SimSlot(i32),
    Apn { pdp: String, apn: String },
}

/// The modem as seen by a radio change. Implemented over the AT channel, and
/// by an in-memory model in the tests.
pub(crate) trait RadioIo {
    async fn write(&self, cmd: &str, timeout: Duration) -> Outcome;
    /// The radio configuration the modem holds now, with bounded retries.
    /// Err: it could not be read, or not understood.
    async fn read(&self) -> Result<RadioConfig, String>;
    /// Re-read only the key targeted by `check` (bounded retries) and return
    /// whether the modem currently holds that value (`None` when unreadable).
    async fn read_holds(&self, check: &WriteCheck) -> Option<bool>;
}

/// The AT channel.
pub(crate) struct SmdRadio<'a> {
    pub app: &'a AppState,
}

fn check_reply_holds(check: &WriteCheck, body: &str) -> Option<bool> {
    match check {
        WriteCheck::Radio(RadioStep::Bands(rat, want)) => {
            let needle = format!("\"{}\"", rat.key());
            if !body.to_ascii_lowercase().contains(&needle) {
                return None;
            }
            Some(same_list(&crate::parsers::parse_qnw_band_list(body, rat.key()), want))
        }
        WriteCheck::Radio(RadioStep::Mode(want)) => parse_mode_pref(body).map(|got| got.eq_ignore_ascii_case(want)),
        WriteCheck::Radio(RadioStep::Disable(want)) => parse_nr5g_disable(body).map(|got| got == *want),
        WriteCheck::SimSlot(want) => crate::parsers::parse_scalar_at_value(body, "+QUIMSLOT:")
            .trim()
            .parse::<i32>()
            .ok()
            .map(|got| got == *want),
        WriteCheck::Apn { pdp, apn } => crate::profiles::parse_cgdcont(body, 1)
            .map(|(got_pdp, got_apn)| got_pdp.eq_ignore_ascii_case(pdp) && got_apn.eq_ignore_ascii_case(apn)),
    }
}

impl RadioIo for SmdRadio<'_> {
    async fn write(&self, cmd: &str, timeout: Duration) -> Outcome {
        match self.app.smd.exec(cmd, Priority::Interactive, timeout).await {
            Ok(r) if r.ok => Outcome::Ok,
            Ok(r) => Outcome::Refused(r.body.trim().to_string()),
            Err(e) if never_sent(&e) => Outcome::NotSent(e),
            Err(e) => Outcome::Lost(e),
        }
    }

    async fn read(&self) -> Result<RadioConfig, String> {
        let mut last = String::new();
        for attempt in 1..=READ_ATTEMPTS {
            match crate::handlers::read_radio_fields(self.app).await {
                Ok((cfg, true)) => return Ok(cfg),
                Ok((_, false)) => return Err("the modem reports a mode_pref this daemon does not understand".into()),
                Err(e) => last = e,
            }
            if attempt < READ_ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt))).await;
            }
        }
        Err(last)
    }

    async fn read_holds(&self, check: &WriteCheck) -> Option<bool> {
        let cmd = match check {
            WriteCheck::Radio(step) => format!("AT+QNWPREFCFG=\"{}\"", step.name()),
            WriteCheck::SimSlot(_) => "AT+QUIMSLOT?".to_string(),
            WriteCheck::Apn { .. } => "AT+CGDCONT?".to_string(),
        };
        for attempt in 1..=READ_ATTEMPTS {
            if let Ok(r) = self.app.smd.exec(&cmd, Priority::Interactive, Duration::from_secs(4)).await
                && r.ok
                && let Some(matches) = check_reply_holds(check, &r.body)
            {
                return Some(matches);
            }
            if attempt < READ_ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt))).await;
            }
        }
        None
    }
}

const READ_ATTEMPTS: u32 = 3;
/// Repair rounds (each: read, plan, write until a write fails), then a final read.
const REPAIR_ROUNDS: usize = 4;
const WRITE_TIMEOUT: Duration = Duration::from_secs(6);

/// One write of a change. Radio writes carry their step (the repair plans
/// them from the re-read state); other settings (SIM slot, APN) carry the
/// write that puts their previous value back, if known.
pub struct PlannedWrite {
    pub name: String,
    pub cmd: String,
    pub radio: Option<RadioStep>,
    pub check: WriteCheck,
    pub known_different: bool,
    pub undo: Option<String>,
    pub timeout: Duration,
}

impl PlannedWrite {
    pub fn radio(step: RadioStep, known_different: bool) -> Self {
        let check = WriteCheck::Radio(step.clone());
        PlannedWrite {
            name: step.name().to_string(),
            cmd: step.command(),
            radio: Some(step),
            check,
            known_different,
            undo: None,
            timeout: WRITE_TIMEOUT,
        }
    }

    pub fn sim_slot(slot: i32, undo: Option<String>, known_different: bool, timeout: Duration) -> Self {
        PlannedWrite {
            name: "sim_slot".to_string(),
            cmd: format!("AT+QUIMSLOT={slot}"),
            radio: None,
            check: WriteCheck::SimSlot(slot),
            known_different,
            undo,
            timeout,
        }
    }

    pub fn apn(pdp: String, apn: String, undo: Option<String>, known_different: bool, timeout: Duration) -> Self {
        PlannedWrite {
            name: "apn".to_string(),
            cmd: format!("AT+CGDCONT=1,\"{pdp}\",\"{apn}\""),
            radio: None,
            check: WriteCheck::Apn { pdp, apn },
            known_different,
            undo,
            timeout,
        }
    }
}

/// What became of the modem after a failed change.
#[derive(Debug, Default, Clone)]
pub struct Rollback {
    /// Writes that put something back (or towards a safe state) and were confirmed.
    pub restored: Vec<String>,
    /// Writes the modem refused while putting things back.
    pub failed: Vec<String>,
    /// Applied (or possibly applied), but the previous value is unknown.
    pub not_restorable: Vec<String>,
    /// The radio configuration read back at the end (None: could not be read).
    pub final_state: Option<RadioConfig>,
    /// Everything is back as it was before the request (final state re-read).
    pub ok: bool,
    /// The final state, as read back, satisfies the invariant.
    pub safe: bool,
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub failed: String,
    pub failed_cmd: String,
    pub outcome: Outcome,
    /// Writes the modem confirmed before the failure.
    pub applied: Vec<String>,
    pub not_applied: Vec<String>,
    /// Whether the failed write itself landed (from the re-read;
    /// None when that could not be told).
    pub failed_write_applied: Option<bool>,
    pub rollback: Rollback,
}

impl Failure {
    /// Something may have changed (or was repaired) on the modem.
    pub fn partial(&self) -> bool {
        !self.applied.is_empty() || self.failed_write_applied != Some(false) || !self.rollback.restored.is_empty()
    }
}

fn eval_holds(holds: Option<bool>, known_different: bool) -> Option<bool> {
    match holds {
        Some(false) => Some(false),
        Some(true) if known_different => Some(true),
        _ => None,
    }
}

/// Run `writes` in order. On the first failure, stop, put back the other
/// settings already written, and reconcile the radio from what the modem
/// really holds (module docs). `pre` is the radio before the request (None:
/// unknown), `target` the radio the request asked for.
pub(crate) async fn run_change<I: RadioIo>(
    io: &I,
    pre: Option<&RadioConfig>,
    target: Option<&RadioConfig>,
    writes: Vec<PlannedWrite>,
) -> Result<Vec<String>, Box<Failure>> {
    let names: Vec<String> = writes.iter().map(|w| w.name.clone()).collect();
    let has_radio = writes.iter().any(|w| w.radio.is_some());
    let mut applied: Vec<PlannedWrite> = Vec::new();
    for (i, w) in writes.into_iter().enumerate() {
        let outcome = io.write(&w.cmd, w.timeout).await;
        if outcome == Outcome::Ok {
            applied.push(w);
            continue;
        }
        let mut rb = Rollback::default();
        // Check non-radio failures before `others` undo overwrites the key;
        // radio failures use `rep.first_read` when available or `read_holds`.
        let mut failed_write_applied = if matches!(outcome, Outcome::NotSent(_)) {
            Some(false)
        } else if w.radio.is_none() {
            eval_holds(io.read_holds(&w.check).await, w.known_different)
        } else {
            None
        };
        // Other settings are independent keys: each is put back on its own,
        // newest first, including a failed write unless proven not applied.
        let mut others: Vec<&PlannedWrite> = applied.iter().filter(|a| a.radio.is_none()).collect();
        if w.radio.is_none() && failed_write_applied != Some(false) {
            others.push(&w);
        }
        let mut others_ok = true;
        for u in others.iter().rev() {
            match &u.undo {
                None => {
                    rb.not_restorable.push(u.name.clone());
                    others_ok = false;
                }
                Some(cmd) => {
                    if io.write(cmd, u.timeout).await == Outcome::Ok {
                        rb.restored.push(u.name.clone());
                    } else {
                        rb.failed.push(u.name.clone());
                        others_ok = false;
                    }
                }
            }
        }
        let rep = repair(io, if has_radio { pre } else { None }, target, has_radio).await;
        if w.radio.is_some() && !matches!(outcome, Outcome::NotSent(_)) {
            let h = match (&w.check, &rep.first_read) {
                (WriteCheck::Radio(step), Some(seen)) => Some(holds(seen, step)),
                _ => io.read_holds(&w.check).await,
            };
            failed_write_applied = eval_holds(h, w.known_different);
        }
        for n in rep.restored {
            push_unique(&mut rb.restored, n);
        }
        for n in rep.failed {
            push_unique(&mut rb.failed, n);
        }
        if has_radio && pre.is_none() && (!applied.is_empty() || failed_write_applied != Some(false)) {
            // nothing to compare the radio against
            for a in applied
                .iter()
                .chain((failed_write_applied != Some(false)).then_some(&w))
                .filter(|a| a.radio.is_some())
            {
                push_unique(&mut rb.not_restorable, a.name.clone());
            }
        }
        rb.safe = rep.final_state.as_ref().is_some_and(|f| f.check().is_ok());
        let radio_back = !has_radio || matches!((pre, &rep.final_state), (Some(p), Some(f)) if p.same(f));
        rb.ok = others_ok && radio_back;
        rb.final_state = rep.final_state;
        return Err(Box::new(Failure {
            failed: w.name.clone(),
            failed_cmd: w.cmd.clone(),
            outcome,
            applied: applied.iter().map(|a| a.name.clone()).collect(),
            not_applied: names[i + 1..].to_vec(),
            failed_write_applied,
            rollback: rb,
        }));
    }
    Ok(applied.into_iter().map(|a| a.name).collect())
}

fn push_unique(v: &mut Vec<String>, n: impl Into<String>) {
    let n = n.into();
    if !v.contains(&n) {
        v.push(n);
    }
}

/// Does `cfg` hold the value `step` writes?
fn holds(cfg: &RadioConfig, step: &RadioStep) -> bool {
    let mut after = cfg.clone();
    after.apply(step);
    after.same(cfg)
}

struct Repair {
    restored: Vec<String>,
    failed: Vec<String>,
    first_read: Option<RadioConfig>,
    final_state: Option<RadioConfig>,
}

/// Re-read the radio and repair it (module docs). Without `radio` in the
/// change nothing is written: the radio is only read back for the report.
async fn repair<I: RadioIo>(io: &I, pre: Option<&RadioConfig>, target: Option<&RadioConfig>, radio: bool) -> Repair {
    let mut out = Repair { restored: Vec::new(), failed: Vec::new(), first_read: None, final_state: None };
    let mut refused: Vec<String> = Vec::new();
    for round in 0..=REPAIR_ROUNDS {
        let Ok(now) = io.read().await else {
            out.final_state = None;
            break;
        };
        if round == 0 {
            out.first_read = Some(now.clone());
        }
        out.final_state = Some(now.clone());
        if !radio || round == REPAIR_ROUNDS || pre.is_some_and(|p| p.same(&now)) {
            break;
        }
        let Some(plan) = choose_repair(&now, pre, target, &refused) else {
            break;
        };
        for step in plan {
            let cmd = step.command();
            match io.write(&cmd, WRITE_TIMEOUT).await {
                Outcome::Ok => push_unique(&mut out.restored, step.name()),
                Outcome::Refused(_) => {
                    push_unique(&mut out.failed, step.name());
                    refused.push(cmd);
                    break;
                }
                // may or may not have landed: the next read tells
                Outcome::Lost(_) | Outcome::NotSent(_) => break,
            }
        }
    }
    out
}

/// The writes from `from` to `to`, in the safe order, without the ones that
/// would not change anything.
pub fn diff_plan(from: &RadioConfig, to: &RadioConfig) -> Vec<RadioStep> {
    let lists = [to.lte.clone(), to.nsa.clone(), to.sa.clone()];
    plan_radio_steps(from, Some(&lists), Some(&to.mode), Some(to.disable))
}

/// States along `plan` (after each write) that break the invariant.
fn invalid_steps(from: &RadioConfig, plan: &[RadioStep]) -> usize {
    let mut s = from.clone();
    plan.iter()
        .filter(|step| {
            s.apply(step);
            s.check().is_err()
        })
        .count()
}

/// The next repair plan from the real state `now` (module docs), or None to
/// leave the modem as it is.
fn choose_repair(now: &RadioConfig, pre: Option<&RadioConfig>, target: Option<&RadioConfig>, refused: &[String]) -> Option<Vec<RadioStep>> {
    let usable = |plan: &[RadioStep]| !plan.is_empty() && !plan.iter().any(|s| refused.contains(&s.command()));
    if let Some(p) = pre.filter(|p| p.check().is_ok()) {
        let plan = diff_plan(now, p);
        if usable(&plan) && invalid_steps(now, &plan) == 0 {
            return Some(plan);
        }
    }
    if now.check().is_ok() {
        return None;
    }
    nearest_safe(now, pre, target, refused).filter(|p| usable(p))
}

/// Among the states made of fields of `now`, `pre` and `target`, the one that
/// satisfies the invariant and is reached with the fewest invalid
/// intermediate states, then the fewest writes, then the fewest fields
/// different from `pre`.
fn nearest_safe(now: &RadioConfig, pre: Option<&RadioConfig>, target: Option<&RadioConfig>, refused: &[String]) -> Option<Vec<RadioStep>> {
    let mut sources: Vec<&RadioConfig> = vec![now];
    for s in [pre, target].into_iter().flatten() {
        if !sources.iter().any(|x| x.same(s)) {
            sources.push(s);
        }
    }
    let differs = |c: &RadioConfig| -> usize {
        pre.map_or(0, |p| {
            let parts = [
                !same_list(&c.lte, &p.lte),
                !same_list(&c.nsa, &p.nsa),
                !same_list(&c.sa, &p.sa),
                !c.mode.eq_ignore_ascii_case(&p.mode),
                c.disable != p.disable,
            ];
            parts.iter().filter(|d| **d).count()
        })
    };
    let mut best: Option<((usize, usize, usize), Vec<RadioStep>)> = None;
    for l in &sources {
        for n in &sources {
            for s in &sources {
                for m in &sources {
                    for d in &sources {
                        let c = RadioConfig { lte: l.lte.clone(), nsa: n.nsa.clone(), sa: s.sa.clone(), mode: m.mode.clone(), disable: d.disable };
                        if c.check().is_err() {
                            continue;
                        }
                        let plan = diff_plan(now, &c);
                        if plan.is_empty() || plan.iter().any(|st| refused.contains(&st.command())) {
                            continue;
                        }
                        let score = (invalid_steps(now, &plan), plan.len(), differs(&c));
                        if best.as_ref().is_none_or(|(b, _)| score < *b) {
                            best = Some((score, plan));
                        }
                    }
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Band lists compared as sets (the modem may report them in its own order).
pub fn same_list(a: &[String], b: &[String]) -> bool {
    let norm = |v: &[String]| {
        let mut x: Vec<u32> = v.iter().filter_map(|s| s.trim().parse().ok()).collect();
        x.sort_unstable();
        x.dedup();
        x
    };
    norm(a) == norm(b)
}

/// Does an AT command line write the radio configuration or reset/reconfigure
/// the modem (derived from the AT guard's normalized parser)? Such console
/// commands take the radio lock like the radio endpoints.
pub fn is_radio_write(command: &str) -> bool {
    crate::atguard::has_dangerous_part(command)
}

/// Serialise radio-changing work: every read-plan-write of the radio holds this.
pub async fn lock(app: &AppState) -> tokio::sync::MutexGuard<'_, ()> {
    app.radio_lock.lock().await
}

/// Acquire the radio lock, waiting at most `max_wait` (`None` if timed out).
pub async fn lock_bounded(app: &AppState, max_wait: std::time::Duration) -> Option<tokio::sync::MutexGuard<'_, ()>> {
    tokio::time::timeout(max_wait, app.radio_lock.lock()).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn mode_values_parse_into_rat_sets() {
        for (m, want) in [
            ("AUTO", Some((true, true))),
            ("auto", Some((true, true))),
            ("LTE", Some((true, false))),
            ("NR5G", Some((false, true))),
            ("LTE:NR5G", Some((true, true))),
            ("NR5G:LTE", Some((true, true))),
            ("nr5g:lte", Some((true, true))),
            ("WCDMA:LTE:NR5G", Some((true, true))),
            ("LTE:WCDMA", Some((true, false))),
            ("WCDMA", Some((false, false))),
            ("LTE:LTE", None),
            ("LTE:", None),
            ("GSM", None),
            ("", None),
            ("AUTO:LTE", None),
        ] {
            assert_eq!(mode_rats(m), want, "{m}");
        }
    }

    #[test]
    fn radio_writes_are_recognised_in_console_lines() {
        for c in [
            "AT+QNWPREFCFG=\"lte_band\",2:66",
            "at+qnwprefcfg=\"mode_pref\",AUTO",
            "AT + QNWPREFCFG = \"lte_band\" , 2:66",
            "AT+QNWLOCK=\"common/4g\",1,66786,371",
            "AT+CFUN=0",
            "AT+CFUN =0",
            "AT+CFUN=1,1",
            "AT+QPRTPARA=1",
            "AT&F",
            "ATZ",
            "ATI;+QNWPREFCFG=\"nr5g_band\",41",
            "AT+QNWLOCK=\"common/4g",
        ] {
            assert!(is_radio_write(c), "{c}");
        }
        for c in [
            "AT+QNWPREFCFG=\"lte_band\"",
            "AT+QNWLOCK=\"common/4g\"",
            "AT+QNWLOCK=\"common/4g;+CFUN=0\"",
            "AT+CFUN?",
            "AT+CFUN=?",
            "ATI",
            "AT+QENG=\"servingcell\"",
        ] {
            assert!(!is_radio_write(c), "{c}");
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Fault {
        Refuse,
        ApplyRefuse,
        Drop,
        ApplyDrop,
        NotSent,
    }

    /// In-memory modem: applies QNWPREFCFG writes, injects faults on exact
    /// commands, records every state the radio passes through.
    struct Model {
        radio: RefCell<RadioConfig>,
        faults: RefCell<Vec<(String, Fault, Option<usize>)>>,
        states: RefCell<Vec<RadioConfig>>,
        writes: RefCell<Vec<String>>,
        reads_fail_after_fault: bool,
        faulted: RefCell<bool>,
    }

    fn parse(cmd: &str) -> RadioStep {
        let rest = cmd.strip_prefix("AT+QNWPREFCFG=\"").unwrap();
        let (key, val) = rest.split_once("\",").unwrap();
        let list = || if val == "0" { Vec::new() } else { val.split(':').map(String::from).collect() };
        match key {
            "lte_band" => RadioStep::Bands(crate::handlers::BandRat::Lte, list()),
            "nsa_nr5g_band" => RadioStep::Bands(crate::handlers::BandRat::NsaNr5g, list()),
            "nr5g_band" => RadioStep::Bands(crate::handlers::BandRat::SaNr5g, list()),
            "mode_pref" => RadioStep::Mode(val.into()),
            "nr5g_disable_mode" => RadioStep::Disable(val.parse().unwrap()),
            _ => panic!("{cmd}"),
        }
    }

    impl Model {
        fn new(radio: RadioConfig) -> Self {
            Model {
                radio: RefCell::new(radio),
                faults: RefCell::new(Vec::new()),
                states: RefCell::new(Vec::new()),
                writes: RefCell::new(Vec::new()),
                reads_fail_after_fault: false,
                faulted: RefCell::new(false),
            }
        }
        fn fault(&self, cmd: &str, f: Fault, times: Option<usize>) {
            self.faults.borrow_mut().push((cmd.to_string(), f, times));
        }
        fn apply(&self, cmd: &str) {
            let mut r = self.radio.borrow_mut();
            r.apply(&parse(cmd));
            self.states.borrow_mut().push(r.clone());
        }
    }

    impl RadioIo for Model {
        async fn write(&self, cmd: &str, _t: Duration) -> Outcome {
            self.writes.borrow_mut().push(cmd.to_string());
            let hit = {
                let mut faults = self.faults.borrow_mut();
                faults.iter_mut().find(|(c, _, n)| c == cmd && *n != Some(0)).map(|(_, f, n)| {
                    if let Some(n) = n {
                        *n -= 1;
                    }
                    *f
                })
            };
            if hit.is_some() {
                *self.faulted.borrow_mut() = true;
            }
            match hit {
                Some(Fault::Refuse) => Outcome::Refused("+CME ERROR: 50".into()),
                Some(Fault::ApplyRefuse) => {
                    self.apply(cmd);
                    Outcome::Refused("+CME ERROR: 50".into())
                }
                Some(Fault::Drop) => Outcome::Lost("EOF".into()),
                Some(Fault::ApplyDrop) => {
                    self.apply(cmd);
                    Outcome::Lost("EOF".into())
                }
                Some(Fault::NotSent) => Outcome::NotSent("command not sent: port closed".into()),
                None => {
                    self.apply(cmd);
                    Outcome::Ok
                }
            }
        }
        async fn read(&self) -> Result<RadioConfig, String> {
            if self.reads_fail_after_fault && *self.faulted.borrow() {
                return Err("dead line".into());
            }
            Ok(self.radio.borrow().clone())
        }
        async fn read_holds(&self, check: &WriteCheck) -> Option<bool> {
            if self.reads_fail_after_fault && *self.faulted.borrow() {
                return None;
            }
            let r = self.radio.borrow();
            match check {
                WriteCheck::Radio(step) => Some(holds(&r, step)),
                _ => None,
            }
        }
    }

    fn cfg(p: u8, m: &str, d: i32) -> RadioConfig {
        let l = |bit: u8, v: &str| if p & bit != 0 { v.split(':').map(String::from).collect() } else { Vec::new() };
        RadioConfig { lte: l(1, "2:66"), nsa: l(2, "41"), sa: l(4, "41:71"), mode: m.into(), disable: d }
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    /// Every valid start x every valid request (bands + mode), every single
    /// forward-write fault (refused / apply-refused / dropped / applied with
    /// the reply lost), alone and with every fault on each repair write it
    /// causes: the modem ends where the outcome says, that state satisfies the
    /// invariant (safe), every state on the way does too, and a single fault is
    /// always fully rolled back.
    #[test]
    fn exhaustive_fault_injection_always_ends_safe_and_honest() {
        block(async {
            let modes = ["AUTO", "LTE", "NR5G", "LTE:NR5G", "NR5G:LTE"];
            let (mut plans, mut single, mut double) = (0usize, 0usize, 0usize);
            for sm in modes {
                for sd in 0..=2 {
                    for sp in 0..8u8 {
                        let start = cfg(sp, sm, sd);
                        if start.check().is_err() {
                            continue;
                        }
                        for tm in [None, Some("AUTO"), Some("LTE"), Some("NR5G"), Some("LTE:NR5G")] {
                            for td in [None, Some(0), Some(1), Some(2)] {
                                for tp in 0..8u8 {
                                    let t = cfg(tp, tm.unwrap_or(sm), td.unwrap_or(sd));
                                    if t.check().is_err() {
                                        continue;
                                    }
                                    let lists = [t.lte.clone(), t.nsa.clone(), t.sa.clone()];
                                    let steps = plan_radio_steps(&start, Some(&lists), tm, td);
                                    let fwd: Vec<String> = steps.iter().map(RadioStep::command).collect();
                                    plans += 1;
                                    let run = |faults: Vec<(String, Fault, Option<usize>)>| {
                                        let (start, t, steps) = (start.clone(), t.clone(), steps.clone());
                                        async move {
                                            let m = Model::new(start.clone());
                                            for (c, f, n) in &faults {
                                                m.fault(c, *f, *n);
                                            }
                                            let writes = steps.into_iter().map(|s| PlannedWrite::radio(s, true)).collect();
                                            let r = run_change(&m, Some(&start), Some(&t), writes).await;
                                            (m, r)
                                        }
                                    };
                                    for fw in &fwd {
                                        for f in [Fault::Refuse, Fault::ApplyRefuse, Fault::Drop, Fault::ApplyDrop] {
                                            let (m, r) = run(vec![(fw.clone(), f, Some(1))]).await;
                                            let ctx = format!("{start:?} -> {t:?}: {f:?} on {fw}; writes {:?}", m.writes.borrow());
                                            let e = r.expect_err(&ctx);
                                            let fin = m.radio.borrow().clone();
                                            assert!(fin.check().is_ok() && e.rollback.safe, "{ctx}: {fin:?} {e:?}");
                                            assert!(e.rollback.final_state.as_ref().is_some_and(|x| x.same(&fin)), "{ctx}: {e:?}");
                                            assert!(e.rollback.ok && fin.same(&start), "single fault not rolled back: {ctx}: {fin:?} {e:?}");
                                            assert!(m.states.borrow().iter().all(|s| s.check().is_ok()), "{ctx}: {:?}", m.states.borrow());
                                            if matches!(f, Fault::ApplyDrop | Fault::ApplyRefuse) {
                                                assert_eq!(e.failed_write_applied, Some(true), "{ctx}");
                                            } else {
                                                assert_eq!(e.failed_write_applied, Some(false), "{ctx}");
                                            }
                                            single += 1;
                                            let writes = m.writes.borrow().clone();
                                            let at = writes.iter().position(|w| w == fw).unwrap();
                                            let mut repair: Vec<String> = writes[at + 1..].to_vec();
                                            repair.dedup();
                                            for rw in repair {
                                                for (g, n) in [
                                                    (Fault::Refuse, None),
                                                    (Fault::ApplyRefuse, Some(1)),
                                                    (Fault::Drop, Some(1)),
                                                    (Fault::ApplyDrop, Some(1)),
                                                ] {
                                                    let (m2, r2) = run(vec![(fw.clone(), f, Some(1)), (rw.clone(), g, n)]).await;
                                                    let ctx = format!("{ctx}; then {g:?} on {rw}; writes {:?}", m2.writes.borrow());
                                                    let e = r2.expect_err(&ctx);
                                                    let fin = m2.radio.borrow().clone();
                                                    assert!(fin.check().is_ok() && e.rollback.safe, "{ctx}: {fin:?} {e:?}");
                                                    assert!(e.rollback.final_state.as_ref().is_some_and(|x| x.same(&fin)), "{ctx}: {e:?}");
                                                    assert_eq!(e.rollback.ok, fin.same(&start), "{ctx}: {e:?}");
                                                    assert!(m2.states.borrow().iter().all(|s| s.check().is_ok()), "{ctx}: {:?}", m2.states.borrow());
                                                    double += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            assert!(plans > 1000 && single > 10_000 && double > 10_000, "{plans} plans, {single} single, {double} double faults");
        });
    }

    /// When the modem cannot be read back after a failure, nothing is claimed:
    /// safe and ok are false and there is no final state (NotSent still knows
    /// the write never reached the modem, while Refused/Lost cannot rule out
    /// that it took effect).
    #[test]
    fn unreadable_after_failure_is_never_reported_safe() {
        block(async {
            let start = cfg(7, "AUTO", 0);
            let t = cfg(1, "LTE", 0);
            let steps = plan_radio_steps(&start, Some(&[t.lte.clone(), t.nsa.clone(), t.sa.clone()]), Some("LTE"), Some(0));
            for i in 0..steps.len() {
                for f in [Fault::Refuse, Fault::ApplyRefuse, Fault::Drop, Fault::ApplyDrop, Fault::NotSent] {
                    let mut m = Model::new(start.clone());
                    m.reads_fail_after_fault = true;
                    m.fault(&steps[i].command(), f, Some(1));
                    let writes = steps.iter().cloned().map(|s| PlannedWrite::radio(s, true)).collect();
                    let e = run_change(&m, Some(&start), Some(&t), writes).await.unwrap_err();
                    assert!(!e.rollback.safe && !e.rollback.ok && e.rollback.final_state.is_none(), "{e:?}");
                    if f == Fault::NotSent {
                        assert_eq!(e.failed_write_applied, Some(false));
                    } else {
                        assert_eq!(e.failed_write_applied, None, "refused or lost reply with no re-read is not known");
                    }
                }
            }
        });
    }

    #[tokio::test(start_paused = true)]
    async fn lock_bounded_times_out_or_acquires() {
        let dir = std::env::temp_dir().join(format!("qm-lock-bounded-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let auth = crate::auth::AuthStore::new(dir.join("sessions"));
        let app = AppState::for_tests(dir, auth);
        let guard = lock(&app).await;
        assert!(lock_bounded(&app, Duration::from_millis(50)).await.is_none());
        drop(guard);
        assert!(lock_bounded(&app, Duration::from_millis(50)).await.is_some());
    }

    /// A real state that breaks the invariant (e.g. changed from outside) is
    /// repaired to the nearest valid state when the way back is refused.
    #[test]
    fn invalid_real_state_is_repaired_to_the_nearest_safe_state() {
        block(async {
            // LTE-only mode with no LTE band; the pre-request mode (NR5G) is refused
            let now = RadioConfig { lte: vec![], nsa: vec![], sa: vec!["41".into()], mode: "LTE".into(), disable: 0 };
            let pre = RadioConfig { lte: vec![], nsa: vec![], sa: vec!["41".into()], mode: "NR5G".into(), disable: 0 };
            let t = RadioConfig { lte: vec!["2".into()], nsa: vec![], sa: vec![], mode: "LTE".into(), disable: 0 };
            let refused = vec!["AT+QNWPREFCFG=\"mode_pref\",NR5G".to_string()];
            let plan = choose_repair(&now, Some(&pre), Some(&t), &refused).unwrap();
            assert_eq!(plan, vec![RadioStep::Bands(crate::handlers::BandRat::Lte, vec!["2".into()])], "restore the band the current mode needs");
            // not refused: back to the pre-request state, one write
            let plan = choose_repair(&now, Some(&pre), Some(&t), &[]).unwrap();
            assert_eq!(plan, vec![RadioStep::Mode("NR5G".into())]);
            // valid and not the pre-request state, and the way back refused: stay
            let ok_now = RadioConfig { lte: vec!["2".into()], ..now.clone() };
            assert_eq!(choose_repair(&ok_now, Some(&pre), Some(&t), &refused), None);
        });
    }
}

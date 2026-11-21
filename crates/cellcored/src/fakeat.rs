//! Test-only stateful fake of the modem's AT channel, wired into the real
//! SMD actor through a socketpair (the same seam the smd tests use). It keeps
//! the radio configuration the handlers read and write (band lists, network
//! mode, SIM slot, APN, cell locks), records every command it receives and a
//! snapshot of the radio after every accepted band/mode write, and can be
//! told to answer a command with ERROR / +CME ERROR, to drop the line (before
//! or after applying the command: a lost reply), or to answer late.
//!
//! Each (re)open of the device gets a fresh socketpair and reader thread, so
//! a dropped line behaves like the real channel: the command in flight fails
//! with a transport error and the next command reopens.

use std::{
    os::fd::RawFd,
    sync::{Arc, Mutex},
    thread,
};

use crate::smd::SmdClient;

/// The radio configuration as the modem holds it. Band lists are
/// colon-separated ("" = none, written as `0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Radio {
    pub lte: String,
    pub nsa: String,
    pub sa: String,
    pub mode: String,
    pub disable: i32,
}

impl Radio {
    pub fn new(lte: &str, nsa: &str, sa: &str, mode: &str, disable: i32) -> Self {
        Radio { lte: lte.into(), nsa: nsa.into(), sa: sa.into(), mode: mode.into(), disable }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// Final result `ERROR`.
    Error,
    /// Final result `+CME ERROR: n`.
    Cme(u32),
    /// Apply the command, then answer `ERROR` (apply-then-refuse).
    ApplyError,
    /// Apply the command, then answer `+CME ERROR: n` (apply-then-refuse).
    ApplyCme(u32),
    /// Close the line without answering (transport failure); the command is
    /// not applied.
    Drop,
    /// Apply the command, then close the line without answering: the write
    /// took effect but its reply is lost.
    ApplyDrop,
    /// Answer normally, after this many milliseconds (the line is busy meanwhile).
    Delay(u64),
}

#[derive(Clone, Debug)]
pub struct Rule {
    /// Matches when the command contains this text.
    pub needle: String,
    pub fail: Fail,
    /// How many more times it fires (`None` = always).
    pub times: Option<usize>,
    /// Match the whole command instead of a substring.
    pub exact: bool,
}

#[derive(Debug)]
pub struct FakeState {
    pub radio: Radio,
    /// Supported bands reported by `policy_band` (lte, nsa, sa).
    pub policy: (String, String, String),
    pub sim_slot: i32,
    pub cgdcont: (String, String),
    pub lock4g: Option<String>,
    pub lock5g: Option<String>,
    pub save_ctrl: Option<String>,
    /// Every command received, in order.
    pub log: Vec<String>,
    /// Every configuration write received (accepted or not), in order.
    pub writes: Vec<String>,
    /// The radio after each accepted band / mode write.
    pub snapshots: Vec<Radio>,
    pub rules: Vec<Rule>,
}

#[derive(Clone)]
pub struct FakeModem {
    pub state: Arc<Mutex<FakeState>>,
}

/// Configuration writes (as opposed to reads / queries).
pub fn is_write(cmd: &str) -> bool {
    let up = cmd.to_ascii_uppercase();
    (up.starts_with("AT+QNWPREFCFG=") && up.contains(','))
        || up.starts_with("AT+QUIMSLOT=")
        || up.starts_with("AT+CGDCONT=")
        || (up.starts_with("AT+QNWLOCK=") && up.contains(','))
        || (up.starts_with("AT+QMBNCFG=") && up.contains(','))
}

fn quoted_key(cmd: &str) -> Option<String> {
    let start = cmd.find('"')? + 1;
    let end = start + cmd[start..].find('"')?;
    Some(cmd[start..end].to_string())
}

fn after_key(cmd: &str) -> String {
    // value after `"key",`
    cmd.split_once("\",").map(|(_, v)| v.trim().to_string()).unwrap_or_default()
}

fn band_value(v: &str) -> String {
    if v == "0" { String::new() } else { v.to_string() }
}

fn shown(v: &str) -> &str {
    if v.is_empty() { "0" } else { v }
}

impl FakeState {
    fn new(radio: Radio) -> Self {
        FakeState {
            radio,
            policy: (
                "1:2:3:4:5:7:12:13:14:25:26:29:30:41:46:48:66:71".into(),
                "2:5:7:12:25:41:48:66:71:77:78".into(),
                "2:5:7:12:25:41:48:66:71:77:78".into(),
            ),
            sim_slot: 1,
            cgdcont: ("IPV4V6".into(), "old.apn".into()),
            lock4g: None,
            lock5g: None,
            save_ctrl: None,
            log: Vec::new(),
            writes: Vec::new(),
            snapshots: Vec::new(),
            rules: Vec::new(),
        }
    }

    fn rule_for(&mut self, cmd: &str) -> Option<Fail> {
        let r = self
            .rules
            .iter_mut()
            .find(|r| (if r.exact { cmd == r.needle } else { cmd.contains(&r.needle) }) && r.times != Some(0))?;
        if let Some(n) = r.times.as_mut() {
            *n -= 1;
        }
        Some(r.fail.clone())
    }

    /// The reply body for `cmd` (without the final result), applying writes.
    fn answer(&mut self, cmd: &str) -> String {
        let up = cmd.to_ascii_uppercase();
        if up.starts_with("AT+QNWPREFCFG=") {
            let key = quoted_key(cmd).unwrap_or_default();
            if up.contains(',') {
                let v = after_key(cmd);
                let r = &mut self.radio;
                match key.as_str() {
                    "lte_band" => r.lte = band_value(&v),
                    "nsa_nr5g_band" => r.nsa = band_value(&v),
                    "nr5g_band" => r.sa = band_value(&v),
                    "mode_pref" => r.mode = v.to_ascii_uppercase(),
                    "nr5g_disable_mode" => r.disable = v.parse().unwrap_or(-1),
                    _ => return String::new(),
                }
                self.snapshots.push(self.radio.clone());
                return String::new();
            }
            let r = &self.radio;
            return match key.as_str() {
                "lte_band" => format!("+QNWPREFCFG: \"lte_band\",{}", shown(&r.lte)),
                "nsa_nr5g_band" => format!("+QNWPREFCFG: \"nsa_nr5g_band\",{}", shown(&r.nsa)),
                "nr5g_band" => format!("+QNWPREFCFG: \"nr5g_band\",{}", shown(&r.sa)),
                "mode_pref" => format!("+QNWPREFCFG: \"mode_pref\",{}", r.mode),
                "nr5g_disable_mode" => format!("+QNWPREFCFG: \"nr5g_disable_mode\",{}", r.disable),
                "policy_band" => format!(
                    "+QNWPREFCFG: \"lte_band\",{}\r\n+QNWPREFCFG: \"nsa_nr5g_band\",{}\r\n+QNWPREFCFG: \"nr5g_band\",{}",
                    self.policy.0, self.policy.1, self.policy.2
                ),
                _ => String::new(),
            };
        }
        if up == "AT+QUIMSLOT?" {
            return format!("+QUIMSLOT: {}", self.sim_slot);
        }
        if let Some(v) = up.strip_prefix("AT+QUIMSLOT=") {
            self.sim_slot = v.trim().parse().unwrap_or(-1);
            return String::new();
        }
        if up == "AT+CGDCONT?" {
            return format!("+CGDCONT: 1,\"{}\",\"{}\",\"0.0.0.0\",0,0", self.cgdcont.0, self.cgdcont.1);
        }
        if let Some(rest) = cmd.strip_prefix("AT+CGDCONT=1,") {
            let f: Vec<String> = rest.split(',').map(|s| s.trim().trim_matches('"').to_string()).collect();
            self.cgdcont = (f.first().cloned().unwrap_or_default(), f.get(1).cloned().unwrap_or_default());
            return String::new();
        }
        if up.starts_with("AT+QNWLOCK=") && up.contains(',') {
            let key = quoted_key(cmd).unwrap_or_default();
            let v = after_key(cmd);
            let slot = if v == "0" { None } else { Some(v) };
            match key.as_str() {
                "common/4g" => self.lock4g = slot,
                "common/5g" => self.lock5g = slot,
                "save_ctrl" => self.save_ctrl = slot,
                _ => {}
            }
            return String::new();
        }
        String::new()
    }
}

fn socketpair() -> Result<(RawFd, RawFd), String> {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

fn write_all(fd: RawFd, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let n = unsafe { libc::write(fd, data[off..].as_ptr() as *const libc::c_void, data.len() - off) };
        if n <= 0 {
            return;
        }
        off += n as usize;
    }
}

fn serve(fd: RawFd, state: Arc<Mutex<FakeState>>) {
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 2048];
    'outer: loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n as usize]);
        while let Some(pos) = acc.iter().position(|&b| b == b'\r' || b == b'\n') {
            let line: Vec<u8> = acc.drain(..=pos).collect();
            let cmd = String::from_utf8_lossy(&line).trim().to_string();
            if cmd.is_empty() {
                continue;
            }
            let ok = |body: String| if body.is_empty() { "\r\nOK\r\n".to_string() } else { format!("\r\n{body}\r\n\r\nOK\r\n") };
            let (reply, delay) = {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                st.log.push(cmd.clone());
                if is_write(&cmd) {
                    st.writes.push(cmd.clone());
                }
                match st.rule_for(&cmd) {
                    Some(Fail::Drop) => (None, 0),
                    Some(Fail::ApplyDrop) => {
                        st.answer(&cmd);
                        (None, 0)
                    }
                    Some(Fail::Error) => (Some("\r\nERROR\r\n".to_string()), 0),
                    Some(Fail::Cme(n)) => (Some(format!("\r\n+CME ERROR: {n}\r\n")), 0),
                    Some(Fail::ApplyError) => {
                        st.answer(&cmd);
                        (Some("\r\nERROR\r\n".to_string()), 0)
                    }
                    Some(Fail::ApplyCme(n)) => {
                        st.answer(&cmd);
                        (Some(format!("\r\n+CME ERROR: {n}\r\n")), 0)
                    }
                    Some(Fail::Delay(ms)) => (Some(ok(st.answer(&cmd))), ms),
                    None => (Some(ok(st.answer(&cmd))), 0),
                }
            };
            if delay > 0 {
                thread::sleep(std::time::Duration::from_millis(delay));
            }
            match reply {
                Some(r) => write_all(fd, r.as_bytes()),
                None => break 'outer,
            }
        }
    }
    unsafe {
        libc::shutdown(fd, libc::SHUT_RDWR);
        libc::close(fd);
    }
}

impl FakeModem {
    pub fn new(radio: Radio) -> Self {
        FakeModem { state: Arc::new(Mutex::new(FakeState::new(radio))) }
    }

    /// An AT client whose device is this fake.
    pub fn client(&self) -> SmdClient {
        let state = Arc::clone(&self.state);
        SmdClient::spawn_with_opener(Box::new(move || {
            let (ours, theirs) = socketpair()?;
            let st = Arc::clone(&state);
            thread::spawn(move || serve(theirs, st));
            Ok(ours)
        }))
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut FakeState) -> R) -> R {
        f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Start a new scenario: radio as given, logs and rules cleared.
    pub fn reset(&self, radio: Radio) {
        self.with(|s| {
            s.radio = radio;
            s.log.clear();
            s.writes.clear();
            s.snapshots.clear();
            s.rules.clear();
        });
    }

    pub fn radio(&self) -> Radio {
        self.with(|s| s.radio.clone())
    }

    pub fn writes(&self) -> Vec<String> {
        self.with(|s| s.writes.clone())
    }

    pub fn snapshots(&self) -> Vec<Radio> {
        self.with(|s| s.snapshots.clone())
    }

    pub fn fail(&self, needle: &str, fail: Fail, times: Option<usize>) {
        self.with(|s| s.rules.push(Rule { needle: needle.into(), fail, times, exact: false }));
    }

    /// Like [`FakeModem::fail`], for exactly this command.
    pub fn fail_exact(&self, cmd: &str, fail: Fail, times: Option<usize>) {
        self.with(|s| s.rules.push(Rule { needle: cmd.into(), fail, times, exact: true }));
    }

    pub fn log(&self) -> Vec<String> {
        self.with(|s| s.log.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smd::Priority;
    use std::time::Duration;

    #[tokio::test]
    async fn fake_modem_reads_writes_fails_and_reopens() {
        let m = FakeModem::new(Radio::new("2:66", "41", "41:71", "AUTO", 0));
        let c = m.client();
        let t = Duration::from_secs(3);
        let r = c.exec("AT+QNWPREFCFG=\"lte_band\"", Priority::Interactive, t).await.unwrap();
        assert!(r.ok && r.body.contains("\"lte_band\",2:66"), "{r:?}");
        assert!(c.exec("AT+QNWPREFCFG=\"nsa_nr5g_band\",0", Priority::Interactive, t).await.unwrap().ok);
        assert_eq!(m.radio().nsa, "");
        m.fail("mode_pref\",", Fail::Cme(50), Some(1));
        let r = c.exec("AT+QNWPREFCFG=\"mode_pref\",LTE", Priority::Interactive, t).await.unwrap();
        assert!(!r.ok, "{r:?}");
        assert_eq!(m.radio().mode, "AUTO", "a refused write changes nothing");
        m.fail("nr5g_disable_mode\",", Fail::Drop, Some(1));
        assert!(c.exec("AT+QNWPREFCFG=\"nr5g_disable_mode\",1", Priority::Interactive, t).await.is_err());
        // the next command reopens the line
        let r = c.exec("AT+QNWPREFCFG=\"nr5g_disable_mode\"", Priority::Interactive, t).await.unwrap();
        assert!(r.body.ends_with(",0"), "{r:?}");
        assert_eq!(
            m.writes(),
            vec![
                "AT+QNWPREFCFG=\"nsa_nr5g_band\",0".to_string(),
                "AT+QNWPREFCFG=\"mode_pref\",LTE".to_string(),
                "AT+QNWPREFCFG=\"nr5g_disable_mode\",1".to_string(),
            ]
        );
        assert_eq!(m.snapshots(), vec![Radio::new("2:66", "", "41:71", "AUTO", 0)]);
        m.reset(Radio::new("2", "", "", "LTE", 0));
        m.fail("QUIMSLOT=", Fail::Error, None);
        let r = c.exec("AT+QUIMSLOT=2", Priority::Interactive, t).await.unwrap();
        assert!(!r.ok && r.raw.contains("ERROR"), "{r:?}");
        assert_eq!(m.with(|s| s.sim_slot), 1);
        assert_eq!(m.writes(), vec!["AT+QUIMSLOT=2".to_string()]);
        // a lost reply: applied, then the line drops
        m.reset(Radio::new("2", "", "", "LTE", 0));
        m.fail_exact("AT+QNWPREFCFG=\"lte_band\",2:66", Fail::ApplyDrop, Some(1));
        assert!(c.exec("AT+QNWPREFCFG=\"lte_band\",2:66", Priority::Interactive, t).await.is_err());
        assert_eq!(m.radio().lte, "2:66", "applied although the reply was lost");
        // exact rules do not match a longer command
        m.fail_exact("AT+QNWPREFCFG=\"lte_band\",2", Fail::Error, None);
        assert!(c.exec("AT+QNWPREFCFG=\"lte_band\",2:4", Priority::Interactive, t).await.unwrap().ok);
        assert!(!c.exec("AT+QNWPREFCFG=\"lte_band\",2", Priority::Interactive, t).await.unwrap().ok);
        // a late answer still lands
        m.fail("AT+QNWPREFCFG=\"mode_pref\",AUTO", Fail::Delay(150), Some(1));
        let t0 = std::time::Instant::now();
        assert!(c.exec("AT+QNWPREFCFG=\"mode_pref\",AUTO", Priority::Interactive, t).await.unwrap().ok);
        assert!(t0.elapsed() >= Duration::from_millis(150));
        assert_eq!(m.radio().mode, "AUTO");
        // apply-then-refuse: applied even though ERROR / +CME ERROR was returned
        m.fail_exact("AT+QNWPREFCFG=\"lte_band\",2:4:66", Fail::ApplyError, Some(1));
        let r = c.exec("AT+QNWPREFCFG=\"lte_band\",2:4:66", Priority::Interactive, t).await.unwrap();
        assert!(!r.ok && r.raw.contains("ERROR"), "{r:?}");
        assert_eq!(m.radio().lte, "2:4:66");
        m.fail_exact("AT+QNWPREFCFG=\"mode_pref\",LTE", Fail::ApplyCme(50), Some(1));
        let r = c.exec("AT+QNWPREFCFG=\"mode_pref\",LTE", Priority::Interactive, t).await.unwrap();
        assert!(!r.ok && r.raw.contains("+CME ERROR: 50"), "{r:?}");
        assert_eq!(m.radio().mode, "LTE");
    }
}

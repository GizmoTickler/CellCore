use std::{
    cmp::Ordering,
    collections::{BinaryHeap, VecDeque},
    ffi::CString,
    os::fd::RawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    thread,
    time::{Duration, Instant},
};

use tokio::sync::{mpsc, oneshot};

pub const DEFAULT_SMD_DEVICE: &str = "/dev/smd11";
pub const FALLBACK_SMD_DEVICE: &str = "/dev/smd7";
/// Consecutive failed `QMRESYNC` cycles before closing & reopening the serial fd (~90s wedged).
pub const MAX_CONSECUTIVE_RESYNC_FAILURES: u32 = 3;
/// Maximum buffered partial bytes in [`Framer::pending`] before dropping and forcing resync.
pub const MAX_FRAMER_PENDING: usize = 64 * 1024;

/// Long commands that have run at least this long yield to Emergency work.
pub const PREEMPT_GRACE: Duration = Duration::from_secs(2);
/// A write that has not completed within this is reported as failed.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// After a timeout, read until the line has been silent this long ...
const DRAIN_QUIET: Duration = Duration::from_millis(200);
/// ... but never longer than this.
const DRAIN_MAX: Duration = Duration::from_millis(1500);
/// A timed-out command's late terminator is expected at most this long.
const STALE_TTL: Duration = Duration::from_secs(200);
/// Resync probe command. It does not exist on the modem (answers ERROR); only
/// its echo matters: the per-probe nonce makes that echo line unique, so
/// on a modem that echoes lines in the order they were written, everything
/// before it is older output. See [`Framer::start_sync`] for the exact guarantee.
const RESYNC_PROBE_PREFIX: &str = "AT+QMRESYNC=";
/// An unanswered probe is re-sent after this long (the modem may have dropped it).
const PROBE_RETRY: Duration = Duration::from_secs(10);
/// How long the probe waits for the `ATE1` that precedes it to be answered.
const PROBE_ECHO_ON_WAIT: Duration = Duration::from_secs(1);
/// An Emergency command written behind an unanswered probe gets its own
/// timeout, clamped to this range, for its final result code; past that the
/// resync gives up on it and re-probes (see [`Framer::sync_overdue`]).
const UNAWAITED_REPLY_MIN: Duration = Duration::from_secs(1);
const UNAWAITED_REPLY_MAX: Duration = Duration::from_secs(5);
/// `ATE0` refused this many times in a row (once per resync) is given up on:
/// the modem keeps echoing and the framer copes.
const ECHO_RESTORE_ATTEMPTS: u32 = 3;

pub type Opener = Box<dyn FnMut() -> Result<RawFd, String> + Send>;

/// Upper bounds (ms) of the AT latency histogram buckets; the implicit last
/// bucket is +Inf.
pub const LATENCY_BUCKETS_MS: [u64; 8] = [25, 50, 100, 250, 500, 1000, 2500, 5000];

/// Lock-free counters kept by the AT actor. Read by the metrics renderer;
/// observing them never touches the modem.
#[derive(Debug, Default)]
pub struct SmdStats {
    /// Requests accepted and not yet answered (waiting or executing).
    pub queued: AtomicU64,
    /// Individual AT commands written to the port.
    pub commands_total: AtomicU64,
    /// Commands that completed with a final ERROR / +CME / +CMS result.
    pub at_errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub preempted: AtomicU64,
    /// Port open/write/read failures.
    pub broken: AtomicU64,
    /// Non-cumulative per-bucket counts for completed commands.
    pub latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    pub latency_count: AtomicU64,
    pub latency_sum_ms: AtomicU64,
    pub last_latency_ms: AtomicU64,
}

impl SmdStats {
    pub fn observe_latency(&self, ms: u64) {
        if let Some(i) = LATENCY_BUCKETS_MS.iter().position(|&b| ms <= b) {
            self.latency_buckets[i].fetch_add(1, AtomicOrdering::Relaxed);
        }
        self.latency_count.fetch_add(1, AtomicOrdering::Relaxed);
        self.latency_sum_ms.fetch_add(ms, AtomicOrdering::Relaxed);
        self.last_latency_ms.store(ms, AtomicOrdering::Relaxed);
    }

    fn dequeued(&self) {
        // Every decrement pairs with the increment in `SmdClient::enqueue`.
        self.queued.fetch_sub(1, AtomicOrdering::Relaxed);
    }
}

/// Prefix of an `exec` error raised before the command reached the device
/// (the port could not be opened, or was already broken): the modem cannot
/// have acted on it. Any other transport error leaves that open.
pub const NOT_SENT: &str = "command not sent: ";

/// Did this `exec` error happen before the command reached the device?
pub fn never_sent(err: &str) -> bool {
    err.starts_with(NOT_SENT)
        || err.ends_with("; command not sent")
        || err.ends_with("before it reached the modem")
        || err.ends_with("during resync")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Emergency = 0,
    Interactive = 1,
    Telemetry = 2,
    Background = 3,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AtResponse {
    pub command: String,
    pub raw: String,
    pub body: String,
    pub ok: bool,
    pub latency_ms: u64,
}

enum WorkKind {
    Single {
        command: String,
        timeout: Duration,
        /// Fixed at enqueue time for callers whose timeout covers the wait in
        /// the queue too (`exec_within`); otherwise counted from dequeue.
        deadline: Option<tokio::time::Instant>,
        reply: oneshot::Sender<Result<AtResponse, String>>,
    },
    Batch {
        commands: Vec<(String, Duration)>,
        reply: oneshot::Sender<Vec<Result<AtResponse, String>>>,
    },
    Pdu {
        cmgs_cmd: String,
        hex_pdu: String,
        timeout: Duration,
        reply: oneshot::Sender<Result<AtResponse, String>>,
    },
}

struct QueuedRequest {
    priority: Priority,
    seq: u64,
    work: WorkKind,
}

impl PartialEq for QueuedRequest {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.seq == other.seq
    }
}

impl Eq for QueuedRequest {}

impl PartialOrd for QueuedRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for max-heap -> lowest Priority enum value pops first, then earliest seq
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

#[derive(Clone)]
pub struct SmdClient {
    tx: mpsc::UnboundedSender<QueuedRequest>,
    seq: Arc<AtomicU64>,
    #[allow(dead_code)]
    healthy: Arc<AtomicBool>,
    stats: Arc<SmdStats>,
}

impl SmdClient {
    pub fn spawn(device: impl Into<String>) -> Self {
        let device = device.into();
        let mut attempt = 0usize;
        Self::spawn_with_opener(Box::new(move || {
            let res = open_device_rotating(&device, attempt);
            attempt = attempt.wrapping_add(1);
            res
        }))
    }

    /// Spawn the AT actor on an arbitrary fd source (tests use a socketpair).
    pub fn spawn_with_opener(opener: Opener) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let healthy = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(SmdStats::default());
        let actor = Actor {
            opener,
            req_rx: rx,
            req_closed: false,
            heap: BinaryHeap::new(),
            port: None,
            framer: Framer::default(),
            healthy: Arc::clone(&healthy),
            stats: Arc::clone(&stats),
            probe_seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                % 1_000_000_000,
            probe_sent: None,
            sync_gen: 0,
            restore_echo_off: false,
            echo_restore_refusals: 0,
            echo_restore_refused_gen: None,
            unresponsive: false,
            consecutive_resync_failures: 0,
            consecutive_timeouts: 0,
        };
        tokio::spawn(actor.run());
        Self {
            tx,
            seq: Arc::new(AtomicU64::new(1)),
            healthy,
            stats,
        }
    }

    #[allow(dead_code)]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(AtomicOrdering::Relaxed)
    }

    pub fn stats(&self) -> &SmdStats {
        &self.stats
    }

    fn enqueue(&self, req: QueuedRequest) -> Result<(), ()> {
        self.stats.queued.fetch_add(1, AtomicOrdering::Relaxed);
        self.tx.send(req).map_err(|_| self.stats.dequeued())
    }

    /// `timeout` bounds the command once it reaches the channel.
    pub async fn exec(
        &self,
        command: impl Into<String>,
        priority: Priority,
        timeout: Duration,
    ) -> Result<AtResponse, String> {
        self.exec_single(command.into(), priority, timeout, None).await
    }

    /// Like [`exec`](Self::exec), but `timeout` is the caller's whole budget,
    /// queue wait included: a request still queued at its deadline fails
    /// without ever being written to the modem.
    pub async fn exec_within(
        &self,
        command: impl Into<String>,
        priority: Priority,
        timeout: Duration,
    ) -> Result<AtResponse, String> {
        let command = command.into();
        let deadline = tokio::time::Instant::now() + timeout;
        // The actor drops the request unsent if it is dequeued after the
        // deadline; the caller does not wait for that to happen.
        match tokio::time::timeout_at(
            deadline + Duration::from_millis(50),
            self.exec_single(command.clone(), priority, timeout, Some(deadline)),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(format!("AT command timed out ({}) waiting for the AT channel", command.trim())),
        }
    }

    async fn exec_single(
        &self,
        command: String,
        priority: Priority,
        timeout: Duration,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<AtResponse, String> {
        self.exec_single_inner(
            command,
            priority,
            timeout,
            deadline,
            crate::dataplane::is_native_mode(),
        )
        .await
    }

    async fn exec_single_inner(
        &self,
        command: String,
        priority: Priority,
        timeout: Duration,
        deadline: Option<tokio::time::Instant>,
        native_mode: bool,
    ) -> Result<AtResponse, String> {
        let command = sanitize_at_command(&command)?;
        if native_mode && is_qcmap_dependent_at_cmd(&command) {
            return Err(qcmap_unavailable_err(&command));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let seq = self.seq.fetch_add(1, AtomicOrdering::Relaxed);
        self.enqueue(QueuedRequest {
            priority,
            seq,
            work: WorkKind::Single {
                command,
                timeout,
                deadline,
                reply: reply_tx,
            },
        })
        .map_err(|_| "SMD actor stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "SMD reply channel dropped".to_string())?
    }

    pub async fn exec_batch(
        &self,
        commands: Vec<(String, Duration)>,
        priority: Priority,
    ) -> Result<Vec<Result<AtResponse, String>>, String> {
        self.exec_batch_inner(commands, priority, crate::dataplane::is_native_mode())
            .await
    }

    async fn exec_batch_inner(
        &self,
        commands: Vec<(String, Duration)>,
        priority: Priority,
        native_mode: bool,
    ) -> Result<Vec<Result<AtResponse, String>>, String> {
        let mut cleaned = Vec::with_capacity(commands.len());
        for (cmd, dur) in commands {
            cleaned.push((sanitize_at_command(&cmd)?, dur));
        }

        if !native_mode {
            let (reply_tx, reply_rx) = oneshot::channel();
            let seq = self.seq.fetch_add(1, AtomicOrdering::Relaxed);
            self.enqueue(QueuedRequest {
                priority,
                seq,
                work: WorkKind::Batch {
                    commands: cleaned,
                    reply: reply_tx,
                },
            })
            .map_err(|_| "SMD actor stopped".to_string())?;
            return reply_rx
                .await
                .map_err(|_| "SMD batch reply channel dropped".to_string());
        }

        let total = cleaned.len();
        let mut out: Vec<Option<Result<AtResponse, String>>> = vec![None; total];
        let mut pass_idx = Vec::with_capacity(total);
        let mut pass_cmds = Vec::with_capacity(total);
        for (idx, (cmd, dur)) in cleaned.into_iter().enumerate() {
            if is_qcmap_dependent_at_cmd(&cmd) {
                out[idx] = Some(Err(qcmap_unavailable_err(&cmd)));
            } else {
                pass_idx.push(idx);
                pass_cmds.push((cmd, dur));
            }
        }

        if !pass_cmds.is_empty() {
            let (reply_tx, reply_rx) = oneshot::channel();
            let seq = self.seq.fetch_add(1, AtomicOrdering::Relaxed);
            self.enqueue(QueuedRequest {
                priority,
                seq,
                work: WorkKind::Batch {
                    commands: pass_cmds,
                    reply: reply_tx,
                },
            })
            .map_err(|_| "SMD actor stopped".to_string())?;
            let replies = reply_rx
                .await
                .map_err(|_| "SMD batch reply channel dropped".to_string())?;
            for (idx, res) in pass_idx.into_iter().zip(replies) {
                out[idx] = Some(res);
            }
        }

        Ok(out
            .into_iter()
            .map(|slot| slot.unwrap_or_else(|| Err("SMD batch reply truncated".into())))
            .collect())
    }

    pub async fn exec_pdu(
        &self,
        cmgs_cmd: impl Into<String>,
        hex_pdu: impl Into<String>,
        priority: Priority,
        timeout: Duration,
    ) -> Result<AtResponse, String> {
        let cmgs_cmd = sanitize_at_command(&cmgs_cmd.into())?;
        let hex_pdu = hex_pdu.into().trim().to_string();
        if hex_pdu.is_empty() || !hex_pdu.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid SMS PDU hex payload".into());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let seq = self.seq.fetch_add(1, AtomicOrdering::Relaxed);
        self
            .enqueue(QueuedRequest {
                priority,
                seq,
                work: WorkKind::Pdu {
                    cmgs_cmd,
                    hex_pdu,
                    timeout,
                    reply: reply_tx,
                },
            })
            .map_err(|_| "SMD actor stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "SMD PDU reply channel dropped".to_string())?
    }
}

pub(crate) fn is_qcmap_dependent_at_cmd(cmd: &str) -> bool {
    const PREFIXES: &[&str] = &["+QMAP", "+QMAPWAC", "+QDMZ", "+QIP6CFG"];
    let bytes = cmd.as_bytes();
    let mut in_quotes = false;
    let mut start = 0usize;
    for i in 0..=bytes.len() {
        let at_end = i == bytes.len();
        if !at_end && bytes[i] == b'"' {
            in_quotes = !in_quotes;
            continue;
        }
        if at_end || (!in_quotes && bytes[i] == b';') {
            let seg = cmd[start..i].trim();
            start = i + 1;
            if seg.is_empty() {
                continue;
            }
            let body = if seg.len() >= 2 && seg[..2].eq_ignore_ascii_case("AT") {
                seg[2..].trim_start()
            } else {
                seg
            };
            for &pfx in PREFIXES {
                if body.len() >= pfx.len() && body[..pfx.len()].eq_ignore_ascii_case(pfx) {
                    match body.as_bytes().get(pfx.len()) {
                        None | Some(b'=') | Some(b'?') | Some(b' ') | Some(b'\t') => return true,
                        _ => {}
                    }
                }
            }
        }
    }
    false
}

fn qcmap_unavailable_err(cmd: &str) -> String {
    format!("{cmd} unavailable while QCMAP is stopped in Native mode")
}

pub fn sanitize_at_command(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 {
        return Err("Invalid AT command length".into());
    }
    if trimmed
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b == 0x1a)
    {
        return Err("Invalid control character in AT command".into());
    }
    Ok(trimmed.to_string())
}


// ---------------------------------------------------------------------------
// Response framing / correlation (pure, unit-tested)
// ---------------------------------------------------------------------------

pub fn is_final_result_line(t: &str) -> Option<bool> {
    if t == "OK" {
        return Some(true);
    }
    if t == "ERROR" || t.starts_with("+CME ERROR:") || t.starts_with("+CMS ERROR:") {
        return Some(false);
    }
    None
}

struct Current {
    command: String,
    capturing: bool,
    saw_echo: bool,
    lines: Vec<String>,
    /// For the PDU body phase: never wait for an echo.
    no_echo_expect: bool,
}

/// Splits the byte stream into lines and attributes them to the command in
/// flight. Replies that belong to commands which already timed out
/// ("stale" commands) are recognised and discarded:
///
/// * if the channel echoes commands, the echo of the current command marks
///   the start of its response and everything before it is stale;
/// * otherwise one final result code is discarded per outstanding stale
///   command (each entry expires after `STALE_TTL`).
///
/// Counting final codes cannot tell a reply that will never come (dropped,
/// stuck, garbled) from one that is merely late. So before the AT actor
/// waits for a command's reply it brings the line back in step with a probe
/// ([`Framer::start_sync`]) whose echo is unique. The one exception is an
/// Emergency command whose resync did not finish in time: it is written
/// anyway, without waiting, and the framer is told a reply is owed
/// ([`Framer::expect_unawaited_reply`]).
#[derive(Default)]
pub struct Framer {
    pending: Vec<u8>,
    pending_pos: usize,
    overflowed: bool,
    stale: VecDeque<Instant>,
    echo: Option<bool>,
    current: Option<Current>,
    /// The resync in progress, if any.
    sync: Option<SyncProbe>,
    /// Final result codes seen on the line (any owner).
    finals_seen: u64,
}

/// Where a resync has found the end of the older output.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fence {
    /// Not yet: every line is discarded.
    None,
    /// The probe's own echo.
    Probe,
    /// The echo of `behind[i]`, read before any echo of the probe (taken to
    /// mean the probe line was lost or garbled on the way to the modem).
    Behind(usize),
}

struct SyncProbe {
    /// Upper-cased probe command.
    token: String,
    fence: Fence,
    /// Final result codes read since the fence.
    finals_after_fence: u32,
    /// Commands written behind the probe without waiting
    /// ([`Framer::expect_unawaited_reply`]), in write order.
    behind: Vec<Unawaited>,
}

struct Unawaited {
    /// Upper-cased command, as the modem echoes it.
    command: String,
    /// Its final result code is not waited for past this.
    reply_by: Instant,
}

impl SyncProbe {
    /// Final result codes the fence obliges the sync to read before it ends:
    /// one per line written at or after the fence.
    fn finals_owed(&self) -> u32 {
        let n = match self.fence {
            Fence::None => return u32::MAX,
            Fence::Probe => 1 + self.behind.len(),
            Fence::Behind(i) => self.behind.len() - i,
        };
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// When the sync is given up on because a command written behind the
    /// probe did not answer in time (the latest `reply_by`), if any was.
    fn give_up_at(&self) -> Option<Instant> {
        self.behind.iter().map(|b| b.reply_by).max()
    }
}

impl Framer {
    pub fn stale_count(&self) -> usize {
        self.stale.len()
    }

    pub fn prune_stale(&mut self, now: Instant) {
        self.stale.retain(|exp| *exp > now);
    }

    /// True when no resync is in progress and no abandoned command is still
    /// counted as owing a reply. Only then is the next reply attributed to
    /// the next command. (An abandoned command stops being counted when its
    /// `STALE_TTL` expires, when a reply is credited to it, or when a resync
    /// completes; see [`Framer::start_sync`] for what a resync guarantees.)
    pub fn in_sync(&self) -> bool {
        !self.overflowed && self.sync.is_none() && self.stale.is_empty()
    }

    pub fn syncing(&self) -> bool {
        self.sync.is_some()
    }

    /// The resync in progress waits for the reply of a command written behind
    /// its probe, and that command's `reply_by` has passed: something on the
    /// line was lost (that reply, the probe's, or the probe line itself) and
    /// waiting longer cannot finish the sync. The caller starts a fresh probe.
    pub fn sync_overdue(&self, now: Instant) -> bool {
        self.sync.as_ref().and_then(SyncProbe::give_up_at).is_some_and(|t| t <= now)
    }

    /// When [`Framer::sync_overdue`] becomes true, if it can.
    pub fn sync_give_up_at(&self) -> Option<Instant> {
        self.sync.as_ref().and_then(SyncProbe::give_up_at)
    }

    pub fn echo_state(&self) -> Option<bool> {
        self.echo
    }

    pub fn finals_seen(&self) -> u64 {
        self.finals_seen
    }

    /// Start a resync on `probe` (a command carrying a unique nonce, sent with
    /// echo on). Every line is discarded until the probe's echo; after it the
    /// sync ends at the N-th final result code, N being one for the probe plus
    /// one per command written behind it ([`Framer::expect_unawaited_reply`]).
    /// The framer is then in sync with echo on.
    ///
    /// What this guarantees, assuming the modem reads the lines in the order
    /// they were written and echoes each line as it reads it: no output of a
    /// command written before the probe is credited to a later command,
    /// unless that output arrives after the probe's echo (only a modem that
    /// holds back a final result code past the next line's echo does that).
    /// After the echo, final codes are counted, not matched: if each owed
    /// line answers exactly once, in any order, nothing owed is left over. A
    /// line that answers twice ends the sync early and its extra final is
    /// left over. A line that does not answer stalls the sync until the
    /// caller gives up on it (an unawaited command's `reply_by`, see
    /// [`Framer::sync_overdue`]; `PROBE_RETRY` for the probe) and starts a
    /// fresh probe; a final code that then arrives after the fresh probe's
    /// echo is miscounted.
    pub fn start_sync(&mut self, probe: &str) {
        self.current = None;
        self.overflowed = false;
        self.sync = Some(SyncProbe {
            token: probe.trim().to_ascii_uppercase(),
            fence: Fence::None,
            finals_after_fence: 0,
            behind: Vec::new(),
        });
    }

    /// `command` was written at `now` without waiting for its reply (the
    /// Emergency delivery on a line that could not be resynchronised).
    ///
    /// * While a probe is outstanding the command was written behind it: the
    ///   sync also counts the command's final code (so a reply order of
    ///   probe-then-command and command-then-probe both end the sync after
    ///   the second final), but only until `now + reply_wait`; after that the
    ///   sync is overdue and the caller re-probes instead of waiting for
    ///   `PROBE_RETRY`. If this command's echo arrives before any echo of
    ///   the probe, the probe line is taken as lost (echo is in write order):
    ///   the command's echo becomes the fence and only its final (and those
    ///   of later unawaited commands) are owed.
    /// * Otherwise it is accounted like an abandoned command (`STALE_TTL`),
    ///   which forces a resync before the next command is written.
    pub fn expect_unawaited_reply(&mut self, command: &str, now: Instant, reply_wait: Duration) {
        match self.sync.as_mut() {
            Some(sync) => sync.behind.push(Unawaited {
                command: command.trim().to_ascii_uppercase(),
                reply_by: now + reply_wait,
            }),
            None => self.stale.push_back(now + STALE_TTL),
        }
    }

    pub fn begin(&mut self, command: &str) {
        self.current = Some(Current {
            command: command.trim().to_string(),
            capturing: false,
            saw_echo: false,
            lines: Vec::new(),
            no_echo_expect: false,
        });
    }

    fn begin_pdu_body(&mut self, hex: &str) {
        self.begin(hex);
        if let Some(c) = self.current.as_mut() {
            c.no_echo_expect = true;
        }
    }

    /// Drop any buffered partial line (idle URC noise) before a new command.
    pub fn clear_partial(&mut self) {
        self.pending.clear();
        self.pending_pos = 0;
    }

    fn compact_pending(&mut self) {
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        } else if self.pending_pos >= 4096 {
            self.pending.drain(..self.pending_pos);
            self.pending_pos = 0;
        }
    }

    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.len().saturating_sub(self.pending_pos)
    }

    /// The current command will not be waited for any longer. Its final
    /// result code may still arrive and must not be credited to the next
    /// command.
    pub fn abandon(&mut self, expiry: Instant) {
        if let Some(cur) = self.current.take() {
            self.stale.push_back(expiry);
            if self.echo == Some(true) && !cur.saw_echo {
                // The echo assumption may be wrong (e.g. ATE0 issued
                // elsewhere); fall back to terminator counting.
                self.echo = None;
            }
        }
    }

    /// Feed bytes; returns `Some((ok, raw))` once the current command's
    /// response is complete. Caps unread buffer at [`MAX_FRAMER_PENDING`]
    /// (dropping buffered noise and forcing a resync on overflow) and uses a
    /// read cursor for O(N) scanning.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<(bool, String)> {
        if self.pending_pos > 0 && self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        let unread = self.pending.len().saturating_sub(self.pending_pos);
        if unread.saturating_add(bytes.len()) > MAX_FRAMER_PENDING {
            self.pending.clear();
            self.pending_pos = 0;
            self.overflowed = true;
            return None;
        }
        self.pending.extend_from_slice(bytes);
        while let Some(rel) = self.pending[self.pending_pos..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
        {
            let line_end = self.pending_pos + rel;
            let term = self.pending[line_end];
            let line = String::from_utf8_lossy(&self.pending[self.pending_pos..line_end]).into_owned();
            self.pending_pos = line_end + 1;
            if term == b'\r' && self.pending.get(self.pending_pos) == Some(&b'\n') {
                self.pending_pos += 1;
            }
            if let Some(done) = self.process_line(&line) {
                self.compact_pending();
                return Some(done);
            }
        }
        self.compact_pending();
        None
    }

    /// True when the unterminated tail of the buffer is an SMS `>` prompt.
    fn take_prompt(&mut self) -> bool {
        let tail = String::from_utf8_lossy(&self.pending[self.pending_pos..]).to_string();
        if tail.trim_start().starts_with('>') {
            self.pending.clear();
            self.pending_pos = 0;
            return true;
        }
        false
    }

    fn process_line(&mut self, line: &str) -> Option<(bool, String)> {
        let t = line.trim();
        if t.is_empty() {
            return None;
        }
        let final_code = is_final_result_line(t);
        if final_code.is_some() {
            self.finals_seen += 1;
        }
        if let Some(sync) = self.sync.as_mut() {
            // Suffix matches: a garbled partial line may precede an echo.
            let upper = t.to_ascii_uppercase();
            if upper.ends_with(&sync.token) {
                // The probe's echo is the authoritative fence (unique nonce).
                sync.fence = Fence::Probe;
                sync.finals_after_fence = 0;
                return None;
            }
            if sync.fence == Fence::None {
                // The echo of a command written behind the probe, read before
                // the probe's echo: on a modem that echoes lines in write
                // order, the probe line did not reach it intact (lost or
                // garbled), so no final code is counted for it. (A late echo of
                // an older identical command would be taken for this one.)
                if let Some(i) = sync.behind.iter().position(|b| upper.ends_with(&b.command)) {
                    sync.fence = Fence::Behind(i);
                    sync.finals_after_fence = 0;
                }
                return None;
            }
            if final_code.is_some() {
                sync.finals_after_fence += 1;
                if sync.finals_after_fence >= sync.finals_owed() {
                    self.sync = None;
                    self.stale.clear();
                    self.echo = Some(true);
                }
            }
            return None;
        }
        let expect_echo = self.echo == Some(true);
        let Some(cur) = self.current.as_mut() else {
            // Nothing in flight: late output of an abandoned command or URC.
            if final_code.is_some() {
                self.stale.pop_front();
            }
            return None;
        };
        if !cur.no_echo_expect && t.eq_ignore_ascii_case(&cur.command) {
            // Our own echo: everything before it belongs to older commands
            // (echo is in write order; a late final code is not).
            cur.capturing = true;
            cur.saw_echo = true;
            cur.lines = vec![line.to_string()];
            self.stale.clear();
            return None;
        }
        if !cur.capturing {
            let waiting_for_echo = expect_echo && !cur.no_echo_expect;
            match final_code {
                Some(_) if !self.stale.is_empty() => {
                    self.stale.pop_front();
                    return None;
                }
                Some(_) if waiting_for_echo => return None,
                Some(_) => {}
                None if !self.stale.is_empty() || waiting_for_echo => return None,
                None => {}
            }
            cur.capturing = true;
        }
        cur.lines.push(line.to_string());
        let ok = final_code?;
        let cur = self.current.take()?;
        if !cur.no_echo_expect {
            self.echo = if cur.command.to_ascii_uppercase().starts_with("ATE") {
                None
            } else {
                Some(cur.saw_echo)
            };
        }
        let mut raw = cur.lines.join("\r\n");
        raw.push_str("\r\n");
        Some((ok, raw))
    }
}

#[cfg(test)]
pub fn check_at_terminator(buf: &[u8]) -> Option<(bool, String)> {
    let text = String::from_utf8_lossy(buf).to_string();
    let norm = text.replace('\r', "\n");
    if !norm.ends_with('\n') {
        return None;
    }
    for line in norm.lines().rev() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        return is_final_result_line(t).map(|ok| (ok, text));
    }
    None
}

fn is_unsolicited_urc_for(command: &str, trimmed_line: &str) -> bool {
    const ALWAYS_URC_PREFIXES: &[&str] = &[
        "+QIND:", "+CMTI:", "+CMT:", "+CBM:", "+CDS:", "+CRING:",
    ];
    const ALWAYS_URC_EXACT: &[&str] = &[
        "RING", "RDY", "APP RDY", "SMS DONE", "PB DONE", "CALL READY",
    ];
    let line_up = trimmed_line.to_ascii_uppercase();
    if ALWAYS_URC_EXACT.iter().any(|u| line_up == *u)
        || ALWAYS_URC_PREFIXES.iter().any(|p| line_up.starts_with(p))
    {
        return true;
    }
    const GATED_URCS: &[(&str, &str)] = &[
        ("+CREG:", "+CREG"),
        ("+CGREG:", "+CGREG"),
        ("+CEREG:", "+CEREG"),
        ("+C5GREG:", "+C5GREG"),
        ("+QNWINFO:", "+QNWINFO"),
        ("+QSIMSTAT:", "+QSIMSTAT"),
        ("+CPIN:", "+CPIN"),
        ("+QUIMSLOT:", "+QUIMSLOT"),
        ("+CFUN:", "+CFUN"),
    ];
    let cmd_up = command.to_ascii_uppercase();
    GATED_URCS
        .iter()
        .any(|(prefix, tag)| line_up.starts_with(prefix) && !cmd_up.contains(tag))
}

pub fn clean_at_body(command: &str, raw: &str) -> String {
    let cmd_trim = command.trim();
    let norm = raw.replace('\r', "");
    let mut lines: Vec<&str> = Vec::new();
    let mut skipped_echo = false;
    for line in norm.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if !skipped_echo && t.eq_ignore_ascii_case(cmd_trim) {
            skipped_echo = true;
            continue;
        }
        if t == "OK" {
            continue;
        }
        if is_unsolicited_urc_for(cmd_trim, t) {
            continue;
        }
        lines.push(line.trim_end());
    }
    lines.join("\n")
}

fn make_response(command: &str, ok: bool, raw: String, started: Instant) -> AtResponse {
    let body = clean_at_body(command, &raw);
    AtResponse {
        command: command.to_string(),
        raw,
        body,
        ok,
        latency_ms: started.elapsed().as_millis() as u64,
    }
}

// ---------------------------------------------------------------------------
// Port: one long-lived reader thread + one writer thread per open fd
// ---------------------------------------------------------------------------

pub fn open_device_fd(device: &str) -> Result<RawFd, String> {
    let c_path = CString::new(device).map_err(|e| format!("Invalid device path: {e}"))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("Failed to open {device}: {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Return ordered SMD device candidates for `attempt`, alternating between
/// `/dev/smd11` and `/dev/smd7` across reopens so a wedged SMD channel fails
/// over to the peer port instead of retrying the same wedged node forever.
pub(crate) fn smd_device_candidates(primary: &str, attempt: usize) -> Vec<String> {
    let default_mapped = crate::paths::p(DEFAULT_SMD_DEVICE);
    let fallback_mapped = crate::paths::p(FALLBACK_SMD_DEVICE);
    let alternate = if primary == fallback_mapped || primary == FALLBACK_SMD_DEVICE {
        default_mapped
    } else {
        fallback_mapped
    };
    if alternate == primary {
        return vec![primary.to_string()];
    }
    if attempt.is_multiple_of(2) {
        vec![primary.to_string(), alternate]
    } else {
        vec![alternate, primary.to_string()]
    }
}

/// Open an SMD AT port using rotating failover candidates (`/dev/smd11` ↔ `/dev/smd7`).
pub fn open_device_rotating(primary: &str, attempt: usize) -> Result<RawFd, String> {
    let candidates = smd_device_candidates(primary, attempt);
    let mut last_err = None;
    for (idx, dev) in candidates.iter().enumerate() {
        match open_device_fd(dev) {
            Ok(fd) => {
                if idx > 0 || (attempt > 0 && dev != primary) {
                    eprintln!("cellcored: opened SMD port {dev} (attempt {attempt}, primary {primary})");
                }
                return Ok(fd);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| format!("Failed to open {primary}")))
}

/// Open the primary SMD AT port, falling back to `/dev/smd7` on real hardware if the
/// primary node (typically `/dev/smd11`) cannot be opened.
#[allow(dead_code)]
pub fn open_device_with_fallback(device: &str) -> Result<RawFd, String> {
    open_device_rotating(device, 0)
}

fn write_all_fd(fd: RawFd, data: &[u8]) -> Result<(), String> {
    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if n > 0 {
            written += n as usize;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("SMD write error: {err}"));
        }
    }
    Ok(())
}

/// Wait up to `ms` for `fd` to become readable. `None` = poll unsupported.
fn poll_readable(fd: RawFd, ms: i32) -> Option<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        return Some(rc > 0);
    }
}

enum RxEvent {
    Bytes(Vec<u8>),
    Broken(String),
}

struct WriteJob {
    data: Vec<u8>,
    done: oneshot::Sender<Result<(), String>>,
}

struct Port {
    writer: std::sync::mpsc::Sender<WriteJob>,
    rx: mpsc::UnboundedReceiver<RxEvent>,
    stop: Arc<AtomicBool>,
}

impl Port {
    /// Takes ownership of `fd`. The reader thread owns a dup of it and is the
    /// only code that ever closes that dup, so no fd is closed underneath a
    /// blocked read; the writer thread owns `fd` itself.
    fn start(fd: RawFd) -> Result<Port, String> {
        let read_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if read_fd < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("Failed to dup SMD fd: {err}"));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::unbounded_channel();
        let reader_stop = Arc::clone(&stop);
        let spawned = thread::Builder::new().name("smd-rx".into()).spawn(move || {
            let mut buf = [0u8; 4096];
            let mut use_poll = true;
            loop {
                if reader_stop.load(AtomicOrdering::Relaxed) {
                    break;
                }
                if use_poll {
                    match poll_readable(read_fd, 250) {
                        Some(false) => continue,
                        Some(true) => {}
                        None => use_poll = false,
                    }
                    if reader_stop.load(AtomicOrdering::Relaxed) {
                        break;
                    }
                }
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    if tx.send(RxEvent::Bytes(buf[..n as usize].to_vec())).is_err() {
                        break;
                    }
                } else if n == 0 {
                    let _ = tx.send(RxEvent::Broken("EOF on SMD device".into()));
                    break;
                } else {
                    let err = std::io::Error::last_os_error();
                    match err.kind() {
                        std::io::ErrorKind::Interrupted => continue,
                        std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        _ => {
                            let _ = tx.send(RxEvent::Broken(format!("Read error: {err}")));
                            break;
                        }
                    }
                }
            }
            unsafe { libc::close(read_fd) };
        });
        if let Err(e) = spawned {
            unsafe {
                libc::close(read_fd);
                libc::close(fd);
            }
            return Err(format!("Failed to spawn smd-rx thread: {e}"));
        }

        let (wtx, wrx) = std::sync::mpsc::channel::<WriteJob>();
        let spawned = thread::Builder::new().name("smd-tx".into()).spawn(move || {
            while let Ok(job) = wrx.recv() {
                let _ = job.done.send(write_all_fd(fd, &job.data));
            }
            unsafe { libc::close(fd) };
        });
        if let Err(e) = spawned {
            stop.store(true, AtomicOrdering::Relaxed);
            unsafe { libc::close(fd) };
            return Err(format!("Failed to spawn smd-tx thread: {e}"));
        }
        Ok(Port { writer: wtx, rx, stop })
    }

    /// Blocking write happens on the dedicated smd-tx thread, never on a
    /// tokio worker.
    async fn write(&self, data: Vec<u8>) -> Result<(), String> {
        let (done, wait) = oneshot::channel();
        self.writer
            .send(WriteJob { data, done })
            .map_err(|_| "SMD write error: writer stopped".to_string())?;
        match tokio::time::timeout(WRITE_TIMEOUT, wait).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err("SMD write error: writer stopped".into()),
            Err(_) => Err("SMD write timed out".into()),
        }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // The reader notices within one poll interval and closes its own fd.
        self.stop.store(true, AtomicOrdering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

struct Actor {
    opener: Opener,
    req_rx: mpsc::UnboundedReceiver<QueuedRequest>,
    req_closed: bool,
    heap: BinaryHeap<QueuedRequest>,
    port: Option<Port>,
    framer: Framer,
    healthy: Arc<AtomicBool>,
    stats: Arc<SmdStats>,
    /// Nonce source for resync probes.
    probe_seq: u64,
    /// When the outstanding resync probe was written.
    probe_sent: Option<Instant>,
    /// Counts the times the line came back in step: a probe answered (in a
    /// command's resync or while idle) or the port (re)opened.
    sync_gen: u64,
    /// Echo was off before a probe turned it on: switch it off again once in
    /// sync. Kept across failed resyncs and port reopens (echo is modem
    /// state, not fd state). Cleared when `ATE0` is answered `OK`, or when it
    /// has been refused `ECHO_RESTORE_ATTEMPTS` times.
    restore_echo_off: bool,
    /// `ATE0` refusals in a row while `restore_echo_off` is set.
    echo_restore_refusals: u32,
    /// `sync_gen` at the last refusal: `ATE0` is retried after the next
    /// resync, not before every command.
    echo_restore_refused_gen: Option<u64>,
    /// The outstanding resync probe went unanswered for a whole command
    /// budget. Set only by a resync that timed out; cleared when a fresh
    /// probe is sent, when the line is found in sync (in a resync or by
    /// `absorb_idle`), when a command is answered on an in-sync line, and when
    /// the port breaks or is reopened.
    unresponsive: bool,
    /// Consecutive resync timeouts on the current open fd. At `>= MAX_CONSECUTIVE_RESYNC_FAILURES`,
    /// the fd is treated as wedged and reopened via `mark_broken`.
    consecutive_resync_failures: u32,
    /// Consecutive AT command timeouts in `send_and_wait` on the current open fd.
    consecutive_timeouts: u32,
}

enum WaitOutcome {
    Done(bool, String),
    Prompt,
    TimedOut,
    Preempted,
    Broken(String),
}

impl Actor {
    async fn run(mut self) {
        loop {
            if self.heap.is_empty() {
                if self.req_closed {
                    break;
                }
                match self.req_rx.recv().await {
                    Some(item) => self.heap.push(item),
                    None => break,
                }
            }
            self.pull_pending();
            let Some(req) = self.heap.pop() else {
                continue;
            };
            self.execute(req, true).await;
        }
    }

    fn pull_pending(&mut self) {
        while let Ok(more) = self.req_rx.try_recv() {
            self.heap.push(more);
        }
    }

    fn has_preemptor(&self, current: Priority) -> bool {
        current > Priority::Emergency
            && self.heap.peek().is_some_and(|r| r.priority == Priority::Emergency)
    }

    fn has_batch_preemptor(&self, current: Priority) -> bool {
        self.heap.peek().is_some_and(|r| r.priority < current)
    }

    async fn execute(&mut self, req: QueuedRequest, allow_yield: bool) {
        self.execute_inner(req, allow_yield).await;
        self.stats.dequeued();
    }

    async fn execute_inner(&mut self, req: QueuedRequest, allow_yield: bool) {
        let prio = req.priority;
        match req.work {
            WorkKind::Single {
                command,
                timeout,
                deadline,
                reply,
            } => {
                let deadline = deadline.unwrap_or_else(|| tokio::time::Instant::now() + timeout);
                // Emergency commands (Route10 actions) are delivered even when
                // the channel cannot be resynchronised in time, as before. The
                // final code of such a command is waited for (by the resync
                // that follows) for its own timeout, clamped.
                let must_send = (prio == Priority::Emergency)
                    .then(|| timeout.clamp(UNAWAITED_REPLY_MIN, UNAWAITED_REPLY_MAX));
                let res = self.exec_one(&command, deadline, prio, allow_yield, must_send).await;
                let _ = reply.send(res);
            }
            WorkKind::Batch { commands, reply } => {
                let mut results = Vec::with_capacity(commands.len());
                let mut failed = false;
                for (cmd, timeout) in commands {
                    if allow_yield {
                        // Chunking: higher-priority (Emergency / Interactive) work runs between batch items.
                        self.run_batch_preemptors(prio).await;
                    }
                    if failed && self.still_unresponsive() {
                        // The modem did not answer a resync probe: do not spend
                        // every remaining item's timeout on a dead line (the
                        // queue behind this batch would wait for all of them).
                        results.push(Err(format!("AT command skipped ({cmd}): AT channel unresponsive")));
                        continue;
                    }
                    let deadline = tokio::time::Instant::now() + timeout;
                    let res = self.exec_one(&cmd, deadline, prio, allow_yield, None).await;
                    failed |= res.is_err();
                    results.push(res);
                }
                let _ = reply.send(results);
            }
            WorkKind::Pdu {
                cmgs_cmd,
                hex_pdu,
                timeout,
                reply,
            } => {
                let res = self.exec_pdu(&cmgs_cmd, &hex_pdu, timeout).await;
                self.record(&res);
                let _ = reply.send(res);
            }
        }
    }

    async fn run_batch_preemptors(&mut self, current: Priority) {
        self.pull_pending();
        while self.has_batch_preemptor(current) {
            let Some(r) = self.heap.pop() else { break };
            Box::pin(self.execute(r, false)).await;
            self.pull_pending();
        }
    }

    async fn ensure_port(&mut self) -> Result<(), String> {
        if self.port.is_some() {
            return Ok(());
        }
        let res = (self.opener)().and_then(Port::start);
        match res {
            Ok(p) => {
                self.port = Some(p);
                // A fresh fd: nothing is owed on it and no probe is outstanding.
                // `restore_echo_off` is kept: a previous probe may have left the
                // modem's echo on; the restore is attempted before the next
                // command (see `restore_echo`).
                self.framer = Framer::default();
                self.probe_sent = None;
                self.unresponsive = false;
                self.consecutive_resync_failures = 0;
                self.consecutive_timeouts = 0;
                // A fresh start: a pending echo restore is tried again.
                self.sync_gen += 1;
                self.healthy.store(true, AtomicOrdering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.healthy.store(false, AtomicOrdering::Relaxed);
                tokio::time::sleep(Duration::from_millis(250)).await;
                Err(e)
            }
        }
    }

    /// Consume whatever is already buffered (idle URCs, late replies of
    /// abandoned commands) without blocking.
    fn absorb_idle(&mut self) -> Result<(), String> {
        let Some(port) = self.port.as_mut() else {
            return Ok(());
        };
        loop {
            match port.rx.try_recv() {
                Ok(RxEvent::Bytes(b)) => {
                    let _ = self.framer.feed(&b);
                }
                Ok(RxEvent::Broken(e)) => return Err(e),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Err("RX channel closed".into()),
            }
        }
        if self.framer.syncing() {
            // (A partial line may be the start of the probe echo: keep it.)
        } else {
            self.framer.clear_partial();
            // A probe answered while nothing was in flight is as good as one
            // answered while a command waited for it.
            self.note_in_sync();
        }
        Ok(())
    }

    /// If the line is in step, no probe is outstanding, so the channel is
    /// not unresponsive whatever the last probe did.
    fn note_in_sync(&mut self) {
        if self.framer.in_sync() {
            let probe_answered = self.probe_sent.take().is_some();
            if probe_answered {
                self.sync_gen += 1;
            }
            if probe_answered || self.unresponsive {
                self.healthy.store(true, AtomicOrdering::Relaxed);
            }
            self.unresponsive = false;
            self.consecutive_resync_failures = 0;
        }
    }

    /// Whether the channel is still unresponsive, judged after consuming what
    /// the modem has sent meanwhile (a late probe answer clears it).
    fn still_unresponsive(&mut self) -> bool {
        if self.unresponsive
            && let Err(e) = self.absorb_idle()
        {
            // The port is gone; the next item reopens it.
            let _ = self.mark_broken(&e);
        }
        self.unresponsive
    }

    fn mark_broken(&mut self, err: &str) -> String {
        // The reader has exited (EOF / read error), so dropping the port
        // cannot close an fd under a blocked read. Reopen on next request.
        self.port = None;
        // Its outstanding probe died with it: unresponsiveness is re-judged on
        // the reopened port.
        self.probe_sent = None;
        self.unresponsive = false;
        self.consecutive_resync_failures = 0;
        self.consecutive_timeouts = 0;
        self.healthy.store(false, AtomicOrdering::Relaxed);
        format!("Broken SMD stream: {err}")
    }

    async fn wait_response(
        &mut self,
        deadline: tokio::time::Instant,
        preempt: Option<(Priority, Instant)>,
        want_prompt: bool,
    ) -> WaitOutcome {
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return WaitOutcome::TimedOut;
            }
            let slice = (deadline - now).min(Duration::from_millis(250));
            let Some(port) = self.port.as_mut() else {
                return WaitOutcome::Broken("port closed".into());
            };
            tokio::select! {
                biased;
                ev = port.rx.recv() => match ev {
                    Some(RxEvent::Bytes(b)) => {
                        if let Some((ok, raw)) = self.framer.feed(&b) {
                            return WaitOutcome::Done(ok, raw);
                        }
                        if want_prompt && self.framer.take_prompt() {
                            return WaitOutcome::Prompt;
                        }
                    }
                    Some(RxEvent::Broken(e)) => return WaitOutcome::Broken(e),
                    None => return WaitOutcome::Broken("RX channel closed".into()),
                },
                req = self.req_rx.recv(), if !self.req_closed => match req {
                    Some(r) => self.heap.push(r),
                    None => self.req_closed = true,
                },
                _ = tokio::time::sleep(slice) => {}
            }
            if let Some((prio, started)) = preempt
                && started.elapsed() >= PREEMPT_GRACE
            {
                self.pull_pending();
                if self.has_preemptor(prio) {
                    return WaitOutcome::Preempted;
                }
            }
        }
    }

    /// After giving up on a command: keep reading until the line has been
    /// quiet for `DRAIN_QUIET` (at most `DRAIN_MAX`), so a late reply that
    /// arrives meanwhile is consumed here. Anything later is handled by the
    /// resync before the next command. The port is NOT reopened.
    async fn drain_until_quiet(&mut self) -> Option<String> {
        let hard = tokio::time::Instant::now() + DRAIN_MAX;
        loop {
            if self.framer.stale_count() == 0 {
                return None;
            }
            let now = tokio::time::Instant::now();
            if now >= hard {
                return None;
            }
            let wait = DRAIN_QUIET.min(hard - now);
            let port = self.port.as_mut()?;
            match tokio::time::timeout(wait, port.rx.recv()).await {
                Ok(Some(RxEvent::Bytes(b))) => {
                    let _ = self.framer.feed(&b);
                }
                Ok(Some(RxEvent::Broken(e))) => return Some(e),
                Ok(None) => return Some("RX channel closed".into()),
                Err(_) => return None, // quiet
            }
        }
    }

    async fn exec_one(
        &mut self,
        command: &str,
        deadline: tokio::time::Instant,
        prio: Priority,
        allow_preempt: bool,
        must_send: Option<Duration>,
    ) -> Result<AtResponse, String> {
        let res = self.exec_one_inner(command, deadline, prio, allow_preempt, must_send).await;
        self.record(&res);
        res
    }

    /// Read until `done(&framer)` holds, the deadline passes, the line breaks
    /// or (with `preempt`) Emergency work is waiting.
    async fn wait_framer(
        &mut self,
        deadline: tokio::time::Instant,
        preempt: Option<(Priority, Instant)>,
        done: impl Fn(&Framer) -> bool,
    ) -> WaitOutcome {
        loop {
            if done(&self.framer) {
                return WaitOutcome::Done(true, String::new());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return WaitOutcome::TimedOut;
            }
            let mut slice = (deadline - now).min(Duration::from_millis(250));
            if let Some(at) = self.framer.sync_give_up_at() {
                // Re-check `done` as soon as the sync can become overdue.
                slice = slice.min(at.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)));
            }
            let Some(port) = self.port.as_mut() else {
                return WaitOutcome::Broken("port closed".into());
            };
            tokio::select! {
                biased;
                ev = port.rx.recv() => match ev {
                    Some(RxEvent::Bytes(b)) => {
                        let _ = self.framer.feed(&b);
                    }
                    Some(RxEvent::Broken(e)) => return WaitOutcome::Broken(e),
                    None => return WaitOutcome::Broken("RX channel closed".into()),
                },
                req = self.req_rx.recv(), if !self.req_closed => match req {
                    Some(r) => self.heap.push(r),
                    None => self.req_closed = true,
                },
                _ = tokio::time::sleep(slice) => {}
            }
            if let Some((prio, started)) = preempt
                && started.elapsed() >= PREEMPT_GRACE
            {
                self.pull_pending();
                if self.has_preemptor(prio) {
                    return WaitOutcome::Preempted;
                }
            }
        }
    }

    async fn write_raw(&mut self, data: Vec<u8>) -> Result<(), String> {
        let res = match self.port.as_ref() {
            Some(p) => p.write(data).await,
            None => Err("SMD write error: port closed".into()),
        };
        if res.is_err() {
            self.healthy.store(false, AtomicOrdering::Relaxed);
        }
        res
    }

    /// Bring the line back in step after a dropped, late, stuck or garbled
    /// reply, within `deadline`.
    ///
    /// The sequence written on the shared SMD port (nothing else is written
    /// while it runs; the actor owns the port):
    ///
    /// 1. `ATE1`, unless echo is already known to be on. The probe only works
    ///    if the modem echoes it. If echo was known to be off,
    ///    `restore_echo_off` is set so that step 4 switches it off again.
    ///    Waited for at most `PROBE_ECHO_ON_WAIT` (its reply is discarded by
    ///    the sync anyway).
    /// 2. `AT+QMRESYNC=<nonce>`, the probe. The modem does not know it and
    ///    answers `ERROR`; only its echo matters: the nonce makes that echo a
    ///    line no earlier command can produce. [`Framer::start_sync`] states
    ///    what reading it (and the final codes owed after it) guarantees. A
    ///    probe still unanswered is reused (not re-sent) for `PROBE_RETRY`,
    ///    unless an Emergency command written behind it is overdue
    ///    ([`Framer::sync_overdue`]): then a fresh probe is sent at once,
    ///    within the same `deadline`. A stuck modem so receives at most one
    ///    probe per `PROBE_RETRY` plus one per Emergency command written
    ///    behind a probe.
    /// 3. Wait for the sync within `deadline`. If it does not complete the
    ///    channel is marked unresponsive and the command is not written
    ///    (except Emergency singles, see `exec_one_inner`). The probe stays
    ///    outstanding: its answer is picked up later, by the next command or
    ///    while the actor is idle (`absorb_idle`), which clears the flag.
    /// 4. On an in-sync line, `ATE0` if a probe turned echo on
    ///    ([`Actor::restore_echo`]). `resync` runs before every command and
    ///    reaches this step whenever the line is in sync, so a pending restore
    ///    is considered after a probe answered in this call, before the next
    ///    command when an earlier resync failed (timeout, preemption) and its
    ///    probe was answered later, and on a reopened port; it is written
    ///    unless `ATE0` was refused since the last resync. `ATE0` is never
    ///    written on a line that is not in sync: its echo/`OK` would then be
    ///    indistinguishable from older output.
    ///
    /// `Err` carries the kind of failure: a `WaitOutcome::TimedOut`,
    /// `Preempted` or `Broken`.
    async fn resync(
        &mut self,
        deadline: tokio::time::Instant,
        preempt: Option<(Priority, Instant)>,
    ) -> Result<(), WaitOutcome> {
        while !self.framer.in_sync() {
            let reuse = self.framer.syncing()
                && self.probe_sent.is_some_and(|t| t.elapsed() < PROBE_RETRY)
                && !self.framer.sync_overdue(Instant::now());
            if !reuse {
                self.probe_seq = self.probe_seq.wrapping_add(1);
                let probe = format!("{RESYNC_PROBE_PREFIX}{}", self.probe_seq);
                let echo = self.framer.echo_state();
                if echo == Some(false) && !self.restore_echo_off {
                    self.restore_echo_off = true;
                    self.echo_restore_refusals = 0;
                    self.echo_restore_refused_gen = None;
                }
                self.framer.start_sync(&probe);
                self.probe_sent = Some(Instant::now());
                // A fresh probe has not gone unanswered yet.
                self.unresponsive = false;
                if echo != Some(true) {
                    // Step 1: echo on, so the probe's echo is seen.
                    if let Err(e) = self.write_raw(b"ATE1\r\n".to_vec()).await {
                        return Err(WaitOutcome::Broken(e));
                    }
                    let seen = self.framer.finals_seen();
                    let until = deadline.min(tokio::time::Instant::now() + PROBE_ECHO_ON_WAIT);
                    match self.wait_framer(until, preempt, |f| f.finals_seen() > seen || !f.syncing()).await {
                        WaitOutcome::Broken(e) => return Err(WaitOutcome::Broken(e)),
                        WaitOutcome::Preempted => return Err(WaitOutcome::Preempted),
                        _ => {}
                    }
                }
                // Step 2: the probe.
                if let Err(e) = self.write_raw(format!("{probe}\r\n").into_bytes()).await {
                    return Err(WaitOutcome::Broken(e));
                }
            }
            // Step 3. Done also when the sync turned overdue: the loop then
            // sends a fresh probe.
            match self
                .wait_framer(deadline, preempt, |f| !f.syncing() || f.sync_overdue(Instant::now()))
                .await
            {
                WaitOutcome::Done(..) => {}
                WaitOutcome::TimedOut => {
                    self.unresponsive = true;
                    self.consecutive_resync_failures = self.consecutive_resync_failures.saturating_add(1);
                    self.healthy.store(false, AtomicOrdering::Relaxed);
                    return Err(WaitOutcome::TimedOut);
                }
                other => return Err(other),
            }
        }
        self.note_in_sync();
        // Step 4.
        self.restore_echo(deadline, preempt).await
    }

    /// Switch echo back off if a resync probe turned it on. Only called on an
    /// in-sync line (see [`Actor::resync`], step 4).
    ///
    /// `ATE0` answered `OK` ends the restore. Refused, it is retried once
    /// after each later resync (not before every command), up to
    /// `ECHO_RESTORE_ATTEMPTS` refusals in a row; the modem then keeps echo on
    /// and the framer copes. Not answered (timeout, preemption, broken port),
    /// it stays pending and is retried the next time the line is in sync.
    async fn restore_echo(
        &mut self,
        deadline: tokio::time::Instant,
        preempt: Option<(Priority, Instant)>,
    ) -> Result<(), WaitOutcome> {
        if !self.restore_echo_off || self.echo_restore_refused_gen == Some(self.sync_gen) {
            return Ok(());
        }
        // The framer expects the echo if it knows echo is on, and copes with
        // either if it does not (a reopened port).
        match self.send_and_wait("ATE0", deadline, preempt, Instant::now()).await {
            Ok(r) if r.ok => {
                self.restore_echo_off = false;
                self.echo_restore_refusals = 0;
                self.echo_restore_refused_gen = None;
                Ok(())
            }
            Ok(_) => {
                self.echo_restore_refusals += 1;
                if self.echo_restore_refusals >= ECHO_RESTORE_ATTEMPTS {
                    self.restore_echo_off = false;
                    self.echo_restore_refusals = 0;
                    self.echo_restore_refused_gen = None;
                } else {
                    self.echo_restore_refused_gen = Some(self.sync_gen);
                }
                Ok(())
            }
            Err(e) if e.starts_with("Broken") => Err(WaitOutcome::Broken(e)),
            Err(e) if e.starts_with("AT command preempted") => Err(WaitOutcome::Preempted),
            Err(_) => Err(WaitOutcome::TimedOut),
        }
    }

    fn record(&self, res: &Result<AtResponse, String>) {
        let st = &self.stats;
        match res {
            Ok(r) => {
                st.commands_total.fetch_add(1, AtomicOrdering::Relaxed);
                st.observe_latency(r.latency_ms);
                if !r.ok {
                    st.at_errors.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
            Err(e) => {
                let counter = if e.starts_with("AT command timed out") || e.starts_with("Timed out") {
                    st.commands_total.fetch_add(1, AtomicOrdering::Relaxed);
                    &st.timeouts
                } else if e.starts_with("AT command preempted") {
                    st.commands_total.fetch_add(1, AtomicOrdering::Relaxed);
                    &st.preempted
                } else {
                    &st.broken
                };
                counter.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
    }

    /// `must_send`: write the command even if the line cannot be brought in
    /// step before `deadline`, and wait that long for its final code then.
    async fn exec_one_inner(
        &mut self,
        command: &str,
        deadline: tokio::time::Instant,
        prio: Priority,
        allow_preempt: bool,
        must_send: Option<Duration>,
    ) -> Result<AtResponse, String> {
        // Failures before the first byte is written are marked: the modem
        // never saw the command (see [`NOT_SENT`]).
        self.ensure_port().await.map_err(|e| format!("{NOT_SENT}{e}"))?;
        self.framer.prune_stale(Instant::now());
        if let Err(e) = self.absorb_idle() {
            let e = self.mark_broken(&e);
            return Err(format!("{NOT_SENT}{e}"));
        }
        let started = Instant::now();
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("AT command timed out ({command}) before it reached the modem"));
        }
        let preempt = (allow_preempt && prio > Priority::Emergency).then_some((prio, started));
        if let Err(outcome) = self.resync(deadline, preempt).await {
            return Err(match outcome {
                WaitOutcome::Broken(e) => format!("{NOT_SENT}{}", self.mark_broken(&e)),
                WaitOutcome::Preempted => format!("AT command preempted by priority request ({command}) during resync"),
                _ => {
                    if let Some(reply_wait) = must_send {
                        // Delivered behind the outstanding probe (or behind an
                        // abandoned ATE0). The framer is told a reply is owed,
                        // for `reply_wait`: the sync that follows counts this
                        // command's final code as well as the probe's, in
                        // either order, and is given up on (fresh probe) once
                        // `reply_wait` has passed without both. What that
                        // does and does not guarantee: `Framer::start_sync`.
                        if self.write_raw(format!("{command}\r\n").into_bytes()).await.is_ok() {
                            self.framer.expect_unawaited_reply(command, Instant::now(), reply_wait);
                        }
                        if self.consecutive_resync_failures >= MAX_CONSECUTIVE_RESYNC_FAILURES {
                            let _ = self.mark_broken("consecutive QMRESYNC probes failed");
                        }
                        format!("AT command timed out ({command}): AT channel did not resync; command sent without waiting")
                    } else {
                        if self.consecutive_resync_failures >= MAX_CONSECUTIVE_RESYNC_FAILURES {
                            let _ = self.mark_broken("consecutive QMRESYNC probes failed");
                        }
                        format!("AT command timed out ({command}): AT channel did not resync; command not sent")
                    }
                }
            });
        }
        self.send_and_wait(command, deadline, preempt, started).await
    }

    /// Write one command on an in-sync line and wait for its reply.
    async fn send_and_wait(
        &mut self,
        command: &str,
        deadline: tokio::time::Instant,
        preempt: Option<(Priority, Instant)>,
        started: Instant,
    ) -> Result<AtResponse, String> {
        self.framer.begin(command);
        if let Err(e) = self.write_raw(format!("{command}\r\n").into_bytes()).await {
            self.framer.abandon(Instant::now() + STALE_TTL);
            return Err(self.mark_broken(&e));
        }
        match self.wait_response(deadline, preempt, false).await {
            WaitOutcome::Done(ok, raw) => {
                // A reply (OK or an error result) on an in-sync line: the
                // channel answers.
                self.unresponsive = false;
                self.consecutive_resync_failures = 0;
                self.consecutive_timeouts = 0;
                self.healthy.store(true, AtomicOrdering::Relaxed);
                Ok(make_response(command, ok, raw, started))
            }
            WaitOutcome::Broken(e) => Err(self.mark_broken(&e)),
            WaitOutcome::Prompt => Err("Unexpected prompt".into()),
            WaitOutcome::TimedOut => {
                // Return at the caller's deadline. Whatever this command still
                // prints is consumed by the resync that precedes the next one.
                self.framer.abandon(Instant::now() + STALE_TTL);
                self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
                if self.consecutive_timeouts >= MAX_CONSECUTIVE_RESYNC_FAILURES {
                    let _ = self.mark_broken("consecutive AT command timeouts");
                }
                Err(format!("AT command timed out ({command})"))
            }
            WaitOutcome::Preempted => {
                // Best-effort abort (V.250: abortable commands stop on any
                // character; a bare CR is ignored by an idle command parser).
                let _ = self.write_raw(b"\r".to_vec()).await;
                self.framer.abandon(Instant::now() + STALE_TTL);
                if let Some(e) = self.drain_until_quiet().await {
                    return Err(self.mark_broken(&e));
                }
                Err(format!("AT command preempted by priority request ({command})"))
            }
        }
    }

    async fn exec_pdu(&mut self, cmgs_cmd: &str, hex_pdu: &str, timeout: Duration) -> Result<AtResponse, String> {
        self.ensure_port().await?;
        self.framer.prune_stale(Instant::now());
        if let Err(e) = self.absorb_idle() {
            return Err(self.mark_broken(&e));
        }
        match self.resync(tokio::time::Instant::now() + timeout, None).await {
            Ok(()) => {}
            Err(WaitOutcome::Broken(e)) => return Err(self.mark_broken(&e)),
            Err(_) => {
                if self.consecutive_resync_failures >= MAX_CONSECUTIVE_RESYNC_FAILURES {
                    let _ = self.mark_broken("consecutive QMRESYNC probes failed");
                }
                return Err("Timed out waiting for SMS > prompt: AT channel did not resync".into());
            }
        }
        let started = Instant::now();
        self.framer.begin(cmgs_cmd);
        if let Err(e) = self.write_raw(format!("{cmgs_cmd}\r").into_bytes()).await {
            self.framer.abandon(Instant::now() + STALE_TTL);
            return Err(self.mark_broken(&e));
        }
        let prompt_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        match self.wait_response(prompt_deadline, None, true).await {
            WaitOutcome::Prompt => {}
            WaitOutcome::Done(ok, raw) => return Ok(make_response(cmgs_cmd, ok, raw, started)),
            WaitOutcome::Broken(e) => return Err(self.mark_broken(&e)),
            WaitOutcome::TimedOut | WaitOutcome::Preempted => {
                let _ = self.write_raw(vec![0x1b]).await;
                self.framer.abandon(Instant::now() + STALE_TTL);
                let _ = self.drain_until_quiet().await;
                return Err("Timed out waiting for SMS > prompt".into());
            }
        }
        self.framer.begin_pdu_body(hex_pdu);
        if let Err(e) = self.write_raw(format!("{hex_pdu}\x1a").into_bytes()).await {
            self.framer.abandon(Instant::now() + STALE_TTL);
            return Err(self.mark_broken(&e));
        }
        let deadline = tokio::time::Instant::now() + timeout;
        match self.wait_response(deadline, None, false).await {
            WaitOutcome::Done(ok, raw) => Ok(make_response(cmgs_cmd, ok, raw, started)),
            WaitOutcome::Broken(e) => Err(self.mark_broken(&e)),
            _ => {
                self.framer.abandon(Instant::now() + STALE_TTL);
                let _ = self.drain_until_quiet().await;
                Err("Timed out waiting for SMS submit confirmation".into())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Direct (daemon not running) synchronous session for the CLI
// ---------------------------------------------------------------------------

/// One fd, no threads: used by `r10-modem-ctl`/`cellctl` only when the
/// daemon is not running (see `cli::DirectGuard`).
pub struct DirectSession {
    fd: RawFd,
    framer: Framer,
}

impl DirectSession {
    pub fn open(device: &str) -> Result<Self, String> {
        Ok(Self::from_fd(open_device_fd(device)?))
    }

    pub fn from_fd(fd: RawFd) -> Self {
        Self {
            fd,
            framer: Framer::default(),
        }
    }

    fn read_some(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, String> {
        let ms = wait.as_millis().min(i32::MAX as u128) as i32;
        if poll_readable(self.fd, ms) == Some(false) {
            return Ok(None);
        }
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            Ok(Some(buf[..n as usize].to_vec()))
        } else if n == 0 {
            Err("EOF on SMD device".into())
        } else {
            let err = std::io::Error::last_os_error();
            if matches!(err.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) {
                Ok(None)
            } else {
                Err(format!("Read error: {err}"))
            }
        }
    }

    pub fn exec(&mut self, command: &str, timeout: Duration) -> Result<AtResponse, String> {
        let command = sanitize_at_command(command)?;
        self.framer.prune_stale(Instant::now());
        while let Some(b) = self.read_some(Duration::ZERO)? {
            let _ = self.framer.feed(&b);
        }
        self.framer.clear_partial();
        let started = Instant::now();
        self.framer.begin(&command);
        write_all_fd(self.fd, format!("{command}\r\n").as_bytes())?;
        let deadline = started + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if let Some(b) = self.read_some((deadline - now).min(Duration::from_millis(250)))?
                && let Some((ok, raw)) = self.framer.feed(&b)
            {
                return Ok(make_response(&command, ok, raw, started));
            }
        }
        self.framer.abandon(Instant::now() + STALE_TTL);
        let hard = Instant::now() + DRAIN_MAX;
        while self.framer.stale_count() > 0 && Instant::now() < hard {
            match self.read_some(DRAIN_QUIET)? {
                Some(b) => {
                    let _ = self.framer.feed(&b);
                }
                None => break,
            }
        }
        Err(format!("Direct SMD AT timed out ({command})"))
    }
}

impl Drop for DirectSession {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_terminator_and_clean_body() {
        let raw = b"AT+QGMR\r\nRM551EGL00AAR02A02M8G_01.001.01.001\r\n\r\nOK\r\n";
        let (ok, text) = check_at_terminator(raw).expect("terminator detected");
        assert!(ok);
        assert_eq!(
            clean_at_body("AT+QGMR", &text),
            "RM551EGL00AAR02A02M8G_01.001.01.001"
        );

        let err_raw = b"AT+BAD\r\n+CME ERROR: 100\r\n";
        let (ok2, _) = check_at_terminator(err_raw).expect("error terminator");
        assert!(!ok2);
    }

    #[test]
    fn clean_at_body_strips_unsolicited_urcs_but_keeps_command_replies() {
        let storm = "AT+CFUN?\r\n+QIND: \"csq\",20,99\r\n+CMTI: \"ME\",9\r\n+CREG: 1\r\n+QNWINFO: \"FDD LTE\"\r\n+CFUN: 1\r\nOK\r\n";
        assert_eq!(clean_at_body("AT+CFUN?", storm), "+CFUN: 1");

        let ati = "ATI\r\n+QIND: \"nwscanmode\",1\r\nQuectel\r\nRM551E-GL\r\nOK\r\n";
        assert_eq!(clean_at_body("ATI", ati), "Quectel\nRM551E-GL");

        let creg = "AT+CREG?\r\n+QIND: \"csq\",20,99\r\n+CREG: 0,1\r\nOK\r\n";
        assert_eq!(clean_at_body("AT+CREG?", creg), "+CREG: 0,1");

        let qnw = "AT+QNWINFO\r\n+CREG: 1\r\n+QNWINFO: \"TDD NR5G\",\"310260\",\"NR5G BAND 41\",521310\r\nOK\r\n";
        assert_eq!(
            clean_at_body("AT+QNWINFO", qnw),
            "+QNWINFO: \"TDD NR5G\",\"310260\",\"NR5G BAND 41\",521310"
        );
    }

    #[test]
    fn priority_queue_pops_lowest_enum_first() {
        let mut heap = BinaryHeap::new();
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();
        let (tx3, _rx3) = oneshot::channel();
        heap.push(QueuedRequest {
            priority: Priority::Background,
            seq: 1,
            work: WorkKind::Single {
                command: "BG".into(),
                timeout: Duration::from_secs(1),
                deadline: None,
                reply: tx1,
            },
        });
        heap.push(QueuedRequest {
            priority: Priority::Emergency,
            seq: 2,
            work: WorkKind::Single {
                command: "EM".into(),
                timeout: Duration::from_secs(1),
                deadline: None,
                reply: tx2,
            },
        });
        heap.push(QueuedRequest {
            priority: Priority::Interactive,
            seq: 3,
            work: WorkKind::Single {
                command: "UI".into(),
                timeout: Duration::from_secs(1),
                deadline: None,
                reply: tx3,
            },
        });
        let p1 = match heap.pop().unwrap().work {
            WorkKind::Single { command, .. } => command,
            _ => unreachable!(),
        };
        let p2 = match heap.pop().unwrap().work {
            WorkKind::Single { command, .. } => command,
            _ => unreachable!(),
        };
        let p3 = match heap.pop().unwrap().work {
            WorkKind::Single { command, .. } => command,
            _ => unreachable!(),
        };
        assert_eq!((p1.as_str(), p2.as_str(), p3.as_str()), ("EM", "UI", "BG"));
    }

    // ---------------- framer ----------------

    #[test]
    fn framer_discards_late_reply_of_abandoned_command_without_echo() {
        let mut f = Framer::default();
        f.begin("AT+SLOW");
        assert!(f.feed(b"").is_none());
        f.abandon(Instant::now() + Duration::from_secs(60));
        f.begin("AT+CFUN?");
        // late reply of AT+SLOW, then the real CFUN reply, in one chunk
        let got = f.feed(b"\r\n+SLOW: 1\r\n\r\nOK\r\n\r\n+CFUN: 1\r\n\r\nOK\r\n").expect("cfun reply");
        assert!(got.0);
        assert_eq!(clean_at_body("AT+CFUN?", &got.1), "+CFUN: 1");
        assert_eq!(f.stale_count(), 0);
    }

    #[test]
    fn framer_uses_echo_to_correlate() {
        let mut f = Framer::default();
        f.begin("AT+QGMR");
        let r = f.feed(b"AT+QGMR\r\nRM551E\r\nOK\r\n").unwrap();
        assert_eq!(clean_at_body("AT+QGMR", &r.1), "RM551E");
        // echo is now expected; a timed-out command's reply arrives late
        f.begin("AT+QSCAN=3,1");
        f.feed(b"AT+QSCAN=3,1\r\n+QSCAN: \"NR5G\",1\r\n");
        f.abandon(Instant::now() + Duration::from_secs(60));
        f.begin("AT+CFUN?");
        assert!(f.feed(b"+QSCAN: \"LTE\",2\r\nOK\r\n").is_none(), "stale lines must not complete CFUN");
        let r = f.feed(b"AT+CFUN?\r\n+CFUN: 1\r\n\r\nOK\r\n").unwrap();
        assert_eq!(clean_at_body("AT+CFUN?", &r.1), "+CFUN: 1");
    }

    #[test]
    fn framer_waits_for_complete_lines_and_handles_errors() {
        let mut f = Framer::default();
        f.begin("AT+BAD");
        assert!(f.feed(b"+CME ERR").is_none());
        let r = f.feed(b"OR: 100\r\n").unwrap();
        assert!(!r.0);
        assert!(r.1.contains("+CME ERROR: 100"));
        // stale entries expire
        f.begin("AT+X");
        f.abandon(Instant::now() - Duration::from_millis(1));
        f.prune_stale(Instant::now());
        assert_eq!(f.stale_count(), 0);
    }

    #[test]
    fn framer_detects_sms_prompt() {
        let mut f = Framer::default();
        f.begin("AT+CMGS=20");
        assert!(f.feed(b"\r\n> ").is_none());
        assert!(f.take_prompt());
        f.begin_pdu_body("0011");
        let r = f.feed(b"\r\n+CMGS: 12\r\n\r\nOK\r\n").unwrap();
        assert!(r.0 && r.1.contains("+CMGS: 12"));
    }

    // ---------------- fake modem over a socketpair ----------------

    fn socketpair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (fds[0], fds[1])
    }

    type Script = Box<dyn FnMut(&str) -> Vec<(u64, String)> + Send>;

    /// Reads CR-terminated commands from `fd` and answers per `script`
    /// (each reply chunk is written after `delay` ms). Runs until EOF.
    /// Commands are handled one at a time, like the modem: a reply delay holds
    /// back everything written after it. Echo starts as `echo` and follows
    /// ATE0/ATE1 unless the script answers them with an ERROR (the script
    /// answers them); a bare CR (V.250 abort) is logged as "<CR>" and handed
    /// to the script as "".
    fn fake_modem(fd: RawFd, echo: bool, script: Script) -> thread::JoinHandle<Vec<String>> {
        fake_modem_shared_echo(fd, Arc::new(AtomicBool::new(echo)), script)
    }

    /// [`fake_modem`] whose echo setting lives in `echo`, so two ports (a
    /// reopen) can talk to the same modem state.
    fn fake_modem_shared_echo(fd: RawFd, echo: Arc<AtomicBool>, script: Script) -> thread::JoinHandle<Vec<String>> {
        fake_modem_lossy(fd, echo, Box::new(|_| None), script)
    }

    /// What the line does to a command on its way to the modem: `None`
    /// delivers it intact, `Some(text)` delivers `text` instead (garbled), and
    /// `Some("")` loses the line (no echo, no reply; logged as "<LOST:cmd>").
    type Mangle = Box<dyn FnMut(&str) -> Option<String> + Send>;

    /// [`fake_modem_shared_echo`] behind a lossy line.
    fn fake_modem_lossy(fd: RawFd, echo: Arc<AtomicBool>, mut mangle: Mangle, mut script: Script) -> thread::JoinHandle<Vec<String>> {
        thread::spawn(move || {
            let mut seen = Vec::new();
            let mut acc = Vec::new();
            let mut buf = [0u8; 2048];
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n as usize]);
                while let Some(pos) = acc.iter().position(|&b| b == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    if cmd.is_empty() {
                        seen.push("<CR>".into());
                        for (delay, out) in script("") {
                            thread::sleep(Duration::from_millis(delay));
                            let _ = write_all_fd(fd, out.as_bytes());
                        }
                        continue;
                    }
                    let cmd = match mangle(&cmd) {
                        Some(m) if m.is_empty() => {
                            seen.push(format!("<LOST:{cmd}>"));
                            continue;
                        }
                        Some(m) => m,
                        None => cmd,
                    };
                    seen.push(cmd.clone());
                    if echo.load(AtomicOrdering::SeqCst) {
                        let _ = write_all_fd(fd, format!("{cmd}\r\n").as_bytes());
                    }
                    let replies = script(&cmd);
                    let refused = replies.iter().any(|(_, out)| out.contains("ERROR"));
                    match cmd.to_ascii_uppercase().as_str() {
                        "ATE1" if !refused => echo.store(true, AtomicOrdering::SeqCst),
                        "ATE0" if !refused => echo.store(false, AtomicOrdering::SeqCst),
                        _ => {}
                    }
                    for (delay, out) in replies {
                        thread::sleep(Duration::from_millis(delay));
                        let _ = write_all_fd(fd, out.as_bytes());
                    }
                }
            }
            unsafe { libc::close(fd) };
            seen
        })
    }

    fn client_on(fd: RawFd, opens: Arc<AtomicU64>) -> SmdClient {
        let mut fd_slot = Some(fd);
        SmdClient::spawn_with_opener(Box::new(move || {
            opens.fetch_add(1, AtomicOrdering::SeqCst);
            fd_slot.take().ok_or_else(|| "no more fds".to_string())
        }))
    }

    fn standard_script(slow_ms: u64) -> Script {
        Box::new(move |cmd| match cmd {
            "AT+SLOW" => vec![(slow_ms, "\r\n+SLOW: 1\r\n\r\nOK\r\n".into())],
            "AT+CFUN?" => vec![(5, "\r\n+CFUN: 1\r\n\r\nOK\r\n".into())],
            "AT+QNWINFO" => vec![(5, "\r\n+QNWINFO: \"TDD NR5G\"\r\n\r\nOK\r\n".into())],
            "AT+ITEM" => vec![(400, "\r\nOK\r\n".into())],
            _ => vec![(5, "\r\nOK\r\n".into())],
        })
    }

    async fn late_reply_not_misattributed(echo: bool) {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, echo, standard_script(400));
        let opens = Arc::new(AtomicU64::new(0));
        let c = client_on(ours, Arc::clone(&opens));
        let r = c.exec("AT+SLOW", Priority::Telemetry, Duration::from_millis(100)).await;
        assert!(r.unwrap_err().contains("timed out"));
        for _ in 0..3 {
            let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(3)).await.expect("cfun");
            assert_eq!(r.body, "+CFUN: 1", "late +SLOW reply leaked into the next command");
        }
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(3)).await.unwrap();
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        assert_eq!(opens.load(AtomicOrdering::SeqCst), 1, "a timeout must not reopen the device");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn timeout_keeps_channel_and_drops_late_reply_without_echo() {
        late_reply_not_misattributed(false).await;
    }

    #[tokio::test]
    async fn timeout_keeps_channel_and_drops_late_reply_with_echo() {
        late_reply_not_misattributed(true).await;
    }

    #[tokio::test]
    async fn emergency_preempts_long_interactive_command() {
        let (ours, theirs) = socketpair();
        // AT+QSCAN only answers after an abort character (or 30 s).
        let aborted = Arc::new(AtomicBool::new(false));
        let ab = Arc::clone(&aborted);
        let mut scanning = false;
        let modem = fake_modem(theirs, false, Box::new(move |cmd| {
            if cmd == "AT+QSCAN=3,1" {
                scanning = true;
                return vec![];
            }
            if scanning {
                // the scan is aborted by the first character after it (the
                // preemption CR); whatever followed is then answered
                scanning = false;
                ab.store(true, AtomicOrdering::SeqCst);
                let mut out = vec![(5, "\r\nOK\r\n".to_string())];
                if !cmd.is_empty() {
                    out.push((5, "\r\n+CFUN: 1\r\n\r\nOK\r\n".into()));
                }
                return out;
            }
            if cmd.is_empty() {
                return vec![];
            }
            vec![(5, "\r\n+CFUN: 1\r\n\r\nOK\r\n".into())]
        }));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let c2 = c.clone();
        let scan = tokio::spawn(async move {
            c2.exec("AT+QSCAN=3,1", Priority::Interactive, Duration::from_secs(180)).await
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let t0 = Instant::now();
        let r = c.exec("AT+CFUN?", Priority::Emergency, Duration::from_secs(4)).await.expect("emergency cfun");
        assert_eq!(r.body, "+CFUN: 1");
        assert!(t0.elapsed() < Duration::from_secs(5), "emergency waited {:?}", t0.elapsed());
        let scan_res = scan.await.unwrap();
        assert!(scan_res.unwrap_err().contains("preempted"));
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn emergency_runs_between_batch_items() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, standard_script(10));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let c2 = c.clone();
        let batch = tokio::spawn(async move {
            let cmds = (0..10).map(|_| ("AT+ITEM".to_string(), Duration::from_secs(2))).collect();
            c2.exec_batch(cmds, Priority::Telemetry).await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t0 = Instant::now();
        let r = c.exec("AT+CFUN?", Priority::Emergency, Duration::from_secs(4)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        assert!(t0.elapsed() < Duration::from_millis(1500), "emergency waited {:?}", t0.elapsed());
        let results = batch.await.unwrap().unwrap();
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.as_ref().is_ok_and(|r| r.ok)));
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn interactive_runs_between_telemetry_batch_items() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, standard_script(80));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let c2 = c.clone();
        let batch = tokio::spawn(async move {
            let cmds = (0..10).map(|_| ("AT+ITEM".to_string(), Duration::from_secs(2))).collect();
            c2.exec_batch(cmds, Priority::Telemetry).await
        });
        tokio::time::sleep(Duration::from_millis(120)).await;
        let t0 = Instant::now();
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(4)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        assert!(t0.elapsed() < Duration::from_millis(500), "interactive waited {:?} behind telemetry batch", t0.elapsed());
        let results = batch.await.unwrap().unwrap();
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.as_ref().is_ok_and(|r| r.ok)));
        drop(c);
        let _ = modem;
    }

    #[test]
    fn blocked_smd_write_does_not_stall_the_runtime() {
        let (ours, theirs) = socketpair();
        // Fill the socket so the next write blocks (the peer never reads).
        unsafe {
            let fl = libc::fcntl(ours, libc::F_GETFL);
            libc::fcntl(ours, libc::F_SETFL, fl | libc::O_NONBLOCK);
            let junk = [b'x'; 4096];
            while libc::write(ours, junk.as_ptr() as *const libc::c_void, junk.len()) > 0 {}
            libc::fcntl(ours, libc::F_SETFL, fl);
        }
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let out = rt.block_on(async move {
                let ticks = Arc::new(AtomicU64::new(0));
                let t = Arc::clone(&ticks);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        t.fetch_add(1, AtomicOrdering::SeqCst);
                    }
                });
                let c = client_on(ours, Arc::new(AtomicU64::new(0)));
                let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_millis(500)).await;
                (r, ticks.load(AtomicOrdering::SeqCst))
            });
            let _ = done_tx.send(out);
        });
        let (r, ticks) = done_rx.recv_timeout(Duration::from_secs(20)).expect("runtime stalled by blocking write");
        assert!(r.unwrap_err().contains("write timed out"));
        assert!(ticks > 100, "runtime starved during blocked write: {ticks} ticks");
        unsafe { libc::close(theirs) };
    }

    #[test]
    fn direct_session_keeps_one_fd_and_skips_late_reply() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, standard_script(400));
        let mut s = DirectSession::from_fd(ours);
        assert!(s.exec("AT+SLOW", Duration::from_millis(100)).is_err());
        let r = s.exec("AT+CFUN?", Duration::from_secs(3)).unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        for _ in 0..5 {
            let r = s.exec("AT+QNWINFO", Duration::from_secs(3)).unwrap();
            assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        }
        drop(s);
        let seen = modem.join().unwrap();
        assert_eq!(seen[0], "AT+SLOW");
    }

    // ---------------- resync after dropped / stuck / garbled replies (HARD-02) ----------------

    #[test]
    fn framer_sync_discards_everything_before_the_probe_echo() {
        let mut f = Framer::default();
        f.begin("AT+DROP");
        f.abandon(Instant::now() + Duration::from_secs(60));
        assert!(!f.in_sync());
        f.start_sync("AT+QMRESYNC=42");
        // late replies, an old probe's echo, garbage and the ATE1 answer: all discarded
        assert!(f.feed(b"\r\n+DROP: 1\r\n\r\nOK\r\nAT+QMRESYNC=41\r\nERROR\r\n\xff\xfeOK\r\n").is_none());
        assert!(f.syncing());
        // garbage glued in front of the echo is tolerated; the final code completes the sync
        assert!(f.feed(b"\x00\x1b[2JAT+QMRESYNC=42\r\nERROR\r\n").is_none());
        assert!(f.in_sync());
        assert_eq!(f.echo_state(), Some(true));
        f.begin("AT+CFUN?");
        let r = f.feed(b"AT+CFUN?\r\n+CFUN: 1\r\n\r\nOK\r\n").expect("in sync");
        assert_eq!(clean_at_body("AT+CFUN?", &r.1), "+CFUN: 1");
    }

    /// Records every command the fake receives, in order.
    fn logging(log: Arc<std::sync::Mutex<Vec<String>>>, mut inner: Script) -> Script {
        Box::new(move |cmd| {
            log.lock().unwrap().push(cmd.to_string());
            inner(cmd)
        })
    }

    fn resync_script(stuck_ms: u64) -> Script {
        let mut std = standard_script(400);
        Box::new(move |cmd| match cmd {
            // the modem swallows the command: no reply, ever
            "AT+DROP" => vec![],
            // the modem hangs (everything written meanwhile waits), then drops it
            "AT+STUCK" => vec![(stuck_ms, String::new())],
            // an unterminated garbage reply
            "AT+QG" => vec![(5, "\r\n\u{0}\u{ff}\u{fe}+CME ERR\x1b[2J\r\n#$%garbage-no-terminator".into())],
            _ => std(cmd),
        })
    }

    async fn dropped_reply_resyncs(echo: bool) {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, echo, resync_script(0));
        let opens = Arc::new(AtomicU64::new(0));
        let c = client_on(ours, Arc::clone(&opens));
        // learn the echo state first, as the daemon does at start-up
        c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(3)).await.expect("first");
        let r = c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await;
        assert!(r.unwrap_err().contains("timed out"));
        for i in 0..3 {
            let t0 = Instant::now();
            let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await;
            let r = r.unwrap_or_else(|e| panic!("command {i} after one dropped reply failed: {e}"));
            assert_eq!(r.body, "+CFUN: 1");
            assert!(t0.elapsed() < Duration::from_millis(1000), "command {i} took {:?}", t0.elapsed());
        }
        assert_eq!(opens.load(AtomicOrdering::SeqCst), 1, "resync must not reopen the device");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn one_dropped_reply_does_not_time_out_the_following_commands() {
        dropped_reply_resyncs(false).await;
    }

    #[tokio::test]
    async fn one_dropped_reply_does_not_time_out_the_following_commands_with_echo() {
        dropped_reply_resyncs(true).await;
    }

    #[tokio::test]
    async fn echo_off_is_restored_after_a_resync() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), resync_script(0)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.unwrap();
        assert!(c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await.is_err());
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        let seen = log.lock().unwrap().clone();
        let probe = seen.iter().position(|c| c.starts_with(RESYNC_PROBE_PREFIX)).expect("a resync probe was sent");
        assert_eq!(seen[probe - 1], "ATE1");
        assert_eq!(seen[probe + 1], "ATE0", "echo must be switched back off: {seen:?}");
        assert_eq!(seen[probe + 2], "AT+QNWINFO");
        // no further probes once in sync
        let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        assert_eq!(log.lock().unwrap().iter().filter(|c| c.starts_with(RESYNC_PROBE_PREFIX)).count(), 1);
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn stuck_channel_fails_at_the_timeout_and_heals_within_one_command() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), resync_script(1500)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let t0 = Instant::now();
        assert!(c.exec("AT+STUCK", Priority::Interactive, Duration::from_millis(300)).await.is_err());
        // while the modem hangs every command fails at its own timeout
        for _ in 0..2 {
            let t = Instant::now();
            let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_millis(300)).await;
            assert!(r.unwrap_err().contains("timed out"));
            assert!(t.elapsed() < Duration::from_millis(450), "timeout not honoured: {:?}", t.elapsed());
        }
        // the commands that failed were never written: only the resync probe waits in the modem
        assert!(!log.lock().unwrap().iter().any(|c| c == "AT+CFUN?"));
        tokio::time::sleep(Duration::from_millis(1600u64.saturating_sub(t0.elapsed().as_millis() as u64))).await;
        // the line is quiet again: the very next command answers
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.expect("healed");
        assert_eq!(r.body, "+CFUN: 1");
        for _ in 0..3 {
            let r = c.exec("AT+QNWINFO", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
            assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        }
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn unterminated_garbage_reply_is_survived() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, resync_script(0));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        assert!(c.exec("AT+QG", Priority::Interactive, Duration::from_millis(300)).await.is_err());
        for _ in 0..3 {
            let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.expect("after garbage");
            assert_eq!(r.body, "+CFUN: 1");
        }
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn one_dropped_reply_inside_a_batch_keeps_the_rest_of_the_batch() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, resync_script(0));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let cmds = vec![
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
            ("AT+DROP".to_string(), Duration::from_millis(300)),
            ("AT+QNWINFO".to_string(), Duration::from_secs(2)),
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
        ];
        let t0 = Instant::now();
        let res = c.exec_batch(cmds, Priority::Telemetry).await.unwrap();
        assert_eq!(res[0].as_ref().unwrap().body, "+CFUN: 1");
        assert!(res[1].is_err());
        assert_eq!(res[2].as_ref().expect("item after the dropped one").body, "+QNWINFO: \"TDD NR5G\"");
        assert_eq!(res[3].as_ref().unwrap().body, "+CFUN: 1");
        assert!(t0.elapsed() < Duration::from_millis(1500), "batch took {:?}", t0.elapsed());
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn a_hung_modem_fails_a_batch_fast_instead_of_item_by_item() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, resync_script(4000));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let cmds: Vec<_> = std::iter::once(("AT+STUCK".to_string(), Duration::from_millis(300)))
            .chain((0..8).map(|_| ("AT+CFUN?".to_string(), Duration::from_millis(400))))
            .collect();
        let t0 = Instant::now();
        let res = c.exec_batch(cmds, Priority::Telemetry).await.unwrap();
        assert_eq!(res.len(), 9);
        assert!(res.iter().all(|r| r.is_err()));
        assert!(t0.elapsed() < Duration::from_millis(1500), "every item waited its timeout: {:?}", t0.elapsed());
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn emergency_command_is_still_delivered_exactly_once_when_resync_fails() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), resync_script(1200)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        assert!(c.exec("AT+STUCK", Priority::Interactive, Duration::from_millis(200)).await.is_err());
        let r = c.exec("AT+CFUN=1", Priority::Emergency, Duration::from_millis(400)).await;
        assert!(r.unwrap_err().contains("timed out"));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let r = c.exec("AT+CFUN?", Priority::Emergency, Duration::from_secs(2)).await.expect("healed");
        assert_eq!(r.body, "+CFUN: 1");
        let seen = log.lock().unwrap().clone();
        assert_eq!(seen.iter().filter(|c| *c == "AT+CFUN=1").count(), 1, "{seen:?}");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn exec_within_counts_time_spent_queued_and_never_sends_a_late_command() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), standard_script(1200)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        let c2 = c.clone();
        let slow = tokio::spawn(async move { c2.exec("AT+SLOW", Priority::Interactive, Duration::from_secs(3)).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = Instant::now();
        let r = c.exec_within("AT+QNWINFO", Priority::Interactive, Duration::from_millis(500)).await;
        assert!(r.unwrap_err().contains("timed out"));
        assert!(t0.elapsed() < Duration::from_millis(700), "budget overrun: {:?}", t0.elapsed());
        assert_eq!(slow.await.unwrap().unwrap().body, "+SLOW: 1");
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        assert!(!log.lock().unwrap().iter().any(|c| c == "AT+QNWINFO"), "expired request was written");
        drop(c);
        let _ = modem;
    }

    // ---------------- HARD-02 follow-up: the unresponsive flag, echo restore, late probe replies ----------------

    /// Hands out the given fds in order, one per (re)open.
    fn client_on_fds(fds: Vec<RawFd>) -> SmdClient {
        let mut fds: VecDeque<RawFd> = fds.into();
        SmdClient::spawn_with_opener(Box::new(move || fds.pop_front().ok_or_else(|| "no more fds".to_string())))
    }

    /// Hang the modem, let one command's resync probe go unanswered (the
    /// actor marks the channel unresponsive), then let the modem answer
    /// everything while the actor is idle.
    async fn probe_answered_while_idle(c: &SmdClient) {
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        assert!(c.exec("AT+STUCK", Priority::Interactive, Duration::from_millis(200)).await.is_err());
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_millis(300)).await;
        assert!(r.unwrap_err().contains("did not resync"));
        // the modem un-hangs at 700 ms and answers the probe; nothing is in flight
        tokio::time::sleep(Duration::from_millis(900)).await;
    }

    #[tokio::test]
    async fn a_probe_answered_while_idle_clears_the_unresponsive_flag() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, resync_script(700));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        probe_answered_while_idle(&c).await;
        // one item times out, the rest of the batch must still run
        let cmds = vec![
            ("AT+DROP".to_string(), Duration::from_millis(300)),
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
            ("AT+QNWINFO".to_string(), Duration::from_secs(2)),
        ];
        let t0 = Instant::now();
        let res = c.exec_batch(cmds, Priority::Telemetry).await.unwrap();
        assert!(res[0].is_err());
        assert_eq!(res[1].as_ref().expect("good item after a timeout").body, "+CFUN: 1");
        assert_eq!(res[2].as_ref().expect("good item after a timeout").body, "+QNWINFO: \"TDD NR5G\"");
        assert!(t0.elapsed() < Duration::from_millis(1500), "batch took {:?}", t0.elapsed());
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn a_successful_command_clears_the_unresponsive_flag() {
        let (ours, theirs) = socketpair();
        let modem = fake_modem(theirs, false, resync_script(700));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        probe_answered_while_idle(&c).await;
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(2)).await.expect("healthy again");
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        let cmds = vec![
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
            ("AT+DROP".to_string(), Duration::from_millis(300)),
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
            ("AT+QNWINFO".to_string(), Duration::from_secs(2)),
        ];
        let res = c.exec_batch(cmds, Priority::Telemetry).await.unwrap();
        assert_eq!(res[0].as_ref().unwrap().body, "+CFUN: 1");
        assert!(res[1].is_err());
        assert_eq!(res[2].as_ref().expect("item after the dropped one").body, "+CFUN: 1");
        assert_eq!(res[3].as_ref().expect("item after the dropped one").body, "+QNWINFO: \"TDD NR5G\"");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn reopening_the_port_clears_the_unresponsive_flag() {
        let (ours1, theirs1) = socketpair();
        let (ours2, theirs2) = socketpair();
        // port 1: a dead line (nothing is ever answered) that then breaks
        let dead = fake_modem(theirs1, false, Box::new(|_| vec![]));
        let good = fake_modem(theirs2, false, standard_script(10));
        let c = client_on_fds(vec![ours1, ours2]);
        assert!(c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await.is_err());
        let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_millis(300)).await;
        assert!(r.unwrap_err().contains("did not resync"));
        unsafe { libc::shutdown(theirs1, libc::SHUT_RDWR) };
        let _ = dead.join();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let cmds = vec![
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
            ("AT+QNWINFO".to_string(), Duration::from_secs(2)),
            ("AT+CFUN?".to_string(), Duration::from_secs(2)),
        ];
        let res = c.exec_batch(cmds, Priority::Telemetry).await.unwrap();
        // the first item notices the broken port; the reopened port serves the rest
        assert!(res[0].as_ref().unwrap_err().contains("Broken"), "{:?}", res[0]);
        assert_eq!(res[1].as_ref().expect("reopened port").body, "+QNWINFO: \"TDD NR5G\"");
        assert_eq!(res[2].as_ref().expect("reopened port").body, "+CFUN: 1");
        drop(c);
        let _ = good;
    }

    #[tokio::test]
    async fn echo_off_is_restored_after_a_failed_resync() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), resync_script(700)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        probe_answered_while_idle(&c).await;
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(2)).await.expect("after recovery");
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        assert!(!r.raw.contains("AT+QNWINFO"), "echo still on: {:?}", r.raw);
        let seen = log.lock().unwrap().clone();
        let probe = seen.iter().position(|c| c.starts_with(RESYNC_PROBE_PREFIX)).expect("probe");
        assert_eq!(seen[probe - 1], "ATE1");
        assert_eq!(seen[probe + 1..], ["ATE0".to_string(), "AT+QNWINFO".to_string()], "{seen:?}");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn echo_off_is_restored_on_a_reopened_port_after_a_failed_resync() {
        let (ours1, theirs1) = socketpair();
        let (ours2, theirs2) = socketpair();
        // one modem behind two ports: echo is modem state and survives the reopen
        let echo = Arc::new(AtomicBool::new(false));
        let drop_probes: Script = Box::new(|cmd| {
            if cmd == "AT+DROP" || cmd.starts_with(RESYNC_PROBE_PREFIX) {
                return vec![];
            }
            vec![(5, "\r\n+CFUN: 1\r\n\r\nOK\r\n".into())]
        });
        let first = fake_modem_shared_echo(theirs1, Arc::clone(&echo), drop_probes);
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let second = fake_modem_shared_echo(theirs2, Arc::clone(&echo), logging(Arc::clone(&log), standard_script(10)));
        let c = client_on_fds(vec![ours1, ours2]);
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        assert!(c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await.is_err());
        // ATE1 is answered, the probe is not: the resync fails with echo on
        let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_millis(400)).await;
        assert!(r.unwrap_err().contains("did not resync"));
        assert!(echo.load(AtomicOrdering::SeqCst), "ATE1 should have reached the modem");
        unsafe { libc::shutdown(theirs1, libc::SHUT_RDWR) };
        let _ = first.join();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // this one sees the broken port
        assert!(c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.is_err());
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(2)).await.expect("reopened");
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        assert!(!echo.load(AtomicOrdering::SeqCst), "echo left on after the reopen");
        assert_eq!(log.lock().unwrap().clone(), ["ATE0", "AT+QNWINFO"]);
        drop(c);
        let _ = second;
    }

    #[tokio::test]
    async fn a_late_probe_reply_after_an_emergency_write_is_not_misattributed() {
        let (ours, theirs) = socketpair();
        let late_fd = unsafe { libc::dup(theirs) };
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut std = standard_script(400);
        let script: Script = Box::new(move |cmd| {
            if cmd.starts_with(RESYNC_PROBE_PREFIX) {
                // the probe's echo goes out now, its final result code only
                // after the Emergency command written behind it has answered
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(150));
                    let _ = write_all_fd(late_fd, b"\r\nERROR\r\n");
                    unsafe { libc::close(late_fd) };
                });
                return vec![];
            }
            match cmd {
                "AT+STUCK" => vec![(600, String::new())],
                "AT+CFUN=1" => vec![(5, "\r\nOK\r\n".into())],
                "AT+SLOWQ" => vec![(300, "\r\n+SLOWQ: 1\r\n\r\nOK\r\n".into())],
                _ => std(cmd),
            }
        });
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), script));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        assert!(c.exec("AT+STUCK", Priority::Interactive, Duration::from_millis(200)).await.is_err());
        let r = c.exec("AT+CFUN=1", Priority::Emergency, Duration::from_millis(300)).await;
        assert!(r.unwrap_err().contains("sent without waiting"));
        let r = c.exec("AT+SLOWQ", Priority::Interactive, Duration::from_secs(3)).await.expect("slowq");
        assert!(r.ok, "late probe reply credited to the next command: {:?}", r.raw);
        assert_eq!(r.body, "+SLOWQ: 1");
        for _ in 0..2 {
            let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
            assert_eq!(r.body, "+CFUN: 1");
        }
        let seen = log.lock().unwrap().clone();
        assert_eq!(seen.iter().filter(|c| *c == "AT+CFUN=1").count(), 1, "{seen:?}");
        drop(c);
        let _ = modem;
    }

    #[test]
    fn framer_sync_waits_for_replies_owed_by_commands_written_behind_the_probe() {
        let mut f = Framer::default();
        f.begin("AT+DROP");
        f.abandon(Instant::now() + Duration::from_secs(60));
        f.start_sync("AT+QMRESYNC=7");
        f.expect_unawaited_reply("AT+CFUN=1", Instant::now(), Duration::from_secs(60));
        // the command behind the probe answers before the probe does
        assert!(f.feed(b"AT+QMRESYNC=7\r\nAT+CFUN=1\r\nOK\r\n").is_none());
        assert!(f.syncing(), "the probe's own final code is still owed");
        assert!(f.feed(b"ERROR\r\n").is_none());
        assert!(f.in_sync());
        // not syncing: an unawaited write is an abandoned command (forces a resync)
        f.expect_unawaited_reply("AT+CFUN=1", Instant::now(), Duration::from_secs(60));
        assert!(!f.in_sync());
    }

    // ---------------- HARD-02 round 3: an Emergency command written behind an unanswered probe ----------------

    #[test]
    fn framer_fences_on_a_command_written_behind_a_lost_probe() {
        let mut f = Framer::default();
        f.begin("AT+DROP");
        f.abandon(Instant::now() + Duration::from_secs(60));
        f.start_sync("AT+QMRESYNC=9");
        f.expect_unawaited_reply("AT+CFUN=1", Instant::now(), Duration::from_secs(60));
        // older output, then no probe echo at all (the probe line was lost):
        // the Emergency command's echo is the fence, its final ends the sync
        assert!(f.feed(b"\r\n+DROP: 1\r\nOK\r\nAT+QMRES\xffNC=9\r\nERROR\r\n").is_none());
        assert!(f.syncing());
        assert!(f.feed(b"AT+CFUN=1\r\n").is_none());
        assert!(f.syncing());
        assert!(f.feed(b"OK\r\n").is_none());
        assert!(f.in_sync(), "the probe's final is not owed when its echo never came");
        assert_eq!(f.echo_state(), Some(true));
    }

    #[test]
    fn framer_sync_turns_overdue_at_the_unawaited_reply_deadline() {
        let mut f = Framer::default();
        let t0 = Instant::now();
        f.start_sync("AT+QMRESYNC=11");
        assert!(!f.sync_overdue(t0 + Duration::from_secs(3600)), "the probe alone is never overdue here (PROBE_RETRY)");
        assert_eq!(f.sync_give_up_at(), None);
        f.expect_unawaited_reply("AT+CFUN=1", t0, Duration::from_millis(500));
        assert_eq!(f.sync_give_up_at(), Some(t0 + Duration::from_millis(500)));
        // the probe answers, the command's reply is lost
        assert!(f.feed(b"AT+QMRESYNC=11\r\nERROR\r\nAT+CFUN=1\r\n").is_none());
        assert!(f.syncing());
        assert!(!f.sync_overdue(t0 + Duration::from_millis(499)));
        assert!(f.sync_overdue(t0 + Duration::from_millis(500)));
        // a fresh probe starts over: nothing is owed for the old one
        f.start_sync("AT+QMRESYNC=12");
        assert!(!f.sync_overdue(t0 + Duration::from_secs(3600)));
        assert!(f.feed(b"OK\r\nAT+QMRESYNC=12\r\nERROR\r\n").is_none());
        assert!(f.in_sync());
    }

    /// Number of resync probes the modem received (lost lines included).
    fn probes_in(log: &[String]) -> usize {
        log.iter().filter(|c| c.contains("QMRESYNC") || c.contains("QMRES")).count()
    }

    /// DROP leaves the line out of step, then an Emergency `AT+CFUN=1` with a
    /// 400 ms budget cannot get the probe answered in time and is written
    /// behind it ("sent without waiting"). Its reply deadline is the clamped
    /// timeout, 1 s. Returns when the Emergency call has returned.
    async fn emergency_written_behind_the_probe(c: &SmdClient) {
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        assert!(c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await.is_err());
        let r = c.exec("AT+CFUN=1", Priority::Emergency, Duration::from_millis(400)).await;
        assert!(r.unwrap_err().contains("sent without waiting"));
    }

    #[tokio::test]
    async fn an_emergency_reply_lost_behind_an_answered_probe_stalls_only_until_its_reply_deadline() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut std = resync_script(0);
        let mut first_probe = true;
        let script: Script = Box::new(move |cmd| {
            if cmd.starts_with(RESYNC_PROBE_PREFIX) && first_probe {
                // answered, but only after the Emergency command was written
                first_probe = false;
                return vec![(700, "\r\nERROR\r\n".into())];
            }
            match cmd {
                // the Emergency command's reply is lost
                "AT+CFUN=1" => vec![],
                _ => std(cmd),
            }
        });
        let modem = fake_modem(theirs, false, logging(Arc::clone(&log), script));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        emergency_written_behind_the_probe(&c).await;
        let t0 = Instant::now();
        let r = c.exec("AT+QNWINFO", Priority::Interactive, Duration::from_secs(5)).await;
        let took = t0.elapsed();
        let r = r.unwrap_or_else(|e| panic!("stalled behind a lost Emergency reply: {e} after {took:?}"));
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        // re-probed at the Emergency command's own deadline (1 s after it was
        // written), not at PROBE_RETRY
        assert!(took >= Duration::from_millis(800), "gave up before the reply deadline: {took:?}");
        assert!(took < Duration::from_millis(1600), "stalled past the reply deadline: {took:?}");
        // and the line is in step again: no further probes, no stall
        let t1 = Instant::now();
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        assert!(t1.elapsed() < Duration::from_millis(300), "{:?}", t1.elapsed());
        let seen = log.lock().unwrap().clone();
        assert_eq!(probes_in(&seen), 2, "{seen:?}");
        assert_eq!(seen.iter().filter(|c| *c == "AT+CFUN=1").count(), 1, "{seen:?}");
        drop(c);
        let _ = modem;
    }

    async fn lost_probe_line_then_emergency_answered(garble: bool) {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut first_probe = true;
        let mangle: Mangle = Box::new(move |cmd| {
            if cmd.starts_with(RESYNC_PROBE_PREFIX) && first_probe {
                first_probe = false;
                return Some(if garble { cmd.replace("RESYNC", "RES\u{fffd}NC") } else { String::new() });
            }
            None
        });
        let mut std = resync_script(0);
        let script: Script = Box::new(move |cmd| {
            if cmd.contains('\u{fffd}') {
                return vec![(5, "\r\nERROR\r\n".into())];
            }
            match cmd {
                "AT+CFUN=1" => vec![(5, "\r\nOK\r\n".into())],
                _ => std(cmd),
            }
        });
        let modem = fake_modem_lossy(theirs, Arc::new(AtomicBool::new(false)), mangle, logging(Arc::clone(&log), script));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        emergency_written_behind_the_probe(&c).await;
        // the Emergency command is answered right away; nothing else is owed
        let t0 = Instant::now();
        let r = c.exec("AT+QNWINFO", Priority::Interactive, Duration::from_secs(3)).await;
        let took = t0.elapsed();
        let r = r.unwrap_or_else(|e| panic!("sync waited for a probe that never reached the modem: {e} after {took:?}"));
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        // completed by the Emergency final: well before its 1 s reply deadline
        // (and PROBE_RETRY), without a second probe
        assert!(took < Duration::from_millis(500), "{took:?}");
        let seen = log.lock().unwrap().clone();
        assert_eq!(probes_in(&seen), usize::from(garble), "no fresh probe may be needed: {seen:?}");
        assert_eq!(seen.iter().filter(|c| *c == "AT+CFUN=1").count(), 1, "{seen:?}");
        assert!(!r.raw.contains("AT+QNWINFO"), "echo not restored: {:?}", r.raw);
        for _ in 0..2 {
            let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
            assert_eq!(r.body, "+CFUN: 1");
        }
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn a_lost_probe_line_completes_the_sync_at_the_emergency_final() {
        lost_probe_line_then_emergency_answered(false).await;
    }

    #[tokio::test]
    async fn a_garbled_probe_line_completes_the_sync_at_the_emergency_final() {
        lost_probe_line_then_emergency_answered(true).await;
    }

    #[tokio::test]
    async fn emergency_behind_the_probe_probe_answers_first_ends_the_sync_at_the_second_final() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Arc::new(AtomicBool::new(false));
        let mut std = resync_script(0);
        let mut first_probe = true;
        let script: Script = Box::new(move |cmd| {
            if cmd.starts_with(RESYNC_PROBE_PREFIX) && first_probe {
                first_probe = false;
                // answered 500 ms after it was read; the modem holds back the
                // Emergency command meanwhile and answers it after
                return vec![(500, "\r\nERROR\r\n".into())];
            }
            match cmd {
                "AT+CFUN=1" => vec![(5, "\r\nOK\r\n".into())],
                _ => std(cmd),
            }
        });
        let modem = fake_modem_shared_echo(theirs, Arc::clone(&echo), logging(Arc::clone(&log), script));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        emergency_written_behind_the_probe(&c).await;
        let t0 = Instant::now();
        let r = c.exec("AT+QNWINFO", Priority::Interactive, Duration::from_secs(3)).await.expect("after both finals");
        let took = t0.elapsed();
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        // the probe answers ~100 ms after the Emergency write, the command right
        // after it: done then, not at the 1 s reply deadline
        assert!(took < Duration::from_millis(600), "{took:?}");
        assert!(!r.raw.contains("AT+QNWINFO"), "echo not restored: {:?}", r.raw);
        assert!(!echo.load(AtomicOrdering::SeqCst));
        let seen = log.lock().unwrap().clone();
        assert_eq!(probes_in(&seen), 1, "{seen:?}");
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn emergency_behind_the_probe_emergency_answers_first_waits_for_the_late_probe_final() {
        let (ours, theirs) = socketpair();
        let late_fd = unsafe { libc::dup(theirs) };
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Arc::new(AtomicBool::new(false));
        let mut std = resync_script(0);
        let mut first_probe = true;
        let script: Script = Box::new(move |cmd| {
            if cmd.starts_with(RESYNC_PROBE_PREFIX) && first_probe {
                first_probe = false;
                // the probe's echo now, its final 400 ms later: after the
                // Emergency command written behind it has answered
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(400));
                    let _ = write_all_fd(late_fd, b"\r\nERROR\r\n");
                    unsafe { libc::close(late_fd) };
                });
                return vec![(200, String::new())];
            }
            match cmd {
                "AT+CFUN=1" => vec![(5, "\r\nOK\r\n".into())],
                _ => std(cmd),
            }
        });
        let modem = fake_modem_shared_echo(theirs, Arc::clone(&echo), logging(Arc::clone(&log), script));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        emergency_written_behind_the_probe(&c).await;
        let t0 = Instant::now();
        let r = c.exec("AT+QNWINFO", Priority::Interactive, Duration::from_secs(3)).await.expect("after both finals");
        let took = t0.elapsed();
        assert!(r.ok, "the late probe final was credited: {:?}", r.raw);
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        // ended by the late probe final (~0.4 s), not by giving up at the
        // Emergency command's 1 s reply deadline (that would send a 2nd probe)
        assert!(took < Duration::from_millis(800), "{took:?}");
        assert!(!echo.load(AtomicOrdering::SeqCst), "the late ERROR was credited to ATE0");
        let seen = log.lock().unwrap().clone();
        assert_eq!(probes_in(&seen), 1, "{seen:?}");
        assert_eq!(seen.iter().filter(|c| *c == "ATE0").count(), 1, "{seen:?}");
        let r = c.exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.body, "+CFUN: 1");
        drop(c);
        let _ = modem;
    }

    // ---------------- HARD-02 round 3: a refused ATE0 ----------------

    /// Echo starts off; `ATE0` is refused for the first `refusals` attempts.
    fn refusing_ate0(refusals: usize) -> Script {
        let mut std = resync_script(0);
        let mut ate0 = 0;
        Box::new(move |cmd| {
            if cmd == "ATE0" {
                ate0 += 1;
                if ate0 <= refusals {
                    return vec![(5, "\r\nERROR\r\n".into())];
                }
            }
            std(cmd)
        })
    }

    async fn drop_then_command(c: &SmdClient) -> AtResponse {
        assert!(c.exec("AT+DROP", Priority::Telemetry, Duration::from_millis(300)).await.is_err());
        let r = c.exec("AT+QNWINFO", Priority::Telemetry, Duration::from_secs(2)).await.expect("after resync");
        assert_eq!(r.body, "+QNWINFO: \"TDD NR5G\"");
        r
    }

    fn ate0_count(log: &Arc<std::sync::Mutex<Vec<String>>>) -> usize {
        log.lock().unwrap().iter().filter(|c| *c == "ATE0").count()
    }

    #[tokio::test]
    async fn a_refused_ate0_is_retried_after_the_next_resync_and_restores_echo_off() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Arc::new(AtomicBool::new(false));
        let modem = fake_modem_shared_echo(theirs, Arc::clone(&echo), logging(Arc::clone(&log), refusing_ate0(1)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        drop_then_command(&c).await;
        assert_eq!(ate0_count(&log), 1);
        assert!(echo.load(AtomicOrdering::SeqCst), "the modem refused ATE0");
        // not retried before every command ...
        for _ in 0..2 {
            let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.unwrap();
            assert_eq!(r.body, "+CFUN: 1");
        }
        assert_eq!(ate0_count(&log), 1, "ATE0 retried before every command");
        // ... but after the next resync, where the modem accepts it
        let r = drop_then_command(&c).await;
        assert_eq!(ate0_count(&log), 2);
        assert!(!echo.load(AtomicOrdering::SeqCst), "echo left on after a refused ATE0");
        assert!(!r.raw.contains("AT+QNWINFO"), "echo still on: {:?}", r.raw);
        // done: no further ATE0 on an in-sync line
        for _ in 0..2 {
            let r = c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.unwrap();
            assert_eq!(r.raw, "+CFUN: 1\r\nOK\r\n");
        }
        assert_eq!(ate0_count(&log), 2);
        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn a_refused_ate0_is_given_up_after_a_bounded_number_of_resyncs() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Arc::new(AtomicBool::new(false));
        let modem = fake_modem_shared_echo(theirs, Arc::clone(&echo), logging(Arc::clone(&log), refusing_ate0(usize::MAX)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));
        c.exec("AT+CFUN?", Priority::Telemetry, Duration::from_secs(2)).await.expect("learn echo");
        for i in 1..=ECHO_RESTORE_ATTEMPTS as usize {
            drop_then_command(&c).await;
            assert_eq!(ate0_count(&log), i);
        }
        for _ in 0..2 {
            drop_then_command(&c).await;
        }
        assert_eq!(ate0_count(&log), ECHO_RESTORE_ATTEMPTS as usize, "ATE0 retried without bound");
        assert!(echo.load(AtomicOrdering::SeqCst));
        drop(c);
        let _ = modem;
    }

    #[test]
    fn qcmap_dependent_at_cmd_matches_qcmap_family_only() {
        for matched in [
            r#"AT+QMAP="WWAN""#,
            r#"at+qmap="sfe""#,
            "AT+QMAP?",
            "AT+QMAPWAC?",
            r#"AT+QDMZ=1,4,"192.168.1.2""#,
            "AT+QIP6CFG?",
            r#"AT+CFUN?;+QMAP="SFE""#,
            r#"AT+CFUN?; AT+QMAP="WWAN""#,
        ] {
            assert!(is_qcmap_dependent_at_cmd(matched), "expected match for {matched:?}");
        }
        for unmatched in [
            "AT+CFUN?",
            "AT+QTEMP",
            "AT+CGCONTRDP",
            r#"AT+QNWCFG="foo;+QMAP""#,
            "AT+QMAPPING?",
        ] {
            assert!(!is_qcmap_dependent_at_cmd(unmatched), "unexpected match for {unmatched:?}");
        }
    }

    #[tokio::test]
    async fn native_mode_short_circuits_qcmap_single_and_preserves_batch_indices() {
        let (ours, theirs) = socketpair();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Arc::new(AtomicBool::new(false));
        let modem = fake_modem_shared_echo(theirs, echo, logging(Arc::clone(&log), resync_script(0)));
        let c = client_on(ours, Arc::new(AtomicU64::new(0)));

        let err = c
            .exec_single_inner(
                r#"AT+QMAP="WWAN""#.into(),
                Priority::Interactive,
                Duration::from_secs(2),
                None,
                true,
            )
            .await
            .unwrap_err();
        assert!(err.contains("unavailable while QCMAP is stopped in Native mode"), "{err}");
        assert!(log.lock().unwrap().is_empty(), "QMAP command reached modem: {:?}", *log.lock().unwrap());

        let batch = c
            .exec_batch_inner(
                vec![
                    ("AT+CFUN?".into(), Duration::from_secs(2)),
                    (r#"AT+QMAP="SFE""#.into(), Duration::from_secs(2)),
                    ("AT+QNWINFO".into(), Duration::from_secs(2)),
                ],
                Priority::Interactive,
                true,
            )
            .await
            .expect("batch result");
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].as_ref().unwrap().body, "+CFUN: 1");
        assert!(batch[1].as_ref().unwrap_err().contains("Native mode"));
        assert_eq!(batch[2].as_ref().unwrap().body, r#"+QNWINFO: "TDD NR5G""#);
        assert_eq!(*log.lock().unwrap(), vec!["AT+CFUN?".to_string(), "AT+QNWINFO".to_string()]);

        let all_qmap = c
            .exec_batch_inner(
                vec![
                    (r#"AT+QMAP="LANIP""#.into(), Duration::from_secs(2)),
                    ("AT+QDMZ?".into(), Duration::from_secs(2)),
                ],
                Priority::Interactive,
                true,
            )
            .await
            .expect("all-qcmap batch");
        assert_eq!(all_qmap.len(), 2);
        assert!(all_qmap[0].as_ref().unwrap_err().contains("Native mode"));
        assert!(all_qmap[1].as_ref().unwrap_err().contains("Native mode"));
        assert_eq!(*log.lock().unwrap(), vec!["AT+CFUN?".to_string(), "AT+QNWINFO".to_string()]);

        drop(c);
        let _ = modem;
    }

    #[tokio::test]
    async fn three_consecutive_failed_qmresync_probes_reopen_serial_fd() {
        use std::io::{Read, Write};
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;

        let (a1, mut b1) = UnixStream::pair().unwrap();
        let (a2, mut b2) = UnixStream::pair().unwrap();

        // Port 1 swallows every command and every QMRESYNC probe silently (wedged /dev/smd11).
        let _t1 = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            while let Ok(n) = b1.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
        // Port 2 responds normally once Actor marks port 1 broken and reopens.
        let _t2 = std::thread::spawn(move || {
            let mut acc = Vec::new();
            let mut buf = [0u8; 256];
            while let Ok(n) = b2.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                while let Some(pos) = acc.iter().position(|&c| c == b'\r') {
                    let line: Vec<u8> = acc.drain(..=pos).collect();
                    if acc.first() == Some(&b'\n') {
                        acc.remove(0);
                    }
                    let cmd = String::from_utf8_lossy(&line).trim().to_string();
                    if cmd.is_empty() {
                        continue;
                    }
                    let _ = b2.write_all(format!("{cmd}\r\r\n+CFUN: 1\r\nOK\r\n").as_bytes());
                }
            }
        });

        let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let opens_cl = opens.clone();
        let fds = std::sync::Mutex::new(VecDeque::from([a1.into_raw_fd(), a2.into_raw_fd()]));
        let client = SmdClient::spawn_with_opener(Box::new(move || {
            opens_cl.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fds.lock().unwrap().pop_front().ok_or_else(|| "no more fds".into())
        }));

        // 1st command times out and leaves stale owed final -> next commands trigger QMRESYNC.
        let _ = client
            .exec("AT+CFUN?", Priority::Interactive, Duration::from_millis(30))
            .await;
        // Drive 3 consecutive failed QMRESYNC probes; the 3rd marks port 1 broken.
        for _ in 0..MAX_CONSECUTIVE_RESYNC_FAILURES {
            let _ = client
                .exec("AT+CFUN?", Priority::Interactive, Duration::from_millis(80))
                .await;
        }
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Next call reopens onto port 2 and succeeds cleanly!
        let recovered = client
            .exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(1))
            .await
            .expect("reopened port 2 should answer");
        assert!(recovered.ok);
        assert!(recovered.body.contains("+CFUN: 1"));
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn framer_caps_pending_at_64kib_and_cursor_scans_cleanly() {
        let mut f = Framer::default();
        f.begin("AT+TEST");
        // Feed many lines in one chunk to exercise cursor scanning
        let mut chunk = Vec::new();
        chunk.extend_from_slice(b"AT+TEST\r\n");
        for i in 0..200 {
            chunk.extend_from_slice(format!("+DATA: {i}\r\n").as_bytes());
        }
        chunk.extend_from_slice(b"OK\r\n");
        let (ok, raw) = f.feed(&chunk).expect("response parsed");
        assert!(ok);
        assert!(raw.contains("+DATA: 199"));
        assert_eq!(f.pending_len(), 0);
        assert!(f.in_sync());

        // Overflow (> 64 KiB without line terminator) drops buffer and forces resync
        let noise = vec![b'X'; MAX_FRAMER_PENDING + 128];
        assert!(f.feed(&noise).is_none());
        assert_eq!(f.pending_len(), 0);
        assert!(!f.in_sync(), "overflow must force resync");

        // Starting and completing a sync probe clears the overflow flag
        f.start_sync("AT+QMRESYNC=42");
        let _ = f.feed(b"AT+QMRESYNC=42\r\nERROR\r\n");
        assert!(f.in_sync());
    }

    #[test]
    fn smd_device_candidates_rotate_between_smd11_and_smd7() {
        let c0 = smd_device_candidates(DEFAULT_SMD_DEVICE, 0);
        assert_eq!(c0, vec![DEFAULT_SMD_DEVICE.to_string(), FALLBACK_SMD_DEVICE.to_string()]);
        let c1 = smd_device_candidates(DEFAULT_SMD_DEVICE, 1);
        assert_eq!(c1, vec![FALLBACK_SMD_DEVICE.to_string(), DEFAULT_SMD_DEVICE.to_string()]);
        let c2 = smd_device_candidates(DEFAULT_SMD_DEVICE, 2);
        assert_eq!(c2, vec![DEFAULT_SMD_DEVICE.to_string(), FALLBACK_SMD_DEVICE.to_string()]);
    }

    #[tokio::test]
    async fn write_failure_marks_port_broken_and_reopens() {
        let (a1, b1) = socketpair();
        let (a2, b2) = socketpair();
        // Close peer b1 immediately so writes to a1 fail with EPIPE/ECONNRESET
        unsafe { libc::close(b1) };
        let _t2 = fake_modem(b2, true, Box::new(|_| vec![(0, "+CFUN: 1\r\nOK\r\n".into())]));

        let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let opens_cl = opens.clone();
        let fds = std::sync::Mutex::new(VecDeque::from([a1, a2]));
        let client = SmdClient::spawn_with_opener(Box::new(move || {
            opens_cl.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fds.lock().unwrap().pop_front().ok_or_else(|| "no more fds".into())
        }));

        let err = client
            .exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.contains("Broken"), "write/read failure must mark broken: {err}");

        let ok = client
            .exec("AT+CFUN?", Priority::Interactive, Duration::from_secs(1))
            .await
            .expect("second call must reopen onto healthy port");
        assert!(ok.ok);
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}

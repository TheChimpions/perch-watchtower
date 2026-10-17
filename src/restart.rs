//! Following a coordinated cluster restart.
//!
//! A restart has three visible stages: the cluster is still producing blocks,
//! then it halts while operators restart with the new snapshot and wait for a
//! supermajority, then it produces blocks again. Two sources say which stage
//! it is in:
//!
//! * the slots the endpoints report, which is all a box without the validator
//!   log has;
//! * the validator's own log, which says it is waiting for supermajority (and
//!   how much stake is in gossip) every ten seconds until it starts up.
//!
//! This module turns both into stages; `main` turns the stages into messages
//! and decides when alerting resumes.
//!
//! Slots are compared per endpoint, never as a fleet-wide maximum. During a
//! restart the endpoints come back at different times, and the cluster usually
//! resumes from an earlier slot than the highest one anyone saw before the
//! halt: a maximum would be pinned by the one endpoint still serving the old
//! fork, and the restart would look like an hour-long stall.

use crate::state::ClusterPhase;
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

/// How long no endpoint's slot may stand still before the cluster counts as
/// halted. Long enough that a slow cycle or a lagging provider never looks like
/// a halt; a real restart halts for hours.
pub const HALT_AFTER_SECS: u64 = 5 * 60;

/// Cycles in a row in which some endpoint's slot moved forward before a halted
/// cluster counts as producing again. One could be an endpoint replaying the
/// old fork as it shuts down.
pub const ADVANCING_CYCLES: u32 = 2;

/// Agave logs the wait every ten seconds, so a line older than this means the
/// validator has stopped waiting: it started up, or it is down.
pub const WAITING_FRESH_SECS: i64 = 3 * 60;

/// "Supermajority reached" counts only this long after it was logged, so the
/// last restart's line in a long log cannot end a new window.
pub const REACHED_FRESH_SECS: i64 = 30 * 60;

/// While the validator is waiting for supermajority the window cannot expire;
/// it runs at least this long past the last wait line, which also leaves the
/// validator time to catch up once the cluster starts. Some testnet restarts
/// have waited longer than any deadline worth setting up front.
pub const WAIT_GRACE_SECS: u64 = 2 * 3600;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    Halted { slot: u64 },
    /// The validator is waiting for supermajority, said once per halt.
    Waiting { slot: Option<u64>, gossip_percent: Option<f64> },
    SupermajorityReached { percent: Option<f64> },
    Restarted { slot: u64 },
}

/// What the validator's log says this cycle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Local {
    /// No log configured, or it could not be read: slots alone decide.
    Unknown,
    /// Not waiting: running normally, or not running at all.
    Idle,
    Waiting { slot: Option<u64>, gossip_percent: Option<f64> },
    Reached { percent: Option<f64> },
}

/// The supermajority lines last seen in the validator log.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WaitLog {
    pub waiting_at: Option<DateTime<Utc>>,
    pub wait_slot: Option<u64>,
    pub gossip_percent: Option<f64>,
    pub reached_at: Option<DateTime<Utc>>,
    pub reached_percent: Option<f64>,
}

/// The message after Agave's `[timestamp LEVEL target] ` prefix.
fn message(line: &str) -> &str {
    line.split_once("] ").map_or(line, |(_, m)| m).trim_end()
}

/// The number in front of the first `%` in `s`.
fn percent_before(s: &str) -> Option<f64> {
    let head = &s[..s.find('%')?];
    let start = head
        .rfind(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map_or(0, |i| i + 1);
    head[start..].parse().ok()
}

impl WaitLog {
    /// Fold one log line in. Agave v4.3 core/src/validator.rs:
    ///
    /// ```text
    /// Waiting for 80% of activated stake at slot 451203317 to be in gossip...
    /// 61.234% of active stake visible in gossip
    /// Supermajority reached, 81% active stake detected, starting up now.
    /// ```
    pub fn apply(&mut self, at: DateTime<Utc>, line: &str) {
        let m = message(line);
        if m.contains("% of activated stake at slot") && m.contains("to be in gossip") {
            self.waiting_at = Some(at);
            self.wait_slot = m
                .split_once("at slot ")
                .and_then(|(_, r)| r.split_whitespace().next())
                .and_then(|s| s.parse().ok());
        } else if m.ends_with("% of active stake visible in gossip") {
            self.gossip_percent = percent_before(m);
        } else if let Some(rest) = m.strip_prefix("Supermajority reached, ") {
            self.reached_at = Some(at);
            self.reached_percent = percent_before(rest);
        }
    }

    pub fn local(&self, now: DateTime<Utc>) -> Local {
        let age = |t: DateTime<Utc>| (now - t).num_seconds();
        if let Some(r) = self.reached_at {
            if self.waiting_at.is_none_or(|w| r >= w) && age(r) <= REACHED_FRESH_SECS {
                return Local::Reached { percent: self.reached_percent };
            }
        }
        match self.waiting_at {
            Some(w) if age(w) <= WAITING_FRESH_SECS => Local::Waiting {
                slot: self.wait_slot,
                gossip_percent: self.gossip_percent,
            },
            _ => Local::Idle,
        }
    }
}

/// Follows the validator log from cycle to cycle, reading only what was
/// appended. A busy testnet log grows by gigabytes a day, so rescanning it each
/// minute is not an option; the first read starts a few minutes back.
#[derive(Debug)]
pub struct LogTail {
    path: PathBuf,
    offset: Option<u64>,
    pub wait: WaitLog,
}

/// The first read reaches back this far, so a window armed (or a perch
/// restarted) mid-wait sees the wait at once.
const FIRST_READ_LOOKBACK_SECS: i64 = 10 * 60;
/// Never read more than this in one cycle.
const MAX_READ_BYTES: u64 = 256 << 20;

impl LogTail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        LogTail {
            path: path.into(),
            offset: None,
            wait: WaitLog::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn poll(&mut self, now: DateTime<Utc>) -> std::io::Result<()> {
        let mut file = File::open(&self.path)?;
        let len = file.metadata()?.len();
        let start = match self.offset {
            // Rotated or truncated: start the new file from the top.
            Some(o) if o > len => 0,
            Some(o) => o.max(len.saturating_sub(MAX_READ_BYTES)),
            None => crate::diagnose::offset_for(
                &mut file,
                len,
                now - chrono::Duration::seconds(FIRST_READ_LOOKBACK_SECS),
                MAX_READ_BYTES,
            ),
        };
        file.seek(SeekFrom::Start(start))?;
        let mut reader = BufReader::with_capacity(1 << 20, file.take(len - start));
        let mut buf = Vec::new();
        let mut consumed = start;
        // Starting mid-file can land inside a line.
        if self.offset.is_none() && start > 0 {
            consumed += reader.read_until(b'\n', &mut buf)? as u64;
        }
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            // A line still being written is read whole next cycle.
            if n == 0 || buf.last() != Some(&b'\n') {
                break;
            }
            consumed += n as u64;
            let line = String::from_utf8_lossy(&buf);
            if let Some(at) = crate::diagnose::line_time(&line) {
                self.wait.apply(at, &line);
            }
        }
        self.offset = Some(consumed);
        Ok(())
    }
}

/// What has been seen since the window was armed, or since this process
/// started. Deliberately not persisted: the phase is, in the silence file, and
/// everything here re-establishes itself within a few cycles.
#[derive(Debug, Default)]
pub struct Watch {
    last_slot: HashMap<String, u64>,
    last_advance_unix: Option<u64>,
    advancing_streak: u32,
    announced_waiting: bool,
    /// The window cannot expire before this: the last wait line plus
    /// [`WAIT_GRACE_SECS`].
    hold_until_unix: Option<u64>,
}

impl Watch {
    /// The time the window is held open to while the validator waits, if it
    /// is: what peers must be told, so the hub does not report the box once
    /// the original deadline passes.
    pub fn hold_until_unix(&self) -> Option<u64> {
        self.hold_until_unix
    }

    /// Whether a window with this deadline has run out.
    pub fn expired(&self, deadline_unix: u64, now_unix: u64) -> bool {
        now_unix >= deadline_unix.max(self.hold_until_unix.unwrap_or(0))
    }

    /// Feed one cycle: each endpoint's slot, if it answered, and what the
    /// validator log says. Returns the phase after this cycle and what changed.
    pub fn observe(
        &mut self,
        phase: ClusterPhase,
        readings: &[(String, Option<u64>)],
        local: Local,
        now_unix: u64,
    ) -> (ClusterPhase, Option<Event>) {
        let (slot_phase, slot_event) = self.observe_slots(phase, readings, now_unix);

        let (next, event) = match (phase, local) {
            // The validator's own word that it is starting beats waiting two
            // cycles for slots to move.
            (ClusterPhase::Halted, Local::Reached { percent }) => {
                (ClusterPhase::Restarted, Some(Event::SupermajorityReached { percent }))
            }
            // Waiting means the cluster is down, whatever the slots say yet.
            // Only from Running: a validator still waiting after the cluster
            // restarted without it is a problem to alert on, not a halt.
            (ClusterPhase::Running, Local::Waiting { slot, gossip_percent }) => {
                (ClusterPhase::Halted, Some(Event::Waiting { slot, gossip_percent }))
            }
            (ClusterPhase::Halted, Local::Waiting { slot, gossip_percent })
                if slot_phase == ClusterPhase::Halted && !self.announced_waiting =>
            {
                (ClusterPhase::Halted, Some(Event::Waiting { slot, gossip_percent }))
            }
            _ => (slot_phase, slot_event),
        };

        if matches!(event, Some(Event::Waiting { .. })) {
            self.announced_waiting = true;
        }
        if next != ClusterPhase::Halted {
            self.announced_waiting = false;
        }
        if next == ClusterPhase::Restarted && phase != ClusterPhase::Restarted {
            self.advancing_streak = 0;
            // The stall clock starts over: a cluster that has only just
            // started must not read as halted for the hours it was down.
            self.last_advance_unix = Some(now_unix);
        }
        // Hold the window open while the validator waits on a halted cluster.
        if next == ClusterPhase::Halted && matches!(local, Local::Waiting { .. }) {
            self.hold_until_unix = Some(now_unix + WAIT_GRACE_SECS);
        }
        (next, event)
    }

    fn observe_slots(
        &mut self,
        phase: ClusterPhase,
        readings: &[(String, Option<u64>)],
        now_unix: u64,
    ) -> (ClusterPhase, Option<Event>) {
        let mut advanced = false;
        let mut highest: Option<u64> = None;
        for (endpoint, slot) in readings {
            let Some(slot) = *slot else { continue };
            highest = Some(highest.map_or(slot, |h| h.max(slot)));
            if let Some(prev) = self.last_slot.insert(endpoint.clone(), slot) {
                if slot > prev {
                    advanced = true;
                }
            }
        }
        // An endpoint that did not answer says nothing either way: perch's own
        // network dropping out must not read as the cluster halting.
        let Some(highest) = highest else {
            return (phase, None);
        };

        if advanced {
            self.last_advance_unix = Some(now_unix);
            self.advancing_streak += 1;
        } else {
            self.advancing_streak = 0;
        }
        // The first readings are a baseline, not evidence of a stall.
        let since_advance = now_unix.saturating_sub(*self.last_advance_unix.get_or_insert(now_unix));
        let stalled = since_advance >= HALT_AFTER_SECS;

        match phase {
            // A restart that halts again before recovering (it happens) goes
            // back to waiting for the next attempt.
            ClusterPhase::Running | ClusterPhase::Restarted if stalled => {
                self.advancing_streak = 0;
                (ClusterPhase::Halted, Some(Event::Halted { slot: highest }))
            }
            ClusterPhase::Halted if self.advancing_streak >= ADVANCING_CYCLES => {
                (ClusterPhase::Restarted, Some(Event::Restarted { slot: highest }))
            }
            other => (other, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNKNOWN: Local = Local::Unknown;

    fn r(pairs: &[(&str, Option<u64>)]) -> Vec<(String, Option<u64>)> {
        pairs.iter().map(|(n, s)| (n.to_string(), *s)).collect()
    }

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn waiting() -> Local {
        Local::Waiting { slot: Some(1_000), gossip_percent: Some(61.2) }
    }

    #[test]
    fn a_producing_cluster_never_halts() {
        let mut w = Watch::default();
        for i in 0..30u64 {
            let (phase, event) = w.observe(ClusterPhase::Running, &r(&[("a", Some(100 + i * 150))]), UNKNOWN, i * 60);
            assert_eq!((phase, event), (ClusterPhase::Running, None));
        }
    }

    #[test]
    fn a_stalled_cluster_halts_after_the_threshold_not_before() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Running, &r(&[("a", Some(100))]), UNKNOWN, 0);
        // Last progress at t=60.
        w.observe(ClusterPhase::Running, &r(&[("a", Some(200))]), UNKNOWN, 60);
        for t in [120, 180, 240, 300, 359] {
            assert_eq!(
                w.observe(ClusterPhase::Running, &r(&[("a", Some(200))]), UNKNOWN, t),
                (ClusterPhase::Running, None),
                "{}s without progress is not a halt yet",
                t - 60
            );
        }
        let (phase, event) = w.observe(ClusterPhase::Running, &r(&[("a", Some(200))]), UNKNOWN, 60 + HALT_AFTER_SECS);
        assert_eq!(phase, ClusterPhase::Halted);
        assert_eq!(event, Some(Event::Halted { slot: 200 }));
    }

    #[test]
    fn unanswered_readings_are_neither_a_halt_nor_progress() {
        // perch's own network down for an hour while the cluster is fine.
        let mut w = Watch::default();
        w.observe(ClusterPhase::Running, &r(&[("a", Some(100))]), UNKNOWN, 0);
        assert_eq!(w.observe(ClusterPhase::Running, &r(&[("a", None)]), UNKNOWN, 3_600), (ClusterPhase::Running, None));
        // Back, and moving: the gap is not a stall.
        assert_eq!(
            w.observe(ClusterPhase::Running, &r(&[("a", Some(30_000))]), UNKNOWN, 3_660),
            (ClusterPhase::Running, None)
        );
    }

    #[test]
    fn a_restart_from_an_earlier_slot_is_seen_as_producing() {
        // Halted at 1,000; the cluster resumes from 900, below the old fork.
        let mut w = Watch::default();
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), UNKNOWN, 0);
        assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(900))]), UNKNOWN, 60).0, ClusterPhase::Halted);
        assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(950))]), UNKNOWN, 120).0, ClusterPhase::Halted);
        let (phase, event) = w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_010))]), UNKNOWN, 180);
        assert_eq!(phase, ClusterPhase::Restarted);
        assert_eq!(event, Some(Event::Restarted { slot: 1_010 }));
    }

    #[test]
    fn one_endpoint_stuck_on_the_old_fork_does_not_hide_the_restart() {
        let mut w = Watch::default();
        let stuck = Some(5_000);
        w.observe(ClusterPhase::Halted, &r(&[("old", stuck), ("new", Some(4_000))]), UNKNOWN, 0);
        w.observe(ClusterPhase::Halted, &r(&[("old", stuck), ("new", Some(4_100))]), UNKNOWN, 60);
        let (phase, _) = w.observe(ClusterPhase::Halted, &r(&[("old", stuck), ("new", Some(4_200))]), UNKNOWN, 120);
        assert_eq!(phase, ClusterPhase::Restarted);
    }

    #[test]
    fn a_single_blip_of_progress_during_a_halt_is_not_a_restart() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), UNKNOWN, 0);
        assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_001))]), UNKNOWN, 60).0, ClusterPhase::Halted);
        assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_001))]), UNKNOWN, 120).0, ClusterPhase::Halted);
        assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_002))]), UNKNOWN, 180).0, ClusterPhase::Halted);
    }

    #[test]
    fn a_restart_that_halts_again_goes_back_to_halted() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_000))]), UNKNOWN, 0);
        w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_100))]), UNKNOWN, 60);
        let (phase, event) = w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_100))]), UNKNOWN, 60 + HALT_AFTER_SECS);
        assert_eq!(phase, ClusterPhase::Halted);
        assert_eq!(event, Some(Event::Halted { slot: 1_100 }));
    }

    #[test]
    fn a_fresh_process_in_a_halted_window_waits_for_real_progress() {
        // perch restarted mid-halt: its first reading is only a baseline.
        let mut w = Watch::default();
        let (phase, event) = w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), UNKNOWN, 0);
        assert_eq!((phase, event), (ClusterPhase::Halted, None));
    }

    #[test]
    fn waiting_for_supermajority_is_a_halt_at_once_and_said_once() {
        let mut w = Watch::default();
        // Endpoints still answering with a moving slot (the halt is minutes old).
        let (phase, event) = w.observe(ClusterPhase::Running, &r(&[("a", Some(1_000))]), waiting(), 0);
        assert_eq!(phase, ClusterPhase::Halted);
        assert_eq!(event, Some(Event::Waiting { slot: Some(1_000), gossip_percent: Some(61.2) }));
        for t in [60, 120, 600] {
            assert_eq!(w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), waiting(), t), (ClusterPhase::Halted, None));
        }
    }

    #[test]
    fn a_slot_halt_is_followed_by_the_wait_note() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Running, &r(&[("a", Some(1_000))]), Local::Idle, 0);
        let (phase, event) = w.observe(ClusterPhase::Running, &r(&[("a", Some(1_000))]), Local::Idle, HALT_AFTER_SECS);
        assert_eq!((phase, event), (ClusterPhase::Halted, Some(Event::Halted { slot: 1_000 })));
        // The operator restarts the validator with --wait-for-supermajority.
        let (phase, event) = w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), waiting(), HALT_AFTER_SECS + 600);
        assert_eq!(phase, ClusterPhase::Halted);
        assert!(matches!(event, Some(Event::Waiting { .. })), "{event:?}");
    }

    #[test]
    fn supermajority_reached_ends_the_halt_without_waiting_for_slots() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), waiting(), 0);
        let (phase, event) = w.observe(
            ClusterPhase::Halted,
            &r(&[("a", Some(1_000))]),
            Local::Reached { percent: Some(80.4) },
            60,
        );
        assert_eq!(phase, ClusterPhase::Restarted);
        assert_eq!(event, Some(Event::SupermajorityReached { percent: Some(80.4) }));
        // Slots have not moved for hours, but the cluster only just started.
        let (phase, event) = w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_000))]), Local::Idle, 120);
        assert_eq!((phase, event), (ClusterPhase::Restarted, None));
        let (phase, _) = w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_050))]), Local::Idle, 180);
        assert_eq!(phase, ClusterPhase::Restarted);
    }

    #[test]
    fn a_long_halt_does_not_read_as_a_fresh_halt_once_restarted() {
        let mut w = Watch::default();
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), Local::Idle, 0);
        // Ten hours later the cluster starts moving.
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_001))]), Local::Idle, 36_000);
        let (phase, _) = w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_100))]), Local::Idle, 36_060);
        assert_eq!(phase, ClusterPhase::Restarted);
        // One slow cycle right after is not a second halt.
        let (phase, event) = w.observe(ClusterPhase::Restarted, &r(&[("a", Some(1_100))]), Local::Idle, 36_120);
        assert_eq!((phase, event), (ClusterPhase::Restarted, None));
    }

    #[test]
    fn the_window_cannot_expire_while_the_validator_waits() {
        let mut w = Watch::default();
        let deadline = 12 * 3600;
        // Waiting for a day and a half on a halted cluster.
        let mut now = 0;
        while now < 36 * 3600 {
            w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), waiting(), now);
            assert!(!w.expired(deadline, now), "expired while waiting at {now}s");
            now += 60;
        }
        // It starts; there is still the grace to catch up in.
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), Local::Reached { percent: Some(81.0) }, now);
        assert!(!w.expired(deadline, now + WAIT_GRACE_SECS - 120));
        assert!(w.expired(deadline, now + WAIT_GRACE_SECS));
    }

    #[test]
    fn without_a_wait_the_deadline_stands() {
        let w = Watch::default();
        assert!(!w.expired(3_600, 3_599));
        assert!(w.expired(3_600, 3_600));
    }

    #[test]
    fn stuck_waiting_after_the_cluster_restarted_does_not_hold_the_window() {
        // The cluster came back without this validator: that is for alerting
        // to report, so the wait no longer extends the deadline.
        let mut w = Watch::default();
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_000))]), waiting(), 0);
        w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_100))]), waiting(), 60);
        let (phase, _) = w.observe(ClusterPhase::Halted, &r(&[("a", Some(1_200))]), waiting(), 120);
        assert_eq!(phase, ClusterPhase::Restarted);
        let mut now = 180;
        let mut slot = 1_300;
        while now < 10 * 3600 {
            let (phase, _) = w.observe(ClusterPhase::Restarted, &r(&[("a", Some(slot))]), waiting(), now);
            assert_eq!(phase, ClusterPhase::Restarted, "a wait must not undo the restart");
            now += 60;
            slot += 150;
        }
        assert!(w.expired(3_600, now));
    }

    #[test]
    fn parses_agaves_supermajority_lines() {
        let mut log = WaitLog::default();
        log.apply(
            t("2026-10-21T03:00:00Z"),
            "[2026-10-21T03:00:00.123456789Z INFO  solana_core::validator] Waiting for 80% of activated stake at slot 451203317 to be in gossip...",
        );
        log.apply(
            t("2026-10-21T03:00:00Z"),
            "[2026-10-21T03:00:00.223456789Z INFO  solana_core::validator] 61.234% of active stake visible in gossip",
        );
        assert_eq!(log.wait_slot, Some(451_203_317));
        assert_eq!(log.gossip_percent, Some(61.234));
        assert_eq!(
            log.local(t("2026-10-21T03:02:00Z")),
            Local::Waiting { slot: Some(451_203_317), gossip_percent: Some(61.234) }
        );
        // The wait goes quiet: not waiting any more.
        assert_eq!(log.local(t("2026-10-21T03:10:00Z")), Local::Idle);

        log.apply(
            t("2026-10-21T05:00:00Z"),
            "[2026-10-21T05:00:00.000000001Z INFO  solana_core::validator] Supermajority reached, 81% active stake detected, starting up now.",
        );
        assert_eq!(log.local(t("2026-10-21T05:01:00Z")), Local::Reached { percent: Some(81.0) });
        // A day later it is history, not news.
        assert_eq!(log.local(t("2026-10-22T05:01:00Z")), Local::Idle);
    }

    #[test]
    fn the_not_visible_line_is_not_read_as_the_visible_share() {
        let mut log = WaitLog::default();
        log.apply(t("2026-10-21T03:00:00Z"), "[2026-10-21T03:00:00Z INFO  x] 38.766% of active stake is not visible in gossip");
        assert_eq!(log.gossip_percent, None);
    }

    #[test]
    fn a_new_wait_after_an_old_start_is_waiting() {
        let mut log = WaitLog::default();
        log.apply(t("2026-10-21T05:00:00Z"), "[x] Supermajority reached, 81% active stake detected, starting up now.");
        log.apply(t("2026-10-21T05:10:00Z"), "[x] Waiting for 80% of activated stake at slot 5 to be in gossip...");
        assert!(matches!(log.local(t("2026-10-21T05:11:00Z")), Local::Waiting { .. }));
    }

    #[test]
    fn the_tail_reads_only_what_was_appended() {
        let dir = std::env::temp_dir().join(format!("perch-tail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("validator.log");
        let line = |ts: &str, m: &str| format!("[{ts} INFO  solana_core::validator] {m}\n");
        std::fs::write(&path, line("2026-10-21T03:00:00Z", "Waiting for 80% of activated stake at slot 7 to be in gossip...")).unwrap();
        let mut tail = LogTail::new(&path);
        let now = t("2026-10-21T03:01:00Z");
        tail.poll(now).unwrap();
        assert_eq!(tail.wait.wait_slot, Some(7));

        // A half-written line is left for the next read.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"[2026-10-21T03:02:00Z INFO  solana_core::validator] Supermajority reached, 8").unwrap();
        tail.poll(now).unwrap();
        assert_eq!(tail.wait.reached_at, None);
        f.write_all(b"2% active stake detected, starting up now.\n").unwrap();
        tail.poll(now).unwrap();
        assert_eq!(tail.wait.reached_percent, Some(82.0));

        // Truncated by rotation: read the new file from the top.
        std::fs::write(&path, line("2026-10-21T04:00:00Z", "Waiting for 80% of activated stake at slot 9 to be in gossip...")).unwrap();
        tail.poll(now).unwrap();
        assert_eq!(tail.wait.wait_slot, Some(9));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_log_is_an_error() {
        let mut tail = LogTail::new("/nonexistent/perch/validator.log");
        assert!(tail.poll(Utc::now()).is_err());
    }
}

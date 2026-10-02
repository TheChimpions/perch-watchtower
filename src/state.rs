//! Per-check alert state machines.
//!
//! The important property: a check's "for" duration accumulates only across
//! cycles where we actually *observed* something definite, and each observation
//! can credit at most one interval. Upstream counts consecutive failing cycles,
//! so a watchtower that was blind for an hour and then sees one bad reading would
//! have already "elapsed" its threshold on wall-clock. Here, going blind freezes
//! the timer instead of advancing it, so coming back from an outage never
//! instantly pages.

use crate::config::{CheckConfig, Severity};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Crossed the threshold for the first time.
    Firing,
    /// Still firing, and the renotify interval has elapsed.
    Renotify,
    /// Recovered, after `clear_after` consecutive healthy observations.
    Resolved,
    /// We can see the cluster, but this particular check has been inconclusive
    /// long enough that it is effectively switched off. Reported once, on the
    /// notify tier. Without this, suppressing noise could quietly become a check
    /// that has not evaluated in days and nobody noticing.
    Starved,
    /// Nothing to tell anyone.
    Quiet,
}

/// A `CheckState` reduced to the facts that outlive a process restart.
///
/// Deliberately excludes every `Instant`: monotonic clocks reset at boot, and a
/// restored one would be meaningless. Durations and the incident key are what
/// actually matter -- above all the incident key, without which a resolve after
/// a restart would be sent under a dedup key PagerDuty has never seen, leaving
/// the real incident open forever.
#[derive(Debug, Clone)]
pub struct CheckSnapshot {
    pub unhealthy_for: Duration,
    pub healthy_streak: u32,
    pub firing: bool,
    pub incident_key: String,
    pub incident_closed: bool,
    /// How long ago the check went pending, at the moment of the snapshot.
    pub pending_ago: Option<Duration>,
}

#[derive(Debug)]
pub struct CheckState {
    /// Observed (not wall-clock) time this check has been confirmed unhealthy.
    unhealthy_for: Duration,
    last_definite_at: Option<Instant>,
    healthy_streak: u32,
    firing: bool,
    last_notified_at: Option<Instant>,
    incident_key: String,
    /// Set when the check first went pending, for the resolve message.
    pending_since: Option<Instant>,
    /// How long the incident that just resolved lasted. `pending_since` is
    /// cleared the moment the check resolves, before the caller gets to ask how
    /// long it was, so the answer has to be kept here.
    resolved_after: Duration,
    /// When this check last stopped producing a definite answer.
    unknown_since: Option<Instant>,
    starved_reported: bool,
    /// The current key has already been resolved; mint a new one before the
    /// next trigger. Rotating the key *after* returning `Resolved` would leave
    /// the caller sending the resolve under a key PagerDuty has never seen, so
    /// the incident would stay open forever.
    incident_closed: bool,
}

impl Default for CheckState {
    fn default() -> Self {
        Self {
            unhealthy_for: Duration::ZERO,
            last_definite_at: None,
            healthy_streak: 0,
            firing: false,
            last_notified_at: None,
            incident_key: Uuid::new_v4().to_string(),
            pending_since: None,
            resolved_after: Duration::ZERO,
            unknown_since: None,
            starved_reported: false,
            incident_closed: false,
        }
    }
}

impl CheckState {
    pub fn incident_key(&self) -> &str {
        &self.incident_key
    }

    pub fn snapshot(&self, now: Instant) -> CheckSnapshot {
        CheckSnapshot {
            unhealthy_for: self.unhealthy_for,
            healthy_streak: self.healthy_streak,
            firing: self.firing,
            incident_key: self.incident_key.clone(),
            incident_closed: self.incident_closed,
            pending_ago: self.pending_since.map(|s| now.saturating_duration_since(s)),
        }
    }

    /// Rebuild from a snapshot. `downtime` is how long the process was away, so
    /// the incident duration reported on resolve stays honest.
    ///
    /// `last_definite_at` is intentionally left unset: the first observation
    /// after a restart then credits zero hold-down time, so a restart can never
    /// shorten the wait before a page.
    ///
    /// `last_notified_at` is set to *now* rather than left unset, so the
    /// renotify timer restarts with the process. Leaving it unset makes every
    /// restart immediately re-announce every firing check, which turns a routine
    /// deploy into a burst of "still firing" messages.
    pub fn restore(s: &CheckSnapshot, downtime: Duration, now: Instant) -> Self {
        let pending_since = s.pending_ago.map(|ago| {
            let total = ago.saturating_add(downtime);
            now.checked_sub(total).unwrap_or(now)
        });
        Self {
            unhealthy_for: s.unhealthy_for,
            last_definite_at: None,
            healthy_streak: s.healthy_streak,
            firing: s.firing,
            last_notified_at: Some(now),
            incident_key: s.incident_key.clone(),
            pending_since,
            resolved_after: Duration::ZERO,
            unknown_since: None,
            starved_reported: false,
            incident_closed: s.incident_closed,
        }
    }

    pub fn is_firing(&self) -> bool {
        self.firing
    }

    pub fn unhealthy_for(&self) -> Duration {
        self.unhealthy_for
    }

    /// How long the current incident has lasted, or -- on the cycle it
    /// resolves -- how long it lasted in total.
    pub fn incident_duration(&self, now: Instant) -> Duration {
        self.pending_since
            .map(|s| now.saturating_duration_since(s))
            .unwrap_or(self.resolved_after)
    }

    pub fn on_unhealthy(&mut self, cfg: &CheckConfig, interval: Duration, now: Instant) -> Transition {
        self.healthy_streak = 0;
        self.clear_starvation();
        if self.pending_since.is_none() {
            self.pending_since = Some(now);
        }

        let gap = self
            .last_definite_at
            .map(|t| now.saturating_duration_since(t))
            .unwrap_or(Duration::ZERO);

        // Evidence expires. If we have not been able to confirm this check for
        // several intervals, whatever was banked before describes a situation we
        // can no longer vouch for -- it may have healed and re-broken while we
        // were blind. Start the hold-down over rather than letting stale
        // observations complete it.
        //
        // Without this the guarantee depends on the ratio of `pending_for` to
        // `interval`: at a 60s hold-down and a 60s interval, one observation
        // from before a two-hour outage plus one after would page immediately.
        let stale_after = interval.saturating_mul(5);
        let credit = if self.last_definite_at.is_some() && gap > stale_after {
            self.unhealthy_for = Duration::ZERO;
            Duration::ZERO
        } else {
            // Credit at most one interval per observation, so a gap cannot be
            // cashed in as elapsed "for" time. A slow cycle credits slightly
            // less than elapsed, erring toward waiting.
            gap.min(interval)
        };
        self.unhealthy_for = self.unhealthy_for.saturating_add(credit);
        self.last_definite_at = Some(now);

        if !self.firing {
            if self.unhealthy_for >= cfg.pending_for {
                if self.incident_closed {
                    self.incident_key = Uuid::new_v4().to_string();
                    self.incident_closed = false;
                }
                self.firing = true;
                self.last_notified_at = Some(now);
                return Transition::Firing;
            }
            return Transition::Quiet;
        }

        let due = self
            .last_notified_at
            .map(|t| now.saturating_duration_since(t) >= cfg.renotify_after)
            .unwrap_or(true);
        if due && !cfg.renotify_after.is_zero() {
            self.last_notified_at = Some(now);
            return Transition::Renotify;
        }
        Transition::Quiet
    }

    pub fn on_healthy(&mut self, cfg: &CheckConfig, now: Instant) -> Transition {
        self.clear_starvation();
        self.last_definite_at = Some(now);
        self.healthy_streak = self.healthy_streak.saturating_add(1);

        if self.healthy_streak < cfg.clear_after.max(1) {
            return Transition::Quiet;
        }

        self.unhealthy_for = Duration::ZERO;
        self.resolved_after = self
            .pending_since
            .take()
            .map(|s| now.saturating_duration_since(s))
            .unwrap_or(Duration::ZERO);

        if self.firing {
            self.firing = false;
            self.last_notified_at = None;
            // The key stays valid so the caller can send the resolve under it;
            // it is rotated on the next trigger instead.
            self.incident_closed = true;
            return Transition::Resolved;
        }
        Transition::Quiet
    }

    fn clear_starvation(&mut self) {
        self.unknown_since = None;
        self.starved_reported = false;
    }

    /// No usable data for this check, though the cluster is otherwise visible.
    ///
    /// Freeze: do not advance toward firing, do not count toward clearing, and
    /// above all do not resolve a live incident just because we stopped being
    /// able to see it. If the inconclusiveness persists, say so once.
    pub fn on_unknown(&mut self, starvation_after: Duration, now: Instant) -> Transition {
        let since = *self.unknown_since.get_or_insert(now);
        if !self.starved_reported && now.saturating_duration_since(since) >= starvation_after {
            self.starved_reported = true;
            return Transition::Starved;
        }
        Transition::Quiet
    }

    /// The whole cycle was blind. Freeze exactly as `on_unknown` does, but do not
    /// accrue starvation: blindness has its own alert and should not also be
    /// reported once per check.
    pub fn on_blind(&mut self) -> Transition {
        self.unknown_since = None;
        Transition::Quiet
    }

    pub fn inconclusive_for(&self, now: Instant) -> Duration {
        self.unknown_since
            .map(|s| now.saturating_duration_since(s))
            .unwrap_or(Duration::ZERO)
    }
}

/// Tracks how long we have been unable to see the network at all.
///
/// Suppressing transient RPC noise must not become silently ignoring a real
/// outage, so blindness is itself an alert -- just a slow one, on a timescale
/// where provider flakiness has long since resolved on its own.
#[derive(Debug, Default)]
pub struct BlindnessState {
    blind_since: Option<Instant>,
    notified: bool,
    paged: bool,
    incident_key: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlindnessEvent {
    Quiet,
    Notify { blind_for: Duration },
    Page { blind_for: Duration },
    Recovered { blind_for: Duration },
}

impl BlindnessState {
    pub fn incident_key(&self) -> Option<&str> {
        self.incident_key.as_deref()
    }

    /// Restore an in-flight blindness incident so its resolve lands on the
    /// incident that was actually opened.
    pub fn restore(&mut self, incident_key: Option<String>, announced: bool) {
        self.incident_key = incident_key;
        self.notified = announced;
    }

    pub fn observe(
        &mut self,
        visible: bool,
        notify_after: Duration,
        page_after: Duration,
        now: Instant,
    ) -> BlindnessEvent {
        if visible {
            let was = self.blind_since.take();
            let announced = self.notified || self.paged;
            self.notified = false;
            self.paged = false;
            return match (was, announced) {
                (Some(since), true) => BlindnessEvent::Recovered {
                    blind_for: now.saturating_duration_since(since),
                },
                _ => {
                    self.incident_key = None;
                    BlindnessEvent::Quiet
                }
            };
        }

        let since = *self.blind_since.get_or_insert(now);
        if self.incident_key.is_none() {
            self.incident_key = Some(Uuid::new_v4().to_string());
        }
        let blind_for = now.saturating_duration_since(since);

        if blind_for >= page_after && !self.paged {
            self.paged = true;
            self.notified = true;
            return BlindnessEvent::Page { blind_for };
        }
        if blind_for >= notify_after && !self.notified {
            self.notified = true;
            return BlindnessEvent::Notify { blind_for };
        }
        BlindnessEvent::Quiet
    }

    /// The blindness incident is only cleared once a recovery has been reported.
    pub fn clear_incident(&mut self) {
        self.incident_key = None;
    }
}

/// What a silence file is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Silence {
    /// No file, so nothing suppressed.
    None,
    /// Suppress paging until a fixed time.
    Until(chrono::DateTime<chrono::Utc>),
    /// Suppress paging until the validator is healthy again, then clear itself.
    ///
    /// A restart takes as long as it takes. A fixed timer is either too short
    /// (paged mid-restart) or too long (unmonitored after recovery), and the
    /// operator has to guess up front. This waits for the actual event instead.
    ///
    /// `deadline` is a backstop: a restart that never finishes is an outage, not
    /// maintenance, so the window expires and paging resumes.
    UntilRecovered {
        deadline: chrono::DateTime<chrono::Utc>,
    },
}

impl Silence {
    pub fn suppresses_paging(&self) -> bool {
        !matches!(self, Silence::None)
    }
}

/// Read the silence file.
///
/// Format, chosen so the simple cases stay writable by hand:
///   (empty)                        open-ended
///   2026-09-18T04:30:00Z           until that time
///   auto 2026-09-18T04:30:00Z      until recovered, or that deadline
pub fn read_silence(path: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> Silence {
    let Some(path) = path else {
        return Silence::None;
    };
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Silence::None;
    };
    let trimmed = contents.trim();

    if trimmed.is_empty() {
        // Far-future stand-in for "no end given".
        return Silence::Until(now + chrono::Duration::days(3650));
    }

    if let Some(rest) = trimmed.strip_prefix("auto") {
        return match chrono::DateTime::parse_from_rfc3339(rest.trim()) {
            Ok(d) => Silence::UntilRecovered {
                deadline: d.with_timezone(&chrono::Utc),
            },
            // No parseable deadline: default to an hour rather than forever, so
            // a malformed file cannot silence a validator indefinitely.
            Err(_) => Silence::UntilRecovered {
                deadline: now + chrono::Duration::hours(1),
            },
        };
    }

    match chrono::DateTime::parse_from_rfc3339(trimmed) {
        Ok(until) if now < until.with_timezone(&chrono::Utc) => {
            Silence::Until(until.with_timezone(&chrono::Utc))
        }
        Ok(_) => Silence::None,
        // Unparseable: the operator meant to suppress something, and a typo
        // should not hand them a surprise page. Treated as open-ended.
        Err(_) => Silence::Until(now + chrono::Duration::days(3650)),
    }
}

/// Retained for callers that only need a yes/no.
pub fn silence_active(path: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> bool {
    read_silence(path, now).suppresses_paging()
}

/// What tier an alert actually goes out at while a silence is active.
///
/// Silence is the operator saying "I am working on this box". By default that
/// means the box's own checks go to the journal only: a 🚨 about a validator
/// you deliberately took down is noise, and it reads as an alarm. The
/// maintenance lifecycle messages (back online, window expired) are sent
/// directly at Notify and do not pass through here, so the timeline still has
/// its start and end. `notify_while_silenced` restores the old behaviour of
/// downgrading pages to Telegram instead of dropping them.
pub fn effective_severity(severity: Severity, silenced: bool, notify_while_silenced: bool) -> Severity {
    match (severity, silenced, notify_while_silenced) {
        (s, false, _) => s,
        (Severity::Log, _, _) => Severity::Log,
        // Opted in: pages become notes, notes stay notes.
        (_, true, true) => Severity::Notify,
        (_, true, false) => Severity::Log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pending_for: Duration, clear_after: u32) -> CheckConfig {
        CheckConfig {
            enabled: true,
            pending_for,
            clear_after,
            severity: Severity::Page,
            renotify_after: Duration::from_secs(1800),
        }
    }

    const INTERVAL: Duration = Duration::from_secs(60);

    #[test]
    fn sustained_failure_fires_only_after_the_full_duration() {
        let c = cfg(Duration::from_secs(240), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();

        // Four minutes of sustained trouble = five observations at a 60s interval.
        for i in 0..4 {
            let now = t0 + INTERVAL * i;
            assert_eq!(
                s.on_unhealthy(&c, INTERVAL, now),
                Transition::Quiet,
                "fired early at observation {i}"
            );
        }
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL * 4),
            Transition::Firing
        );
    }

    #[test]
    fn a_blind_gap_does_not_cash_in_as_elapsed_time() {
        // This is the regression that matters: blind for an hour, then a single
        // confirmed-bad reading must not page instantly.
        let c = cfg(Duration::from_secs(240), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();

        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Quiet);
        for i in 1..60 {
            assert_eq!(s.on_blind(), Transition::Quiet, "blind cycle {i}");
        }
        // An hour of wall clock has passed, but only one interval may be credited.
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(3600)),
            Transition::Quiet
        );
        assert!(
            s.unhealthy_for() <= INTERVAL,
            "one observation must never credit more than one interval"
        );
    }

    #[test]
    fn stale_evidence_does_not_complete_a_hold_down() {
        // Confirmed unhealthy, then blind for two hours, then confirmed again.
        // The old observation describes a situation we could not vouch for in
        // between, so the hold-down restarts rather than completing instantly.
        let c = cfg(Duration::from_secs(60), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Quiet);
        for _ in 0..120 {
            s.on_blind();
        }
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(7200)),
            Transition::Quiet,
            "evidence from before a two-hour gap must not complete the hold-down"
        );
        assert_eq!(s.unhealthy_for(), Duration::ZERO, "banked time should reset");
        // Two fresh observations then page legitimately.
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(7260)),
            Transition::Firing
        );
    }

    #[test]
    fn a_short_gap_does_not_discard_evidence() {
        // One missed cycle is normal; it must not restart the hold-down.
        let c = cfg(Duration::from_secs(180), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        s.on_unhealthy(&c, INTERVAL, t0);
        s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL);
        let banked = s.unhealthy_for();
        assert!(banked > Duration::ZERO);
        s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL * 3);
        assert!(s.unhealthy_for() > banked, "a two-interval gap should still count");
    }

    #[test]
    fn one_observation_can_never_satisfy_a_whole_hold_down() {
        // The regression: with a 2-minute hold-down and a 2-interval credit cap,
        // a single observation after a blind gap fired instantly.
        let c = cfg(Duration::from_secs(120), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Quiet);
        for _ in 0..120 {
            s.on_blind();
        }
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(7200)),
            Transition::Quiet,
            "a single post-blindness observation must not satisfy a 2m hold-down"
        );
    }

    #[test]
    fn blindness_never_resolves_a_live_incident() {
        let c = cfg(Duration::ZERO, 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        for _ in 0..100 {
            assert_eq!(s.on_blind(), Transition::Quiet);
        }
        assert!(s.is_firing(), "an unreachable RPC must not clear an incident");
    }

    #[test]
    fn resolve_requires_consecutive_healthy_observations() {
        let c = cfg(Duration::ZERO, 3);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);

        assert_eq!(s.on_healthy(&c, t0 + INTERVAL), Transition::Quiet);
        assert_eq!(s.on_healthy(&c, t0 + INTERVAL * 2), Transition::Quiet);
        assert_eq!(s.on_healthy(&c, t0 + INTERVAL * 3), Transition::Resolved);
        assert!(!s.is_firing());
    }

    /// Every resolve used to say "Recovered after 0s": the start time was
    /// cleared by the transition, before the caller could read it.
    #[test]
    fn a_resolve_reports_how_long_the_incident_lasted() {
        let c = cfg(Duration::ZERO, 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL);
        s.on_healthy(&c, t0 + INTERVAL * 2);
        assert_eq!(s.on_healthy(&c, t0 + INTERVAL * 3), Transition::Resolved);
        assert_eq!(s.incident_duration(t0 + INTERVAL * 3), INTERVAL * 3);
    }

    #[test]
    fn a_single_healthy_blip_does_not_reset_a_pending_timer() {
        // Flapping delinquency is a real problem; upstream's consecutive-failure
        // counter resets on any single success and so never alerts on it.
        let c = cfg(Duration::from_secs(120), 3);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        s.on_unhealthy(&c, INTERVAL, t0);
        s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL);
        let accumulated = s.unhealthy_for();
        assert_eq!(s.on_healthy(&c, t0 + INTERVAL * 2), Transition::Quiet);
        assert_eq!(
            s.unhealthy_for(),
            accumulated,
            "one healthy observation must not discard accumulated time"
        );
    }

    #[test]
    fn resolve_is_sent_under_the_same_key_as_the_trigger() {
        // If the key rotated on resolve, PagerDuty would receive a resolve for a
        // dedup key it has never seen and the real incident would never close.
        let c = cfg(Duration::ZERO, 1);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        let triggered_under = s.incident_key().to_string();
        assert_eq!(s.on_healthy(&c, t0 + INTERVAL), Transition::Resolved);
        assert_eq!(s.incident_key(), triggered_under);
    }

    #[test]
    fn the_next_occurrence_opens_a_distinct_incident() {
        let c = cfg(Duration::ZERO, 1);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        s.on_unhealthy(&c, INTERVAL, t0);
        let first = s.incident_key().to_string();
        s.on_healthy(&c, t0 + INTERVAL);
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL * 2),
            Transition::Firing
        );
        assert_ne!(s.incident_key(), first);
    }

    #[test]
    fn renotify_is_rate_limited() {
        let mut c = cfg(Duration::ZERO, 2);
        c.renotify_after = Duration::from_secs(600);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(300)),
            Transition::Quiet
        );
        assert_eq!(
            s.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(660)),
            Transition::Renotify
        );
    }

    #[test]
    fn a_permanently_inconclusive_check_is_reported_once() {
        // The cluster is visible, but this check never gets a definite answer --
        // for instance one endpoint's vote account query keeps failing, so the
        // confirmation quorum can never be met. Silently freezing forever would
        // mean the check is off and nobody knows.
        let mut s = CheckState::default();
        let t0 = Instant::now();
        let starve = Duration::from_secs(1200);

        for i in 0..20 {
            assert_eq!(
                s.on_unknown(starve, t0 + Duration::from_secs(60 * i)),
                Transition::Quiet
            );
        }
        assert_eq!(
            s.on_unknown(starve, t0 + Duration::from_secs(1260)),
            Transition::Starved
        );
        // Reported once, not once per cycle.
        for i in 22..40 {
            assert_eq!(
                s.on_unknown(starve, t0 + Duration::from_secs(60 * i)),
                Transition::Quiet
            );
        }
    }

    #[test]
    fn a_definite_answer_resets_starvation() {
        let c = cfg(Duration::from_secs(600), 1);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        let starve = Duration::from_secs(1200);

        s.on_unknown(starve, t0);
        assert_eq!(s.on_healthy(&c, t0 + Duration::from_secs(600)), Transition::Quiet);
        assert_eq!(s.inconclusive_for(t0 + Duration::from_secs(600)), Duration::ZERO);
        assert_eq!(
            s.on_unknown(starve, t0 + Duration::from_secs(660)),
            Transition::Quiet
        );
    }

    #[test]
    fn blind_cycles_do_not_accrue_starvation() {
        // Blindness has its own alert; reporting it again per check would turn
        // one outage into a burst of messages.
        let mut s = CheckState::default();
        let t0 = Instant::now();
        let starve = Duration::from_secs(600);
        for i in 0..60 {
            assert_eq!(s.on_blind(), Transition::Quiet, "blind cycle {i}");
        }
        assert_eq!(
            s.on_unknown(starve, t0 + Duration::from_secs(3600)),
            Transition::Quiet
        );
    }

    #[test]
    fn brief_blindness_stays_quiet_then_escalates() {
        let mut b = BlindnessState::default();
        let t0 = Instant::now();
        let notify = Duration::from_secs(300);
        let page = Duration::from_secs(1200);

        // Two minutes of total RPC failure: exactly the case that pages today.
        for i in 0..2 {
            assert_eq!(
                b.observe(false, notify, page, t0 + Duration::from_secs(60 * i)),
                BlindnessEvent::Quiet
            );
        }
        assert!(matches!(
            b.observe(false, notify, page, t0 + Duration::from_secs(360)),
            BlindnessEvent::Notify { .. }
        ));
        assert!(matches!(
            b.observe(false, notify, page, t0 + Duration::from_secs(1260)),
            BlindnessEvent::Page { .. }
        ));
    }

    #[test]
    fn blindness_escalation_happens_once_each() {
        let mut b = BlindnessState::default();
        let t0 = Instant::now();
        let (notify, page) = (Duration::from_secs(300), Duration::from_secs(1200));
        b.observe(false, notify, page, t0);
        b.observe(false, notify, page, t0 + Duration::from_secs(360));
        for i in 7..20 {
            assert_eq!(
                b.observe(false, notify, page, t0 + Duration::from_secs(60 * i)),
                BlindnessEvent::Quiet
            );
        }
    }

    #[test]
    fn recovery_is_only_announced_if_blindness_was() {
        let mut b = BlindnessState::default();
        let t0 = Instant::now();
        let (notify, page) = (Duration::from_secs(300), Duration::from_secs(1200));
        // Blind briefly, never announced -> recovery is silent.
        b.observe(false, notify, page, t0);
        assert_eq!(
            b.observe(true, notify, page, t0 + Duration::from_secs(60)),
            BlindnessEvent::Quiet
        );
        // Blind long enough to announce -> recovery is announced.
        b.observe(false, notify, page, t0 + Duration::from_secs(120));
        b.observe(false, notify, page, t0 + Duration::from_secs(480));
        assert!(matches!(
            b.observe(true, notify, page, t0 + Duration::from_secs(540)),
            BlindnessEvent::Recovered { .. }
        ));
    }

    #[test]
    fn a_restart_preserves_the_incident_key_so_the_resolve_lands() {
        // Without this, restarting perch during an incident leaves the
        // PagerDuty incident open forever: the resolve goes out under a fresh
        // UUID that PagerDuty has never seen.
        let c = cfg(Duration::ZERO, 1);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        let key = s.incident_key().to_string();

        let snap = s.snapshot(t0 + INTERVAL);
        let mut restored =
            CheckState::restore(&snap, Duration::from_secs(90), Instant::now());

        assert!(restored.is_firing());
        assert_eq!(restored.incident_key(), key);
        assert_eq!(
            restored.on_healthy(&c, Instant::now() + INTERVAL),
            Transition::Resolved
        );
        assert_eq!(restored.incident_key(), key, "resolve must use the original key");
    }

    #[test]
    fn a_restart_does_not_immediately_renotify() {
        // Restarting during an incident should not re-announce it. Deploys and
        // reboots are routine; each one should not cost the on-call a message.
        let mut c = cfg(Duration::ZERO, 2);
        c.renotify_after = Duration::from_secs(1800);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(s.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);

        let snap = s.snapshot(t0 + INTERVAL);
        let now = Instant::now();
        let mut restored = CheckState::restore(&snap, Duration::from_secs(5), now);

        assert_eq!(
            restored.on_unhealthy(&c, INTERVAL, now + INTERVAL),
            Transition::Quiet,
            "a restart must not re-announce a firing check"
        );
        // The reminder still arrives once the interval genuinely elapses.
        assert_eq!(
            restored.on_unhealthy(&c, INTERVAL, now + Duration::from_secs(1900)),
            Transition::Renotify
        );
    }

    #[test]
    fn a_restart_does_not_shorten_the_hold_down() {
        // Restoring `last_definite_at` from before the restart would let the
        // downtime itself be credited as sustained-unhealthy time.
        let c = cfg(Duration::from_secs(240), 2);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        s.on_unhealthy(&c, INTERVAL, t0);
        s.on_unhealthy(&c, INTERVAL, t0 + INTERVAL);
        let snap = s.snapshot(t0 + INTERVAL);

        let now = Instant::now();
        let mut restored = CheckState::restore(&snap, Duration::from_secs(3600), now);
        let before = restored.unhealthy_for();
        assert_eq!(restored.on_unhealthy(&c, INTERVAL, now), Transition::Quiet);
        assert_eq!(
            restored.unhealthy_for(),
            before,
            "the first observation after a restart must credit no elapsed time"
        );
    }

    #[test]
    fn a_restart_keeps_the_incident_duration_honest() {
        let c = cfg(Duration::ZERO, 1);
        let mut s = CheckState::default();
        let t0 = Instant::now();
        s.on_unhealthy(&c, INTERVAL, t0);
        // Pending for 5 minutes, then 10 minutes of downtime.
        let snap = s.snapshot(t0 + Duration::from_secs(300));
        let now = Instant::now();
        let restored = CheckState::restore(&snap, Duration::from_secs(600), now);
        assert_eq!(restored.incident_duration(now), Duration::from_secs(900));
    }

    #[test]
    fn silence_is_journal_only_unless_opted_into_telegram() {
        // Default: a silenced box is quiet on every channel except the journal.
        assert_eq!(effective_severity(Severity::Page, true, false), Severity::Log);
        assert_eq!(effective_severity(Severity::Notify, true, false), Severity::Log);
        // Not silenced: nothing changes.
        assert_eq!(effective_severity(Severity::Page, false, false), Severity::Page);
        assert_eq!(effective_severity(Severity::Notify, false, false), Severity::Notify);
        // Opt back in to the old timeline-on-Telegram behaviour.
        assert_eq!(effective_severity(Severity::Page, true, true), Severity::Notify);
        assert_eq!(effective_severity(Severity::Notify, true, true), Severity::Notify);
    }

    #[test]
    fn an_auto_silence_waits_for_recovery_with_a_deadline() {
        let dir = std::env::temp_dir().join(format!("perch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("silence");
        std::fs::write(&path, "auto 2099-01-01T00:00:00Z").unwrap();
        let now = chrono::Utc::now();
        match read_silence(Some(path.to_str().unwrap()), now) {
            Silence::UntilRecovered { deadline } => assert!(deadline > now),
            other => panic!("expected UntilRecovered, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_auto_silence_without_a_deadline_defaults_to_an_hour() {
        // A malformed file must not silence a validator forever.
        let dir = std::env::temp_dir().join(format!("perch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("silence");
        std::fs::write(&path, "auto").unwrap();
        let now = chrono::Utc::now();
        match read_silence(Some(path.to_str().unwrap()), now) {
            Silence::UntilRecovered { deadline } => {
                let hours = (deadline - now).num_minutes();
                assert!((55..=65).contains(&hours), "got {hours} minutes");
            }
            other => panic!("expected UntilRecovered, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn expired_silence_file_stops_silencing() {
        let dir = std::env::temp_dir().join(format!("perch-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("silence");
        std::fs::write(&path, "2020-01-01T00:00:00Z").unwrap();
        let p = path.to_str().unwrap();
        assert!(!silence_active(Some(p), chrono::Utc::now()));

        std::fs::write(&path, "2999-01-01T00:00:00Z").unwrap();
        assert!(silence_active(Some(p), chrono::Utc::now()));

        std::fs::write(&path, "").unwrap();
        assert!(silence_active(Some(p), chrono::Utc::now()));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absent_silence_file_does_not_silence() {
        assert!(!silence_active(Some("/nonexistent/perch/silence"), chrono::Utc::now()));
        assert!(!silence_active(None, chrono::Utc::now()));
    }
}

#[cfg(test)]
mod renotify_cadence {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(60);

    fn cfg(renotify: Duration) -> CheckConfig {
        CheckConfig {
            enabled: true,
            pending_for: Duration::ZERO,
            clear_after: 1,
            severity: Severity::Page,
            renotify_after: renotify,
        }
    }

    /// A slow drain measured in days produced four identical "still firing"
    /// messages in 90 minutes. Zero means say it once and stop.
    #[test]
    fn zero_renotify_says_it_once() {
        let c = cfg(Duration::ZERO);
        let mut st = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(st.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        for mins in [30u64, 60, 120, 1440] {
            let later = t0 + Duration::from_secs(mins * 60);
            assert_eq!(
                st.on_unhealthy(&c, INTERVAL, later),
                Transition::Quiet,
                "must stay quiet {mins} minutes after firing"
            );
        }
    }

    /// A non-zero interval still repeats, for checks where it earns its place.
    #[test]
    fn a_nonzero_interval_still_repeats() {
        let c = cfg(Duration::from_secs(1800));
        let mut st = CheckState::default();
        let t0 = Instant::now();
        assert_eq!(st.on_unhealthy(&c, INTERVAL, t0), Transition::Firing);
        assert_eq!(st.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(600)), Transition::Quiet);
        assert_eq!(st.on_unhealthy(&c, INTERVAL, t0 + Duration::from_secs(1800)), Transition::Renotify);
    }

    /// The identity balance default, which is what the fleet actually runs.
    #[test]
    fn the_identity_balance_default_is_fire_once_and_page_at_half_a_sol() {
        let c = crate::config::Checks::default().identity_balance;
        assert_eq!(c.base.renotify_after, Duration::ZERO, "must not repeat");
        assert_eq!(c.page_sol, 0.5);
        assert_eq!(c.warn_sol, 3.0);
        assert!(c.page_sol < c.warn_sol, "bands must not overlap");
    }
}

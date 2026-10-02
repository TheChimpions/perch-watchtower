//! Projecting time-to-full from observed free space.
//!
//! A percentage threshold is the wrong primary signal for a validator. 85% of a
//! 4TB disk is 600GB of headroom; 85% of a 500GB disk is 75GB. And because the
//! ledger and accounts database grow continuously, what actually matters is how
//! long you have: a disk at 60% filling at 40GB/hour needs attention today,
//! while one sitting flat at 88% may not need any.
//!
//! So the paging signal is projected time-to-full, with a free-space floor as
//! the backstop.
//!
//! Free space on a validator is a sawtooth -- snapshots accumulate and are
//! purged -- so the slope is fitted by least squares over a multi-hour window
//! rather than taken from the last two samples, which would alternate between
//! "filling instantly" and "never filling".

use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::Duration};

#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    /// Not enough history to say anything yet. Maps to `Unknown`, never to
    /// `Healthy`: "we have not been watching long enough" is not "fine".
    Insufficient { have: Duration, need: Duration },
    /// Flat or draining.
    NotFilling,
    Filling {
        time_to_full: Duration,
        bytes_per_sec: f64,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FillHistory {
    /// `(unix_seconds, avail_bytes)`, oldest first.
    samples: VecDeque<(u64, u64)>,
}

impl FillHistory {
    /// Record a sample, thinning to at most one per `sample_every` and dropping
    /// anything older than `window`.
    ///
    /// Thinning matters: at a 60-second interval an unthinned 6-hour window
    /// would hold 360 points per filesystem, all of it persisted to disk every
    /// cycle, to compute a single slope that a dozen points estimate just as
    /// well.
    pub fn record(&mut self, now_unix: u64, avail_bytes: u64, sample_every: Duration, window: Duration) {
        let too_soon = self
            .samples
            .back()
            .map(|(t, _)| now_unix.saturating_sub(*t) < sample_every.as_secs())
            .unwrap_or(false);
        if too_soon {
            return;
        }

        self.samples.push_back((now_unix, avail_bytes));

        let cutoff = now_unix.saturating_sub(window.as_secs());
        while self
            .samples
            .front()
            .map(|(t, _)| *t < cutoff)
            .unwrap_or(false)
        {
            self.samples.pop_front();
        }
    }

    pub fn span(&self) -> Duration {
        match (self.samples.front(), self.samples.back()) {
            (Some((first, _)), Some((last, _))) => Duration::from_secs(last.saturating_sub(*first)),
            _ => Duration::ZERO,
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Least-squares fit of available bytes against time.
    ///
    /// `min_span` guards against projecting from a couple of minutes of noise,
    /// which on a sawtooth would routinely predict the disk filling in seconds.
    pub fn project(&self, min_span: Duration, min_samples: usize) -> Projection {
        let span = self.span();
        if self.samples.len() < min_samples.max(2) || span < min_span {
            return Projection::Insufficient {
                have: span,
                need: min_span,
            };
        }

        // Times are taken relative to the first sample: squaring raw unix
        // timestamps loses precision in f64.
        let t0 = self.samples.front().map(|(t, _)| *t).unwrap_or(0);
        let n = self.samples.len() as f64;
        let (mut sum_t, mut sum_y, mut sum_ty, mut sum_tt) = (0.0, 0.0, 0.0, 0.0);
        for (t, y) in &self.samples {
            let t = t.saturating_sub(t0) as f64;
            let y = *y as f64;
            sum_t += t;
            sum_y += y;
            sum_ty += t * y;
            sum_tt += t * t;
        }

        let denom = n * sum_tt - sum_t * sum_t;
        if denom.abs() < f64::EPSILON {
            return Projection::Insufficient {
                have: span,
                need: min_span,
            };
        }

        // Bytes of available space gained per second; negative means filling.
        let slope = (n * sum_ty - sum_t * sum_y) / denom;
        if !slope.is_finite() || slope >= 0.0 {
            return Projection::NotFilling;
        }

        let latest_avail = self.samples.back().map(|(_, y)| *y).unwrap_or(0) as f64;
        let seconds = latest_avail / -slope;
        if !seconds.is_finite() || seconds < 0.0 {
            return Projection::NotFilling;
        }

        // Saturate rather than overflow on a nearly-flat slope.
        let capped = seconds.min(u64::MAX as f64 / 2.0) as u64;
        Projection::Filling {
            time_to_full: Duration::from_secs(capped),
            bytes_per_sec: -slope,
        }
    }
}

/// Human-readable fill rate, e.g. "42.1 GB/hour".
pub fn rate_per_hour(bytes_per_sec: f64) -> String {
    let gb_per_hour = bytes_per_sec * 3600.0 / crate::node_exporter::BYTES_PER_GB;
    if gb_per_hour >= 1.0 {
        format!("{gb_per_hour:.1} GB/hour")
    } else {
        format!("{:.0} MB/hour", gb_per_hour * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1_073_741_824;
    const EVERY: Duration = Duration::from_secs(300);
    const WINDOW: Duration = Duration::from_secs(6 * 3600);
    const MIN_SPAN: Duration = Duration::from_secs(45 * 60);

    fn history(points: &[(u64, u64)]) -> FillHistory {
        let mut h = FillHistory::default();
        for (t, avail) in points {
            h.record(*t, *avail, Duration::ZERO, WINDOW);
        }
        h
    }

    #[test]
    fn insufficient_history_is_not_healthy() {
        let h = history(&[(0, 100 * GB), (300, 99 * GB)]);
        assert!(matches!(
            h.project(MIN_SPAN, 4),
            Projection::Insufficient { .. }
        ));
    }

    #[test]
    fn a_steady_disk_is_not_filling() {
        let pts: Vec<_> = (0..12).map(|i| (i * 300, 100 * GB)).collect();
        assert_eq!(history(&pts).project(MIN_SPAN, 4), Projection::NotFilling);
    }

    #[test]
    fn a_draining_disk_is_not_filling() {
        // Someone is deleting things; free space rising.
        let pts: Vec<_> = (0..12).map(|i| (i * 300, (50 + i) * GB)).collect();
        assert_eq!(history(&pts).project(MIN_SPAN, 4), Projection::NotFilling);
    }

    #[test]
    fn projects_time_to_full_from_a_steady_fill() {
        // 100GB free, losing 10GB/hour -> full in ~10 hours.
        let pts: Vec<_> = (0..13)
            .map(|i| {
                let t = i * 300;
                let lost = (10.0 * GB as f64 / 3600.0) * t as f64;
                (t, (100.0 * GB as f64 - lost) as u64)
            })
            .collect();
        match history(&pts).project(MIN_SPAN, 4) {
            Projection::Filling { time_to_full, bytes_per_sec } => {
                let hours = time_to_full.as_secs_f64() / 3600.0;
                // One hour has already elapsed, so ~9 hours remain.
                assert!((hours - 9.0).abs() < 0.3, "projected {hours} hours");
                let gb_hr = bytes_per_sec * 3600.0 / GB as f64;
                assert!((gb_hr - 10.0).abs() < 0.2, "rate {gb_hr} GB/hour");
            }
            other => panic!("expected Filling, got {other:?}"),
        }
    }

    #[test]
    fn a_snapshot_purge_sawtooth_does_not_read_as_instantly_full() {
        // Free space falls steadily, then jumps back up when snapshots are
        // purged. Taking the slope from the last two samples would alternate
        // between "full in minutes" and "never"; the fit sees the real trend.
        let mut pts = Vec::new();
        let mut avail = 400.0 * GB as f64;
        for i in 0..72u64 {
            let t = i * 300;
            avail -= 2.0 * GB as f64; // steady growth
            if i % 12 == 11 {
                avail += 20.0 * GB as f64; // purge
            }
            pts.push((t, avail.max(0.0) as u64));
        }
        match history(&pts).project(MIN_SPAN, 4) {
            Projection::Filling { time_to_full, .. } => {
                let hours = time_to_full.as_secs_f64() / 3600.0;
                assert!(hours > 5.0, "sawtooth projected an alarmist {hours} hours");
            }
            // Net-flat across the window is an acceptable read too; alarmist is not.
            Projection::NotFilling => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn samples_are_thinned_to_the_configured_cadence() {
        let mut h = FillHistory::default();
        // One sample per minute offered, five-minute cadence requested.
        for i in 0..60u64 {
            h.record(i * 60, 100 * GB, EVERY, WINDOW);
        }
        assert!(h.len() <= 13, "kept {} samples, expected ~12", h.len());
        assert!(h.len() >= 11);
    }

    #[test]
    fn samples_older_than_the_window_are_dropped() {
        let mut h = FillHistory::default();
        for i in 0..200u64 {
            h.record(i * 300, 100 * GB, EVERY, WINDOW);
        }
        assert!(h.span() <= WINDOW, "span {:?} exceeds window", h.span());
    }

    #[test]
    fn an_already_full_disk_projects_zero_not_a_panic() {
        let pts: Vec<_> = (0..13)
            .map(|i| (i * 300, (10 * GB).saturating_sub(i * GB)))
            .collect();
        match history(&pts).project(MIN_SPAN, 4) {
            Projection::Filling { time_to_full, .. } => {
                assert!(time_to_full.as_secs() < 3600);
            }
            other => panic!("expected Filling, got {other:?}"),
        }
    }

    #[test]
    fn identical_timestamps_do_not_divide_by_zero() {
        let pts: Vec<_> = (0..10).map(|_| (1000u64, 50 * GB)).collect();
        assert!(matches!(
            history(&pts).project(MIN_SPAN, 4),
            Projection::Insufficient { .. }
        ));
    }

    #[test]
    fn rates_render_readably() {
        assert_eq!(rate_per_hour(10.0 * GB as f64 / 3600.0), "10.0 GB/hour");
        assert!(rate_per_hour(GB as f64 / 3600.0 / 10.0).ends_with("MB/hour"));
    }
}

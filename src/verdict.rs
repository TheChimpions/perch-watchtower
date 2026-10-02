//! The tri-state verdict.
//!
//! agave-watchtower has exactly two states: a check either passed or it produced
//! a `failures` entry. An RPC timeout lands in `failures`, so "I could not reach
//! the network" is indistinguishable from "your validator is delinquent", and both
//! page you.
//!
//! Here, evidence about the validator and evidence about the observability path are
//! different types. `Unknown` can never be promoted into `Unhealthy` -- there is no
//! constructor and no code path that does it. Transport failures produce `Unknown`
//! and `Unknown` never fires an alert, so the entire class of
//! `rpc-error: operation timed out` pages is impossible by construction rather than
//! by a suppression flag someone has to remember to set.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The endpoint answered, and the answer says things are fine.
    Healthy,
    /// The endpoint answered, the answer is well-formed, and it says things are broken.
    /// This is the *only* variant that can ever lead to a notification.
    Unhealthy(String),
    /// We do not know. Timeout, rate limit, 502, connection reset, garbage JSON,
    /// a field the node declined to populate. Carries no information about the
    /// validator, and is never counted as evidence of a problem.
    Unknown(String),
}

impl Verdict {
    pub fn unhealthy(detail: impl Into<String>) -> Self {
        Verdict::Unhealthy(detail.into())
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        Verdict::Unknown(reason.into())
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Verdict::Unhealthy(d) => Some(d),
            _ => None,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Healthy => write!(f, "healthy"),
            Verdict::Unhealthy(d) => write!(f, "unhealthy: {d}"),
            Verdict::Unknown(r) => write!(f, "unknown: {r}"),
        }
    }
}

/// How many independent endpoints said what, for one check, in one cycle.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    pub healthy: usize,
    pub unhealthy: usize,
    pub unknown: usize,
    /// Distinct `Unhealthy` details, for the alert body.
    pub details: Vec<String>,
    /// Distinct `Unknown` reasons, so an inconclusive cycle is diagnosable
    /// rather than logging a generic "no usable answer".
    pub reasons: Vec<String>,
}

impl Tally {
    pub fn definite(&self) -> usize {
        self.healthy + self.unhealthy
    }
}

/// Fold per-endpoint verdicts into one, requiring independent corroboration.
///
/// A check may only be declared `Unhealthy` when at least `min_confirmations`
/// endpoints independently say so *and* no larger group of endpoints disagrees.
/// One flaky provider returning nonsense cannot drag the cluster view with it.
pub fn aggregate(verdicts: &[(String, Verdict)], min_confirmations: usize) -> (Verdict, Tally) {
    let mut tally = Tally::default();

    for (_, v) in verdicts {
        match v {
            Verdict::Healthy => tally.healthy += 1,
            Verdict::Unhealthy(d) => {
                tally.unhealthy += 1;
                if !tally.details.contains(d) {
                    tally.details.push(d.clone());
                }
            }
            Verdict::Unknown(r) => {
                tally.unknown += 1;
                if !tally.reasons.contains(r) {
                    tally.reasons.push(r.clone());
                }
            }
        }
    }

    // Never let a check fire on fewer corroborating sources than we actually have
    // available -- with a single reachable endpoint, `min_confirmations` of 2 is
    // unsatisfiable and the check correctly stays Unknown rather than firing blind.
    let confirmed = tally.unhealthy >= min_confirmations && tally.unhealthy > tally.healthy;

    let verdict = if confirmed {
        Verdict::Unhealthy(tally.details.join("; "))
    } else if tally.healthy > 0 {
        Verdict::Healthy
    } else if tally.unhealthy > 0 {
        // Some endpoints report trouble but not enough to corroborate. Not healthy,
        // not confirmed -- explicitly unknown, so the check's timer freezes instead
        // of resetting. A real problem seen by one endpoint will keep accumulating
        // as other endpoints come back.
        Verdict::Unknown(format!(
            "{} endpoint(s) report trouble, below the {min_confirmations} needed to confirm: {}",
            tally.unhealthy,
            tally.details.join("; ")
        ))
    } else if tally.reasons.is_empty() {
        Verdict::Unknown("no endpoint returned a usable answer".into())
    } else {
        Verdict::Unknown(tally.reasons.join("; "))
    };

    (verdict, tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(pairs: Vec<(&str, Verdict)>) -> Vec<(String, Verdict)> {
        pairs.into_iter().map(|(n, v)| (n.to_string(), v)).collect()
    }

    #[test]
    fn all_timeouts_never_produce_unhealthy() {
        let (verdict, tally) = aggregate(
            &v(vec![
                ("a", Verdict::unknown("operation timed out")),
                ("b", Verdict::unknown("operation timed out")),
                ("c", Verdict::unknown("429 Too Many Requests")),
            ]),
            2,
        );
        assert!(matches!(verdict, Verdict::Unknown(_)));
        assert_eq!(tally.definite(), 0);
    }

    #[test]
    fn single_endpoint_cannot_confirm_when_two_required() {
        let (verdict, _) = aggregate(
            &v(vec![
                ("a", Verdict::unhealthy("delinquent")),
                ("b", Verdict::unknown("timed out")),
            ]),
            2,
        );
        assert!(matches!(verdict, Verdict::Unknown(_)));
    }

    #[test]
    fn corroborated_failure_confirms() {
        let (verdict, tally) = aggregate(
            &v(vec![
                ("a", Verdict::unhealthy("delinquent")),
                ("b", Verdict::unhealthy("delinquent")),
                ("c", Verdict::unknown("timed out")),
            ]),
            2,
        );
        assert_eq!(verdict, Verdict::Unhealthy("delinquent".into()));
        assert_eq!(tally.unhealthy, 2);
    }

    #[test]
    fn majority_healthy_overrides_minority_unhealthy() {
        let (verdict, _) = aggregate(
            &v(vec![
                ("a", Verdict::unhealthy("delinquent")),
                ("b", Verdict::Healthy),
                ("c", Verdict::Healthy),
            ]),
            1,
        );
        assert_eq!(verdict, Verdict::Healthy);
    }

    #[test]
    fn preserves_the_specific_reason_a_cycle_was_inconclusive() {
        let (verdict, tally) = aggregate(
            &v(vec![
                ("a", Verdict::unknown("operation timed out")),
                ("b", Verdict::unknown("rate limited (429)")),
            ]),
            2,
        );
        assert_eq!(tally.reasons.len(), 2);
        match verdict {
            Verdict::Unknown(r) => {
                assert!(r.contains("timed out") && r.contains("429"), "got {r}")
            }
            other => panic!("expected Unknown, got {other}"),
        }
    }

    #[test]
    fn deduplicates_identical_details() {
        let (_, tally) = aggregate(
            &v(vec![
                ("a", Verdict::unhealthy("chimps-1 delinquent")),
                ("b", Verdict::unhealthy("chimps-1 delinquent")),
            ]),
            2,
        );
        assert_eq!(tally.details.len(), 1);
    }
}

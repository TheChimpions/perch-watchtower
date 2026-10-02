//! Alert inhibition.
//!
//! A delinquent validator is, necessarily and simultaneously, a validator whose
//! last vote is stale, whose root slot is stale, and whose vote credits have
//! stopped. Without inhibition that single event opens four PagerDuty incidents.
//! Prometheus solves this with `inhibit_rules`; this is the same idea, keyed on
//! the per-validator check IDs.
//!
//! Inhibition is computed from *this cycle's verdicts*, not from which checks
//! happen to be firing, so it does not depend on two checks crossing their
//! hold-downs in the same cycle.

use crate::{checks::CheckOutcome, verdict::Verdict};
use std::collections::HashMap;

/// `(cause, symptoms)`. If `cause` is confirmed unhealthy, every `symptom` for
/// the same subject is a consequence of it rather than separate news.
///
/// Ordered widest-cause-first: a cluster-wide halt explains everything, a
/// missing vote account explains delinquency, delinquency explains the lag and
/// credit checks.
const RULES: &[(&str, &[&str])] = &[
    (
        "cluster_stalled",
        &[
            "vote_delinquent",
            "vote_account_missing",
            "vote_lag",
            "root_lag",
            "vote_stalled",
        ],
    ),
    (
        "vote_account_missing",
        &["vote_delinquent", "vote_lag", "root_lag", "vote_stalled"],
    ),
    ("vote_delinquent", &["vote_lag", "root_lag", "vote_stalled"]),
    // Deliberately absent: vote_admission_critical inhibiting delinquency. It
    // is about the *next* boundary, so while it fires the validator is still
    // admitted to the current epoch, and a delinquency now is a different
    // failure. Folding it in would hide a crash behind "will be excluded".
    ("vote_admission_critical", &["vote_admission_warn"]),
    // A machine that is gone explains its own monitor being silent.
    ("machine_down", &["peer_down"]),
    // A read-only filesystem is not filling, and its free space is moot.
    (
        "disk_readonly",
        &[
            "disk_space_critical",
            "disk_space_warn",
            "disk_fill_critical",
            "disk_fill_warn",
            "disk_inodes_critical",
            "disk_inodes_warn",
        ],
    ),
    // Already below the floor; a projection of when it will get there adds
    // nothing.
    (
        "disk_space_critical",
        &["disk_fill_critical", "disk_fill_warn"],
    ),
];

/// Rules that cross from a host to the validator running on it.
///
/// A full or read-only ledger disk will take the validator delinquent. Without
/// this you get two pages for one event, and the one that arrives first is the
/// symptom. "chimps-1 ledger disk full" is a far more actionable page than
/// "chimps-1 delinquent", so the disk cause wins and the delinquency folds into
/// its body.
///
/// Requires the host to declare `validator = "<label>"`; unlinked hosts inhibit
/// nothing, because nothing tells us whose disk it is.
const CROSS_RULES: &[(&str, &[&str])] = &[
    (
        "disk_readonly",
        &["vote_delinquent", "vote_lag", "root_lag", "vote_stalled"],
    ),
    (
        "disk_space_critical",
        &["vote_delinquent", "vote_lag", "root_lag", "vote_stalled"],
    ),
    // The machine is gone. "chimps-1's machine is hard down" is the page worth
    // reading; "chimps-1 delinquent" is a consequence of it.
    (
        "machine_down",
        &["vote_delinquent", "vote_lag", "root_lag", "vote_stalled"],
    ),
];

/// Split a check id into its `(kind, subject)`. Cluster-wide checks have no
/// subject and inhibit every subject.
fn split(id: &str) -> (&str, Option<&str>) {
    match id.split_once(':') {
        Some((kind, subject)) => (kind, Some(subject)),
        None => (id, None),
    }
}

/// Map of `suppressed check id -> the check id explaining it`.
pub fn compute(outcomes: &[CheckOutcome]) -> HashMap<String, String> {
    let unhealthy: Vec<(&str, Option<&str>, &str, Option<&str>)> = outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Unhealthy(_)))
        .map(|o| {
            let (kind, subject) = split(&o.id);
            (kind, subject, o.id.as_str(), o.owner.as_deref())
        })
        .collect();

    let mut suppressed = HashMap::new();

    for (cause_kind, symptom_kinds) in RULES {
        for (kind, cause_subject, cause_id, _) in &unhealthy {
            if kind != cause_kind {
                continue;
            }
            for o in outcomes {
                let (sym_kind, sym_subject) = split(&o.id);
                if !symptom_kinds.contains(&sym_kind) {
                    continue;
                }
                // A cluster-wide cause covers every validator; a per-validator
                // cause only covers its own.
                if cause_subject.is_some() && cause_subject != &sym_subject {
                    continue;
                }
                if o.id == *cause_id {
                    continue;
                }
                suppressed
                    .entry(o.id.clone())
                    .or_insert_with(|| cause_id.to_string());
            }
        }
    }

    // Host-to-validator: the cause's owner must be the symptom's subject.
    for (cause_kind, symptom_kinds) in CROSS_RULES {
        for (kind, _, cause_id, owner) in &unhealthy {
            if kind != cause_kind {
                continue;
            }
            let Some(owner) = owner else { continue };
            for o in outcomes {
                let (sym_kind, sym_subject) = split(&o.id);
                if !symptom_kinds.contains(&sym_kind) || sym_subject != Some(*owner) {
                    continue;
                }
                suppressed
                    .entry(o.id.clone())
                    .or_insert_with(|| cause_id.to_string());
            }
        }
    }

    // A cause that is itself suppressed by a wider cause cannot go on to explain
    // anything: during a cluster halt the page should say "cluster halted", not
    // "delinquent". Resolving transitively keeps one root cause per subject.
    let mut resolved: HashMap<String, String> = HashMap::new();
    for (symptom, cause) in &suppressed {
        let mut root = cause.clone();
        // The bound guarantees termination if a cycle is ever introduced.
        for _ in 0..RULES.len() + CROSS_RULES.len() {
            match suppressed.get(&root) {
                Some(next) if *next != root => root = next.clone(),
                _ => break,
            }
        }
        resolved.insert(symptom.clone(), root);
    }
    resolved
}

/// Human-readable symptom list for the surviving alert's body.
pub fn symptoms_of<'a>(
    cause_id: &str,
    suppressed: &HashMap<String, String>,
    outcomes: &'a [CheckOutcome],
) -> Vec<&'a str> {
    let mut out: Vec<&str> = outcomes
        .iter()
        .filter(|o| suppressed.get(&o.id).map(|c| c == cause_id).unwrap_or(false))
        .filter_map(|o| o.verdict.detail())
        .collect();
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CheckConfig, Severity};
    use crate::verdict::Tally;
    use std::time::Duration;

    fn outcome(id: &str, verdict: Verdict) -> CheckOutcome {
        CheckOutcome {
            id: id.into(),
            title: id.into(),
            cfg: CheckConfig {
                enabled: true,
                pending_for: Duration::ZERO,
                clear_after: 1,
                severity: Severity::Page,
                renotify_after: Duration::ZERO,
            },
            verdict,
            tally: Tally::default(),
            warming_up: false,
            owner: None,
        }
    }

    fn owned(id: &str, owner: &str) -> CheckOutcome {
        CheckOutcome {
            owner: Some(owner.to_string()),
            ..bad(id)
        }
    }

    fn bad(id: &str) -> CheckOutcome {
        outcome(id, Verdict::unhealthy(format!("{id} is bad")))
    }

    #[test]
    fn delinquency_absorbs_its_own_symptoms() {
        // The exact case measured against the real binary: one delinquency
        // producing four pages.
        let outcomes = vec![
            bad("vote_delinquent:chimps-1"),
            bad("vote_lag:chimps-1"),
            bad("root_lag:chimps-1"),
            bad("vote_stalled:chimps-1"),
        ];
        let s = compute(&outcomes);
        assert_eq!(s.len(), 3);
        for sym in ["vote_lag", "root_lag", "vote_stalled"] {
            assert_eq!(
                s.get(&format!("{sym}:chimps-1")).map(String::as_str),
                Some("vote_delinquent:chimps-1")
            );
        }
        assert!(!s.contains_key("vote_delinquent:chimps-1"));
    }

    #[test]
    fn inhibition_does_not_cross_validators() {
        let outcomes = vec![bad("vote_delinquent:chimps-1"), bad("vote_lag:chimps-2")];
        let s = compute(&outcomes);
        assert!(
            !s.contains_key("vote_lag:chimps-2"),
            "one validator's delinquency must not mask another's lag"
        );
    }

    #[test]
    fn a_cluster_halt_explains_every_validator() {
        let outcomes = vec![
            bad("cluster_stalled"),
            bad("vote_delinquent:chimps-1"),
            bad("vote_lag:chimps-1"),
            bad("vote_delinquent:chimps-2"),
        ];
        let s = compute(&outcomes);
        assert_eq!(s.get("vote_delinquent:chimps-1").map(String::as_str), Some("cluster_stalled"));
        assert_eq!(s.get("vote_delinquent:chimps-2").map(String::as_str), Some("cluster_stalled"));
        // Transitive: lag is explained by the halt, not by the delinquency that
        // is itself explained by the halt.
        assert_eq!(s.get("vote_lag:chimps-1").map(String::as_str), Some("cluster_stalled"));
        assert!(!s.contains_key("cluster_stalled"));
    }

    #[test]
    fn a_healthy_check_inhibits_nothing() {
        let outcomes = vec![
            outcome("vote_delinquent:chimps-1", Verdict::Healthy),
            bad("vote_lag:chimps-1"),
        ];
        assert!(compute(&outcomes).is_empty());
    }

    #[test]
    fn an_unknown_cause_inhibits_nothing() {
        // Inhibition must require confirmed evidence. Suppressing a real lag
        // alert because delinquency was merely inconclusive would hide it.
        let outcomes = vec![
            outcome("vote_delinquent:chimps-1", Verdict::unknown("timed out")),
            bad("vote_lag:chimps-1"),
        ];
        assert!(compute(&outcomes).is_empty());
    }

    #[test]
    fn unrelated_checks_are_never_inhibited() {
        let outcomes = vec![
            bad("vote_delinquent:chimps-1"),
            bad("identity_balance_critical:chimps-1"),
            bad("commission_changed:chimps-1"),
        ];
        let s = compute(&outcomes);
        assert!(!s.contains_key("identity_balance_critical:chimps-1"));
        assert!(
            !s.contains_key("commission_changed:chimps-1"),
            "a possible key compromise must never be masked by delinquency"
        );
    }

    #[test]
    fn a_downed_machine_explains_its_validators_delinquency() {
        let outcomes = vec![
            owned("machine_down:chimps-1-box", "chimps-1"),
            bad("peer_down:chimps-1-box"),
            bad("vote_delinquent:chimps-1"),
            bad("vote_lag:chimps-1"),
        ];
        let s = compute(&outcomes);
        assert_eq!(
            s.get("vote_delinquent:chimps-1").map(String::as_str),
            Some("machine_down:chimps-1-box")
        );
        assert_eq!(
            s.get("peer_down:chimps-1-box").map(String::as_str),
            Some("machine_down:chimps-1-box")
        );
        assert!(!s.contains_key("machine_down:chimps-1-box"));
    }

    #[test]
    fn a_silent_peer_alone_masks_nothing() {
        // peer_down means lost visibility, not an outage; it must never
        // suppress a real delinquency alert.
        let outcomes = vec![
            bad("peer_down:chimps-1-box"),
            bad("vote_delinquent:chimps-1"),
        ];
        assert!(!compute(&outcomes).contains_key("vote_delinquent:chimps-1"));
    }

    #[test]
    fn a_read_only_filesystem_absorbs_its_own_space_and_fill_checks() {
        let outcomes = vec![
            bad("disk_readonly:host-a /mnt/ledger"),
            bad("disk_space_critical:host-a /mnt/ledger"),
            bad("disk_fill_critical:host-a /mnt/ledger"),
        ];
        let s = compute(&outcomes);
        assert_eq!(
            s.get("disk_space_critical:host-a /mnt/ledger").map(String::as_str),
            Some("disk_readonly:host-a /mnt/ledger")
        );
        assert_eq!(
            s.get("disk_fill_critical:host-a /mnt/ledger").map(String::as_str),
            Some("disk_readonly:host-a /mnt/ledger")
        );
    }

    #[test]
    fn a_full_disk_explains_the_delinquency_it_causes() {
        // One page naming the root cause, not two describing the same event.
        let outcomes = vec![
            owned("disk_space_critical:host-a /mnt/ledger", "chimps-1"),
            bad("vote_delinquent:chimps-1"),
            bad("vote_lag:chimps-1"),
        ];
        let s = compute(&outcomes);
        assert_eq!(
            s.get("vote_delinquent:chimps-1").map(String::as_str),
            Some("disk_space_critical:host-a /mnt/ledger")
        );
        assert_eq!(
            s.get("vote_lag:chimps-1").map(String::as_str),
            Some("disk_space_critical:host-a /mnt/ledger"),
            "transitively, the disk explains the lag too"
        );
        assert!(!s.contains_key("disk_space_critical:host-a /mnt/ledger"));
    }

    #[test]
    fn an_unlinked_host_does_not_inhibit_any_validator() {
        // Without `validator = "..."` on the host there is nothing to say whose
        // disk it is, so suppressing a delinquency would be a guess.
        let outcomes = vec![
            bad("disk_space_critical:host-a /mnt/ledger"),
            bad("vote_delinquent:chimps-1"),
        ];
        assert!(!compute(&outcomes).contains_key("vote_delinquent:chimps-1"));
    }

    #[test]
    fn a_disk_problem_on_one_host_does_not_mask_another_validator() {
        let outcomes = vec![
            owned("disk_space_critical:host-a /mnt/ledger", "chimps-1"),
            bad("vote_delinquent:chimps-2"),
        ];
        assert!(!compute(&outcomes).contains_key("vote_delinquent:chimps-2"));
    }

    #[test]
    fn a_disk_warning_does_not_mask_a_delinquency() {
        // Only the critical band crosses over. A disk merely trending low is
        // not evidence that it caused anything.
        let outcomes = vec![
            owned("disk_space_warn:host-a /mnt/ledger", "chimps-1"),
            bad("vote_delinquent:chimps-1"),
        ];
        assert!(!compute(&outcomes).contains_key("vote_delinquent:chimps-1"));
    }

    #[test]
    fn symptoms_are_listed_for_the_surviving_alert() {
        let outcomes = vec![
            bad("vote_delinquent:chimps-1"),
            bad("vote_lag:chimps-1"),
            bad("root_lag:chimps-1"),
        ];
        let s = compute(&outcomes);
        let listed = symptoms_of("vote_delinquent:chimps-1", &s, &outcomes);
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|d| d.contains("vote_lag")));
    }
}

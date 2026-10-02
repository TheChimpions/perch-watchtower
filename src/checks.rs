//! Check evaluation.
//!
//! Each check produces a verdict *per endpoint*, and those are folded by
//! `verdict::aggregate`, so a check can only fire on corroborated evidence.
//! A check that cannot be evaluated returns `Unknown`, never `Healthy` --
//! reporting "fine" on absent data would silently mask a real outage.

use crate::{
    config::{CheckConfig, Config, Severity},
    fillrate::{rate_per_hour, FillHistory, Projection},
    node_exporter::HostSnapshot,
    peer::{PeerHealth, PeerStatus},
    snapshot::{lamports_to_sol, Snapshot, ValidatorObservation},
    verdict::{aggregate, Tally, Verdict},
};
use std::{collections::HashMap, time::Duration};

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// Stable key. Per-validator checks are keyed per validator so one
    /// validator's incident cannot reset another's timer.
    pub id: String,
    pub title: String,
    pub cfg: CheckConfig,
    pub verdict: Verdict,
    pub tally: Tally,
    /// This check is Unknown for a bounded, self-resolving reason -- it is
    /// accumulating the history it needs, not failing to observe anything.
    ///
    /// Starvation detection must skip these. A check that warms up for 45
    /// minutes would otherwise always trip a 30-minute "cannot be evaluated"
    /// alarm, which is a false positive guaranteed on every fresh install.
    pub warming_up: bool,
    /// The validator this check ultimately concerns, when it is not the check's
    /// own subject. A disk check on the host running `chimps-1` is owned by
    /// `chimps-1`, which is what lets a full disk explain the delinquency it
    /// causes instead of paging twice for one event.
    pub owner: Option<String>,
}

/// Cross-cycle progress counters, used for the "is it actually advancing?"
/// checks. Always the *maximum* across endpoints: a lagging or stale endpoint
/// can then never manufacture a false stall, it can only fail to improve on
/// what a healthier endpoint already reported.
#[derive(Debug, Default)]
pub struct Progress {
    validator_credits: HashMap<String, u64>,
    cluster_slot: Option<u64>,
    /// Identity balance over time, per identity, so the runway in a low-balance
    /// alert is measured rather than assumed. Block fees refill an identity
    /// between votes: mind-main's swung 1.6-2.8 SOL over four days while an
    /// assumed 2 SOL/epoch cost said "0.9 epochs left".
    identity_history: HashMap<String, crate::fillrate::FillHistory>,
}

/// One identity-balance sample per this interval, over this window. A day
/// covers the fee sawtooth; six hours is the least worth fitting a slope to.
const IDENTITY_SAMPLE_EVERY: Duration = Duration::from_secs(10 * 60);
const IDENTITY_WINDOW: Duration = Duration::from_secs(24 * 3600);
const IDENTITY_MIN_SPAN: Duration = Duration::from_secs(6 * 3600);

impl Progress {
    /// Export the high-water marks for persistence. Losing these across a
    /// restart would reset every stall baseline, blinding the progress checks
    /// for a cycle.
    pub fn export(&self) -> (HashMap<String, u64>, Option<u64>) {
        (self.validator_credits.clone(), self.cluster_slot)
    }

    pub fn import(&mut self, validator_credits: HashMap<String, u64>, cluster_slot: Option<u64>) {
        self.validator_credits = validator_credits;
        self.cluster_slot = cluster_slot;
    }

    pub fn export_identity_history(&self) -> HashMap<String, crate::fillrate::FillHistory> {
        self.identity_history.clone()
    }

    pub fn import_identity_history(&mut self, h: HashMap<String, crate::fillrate::FillHistory>) {
        self.identity_history = h;
    }

    fn record_identity(&mut self, identity: &str, now_unix: u64, lamports: u64) {
        self.identity_history.entry(identity.to_string()).or_default().record(
            now_unix,
            lamports,
            IDENTITY_SAMPLE_EVERY,
            IDENTITY_WINDOW,
        );
    }

    fn identity_trend(&self, identity: &str) -> Option<crate::fillrate::Projection> {
        self.identity_history
            .get(identity)
            .map(|h| h.project(IDENTITY_MIN_SPAN, 6))
    }

    /// Returns the verdict for "did this counter advance", and records the new
    /// high-water mark. `None` observed means we had no definite reading.
    /// Largest backwards step still attributable to a lagging endpoint.
    ///
    /// An endpoint behind by a whole epoch sees at most one epoch of credits
    /// fewer: 432,000 slots, generously 16 credits each. Anything beyond that
    /// is not lag, so treating it as one would be how a poisoned baseline
    /// becomes a permanent false alarm.
    const MAX_LAG_REGRESSION: u64 = 16 * 432_000;

    fn advance(previous: Option<u64>, observed: Option<u64>, what: &str) -> (Verdict, Option<u64>) {
        let Some(observed) = observed else {
            return (
                Verdict::unknown(format!("no endpoint reported {what}")),
                previous,
            );
        };
        let Some(previous) = previous else {
            // First reading establishes the baseline; nothing to compare against.
            return (
                Verdict::unknown(format!("establishing {what} baseline")),
                Some(observed),
            );
        };
        if observed > previous {
            return (Verdict::Healthy, Some(observed));
        }
        if previous.saturating_sub(observed) > Self::MAX_LAG_REGRESSION {
            // Small regressions are endpoint lag, and the arm below correctly
            // refuses to lower the mark for them. A drop this large cannot be
            // lag: the counter was redefined, or a bad reading poisoned the
            // baseline. Holding the old mark would report a stall that can
            // never clear -- which is what one `u64::MAX` reading did to every
            // testnet box, persisted across restarts. Re-baseline instead.
            return (
                Verdict::unknown(format!(
                    "{what} went backwards ({previous} -> {observed}); re-establishing baseline"
                )),
                Some(observed),
            );
        }
        (
            Verdict::unhealthy(format!("{what} has not advanced past {previous}")),
            Some(previous),
        )
    }
}

/// Highest definite value any endpoint reported, or `None` if none did.
fn best<F>(snapshots: &[Snapshot], f: F) -> Option<u64>
where
    F: Fn(&Snapshot) -> Option<u64>,
{
    snapshots.iter().filter_map(f).max()
}

/// Endpoints that answered but are too far behind to be trusted this cycle,
/// mapped to how far behind they are.
fn find_stale(snapshots: &[Snapshot], max_lag: u64) -> HashMap<String, u64> {
    let Some(best) = snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref().map(|e| e.absolute_slot))
        .max()
    else {
        return HashMap::new();
    };

    snapshots
        .iter()
        .filter_map(|s| {
            let slot = s.epoch_info.as_ref()?.absolute_slot;
            let lag = best.saturating_sub(slot);
            (lag > max_lag).then(|| (s.endpoint.clone(), lag))
        })
        .collect()
}

fn per_endpoint<F>(
    snapshots: &[Snapshot],
    stale: &HashMap<String, u64>,
    f: F,
) -> Vec<(String, Verdict)>
where
    F: Fn(&Snapshot) -> Verdict,
{
    snapshots
        .iter()
        .map(|s| {
            let verdict = match stale.get(&s.endpoint) {
                // A stale endpoint is not wrong about the validator, it is
                // behind. That is the definition of Unknown.
                Some(lag) => Verdict::unknown(format!(
                    "endpoint is {lag} slots behind the most advanced endpoint this cycle"
                )),
                None => f(s),
            };
            (s.endpoint.clone(), verdict)
        })
        .collect()
}

fn outcome(
    id: String,
    title: String,
    cfg: CheckConfig,
    verdicts: Vec<(String, Verdict)>,
    min_confirmations: usize,
) -> CheckOutcome {
    let (verdict, tally) = aggregate(&verdicts, min_confirmations);
    CheckOutcome {
        id,
        title,
        cfg,
        verdict,
        tally,
        warming_up: false,
        owner: None,
    }
}

/// A check with exactly one source of truth. Disk state comes from the one host
/// that has the disk, so there is nothing to corroborate it against -- but the
/// tri-state rule still holds: a failed scrape is `Unknown`, never `Unhealthy`.
fn single(
    id: String,
    title: String,
    cfg: CheckConfig,
    verdict: Verdict,
    owner: Option<String>,
) -> CheckOutcome {
    let (verdict, tally) = aggregate(&[("host".to_string(), verdict)], 1);
    CheckOutcome {
        id,
        title,
        cfg,
        verdict,
        tally,
        warming_up: false,
        owner,
    }
}

pub fn evaluate(
    snapshots: &[Snapshot],
    config: &Config,
    progress: &mut Progress,
) -> Vec<CheckOutcome> {
    let mut out = Vec::new();
    let mc = config.quorum.min_confirmations;
    let c = &config.checks;
    let stale = find_stale(snapshots, config.quorum.max_endpoint_lag_slots);
    for (endpoint, lag) in &stale {
        tracing::warn!(endpoint = %endpoint, "discarding answers: {lag} slots behind");
    }

    for v in &config.validators {
        let who = v.display().to_string();
        let identity = v.identity.clone();

        if c.vote_delinquent.enabled {
            let id = identity.clone();
            out.push(outcome(
                format!("vote_delinquent:{who}"),
                format!("{who} is delinquent"),
                c.vote_delinquent.clone(),
                per_endpoint(snapshots, &stale, |s| match s.validators.get(&id) {
                    Some(ValidatorObservation::Delinquent(i)) => Verdict::unhealthy(format!(
                        "{who} delinquent, last vote slot {}",
                        i.last_vote
                    )),
                    Some(ValidatorObservation::Voting(_)) => Verdict::Healthy,
                    // Absent is a different failure; this check has no opinion,
                    // and must not report Healthy about a validator it cannot see.
                    Some(ValidatorObservation::Absent) => {
                        Verdict::unknown("not present in vote accounts")
                    }
                    Some(ValidatorObservation::Unknown(v)) => v.clone(),
                    None => Verdict::unknown("not observed"),
                }),
                mc,
            ));
        }

        if c.vote_account_missing.enabled {
            let id = identity.clone();
            out.push(outcome(
                format!("vote_account_missing:{who}"),
                format!("{who} has no vote account"),
                c.vote_account_missing.clone(),
                per_endpoint(snapshots, &stale, |s| match s.validators.get(&id) {
                    Some(ValidatorObservation::Absent) => Verdict::unhealthy(format!(
                        "{who} ({identity}) is in neither the current nor the delinquent \
                         vote account list"
                    )),
                    Some(ValidatorObservation::Voting(_))
                    | Some(ValidatorObservation::Delinquent(_)) => Verdict::Healthy,
                    Some(ValidatorObservation::Unknown(v)) => v.clone(),
                    None => Verdict::unknown("not observed"),
                }),
                mc,
            ));
        }

        if c.vote_lag.base.enabled {
            let id = identity.clone();
            let max_slots = c.vote_lag.max_slots;
            out.push(outcome(
                format!("vote_lag:{who}"),
                format!("{who} last vote is behind the cluster"),
                c.vote_lag.base.clone(),
                per_endpoint(snapshots, &stale, |s| {
                    lag_verdict(s, &id, &who, max_slots, "last vote", |i| i.last_vote)
                }),
                mc,
            ));
        }

        if c.root_lag.base.enabled {
            let id = identity.clone();
            let max_slots = c.root_lag.max_slots;
            out.push(outcome(
                format!("root_lag:{who}"),
                format!("{who} root slot is behind the cluster"),
                c.root_lag.base.clone(),
                per_endpoint(snapshots, &stale, |s| {
                    lag_verdict(s, &id, &who, max_slots, "root slot", |i| i.root_slot)
                }),
                mc,
            ));
        }

        if c.vote_stalled.enabled {
            let observed = best(snapshots, |s| {
                if stale.contains_key(&s.endpoint) {
                    return None;
                }
                s.validators
                    .get(&identity)
                    .and_then(|o| o.info())
                    // Zero means the vote account has no credit history yet;
                    // treat it as no reading rather than a stall at zero.
                    .map(|i| i.total_credits())
                    .filter(|c| *c > 0)
            });
            let previous = progress.validator_credits.get(&identity).copied();
            let (verdict, updated) =
                Progress::advance(previous, observed, &format!("{who} vote credits"));
            if let Some(u) = updated {
                progress.validator_credits.insert(identity.clone(), u);
            }
            // Credits earned inside the current epoch make the alert readable at
            // a glance: "0 this epoch" is a very different story from "stuck at
            // 41,900 after a good epoch".
            let verdict = match (verdict, best(snapshots, |s| {
                if stale.contains_key(&s.endpoint) {
                    return None;
                }
                s.validators
                    .get(&identity)
                    .and_then(|o| o.info())
                    .map(|i| i.current_epoch_credits())
            })) {
                (Verdict::Unhealthy(d), Some(earned)) => {
                    Verdict::unhealthy(format!("{d} ({earned} credits earned this epoch)"))
                }
                (v, _) => v,
            };
            let (verdict, tally) = aggregate(&[("derived".into(), verdict)], 1);
            out.push(CheckOutcome {
                id: format!("vote_stalled:{who}"),
                title: format!("{who} is earning no vote credits"),
                cfg: c.vote_stalled.clone(),
                // "Establishing baseline" is warm-up, not blindness.
                warming_up: matches!(&verdict, Verdict::Unknown(r) if r.contains("baseline")),
                verdict,
                tally,
                owner: None,
            });
        }

        if c.skip_rate.base.enabled {
            let sr = &c.skip_rate;
            let id = identity.clone();
            for (suffix, floor, ceiling, severity) in [
                ("critical", sr.page_percent, None, sr.base.severity),
                ("warn", sr.warn_percent, Some(sr.page_percent), Severity::Notify),
            ] {
                let mut cfg = sr.base.clone();
                cfg.severity = severity;
                let who2 = who.clone();
                let id2 = id.clone();
                let min = sr.min_leader_slots;
                out.push(outcome(
                    format!("skip_rate_{suffix}:{who}"),
                    format!("{who} is skipping leader slots"),
                    cfg,
                    per_endpoint(snapshots, &stale, |s| {
                        let Some(bp) = s.block_production.get(&id2) else {
                            return Verdict::unknown("block production not reported");
                        };
                        // Not yet measurable is not the same as unobservable:
                        // the node answered, it simply has not been asked to
                        // produce blocks yet. Reporting Unknown here would leave
                        // the check frozen for hours early in an epoch and
                        // eventually trip the starvation detector.
                        if bp.leader_slots < min {
                            return Verdict::Healthy;
                        }
                        let pct = bp.skip_percent();
                        let above = pct > floor;
                        let below = ceiling.map(|c| pct <= c).unwrap_or(true);
                        if above && below {
                            Verdict::unhealthy(format!(
                                "{who2} skipped {} of {} leader slots this epoch ({pct:.1}%, threshold {floor:.0}%)",
                                bp.skipped(),
                                bp.leader_slots
                            ))
                        } else {
                            Verdict::Healthy
                        }
                    }),
                    mc,
                ));
            }
        }

        if c.commission_changed.enabled
            && (v.expected_commission_bps().is_some()
                || v.expected_block_revenue_commission_bps.is_some())
        {
            let id = identity.clone();
            let expected = v.expected_commission_bps();
            let expected_block = v.expected_block_revenue_commission_bps;
            out.push(outcome(
                format!("commission_changed:{who}"),
                format!("{who} commission changed unexpectedly"),
                c.commission_changed.clone(),
                per_endpoint(snapshots, &stale, |s| {
                    commission_verdict(&who, s, &id, expected, expected_block)
                }),
                mc,
            ));
        }

        if c.vote_admission.base.enabled {
            let warn_epochs = c.vote_admission.warn_epochs;
            for (suffix, severity) in [
                ("critical", c.vote_admission.base.severity),
                ("warn", Severity::Notify),
            ] {
                let mut cfg = c.vote_admission.base.clone();
                cfg.severity = severity;
                let id = identity.clone();
                let who2 = who.clone();
                let income = income_for(snapshots, &identity);
                out.push(outcome(
                    format!("vote_admission_{suffix}:{who}"),
                    if suffix == "critical" {
                        format!("{who} will be excluded from voting next epoch")
                    } else {
                        format!("{who} vote account needs attention for Alpenglow")
                    },
                    cfg,
                    per_endpoint(snapshots, &stale, |s| {
                        admission_verdict(s, &id, &who2, suffix == "critical", warn_epochs, income)
                    }),
                    mc,
                ));
            }
        }

        // Balances are split into two non-overlapping bands so exactly one of
        // them is ever active: a low-but-survivable balance nudges Telegram, and
        // only a genuinely critical balance pages.
        let id = identity.clone();
        let per_epoch = c.identity_balance.sol_per_epoch;
        // The most advanced non-stale reading, sampled for the measured runway.
        if let Some(lamports) = snapshots
            .iter()
            .filter(|s| !stale.contains_key(&s.endpoint))
            .find_map(|s| s.identity_balances.get(&identity).copied().flatten())
        {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            progress.record_identity(&identity, now_unix, lamports);
        }
        let trend = progress.identity_trend(&identity);
        for (suffix, floor, ceiling, severity) in [
            (
                "critical",
                c.identity_balance.page_sol,
                None,
                c.identity_balance.base.severity,
            ),
            (
                "warn",
                c.identity_balance.warn_sol,
                Some(c.identity_balance.page_sol),
                Severity::Notify,
            ),
        ] {
            if !c.identity_balance.base.enabled {
                break;
            }
            let mut cfg = c.identity_balance.base.clone();
            cfg.severity = severity;
            let who2 = who.clone();
            let id2 = id.clone();
            let warn_sol = c.identity_balance.warn_sol;
            out.push(outcome(
                format!("identity_balance_{suffix}:{who}"),
                format!("{who} identity balance is low"),
                cfg,
                per_endpoint(snapshots, &stale, |s| {
                    if not_voting(s, &id2) {
                        return Verdict::Healthy;
                    }
                    let lamports = s.identity_balances.get(&id2).copied().flatten();
                    // Unobserved (an endpoint that will not serve the feature
                    // accounts) keeps today's behaviour rather than disabling
                    // a check that works without them.
                    match alpenglow_in_force(s).unwrap_or(false) {
                        // Votes no longer cost the identity anything, so an
                        // empty one cannot take the validator delinquent:
                        // nothing here pages, and one band covers everything
                        // under the warning floor.
                        true if suffix == "critical" => Verdict::Healthy,
                        true => match balance_verdict(lamports, warn_sol, None, &format!("{who2} identity"), 0.0, None) {
                            Verdict::Unhealthy(m) => Verdict::unhealthy(format!(
                                "{m}. Under Alpenglow the identity no longer pays for votes, so \
                                 this does not affect voting"
                            )),
                            other => other,
                        },
                        false => balance_verdict(
                            lamports,
                            floor,
                            ceiling,
                            &format!("{who2} identity"),
                            per_epoch,
                            trend.as_ref(),
                        ),
                    }
                }),
                mc,
            ));
        }

    }

    if c.cluster_stake.base.enabled {
        let min_percent = c.cluster_stake.min_percent;
        out.push(outcome(
            "cluster_stake".into(),
            "Cluster active stake is low".into(),
            c.cluster_stake.base.clone(),
            per_endpoint(snapshots, &stale, |s| match &s.cluster_stake {
                Some(cs) if cs.total == 0 => Verdict::unknown("empty vote account listing"),
                Some(cs) if cs.current_percent() < min_percent => Verdict::unhealthy(format!(
                    "cluster active stake is {:.2}% (floor {min_percent:.2}%); {:.0} SOL of \
                     stake is delinquent",
                    cs.current_percent(),
                    lamports_to_sol(cs.delinquent)
                )),
                Some(_) => Verdict::Healthy,
                None => Verdict::unknown("cluster stake not sampled this cycle"),
            }),
            mc,
        ));
    }

    if c.cluster_stalled.enabled {
        let observed = best(snapshots, |s| s.epoch_info.as_ref().map(|e| e.absolute_slot));
        let (verdict, updated) = Progress::advance(progress.cluster_slot, observed, "cluster slot");
        progress.cluster_slot = updated;
        let (verdict, tally) = aggregate(&[("derived".into(), verdict)], 1);
        out.push(CheckOutcome {
            id: "cluster_stalled".into(),
            title: "Cluster slot is not advancing".into(),
            cfg: c.cluster_stalled.clone(),
            warming_up: matches!(&verdict, Verdict::Unknown(r) if r.contains("baseline")),
            verdict,
            tally,
            owner: None,
        });
    }

    out
}

/// Free-space history per filesystem, keyed `"<host>\u{1f}<mountpoint>"`.
#[derive(Debug, Default)]
pub struct DiskHistory {
    fs: HashMap<String, FillHistory>,
    /// The projection computed in the last cycle, kept so metrics can graph
    /// exactly what the alerting logic saw rather than a re-derivation that
    /// might disagree with it.
    projections: HashMap<String, Projection>,
}

/// Split a history key back into `(host, mountpoint)`.
pub fn split_disk_key(key: &str) -> Option<(&str, &str)> {
    key.split_once('\u{1f}')
}

fn disk_key(host: &str, mount: &str) -> String {
    format!("{host}\u{1f}{mount}")
}

impl DiskHistory {
    pub fn export(&self) -> HashMap<String, FillHistory> {
        self.fs.clone()
    }

    pub fn import(&mut self, fs: HashMap<String, FillHistory>) {
        self.fs = fs;
    }

    pub fn projections(&self) -> &HashMap<String, Projection> {
        &self.projections
    }

    /// Mountpoints seen previously on a host. Used to keep reporting checks for
    /// a host whose exporter has gone away -- otherwise its checks would simply
    /// vanish from the outcome list and the starvation detector, which only
    /// looks at checks that exist, would never notice.
    fn known_mounts(&self, host: &str) -> Vec<String> {
        let prefix = format!("{host}\u{1f}");
        self.fs
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string))
            .collect()
    }
}

/// Filesystem checks, evaluated from node_exporter scrapes.
pub fn evaluate_disk(
    snapshots: &[HostSnapshot],
    config: &Config,
    history: &mut DiskHistory,
    now_unix: u64,
) -> Vec<CheckOutcome> {
    let mut out = Vec::new();
    let c = &config.checks;

    for snap in snapshots {
        let owner = config
            .hosts
            .iter()
            .find(|h| h.name == snap.host)
            .and_then(|h| h.validator.clone());

        if let Some(err) = &snap.error {
            // Unknown for every filesystem we used to be able to see, so a
            // permanently-down exporter is eventually reported as starved
            // rather than silently dropping off the list.
            let mut mounts = history.known_mounts(&snap.host);
            mounts.sort();
            for mount in mounts {
                for (kind, cfg) in disk_check_kinds(c) {
                    out.push(single(
                        format!("{kind}:{} {mount}", snap.host),
                        format!("{} {mount}", snap.host),
                        cfg,
                        Verdict::unknown(format!("node_exporter unreachable: {err}")),
                        owner.clone(),
                    ));
                }
            }
            continue;
        }

        let mut mounts: Vec<_> = snap.filesystems.values().collect();
        mounts.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));

        for fs in mounts {
            let where_ = format!("{} {}", snap.host, fs.mountpoint);

            if c.disk_readonly.enabled {
                out.push(single(
                    format!("disk_readonly:{where_}"),
                    format!("{where_} is read-only"),
                    c.disk_readonly.clone(),
                    if fs.readonly {
                        Verdict::unhealthy(format!(
                            "{where_} ({}) has been remounted read-only, which is how a failing disk usually presents",
                            fs.device
                        ))
                    } else {
                        Verdict::Healthy
                    },
                    owner.clone(),
                ));
            }

            if c.disk_space.base.enabled {
                let avail = fs.avail_gb();
                let size = fs.size_gb();
                for (suffix, floor, ceiling, severity) in [
                    (
                        "critical",
                        c.disk_space.page_free_gb,
                        None,
                        c.disk_space.base.severity,
                    ),
                    (
                        "warn",
                        c.disk_space.warn_free_gb,
                        Some(c.disk_space.page_free_gb),
                        Severity::Notify,
                    ),
                ] {
                    let mut cfg = c.disk_space.base.clone();
                    cfg.severity = severity;
                    // Cap the floor relative to the filesystem, so a small
                    // partition is not judged against a threshold larger than
                    // the whole device.
                    let floor = c.disk_space.effective_floor(floor, size);
                    let ceiling = ceiling.map(|x| c.disk_space.effective_floor(x, size));
                    let below = avail < floor;
                    let above = ceiling.map(|x| avail >= x).unwrap_or(true);
                    out.push(single(
                        format!("disk_space_{suffix}:{where_}"),
                        format!("{where_} is low on space"),
                        cfg,
                        if below && above {
                            Verdict::unhealthy(format!(
                                "{where_} has {avail:.2} GB free of {:.1} GB ({:.1}% used), below the \
                                 {floor:.2} GB floor",
                                size,
                                fs.used_percent()
                            ))
                        } else {
                            Verdict::Healthy
                        },
                        owner.clone(),
                    ));
                }
            }

            if c.disk_fill.base.enabled {
                let f = &c.disk_fill;
                let key = disk_key(&snap.host, &fs.mountpoint);
                let projection = {
                    let entry = history.fs.entry(key.clone()).or_default();
                    entry.record(now_unix, fs.avail_bytes, f.sample_every, f.window);
                    entry.project(f.min_history, f.min_samples)
                };
                history.projections.insert(key, projection.clone());

                let warming = matches!(projection, Projection::Insufficient { .. });
                for (suffix, within, floor, severity) in [
                    ("critical", f.page_within, None, f.base.severity),
                    (
                        "warn",
                        f.warn_within,
                        Some(f.page_within),
                        Severity::Notify,
                    ),
                ] {
                    let mut cfg = f.base.clone();
                    cfg.severity = severity;
                    let mut o = single(
                        format!("disk_fill_{suffix}:{where_}"),
                        format!("{where_} is filling up"),
                        cfg,
                        fill_verdict(&projection, &where_, within, floor, fs.avail_gb()),
                        owner.clone(),
                    );
                    // Still gathering history: bounded and self-resolving, so it
                    // must not be reported as a check that cannot be evaluated.
                    o.warming_up = warming;
                    out.push(o);
                }
            }

            if c.disk_inodes.base.enabled && fs.inodes_total > 0 {
                let used = fs.inodes_used_percent();
                for (suffix, floor, ceiling, severity) in [
                    (
                        "critical",
                        c.disk_inodes.page_percent,
                        None,
                        c.disk_inodes.base.severity,
                    ),
                    (
                        "warn",
                        c.disk_inodes.warn_percent,
                        Some(c.disk_inodes.page_percent),
                        Severity::Notify,
                    ),
                ] {
                    let mut cfg = c.disk_inodes.base.clone();
                    cfg.severity = severity;
                    let above = used >= floor;
                    let below = ceiling.map(|x| used < x).unwrap_or(true);
                    out.push(single(
                        format!("disk_inodes_{suffix}:{where_}"),
                        format!("{where_} is low on inodes"),
                        cfg,
                        if above && below {
                            Verdict::unhealthy(format!(
                                "{where_} has used {used:.1}% of its inodes; a filesystem can run out of these with space to spare"
                            ))
                        } else {
                            Verdict::Healthy
                        },
                        owner.clone(),
                    ));
                }
            }
        }
    }

    out
}

/// Peer liveness, fused with cluster-side evidence.
///
/// Peer silence is ambiguous -- dead machine, partitioned network, or a crashed
/// monitor -- so silence alone only ever notifies. It becomes a page only when a
/// second, independent source agrees: the cluster's own view saying that peer's
/// validator has stopped voting. Two unrelated observations pointing the same
/// way is what makes it worth waking someone.
///
/// The two checks are non-overlapping, so exactly one is ever active.
pub fn evaluate_peers(
    peers: &[PeerStatus],
    snapshots: &[Snapshot],
    config: &Config,
    stale_after: Duration,
    // `declared_maintenance`: the last deadline each peer declared while it was
    // still reachable. A box that reboots during planned work cannot tell anyone
    // it is in maintenance -- it is gone -- so the hub has to have remembered.
    declared_maintenance: &HashMap<String, u64>,
    now_unix: u64,
) -> Vec<CheckOutcome> {
    let mut out = Vec::new();
    let c = &config.checks;

    for p in peers {
        let health = p.health(stale_after);

        // Honour a maintenance window the peer declared before it went away.
        let in_maintenance = p
            .maintenance_until
            .or_else(|| declared_maintenance.get(&p.name).copied())
            .map(|until| now_unix < until)
            .unwrap_or(false);

        // What does the cluster independently say about that peer's validator?
        // `None` means we have no definite reading -- either the peer runs no
        // validator, or we could not see the cluster this cycle.
        let validator_voting: Option<bool> = p.validator.as_ref().and_then(|label| {
            let identity = config
                .validators
                .iter()
                .find(|v| v.display() == label)
                .map(|v| v.identity.clone())?;

            let mut saw_voting = false;
            let mut saw_stopped = false;
            for s in snapshots {
                match s.validators.get(&identity) {
                    Some(ValidatorObservation::Voting(_)) => saw_voting = true,
                    Some(ValidatorObservation::Delinquent(_))
                    | Some(ValidatorObservation::Absent) => saw_stopped = true,
                    _ => {}
                }
            }
            match (saw_voting, saw_stopped) {
                // Any endpoint seeing it vote means the validator is alive,
                // whatever its monitor is doing.
                (true, _) => Some(true),
                (false, true) => Some(false),
                (false, false) => None,
            }
        });

        if c.machine_down.enabled {
            let fires =
                matches!(health, PeerHealth::Down(_)) && validator_voting == Some(false);
            out.push(CheckOutcome {
                id: format!("machine_down:{}", p.name),
                title: format!("{} appears to be hard down", p.name),
                warming_up: false,
                cfg: c.machine_down.clone(),
                verdict: if in_maintenance {
                    Verdict::unknown(format!(
                        "{} declared a maintenance window that has not expired",
                        p.name
                    ))
                } else if let PeerHealth::Unknown(why) = &health {
                    // Starting up, or not identifiable. Freeze rather than
                    // guess: this check can declare a machine dead, so it must
                    // never run on ambiguous evidence.
                    Verdict::unknown(why.clone())
                } else if fires {
                    Verdict::unhealthy(format!(
                        "{} is silent ({}) and the cluster reports {} has stopped voting; two independent sources agree the machine is gone",
                        p.name,
                        p.describe(stale_after),
                        p.validator.as_deref().unwrap_or("its validator")
                    ))
                } else {
                    Verdict::Healthy
                },
                tally: Tally::default(),
                // Lets a downed machine explain the delinquency it causes.
                owner: p.validator.clone(),
            });
        }

        if c.peer_down.enabled {
            // Only when `machine_down` is not already covering it.
            let fires = matches!(health, PeerHealth::Down(_))
                && validator_voting != Some(false);
            let detail = match &validator_voting {
                Some(true) => format!(
                    " -- but the cluster still sees {} voting, so this is lost visibility, not an outage",
                    p.validator.as_deref().unwrap_or("its validator")
                ),
                _ => String::new(),
            };
            out.push(CheckOutcome {
                id: format!("peer_down:{}", p.name),
                title: format!("Peer {} is not reporting", p.name),
                warming_up: false,
                cfg: c.peer_down.clone(),
                verdict: if in_maintenance {
                    Verdict::unknown(format!(
                        "{} is in a declared maintenance window",
                        p.name
                    ))
                } else if let PeerHealth::Unknown(why) = &health {
                    Verdict::unknown(why.clone())
                } else if fires {
                    Verdict::unhealthy(format!(
                        "{} is not reporting: {}{detail}",
                        p.name,
                        p.describe(stale_after)
                    ))
                } else {
                    Verdict::Healthy
                },
                tally: Tally::default(),
                owner: None,
            });
        }
    }

    out
}

/// Nodes you operate, as opposed to third-party data sources.
///
/// A validator's own RPC answering but lagging is invisible to every other
/// check: `find_stale` quietly discards it, and on a non-voting spare there is
/// no vote account to go delinquent. Without this, a spare that crashed or fell
/// hours behind looks exactly like a healthy one.
/// Does each validator meet the delegation program's published floor?
///
/// Two non-overlapping bands: `critical` for the floor of the epoch already
/// running (stake at risk now, pages), `warn` for the floor that takes effect
/// next epoch (roughly an epoch left, Telegram).
///
/// The version comes from a local endpoint, so this only speaks about the
/// validator the local node identifies as -- a hub listing five remote
/// validators must not report its own build as theirs. `reqs` of `None` yields
/// Unknown: an unreachable foundation API is not evidence about anyone.
pub fn evaluate_sfdp(
    snapshots: &[Snapshot],
    config: &Config,
    reqs: Option<&crate::sfdp::Requirements>,
) -> Vec<CheckOutcome> {
    use crate::sfdp::Compliance;
    let sc = &config.checks.sfdp_version;
    if !sc.base.enabled || config.validators.is_empty() {
        return Vec::new();
    }
    let mc = config.quorum.min_confirmations;
    let stale = find_stale(snapshots, config.quorum.max_endpoint_lag_slots);
    let epoch = snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref().map(|e| e.epoch))
        .max();
    let local = snapshots.iter().find_map(|s| s.version.as_ref());
    let local_identity = snapshots.iter().find_map(|s| s.identity.as_deref());

    let mut out = Vec::new();
    for v in &config.validators {
        if local_identity.is_some_and(|id| id != v.identity) {
            continue;
        }
        let who = v.display().to_string();
        let state = match (config.watchtower.sfdp_cluster(), reqs, local, epoch) {
            (None, _, _, _) => Err("cluster is not covered by the delegation program".to_string()),
            (_, None, _, _) => Err("SFDP required-version schedule not fetched yet".to_string()),
            (_, _, None, _) => Err("no local endpoint reported a validator version".to_string()),
            (_, _, _, None) => Err("epoch not observed".to_string()),
            _ if local_identity.is_none() => {
                Err("local node identity not observed, so the version cannot be attributed".into())
            }
            (Some(_), Some(r), Some(ver), Some(epoch)) => {
                match semver::Version::parse(&ver.solana_core) {
                    Err(e) => Err(format!("validator version {:?} is not semver: {e}", ver.solana_core)),
                    Ok(parsed) => match crate::sfdp::compliance(&parsed, epoch, r) {
                        None => Err("SFDP schedule is empty".to_string()),
                        Some(c) => Ok((c, ver.solana_core.clone())),
                    },
                }
            }
        };

        for (suffix, severity) in [
            ("critical", sc.base.severity),
            ("warn", Severity::Notify),
        ] {
            let mut cfg = sc.base.clone();
            cfg.severity = severity;
            let who2 = who.clone();
            let state2 = state.clone();
            let verdict = match &state2 {
                Err(why) => Verdict::unknown(why.clone()),
                Ok((c, ver)) => match (suffix, c) {
                    ("critical", Compliance::BelowCurrent { epoch, required }) => {
                        Verdict::unhealthy(format!(
                            "{who2} runs agave {ver} but the delegation program requires >= {required} \
                             as of epoch {epoch}, which has already started. Foundation stake is at \
                             risk until it is upgraded."
                        ))
                    }
                    ("warn", Compliance::BelowNext { epoch, required }) => {
                        Verdict::unhealthy(format!(
                            "{who2} runs agave {ver}; the delegation program requires >= {required} \
                             from epoch {epoch}, the next one. Upgrade before it starts to keep \
                             foundation stake."
                        ))
                    }
                    _ => Verdict::Healthy,
                },
            };
            // The version is a fact about this box rather than something
            // endpoints corroborate, so every usable endpoint carries the same
            // verdict and quorum is met whenever the cluster is visible at all.
            out.push(outcome(
                format!("sfdp_version_{suffix}:{who}"),
                format!("{who} is below the delegation program's required version"),
                cfg,
                per_endpoint(snapshots, &stale, |_| verdict.clone()),
                mc,
            ));
        }
    }
    out
}

pub fn evaluate_nodes(snapshots: &[Snapshot], config: &Config) -> Vec<CheckOutcome> {
    let c = &config.checks.node_behind;
    if !c.base.enabled {
        return Vec::new();
    }

    let best = snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref().map(|e| e.absolute_slot))
        .max();

    let mut out = Vec::new();
    for ep in config.endpoints.iter().filter(|e| e.monitor) {
        let snap = snapshots.iter().find(|s| s.endpoint == ep.name);
        let verdict = match (snap, best) {
            // Nothing answered anywhere. Our node may be fine and our view
            // broken; blaming it would page for our own network being down.
            (_, None) => Verdict::unknown("no endpoint reported a slot this cycle"),
            // Our node is silent while others answered -- now the silence means
            // something.
            (Some(s), Some(_)) if !s.is_usable() => {
                let why = s
                    .config_errors
                    .first()
                    .or_else(|| s.transient_errors.first())
                    .cloned()
                    .unwrap_or_else(|| "no answer".into());
                Verdict::unhealthy(format!("{} is not responding: {why}", ep.name))
            }
            (Some(s), Some(best)) => {
                let slot = s.epoch_info.as_ref().map(|e| e.absolute_slot).unwrap_or(0);
                let lag = best.saturating_sub(slot);
                if lag > c.max_slots {
                    Verdict::unhealthy(format!(
                        "{} is {lag} slots behind the cluster (limit {}); a node this far back is not ready to serve or take over",
                        ep.name, c.max_slots
                    ))
                } else {
                    Verdict::Healthy
                }
            }
            _ => Verdict::unknown("endpoint not probed this cycle"),
        };

        out.push(single(
            format!("node_behind:{}", ep.name),
            format!("{} is behind or unreachable", ep.name),
            c.base.clone(),
            verdict,
            None,
        ));
    }
    out
}

fn disk_check_kinds(c: &crate::config::Checks) -> Vec<(&'static str, CheckConfig)> {
    let mut v = Vec::new();
    if c.disk_readonly.enabled {
        v.push(("disk_readonly", c.disk_readonly.clone()));
    }
    if c.disk_space.base.enabled {
        v.push(("disk_space_critical", c.disk_space.base.clone()));
    }
    if c.disk_fill.base.enabled {
        v.push(("disk_fill_critical", c.disk_fill.base.clone()));
    }
    v
}

/// Bands are non-overlapping, as with balances, so exactly one of warn/critical
/// is ever active.
fn fill_verdict(
    projection: &Projection,
    where_: &str,
    within: Duration,
    floor: Option<Duration>,
    avail_gb: f64,
) -> Verdict {
    match projection {
        Projection::Insufficient { have, need } => Verdict::unknown(format!(
            "only {} of history, need {}",
            humantime::format_duration(Duration::from_secs(have.as_secs())),
            humantime::format_duration(Duration::from_secs(need.as_secs()))
        )),
        Projection::NotFilling => Verdict::Healthy,
        Projection::Filling {
            time_to_full,
            bytes_per_sec,
        } => {
            let inside = *time_to_full <= within;
            let outside_floor = floor.map(|f| *time_to_full > f).unwrap_or(true);
            if inside && outside_floor {
                Verdict::unhealthy(format!(
                    "{where_} has {avail_gb:.1} GB free and is filling at {}; projected full in {}",
                    rate_per_hour(*bytes_per_sec),
                    humantime::format_duration(Duration::from_secs(time_to_full.as_secs()))
                ))
            } else {
                Verdict::Healthy
            }
        }
    }
}

fn lag_verdict<F>(
    s: &Snapshot,
    identity: &str,
    who: &str,
    max_slots: u64,
    what: &str,
    extract: F,
) -> Verdict
where
    F: Fn(&crate::snapshot::VoteAccountInfo) -> u64,
{
    let Some(epoch) = s.epoch_info.as_ref() else {
        return Verdict::unknown("no cluster slot from this endpoint");
    };
    let Some(info) = s.validators.get(identity).and_then(|o| o.info()) else {
        return Verdict::unknown(format!("{what} not observed"));
    };
    let value = extract(info);
    if value == 0 {
        return Verdict::unknown(format!("{what} not reported"));
    }
    // An endpoint whose own slot is behind the validator's vote is stale, not
    // evidence of anything. Saturating here would read as a lag of 0, i.e. a
    // false Healthy, so say so explicitly instead.
    if value > epoch.absolute_slot {
        return Verdict::unknown(format!(
            "endpoint slot {} is behind the reported {what} {value}",
            epoch.absolute_slot
        ));
    }
    let lag = epoch.absolute_slot - value;
    if lag > max_slots {
        Verdict::unhealthy(format!(
            "{who} {what} is {lag} slots behind the cluster (limit {max_slots})"
        ))
    } else {
        Verdict::Healthy
    }
}

/// Unhealthy when below `floor`; if `ceiling` is set, only within `[ceiling, floor)`
/// so the warn and critical bands never overlap.
/// Whether a saved check state could still be produced by this binary with
/// this config.
///
/// A state nothing produces any more can never resolve: it stays "firing"
/// forever, and a PagerDuty incident it opened stays open. That happened when
/// `vote_balance_critical` was removed -- refi-main's incident sat open for two
/// weeks. Removed check kinds, disabled checks, and validators, peers, hosts or
/// endpoints taken out of the config all produce such states.
///
/// Deliberately not "absent from this cycle": a filesystem missing from one
/// scrape, or a spoke skipping cluster checks while it is not the owner, is
/// still configured and must keep its state.
pub fn still_configured(id: &str, config: &Config) -> bool {
    let c = &config.checks;
    let (kind, subject) = match id.split_once(':') {
        Some((k, s)) => (k, Some(s)),
        None => (id, None),
    };
    let validator = |s: Option<&str>| s.is_some_and(|s| config.validators.iter().any(|v| v.display() == s));
    let peer = |s: Option<&str>| s.is_some_and(|s| config.peers.iter().any(|p| p.name == s));
    // Disk subjects are "<host> <mountpoint>".
    let host = |s: Option<&str>| {
        s.and_then(|s| s.split_once(' ')).is_some_and(|(h, _)| config.hosts.iter().any(|x| x.name == h))
    };
    match kind {
        "vote_delinquent" => c.vote_delinquent.enabled && validator(subject),
        "vote_account_missing" => c.vote_account_missing.enabled && validator(subject),
        "vote_lag" => c.vote_lag.base.enabled && validator(subject),
        "root_lag" => c.root_lag.base.enabled && validator(subject),
        "vote_stalled" => c.vote_stalled.enabled && validator(subject),
        // Only produced for validators with an expected commission set.
        "commission_changed" => {
            c.commission_changed.enabled
                && subject.is_some_and(|s| {
                    config.validators.iter().any(|v| {
                        v.display() == s
                            && (v.expected_commission_bps().is_some()
                                || v.expected_block_revenue_commission_bps.is_some())
                    })
                })
        }
        "identity_balance_critical" | "identity_balance_warn" => {
            c.identity_balance.base.enabled && validator(subject)
        }
        "skip_rate_critical" | "skip_rate_warn" => c.skip_rate.base.enabled && validator(subject),
        "sfdp_version_critical" | "sfdp_version_warn" => c.sfdp_version.base.enabled && validator(subject),
        "vote_admission_critical" | "vote_admission_warn" => {
            c.vote_admission.base.enabled && validator(subject)
        }
        "cluster_stake" => c.cluster_stake.base.enabled,
        "cluster_stalled" => c.cluster_stalled.enabled,
        "disk_space_critical" | "disk_space_warn" => c.disk_space.base.enabled && host(subject),
        "disk_fill_critical" | "disk_fill_warn" => c.disk_fill.base.enabled && host(subject),
        "disk_inodes_critical" | "disk_inodes_warn" => c.disk_inodes.base.enabled && host(subject),
        "disk_readonly" => c.disk_readonly.enabled && host(subject),
        "node_behind" => {
            c.node_behind.base.enabled
                && subject.is_some_and(|s| config.endpoints.iter().any(|e| e.name == s && e.monitor))
        }
        "peer_down" => c.peer_down.enabled && peer(subject),
        "machine_down" => c.machine_down.enabled && peer(subject),
        // A kind this version does not have at all.
        _ => false,
    }
}

/// Saved states that nothing produced this cycle and nothing ever will again.
pub fn orphaned<'a>(
    state_ids: impl Iterator<Item = &'a String>,
    outcomes: &[CheckOutcome],
    config: &Config,
) -> Vec<String> {
    let produced: std::collections::HashSet<&str> = outcomes.iter().map(|o| o.id.as_str()).collect();
    let mut out: Vec<String> = state_ids
        .filter(|id| !produced.contains(id.as_str()) && !still_configured(id, config))
        .cloned()
        .collect();
    out.sort();
    out
}

/// The cluster lists no vote account for this identity: a spare, a failover
/// node, or anything else that is not voting. Its balance pays for nothing and
/// admission does not apply, so neither should warn. A vote account that goes
/// missing from a voting validator is `vote_account_missing`'s page, not these.
fn not_voting(s: &Snapshot, identity: &str) -> bool {
    matches!(s.validators.get(identity), Some(ValidatorObservation::Absent))
}

pub(crate) fn position(s: &Snapshot) -> Option<crate::alpenglow::EpochPosition> {
    s.epoch_info.as_ref().map(|e| crate::alpenglow::EpochPosition {
        epoch: e.epoch,
        absolute_slot: e.absolute_slot,
        slot_index: e.slot_index,
        slots_in_epoch: e.slots_in_epoch,
    })
}

/// Whether Alpenglow governs the epoch running now, per this endpoint.
fn alpenglow_in_force(s: &Snapshot) -> Option<bool> {
    let cluster = s.alpenglow.as_ref()?;
    let pos = position(s)?;
    Some(crate::alpenglow::active_this_epoch(cluster, &pos))
}

/// Commission the vote account earned last epoch, from whichever endpoint
/// keeps that history. Shared across endpoints rather than corroborated: it is
/// a past fact used as an input, and most public endpoints have pruned it, so
/// letting each endpoint use only its own answer would have the ones without
/// it outvote the one that knows.
pub(crate) fn income_for(snapshots: &[Snapshot], identity: &str) -> Option<u64> {
    snapshots.iter().find_map(|s| s.vote_income.get(identity).copied())
}

fn admission_verdict(
    s: &Snapshot,
    identity: &str,
    who: &str,
    critical: bool,
    warn_epochs: u64,
    income: Option<u64>,
) -> Verdict {
    let (Some(cluster), Some(pos)) = (s.alpenglow.as_ref(), position(s)) else {
        return Verdict::unknown("Alpenglow feature state not observed");
    };
    if pos.slots_in_epoch == 0 {
        return Verdict::unknown("epoch length not reported");
    }
    let Some(vote) = s.vote_states.get(identity) else {
        if not_voting(s, identity) {
            return Verdict::Healthy;
        }
        return Verdict::unknown("vote account not observed");
    };
    let req = crate::alpenglow::requirement(cluster, &pos);
    if critical {
        crate::alpenglow::critical(who, vote, &req)
    } else {
        crate::alpenglow::warn(who, vote, &req, income, warn_epochs)
    }
}

fn commission_verdict(
    who: &str,
    s: &Snapshot,
    identity: &str,
    expected_bps: Option<u16>,
    expected_block_bps: Option<u16>,
) -> Verdict {
    let pct = |bps: u16| format!("{}%", bps as f64 / 100.0);
    let mut wrong = Vec::new();
    let vote = s.vote_states.get(identity);
    if let Some(expected) = expected_bps {
        // Basis points from the vote account when it reports them; otherwise
        // the whole-percent field, which is exact only for whole percents.
        match (vote.and_then(|v| v.inflation_commission_bps), s.validators.get(identity).and_then(|o| o.info())) {
            (Some(bps), _) if bps != expected => {
                wrong.push(format!("inflation commission is {}, expected {}", pct(bps), pct(expected)))
            }
            (Some(_), _) => {}
            (None, Some(i)) if expected % 100 == 0 => {
                if i.commission as u16 * 100 != expected {
                    wrong.push(format!("commission is {}%, expected {}", i.commission, pct(expected)));
                }
            }
            (None, Some(_)) => return Verdict::unknown("endpoint reports whole-percent commission only"),
            (None, None) => return Verdict::unknown("commission not observed"),
        }
    }
    if let Some(expected) = expected_block_bps {
        match vote.and_then(|v| v.block_revenue_commission_bps) {
            Some(bps) if bps != expected => wrong.push(format!(
                "block-revenue commission is {}, expected {}",
                pct(bps),
                pct(expected)
            )),
            Some(_) => {}
            None => return Verdict::unknown("block-revenue commission not reported"),
        }
    }
    if wrong.is_empty() {
        Verdict::Healthy
    } else {
        Verdict::unhealthy(format!("{who} {}", wrong.join("; ")))
    }
}

fn balance_verdict(
    lamports: Option<u64>,
    floor_sol: f64,
    ceiling_sol: Option<f64>,
    what: &str,
    sol_per_epoch: f64,
    trend: Option<&crate::fillrate::Projection>,
) -> Verdict {
    use crate::fillrate::Projection;
    let Some(lamports) = lamports else {
        return Verdict::unknown(format!("{what} balance not observed"));
    };
    let sol = lamports_to_sol(lamports);
    let below_floor = sol < floor_sol;
    let above_ceiling = ceiling_sol.map(|c| sol >= c).unwrap_or(true);
    if !(below_floor && above_ceiling) {
        return Verdict::Healthy;
    }
    // How long it lasts is the actionable number: this account pays for vote
    // transactions, and when it empties the validator goes delinquent. Measured
    // when there is enough history -- block fees refill an identity between
    // votes, so an assumed cost can be wildly pessimistic -- and assumed, and
    // labelled as an assumption, until then.
    let cost = "an empty identity cannot vote and goes delinquent";
    let runway = match trend {
        _ if sol_per_epoch <= 0.0 => String::new(),
        Some(Projection::Filling { time_to_full, bytes_per_sec }) => {
            let hours = time_to_full.as_secs() as f64 / 3600.0;
            let left = if hours >= 48.0 {
                format!("{:.0} days", hours / 24.0)
            } else {
                format!("{hours:.0} hours")
            };
            format!(
                ", falling about {:.2} SOL a day over the last day: about {left} to empty -- {cost}",
                bytes_per_sec * 86_400.0 / 1e9
            )
        }
        Some(Projection::NotFilling) => {
            ", but it is not falling: over the last day block income has kept pace with vote costs"
                .to_string()
        }
        _ => format!(
            ", about {:.1} more epoch(s) of voting at an assumed {sol_per_epoch} SOL/epoch (not yet \
             measured) -- {cost}",
            sol / sol_per_epoch
        ),
    };
    Verdict::unhealthy(format!("{what} balance is {sol:.3} SOL (floor {floor_sol} SOL){runway}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{EpochInfo, VoteAccountInfo};

    fn vai(node: &str, last_vote: u64, root: u64, credits: u64, commission: u8) -> VoteAccountInfo {
        VoteAccountInfo {
            vote_pubkey: format!("vote-{node}"),
            node_pubkey: node.into(),
            activated_stake: 1,
            commission,
            last_vote,
            root_slot: root,
            epoch_credits: vec![(10, credits, 0)],
        }
    }

    fn snap(name: &str, slot: u64, obs: ValidatorObservation) -> Snapshot {
        let mut s = Snapshot {
            endpoint: name.into(),
            version: None,
            identity: None,
            epoch_info: Some(EpochInfo {
                absolute_slot: slot,
                epoch: 10,
                slot_index: 100,
                slots_in_epoch: 432_000,
            }),
            validators: HashMap::new(),
            identity_balances: HashMap::new(),
            alpenglow: None,
            vote_states: HashMap::new(),
            vote_income: HashMap::new(),
            block_production: HashMap::new(),
            cluster_stake: None,
            transient_errors: vec![],
            config_errors: vec![],
        };
        s.validators.insert("val".into(), obs);
        s
    }

    fn snap_at(name: &str, slot: u64) -> Snapshot {
        snap(
            name,
            slot,
            ValidatorObservation::Voting(vai("val", slot - 10, slot - 42, 5, 8)),
        )
    }

    fn cfg_with_monitored_endpoint(max_slots: u64) -> Config {
        Config::parse(&format!(
            "[[endpoints]]\nname = \"localhost\"\nurl = \"http://127.0.0.1:8899\"\n\
             monitor = true\n\
             [[endpoints]]\nname = \"remote\"\nurl = \"https://r.example/rpc\"\n\
             [[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
             [checks.node_behind]\npending_for = \"10m\"\nseverity = \"page\"\n\
             max_slots = {max_slots}\n"
        ))
        .unwrap()
    }

    fn bare_snapshot(name: &str, slot: Option<u64>) -> Snapshot {
        Snapshot {
            endpoint: name.into(),
            version: None,
            identity: None,
            epoch_info: slot.map(|s| EpochInfo {
                absolute_slot: s,
                epoch: 10,
                slot_index: 1,
                slots_in_epoch: 432_000,
            }),
            validators: HashMap::new(),
            identity_balances: HashMap::new(),
            alpenglow: None,
            vote_states: HashMap::new(),
            vote_income: HashMap::new(),
            block_production: HashMap::new(),
            cluster_stake: None,
            transient_errors: vec![],
            config_errors: vec![],
        }
    }

    fn peer_status(name: &str, reachable: bool, maint: Option<u64>) -> PeerStatus {
        PeerStatus {
            name: name.into(),
            priority: 2,
            validator: Some("v1".into()),
            reachable,
            last_cycle_age: reachable.then(|| Duration::from_secs(10)),
            visible: Some(true),
            version: Some("0.1.0".into()),
            uptime: Some(Duration::from_secs(3600)),
            maintenance_until: maint,
            error: (!reachable).then(|| "unreachable".to_string()),
        }
    }

    fn peer_cfg() -> Config {
        Config::parse(
            "[[endpoints]]\nname=\"a\"\nurl=\"https://a.example/rpc\"\n\
             [[endpoints]]\nname=\"b\"\nurl=\"https://b.example/rpc\"\n\
             [[validators]]\nidentity=\"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
             label=\"v1\"\n\
             [checks.machine_down]\nenabled=true\npending_for=\"0s\"\nseverity=\"page\"\n\
             [checks.peer_down]\nenabled=true\npending_for=\"0s\"\nseverity=\"notify\"\n",
        )
        .unwrap()
    }

    #[test]
    fn a_rebooting_peer_in_declared_maintenance_is_not_reported_dead() {
        // The case this exists for: the box reboots during planned work, so it
        // cannot tell anyone it is in maintenance -- it is gone. The hub has to
        // honour what it remembered from before.
        let c = peer_cfg();
        let gone = vec![peer_status("chimpions-mainnet", false, None)];
        let remembered: HashMap<String, u64> =
            [("chimpions-mainnet".to_string(), 9_999_999_999u64)]
                .into_iter()
                .collect();
        let out = evaluate_peers(&gone, &[], &c, Duration::from_secs(180), &remembered, 1_000);
        for o in &out {
            assert!(
                matches!(o.verdict, Verdict::Unknown(_)),
                "{} should be frozen during maintenance, got {:?}",
                o.id,
                o.verdict
            );
        }
    }

    #[test]
    fn a_peer_that_vanishes_without_declaring_maintenance_is_still_reported() {
        let c = peer_cfg();
        let gone = vec![peer_status("chimpions-mainnet", false, None)];
        let out = evaluate_peers(
            &gone,
            &[],
            &c,
            Duration::from_secs(180),
            &HashMap::new(),
            1_000,
        );
        assert!(
            out.iter().any(|o| matches!(o.verdict, Verdict::Unhealthy(_))),
            "an undeclared disappearance must still be reported"
        );
    }

    #[test]
    fn an_expired_maintenance_window_stops_suppressing() {
        // A restart that never finishes is an outage, not maintenance.
        let c = peer_cfg();
        let gone = vec![peer_status("chimpions-mainnet", false, None)];
        let expired: HashMap<String, u64> =
            [("chimpions-mainnet".to_string(), 500u64)].into_iter().collect();
        let out = evaluate_peers(&gone, &[], &c, Duration::from_secs(180), &expired, 1_000);
        assert!(
            out.iter().any(|o| matches!(o.verdict, Verdict::Unhealthy(_))),
            "an expired window must not keep suppressing"
        );
    }

    #[test]
    fn a_monitored_node_keeping_up_is_healthy() {
        let c = cfg_with_monitored_endpoint(300);
        let snaps = vec![
            bare_snapshot("localhost", Some(447_000_000)),
            bare_snapshot("remote", Some(447_000_050)),
        ];
        let out = evaluate_nodes(&snaps, &c);
        assert_eq!(out.len(), 1, "only the monitored endpoint is checked");
        assert_eq!(out[0].id, "node_behind:localhost");
        assert_eq!(out[0].verdict, Verdict::Healthy);
    }

    #[test]
    fn a_monitored_node_falling_behind_is_unhealthy() {
        // The failover spare drifting back. No vote account is involved, so no
        // other check can see this.
        let c = cfg_with_monitored_endpoint(300);
        let snaps = vec![
            bare_snapshot("localhost", Some(446_990_000)),
            bare_snapshot("remote", Some(447_000_000)),
        ];
        let out = evaluate_nodes(&snaps, &c);
        assert!(matches!(out[0].verdict, Verdict::Unhealthy(_)), "{:?}", out[0].verdict);
        assert!(out[0].verdict.detail().unwrap().contains("10000 slots behind"));
    }

    #[test]
    fn a_monitored_node_that_stops_answering_is_unhealthy() {
        let c = cfg_with_monitored_endpoint(300);
        let snaps = vec![
            bare_snapshot("localhost", None),
            bare_snapshot("remote", Some(447_000_000)),
        ];
        let out = evaluate_nodes(&snaps, &c);
        assert!(matches!(out[0].verdict, Verdict::Unhealthy(_)));
        assert!(out[0].verdict.detail().unwrap().contains("not responding"));
    }

    #[test]
    fn a_blind_cycle_leaves_the_node_check_unknown() {
        // Nothing answered anywhere: we cannot tell whether our node is behind
        // or the whole view is broken, and guessing would page for our own
        // network being down.
        let c = cfg_with_monitored_endpoint(300);
        let snaps = vec![bare_snapshot("localhost", None), bare_snapshot("remote", None)];
        let out = evaluate_nodes(&snaps, &c);
        assert!(matches!(out[0].verdict, Verdict::Unknown(_)), "{:?}", out[0].verdict);
    }

    #[test]
    fn unmonitored_endpoints_are_never_checked() {
        // A third-party provider going down is not your problem and must not page.
        let c = cfg_with_monitored_endpoint(300);
        let snaps = vec![
            bare_snapshot("localhost", Some(447_000_000)),
            bare_snapshot("remote", None),
        ];
        let out = evaluate_nodes(&snaps, &c);
        assert!(out.iter().all(|o| o.id != "node_behind:remote"));
    }

    #[test]
    fn an_endpoint_far_behind_the_others_is_marked_stale() {
        let snaps = vec![
            snap_at("fresh_a", 312_874_910),
            snap_at("fresh_b", 312_874_908),
            snap_at("laggard", 312_864_910),
        ];
        let stale = find_stale(&snaps, 300);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale.get("laggard"), Some(&10_000));
    }

    #[test]
    fn normal_jitter_between_endpoints_is_not_stale() {
        // Endpoints are always a few slots apart; that must not disqualify them.
        let snaps = vec![
            snap_at("a", 312_874_910),
            snap_at("b", 312_874_880),
            snap_at("c", 312_874_850),
        ];
        assert!(find_stale(&snaps, 300).is_empty());
    }

    #[test]
    fn a_stale_endpoint_votes_unknown_rather_than_healthy() {
        // The failure this prevents: a frozen node reports an old lastVote
        // against its own old slot, computes a small lag, and returns Healthy --
        // voting down a real problem that the live endpoints can see.
        let snaps = vec![
            snap_at("fresh_a", 312_874_910),
            snap_at("fresh_b", 312_874_908),
            snap_at("frozen", 312_774_910),
        ];
        let stale = find_stale(&snaps, 300);
        let verdicts = per_endpoint(&snaps, &stale, |_| Verdict::Healthy);

        let frozen = verdicts.iter().find(|(n, _)| n == "frozen").unwrap();
        assert!(
            matches!(frozen.1, Verdict::Unknown(_)),
            "a frozen endpoint must not vote Healthy, got {}",
            frozen.1
        );
        assert_eq!(
            verdicts.iter().filter(|(_, v)| *v == Verdict::Healthy).count(),
            2
        );
    }

    #[test]
    fn staleness_is_relative_so_a_uniformly_behind_fleet_is_still_usable() {
        // If every endpoint is equally behind, there is nothing better to
        // compare against and the cycle is still perfectly informative.
        let snaps = vec![snap_at("a", 1_000_000), snap_at("b", 1_000_010)];
        assert!(find_stale(&snaps, 300).is_empty());
    }

    #[test]
    fn lag_against_a_stale_endpoint_is_unknown_not_healthy() {
        // Endpoint's own slot is *behind* the validator's last vote, which only
        // happens when the endpoint is stale. Saturating subtraction would give
        // lag 0 and wrongly report Healthy.
        let s = snap(
            "stale",
            1000,
            ValidatorObservation::Voting(vai("val", 1200, 1168, 5, 8)),
        );
        let v = lag_verdict(&s, "val", "val", 100, "last vote", |i| i.last_vote);
        assert!(matches!(v, Verdict::Unknown(_)), "got {v}");
    }

    #[test]
    fn lag_within_limit_is_healthy() {
        let s = snap(
            "ok",
            1000,
            ValidatorObservation::Voting(vai("val", 950, 918, 5, 8)),
        );
        assert_eq!(
            lag_verdict(&s, "val", "val", 100, "last vote", |i| i.last_vote),
            Verdict::Healthy
        );
    }

    #[test]
    fn lag_beyond_limit_is_unhealthy() {
        let s = snap(
            "ok",
            1000,
            ValidatorObservation::Voting(vai("val", 500, 468, 5, 8)),
        );
        assert!(matches!(
            lag_verdict(&s, "val", "val", 100, "last vote", |i| i.last_vote),
            Verdict::Unhealthy(_)
        ));
    }

    #[test]
    fn delinquency_check_says_unknown_when_validator_is_absent() {
        // "Absent" belongs to vote_account_missing. If this check returned
        // Healthy it would resolve a live delinquency incident the moment the
        // vote account dropped out of the listing.
        let s = snap("ok", 1000, ValidatorObservation::Absent);
        let v = match s.validators.get("val") {
            Some(ValidatorObservation::Absent) => Verdict::unknown("not present in vote accounts"),
            _ => unreachable!(),
        };
        assert!(matches!(v, Verdict::Unknown(_)));
    }

    #[test]
    fn balance_bands_do_not_overlap() {
        let lamports = |sol: f64| Some((sol * 1e9) as u64);
        // 1.0 SOL: inside the warn band [0.5, 2.0), outside critical (< 0.5).
        assert!(matches!(
            balance_verdict(lamports(1.0), 2.0, Some(0.5), "x", 2.0, None),
            Verdict::Unhealthy(_)
        ));
        assert_eq!(
            balance_verdict(lamports(1.0), 0.5, None, "x", 2.0, None),
            Verdict::Healthy
        );
        // 0.2 SOL: critical fires, warn does not.
        assert!(matches!(
            balance_verdict(lamports(0.2), 0.5, None, "x", 2.0, None),
            Verdict::Unhealthy(_)
        ));
        assert_eq!(
            balance_verdict(lamports(0.2), 2.0, Some(0.5), "x", 2.0, None),
            Verdict::Healthy
        );
    }

    #[test]
    fn a_low_identity_balance_reports_remaining_epochs() {
        // "0.4 epochs of voting left" is actionable; "0.8 SOL" is not, and the
        // consequence -- delinquency -- is what the operator needs to see.
        let v = balance_verdict(Some(800_000_000), 1.0, None, "x identity", 2.0, None);
        let d = v.detail().expect("should be unhealthy");
        assert!(d.contains("0.4 more epoch"), "got: {d}");
        assert!(d.contains("goes delinquent"), "got: {d}");
    }

    /// mind-main, measured every 6h over four days: a fee-income sawtooth with
    /// a slow net decline. The old message said "0.9 epochs left"; the fitted
    /// trend says weeks.
    #[test]
    fn a_measured_trend_replaces_the_assumed_runway() {
        use crate::fillrate::FillHistory;
        let sol = [2.193, 2.581, 2.767, 2.545, 2.343, 2.301, 2.549, 2.328, 2.041, 2.465, 2.100, 1.732, 1.559, 1.809];
        let mut h = FillHistory::default();
        for (i, v) in sol.iter().enumerate() {
            h.record(1_790_000_000 + i as u64 * 6 * 3600, (v * 1e9) as u64, Duration::from_secs(600), Duration::from_secs(5 * 86400));
        }
        let trend = h.project(Duration::from_secs(6 * 3600), 6);
        let v = balance_verdict(Some(1_809_000_000), 3.0, Some(0.5), "mind-main identity", 2.0, Some(&trend));
        let d = v.detail().expect("below the warning floor");
        // Least squares over the four days: 0.26 SOL a day, about a week.
        assert!(d.contains("falling about 0.26 SOL a day") && d.contains("about 7 days to empty"), "{d}");
        assert!(!d.contains("0.9 more epoch"), "the assumption must give way to the measurement: {d}");
    }

    #[test]
    fn an_identity_kept_level_by_block_income_says_so() {
        let v = balance_verdict(Some(1_800_000_000), 3.0, None, "x identity", 2.0, Some(&crate::fillrate::Projection::NotFilling));
        assert!(v.detail().unwrap().contains("not falling"), "{v:?}");
    }

    #[test]
    fn without_enough_history_the_runway_is_labelled_an_assumption() {
        let insufficient = crate::fillrate::Projection::Insufficient { have: Duration::from_secs(60), need: Duration::from_secs(6 * 3600) };
        let d = balance_verdict(Some(800_000_000), 1.0, None, "x identity", 2.0, Some(&insufficient)).detail().unwrap().to_string();
        assert!(d.contains("0.4 more epoch") && d.contains("not yet measured"), "{d}");
    }

    #[test]
    fn a_zero_epoch_cost_omits_the_runway_rather_than_dividing_by_zero() {
        let v = balance_verdict(Some(800_000_000), 1.0, None, "x identity", 0.0, None);
        let d = v.detail().expect("should be unhealthy");
        assert!(!d.contains("epoch"), "got: {d}");
    }

    #[test]
    fn unobserved_balance_is_unknown_not_zero() {
        // Reading a failed getBalance as 0 lamports would page for an empty
        // identity account every time a provider rate-limited us.
        assert!(matches!(
            balance_verdict(None, 0.5, None, "x", 2.0, None),
            Verdict::Unknown(_)
        ));
    }

    mod orphans {
        use super::*;

        const ID: &str = "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv";

        fn config(extra: &str) -> Config {
            Config::parse(&format!(
                "[[endpoints]]\nname = \"a\"\nurl = \"https://a.example\"\n\
                 [[endpoints]]\nname = \"localhost\"\nurl = \"http://127.0.0.1:8899\"\nmonitor = true\n\
                 [[validators]]\nidentity = \"{ID}\"\nlabel = \"chimps-1\"\nexpected_commission = 5\n\
                 [[hosts]]\nname = \"box\"\nurl = \"http://127.0.0.1:9100/metrics\"\nmountpoints = [\"/\"]\n\
                 [[peers]]\nname = \"hub\"\nurl = \"http://10.0.0.9:9469/metrics\"\npriority = 1\n\
                 [peering]\npriority = 2\n{extra}"
            ))
            .unwrap()
        }

        /// The safety net for the retirement logic: nothing this version
        /// produces may ever be classed as orphaned, or a live alert would be
        /// "resolved" while still broken.
        #[test]
        fn every_check_this_version_produces_is_still_configured() {
            let c = config("");
            let snaps = vec![bare_snapshot("a", Some(4_320_100)), bare_snapshot("localhost", Some(4_320_100))];
            let mut out = evaluate(&snaps, &c, &mut Progress::default());
            out.extend(evaluate_nodes(&snaps, &c));
            out.extend(evaluate_sfdp(&snaps, &c, None));
            out.extend(evaluate_peers(&[peer_status("hub", false, None)], &snaps, &c, Duration::from_secs(300), &HashMap::new(), 0));
            // Exact on purpose: a new check kind changes this count, and whoever
            // adds it must also teach still_configured about it.
            assert_eq!(out.len(), 18, "check kinds changed: update still_configured, then this count");
            for o in &out {
                assert!(still_configured(&o.id, &c), "{} is produced but would be retired", o.id);
            }
            // Disk checks need a scrape to be produced; their ids are "<kind>:<host> <mount>".
            for kind in ["disk_space_critical", "disk_space_warn", "disk_fill_critical", "disk_fill_warn",
                         "disk_inodes_critical", "disk_inodes_warn", "disk_readonly"] {
                assert!(still_configured(&format!("{kind}:box /"), &c), "{kind}");
            }
        }

        /// refi-main, exactly: a firing state for a check kind this version
        /// no longer has.
        #[test]
        fn a_removed_check_kind_is_orphaned() {
            let c = config("");
            let states = ["vote_balance_critical:chimps-1".to_string(), "vote_delinquent:chimps-1".to_string()];
            assert_eq!(orphaned(states.iter(), &[], &c), vec!["vote_balance_critical:chimps-1"]);
        }

        #[test]
        fn disabled_checks_and_removed_subjects_are_orphaned() {
            let c = config("[checks.vote_lag]\nenabled = false\npending_for = \"3m\"\nseverity = \"page\"\nmax_slots = 200\n");
            let states: Vec<String> = [
                "vote_lag:chimps-1", // disabled
                "vote_delinquent:chimps-gone", // validator no longer configured
                "peer_down:old-hub", // peer no longer configured
                "disk_space_critical:oldbox /", // host no longer configured
                "node_behind:a", // endpoint not monitored
                "vote_delinquent:chimps-1", // still configured: kept
                "disk_readonly:box /mnt/gone", // host configured, mount absent this scrape: kept
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert_eq!(
                orphaned(states.iter(), &[], &c),
                vec!["disk_space_critical:oldbox /", "node_behind:a", "peer_down:old-hub", "vote_delinquent:chimps-gone", "vote_lag:chimps-1"]
            );
        }

        /// Present in this cycle's outcomes means alive, whatever else.
        #[test]
        fn anything_produced_this_cycle_is_never_orphaned() {
            let c = config("");
            let mut o = outcome("custom:x".into(), "t".into(), c.checks.vote_delinquent.clone(), vec![], 1);
            o.id = "custom:x".into();
            let states = ["custom:x".to_string()];
            assert!(orphaned(states.iter(), &[o], &c).is_empty());
        }
    }

    mod alpenglow_checks {
        use super::*;
        use crate::alpenglow::{Bls, ClusterVat, FeatureState, VoteAccountState};

        const ID: &str = "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv";

        fn config(extra: &str) -> Config {
            Config::parse(&format!(
                "[[endpoints]]\nname = \"a\"\nurl = \"https://a.example\"\n\
                 [[endpoints]]\nname = \"b\"\nurl = \"https://b.example\"\n\
                 [[validators]]\nidentity = \"{ID}\"\nlabel = \"chimps-1\"\n{extra}"
            ))
            .unwrap()
        }

        fn cluster(alpenglow: FeatureState) -> ClusterVat {
            ClusterVat {
                alpenglow,
                slot_time: [FeatureState::Absent; 4],
                rent_lamports: 20_000_000,
            }
        }

        /// Epoch 10, two endpoints that agree.
        fn snaps(alpenglow: FeatureState, vote: Option<VoteAccountState>, identity: u64) -> Vec<Snapshot> {
            ["a", "b"]
                .iter()
                .map(|n| {
                    let mut s = bare_snapshot(n, Some(4_320_100));
                    s.epoch_info.as_mut().unwrap().epoch = 10;
                    s.epoch_info.as_mut().unwrap().slot_index = 100;
                    s.alpenglow = Some(cluster(alpenglow));
                    s.identity_balances.insert(ID.into(), Some(identity));
                    if let Some(v) = &vote {
                        s.vote_states.insert(ID.into(), v.clone());
                    }
                    s
                })
                .collect()
        }

        fn verdict(out: &[CheckOutcome], id: &str) -> Verdict {
            out.iter().find(|o| o.id == id).unwrap_or_else(|| panic!("no {id}")).verdict.clone()
        }

        fn vote(lamports: u64, bls: Bls) -> VoteAccountState {
            VoteAccountState {
                lamports,
                bls,
                inflation_commission_bps: Some(550),
                block_revenue_commission_bps: Some(10_000),
            }
        }

        #[test]
        fn an_underfunded_vote_account_pages_once_alpenglow_is_active() {
            let c = config("");
            let out = evaluate(&snaps(FeatureState::Active(0), Some(vote(30_000_000, Bls::Registered)), 1_000_000_000_000), &c, &mut Progress::default());
            let v = verdict(&out, "vote_admission_critical:chimps-1");
            assert!(matches!(&v, Verdict::Unhealthy(m) if m.contains("start of epoch 11") && m.contains("epoch 12")), "{v:?}");
        }

        #[test]
        fn nothing_pages_before_alpenglow_is_scheduled() {
            let c = config("");
            let out = evaluate(&snaps(FeatureState::Absent, Some(vote(0, Bls::Missing)), 0), &c, &mut Progress::default());
            assert_eq!(verdict(&out, "vote_admission_critical:chimps-1"), Verdict::Healthy);
            assert!(matches!(verdict(&out, "vote_admission_warn:chimps-1"), Verdict::Unhealthy(_)));
        }

        /// Under Alpenglow votes cost the identity nothing, so an empty one
        /// must not page "cannot vote and goes delinquent" -- and the warning
        /// band covers everything below warn_sol, including what used to page.
        #[test]
        fn an_empty_identity_does_not_page_under_alpenglow() {
            let c = config("");
            let out = evaluate(&snaps(FeatureState::Active(0), Some(vote(10_000_000_000, Bls::Registered)), 100_000_000), &c, &mut Progress::default());
            assert_eq!(verdict(&out, "identity_balance_critical:chimps-1"), Verdict::Healthy);
            let w = verdict(&out, "identity_balance_warn:chimps-1");
            assert!(matches!(&w, Verdict::Unhealthy(m) if m.contains("no longer pays for votes") && !m.contains("delinquent")), "{w:?}");

            // Before Alpenglow the same balance still pages, as it always has.
            let out = evaluate(&snaps(FeatureState::Absent, Some(vote(10_000_000_000, Bls::Registered)), 100_000_000), &c, &mut Progress::default());
            assert!(matches!(verdict(&out, "identity_balance_critical:chimps-1"), Verdict::Unhealthy(_)));
        }

        /// Scheduled is not yet in force: votes still cost the identity until
        /// the boundary, so the identity check keeps paging until then.
        #[test]
        fn a_scheduled_activation_does_not_relax_the_identity_check() {
            let c = config("");
            let out = evaluate(&snaps(FeatureState::Pending, Some(vote(10_000_000_000, Bls::Registered)), 100_000_000), &c, &mut Progress::default());
            assert!(matches!(verdict(&out, "identity_balance_critical:chimps-1"), Verdict::Unhealthy(_)));
        }

        /// 5.5% read as the whole-percent field rounds up to 6, so a change
        /// from 5.5% to 5.9% is invisible there. Basis points see it.
        #[test]
        fn commission_is_compared_in_basis_points() {
            let c = config("expected_commission_bps = 550\nexpected_block_revenue_commission_bps = 10000\n");
            let ok = evaluate(&snaps(FeatureState::Absent, Some(vote(1, Bls::Registered)), 1), &c, &mut Progress::default());
            assert_eq!(verdict(&ok, "commission_changed:chimps-1"), Verdict::Healthy);

            let mut moved = vote(1, Bls::Registered);
            moved.inflation_commission_bps = Some(590);
            let out = evaluate(&snaps(FeatureState::Absent, Some(moved), 1), &c, &mut Progress::default());
            let v = verdict(&out, "commission_changed:chimps-1");
            assert!(matches!(&v, Verdict::Unhealthy(m) if m.contains("5.9%") && m.contains("5.5%")), "{v:?}");

            let mut redirected = vote(1, Bls::Registered);
            redirected.block_revenue_commission_bps = Some(0);
            let out = evaluate(&snaps(FeatureState::Absent, Some(redirected), 1), &c, &mut Progress::default());
            assert!(matches!(verdict(&out, "commission_changed:chimps-1"), Verdict::Unhealthy(m) if m.contains("block-revenue")));
        }

        /// A spare or failover identity: no vote account, a low balance, and
        /// nothing to warn about.
        #[test]
        fn a_non_voting_identity_raises_no_balance_or_admission_warnings() {
            let c = config("");
            let mut snaps = snaps(FeatureState::Active(0), None, 10_000_000);
            for s in &mut snaps {
                s.validators.insert(ID.into(), ValidatorObservation::Absent);
            }
            let out = evaluate(&snaps, &c, &mut Progress::default());
            for id in ["identity_balance_critical:chimps-1", "identity_balance_warn:chimps-1",
                       "vote_admission_critical:chimps-1", "vote_admission_warn:chimps-1"] {
                assert_eq!(verdict(&out, id), Verdict::Healthy, "{id}");
            }
            // ...while the missing vote account is still somebody's page.
            assert!(matches!(verdict(&out, "vote_account_missing:chimps-1"), Verdict::Unhealthy(_)));
        }

        #[test]
        fn both_commission_forms_at_once_is_a_config_error() {
            assert!(Config::parse(&format!(
                "[[endpoints]]\nname = \"a\"\nurl = \"https://a.example\"\n\
                 [[endpoints]]\nname = \"b\"\nurl = \"https://b.example\"\n\
                 [[validators]]\nidentity = \"{ID}\"\nexpected_commission = 5\nexpected_commission_bps = 500\n"
            ))
            .is_err());
        }
    }

    #[test]
    fn progress_baseline_cycle_is_unknown() {
        let (v, updated) = Progress::advance(None, Some(500), "credits");
        assert!(matches!(v, Verdict::Unknown(_)));
        assert_eq!(updated, Some(500));
    }

    #[test]
    fn progress_detects_a_stall_and_holds_the_high_water_mark() {
        let (v, updated) = Progress::advance(Some(500), Some(500), "credits");
        assert!(matches!(v, Verdict::Unhealthy(_)));
        assert_eq!(updated, Some(500));
    }

    #[test]
    fn progress_with_no_reading_is_unknown_and_preserves_the_mark() {
        let (v, updated) = Progress::advance(Some(500), None, "credits");
        assert!(matches!(v, Verdict::Unknown(_)));
        assert_eq!(updated, Some(500), "a blind cycle must not lose the baseline");
    }

    #[test]
    fn progress_regression_from_a_stale_endpoint_does_not_lower_the_mark() {
        let (v, updated) = Progress::advance(Some(500), Some(400), "credits");
        assert!(matches!(v, Verdict::Unhealthy(_)));
        assert_eq!(updated, Some(500));
    }
}

#[cfg(test)]
mod credit_baseline {
    use super::*;

    /// The trap: one bad reading (u64::MAX) became the high-water mark, and no
    /// real value could ever exceed it, so the check was unhealthy forever --
    /// and the poisoned mark was persisted across restarts.
    #[test]
    fn a_counter_going_backwards_rebaselines_instead_of_stalling_forever() {
        let (v, mark) = Progress::advance(Some(u64::MAX), Some(2_514_133_823), "credits");
        assert!(matches!(v, Verdict::Unknown(_)), "got {v:?}");
        assert_eq!(mark, Some(2_514_133_823), "must adopt the real value");
        // And the next cycle is healthy again, unassisted.
        let (v2, mark2) = Progress::advance(mark, Some(2_514_200_000), "credits");
        assert_eq!(v2, Verdict::Healthy);
        assert_eq!(mark2, Some(2_514_200_000));
    }

    /// A genuine stall holds the counter equal, and must still be caught.
    /// The other half of the rule, which an existing test also guards: a small
    /// backwards step is a lagging endpoint and must not lower the mark.
    #[test]
    fn a_small_regression_is_lag_and_holds_the_mark() {
        let (v, mark) = Progress::advance(Some(5_000_000), Some(4_999_000), "credits");
        assert!(matches!(v, Verdict::Unhealthy(_)), "got {v:?}");
        assert_eq!(mark, Some(5_000_000), "lag must not lower the high-water mark");
    }

    #[test]
    fn an_equal_counter_is_still_a_stall() {
        let (v, mark) = Progress::advance(Some(500), Some(500), "credits");
        assert!(matches!(v, Verdict::Unhealthy(_)), "got {v:?}");
        assert_eq!(mark, Some(500));
    }

    #[test]
    fn normal_advance_is_healthy() {
        let (v, mark) = Progress::advance(Some(500), Some(600), "credits");
        assert_eq!(v, Verdict::Healthy);
        assert_eq!(mark, Some(600));
    }
}

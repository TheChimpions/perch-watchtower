//! Cluster context, fetched only when an alert is about to go out.
//!
//! "chimps-1 is delinquent" leaves the most important triage question
//! unanswered: is this me, or is this everyone? Three delinquent validators
//! means check your box. Two hundred means check Discord and wait. That single
//! sentence is the difference between a useful page and a page that starts with
//! ten minutes of guessing.
//!
//! The full `getVoteAccounts` listing is multiple megabytes, far too heavy to
//! pull every cycle on a free endpoint. So it is fetched only at the moment an
//! alert fires, from one endpoint, and cached -- steady-state cost is zero.

use crate::{
    rpc::Endpoint,
    snapshot::{lamports_to_sol, summarize_stake, VoteAccounts},
};
use serde_json::json;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct ClusterContext {
    pub delinquent_validators: usize,
    pub total_validators: usize,
    pub delinquent_stake_percent: f64,
    pub delinquent_stake_sol: f64,
}

impl ClusterContext {
    /// The judgement call the operator would otherwise make themselves, half
    /// awake.
    pub fn summary(&self) -> String {
        let scope = if self.delinquent_stake_percent >= 10.0 {
            "This looks cluster-wide, not specific to you \u{2014} check the validator \
             channels before touching anything."
        } else if self.delinquent_validators > self.total_validators / 20 {
            "An unusual number of validators are delinquent; this may not be specific to you."
        } else {
            "The cluster is otherwise healthy, so this looks specific to your validator."
        };

        format!(
            "Cluster: {} of {} validators delinquent ({:.1}% of stake, {:.0} SOL). {scope}",
            self.delinquent_validators,
            self.total_validators,
            self.delinquent_stake_percent,
            self.delinquent_stake_sol
        )
    }
}

pub struct Enricher {
    cached: Option<(ClusterContext, Instant)>,
    ttl: Duration,
    enabled: bool,
}

impl Enricher {
    pub fn new(enabled: bool, ttl: Duration) -> Self {
        Self {
            cached: None,
            ttl,
            enabled,
        }
    }

    /// Best-effort. Enrichment failing must never block or alter an alert; the
    /// page goes out either way, just with less context.
    pub async fn context(&mut self, endpoints: &[Endpoint], now: Instant) -> Option<ClusterContext> {
        if !self.enabled {
            return None;
        }
        if let Some((ctx, at)) = &self.cached {
            if now.saturating_duration_since(*at) < self.ttl {
                debug!("using cached cluster context");
                return Some(ctx.clone());
            }
        }

        for endpoint in endpoints {
            match endpoint
                .call(
                    "getVoteAccounts",
                    json!([{ "commitment": "confirmed" }]),
                )
                .await
                .and_then(|v| {
                    serde_json::from_value::<VoteAccounts>(v).map_err(|e| {
                        crate::rpc::RpcError::Transient(format!("bad listing: {e}"))
                    })
                }) {
                Ok(va) => {
                    let stake = summarize_stake(&va);
                    let ctx = ClusterContext {
                        delinquent_validators: va.delinquent.len(),
                        total_validators: va.current.len() + va.delinquent.len(),
                        delinquent_stake_percent: 100.0 - stake.current_percent(),
                        delinquent_stake_sol: lamports_to_sol(stake.delinquent),
                    };
                    self.cached = Some((ctx.clone(), now));
                    return Some(ctx);
                }
                Err(e) => {
                    warn!(endpoint = %endpoint.name, "cluster context unavailable: {e}");
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(delinquent: usize, total: usize, stake_pct: f64) -> ClusterContext {
        ClusterContext {
            delinquent_validators: delinquent,
            total_validators: total,
            delinquent_stake_percent: stake_pct,
            delinquent_stake_sol: 1000.0,
        }
    }

    #[test]
    fn an_isolated_failure_points_at_your_validator() {
        let s = ctx(3, 1045, 0.4).summary();
        assert!(s.contains("specific to your validator"), "got {s}");
    }

    #[test]
    fn a_cluster_wide_failure_says_so() {
        let s = ctx(212, 1045, 31.0).summary();
        assert!(s.contains("cluster-wide"), "got {s}");
    }

    #[test]
    fn an_elevated_but_not_dominant_count_is_flagged_as_ambiguous() {
        // Many validators delinquent but little stake: worth noting, not
        // conclusive either way.
        let s = ctx(120, 1045, 2.0).summary();
        assert!(s.contains("may not be specific to you"), "got {s}");
    }

    #[tokio::test]
    async fn a_disabled_enricher_never_calls_out() {
        let mut e = Enricher::new(false, Duration::from_secs(300));
        // A bogus endpoint: if it were contacted the test would hang or error.
        let ep = Endpoint::new(
            "nope".into(),
            "http://127.0.0.1:1".into(),
            Duration::from_millis(50),
            1,
        )
        .unwrap();
        assert!(e.context(&[ep], Instant::now()).await.is_none());
    }
}

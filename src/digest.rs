//! One message per epoch saying how it went.
//!
//! Alerts tell you when something is wrong. The digest tells you, once an
//! epoch, that the watchtower is still looking and what it saw: leader slots,
//! blocks produced and skipped, credits earned, balance, version. The weekly
//! self-test proves perch can deliver; this proves it is watching.

use crate::{config::Config, snapshot::Snapshot};
use std::collections::HashMap;

/// The last thing we saw for a validator inside an epoch. Captured every cycle
/// and read at rollover, because once the epoch ends the RPC's block-production
/// view is already the new epoch and the old numbers are gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTail {
    pub epoch: u64,
    pub leader_slots: u64,
    pub blocks_produced: u64,
    pub balance_lamports: Option<u64>,
    /// Under Alpenglow, the balance that pays the VAT each epoch.
    pub vote_lamports: Option<u64>,
    pub version: Option<String>,
}

/// Current epoch as the endpoints see it, and each validator's tail.
pub fn capture(snapshots: &[Snapshot], config: &Config) -> (Option<u64>, HashMap<String, EpochTail>) {
    let epoch = snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref().map(|e| e.epoch))
        .max();
    let Some(epoch) = epoch else {
        return (None, HashMap::new());
    };
    let version = snapshots
        .iter()
        .find_map(|s| s.version.as_ref().map(|v| v.solana_core.clone()));
    // Only attributable to the validator the local node identifies as.
    let local_identity = snapshots.iter().find_map(|s| s.identity.clone());

    let mut tails = HashMap::new();
    for v in &config.validators {
        // Only endpoints that are in the same epoch we are summarising.
        let prod = snapshots
            .iter()
            .filter(|s| s.epoch_info.as_ref().map(|e| e.epoch) == Some(epoch))
            .find_map(|s| s.block_production.get(&v.identity));
        let balance = snapshots
            .iter()
            .find_map(|s| s.identity_balances.get(&v.identity).copied().flatten());
        tails.insert(
            v.identity.clone(),
            EpochTail {
                epoch,
                leader_slots: prod.map(|p| p.leader_slots).unwrap_or(0),
                blocks_produced: prod.map(|p| p.blocks_produced).unwrap_or(0),
                balance_lamports: balance,
                vote_lamports: snapshots
                    .iter()
                    .find_map(|s| s.vote_states.get(&v.identity).map(|vs| vs.lamports)),
                version: if local_identity.as_deref() == Some(v.identity.as_str()) {
                    version.clone()
                } else {
                    None
                },
            },
        );
    }
    (Some(epoch), tails)
}

/// Credits a validator earned in a given epoch, from the vote account's own
/// per-epoch history. Available after rollover, unlike block production.
pub fn credits_for(snapshots: &[Snapshot], identity: &str, epoch: u64) -> Option<u64> {
    snapshots.iter().find_map(|s| {
        let info = s.validators.get(identity)?.info()?;
        info.epoch_credits
            .iter()
            .find(|(e, _, _)| *e == epoch)
            .map(|(_, credits, prev)| credits.saturating_sub(*prev))
    })
}

/// The vote account against the VAT, counting the commission it earned in the
/// epoch being summarised. Before Alpenglow is scheduled this is what it
/// *would* do, so the trend is visible before it costs anything.
fn vat_runway(snapshots: &[Snapshot], identity: &str, vote_lamports: u64) -> Option<String> {
    use crate::alpenglow::{requirement, runway, Bls, Phase, VoteAccountState};
    let (cluster, pos) = snapshots
        .iter()
        .filter_map(|s| Some((s.alpenglow.as_ref()?, crate::checks::position(s)?)))
        .filter(|(_, p)| p.slots_in_epoch > 0)
        .max_by_key(|(_, p)| p.absolute_slot)?;
    let req = requirement(cluster, &pos);
    if req.vat_lamports == 0 {
        return None;
    }
    let vote = VoteAccountState {
        lamports: vote_lamports,
        bls: Bls::NotReported,
        inflation_commission_bps: None,
        block_revenue_commission_bps: None,
    };
    let r = runway(&vote, &req, crate::checks::income_for(snapshots, identity));
    Some(if req.phase == Phase::NotScheduled {
        r.describe_hypothetically(&req)
    } else {
        r.describe(&req)
    })
}

fn sol(lamports: u64) -> String {
    format!("{:.2} SOL", lamports as f64 / 1e9)
}

fn with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Render the summary for one finished epoch. Returns None when there is
/// nothing to say -- no validators, or no tail captured for that epoch.
pub fn render(
    epoch: u64,
    tails: &HashMap<String, EpochTail>,
    snapshots: &[Snapshot],
    config: &Config,
) -> Option<(String, String)> {
    let mut lines = Vec::new();
    for v in &config.validators {
        let Some(t) = tails.get(&v.identity).filter(|t| t.epoch == epoch) else {
            continue;
        };
        let skipped = t.leader_slots.saturating_sub(t.blocks_produced);
        let skip_pct = if t.leader_slots > 0 {
            format!(" ({:.1}%)", skipped as f64 * 100.0 / t.leader_slots as f64)
        } else {
            String::new()
        };
        lines.push(v.display().to_string());
        lines.push(format!(
            "  leader slots {}, produced {}, skipped {}{skip_pct}",
            t.leader_slots, t.blocks_produced, skipped
        ));
        match credits_for(snapshots, &v.identity, epoch) {
            Some(c) => lines.push(format!("  credits earned {}", with_commas(c))),
            None => lines.push("  credits earned: not reported".into()),
        }
        if let Some(b) = t.balance_lamports {
            lines.push(format!("  identity balance {}", sol(b)));
        }
        if let Some(b) = t.vote_lamports {
            let runway = vat_runway(snapshots, &v.identity, b)
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            lines.push(format!("  vote account {}{runway}", sol(b)));
        }
        if let Some(ver) = &t.version {
            lines.push(format!("  agave {ver}"));
        }
    }
    if lines.is_empty() {
        return None;
    }
    Some((format!("Epoch {epoch} summary"), lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_separators() {
        assert_eq!(with_commas(0), "0");
        assert_eq!(with_commas(999), "999");
        assert_eq!(with_commas(1000), "1,000");
        assert_eq!(with_commas(5_618_429), "5,618,429");
    }

    #[test]
    fn skip_percentage_is_of_leader_slots_and_absent_when_none() {
        let mut tails = HashMap::new();
        tails.insert("id".to_string(), EpochTail {
            epoch: 10, leader_slots: 40, blocks_produced: 38, balance_lamports: Some(18_796_000_000), vote_lamports: Some(6_481_200_000), version: Some("4.2.2".into()),
        });
        let config: Config = toml::from_str(r#"
            [[validators]]
            identity = "id"
            vote_account = "vote"
            label = "chimps"
        "#).unwrap();
        let (title, body) = render(10, &tails, &[], &config).unwrap();
        assert_eq!(title, "Epoch 10 summary");
        assert!(body.contains("chimps"), "{body}");
        assert!(body.contains("leader slots 40, produced 38, skipped 2 (5.0%)"), "{body}");
        assert!(body.contains("identity balance 18.80 SOL"), "{body}");
        assert!(body.contains("agave 4.2.2"), "{body}");
        // No Alpenglow state observed: the balance, but no VAT runway claim.
        assert!(body.contains("vote account 6.48 SOL\n"), "{body}");

        tails.get_mut("id").unwrap().leader_slots = 0;
        tails.get_mut("id").unwrap().blocks_produced = 0;
        let (_, body) = render(10, &tails, &[], &config).unwrap();
        assert!(body.contains("skipped 0\n"), "no percentage when there were no leader slots: {body}");
    }

    /// A tail from a different epoch must not be reported as this one's.
    #[test]
    fn a_stale_tail_is_not_reported() {
        let mut tails = HashMap::new();
        tails.insert("id".to_string(), EpochTail {
            epoch: 9, leader_slots: 1, blocks_produced: 1, balance_lamports: None, vote_lamports: None, version: None,
        });
        let config: Config = toml::from_str(r#"
            [[validators]]
            identity = "id"
            vote_account = "vote"
        "#).unwrap();
        assert_eq!(render(10, &tails, &[], &config), None);
    }

    /// Under Alpenglow the summary says how many epochs of VAT are left.
    #[test]
    fn the_vote_account_line_carries_vat_runway_under_alpenglow() {
        use crate::alpenglow::{ClusterVat, FeatureState};
        use crate::snapshot::EpochInfo;
        let mut snap = Snapshot::empty_for_test("a");
        snap.epoch_info = Some(EpochInfo { absolute_slot: 4_320_100, epoch: 10, slot_index: 100, slots_in_epoch: 432_000 });
        snap.alpenglow = Some(ClusterVat {
            alpenglow: FeatureState::Active(0),
            slot_time: [FeatureState::Absent; 4],
            rent_lamports: 19_761_200,
        });
        let mut tails = HashMap::new();
        tails.insert("id".to_string(), EpochTail {
            epoch: 10, leader_slots: 0, blocks_produced: 0, balance_lamports: None,
            vote_lamports: Some(6_481_200_000), version: None,
        });
        let config: Config = toml::from_str("[[validators]]\nidentity = \"id\"\n").unwrap();
        let (_, body) = render(10, &tails, std::slice::from_ref(&snap), &config).unwrap();
        // (6.4812 - 1.6198) / 1.6 + 1 = 4, with no income reported.
        assert!(body.contains("vote account 6.48 SOL: pays 1.60 SOL VAT per epoch: 4 more epoch(s)"), "{body}");

        // A mainnet vote account, measured: 0.637 SOL commission against a 1.6 SOL VAT here.
        let mut with_income = snap.clone();
        with_income.vote_income.insert("id".into(), 637_000_000);
        let (_, body) = render(10, &tails, &[with_income], &config).unwrap();
        assert!(body.contains("loses about 0.96 SOL per epoch (1.60 SOL VAT, 0.64 SOL commission income): about 6 epoch(s) left"), "{body}");
    }
}

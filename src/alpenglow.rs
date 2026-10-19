//! Alpenglow vote-account admission (SIMD-0357).
//!
//! Under Alpenglow, at the first slot of every epoch N+1 the runtime decides
//! which vote accounts take part in epoch N+2. A vote account is admitted only
//! if it
//!
//! 1. has a BLS public key registered,
//! 2. holds at least the rent-exempt minimum for a vote account plus one
//!    epoch's Validator Admission Ticket (VAT), and
//! 3. is among the 2,000 most-staked accounts that pass 1 and 2.
//!
//! Admitted accounts then have the VAT burned. One that fails cannot vote or
//! produce blocks for a whole epoch -- which is why this pages, and why it
//! warns while there is still an epoch to fix it in. Agave's own wording, from
//! the check it runs locally (core/src/replay_stage.rs):
//!
//! > Currently you will fail the VAT check at the start of epoch N+1 meaning
//! > that you will be unable to vote or produce blocks in epoch N+2.
//!
//! That check is only reachable over the validator's admin socket, which the
//! sandbox deliberately does not allow, so the same rules are evaluated here
//! from public RPC: the vote account and the rent minimum. Every constant
//! below is taken from Agave v4.3.0 and solana-vote-interface 6.1.0.
//!
//! The 2,000-account cap is not evaluated: it needs every other vote
//! account's BLS key and balance, and both clusters are far below it (mainnet
//! has under 700 staked vote accounts).
//!
//! No feature account is read. perch 1.3.0 ships after Alpenglow and every
//! slot-time reduction are active on every cluster it watches: 200ms slots
//! took effect on mainnet in epoch 1053 and on testnet earlier. The VAT is
//! therefore the 200ms amount, a constant. Pointed at a cluster still on
//! longer slots, or without Alpenglow, this check would be wrong.

use crate::verdict::Verdict;
use serde_json::Value;

/// `VoteStateV4::size_of()`: the same as V3, so accounts never need resizing.
pub const VOTE_STATE_V4_SIZE: u64 = 3762;

/// The VAT burned per epoch at 200ms slots (runtime/src/slot_params.rs).
pub const VAT_LAMPORTS: u64 = 800_000_000;

/// Slot duration, for turning slots into time.
pub const MS_PER_SLOT: u64 = 200;

/// Where the current epoch sits, from `getEpochInfo`.
#[derive(Debug, Clone, Copy)]
pub struct EpochPosition {
    pub epoch: u64,
    pub absolute_slot: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
}

impl EpochPosition {
    pub fn next_boundary_slot(&self) -> u64 {
        self.absolute_slot.saturating_sub(self.slot_index) + self.slots_in_epoch
    }
}

/// The admission requirement at the next epoch boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Requirement {
    /// The epoch whose first slot runs the check.
    pub checked_at_epoch: u64,
    pub vat_lamports: u64,
    /// Rent-exempt minimum for a `VoteStateV4`-sized account.
    pub rent_lamports: u64,
    pub slots_until_check: u64,
    pub slots_per_epoch: u64,
}

impl Requirement {
    pub fn minimum_lamports(&self) -> u64 {
        self.rent_lamports + self.vat_lamports
    }

    /// The epoch that is lost if the check fails.
    pub fn excluded_epoch(&self) -> u64 {
        self.checked_at_epoch + 1
    }

    pub fn hours_until_check(&self) -> f64 {
        self.slots_until_check as f64 * MS_PER_SLOT as f64 / 3_600_000.0
    }
}

pub fn requirement(rent_lamports: u64, pos: &EpochPosition) -> Requirement {
    Requirement {
        checked_at_epoch: pos.epoch + 1,
        vat_lamports: VAT_LAMPORTS,
        rent_lamports,
        slots_until_check: pos.next_boundary_slot().saturating_sub(pos.absolute_slot),
        slots_per_epoch: pos.slots_in_epoch,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bls {
    Registered,
    /// The account was parsed and reports no key.
    Missing,
    /// The endpoint's parser does not report the field at all. Not the same as
    /// Missing: an older RPC node must never make a registered key look absent.
    NotReported,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VoteAccountState {
    pub lamports: u64,
    pub bls: Bls,
    pub inflation_commission_bps: Option<u16>,
    pub block_revenue_commission_bps: Option<u16>,
}

impl VoteAccountState {
    /// From one `getMultipleAccounts` entry fetched with `jsonParsed`.
    pub fn from_account(account: &Value) -> Option<VoteAccountState> {
        let lamports = account["lamports"].as_u64()?;
        let info = &account["data"]["parsed"]["info"];
        if !info.is_object() {
            return None;
        }
        let bls = match info.get("blsPubkeyCompressed") {
            None => Bls::NotReported,
            Some(Value::Null) => Bls::Missing,
            Some(Value::String(s)) if !s.is_empty() => Bls::Registered,
            Some(_) => Bls::Missing,
        };
        let bps = |k: &str| {
            info.get(k)
                .and_then(Value::as_u64)
                .map(|v| v.min(u16::MAX as u64) as u16)
        };
        Some(VoteAccountState {
            lamports,
            bls,
            inflation_commission_bps: bps("inflationRewardsCommissionBps"),
            block_revenue_commission_bps: bps("blockRevenueCommissionBps"),
        })
    }
}

/// How long a vote account lasts against the VAT, counting the commission it
/// earns. Each boundary checks the balance, burns one VAT, and then pays the
/// commission for the epoch that just ended -- after the check, so this
/// epoch's income never rescues this boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Runway {
    /// Commission per epoch, from the last completed epoch. None when no
    /// endpoint keeps that history; the runway then assumes no income.
    pub income: Option<u64>,
    /// Income minus VAT. Negative is a vote account that drains.
    pub net_per_epoch: i64,
    /// Boundaries still passed before the balance falls short. None when the
    /// account is not draining at all.
    pub boundaries: Option<u64>,
}

pub fn runway(v: &VoteAccountState, req: &Requirement, income: Option<u64>) -> Runway {
    let earned = income.unwrap_or(0);
    let net_per_epoch = earned as i64 - req.vat_lamports as i64;
    let boundaries = if earned >= req.vat_lamports {
        None
    } else if v.lamports < req.minimum_lamports() {
        Some(0)
    } else {
        let drain = req.vat_lamports - earned;
        Some((v.lamports - req.minimum_lamports()) / drain + 1)
    };
    Runway {
        income,
        net_per_epoch,
        boundaries,
    }
}

/// "3 weeks", "4 days", "30 hours": how long `epochs` epochs take at the
/// current slot time.
fn epochs_as_time(epochs: u64, req: &Requirement) -> String {
    let hours = epochs as f64 * req.slots_per_epoch as f64 * MS_PER_SLOT as f64 / 3_600_000.0;
    if hours < 48.0 {
        format!("{hours:.0} hours")
    } else if hours < 24.0 * 14.0 {
        format!("{:.0} days", hours / 24.0)
    } else {
        format!("{:.0} weeks", hours / (24.0 * 7.0))
    }
}

impl Runway {
    /// The sentence the alert, `perch status` and the epoch summary share.
    pub fn describe(&self, req: &Requirement) -> String {
        let vat = sol(req.vat_lamports);
        match (self.income, self.boundaries) {
            (Some(income), None) => format!(
                "gains about {:.2} SOL per epoch ({:.2} SOL commission against a {vat:.2} SOL VAT), \
                 so it is not draining",
                sol(self.net_per_epoch as u64),
                sol(income)
            ),
            (Some(income), Some(n)) => format!(
                "loses about {:.2} SOL per epoch ({vat:.2} SOL VAT, {:.2} SOL commission income): \
                 about {n} epoch(s) left, roughly {}",
                sol(self.net_per_epoch.unsigned_abs()),
                sol(income),
                epochs_as_time(n, req)
            ),
            (None, Some(n)) => format!(
                "pays {vat:.2} SOL VAT per epoch: {n} more epoch(s), roughly {}, assuming no \
                 commission income (no endpoint reports its history)",
                epochs_as_time(n, req)
            ),
            // No income means a positive VAT drains, so this cannot happen.
            (None, None) => "is not draining".into(),
        }
    }
}

fn sol(lamports: u64) -> f64 {
    lamports as f64 / 1e9
}

fn deadline(req: &Requirement) -> String {
    let h = req.hours_until_check();
    if h < 1.0 {
        format!("in about {:.0} minutes", h * 60.0)
    } else {
        format!("in about {h:.0}h")
    }
}

/// Will this vote account be admitted at the next boundary? Pages.
pub fn critical(who: &str, v: &VoteAccountState, req: &Requirement) -> Verdict {
    let mut reasons = Vec::new();
    if v.bls == Bls::Missing {
        reasons.push("its vote account has no BLS public key registered".to_string());
    }
    if v.lamports < req.minimum_lamports() {
        reasons.push(format!(
            "its vote account holds {:.4} SOL and needs {:.4} SOL (rent-exempt {:.4} plus one \
             epoch's VAT {:.2}): {:.4} SOL short",
            sol(v.lamports),
            sol(req.minimum_lamports()),
            sol(req.rent_lamports),
            sol(req.vat_lamports),
            sol(req.minimum_lamports() - v.lamports)
        ));
    }
    if reasons.is_empty() {
        if v.bls == Bls::NotReported {
            return Verdict::unknown("endpoint does not report vote-account BLS keys");
        }
        return Verdict::Healthy;
    }
    Verdict::unhealthy(format!(
        "{who} will fail the VAT check at the start of epoch {}, {}: {}. It will be unable to vote \
         or produce blocks in epoch {}.",
        req.checked_at_epoch,
        deadline(req),
        reasons.join("; "),
        req.excluded_epoch()
    ))
}

/// Runway: a vote account that passes the next boundary but will not pass
/// many more. Telegram only.
pub fn warn(
    who: &str,
    v: &VoteAccountState,
    req: &Requirement,
    income: Option<u64>,
    warn_boundaries: u64,
) -> Verdict {
    let r = runway(v, req, income);
    let short = r.boundaries.is_some_and(|n| n < warn_boundaries);
    // The critical band owns anything that fails at the next boundary.
    if v.bls == Bls::Missing || v.lamports < req.minimum_lamports() {
        return Verdict::Healthy;
    }
    if short {
        return Verdict::unhealthy(format!(
            "{who}'s vote account holds {:.4} SOL and {}. Top it up before it falls under {:.4} SOL.",
            sol(v.lamports),
            r.describe(req),
            sol(req.minimum_lamports())
        ));
    }
    Verdict::Healthy
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SOL: u64 = 1_000_000_000;

    /// Rent-exempt minimum for a vote account, as both clusters report it.
    const RENT: u64 = 19_761_200;

    /// testnet, measured: epoch 1049 at slot 447,765,650. Epoch 1049 starts at
    /// 447,644,256: testnet had a warmup period, so this is
    /// `524_256 + (1049 - 14) * 432_000`, not `1049 * 432_000`.
    fn testnet() -> EpochPosition {
        EpochPosition {
            epoch: 1049,
            absolute_slot: 447_765_650,
            slot_index: 447_765_650 - 447_644_256,
            slots_in_epoch: 432_000,
        }
    }

    /// mainnet, measured 2026-10-19: epoch 1062 at slot 458,953,791.
    fn mainnet() -> EpochPosition {
        EpochPosition {
            epoch: 1062,
            absolute_slot: 458_953_791,
            slot_index: 169_791,
            slots_in_epoch: 432_000,
        }
    }

    fn vote(lamports: u64, bls: Bls) -> VoteAccountState {
        VoteAccountState {
            lamports,
            bls,
            inflation_commission_bps: Some(500),
            block_revenue_commission_bps: Some(10_000),
        }
    }

    #[test]
    fn the_vat_is_the_200ms_amount() {
        let r = requirement(RENT, &mainnet());
        assert_eq!(r.vat_lamports, 800_000_000);
        assert_eq!(r.minimum_lamports(), 19_761_200 + 800_000_000);
    }

    #[test]
    fn the_next_boundary_matches_the_cluster() {
        // Epoch 1062 starts at 458,784,000.
        assert_eq!(mainnet().next_boundary_slot(), 459_216_000);
    }

    /// Checked against the cluster: testnet's warmup offset puts the boundary
    /// into 1050 at 448,076,256, 310,606 slots or about 17h at 200ms away.
    #[test]
    fn the_deadline_survives_testnets_warmup_offset() {
        let p = testnet();
        assert_eq!(p.next_boundary_slot(), 448_076_256);
        assert!((requirement(RENT, &p).hours_until_check() - 17.25).abs() < 0.01);
    }

    #[test]
    fn an_underfunded_vote_account_pages_with_the_epoch_it_loses() {
        let r = requirement(RENT, &testnet());
        let v = critical("chimp-test", &vote(500_000_000, Bls::Registered), &r);
        let Verdict::Unhealthy(msg) = v else {
            panic!("{v:?}")
        };
        assert!(msg.contains("start of epoch 1050"), "{msg}");
        assert!(msg.contains("epoch 1051"), "{msg}");
        assert!(msg.contains("0.5000 SOL and needs 0.8198 SOL"), "{msg}");
    }

    #[test]
    fn a_missing_bls_key_pages_whatever_the_balance() {
        let r = requirement(RENT, &testnet());
        let v = critical("x", &vote(1_000 * SOL, Bls::Missing), &r);
        assert!(
            matches!(&v, Verdict::Unhealthy(m) if m.contains("no BLS public key")),
            "{v:?}"
        );
    }

    /// An RPC node too old to report the field must not page a validator that
    /// has a key.
    #[test]
    fn an_unreported_bls_field_is_unknown_not_missing() {
        let r = requirement(RENT, &testnet());
        assert!(matches!(
            critical("x", &vote(1_000 * SOL, Bls::NotReported), &r),
            Verdict::Unknown(_)
        ));
        // A balance shortfall is still a definite answer.
        assert!(matches!(
            critical("x", &vote(1, Bls::NotReported), &r),
            Verdict::Unhealthy(_)
        ));
    }

    #[test]
    fn runway_warns_in_its_own_band() {
        let r = requirement(RENT, &testnet());
        // Two VATs above rent: passes the next boundary, warns at 3.
        let two = vote(r.rent_lamports + 2 * r.vat_lamports, Bls::Registered);
        assert_eq!(critical("x", &two, &r), Verdict::Healthy);
        assert!(matches!(
            warn("x", &two, &r, None, 3),
            Verdict::Unhealthy(_)
        ));
        // Failing the next boundary is the critical band's alone.
        let short = vote(r.rent_lamports, Bls::Registered);
        assert_eq!(warn("x", &short, &r, None, 3), Verdict::Healthy);
        // Plenty.
        assert_eq!(
            warn("x", &vote(56_528 * SOL, Bls::Registered), &r, None, 3),
            Verdict::Healthy
        );
    }

    /// Shapes the RPC really returns (mainnet, 2026-10-02).
    #[test]
    fn vote_accounts_parse_from_json_parsed() {
        let account = json!({"lamports": 6_481_200_000u64, "data": {"parsed": {"type": "vote", "info": {
            "blsPubkeyCompressed": "BLSPUBKEYPLACEHOLDER",
            "inflationRewardsCommissionBps": 500, "blockRevenueCommissionBps": 10000, "commission": 5}}}});
        let v = VoteAccountState::from_account(&account).unwrap();
        assert_eq!(v.bls, Bls::Registered);
        assert_eq!(v.inflation_commission_bps, Some(500));
        assert_eq!(v.block_revenue_commission_bps, Some(10_000));

        let none =
            json!({"lamports": 1, "data": {"parsed": {"info": {"blsPubkeyCompressed": null}}}});
        assert_eq!(
            VoteAccountState::from_account(&none).unwrap().bls,
            Bls::Missing
        );
        let old = json!({"lamports": 1, "data": {"parsed": {"info": {"commission": 5}}}});
        assert_eq!(
            VoteAccountState::from_account(&old).unwrap().bls,
            Bls::NotReported
        );
        assert_eq!(VoteAccountState::from_account(&Value::Null), None);
    }

    /// mainnet as measured.
    fn mainnet_active() -> Requirement {
        requirement(RENT, &mainnet())
    }

    /// A mainnet vote account, measured: 6.4812 SOL and 0.637 SOL commission an
    /// epoch, against the 0.8 SOL VAT. (6.4812 - 0.8198) / 0.163 = 34.7, plus
    /// the boundary it passes now: 35.
    #[test]
    fn runway_counts_commission_income() {
        let req = mainnet_active();
        let r = runway(
            &vote(6_481_200_000, Bls::Registered),
            &req,
            Some(637_000_000),
        );
        assert_eq!(r.boundaries, Some(35));
        assert_eq!(r.net_per_epoch, -163_000_000);
        let text = r.describe(&req);
        assert!(
            text.contains(
                "loses about 0.16 SOL per epoch (0.80 SOL VAT, 0.64 SOL commission income)"
            ),
            "{text}"
        );
        // 35 epochs of 432,000 slots at 200ms is 35 days.
        assert!(
            text.contains("about 35 epoch(s) left, roughly 5 weeks"),
            "{text}"
        );
    }

    /// refi-main, measured: the lowest balance of the five, and the only one
    /// whose commission more than pays the VAT. It must not be the one warned.
    #[test]
    fn a_vote_account_that_earns_more_than_the_vat_never_warns() {
        let req = mainnet_active();
        let refi = vote(2_508_700_000, Bls::Registered);
        let r = runway(&refi, &req, Some(1_227_000_000));
        assert_eq!(r.boundaries, None);
        assert!(
            r.describe(&req).contains("gains about 0.43 SOL per epoch"),
            "{}",
            r.describe(&req)
        );
        // Without the income it passes only three more boundaries, so a
        // four-boundary warning would fire; the income is what keeps it quiet.
        assert_eq!(
            warn("refi-main", &refi, &req, Some(1_227_000_000), 4),
            Verdict::Healthy
        );
        assert!(matches!(
            warn("refi-main", &refi, &req, None, 4),
            Verdict::Unhealthy(_)
        ));
    }

    /// With no income known, runway is exactly the old no-income count.
    #[test]
    fn unknown_income_is_the_no_income_estimate_and_says_so() {
        let req = mainnet_active();
        let v = vote(6_481_200_000, Bls::Registered);
        let r = runway(&v, &req, None);
        assert_eq!(
            r.boundaries,
            Some((v.lamports - req.rent_lamports) / req.vat_lamports)
        );
        assert!(
            r.describe(&req).contains("assuming no commission income"),
            "{}",
            r.describe(&req)
        );
    }

    #[test]
    fn a_short_runway_warns_with_the_net_drain() {
        let req = mainnet_active();
        // 2 VATs above the minimum, earning a fifth of one: 3 boundaries.
        let v = vote(
            req.minimum_lamports() + 2 * req.vat_lamports,
            Bls::Registered,
        );
        let w = warn("x", &v, &req, Some(200_000_000), 4);
        assert!(
            matches!(&w, Verdict::Unhealthy(m) if m.contains("loses about 0.60 SOL") && m.contains("about 3 epoch(s) left")),
            "{w:?}"
        );
    }

    /// fox-main's vote account, swept to rent by a routine commission
    /// withdrawal: Alpenglow is assumed active, so that is the critical band's
    /// page, and the warning stays out of it.
    #[test]
    fn a_vote_account_swept_to_rent_pages() {
        let req = mainnet_active();
        let swept = vote(19_761_200, Bls::Registered);
        assert!(matches!(critical("fox-main", &swept, &req), Verdict::Unhealthy(_)));
        assert_eq!(warn("fox-main", &swept, &req, Some(740_000_000), 3), Verdict::Healthy);
    }
}

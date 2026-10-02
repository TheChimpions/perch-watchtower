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
//! from public RPC: the feature accounts, the vote account, and the rent
//! minimum. Every constant below is taken from Agave v4.3.0 and
//! solana-vote-interface 6.1.0.
//!
//! The 2,000-account cap is not evaluated: it needs every other vote
//! account's BLS key and balance, and both clusters are far below it (mainnet
//! has under 700 staked vote accounts).

use crate::verdict::Verdict;
use base64::Engine as _;
use serde_json::Value;

pub const ALPENGLOW_FEATURE: &str = "A1pengvuM6JEcyNuTnMqepBKhwHE3N6PmUrdATGawhJS";

/// `VoteStateV4::size_of()`: the same as V3, so accounts never need resizing.
pub const VOTE_STATE_V4_SIZE: u64 = 3762;

/// The VAT burned per epoch before any slot-time reduction (400ms slots).
pub const LEGACY_VAT_LAMPORTS: u64 = 1_600_000_000;

/// Slot-time reductions: feature id, slot duration in milliseconds, VAT.
/// runtime/src/slot_params.rs.
pub const SLOT_TIME_FEATURES: [(&str, u64, u64); 4] = [
    (
        "iBRL5RuWhw4yqaAZu96RUULHckHTZAoe2b77qaV38JZ",
        350,
        1_400_000_000,
    ),
    (
        "iBRLL3k18HST852F1Mf3Lv83waTNQmmqvKDxvYGwQFL",
        300,
        1_200_000_000,
    ),
    (
        "iBRLMc81UjRa8fn8A6eE8bJTnRbgQoPTynM51akENCV",
        250,
        1_000_000_000,
    ),
    (
        "iBRLjhJnkmDZgNoZRDMW11d8ZV7HvsL3vAyRjZB5npW",
        200,
        800_000_000,
    ),
];

/// Every feature account this module reads, in a fixed order.
pub fn feature_accounts() -> Vec<&'static str> {
    std::iter::once(ALPENGLOW_FEATURE)
        .chain(SLOT_TIME_FEATURES.iter().map(|(id, _, _)| *id))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureState {
    /// No feature account: nobody has scheduled it.
    Absent,
    /// The account exists and is not yet activated. The runtime activates
    /// pending features at the next epoch boundary.
    Pending,
    Active(u64),
}

impl FeatureState {
    /// A feature account is bincode `Feature { activated_at: Option<u64> }`.
    /// The RPC hands it back as `[base64, "base64"]` even under jsonParsed,
    /// because nothing parses the feature program's accounts.
    pub fn from_account(account: &Value) -> Option<FeatureState> {
        if account.is_null() {
            return Some(FeatureState::Absent);
        }
        let b64 = account["data"].get(0)?.as_str()?;
        let data = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        match data.first()? {
            0 => Some(FeatureState::Pending),
            1 if data.len() >= 9 => {
                let mut slot = [0u8; 8];
                slot.copy_from_slice(&data[1..9]);
                Some(FeatureState::Active(u64::from_le_bytes(slot)))
            }
            _ => None,
        }
    }
}

/// What the cluster's feature accounts and rent say, as one endpoint saw them.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterVat {
    pub alpenglow: FeatureState,
    pub slot_time: [FeatureState; 4],
    /// Rent-exempt minimum for a `VoteStateV4`-sized account.
    pub rent_lamports: u64,
}

/// Where the current epoch sits, from `getEpochInfo`.
#[derive(Debug, Clone, Copy)]
pub struct EpochPosition {
    pub epoch: u64,
    pub absolute_slot: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
}

impl EpochPosition {
    fn epoch_start(&self) -> u64 {
        self.absolute_slot.saturating_sub(self.slot_index)
    }

    pub fn next_boundary_slot(&self) -> u64 {
        self.epoch_start() + self.slots_in_epoch
    }

    /// The epoch containing `slot`. Exact for any slot after the cluster's
    /// warmup period, which every feature activation on a real cluster is.
    pub fn epoch_of(&self, slot: u64) -> u64 {
        let start = self.epoch_start() as i128;
        let len = self.slots_in_epoch.max(1) as i128;
        let delta = (slot as i128 - start).div_euclid(len);
        (self.epoch as i128 + delta).max(0) as u64
    }

    fn first_slot_of(&self, epoch: u64) -> u64 {
        let start = self.epoch_start() as i128;
        let len = self.slots_in_epoch as i128;
        (start + (epoch as i128 - self.epoch as i128) * len).max(0) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Alpenglow is not scheduled. Nothing is enforced yet; readiness only.
    NotScheduled,
    /// Scheduled: it activates at the next boundary, and because feature
    /// activation runs before epoch stakes are computed, that same boundary
    /// already applies the admission check.
    ActivatesAtNextBoundary,
    Active,
}

/// The admission requirement at the next epoch boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Requirement {
    pub phase: Phase,
    /// The epoch whose first slot runs the check.
    pub checked_at_epoch: u64,
    pub vat_lamports: u64,
    pub rent_lamports: u64,
    pub slots_until_check: u64,
    /// Current slot duration, for turning slots into time.
    pub ms_per_slot: u64,
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
        self.slots_until_check as f64 * self.ms_per_slot as f64 / 3_600_000.0
    }
}

/// Slot duration and VAT in effect at `slot`. A reduction takes effect at the
/// first slot of the epoch after it activates; the shortest one in effect
/// wins, because slot time never increases.
fn params_at(cluster: &ClusterVat, pos: &EpochPosition, slot: u64) -> (u64, u64) {
    let mut best = (400, LEGACY_VAT_LAMPORTS);
    for (state, (_, ms, vat)) in cluster.slot_time.iter().zip(SLOT_TIME_FEATURES) {
        if let FeatureState::Active(activated) = state {
            let effective = pos.first_slot_of(pos.epoch_of(*activated) + 1);
            if effective <= slot && ms < best.0 {
                best = (ms, vat);
            }
        }
    }
    best
}

pub fn requirement(cluster: &ClusterVat, pos: &EpochPosition) -> Requirement {
    let boundary = pos.next_boundary_slot();
    let phase = match cluster.alpenglow {
        FeatureState::Absent => Phase::NotScheduled,
        FeatureState::Pending => Phase::ActivatesAtNextBoundary,
        FeatureState::Active(_) => Phase::Active,
    };
    let (_, vat_lamports) = params_at(cluster, pos, boundary);
    let (ms_per_slot, _) = params_at(cluster, pos, pos.absolute_slot);
    Requirement {
        phase,
        checked_at_epoch: pos.epoch + 1,
        vat_lamports,
        rent_lamports: cluster.rent_lamports,
        slots_until_check: boundary.saturating_sub(pos.absolute_slot),
        ms_per_slot,
        slots_per_epoch: pos.slots_in_epoch,
    }
}

/// Alpenglow was in force for the epoch now running, so votes no longer cost
/// the identity anything. Measured on testnet: identity balances fell ~1.9 SOL
/// a day until the switch, then started rising.
pub fn active_this_epoch(cluster: &ClusterVat, pos: &EpochPosition) -> bool {
    matches!(cluster.alpenglow, FeatureState::Active(slot) if pos.epoch_of(slot) <= pos.epoch)
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
    let hours = epochs as f64 * req.slots_per_epoch as f64 * req.ms_per_slot as f64 / 3_600_000.0;
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
        self.phrase(req, false)
    }

    /// The same, as what would happen once Alpenglow activates.
    pub fn describe_hypothetically(&self, req: &Requirement) -> String {
        format!("under Alpenglow it would {}", self.phrase(req, true))
    }

    fn phrase(&self, req: &Requirement, would: bool) -> String {
        let verb = |present: &'static str, base: &'static str| if would { base } else { present };
        let vat = sol(req.vat_lamports);
        match (self.income, self.boundaries) {
            (Some(income), None) => format!(
                "{} about {:.2} SOL per epoch ({:.2} SOL commission against a {vat:.2} SOL VAT), \
                 so it is not draining",
                verb("gains", "gain"),
                sol(self.net_per_epoch as u64),
                sol(income)
            ),
            (Some(income), Some(n)) => format!(
                "{} about {:.2} SOL per epoch ({vat:.2} SOL VAT, {:.2} SOL commission income): \
                 about {n} epoch(s) left, roughly {}",
                verb("loses", "lose"),
                sol(self.net_per_epoch.unsigned_abs()),
                sol(income),
                epochs_as_time(n, req)
            ),
            (None, Some(n)) => format!(
                "{} {vat:.2} SOL VAT per epoch: {n} more epoch(s), roughly {}, assuming no \
                 commission income (no endpoint reports its history)",
                verb("pays", "pay"),
                epochs_as_time(n, req)
            ),
            // No income means a positive VAT drains, so this cannot happen.
            (None, None) => verb("is not draining", "not drain").into(),
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
    if req.phase == Phase::NotScheduled {
        return Verdict::Healthy;
    }
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
    let activation = if req.phase == Phase::ActivatesAtNextBoundary {
        " Alpenglow is scheduled to activate at that boundary."
    } else {
        ""
    };
    Verdict::unhealthy(format!(
        "{who} will fail the VAT check at the start of epoch {}, {}: {}. It will be unable to vote \
         or produce blocks in epoch {}.{activation}",
        req.checked_at_epoch,
        deadline(req),
        reasons.join("; "),
        req.excluded_epoch()
    ))
}

/// Runway, and readiness before Alpenglow is scheduled. Telegram only.
pub fn warn(
    who: &str,
    v: &VoteAccountState,
    req: &Requirement,
    income: Option<u64>,
    warn_boundaries: u64,
) -> Verdict {
    let r = runway(v, req, income);
    let short = r.boundaries.is_some_and(|n| n < warn_boundaries);
    if req.phase == Phase::NotScheduled {
        let mut reasons = Vec::new();
        if v.bls == Bls::Missing {
            reasons.push("no BLS public key is registered on its vote account".to_string());
        }
        if v.lamports < req.minimum_lamports() {
            reasons.push(format!(
                "its vote account holds {:.4} SOL, under the {:.4} SOL it must hold at every \
                 epoch boundary",
                sol(v.lamports),
                sol(req.minimum_lamports())
            ));
        } else if short {
            reasons.push(format!(
                "its vote account holds {:.4} SOL, and {}",
                sol(v.lamports),
                r.describe_hypothetically(req)
            ));
        }
        if reasons.is_empty() {
            return Verdict::Healthy;
        }
        return Verdict::unhealthy(format!(
            "{who} is not ready for Alpenglow: {}. Once Alpenglow activates, a vote account in \
             this state cannot vote or produce blocks.",
            reasons.join("; ")
        ));
    }
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

    fn feature(active_at: Option<u64>) -> Value {
        let mut d = vec![active_at.is_some() as u8];
        if let Some(s) = active_at {
            d.extend_from_slice(&s.to_le_bytes());
        }
        json!({"data": [base64::engine::general_purpose::STANDARD.encode(d), "base64"], "lamports": 1})
    }

    /// testnet, measured: epoch 1049 at slot 447,765,650, with Alpenglow
    /// activated at 444,620,256 and every slot-time reduction active. Epoch
    /// 1049 starts at 447,644,256: testnet had a warmup period, so this is
    /// `524_256 + (1049 - 14) * 432_000`, not `1049 * 432_000`.
    fn testnet() -> (ClusterVat, EpochPosition) {
        let pos = EpochPosition {
            epoch: 1049,
            absolute_slot: 447_765_650,
            slot_index: 447_765_650 - 447_644_256,
            slots_in_epoch: 432_000,
        };
        let cluster = ClusterVat {
            alpenglow: FeatureState::Active(444_620_256),
            slot_time: [426_476_256, 427_340_256, 428_204_256, 429_068_256]
                .map(FeatureState::Active),
            rent_lamports: 19_761_200,
        };
        (cluster, pos)
    }

    /// mainnet, measured: 350/300/250ms active, 200ms and Alpenglow absent.
    fn mainnet() -> (ClusterVat, EpochPosition) {
        let pos = EpochPosition {
            epoch: 1047,
            absolute_slot: 452_690_556,
            slot_index: 452_690_556 - 452_304_000,
            slots_in_epoch: 432_000,
        };
        let cluster = ClusterVat {
            alpenglow: FeatureState::Absent,
            slot_time: [
                FeatureState::Active(440_208_000),
                FeatureState::Active(441_936_000),
                FeatureState::Active(447_552_000),
                FeatureState::Absent,
            ],
            rent_lamports: 19_761_200,
        };
        (cluster, pos)
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
    fn feature_accounts_parse_into_three_states() {
        assert_eq!(
            FeatureState::from_account(&Value::Null),
            Some(FeatureState::Absent)
        );
        assert_eq!(
            FeatureState::from_account(&feature(None)),
            Some(FeatureState::Pending)
        );
        assert_eq!(
            FeatureState::from_account(&feature(Some(444_620_256))),
            Some(FeatureState::Active(444_620_256))
        );
        // What testnet actually returned for the Alpenglow feature account.
        let real = json!({"data": ["AeBdgBoAAAAA", "base64"]});
        assert_eq!(
            FeatureState::from_account(&real),
            Some(FeatureState::Active(0x1a80_5de0))
        );
    }

    #[test]
    fn the_vat_follows_the_shortest_slot_time_in_effect() {
        let (c, p) = testnet();
        let r = requirement(&c, &p);
        assert_eq!(r.vat_lamports, 800_000_000, "200ms is in effect on testnet");
        assert_eq!(r.ms_per_slot, 200);
        assert_eq!(r.minimum_lamports(), 19_761_200 + 800_000_000);

        let (c, p) = mainnet();
        let r = requirement(&c, &p);
        assert_eq!(
            r.vat_lamports, 1_000_000_000,
            "250ms took effect in epoch 1037"
        );
        assert_eq!(r.phase, Phase::NotScheduled);
    }

    /// A reduction activates in one epoch and takes effect at the start of the
    /// next. 250ms activated at the first slot of mainnet epoch 1036, so a
    /// boundary into 1036 itself still burns the 300ms amount.
    #[test]
    fn a_reduction_takes_effect_the_epoch_after_it_activates() {
        let (c, _) = mainnet();
        let pos = EpochPosition {
            epoch: 1035,
            absolute_slot: 447_200_000,
            slot_index: 447_200_000 - 447_120_000,
            slots_in_epoch: 432_000,
        };
        let mut c = c;
        c.slot_time[2] = FeatureState::Active(447_552_000);
        assert_eq!(requirement(&c, &pos).vat_lamports, 1_200_000_000);
    }

    #[test]
    fn no_reductions_means_the_legacy_vat() {
        let (mut c, p) = mainnet();
        c.slot_time = [FeatureState::Absent; 4];
        let r = requirement(&c, &p);
        assert_eq!(r.vat_lamports, LEGACY_VAT_LAMPORTS);
        assert_eq!(r.ms_per_slot, 400);
    }

    #[test]
    fn epoch_arithmetic_matches_the_cluster() {
        let (_, p) = mainnet();
        assert_eq!(p.epoch_of(447_552_000), 1036);
        assert_eq!(p.epoch_of(452_304_000), 1047);
        assert_eq!(p.epoch_of(452_303_999), 1046);
        assert_eq!(p.next_boundary_slot(), 452_736_000);
    }

    /// Every epoch number here was checked against the cluster: a testnet
    /// perch's own alert log puts slot 444,628,562 in epoch 1042, 1.9% complete.
    #[test]
    fn epoch_arithmetic_survives_testnets_warmup_offset() {
        let (_, p) = testnet();
        assert_eq!(
            p.epoch_of(444_620_256),
            1042,
            "Alpenglow activated at the start of 1042"
        );
        assert_eq!(p.epoch_of(444_628_562), 1042);
        assert_eq!(p.next_boundary_slot(), 448_076_256);
        // 310,606 slots at 200ms.
        let (c, _) = testnet();
        assert!((requirement(&c, &p).hours_until_check() - 17.25).abs() < 0.01);
    }

    #[test]
    fn an_underfunded_vote_account_pages_with_the_epoch_it_loses() {
        let (c, p) = testnet();
        let r = requirement(&c, &p);
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
        let (c, p) = testnet();
        let r = requirement(&c, &p);
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
        let (c, p) = testnet();
        let r = requirement(&c, &p);
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
    fn nothing_pages_before_alpenglow_is_scheduled() {
        let (c, p) = mainnet();
        let r = requirement(&c, &p);
        assert_eq!(critical("x", &vote(0, Bls::Missing), &r), Verdict::Healthy);
        // ...but readiness is reported, on Telegram.
        let w = warn("x", &vote(0, Bls::Missing), &r, None, 3);
        assert!(
            matches!(&w, Verdict::Unhealthy(m) if m.contains("not ready for Alpenglow")),
            "{w:?}"
        );
        assert_eq!(
            warn("x", &vote(6_481_200_000, Bls::Registered), &r, None, 3),
            Verdict::Healthy
        );
    }

    /// Feature activation runs before epoch stakes are computed, so the
    /// boundary that activates Alpenglow already enforces it.
    #[test]
    fn a_scheduled_activation_is_enforced_at_the_next_boundary() {
        let (mut c, p) = mainnet();
        c.alpenglow = FeatureState::Pending;
        let r = requirement(&c, &p);
        assert_eq!(r.phase, Phase::ActivatesAtNextBoundary);
        let v = critical("chimpions-mainnet", &vote(0, Bls::Registered), &r);
        assert!(
            matches!(&v, Verdict::Unhealthy(m) if m.contains("scheduled to activate")),
            "{v:?}"
        );
    }

    #[test]
    fn runway_warns_in_its_own_band() {
        let (c, p) = testnet();
        let r = requirement(&c, &p);
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

    #[test]
    fn identity_stops_paying_for_votes_the_epoch_alpenglow_is_active() {
        let (c, p) = testnet();
        assert!(active_this_epoch(&c, &p));
        let (mut c, p) = mainnet();
        assert!(!active_this_epoch(&c, &p));
        c.alpenglow = FeatureState::Pending;
        assert!(!active_this_epoch(&c, &p), "scheduled is not yet in force");
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

    /// mainnet with Alpenglow active, everything else as measured.
    fn mainnet_active() -> Requirement {
        let (mut c, p) = mainnet();
        c.alpenglow = FeatureState::Active(0);
        requirement(&c, &p)
    }

    /// A mainnet vote account, measured: 6.4812 SOL, 0.637 SOL commission a 250ms epoch,
    /// against a 1.0 SOL VAT. (6.4812 - 1.0198) / 0.363 = 15.04, plus the
    /// boundary it passes now: 16.
    #[test]
    fn runway_counts_commission_income() {
        let req = mainnet_active();
        let r = runway(
            &vote(6_481_200_000, Bls::Registered),
            &req,
            Some(637_000_000),
        );
        assert_eq!(r.boundaries, Some(16));
        assert_eq!(r.net_per_epoch, -363_000_000);
        let text = r.describe(&req);
        assert!(
            text.contains(
                "loses about 0.36 SOL per epoch (1.00 SOL VAT, 0.64 SOL commission income)"
            ),
            "{text}"
        );
        // 16 epochs of 432,000 slots at 250ms is 20 days.
        assert!(
            text.contains("about 16 epoch(s) left, roughly 3 weeks"),
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
            r.describe(&req).contains("gains about 0.23 SOL per epoch"),
            "{}",
            r.describe(&req)
        );
        assert_eq!(
            warn("refi-main", &refi, &req, Some(1_227_000_000), 3),
            Verdict::Healthy
        );
        // Without the income it would have warned, which is the old behaviour.
        assert!(matches!(
            warn("refi-main", &refi, &req, None, 3),
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
            matches!(&w, Verdict::Unhealthy(m) if m.contains("loses about 0.80 SOL") && m.contains("about 3 epoch(s) left")),
            "{w:?}"
        );
    }

    /// Before Alpenglow is scheduled, a short hypothetical runway is reported
    /// as readiness, in the conditional.
    #[test]
    fn readiness_reports_a_drain_before_it_starts() {
        let (c, p) = mainnet();
        let req = requirement(&c, &p);
        let v = vote(req.minimum_lamports() + req.vat_lamports, Bls::Registered);
        let w = warn("x", &v, &req, Some(0), 3);
        assert!(
            matches!(&w, Verdict::Unhealthy(m) if m.contains("under Alpenglow it would lose")),
            "{w:?}"
        );
        // The measured numbers above: 16 epochs is not short.
        assert_eq!(
            warn(
                "x",
                &vote(6_481_200_000, Bls::Registered),
                &req,
                Some(637_000_000),
                3
            ),
            Verdict::Healthy
        );
    }
}

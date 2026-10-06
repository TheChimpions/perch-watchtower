//! Taking one observation of the network from one endpoint.
//!
//! Every field is fallible and independently so: a `getBalance` that times out
//! must not poison the delinquency reading taken from the same endpoint in the
//! same cycle. Upstream's `get_cluster_info` uses `?` on every call, so one
//! slow balance lookup discards the whole snapshot.

use crate::{
    config::{Config, ValidatorConfig},
    rpc::{Endpoint, RpcError},
    verdict::Verdict,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{debug, warn};

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL as f64
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochInfo {
    pub absolute_slot: u64,
    pub epoch: u64,
    #[serde(default)]
    pub slot_index: u64,
    #[serde(default)]
    pub slots_in_epoch: u64,
}

impl EpochInfo {
    /// How far through the epoch we are. Useful triage context: a problem at
    /// 99% of an epoch has very different urgency to one at 2%.
    pub fn epoch_percent(&self) -> f64 {
        if self.slots_in_epoch == 0 {
            return 0.0;
        }
        self.slot_index as f64 * 100.0 / self.slots_in_epoch as f64
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteAccountInfo {
    pub vote_pubkey: String,
    pub node_pubkey: String,
    #[serde(default)]
    pub activated_stake: u64,
    #[serde(default)]
    pub commission: u8,
    #[serde(default)]
    pub last_vote: u64,
    #[serde(default)]
    pub root_slot: u64,
    /// `[(epoch, credits, previous_credits)]`
    #[serde(default)]
    pub epoch_credits: Vec<(u64, u64, u64)>,
}

/// A row the chain emits that does not describe a real epoch.
///
/// During the September 2026 testnet protocol transition, 91% of vote accounts
/// began carrying a `[u64::MAX, u64::MAX, u64::MAX]` entry. Picking "the latest
/// epoch" by maximum epoch number then selected the sentinel every time, so the
/// lifetime counter read `u64::MAX` and no real reading could ever exceed it --
/// a permanent "earning no vote credits" on a validator that was voting fine.
/// Mainnet showed none of these, which is exactly why a watchtower must not
/// assume the shape of a reply it did not produce.
fn is_sentinel(&(epoch, credits, prev): &(u64, u64, u64)) -> bool {
    epoch == u64::MAX || credits == u64::MAX || prev == u64::MAX
}

impl VoteAccountInfo {
    fn real_epochs(&self) -> impl Iterator<Item = &(u64, u64, u64)> {
        self.epoch_credits.iter().filter(|e| !is_sentinel(e))
    }

    /// Credits earned so far in the most recent real epoch.
    ///
    /// That epoch may appear more than once -- 87% of testnet accounts carried
    /// duplicate rows for epoch 1042 -- so the span is measured from the lowest
    /// starting point to the highest ending point across all of its rows.
    pub fn current_epoch_credits(&self) -> u64 {
        let Some(latest) = self.real_epochs().map(|(e, _, _)| *e).max() else {
            return 0;
        };
        let rows = || self.real_epochs().filter(|(e, _, _)| *e == latest);
        let end = rows().map(|(_, c, _)| *c).max().unwrap_or(0);
        let start = rows().map(|(_, _, p)| *p).min().unwrap_or(0);
        end.saturating_sub(start)
    }

    /// Lifetime credits, monotonic across epochs -- the progress counter used to
    /// detect a stall independently of the `delinquent` flag.
    ///
    /// Taken as the maximum over real rows rather than the newest row, so
    /// duplicate or out-of-order entries cannot make a monotonic counter appear
    /// to go backwards.
    pub fn total_credits(&self) -> u64 {
        self.real_epochs().map(|(_, c, _)| *c).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteAccounts {
    #[serde(default)]
    pub current: Vec<VoteAccountInfo>,
    #[serde(default)]
    pub delinquent: Vec<VoteAccountInfo>,
}

/// What one endpoint had to say about one validator.
#[derive(Debug, Clone)]
pub enum ValidatorObservation {
    /// Present in `current`.
    Voting(VoteAccountInfo),
    /// Present in `delinquent`. The node is sure.
    Delinquent(VoteAccountInfo),
    /// The node returned a complete vote-account listing and this validator was
    /// not in it. Definite evidence, not an error.
    Absent,
    /// We could not find out. Typed as a `Verdict` so an RPC failure has no way
    /// to re-enter the pipeline as anything other than `Unknown`.
    Unknown(Verdict),
}

impl ValidatorObservation {
    pub fn info(&self) -> Option<&VoteAccountInfo> {
        match self {
            ValidatorObservation::Voting(i) | ValidatorObservation::Delinquent(i) => Some(i),
            _ => None,
        }
    }
}

/// Leader-slot performance for the current epoch.
#[derive(Debug, Clone, Copy)]
pub struct BlockProduction {
    pub leader_slots: u64,
    pub blocks_produced: u64,
}

impl BlockProduction {
    pub fn skipped(&self) -> u64 {
        self.leader_slots.saturating_sub(self.blocks_produced)
    }

    pub fn skip_percent(&self) -> f64 {
        if self.leader_slots == 0 {
            return 0.0;
        }
        self.skipped() as f64 * 100.0 / self.leader_slots as f64
    }
}

#[derive(Debug, Clone)]
pub struct ClusterStake {
    pub total: u64,
    pub current: u64,
    pub delinquent: u64,
}

impl ClusterStake {
    pub fn current_percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.current as f64 * 100.0 / self.total as f64
    }
}

/// The software a node reports running. Only collected from local endpoints:
/// a public RPC's version says nothing about your validator, and asking costs a
/// request against a rate limit for an answer nobody wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeVersion {
    pub solana_core: String,
    pub feature_set: u64,
}

/// One endpoint's complete view for one cycle. Every field is optional because
/// partial visibility is the normal case, not an error.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub endpoint: String,
    pub version: Option<NodeVersion>,
    /// Identity pubkey of the node behind a local endpoint. This is what makes
    /// "the version this box runs" attributable to exactly one configured
    /// validator, instead of to every validator the config happens to list.
    pub identity: Option<String>,
    pub epoch_info: Option<EpochInfo>,
    pub validators: HashMap<String, ValidatorObservation>,
    /// Identity pubkey -> lamports.
    pub identity_balances: HashMap<String, Option<u64>>,
    /// Identity -> leader slots and blocks produced this epoch.
    pub block_production: HashMap<String, BlockProduction>,
    pub cluster_stake: Option<ClusterStake>,
    /// Feature accounts and rent behind the Alpenglow admission check.
    pub alpenglow: Option<crate::alpenglow::ClusterVat>,
    /// Identity pubkey -> its vote account, as the vote program sees it.
    pub vote_states: HashMap<String, crate::alpenglow::VoteAccountState>,
    /// Identity pubkey -> commission paid into its vote account for the last
    /// completed epoch, in lamports. Only from endpoints that keep that much
    /// history; most public ones do not.
    pub vote_income: HashMap<String, u64>,
    /// Identity pubkey -> every invoice The Vault has issued its vote account.
    /// Absent when this endpoint was not asked: local nodes never are.
    pub vault_invoices: HashMap<String, Result<Vec<crate::pools::Invoice>, String>>,
    /// Identity pubkey -> its JPool bonds and the pool's stake on it.
    pub jpool: HashMap<String, Result<crate::pools::JpoolPosition, String>>,
    /// Transport-level trouble seen while building this snapshot. Reported in
    /// the endpoint-health digest; never alerted on directly.
    pub transient_errors: Vec<String>,
    pub config_errors: Vec<String>,
}

impl Snapshot {
    #[cfg(test)]
    pub fn empty_for_test(endpoint: &str) -> Self {
        Self::empty(endpoint)
    }

    fn empty(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            version: None,
            identity: None,
            epoch_info: None,
            validators: HashMap::new(),
            identity_balances: HashMap::new(),
            block_production: HashMap::new(),
            cluster_stake: None,
            alpenglow: None,
            vote_states: HashMap::new(),
            vote_income: HashMap::new(),
            vault_invoices: HashMap::new(),
            jpool: HashMap::new(),
            transient_errors: Vec::new(),
            config_errors: Vec::new(),
        }
    }

    fn record(&mut self, err: RpcError) {
        match err {
            RpcError::Transient(m) => self.transient_errors.push(m),
            RpcError::Config(m) => self.config_errors.push(m),
            // Deliberately dropped. The endpoint has said it does not serve
            // the method; that was logged once when it was learned, and
            // counting it every cycle would report 355 "errors" for a fact.
            RpcError::Unsupported(_) => {}
        }
    }

    /// Did this endpoint tell us anything load-bearing at all?
    pub fn is_usable(&self) -> bool {
        self.epoch_info.is_some()
    }
}

fn commitment() -> Value {
    json!({ "commitment": "confirmed" })
}

/// Vote accounts we know the pubkey for can be fetched individually, which is a
/// few hundred bytes instead of the multi-megabyte full listing. That difference
/// is most of why the public endpoints rate-limit a 60-second watchtower in the
/// first place -- the fix for false positives starts with not provoking them.
fn needs_full_listing(config: &Config, known_vote_accounts: &HashMap<String, String>) -> bool {
    config.checks.cluster_stake.base.enabled
        || config
            .validators
            .iter()
            .any(|v| !known_vote_accounts.contains_key(&v.identity))
}

fn is_local(url: &str) -> bool {
    crate::config::is_local_url(url)
}

pub async fn probe(
    endpoint: &Endpoint,
    config: &Config,
    known_vote_accounts: &HashMap<String, String>,
) -> Snapshot {
    let mut snap = Snapshot::empty(&endpoint.name);

    match endpoint
        .call("getEpochInfo", json!([commitment()]))
        .await
        .and_then(|v| {
            serde_json::from_value::<EpochInfo>(v)
                .map_err(|e| RpcError::Transient(format!("bad getEpochInfo payload: {e}")))
        }) {
        Ok(info) => snap.epoch_info = Some(info),
        Err(e) => {
            warn!(endpoint = %endpoint.name, "epoch info unavailable: {e}");
            snap.record(e);
            // Without a cluster slot nothing else can be interpreted, and every
            // check will correctly read Unknown for this endpoint.
            return snap;
        }
    }

    // Version is only meaningful for a node you run. Fetching it from a shared
    // public RPC would report that provider's build, not yours, so this is
    // deliberately restricted to local endpoints.
    if is_local(&endpoint.url) {
        match endpoint.call("getVersion", json!([])).await {
            Ok(v) => {
                let core = v.get("solana-core").and_then(|x| x.as_str());
                let fs = v.get("feature-set").and_then(|x| x.as_u64());
                if let Some(core) = core {
                    snap.version = Some(NodeVersion {
                        solana_core: core.to_string(),
                        feature_set: fs.unwrap_or(0),
                    });
                }
            }
            // Never recorded as an endpoint error: not knowing the version is a
            // missing nicety, not evidence about the validator's health.
            Err(e) => debug!(endpoint = %endpoint.name, "getVersion unavailable: {e}"),
        }
        match endpoint.call("getIdentity", json!([])).await {
            Ok(v) => {
                snap.identity = v
                    .get("identity")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
            }
            Err(e) => debug!(endpoint = %endpoint.name, "getIdentity unavailable: {e}"),
        }
    }

    if needs_full_listing(config, known_vote_accounts) {
        match fetch_vote_accounts(endpoint, None).await {
            Ok(va) => {
                apply_full_listing(&mut snap, config, &va);
                snap.cluster_stake = Some(summarize_stake(&va));
            }
            Err(e) => {
                warn!(endpoint = %endpoint.name, "full vote account listing unavailable: {e}");
                snap.record(e);
                for v in &config.validators {
                    snap.validators.insert(
                        v.identity.clone(),
                        ValidatorObservation::Unknown(Verdict::unknown(
                            "vote account listing unavailable",
                        )),
                    );
                }
            }
        }
    } else {
        for v in &config.validators {
            let vote_pubkey = known_vote_accounts
                .get(&v.identity)
                .expect("needs_full_listing guarantees every identity is known here");
            let obs = match fetch_vote_accounts(endpoint, Some(vote_pubkey)).await {
                Ok(va) => classify_one(&v.identity, &va),
                Err(e) => {
                    let verdict = e.clone().into_verdict();
                    snap.record(e);
                    ValidatorObservation::Unknown(verdict)
                }
            };
            snap.validators.insert(v.identity.clone(), obs);
        }
    }

    fetch_accounts(endpoint, config, known_vote_accounts, &mut snap).await;

    // Program scans are cheap on an RPC provider's indexed node and expensive
    // on a validator: without an account index, getProgramAccounts walks the
    // whole accounts database of the machine that is supposed to be voting.
    if !is_local(&endpoint.url) {
        fetch_pools(endpoint, config, known_vote_accounts, &mut snap).await;
    }

    if config.checks.skip_rate.base.enabled {
        for v in &config.validators {
            match fetch_block_production(endpoint, &v.identity).await {
                Ok(bp) => {
                    snap.block_production.insert(v.identity.clone(), bp);
                }
                Err(e) => snap.record(e),
            }
        }
    }

    debug!(
        endpoint = %endpoint.name,
        slot = snap.epoch_info.as_ref().map(|e| e.absolute_slot),
        epoch = snap.epoch_info.as_ref().map(|e| e.epoch),
        transient = snap.transient_errors.len(),
        "probe complete"
    );
    snap
}

async fn fetch_vote_accounts(
    endpoint: &Endpoint,
    vote_pubkey: Option<&str>,
) -> Result<VoteAccounts, RpcError> {
    let mut params = commitment();
    if let Some(vp) = vote_pubkey {
        params["votePubkey"] = json!(vp);
        // Without this, an unstaked delinquent vote account is omitted entirely
        // and we would read "absent" instead of "delinquent".
        params["keepUnstakedDelinquents"] = json!(true);
    }
    let raw = endpoint.call("getVoteAccounts", json!([params])).await?;
    serde_json::from_value(raw)
        .map_err(|e| RpcError::Transient(format!("bad getVoteAccounts payload: {e}")))
}

/// Leader slots and blocks produced for one identity in the current epoch.
///
/// Filtered by identity so the response is a single entry rather than the whole
/// cluster, which would be megabytes.
///
/// A validator with no leader slots yet this epoch is simply absent from
/// `byIdentity`. That is an answer -- zero slots, zero blocks -- and it is
/// returned as one, so the check downstream can tell "not asked to produce
/// yet" from "the endpoint did not answer". Conflating the two left every
/// low-stake validator Unknown for the first hours of each epoch, until the
/// starvation detector reported the check as broken.
async fn fetch_block_production(
    endpoint: &Endpoint,
    identity: &str,
) -> Result<BlockProduction, RpcError> {
    #[derive(Deserialize)]
    struct Resp {
        value: Value,
    }
    let raw = endpoint
        .call(
            "getBlockProduction",
            json!([{ "commitment": "confirmed", "identity": identity }]),
        )
        .await?;
    let resp: Resp = serde_json::from_value(raw)
        .map_err(|e| RpcError::Transient(format!("bad getBlockProduction payload: {e}")))?;

    parse_block_production(&resp.value, identity)
}

/// The parsing half of `fetch_block_production`. One implementation, used by
/// the network path and by the tests alike, so the absent-identity rule cannot
/// drift between what is tested and what runs.
fn parse_block_production(value: &Value, identity: &str) -> Result<BlockProduction, RpcError> {
    let Some(by_identity) = value.get("byIdentity") else {
        // No map at all is a malformed reply, not a quiet validator.
        return Err(RpcError::Transient(
            "getBlockProduction payload had no byIdentity map".into(),
        ));
    };
    let Some(entry) = by_identity.get(identity).and_then(|v| v.as_array()) else {
        return Ok(BlockProduction {
            leader_slots: 0,
            blocks_produced: 0,
        });
    };
    if entry.len() < 2 {
        return Err(RpcError::Transient(
            "getBlockProduction entry was not a [leaderSlots, blocksProduced] pair".into(),
        ));
    }
    Ok(BlockProduction {
        leader_slots: entry[0].as_u64().unwrap_or(0),
        blocks_produced: entry[1].as_u64().unwrap_or(0),
    })
}

/// Feature accounts, vote accounts and identity balances, batched.
///
/// `getMultipleAccounts` replaces a `getBalance` per validator, so adding the
/// Alpenglow inputs costs no extra calls for one validator, and fewer than
/// before for most fleets. An endpoint that will not serve it falls back
/// to `getBalance`, and the Alpenglow check reads Unknown for that endpoint.
async fn fetch_accounts(
    endpoint: &Endpoint,
    config: &Config,
    known_vote_accounts: &HashMap<String, String>,
    snap: &mut Snapshot,
) {
    use crate::alpenglow::{feature_accounts, ClusterVat, FeatureState, VoteAccountState, VOTE_STATE_V4_SIZE};

    let features = feature_accounts();
    // The vote pubkey the cluster just reported is the authority; the config
    // and discovery are the fallback when this endpoint did not see it.
    let votes: Vec<(String, String)> = config
        .validators
        .iter()
        .filter_map(|v| {
            let observed = snap.validators.get(&v.identity).and_then(|o| o.info()).map(|i| i.vote_pubkey.clone());
            observed
                .or_else(|| v.vote_account.clone())
                .or_else(|| known_vote_accounts.get(&v.identity).cloned())
                .map(|vote| (v.identity.clone(), vote))
        })
        .collect();
    let identities: Vec<String> = config.validators.iter().map(|v| v.identity.clone()).collect();

    let mut keys: Vec<String> = features.iter().map(|f| f.to_string()).collect();
    keys.extend(votes.iter().map(|(_, vote)| vote.clone()));
    keys.extend(identities.iter().cloned());

    let accounts = match fetch_multiple(endpoint, &keys).await {
        Ok(a) => a,
        Err(e) => {
            snap.record(e);
            fetch_balances_one_by_one(endpoint, &identities, snap).await;
            return;
        }
    };

    let (feature_part, rest) = accounts.split_at(features.len());
    let (vote_part, identity_part) = rest.split_at(votes.len());

    for (identity, account) in identities.iter().zip(identity_part) {
        // A missing account is an empty one: getBalance would report 0.
        let lamports = if account.is_null() { Some(0) } else { account["lamports"].as_u64() };
        snap.identity_balances.insert(identity.clone(), lamports);
    }
    for ((identity, _), account) in votes.iter().zip(vote_part) {
        if let Some(state) = VoteAccountState::from_account(account) {
            snap.vote_states.insert(identity.clone(), state);
        }
    }

    fetch_vote_income(endpoint, &votes, snap).await;

    let states: Option<Vec<FeatureState>> = feature_part.iter().map(FeatureState::from_account).collect();
    // The rent minimum moves only when a feature does; an hour is plenty fresh.
    let rent = endpoint
        .call_cached(
            "getMinimumBalanceForRentExemption",
            json!([VOTE_STATE_V4_SIZE]),
            std::time::Duration::from_secs(3600),
        )
        .await;
    match (states, rent) {
        (Some(states), Ok(rent)) => {
            if let Some(rent_lamports) = rent.as_u64() {
                snap.alpenglow = Some(ClusterVat {
                    alpenglow: states[0],
                    slot_time: [states[1], states[2], states[3], states[4]],
                    rent_lamports,
                });
            }
        }
        (None, _) => snap.record(RpcError::Transient("unparseable feature account".into())),
        (_, Err(e)) => snap.record(e),
    }
}

/// Vault invoices and JPool bonds, each cached per endpoint for the check's
/// poll interval: both change once an epoch, and these are program scans.
async fn fetch_pools(
    endpoint: &Endpoint,
    config: &Config,
    known_vote_accounts: &HashMap<String, String>,
    snap: &mut Snapshot,
) {
    use crate::pools::{fetch_invoices, fetch_jpool, FetchError};
    if !config.watchtower.may_be_mainnet() {
        return;
    }
    let floor = std::time::Duration::from_secs(60);
    let vault = &config.checks.vault_invoices;
    let jpool = &config.checks.jpool_bond;
    for v in &config.validators {
        // The vote account the cluster reports is the authority, as for the
        // vote account fetch; no vote account at all means nothing to bill.
        let vote = snap
            .validators
            .get(&v.identity)
            .and_then(|o| o.info())
            .map(|i| i.vote_pubkey.clone())
            .or_else(|| v.vote_account.clone())
            .or_else(|| known_vote_accounts.get(&v.identity).cloned());
        if vault.base.enabled {
            if let Some(vote) = &vote {
                let r = fetch_invoices(endpoint, vote, vault.poll_interval.max(floor)).await;
                if let Err(FetchError::Rpc(e)) = &r {
                    snap.record(e.clone());
                }
                snap.vault_invoices.insert(v.identity.clone(), r.map_err(|e| e.to_string()));
            }
        }
        if jpool.base.enabled {
            let r = fetch_jpool(endpoint, &v.identity, vote.as_deref(), jpool.poll_interval.max(floor)).await;
            if let Err(FetchError::Rpc(e)) = &r {
                snap.record(e.clone());
            }
            snap.jpool.insert(v.identity.clone(), r.map_err(|e| e.to_string()));
        }
    }
}

/// Commission each vote account earned in the last completed epoch, which is
/// what refills it against the VAT. A past epoch's rewards never change, and
/// endpoints that have pruned the boundary block or do not serve the method
/// are normal, so either answer is kept for an hour: one call per endpoint per
/// hour, never an endpoint error.
async fn fetch_vote_income(endpoint: &Endpoint, votes: &[(String, String)], snap: &mut Snapshot) {
    let Some(epoch) = snap.epoch_info.as_ref().map(|e| e.epoch) else { return };
    if votes.is_empty() || epoch == 0 {
        return;
    }
    let keys: Vec<&str> = votes.iter().map(|(_, vote)| vote.as_str()).collect();
    let params = json!([keys, { "epoch": epoch - 1 }]);
    let ttl = std::time::Duration::from_secs(3600);
    let Some(rewards) = endpoint.call_optional("getInflationReward", params, ttl).await else {
        return;
    };
    let Some(rewards) = rewards.as_array().filter(|r| r.len() == votes.len()) else { return };
    for ((identity, _), reward) in votes.iter().zip(rewards) {
        // A null entry from an endpoint that answered is a vote account that
        // earned nothing that epoch, which is a real zero.
        let amount = if reward.is_null() { Some(0) } else { reward["amount"].as_u64() };
        if let Some(a) = amount {
            snap.vote_income.insert(identity.clone(), a);
        }
    }
}

/// Accounts per `getMultipleAccounts` call. Solana allows 100, but
/// publicnode -- one of the free endpoints perch ships with -- rejects more
/// than 10 with a 403, which a hub watching three validators already exceeds.
const ACCOUNTS_PER_CALL: usize = 10;

/// `getMultipleAccounts` over any number of keys, in order. All or nothing: a
/// partial answer would misalign accounts with the keys they belong to.
async fn fetch_multiple(endpoint: &Endpoint, keys: &[String]) -> Result<Vec<Value>, RpcError> {
    let mut out = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(ACCOUNTS_PER_CALL) {
        let raw = endpoint
            .call(
                "getMultipleAccounts",
                json!([chunk, { "encoding": "jsonParsed", "commitment": "confirmed" }]),
            )
            .await?;
        match raw["value"].as_array() {
            Some(a) if a.len() == chunk.len() => out.extend(a.iter().cloned()),
            _ => return Err(RpcError::Transient("bad getMultipleAccounts payload".into())),
        }
    }
    Ok(out)
}

async fn fetch_balances_one_by_one(endpoint: &Endpoint, identities: &[String], snap: &mut Snapshot) {
    for identity in identities {
        let balance = fetch_balance(endpoint, identity).await;
        if let Err(e) = &balance {
            snap.record(e.clone());
        }
        snap.identity_balances.insert(identity.clone(), balance.ok());
    }
}

async fn fetch_balance(endpoint: &Endpoint, pubkey: &str) -> Result<u64, RpcError> {
    #[derive(Deserialize)]
    struct BalanceResponse {
        value: u64,
    }
    let raw = endpoint
        .call("getBalance", json!([pubkey, commitment()]))
        .await?;
    serde_json::from_value::<BalanceResponse>(raw)
        .map(|b| b.value)
        .map_err(|e| RpcError::Transient(format!("bad getBalance payload: {e}")))
}

fn classify_one(identity: &str, va: &VoteAccounts) -> ValidatorObservation {
    if let Some(info) = va.delinquent.iter().find(|i| i.node_pubkey == identity) {
        return ValidatorObservation::Delinquent(info.clone());
    }
    if let Some(info) = va.current.iter().find(|i| i.node_pubkey == identity) {
        return ValidatorObservation::Voting(info.clone());
    }
    ValidatorObservation::Absent
}

fn apply_full_listing(snap: &mut Snapshot, config: &Config, va: &VoteAccounts) {
    for v in &config.validators {
        snap.validators
            .insert(v.identity.clone(), classify_one(&v.identity, va));
    }
}

pub fn summarize_stake(va: &VoteAccounts) -> ClusterStake {
    let current: u64 = va.current.iter().map(|i| i.activated_stake).sum();
    let delinquent: u64 = va.delinquent.iter().map(|i| i.activated_stake).sum();
    ClusterStake {
        total: current.saturating_add(delinquent),
        current,
        delinquent,
    }
}

/// Vote accounts learned from a full listing, so later cycles can use the cheap
/// filtered query.
pub fn learn_vote_accounts(
    snapshots: &[Snapshot],
    validators: &[ValidatorConfig],
    known: &mut HashMap<String, String>,
) {
    for v in validators {
        if known.contains_key(&v.identity) {
            continue;
        }
        if let Some(vp) = v.vote_account.clone() {
            known.insert(v.identity.clone(), vp);
            continue;
        }
        if let Some(vp) = snapshots
            .iter()
            .filter_map(|s| s.validators.get(&v.identity))
            .filter_map(|o| o.info())
            .map(|i| i.vote_pubkey.clone())
            .next()
        {
            debug!(identity = %v.identity, vote_account = %vp, "discovered vote account");
            known.insert(v.identity.clone(), vp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(node: &str, last_vote: u64, credits: u64) -> VoteAccountInfo {
        VoteAccountInfo {
            vote_pubkey: format!("vote-{node}"),
            node_pubkey: node.into(),
            activated_stake: 100,
            commission: 8,
            last_vote,
            root_slot: last_vote.saturating_sub(32),
            epoch_credits: vec![(10, credits, credits.saturating_sub(1000))],
        }
    }

    #[test]
    fn skip_percent_is_slots_missed_over_slots_assigned() {
        let bp = BlockProduction {
            leader_slots: 200,
            blocks_produced: 150,
        };
        assert_eq!(bp.skipped(), 50);
        assert_eq!(bp.skip_percent(), 25.0);
    }

    #[test]
    fn skip_percent_with_no_leader_slots_is_zero_not_nan() {
        let bp = BlockProduction {
            leader_slots: 0,
            blocks_produced: 0,
        };
        assert_eq!(bp.skip_percent(), 0.0);
    }

    #[test]
    fn producing_more_blocks_than_assigned_does_not_underflow() {
        // Should not happen, but a saturating subtraction beats a panic or a
        // wrapped u64 that reads as a catastrophic skip rate.
        let bp = BlockProduction {
            leader_slots: 10,
            blocks_produced: 12,
        };
        assert_eq!(bp.skipped(), 0);
        assert_eq!(bp.skip_percent(), 0.0);
    }

    #[test]
    fn epoch_progress_is_a_percentage() {
        let e = EpochInfo {
            absolute_slot: 1,
            epoch: 820,
            slot_index: 216_000,
            slots_in_epoch: 432_000,
        };
        assert_eq!(e.epoch_percent(), 50.0);
    }

    #[test]
    fn epoch_progress_on_a_node_that_omits_the_fields_is_zero_not_nan() {
        let e = EpochInfo {
            absolute_slot: 1,
            epoch: 820,
            slot_index: 0,
            slots_in_epoch: 0,
        };
        assert_eq!(e.epoch_percent(), 0.0);
    }

    #[test]
    fn delinquent_listing_wins_over_current() {
        let va = VoteAccounts {
            current: vec![info("a", 100, 5000)],
            delinquent: vec![info("a", 100, 5000)],
        };
        assert!(matches!(
            classify_one("a", &va),
            ValidatorObservation::Delinquent(_)
        ));
    }

    #[test]
    fn missing_validator_is_absent_not_unknown() {
        let va = VoteAccounts {
            current: vec![info("a", 100, 5000)],
            delinquent: vec![],
        };
        assert!(matches!(classify_one("b", &va), ValidatorObservation::Absent));
    }

    #[test]
    fn stake_percent_handles_empty_cluster() {
        let s = summarize_stake(&VoteAccounts {
            current: vec![],
            delinquent: vec![],
        });
        assert_eq!(s.current_percent(), 0.0);
    }

    #[test]
    fn stake_percent_is_share_of_total() {
        let mut a = info("a", 1, 1);
        a.activated_stake = 750;
        let mut b = info("b", 1, 1);
        b.activated_stake = 250;
        let s = summarize_stake(&VoteAccounts {
            current: vec![a],
            delinquent: vec![b],
        });
        assert_eq!(s.current_percent(), 75.0);
    }

    #[test]
    fn credits_are_read_from_the_latest_epoch() {
        let i = VoteAccountInfo {
            epoch_credits: vec![(9, 1000, 0), (10, 2500, 1000)],
            ..info("a", 1, 1)
        };
        assert_eq!(i.total_credits(), 2500);
        assert_eq!(i.current_epoch_credits(), 1500);
    }

    #[test]
    fn credits_on_a_brand_new_vote_account_are_zero_not_a_panic() {
        let i = VoteAccountInfo {
            epoch_credits: vec![],
            ..info("a", 1, 1)
        };
        assert_eq!(i.total_credits(), 0);
        assert_eq!(i.current_epoch_credits(), 0);
    }
}

#[cfg(test)]
mod local_endpoint {
    use super::*;

    #[test]
    fn a_node_on_this_machine_is_local() {
        for u in [
            "http://127.0.0.1:8899",
            "http://localhost:8899",
            "http://[::1]:8899",
            "http://0.0.0.0:8899",
            "HTTP://LOCALHOST:8899",
        ] {
            assert!(is_local(u), "{u} should be local");
        }
    }

    /// Asking a shared public RPC for its version reports that provider's build,
    /// not yours. Doing it anyway would also spend a request against a rate
    /// limit for an answer nobody asked for.
    #[test]
    fn a_public_rpc_is_not_local() {
        for u in [
            "https://api.mainnet-beta.solana.com",
            "https://api.testnet.solana.com",
            "https://solana-rpc.publicnode.com",
        ] {
            assert!(!is_local(u), "{u} must not be treated as local");
        }
    }
}

#[cfg(test)]
mod block_production_absence {
    use super::*;

    /// The false starvation notice: a validator with no leader slots yet this
    /// epoch is absent from byIdentity. That is "zero so far", not "unknown".
    #[test]
    fn absent_from_by_identity_means_zero_slots_not_unknown() {
        let v = json!({"byIdentity": {"SomeoneElse": [10, 10]}, "range": {"firstSlot": 1, "lastSlot": 2}});
        let bp = parse_block_production(&v, "2AKKnirWVZMhnzuwqpizw9SwfZjGpRFLx2zCCNtPWpbc").unwrap();
        assert_eq!((bp.leader_slots, bp.blocks_produced), (0, 0));
    }

    #[test]
    fn a_present_entry_is_read() {
        let v = json!({"byIdentity": {"me": [4, 3]}});
        let bp = parse_block_production(&v, "me").unwrap();
        assert_eq!((bp.leader_slots, bp.blocks_produced), (4, 3));
        assert_eq!(bp.skipped(), 1);
    }

    /// A reply with no map at all is malformed, and must stay an error rather
    /// than quietly reading as a validator with nothing to do.
    #[test]
    fn a_missing_map_is_an_error_not_zero() {
        let v = json!({"range": {"firstSlot": 1, "lastSlot": 2}});
        assert!(parse_block_production(&v, "me").is_err());
    }
}

#[cfg(test)]
mod chain_sentinels {
    use super::*;

    fn acct(epoch_credits: Vec<(u64, u64, u64)>) -> VoteAccountInfo {
        VoteAccountInfo {
            vote_pubkey: "v".into(),
            node_pubkey: "n".into(),
            activated_stake: 1,
            commission: 0,
            last_vote: 1,
            root_slot: 1,
            epoch_credits,
        }
    }

    /// Exactly what testnet returned for fox-test during the September 2026
    /// transition: two real rows for epoch 1042 with a u64::MAX sentinel between
    /// them. Before the fix this read u64::MAX lifetime and 0 this epoch.
    #[test]
    fn the_real_testnet_shape_is_read_correctly() {
        const MAX: u64 = u64::MAX;
        let i = acct(vec![
            (1042, 1_237_760_699, 1_237_696_220),
            (MAX, MAX, MAX),
            (1042, 2_514_133_823, 1_237_760_699),
        ]);
        assert_eq!(i.total_credits(), 2_514_133_823, "sentinel must not win");
        assert_ne!(i.total_credits(), MAX);
        // Span across both rows for the epoch: 2_514_133_823 - 1_237_696_220.
        assert_eq!(i.current_epoch_credits(), 1_276_437_603);
    }

    #[test]
    fn a_sentinel_only_account_reports_zero_not_max() {
        let i = acct(vec![(u64::MAX, u64::MAX, u64::MAX)]);
        assert_eq!(i.total_credits(), 0);
        assert_eq!(i.current_epoch_credits(), 0);
    }

    /// The ordinary mainnet shape must keep behaving exactly as before.
    #[test]
    fn ordinary_accounts_are_unaffected() {
        let i = acct(vec![(9, 1000, 0), (10, 2500, 1000)]);
        assert_eq!(i.total_credits(), 2500);
        assert_eq!(i.current_epoch_credits(), 1500);
    }

    /// Out-of-order rows must not make a monotonic counter look like it fell.
    #[test]
    fn out_of_order_rows_do_not_lower_the_lifetime_counter() {
        let i = acct(vec![(10, 2500, 1000), (9, 1000, 0)]);
        assert_eq!(i.total_credits(), 2500);
    }
}

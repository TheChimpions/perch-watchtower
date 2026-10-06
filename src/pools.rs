//! What a validator owes the stake pools that delegate to it.
//!
//! Two pools put conditions on their stake that can lapse without the validator
//! itself ever looking unhealthy:
//!
//! - **The Vault** bills each validator in vSOL, one on-chain `Invoice` per
//!   epoch. Ten left unpaid and the validator is removed from the Vault.
//! - **JPool** holds a bond against each validator and draws on it every epoch
//!   to cover any shortfall against its target APY. A bond that runs dry cuts
//!   the delegation and, at zero, flags the validator for removal.
//!
//! Both are read straight from the pools' programs and keyed by what the
//! validator already is: its vote account for the Vault, its identity for
//! JPool. Joining either pool therefore needs no configuration, and a validator
//! in neither simply has nothing owed.

use crate::rpc::{Endpoint, RpcError};
use base64::Engine;
use serde_json::{json, Value};
use std::{collections::HashMap, time::Duration};

/// The Vault's directed-stake program. Each epoch's bill is an `Invoice`
/// account, and paying one zeroes its outstanding amount rather than closing it.
pub const VAULT_PROGRAM: &str = "EpoivtVh9dgWFxE6MYgF3YnobYWtZr2VfCuP7iT3N927";
/// Anchor discriminator, `sha256("account:Invoice")[..8]`.
const INVOICE_DISCRIMINATOR: [u8; 8] = [0x33, 0xc2, 0xfa, 0x72, 0x06, 0x68, 0x12, 0xa4];
/// discriminator | vault config | vote account | epoch | amount | outstanding
const INVOICE_LEN: usize = 96;
const INVOICE_VOTE_OFFSET: usize = 40;

/// JPool's bond program (the `prod` id in `@jpool/bond-cli`).
pub const JPOOL_BOND_PROGRAM: &str = "BondQ7KqZreTcW2UbeTNDcLCJQ3aXAtLn2Fm6ftaJDU";
const VALIDATOR_BOND_DISCRIMINATOR: [u8; 8] = [82, 127, 243, 208, 195, 42, 80, 35];
const BOND_STATE_DISCRIMINATOR: [u8; 8] = [251, 95, 76, 47, 191, 108, 163, 92];
/// discriminator | bond state | identity | vote account | creator | ...
const VALIDATOR_BOND_IDENTITY_OFFSET: usize = 40;
const VALIDATOR_BOND_MIN_LEN: usize = 136;

/// JSOL, and the SPL stake pool whose exchange rate values a JSOL bond.
pub const JSOL_MINT: &str = "7Q2afV64in6N6SeZsAAB81TJzwDoD6zpqmHkzi9Dcavn";
pub const JPOOL_STAKE_POOL: &str = "CtMyWsrUtAwXWiGr9WjHT5fC3p3fgV8cyGpLTo2LJzG1";
/// SPL stake pool layout: `total_lamports` and `pool_token_supply`, both u64,
/// follow the account type and nine pubkey-sized fields.
const STAKE_POOL_TOTALS_OFFSET: usize = 258;
/// The pool's `validator_list` address, after account type, three authorities
/// and the withdraw bump.
const STAKE_POOL_VALIDATOR_LIST_OFFSET: usize = 98;
/// Validator list: account type, max_validators (u32), vec length (u32), then
/// one 73-byte entry per validator whose vote account is its last 32 bytes.
const VALIDATOR_LIST_HEADER: usize = 9;
const VALIDATOR_STAKE_INFO_LEN: usize = 73;
const VALIDATOR_STAKE_INFO_VOTE_OFFSET: usize = 41;

/// A bond's configuration changes when JPool adds a product, not per epoch.
const BOND_STATE_TTL: Duration = Duration::from_secs(6 * 3600);
const RENT_TTL: Duration = Duration::from_secs(3600);

// ---------------------------------------------------------------- The Vault

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The Vault config account that issued it. The program serves more than one
    /// vault, and removal is counted per vault.
    pub vault: String,
    pub epoch: u64,
    /// vSOL lamports billed.
    pub amount: u64,
    /// vSOL lamports still owed; zero once paid.
    pub outstanding: u64,
}

impl Invoice {
    pub fn is_unpaid(&self) -> bool {
        self.outstanding > 0
    }
}

pub fn parse_invoice(data: &[u8]) -> Option<Invoice> {
    if data.len() < INVOICE_LEN || data[..8] != INVOICE_DISCRIMINATOR {
        return None;
    }
    Some(Invoice {
        vault: base58(&data[8..40]),
        epoch: u64_at(data, 72)?,
        amount: u64_at(data, 80)?,
        outstanding: u64_at(data, 88)?,
    })
}

/// Unpaid invoices in the vault where the validator is furthest behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrears {
    pub vault: String,
    pub unpaid: usize,
    /// vSOL lamports.
    pub owed: u64,
    pub oldest_epoch: u64,
    pub newest_epoch: u64,
}

/// `None` when nothing is owed, including a validator the Vault has never billed.
pub fn arrears(invoices: &[Invoice]) -> Option<Arrears> {
    let mut by_vault: HashMap<&str, Arrears> = HashMap::new();
    for i in invoices.iter().filter(|i| i.is_unpaid()) {
        let a = by_vault.entry(i.vault.as_str()).or_insert_with(|| Arrears {
            vault: i.vault.clone(),
            unpaid: 0,
            owed: 0,
            oldest_epoch: i.epoch,
            newest_epoch: i.epoch,
        });
        a.unpaid += 1;
        a.owed = a.owed.saturating_add(i.outstanding);
        a.oldest_epoch = a.oldest_epoch.min(i.epoch);
        a.newest_epoch = a.newest_epoch.max(i.epoch);
    }
    // Ties broken by address so the same data always names the same vault.
    by_vault
        .into_values()
        .max_by(|a, b| a.unpaid.cmp(&b.unpaid).then_with(|| b.vault.cmp(&a.vault)))
}

// ---------------------------------------------------------------- JPool

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collateral {
    Native,
    StakeAccount,
    Token(String),
}

/// One bond product, e.g. the legacy SOL "performance" bond or the JSOL "perf" bond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondState {
    pub name: String,
    pub collateral: Collateral,
}

pub fn parse_bond_state(data: &[u8]) -> Option<BondState> {
    if data.len() < 12 || data[..8] != BOND_STATE_DISCRIMINATOR {
        return None;
    }
    let len = u32::from_le_bytes(data[8..12].try_into().ok()?) as usize;
    let name_end = 12usize.checked_add(len)?;
    let name = String::from_utf8(data.get(12..name_end)?.to_vec()).ok()?;
    // bond_type (u8), then the collateral enum's tag.
    let tag = *data.get(name_end + 1)?;
    let collateral = match tag {
        0 => Collateral::Native,
        1 => Collateral::StakeAccount,
        2 => Collateral::Token(base58(data.get(name_end + 2..name_end + 34)?)),
        _ => return None,
    };
    Some(BondState { name, collateral })
}

/// The per-validator account. Its address is where the collateral lives: as its
/// own lamports for a SOL bond, or in a token account it owns for JSOL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorBond {
    pub state: String,
    pub identity: String,
    pub vote_account: String,
}

pub fn parse_validator_bond(data: &[u8]) -> Option<ValidatorBond> {
    if data.len() < VALIDATOR_BOND_MIN_LEN || data[..8] != VALIDATOR_BOND_DISCRIMINATOR {
        return None;
    }
    Some(ValidatorBond {
        state: base58(&data[8..40]),
        identity: base58(&data[40..72]),
        vote_account: base58(&data[72..104]),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    /// Collateral is the account's own lamports above rent.
    Sol,
    /// Collateral is JSOL, valued at the pool's exchange rate.
    Jsol { tokens: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bond {
    /// The validator bond account.
    pub address: String,
    /// The bond product's name, as JPool calls it.
    pub name: String,
    pub asset: Asset,
    /// SOL-equivalent, in lamports. This is what JPool measures requirements in.
    pub lamports: u64,
    /// Slot the reading was taken at, so an endpoint serving an older answer
    /// cannot read as a top-up followed by a second drawdown.
    pub slot: u64,
}

impl Bond {
    /// What the program actually moves. A JSOL bond's SOL value rises with the
    /// exchange rate every epoch, so only its token count says it was drawn on.
    fn units(&self) -> u64 {
        match self.asset {
            Asset::Sol => self.lamports,
            Asset::Jsol { tokens } => tokens,
        }
    }
}

pub fn total_lamports(bonds: &[Bond]) -> u64 {
    bonds.iter().map(|b| b.lamports).fold(0, u64::saturating_add)
}

/// Everything JPool holds against one validator: its bonds, and the stake the
/// pool delegates to it, which sizes the security part of the requirement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JpoolPosition {
    pub bonds: Vec<Bond>,
    /// Lamports the pool actively delegates to the vote account. Direct stake
    /// is staked through the pool, so it is included. Zero when not listed.
    pub pool_stake: u64,
}

impl JpoolPosition {
    pub fn bond_lamports(&self) -> u64 {
        total_lamports(&self.bonds)
    }

    /// JPool's security bond: `sol_per_1000` SOL per 1,000 SOL of JPool stake.
    ///
    /// The other part of the requirement covers the APY shortfall and is
    /// computed off-chain, so the true requirement is never less than this.
    /// That is what makes it safe to alert on: a bond below it is certainly
    /// below 100% health, whatever the performance part is.
    pub fn security_requirement(&self, sol_per_1000: f64) -> u64 {
        (self.pool_stake as f64 * sol_per_1000 / 1000.0) as u64
    }

    /// Neither bonded nor delegated to: not in JPool, nothing to watch.
    pub fn is_empty(&self) -> bool {
        self.bonds.is_empty() && self.pool_stake == 0
    }
}

/// The validator list address, from the stake pool account.
pub fn pool_validator_list(data: &[u8]) -> Option<String> {
    if data.first() != Some(&1) {
        return None;
    }
    data.get(STAKE_POOL_VALIDATOR_LIST_OFFSET..STAKE_POOL_VALIDATOR_LIST_OFFSET + 32).map(base58)
}

/// Active lamports the pool delegates to `vote`, from its validator list.
/// `Some(0)` when the vote account is not listed; `None` when the account is
/// not a readable validator list.
pub fn delegated_to(list: &[u8], vote: &str) -> Option<u64> {
    if list.first() != Some(&2) {
        return None;
    }
    let len = u32::from_le_bytes(list.get(5..9)?.try_into().ok()?) as usize;
    for i in 0..len {
        let start = VALIDATOR_LIST_HEADER + i * VALIDATOR_STAKE_INFO_LEN;
        let entry = list.get(start..start + VALIDATOR_STAKE_INFO_LEN)?;
        if base58(&entry[VALIDATOR_STAKE_INFO_VOTE_OFFSET..]) == vote {
            return u64_at(entry, 0);
        }
    }
    Some(0)
}

/// `(total_lamports, pool_token_supply)` from an SPL stake pool account.
pub fn pool_rate(data: &[u8]) -> Option<(u64, u64)> {
    // Account type 1 is StakePool; anything else is the wrong account.
    if data.first() != Some(&1) {
        return None;
    }
    let total = u64_at(data, STAKE_POOL_TOTALS_OFFSET)?;
    let supply = u64_at(data, STAKE_POOL_TOTALS_OFFSET + 8)?;
    (supply > 0).then_some((total, supply))
}

pub fn jsol_to_lamports(tokens: u64, (total, supply): (u64, u64)) -> u64 {
    (tokens as u128 * total as u128 / supply as u128).min(u64::MAX as u128) as u64
}

/// A bond balance that went down between two readings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawdown {
    pub address: String,
    pub name: String,
    /// SOL-equivalent lamports, before and after.
    pub before: u64,
    pub after: u64,
}

/// The last accepted reading of each bond, to notice when one is drawn on.
///
/// Not persisted: after a restart the first reading is a new baseline, so a
/// restart can miss one drawdown but can never announce one that did not happen.
#[derive(Debug, Default)]
pub struct BondLedger {
    last: HashMap<String, Bond>,
}

impl BondLedger {
    /// Record this cycle's readings and return the bonds that went down.
    ///
    /// A reading from an older slot than the one already accepted is ignored.
    /// Readings are cached per endpoint, so without this a lagging endpoint
    /// would look like a top-up, and the next fresh one like a second drawdown.
    pub fn observe(&mut self, bonds: &[Bond]) -> Vec<Drawdown> {
        let mut out = Vec::new();
        for b in bonds {
            match self.last.get(&b.address) {
                Some(prev) if b.slot <= prev.slot => continue,
                Some(prev) if b.units() < prev.units() => out.push(Drawdown {
                    address: b.address.clone(),
                    name: b.name.clone(),
                    before: prev.lamports,
                    after: b.lamports,
                }),
                _ => {}
            }
            self.last.insert(b.address.clone(), b.clone());
        }
        out
    }
}

// ---------------------------------------------------------------- fetching

/// Why a pool reading is missing. Either way the check reads Unknown, but only
/// an RPC failure counts against the endpoint.
#[derive(Debug, Clone)]
pub enum FetchError {
    Rpc(RpcError),
    Unreadable(String),
}

impl From<RpcError> for FetchError {
    fn from(e: RpcError) -> Self {
        FetchError::Rpc(e)
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Rpc(e) => write!(f, "{e}"),
            FetchError::Unreadable(m) => write!(f, "{m}"),
        }
    }
}

/// Every invoice the Vault has issued to this vote account.
pub async fn fetch_invoices(endpoint: &Endpoint, vote: &str, ttl: Duration) -> Result<Vec<Invoice>, FetchError> {
    let params = json!([VAULT_PROGRAM, {
        "commitment": "confirmed",
        "encoding": "base64",
        "filters": [
            { "dataSize": INVOICE_LEN },
            { "memcmp": { "offset": 0, "bytes": base58(&INVOICE_DISCRIMINATOR) } },
            { "memcmp": { "offset": INVOICE_VOTE_OFFSET, "bytes": vote } },
        ],
    }]);
    let raw = endpoint.call_cached("getProgramAccounts", params, ttl).await?;
    let accounts = raw
        .as_array()
        .ok_or_else(|| FetchError::Unreadable("Vault invoice listing was not an array".into()))?;
    accounts
        .iter()
        .map(|a| {
            account_data(&a["account"])
                .as_deref()
                .and_then(parse_invoice)
                .ok_or_else(|| FetchError::Unreadable("unreadable Vault invoice account".into()))
        })
        .collect()
}

/// What JPool holds against this validator: its bonds, found from the
/// identity, and the pool's stake on its vote account. `vote` is the vote
/// account the cluster reports; a bond names its own, which wins.
pub async fn fetch_jpool(
    endpoint: &Endpoint,
    identity: &str,
    vote: Option<&str>,
    ttl: Duration,
) -> Result<JpoolPosition, FetchError> {
    let (bonds, bonded_vote) = fetch_bonds(endpoint, identity, ttl).await?;
    let Some(vote) = bonded_vote.as_deref().or(vote) else {
        return Ok(JpoolPosition { bonds, pool_stake: 0 });
    };
    let pool = fetch_pool_head(endpoint, ttl).await?;
    let list = pool_validator_list(&pool)
        .ok_or_else(|| FetchError::Unreadable("unreadable JPool stake pool account".into()))?;
    let raw = endpoint
        .call_cached("getAccountInfo", json!([list, { "encoding": "base64" }]), ttl)
        .await?;
    let pool_stake = account_data(&raw["value"])
        .as_deref()
        .and_then(|d| delegated_to(d, vote))
        .ok_or_else(|| FetchError::Unreadable("unreadable JPool validator list".into()))?;
    Ok(JpoolPosition { bonds, pool_stake })
}

/// Every JPool bond held against this identity, valued in SOL, and the vote
/// account they are for.
async fn fetch_bonds(
    endpoint: &Endpoint,
    identity: &str,
    ttl: Duration,
) -> Result<(Vec<Bond>, Option<String>), FetchError> {
    let params = json!([JPOOL_BOND_PROGRAM, {
        "commitment": "confirmed",
        "encoding": "base64",
        "withContext": true,
        "filters": [
            { "memcmp": { "offset": 0, "bytes": base58(&VALIDATOR_BOND_DISCRIMINATOR) } },
            { "memcmp": { "offset": VALIDATOR_BOND_IDENTITY_OFFSET, "bytes": identity } },
        ],
    }]);
    let raw = endpoint.call_cached("getProgramAccounts", params, ttl).await?;
    let slot = raw["context"]["slot"].as_u64().unwrap_or(0);
    let accounts = raw["value"]
        .as_array()
        .ok_or_else(|| FetchError::Unreadable("JPool bond listing was not an array".into()))?;

    let mut bonds = Vec::new();
    let mut vote = None;
    for a in accounts {
        let address = a["pubkey"].as_str().unwrap_or_default().to_string();
        let account = &a["account"];
        let data = account_data(account)
            .ok_or_else(|| FetchError::Unreadable(format!("unreadable JPool bond {address}")))?;
        let vb = parse_validator_bond(&data)
            .ok_or_else(|| FetchError::Unreadable(format!("unreadable JPool bond {address}")))?;
        vote = Some(vb.vote_account.clone());
        let state = fetch_bond_state(endpoint, &vb.state).await?;
        let lamports = account["lamports"].as_u64().unwrap_or(0);

        let bond = match &state.collateral {
            Collateral::Native => {
                let rent = endpoint
                    .call_cached("getMinimumBalanceForRentExemption", json!([data.len()]), RENT_TTL)
                    .await?
                    .as_u64()
                    .ok_or_else(|| FetchError::Unreadable("bad rent-exemption answer".into()))?;
                Bond {
                    address,
                    name: state.name,
                    asset: Asset::Sol,
                    lamports: lamports.saturating_sub(rent),
                    slot,
                }
            }
            Collateral::Token(mint) if mint == JSOL_MINT => {
                let (tokens, token_slot) = fetch_token_balance(endpoint, &address, mint, ttl).await?;
                let rate = fetch_jsol_rate(endpoint, ttl).await?;
                Bond {
                    address,
                    name: state.name,
                    asset: Asset::Jsol { tokens },
                    lamports: jsol_to_lamports(tokens, rate),
                    slot: token_slot,
                }
            }
            other => {
                return Err(FetchError::Unreadable(format!(
                    "JPool bond {:?} holds collateral perch cannot value ({other:?})",
                    state.name
                )))
            }
        };
        bonds.push(bond);
    }
    bonds.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((bonds, vote))
}

async fn fetch_bond_state(endpoint: &Endpoint, state: &str) -> Result<BondState, FetchError> {
    let raw = endpoint
        .call_cached("getAccountInfo", json!([state, { "encoding": "base64" }]), BOND_STATE_TTL)
        .await?;
    account_data(&raw["value"])
        .as_deref()
        .and_then(parse_bond_state)
        .ok_or_else(|| FetchError::Unreadable(format!("unreadable JPool bond state {state}")))
}

/// Raw token units held by `owner` in `mint`, and the slot of the reading.
async fn fetch_token_balance(
    endpoint: &Endpoint,
    owner: &str,
    mint: &str,
    ttl: Duration,
) -> Result<(u64, u64), FetchError> {
    let raw = endpoint
        .call_cached(
            "getTokenAccountsByOwner",
            json!([owner, { "mint": mint }, { "commitment": "confirmed", "encoding": "jsonParsed" }]),
            ttl,
        )
        .await?;
    let slot = raw["context"]["slot"].as_u64().unwrap_or(0);
    let accounts = raw["value"]
        .as_array()
        .ok_or_else(|| FetchError::Unreadable("token account listing was not an array".into()))?;
    let mut tokens: u64 = 0;
    for a in accounts {
        let amount = a["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| FetchError::Unreadable("unreadable JSOL token balance".into()))?;
        tokens = tokens.saturating_add(amount);
    }
    Ok((tokens, slot))
}

async fn fetch_jsol_rate(endpoint: &Endpoint, ttl: Duration) -> Result<(u64, u64), FetchError> {
    pool_rate(&fetch_pool_head(endpoint, ttl).await?)
        .ok_or_else(|| FetchError::Unreadable("unreadable JPool stake pool account".into()))
}

/// The fixed-size head of the JPool stake pool account: the validator list
/// address and the totals behind the exchange rate. One cached call for both.
async fn fetch_pool_head(endpoint: &Endpoint, ttl: Duration) -> Result<Vec<u8>, FetchError> {
    let raw = endpoint
        .call_cached(
            "getAccountInfo",
            json!([JPOOL_STAKE_POOL, {
                "encoding": "base64",
                "dataSlice": { "offset": 0, "length": STAKE_POOL_TOTALS_OFFSET + 16 },
            }]),
            ttl,
        )
        .await?;
    account_data(&raw["value"])
        .ok_or_else(|| FetchError::Unreadable("unreadable JPool stake pool account".into()))
}

// ---------------------------------------------------------------- helpers

fn account_data(account: &Value) -> Option<Vec<u8>> {
    let b64 = account["data"][0].as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?))
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bitcoin-alphabet base58, as Solana writes addresses.
pub fn base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Little-endian base-58 digits.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| BASE58_ALPHABET[d as usize] as char));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    /// Paid in tx 7v3CdMAc...: epoch 1049, billed 0.0267 vSOL, nothing outstanding.
    const PAID_INVOICE: &str = "M8L6cgZoEqTbj4+JbZZKuqUf0EdYo/U/HDzr+TZA58wsAxxrO6OCzQLkSnKO9rbVH3ZuZAHqwIAy6t7f5Mcv0RE8nQD0jIjsGQQAAAAAAADO85cBAAAAAAAAAAAAAAAA";
    /// Still owed in full.
    const UNPAID_INVOICE: &str = "M8L6cgZoEqTbj4+JbZZKuqUf0EdYo/U/HDzr+TZA58wsAxxrO6OCzQ3IzVuGPYzYz6cmz7DAudbflbNHDFEICfW0qkKdylrwAAMAAAAAAABzDFkFAAAAAHMMWQUAAAAA";
    /// chimps' legacy SOL bond, read after the epoch-1050 claim in tx 5FF9Laqf...
    const SOL_BOND: &str = "Un/z0MMqUCOUpw6QTI6ML+JAdowFy2i2ZWC70lzNOu+3gBFeX5SkoxE+ohYKiwa5J9Vm6nh0B/lgoCf2Jy5urL3GxnaomI37AuRKco72ttUfdm5kAerAgDLq3t/kxy/RETydAPSMiOxwYJMgYQbga1AoeMXn0AVVoiQrFCeRwZrAQaheav+HBQB30wRpAAAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const PERFORMANCE_STATE: &str = "+19ML79so1wLAAAAcGVyZm9ybWFuY2UAAI2jckW1NrCzDbv9Jn/RWcT0cAMYKm8U4SfG/F878wV03Noj1MlCDU6CVh08awajdvCUB/G3tPyo/emrHFdD8WcAAAAA7wCmglXDyAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PERF_STATE: &str = "+19ML79so1wEAAAAcGVyZgACXwxEYxirEMlfQJSVhXDNBXRlpU2rFNnd40gahv7V/MtfDERjGKsQyV9AlJWFcM0FdGWlTasU2d3jSBqG/tX8y9zaI9TJQg1OglYdPGsGo3bwlAfxt7T8qP3pqxxXQ/FnAAAAACkAtUH+jgYAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// The first 274 bytes of the JSOL stake pool account.
    const JSOL_POOL: &str = "AaJQsfK4RSIaDQOJ6nSG9+GXmeYL7Y6vJyd3PkVDpTuD3Noj1MlCDU6CVh08awajdvCUB/G3tPyo/emrHFdD8Wfh4Pippvxf8kLk81F78B7Wst0ZUaC6ttlDVyWShgT3cP/LqkIDCUdVLBkThURwDuYX1RR+JyWBHNvgnIkDCm914o2jckW1NrCzDbv9Jn/RWcT0cAMYKm8U4SfG/F878wV0XwxEYxirEMlfQJSVhXDNBXRlpU2rFNnd40gahv7V/Mvj/aPav/vdTOwRdFALTRZQlijB9G5myz+0QWe7U7EGIQbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCptO5TdEFoBADCvO05wDEDAA==";

    #[test]
    fn base58_matches_solana_addresses() {
        assert_eq!(base58(&[0u8; 32]), "11111111111111111111111111111111");
        assert_eq!(base58(&INVOICE_DISCRIMINATOR), "9f9reTQtGr7");
        let d = b64(PAID_INVOICE);
        assert_eq!(base58(&d[8..40]), "Fn5FbRbJzohohUBnwcAYHuQyAz89Q4VBHwsR5hZSGkDa");
    }

    #[test]
    fn a_paid_invoice_has_nothing_outstanding() {
        let i = parse_invoice(&b64(PAID_INVOICE)).unwrap();
        assert_eq!(i, Invoice {
            vault: "Fn5FbRbJzohohUBnwcAYHuQyAz89Q4VBHwsR5hZSGkDa".into(),
            epoch: 1049,
            amount: 26_735_566,
            outstanding: 0,
        });
        assert!(!i.is_unpaid());
    }

    #[test]
    fn an_unpaid_invoice_still_owes_its_amount() {
        let i = parse_invoice(&b64(UNPAID_INVOICE)).unwrap();
        assert!(i.is_unpaid());
        assert_eq!(i.outstanding, i.amount);
    }

    #[test]
    fn other_accounts_are_not_invoices() {
        assert_eq!(parse_invoice(&b64(SOL_BOND)), None);
        assert_eq!(parse_invoice(&b64(PAID_INVOICE)[..95]), None, "truncated");
    }

    fn inv(vault: &str, epoch: u64, outstanding: u64) -> Invoice {
        Invoice { vault: vault.into(), epoch, amount: 25_000_000, outstanding }
    }

    #[test]
    fn arrears_are_counted_per_vault() {
        let invoices = vec![
            inv("A", 1040, 0),
            inv("A", 1041, 10),
            inv("A", 1042, 20),
            inv("B", 1043, 5),
        ];
        assert_eq!(arrears(&invoices), Some(Arrears {
            vault: "A".into(),
            unpaid: 2,
            owed: 30,
            oldest_epoch: 1041,
            newest_epoch: 1042,
        }));
    }

    #[test]
    fn nothing_owed_is_no_arrears() {
        assert_eq!(arrears(&[]), None, "never billed");
        assert_eq!(arrears(&[inv("A", 1040, 0), inv("A", 1041, 0)]), None, "all paid");
    }

    #[test]
    fn reads_both_live_bond_products() {
        assert_eq!(parse_bond_state(&b64(PERFORMANCE_STATE)), Some(BondState {
            name: "performance".into(),
            collateral: Collateral::Native,
        }));
        assert_eq!(parse_bond_state(&b64(PERF_STATE)), Some(BondState {
            name: "perf".into(),
            collateral: Collateral::Token(JSOL_MINT.into()),
        }));
    }

    #[test]
    fn a_validator_bond_names_its_identity_and_vote_account() {
        assert_eq!(parse_validator_bond(&b64(SOL_BOND)), Some(ValidatorBond {
            state: "B1H5wi6YpLm4DAWsbofpHCJy4LRHV7CLT3ocmXnWAQCJ".into(),
            identity: "2AKKnirWVZMhnzuwqpizw9SwfZjGpRFLx2zCCNtPWpbc".into(),
            vote_account: "CHiaohVV2SQCFhiYP73iQzWT6HxnZqnAZJJqAYTeLAo".into(),
        }));
        assert_eq!(parse_validator_bond(&b64(PERF_STATE)), None, "a bond state is not a validator bond");
    }

    #[test]
    fn jsol_is_valued_at_the_pool_rate() {
        let rate = pool_rate(&b64(JSOL_POOL)).unwrap();
        assert_eq!(rate, (1_240_530_240_663_220, 899_126_605_495_490));
        // 1 JSOL was worth about 1.3797 SOL when this was captured.
        assert_eq!(jsol_to_lamports(1_000_000_000, rate), 1_379_705_853);
        assert_eq!(pool_rate(&[0u8; 274]), None, "not a stake pool");
    }

    #[test]
    fn the_pool_names_its_validator_list() {
        assert_eq!(
            pool_validator_list(&b64(JSOL_POOL)).as_deref(),
            Some("Ei2LhH2tDKPERnoNjQV5darTToZmbg45vDvftFFLNNWd")
        );
    }

    /// A list in the pool's layout: header, then 73-byte entries ending in the
    /// vote account.
    fn validator_list(entries: &[([u8; 32], u64)]) -> Vec<u8> {
        let mut d = vec![2u8];
        d.extend(1000u32.to_le_bytes());
        d.extend((entries.len() as u32).to_le_bytes());
        for (vote, active) in entries {
            let mut e = vec![0u8; VALIDATOR_STAKE_INFO_LEN];
            e[..8].copy_from_slice(&active.to_le_bytes());
            e[VALIDATOR_STAKE_INFO_VOTE_OFFSET..].copy_from_slice(vote);
            d.extend(e);
        }
        d
    }

    /// chimps had 28.416 SOL of JPool stake at idx 103 of the live list.
    #[test]
    fn pool_stake_is_read_by_vote_account() {
        let ours = [7u8; 32];
        let list = validator_list(&[([1u8; 32], 5_000_000_000), (ours, 28_416_459_181)]);
        assert_eq!(delegated_to(&list, &base58(&ours)), Some(28_416_459_181));
        assert_eq!(delegated_to(&list, &base58(&[9u8; 32])), Some(0), "not in the pool");
        assert_eq!(delegated_to(&list[..20], &base58(&ours)), None, "truncated is unreadable, not zero");
        assert_eq!(delegated_to(&b64(JSOL_POOL), &base58(&ours)), None, "not a validator list");
    }

    #[test]
    fn the_security_requirement_is_half_a_sol_per_thousand() {
        let pos = JpoolPosition { bonds: vec![], pool_stake: 28_416_459_181 };
        assert_eq!(pos.security_requirement(0.5), 14_208_229);
        assert!(!pos.is_empty(), "delegated to without a bond is still in JPool");
        assert!(JpoolPosition::default().is_empty());
    }

    fn sol_bond(lamports: u64, slot: u64) -> Bond {
        Bond { address: "bond".into(), name: "performance".into(), asset: Asset::Sol, lamports, slot }
    }

    /// The epoch-1050 claim: 0.00027 SOL out of a 0.5047 SOL bond.
    #[test]
    fn a_claim_is_reported_once() {
        let mut l = BondLedger::default();
        assert!(l.observe(&[sol_bond(504_663_361, 100)]).is_empty(), "first reading is a baseline");
        assert_eq!(l.observe(&[sol_bond(504_393_361, 200)]), vec![Drawdown {
            address: "bond".into(),
            name: "performance".into(),
            before: 504_663_361,
            after: 504_393_361,
        }]);
        assert!(l.observe(&[sol_bond(504_393_361, 300)]).is_empty());
    }

    /// One endpoint still serving its cached pre-claim answer must not read as
    /// a top-up, or the next fresh answer would announce the claim again.
    #[test]
    fn an_older_reading_is_not_a_top_up() {
        let mut l = BondLedger::default();
        l.observe(&[sol_bond(504_663_361, 100)]);
        assert_eq!(l.observe(&[sol_bond(504_393_361, 200)]).len(), 1);
        assert!(l.observe(&[sol_bond(504_663_361, 150)]).is_empty());
        assert!(l.observe(&[sol_bond(504_393_361, 250)]).is_empty(), "same claim, said once");
    }

    #[test]
    fn a_top_up_is_not_a_drawdown() {
        let mut l = BondLedger::default();
        l.observe(&[sol_bond(500_000_000, 100)]);
        assert!(l.observe(&[sol_bond(1_500_000_000, 200)]).is_empty());
    }

    /// JSOL appreciates every epoch, so a JSOL bond's SOL value moves without
    /// anyone touching it; only fewer tokens is a drawdown.
    #[test]
    fn a_jsol_bond_is_drawn_on_only_when_tokens_leave() {
        let jsol = |tokens: u64, lamports: u64, slot: u64| Bond {
            address: "j".into(),
            name: "perf".into(),
            asset: Asset::Jsol { tokens },
            lamports,
            slot,
        };
        let mut l = BondLedger::default();
        l.observe(&[jsol(1_000, 1_400, 1)]);
        assert!(l.observe(&[jsol(1_000, 1_380, 2)]).is_empty(), "rate moved, tokens did not");
        assert_eq!(l.observe(&[jsol(900, 1_250, 3)]).len(), 1);
    }
}

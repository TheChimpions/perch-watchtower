//! Solana Foundation Delegation Program required versions.
//!
//! The foundation publishes a minimum validator version per upcoming epoch.
//! Fall below it and the delegated stake leaves -- a financial event with days
//! of notice, which is exactly the kind of thing a watchtower should turn into
//! a warning rather than a surprise.
//!
//! Two tiers, because the two situations are not the same. Being below the
//! floor for an epoch that has *already started* means stake is at risk right
//! now: that pages. Being below the floor that takes effect *next* epoch means
//! there is roughly an epoch left to upgrade: that is a Telegram note.

use anyhow::{Context, Result};
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::rpc::Endpoint;

const ENDPOINT: &str = "https://api.solana.org/api/community/v1/sfdp_required_versions";

/// The schedule's way of saying a client may not hold delegated stake at all.
const NOT_ALLOWED: &str = "client not allowed";

/// Which of the schedule's three columns a validator is held to.
///
/// The version numbers are not comparable across clients -- Agave is at 4.x
/// while Firedancer counts 26.x -- so reading the wrong column is worse than
/// reading none: a Firedancer node would pass every Agave floor forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Client {
    /// Agave and its forks (Jito, BAM, Harmonic, Rakurai, ...).
    Agave,
    /// Firedancer's networking in front of an Agave runtime.
    Frankendancer,
    /// Full Firedancer and its forks.
    Firedancer,
}

impl Client {
    /// From what the node says about itself in gossip.
    ///
    /// `client_id` is the `clientId` of `getClusterNodes`; older RPC nodes do
    /// not report one, and then the shape of the version decides. A fork keeps
    /// its base client's name inside its own (`HarmonicFiredancer`, `FireBAM`,
    /// `AgaveBam`), and anything unrecognised is an Agave fork, which is what
    /// nearly all of them are. Frankendancer builds announce themselves as
    /// Firedancer with a 0.x version, so the major number has the last word.
    pub fn classify(client_id: Option<&str>, version: &Version) -> Client {
        let id = client_id.unwrap_or_default().to_ascii_lowercase();
        if id.contains("franken") {
            return Client::Frankendancer;
        }
        let fire = if id.is_empty() {
            version.major == 0 || version.major >= 20
        } else {
            id.contains("fire")
        };
        match (fire, version.major) {
            (true, 0) => Client::Frankendancer,
            (true, _) => Client::Firedancer,
            (false, _) => Client::Agave,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Client::Agave => "agave",
            Client::Frankendancer => "frankendancer",
            Client::Firedancer => "firedancer",
        }
    }
}

#[derive(Debug, Deserialize)]
struct Entry {
    epoch: u64,
    agave_min_version: Option<String>,
    /// Frankendancer. The schedule named this column before full Firedancer
    /// had one of its own.
    #[serde(default)]
    firedancer_min_version: Option<String>,
    #[serde(default)]
    firedancer_full_min_version: Option<String>,
    #[serde(default)]
    inherited_from_prev_epoch: bool,
}

#[derive(Debug, Deserialize)]
struct Response {
    data: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Floor {
    Min(Version),
    /// No version of this client qualifies.
    NotAllowed,
}

impl std::fmt::Display for Floor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Floor::Min(v) => write!(f, ">= {v}"),
            Floor::NotAllowed => f.write_str("not allowed"),
        }
    }
}

/// One epoch's floor for one client. `inherited` is false on the epoch where
/// the foundation actually set a new requirement, true where it was carried
/// forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub epoch: u64,
    pub client: Client,
    pub floor: Floor,
    pub inherited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirements {
    pub cluster: String,
    pub entries: Vec<Requirement>,
}

/// Where a validator stands against the published schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compliance {
    Ok,
    /// Below the floor for the epoch already in progress. Stake at risk now.
    BelowCurrent { epoch: u64, required: Floor },
    /// Meets the current floor, but next epoch raises it above this version.
    BelowNext { epoch: u64, required: Floor },
}

impl Requirements {
    /// The floor in force for `client` at `epoch`: the latest published entry
    /// at or before it, since a requirement carries forward until the next one
    /// supersedes it.
    pub fn floor_at(&self, client: Client, epoch: u64) -> Option<&Requirement> {
        self.entries
            .iter()
            .filter(|r| r.client == client && r.epoch <= epoch)
            .max_by_key(|r| r.epoch)
    }
}

fn below(local: &Version, floor: &Floor) -> bool {
    match floor {
        Floor::Min(min) => local < min,
        Floor::NotAllowed => true,
    }
}

/// Decide compliance from the running client, its version and the current
/// epoch.
///
/// Pure, so the rule can be tested against real published schedules without a
/// network. `None` means no opinion: a schedule with nothing for this client
/// is not evidence.
pub fn compliance(
    client: Client,
    local: &Version,
    current_epoch: u64,
    reqs: &Requirements,
) -> Option<Compliance> {
    if !reqs.entries.iter().any(|r| r.client == client) {
        return None;
    }
    if let Some(now) = reqs.floor_at(client, current_epoch) {
        if below(local, &now.floor) {
            return Some(Compliance::BelowCurrent {
                epoch: now.epoch,
                required: now.floor.clone(),
            });
        }
    }
    // Only the very next epoch. A floor three epochs out is real but not yet
    // actionable, and warning about it for days is how a useful alert becomes
    // background noise.
    if let Some(next) = reqs.floor_at(client, current_epoch + 1) {
        if below(local, &next.floor) {
            return Some(Compliance::BelowNext {
                epoch: next.epoch,
                required: next.floor.clone(),
            });
        }
    }
    Some(Compliance::Ok)
}

fn floor(epoch: u64, client: Client, raw: Option<&str>) -> Option<Floor> {
    let raw = raw?.trim();
    if raw.eq_ignore_ascii_case(NOT_ALLOWED) {
        return Some(Floor::NotAllowed);
    }
    match Version::parse(raw) {
        Ok(min) => Some(Floor::Min(min)),
        Err(err) => {
            debug!(
                "ignoring unparseable SFDP {} version {raw:?} for epoch {epoch}: {err}",
                client.name()
            );
            None
        }
    }
}

pub fn parse(cluster: &str, body: &str) -> Result<Requirements> {
    let resp: Response = serde_json::from_str(body).context("decoding SFDP response")?;
    let mut entries: Vec<Requirement> = Vec::new();
    for e in &resp.data {
        for (client, raw) in [
            (Client::Agave, &e.agave_min_version),
            (Client::Frankendancer, &e.firedancer_min_version),
            (Client::Firedancer, &e.firedancer_full_min_version),
        ] {
            if let Some(floor) = floor(e.epoch, client, raw.as_deref()) {
                entries.push(Requirement {
                    epoch: e.epoch,
                    client,
                    floor,
                    inherited: e.inherited_from_prev_epoch,
                });
            }
        }
    }
    entries.sort_by_key(|r| (r.epoch, r.client as u8));
    entries.dedup_by_key(|r| (r.epoch, r.client));
    Ok(Requirements {
        cluster: cluster.to_string(),
        entries,
    })
}

/// Lines describing what changed between two fetches, for a notification.
/// An epoch sliding out of the published window is not a change.
pub fn diff(old: &Requirements, new: &Requirements) -> Vec<String> {
    let mut lines = Vec::new();
    for r in &new.entries {
        let who = r.client.name();
        match old.entries.iter().find(|o| o.epoch == r.epoch && o.client == r.client) {
            None => lines.push(format!(
                "epoch {}: {who} {}{}",
                r.epoch,
                r.floor,
                if r.inherited { "" } else { " (newly announced)" }
            )),
            Some(o) if o.floor != r.floor => {
                lines.push(format!("epoch {}: {who} {} -> {}", r.epoch, o.floor, r.floor))
            }
            Some(_) => {}
        }
    }
    lines
}

/// What a validator announces about itself in gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipNode {
    pub version: String,
    pub client_id: Option<String>,
}

/// Pick the wanted identities out of a `getClusterNodes` listing.
pub fn parse_cluster_nodes(listing: &Value, wanted: &[&str]) -> HashMap<String, GossipNode> {
    let mut out = HashMap::new();
    for node in listing.as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some(pubkey) = node.get("pubkey").and_then(Value::as_str) else {
            continue;
        };
        if !wanted.contains(&pubkey) {
            continue;
        }
        // A node that has not published a version yet reports null.
        let Some(version) = node.get("version").and_then(Value::as_str) else {
            continue;
        };
        out.insert(
            pubkey.to_string(),
            GossipNode {
                version: version.to_string(),
                client_id: node.get("clientId").and_then(Value::as_str).map(str::to_string),
            },
        );
    }
    out
}

/// Validator versions as the cluster sees them.
///
/// Gossip is where the foundation reads a validator's version, and any RPC
/// node can relay it. So the check needs neither the validator's own RPC port
/// -- Firedancer is commonly run with it off -- nor anything on its machine,
/// and a hub can speak for validators it only watches from outside.
///
/// The listing is every node in the cluster, over a megabyte, so it is fetched
/// from one endpoint on the schedule's own cadence instead of every cycle.
#[derive(Default)]
pub struct Gossip {
    nodes: HashMap<String, GossipNode>,
    last_attempt: Option<Instant>,
    fetched: bool,
}

impl Gossip {
    pub fn nodes(&self) -> &HashMap<String, GossipNode> {
        &self.nodes
    }

    pub async fn refresh(
        &mut self,
        endpoints: &[Endpoint],
        wanted: &[&str],
        interval: Duration,
        now: Instant,
    ) {
        // A failed fetch is retried sooner, as with the schedule itself.
        let wait = if self.fetched { interval } else { Duration::from_secs(300) };
        if self
            .last_attempt
            .is_some_and(|t| now.saturating_duration_since(t) < wait)
        {
            return;
        }
        self.last_attempt = Some(now);
        for endpoint in endpoints {
            match endpoint.call("getClusterNodes", serde_json::json!([])).await {
                Ok(listing) => {
                    // Merged, not replaced: a validator that is down drops out
                    // of gossip, and its last announced version is still the
                    // best answer to "what does it run".
                    self.nodes.extend(parse_cluster_nodes(&listing, wanted));
                    self.fetched = true;
                    return;
                }
                Err(e) => debug!(endpoint = %endpoint.name, "gossip listing unavailable: {e}"),
            }
        }
        self.fetched = false;
        warn!("no endpoint returned the gossip node listing; validator versions not refreshed");
    }
}

pub struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
                .build()?,
        })
    }

    pub async fn fetch(&self, cluster: &str) -> Result<Requirements> {
        let resp = self
            .client
            .get(ENDPOINT)
            .query(&[("cluster", cluster)])
            .send()
            .await
            .context("requesting SFDP required versions")?
            .error_for_status()
            .context("SFDP API returned an error")?;
        // The schedule is a few KB; a megabyte is already wrong.
        let body = crate::rpc::body_capped(resp, 1 << 20)
            .await
            .map_err(|e| anyhow::anyhow!("reading SFDP response: {e}"))?;
        parse(cluster, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }
    fn min(s: &str) -> Floor {
        Floor::Min(v(s))
    }
    fn reqs_for(client: Client, pairs: &[(u64, &str)]) -> Requirements {
        Requirements {
            cluster: "testnet".into(),
            entries: pairs
                .iter()
                .map(|(e, s)| Requirement { epoch: *e, client, floor: min(s), inherited: true })
                .collect(),
        }
    }
    fn reqs(pairs: &[(u64, &str)]) -> Requirements {
        reqs_for(Client::Agave, pairs)
    }
    fn agave(ver: &str, epoch: u64, r: &Requirements) -> Option<Compliance> {
        compliance(Client::Agave, &v(ver), epoch, r)
    }

    /// Below the floor for the epoch already running: this is the one that pages.
    #[test]
    fn below_the_current_floor_is_the_paging_case() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        assert_eq!(
            agave("4.2.2", 1042, &r),
            Some(Compliance::BelowCurrent { epoch: 1042, required: min("4.3.0") })
        );
    }

    /// Compliant now, but next epoch raises the floor: Telegram, not the pager.
    #[test]
    fn below_the_next_floor_is_the_warning_case() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        assert_eq!(
            agave("4.2.2", 1041, &r),
            Some(Compliance::BelowNext { epoch: 1042, required: min("4.3.0") })
        );
    }

    /// Exactly one band can be active, so the two checks never both fire.
    #[test]
    fn the_two_bands_never_overlap() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        for (ver, epoch) in [("4.2.2", 1041u64), ("4.2.2", 1042), ("4.3.0", 1041), ("4.3.0", 1042)] {
            match agave(ver, epoch, &r) {
                Some(Compliance::BelowCurrent { .. }) | Some(Compliance::BelowNext { .. })
                | Some(Compliance::Ok) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// A floor further out than the next epoch is real but not yet actionable.
    #[test]
    fn a_distant_floor_does_not_warn_yet() {
        let r = reqs(&[(1041, "4.2.2"), (1045, "5.0.0")]);
        assert_eq!(agave("4.2.2", 1041, &r), Some(Compliance::Ok));
        // ...and it does warn once it is the next epoch.
        assert_eq!(
            agave("4.2.2", 1044, &r),
            Some(Compliance::BelowNext { epoch: 1045, required: min("5.0.0") })
        );
    }

    /// Requirements carry forward, so a gap in the published window still has a
    /// floor in force.
    #[test]
    fn a_floor_carries_forward_until_superseded() {
        let r = reqs(&[(1040, "4.2.2")]);
        assert_eq!(r.floor_at(Client::Agave, 1043).map(|x| x.floor.clone()), Some(min("4.2.2")));
    }

    /// Pre-release ordering, which is where a hand-rolled comparison goes wrong.
    #[test]
    fn prerelease_ordering_is_semver() {
        let r = reqs(&[(1, "4.3.0-rc.1")]);
        assert_eq!(agave("4.3.0-rc.0", 1, &r),
            Some(Compliance::BelowCurrent { epoch: 1, required: min("4.3.0-rc.1") }));
        assert_eq!(agave("4.3.0-rc.1", 1, &r), Some(Compliance::Ok));
        assert_eq!(agave("4.3.0", 1, &r), Some(Compliance::Ok),
            "a release outranks its own candidates");
    }

    #[test]
    fn an_empty_schedule_is_no_opinion() {
        assert_eq!(agave("4.2.2", 1, &reqs(&[])), None);
    }

    /// The mainnet schedule in the shape published on 2026-11-22. The Firedancer
    /// floor for 1096 is raised here so the warning band has something to say.
    const REAL: &str = r#"{"data":[
      {"cluster":"mainnet-beta","epoch":1095,"agave_min_version":"4.4.0","agave_max_version":null,
       "firedancer_max_version":null,"firedancer_min_version":"client not allowed",
       "firedancer_full_min_version":"26.10.6","firedancer_full_max_version":null,
       "inherited_from_prev_epoch":true},
      {"cluster":"mainnet-beta","epoch":1096,"agave_min_version":"4.4.0","agave_max_version":null,
       "firedancer_max_version":null,"firedancer_min_version":"client not allowed",
       "firedancer_full_min_version":"26.10.8","firedancer_full_max_version":null,
       "inherited_from_prev_epoch":false}
    ]}"#;

    /// Each client is held to its own column. Firedancer's 26.x would pass any
    /// Agave floor, so reading the Agave column for it could never warn.
    #[test]
    fn each_client_is_held_to_its_own_floor() {
        let r = parse("mainnet-beta", REAL).unwrap();
        assert_eq!(compliance(Client::Agave, &v("4.4.0"), 1095, &r), Some(Compliance::Ok));
        assert_eq!(
            compliance(Client::Firedancer, &v("26.10.6"), 1095, &r),
            Some(Compliance::BelowNext { epoch: 1096, required: min("26.10.8") })
        );
        assert_eq!(
            compliance(Client::Firedancer, &v("26.10.5"), 1095, &r),
            Some(Compliance::BelowCurrent { epoch: 1095, required: min("26.10.6") })
        );
        assert_eq!(compliance(Client::Firedancer, &v("26.10.8"), 1095, &r), Some(Compliance::Ok));
    }

    /// "client not allowed" is a floor no version clears.
    #[test]
    fn a_client_that_is_not_allowed_is_below_every_floor() {
        let r = parse("mainnet-beta", REAL).unwrap();
        assert_eq!(
            compliance(Client::Frankendancer, &v("0.101.40300"), 1095, &r),
            Some(Compliance::BelowCurrent { epoch: 1095, required: Floor::NotAllowed })
        );
    }

    /// A schedule that says nothing about a client is not a verdict on it.
    #[test]
    fn a_client_missing_from_the_schedule_is_no_opinion() {
        let r = reqs(&[(1, "4.4.0")]);
        assert_eq!(compliance(Client::Firedancer, &v("26.10.8"), 1, &r), None);
    }

    /// Client ids and versions as seen in mainnet gossip on 2026-11-22.
    #[test]
    fn the_client_is_read_from_gossip() {
        for (id, ver, want) in [
            (Some("Agave"), "4.4.0", Client::Agave),
            (Some("JitoLabs"), "4.4.0", Client::Agave),
            (Some("AgaveBam"), "4.4.0", Client::Agave),
            (Some("HarmonicAgave"), "4.4.0", Client::Agave),
            (Some("Rakurai"), "4.4.0", Client::Agave),
            (Some("Firedancer"), "26.10.8", Client::Firedancer),
            (Some("HarmonicFiredancer"), "26.10.8", Client::Firedancer),
            (Some("FireBAM"), "26.11.0", Client::Firedancer),
            (Some("Frankendancer"), "0.101.40300", Client::Frankendancer),
            // A Frankendancer build that announces itself as Firedancer.
            (Some("Firedancer"), "0.1.1", Client::Frankendancer),
            // An RPC node too old to report a client id.
            (None, "4.4.0", Client::Agave),
            (None, "26.10.8", Client::Firedancer),
            (None, "0.101.40300", Client::Frankendancer),
        ] {
            assert_eq!(Client::classify(id, &v(ver)), want, "{id:?} {ver}");
        }
    }

    #[test]
    fn parses_the_real_response_shape() {
        let body = r#"{"data":[
          {"cluster":"testnet","epoch":1036,"agave_min_version":"4.3.0-rc.1","inherited_from_prev_epoch":false},
          {"cluster":"testnet","epoch":1035,"agave_min_version":"4.2.2","inherited_from_prev_epoch":true},
          {"cluster":"testnet","epoch":1037,"agave_min_version":"not a version","inherited_from_prev_epoch":true}
        ]}"#;
        let r = parse("testnet", body).unwrap();
        assert_eq!(r.entries, vec![
            Requirement { epoch: 1035, client: Client::Agave, floor: min("4.2.2"), inherited: true },
            Requirement { epoch: 1036, client: Client::Agave, floor: min("4.3.0-rc.1"), inherited: false },
        ]);
    }

    #[test]
    fn a_newly_announced_floor_is_reported_as_such() {
        let old = reqs(&[(1041, "4.2.2")]);
        let mut new = reqs(&[(1041, "4.2.2"), (1043, "4.3.0")]);
        new.entries[1].inherited = false;
        assert_eq!(diff(&old, &new), vec!["epoch 1043: agave >= 4.3.0 (newly announced)".to_string()]);
        assert!(diff(&new, &new).is_empty());
    }

    /// One client's floor moving is reported under that client's name.
    #[test]
    fn a_change_names_the_client_it_applies_to() {
        let old = reqs_for(Client::Firedancer, &[(1095, "26.10.6")]);
        let new = reqs_for(Client::Firedancer, &[(1095, "26.10.8")]);
        assert_eq!(diff(&old, &new), vec!["epoch 1095: firedancer >= 26.10.6 -> >= 26.10.8".to_string()]);
    }

    #[test]
    fn only_the_wanted_identities_are_kept_from_gossip() {
        let listing = json!([
            {"pubkey": "mine", "version": "26.10.8", "clientId": "Firedancer", "gossip": "1.2.3.4:8001"},
            {"pubkey": "other", "version": "4.4.0", "clientId": "Agave"},
            {"pubkey": "quiet", "version": null, "clientId": null},
            {"pubkey": "old-rpc", "version": "4.4.0"}
        ]);
        let got = parse_cluster_nodes(&listing, &["mine", "quiet", "old-rpc"]);
        assert_eq!(got.len(), 2);
        assert_eq!(got["mine"], GossipNode { version: "26.10.8".into(), client_id: Some("Firedancer".into()) });
        assert_eq!(got["old-rpc"], GossipNode { version: "4.4.0".into(), client_id: None });
    }
}

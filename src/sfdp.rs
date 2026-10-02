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
use std::time::Duration;
use tracing::debug;

const ENDPOINT: &str = "https://api.solana.org/api/community/v1/sfdp_required_versions";

#[derive(Debug, Deserialize)]
struct Entry {
    epoch: u64,
    agave_min_version: Option<String>,
    #[serde(default)]
    inherited_from_prev_epoch: bool,
}

#[derive(Debug, Deserialize)]
struct Response {
    data: Vec<Entry>,
}

/// One epoch's floor. `inherited` is false on the epoch where the foundation
/// actually set a new requirement, true where it was carried forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub epoch: u64,
    pub min: Version,
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
    BelowCurrent { epoch: u64, required: Version },
    /// Meets the current floor, but next epoch raises it above this version.
    BelowNext { epoch: u64, required: Version },
}

impl Requirements {
    /// The floor in force at `epoch`: the latest published entry at or before
    /// it, since a requirement carries forward until the next one supersedes it.
    pub fn floor_at(&self, epoch: u64) -> Option<&Requirement> {
        self.entries
            .iter()
            .filter(|r| r.epoch <= epoch)
            .max_by_key(|r| r.epoch)
    }
}

/// Decide compliance from the local version and the current epoch.
///
/// Pure, so the rule can be tested against real published schedules without a
/// network. `None` means no opinion: an empty schedule is not evidence.
pub fn compliance(local: &Version, current_epoch: u64, reqs: &Requirements) -> Option<Compliance> {
    if reqs.entries.is_empty() {
        return None;
    }
    if let Some(now) = reqs.floor_at(current_epoch) {
        if *local < now.min {
            return Some(Compliance::BelowCurrent {
                epoch: now.epoch,
                required: now.min.clone(),
            });
        }
    }
    // Only the very next epoch. A floor three epochs out is real but not yet
    // actionable, and warning about it for days is how a useful alert becomes
    // background noise.
    if let Some(next) = reqs.floor_at(current_epoch + 1) {
        if *local < next.min {
            return Some(Compliance::BelowNext {
                epoch: next.epoch,
                required: next.min.clone(),
            });
        }
    }
    Some(Compliance::Ok)
}

pub fn parse(cluster: &str, body: &str) -> Result<Requirements> {
    let resp: Response = serde_json::from_str(body).context("decoding SFDP response")?;
    let mut entries: Vec<Requirement> = resp
        .data
        .into_iter()
        .filter_map(|e| {
            let v = e.agave_min_version?;
            match Version::parse(&v) {
                Ok(min) => Some(Requirement {
                    epoch: e.epoch,
                    min,
                    inherited: e.inherited_from_prev_epoch,
                }),
                Err(err) => {
                    debug!("ignoring unparseable SFDP version {v:?} for epoch {}: {err}", e.epoch);
                    None
                }
            }
        })
        .collect();
    entries.sort_by_key(|r| r.epoch);
    entries.dedup_by_key(|r| r.epoch);
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
        match old.entries.iter().find(|o| o.epoch == r.epoch) {
            None => lines.push(format!(
                "epoch {}: >= {}{}",
                r.epoch,
                r.min,
                if r.inherited { "" } else { " (newly announced)" }
            )),
            Some(o) if o.min != r.min => {
                lines.push(format!("epoch {}: >= {} -> >= {}", r.epoch, o.min, r.min))
            }
            Some(_) => {}
        }
    }
    lines
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
        let body = self
            .client
            .get(ENDPOINT)
            .query(&[("cluster", cluster)])
            .send()
            .await
            .context("requesting SFDP required versions")?
            .error_for_status()
            .context("SFDP API returned an error")?
            .text()
            .await
            .context("reading SFDP response")?;
        parse(cluster, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }
    fn reqs(pairs: &[(u64, &str)]) -> Requirements {
        Requirements {
            cluster: "testnet".into(),
            entries: pairs
                .iter()
                .map(|(e, s)| Requirement { epoch: *e, min: v(s), inherited: true })
                .collect(),
        }
    }

    /// Below the floor for the epoch already running: this is the one that pages.
    #[test]
    fn below_the_current_floor_is_the_paging_case() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        assert_eq!(
            compliance(&v("4.2.2"), 1042, &r),
            Some(Compliance::BelowCurrent { epoch: 1042, required: v("4.3.0") })
        );
    }

    /// Compliant now, but next epoch raises the floor: Telegram, not the pager.
    #[test]
    fn below_the_next_floor_is_the_warning_case() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        assert_eq!(
            compliance(&v("4.2.2"), 1041, &r),
            Some(Compliance::BelowNext { epoch: 1042, required: v("4.3.0") })
        );
    }

    /// Exactly one band can be active, so the two checks never both fire.
    #[test]
    fn the_two_bands_never_overlap() {
        let r = reqs(&[(1041, "4.2.2"), (1042, "4.3.0")]);
        for (ver, epoch) in [("4.2.2", 1041u64), ("4.2.2", 1042), ("4.3.0", 1041), ("4.3.0", 1042)] {
            match compliance(&v(ver), epoch, &r) {
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
        assert_eq!(compliance(&v("4.2.2"), 1041, &r), Some(Compliance::Ok));
        // ...and it does warn once it is the next epoch.
        assert_eq!(
            compliance(&v("4.2.2"), 1044, &r),
            Some(Compliance::BelowNext { epoch: 1045, required: v("5.0.0") })
        );
    }

    /// Requirements carry forward, so a gap in the published window still has a
    /// floor in force.
    #[test]
    fn a_floor_carries_forward_until_superseded() {
        let r = reqs(&[(1040, "4.2.2")]);
        assert_eq!(r.floor_at(1043).map(|x| x.min.clone()), Some(v("4.2.2")));
    }

    /// Pre-release ordering, which is where a hand-rolled comparison goes wrong.
    #[test]
    fn prerelease_ordering_is_semver() {
        let r = reqs(&[(1, "4.3.0-rc.1")]);
        assert_eq!(compliance(&v("4.3.0-rc.0"), 1, &r),
            Some(Compliance::BelowCurrent { epoch: 1, required: v("4.3.0-rc.1") }));
        assert_eq!(compliance(&v("4.3.0-rc.1"), 1, &r), Some(Compliance::Ok));
        assert_eq!(compliance(&v("4.3.0"), 1, &r), Some(Compliance::Ok),
            "a release outranks its own candidates");
    }

    #[test]
    fn an_empty_schedule_is_no_opinion() {
        assert_eq!(compliance(&v("4.2.2"), 1, &reqs(&[])), None);
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
            Requirement { epoch: 1035, min: v("4.2.2"), inherited: true },
            Requirement { epoch: 1036, min: v("4.3.0-rc.1"), inherited: false },
        ]);
    }

    #[test]
    fn a_newly_announced_floor_is_reported_as_such() {
        let old = reqs(&[(1041, "4.2.2")]);
        let mut new = reqs(&[(1041, "4.2.2"), (1043, "4.3.0")]);
        new.entries[1].inherited = false;
        assert_eq!(diff(&old, &new), vec!["epoch 1043: >= 4.3.0 (newly announced)".to_string()]);
        assert!(diff(&new, &new).is_empty());
    }
}

//! Scraping Firedancer's own metrics endpoint.
//!
//! Firedancer is commonly run with its RPC port off, which leaves perch with
//! nothing local to ask: `node_behind` has no endpoint, and a validator that
//! falls behind is only noticed once the cluster calls it delinquent. But the
//! metric tile serves a Prometheus page (`[tiles.metric]`, port 7999 unless
//! changed) in which the validator says what state it believes it is in, and
//! reading it takes one unauthenticated HTTP GET -- no key, no privilege,
//! nothing the sandbox has to be loosened for.
//!
//! Every field is optional. The metric names are Firedancer's, they have
//! changed between releases, and forks add and remove tiles; a name this
//! build does not export is no opinion, never an alert.

use crate::{
    node_exporter::parse_line,
    rpc::RpcError,
};
use std::time::Duration;
use tracing::debug;

/// `diag_vote_state`.
pub mod vote {
    pub const DISABLED: u64 = 0;
    pub const NOT_STARTED: u64 = 1;
    pub const DELINQUENT: u64 = 2;
    pub const VOTING: u64 = 3;
    pub const INADMISSIBLE: u64 = 4;
}

/// `diag_replay_state`.
pub mod replay {
    pub const DISABLED: u64 = 0;
    pub const NOT_STARTED: u64 = 1;
    pub const BEHIND: u64 = 2;
    pub const RUNNING: u64 = 3;
}

/// `diag_turbine_state`.
pub mod turbine {
    pub const DISABLED: u64 = 0;
    pub const NOT_STARTED: u64 = 1;
    pub const STALLED: u64 = 2;
    pub const REPAIR_OUTPACING: u64 = 3;
    pub const RUNNING: u64 = 4;
}

/// `tile_state`: 0 booting, 1 running, 2 shut down.
const TILE_RUNNING: u64 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct Tile {
    /// "replay", "execrp", ...
    pub kind: String,
    /// The index among tiles of that kind.
    pub id: String,
    /// False for a tile still booting, and for the ones that exit once their
    /// work is done: the snapshot loaders, genesis.
    pub running: bool,
    /// Wall-clock nanoseconds on the validator's own clock.
    pub heartbeat_ns: Option<u64>,
}

impl Tile {
    pub fn name(&self) -> String {
        format!("{}:{}", self.kind, self.id)
    }
}

/// What one Firedancer said about itself in one scrape.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    pub vote_state: Option<u64>,
    pub replay_state: Option<u64>,
    pub turbine_state: Option<u64>,
    /// `replay_is_caught_up`: set once per run, when replay first reaches the
    /// cluster tip, and never cleared.
    pub caught_up: Option<bool>,
    pub boot_time_unix: Option<u64>,
    pub tiles: Vec<Tile>,
    /// Account versions in the index, and how many it can hold.
    pub accounts_used: Option<u64>,
    pub accounts_capacity: Option<u64>,
    pub accounts_disk_used_bytes: Option<u64>,
    pub accounts_disk_allocated_bytes: Option<u64>,
}

impl Metrics {
    /// Nothing recognisable was on the page: the URL points at something
    /// else, or at a Firedancer whose metrics share no name with these.
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn accounts_used_percent(&self) -> Option<f64> {
        match (self.accounts_used, self.accounts_capacity) {
            (Some(used), Some(cap)) if cap > 0 => Some(used as f64 * 100.0 / cap as f64),
            _ => None,
        }
    }

    /// Running tiles whose heartbeat trails the freshest one on the page by
    /// more than `stale_after`, with how far each trails, worst first.
    ///
    /// Measured against the page rather than against perch's clock: the two
    /// machines need not agree on the time, and a page that was served at all
    /// has at least one tile alive to compare with.
    pub fn stalled_tiles(&self, stale_after: Duration) -> Vec<(String, Duration)> {
        let Some(newest) = self.tiles.iter().filter_map(|t| t.heartbeat_ns).max() else {
            return Vec::new();
        };
        let mut out: Vec<(String, Duration)> = self
            .tiles
            .iter()
            .filter(|t| t.running)
            .filter_map(|t| {
                let behind = Duration::from_nanos(newest - t.heartbeat_ns?);
                (behind > stale_after).then(|| (t.name(), behind))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// Whether any tile reported a heartbeat, so that "none stalled" means
    /// something.
    pub fn has_heartbeats(&self) -> bool {
        self.tiles.iter().any(|t| t.running && t.heartbeat_ns.is_some())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Scrape {
    Ok(Metrics),
    /// Nothing answered, or not with a 2xx.
    Unreachable(String),
    /// Something answered, with none of the metrics read here. A wrong URL is
    /// the usual cause, and it is not evidence about the validator.
    Unrecognised,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// The `[[hosts]]` entry this Firedancer runs on.
    pub host: String,
    pub scrape: Scrape,
}

impl Snapshot {
    pub fn metrics(&self) -> Option<&Metrics> {
        match &self.scrape {
            Scrape::Ok(m) => Some(m),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Scraper {
    pub host: String,
    url: String,
    client: reqwest::Client,
    attempts: u32,
}

impl Scraper {
    pub fn new(host: String, url: String, timeout: Duration, attempts: u32) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            host,
            url,
            client,
            attempts: attempts.max(1),
        })
    }

    pub async fn scrape(&self) -> Snapshot {
        let mut last = String::from("no attempt made");
        for attempt in 0..self.attempts {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(300 * u64::from(attempt))).await;
            }
            match self.scrape_once().await {
                Ok(text) => {
                    let metrics = parse(&text);
                    let scrape = if metrics.is_empty() {
                        Scrape::Unrecognised
                    } else {
                        debug!(host = %self.host, "scraped firedancer: {} tile(s)", metrics.tiles.len());
                        Scrape::Ok(metrics)
                    };
                    return Snapshot {
                        host: self.host.clone(),
                        scrape,
                    };
                }
                Err(e) => last = e.to_string(),
            }
        }
        Snapshot {
            host: self.host.clone(),
            scrape: Scrape::Unreachable(last),
        }
    }

    async fn scrape_once(&self) -> Result<String, RpcError> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| RpcError::Transient(format!("scrape failed: {}", crate::rpc::scrub(e))))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(RpcError::Transient(format!("firedancer metrics returned {status}")));
        }
        // Over a megabyte on a current build: every tile and link, with
        // histograms. Still far under the scrape cap.
        crate::rpc::body_capped(resp, crate::rpc::MAX_SCRAPE_BODY)
            .await
            .map_err(|e| RpcError::Transient(format!("unreadable scrape body: {e}")))
    }
}

/// The few series read here, by the prefix they share. The page runs to tens
/// of thousands of lines, so everything else is skipped before it is parsed.
const WANTED_PREFIXES: &[&str] = &[
    "diag_vote_state",
    "diag_replay_state",
    "diag_turbine_state",
    "replay_is_caught_up",
    "metric_boot_time",
    "tile_state",
    "tile_heartbeat_time",
    "accdb_account_used",
    "accdb_account_capacity",
    "accdb_disk_used_bytes",
    "accdb_disk_allocated_bytes",
];

pub fn parse(text: &str) -> Metrics {
    let mut m = Metrics::default();
    // Negative, NaN and infinite values say nothing usable.
    let whole = |v: f64| (v.is_finite() && v >= 0.0).then_some(v as u64);

    for line in text.lines() {
        if !WANTED_PREFIXES.iter().any(|p| line.starts_with(p)) {
            continue;
        }
        let Some((name, labels, value)) = parse_line(line) else {
            continue;
        };
        let Some(value) = whole(value) else { continue };
        match name.as_str() {
            "diag_vote_state" => m.vote_state = Some(value),
            "diag_replay_state" => m.replay_state = Some(value),
            "diag_turbine_state" => m.turbine_state = Some(value),
            "replay_is_caught_up" => m.caught_up = Some(value != 0),
            // Nanoseconds since the epoch.
            "metric_boot_time" => m.boot_time_unix = Some(value / 1_000_000_000),
            "accdb_account_used" => m.accounts_used = Some(value),
            "accdb_account_capacity" => m.accounts_capacity = Some(value),
            "accdb_disk_used_bytes" => m.accounts_disk_used_bytes = Some(value),
            "accdb_disk_allocated_bytes" => m.accounts_disk_allocated_bytes = Some(value),
            "tile_state" | "tile_heartbeat_time" => {
                let (Some(kind), Some(id)) = (labels.get("kind"), labels.get("kind_id")) else {
                    continue;
                };
                let i = match m.tiles.iter().position(|t| &t.kind == kind && &t.id == id) {
                    Some(i) => i,
                    None => {
                        m.tiles.push(Tile {
                            kind: kind.clone(),
                            id: id.clone(),
                            running: false,
                            heartbeat_ns: None,
                        });
                        m.tiles.len() - 1
                    }
                };
                if name == "tile_state" {
                    m.tiles[i].running = value == TILE_RUNNING;
                } else {
                    m.tiles[i].heartbeat_ns = Some(value);
                }
            }
            _ => {}
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines as fox-main's Firedancer v26.10.8 served them on 2026-11-25,
    /// with the help text and the tiles cut down.
    const PAGE: &str = r#"
# HELP tile_pid Process ID of the tile
# TYPE tile_pid gauge
tile_pid{kind="replay",kind_id="0"} 1866
# HELP tile_state Tile lifecycle state: 0=booting, 1=running, 2=shutdown
# TYPE tile_state gauge
tile_state{kind="snapin",kind_id="0"} 2
tile_state{kind="replay",kind_id="0"} 1
tile_state{kind="execrp",kind_id="0"} 1
tile_state{kind="execrp",kind_id="1"} 1
tile_state_extra{kind="replay",kind_id="0"} 7
tile_heartbeat_time{kind="snapin",kind_id="0"} 1795572050713045105
tile_heartbeat_time{kind="replay",kind_id="0"} 1795640839142777269
tile_heartbeat_time{kind="execrp",kind_id="0"} 1795640839140254219
tile_heartbeat_time{kind="execrp",kind_id="1"} 1795640839141526984
diag_vote_state{kind="diag",kind_id="0"} 3
diag_replay_state{kind="diag",kind_id="0"} 3
diag_turbine_state{kind="diag",kind_id="0"} 4
replay_is_caught_up{kind="replay",kind_id="0"} 1
metric_boot_time{kind="metric",kind_id="0"} 1795571938701405622
accdb_account_used{kind="accdb",kind_id="0"} 1237922396
accdb_account_capacity{kind="accdb",kind_id="0"} 1300000000
accdb_disk_allocated_bytes{kind="accdb",kind_id="0"} 584115552256
accdb_disk_used_bytes{kind="accdb",kind_id="0"} 447228086798
accdb_disk_written_bytes_total{kind="accdb",kind_id="0"} 99
"#;

    #[test]
    fn reads_a_real_page() {
        let m = parse(PAGE);
        assert_eq!(m.vote_state, Some(vote::VOTING));
        assert_eq!(m.replay_state, Some(replay::RUNNING));
        assert_eq!(m.turbine_state, Some(turbine::RUNNING));
        assert_eq!(m.caught_up, Some(true));
        assert_eq!(m.boot_time_unix, Some(1795571938));
        assert_eq!(m.accounts_used, Some(1_237_922_396));
        assert_eq!(m.accounts_capacity, Some(1_300_000_000));
        assert_eq!(m.accounts_disk_allocated_bytes, Some(584_115_552_256));
        assert_eq!(m.accounts_disk_used_bytes, Some(447_228_086_798));
        let used = m.accounts_used_percent().unwrap();
        assert!((used - 95.22).abs() < 0.01, "{used}");

        assert_eq!(m.tiles.len(), 4);
        let replay = m.tiles.iter().find(|t| t.kind == "replay").unwrap();
        // `tile_state_extra` shares the prefix and is not the tile's state.
        assert!(replay.running);
        assert!(!m.tiles.iter().find(|t| t.kind == "snapin").unwrap().running);
    }

    /// The snapshot loaders exit after boot and their heartbeats stop for
    /// good. That is not a stall, however old they get.
    #[test]
    fn a_tile_that_has_shut_down_is_not_stalled() {
        let m = parse(PAGE);
        assert!(m.has_heartbeats());
        assert_eq!(m.stalled_tiles(Duration::from_secs(30)), vec![]);
    }

    #[test]
    fn a_running_tile_whose_heartbeat_trails_the_rest_is_stalled() {
        let page = PAGE.replace(
            r#"tile_heartbeat_time{kind="execrp",kind_id="1"} 1795640839141526984"#,
            r#"tile_heartbeat_time{kind="execrp",kind_id="1"} 1795640749141526984"#,
        );
        let stalled = parse(&page).stalled_tiles(Duration::from_secs(30));
        assert_eq!(stalled.len(), 1);
        assert_eq!(stalled[0].0, "execrp:1");
        assert_eq!(stalled[0].1.as_secs(), 90);
    }

    /// A page from something that is not Firedancer must not read as a
    /// Firedancer with every field absent.
    #[test]
    fn a_page_with_none_of_the_metrics_is_empty() {
        let m = parse("node_filesystem_avail_bytes{mountpoint=\"/\"} 1\nup 1\n");
        assert!(m.is_empty());
        assert!(!m.has_heartbeats());
    }

    /// An older or forked build: whatever it does export is read, and the
    /// rest stays absent.
    #[test]
    fn a_missing_metric_is_absent_not_zero() {
        let m = parse("diag_replay_state{kind=\"diag\",kind_id=\"0\"} 2\n");
        assert_eq!(m.replay_state, Some(replay::BEHIND));
        assert_eq!(m.vote_state, None);
        assert_eq!(m.caught_up, None);
        assert_eq!(m.accounts_used_percent(), None);
        assert!(!m.is_empty());
    }

    #[test]
    fn a_zero_capacity_gives_no_percentage() {
        let m = parse("accdb_account_used 5\naccdb_account_capacity 0\n");
        assert_eq!(m.accounts_used_percent(), None);
    }
}

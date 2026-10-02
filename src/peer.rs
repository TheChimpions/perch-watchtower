//! Peer monitoring: watchtowers watching each other.
//!
//! A monitor on the validator machine has the best view of it and dies with it.
//! A remote monitor survives and sees less. Running both and having them watch
//! each other closes the hole where a machine goes hard down and takes the
//! validator *and* the only thing that could have explained why.
//!
//! The hard part is that peer silence is ambiguous: machine dead, network
//! partitioned, or just the monitor crashed. Treating silence as "machine down"
//! would reintroduce exactly the false positives this tool exists to remove. So
//! silence alone is never a page -- it is fused with cluster-side evidence about
//! whether that validator is still voting. See `checks::evaluate_peers`.
//!
//! The peer protocol is the existing `/metrics` endpoint. No new protocol, no
//! new port, and a peer that is running but not working is distinguishable from
//! one that is healthy, because `perch_visible` says so.

use crate::node_exporter::parse_line;
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn};

/// Tri-state, for the same reason everything else here is.
///
/// A peer that is reachable but has not completed its first cycle is not down --
/// it is starting. Reading that as down meant a freshly restarted instance was
/// declared dead, and combined with an unrelated delinquency it could escalate
/// to "the machine is hard down" about a perfectly healthy box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHealth {
    Live,
    Down(String),
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub name: String,
    pub priority: u32,
    /// The validator running on that peer's machine, if it runs one.
    pub validator: Option<String>,
    pub reachable: bool,
    /// How long ago the peer completed a cycle, by its own clock.
    pub last_cycle_age: Option<Duration>,
    /// Whether the peer could see the cluster in its last cycle. A peer that is
    /// up but blind is running, not working.
    pub visible: Option<bool>,
    pub version: Option<String>,
    /// How long the peer process has been up, by its own clock.
    pub uptime: Option<Duration>,
    /// Unix deadline of a maintenance window the peer declared, if any.
    pub maintenance_until: Option<u64>,
    pub error: Option<String>,
}

impl PeerStatus {
    /// Live means reachable *and* actually cycling. A process accepting
    /// connections but doing no work is not a functioning peer.
    pub fn health(&self, stale_after: Duration) -> PeerHealth {
        if !self.reachable {
            return PeerHealth::Down(
                self.error.clone().unwrap_or_else(|| "unreachable".into()),
            );
        }
        match self.last_cycle_age {
            Some(age) if age <= stale_after => PeerHealth::Live,
            Some(age) => PeerHealth::Down(format!(
                "last cycled {} ago",
                humantime::format_duration(Duration::from_secs(age.as_secs()))
            )),
            // Reachable, no cycle yet. Whether that is alarming depends
            // entirely on how long it has been up.
            None => match self.uptime {
                Some(up) if up <= stale_after => PeerHealth::Unknown(format!(
                    "started {} ago, first cycle not complete",
                    humantime::format_duration(Duration::from_secs(up.as_secs()))
                )),
                Some(up) => PeerHealth::Down(format!(
                    "up {} without completing a cycle",
                    humantime::format_duration(Duration::from_secs(up.as_secs()))
                )),
                // Cannot tell how long it has been up, so cannot tell whether
                // this is startup or a wedge. Never page on that.
                None => PeerHealth::Unknown(
                    "answered but exposed no cycle or start timestamp".into(),
                ),
            },
        }
    }

    pub fn is_live(&self, stale_after: Duration) -> bool {
        matches!(self.health(stale_after), PeerHealth::Live)
    }

    /// For ownership only: an ambiguous peer keeps its claim. Taking over on
    /// "we are not sure" is how you end up with two instances alerting.
    pub fn blocks_takeover(&self, stale_after: Duration) -> bool {
        !matches!(self.health(stale_after), PeerHealth::Down(_))
    }

    pub fn describe(&self, stale_after: Duration) -> String {
        match self.health(stale_after) {
            PeerHealth::Down(why) => why,
            PeerHealth::Unknown(why) => why,
            PeerHealth::Live => {
                let vis = match self.visible {
                    Some(true) => "visible",
                    Some(false) => "BLIND",
                    None => "visibility unknown",
                };
                let age = self.last_cycle_age.unwrap_or_default();
                format!(
                    "ok, cycled {} ago, {vis}",
                    humantime::format_duration(Duration::from_secs(age.as_secs()))
                )
            }
        }
    }
}

#[derive(Clone)]
pub struct Peer {
    pub name: String,
    pub url: String,
    pub priority: u32,
    pub validator: Option<String>,
    client: reqwest::Client,
}

/// Read a peer's Prometheus exposition into its status.
///
/// Split out from the network path so the peer protocol can actually be tested:
/// this is what decides whether a peer counts as alive, and getting it wrong
/// pages the whole fleet.
fn absorb_exposition(status: &mut PeerStatus, text: &str, now_unix: f64) {
    for line in text.lines() {
        let Some((name, labels, value)) = parse_line(line) else {
            continue;
        };
        // A peer mid-rename still speaks the old prefix. Matching on the suffix
        // lets a renamed instance and an un-renamed one read each other, which
        // is the difference between a staged rollout and a fleet-wide false
        // `peer_down` in both directions at once.
        let Some(suffix) = name
            .strip_prefix("perch_")
            .or_else(|| name.strip_prefix("chimpstower_"))
        else {
            continue;
        };
        match suffix {
            "last_cycle_timestamp_seconds" => {
                // Clamped at zero: a peer whose clock is ahead of ours would
                // otherwise produce a negative age and read as impossibly fresh.
                let age = (now_unix - value).max(0.0);
                status.last_cycle_age = Some(Duration::from_secs_f64(age));
            }
            "visible" => status.visible = Some(value != 0.0),
            "maintenance_until_seconds" if value > 0.0 => {
                status.maintenance_until = Some(value as u64);
            }
            "start_timestamp_seconds" => {
                status.uptime = Some(Duration::from_secs_f64((now_unix - value).max(0.0)));
            }
            "build_info" => {
                status.version = labels.get("version").cloned();
            }
            _ => {}
        }
    }
}

impl Peer {
    pub fn new(
        name: String,
        url: String,
        priority: u32,
        validator: Option<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            name,
            url,
            priority,
            validator,
            client,
        })
    }

    pub async fn poll(&self) -> PeerStatus {
        let mut status = PeerStatus {
            name: self.name.clone(),
            priority: self.priority,
            validator: self.validator.clone(),
            reachable: false,
            last_cycle_age: None,
            visible: None,
            version: None,
            uptime: None,
            maintenance_until: None,
            error: None,
        };

        let text = match self.fetch().await {
            Ok(t) => t,
            Err(e) => {
                debug!(peer = %self.name, "poll failed: {e}");
                status.error = Some(e);
                return status;
            }
        };

        status.reachable = true;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        absorb_exposition(&mut status, &text, now_unix);

        if status.last_cycle_age.is_none() && status.uptime.is_none() {
            warn!(
                peer = %self.name,
                "answered but exposed neither a cycle nor a start timestamp; is it really a perch?"
            );
        }
        status
    }

    async fn fetch(&self) -> Result<String, String> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| crate::rpc::scrub(e).to_string())?;
        if !resp.status().is_success() {
            return Err(format!("http {}", resp.status()));
        }
        resp.text().await.map_err(|e| crate::rpc::scrub(e).to_string())
    }
}

/// Which instance is responsible for notifying.
///
/// Only the lowest-priority *live* instance alerts; the rest run hot and take
/// over if it goes silent. A network partition makes both sides believe they
/// own alerting, which produces duplicate pages. That is the correct failure
/// mode to choose: the inverse -- both sides deferring and nobody paging -- is
/// the one that costs you an outage.
///
/// This decides who *notifies*, and nothing else. It must never be wired to
/// failover: moving a validator identity on a monitor's opinion invites
/// double-voting under exactly this partition.
#[derive(Debug, Default)]
pub struct Ownership {
    /// Higher-priority peers currently considered down, and since when.
    down_since: HashMap<String, Instant>,
    owner: bool,
    announced: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OwnershipChange {
    Unchanged,
    /// Took over alerting because every higher-priority peer is down.
    Assumed { from: Vec<String> },
    /// Handed alerting back to a higher-priority peer that recovered.
    Relinquished { to: String },
}

impl Ownership {
    pub fn is_owner(&self) -> bool {
        self.owner
    }

    /// Recompute ownership. `takeover_after` is a grace period so a brief blip
    /// on the primary does not cause a handoff, and so a recovering primary is
    /// not immediately handed back a flapping role.
    pub fn evaluate(
        &mut self,
        own_priority: u32,
        peers: &[PeerStatus],
        stale_after: Duration,
        takeover_after: Duration,
        now: Instant,
    ) -> OwnershipChange {
        let mut blocking = Vec::new();

        for p in peers.iter().filter(|p| p.priority < own_priority) {
            if p.blocks_takeover(stale_after) {
                self.down_since.remove(&p.name);
                blocking.push(p.name.clone());
                continue;
            }
            let since = *self.down_since.entry(p.name.clone()).or_insert(now);
            // Still within the grace period: they keep ownership for now.
            if now.saturating_duration_since(since) < takeover_after {
                blocking.push(p.name.clone());
            }
        }

        // Peers that have gone away entirely should not keep stale entries.
        let names: Vec<String> = peers.iter().map(|p| p.name.clone()).collect();
        self.down_since.retain(|k, _| names.contains(k));

        let should_own = blocking.is_empty();
        let was = self.owner;
        self.owner = should_own;

        match (was, should_own) {
            (false, true) if !self.announced => {
                self.announced = true;
                let from = peers
                    .iter()
                    .filter(|p| p.priority < own_priority)
                    .map(|p| p.name.clone())
                    .collect();
                OwnershipChange::Assumed { from }
            }
            (true, false) => {
                self.announced = false;
                OwnershipChange::Relinquished {
                    to: blocking.first().cloned().unwrap_or_default(),
                }
            }
            _ => OwnershipChange::Unchanged,
        }
    }

    /// An instance with no higher-priority peers configured owns alerting from
    /// the first cycle, with nothing to wait for.
    pub fn assume_sole_owner(&mut self) {
        self.owner = true;
        self.announced = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STALE: Duration = Duration::from_secs(180);
    const TAKEOVER: Duration = Duration::from_secs(300);

    fn peer(name: &str, priority: u32, age_secs: Option<u64>) -> PeerStatus {
        PeerStatus {
            name: name.into(),
            priority,
            validator: None,
            reachable: age_secs.is_some(),
            last_cycle_age: age_secs.map(Duration::from_secs),
            visible: Some(true),
            version: Some("0.1.0".into()),
            uptime: age_secs.map(|a| Duration::from_secs(a + 60)),
            maintenance_until: None,
            error: None,
        }
    }

    /// Reachable, answering, but has not finished its first cycle.
    fn starting(name: &str, priority: u32, up_secs: u64) -> PeerStatus {
        PeerStatus {
            name: name.into(),
            priority,
            validator: None,
            reachable: true,
            last_cycle_age: None,
            visible: None,
            version: Some("0.1.0".into()),
            uptime: Some(Duration::from_secs(up_secs)),
            maintenance_until: None,
            error: None,
        }
    }

    #[test]
    fn a_fresh_peer_is_live_and_a_stale_one_is_not() {
        assert!(peer("a", 1, Some(30)).is_live(STALE));
        assert!(!peer("a", 1, Some(600)).is_live(STALE));
        assert!(!peer("a", 1, None).is_live(STALE));
    }

    #[test]
    fn a_peer_that_has_just_started_is_unknown_not_down() {
        // The bug this pins: a freshly restarted peer exposes no cycle
        // timestamp, was read as down, and -- combined with an unrelated
        // delinquency -- escalated to "the machine is hard down" about a
        // perfectly healthy box.
        let p = starting("hub", 1, 5);
        assert!(matches!(p.health(STALE), PeerHealth::Unknown(_)), "{:?}", p.health(STALE));
        assert!(!p.is_live(STALE));
        assert!(p.blocks_takeover(STALE), "ambiguity must not trigger a takeover");
    }

    #[test]
    fn a_peer_up_a_long_time_with_no_cycle_is_down() {
        // Past the staleness window without ever cycling is a wedge, not a boot.
        let p = starting("hub", 1, 3600);
        assert!(matches!(p.health(STALE), PeerHealth::Down(_)));
    }

    #[test]
    fn a_peer_with_no_timestamps_at_all_is_unknown() {
        let mut p = starting("hub", 1, 5);
        p.uptime = None;
        assert!(matches!(p.health(STALE), PeerHealth::Unknown(_)));
    }

    #[test]
    fn a_reachable_but_wedged_peer_is_not_live() {
        // Accepting connections while having stopped cycling is not a
        // functioning peer, and must not hold alerting ownership.
        let mut p = peer("a", 1, Some(9999));
        p.reachable = true;
        assert!(!p.is_live(STALE));
    }

    #[test]
    fn a_peer_clock_ahead_of_ours_does_not_read_as_negative_age() {
        let p = peer("a", 1, Some(0));
        assert!(p.is_live(STALE));
    }

    #[test]
    fn the_primary_owns_alerting_while_it_is_live() {
        let mut o = Ownership::default();
        let peers = vec![peer("failover", 1, Some(30))];
        assert_eq!(
            o.evaluate(2, &peers, STALE, TAKEOVER, Instant::now()),
            OwnershipChange::Unchanged
        );
        assert!(!o.is_owner(), "a standby must not alert while the primary is up");
    }

    #[test]
    fn a_starting_peer_does_not_trigger_a_takeover() {
        let mut o = Ownership::default();
        let t0 = Instant::now();
        let booting = vec![starting("failover", 1, 5)];
        o.evaluate(2, &booting, STALE, TAKEOVER, t0);
        o.evaluate(2, &booting, STALE, TAKEOVER, t0 + Duration::from_secs(600));
        assert!(!o.is_owner(), "a peer that is merely booting must keep ownership");
    }

    #[test]
    fn takeover_waits_out_the_grace_period() {
        let mut o = Ownership::default();
        let t0 = Instant::now();
        let down = vec![peer("failover", 1, None)];

        // Primary just went silent: do not take over yet.
        assert_eq!(
            o.evaluate(2, &down, STALE, TAKEOVER, t0),
            OwnershipChange::Unchanged
        );
        assert!(!o.is_owner());

        // Still inside the grace period.
        assert_eq!(
            o.evaluate(2, &down, STALE, TAKEOVER, t0 + Duration::from_secs(200)),
            OwnershipChange::Unchanged
        );
        assert!(!o.is_owner());

        // Past it: take over.
        let change = o.evaluate(2, &down, STALE, TAKEOVER, t0 + Duration::from_secs(320));
        assert!(matches!(change, OwnershipChange::Assumed { .. }));
        assert!(o.is_owner());
    }

    #[test]
    fn a_brief_primary_blip_does_not_cause_a_handoff() {
        let mut o = Ownership::default();
        let t0 = Instant::now();
        o.evaluate(2, &[peer("failover", 1, None)], STALE, TAKEOVER, t0);
        let change = o.evaluate(
            2,
            &[peer("failover", 1, Some(20))],
            STALE,
            TAKEOVER,
            t0 + Duration::from_secs(120),
        );
        assert_eq!(change, OwnershipChange::Unchanged);
        assert!(!o.is_owner());
    }

    #[test]
    fn ownership_is_handed_back_when_the_primary_returns() {
        let mut o = Ownership::default();
        let t0 = Instant::now();
        o.evaluate(2, &[peer("failover", 1, None)], STALE, TAKEOVER, t0);
        o.evaluate(
            2,
            &[peer("failover", 1, None)],
            STALE,
            TAKEOVER,
            t0 + Duration::from_secs(320),
        );
        assert!(o.is_owner());

        let change = o.evaluate(
            2,
            &[peer("failover", 1, Some(10))],
            STALE,
            TAKEOVER,
            t0 + Duration::from_secs(400),
        );
        assert!(matches!(change, OwnershipChange::Relinquished { .. }));
        assert!(!o.is_owner());
    }

    #[test]
    fn takeover_is_announced_once_not_every_cycle() {
        let mut o = Ownership::default();
        let t0 = Instant::now();
        let down = vec![peer("failover", 1, None)];
        o.evaluate(2, &down, STALE, TAKEOVER, t0);
        o.evaluate(2, &down, STALE, TAKEOVER, t0 + Duration::from_secs(320));
        for i in 6..20 {
            assert_eq!(
                o.evaluate(2, &down, STALE, TAKEOVER, t0 + Duration::from_secs(60 * i)),
                OwnershipChange::Unchanged
            );
        }
    }

    #[test]
    fn lower_priority_peers_never_block_ownership() {
        let mut o = Ownership::default();
        // We are priority 1; a live priority-2 peer is subordinate.
        o.evaluate(
            1,
            &[peer("validator-box", 2, Some(10))],
            STALE,
            TAKEOVER,
            Instant::now(),
        );
        assert!(o.is_owner());
    }

    #[test]
    fn with_no_peers_configured_we_own_alerting_immediately() {
        let mut o = Ownership::default();
        assert!(matches!(
            o.evaluate(1, &[], STALE, TAKEOVER, Instant::now()),
            OwnershipChange::Assumed { .. }
        ));
        assert!(o.is_owner());
    }

    #[test]
    fn a_partition_gives_duplicate_pages_not_silence() {
        // Both sides believe they own alerting. Duplicate pages are the correct
        // failure mode; both deferring would mean nobody pages.
        let mut primary = Ownership::default();
        let mut standby = Ownership::default();
        let t0 = Instant::now();
        let late = t0 + Duration::from_secs(600);

        primary.evaluate(1, &[peer("standby", 2, None)], STALE, TAKEOVER, late);
        standby.evaluate(2, &[peer("failover", 1, None)], STALE, TAKEOVER, t0);
        standby.evaluate(2, &[peer("failover", 1, None)], STALE, TAKEOVER, late);

        assert!(primary.is_owner() && standby.is_owner());
    }
}

#[cfg(test)]
mod rename_compat {
    use super::*;

    fn blank() -> PeerStatus {
        PeerStatus {
            name: "p".into(),
            priority: 1,
            validator: None,
            reachable: true,
            last_cycle_age: None,
            visible: None,
            version: None,
            uptime: None,
            maintenance_until: None,
            error: None,
        }
    }

    fn exposition(prefix: &str, now: f64) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{prefix}_last_cycle_timestamp_seconds {}\n",
            now - 10.0
        ));
        out.push_str(&format!("{prefix}_visible 1\n"));
        out.push_str(&format!(
            "{prefix}_start_timestamp_seconds {}\n",
            now - 3600.0
        ));
        out.push_str(&format!("{prefix}_build_info{{version=\"0.1.0\"}} 1\n"));
        out
    }

    /// The rollout property: a renamed instance must be able to read a peer
    /// still running the old binary. Without this the hub and every spoke
    /// declare each other down the moment the first box is upgraded.
    #[test]
    fn a_renamed_instance_can_read_an_unrenamed_peer() {
        let now = 1_700_000_000.0;
        let mut st = blank();
        absorb_exposition(&mut st, &exposition("chimpstower", now), now);
        assert_eq!(st.visible, Some(true));
        assert_eq!(st.version.as_deref(), Some("0.1.0"));
        assert!(st.last_cycle_age.unwrap().as_secs() <= 11);
        assert!(st.uptime.unwrap().as_secs() >= 3599);
    }

    #[test]
    fn the_new_prefix_still_reads_identically() {
        let now = 1_700_000_000.0;
        let (mut a, mut b) = (blank(), blank());
        absorb_exposition(&mut a, &exposition("perch", now), now);
        absorb_exposition(&mut b, &exposition("chimpstower", now), now);
        assert_eq!(a.visible, b.visible);
        assert_eq!(a.version, b.version);
        assert_eq!(a.last_cycle_age, b.last_cycle_age);
    }

    /// An unrelated exporter on the same port must not be mistaken for a peer.
    #[test]
    fn foreign_metrics_are_ignored() {
        let mut st = blank();
        absorb_exposition(&mut st, "node_visible 1\nup 1\n", 1_700_000_000.0);
        assert_eq!(st.visible, None);
        assert_eq!(st.last_cycle_age, None);
    }
}

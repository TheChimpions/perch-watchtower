//! TOML configuration. Secrets may be written as `env:VAR_NAME` so the file
//! itself stays safe to keep in a config repo.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

fn d(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub watchtower: Watchtower,
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    /// node_exporter instances to scrape for filesystem state. Optional: with
    /// none configured, the disk checks simply do not run.
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
    /// Other perch instances to watch. Optional.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub peering: Peering,
    #[serde(default)]
    pub quorum: Quorum,
    #[serde(default)]
    pub blindness: Blindness,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub checks: Checks,
    #[serde(default)]
    pub notify: Notify,
    #[serde(default)]
    pub silence: Silence,
    #[serde(default)]
    pub digest: Digest,
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub heartbeat: Option<HeartbeatConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub context: ContextConfig,
    #[serde(default)]
    pub diagnose: DiagnoseConfig,
    /// Channels switched off because their secret was missing or empty.
    /// Populated during validation; not read from the file.
    #[serde(skip)]
    pub secret_problems: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Where to persist alert state between restarts. Without this, a restart
    /// during a live incident loses the PagerDuty dedup key and that incident
    /// stays open forever.
    #[serde(default = "default_state_file")]
    pub file: String,
}

fn default_state_file() -> String {
    "/var/lib/perch/state.json".into()
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            file: default_state_file(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Pinged on every cycle where the cluster was visible.
    pub url: String,
    /// Optional, pinged instead while blind. Healthchecks.io calls this
    /// `<url>/fail`.
    #[serde(default)]
    pub fail_url: Option<String>,
    /// Only check in when checks could actually be evaluated. Leaving this on
    /// means the dead-man's switch reports "working", not merely "running".
    #[serde(default = "yes")]
    pub require_visibility: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Bind address for the Prometheus endpoint. Keep it on localhost or a
    /// private interface; it is unauthenticated.
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
    /// Optional link to your Grafana, shown on the status page. Purely a
    /// convenience link; perch never talks to Grafana itself.
    #[serde(default)]
    pub grafana_url: Option<String>,
    /// Emit every metric a second time under this prefix. Exists only to make a
    /// rename survivable: during a staged rollout the un-renamed half of the
    /// fleet, and any dashboard or rule still written against the old name,
    /// keep working. Remove it once the rollout is done.
    #[serde(default)]
    pub compat_prefix: Option<String>,
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9469".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConfig {
    /// Fetch cluster-wide delinquency at alert time, to answer "is this me or
    /// is this everyone?" in the alert body. Costs one full getVoteAccounts
    /// listing per alert burst, and nothing at all when things are quiet.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(with = "humantime_serde", default = "default_context_ttl")]
    pub cache_for: Duration,
}

fn default_context_ttl() -> Duration {
    d(5 * 60)
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_for: default_context_ttl(),
        }
    }
}

/// Read likely causes off this box when one of its validator's checks fires.
/// See `diagnose.rs`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseConfig {
    /// Label of the validator running on this machine. Unset disables the
    /// feature: a hub has no business reading its own log to explain a spoke.
    #[serde(default)]
    pub validator: Option<String>,
    /// The validator's `--log` file.
    #[serde(default)]
    pub log: Option<PathBuf>,
    /// How far back to look. Widened automatically to cover a longer incident.
    #[serde(with = "humantime_serde", default = "default_diagnose_lookback")]
    pub lookback: Duration,
    /// Cap on how much of the log tail a single diagnosis may read.
    #[serde(default = "default_diagnose_max_scan_mb")]
    pub max_scan_mb: u64,
    /// Sample NIC carrier-down counters so link flaps show up as a cause.
    #[serde(default = "yes")]
    pub watch_links: bool,
    #[serde(default = "default_diagnose_max_findings")]
    pub max_findings: usize,
}

fn default_diagnose_lookback() -> Duration {
    d(20 * 60)
}

fn default_diagnose_max_scan_mb() -> u64 {
    512
}

fn default_diagnose_max_findings() -> usize {
    5
}

impl Default for DiagnoseConfig {
    fn default() -> Self {
        Self {
            validator: None,
            log: None,
            lookback: default_diagnose_lookback(),
            max_scan_mb: default_diagnose_max_scan_mb(),
            watch_links: true,
            max_findings: default_diagnose_max_findings(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watchtower {
    /// Prefixed to every notification so you can tell fleets apart.
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(with = "humantime_serde", default = "default_interval")]
    pub interval: Duration,
    /// Periodic Telegram digest of per-endpoint reliability, so you can see
    /// which provider is generating the noise instead of guessing. Zero disables.
    #[serde(with = "humantime_serde", default = "default_endpoint_report")]
    pub endpoint_report_interval: Duration,
    /// Pin the cluster: "mainnet-beta", "testnet", "devnet", or a raw genesis
    /// hash. Checked against every endpoint at startup.
    ///
    /// Endpoints are already cross-checked against each other, which catches a
    /// config that *mixes* clusters. This catches the other mistake, which is
    /// the one you actually make when you run both: copying a mainnet config,
    /// changing the URLs to testnet, and forgetting the validator identities.
    /// Without the pin that fails as a 3am page for a "missing" vote account;
    /// with it, it fails at startup with the reason.
    #[serde(default)]
    pub cluster: Option<String>,
}

/// One Telegram message per finished epoch: leader slots, skips, credits,
/// balance, version. Sent by whichever instance owns alerting for the
/// validator, so a fleet produces one summary per validator, not one per box.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl Default for Digest {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Genesis hashes of the public clusters.
const KNOWN_CLUSTERS: &[(&str, &str)] = &[
    ("mainnet-beta", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
    ("mainnet", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
    ("testnet", "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
    ("devnet", "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
];

/// Resolve a cluster name to its genesis hash, or pass through a literal hash
/// so private clusters and local test validators can be pinned too.
pub fn resolve_cluster(value: &str) -> Result<String> {
    let lower = value.to_ascii_lowercase();
    if let Some((_, hash)) = KNOWN_CLUSTERS.iter().find(|(name, _)| *name == lower) {
        return Ok((*hash).to_string());
    }
    if (32..=44).contains(&value.len()) && value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(value.to_string());
    }
    bail!(
        "watchtower.cluster {value:?} is not a known cluster name (mainnet-beta, testnet, \
         devnet) and does not look like a genesis hash"
    )
}

impl Watchtower {
    /// The cluster name the SFDP API understands, if this fleet is on one the
    /// program covers. Accepts a name or a genesis hash, since either may be
    /// pinned. Devnet and private clusters have no delegation program.
    pub fn sfdp_cluster(&self) -> Option<&'static str> {
        let genesis = resolve_cluster(self.cluster.as_deref()?).ok()?;
        match genesis.as_str() {
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" => Some("mainnet-beta"),
            "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY" => Some("testnet"),
            _ => None,
        }
    }

    /// The genesis hash every endpoint must report, if pinned.
    pub fn expected_genesis_hash(&self) -> Option<String> {
        self.cluster.as_deref().and_then(|c| resolve_cluster(c).ok())
    }
}

fn default_endpoint_report() -> Duration {
    d(6 * 60 * 60)
}

fn default_name() -> String {
    "perch".into()
}
fn default_interval() -> Duration {
    d(60)
}

impl Default for Watchtower {
    fn default() -> Self {
        Self {
            name: default_name(),
            interval: default_interval(),
            endpoint_report_interval: default_endpoint_report(),
            cluster: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    pub name: String,
    pub url: String,
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,
    /// Retries *within* one cycle. Most transient blips die here and are never
    /// seen by the alerting logic at all.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// This endpoint is a node you operate, not merely a data source.
    ///
    /// Alerts if it stops answering or falls behind the cluster. On a failover
    /// box this is the only way to learn the spare is not actually ready to take
    /// over: its validator runs an unstaked identity, so it never appears in the
    /// vote accounts and no delinquency check can ever see it.
    #[serde(default)]
    pub monitor: bool,
}

fn default_timeout() -> Duration {
    d(15)
}
fn default_attempts() -> u32 {
    3
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub name: String,
    /// node_exporter metrics URL, e.g. "http://10.0.0.5:9100/metrics".
    /// Reach it over a private network; never expose node_exporter publicly.
    pub url: String,
    /// Mountpoints to watch. Empty means every real filesystem, with
    /// pseudo-filesystems (tmpfs, overlay, ...) excluded automatically.
    #[serde(default)]
    pub mountpoints: Vec<String>,
    /// The validator label this host runs. Setting it lets a full disk explain
    /// the delinquency it causes, so you get one page naming the root cause
    /// instead of two describing the same event.
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(with = "humantime_serde", default = "default_host_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_host_attempts")]
    pub attempts: u32,
}

fn default_host_timeout() -> Duration {
    d(10)
}
fn default_host_attempts() -> u32 {
    2
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Runs every check, always.
    Full,
    /// Runs local (disk) and peer checks only. Cluster checks stay off until
    /// this instance becomes the alerting owner, at which point it escalates --
    /// otherwise a promoted standby would own alerting with nothing to alert
    /// about.
    Local,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Alerting {
    /// Report everything this instance is configured to watch, always, with no
    /// deferral to any peer.
    ///
    /// The right setting for a spoke that owns its own validator. Duplication is
    /// prevented by scope rather than by ownership: spoke-1 lists only
    /// validator-1, so it is the only instance that can alert about it. Nothing
    /// to arbitrate, and no hub to be a single point of failure for alerting.
    Always,
    /// Take over notification if every higher-priority peer goes silent.
    ///
    /// For mesh layouts where several instances watch the *same* subjects and
    /// one of them has to be chosen. Not needed when scopes are disjoint.
    Auto,
    /// Notify only about peer liveness -- never about validators, the cluster,
    /// or disks.
    ///
    /// The right setting for a supervising hub: the spokes own their own
    /// validators, and the hub's job is to notice when one of them dies. It
    /// still *runs* cluster checks (set `role = "full"`), because deciding that
    /// a silent spoke means a dead machine requires independent cluster evidence
    /// that its validator stopped voting.
    ///
    /// Also correct on a spoke that should report the hub dying but nothing
    /// else. Peer alerts use a dedup key derived only from the peer's name, so
    /// several observers of one dead peer collapse into a single incident.
    Peers,
    /// Never notify, whatever the peers are doing. The instance still runs its
    /// checks and serves metrics; it simply does not speak.
    Never,
}

impl Alerting {
    /// Whether this instance may notify about a given check.
    pub fn may_report(&self, check_id: &str) -> bool {
        match self {
            Alerting::Always | Alerting::Auto => true,
            Alerting::Never => false,
            Alerting::Peers => is_peer_check(check_id),
        }
    }
}

impl Alerting {
    /// Whether a check is this instance's own, for display and counting.
    ///
    /// A `peers` hub evaluates every validator's checks, but only to judge
    /// whether a silent peer's machine is down; it never reports them. Showing
    /// them as the hub's own put mind-main's identity warning on the hub, as a
    /// second copy of an alert only mind-main sends. Every other mode shows all
    /// it evaluates: a `never` instance is a data source, and showing state is
    /// its job.
    pub fn owns_check(&self, check_id: &str) -> bool {
        !matches!(self, Alerting::Peers) || is_peer_check(check_id)
    }
}

/// Peer checks are about a shared subject rather than about the observer, so
/// several instances can legitimately report the same one.
pub fn is_peer_check(check_id: &str) -> bool {
    check_id.starts_with("peer_down:") || check_id.starts_with("machine_down:")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peering {
    /// This instance's name, as its peers refer to it.
    #[serde(default)]
    pub name: Option<String>,
    /// Lower numbers alert first. Give the failover box 1.
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_role")]
    pub role: Role,
    #[serde(default = "default_alerting")]
    pub alerting: Alerting,
    /// A peer that has not completed a cycle within this long is not live, even
    /// if its port still answers.
    #[serde(with = "humantime_serde", default = "default_stale_after")]
    pub stale_after: Duration,
    /// How long a higher-priority peer must be down before this instance takes
    /// over alerting. Stops a brief blip from causing a handoff.
    #[serde(with = "humantime_serde", default = "default_takeover_after")]
    pub takeover_after: Duration,
    #[serde(with = "humantime_serde", default = "default_peer_timeout")]
    pub timeout: Duration,
}

fn default_priority() -> u32 {
    1
}
fn default_role() -> Role {
    Role::Full
}
fn default_alerting() -> Alerting {
    // The least surprising default: this instance reports what it is configured
    // to watch. `auto` would silently go standby the moment a higher-priority
    // peer is added, which is a sharp edge to leave in a released tool.
    Alerting::Always
}
fn default_stale_after() -> Duration {
    d(180)
}
fn default_takeover_after() -> Duration {
    d(300)
}
fn default_peer_timeout() -> Duration {
    d(10)
}

impl Default for Peering {
    fn default() -> Self {
        Self {
            name: None,
            priority: default_priority(),
            role: default_role(),
            alerting: default_alerting(),
            stale_after: default_stale_after(),
            takeover_after: default_takeover_after(),
            timeout: default_peer_timeout(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    /// The peer's perch metrics endpoint, e.g.
    /// "http://10.0.0.9:9469/metrics". The existing metrics endpoint is the
    /// peer protocol; there is no separate one.
    pub url: String,
    /// Lower numbers alert first.
    pub priority: u32,
    /// The validator running on that peer's machine, if any. Setting it is what
    /// lets peer silence be fused with cluster-side evidence instead of paging
    /// on silence alone.
    #[serde(default)]
    pub validator: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    /// Endpoints that must return a usable answer before the cycle counts as
    /// "we could see the network at all".
    #[serde(default = "default_min_definite")]
    pub min_definite: usize,
    /// Endpoints that must independently agree before any check may fire.
    #[serde(default = "default_min_confirmations")]
    pub min_confirmations: usize,
    /// An endpoint whose own slot is this far behind the best slot seen in the
    /// cycle is stale, and every answer it gave is discarded for that cycle.
    ///
    /// Without this, an endpoint that is lagging but responsive votes with full
    /// weight. It reports an old `lastVote` against its own old slot, computes a
    /// small lag, and returns Healthy -- so a lagging endpoint can vote down a
    /// real problem. It matters most when mixing endpoints of different quality,
    /// such as your own validator's RPC alongside public ones.
    #[serde(default = "default_max_endpoint_lag")]
    pub max_endpoint_lag_slots: u64,
}

fn default_max_endpoint_lag() -> u64 {
    300
}

fn default_min_definite() -> usize {
    2
}
fn default_min_confirmations() -> usize {
    2
}

impl Default for Quorum {
    fn default() -> Self {
        Self {
            min_definite: default_min_definite(),
            min_confirmations: default_min_confirmations(),
            max_endpoint_lag_slots: default_max_endpoint_lag(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blindness {
    /// Being unable to see the network is itself worth knowing about -- quietly
    /// at first...
    #[serde(with = "humantime_serde", default = "default_blind_notify")]
    pub notify_after: Duration,
    /// ...and eventually worth waking up for, because sustained total blindness
    /// could be hiding a real outage. Long enough that ordinary provider
    /// flakiness never reaches it.
    #[serde(with = "humantime_serde", default = "default_blind_page")]
    pub page_after: Duration,
}

fn default_blind_notify() -> Duration {
    // Losing sight of the cluster is an RPC problem, not a validator problem,
    // and almost always resolves itself. Slower and quieter than anything that
    // reflects the validator's actual health.
    d(10 * 60)
}
fn default_blind_page() -> Duration {
    d(30 * 60)
}

impl Default for Blindness {
    fn default() -> Self {
        Self {
            notify_after: default_blind_notify(),
            page_after: default_blind_page(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    pub identity: String,
    /// Optional: discovered from the vote accounts if omitted.
    #[serde(default)]
    pub vote_account: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// If set, a commission that differs pages immediately -- an unexpected
    /// commission change is a hijacked-identity signal, not a flaky one.
    #[serde(default)]
    pub expected_commission: Option<u8>,
    /// The same, in basis points, for a commission that is not a whole
    /// percent (550 = 5.5%). Vote state v4 stores commission in basis points,
    /// and the whole-percent field RPC still reports rounds up, so a change
    /// within one percent is only visible this way.
    #[serde(default)]
    pub expected_commission_bps: Option<u16>,
    /// Expected block-revenue commission in basis points (vote state v4 only).
    #[serde(default)]
    pub expected_block_revenue_commission_bps: Option<u16>,
}

impl ValidatorConfig {
    /// Inflation-rewards commission to expect, in basis points.
    pub fn expected_commission_bps(&self) -> Option<u16> {
        self.expected_commission_bps
            .or(self.expected_commission.map(|pct| pct as u16 * 100))
    }
}

impl ValidatorConfig {
    pub fn display(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.identity)
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// PagerDuty trigger plus Telegram.
    Page,
    /// Telegram only. Never wakes anyone.
    Notify,
    /// Logs only.
    Log,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CheckConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The check must stay confirmed-unhealthy continuously for this long before
    /// it fires. This is wall-clock, not a cycle count, so it keeps its meaning
    /// if the interval changes or cycles are skipped while blind.
    #[serde(with = "humantime_serde")]
    pub pending_for: Duration,
    /// Consecutive confirmed-healthy cycles required to resolve. >1 damps flapping.
    #[serde(default = "default_clear_after")]
    pub clear_after: u32,
    pub severity: Severity,
    /// Suppress re-firing the same alert more often than this.
    #[serde(with = "humantime_serde", default = "default_renotify")]
    pub renotify_after: Duration,
}

fn yes() -> bool {
    true
}
fn default_clear_after() -> u32 {
    2
}
fn default_renotify() -> Duration {
    d(30 * 60)
}

impl CheckConfig {
    fn new(pending_for: Duration, severity: Severity) -> Self {
        Self {
            enabled: true,
            pending_for,
            clear_after: default_clear_after(),
            severity,
            renotify_after: default_renotify(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LagCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    pub max_slots: u64,
}

/// Alpenglow vote-account admission (SIMD-0357). See `alpenglow.rs`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct VoteAdmissionCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    /// Telegram when the vote account's balance covers fewer than this many
    /// epoch boundaries of VAT with no income.
    #[serde(default = "default_vote_admission_warn_epochs")]
    pub warn_epochs: u64,
}

fn default_vote_admission_warn_epochs() -> u64 {
    3
}

fn default_vote_admission() -> VoteAdmissionCheckConfig {
    VoteAdmissionCheckConfig {
        base: CheckConfig {
            // The deadline is the next epoch boundary, usually hours away, so
            // there is no value in repeating the same message: once when it
            // crosses, and PagerDuty owns escalation from there.
            renotify_after: Duration::ZERO,
            ..CheckConfig::new(d(10 * 60), Severity::Page)
        },
        warn_epochs: default_vote_admission_warn_epochs(),
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BalanceCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    /// Telegram at this level...
    pub warn_sol: f64,
    /// ...page at this one.
    pub page_sol: f64,
    /// What voting costs per epoch, used to express a balance as remaining
    /// epochs in the alert. "0.4 epochs of voting left" is actionable in a way
    /// that "0.8 SOL" is not, and it is the mechanism by which an empty identity
    /// takes the validator delinquent.
    #[serde(default = "default_sol_per_epoch")]
    pub sol_per_epoch: f64,
}

fn default_sol_per_epoch() -> f64 {
    2.0
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SkipRateCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    /// Telegram above this skip rate...
    pub warn_percent: f64,
    /// ...PagerDuty above this.
    pub page_percent: f64,
    /// Leader slots required before judging at all.
    ///
    /// Skip rate over a handful of slots is noise: missing 2 of 4 reads as 50%
    /// and means nothing. Solana assigns leader slots in groups of four, so this
    /// is several rotations' worth of evidence.
    #[serde(default = "default_min_leader_slots")]
    pub min_leader_slots: u64,
}

fn default_min_leader_slots() -> u64 {
    40
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DiskSpaceCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    /// Telegram below this much free space...
    pub warn_free_gb: f64,
    /// ...PagerDuty below this.
    pub page_free_gb: f64,
    /// Ceiling on the floors above, as a percentage of the filesystem's size.
    ///
    /// An absolute floor is right for a multi-terabyte ledger disk and absurd
    /// for a 1 GB /boot, which can never have 40 GB free and would therefore
    /// alert forever. The effective floor is whichever is smaller, so the
    /// absolute value governs big disks and this governs small ones.
    #[serde(default = "default_max_floor_percent")]
    pub max_floor_percent: f64,
}

fn default_max_floor_percent() -> f64 {
    25.0
}

impl DiskSpaceCheckConfig {
    /// The floor actually applied to a filesystem of `size_gb`.
    pub fn effective_floor(&self, configured_gb: f64, size_gb: f64) -> f64 {
        let cap = size_gb * self.max_floor_percent / 100.0;
        configured_gb.min(cap)
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DiskFillCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    /// Telegram when projected to fill within this long...
    #[serde(with = "humantime_serde")]
    pub warn_within: Duration,
    /// ...PagerDuty within this.
    #[serde(with = "humantime_serde")]
    pub page_within: Duration,
    /// Refuse to project from less history than this. Free space on a validator
    /// is a sawtooth, and a short window would routinely predict the disk
    /// filling in minutes.
    #[serde(with = "humantime_serde", default = "default_min_history")]
    pub min_history: Duration,
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    /// How far back the slope is fitted over.
    #[serde(with = "humantime_serde", default = "default_fill_window")]
    pub window: Duration,
    /// History is thinned to at most one sample per this interval.
    #[serde(with = "humantime_serde", default = "default_sample_every")]
    pub sample_every: Duration,
}

fn default_min_history() -> Duration {
    d(45 * 60)
}
fn default_min_samples() -> usize {
    4
}
fn default_fill_window() -> Duration {
    d(6 * 3600)
}
fn default_sample_every() -> Duration {
    d(300)
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DiskInodeCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    pub warn_percent: f64,
    pub page_percent: f64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StakeCheckConfig {
    #[serde(flatten)]
    pub base: CheckConfig,
    pub min_percent: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    #[serde(default = "default_delinquent")]
    pub vote_delinquent: CheckConfig,
    #[serde(default = "default_missing")]
    pub vote_account_missing: CheckConfig,
    #[serde(default = "default_vote_lag")]
    pub vote_lag: LagCheckConfig,
    #[serde(default = "default_root_lag")]
    pub root_lag: LagCheckConfig,
    #[serde(default = "default_vote_stalled")]
    pub vote_stalled: CheckConfig,
    #[serde(default = "default_vote_admission")]
    pub vote_admission: VoteAdmissionCheckConfig,
    #[serde(default = "default_identity_balance")]
    pub identity_balance: BalanceCheckConfig,
    #[serde(default = "default_commission")]
    pub commission_changed: CheckConfig,
    /// Whether the validator meets the Solana Foundation Delegation Program's
    /// published minimum version. Two bands: below the floor for the epoch
    /// already running pages; below the floor that takes effect next epoch is
    /// a Telegram note with roughly an epoch left to act.
    #[serde(default = "default_sfdp_version")]
    pub sfdp_version: SfdpCheckConfig,
    #[serde(default = "default_cluster_stake")]
    pub cluster_stake: StakeCheckConfig,
    #[serde(default = "default_cluster_stalled")]
    pub cluster_stalled: CheckConfig,
    #[serde(default = "default_disk_space")]
    pub disk_space: DiskSpaceCheckConfig,
    #[serde(default = "default_disk_fill")]
    pub disk_fill: DiskFillCheckConfig,
    #[serde(default = "default_disk_readonly")]
    pub disk_readonly: CheckConfig,
    #[serde(default = "default_disk_inodes")]
    pub disk_inodes: DiskInodeCheckConfig,
    #[serde(default = "default_node_behind")]
    pub node_behind: LagCheckConfig,
    #[serde(default = "default_skip_rate")]
    pub skip_rate: SkipRateCheckConfig,
    #[serde(default = "default_peer_down")]
    pub peer_down: CheckConfig,
    #[serde(default = "default_machine_down")]
    pub machine_down: CheckConfig,
}

fn default_skip_rate() -> SkipRateCheckConfig {
    SkipRateCheckConfig {
        // Skipping costs revenue but is not an emergency, and a bad patch of
        // network makes it spike briefly. Long hold-down, and only a severe
        // rate pages.
        base: CheckConfig::new(d(20 * 60), Severity::Page),
        warn_percent: 20.0,
        page_percent: 45.0,
        min_leader_slots: default_min_leader_slots(),
    }
}

fn default_node_behind() -> LagCheckConfig {
    LagCheckConfig {
        // A local RPC lagging or restarting is routine and self-correcting; a
        // node genuinely stuck behind will still be stuck in fifteen minutes.
        base: CheckConfig::new(d(15 * 60), Severity::Page),
        max_slots: 300,
    }
}

fn default_peer_down() -> CheckConfig {
    CheckConfig {
        enabled: true,
        // Losing a peer monitor is reduced visibility, not an outage, and a
        // watchtower restart trips it routinely.
        pending_for: d(10 * 60),
        clear_after: 2,
        severity: Severity::Notify,
        renotify_after: d(2 * 3600),
    }
}
fn default_machine_down() -> CheckConfig {
    CheckConfig {
        enabled: true,
        // The peer is silent *and* the cluster says its validator stopped
        // voting. Two independent sources agreeing is what makes this a page.
        pending_for: d(3 * 60),
        clear_after: 2,
        severity: Severity::Page,
        renotify_after: d(30 * 60),
    }
}

fn default_disk_space() -> DiskSpaceCheckConfig {
    DiskSpaceCheckConfig {
        base: CheckConfig::new(d(10 * 60), Severity::Page),
        warn_free_gb: 100.0,
        page_free_gb: 40.0,
        max_floor_percent: default_max_floor_percent(),
    }
}
fn default_disk_fill() -> DiskFillCheckConfig {
    DiskFillCheckConfig {
        base: CheckConfig::new(d(15 * 60), Severity::Page),
        warn_within: d(24 * 3600),
        page_within: d(6 * 3600),
        min_history: default_min_history(),
        min_samples: default_min_samples(),
        window: default_fill_window(),
        sample_every: default_sample_every(),
    }
}
fn default_disk_readonly() -> CheckConfig {
    CheckConfig {
        // A filesystem that has gone read-only is definite and immediate: it is
        // how a disk usually fails under a validator, and nothing recovers on
        // its own.
        enabled: true,
        pending_for: d(0),
        clear_after: 2,
        severity: Severity::Page,
        renotify_after: d(60 * 60),
    }
}
fn default_disk_inodes() -> DiskInodeCheckConfig {
    DiskInodeCheckConfig {
        base: CheckConfig::new(d(15 * 60), Severity::Notify),
        warn_percent: 85.0,
        page_percent: 95.0,
    }
}

// Defaults are deliberately slower than upstream's. Every one of these is a
// condition that, if real, stays true for minutes; none of them need a 60-second
// trigger, and a 60-second trigger is what turns noise into pages.
fn default_delinquent() -> CheckConfig {
    // Strict. Delinquency already requires `min_confirmations` independent
    // endpoints to agree, which is a far stronger filter than any
    // single-endpoint watchtower has -- so the hold-down is not carrying the
    // false-positive load and can be short. At a 60s interval this is two
    // consecutive corroborated observations. Every minute here is lost rewards.
    CheckConfig::new(d(60), Severity::Page)
}
fn default_missing() -> CheckConfig {
    CheckConfig::new(d(10 * 60), Severity::Page)
}
fn default_vote_lag() -> LagCheckConfig {
    LagCheckConfig {
        base: CheckConfig::new(d(3 * 60), Severity::Page),
        max_slots: 200,
    }
}
fn default_root_lag() -> LagCheckConfig {
    LagCheckConfig {
        base: CheckConfig::new(d(5 * 60), Severity::Page),
        max_slots: 400,
    }
}
fn default_vote_stalled() -> CheckConfig {
    CheckConfig::new(d(5 * 60), Severity::Page)
}
fn default_identity_balance() -> BalanceCheckConfig {
    BalanceCheckConfig {
        base: CheckConfig {
            // A draining balance is measured in days, so repeating the same
            // message every 30 minutes says nothing new and trains you to skim
            // past it. Said once when it crosses, and once more only if it
            // falls to the paging band. PagerDuty owns escalation from there;
            // re-sending the same dedup key would only update the incident.
            renotify_after: Duration::ZERO,
            ..CheckConfig::new(d(15 * 60), Severity::Page)
        },
        // The identity pays for every vote transaction, at roughly 2 SOL per
        // epoch. When it empties the validator simply stops voting and goes
        // delinquent, so this is the one balance that is load-bearing.
        warn_sol: 3.0,
        // Roughly a quarter of an epoch of voting left: late enough that it has
        // not paged for a balance that was going to be topped up anyway, early
        // enough to act before it stops voting.
        page_sol: 0.5,
        sol_per_epoch: default_sol_per_epoch(),
    }
}
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SfdpCheckConfig {
    /// `severity` here is the paging band: below the floor for the current
    /// epoch. The warning band is always `notify`.
    #[serde(flatten)]
    pub base: CheckConfig,
    /// How often to re-fetch the schedule. Once per epoch would notice a
    /// mid-epoch announcement up to two days late. Floored at 5m.
    #[serde(with = "humantime_serde", default = "default_sfdp_poll")]
    pub poll_interval: Duration,
    /// Telegram note whenever the published schedule changes, affected or not.
    /// Every box on a cluster sees the same schedule, so enable on one.
    #[serde(default)]
    pub announce_changes: bool,
}

fn default_sfdp_poll() -> Duration {
    d(60 * 60)
}

fn default_sfdp_version() -> SfdpCheckConfig {
    SfdpCheckConfig {
        base: CheckConfig {
            enabled: true,
            // Confirmed by quorum against a published schedule; nothing to wait
            // for, and the epoch boundary has already arrived.
            pending_for: d(0),
            clear_after: 1,
            severity: Severity::Page,
            renotify_after: d(6 * 60 * 60),
        },
        poll_interval: default_sfdp_poll(),
        announce_changes: false,
    }
}

fn default_commission() -> CheckConfig {
    CheckConfig {
        // Confirmed by quorum, so it is safe to fire on the first cycle.
        enabled: true,
        pending_for: d(0),
        clear_after: 1,
        severity: Severity::Page,
        renotify_after: d(60 * 60),
    }
}
fn default_cluster_stake() -> StakeCheckConfig {
    // Off unless asked for: it is the one check that needs the full
    // multi-megabyte vote-account listing every cycle, which is how a free RPC
    // tier gets throttled. The docs have always said to leave it off; the
    // default now agrees with them.
    let mut base = CheckConfig::new(d(10 * 60), Severity::Notify);
    base.enabled = false;
    StakeCheckConfig {
        base,
        min_percent: 80.0,
    }
}
fn default_cluster_stalled() -> CheckConfig {
    CheckConfig::new(d(3 * 60), Severity::Notify)
}

impl Default for Checks {
    fn default() -> Self {
        Self {
            vote_delinquent: default_delinquent(),
            vote_account_missing: default_missing(),
            vote_lag: default_vote_lag(),
            root_lag: default_root_lag(),
            vote_stalled: default_vote_stalled(),
            vote_admission: default_vote_admission(),
            identity_balance: default_identity_balance(),
            commission_changed: default_commission(),
            sfdp_version: default_sfdp_version(),
            cluster_stake: default_cluster_stake(),
            cluster_stalled: default_cluster_stalled(),
            disk_space: default_disk_space(),
            disk_fill: default_disk_fill(),
            disk_readonly: default_disk_readonly(),
            disk_inodes: default_disk_inodes(),
            node_behind: default_node_behind(),
            skip_rate: default_skip_rate(),
            peer_down: default_peer_down(),
            machine_down: default_machine_down(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    #[serde(default)]
    pub pagerduty: Option<PagerDutyConfig>,
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    #[serde(default)]
    pub self_test: SelfTestConfig,
}

/// Periodic proof that the notification path still works.
///
/// On by default, and deliberately so. A revoked routing key, a rotated bot
/// token or a new egress rule leaves every check looking perfectly healthy
/// while nothing can actually be delivered; the failure is invisible until the
/// night it matters. An opt-in guard against that tends to stay opted out, so
/// this one defaults on and is documented rather than left as a switch nobody
/// finds.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SelfTestConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(with = "humantime_serde", default = "default_self_test_interval")]
    pub interval: Duration,
}

impl Default for SelfTestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_self_test_interval(),
        }
    }
}

fn default_self_test_interval() -> Duration {
    Duration::from_secs(7 * 24 * 60 * 60)
}

/// Floor on the self-test interval. The test opens and closes a real PagerDuty
/// incident; a typo of `10s` would turn the safety net into an outage of its
/// own, so the configured value is clamped rather than trusted.
pub const MIN_SELF_TEST_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PagerDutyConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub integration_key: String,
}

/// One chat, or several. Accepts a bare string or a list, so existing configs
/// keep working:
///
/// ```toml
/// chat_id = "123"
/// chat_id = ["123", "-1001234567890"]
/// chat_id = "env:TELEGRAM_CHAT_ID"      # may itself be comma-separated
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ChatIds {
    One(String),
    Many(Vec<String>),
}

impl ChatIds {
    fn raw(&self) -> Vec<String> {
        match self {
            ChatIds::One(s) => vec![s.clone()],
            ChatIds::Many(v) => v.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: ChatIds,
    /// Resolved at load: env references expanded, comma-separated values split,
    /// duplicates dropped.
    #[serde(skip)]
    pub chat_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Silence {
    /// Touch this file before a planned restart and this box's own checks are
    /// suppressed while it exists -- journal only, nothing to PagerDuty or
    /// Telegram. The maintenance lifecycle messages still arrive.
    /// An RFC3339 timestamp inside the file auto-expires the silence.
    #[serde(default)]
    pub file: Option<String>,
    /// Instead of dropping them, downgrade pages to Telegram notes while
    /// silenced, so the timeline shows what happened mid-maintenance. Off by
    /// default: a 🚨 about a box you just took down reads as an alarm.
    #[serde(default)]
    pub notify_while_silenced: bool,
}

/// Resolve `env:VAR` indirection for secrets.
/// Resolve a secret, or explain why it is unusable.
///
/// Returns `Err` only for a problem the operator must fix; the caller decides
/// whether that is fatal. A watchtower must never refuse to start because a
/// notification channel is misconfigured -- one that will not boot monitors
/// nothing, which is strictly worse than one that cannot page.
fn resolve_secret(field: &str, raw: &str) -> Result<String> {
    let value = match raw.strip_prefix("env:") {
        Some(var) => std::env::var(var)
            .with_context(|| format!("{field} references ${var}, which is not set"))?,
        None => raw.to_string(),
    };
    // `KEY=` in an env file sets the variable to empty rather than leaving it
    // unset, so this is the common case, not the exotic one.
    if value.trim().is_empty() {
        match raw.strip_prefix("env:") {
            Some(var) => anyhow::bail!("{field} references ${var}, which is set but empty"),
            None => anyhow::bail!("{field} is empty"),
        }
    }
    Ok(value)
}

impl Config {
    /// How long a check may sit inconclusive before it is reported as unable to
    /// evaluate.
    ///
    /// Deliberately far longer than the blindness page threshold it used to
    /// borrow. A starved check is an FYI, not an incident -- and reusing a
    /// 30-minute threshold put it in direct collision with `disk_fill`, which is
    /// inconclusive by design for its first 45 minutes.
    pub fn starvation_after(&self) -> Duration {
        let warmup = self.checks.disk_fill.min_history;
        // Never fire before the slowest legitimate warm-up has had room to
        // finish, whatever it is configured to.
        (warmup.saturating_mul(2)).max(Duration::from_secs(2 * 3600))
    }

    /// Parse and validate configuration from a TOML string.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(raw).context("parsing config")?;
        cfg.resolve_and_validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing config {}", path.display()))?;
        cfg.resolve_and_validate()?;
        Ok(cfg)
    }

    fn resolve_and_validate(&mut self) -> Result<()> {
        // A spoke that only reports local state and never notifies has no use
        // for RPC endpoints; requiring them would mean carrying dead config to
        // every validator.
        let data_source_only = self.peering.role == Role::Local
            && matches!(self.peering.alerting, Alerting::Never | Alerting::Peers);

        // An `always` instance reports about its own validators, which it can
        // only judge with cluster data.
        if self.peering.alerting == Alerting::Always
            && !self.validators.is_empty()
            && self.endpoints.is_empty()
        {
            bail!(
                "peering.alerting is \"always\" with [[validators]] configured, but no \
                 [[endpoints]]; this instance owns alerting for its validators and needs RPC \
                 endpoints to judge them"
            );
        }

        if self.endpoints.is_empty() && !data_source_only {
            bail!(
                "at least one [[endpoints]] entry is required (or set peering.role = \"local\" \
                 with peering.alerting = \"never\" for a pure data-source instance)"
            );
        }
        if self.peering.alerting == Alerting::Peers && self.peers.is_empty() {
            bail!(
                "peering.alerting is \"peers\" but no [[peers]] are configured, so this \
                 instance could never report anything"
            );
        }
        if data_source_only && self.hosts.is_empty() && self.peers.is_empty() {
            bail!(
                "this instance neither alerts, scrapes any [[hosts]], nor watches any \
                 [[peers]], so it would do nothing"
            );
        }
        match self.watchtower.cluster.as_deref() {
            Some(c) => {
                resolve_cluster(c)?;
            }
            None => tracing::warn!(
                "watchtower.cluster is not set: a config pointed at the wrong cluster will be \
                 caught as a missing vote account at alert time rather than at startup"
            ),
        }
        if self.validators.is_empty() {
            bail!("at least one [[validators]] entry is required");
        }

        let mut seen = HashMap::new();
        for e in &self.endpoints {
            if let Some(prev) = seen.insert(e.name.clone(), e.url.clone()) {
                bail!("duplicate endpoint name {:?} (urls {} and {})", e.name, prev, e.url);
            }
            if !e.url.starts_with("http://") && !e.url.starts_with("https://") {
                bail!("endpoint {:?} url must be http(s): {}", e.name, e.url);
            }
        }

        // Quorum settings that cannot be satisfied would silently disable all
        // alerting, which is a far worse failure than a noisy page. Refuse to start.
        let n = self.endpoints.len();
        if n > 0 && (self.quorum.min_definite == 0 || self.quorum.min_confirmations == 0) {
            bail!("quorum.min_definite and quorum.min_confirmations must be >= 1");
        }
        if self.quorum.max_endpoint_lag_slots == 0 {
            bail!(
                "quorum.max_endpoint_lag_slots must be >= 1; zero would mark every endpoint but \
                 the single most advanced one as stale"
            );
        }
        if n > 0 && self.quorum.min_definite > n {
            bail!(
                "quorum.min_definite is {} but only {n} endpoint(s) are configured; no cycle \
                 could ever count as visible",
                self.quorum.min_definite
            );
        }
        if n > 0 && self.quorum.min_confirmations > n {
            bail!(
                "quorum.min_confirmations is {} but only {n} endpoint(s) are configured; no \
                 check could ever fire",
                self.quorum.min_confirmations
            );
        }
        if n == 1 {
            tracing::warn!(
                "only one endpoint configured: a single flaky provider cannot be \
                 cross-checked. Three independent providers is the recommended minimum."
            );
        }

        if self.blindness.page_after <= self.blindness.notify_after {
            bail!("blindness.page_after must be greater than blindness.notify_after");
        }

        for v in &self.validators {
            if v.identity.len() < 32 || v.identity.len() > 44 {
                bail!("validator identity {:?} does not look like a base58 pubkey", v.identity);
            }
            if let Some(c) = v.expected_commission {
                if c > 100 {
                    bail!("expected_commission for {} must be 0-100", v.display());
                }
            }
            if v.expected_commission.is_some() && v.expected_commission_bps.is_some() {
                bail!(
                    "{} sets both expected_commission and expected_commission_bps; keep one",
                    v.display()
                );
            }
            for (name, bps) in [
                ("expected_commission_bps", v.expected_commission_bps),
                ("expected_block_revenue_commission_bps", v.expected_block_revenue_commission_bps),
            ] {
                if bps.is_some_and(|b| b > 10_000) {
                    bail!("{name} for {} must be 0-10000", v.display());
                }
            }
        }

        let b = &self.checks.identity_balance;
        if b.page_sol > b.warn_sol {
            bail!("checks.identity_balance.page_sol must be <= warn_sol");
        }

        let mut host_names = HashMap::new();
        for h in &self.hosts {
            if let Some(prev) = host_names.insert(h.name.clone(), h.url.clone()) {
                bail!("duplicate host name {:?} (urls {} and {})", h.name, prev, h.url);
            }
            if !h.url.starts_with("http://") && !h.url.starts_with("https://") {
                bail!("host {:?} url must be http(s): {}", h.name, h.url);
            }
            if let Some(v) = &h.validator {
                if !self.validators.iter().any(|x| x.display() == v) {
                    bail!(
                        "host {:?} is linked to validator {v:?}, which is not a configured \
                         validator label",
                        h.name
                    );
                }
            }
        }

        if let Some(v) = &self.diagnose.validator {
            if !self.validators.iter().any(|x| x.display() == v) {
                bail!("diagnose.validator {v:?} is not a configured validator label");
            }
        }

        let mut peer_names = HashMap::new();
        for p in &self.peers {
            if let Some(prev) = peer_names.insert(p.name.clone(), p.url.clone()) {
                bail!("duplicate peer name {:?} (urls {} and {})", p.name, prev, p.url);
            }
            if !p.url.starts_with("http://") && !p.url.starts_with("https://") {
                bail!("peer {:?} url must be http(s): {}", p.name, p.url);
            }
            if p.priority == self.peering.priority {
                bail!(
                    "peer {:?} has priority {}, the same as this instance; priorities must be \
                     unique or two instances will both believe they own alerting",
                    p.name,
                    p.priority
                );
            }
        }
        if let Some(name) = &self.peering.name {
            if self.peers.iter().any(|p| &p.name == name) {
                bail!("peering.name {name:?} also appears in [[peers]]; an instance must not \
                       be its own peer");
            }
        }
        if self.peering.role == Role::Local
            && self.peers.iter().all(|p| p.priority > self.peering.priority)
            && !self.peers.is_empty()
        {
            tracing::warn!(
                "role is \"local\" but no peer outranks this instance, so it owns alerting from \
                 the start and will run cluster checks anyway"
            );
        }
        // Only an `auto` instance can be promoted into running cluster checks,
        // so only it needs endpoints.
        if self.peering.role == Role::Local
            && self.peering.alerting == Alerting::Auto
            && self.endpoints.is_empty()
        {
            bail!(
                "role is \"local\" with alerting \"auto\" but no [[endpoints]] are configured; \
                 a promoted standby needs them to run cluster checks. Set \
                 peering.alerting = \"never\" if this instance should never notify."
            );
        }
        if self.peering.alerting == Alerting::Auto && !self.peers.is_empty() {
            tracing::warn!(
                "peering.alerting = \"auto\" arbitrates by priority, which only works when every \
                 instance can see every other. If your instances watch disjoint scopes (one \
                 validator each), use \"always\" instead -- there is nothing to arbitrate."
            );
        }

        if self.checks.node_behind.base.enabled
            && !self.endpoints.iter().any(|e| e.monitor)
            && self.endpoints.iter().count() > 0
        {
            tracing::debug!(
                "checks.node_behind is enabled but no endpoint sets monitor = true, so it \
                 will not run"
            );
        }

        let sr = &self.checks.skip_rate;
        if sr.page_percent < sr.warn_percent {
            bail!("checks.skip_rate.page_percent must be >= warn_percent");
        }
        if sr.min_leader_slots < 4 {
            bail!(
                "checks.skip_rate.min_leader_slots must be >= 4; leader slots are assigned in \
                 groups of four and a smaller sample is noise"
            );
        }

        let ds = &self.checks.disk_space;
        if ds.page_free_gb > ds.warn_free_gb {
            bail!("checks.disk_space.page_free_gb must be <= warn_free_gb");
        }
        if !(0.0..=100.0).contains(&ds.max_floor_percent) {
            bail!("checks.disk_space.max_floor_percent must be between 0 and 100");
        }
        let df = &self.checks.disk_fill;
        if df.page_within > df.warn_within {
            bail!("checks.disk_fill.page_within must be <= warn_within");
        }
        if df.window <= df.min_history {
            bail!("checks.disk_fill.window must be greater than min_history");
        }
        if df.min_samples < 2 {
            bail!("checks.disk_fill.min_samples must be >= 2 to fit a slope");
        }
        let di = &self.checks.disk_inodes;
        if di.page_percent < di.warn_percent {
            bail!("checks.disk_inodes.page_percent must be >= warn_percent");
        }
        if self.hosts.is_empty()
            && (ds.base.enabled || df.base.enabled || self.checks.disk_readonly.enabled)
        {
            tracing::info!(
                "disk checks are enabled but no [[hosts]] are configured, so they will not run"
            );
        }

        // A channel whose secret is missing or empty is switched off and
        // reported loudly, rather than taken as a reason to stop monitoring.
        // `--check-config` still exits non-zero (see `secret_problems`), so the
        // mistake is caught when you are actually looking for it.
        if let Some(pd) = self.notify.pagerduty.as_mut() {
            if pd.enabled {
                match resolve_secret("notify.pagerduty.integration_key", &pd.integration_key) {
                    Ok(v) => pd.integration_key = v,
                    Err(e) => {
                        tracing::error!("PagerDuty disabled: {e:#}");
                        self.secret_problems.push(format!("{e:#}"));
                        pd.enabled = false;
                    }
                }
            }
        }
        if let Some(tg) = self.notify.telegram.as_mut() {
            if tg.enabled {
                let token = resolve_secret("notify.telegram.bot_token", &tg.bot_token);

                // Each entry may be an env reference, and each resolved value
                // may itself list several ids separated by commas -- an env file
                // cannot hold a TOML array, so this is how you configure more
                // than one chat without hardcoding it in the config.
                let mut ids: Vec<String> = Vec::new();
                let mut chat_err: Option<anyhow::Error> = None;
                for (i, raw) in tg.chat_id.raw().iter().enumerate() {
                    match resolve_secret(&format!("notify.telegram.chat_id[{i}]"), raw) {
                        Ok(v) => {
                            for part in v.split(',') {
                                let part = part.trim();
                                if !part.is_empty() && !ids.contains(&part.to_string()) {
                                    ids.push(part.to_string());
                                }
                            }
                        }
                        Err(e) => chat_err = Some(e),
                    }
                }
                if chat_err.is_none() && ids.is_empty() {
                    chat_err = Some(anyhow::anyhow!("notify.telegram.chat_id resolved to no ids"));
                }

                match (token, chat_err) {
                    (Ok(t), None) => {
                        tg.bot_token = t;
                        tg.chat_ids = ids;
                    }
                    (t, c) => {
                        for e in [t.err(), c].into_iter().flatten() {
                            tracing::error!("Telegram disabled: {e:#}");
                            self.secret_problems.push(format!("{e:#}"));
                        }
                        tg.enabled = false;
                    }
                }
            }
        }

        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<()> {
        if let Some(hb) = self.heartbeat.as_mut().filter(|h| h.enabled) {
            // A literal URL with no scheme is a typo in this file: refuse it.
            if !hb.url.starts_with("env:") && !hb.url.starts_with("http") {
                bail!("heartbeat.url must be an http(s) URL");
            }
            // An unset or empty secret is the same situation as a missing
            // PagerDuty key, and gets the same treatment: switch it off, say
            // so, and keep monitoring. Refusing to start over it would trade a
            // missing dead-man's switch for a dead watchtower.
            let url = resolve_secret("heartbeat.url", &hb.url).and_then(|u| {
                if u.starts_with("http") {
                    Ok(u)
                } else {
                    Err(anyhow::anyhow!("heartbeat.url must be an http(s) URL"))
                }
            });
            let fail_url = hb
                .fail_url
                .as_ref()
                .map(|f| resolve_secret("heartbeat.fail_url", f))
                .transpose();
            match (url, fail_url) {
                (Ok(u), Ok(f)) => {
                    hb.url = u;
                    hb.fail_url = f;
                }
                (u, f) => {
                    for e in [u.err(), f.err()].into_iter().flatten() {
                        tracing::error!("Heartbeat disabled: {e:#}");
                        self.secret_problems.push(format!("{e:#}"));
                    }
                    hb.enabled = false;
                }
            }
        } else if self.heartbeat.is_none() {
            tracing::warn!(
                "no heartbeat configured: if perch dies you will get silence, which \
                 looks exactly like everything being fine"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[[endpoints]]
name = "a"
url = "https://a.example/rpc"
[[endpoints]]
name = "b"
url = "https://b.example/rpc"
[[validators]]
identity = "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv"
"#;

    #[test]
    fn always_mode_reports_its_whole_scope_without_deferring() {
        let a = Alerting::Always;
        assert!(a.may_report("vote_delinquent:chimps-1"));
        assert!(a.may_report("disk_space_critical:chimps-1-box /mnt/ledger"));
        assert!(a.may_report("peer_down:failover-box"));
    }

    #[test]
    fn always_mode_with_validators_requires_endpoints() {
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nalerting=\"always\"\npriority=2\n\
                   [[peers]]\nname=\"hub\"\nurl=\"http://10.0.0.9:9469/metrics\"\npriority=1\n";
        let err = Config::parse(src).unwrap_err().to_string();
        assert!(err.contains("needs RPC endpoints"), "got: {err}");
    }

    #[test]
    fn a_peers_mode_spoke_reports_only_peer_checks() {
        let a = Alerting::Peers;
        assert!(a.may_report("peer_down:failover-box"));
        assert!(a.may_report("machine_down:failover-box"));
        // The hub owns these; a spoke reporting them would duplicate it N times.
        assert!(!a.may_report("vote_delinquent:chimps-1"));
        assert!(!a.may_report("disk_space_critical:chimps-1-box /mnt/ledger"));
        assert!(!a.may_report("cluster_stalled"));
    }

    #[test]
    fn auto_reports_everything_and_never_reports_nothing() {
        for id in ["peer_down:hub", "vote_delinquent:chimps-1", "cluster_stalled"] {
            assert!(Alerting::Auto.may_report(id));
            assert!(!Alerting::Never.may_report(id));
        }
    }

    #[test]
    fn peers_mode_without_peers_is_rejected() {
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nrole=\"local\"\nalerting=\"peers\"\npriority=2\n\
                   [[hosts]]\nname=\"self\"\nurl=\"http://127.0.0.1:9100/metrics\"\n";
        let err = Config::parse(src).unwrap_err().to_string();
        assert!(err.contains("could never report anything"), "got: {err}");
    }

    #[test]
    fn a_peers_mode_spoke_needs_no_endpoints() {
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nrole=\"local\"\nalerting=\"peers\"\npriority=2\n\
                   [[peers]]\nname=\"hub\"\nurl=\"http://10.0.0.9:9469/metrics\"\npriority=1\n";
        let c = Config::parse(src).unwrap();
        assert!(c.endpoints.is_empty());
        assert_eq!(c.peering.alerting, Alerting::Peers);
    }

    #[test]
    fn a_data_source_spoke_needs_no_endpoints_at_all() {
        // In a hub-and-spoke layout the validator boxes only report local state.
        // Requiring RPC endpoints would mean shipping dead config to every one.
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nrole=\"local\"\nalerting=\"never\"\npriority=2\n\
                   [[hosts]]\nname=\"self\"\nurl=\"http://127.0.0.1:9100/metrics\"\n";
        let c = Config::parse(src).unwrap();
        assert_eq!(c.peering.alerting, Alerting::Never);
        assert!(c.endpoints.is_empty());
    }

    #[test]
    fn a_data_source_that_would_do_nothing_is_rejected() {
        // No endpoints, no hosts, no peers, never alerts: a process that would
        // start cleanly and accomplish nothing is worse than a startup error.
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nrole=\"local\"\nalerting=\"never\"\npriority=2\n";
        let err = Config::parse(src).unwrap_err().to_string();
        assert!(err.contains("would do nothing"), "got: {err}");
    }

    #[test]
    fn an_alerting_instance_still_requires_endpoints() {
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [[hosts]]\nname=\"self\"\nurl=\"http://127.0.0.1:9100/metrics\"\n";
        assert!(Config::parse(src).is_err());
    }

    #[test]
    fn alerting_defaults_to_always() {
        // Adding a peer must not silently stop an instance from alerting.
        assert_eq!(
            Config::parse(MINIMAL).unwrap().peering.alerting,
            Alerting::Always
        );
    }

    #[test]
    fn peering_defaults_to_a_sole_full_instance() {
        let c = Config::parse(MINIMAL).unwrap();
        assert!(c.peers.is_empty());
        assert_eq!(c.peering.priority, 1);
        assert_eq!(c.peering.role, Role::Full);
        // Silence alone notifies; only corroborated silence pages.
        assert_eq!(c.checks.peer_down.severity, Severity::Notify);
        assert_eq!(c.checks.machine_down.severity, Severity::Page);
    }

    #[test]
    fn rejects_a_peer_sharing_this_instances_priority() {
        // Equal priorities would leave two instances each believing they own
        // alerting, permanently.
        let src = format!(
            "{MINIMAL}\n[peering]\npriority = 1\n\
             [[peers]]\nname=\"other\"\nurl=\"http://10.0.0.9:9469/metrics\"\npriority=1\n"
        );
        let err = Config::parse(&src).unwrap_err().to_string();
        assert!(err.contains("priorities must be unique"), "got: {err}");
    }

    #[test]
    fn rejects_an_instance_listing_itself_as_a_peer() {
        let src = format!(
            "{MINIMAL}\n[peering]\nname=\"box-a\"\npriority=1\n\
             [[peers]]\nname=\"box-a\"\nurl=\"http://10.0.0.9:9469/metrics\"\npriority=2\n"
        );
        assert!(Config::parse(&src).unwrap_err().to_string().contains("its own peer"));
    }

    #[test]
    fn rejects_duplicate_peer_names() {
        let src = format!(
            "{MINIMAL}\n[[peers]]\nname=\"p\"\nurl=\"http://a:9469/metrics\"\npriority=2\n\
             [[peers]]\nname=\"p\"\nurl=\"http://b:9469/metrics\"\npriority=3\n"
        );
        assert!(Config::parse(&src).unwrap_err().to_string().contains("duplicate peer"));
    }

    #[test]
    fn a_local_role_still_requires_endpoints_for_escalation() {
        let src = "[[validators]]\nidentity = \"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n\
                   [peering]\nrole = \"local\"\npriority = 2\n";
        // No endpoints at all -- caught earlier, but the message should still
        // make sense for a local instance.
        assert!(Config::parse(src).is_err());
    }

    #[test]
    fn accepts_a_local_standby_with_a_higher_priority_peer() {
        let src = format!(
            "{MINIMAL}\n[peering]\nname=\"chimps-1-box\"\npriority=2\nrole=\"local\"\n\
             [[peers]]\nname=\"failover\"\nurl=\"http://10.0.0.9:9469/metrics\"\n\
             priority=1\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.peering.role, Role::Local);
        assert_eq!(c.peers.len(), 1);
    }

    #[test]
    fn disk_defaults_are_sane() {
        let c = Config::parse(MINIMAL).unwrap();
        assert!(c.hosts.is_empty());
        assert_eq!(c.checks.disk_space.page_free_gb, 40.0);
        assert_eq!(c.checks.disk_fill.page_within, d(6 * 3600));
        // A read-only filesystem is definite; no hold-down.
        assert_eq!(c.checks.disk_readonly.pending_for, d(0));
    }

    #[test]
    fn starvation_never_fires_before_a_legitimate_warmup_completes() {
        // The collision this fixes: disk_fill is inconclusive for 45 minutes by
        // design, and starvation used to fire at 30.
        let c = Config::parse(MINIMAL).unwrap();
        assert!(
            c.starvation_after() > c.checks.disk_fill.min_history,
            "starvation at {:?} would trip during a {:?} warm-up",
            c.starvation_after(),
            c.checks.disk_fill.min_history
        );
        assert!(c.starvation_after() >= d(2 * 3600));
    }

    #[test]
    fn a_long_configured_warmup_pushes_starvation_out_further() {
        let src = format!(
            "{MINIMAL}\n[checks.disk_fill]\npending_for=\"15m\"\nseverity=\"page\"\n\
             warn_within=\"24h\"\npage_within=\"6h\"\nmin_history=\"6h\"\nwindow=\"12h\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert!(c.starvation_after() >= d(12 * 3600));
    }

    #[test]
    fn a_small_partition_does_not_inherit_a_huge_absolute_floor() {
        // The false positive this fixes: /boot is ~1 GB, can never have 40 GB
        // free, and alerted permanently.
        let c = Config::parse(MINIMAL).unwrap();
        let ds = &c.checks.disk_space;
        // 4 TB ledger: the absolute floor governs.
        assert_eq!(ds.effective_floor(40.0, 4000.0), 40.0);
        // ~1 GB /boot: 25% of it, i.e. ~0.24 GB.
        let boot = ds.effective_floor(40.0, 0.965);
        assert!((boot - 0.241).abs() < 0.01, "got {boot}");
        // 720 MB free on that /boot is comfortably above the floor.
        assert!(0.72 > boot);
    }

    #[test]
    fn the_cap_scales_with_the_filesystem() {
        let c = Config::parse(MINIMAL).unwrap();
        let ds = &c.checks.disk_space;
        for (size, expect_absolute) in [(4000.0, true), (500.0, true), (100.0, false), (1.0, false)] {
            let f = ds.effective_floor(40.0, size);
            if expect_absolute {
                assert_eq!(f, 40.0, "size {size} should use the absolute floor");
            } else {
                assert!(f < 40.0, "size {size} should be capped, got {f}");
            }
        }
    }

    #[test]
    fn rejects_an_out_of_range_floor_cap() {
        let src = format!(
            "{MINIMAL}\n[checks.disk_space]\npending_for=\"10m\"\nseverity=\"page\"\n\
             warn_free_gb=100.0\npage_free_gb=40.0\nmax_floor_percent=150.0\n"
        );
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn rejects_inverted_disk_thresholds() {
        for bad in [
            "[checks.disk_space]\npending_for=\"10m\"\nseverity=\"page\"\n\
             warn_free_gb=40.0\npage_free_gb=100.0\n",
            "[checks.disk_fill]\npending_for=\"15m\"\nseverity=\"page\"\n\
             warn_within=\"6h\"\npage_within=\"24h\"\n",
            "[checks.disk_inodes]\npending_for=\"15m\"\nseverity=\"notify\"\n\
             warn_percent=95.0\npage_percent=85.0\n",
        ] {
            let src = format!("{MINIMAL}\n{bad}");
            assert!(Config::parse(&src).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn rejects_a_fill_window_shorter_than_its_minimum_history() {
        let src = format!(
            "{MINIMAL}\n[checks.disk_fill]\npending_for=\"15m\"\nseverity=\"page\"\n\
             warn_within=\"24h\"\npage_within=\"6h\"\nmin_history=\"6h\"\nwindow=\"1h\"\n"
        );
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn rejects_a_host_linked_to_an_unknown_validator() {
        // Catches a typo that would silently disable disk-to-delinquency
        // inhibition rather than failing loudly.
        let src = format!(
            "{MINIMAL}\n[[hosts]]\nname=\"h1\"\nurl=\"http://10.0.0.5:9100/metrics\"\n\
             validator=\"typo-label\"\n"
        );
        let err = Config::parse(&src).unwrap_err().to_string();
        assert!(err.contains("not a configured validator label"), "got: {err}");
    }

    #[test]
    fn accepts_a_host_linked_to_a_real_validator() {
        let src = format!(
            "{MINIMAL}\n[[hosts]]\nname=\"h1\"\nurl=\"http://10.0.0.5:9100/metrics\"\n\
             validator=\"GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv\"\n"
        );
        assert_eq!(Config::parse(&src).unwrap().hosts.len(), 1);
    }

    #[test]
    fn rejects_duplicate_host_names() {
        let src = format!(
            "{MINIMAL}\n[[hosts]]\nname=\"h\"\nurl=\"http://a:9100/metrics\"\n\
             [[hosts]]\nname=\"h\"\nurl=\"http://b:9100/metrics\"\n"
        );
        assert!(Config::parse(&src).unwrap_err().to_string().contains("duplicate host"));
    }

    #[test]
    fn sfdp_cluster_from_name_or_hash() {
        let w = |c: &str| Watchtower { cluster: Some(c.into()), ..Default::default() };
        assert_eq!(w("mainnet-beta").sfdp_cluster(), Some("mainnet-beta"));
        assert_eq!(w("TESTNET").sfdp_cluster(), Some("testnet"));
        assert_eq!(w("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY").sfdp_cluster(), Some("testnet"));
        assert_eq!(w("devnet").sfdp_cluster(), None, "no delegation program on devnet");
        assert_eq!(Watchtower::default().sfdp_cluster(), None, "unpinned: no opinion");
    }

    #[test]
    fn cluster_names_resolve_to_genesis_hashes() {
        assert_eq!(
            resolve_cluster("mainnet-beta").unwrap(),
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
        );
        // Verified live against api.testnet.solana.com and api.devnet.solana.com.
        assert_eq!(
            resolve_cluster("testnet").unwrap(),
            "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
        );
        assert_eq!(
            resolve_cluster("devnet").unwrap(),
            "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
        );
    }

    #[test]
    fn cluster_names_are_case_insensitive() {
        assert_eq!(
            resolve_cluster("Testnet").unwrap(),
            resolve_cluster("testnet").unwrap()
        );
    }

    #[test]
    fn a_raw_genesis_hash_passes_through_for_private_clusters() {
        let hash = "9tDrPRPUrLmFdvCjyVjoYCxwZaLYFJRcNpBzRoJFH1tE";
        assert_eq!(resolve_cluster(hash).unwrap(), hash);
    }

    #[test]
    fn a_typo_in_the_cluster_name_is_rejected_at_startup() {
        assert!(resolve_cluster("mainet").is_err());
        let src = format!("{MINIMAL}\n[watchtower]\ncluster = \"mainet\"\n");
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn a_pinned_cluster_exposes_its_expected_hash() {
        let src = format!("{MINIMAL}\n[watchtower]\ncluster = \"testnet\"\n");
        let c = Config::parse(&src).unwrap();
        assert_eq!(
            c.watchtower.expected_genesis_hash().unwrap(),
            "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
        );
    }

    #[test]
    fn an_unpinned_cluster_is_allowed() {
        let c = Config::parse(MINIMAL).unwrap();
        assert!(c.watchtower.expected_genesis_hash().is_none());
    }

    /// A `peers` hub shows only peer checks as its own; every other mode
    /// owns everything it evaluates.
    #[test]
    fn only_a_peers_hub_disowns_validator_checks() {
        assert!(!Alerting::Peers.owns_check("identity_balance_warn:mind-main"));
        assert!(Alerting::Peers.owns_check("peer_down:mind-main"));
        assert!(Alerting::Peers.owns_check("machine_down:mind-main"));
        for mode in [Alerting::Always, Alerting::Auto, Alerting::Never] {
            assert!(mode.owns_check("identity_balance_warn:mind-main"));
        }
    }

    #[test]
    fn heartbeat_url_supports_env_indirection() {
        std::env::set_var("PERCH_TEST_HB", "https://hc-ping.com/abc");
        let src = format!("{MINIMAL}\n[heartbeat]\nurl = \"env:PERCH_TEST_HB\"\n");
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.heartbeat.unwrap().url, "https://hc-ping.com/abc");
    }

    /// The env file an installer writes has the variable present and empty.
    /// That must start, with the heartbeat off and the problem recorded for
    /// --check-config, rather than refuse to boot.
    #[test]
    fn an_empty_heartbeat_secret_disables_it_instead_of_stopping_startup() {
        std::env::set_var("PERCH_TEST_HB_EMPTY", "");
        let src = format!("{MINIMAL}\n[heartbeat]\nurl = \"env:PERCH_TEST_HB_EMPTY\"\n");
        let c = Config::parse(&src).unwrap();
        assert!(!c.heartbeat.unwrap().enabled);
        assert_eq!(c.secret_problems.len(), 1, "{:?}", c.secret_problems);
    }

    #[test]
    fn heartbeat_requires_a_url_scheme() {
        let src = format!("{MINIMAL}\n[heartbeat]\nurl = \"hc-ping.com/abc\"\n");
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn state_and_context_have_working_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert!(c.state.file.ends_with("state.json"));
        assert!(c.context.enabled);
        assert_eq!(c.context.cache_for, d(300));
    }

    #[test]
    fn validator_health_is_strict_and_rpc_trouble_is_lenient() {
        // The asymmetry that matters: what the validator is doing should page
        // fast, what the monitoring path is doing should stay quiet.
        let c = Config::parse(MINIMAL).unwrap();
        let delinquent = c.checks.vote_delinquent.pending_for;
        assert_eq!(delinquent, d(60), "delinquency must be strict");

        for (name, slower) in [
            ("blindness.notify_after", c.blindness.notify_after),
            ("blindness.page_after", c.blindness.page_after),
            ("node_behind", c.checks.node_behind.base.pending_for),
            ("peer_down", c.checks.peer_down.pending_for),
        ] {
            assert!(
                slower > delinquent * 5,
                "{name} ({slower:?}) should be far more patient than delinquency"
            );
        }
    }

    #[test]
    fn minimal_config_uses_conservative_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.quorum.min_confirmations, 2);
        assert_eq!(c.checks.vote_delinquent.pending_for, d(60));
        assert_eq!(c.watchtower.interval, d(60));
    }

    #[test]
    fn rejects_unsatisfiable_confirmation_quorum() {
        let src = format!("{MINIMAL}\n[quorum]\nmin_confirmations = 5\n");
        let err = Config::parse(&src).unwrap_err().to_string();
        assert!(err.contains("could ever fire"), "got: {err}");
    }

    #[test]
    fn rejects_unsatisfiable_definite_quorum() {
        let src = format!("{MINIMAL}\n[quorum]\nmin_definite = 9\n");
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn rejects_duplicate_endpoint_names() {
        let src = r#"
[[endpoints]]
name = "a"
url = "https://a.example/rpc"
[[endpoints]]
name = "a"
url = "https://b.example/rpc"
[[validators]]
identity = "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv"
"#;
        assert!(Config::parse(src).unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_blind_page_before_blind_notify() {
        let src = format!("{MINIMAL}\n[blindness]\nnotify_after = \"20m\"\npage_after = \"5m\"\n");
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn identity_balance_pages_at_one_sol_of_runway() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.checks.identity_balance.page_sol, 0.5);
        assert_eq!(c.checks.identity_balance.warn_sol, 3.0);
    }

    #[test]
    fn rejects_inverted_balance_thresholds() {
        let src = format!(
            "{MINIMAL}\n[checks.identity_balance]\npending_for = \"15m\"\nseverity = \"page\"\n\
             warn_sol = 0.5\npage_sol = 2.0\n"
        );
        assert!(Config::parse(&src).is_err());
    }

    #[test]
    fn resolves_env_indirection_for_secrets() {
        std::env::set_var("PERCH_TEST_PD_KEY", "secret-value");
        let src = format!(
            "{MINIMAL}\n[notify.pagerduty]\nintegration_key = \"env:PERCH_TEST_PD_KEY\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.notify.pagerduty.unwrap().integration_key, "secret-value");
    }

    #[test]
    fn an_empty_secret_disables_the_channel_but_still_starts() {
        // The regression this pins: an unfilled secret used to abort startup,
        // so adding a [notify] block before pasting the key took the whole
        // watchtower down. Monitoring must survive a broken notifier.
        std::env::set_var("PERCH_TEST_EMPTY", "");
        let src = format!(
            "{MINIMAL}\n[notify.pagerduty]\nintegration_key = \"env:PERCH_TEST_EMPTY\"\n"
        );
        let c = Config::parse(&src).expect("must still load");
        assert!(!c.notify.pagerduty.unwrap().enabled, "channel should be off");
        assert_eq!(c.secret_problems.len(), 1);
        assert!(c.secret_problems[0].contains("set but empty"));
    }

    #[test]
    fn a_single_chat_id_still_works() {
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"t\"\nchat_id = \"123\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.notify.telegram.unwrap().chat_ids, vec!["123"]);
    }

    #[test]
    fn a_list_of_chat_ids_is_accepted() {
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"t\"\n\
             chat_id = [\"123\", \"-1001234567890\"]\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(
            c.notify.telegram.unwrap().chat_ids,
            vec!["123", "-1001234567890"]
        );
    }

    #[test]
    fn a_comma_separated_env_value_expands_to_several_ids() {
        // An env file cannot hold a TOML array, so this is how you add a second
        // chat without moving the id into the config file.
        std::env::set_var("PERCH_TEST_CHATS", "123, -456 ,789");
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"t\"\n\
             chat_id = \"env:PERCH_TEST_CHATS\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.notify.telegram.unwrap().chat_ids, vec!["123", "-456", "789"]);
    }

    #[test]
    fn duplicate_chat_ids_are_dropped() {
        // Otherwise the same person is messaged twice for one alert.
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"t\"\n\
             chat_id = [\"123\", \"123\", \"456\"]\n"
        );
        let c = Config::parse(&src).unwrap();
        assert_eq!(c.notify.telegram.unwrap().chat_ids, vec!["123", "456"]);
    }

    #[test]
    fn an_empty_chat_list_disables_the_channel() {
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"t\"\nchat_id = []\n"
        );
        let c = Config::parse(&src).unwrap();
        assert!(!c.notify.telegram.unwrap().enabled);
    }

    #[test]
    fn a_whitespace_only_secret_disables_the_channel() {
        std::env::set_var("PERCH_TEST_BLANK", "   ");
        let src = format!(
            "{MINIMAL}\n[notify.telegram]\nbot_token = \"env:PERCH_TEST_BLANK\"\n\
             chat_id = \"123\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert!(!c.notify.telegram.unwrap().enabled);
        assert!(!c.secret_problems.is_empty());
    }

    #[test]
    fn a_fully_configured_channel_reports_no_problems() {
        std::env::set_var("PERCH_TEST_GOOD", "a-real-looking-key");
        let src = format!(
            "{MINIMAL}\n[notify.pagerduty]\nintegration_key = \"env:PERCH_TEST_GOOD\"\n"
        );
        let c = Config::parse(&src).unwrap();
        assert!(c.notify.pagerduty.unwrap().enabled);
        assert!(c.secret_problems.is_empty());
    }

    #[test]
    fn a_missing_env_secret_disables_the_channel_and_is_recorded() {
        // Same treatment as an empty one: switch the channel off and say so,
        // rather than take the watchtower down with it.
        let src = format!(
            "{MINIMAL}\n[notify.pagerduty]\n\
             integration_key = \"env:PERCH_DEFINITELY_UNSET_VAR\"\n"
        );
        let c = Config::parse(&src).expect("must still load");
        assert!(!c.notify.pagerduty.unwrap().enabled);
        assert_eq!(c.secret_problems.len(), 1);
        assert!(c.secret_problems[0].contains("not set"), "{:?}", c.secret_problems);
    }

    #[test]
    fn rejects_unknown_keys_so_typos_do_not_silently_disable_checks() {
        let src = format!("{MINIMAL}\n[checks.vote_delinquint]\npending_for = \"1m\"\n");
        assert!(Config::parse(&src).is_err());
    }
}

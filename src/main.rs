//! perch -- a Solana validator watchtower that does not wake you up for
//! transient RPC failures.
//!
//! The design rule the whole program follows: evidence about the *validator* and
//! evidence about the *observability path* are different kinds of thing, and only
//! the first kind can ever page you. See `verdict.rs`.

use anyhow::{Context, Result};
use perch::{
    checks, config, diagnose, digest, enrich, heartbeat, inhibit, metrics, node_exporter, notify, peer, persist,
    pools, rpc, selfcheck, sfdp, snapshot, state, status, verdict, web,
};
use clap::{Parser, Subcommand};
use config::{Alerting, Config, Role, Severity};
use metrics::{EndpointHealth, Metrics};
use notify::{Alert, AlertKind, Notifier, SelfTestMode};
use rand::Rng;
use snapshot::Snapshot;
use state::{BlindnessEvent, BlindnessState, CheckState, Transition};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use verdict::Verdict;

#[derive(Subcommand, Debug)]
enum Command {
    /// Send a test through every configured channel.
    ///
    /// By default this is loud: a real PagerDuty incident that resolves itself
    /// a moment later, and a 🚨 on Telegram -- proof the phone actually rings.
    /// With --quiet it is what the weekly schedule does: a PagerDuty change
    /// event (never an incident, never a page) and a Telegram ℹ️.
    TestNotify {
        /// Change event + info message instead of a real incident.
        #[arg(long)]
        quiet: bool,
    },

    /// Print what is true right now and why: per-check verdicts, what is
    /// inhibiting what, how close each check is to firing, and endpoint health.
    ///
    /// Read-only -- runs one probe, writes nothing, and cannot perturb a live
    /// incident.
    Status {
        /// Never emit ANSI colour, even to a terminal.
        #[arg(long)]
        no_color: bool,
    },

    /// Declare planned work so it does not page.
    ///
    ///   perch maint restart [2h]   suppress until the validator is back (deadline 1h)
    ///   perch maint 30m            plain timed silence
    ///   perch maint off            resume paging now
    ///   perch maint                show current state
    Maint {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Parser, Debug)]
#[command(name = "perch", version = perch::BUILD, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    // Optional rather than required so it can be given either before or after a
    // subcommand: a clap `global` argument that is also `required` must be
    // repeated in both positions. Absence is rejected in `main` instead.
    /// Path to the TOML configuration file [default: /etc/perch/config.toml].
    #[arg(short, long, env = "PERCH_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Parse and validate the configuration, then exit without probing.
    #[arg(long)]
    check_config: bool,

    /// Run one cycle and exit. Useful for testing configuration changes.
    #[arg(long)]
    once: bool,

    /// Evaluate everything and log what would be sent, but deliver nothing and
    /// persist nothing.
    #[arg(long)]
    dry_run: bool,

    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,
}

fn build_endpoints(config: &Config) -> Result<Vec<rpc::Endpoint>> {
    config
        .endpoints
        .iter()
        .map(|e| {
            rpc::Endpoint::new(e.name.clone(), e.url.clone(), e.timeout, e.attempts)
                .with_context(|| format!("building client for endpoint {:?}", e.name))
        })
        .collect()
}

fn build_peers(config: &Config) -> Result<Vec<peer::Peer>> {
    config
        .peers
        .iter()
        .map(|p| {
            peer::Peer::new(
                p.name.clone(),
                p.url.clone(),
                p.priority,
                p.validator.clone(),
                config.peering.timeout,
            )
            .with_context(|| format!("building poller for peer {:?}", p.name))
        })
        .collect()
}

fn build_hosts(config: &Config) -> Result<Vec<node_exporter::Host>> {
    config
        .hosts
        .iter()
        .map(|h| {
            node_exporter::Host::new(
                h.name.clone(),
                h.url.clone(),
                h.mountpoints.clone(),
                h.timeout,
                h.attempts,
            )
            .with_context(|| format!("building scraper for host {:?}", h.name))
        })
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // `status` prints a report; routine startup logging would only get in its way.
    // `status` and `maint` send nothing, so unresolved secrets -- normal for an
    // operator who cannot read the env file -- are not worth an ERROR line.
    let default_level = match args.command {
        Some(Command::Status { .. }) | Some(Command::Maint { .. }) => "off",
        Some(_) => "error",
        None => args.log_level.as_str(),
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(default_level).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Where install.sh puts it, so `perch maint restart` and `perch status`
    // work without restating the path every time.
    const DEFAULT_CONFIG: &str = "/etc/perch/config.toml";
    let config_path = args
        .config
        .clone()
        .or_else(|| {
            let p = PathBuf::from(DEFAULT_CONFIG);
            p.exists().then_some(p)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--config <PATH> is required (or set PERCH_CONFIG); {DEFAULT_CONFIG} does not exist"
            )
        })?;
    // Before the full load: that resolves secrets, and the operator declaring
    // maintenance usually cannot read the env file -- nor should they need to.
    if let Some(Command::Maint { args: maint_args }) = &args.command {
        let silence = perch::maint::silence_file_from(&config_path)?;
        return perch::maint::run(silence.as_deref(), maint_args);
    }

    let config = Config::load(&config_path)?;

    if let Some(Command::TestNotify { quiet }) = args.command {
        let notifier = Notifier::new(
            &config.notify,
            format!("perch/{}", config.watchtower.name),
            false,
        )?;
        let source = format!("perch/{}", config.watchtower.name);
        let mode = if quiet { SelfTestMode::Quiet } else { SelfTestMode::Loud };
        match mode {
            SelfTestMode::Loud => println!("Sending a test alert as {source} (a real incident, resolved a moment later) ...\n"),
            SelfTestMode::Quiet => println!("Sending a quiet delivery check as {source} (change event + info message; nothing pages) ...\n"),
        }

        let results = notifier.self_test(&source, mode).await;
        let mut failed = false;
        for r in &results {
            match (r.configured, &r.error) {
                // A channel you asked for that got switched off is a failure,
                // not a neutral "not configured". Reporting it as the latter
                // means the tool you run to check your alerting path tells you
                // everything is fine while a channel you wanted is dead.
                (false, _) if config.secret_problems.iter().any(|p| p.contains(r.channel)) => {
                    failed = true;
                    let why: Vec<&str> = config
                        .secret_problems
                        .iter()
                        .filter(|p| p.contains(r.channel))
                        .map(|s| s.as_str())
                        .collect();
                    println!("  {:<10} DISABLED: {}", r.channel, why.join("; "));
                }
                (false, _) => println!("  {:<10} not configured", r.channel),
                (true, None) => println!("  {:<10} OK", r.channel),
                (true, Some(e)) => {
                    failed = true;
                    println!("  {:<10} FAILED: {e}", r.channel);
                }
            }
        }
        if results.iter().all(|r| !r.configured) {
            anyhow::bail!("no notification channel is configured; nothing would ever reach you");
        }
        if failed {
            anyhow::bail!("at least one channel could not deliver");
        }
        println!("\nCheck that the message actually arrived. A channel can accept a\nrequest and still deliver nowhere -- a muted chat, a suppressed\nPagerDuty service.");
        return Ok(());
    }

    if let Some(Command::Status { no_color }) = args.command {
        let endpoints = build_endpoints(&config)?;
        let hosts = build_hosts(&config)?;
        let peers = build_peers(&config)?;
        return status::run(&config, &endpoints, &hosts, &peers, no_color).await;
    }

    info!(
        "perch {} starting: {} endpoint(s), {} validator(s), {}s interval",
        perch::BUILD,
        config.endpoints.len(),
        config.validators.len(),
        config.watchtower.interval.as_secs()
    );

    // Before anything starts depending on this configuration being what it looks
    // like. Runs on the normal path and under --check-config both, because the
    // whole point is to surface things that produce healthy-looking output.
    selfcheck::report(&config);

    if args.check_config {
        // Runtime keeps going with a broken notifier; `--check-config` is where
        // you have explicitly asked to be told, so it fails.
        if !config.secret_problems.is_empty() {
            for p in &config.secret_problems {
                eprintln!("  {p}");
            }
            anyhow::bail!(
                "{} notification secret(s) unusable; those channels are switched off",
                config.secret_problems.len()
            );
        }
        info!("configuration is valid");
        return Ok(());
    }

    if !config.secret_problems.is_empty() {
        warn!(
            "starting with {} unusable secret(s), so the channels above are switched off; \
             monitoring continues but those channels cannot reach you",
            config.secret_problems.len()
        );
    }

    let endpoints = build_endpoints(&config)?;

    preflight(&endpoints, config.watchtower.expected_genesis_hash().as_deref()).await?;

    let notifier = Notifier::new(
        &config.notify,
        format!("perch/{}", config.watchtower.name),
        args.dry_run,
    )?;

    let heartbeat = match config.heartbeat.as_ref().filter(|h| h.enabled) {
        Some(h) => Some(heartbeat::Heartbeat::new(
            h.url.clone(),
            h.fail_url.clone(),
            h.require_visibility,
        )?),
        None => None,
    };

    let metrics = Metrics::new();
    if let Some(m) = config.metrics.as_ref().filter(|m| m.enabled) {
        metrics
            .serve(&m.listen)
            .await
            .with_context(|| format!("binding metrics listener on {}", m.listen))?;
    }

    let peers = build_peers(&config)?;
    if !peers.is_empty() {
        info!(
            "peering as priority {} ({:?} role), watching {} peer(s)",
            config.peering.priority,
            config.peering.role,
            peers.len()
        );
    }

    let hosts = build_hosts(&config)?;
    if !hosts.is_empty() {
        info!("scraping {} node_exporter host(s) for disk state", hosts.len());
    }

    let state_path = PathBuf::from(&config.state.file);
    let mut progress = checks::Progress::default();
    let mut disk = checks::DiskHistory::default();
    let mut blindness = BlindnessState::default();
    let restored = if args.dry_run {
        info!("dry run: not reading or writing persisted state");
        persist::Restored {
            states: HashMap::new(),
            announced: HashSet::new(),
            peer_maintenance: HashMap::new(),
            downtime: Duration::ZERO,
            last_self_test_unix: 0,
            last_digest_epoch: None,
        }
    } else {
        persist::load(&state_path, &mut progress, &mut disk, &mut blindness)
    };

    let mut runtime = Runtime {
        started_at_unix: unix_now(),
        maintenance_healthy_streak: 0,
        maintenance_window: None,
        maintenance_saw_trouble: false,
        peer_maintenance: restored.peer_maintenance.clone(),
        states: restored.states,
        announced: restored.announced,
        blindness,
        blind_announced: false,
        progress,
        disk,
        known_vote_accounts: HashMap::new(),
        endpoint_health: HashMap::new(),
        last_endpoint_report: Instant::now(),
        ownership: {
            let mut o = peer::Ownership::default();
            // With nobody outranking us there is nothing to wait for.
            if config.peers.iter().all(|p| p.priority > config.peering.priority) {
                o.assume_sole_owner();
            }
            o
        },
        enricher: enrich::Enricher::new(config.context.enabled, config.context.cache_for),
        diagnoser: diagnose::Diagnoser::new(config.diagnose.clone()),
        metrics: metrics.clone(),
        state_path,
        persist: !args.dry_run,
        sfdp: None,
        sfdp_last_fetch: None,
        sfdp_fetcher: match sfdp::Fetcher::new() {
            Ok(f) => Some(f),
            Err(e) => {
                warn!("SFDP version check disabled: could not build HTTP client: {e:#}");
                None
            }
        },
        last_self_test_unix: restored.last_self_test_unix,
        epoch_tails: HashMap::new(),
        last_digest_epoch: restored.last_digest_epoch,
        bond_ledger: pools::BondLedger::default(),
    };

    if args.once {
        run_cycle(
            &config,
            &endpoints,
            &hosts,
            &peers,
            &notifier,
            heartbeat.as_ref(),
            &mut runtime,
        )
        .await;
        return Ok(());
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                return Ok(());
            }
            _ = run_cycle(
                &config,
                &endpoints,
                &hosts,
                &peers,
                &notifier,
                heartbeat.as_ref(),
                &mut runtime,
            ) => {}
        }

        // Jitter so a fleet of watchtowers does not query in lockstep, which is
        // itself a way to provoke the rate limiting that causes false alarms.
        let base = config.watchtower.interval.as_millis() as u64;
        let jitter = rand::thread_rng().gen_range(0..=(base / 10).max(1));
        let sleep_for = Duration::from_millis(base.saturating_sub(base / 20) + jitter);

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                return Ok(());
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }
    }
}

struct Runtime {
    started_at_unix: u64,
    /// Consecutive clean cycles observed while in an `auto` maintenance window.
    maintenance_healthy_streak: u32,
    /// Deadline of the window currently being tracked. A newly armed window
    /// resets the recovery watch rather than inheriting the last one's progress.
    maintenance_window: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether this window has yet seen the validator actually unhealthy.
    ///
    /// Without it, arming `auto` on a healthy validator satisfies the recovery
    /// condition immediately and the window clears about two minutes later --
    /// before the operator has touched anything. Waiting for trouble first is
    /// what makes "arm it, then do the work" behave the way the name promises.
    maintenance_saw_trouble: bool,
    /// Peer name -> unix deadline of a maintenance window it declared.
    peer_maintenance: HashMap<String, u64>,
    states: HashMap<String, CheckState>,
    /// Checks we actually sent a trigger for. An inhibited check never gets a
    /// trigger, so it must never get a resolve either.
    announced: HashSet<String>,
    blindness: BlindnessState,
    blind_announced: bool,
    progress: checks::Progress,
    disk: checks::DiskHistory,
    known_vote_accounts: HashMap<String, String>,
    endpoint_health: HashMap<String, EndpointHealth>,
    last_endpoint_report: Instant,
    ownership: peer::Ownership,
    enricher: enrich::Enricher,
    diagnoser: diagnose::Diagnoser,
    metrics: Metrics,
    state_path: PathBuf,
    persist: bool,
    /// SFDP required-version schedule, re-fetched on an interval.
    sfdp: Option<sfdp::Requirements>,
    sfdp_last_fetch: Option<Instant>,
    sfdp_fetcher: Option<sfdp::Fetcher>,
    /// Scheduler clock for the notification self-test: the unix time the
    /// interval last restarted, whether because a test ran or because this is
    /// the first boot. Distinct from the exported
    /// `perch_notify_self_test_timestamp_seconds`, which only advances on an
    /// actual success -- conflating the two would let a permanently failing
    /// channel look freshly verified.
    last_self_test_unix: u64,
    /// Epoch summaries: what each validator looked like last cycle, and the last
    /// epoch already summarised.
    epoch_tails: HashMap<String, digest::EpochTail>,
    last_digest_epoch: Option<u64>,
    /// Last reading of each JPool bond, to notice when one is drawn on.
    bond_ledger: pools::BondLedger,
}

/// Confirm the endpoints are pointed at the same cluster before we start
/// trusting them to corroborate each other.
///
/// Upstream exits the process when this validation fails, which turns a
/// momentary RPC hiccup at boot into a crash loop under systemd. Here, only a
/// genuine genesis-hash disagreement -- proof of a misconfiguration that no
/// amount of waiting will fix -- is fatal. Unreachable endpoints are a warning;
/// the blindness alert covers them if they stay down.
async fn preflight(endpoints: &[rpc::Endpoint], expected_genesis: Option<&str>) -> Result<()> {
    use serde_json::json;

    let results = futures::future::join_all(
        endpoints
            .iter()
            .map(|e| async move { (e.name.clone(), e.call("getGenesisHash", json!([])).await) }),
    )
    .await;

    let mut seen: HashMap<String, String> = HashMap::new();
    let mut reachable = 0;

    for (name, result) in results {
        match result {
            Ok(v) => {
                reachable += 1;
                let hash = v.as_str().unwrap_or_default().to_string();
                info!(endpoint = %name, "genesis hash {hash}");

                // Catches the config pointed at the wrong cluster entirely,
                // which endpoint-vs-endpoint agreement cannot see.
                if let Some(expected) = expected_genesis {
                    if hash != expected {
                        anyhow::bail!(
                            "endpoint {name} is on genesis {hash}, but watchtower.cluster pins \
                             {expected}. The endpoints are pointed at a different cluster than \
                             the one this config is written for."
                        );
                    }
                }
                if let Some((other, other_hash)) = seen
                    .iter()
                    .find(|(_, h)| **h != hash)
                    .map(|(n, h)| (n.clone(), h.clone()))
                {
                    anyhow::bail!(
                        "endpoints {other} and {name} disagree on the genesis hash ({other_hash} \
                         vs {hash}); they are pointed at different clusters"
                    );
                }
                seen.insert(name, hash);
            }
            Err(e) => warn!(endpoint = %name, "preflight failed, continuing anyway: {e}"),
        }
    }

    if expected_genesis.is_some() && reachable > 0 {
        info!("cluster pin satisfied by {reachable} endpoint(s)");
    }

    if reachable == 0 {
        warn!(
            "no endpoint was reachable at startup; starting anyway and relying on the blindness \
             alert rather than crash-looping"
        );
    }
    Ok(())
}

/// One check's resolved state after its state machine ran, captured so the
/// dispatch phase does not need to keep borrowing `Runtime`.
struct Pending {
    index: usize,
    transition: Transition,
    incident_key: String,
    unhealthy_for: Duration,
    incident_duration: Duration,
    inconclusive_for: Duration,
}

#[allow(clippy::too_many_arguments)]
async fn run_cycle(
    config: &Config,
    endpoints: &[rpc::Endpoint],
    hosts: &[node_exporter::Host],
    peers: &[peer::Peer],
    notifier: &Notifier,
    heartbeat: Option<&heartbeat::Heartbeat>,
    rt: &mut Runtime,
) {
    let started = Instant::now();
    let now = started;
    // Every cycle, not just when alerting: a link flap is only timestamped by
    // watching its counter change.
    rt.diagnoser.sample(unix_now());

    // Peers are polled first: whether this instance runs cluster checks at all
    // depends on whether it owns alerting.
    let peer_statuses: Vec<peer::PeerStatus> =
        futures::future::join_all(peers.iter().map(|p| p.poll())).await;

    let change = rt.ownership.evaluate(
        config.peering.priority,
        &peer_statuses,
        config.peering.stale_after,
        config.peering.takeover_after,
        now,
    );
    // What this instance is allowed to say. `peers` mode speaks regardless of
    // ownership: the whole point is that it reports the hub being gone, and by
    // then there is no owner to defer to.
    let alerting = config.peering.alerting;
    // Only `auto` arbitrates. The other modes are scoped by configuration, so
    // there is nothing to arbitrate and nobody to defer to.
    let is_owner = match alerting {
        Alerting::Auto => rt.ownership.is_owner(),
        Alerting::Always | Alerting::Peers => true,
        Alerting::Never => false,
    };
    if alerting == Alerting::Auto {
        announce_ownership(config, notifier, &change).await;
    }

    // A `local` standby does not probe the cluster -- that is the failover
    // box's job. But a standby that gets promoted would then own alerting with
    // nothing to alert about, so promotion escalates it to full checks.
    // Only a full instance, or a standby promoted into full ownership, probes
    // the cluster. A `peers` spoke never does: those checks are the hub's.
    let run_cluster =
        config.peering.role == Role::Full || (alerting == Alerting::Auto && is_owner);

    // RPC and node_exporter are independent; a slow validator host must not
    // delay the cluster probe.
    let (snapshots, host_snapshots): (Vec<Snapshot>, Vec<node_exporter::HostSnapshot>) = tokio::join!(
        futures::future::join_all(
            endpoints
                .iter()
                .filter(|_| run_cluster)
                .map(|e| snapshot::probe(e, config, &rt.known_vote_accounts)),
        ),
        futures::future::join_all(hosts.iter().map(|h| h.scrape())),
    );

    for hs in &host_snapshots {
        if let Some(err) = &hs.error {
            warn!(host = %hs.host, "node_exporter scrape failed: {err}");
        }
    }

    for s in &snapshots {
        let h = rt.endpoint_health.entry(s.endpoint.clone()).or_default();
        h.cycles += 1;
        if s.is_usable() {
            h.usable += 1;
        }
        h.transient_errors += s.transient_errors.len() as u64;
        h.config_errors += s.config_errors.len() as u64;

        for e in &s.config_errors {
            // Misconfiguration is worth fixing, but it is never a validator fault
            // and so never pages.
            warn!(endpoint = %s.endpoint, "configuration problem: {e}");
        }
    }

    snapshot::learn_vote_accounts(&snapshots, &config.validators, &mut rt.known_vote_accounts);

    let usable = snapshots.iter().filter(|s| s.is_usable()).count();
    // A standby that is not probing is not blind; it is deliberately not
    // looking. Treating it as visible keeps its own checks running normally.
    let visible = !run_cluster || usable >= config.quorum.min_definite;
    let now_utc = chrono::Utc::now();
    let silence = state::read_silence(config.silence.file.as_deref(), now_utc);
    let silenced = silence.suppresses_paging();
    if silenced {
        debug!("silence file is active; paging is suppressed");
    }

    if run_cluster {
        handle_blindness(config, notifier, rt, visible, silenced, now).await;
    }

    let mut outcomes = if run_cluster {
        checks::evaluate(&snapshots, config, &mut rt.progress)
    } else {
        Vec::new()
    };
    outcomes.extend(checks::evaluate_disk(
        &host_snapshots,
        config,
        &mut rt.disk,
        unix_now(),
    ));
    if run_cluster {
        outcomes.extend(checks::evaluate_nodes(&snapshots, config));
        maybe_refresh_sfdp(config, notifier, rt, now).await;
        outcomes.extend(checks::evaluate_sfdp(&snapshots, config, rt.sfdp.as_ref()));
    }
    // Remember what each peer declared while we could still reach it.
    for p in &peer_statuses {
        match p.maintenance_until {
            Some(until) => {
                rt.peer_maintenance.insert(p.name.clone(), until);
            }
            // Only forget once the peer is healthy again and no longer claiming
            // one; a silent peer must keep its remembered window.
            None if p.is_live(config.peering.stale_after) => {
                rt.peer_maintenance.remove(&p.name);
            }
            None => {}
        }
    }
    rt.peer_maintenance.retain(|_, until| unix_now() < *until);

    outcomes.extend(checks::evaluate_peers(
        &peer_statuses,
        &snapshots,
        config,
        config.peering.stale_after,
        &rt.peer_maintenance,
        unix_now(),
    ));
    let suppressed = inhibit::compute(&outcomes);
    for (symptom, cause) in &suppressed {
        debug!("suppressing {symptom}: explained by {cause}");
    }

    // Phase 1: advance every state machine, recording what each one wants to say.
    // Taken before the loop so phase 1 can tell what has already been announced
    // without holding a borrow on `rt`.
    let already_announced = rt.announced.clone();
    let mut pending = Vec::new();
    for (index, outcome) in outcomes.iter().enumerate() {
        let state = rt.states.entry(outcome.id.clone()).or_default();

        // When we cannot see the network, every check freezes regardless of what
        // a partial snapshot happened to contain.
        let transition = if !visible {
            state.on_blind()
        } else {
            match &outcome.verdict {
                Verdict::Unhealthy(_) => {
                    state.on_unhealthy(&outcome.cfg, config.watchtower.interval, now)
                }
                Verdict::Healthy => state.on_healthy(&outcome.cfg, now),
                Verdict::Unknown(reason) => {
                    debug!(check = %outcome.id, "inconclusive: {reason}");
                    if outcome.warming_up {
                        // Bounded and self-resolving. Freeze the check, but do
                        // not accrue toward "this cannot be evaluated".
                        state.on_blind()
                    } else {
                        state.on_unknown(config.starvation_after(), now)
                    }
                }
            }
        };

        // A standby that has just been promoted must announce conditions that
        // began while it was quiet: their state machines are already firing, so
        // they would otherwise produce no transition and never be reported.
        let unannounced_while_standby = is_owner
            && alerting.may_report(&outcome.id)
            && state.is_firing()
            && !already_announced.contains(&outcome.id);
        let transition = if transition == Transition::Quiet && unannounced_while_standby {
            Transition::Firing
        } else {
            transition
        };

        if transition != Transition::Quiet {
            pending.push(Pending {
                index,
                transition,
                incident_key: state.incident_key().to_string(),
                unhealthy_for: state.unhealthy_for(),
                incident_duration: state.incident_duration(now),
                inconclusive_for: state.inconclusive_for(now),
            });
        }
    }

    let firing = rt
        .states
        .iter()
        .filter(|(id, s)| s.is_firing() && alerting.owns_check(id))
        .count();
    let hosts_ok = host_snapshots.iter().filter(|h| h.is_usable()).count();
    let peers_live = peer_statuses
        .iter()
        .filter(|p| p.is_live(config.peering.stale_after))
        .count();
    info!(
        "cycle complete: {}/{} endpoint(s) usable, {hosts_ok}/{} host(s) scraped, \
         {peers_live}/{} peer(s) live, visibility {}, {firing} check(s) firing, {} suppressed, \
         alerting {}",
        usable,
        if run_cluster { endpoints.len() } else { 0 },
        host_snapshots.len(),
        peer_statuses.len(),
        if visible { "ok" } else { "DEGRADED" },
        suppressed.len(),
        match (alerting, is_owner) {
            (Alerting::Never, _) => "never (data source)",
            (Alerting::Peers, _) => "peers only",
            // Ownership is an arbitration concept; saying "OWNED" to someone
            // running a single instance is noise.
            (Alerting::Always, _) if peer_statuses.is_empty() => "on",
            (Alerting::Always, _) => "own scope",
            (_, true) => "OWNED",
            (_, false) => "standby",
        }
    );

    // Phase 2: deliver -- but only if this instance owns alerting. A standby
    // keeps every state machine current so a handover is seamless; it just does
    // not speak.
    if is_owner {
        let epoch_line = epoch_context(&snapshots);
        for p in pending {
            let outcome = &outcomes[p.index];
            // A spoke in `peers` mode stays out of everything the hub owns.
            if !alerting.may_report(&outcome.id) {
                debug!(check = %outcome.id, "not reported: outside this instance's alerting scope");
                continue;
            }
            dispatch_check(
                config, endpoints, notifier, rt, outcome, &outcomes, &p, &suppressed, &epoch_line,
                silenced, endpoints.len(), now,
            )
            .await;
        }
    } else if !pending.is_empty() {
        debug!(
            "not alerting: {} transition(s) not delivered ({})",
            pending.len(),
            match alerting {
                Alerting::Never => "peering.alerting is \"never\"",
                _ => "a higher-priority peer owns alerting",
            }
        );
    }

    retire_orphans(config, notifier, rt, &outcomes).await;

    let validator_labels: HashMap<String, String> = config
        .validators
        .iter()
        .map(|v| (v.identity.clone(), v.display().to_string()))
        .collect();
    let solana_cluster = config
        .watchtower
        .sfdp_cluster()
        .map(str::to_string)
        .or_else(|| config.watchtower.cluster.clone())
        .unwrap_or_else(|| "unpinned".into());
    let rendered = metrics::render(&metrics::CycleReport {
        watchtower_name: &config.watchtower.name,
        solana_cluster: &solana_cluster,
        validator_labels: &validator_labels,
        alerting,
        jpool_security_sol_per_1000: config.checks.jpool_bond.security_sol_per_1000,
        snapshots: &snapshots,
        host_snapshots: &host_snapshots,
        peers: &peer_statuses,
        is_owner,
        disk: &rt.disk,
        outcomes: &outcomes,
        states: &rt.states,
        endpoint_health: &rt.endpoint_health,
        suppressed: &suppressed,
        visible,
        silenced,
        cycle_duration: started.elapsed(),
        unix_time: unix_now(),
        start_time: rt.started_at_unix,
        notify: notifier.stats().counts(),
        maintenance_streak: rt.maintenance_healthy_streak,
        // From this cycle's silence file, not `rt.maintenance_window`: that is
        // only updated after metrics render, so a freshly armed window -- and
        // every window on the first cycle after a restart -- read 0 for a cycle.
        maintenance_awaiting_work: match silence {
            state::Silence::UntilRecovered { deadline } => {
                !(rt.maintenance_window == Some(deadline) && rt.maintenance_saw_trouble)
            }
            _ => false,
        },
        maintenance_until: match silence {
            state::Silence::UntilRecovered { deadline } => deadline.timestamp().max(0) as u64,
            state::Silence::Until(until) => until.timestamp().max(0) as u64,
            state::Silence::None => 0,
        },
    });
    rt.metrics.set(match config.metrics.as_ref().and_then(|m| m.compat_prefix.as_deref()) {
        Some(prefix) => metrics::with_compat_alias(&rendered, prefix),
        None => rendered,
    });

    rt.metrics.set_html(web::render(&web::PageData {
        name: &config.watchtower.name,
        disk_space: &config.checks.disk_space,
        snapshots: &snapshots,
        host_snapshots: &host_snapshots,
        peers: &peer_statuses,
        outcomes: &outcomes,
        states: &rt.states,
        suppressed: &suppressed,
        visible,
        silenced,
        alerting: match (alerting, is_owner) {
            (Alerting::Never, _) => "never (data source)",
            (Alerting::Peers, _) => "peers only",
            (Alerting::Always, _) if peer_statuses.is_empty() => "on",
            (Alerting::Always, _) => "own scope",
            (_, true) => "owner",
            (_, false) => "standby",
        },
        stale_after: config.peering.stale_after,
        max_endpoint_lag: config.quorum.max_endpoint_lag_slots,
        grafana_url: config.metrics.as_ref().and_then(|m| m.grafana_url.as_deref()),
        epoch_line: &epoch_context(&snapshots),
    }));

    if let Some(hb) = heartbeat {
        hb.beat(visible).await;
    }

    maybe_self_test(config, notifier, rt).await;

    // Before persisting, so the epoch it records is in the state file this
    // cycle rather than the next one.
    maybe_epoch_digest(config, notifier, rt, &snapshots, alerting, is_owner).await;
    if run_cluster {
        announce_bond_drawdowns(config, notifier, rt, &snapshots, alerting, is_owner).await;
    }

    if rt.persist {
        if let Err(e) = persist::save(
            &rt.state_path,
            &rt.states,
            &rt.announced,
            &rt.peer_maintenance,
            &rt.progress,
            &rt.disk,
            &rt.blindness,
            rt.blind_announced,
            rt.last_self_test_unix,
            rt.last_digest_epoch,
            now,
        ) {
            // Losing persistence degrades restart behaviour but must not stop
            // the watchtower from watching.
            warn!("could not persist state: {e:#}");
        }
    }

    // A maintenance window that waits for recovery, rather than a timer the
    // operator had to guess at up front.
    if let state::Silence::UntilRecovered { deadline } = silence {
        resolve_maintenance(config, notifier, rt, &outcomes, deadline, now_utc).await;
    }

    maybe_report_endpoints(config, notifier, rt, now).await;
}

/// Checks that actually indicate the validator is back.
///
/// Recovery is judged only on these. An earlier version required *every* check
/// to be conclusive, which could never happen on a freshly restarted watchtower:
/// `disk_fill` is Unknown by design until it has 45 minutes of history, so
/// maintenance would never clear in exactly the situation it exists for.
fn is_recovery_signal(check_id: &str) -> bool {
    [
        "vote_delinquent:",
        "vote_lag:",
        "root_lag:",
        "vote_stalled:",
        "node_behind:",
    ]
    .iter()
    .any(|p| check_id.starts_with(p))
}

/// What an `auto` maintenance window should do this cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaintenanceStep {
    /// Deadline passed without recovery. A restart that never finishes is an
    /// outage, not maintenance.
    Expired,
    /// Something is unhealthy or inconclusive: the work is underway.
    Working,
    /// Armed, but nothing has gone wrong yet -- the operator has not started.
    /// Resuming here would disarm the protection they just asked for.
    AwaitingWork,
    /// First clean cycle after trouble. A validator often looks briefly fine
    /// mid-restart, so one is not enough.
    Confirming,
    /// Recovered for long enough; put paging back on.
    Resume,
}

fn maintenance_step(
    expired: bool,
    troubled: usize,
    unconfirmed: usize,
    saw_trouble: bool,
    streak_after_increment: u32,
) -> MaintenanceStep {
    if expired {
        return MaintenanceStep::Expired;
    }
    if troubled > 0 || unconfirmed > 0 {
        return MaintenanceStep::Working;
    }
    if !saw_trouble {
        return MaintenanceStep::AwaitingWork;
    }
    if streak_after_increment < 2 {
        return MaintenanceStep::Confirming;
    }
    MaintenanceStep::Resume
}

/// Clear an `auto` maintenance window once the validator is genuinely healthy
/// again, or when its deadline passes.
///
/// Recovery requires that nothing is reporting trouble, and that the checks
/// which show the validator voting are *definitively* healthy rather than merely
/// inconclusive -- resuming on Unknown would turn paging back on while still
/// half-blind.
/// Send the scheduled synthetic alert if the interval has elapsed.
///
/// This is the only alert perch sends when nothing is wrong, and it is the only
/// one that answers a question no check can answer about itself: if the
/// validator *were* broken, could anyone actually be told? A revoked routing
/// key, a rotated bot token or a new egress rule leaves every check reporting
/// healthy while the path out of the box is dead.
/// Backdate a fresh instance's self-test clock by a random slice of the
/// interval, so the first test lands somewhere in the interval's second half.
///
/// A fleet provisioned in one afternoon would otherwise start every clock
/// together and fire as a thundering herd, one synthetic incident per box
/// within the same few minutes, every week forever. Backdating spreads them
/// while still guaranteeing no instance tests at boot.
fn jittered_start(now: u64, interval: Duration, roll: u64) -> u64 {
    let half = (interval.as_secs() / 2).max(1);
    now.saturating_sub(roll % half)
}

async fn maybe_self_test(config: &Config, notifier: &Notifier, rt: &mut Runtime) {
    let cfg = &config.notify.self_test;
    if !cfg.enabled || !rt.persist {
        return;
    }
    let interval = cfg.interval.max(config::MIN_SELF_TEST_INTERVAL);
    let now = unix_now();

    // A never-tested instance waits instead of firing at boot. Testing on
    // startup would turn a crash loop into a page generator, which is the exact
    // failure this feature exists to prevent.
    if rt.last_self_test_unix == 0 {
        let roll = rand::thread_rng().gen_range(0..u64::MAX);
        rt.last_self_test_unix = jittered_start(now, interval, roll);
        return;
    }
    if now.saturating_sub(rt.last_self_test_unix) < interval.as_secs() {
        return;
    }

    // The clock restarts whether or not the test passed. Retrying a broken
    // channel every cycle would hammer it; the metric is what raises the alarm.
    rt.last_self_test_unix = now;

    let source = format!("perch/{}", config.watchtower.name);
    let failures: Vec<String> = notifier
        .self_test(&source, SelfTestMode::Quiet)
        .await
        .iter()
        .filter(|r| r.configured)
        .filter_map(|r| r.error.as_ref().map(|e| format!("{}: {e}", r.channel)))
        .collect();

    if failures.is_empty() {
        info!("notification self-test passed on every configured channel");
    } else {
        error!(
            "notification self-test FAILED -- alerts may not be deliverable: {}",
            failures.join("; ")
        );
    }
}

async fn resolve_maintenance(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    outcomes: &[checks::CheckOutcome],
    deadline: chrono::DateTime<chrono::Utc>,
    now_utc: chrono::DateTime<chrono::Utc>,
) {
    let Some(path) = config.silence.file.as_deref() else {
        return;
    };

    // A freshly armed window starts its own watch; progress is never inherited.
    if rt.maintenance_window != Some(deadline) {
        rt.maintenance_window = Some(deadline);
        rt.maintenance_saw_trouble = false;
        rt.maintenance_healthy_streak = 0;
    }

    let troubled: Vec<&str> = outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Unhealthy(_)))
        .map(|o| o.id.as_str())
        .collect();
    // Only the recovery signals must be conclusive; a disk-fill projection still
    // warming up says nothing about whether the validator came back.
    let unconfirmed: Vec<&str> = outcomes
        .iter()
        .filter(|o| is_recovery_signal(&o.id) && matches!(o.verdict, Verdict::Unknown(_)))
        .map(|o| o.id.as_str())
        .collect();

    // The branch is decided by `maintenance_step` so the rule is testable on its
    // own; this function only carries it out.
    let step = maintenance_step(
        now_utc >= deadline,
        troubled.len(),
        unconfirmed.len(),
        rt.maintenance_saw_trouble,
        rt.maintenance_healthy_streak + 1,
    );

    match step {
        MaintenanceStep::Expired => {
            let _ = std::fs::remove_file(path);
            rt.maintenance_healthy_streak = 0;
            rt.maintenance_saw_trouble = false;
            rt.maintenance_window = None;
            warn!("maintenance window expired; paging resumed");
            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Info,
                    severity: Severity::Notify,
                    key: "maintenance".into(),
                    title: "Maintenance window expired".into(),
                    body: format!(
                        "The validator did not return to health before the deadline, so paging is back on. {} check(s) still reporting trouble. A restart that does not finish is an outage, not maintenance.",
                        troubled.len()
                    ),
                })
                .await;
            return;
        }
        MaintenanceStep::Working => {
            rt.maintenance_saw_trouble = true;
            rt.maintenance_healthy_streak = 0;
            debug!(
                "maintenance: waiting, {} unhealthy / {} recovery signal(s) unconfirmed",
                troubled.len(),
                unconfirmed.len()
            );
            return;
        }
        MaintenanceStep::AwaitingWork => {
            debug!("maintenance: armed, waiting for the work to begin");
            return;
        }
        MaintenanceStep::Confirming => {
            rt.maintenance_healthy_streak += 1;
            debug!("maintenance: first clean cycle, confirming");
            return;
        }
        MaintenanceStep::Resume => {}
    }

    let _ = std::fs::remove_file(path);
    rt.maintenance_healthy_streak = 0;
    rt.maintenance_saw_trouble = false;
    rt.maintenance_window = None;
    info!("maintenance complete; validator healthy, paging resumed");
    notifier
        .dispatch(&Alert {
            kind: AlertKind::Info,
            severity: Severity::Notify,
            key: "maintenance".into(),
            title: "Back online \u{2014} monitoring resumed".into(),
            body: format!(
                "{} is voting and every check is healthy again. Full paging is back on.",
                config.watchtower.name
            ),
        })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_check(
    config: &Config,
    endpoints: &[rpc::Endpoint],
    notifier: &Notifier,
    rt: &mut Runtime,
    outcome: &checks::CheckOutcome,
    all_outcomes: &[checks::CheckOutcome],
    p: &Pending,
    suppressed: &HashMap<String, String>,
    epoch_line: &str,
    silenced: bool,
    endpoint_count: usize,
    now: Instant,
) {
    // A starved check is a watchtower problem, not a validator problem, so it
    // reports at notify level whatever the check's own severity is.
    if p.transition == Transition::Starved {
        notifier
            .dispatch(&Alert {
                kind: AlertKind::Info,
                severity: Severity::Notify,
                key: format!("starved/{}", outcome.id),
                title: format!("Check \"{}\" cannot be evaluated", outcome.title),
                body: format!(
                    "{} has been inconclusive for {} even though the cluster is visible, so it \
                     cannot alert. Reason: {}",
                    outcome.id,
                    humantime::format_duration(round_secs(p.inconclusive_for)),
                    outcome.verdict
                ),
            })
            .await;
        return;
    }

    let severity = state::effective_severity(outcome.cfg.severity, silenced, config.silence.notify_while_silenced);
    if severity == Severity::Log {
        info!(check = %outcome.id, "{:?}: {}", p.transition, outcome.verdict);
        return;
    }

    // Peer checks describe a shared subject, not the observer, so every spoke
    // watching the same hub must produce the same dedup key -- otherwise a dead
    // hub opens one incident per spoke, which is the duplication this whole
    // design exists to avoid. Everything else stays per-instance.
    let key = if config::is_peer_check(&outcome.id) {
        outcome.id.clone()
    } else {
        format!("{}/{}", outcome.id, p.incident_key)
    };

    // Inhibited: this check is a symptom of something broader that is alerting
    // on its own. If we already paged for it before the broader cause appeared,
    // close that incident rather than leaving two open for one event.
    if let Some(cause) = suppressed.get(&outcome.id) {
        if rt.announced.remove(&outcome.id) {
            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Resolve,
                    severity,
                    key,
                    title: format!("Superseded: {}", outcome.title),
                    body: format!("Folded into the alert for {cause}, which explains it."),
                })
                .await;
        } else {
            debug!(check = %outcome.id, "not alerting: explained by {cause}");
        }
        return;
    }

    match p.transition {
        Transition::Firing | Transition::Renotify => {
            let mut body = outcome.verdict.detail().unwrap_or("no detail").to_string();
            // Peer checks never ask an RPC endpoint, so an endpoint tally for
            // them is "Confirmed by 0 of the 0" -- noise that reads like a
            // contradiction of the line above it.
            if outcome.tally.definite() + outcome.tally.unknown > 0 {
                body.push_str(&format!(
                    "\nConfirmed by {} of the {} endpoint(s) that answered; {} of {endpoint_count} \
                     could not answer.",
                    outcome.tally.unhealthy,
                    outcome.tally.definite(),
                    outcome.tally.unknown
                ));
            }
            body.push_str(&format!(
                "\nUnhealthy for {}.",
                humantime::format_duration(round_secs(p.unhealthy_for))
            ));

            let symptoms = inhibit::symptoms_of(&outcome.id, suppressed, all_outcomes);
            if !symptoms.is_empty() {
                body.push_str(&format!("\nAlso observed: {}", symptoms.join("; ")));
            }

            if !epoch_line.is_empty() {
                body.push('\n');
                body.push_str(epoch_line);
            }

            // Answer "is this me or is this everyone?" in the page itself.
            // Not for peer_down: it already says the validator is voting, so
            // cluster delinquency has nothing to add.
            if is_validator_check(&outcome.id) && !outcome.id.starts_with("peer_down:") {
                if let Some(ctx) = rt.enricher.context(endpoints, now).await {
                    body.push('\n');
                    body.push_str(&ctx.summary());
                }
            }

            // Only on the first trigger: a renotify re-reading the log would
            // mostly repeat itself.
            if p.transition == Transition::Firing
                && rt.diagnoser.applies_to(&outcome.id, outcome.owner.as_deref())
            {
                if let Some(causes) = rt.diagnoser.diagnose(unix_now(), p.incident_duration).await {
                    body.push('\n');
                    body.push_str(&causes);
                }
            }

            if silenced {
                body.push_str(
                    "\nA silence file is active, so this did not page. Remove it to restore \
                     paging.",
                );
            }

            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Trigger,
                    severity,
                    key,
                    title: if p.transition == Transition::Renotify {
                        format!("[still firing] {}", outcome.title)
                    } else {
                        outcome.title.clone()
                    },
                    body,
                })
                .await;
            rt.announced.insert(outcome.id.clone());
        }
        Transition::Resolved => {
            // Never resolve what we never triggered: an inhibited check reaching
            // the end of its incident would otherwise send PagerDuty a resolve
            // for a dedup key it has never seen.
            if !rt.announced.remove(&outcome.id) {
                debug!(check = %outcome.id, "recovered without ever having alerted");
                return;
            }
            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Resolve,
                    severity,
                    key,
                    title: format!("Resolved: {}", outcome.title),
                    body: format!(
                        "Recovered after {}.",
                        humantime::format_duration(round_secs(p.incident_duration))
                    ),
                })
                .await;
        }
        Transition::Quiet | Transition::Starved => unreachable!("handled above"),
    }
    let _ = config;
}

/// Close out states for checks that no longer exist in this version or config.
///
/// Without this a removed or disabled check stays "firing" forever, and a
/// PagerDuty incident it opened is never resolved -- refi-main's sat open for
/// two weeks after `vote_balance_critical` was removed. The resolve goes out
/// under the incident's original dedup key, the only one PagerDuty will match.
async fn retire_orphans(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    outcomes: &[checks::CheckOutcome],
) {
    for id in checks::orphaned(rt.states.keys(), outcomes, config) {
        let Some(state) = rt.states.remove(&id) else { continue };
        if rt.announced.remove(&id) {
            let key = if config::is_peer_check(&id) {
                id.clone()
            } else {
                format!("{id}/{}", state.incident_key())
            };
            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Resolve,
                    // Page, so the resolve reaches PagerDuty as well as Telegram:
                    // the incident may have been opened there.
                    severity: Severity::Page,
                    key,
                    title: format!("Resolved: {id} is no longer monitored"),
                    body: "This check no longer exists in this version of perch or in this \
                           instance's configuration, so it cannot be evaluated. Closing the \
                           incident it opened."
                        .into(),
                })
                .await;
        }
        info!(check = %id, "retired: no longer produced by this version or configuration");
    }
}

/// Ownership changes are operationally important and easy to miss in logs, so
/// they are reported -- on the notify tier, never as a page.
async fn announce_ownership(
    config: &Config,
    notifier: &Notifier,
    change: &peer::OwnershipChange,
) {
    let alert = match change {
        peer::OwnershipChange::Unchanged => return,
        peer::OwnershipChange::Assumed { from } if from.is_empty() => return,
        peer::OwnershipChange::Assumed { from } => Alert {
            kind: AlertKind::Info,
            severity: Severity::Notify,
            key: "alerting_ownership".into(),
            title: "This watchtower has taken over alerting".into(),
            body: format!(
                "Higher-priority peer(s) {} stopped reporting, so {} is now the alerting instance. This affects notification only -- nothing has been failed over.",
                from.join(", "),
                config.peering.name.as_deref().unwrap_or("this instance")
            ),
        },
        peer::OwnershipChange::Relinquished { to } => Alert {
            kind: AlertKind::Info,
            severity: Severity::Notify,
            key: "alerting_ownership".into(),
            title: "Alerting handed back".into(),
            body: format!("{to} is reporting again and has resumed alerting."),
        },
    };
    notifier.dispatch(&alert).await;
}

/// Cluster-wide checks do not benefit from validator-specific context.
fn is_validator_check(id: &str) -> bool {
    id.contains(':')
}

/// "Epoch 820, 63.4% complete (slot 312874910)" -- cheap triage context, taken
/// from the most advanced endpoint.
fn epoch_context(snapshots: &[Snapshot]) -> String {
    let Some(info) = snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref())
        .max_by_key(|e| e.absolute_slot)
    else {
        return String::new();
    };
    if info.slots_in_epoch == 0 {
        return format!("Epoch {}, slot {}.", info.epoch, info.absolute_slot);
    }
    format!(
        "Epoch {}, {:.1}% complete (slot {}).",
        info.epoch,
        info.epoch_percent(),
        info.absolute_slot
    )
}

async fn handle_blindness(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    visible: bool,
    silenced: bool,
    now: Instant,
) {
    let event = rt.blindness.observe(
        visible,
        config.blindness.notify_after,
        config.blindness.page_after,
        now,
    );

    let key = rt
        .blindness
        .incident_key()
        .map(|k| format!("watchtower_blind/{k}"))
        .unwrap_or_else(|| "watchtower_blind".into());

    let alert = match event {
        BlindnessEvent::Quiet => return,
        BlindnessEvent::Notify { blind_for } => {
            rt.blind_announced = true;
            Alert {
                kind: AlertKind::Info,
                severity: Severity::Notify,
                key,
                title: "Watchtower cannot see the cluster".into(),
                body: format!(
                    "Fewer than {} endpoint(s) have answered for {}. No validator alerting is \
                     possible until this clears. Not paging yet: this is usually provider \
                     flakiness and usually resolves on its own.",
                    config.quorum.min_definite,
                    humantime::format_duration(round_secs(blind_for))
                ),
            }
        }
        BlindnessEvent::Page { blind_for } => {
            rt.blind_announced = true;
            Alert {
                kind: AlertKind::Trigger,
                severity: state::effective_severity(Severity::Page, silenced, config.silence.notify_while_silenced),
                key,
                title: "Watchtower has been blind for too long".into(),
                body: format!(
                    "No usable RPC answers for {}. This has gone on long enough that it is no \
                     longer plausibly transient, and a real validator problem could be hidden \
                     behind it. Check the monitoring host's network and the configured RPC \
                     providers.",
                    humantime::format_duration(round_secs(blind_for))
                ),
            }
        }
        BlindnessEvent::Recovered { blind_for } => {
            rt.blind_announced = false;
            Alert {
                kind: AlertKind::Resolve,
                severity: state::effective_severity(Severity::Page, silenced, config.silence.notify_while_silenced),
                key,
                title: "Watchtower visibility restored".into(),
                body: format!(
                    "RPC visibility restored after {}.",
                    humantime::format_duration(round_secs(blind_for))
                ),
            }
        }
    };

    notifier.dispatch(&alert).await;

    if matches!(event, BlindnessEvent::Recovered { .. }) {
        rt.blindness.clear_incident();
    }
}

/// Periodic reliability digest. The point is to make the noisy provider
/// identifiable instead of leaving it to be inferred from pages at 3am.
/// Send the summary for the epoch that just ended, once, from the instance that
/// owns alerting for these validators.
async fn maybe_epoch_digest(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    snapshots: &[Snapshot],
    alerting: Alerting,
    is_owner: bool,
) {
    let (Some(epoch), tails) = digest::capture(snapshots, config) else {
        return;
    };
    let previous = rt.last_digest_epoch;
    // Same rule as validator alerts: `peers` mode (the hub) and `never` stay
    // quiet, so a fleet produces one digest per validator rather than one per
    // box that can see it.
    let speaks = match alerting {
        Alerting::Always => true,
        Alerting::Auto => is_owner,
        Alerting::Peers | Alerting::Never => false,
    };

    match previous {
        // First sight of any epoch: start counting, say nothing. Summarising an
        // epoch we only watched the tail of would be misleading.
        None => rt.last_digest_epoch = Some(epoch),
        Some(last) if epoch > last => {
            if config.digest.enabled && speaks {
                if let Some((title, body)) = digest::render(last, &rt.epoch_tails, snapshots, config) {
                    notifier
                        .dispatch(&Alert {
                            kind: AlertKind::Info,
                            severity: Severity::Notify,
                            key: format!("epoch_digest:{last}"),
                            title,
                            body,
                        })
                        .await;
                }
            }
            rt.last_digest_epoch = Some(epoch);
        }
        Some(_) => {}
    }
    // Always keep the tail current; it is what next rollover will report.
    rt.epoch_tails = tails;
}

/// Anything in this window worth an operator's attention?
fn report_is_worthwhile(health: &HashMap<String, EndpointHealth>) -> bool {
    health
        .values()
        .any(|h| h.cycles > 0 && (h.usable < h.cycles || h.transient_errors > 0 || h.config_errors > 0))
}

/// Say when JPool draws on a validator's bond.
///
/// JPool claims from the bond each epoch the validator falls short of its
/// target APY. The low-bond check says when the balance matters; this says
/// each time it moves, which is how a slow drain gets noticed before it does.
/// Same speaker rule as the epoch digest: one note per validator per fleet.
async fn announce_bond_drawdowns(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    snapshots: &[Snapshot],
    alerting: Alerting,
    is_owner: bool,
) {
    let jc = &config.checks.jpool_bond;
    if !jc.base.enabled {
        return;
    }
    let speaks = match alerting {
        Alerting::Always => true,
        Alerting::Auto => is_owner,
        Alerting::Peers | Alerting::Never => false,
    };
    for v in &config.validators {
        let mut bonds: Vec<pools::Bond> = snapshots
            .iter()
            .filter_map(|s| s.jpool.get(&v.identity))
            .filter_map(|r| r.as_ref().ok())
            .flat_map(|p| p.bonds.iter())
            .cloned()
            .collect();
        // Oldest first, so endpoints that disagree this cycle are replayed in
        // the order the chain moved.
        bonds.sort_by_key(|b| b.slot);
        let drawdowns = rt.bond_ledger.observe(&bonds);
        let Some(latest) = drawdowns.last() else {
            continue;
        };
        let who = v.display();
        let lines: Vec<String> = drawdowns
            .iter()
            .map(|d| {
                format!(
                    "{:.6} SOL out of the {} bond, which now holds {:.4} SOL (was {:.4}). \
                     https://solscan.io/account/{}",
                    snapshot::lamports_to_sol(d.before.saturating_sub(d.after)),
                    d.name,
                    snapshot::lamports_to_sol(d.after),
                    snapshot::lamports_to_sol(d.before),
                    d.address
                )
            })
            .collect();
        info!("{who} JPool bond went down: {}", lines.join("; "));
        if jc.announce_drawdowns && speaks {
            notifier
                .dispatch(&Alert {
                    kind: AlertKind::Info,
                    severity: Severity::Notify,
                    key: format!("jpool_drawdown:{who}:{}:{}", latest.address, latest.after),
                    title: format!("JPool drew on {who}'s bond"),
                    body: format!(
                        "{}\nJPool claims from the bond to cover an APY shortfall; a withdrawal \
                         by the bond authority reads the same.",
                        lines.join("\n")
                    ),
                })
                .await;
        }
    }
}

/// Keep the SFDP schedule fresh, and say so when it changes.
///
/// Polled rather than fetched once an epoch: the foundation can publish a new
/// floor at any point, and the announcement is worth hearing before the epoch
/// that enforces it. Failures keep whatever we had -- a stale schedule beats
/// none, and the check reads Unknown either way until a fetch succeeds.
async fn maybe_refresh_sfdp(config: &Config, notifier: &Notifier, rt: &mut Runtime, now: Instant) {
    let cfg = &config.checks.sfdp_version;
    if !cfg.base.enabled {
        return;
    }
    let (Some(cluster), Some(fetcher)) = (config.watchtower.sfdp_cluster(), rt.sfdp_fetcher.as_ref())
    else {
        return;
    };
    // Floored so a typo cannot turn this into a request every cycle.
    let interval = cfg.poll_interval.max(Duration::from_secs(300));
    let due = match (rt.sfdp.is_some(), rt.sfdp_last_fetch) {
        (true, Some(t)) => now.saturating_duration_since(t) >= interval,
        // Nothing yet: retry sooner, but still backed off, so an API outage on
        // a fresh box warns every few minutes rather than every cycle.
        (false, Some(t)) => now.saturating_duration_since(t) >= Duration::from_secs(300),
        (_, None) => true,
    };
    if !due {
        return;
    }
    rt.sfdp_last_fetch = Some(now);

    match fetcher.fetch(cluster).await {
        Ok(fresh) => {
            match &rt.sfdp {
                None => info!(
                    "SFDP schedule for {cluster}: {}",
                    fresh.entries.iter()
                        .map(|r| format!("epoch {} >= {}", r.epoch, r.min))
                        .collect::<Vec<_>>().join(", ")
                ),
                Some(old) => {
                    let changes = sfdp::diff(old, &fresh);
                    if !changes.is_empty() {
                        info!("SFDP schedule for {cluster} changed: {}", changes.join("; "));
                        if cfg.announce_changes {
                            notifier.dispatch(&Alert {
                                kind: AlertKind::Info,
                                severity: Severity::Notify,
                                key: format!("sfdp_schedule:{cluster}"),
                                title: format!("Delegation program schedule changed ({cluster})"),
                                body: changes.join("\n"),
                            }).await;
                        }
                    }
                }
            }
            rt.sfdp = Some(fresh);
        }
        Err(e) => warn!("could not fetch SFDP required versions: {e:#}"),
    }
}

async fn maybe_report_endpoints(
    config: &Config,
    notifier: &Notifier,
    rt: &mut Runtime,
    now: Instant,
) {
    let period = config.watchtower.endpoint_report_interval;
    if period.is_zero() || now.saturating_duration_since(rt.last_endpoint_report) < period {
        return;
    }
    rt.last_endpoint_report = now;

    // Silence means fine. A six-hourly "100% usable" from every box is dozens
    // of messages a day that carry no information; the report earns its place
    // only when an endpoint was less than perfect.
    if !report_is_worthwhile(&rt.endpoint_health) {
        debug!("endpoint reliability: every endpoint clean this window; not reporting");
        rt.endpoint_health.clear();
        return;
    }

    let mut lines: Vec<String> = rt
        .endpoint_health
        .iter()
        .map(|(name, h)| {
            format!(
                "{name}: {:.1}% usable over {} cycles, {} transient error(s), {} config error(s)",
                h.success_rate(),
                h.cycles,
                h.transient_errors,
                h.config_errors
            )
        })
        .collect();
    lines.sort();

    notifier
        .dispatch(&Alert {
            kind: AlertKind::Info,
            severity: Severity::Notify,
            key: "endpoint_health_report".into(),
            title: "RPC endpoint reliability".into(),
            body: lines.join("\n"),
        })
        .await;

    rt.endpoint_health.clear();
}

/// `humantime` renders sub-second precision that nobody reading an alert wants.
fn round_secs(d: Duration) -> Duration {
    Duration::from_secs(d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use perch::snapshot::EpochInfo;

    fn snap(name: &str, slot: u64, slot_index: u64) -> Snapshot {
        Snapshot {
            endpoint: name.into(),
            version: None,
            identity: None,
            epoch_info: Some(EpochInfo {
                absolute_slot: slot,
                epoch: 820,
                slot_index,
                slots_in_epoch: 432_000,
            }),
            validators: HashMap::new(),
            identity_balances: HashMap::new(),
            alpenglow: None,
            vote_states: HashMap::new(),
            vote_income: HashMap::new(),
            vault_invoices: HashMap::new(),
            jpool: HashMap::new(),
            block_production: HashMap::new(),
            cluster_stake: None,
            transient_errors: vec![],
            config_errors: vec![],
        }
    }

    fn health(cycles: u64, usable: u64, transient: u64, config: u64) -> EndpointHealth {
        EndpointHealth { cycles, usable, transient_errors: transient, config_errors: config }
    }

    /// The report the operator called excessive: every endpoint perfect, sent
    /// anyway, from every box, four times a day.
    #[test]
    fn a_clean_window_is_not_reported() {
        let mut h = HashMap::new();
        h.insert("localhost".to_string(), health(355, 355, 0, 0));
        h.insert("publicnode".to_string(), health(355, 355, 0, 0));
        assert!(!report_is_worthwhile(&h));
        assert!(!report_is_worthwhile(&HashMap::new()), "nothing observed, nothing to say");
    }

    #[test]
    fn any_imperfection_is_reported() {
        for (label, hh) in [
            ("one transient", health(355, 355, 1, 0)),
            ("one config", health(355, 355, 0, 1)),
            ("one unusable cycle", health(355, 354, 0, 0)),
        ] {
            let mut h = HashMap::new();
            h.insert("x".to_string(), hh);
            assert!(report_is_worthwhile(&h), "{label} should be reported");
        }
    }

    /// The bug that shipped: arming `auto` on a healthy validator satisfied the
    /// recovery condition immediately and cleared itself two cycles later,
    /// before any work had started.
    #[test]
    fn arming_maintenance_on_a_healthy_validator_does_not_self_clear() {
        assert_eq!(
            maintenance_step(false, 0, 0, false, 1),
            MaintenanceStep::AwaitingWork
        );
        assert_eq!(
            maintenance_step(false, 0, 0, false, 9),
            MaintenanceStep::AwaitingWork,
            "no number of clean cycles should resume a window whose work never began"
        );
    }

    #[test]
    fn recovery_needs_two_clean_cycles_after_trouble() {
        assert_eq!(maintenance_step(false, 1, 0, true, 0), MaintenanceStep::Working);
        assert_eq!(maintenance_step(false, 0, 0, true, 1), MaintenanceStep::Confirming);
        assert_eq!(maintenance_step(false, 0, 0, true, 2), MaintenanceStep::Resume);
    }

    /// An inconclusive recovery signal must not count as recovered; resuming on
    /// Unknown turns paging back on while still half-blind.
    #[test]
    fn an_unknown_recovery_signal_blocks_resume() {
        assert_eq!(maintenance_step(false, 0, 1, true, 5), MaintenanceStep::Working);
    }

    #[test]
    fn the_deadline_always_wins() {
        for saw in [true, false] {
            for (t, u) in [(0, 0), (3, 0), (0, 2)] {
                assert_eq!(
                    maintenance_step(true, t, u, saw, 9),
                    MaintenanceStep::Expired,
                    "a window past its deadline must resume paging regardless of state"
                );
            }
        }
    }

    #[test]
    fn a_fresh_instance_never_self_tests_at_boot() {
        let interval = Duration::from_secs(7 * 24 * 3600);
        let now = 1_700_000_000u64;
        // Worst case roll: the largest possible backdate.
        for roll in [0, 1, u64::MAX, u64::MAX / 2, 12345] {
            let start = jittered_start(now, interval, roll);
            let first_fire = start + interval.as_secs();
            assert!(
                first_fire >= now + interval.as_secs() / 2,
                "roll {roll} would fire after only {}s",
                first_fire - now
            );
            assert!(first_fire <= now + interval.as_secs());
        }
    }

    /// Seven boxes provisioned in the same afternoon must not all fire in the
    /// same few minutes every week.
    #[test]
    fn a_fleet_booted_together_does_not_fire_together() {
        let interval = Duration::from_secs(7 * 24 * 3600);
        let now = 1_700_000_000u64;
        let starts: Vec<u64> = (0..7)
            .map(|i| jittered_start(now, interval, i * 98_765_431 + 7))
            .collect();
        let spread = starts.iter().max().unwrap() - starts.iter().min().unwrap();
        assert!(
            spread > 3600,
            "first tests are bunched within {spread}s of each other"
        );
    }

    #[test]
    fn durations_are_rounded_for_display() {
        assert_eq!(
            round_secs(Duration::from_millis(125_600)),
            Duration::from_secs(125)
        );
    }

    #[test]
    fn epoch_context_uses_the_most_advanced_endpoint() {
        let snaps = vec![snap("behind", 1000, 108_000), snap("ahead", 2000, 216_000)];
        let line = epoch_context(&snaps);
        assert!(line.contains("50.0%"), "got {line}");
        assert!(line.contains("2000"), "got {line}");
    }

    #[test]
    fn epoch_context_is_empty_when_nothing_answered() {
        assert_eq!(epoch_context(&[]), "");
    }

    #[test]
    fn recovery_is_judged_on_validator_signals_not_on_warmup() {
        // disk_fill is Unknown for its first 45 minutes by design; requiring it
        // to be conclusive meant maintenance could never clear after a restart.
        assert!(is_recovery_signal("vote_delinquent:chimps-1"));
        assert!(is_recovery_signal("node_behind:localhost"));
        assert!(!is_recovery_signal("disk_fill_critical:hw /mnt/ledger"));
        assert!(!is_recovery_signal("identity_balance_warn:chimps-1"));
        assert!(!is_recovery_signal("cluster_stalled"));
    }

    #[test]
    fn cluster_checks_are_not_treated_as_validator_checks() {
        assert!(is_validator_check("vote_delinquent:chimps-1"));
        assert!(!is_validator_check("cluster_stalled"));
    }
}

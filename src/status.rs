//! `perch status` -- what is true right now, and why.
//!
//! Grafana answers "what happened over the last week". It cannot answer "why is
//! this check not firing *right now*", because that depends on live state:
//! which endpoints answered, what is inhibiting what, how much observed time a
//! check has banked toward its hold-down. Answering that from logs means
//! grepping; this prints it.
//!
//! Read-only by construction: it runs one probe, reads the state file, and
//! writes nothing. Running it during an incident cannot perturb the incident.

use crate::{
    checks::{self, CheckOutcome, DiskHistory},
    config::{Alerting, Config, Severity},
    inhibit,
    node_exporter::{Host, HostSnapshot},
    peer::{Peer, PeerStatus},
    persist,
    rpc::Endpoint,
    snapshot::{self, Snapshot},
    state::{self, BlindnessState, CheckState},
    verdict::Verdict,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    io::IsTerminal,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Style {
    on: bool,
}

impl Style {
    fn new(force_no_color: bool) -> Self {
        // Respect the NO_COLOR convention, and never emit escapes into a pipe.
        let on = !force_no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal();
        Self { on }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
}

fn secs(d: Duration) -> String {
    humantime::format_duration(Duration::from_secs(d.as_secs())).to_string()
}

pub async fn run(
    config: &Config,
    endpoints: &[Endpoint],
    hosts: &[Host],
    peers: &[Peer],
    no_color: bool,
) -> Result<()> {
    let s = Style::new(no_color);

    // Reuse persisted progress so the stall checks have their baselines; without
    // it every progress check would read "establishing baseline" and tell us
    // nothing.
    let state_path = Path::new(&config.state.file);
    let mut progress = checks::Progress::default();
    let mut disk = DiskHistory::default();
    let mut blindness = BlindnessState::default();
    let restored = persist::load(state_path, &mut progress, &mut disk, &mut blindness);

    let known = HashMap::new();
    let snapshots: Vec<Snapshot> = futures::future::join_all(
        endpoints.iter().map(|e| snapshot::probe(e, config, &known)),
    )
    .await;

    let host_snapshots: Vec<HostSnapshot> =
        futures::future::join_all(hosts.iter().map(|h| h.scrape())).await;
    let peer_statuses: Vec<PeerStatus> =
        futures::future::join_all(peers.iter().map(|p| p.poll())).await;

    let mut outcomes = checks::evaluate(&snapshots, config, &mut progress);
    // A read-only view: the disk history is not written back, so running status
    // cannot disturb the running daemon's projections.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    outcomes.extend(checks::evaluate_disk(
        &host_snapshots,
        config,
        &mut disk,
        now_unix,
    ));
    outcomes.extend(checks::evaluate_nodes(&snapshots, config));
    // One-shot, so a fresh fetch is what the daemon would have cached.
    // Unreachable means the check reads Unknown here too, never absent.
    let sfdp = match (config.checks.sfdp_version.base.enabled, config.watchtower.sfdp_cluster()) {
        (true, Some(cluster)) => match crate::sfdp::Fetcher::new() {
            Ok(f) => f.fetch(cluster).await.ok(),
            Err(_) => None,
        },
        _ => None,
    };
    outcomes.extend(checks::evaluate_sfdp(&snapshots, config, sfdp.as_ref()));
    outcomes.extend(checks::evaluate_peers(
        &peer_statuses,
        &snapshots,
        config,
        config.peering.stale_after,
        &HashMap::new(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    ));
    let suppressed = inhibit::compute(&outcomes);

    let usable = snapshots.iter().filter(|sn| sn.is_usable()).count();
    let visible = usable >= config.quorum.min_definite;

    println!(
        "{} {}  {}",
        s.bold("perch"),
        crate::BUILD,
        s.dim(&config.watchtower.name)
    );

    if let Some(info) = snapshots
        .iter()
        .filter_map(|sn| sn.epoch_info.as_ref())
        .max_by_key(|e| e.absolute_slot)
    {
        if info.slots_in_epoch > 0 {
            println!(
                "Epoch {}, {:.1}% complete (slot {})",
                info.epoch,
                info.epoch_percent(),
                info.absolute_slot
            );
        } else {
            println!("Epoch {}, slot {}", info.epoch, info.absolute_slot);
        }
    }
    println!();

    print_endpoints(&s, &snapshots, config, usable, visible);
    if !host_snapshots.is_empty() {
        println!();
        print_hosts(&s, &host_snapshots, config);
    }
    if !peer_statuses.is_empty() {
        println!();
        print_peers(&s, &peer_statuses, config);
    }
    println!();
    if print_vote_accounts(&s, &snapshots, config) {
        println!();
    }
    print_checks(&s, &outcomes, &restored.states, &suppressed);
    println!();
    print_footer(&s, config, state_path, &restored);

    Ok(())
}

fn print_endpoints(
    s: &Style,
    snapshots: &[Snapshot],
    config: &Config,
    usable: usize,
    visible: bool,
) {
    println!("{}", s.bold("ENDPOINTS"));

    let best = snapshots
        .iter()
        .filter_map(|sn| sn.epoch_info.as_ref().map(|e| e.absolute_slot))
        .max();

    let width = snapshots
        .iter()
        .map(|sn| sn.endpoint.len())
        .max()
        .unwrap_or(8);

    for sn in snapshots {
        match (&sn.epoch_info, best) {
            (Some(info), Some(best)) => {
                let lag = best.saturating_sub(info.absolute_slot);
                let stale = lag > config.quorum.max_endpoint_lag_slots;
                let note = if stale {
                    s.red(&format!("STALE, {lag} slots behind \u{2014} answers discarded"))
                } else if lag > 0 {
                    s.dim(&format!("{lag} slots behind"))
                } else {
                    s.dim("current")
                };
                println!(
                    "  {} {:width$}  slot {}  {}",
                    s.green("ok  "),
                    sn.endpoint,
                    info.absolute_slot,
                    note,
                    width = width
                );
            }
            _ => {
                let reason = sn
                    .config_errors
                    .first()
                    .map(|e| format!("config: {e}"))
                    .or_else(|| sn.transient_errors.first().map(|e| e.to_string()))
                    .unwrap_or_else(|| "no answer".into());
                let reason: String = reason.chars().take(70).collect();
                println!(
                    "  {} {:width$}  {}",
                    s.red("DOWN"),
                    sn.endpoint,
                    s.dim(&reason),
                    width = width
                );
            }
        }
    }

    let summary = format!(
        "{usable}/{} usable, {} needed",
        snapshots.len(),
        config.quorum.min_definite
    );
    println!();
    if visible {
        println!("  visibility: {}  {}", s.green("OK"), s.dim(&summary));
    } else {
        println!(
            "  visibility: {}  {}",
            s.red("BLIND"),
            s.dim(&format!("{summary} \u{2014} all checks are frozen"))
        );
    }
}

/// Alpenglow admission per validator. Returns whether anything was printed.
///
/// Shown whether or not anything is wrong: the runway is the number to watch
/// between alerts, and before Alpenglow is scheduled it is what *would* happen.
fn print_vote_accounts(s: &Style, snapshots: &[Snapshot], config: &Config) -> bool {
    use crate::alpenglow::{requirement, runway, Bls, Phase};
    let Some((cluster, pos)) = snapshots
        .iter()
        .filter_map(|sn| Some((sn.alpenglow.as_ref()?, checks::position(sn)?)))
        .filter(|(_, p)| p.slots_in_epoch > 0)
        .max_by_key(|(_, p)| p.absolute_slot)
    else {
        return false;
    };
    let req = requirement(cluster, &pos);
    let sol = |l: u64| l as f64 / 1e9;
    let phase = match req.phase {
        Phase::NotScheduled => "Alpenglow not scheduled",
        Phase::ActivatesAtNextBoundary => "Alpenglow ACTIVATES at the next boundary",
        Phase::Active => "Alpenglow active",
    };
    println!("{}", s.bold("VOTE ACCOUNTS"));
    println!(
        "  {}",
        s.dim(&format!(
            "{phase} · VAT {:.2} SOL/epoch · each needs {:.4} SOL at the start of epoch {} (in ~{:.0}h)",
            sol(req.vat_lamports),
            sol(req.minimum_lamports()),
            req.checked_at_epoch,
            req.hours_until_check()
        ))
    );
    let width = config.validators.iter().map(|v| v.display().len()).max().unwrap_or(12);
    let warn_epochs = config.checks.vote_admission.warn_epochs;
    for v in &config.validators {
        let Some(vote) = snapshots
            .iter()
            .filter_map(|sn| sn.vote_states.get(&v.identity))
            .max_by_key(|vs| vs.lamports)
        else {
            println!("  {} {:width$}  {}", s.dim("?     "), v.display(), s.dim("vote account not observed"));
            continue;
        };
        let run = runway(vote, &req, checks::income_for(snapshots, &v.identity));
        let marker = if vote.bls == Bls::Missing {
            s.red("NO KEY")
        } else if vote.lamports < req.minimum_lamports() {
            s.red("SHORT ")
        } else if run.boundaries.is_some_and(|n| n < warn_epochs) {
            s.yellow("LOW   ")
        } else {
            s.green("ok    ")
        };
        let story = if req.phase == Phase::NotScheduled {
            run.describe_hypothetically(&req)
        } else {
            run.describe(&req)
        };
        let key = match vote.bls {
            Bls::Registered => "BLS ok",
            Bls::Missing => "no BLS key",
            Bls::NotReported => "BLS ?",
        };
        println!(
            "  {marker} {:width$}  {:>10.4} SOL  {:10}  {}",
            v.display(),
            sol(vote.lamports),
            key,
            s.dim(&story)
        );
    }
    true
}

fn print_hosts(s: &Style, snapshots: &[HostSnapshot], config: &Config) {
    println!("{}", s.bold("DISKS"));

    let width = snapshots
        .iter()
        .flat_map(|h| h.filesystems.keys().map(|m| h.host.len() + m.len() + 1))
        .max()
        .unwrap_or(16)
        .max(16);

    for snap in snapshots {
        if let Some(err) = &snap.error {
            let err: String = err.chars().take(60).collect();
            println!("  {} {:width$}  {}", s.red("DOWN"), snap.host, s.dim(&err), width = width);
            continue;
        }

        let mut mounts: Vec<_> = snap.filesystems.values().collect();
        mounts.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));

        for fs in mounts {
            let label = format!("{} {}", snap.host, fs.mountpoint);
            let used = fs.used_percent();
            let avail = fs.avail_gb();

            // Use the same size-capped floor the check uses, or a 1 GB /boot
            // renders as FULL while the check correctly reports it healthy.
            let ds = &config.checks.disk_space;
            let page_floor = ds.effective_floor(ds.page_free_gb, fs.size_gb());
            let warn_floor = ds.effective_floor(ds.warn_free_gb, fs.size_gb());
            let marker = if fs.readonly {
                s.red("RO  ")
            } else if avail < page_floor {
                s.red("FULL")
            } else if avail < warn_floor {
                s.yellow("LOW ")
            } else {
                s.green("ok  ")
            };

            let mut detail = format!(
                "{avail:>7.1} GB free of {:>6.0} GB  {used:>5.1}% used",
                fs.size_gb()
            );
            if fs.inodes_total > 0 {
                detail.push_str(&format!("  {:.1}% inodes", fs.inodes_used_percent()));
            }
            if fs.readonly {
                detail.push_str("  READ-ONLY");
            }
            println!("  {} {:width$}  {}", marker, label, s.dim(&detail), width = width);
        }
    }
}

fn print_peers(s: &Style, peers: &[PeerStatus], config: &Config) {
    println!("{}", s.bold("PEERS"));
    let stale = config.peering.stale_after;
    let width = peers.iter().map(|p| p.name.len()).max().unwrap_or(12).max(12);

    let mut sorted: Vec<&PeerStatus> = peers.iter().collect();
    sorted.sort_by_key(|p| p.priority);

    for p in &sorted {
        let live = p.is_live(stale);
        let marker = if live { s.green("ok  ") } else { s.red("DOWN") };
        println!(
            "  {} {:width$}  {}  {}",
            marker,
            p.name,
            s.dim(&format!("pri {}", p.priority)),
            s.dim(&p.describe(stale)),
            width = width
        );
    }

    println!();
    match config.peering.alerting {
        Alerting::Never => {
            println!(
                "  alerting:   {}  {}",
                s.dim("never"),
                s.dim("data source only; the hub notifies")
            );
            return;
        }
        Alerting::Peers => {
            let hub_down = sorted
                .iter()
                .any(|p| p.priority < config.peering.priority && !p.is_live(stale));
            let note = if hub_down {
                s.red("a higher-priority peer is DOWN and will be reported")
            } else {
                s.dim("peer liveness only; the hub owns everything else")
            };
            println!("  alerting:   {}  {}", s.dim("peers only"), note);
            return;
        }
        Alerting::Always => {
            let hub_down = sorted
                .iter()
                .any(|p| p.priority < config.peering.priority && !p.is_live(stale));
            let note = if hub_down {
                s.red("a peer is DOWN and will be reported")
            } else {
                s.dim("this instance owns alerting for everything it watches")
            };
            println!("  alerting:   {}  {}", s.green("OWN SCOPE"), note);
            return;
        }
        Alerting::Auto => {}
    }

    // Who is alerting matters more than any individual peer's state: if this is
    // wrong, alerts are either duplicated or nobody is sending them.
    let outranking_live = sorted
        .iter()
        .any(|p| p.priority < config.peering.priority && p.is_live(stale));
    if outranking_live {
        let owner = sorted
            .iter()
            .filter(|p| p.priority < config.peering.priority && p.is_live(stale))
            .min_by_key(|p| p.priority)
            .map(|p| p.name.as_str())
            .unwrap_or("?");
        println!(
            "  alerting:   {}  {}",
            s.dim("standby"),
            s.dim(&format!("{owner} is the alerting instance"))
        );
    } else {
        println!(
            "  alerting:   {}  {}",
            s.green("THIS INSTANCE"),
            s.dim(&format!(
                "priority {}, nothing live outranks it",
                config.peering.priority
            ))
        );
    }
}

fn print_checks(
    s: &Style,
    outcomes: &[CheckOutcome],
    states: &HashMap<String, CheckState>,
    suppressed: &HashMap<String, String>,
) {
    println!("{}", s.bold("CHECKS"));

    let width = outcomes.iter().map(|o| o.id.len()).max().unwrap_or(20);
    let mut rows: Vec<&CheckOutcome> = outcomes.iter().collect();
    // Most interesting first: problems, then inconclusive, then healthy.
    rows.sort_by_key(|o| match &o.verdict {
        Verdict::Unhealthy(_) => 0,
        Verdict::Unknown(_) => 1,
        Verdict::Healthy => 2,
    });

    for o in rows {
        let st = states.get(&o.id);
        let firing = st.map(|s| s.is_firing()).unwrap_or(false);
        let banked = st.map(|s| s.unhealthy_for()).unwrap_or(Duration::ZERO);

        let (label, detail) = if let Some(cause) = suppressed.get(&o.id) {
            (
                s.dim("MUTED "),
                s.dim(&format!("explained by {cause}")),
            )
        } else if firing {
            (
                s.red("FIRING"),
                format!(
                    "{} {}",
                    o.verdict.detail().unwrap_or("-"),
                    s.dim(&format!("(for {})", secs(banked)))
                ),
            )
        } else {
            match &o.verdict {
                Verdict::Unhealthy(d) => {
                    let remaining = o.cfg.pending_for.saturating_sub(banked);
                    (
                        s.yellow("ARMING"),
                        format!(
                            "{d} {}",
                            s.dim(&format!(
                                "({} of {} banked, fires in ~{})",
                                secs(banked),
                                secs(o.cfg.pending_for),
                                secs(remaining)
                            )),
                        ),
                    )
                }
                Verdict::Unknown(r) => {
                    let r: String = r.chars().take(64).collect();
                    // Warm-up is not the same as blindness; showing both as
                    // FROZEN makes a healthy new install look broken.
                    if o.warming_up {
                        (s.dim("WARMUP"), s.dim(&r))
                    } else {
                        (s.dim("FROZEN"), s.dim(&r))
                    }
                }
                Verdict::Healthy => (
                    s.green("ok    "),
                    s.dim(&format!("{} endpoint(s) agree", o.tally.healthy)),
                ),
            }
        };

        let tier = match o.cfg.severity {
            Severity::Page => "page",
            Severity::Notify => "notify",
            Severity::Log => "log",
        };

        println!(
            "  {} {:width$}  {:6}  {}",
            label,
            o.id,
            s.dim(tier),
            detail,
            width = width
        );
    }
}

fn print_footer(s: &Style, config: &Config, state_path: &Path, restored: &persist::Restored) {
    match config.silence.file.as_deref() {
        Some(path) if state::silence_active(Some(path), chrono::Utc::now()) => {
            let until = std::fs::read_to_string(path).unwrap_or_default();
            let until = until.trim();
            let detail = if until.is_empty() {
                "open-ended \u{2014} remove the file to restore paging".to_string()
            } else {
                format!("until {until}")
            };
            println!(
                "{}    {} {}",
                s.bold("SILENCE"),
                s.yellow("ACTIVE"),
                s.dim(&detail)
            );
        }
        _ => println!("{}    {}", s.bold("SILENCE"), s.dim("none")),
    }

    let age = std::fs::metadata(state_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok());

    let state_note = match age {
        Some(age) => format!(
            "{} ({} check(s), written {} ago)",
            state_path.display(),
            restored.states.len(),
            secs(age)
        ),
        None => format!("{} (not written yet)", state_path.display()),
    };
    println!("{}      {}", s.bold("STATE"), s.dim(&state_note));

    let announced = restored.announced.len();
    if announced > 0 {
        println!(
            "{}  {}",
            s.bold("ANNOUNCED"),
            s.dim(&format!("{announced} open incident(s)"))
        );
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_is_inert_when_disabled() {
        let s = Style { on: false };
        assert_eq!(s.red("boom"), "boom");
        assert_eq!(s.green("ok"), "ok");
    }

    #[test]
    fn style_wraps_when_enabled() {
        let s = Style { on: true };
        assert_eq!(s.red("x"), "\x1b[31mx\x1b[0m");
    }

    #[test]
    fn durations_render_without_subsecond_noise() {
        assert_eq!(secs(Duration::from_millis(125_600)), "2m 5s");
        assert_eq!(secs(Duration::ZERO), "0s");
    }
}

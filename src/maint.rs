//! `perch maint`: declare planned work from the command line.
//!
//! This used to be a shell script with the silence path written into it, which
//! is how a maintenance command ended up printing "paging suppressed" while
//! writing to a file the watchtower never read. The path now comes from the same
//! config the daemon loads, so the two cannot disagree.

use crate::state::{read_silence, ClusterPhase, Silence};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Show,
    Off,
    /// Suppress until the validator recovers, or the deadline.
    Restart(Duration),
    /// Plain timed silence.
    For(Duration),
    /// Hold everything through a coordinated cluster restart, until the
    /// cluster produces blocks again and the validator recovers, or the
    /// deadline.
    ClusterRestart(Duration),
}

const DEFAULT_RESTART_WINDOW: Duration = Duration::from_secs(3600);
/// Cluster restarts wait on a supermajority of stake coming back, which on
/// testnet has taken most of a day.
const DEFAULT_CLUSTER_RESTART_WINDOW: Duration = Duration::from_secs(12 * 3600);

pub fn parse(args: &[String]) -> Result<Action> {
    let dur = |s: &str| {
        humantime::parse_duration(s)
            .with_context(|| format!("{s:?} is not a duration (try 30m, 2h)"))
    };
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(Action::Show),
        ["off" | "clear" | "end"] => Ok(Action::Off),
        ["restart" | "auto"] => Ok(Action::Restart(DEFAULT_RESTART_WINDOW)),
        ["restart" | "auto", d] => Ok(Action::Restart(dur(d)?)),
        ["cluster-restart" | "cluster"] => Ok(Action::ClusterRestart(DEFAULT_CLUSTER_RESTART_WINDOW)),
        ["cluster-restart" | "cluster", d] => Ok(Action::ClusterRestart(dur(d)?)),
        [d] => Ok(Action::For(dur(d)?)),
        _ => bail!("usage: perch maint [restart [DURATION] | cluster-restart [DURATION] | DURATION | off]"),
    }
}

/// What goes in the silence file; the format `read_silence` parses.
pub fn contents(action: &Action, now: DateTime<Utc>) -> Option<String> {
    let until = |d: &Duration| {
        (now + chrono::Duration::from_std(*d).unwrap_or(chrono::Duration::hours(1)))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    match action {
        Action::Restart(d) => Some(format!("auto {}\n", until(d))),
        Action::For(d) => Some(format!("{}\n", until(d))),
        Action::ClusterRestart(d) => Some(format!("cluster {}\n", until(d))),
        Action::Show | Action::Off => None,
    }
}

/// `[silence] file` and nothing else. Reading the whole config would resolve
/// every `env:` secret, and the person typing `perch maint` is usually not the
/// one allowed to read them.
pub fn silence_file_from(config: &std::path::Path) -> Result<Option<String>> {
    let raw = std::fs::read_to_string(config)
        .with_context(|| format!("reading config {}", config.display()))?;
    let doc: toml::Table =
        toml::from_str(&raw).with_context(|| format!("parsing config {}", config.display()))?;
    Ok(doc
        .get("silence")
        .and_then(|s| s.get("file"))
        .and_then(|f| f.as_str())
        .map(str::to_string))
}

pub fn describe(silence: &Silence) -> String {
    match silence {
        Silence::None => "paging armed".into(),
        Silence::Until(t) => format!("SILENCED until {}", t.format("%Y-%m-%dT%H:%M:%SZ")),
        Silence::UntilRecovered { deadline } => format!(
            "MAINTENANCE: waiting for the validator to recover (deadline {})",
            deadline.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        Silence::ClusterRestart { deadline, phase } => format!(
            "CLUSTER RESTART: {} (deadline {})",
            match phase {
                ClusterPhase::Running => "waiting for the cluster to halt",
                ClusterPhase::Halted => "cluster halted, waiting for it to produce blocks again",
                ClusterPhase::Restarted => "cluster producing again, waiting for the validator to recover",
            },
            deadline.format("%Y-%m-%dT%H:%M:%SZ")
        ),
    }
}

/// Declares or clears the window and prints the result. Returns the deadline
/// of a window this call opened, for `confirm_with_peers`.
pub fn run(silence_file: Option<&str>, args: &[String]) -> Result<Option<DateTime<Utc>>> {
    let action = parse(args)?;
    let Some(path) = silence_file else {
        bail!(
            "[silence] file is not set in the config, so perch has nowhere to read a \
             maintenance window from. Set it (e.g. /var/lib/perch/maint/silence) and \
             restart perch."
        );
    };
    let now = Utc::now();
    match &action {
        Action::Show => {}
        Action::Off => match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {path}")),
        },
        Action::Restart(_) | Action::For(_) | Action::ClusterRestart(_) => {
            let body = contents(&action, now).unwrap_or_default();
            write_silence(path, &body)
                .with_context(|| format!("writing {path} (is this user in the perch group?)"))?;
        }
    }

    // Read back through the daemon's own parser, so what is printed is what
    // perch will act on rather than what we meant to write.
    let state = read_silence(Some(path), now);
    println!("{}", describe(&state));
    if matches!(action, Action::Restart(_)) {
        println!(
            "Paging is suppressed. Monitoring resumes by itself once the validator is \
             voting and healthy again, or at the deadline; Telegram tells you either way."
        );
    }
    if matches!(action, Action::ClusterRestart(_)) {
        println!(
            "Every alert is held. Telegram says when the cluster halts, when the validator \
             waits for and reaches supermajority, and when it produces blocks again. \
             Monitoring resumes once this validator is voting and healthy, or at the \
             deadline, which is extended while the validator waits if [diagnose] log is set."
        );
    }
    Ok(match action {
        Action::Restart(_) | Action::For(_) | Action::ClusterRestart(_) => state.deadline(),
        Action::Show | Action::Off => None,
    })
}

/// The other instances this one is configured to watch, and the name they
/// know it by: `[peering] name` and each `[[peers]]` name and url. Like
/// `silence_file_from`, read without resolving a single secret.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Watchers {
    pub name: Option<String>,
    pub peers: Vec<(String, String)>,
}

pub fn watchers_from(config: &std::path::Path) -> Result<Watchers> {
    let raw = std::fs::read_to_string(config)
        .with_context(|| format!("reading config {}", config.display()))?;
    let doc: toml::Table =
        toml::from_str(&raw).with_context(|| format!("parsing config {}", config.display()))?;
    let text = |t: &toml::Value, key: &str| t.get(key).and_then(|v| v.as_str()).map(str::to_string);
    Ok(Watchers {
        name: doc.get("peering").and_then(|p| text(p, "name")),
        peers: doc
            .get("peers")
            .and_then(|p| p.as_array())
            .map(|peers| {
                peers
                    .iter()
                    .filter_map(|p| Some((text(p, "name")?, text(p, "url")?)))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// What a peer's metrics page says about a window this instance declared.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerView {
    /// It holds the window, so this machine going silent will not page there.
    Recorded,
    /// It would say so, and has not yet.
    NotYet,
    /// It does not report the windows it holds: a perch from before 1.5.3,
    /// or one that watches no peers at all.
    CannotSay,
    /// It watches other instances, and none by this one's name.
    NotWatching,
}

/// Read a peer's exposition for the window ending at `deadline` (unix).
///
/// A peer files the window under its own `[[peers]] name` for this instance,
/// which is `[peering] name` here when both are set as documented. A series
/// carrying exactly this deadline is accepted whatever its label, so a name
/// that differs between the two configs does not turn into a wait that can
/// never end. A later deadline under this name also counts: a cluster-restart
/// window is extended while the validator waits.
pub fn peer_view(exposition: &str, me: Option<&str>, deadline: u64) -> PeerView {
    use crate::node_exporter::parse_line;
    let mut declared = exposition.contains("# TYPE perch_peer_maintenance_until_seconds ");
    let mut watched: Vec<String> = Vec::new();
    for line in exposition.lines() {
        let Some((name, labels, value)) = parse_line(line) else { continue };
        let peer = labels.get("peer").map(String::as_str);
        match name.as_str() {
            "perch_peer_maintenance_until_seconds" => {
                declared = true;
                let until = value as u64;
                if until == deadline || (me.is_some() && peer == me && until > deadline) {
                    return PeerView::Recorded;
                }
            }
            "perch_peer_reachable" => watched.extend(peer.map(str::to_string)),
            _ => {}
        }
    }
    if !declared {
        return PeerView::CannotSay;
    }
    match me {
        Some(me) if !watched.is_empty() && !watched.iter().any(|w| w == me) => PeerView::NotWatching,
        _ => PeerView::NotYet,
    }
}

/// A window travels from the silence file to this machine's perch (its next
/// cycle), and from there to each peer (that peer's next cycle). Two default
/// 60-second cycles and their run time fit in this with room to spare.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(180);
const CONFIRM_POLL: Duration = Duration::from_secs(3);

/// Wait until every peer that watches this instance holds the window.
///
/// On 2026-11-23 refi-main was rebooted seconds after `perch maint restart`.
/// The silence file was written, but the box went down before its perch ran
/// another cycle, so the hub never heard of the window and paged a dead
/// machine. Declaring a window and it being known where it matters are two
/// events; this closes the gap by not returning until the second has happened,
/// and fails when it does not, so `perch maint restart && sudo reboot` stops.
pub async fn confirm_with_peers(watchers: &Watchers, deadline: DateTime<Utc>, within: Duration) -> Result<()> {
    if watchers.peers.is_empty() {
        return Ok(());
    }
    let deadline = deadline.timestamp().max(0) as u64;
    let me = watchers.name.as_deref();
    let mut waiting: Vec<crate::peer::Peer> = watchers
        .peers
        .iter()
        .map(|(name, url)| crate::peer::Peer::new(name.clone(), url.clone(), 0, None, Duration::from_secs(5)))
        .collect::<Result<_>>()?;
    println!(
        "Waiting for {} to record this window, so that this machine going down is not \
         reported as a dead one (up to {}). Ctrl-C stops the wait; the window stays.",
        waiting.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "),
        humantime::format_duration(within),
    );

    let started = std::time::Instant::now();
    let mut last_seen: std::collections::HashMap<String, String> = Default::default();
    let (mut recorded, mut unconfirmed) = (0, false);
    loop {
        let mut still = Vec::new();
        for p in waiting {
            match p.fetch().await.map(|text| peer_view(&text, me, deadline)) {
                Ok(PeerView::Recorded) => {
                    recorded += 1;
                    println!("{} has recorded it.", p.name);
                }
                Ok(PeerView::CannotSay) => {
                    unconfirmed = true;
                    println!(
                        "{} does not report the windows it holds (a perch older than 1.5.3?), so \
                         it cannot confirm. Give it two minutes before taking this machine down.",
                        p.name
                    );
                }
                Ok(PeerView::NotWatching) => println!(
                    "{} does not watch this instance ({}), so it has nothing to record.",
                    p.name,
                    me.unwrap_or("?")
                ),
                Ok(PeerView::NotYet) => {
                    last_seen.insert(p.name.clone(), "answers, but has not recorded the window".into());
                    still.push(p);
                }
                Err(e) => {
                    last_seen.insert(p.name.clone(), format!("unreachable: {e}"));
                    still.push(p);
                }
            }
        }
        waiting = still;
        if waiting.is_empty() {
            if recorded > 0 && !unconfirmed {
                println!("Safe to take this machine down.");
            }
            return Ok(());
        }
        if started.elapsed() >= within {
            let why: Vec<String> = waiting
                .iter()
                .map(|p| format!("{} ({})", p.name, last_seen.get(&p.name).map(String::as_str).unwrap_or("no answer")))
                .collect();
            bail!(
                "the window is set here, but after {} it is not recorded by: {}. If this machine \
                 goes down now, that instance may page for it. Is perch running on this machine?",
                humantime::format_duration(within),
                why.join(", ")
            );
        }
        tokio::time::sleep(CONFIRM_POLL).await;
    }
}

/// Write the silence file without following a symlink at its path.
///
/// The maintenance directory is group-writable so operators can declare
/// windows, and perch itself rewrites the file to record a cluster restart's
/// stage. A link planted there must not turn either write into a write
/// somewhere else. Removing first and creating exclusively never follows a
/// link, and the mode is set explicitly so the daemon's umask does not leave
/// a file the operators' `perch maint` cannot read.
pub fn write_silence(path: &str, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o660))?;
    f.write_all(body.as_bytes())
}

/// Whether a config found on another process's command line may be trusted:
/// owned by root or by the user running this command, and not world-writable.
/// Anyone with an account on the box can run something called
/// `perch --config /tmp/theirs.toml`; this is what keeps that from choosing
/// where an operator's `perch maint` writes.
fn trusted_config(path: &std::path::Path, my_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .map(|m| (m.uid() == 0 || m.uid() == my_uid) && m.mode() & 0o002 == 0)
        .unwrap_or(false)
}

/// The uid this process runs as, read from `/proc/self`.
fn my_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// The `--config` a perch command line was started with: `--config PATH`,
/// `--config=PATH`, `-c PATH` or `-cPATH`.
pub fn config_arg(argv: &[String]) -> Option<std::path::PathBuf> {
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--config" || a == "-c" {
            return it.next().map(std::path::PathBuf::from);
        }
        if let Some(p) = a.strip_prefix("--config=") {
            return Some(p.into());
        }
        if let Some(p) = a.strip_prefix("-c").filter(|p| !p.is_empty() && !a.starts_with("--")) {
            return Some(p.into());
        }
    }
    None
}

/// The config every running perch agrees on, if they do. Two watchtowers on
/// one box with different configs leave the choice to `--config`.
pub fn agreed_config(found: Vec<std::path::PathBuf>) -> Result<Option<std::path::PathBuf>> {
    let mut found = found;
    found.sort();
    found.dedup();
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => bail!(
            "several perch instances are running with different configs ({}); say which with --config",
            found.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// The config of the perch already running on this machine, read from its
/// command line, so `perch maint` and `perch status` need no `--config`. The
/// live boxes run `/home/sol/bin/perch --config /home/sol/perch/config.toml`,
/// where the install default does not apply. Linux only; elsewhere, nothing.
pub fn running_config() -> Result<Option<std::path::PathBuf>> {
    let me = std::process::id().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else { return Ok(None) };
    let Some(uid) = my_uid() else { return Ok(None) };
    let mut found = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) || name == me {
            continue;
        }
        let Ok(raw) = std::fs::read(e.path().join("cmdline")) else { continue };
        let argv: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).to_string())
            .collect();
        let is_perch = argv
            .first()
            .and_then(|a| std::path::Path::new(a).file_name())
            .is_some_and(|n| n == "perch");
        // A `perch maint` or `perch status` someone else is running is not the
        // watchtower; only one with no subcommand is.
        let is_daemon = !argv.iter().skip(1).any(|a| matches!(a.as_str(), "maint" | "status" | "test-notify"));
        if !is_perch || !is_daemon {
            continue;
        }
        if let Some(p) = config_arg(&argv) {
            if trusted_config(&p, uid) {
                found.push(p);
            }
        }
    }
    agreed_config(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_every_form() {
        assert_eq!(parse(&args(&[])).unwrap(), Action::Show);
        assert_eq!(parse(&args(&["off"])).unwrap(), Action::Off);
        assert_eq!(
            parse(&args(&["restart"])).unwrap(),
            Action::Restart(Duration::from_secs(3600))
        );
        assert_eq!(
            parse(&args(&["restart", "2h"])).unwrap(),
            Action::Restart(Duration::from_secs(7200))
        );
        assert_eq!(
            parse(&args(&["30m"])).unwrap(),
            Action::For(Duration::from_secs(1800))
        );
        assert_eq!(
            parse(&args(&["cluster-restart"])).unwrap(),
            Action::ClusterRestart(Duration::from_secs(12 * 3600))
        );
        assert_eq!(
            parse(&args(&["cluster-restart", "8h"])).unwrap(),
            Action::ClusterRestart(Duration::from_secs(8 * 3600))
        );
        assert!(parse(&args(&["restart", "soon"])).is_err());
        assert!(parse(&args(&["a", "b", "c"])).is_err());
    }

    /// Whatever this writes, the daemon's parser must read back as intended. A
    /// format drift here is exactly the "printed suppressed, nothing read it"
    /// failure this subcommand exists to prevent.
    #[test]
    fn what_is_written_is_what_the_daemon_reads() {
        let now = DateTime::parse_from_rfc3339("2026-10-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let path = std::env::temp_dir().join(format!("perch-maint-{}", uuid::Uuid::new_v4()));
        let p = path.to_str().unwrap();

        std::fs::write(
            p,
            contents(&Action::Restart(Duration::from_secs(7200)), now).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_silence(Some(p), now),
            Silence::UntilRecovered {
                deadline: DateTime::parse_from_rfc3339("2026-10-02T14:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            }
        );

        std::fs::write(
            p,
            contents(&Action::For(Duration::from_secs(1800)), now).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_silence(Some(p), now),
            Silence::Until(
                DateTime::parse_from_rfc3339("2026-10-02T12:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );

        std::fs::write(
            p,
            contents(&Action::ClusterRestart(Duration::from_secs(8 * 3600)), now).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_silence(Some(p), now),
            Silence::ClusterRestart {
                deadline: DateTime::parse_from_rfc3339("2026-10-02T20:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                phase: ClusterPhase::Running,
            }
        );
        std::fs::remove_file(p).unwrap();
    }

    const HUB: &str = "\
# HELP perch_peer_reachable 1 when the peer's metrics endpoint answered
# TYPE perch_peer_reachable gauge
perch_peer_reachable{peer=\"refi-main\"} 1
perch_peer_reachable{peer=\"fox-main\"} 1
# HELP perch_peer_maintenance_until_seconds Unix deadline
# TYPE perch_peer_maintenance_until_seconds gauge
";

    /// The 2026-11-23 page: the hub answered, and had not heard of the window.
    #[test]
    fn a_peer_that_has_not_heard_of_the_window_is_not_yet() {
        assert_eq!(peer_view(HUB, Some("refi-main"), 1_795_455_396), PeerView::NotYet);
        // Another peer's window is not ours.
        let other = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"fox-main\"}} 1795459999\n");
        assert_eq!(peer_view(&other, Some("refi-main"), 1_795_455_396), PeerView::NotYet);
        // Nor is an older window of our own that the peer still remembers.
        let stale = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"refi-main\"}} 1795450000\n");
        assert_eq!(peer_view(&stale, Some("refi-main"), 1_795_455_396), PeerView::NotYet);
    }

    #[test]
    fn a_peer_holding_the_window_has_recorded_it() {
        let held = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"refi-main\"}} 1795455396\n");
        assert_eq!(peer_view(&held, Some("refi-main"), 1_795_455_396), PeerView::Recorded);
        // A cluster-restart window the validator's wait has extended.
        let extended = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"refi-main\"}} 1795459000\n");
        assert_eq!(peer_view(&extended, Some("refi-main"), 1_795_455_396), PeerView::Recorded);
    }

    /// The hub calls this box something else, or `[peering] name` is unset:
    /// the exact deadline still identifies the window.
    #[test]
    fn the_exact_deadline_is_recognised_under_any_name() {
        let held = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"refi-main\"}} 1795455396\n");
        assert_eq!(peer_view(&held, Some("refi"), 1_795_455_396), PeerView::Recorded);
        assert_eq!(peer_view(&held, None, 1_795_455_396), PeerView::Recorded);
        // A later deadline under someone else's name is someone else's window.
        let later = format!("{HUB}perch_peer_maintenance_until_seconds{{peer=\"refi-main\"}} 1795459000\n");
        assert_eq!(peer_view(&later, None, 1_795_455_396), PeerView::NotYet);
    }

    /// A 1.5.2 hub would never confirm; waiting three minutes for it on every
    /// restart, and then failing, would teach operators to ignore the wait.
    #[test]
    fn a_peer_that_cannot_report_windows_is_told_apart() {
        let old = "perch_peer_reachable{peer=\"refi-main\"} 1\nperch_maintenance_until_seconds 0\n";
        assert_eq!(peer_view(old, Some("refi-main"), 1_795_455_396), PeerView::CannotSay);
    }

    #[test]
    fn a_peer_that_watches_others_but_not_this_instance_has_nothing_to_record() {
        assert_eq!(peer_view(HUB, Some("salmon-main"), 1_795_455_396), PeerView::NotWatching);
        // Without a name of our own there is no telling, so it is waited for.
        assert_eq!(peer_view(HUB, None, 1_795_455_396), PeerView::NotYet);
        // A peer that watches nobody declares no peer metrics at all.
        assert_eq!(peer_view("perch_visible 1\n", Some("salmon-main"), 1), PeerView::CannotSay);
    }

    #[test]
    fn the_peers_to_ask_come_from_the_config_without_its_secrets() {
        let d = tmpdir();
        let cfg = d.join("config.toml");
        std::fs::write(
            &cfg,
            "[peering]\nname = \"refi-main\"\npriority = 2\n\n\
             [[peers]]\nname = \"failover-hub\"\nurl = \"http://127.0.0.1:19469/metrics\"\npriority = 1\n\n\
             [notify.telegram]\nbot_token = \"env:NOT_SET_ANYWHERE\"\n",
        )
        .unwrap();
        assert_eq!(
            watchers_from(&cfg).unwrap(),
            Watchers {
                name: Some("refi-main".into()),
                peers: vec![("failover-hub".into(), "http://127.0.0.1:19469/metrics".into())],
            }
        );
        std::fs::write(&cfg, "[watchtower]\nname = \"solo\"\n").unwrap();
        assert_eq!(watchers_from(&cfg).unwrap(), Watchers::default());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn with_no_peers_there_is_nothing_to_wait_for() {
        confirm_with_peers(&Watchers::default(), Utc::now(), Duration::from_secs(60)).await.unwrap();
    }

    /// A peer that never confirms fails the command, naming the peer and what
    /// it last said, so `perch maint restart && sudo reboot` does not go on.
    #[tokio::test]
    async fn a_peer_that_never_confirms_fails_the_command() {
        let watchers = Watchers {
            name: Some("refi-main".into()),
            // Nothing listens on port 1.
            peers: vec![("failover-hub".into(), "http://127.0.0.1:1/metrics".into())],
        };
        let err = confirm_with_peers(&watchers, Utc::now(), Duration::ZERO).await.unwrap_err().to_string();
        assert!(err.contains("not recorded by: failover-hub (unreachable"), "{err}");
        assert!(err.contains("the window is set here"), "{err}");
    }

    #[test]
    fn refuses_to_pretend_without_a_silence_path() {
        let err = run(None, &args(&["restart"])).unwrap_err().to_string();
        assert!(err.contains("[silence] file is not set"), "{err}");
    }

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_string).collect()
    }

    /// How the live boxes start it, and the other spellings clap accepts.
    #[test]
    fn the_config_is_read_from_a_command_line() {
        use std::path::PathBuf;
        let want = Some(PathBuf::from("/home/sol/perch/config.toml"));
        assert_eq!(config_arg(&argv("/home/sol/bin/perch --config /home/sol/perch/config.toml")), want);
        assert_eq!(config_arg(&argv("perch --config=/home/sol/perch/config.toml")), want);
        assert_eq!(config_arg(&argv("perch -c /home/sol/perch/config.toml")), want);
        assert_eq!(config_arg(&argv("perch -c/home/sol/perch/config.toml")), want);
        assert_eq!(config_arg(&argv("perch --dry-run")), None);
    }

    #[test]
    fn one_running_config_is_used_and_two_are_refused() {
        use std::path::PathBuf;
        let a = PathBuf::from("/home/sol/perch/config.toml");
        assert_eq!(agreed_config(vec![]).unwrap(), None);
        assert_eq!(agreed_config(vec![a.clone(), a.clone()]).unwrap(), Some(a.clone()), "same config twice is one");
        assert!(agreed_config(vec![a, PathBuf::from("/etc/perch/config.toml")]).is_err());
    }

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("perch-maint-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    /// A link planted at the silence path is replaced, never followed.
    #[test]
    fn writing_the_silence_file_does_not_follow_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir();
        let target = d.join("state.json");
        std::fs::write(&target, "precious").unwrap();
        let link = d.join("silence");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        write_silence(link.to_str().unwrap(), "cluster 2099-01-01T00:00:00Z\n").unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious", "the link target is untouched");
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file(), "a regular file now stands where the link was");
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "cluster 2099-01-01T00:00:00Z\n");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A config is trusted when it belongs to root or to the caller and nobody
    /// else can write it; a stranger's file, or a world-writable one, is not.
    #[test]
    fn only_a_config_the_caller_or_root_owns_is_trusted() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = tmpdir();
        let cfg = d.join("config.toml");
        std::fs::write(&cfg, "[watchtower]\n").unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mine = std::fs::metadata(&cfg).unwrap().uid();

        assert!(trusted_config(&cfg, mine));
        assert!(!trusted_config(&cfg, mine.wrapping_add(1)), "someone else's file");
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!trusted_config(&cfg, mine), "world-writable");
        assert!(!trusted_config(&d.join("missing.toml"), mine));
        std::fs::remove_dir_all(&d).unwrap();
    }
}

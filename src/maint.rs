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

pub fn run(silence_file: Option<&str>, args: &[String]) -> Result<()> {
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
    Ok(())
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

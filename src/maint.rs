//! `perch maint`: declare planned work from the command line.
//!
//! This used to be a shell script with the silence path written into it, which
//! is how a maintenance command ended up printing "paging suppressed" while
//! writing to a file the watchtower never read. The path now comes from the same
//! config the daemon loads, so the two cannot disagree.

use crate::state::{read_silence, Silence};
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
}

const DEFAULT_RESTART_WINDOW: Duration = Duration::from_secs(3600);

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
        [d] => Ok(Action::For(dur(d)?)),
        _ => bail!("usage: perch maint [restart [DURATION] | DURATION | off]"),
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
        Action::Restart(_) | Action::For(_) => {
            let body = contents(&action, now).unwrap_or_default();
            std::fs::write(path, body)
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
    Ok(())
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
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn refuses_to_pretend_without_a_silence_path() {
        let err = run(None, &args(&["restart"])).unwrap_err().to_string();
        assert!(err.contains("[silence] file is not set"), "{err}");
    }
}

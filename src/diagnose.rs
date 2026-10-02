//! Likely causes, read off the box at the moment an alert fires.
//!
//! "chimpions-mainnet is delinquent" says what; the validator's own log usually says
//! why. On 2026-09-30 it said `no route for peer` 231,000 times in four minutes
//! and then `must be routed through 5.187.38.22 which has no known MAC
//! address` -- the uplink had dropped and taken the default route with it. That
//! answer was sitting on disk the whole time the page was going out without it.
//!
//! Only meaningful on the machine the validator runs on, so it is opt-in and
//! scoped to one validator. Two sources:
//!
//! * the tail of the validator log, matched against a short list of signatures
//!   that each point at a cause;
//! * NIC carrier-down counters from `/sys/class/net`, sampled every cycle, so a
//!   link flap is reported even when the validator logged nothing useful.
//!
//! Matched lines are counted, never quoted. Validator logs carry credentials --
//! metrics URLs with passwords in the query string -- and alerts go to Telegram.

use crate::config::DiagnoseConfig;
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{debug, warn};

/// A substring that, when it appears in the validator log, points at a cause.
struct Signature {
    needle: &'static str,
    cause: &'static str,
}

/// Ordered roughly by how conclusive each is. Substring matching on purpose: the
/// messages are stable across Agave releases far more than their surroundings.
const SIGNATURES: &[Signature] = &[
    Signature {
        needle: "panicked at",
        cause: "the validator panicked",
    },
    // Agave's own Alpenglow admission check, logged by replay_stage every few
    // minutes while the vote account would be excluded at the next boundary.
    Signature {
        needle: "VAT Health Check: Currently you will fail the VAT check",
        cause: "the validator's own VAT check says it will be excluded next epoch (vote account balance or BLS key)",
    },
    Signature {
        needle: "No space left on device",
        cause: "a disk is full",
    },
    Signature {
        needle: "Too many open files",
        cause: "the validator ran out of file descriptors",
    },
    Signature {
        needle: "no route for peer",
        cause: "the box had no network route to its peers (default route missing)",
    },
    Signature {
        needle: "which has no known MAC address",
        cause: "the gateway was not answering ARP",
    },
    Signature {
        needle: "Network is unreachable",
        cause: "the network was unreachable",
    },
    Signature {
        needle: "Temporary failure in name resolution",
        cause: "DNS lookups were failing",
    },
    Signature {
        needle: "PoH is slower than cluster target tick rate",
        cause: "PoH fell behind (CPU starved or throttled)",
    },
    Signature {
        needle: "Waiting for supermajority",
        cause: "the validator is waiting for supermajority (cluster restart)",
    },
    Signature {
        needle: "Starting validator with",
        cause: "the validator restarted",
    },
];

#[derive(Debug, Clone, PartialEq)]
pub struct LogFinding {
    pub cause: &'static str,
    pub count: u64,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
}

/// Agave writes `[2026-09-30T06:07:11.261801371Z WARN  target] message`.
/// Continuation lines (a multi-line panic, a debug dump) carry no timestamp.
fn line_time(line: &str) -> Option<DateTime<Utc>> {
    let rest = line.strip_prefix('[')?;
    let stamp = rest.split(' ').next()?;
    DateTime::parse_from_rfc3339(stamp)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Timestamp of the first stamped line at or after `offset`.
fn first_time_from(file: &mut File, offset: u64) -> Option<DateTime<Utc>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut reader = BufReader::new(file.take(64 * 1024));
    let mut buf = Vec::new();
    // Discard the partial line the offset landed in.
    if offset > 0 {
        reader.read_until(b'\n', &mut buf).ok()?;
    }
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf).ok()? == 0 {
            return None;
        }
        if let Some(t) = line_time(&String::from_utf8_lossy(&buf)) {
            return Some(t);
        }
    }
}

/// Byte offset of roughly the first line written at or after `since`, found by
/// bisection so a multi-gigabyte log costs a few dozen small reads, not a scan.
/// Never further back than `max_bytes` from the end.
fn offset_for(file: &mut File, len: u64, since: DateTime<Utc>, max_bytes: u64) -> u64 {
    let mut lo = len.saturating_sub(max_bytes);
    let mut hi = len;
    while hi - lo > 64 * 1024 {
        let mid = lo + (hi - lo) / 2;
        match first_time_from(file, mid) {
            Some(t) if t < since => lo = mid,
            _ => hi = mid,
        }
    }
    lo
}

/// Match the log's recent history against [`SIGNATURES`].
pub fn scan_log(
    path: &Path,
    since: DateTime<Utc>,
    max_bytes: u64,
) -> std::io::Result<Vec<LogFinding>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = offset_for(&mut file, len, since, max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(1 << 20, file.take(len - start));

    let mut found: Vec<Option<LogFinding>> = vec![None; SIGNATURES.len()];
    let mut buf = Vec::new();
    let mut current: Option<DateTime<Utc>> = None;
    if start > 0 {
        reader.read_until(b'\n', &mut buf)?;
    }
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        if let Some(t) = line_time(&line) {
            current = Some(t);
        }
        // An unstamped line belongs to the last stamped one before it.
        let Some(at) = current.filter(|t| *t >= since) else {
            continue;
        };
        for (i, sig) in SIGNATURES.iter().enumerate() {
            if line.contains(sig.needle) {
                let f = found[i].get_or_insert(LogFinding {
                    cause: sig.cause,
                    count: 0,
                    first: at,
                    last: at,
                });
                f.count += 1;
                f.last = at;
            }
        }
    }
    Ok(found.into_iter().flatten().collect())
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkFlap {
    pub interface: String,
    /// Carrier losses seen within the lookback.
    pub recent: u64,
    pub last_unix: u64,
    /// The kernel's count since boot. 478 in 115 days is a cable, an optic or a
    /// switch port, not bad luck.
    pub since_boot: u64,
}

/// Samples carrier-down counters each cycle. The kernel keeps the count but not
/// when it happened, so the timing has to come from watching it change.
pub struct LinkWatch {
    root: PathBuf,
    last: HashMap<String, u64>,
    /// `(interface, unix time first seen, losses in that sample)`.
    events: Vec<(String, u64, u64)>,
}

impl LinkWatch {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            last: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Physical interfaces only. Loopback, bridges, tunnels and veths flap for
    /// reasons that say nothing about the uplink.
    fn read(&self) -> Vec<(String, u64)> {
        let Ok(dir) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in dir.flatten() {
            let path = entry.path();
            if !path.join("device").exists() {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(path.join("carrier_down_count")) else {
                continue;
            };
            if let Ok(n) = raw.trim().parse() {
                out.push((entry.file_name().to_string_lossy().into_owned(), n));
            }
        }
        out
    }

    pub fn sample(&mut self, now_unix: u64, keep: Duration) {
        for (iface, count) in self.read() {
            if let Some(prev) = self.last.insert(iface.clone(), count) {
                if count > prev {
                    self.events.push((iface, now_unix, count - prev));
                }
            }
        }
        let cutoff = now_unix.saturating_sub(keep.as_secs());
        self.events.retain(|(_, at, _)| *at >= cutoff);
    }

    pub fn flaps(&self, since_unix: u64) -> Vec<LinkFlap> {
        let mut by_iface: HashMap<&str, LinkFlap> = HashMap::new();
        for (iface, at, n) in self.events.iter().filter(|(_, at, _)| *at >= since_unix) {
            let f = by_iface.entry(iface).or_insert_with(|| LinkFlap {
                interface: iface.clone(),
                recent: 0,
                last_unix: 0,
                since_boot: self.last.get(iface).copied().unwrap_or(0),
            });
            f.recent += n;
            f.last_unix = f.last_unix.max(*at);
        }
        let mut out: Vec<_> = by_iface.into_values().collect();
        out.sort_by(|a, b| a.interface.cmp(&b.interface));
        out
    }
}

fn hhmm(t: DateTime<Utc>) -> String {
    t.format("%H:%M").to_string()
}

fn span(first: DateTime<Utc>, last: DateTime<Utc>) -> String {
    if hhmm(first) == hhmm(last) {
        hhmm(first)
    } else {
        format!("{}\u{2013}{}", hhmm(first), hhmm(last))
    }
}

/// The alert paragraph, or `None` when nothing matched -- an empty "Likely
/// causes" heading would read as "we looked and it is fine".
pub fn render(
    logs: &[LogFinding],
    flaps: &[LinkFlap],
    lookback: Duration,
    max: usize,
) -> Option<String> {
    let mut lines = Vec::new();
    for f in flaps {
        let when = DateTime::from_timestamp(f.last_unix as i64, 0)
            .map(hhmm)
            .unwrap_or_default();
        lines.push(format!(
            "{} lost link {} time(s), most recently around {when} UTC ({} since boot)",
            f.interface, f.recent, f.since_boot
        ));
    }
    for f in logs {
        lines.push(format!(
            "{}: {} log line(s), {} UTC",
            f.cause,
            f.count,
            span(f.first, f.last)
        ));
    }
    if lines.is_empty() {
        return None;
    }
    lines.truncate(max.max(1));
    Some(format!(
        "Likely causes (this box, last {}):\n{}",
        humantime::format_duration(lookback),
        lines
            .iter()
            .map(|l| format!("- {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

pub struct Diagnoser {
    cfg: DiagnoseConfig,
    links: LinkWatch,
}

impl Diagnoser {
    pub fn new(cfg: DiagnoseConfig) -> Self {
        Self {
            cfg,
            links: LinkWatch::new("/sys/class/net"),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.validator.is_some()
    }

    /// Whether a check's alert should carry a diagnosis. Peer checks describe
    /// another machine, whose logs are not here.
    pub fn applies_to(&self, check_id: &str, owner: Option<&str>) -> bool {
        let Some(validator) = self.cfg.validator.as_deref() else {
            return false;
        };
        if crate::config::is_peer_check(check_id) {
            return false;
        }
        let subject = check_id.split_once(':').map(|(_, s)| s);
        subject == Some(validator) || owner == Some(validator)
    }

    /// Once per cycle. Cheap: a handful of sysfs reads.
    pub fn sample(&mut self, now_unix: u64) {
        if self.enabled() && self.cfg.watch_links {
            self.links
                .sample(now_unix, self.cfg.lookback.saturating_mul(2));
        }
    }

    /// `incident_for` widens the window so a long hold-down does not push the
    /// start of the trouble out of view.
    pub async fn diagnose(&self, now_unix: u64, incident_for: Duration) -> Option<String> {
        let lookback = self
            .cfg
            .lookback
            .max(incident_for.saturating_add(Duration::from_secs(5 * 60)));
        let since_unix = now_unix.saturating_sub(lookback.as_secs());

        let flaps = if self.cfg.watch_links {
            self.links.flaps(since_unix)
        } else {
            Vec::new()
        };

        let logs = match self.cfg.log.clone() {
            None => Vec::new(),
            Some(path) => {
                let since = DateTime::from_timestamp(since_unix as i64, 0).unwrap_or_default();
                let max_bytes = self.cfg.max_scan_mb.saturating_mul(1 << 20);
                let scanned =
                    tokio::task::spawn_blocking(move || scan_log(&path, since, max_bytes)).await;
                match scanned {
                    Ok(Ok(found)) => found,
                    Ok(Err(e)) => {
                        // Usually the systemd sandbox: ProtectHome hides the log
                        // unless it is bind-mounted in.
                        warn!("diagnose: cannot read validator log: {e}");
                        Vec::new()
                    }
                    Err(e) => {
                        warn!("diagnose: log scan did not complete: {e}");
                        Vec::new()
                    }
                }
            }
        };
        debug!(logs = logs.len(), flaps = flaps.len(), "diagnosis gathered");
        render(&logs, &flaps, lookback, self.cfg.max_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn write_log(name: &str, lines: &[String]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("perch-diagnose-{name}-{}", uuid::Uuid::new_v4()));
        let mut f = File::create(&path).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        path
    }

    #[test]
    fn parses_agave_timestamps_and_ignores_continuations() {
        assert_eq!(
            line_time("[2026-09-30T06:07:11.261801371Z WARN  agave_xdp::tx_loop] dropping"),
            Some(t("2026-09-30T06:07:11.261801371Z"))
        );
        assert_eq!(line_time("   at src/main.rs:12"), None);
    }

    /// The shape of a real 2026-09-30 outage, compressed.
    #[test]
    fn finds_the_network_outage_and_counts_it() {
        let mut lines = vec![
            "[2026-09-30T05:40:00.000000000Z INFO  solana_core] no route for peer 1.2.3.4:8001 (too old)".to_string(),
        ];
        for s in 0..50 {
            lines.push(format!(
                "[2026-09-30T06:02:{:02}.000000000Z WARN  agave_xdp::tx_loop] dropping packet: no route for peer 1.2.3.4:8001",
                s
            ));
        }
        lines.push("[2026-09-30T06:07:11.000000000Z WARN  agave_xdp::tx_loop] dropping packet: peer 1.2.3.4:8009 must be routed through 5.187.38.22 which has no known MAC address".into());
        let path = write_log("outage", &lines);

        let found = scan_log(&path, t("2026-09-30T05:50:00Z"), 1 << 30).unwrap();
        let route = found
            .iter()
            .find(|f| f.cause.contains("no network route"))
            .unwrap();
        assert_eq!(
            route.count, 50,
            "the line from before the window must not count"
        );
        assert_eq!(route.first, t("2026-09-30T06:02:00Z"));
        assert!(found.iter().any(|f| f.cause.contains("ARP")));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn an_unstamped_panic_line_is_dated_by_the_line_before_it() {
        let lines = vec![
            "[2026-09-30T06:00:00.000000000Z ERROR solana_metrics] datapoint: panic".to_string(),
            "thread 'solReplayStage' panicked at core/src/replay_stage.rs:1:1:".to_string(),
        ];
        let path = write_log("panic", &lines);
        let found = scan_log(&path, t("2026-09-30T05:59:00Z"), 1 << 30).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].cause, "the validator panicked");
        assert_eq!(found[0].first, t("2026-09-30T06:00:00Z"));
        std::fs::remove_file(path).unwrap();
    }

    /// A multi-gigabyte log must not be read from the start. Bisection lands
    /// near the window; lines before it are skipped either way.
    #[test]
    fn bisection_skips_history_before_the_window() {
        let mut lines = Vec::new();
        for m in 0..60 {
            for s in 0..60 {
                lines.push(format!(
                    "[2026-09-30T05:{m:02}:{s:02}.000000000Z INFO  solana_core] Too many open files padding padding padding padding padding"
                ));
            }
        }
        let path = write_log("bisect", &lines);
        let mut file = File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let since = t("2026-09-30T05:55:00Z");
        let offset = offset_for(&mut file, len, since, u64::MAX);
        assert!(
            offset > len / 2,
            "bisection should land in the last part of the file"
        );
        assert!(first_time_from(&mut file, offset).unwrap() <= since);

        let found = scan_log(&path, since, u64::MAX).unwrap();
        assert_eq!(found[0].count, 5 * 60);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_missing_log_is_an_error_not_a_clean_bill_of_health() {
        assert!(scan_log(Path::new("/nonexistent/perch.log"), Utc::now(), 1 << 20).is_err());
    }

    fn fake_sysfs(ifaces: &[(&str, u64, bool)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("perch-sysfs-{}", uuid::Uuid::new_v4()));
        for (name, count, physical) in ifaces {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if *physical {
                std::fs::create_dir_all(dir.join("device")).unwrap();
            }
            std::fs::write(dir.join("carrier_down_count"), format!("{count}\n")).unwrap();
        }
        root
    }

    #[test]
    fn a_carrier_loss_between_samples_is_reported_with_its_time() {
        let root = fake_sysfs(&[("eno1", 477, true), ("lo", 0, false)]);
        let mut w = LinkWatch::new(&root);
        w.sample(1_000, Duration::from_secs(3600));
        assert!(
            w.flaps(0).is_empty(),
            "the first sample is a baseline, not an event"
        );

        std::fs::write(root.join("eno1/carrier_down_count"), "478\n").unwrap();
        w.sample(1_060, Duration::from_secs(3600));
        assert_eq!(
            w.flaps(0),
            vec![LinkFlap {
                interface: "eno1".into(),
                recent: 1,
                last_unix: 1_060,
                since_boot: 478
            }]
        );
        assert!(w.flaps(1_061).is_empty(), "outside the window");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn virtual_interfaces_are_ignored() {
        let root = fake_sysfs(&[("doublezero0", 1, false)]);
        let mut w = LinkWatch::new(&root);
        w.sample(1_000, Duration::from_secs(3600));
        std::fs::write(root.join("doublezero0/carrier_down_count"), "9\n").unwrap();
        w.sample(1_060, Duration::from_secs(3600));
        assert!(w.flaps(0).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn renders_nothing_when_nothing_matched() {
        assert_eq!(render(&[], &[], Duration::from_secs(1200), 5), None);
    }

    #[test]
    fn renders_flaps_before_log_findings() {
        let logs = [LogFinding {
            cause: "the gateway was not answering ARP",
            count: 4683,
            first: t("2026-09-30T06:00:23Z"),
            last: t("2026-09-30T06:07:11Z"),
        }];
        let flaps = [LinkFlap {
            interface: "eno1".into(),
            recent: 1,
            last_unix: 1_790_748_120,
            since_boot: 478,
        }];
        let out = render(&logs, &flaps, Duration::from_secs(1200), 5).unwrap();
        assert_eq!(
            out,
            "Likely causes (this box, last 20m):\n\
             - eno1 lost link 1 time(s), most recently around 06:02 UTC (478 since boot)\n\
             - the gateway was not answering ARP: 4683 log line(s), 06:00\u{2013}06:07 UTC"
        );
    }

    #[test]
    fn only_this_validators_own_checks_are_diagnosed() {
        let d = Diagnoser::new(DiagnoseConfig {
            validator: Some("chimpions-mainnet".into()),
            ..DiagnoseConfig::default()
        });
        assert!(d.applies_to("vote_delinquent:chimpions-mainnet", None));
        assert!(d.applies_to(
            "disk_space_critical:chimpions-mainnet-hw:/mnt/ledger",
            Some("chimpions-mainnet")
        ));
        assert!(!d.applies_to("vote_delinquent:fox-main", None));
        assert!(!d.applies_to("peer_down:chimpions-mainnet", None));
        assert!(!d.applies_to("machine_down:chimpions-mainnet", Some("chimpions-mainnet")));
        assert!(!Diagnoser::new(DiagnoseConfig::default())
            .applies_to("vote_delinquent:chimpions-mainnet", None));
    }
}

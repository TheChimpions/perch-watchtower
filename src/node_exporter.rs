//! Scraping node_exporter for filesystem state.
//!
//! A full disk is one of the most common ways a validator dies: the ledger and
//! accounts database grow continuously, and RPC exposes nothing about the
//! filesystem. perch runs on a separate host, so something on the
//! validator has to report -- node_exporter is the de-facto standard, read-only,
//! and one HTTP GET away over the private network.
//!
//! Scrape failures reuse `RpcError`, so the same rule holds as everywhere else:
//! an unreachable exporter is `Unknown`, never `Unhealthy`. A monitoring host
//! that cannot reach a validator must not be able to page you for a full disk.

use crate::rpc::RpcError;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, warn};

pub const BYTES_PER_GB: f64 = 1_073_741_824.0;

/// Pseudo-filesystems that are never worth alerting on.
const PSEUDO_FSTYPES: &[&str] = &[
    "tmpfs", "devtmpfs", "devfs", "overlay", "squashfs", "iso9660", "ramfs", "autofs", "proc",
    "sysfs", "cgroup", "cgroup2", "debugfs", "tracefs", "securityfs", "pstore", "bpf", "configfs",
    "fusectl", "hugetlbfs", "mqueue", "binfmt_misc", "nsfs", "efivarfs",
];

#[derive(Debug, Clone)]
pub struct Filesystem {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub size_bytes: u64,
    pub avail_bytes: u64,
    pub inodes_total: u64,
    pub inodes_free: u64,
    pub readonly: bool,
}

impl Filesystem {
    pub fn used_percent(&self) -> f64 {
        if self.size_bytes == 0 {
            return 0.0;
        }
        (self.size_bytes - self.avail_bytes) as f64 * 100.0 / self.size_bytes as f64
    }

    pub fn avail_gb(&self) -> f64 {
        self.avail_bytes as f64 / BYTES_PER_GB
    }

    pub fn size_gb(&self) -> f64 {
        self.size_bytes as f64 / BYTES_PER_GB
    }

    pub fn inodes_used_percent(&self) -> f64 {
        if self.inodes_total == 0 {
            return 0.0;
        }
        (self.inodes_total - self.inodes_free) as f64 * 100.0 / self.inodes_total as f64
    }
}

/// What one host had to say about its filesystems in one cycle.
#[derive(Debug, Clone)]
pub struct HostSnapshot {
    pub host: String,
    /// Mountpoint -> filesystem. Empty with `error` set means we could not tell.
    pub filesystems: HashMap<String, Filesystem>,
    pub error: Option<String>,
}

impl HostSnapshot {
    pub fn is_usable(&self) -> bool {
        self.error.is_none()
    }
}

#[derive(Clone)]
pub struct Host {
    pub name: String,
    pub url: String,
    /// Empty means "every real filesystem"; otherwise only these mountpoints.
    pub mountpoints: Vec<String>,
    client: reqwest::Client,
    attempts: u32,
}

impl Host {
    pub fn new(
        name: String,
        url: String,
        mountpoints: Vec<String>,
        timeout: Duration,
        attempts: u32,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            name,
            url,
            mountpoints,
            client,
            attempts: attempts.max(1),
        })
    }

    pub async fn scrape(&self) -> HostSnapshot {
        let mut last = String::from("no attempt made");

        for attempt in 0..self.attempts {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(300 * u64::from(attempt))).await;
            }
            match self.scrape_once().await {
                Ok(text) => {
                    let all = parse_filesystems(&text);
                    let filesystems = all
                        .into_iter()
                        .filter(|fs| self.wanted(fs))
                        .map(|fs| (fs.mountpoint.clone(), fs))
                        .collect::<HashMap<_, _>>();

                    if filesystems.is_empty() {
                        // Reaching node_exporter but matching nothing is a
                        // configuration mistake, not a healthy host. Saying so
                        // is better than silently monitoring zero filesystems.
                        warn!(
                            host = %self.name,
                            "scrape succeeded but no filesystem matched; check the \
                             mountpoints list"
                        );
                        return HostSnapshot {
                            host: self.name.clone(),
                            filesystems,
                            error: Some(
                                "no filesystem matched the configured mountpoints".into(),
                            ),
                        };
                    }

                    debug!(host = %self.name, "scraped {} filesystem(s)", filesystems.len());
                    return HostSnapshot {
                        host: self.name.clone(),
                        filesystems,
                        error: None,
                    };
                }
                Err(e) => last = e.to_string(),
            }
        }

        warn!(host = %self.name, "node_exporter scrape failed: {last}");
        HostSnapshot {
            host: self.name.clone(),
            filesystems: HashMap::new(),
            error: Some(last),
        }
    }

    fn wanted(&self, fs: &Filesystem) -> bool {
        if PSEUDO_FSTYPES.contains(&fs.fstype.as_str()) {
            return false;
        }
        if fs.size_bytes == 0 {
            return false;
        }
        if self.mountpoints.is_empty() {
            return true;
        }
        self.mountpoints.iter().any(|m| m == &fs.mountpoint)
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
            return Err(RpcError::Transient(format!("node_exporter returned {status}")));
        }
        resp.text()
            .await
            .map_err(|e| {
                RpcError::Transient(format!("unreadable scrape body: {}", crate::rpc::scrub(e)))
            })
    }
}

/// Minimal Prometheus text-format parser for the handful of series we need.
///
/// Hand-rolled rather than pulling a parser crate: node_exporter's filesystem
/// collector emits one flat line per series with no histograms or summaries, so
/// the general case does not arise.
pub(crate) fn parse_labels(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut chars = s.chars().peekable();

    while chars.peek().is_some() {
        let key: String = chars
            .by_ref()
            .take_while(|c| *c != '=')
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect();
        if key.is_empty() {
            break;
        }
        // Opening quote.
        if chars.next() != Some('"') {
            break;
        }
        let mut value = String::new();
        let mut escaped = false;
        for c in chars.by_ref() {
            if escaped {
                // node_exporter escapes \\ , \" and \n in label values.
                value.push(match c {
                    'n' => '\n',
                    other => other,
                });
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                break;
            } else {
                value.push(c);
            }
        }
        out.insert(key, value);
        // Trailing comma, if any.
        if chars.peek() == Some(&',') {
            chars.next();
        }
    }
    out
}

pub(crate) fn parse_line(line: &str) -> Option<(String, HashMap<String, String>, f64)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, rest) = match line.find('{') {
        Some(i) => {
            let close = line.rfind('}')?;
            let name = line[..i].to_string();
            let labels = parse_labels(&line[i + 1..close]);
            let value = line[close + 1..].trim();
            return value.parse::<f64>().ok().map(|v| (name, labels, v));
        }
        None => {
            let mut parts = line.split_whitespace();
            (parts.next()?.to_string(), parts.next()?)
        }
    };
    rest.parse::<f64>().ok().map(|v| (name, HashMap::new(), v))
}

pub fn parse_filesystems(text: &str) -> Vec<Filesystem> {
    // Keyed by mountpoint: node_exporter emits one series per metric per mount.
    let mut acc: HashMap<String, Filesystem> = HashMap::new();

    for line in text.lines() {
        let Some((name, labels, value)) = parse_line(line) else {
            continue;
        };
        if !name.starts_with("node_filesystem_") {
            continue;
        }
        let Some(mountpoint) = labels.get("mountpoint") else {
            continue;
        };

        let fs = acc.entry(mountpoint.clone()).or_insert_with(|| Filesystem {
            device: labels.get("device").cloned().unwrap_or_default(),
            mountpoint: mountpoint.clone(),
            fstype: labels.get("fstype").cloned().unwrap_or_default(),
            size_bytes: 0,
            avail_bytes: 0,
            inodes_total: 0,
            inodes_free: 0,
            readonly: false,
        });

        // Values arrive as floats, sometimes in scientific notation. Negative
        // or NaN would wrap on cast, so clamp before converting.
        let as_u64 = |v: f64| -> u64 {
            if v.is_finite() && v > 0.0 {
                v as u64
            } else {
                0
            }
        };

        match name.as_str() {
            "node_filesystem_size_bytes" => fs.size_bytes = as_u64(value),
            // `avail` is space usable by an unprivileged process, which is what
            // actually runs out. `free` includes the root reserve and would
            // overstate the headroom by several percent of the device.
            "node_filesystem_avail_bytes" => fs.avail_bytes = as_u64(value),
            "node_filesystem_files" => fs.inodes_total = as_u64(value),
            "node_filesystem_files_free" => fs.inodes_free = as_u64(value),
            "node_filesystem_readonly" => fs.readonly = value != 0.0,
            _ => {}
        }
    }

    let mut out: Vec<Filesystem> = acc.into_values().collect();
    out.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic node_exporter excerpt, including scientific notation, a
    // read-only mount, and pseudo-filesystems that must be filtered out.
    const SAMPLE: &str = r#"
# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 4.294967296e+10
node_filesystem_avail_bytes{device="/dev/nvme1n1",fstype="ext4",mountpoint="/mnt/ledger"} 3.2212254720e+11
node_filesystem_avail_bytes{device="/dev/nvme2n1",fstype="ext4",mountpoint="/mnt/accounts"} 1.073741824e+11
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 8.2e+09
node_filesystem_size_bytes{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 2.14748364800e+11
node_filesystem_size_bytes{device="/dev/nvme1n1",fstype="ext4",mountpoint="/mnt/ledger"} 2.147483648e+12
node_filesystem_size_bytes{device="/dev/nvme2n1",fstype="ext4",mountpoint="/mnt/accounts"} 5.36870912e+11
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/run"} 1.6e+10
node_filesystem_files{device="/dev/nvme1n1",fstype="ext4",mountpoint="/mnt/ledger"} 1.31072e+08
node_filesystem_files_free{device="/dev/nvme1n1",fstype="ext4",mountpoint="/mnt/ledger"} 1.30000e+08
node_filesystem_readonly{device="/dev/nvme0n1p2",fstype="ext4",mountpoint="/"} 0
node_filesystem_readonly{device="/dev/nvme2n1",fstype="ext4",mountpoint="/mnt/accounts"} 1
node_cpu_seconds_total{cpu="0",mode="idle"} 12345.67
"#;

    fn by_mount(v: &[Filesystem], m: &str) -> Filesystem {
        v.iter().find(|f| f.mountpoint == m).unwrap().clone()
    }

    #[test]
    fn parses_scientific_notation_into_bytes() {
        let fs = parse_filesystems(SAMPLE);
        let ledger = by_mount(&fs, "/mnt/ledger");
        assert_eq!(ledger.size_bytes, 2_147_483_648_000);
        assert_eq!(ledger.avail_bytes, 322_122_547_200);
        assert_eq!(ledger.fstype, "ext4");
        assert_eq!(ledger.device, "/dev/nvme1n1");
    }

    #[test]
    fn joins_separate_series_onto_one_filesystem() {
        // size, avail, files, files_free and readonly arrive as five different
        // lines and must land on the same struct.
        let ledger = by_mount(&parse_filesystems(SAMPLE), "/mnt/ledger");
        assert!(ledger.size_bytes > 0 && ledger.avail_bytes > 0);
        assert_eq!(ledger.inodes_total, 131_072_000);
        assert_eq!(ledger.inodes_free, 130_000_000);
    }

    #[test]
    fn detects_a_read_only_filesystem() {
        let fs = parse_filesystems(SAMPLE);
        assert!(by_mount(&fs, "/mnt/accounts").readonly);
        assert!(!by_mount(&fs, "/").readonly);
    }

    #[test]
    fn ignores_unrelated_metrics() {
        let fs = parse_filesystems(SAMPLE);
        assert!(fs.iter().all(|f| !f.mountpoint.is_empty()));
        assert_eq!(fs.len(), 4, "three real mounts plus /run before filtering");
    }

    #[test]
    fn computes_usage_percentages() {
        let ledger = by_mount(&parse_filesystems(SAMPLE), "/mnt/ledger");
        assert!((ledger.used_percent() - 85.0).abs() < 0.01, "{}", ledger.used_percent());
        assert!((ledger.avail_gb() - 300.0).abs() < 0.01);
        assert!((ledger.inodes_used_percent() - 0.818).abs() < 0.01);
    }

    #[test]
    fn empty_filesystem_percentages_do_not_divide_by_zero() {
        let fs = Filesystem {
            device: "x".into(),
            mountpoint: "/x".into(),
            fstype: "ext4".into(),
            size_bytes: 0,
            avail_bytes: 0,
            inodes_total: 0,
            inodes_free: 0,
            readonly: false,
        };
        assert_eq!(fs.used_percent(), 0.0);
        assert_eq!(fs.inodes_used_percent(), 0.0);
    }

    #[test]
    fn pseudo_filesystems_are_excluded() {
        let host = Host::new(
            "h".into(),
            "http://x/metrics".into(),
            vec![],
            Duration::from_secs(1),
            1,
        )
        .unwrap();
        let kept: Vec<_> = parse_filesystems(SAMPLE)
            .into_iter()
            .filter(|f| host.wanted(f))
            .map(|f| f.mountpoint)
            .collect();
        assert_eq!(kept, vec!["/", "/mnt/accounts", "/mnt/ledger"]);
        assert!(!kept.contains(&"/run".to_string()), "tmpfs must be dropped");
    }

    #[test]
    fn an_explicit_mountpoint_list_is_honoured() {
        let host = Host::new(
            "h".into(),
            "http://x/metrics".into(),
            vec!["/mnt/ledger".into()],
            Duration::from_secs(1),
            1,
        )
        .unwrap();
        let kept: Vec<_> = parse_filesystems(SAMPLE)
            .into_iter()
            .filter(|f| host.wanted(f))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].mountpoint, "/mnt/ledger");
    }

    #[test]
    fn label_values_with_escapes_parse() {
        let l = parse_labels(r#"device="/dev/sda",mountpoint="/mnt/a\"b",fstype="ext4""#);
        assert_eq!(l.get("mountpoint").unwrap(), r#"/mnt/a"b"#);
        assert_eq!(l.get("fstype").unwrap(), "ext4");
    }

    #[test]
    fn negative_or_nan_values_clamp_to_zero_instead_of_wrapping() {
        // `-1 as u64` in Rust wraps to u64::MAX, which would read as an
        // impossibly healthy disk.
        let text = concat!(
            "node_filesystem_size_bytes{mountpoint=\"/x\",fstype=\"ext4\"} 1000\n",
            "node_filesystem_avail_bytes{mountpoint=\"/x\",fstype=\"ext4\"} -1\n",
        );
        let fs = parse_filesystems(text);
        assert_eq!(fs[0].avail_bytes, 0);
    }

    #[test]
    fn a_truncated_scrape_does_not_panic() {
        for bad in [
            "node_filesystem_size_bytes{mountpoint=\"/x\"",
            "node_filesystem_size_bytes{} ",
            "node_filesystem_size_bytes",
            "{mountpoint=\"/x\"} 5",
            "",
        ] {
            let _ = parse_filesystems(bad);
        }
    }
}

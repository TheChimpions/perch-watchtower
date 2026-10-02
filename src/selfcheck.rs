//! Verify at startup that the deployment matches what the config claims.
//!
//! Every serious failure this watchtower has had in production looked healthy
//! from its own outputs. Spokes reported their hub reachable while polling their
//! own metrics port. A maintenance script printed "paging suppressed" while
//! writing to a path nothing read. Six units reported `active` with every
//! sandbox directive silently ignored.
//!
//! None of those are detectable from the metrics, because the metrics were
//! exactly what a working system would produce. They are all trivially
//! checkable once, at boot, before anyone relies on the answer.

use crate::config::Config;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    /// Worth saying out loud; the operator decides.
    Note,
    /// Something claims to be configured and is not doing anything.
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

/// Host and port of a URL or bind address, with loopback spellings normalised.
///
/// `localhost`, `127.0.0.1`, `::1` and `0.0.0.0` all mean "this machine" for the
/// purpose of noticing that a peer is really ourselves.
fn host_port(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let s = s.split("://").last()?;
    let s = s.split('/').next()?;
    let (host, port) = match s.rsplit_once(':') {
        // Bare IPv6 without a port is not something we need to handle here.
        Some((h, p)) if !p.contains(']') => (h, p),
        _ => return None,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host.to_ascii_lowercase().as_str() {
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "" => "local".to_string(),
        other => other.to_string(),
    };
    Some((host, port.to_string()))
}

/// Whether a configured peer is actually this instance's own metrics endpoint.
///
/// This is the check that matters most. A peer entry pointing at our own listen
/// address polls ourselves and reports the result as the peer's health, so the
/// peer looks permanently alive -- including when it is gone.
pub fn peer_points_at_self(peer_url: &str, metrics_listen: &str) -> bool {
    match (host_port(peer_url), host_port(metrics_listen)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The mount visible at `point` as `(root, options, fstype, superblock
/// options)`. The last entry wins: later mounts stack on top of earlier ones.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn mount_at<'a>(mountinfo: &'a str, point: &str) -> Option<(&'a str, &'a str, &'a str, &'a str)> {
    mountinfo
        .lines()
        .filter_map(|l| {
            // id parent major:minor root mountpoint options [optional...] - fstype source superopts
            let (pre, post) = l.split_once(" - ")?;
            let f: Vec<&str> = pre.split(' ').collect();
            if f.get(4) != Some(&point) {
                return None;
            }
            let p: Vec<&str> = post.split(' ').collect();
            Some((
                *f.get(3)?,
                *f.get(5)?,
                *p.first()?,
                *p.get(2).unwrap_or(&""),
            ))
        })
        .next_back()
}

/// What the sandbox actually does to this process's view of the machine, read
/// from `/proc/self/mountinfo`.
///
/// Effects rather than mechanism. This used to compare our mount namespace with
/// PID 1's, which is right in principle and wrong under the shipped unit:
/// `ProtectProc=invisible` hides PID 1, the comparison failed, and a fully
/// sandboxed process reported `mount-namespace=shared`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn mount_facts(mountinfo: &str) -> String {
    let has = |opts: &str, o: &str| opts.split(',').any(|x| x == o);
    let root_ro = mount_at(mountinfo, "/").is_some_and(|(_, opts, _, _)| has(opts, "ro"));
    let home = match mount_at(mountinfo, "/home") {
        None => "visible",
        Some((root, ..)) if root.contains("inaccessible") => "hidden",
        Some((_, _, "tmpfs", _)) => "empty",
        Some((_, opts, ..)) if has(opts, "ro") => "read-only",
        Some(_) => "visible",
    };
    let proc_private = mount_at(mountinfo, "/proc").is_some_and(|(.., superopts)| {
        has(superopts, "hidepid=invisible") || has(superopts, "hidepid=2")
    });
    format!(
        "root={} home={home} proc={}",
        if root_ro { "read-only" } else { "writable" },
        if proc_private { "private" } else { "shared" },
    )
}

/// Facts about the sandbox this process actually got, as opposed to the one its
/// unit file asked for. Silently inert hardening is worse than none, because it
/// reads as protection in review.
#[cfg(target_os = "linux")]
fn sandbox_facts() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("?")
            .to_string()
    };
    let caps_dropped = field("CapBnd") == "0000000000000000";
    let seccomp = field("Seccomp") != "0";
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|m| mount_facts(&m))
        .unwrap_or_else(|_| "mounts=unreadable".into());
    Some(format!(
        "{mounts} capabilities={} seccomp={}",
        if caps_dropped { "none" } else { "retained" },
        if seccomp { "on" } else { "off" },
    ))
}

#[cfg(not(target_os = "linux"))]
fn sandbox_facts() -> Option<String> {
    None
}

/// Run every startup check and return what looked wrong.
pub fn run(config: &Config) -> Vec<Finding> {
    let mut out = Vec::new();

    let listen = config.metrics.as_ref().map(|m| m.listen.as_str());
    if let Some(listen) = listen {
        for p in &config.peers {
            if peer_points_at_self(&p.url, listen) {
                out.push(Finding {
                    severity: Severity::Warn,
                    message: format!(
                        "peer \"{}\" points at {}, which is this instance's own metrics endpoint. \
                         It is polling itself, so that peer will look alive even when it is gone. \
                         A remote peer needs a tunnel or a routable address.",
                        p.name, p.url
                    ),
                });
            }
        }
    }

    if let Some(path) = config.silence.file.as_deref() {
        let dir = std::path::Path::new(path)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        if !dir.exists() {
            out.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "silence file directory {} does not exist, so maintenance mode cannot be \
                     declared and any attempt will silently do nothing",
                    dir.display()
                ),
            });
        }
    }

    if let Some(prefix) = config
        .metrics
        .as_ref()
        .and_then(|m| m.compat_prefix.as_deref())
    {
        out.push(Finding {
            severity: Severity::Note,
            message: format!(
                "metrics.compat_prefix is set to \"{prefix}\", doubling the exposition. \
                 It exists for a rollout; remove it once every instance is renamed."
            ),
        });
    }

    out
}

/// Log the findings, plus the sandbox facts, once at startup.
pub fn report(config: &Config) {
    if let Some(facts) = sandbox_facts() {
        // Stated as fact rather than judgement: the operator knows what the unit
        // asked for, and this is what it got.
        info!("sandbox: {facts}");
    }
    for f in run(config) {
        match f.severity {
            Severity::Warn => warn!("startup check: {}", f.message),
            Severity::Note => info!("startup check: {}", f.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug that shipped to every spoke: a peer entry pointing at our own
    /// metrics port, so the peer read itself and looked permanently alive.
    #[test]
    fn a_peer_on_our_own_listen_address_is_caught() {
        for url in [
            "http://127.0.0.1:9469/metrics",
            "http://localhost:9469/metrics",
            "http://[::1]:9469/metrics",
        ] {
            assert!(
                peer_points_at_self(url, "127.0.0.1:9469"),
                "{url} should be recognised as ourselves"
            );
        }
    }

    /// The corrected wiring: the hub over a forward tunnel on a different port.
    #[test]
    fn a_peer_on_a_different_port_is_fine() {
        assert!(!peer_points_at_self(
            "http://127.0.0.1:19469/metrics",
            "127.0.0.1:9469"
        ));
    }

    #[test]
    fn a_remote_peer_is_fine() {
        assert!(!peer_points_at_self(
            "http://10.0.0.9:9469/metrics",
            "127.0.0.1:9469"
        ));
    }

    /// A bind on all interfaces still means "this machine", so a peer pointed at
    /// our port via loopback must not slip through.
    #[test]
    fn listening_on_all_interfaces_still_counts_as_ourselves() {
        assert!(peer_points_at_self(
            "http://127.0.0.1:9469/metrics",
            "0.0.0.0:9469"
        ));
    }

    #[test]
    fn unparseable_addresses_do_not_produce_false_alarms() {
        assert!(!peer_points_at_self("not a url", "127.0.0.1:9469"));
        assert!(!peer_points_at_self("http://127.0.0.1:9469", "garbage"));
    }
}

#[cfg(test)]
mod mount_facts_tests {
    use super::mount_facts;

    /// Captured from perch under the shipped unit on Ubuntu 24.04.
    const SANDBOXED: &str = "\
788 763 0:212 / / ro,nosuid,relatime shared:204 - overlay overlay rw,lowerdir=x
791 788 0:222 /systemd/inaccessible/dir /home ro,nosuid,nodev,noexec,relatime shared:223 - tmpfs tmpfs rw,mode=755
792 788 0:225 / /proc rw,nosuid,nodev,noexec,relatime shared:224 - proc proc rw,hidepid=invisible,subset=pid
";

    /// Captured from a validator host, outside any sandbox.
    const HOST: &str = "\
29 1 259:3 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
25 29 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
";

    #[test]
    fn the_shipped_sandbox_reads_as_applied() {
        assert_eq!(
            mount_facts(SANDBOXED),
            "root=read-only home=hidden proc=private"
        );
    }

    #[test]
    fn an_unsandboxed_process_reads_as_exposed() {
        assert_eq!(mount_facts(HOST), "root=writable home=visible proc=shared");
    }

    /// ProtectHome=tmpfs plus a bind mount for [diagnose]: /home is an empty
    /// tmpfs with one directory mounted into it.
    #[test]
    fn protect_home_tmpfs_reads_as_empty() {
        let m = format!(
            "{SANDBOXED}800 788 0:230 / /home rw,nosuid,nodev,relatime shared:230 - tmpfs tmpfs rw,mode=755\n"
        );
        assert!(
            mount_facts(&m).contains("home=empty"),
            "{}",
            mount_facts(&m)
        );
    }
}

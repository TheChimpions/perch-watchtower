//! Kernel advisories: is this box still exposed, and can it stop being?
//!
//! Now and then a kernel bug needs every validator operator to act the same
//! day: apply a sysctl as a stopgap, boot a patched kernel when the
//! distribution ships one, then undo the stopgap. CVE-2026-99288 (NoisyTCP) was
//! one. Hearing about it is not the hard part. Knowing a week later which of
//! eleven boxes never got the sysctl, which have had the fix sitting on disk
//! unbooted, and which are still running the stopgap on a fixed kernel is.
//!
//! Advisories are listed, never discovered. Discovery was considered and
//! does not work: Ubuntu's tracker lists over three thousand high-priority
//! kernel CVEs for 24.04, and rated NoisyTCP itself "medium". A feed would
//! have buried the one that mattered and then missed it.
//!
//! The list has two parts. `advisories.toml` is compiled into the binary: the
//! few kernel bugs every validator operator was asked to act on, so a box is
//! tracked against them by upgrading perch and nothing else. `[[advisories]]`
//! in the config adds to it, and replaces a built-in entry of the same id.
//! Nothing is fetched to build the list.
//!
//! For a declared advisory, each host is in one of three actionable states,
//! one check each:
//!
//! - **exposed**: the running kernel lacks the fix and the host is not marked
//!   mitigated.
//! - **upgrade**: marked mitigated, but a fixed kernel now exists and is not
//!   the one running.
//! - **restore**: the fix is running and the host is still marked mitigated.
//!
//! perch sees the kernel and nothing else. On the machine it runs on that is
//! `uname(2)` and `/etc/os-release`; for a remote host, the node_exporter
//! scrape. It does not see whether a mitigation is applied: a firewall rule
//! needs root to list, `/proc/sys` is hidden by perch's own sandbox, and a
//! watchtower that asked for either would be a worse thing to run next to a
//! validator. The operator applies the mitigation and lists the advisory under
//! the host's `mitigated`; that declaration is what moves a host from exposed
//! to waiting for a kernel. Where the fix landed comes from `fixed_in`, and
//! for Ubuntu hosts from Ubuntu's own tracker, which is what turns "as soon
//! as your distribution ships one" into a notification.

use crate::{
    config::{AdvisoryConfig, AdvisoryTracker},
    node_exporter::HostFacts,
    verdict::Verdict,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    cmp::Ordering,
    collections::HashMap,
    time::{Duration, Instant},
};
use tracing::{info, warn};

/// The advisories that ship with perch.
const BUILTIN: &str = include_str!("../advisories.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinFile {
    #[serde(default)]
    advisories: Vec<AdvisoryConfig>,
}

pub fn builtin() -> Result<Vec<AdvisoryConfig>> {
    let file: BuiltinFile = toml::from_str(BUILTIN).context("parsing the built-in advisory list")?;
    Ok(file.advisories)
}

/// The leading numeric components of a kernel or package version, split on
/// `.` and `-`, stopping at the first thing that is not a number:
/// "6.8.0-54-generic" is [6, 8, 0, 54], "6.12.48+deb13-amd64" is [6, 12, 48],
/// and Ubuntu's package version "6.8.0-151.161" is [6, 8, 0, 151, 161].
pub fn components(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut cur: Option<u64> = None;
    for c in s.trim().chars() {
        match c {
            '0'..='9' => {
                let d = u64::from(c as u8 - b'0');
                cur = Some(cur.unwrap_or(0).saturating_mul(10).saturating_add(d));
            }
            '.' | '-' => match cur.take() {
                Some(n) => out.push(n),
                // Two separators in a row, or a leading one: not a version
                // from here on.
                None => break,
            },
            other => {
                // "48+deb13" ends a number cleanly and it counts; a number
                // glued to letters ("13deb") was never a version component.
                if other.is_ascii_alphabetic() {
                    cur = None;
                }
                break;
            }
        }
    }
    out.extend(cur);
    out
}

/// Compares over the components both sides have, so "6.8.0-151" is met by a
/// running 6.8.0-151.161 and by 6.8.0-152, and not by 6.8.0-150.
fn at_least(running: &[u64], fixed: &[u64]) -> bool {
    let n = running.len().min(fixed.len());
    running[..n].cmp(&fixed[..n]) != Ordering::Less
}

/// The kernel a host is running, as far as `uname` tells.
#[derive(Debug, Clone, PartialEq)]
pub struct Kernel {
    pub release: String,
    /// Components of the release, plus the Ubuntu upload number when known, so
    /// it compares directly against an Ubuntu package version.
    comps: Vec<u64>,
    /// "generic", "aws", "lowlatency": what follows the numbers.
    flavour: String,
    /// `uname -v` says this is an Ubuntu build.
    ubuntu: bool,
    /// An Ubuntu backport ("#14~22.04.1-Ubuntu"): a newer series built for an
    /// older release, from a source package named after that series.
    backport: bool,
}

impl Kernel {
    pub fn parse(release: &str, version: Option<&str>) -> Option<Self> {
        let mut comps = components(release);
        if comps.len() < 2 {
            return None;
        }
        // Whatever follows the numeric prefix.
        let flavour = release
            .rsplit('-')
            .next()
            .filter(|f| f.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
            .unwrap_or("")
            .to_string();

        // "#56-Ubuntu SMP ..." or "#14~22.04.1-Ubuntu SMP ...".
        let tag = version.and_then(|v| v.split_whitespace().next()).unwrap_or("");
        let ubuntu = tag.starts_with('#') && tag.ends_with("-Ubuntu");
        let backport = ubuntu && tag.contains('~');
        if ubuntu {
            let digits: String = tag[1..].chars().take_while(char::is_ascii_digit).collect();
            if let Ok(upload) = digits.parse::<u64>() {
                // Only meaningful after the ABI number: 6.8.0-54 upload 56.
                if comps.len() == 4 {
                    comps.push(upload);
                }
            }
        }
        Some(Self {
            release: release.to_string(),
            comps,
            flavour,
            ubuntu,
            backport,
        })
    }

    fn series(&self) -> (u64, u64) {
        (self.comps[0], self.comps[1])
    }

    /// The Ubuntu source package this kernel was built from, where the
    /// flavour and series say so.
    ///
    /// A release's own kernel comes from `linux` or `linux-<flavour>`. A
    /// backport comes from a package named for its series: 24.04 running 7.0
    /// ("#43~24.04.1-Ubuntu") is `linux-hwe-7.0`, which Ubuntu tracks on its
    /// own row. Only the generic and lowlatency backports follow that one
    /// pattern; the cloud flavours do not, and are left to `fixed_in`. A wrong
    /// guess here costs nothing worse than that: the tracker has no such
    /// package for the release, and says so.
    fn ubuntu_package(&self) -> Option<String> {
        if !self.ubuntu || self.flavour.is_empty() {
            return None;
        }
        let (major, minor) = self.series();
        match (self.backport, self.flavour.as_str()) {
            (false, "generic") => Some("linux".to_string()),
            (false, f) => Some(format!("linux-{f}")),
            (true, "generic") => Some(format!("linux-hwe-{major}.{minor}")),
            (true, "lowlatency") => Some(format!("linux-lowlatency-hwe-{major}.{minor}")),
            (true, _) => None,
        }
    }
}

/// Whether the running kernel has the fix.
#[derive(Debug, Clone, PartialEq)]
pub enum Patch {
    /// Running the fix, or something newer. Carries what it was measured against.
    Fixed(String),
    /// The distribution says this kernel never had the bug.
    NotAffected,
    /// Lacks the fix. `fix` is the first version that has it, once one exists.
    Unpatched { fix: Option<String> },
    Unknown(String),
}

/// What `fixed_in` alone says. `None` means it has no opinion about this
/// kernel's series.
fn patch_from_fixed_in(k: &Kernel, fixed_in: &[String]) -> Option<Patch> {
    let parsed: Vec<(&String, Vec<u64>)> = fixed_in
        .iter()
        .map(|f| (f, components(f)))
        .filter(|(_, c)| c.len() >= 2)
        .collect();
    if let Some((text, fixed)) = parsed.iter().find(|(_, c)| (c[0], c[1]) == k.series()) {
        return Some(if at_least(&k.comps, fixed) {
            Patch::Fixed((*text).clone())
        } else {
            Patch::Unpatched {
                fix: Some((*text).clone()),
            }
        });
    }
    // A series newer than every one the fix was backported to was released
    // with it. Anything older or in between was not, as far as this list says.
    let newest = parsed.iter().map(|(_, c)| (c[0], c[1])).max()?;
    (k.series() > newest).then(|| Patch::Fixed(format!("{}.{} and later", newest.0, newest.1)))
}

/// One CVE as Ubuntu's tracker reports it, reduced to the kernel packages.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UbuntuCve {
    /// (source package, release codename) -> (status, description). For a
    /// `released` status the description is the fixed package version.
    statuses: HashMap<(String, String), (String, String)>,
}

#[derive(Deserialize)]
struct UbuntuResponse {
    #[serde(default)]
    packages: Vec<UbuntuPackage>,
}
#[derive(Deserialize)]
struct UbuntuPackage {
    name: String,
    #[serde(default)]
    statuses: Vec<UbuntuStatus>,
}
#[derive(Deserialize)]
struct UbuntuStatus {
    #[serde(default)]
    release_codename: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    description: Option<String>,
}

impl UbuntuCve {
    pub fn parse(body: &str) -> Result<Self> {
        let resp: UbuntuResponse = serde_json::from_str(body).context("decoding Ubuntu CVE record")?;
        let mut statuses = HashMap::new();
        for p in resp.packages {
            if p.name != "linux" && !p.name.starts_with("linux-") {
                continue;
            }
            for s in p.statuses {
                statuses.insert(
                    (p.name.clone(), s.release_codename),
                    (s.status, s.description.unwrap_or_default()),
                );
            }
        }
        if statuses.is_empty() {
            anyhow::bail!("Ubuntu CVE record lists no kernel package");
        }
        Ok(Self { statuses })
    }

    fn patch(&self, k: &Kernel, package: &str, codename: &str) -> Patch {
        let Some((status, description)) = self.statuses.get(&(package.to_string(), codename.to_string())) else {
            return Patch::Unknown(format!("Ubuntu's tracker has no entry for {package} on {codename}"));
        };
        match status.as_str() {
            "released" => {
                let fixed = components(description);
                if fixed.len() < 4 {
                    return Patch::Unknown(format!(
                        "Ubuntu lists {package} on {codename} as released without a usable version ({description:?})"
                    ));
                }
                if at_least(&k.comps, &fixed) {
                    Patch::Fixed(format!("{package} {description}"))
                } else {
                    Patch::Unpatched {
                        fix: Some(format!("{package} {description}")),
                    }
                }
            }
            "not-affected" => Patch::NotAffected,
            // "Does not exist": the release never carried this package, so the
            // kernel was not built from the one perch took it for.
            "DNE" => Patch::Unknown(format!(
                "Ubuntu publishes no {package} for {codename}, so the tracker cannot place this kernel; \
                 add its fixed version to fixed_in"
            )),
            // Acknowledged or not yet looked at; either way nothing to boot.
            "needed" | "needs-triage" | "pending" | "deferred" | "in-progress" => Patch::Unpatched { fix: None },
            other => Patch::Unknown(format!(
                "Ubuntu lists {package} on {codename} as {other:?}, which says nothing about a fix"
            )),
        }
    }
}

/// Tracker records by advisory id.
pub type Tracked = HashMap<String, UbuntuCve>;

/// Whether the running kernel has the fix, from `fixed_in` and, for an Ubuntu
/// host of an advisory that asks for it, Ubuntu's tracker.
pub fn patch_state(adv: &AdvisoryConfig, facts: &HostFacts, tracked: &Tracked) -> Patch {
    let Some(release) = facts.kernel_release.as_deref() else {
        return Patch::Unknown(
            "node_exporter does not report the running kernel; start it with --collector.uname".into(),
        );
    };
    let Some(k) = Kernel::parse(release, facts.kernel_version.as_deref()) else {
        return Patch::Unknown(format!("kernel release {release:?} is not a version perch can compare"));
    };

    let declared = patch_from_fixed_in(&k, &adv.fixed_in);
    if let Some(fixed @ Patch::Fixed(_)) = &declared {
        return fixed.clone();
    }
    // No tracker, or not a host it covers: `fixed_in` is all there is, and a
    // series it does not mention has no fix that perch knows of.
    let fallback = || declared.clone().unwrap_or(Patch::Unpatched { fix: None });

    if adv.tracker != Some(AdvisoryTracker::Ubuntu) || !(k.ubuntu || facts.os_id.as_deref() == Some("ubuntu")) {
        return fallback();
    }
    // An explicit `fixed_in` for this series is the operator overriding the
    // tracker, which is the only recourse for a kernel it cannot place.
    if declared.is_some() {
        return fallback();
    }
    let Some(package) = k.ubuntu_package() else {
        return Patch::Unknown(format!(
            "cannot tell which Ubuntu source package built kernel {release}; add its fixed version to fixed_in"
        ));
    };
    let Some(codename) = facts.os_codename.as_deref() else {
        return Patch::Unknown(
            "node_exporter does not report the Ubuntu release; start it with --collector.os".into(),
        );
    };
    match tracked.get(&adv.id) {
        Some(cve) => cve.patch(&k, &package, codename),
        None => Patch::Unknown("Ubuntu's tracker has not been fetched yet".into()),
    }
}

/// The three verdicts for one advisory on one host. `upgrade` and `restore`
/// are absent only while the kernel itself cannot be judged: three checks
/// repeating one reason would be three "cannot be evaluated" notes.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub exposed: Verdict,
    pub upgrade: Option<Verdict>,
    pub restore: Option<Verdict>,
}

/// `acknowledged` is the operator's word, from the host's `mitigated` list,
/// that the temporary mitigation is in place.
///
/// perch can see a kernel version without help. It cannot see a firewall rule
/// at all, or a sysctl from inside its sandbox, and it is not given the access
/// that would change that. So a mitigation is something the operator applies
/// and then declares. Where a node_exporter does export the sysctl, what it
/// reports is believed over the declaration, in either direction.
pub fn assess(
    host: &str,
    adv: &AdvisoryConfig,
    facts: &HostFacts,
    tracked: &Tracked,
    acknowledged: bool,
) -> Assessment {
    let patch = match patch_state(adv, facts, tracked) {
        Patch::Unknown(why) => {
            return Assessment {
                exposed: Verdict::unknown(why),
                upgrade: None,
                restore: None,
            }
        }
        known => known,
    };

    let label = adv.label();
    let id = &adv.id;
    let release = facts.kernel_release.as_deref().unwrap_or("?");
    let see = adv.url.as_ref().map(|u| format!(" See {u}")).unwrap_or_default();
    let note = adv.note.as_ref().map(|n| format!(" {n}")).unwrap_or_default();
    let sysctl = adv.mitigation.as_ref().map(|m| (m.sysctl.as_str(), m.value));
    // The live value, where an exporter reports it.
    let observed = adv
        .mitigation
        .as_ref()
        .and_then(|m| facts.sysctl(&m.sysctl).map(|v| (v == m.value as f64, v)));
    let applied = observed.map_or(acknowledged, |(applied, _)| applied);
    let healthy = Some(Verdict::Healthy);

    match patch {
        Patch::Unknown(_) => unreachable!("returned above"),

        Patch::Fixed(_) | Patch::NotAffected if !applied => Assessment {
            exposed: Verdict::Healthy,
            upgrade: healthy.clone(),
            restore: healthy,
        },
        patch @ (Patch::Fixed(_) | Patch::NotAffected) => {
            let why = match patch {
                Patch::Fixed(by) => format!("has the fix for {label} ({by})"),
                _ => format!("is not affected by {label}"),
            };
            let delist = if acknowledged {
                format!(" Then remove {id} from this host's `mitigated` list.")
            } else {
                String::new()
            };
            let undo = match (observed, sysctl) {
                (Some(_), Some((name, want))) => format!(
                    "but {name} is still {want}, the temporary mitigation. Restore its previous value."
                ),
                (None, Some((name, want))) => format!(
                    "and the config still marks it mitigated. Undo the temporary mitigation \
                     ({name} = {want})."
                ),
                (_, None) => "and the config still marks it mitigated. Undo the temporary mitigation.".to_string(),
            };
            Assessment {
                exposed: Verdict::Healthy,
                upgrade: healthy,
                restore: Some(Verdict::unhealthy(format!(
                    "{host} runs kernel {release}, which {why}, {undo}{delist}{see}"
                ))),
            }
        }

        Patch::Unpatched { fix } if applied => Assessment {
            exposed: Verdict::Healthy,
            upgrade: Some(match fix {
                Some(fix) => Verdict::unhealthy(format!(
                    "{host} is mitigated against {label} and a patched kernel now exists: {fix}. It \
                     runs {release}. Upgrade and reboot, then undo the mitigation.{see}"
                )),
                None => Verdict::Healthy,
            }),
            restore: healthy,
        },
        Patch::Unpatched { fix } => {
            let kernel = match &fix {
                Some(fix) => format!(" The fix is in {fix}: upgrade and reboot."),
                None => " No patched kernel is listed for it yet.".to_string(),
            };
            let stopgap = match (observed, sysctl) {
                (Some((_, cur)), Some((name, want))) => {
                    let claimed = if acknowledged {
                        " The config marks this host mitigated, but that is not what it reports."
                    } else {
                        ""
                    };
                    format!(" {name} is {cur}; set it to {want} as the temporary mitigation.{claimed}")
                }
                (None, Some((name, want))) => format!(" Until it is running, set {name} = {want}."),
                (_, None) => String::new(),
            };
            // Without something to read, the operator has to say when it is done.
            let declare = if observed.is_none() {
                format!(
                    " perch cannot see whether that is done: once it is, add \"{id}\" to this \
                     host's `mitigated` list."
                )
            } else {
                String::new()
            };
            Assessment {
                exposed: Verdict::unhealthy(format!(
                    "{host} runs kernel {release}, which is affected by {label}.{kernel}{stopgap}{note}{declare}{see}"
                )),
                upgrade: healthy.clone(),
                restore: healthy,
            }
        }
    }
}

const TRACKER_REFRESH: Duration = Duration::from_secs(60 * 60);
/// With nothing fetched yet: sooner, but not every cycle.
const TRACKER_RETRY: Duration = Duration::from_secs(5 * 60);

/// Fetches and caches Ubuntu's record for each advisory that asks for it. A
/// failed fetch keeps the last record: a stale answer about where the fix
/// landed is still true, since fixes do not get unreleased.
pub struct Tracker {
    client: Option<reqwest::Client>,
    tracked: Tracked,
    last_attempt: HashMap<String, Instant>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| warn!("advisory tracker lookups disabled: could not build HTTP client: {e:#}"))
            .ok();
        Self {
            client,
            tracked: Tracked::new(),
            last_attempt: HashMap::new(),
        }
    }

    pub fn tracked(&self) -> &Tracked {
        &self.tracked
    }

    /// `hosts` are the facts scraped this cycle. The tracker is only asked
    /// when one of them is an Ubuntu box: a built-in advisory must not make a
    /// perch watching Debian hosts start talking to ubuntu.com.
    pub async fn refresh(&mut self, advisories: &[AdvisoryConfig], hosts: &[&HostFacts], now: Instant) {
        if !hosts.iter().any(|f| f.is_ubuntu()) {
            return;
        }
        let Some(client) = self.client.clone() else {
            return;
        };
        let due: Vec<&str> = advisories
            .iter()
            .filter(|a| a.tracker == Some(AdvisoryTracker::Ubuntu))
            .filter(|a| {
                let every = if self.tracked.contains_key(&a.id) {
                    TRACKER_REFRESH
                } else {
                    TRACKER_RETRY
                };
                self.last_attempt
                    .get(&a.id)
                    .is_none_or(|t| now.saturating_duration_since(*t) >= every)
            })
            .map(|a| a.id.as_str())
            .collect();
        for id in &due {
            self.last_attempt.insert((*id).to_string(), now);
        }
        // Together, not in turn: Ubuntu's API can take over twenty seconds on
        // a record it has not served lately, and the check cycle waits on
        // this. One slow record must cost one timeout, not one per advisory.
        let fetched = futures::future::join_all(due.iter().map(|id| fetch_ubuntu(&client, id))).await;
        for (id, result) in due.into_iter().zip(fetched) {
            match result {
                Ok(fresh) => {
                    if self.tracked.get(id) != Some(&fresh) {
                        info!(advisory = %id, "Ubuntu tracker record fetched: {}", fresh.summary());
                    }
                    self.tracked.insert(id.to_string(), fresh);
                }
                Err(e) => warn!(advisory = %id, "could not fetch Ubuntu's tracker record: {e:#}"),
            }
        }
    }
}

impl UbuntuCve {
    /// The main kernel package per release, for the log.
    fn summary(&self) -> String {
        let mut lines: Vec<String> = self
            .statuses
            .iter()
            .filter(|((package, _), (status, _))| package == "linux" && status != "DNE")
            .map(|((_, codename), (status, description))| format!("{codename} {status} {description}").trim().to_string())
            .collect();
        lines.sort();
        lines.join(", ")
    }
}

async fn fetch_ubuntu(client: &reqwest::Client, id: &str) -> Result<UbuntuCve> {
    // `id` is validated as CVE-<year>-<number> at config load, so it is safe
    // in a path.
    let resp = client
        .get(format!("https://ubuntu.com/security/cves/{id}.json"))
        .send()
        .await
        .map_err(crate::rpc::scrub)
        .context("requesting Ubuntu CVE record")?
        .error_for_status()
        .map_err(crate::rpc::scrub)
        .context("Ubuntu's tracker returned an error")?;
    // A kernel CVE lists a few hundred package/release pairs, around 100 KB.
    let body = crate::rpc::body_capped(resp, 4 << 20)
        .await
        .map_err(|e| anyhow::anyhow!("reading Ubuntu CVE record: {e}"))?;
    UbuntuCve::parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdvisoryMitigation;

    const NOBLE_54: (&str, &str) = ("6.8.0-54-generic", "#56-Ubuntu SMP PREEMPT_DYNAMIC Sat Feb  8 00:37:57 UTC 2025");

    fn noisytcp() -> AdvisoryConfig {
        AdvisoryConfig {
            id: "CVE-2026-99288".into(),
            name: Some("NoisyTCP".into()),
            fixed_in: vec!["6.12.117".into(), "6.18.63".into(), "7.3.4".into()],
            tracker: Some(AdvisoryTracker::Ubuntu),
            url: None,
            note: None,
            mitigation: Some(AdvisoryMitigation {
                sysctl: "net.ipv4.tcp_syncookies".into(),
                value: 0,
            }),
        }
    }

    fn facts(kernel: (&str, &str), syncookies: Option<f64>) -> HostFacts {
        HostFacts {
            kernel_release: Some(kernel.0.into()),
            kernel_version: Some(kernel.1.into()),
            os_id: Some("ubuntu".into()),
            os_codename: Some("noble".into()),
            sysctls: syncookies
                .map(|v| ("net_ipv4_tcp_syncookies".to_string(), v))
                .into_iter()
                .collect(),
        }
    }

    /// Ubuntu's record as it stood on 2026-11-16: published, not yet triaged.
    fn untriaged() -> Tracked {
        tracked(r#"{"status":"needs-triage","description":""}"#)
    }

    fn released(version: &str) -> Tracked {
        tracked(&format!(r#"{{"status":"released","description":"{version}"}}"#))
    }

    fn tracked(noble: &str) -> Tracked {
        let body = format!(
            r#"{{"id":"CVE-2026-99288","priority":"medium","packages":[
                {{"name":"linux","statuses":[
                    {{"release_codename":"jammy","status":"needs-triage","description":""}},
                    {{"release_codename":"noble","pocket":"security",{}}}]}},
                {{"name":"linux-hwe-6.8","statuses":[
                    {{"release_codename":"noble","status":"DNE","description":""}}]}},
                {{"name":"openssl","statuses":[
                    {{"release_codename":"noble","status":"released","description":"9.9"}}]}}]}}"#,
            noble.trim_matches(|c| c == '{' || c == '}')
        );
        HashMap::from([("CVE-2026-99288".to_string(), UbuntuCve::parse(&body).unwrap())])
    }

    fn unhealthy(v: &Verdict) -> &str {
        match v {
            Verdict::Unhealthy(m) => m,
            other => panic!("expected unhealthy, got {other:?}"),
        }
    }

    /// The list ships inside the binary, so a mistake in it would stop every
    /// perch from loading its config.
    #[test]
    fn the_built_in_list_is_valid() {
        let list = builtin().unwrap();
        assert!(list.iter().any(|a| a.id == "CVE-2026-99288"));
        let mut ids = std::collections::HashSet::new();
        for a in &list {
            a.validate().unwrap();
            assert!(ids.insert(a.id.clone()), "{} is listed twice", a.id);
            assert!(a.name.is_some() && a.url.is_some(), "{} needs a name and a reference", a.id);
        }
    }

    #[test]
    fn versions_split_into_their_numeric_prefix() {
        assert_eq!(components("6.8.0-54-generic"), [6, 8, 0, 54]);
        assert_eq!(components("6.8.0-151.161"), [6, 8, 0, 151, 161]);
        assert_eq!(components("6.12.48+deb13-amd64"), [6, 12, 48]);
        assert_eq!(components("5.15.0-1084-aws"), [5, 15, 0, 1084]);
        assert_eq!(components("7.3.4"), [7, 3, 4]);
        assert_eq!(components("6.1.0-13deb"), [6, 1, 0]);
        assert!(components("generic").is_empty());
        assert!(components("").is_empty());
    }

    #[test]
    fn an_ubuntu_kernel_carries_its_upload_and_source_package() {
        let k = Kernel::parse(NOBLE_54.0, Some(NOBLE_54.1)).unwrap();
        assert_eq!(k.comps, [6, 8, 0, 54, 56]);
        assert_eq!(k.ubuntu_package().as_deref(), Some("linux"));

        let aws = Kernel::parse("6.8.0-1021-aws", Some("#23-Ubuntu SMP Mon Dec  9 2024")).unwrap();
        assert_eq!(aws.ubuntu_package().as_deref(), Some("linux-aws"));

        // A backport is built from linux-hwe-<series>; "linux" would be the
        // release's own, older kernel, and the wrong row.
        let hwe = Kernel::parse("6.8.0-60-generic", Some("#63~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC")).unwrap();
        assert_eq!(hwe.ubuntu_package().as_deref(), Some("linux-hwe-6.8"));
        let low = Kernel::parse("6.8.0-60-lowlatency", Some("#63~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC")).unwrap();
        assert_eq!(low.ubuntu_package().as_deref(), Some("linux-lowlatency-hwe-6.8"));
        // The cloud backports are named less regularly; none is guessed.
        let aws = Kernel::parse("6.8.0-1021-aws", Some("#23~22.04.1-Ubuntu SMP")).unwrap();
        assert_eq!(aws.ubuntu_package(), None);

        let debian = Kernel::parse("6.12.48+deb13-amd64", Some("#1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1")).unwrap();
        assert!(!debian.ubuntu);
        assert_eq!(debian.comps, [6, 12, 48]);
        assert!(Kernel::parse("weird", None).is_none());
    }

    #[test]
    fn fixed_in_matches_by_series() {
        let list: Vec<String> = ["6.12.117", "6.18.63", "7.3.4"].iter().map(|s| s.to_string()).collect();
        let patch = |rel: &str| patch_from_fixed_in(&Kernel::parse(rel, None).unwrap(), &list);
        assert_eq!(patch("6.12.117"), Some(Patch::Fixed("6.12.117".into())));
        assert_eq!(patch("6.12.120-amd64"), Some(Patch::Fixed("6.12.117".into())));
        assert_eq!(
            patch("6.12.48+deb13-amd64"),
            Some(Patch::Unpatched { fix: Some("6.12.117".into()) })
        );
        // Newer than every series the fix went to: released with it.
        assert_eq!(patch("7.4.0"), Some(Patch::Fixed("7.3 and later".into())));
        // Older, or an unsupported series in between: the list is silent, and
        // silence must not read as fixed.
        assert_eq!(patch("6.8.0-54-generic"), None);
        assert_eq!(patch("6.14.2"), None);
        assert_eq!(patch_from_fixed_in(&Kernel::parse("6.8.0-54-generic", None).unwrap(), &[]), None);
    }

    /// What `assess` says for a host that does not export the sysctl, which
    /// is every box whose exporter was left alone.
    fn blind(kernel: (&str, &str)) -> HostFacts {
        facts(kernel, None)
    }

    /// The fleet on 2026-11-18: 24.04 on 6.8, nothing exported but the
    /// kernel, Ubuntu not yet shipping a fix.
    #[test]
    fn unpatched_and_not_marked_mitigated_is_exposed() {
        let a = assess("fox", &noisytcp(), &blind(NOBLE_54), &untriaged(), false);
        let msg = unhealthy(&a.exposed);
        assert!(msg.contains("CVE-2026-99288 (NoisyTCP)"), "{msg}");
        assert!(msg.contains("No patched kernel is listed"), "{msg}");
        assert!(msg.contains("set net.ipv4.tcp_syncookies = 0"), "{msg}");
        assert!(msg.contains("add \"CVE-2026-99288\" to this host's `mitigated` list"), "{msg}");
        assert_eq!(a.upgrade, Some(Verdict::Healthy));
        assert_eq!(a.restore, Some(Verdict::Healthy));
    }

    #[test]
    fn marked_mitigated_with_no_fix_to_boot_is_quiet() {
        let a = assess("fox", &noisytcp(), &blind(NOBLE_54), &untriaged(), true);
        assert_eq!(a.exposed, Verdict::Healthy);
        assert_eq!(a.upgrade, Some(Verdict::Healthy));
        assert_eq!(a.restore, Some(Verdict::Healthy));
    }

    #[test]
    fn a_shipped_fix_asks_a_mitigated_box_to_upgrade() {
        let a = assess("fox", &noisytcp(), &blind(NOBLE_54), &released("6.8.0-151.161"), true);
        assert_eq!(a.exposed, Verdict::Healthy);
        let msg = unhealthy(a.upgrade.as_ref().unwrap());
        assert!(msg.contains("linux 6.8.0-151.161") && msg.contains("6.8.0-54-generic"), "{msg}");
        assert_eq!(a.restore, Some(Verdict::Healthy));

        // Not mitigated: one alert, not two, and it names both ways out.
        let a = assess("fox", &noisytcp(), &blind(NOBLE_54), &released("6.8.0-151.161"), false);
        let msg = unhealthy(&a.exposed);
        assert!(msg.contains("upgrade and reboot.") && msg.contains("set net.ipv4.tcp_syncookies = 0"), "{msg}");
        assert_eq!(a.upgrade, Some(Verdict::Healthy));
    }

    #[test]
    fn the_fixed_kernel_still_marked_mitigated_asks_to_undo_it() {
        let fixed = ("6.8.0-151-generic", "#161-Ubuntu SMP PREEMPT_DYNAMIC");
        let a = assess("fox", &noisytcp(), &blind(fixed), &released("6.8.0-151.161"), true);
        assert_eq!(a.exposed, Verdict::Healthy);
        assert_eq!(a.upgrade, Some(Verdict::Healthy));
        let msg = unhealthy(a.restore.as_ref().unwrap());
        assert!(msg.contains("Undo the temporary mitigation (net.ipv4.tcp_syncookies = 0)"), "{msg}");
        assert!(msg.contains("remove CVE-2026-99288 from this host's `mitigated` list"), "{msg}");

        let quiet = Assessment {
            exposed: Verdict::Healthy,
            upgrade: Some(Verdict::Healthy),
            restore: Some(Verdict::Healthy),
        };
        assert_eq!(assess("fox", &noisytcp(), &blind(fixed), &released("6.8.0-151.161"), false), quiet);
    }

    /// Same ABI, earlier upload: Ubuntu respins a kernel without bumping the
    /// ABI number, and the respin is the one with the fix.
    #[test]
    fn the_upload_number_decides_within_one_abi() {
        let early = ("6.8.0-151-generic", "#160-Ubuntu SMP PREEMPT_DYNAMIC");
        let a = assess("fox", &noisytcp(), &blind(early), &released("6.8.0-151.161"), false);
        assert!(matches!(a.exposed, Verdict::Unhealthy(_)));
    }

    /// An exporter that does report the sysctl is believed over the config,
    /// both ways: a declaration cannot hide a box that is visibly unmitigated,
    /// and a visibly mitigated box needs no declaration.
    #[test]
    fn an_exported_sysctl_outranks_the_declaration() {
        let on = facts(NOBLE_54, Some(1.0));
        let msg = unhealthy(&assess("fox", &noisytcp(), &on, &untriaged(), true).exposed).to_string();
        assert!(msg.contains("net.ipv4.tcp_syncookies is 1; set it to 0"), "{msg}");
        assert!(msg.contains("marks this host mitigated, but that is not what it reports"), "{msg}");
        assert!(!msg.contains("perch cannot see"), "{msg}");

        let off = facts(NOBLE_54, Some(0.0));
        assert_eq!(assess("fox", &noisytcp(), &off, &untriaged(), false).exposed, Verdict::Healthy);

        let fixed = ("6.8.0-151-generic", "#161-Ubuntu SMP PREEMPT_DYNAMIC");
        let a = assess("fox", &noisytcp(), &facts(fixed, Some(0.0)), &released("6.8.0-151.161"), false);
        let msg = unhealthy(a.restore.as_ref().unwrap());
        assert!(msg.contains("is still 0, the temporary mitigation. Restore its previous value."), "{msg}");
        assert!(!msg.contains("`mitigated` list"), "{msg}");
    }

    /// Not being able to see a sysctl is no longer a reason to say nothing:
    /// only a kernel that cannot be placed is.
    #[test]
    fn only_an_unplaceable_kernel_is_unknown() {
        let unknown = |v: &Verdict| match v {
            Verdict::Unknown(m) => m.clone(),
            other => panic!("expected unknown, got {other:?}"),
        };
        // A remote host whose exporter has no uname collector.
        let a = assess("fox", &noisytcp(), &HostFacts::default(), &untriaged(), false);
        assert!(unknown(&a.exposed).contains("--collector.uname"));
        // One check says so, not three.
        assert_eq!((a.upgrade, a.restore), (None, None));

        // An Ubuntu kernel with no release codename to look it up under.
        let mut f = blind(NOBLE_54);
        f.os_id = None;
        f.os_codename = None;
        assert!(unknown(&assess("fox", &noisytcp(), &f, &untriaged(), false).exposed).contains("--collector.os"));

        // Tracker not fetched: no claim either way.
        let a = assess("fox", &noisytcp(), &blind(NOBLE_54), &Tracked::new(), false);
        assert!(unknown(&a.exposed).contains("not been fetched"));

        // A backport whose package the release does not carry (the fixture
        // lists linux-hwe-6.8 on noble as DNE), and one that is never guessed.
        let hwe = ("6.8.0-60-generic", "#63~22.04.1-Ubuntu SMP");
        let why = assess("fox", &noisytcp(), &blind(hwe), &untriaged(), false).exposed;
        assert!(unknown(&why).contains("no linux-hwe-6.8 for noble"), "{why:?}");
        assert!(unknown(&why).contains("fixed_in"), "{why:?}");
        let aws = ("6.8.0-1021-aws", "#23~22.04.1-Ubuntu SMP");
        assert!(unknown(&assess("fox", &noisytcp(), &blind(aws), &untriaged(), false).exposed).contains("fixed_in"));
    }

    /// fox-main's replacement on 2026-11-24: Ubuntu 24.04 on the 7.0 HWE
    /// kernel. perch could not place it and left both advisories unknown,
    /// though Ubuntu tracks linux-hwe-7.0 on its own rows, as below.
    fn hwe_7_0(id: &str, status: &str, description: &str) -> Tracked {
        let body = format!(
            r#"{{"id":"{id}","packages":[
                {{"name":"linux","statuses":[
                    {{"release_codename":"noble","status":"released","description":"6.8.0-149.149"}},
                    {{"release_codename":"resolute","status":"released","description":"7.0.0-43.43"}}]}},
                {{"name":"linux-hwe-7.0","statuses":[
                    {{"release_codename":"resolute","status":"DNE","description":""}},
                    {{"release_codename":"noble","status":"{status}","description":"{description}"}}]}}]}}"#
        );
        HashMap::from([(id.to_string(), UbuntuCve::parse(&body).unwrap())])
    }

    const NOBLE_HWE_43: (&str, &str) = ("7.0.0-43-generic", "#43~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Sat Oct 31 06:52:47 UTC 2026");

    #[test]
    fn an_hwe_kernel_is_judged_on_its_own_tracker_row() {
        let adv = AdvisoryConfig { id: "CVE-2026-98432".into(), fixed_in: vec![], mitigation: None, ..noisytcp() };
        let fixed = hwe_7_0("CVE-2026-98432", "released", "7.0.0-43.43~24.04.1");
        let a = assess("fox", &adv, &blind(NOBLE_HWE_43), &fixed, false);
        assert_eq!(a.exposed, Verdict::Healthy);

        // One upload short of the fix: exposed, and told what to boot. Read
        // against noble's own `linux` row (6.8.0-149), 7.0.0-42 would pass.
        let older = ("7.0.0-42-generic", "#42~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC");
        let a = assess("fox", &adv, &blind(older), &fixed, false);
        assert!(unhealthy(&a.exposed).contains("linux-hwe-7.0 7.0.0-43.43~24.04.1"), "{:?}", a.exposed);
    }

    /// No fix yet for the HWE series: exposed until the operator declares the
    /// mitigation, like any other kernel.
    #[test]
    fn an_hwe_kernel_with_no_fix_yet_follows_the_mitigation() {
        let adv = AdvisoryConfig { fixed_in: vec![], ..noisytcp() };
        let needed = hwe_7_0("CVE-2026-99288", "needed", "");
        let a = assess("fox", &adv, &blind(NOBLE_HWE_43), &needed, false);
        assert!(unhealthy(&a.exposed).contains("No patched kernel is listed"), "{:?}", a.exposed);
        let a = assess("fox", &adv, &blind(NOBLE_HWE_43), &needed, true);
        assert_eq!(a.exposed, Verdict::Healthy);
    }

    #[test]
    fn fixed_in_for_the_series_overrides_the_tracker() {
        let mut adv = noisytcp();
        adv.fixed_in.push("6.8.0-60".into());
        let hwe = ("6.8.0-60-generic", "#63~22.04.1-Ubuntu SMP");
        let a = assess("fox", &adv, &blind(hwe), &Tracked::new(), false);
        assert_eq!(a.exposed, Verdict::Healthy);
    }

    #[test]
    fn upstream_kernels_are_judged_from_fixed_in_alone() {
        let adv = AdvisoryConfig { tracker: None, mitigation: None, ..noisytcp() };
        let debian = ("6.12.48+deb13-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1");
        let a = assess("deb", &adv, &blind(debian), &Tracked::new(), false);
        assert!(unhealthy(&a.exposed).contains("The fix is in 6.12.117"));

        let a = assess("deb", &adv, &blind(("6.12.117-amd64", "#1 SMP")), &Tracked::new(), false);
        assert_eq!(a.exposed, Verdict::Healthy);
    }

    /// CVE-2026-98432: the stopgap is a firewall rule. perch cannot see one,
    /// so the advisory carries the steps as a note and the operator declares
    /// them done.
    #[test]
    fn a_stopgap_perch_cannot_see_is_declared_not_guessed() {
        let adv = builtin().unwrap().into_iter().find(|a| a.id == "CVE-2026-98432").unwrap();
        assert!(adv.mitigation.is_none());
        let fixed = |codename: &str, v: &str| {
            let body = format!(
                r#"{{"packages":[{{"name":"linux","statuses":[
                    {{"release_codename":"{codename}","status":"released","description":"{v}"}}]}}]}}"#
            );
            HashMap::from([(adv.id.clone(), UbuntuCve::parse(&body).unwrap())])
        };
        // fox_test on 2026-11-18: 6.8.0-85, with the fix in 6.8.0-149.149.
        let old = ("6.8.0-85-generic", "#85-Ubuntu SMP PREEMPT_DYNAMIC");
        let noble = fixed("noble", "6.8.0-149.149");
        let a = assess("fox", &adv, &blind(old), &noble, false);
        let msg = unhealthy(&a.exposed);
        assert!(msg.contains("The fix is in linux 6.8.0-149.149: upgrade and reboot."), "{msg}");
        assert!(msg.contains("IPv4 options"), "{msg}");
        assert!(msg.contains("add \"CVE-2026-98432\" to this host's `mitigated` list"), "{msg}");

        // Declared mitigated: no longer exposed, still told the fix is out.
        let a = assess("fox", &adv, &blind(old), &noble, true);
        assert_eq!(a.exposed, Verdict::Healthy);
        assert!(unhealthy(a.upgrade.as_ref().unwrap()).contains("a patched kernel now exists"));

        // failover, on the fixed build, and mind_test on 26.04.
        let new = ("6.8.0-149-generic", "#149-Ubuntu SMP PREEMPT_DYNAMIC");
        assert_eq!(assess("failover", &adv, &blind(new), &noble, false).exposed, Verdict::Healthy);
        let mut resolute = blind(("7.0.0-43-generic", "#43-Ubuntu SMP PREEMPT_DYNAMIC"));
        resolute.os_codename = Some("resolute".into());
        let a = assess("mind", &adv, &resolute, &fixed("resolute", "7.0.0-43.43"), false);
        assert_eq!(a.exposed, Verdict::Healthy);

        // Upstream numbering, from fixed_in alone.
        let adv = AdvisoryConfig { tracker: None, ..adv };
        let stable = |rel: &str| assess("deb", &adv, &blind((rel, "#1 SMP")), &Tracked::new(), false).exposed;
        assert!(matches!(stable("6.12.112"), Verdict::Unhealthy(_)));
        assert_eq!(stable("6.12.113"), Verdict::Healthy);
        assert_eq!(stable("7.3.0"), Verdict::Healthy);
    }

    #[test]
    fn tracker_statuses_map_conservatively() {
        let k = blind(NOBLE_54);
        let exposed = |t: &Tracked| assess("fox", &noisytcp(), &k, t, false).exposed;
        assert_eq!(exposed(&tracked(r#"{"status":"not-affected","description":"6.5.0-9.9"}"#)), Verdict::Healthy);
        assert!(matches!(exposed(&tracked(r#"{"status":"needed","description":""}"#)), Verdict::Unhealthy(_)));
        // "ignored" and "DNE" describe the package, not the fix.
        assert!(matches!(exposed(&tracked(r#"{"status":"ignored","description":"end of life"}"#)), Verdict::Unknown(_)));
        assert!(matches!(exposed(&tracked(r#"{"status":"released","description":""}"#)), Verdict::Unknown(_)));
        assert!(UbuntuCve::parse(r#"{"packages":[{"name":"openssl","statuses":[]}]}"#).is_err());
        assert!(UbuntuCve::parse("<html>502</html>").is_err());
    }
}

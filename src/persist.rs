//! On-disk state, so a restart does not orphan a live incident.
//!
//! Without this, restarting perch while an alert is firing loses the
//! PagerDuty dedup key. The resolve is later sent under a fresh UUID that
//! PagerDuty has never seen, and the real incident stays open forever. Deploys
//! and reboots are routine; losing incident continuity to them is not
//! acceptable in a paging system.

use crate::{
    checks::{DiskHistory, Progress},
    fillrate::FillHistory,
    state::{BlindnessState, CheckSnapshot, CheckState},
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

/// Bumped only for *breaking* changes. New fields are added with
/// `#[serde(default)]` instead, so upgrading perch never discards state --
/// discarding it mid-incident would orphan an open PagerDuty incident, which is
/// exactly what this file exists to prevent.
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedCheck {
    pub unhealthy_for_secs: u64,
    pub healthy_streak: u32,
    pub firing: bool,
    pub incident_key: String,
    pub incident_closed: bool,
    pub pending_ago_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedState {
    pub version: u32,
    pub saved_at_unix: u64,
    pub checks: HashMap<String, PersistedCheck>,
    /// Checks we actually sent a trigger for. An inhibited check never gets a
    /// trigger, and so must never get a resolve either.
    pub announced: Vec<String>,
    pub validator_credits: HashMap<String, u64>,
    pub cluster_slot: Option<u64>,
    pub blind_incident_key: Option<String>,
    pub blind_announced: bool,
    /// Maintenance windows peers declared while still reachable. Must survive a
    /// hub restart: forgetting one means paging for a box that is deliberately
    /// down, which is exactly what the declaration was for.
    #[serde(default)]
    pub peer_maintenance: HashMap<String, u64>,
    /// Free-space history per filesystem, for the time-to-full projection.
    /// Losing it across a restart would blind the fill checks for the whole
    /// `min_history` window.
    #[serde(default)]
    pub disk_history: HashMap<String, FillHistory>,
    /// Unix time of the last successful notification self-test. Persisted so a
    /// restart cannot reset the clock -- a box that reboots weekly would
    /// otherwise never reach its interval and never test the path at all.
    #[serde(default)]
    pub last_self_test_unix: u64,
    /// Last epoch an epoch digest was sent for. Persisted so a restart inside
    /// an epoch neither repeats the summary nor sends one for an epoch it did
    /// not watch.
    #[serde(default)]
    pub last_digest_epoch: Option<u64>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Restored {
    pub states: HashMap<String, CheckState>,
    pub announced: HashSet<String>,
    pub peer_maintenance: HashMap<String, u64>,
    pub downtime: Duration,
    pub last_self_test_unix: u64,
    pub last_digest_epoch: Option<u64>,
}

/// Write atomically: a torn state file read at the next boot would be worse than
/// no state file at all.
#[allow(clippy::too_many_arguments)]
pub fn save(
    path: &Path,
    states: &HashMap<String, CheckState>,
    announced: &HashSet<String>,
    peer_maintenance: &HashMap<String, u64>,
    progress: &Progress,
    disk: &DiskHistory,
    blindness: &BlindnessState,
    blind_announced: bool,
    last_self_test_unix: u64,
    last_digest_epoch: Option<u64>,
    now: Instant,
) -> Result<()> {
    let (validator_credits, cluster_slot) = progress.export();

    let state = PersistedState {
        version: FORMAT_VERSION,
        saved_at_unix: now_unix(),
        checks: states
            .iter()
            .map(|(id, s)| {
                let snap = s.snapshot(now);
                (
                    id.clone(),
                    PersistedCheck {
                        unhealthy_for_secs: snap.unhealthy_for.as_secs(),
                        healthy_streak: snap.healthy_streak,
                        firing: snap.firing,
                        incident_key: snap.incident_key,
                        incident_closed: snap.incident_closed,
                        pending_ago_secs: snap.pending_ago.map(|d| d.as_secs()),
                    },
                )
            })
            .collect(),
        announced: announced.iter().cloned().collect(),
        peer_maintenance: peer_maintenance.clone(),
        validator_credits,
        cluster_slot,
        blind_incident_key: blindness.incident_key().map(str::to_string),
        blind_announced,
        disk_history: disk.export(),
        last_self_test_unix,
        last_digest_epoch,
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
    }

    let tmp: PathBuf = path.with_extension("tmp");
    let encoded = serde_json::to_vec_pretty(&state)?;
    std::fs::write(&tmp, &encoded)
        .with_context(|| format!("writing state to {}", tmp.display()))?;
    // Group-readable so `perch status`, run by an operator in the perch group,
    // reports the real check states instead of an empty file it cannot open.
    // Nothing in here is secret: check states, durations, incident keys.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640));
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replacing state file {}", path.display()))?;
    Ok(())
}

/// Load prior state. Any problem -- missing, unreadable, corrupt, wrong version
/// -- starts clean with a warning rather than failing to boot. A watchtower that
/// will not start because of its own bookkeeping file is worse than one that
/// forgets.
pub fn load(
    path: &Path,
    progress: &mut Progress,
    disk: &mut DiskHistory,
    blindness: &mut BlindnessState,
) -> Restored {
    let empty = Restored {
        states: HashMap::new(),
        announced: HashSet::new(),
        peer_maintenance: HashMap::new(),
        downtime: Duration::ZERO,
        last_self_test_unix: 0,
        last_digest_epoch: None,
    };

    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("no prior state at {}; starting fresh", path.display());
            return empty;
        }
        Err(e) => {
            warn!("could not read state file {}: {e}; starting fresh", path.display());
            return empty;
        }
    };

    let parsed: PersistedState = match serde_json::from_slice(&raw) {
        Ok(p) => p,
        Err(e) => {
            warn!("state file {} is unreadable ({e}); starting fresh", path.display());
            return empty;
        }
    };

    if parsed.version != FORMAT_VERSION {
        warn!(
            "state file {} is version {}, expected {FORMAT_VERSION}; starting fresh",
            path.display(),
            parsed.version
        );
        return empty;
    }

    let downtime = Duration::from_secs(now_unix().saturating_sub(parsed.saved_at_unix));
    let now = Instant::now();

    let states: HashMap<String, CheckState> = parsed
        .checks
        .iter()
        .map(|(id, c)| {
            let snap = CheckSnapshot {
                unhealthy_for: Duration::from_secs(c.unhealthy_for_secs),
                healthy_streak: c.healthy_streak,
                firing: c.firing,
                incident_key: c.incident_key.clone(),
                incident_closed: c.incident_closed,
                pending_ago: c.pending_ago_secs.map(Duration::from_secs),
            };
            (id.clone(), CheckState::restore(&snap, downtime, now))
        })
        .collect();

    progress.import(parsed.validator_credits, parsed.cluster_slot);
    disk.import(parsed.disk_history);
    blindness.restore(parsed.blind_incident_key, parsed.blind_announced);

    let firing = states.values().filter(|s| s.is_firing()).count();
    info!(
        "restored {} check state(s) after {} of downtime; {firing} still firing",
        states.len(),
        humantime::format_duration(Duration::from_secs(downtime.as_secs()))
    );

    Restored {
        states,
        announced: parsed.announced.into_iter().collect(),
        peer_maintenance: parsed.peer_maintenance,
        downtime,
        last_self_test_unix: parsed.last_self_test_unix,
        last_digest_epoch: parsed.last_digest_epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CheckConfig, Severity};
    use crate::state::Transition;

    pub(super) fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("perch-persist-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg() -> CheckConfig {
        CheckConfig {
            enabled: true,
            pending_for: Duration::ZERO,
            clear_after: 1,
            severity: Severity::Page,
            renotify_after: Duration::ZERO,
        }
    }

    #[test]
    fn a_firing_incident_survives_a_restart_and_resolves_under_its_original_key() {
        let dir = tmpdir();
        let path = dir.join("state.json");

        let mut states = HashMap::new();
        let mut s = CheckState::default();
        let now = Instant::now();
        assert_eq!(
            s.on_unhealthy(&cfg(), Duration::from_secs(60), now),
            Transition::Firing
        );
        let key = s.incident_key().to_string();
        states.insert("vote_delinquent:chimps-1".to_string(), s);

        let announced: HashSet<String> =
            ["vote_delinquent:chimps-1".to_string()].into_iter().collect();
        let mut progress = Progress::default();
        progress.import(
            [("id-1".to_string(), 41_900u64)].into_iter().collect(),
            Some(312_874_910),
        );
        let blindness = BlindnessState::default();

        let mut disk = DiskHistory::default();
        let mut fh = FillHistory::default();
        fh.record(1_000, 500 * 1_073_741_824, Duration::ZERO, Duration::from_secs(21_600));
        fh.record(1_300, 499 * 1_073_741_824, Duration::ZERO, Duration::from_secs(21_600));
        disk.import([("host-a\u{1f}/mnt/ledger".to_string(), fh)].into_iter().collect());

        let maint: HashMap<String, u64> =
            [("chimpions-mainnet".to_string(), 9_999_999_999u64)].into_iter().collect();
        save(
            &path, &states, &announced, &maint, &progress, &disk, &blindness, false, 1_700_000_000,
            None, now,
        )
        .unwrap();

        // Restart.
        let mut progress2 = Progress::default();
        let mut disk2 = DiskHistory::default();
        let mut blindness2 = BlindnessState::default();
        let mut restored = load(&path, &mut progress2, &mut disk2, &mut blindness2);

        let mut check = restored.states.remove("vote_delinquent:chimps-1").unwrap();
        assert!(check.is_firing());
        assert_eq!(check.incident_key(), key);
        assert!(restored.announced.contains("vote_delinquent:chimps-1"));
        assert_eq!(
            restored.peer_maintenance.get("chimpions-mainnet"),
            Some(&9_999_999_999u64),
            "a declared maintenance window must survive a hub restart"
        );
        assert_eq!(progress2.export().1, Some(312_874_910));
        assert_eq!(
            disk2.export().get("host-a\u{1f}/mnt/ledger").map(|h| h.len()),
            Some(2),
            "fill history must survive a restart or the projection goes blind"
        );

        assert_eq!(
            check.on_healthy(&cfg(), Instant::now()),
            Transition::Resolved
        );
        assert_eq!(check.incident_key(), key);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_state_file_starts_clean_instead_of_refusing_to_boot() {
        let dir = tmpdir();
        let path = dir.join("state.json");
        std::fs::write(&path, b"{ this is not json").unwrap();

        let restored = load(
            &path,
            &mut Progress::default(),
            &mut DiskHistory::default(),
            &mut BlindnessState::default(),
        );
        assert!(restored.states.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_state_file_from_another_version_is_discarded() {
        let dir = tmpdir();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "version": 999, "saved_at_unix": 0, "checks": {}, "announced": [],
                "validator_credits": {}, "cluster_slot": null,
                "blind_incident_key": null, "blind_announced": false
            }))
            .unwrap(),
        )
        .unwrap();

        let restored = load(
            &path,
            &mut Progress::default(),
            &mut DiskHistory::default(),
            &mut BlindnessState::default(),
        );
        assert!(restored.states.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_state_file_is_not_an_error() {
        let restored = load(
            Path::new("/nonexistent/perch/state.json"),
            &mut Progress::default(),
            &mut DiskHistory::default(),
            &mut BlindnessState::default(),
        );
        assert!(restored.states.is_empty());
        assert_eq!(restored.downtime, Duration::ZERO);
    }

    #[test]
    fn saving_creates_the_parent_directory() {
        let dir = tmpdir();
        let path = dir.join("nested").join("deeper").join("state.json");
        save(
            &path,
            &HashMap::new(),
            &HashSet::new(),
            &HashMap::new(),
            &Progress::default(),
            &DiskHistory::default(),
            &BlindnessState::default(),
            false,
            0,
            None,
            Instant::now(),
        )
        .unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saving_leaves_no_temp_file_behind() {
        let dir = tmpdir();
        let path = dir.join("state.json");
        save(
            &path,
            &HashMap::new(),
            &HashSet::new(),
            &HashMap::new(),
            &Progress::default(),
            &DiskHistory::default(),
            &BlindnessState::default(),
            false,
            0,
            None,
            Instant::now(),
        )
        .unwrap();
        assert!(!path.with_extension("tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod self_test_clock {
    use super::tests::tmpdir;
    use super::*;

    #[test]
    fn the_self_test_clock_survives_a_restart() {
        let d = tmpdir();
        let path = d.join("state.json");
        save(
            &path,
            &HashMap::new(),
            &HashSet::new(),
            &HashMap::new(),
            &Progress::default(),
            &DiskHistory::default(),
            &BlindnessState::default(),
            false,
            1_700_000_000,
            None,
            Instant::now(),
        )
        .unwrap();

        let restored = load(
            &path,
            &mut Progress::default(),
            &mut DiskHistory::default(),
            &mut BlindnessState::default(),
        );
        assert_eq!(
            restored.last_self_test_unix, 1_700_000_000,
            "a reboot must not reset the interval, or a box that restarts often never tests at all"
        );
    }

    /// Every deployed box already has a state.json written before this field
    /// existed. Refusing to parse one would discard every hold-down clock on
    /// upgrade -- the precise failure that once cost a delinquency page.
    #[test]
    fn state_written_before_this_field_existed_still_loads() {
        let d = tmpdir();
        let path = d.join("state.json");
        let legacy = format!(
            r#"{{"version":{FORMAT_VERSION},"saved_at_unix":1700000000,"checks":{{}},
               "announced":[],"validator_credits":{{}},"cluster_slot":null,
               "blind_incident_key":null,"blind_announced":false}}"#
        );
        std::fs::write(&path, legacy).unwrap();

        let restored = load(
            &path,
            &mut Progress::default(),
            &mut DiskHistory::default(),
            &mut BlindnessState::default(),
        );
        assert_eq!(restored.last_self_test_unix, 0);
    }
}

//! Prometheus exposition over a minimal HTTP server.
//!
//! Alerts tell you something is wrong now; metrics tell you what the hours
//! before it looked like. They also make the watchtower's own behaviour
//! reviewable -- which endpoints are actually reliable, how close checks come to
//! their thresholds without crossing -- which is how you tune hold-downs on
//! evidence instead of on a hunch.
//!
//! Hand-rolled rather than pulling in a metrics crate and an HTTP framework: one
//! endpoint serving one text format does not justify the dependency surface.

use crate::{
    checks::{split_disk_key, CheckOutcome, DiskHistory},
    fillrate::Projection,
    node_exporter::HostSnapshot,
    notify::NotifyCounts,
    peer::PeerStatus,
    snapshot::{lamports_to_sol, Snapshot},
    state::CheckState,
    verdict::Verdict,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing::info;

#[derive(Debug, Default, Clone)]
pub struct EndpointHealth {
    pub cycles: u64,
    pub usable: u64,
    pub transient_errors: u64,
    pub config_errors: u64,
}

impl EndpointHealth {
    pub fn success_rate(&self) -> f64 {
        if self.cycles == 0 {
            return 0.0;
        }
        self.usable as f64 * 100.0 / self.cycles as f64
    }
}

/// Holds the most recently rendered exposition. Rendering happens once per
/// cycle; scrapes just read the string, so a scrape can never block a cycle.
#[derive(Clone)]
pub struct Metrics {
    body: Arc<RwLock<String>>,
    html: Arc<RwLock<String>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            body: Arc::new(RwLock::new(String::from(
                "# perch has not completed a cycle yet\n",
            ))),
            html: Arc::new(RwLock::new(String::from(
                "<!doctype html><title>perch</title><body style=\"font-family:monospace\">Starting up; no cycle completed yet.",
            ))),
        }
    }

    pub fn set(&self, rendered: String) {
        if let Ok(mut b) = self.body.write() {
            *b = rendered;
        }
    }

    pub fn set_html(&self, rendered: String) {
        if let Ok(mut b) = self.html.write() {
            *b = rendered;
        }
    }

    fn get_html(&self) -> String {
        self.html
            .read()
            .map(|b| b.clone())
            .unwrap_or_else(|_| "<!doctype html><title>perch</title>unavailable".into())
    }

    fn get(&self) -> String {
        self.body
            .read()
            .map(|b| b.clone())
            .unwrap_or_else(|_| "# metrics unavailable\n".into())
    }

    pub async fn serve(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        info!("metrics listening on http://{bound}/metrics");

        let body = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();

                    let (status, content_type, payload) = match path.as_str() {
                        "/metrics" => (
                            "200 OK",
                            "text/plain; version=0.0.4; charset=utf-8",
                            body.get(),
                        ),
                        "/" => (
                            "200 OK",
                            "text/html; charset=utf-8",
                            body.get_html(),
                        ),
                        _ => ("404 Not Found", "text/plain; charset=utf-8", String::new()),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Ok(())
    }
}

/// Prometheus label values may not contain a raw backslash, quote or newline.
/// Validator labels are operator-supplied, so this is not hypothetical.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

struct Exposition {
    out: String,
}

impl Exposition {
    fn new() -> Self {
        Self { out: String::new() }
    }

    fn metric(&mut self, name: &str, help: &str, kind: &str) -> &mut Self {
        let _ = writeln!(self.out, "# HELP {name} {help}");
        let _ = writeln!(self.out, "# TYPE {name} {kind}");
        self
    }

    fn value(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        if labels.is_empty() {
            let _ = writeln!(self.out, "{name} {value}");
            return;
        }
        let rendered: Vec<String> = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
            .collect();
        let _ = writeln!(self.out, "{name}{{{}}} {value}", rendered.join(","));
    }
}

pub struct CycleReport<'a> {
    pub snapshots: &'a [Snapshot],
    pub host_snapshots: &'a [HostSnapshot],
    pub peers: &'a [PeerStatus],
    pub is_owner: bool,
    pub disk: &'a DiskHistory,
    pub outcomes: &'a [CheckOutcome],
    pub states: &'a HashMap<String, CheckState>,
    pub endpoint_health: &'a HashMap<String, EndpointHealth>,
    pub suppressed: &'a HashMap<String, String>,
    pub visible: bool,
    pub silenced: bool,
    pub cycle_duration: Duration,
    pub unix_time: u64,
    /// Unix deadline of an active maintenance window, or 0.
    pub maintenance_until: u64,
    /// Unix time this process started. Lets a peer distinguish "has not cycled
    /// yet because it just booted" from "has not cycled because it is wedged".
    pub start_time: u64,
    /// Delivery counters for the notification channels themselves.
    pub notify: NotifyCounts,
    /// Clean cycles banked toward auto-resuming an `auto` maintenance window.
    pub maintenance_streak: u32,
    /// An `auto` window is armed but the validator has not gone unhealthy yet --
    /// the operator has armed it and not started the work.
    pub maintenance_awaiting_work: bool,
    /// `[watchtower] name`, and the cluster it is pinned to ("unpinned" if not).
    /// Exported so a dashboard can label and group instances without the
    /// operator having to add relabeling rules to Prometheus.
    pub watchtower_name: &'a str,
    pub solana_cluster: &'a str,
    /// Identity pubkey -> configured label, so graphs say "chimps-1" rather
    /// than a 44-character key.
    pub validator_labels: &'a HashMap<String, String>,
    /// Which checks are this instance's own to show as firing.
    pub alerting: crate::config::Alerting,
}

/// Duplicate a rendered exposition under a second metric prefix.
///
/// Purely a rename shim. A fleet cannot be renamed atomically, so for the
/// duration of a rollout the old names have to keep answering -- for the half of
/// the fleet still running the old binary, and for every dashboard and alert
/// rule written against them. Delete the config key and this function once the
/// rollout is finished.
pub fn with_compat_alias(rendered: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(rendered.len() * 2);
    for line in rendered.lines() {
        out.push_str(line);
        out.push('\n');
        let aliased = if let Some(rest) = line.strip_prefix("# HELP perch_") {
            Some(format!("# HELP {prefix}_{rest}"))
        } else if let Some(rest) = line.strip_prefix("# TYPE perch_") {
            Some(format!("# TYPE {prefix}_{rest}"))
        } else {
            line.strip_prefix("perch_").map(|rest| format!("{prefix}_{rest}"))
        };
        if let Some(a) = aliased {
            out.push_str(&a);
            out.push('\n');
        }
    }
    out
}

pub fn render(r: &CycleReport<'_>) -> String {
    let mut e = Exposition::new();

    // `solana_cluster`, not `cluster`: Prometheus setups commonly attach their
    // own `cluster` target label, and a clash would rename ours out of reach.
    e.metric(
        "perch_watchtower_info",
        "This instance's [watchtower] name and the Solana cluster it watches. Always 1.",
        "gauge",
    );
    e.value(
        "perch_watchtower_info",
        &[("name", r.watchtower_name), ("solana_cluster", r.solana_cluster)],
        1.0,
    );

    e.metric("perch_build_info", "Build information", "gauge");
    e.value(
        "perch_build_info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("commit", crate::COMMIT),
        ],
        1.0,
    );

    // The watchtower watching its own mouth. Every other metric here describes
    // the validators; these describe whether anything said about them can
    // actually leave the box.
    // The version each box is actually running. Only local endpoints report one,
    // so every instance describes its own validator and nobody else's.
    // Makes the auto-resume legible instead of a black box: you can see whether
    // a window is still waiting for the work to start, or counting clean cycles.
    e.metric(
        "perch_maintenance_healthy_streak",
        "Consecutive clean cycles banked toward auto-resuming maintenance (2 resumes)",
        "gauge",
    );
    e.value(
        "perch_maintenance_healthy_streak",
        &[],
        r.maintenance_streak as f64,
    );
    e.metric(
        "perch_maintenance_awaiting_work",
        "1 when an auto maintenance window is armed but the work has not started yet",
        "gauge",
    );
    e.value(
        "perch_maintenance_awaiting_work",
        &[],
        r.maintenance_awaiting_work as u8 as f64,
    );

    e.metric(
        "perch_node_version",
        "Validator software reported by a local endpoint. Always 1; read the labels.",
        "gauge",
    );
    for s in r.snapshots {
        if let Some(v) = &s.version {
            let fs = v.feature_set.to_string();
            e.value(
                "perch_node_version",
                &[
                    ("endpoint", s.endpoint.as_str()),
                    ("version", v.solana_core.as_str()),
                    ("feature_set", fs.as_str()),
                ],
                1.0,
            );
        }
    }

    e.metric(
        "perch_notify_deliveries_total",
        "Notifications delivered successfully, by channel",
        "counter",
    );
    e.metric(
        "perch_notify_failures_total",
        "Notifications that failed every retry and were lost, by channel",
        "counter",
    );
    e.metric(
        "perch_notify_last_success_timestamp_seconds",
        "Unix time of the last successful delivery, by channel (0 if never)",
        "gauge",
    );
    e.metric(
        "perch_notify_self_test_failures_total",
        "Scheduled notification self-tests that failed, by channel",
        "counter",
    );
    e.metric(
        "perch_notify_self_test_timestamp_seconds",
        "Unix time of the last successful self-test, by channel (0 if never)",
        "gauge",
    );
    for (channel, c) in [
        ("pagerduty", r.notify.pagerduty),
        ("telegram", r.notify.telegram),
    ] {
        let at = [("channel", channel)];
        e.value("perch_notify_deliveries_total", &at, c.delivered as f64);
        e.value("perch_notify_failures_total", &at, c.failed as f64);
        e.value(
            "perch_notify_last_success_timestamp_seconds",
            &at,
            c.last_success_unix as f64,
        );
        e.value(
            "perch_notify_self_test_failures_total",
            &at,
            c.self_test_failed as f64,
        );
        e.value(
            "perch_notify_self_test_timestamp_seconds",
            &at,
            c.last_self_test_unix as f64,
        );
    }

    e.metric(
        "perch_visible",
        "1 when enough endpoints answered for checks to be evaluated",
        "gauge",
    );
    e.value("perch_visible", &[], r.visible as u8 as f64);

    e.metric(
        "perch_alerting_owner",
        "1 when this instance is the one responsible for notifying",
        "gauge",
    );
    e.value("perch_alerting_owner", &[], r.is_owner as u8 as f64);

    e.metric(
        "perch_maintenance_until_seconds",
        "Unix deadline of a declared maintenance window, or 0 if none. Peers remember this, so a box that reboots during planned work does not get reported as a dead machine.",
        "gauge",
    );
    e.value(
        "perch_maintenance_until_seconds",
        &[],
        r.maintenance_until as f64,
    );

    e.metric(
        "perch_silenced",
        "1 while a silence file is suppressing paging",
        "gauge",
    );
    e.value("perch_silenced", &[], r.silenced as u8 as f64);

    e.metric(
        "perch_start_timestamp_seconds",
        "Unix time this process started",
        "gauge",
    );
    e.value("perch_start_timestamp_seconds", &[], r.start_time as f64);

    e.metric(
        "perch_last_cycle_timestamp_seconds",
        "Unix time the last cycle completed",
        "gauge",
    );
    e.value(
        "perch_last_cycle_timestamp_seconds",
        &[],
        r.unix_time as f64,
    );

    e.metric(
        "perch_cycle_duration_seconds",
        "Wall time taken by the last probe cycle",
        "gauge",
    );
    e.value(
        "perch_cycle_duration_seconds",
        &[],
        r.cycle_duration.as_secs_f64(),
    );

    // --- endpoints ---
    e.metric(
        "perch_endpoint_usable",
        "1 when the endpoint returned a usable answer in the last cycle",
        "gauge",
    );
    for s in r.snapshots {
        e.value(
            "perch_endpoint_usable",
            &[("endpoint", &s.endpoint)],
            s.is_usable() as u8 as f64,
        );
    }

    e.metric(
        "perch_endpoint_slot",
        "Cluster slot as reported by each endpoint",
        "gauge",
    );
    for s in r.snapshots {
        if let Some(info) = &s.epoch_info {
            e.value(
                "perch_endpoint_slot",
                &[("endpoint", &s.endpoint)],
                info.absolute_slot as f64,
            );
        }
    }

    e.metric(
        "perch_endpoint_transient_errors_total",
        "Transient RPC errors seen since the last reliability digest",
        "counter",
    );
    e.metric(
        "perch_endpoint_config_errors_total",
        "Config-level RPC errors (bad key, wrong URL, unsupported plan)",
        "counter",
    );
    for (name, h) in r.endpoint_health {
        e.value(
            "perch_endpoint_transient_errors_total",
            &[("endpoint", name)],
            h.transient_errors as f64,
        );
        e.value(
            "perch_endpoint_config_errors_total",
            &[("endpoint", name)],
            h.config_errors as f64,
        );
    }

    // --- checks ---
    // The verdict gauge is the one to graph: it makes "we could not tell"
    // visible as its own state rather than collapsing it into healthy.
    e.metric(
        "perch_check_verdict",
        "Last verdict per check: 1 healthy, 0 unhealthy, -1 unknown",
        "gauge",
    );
    e.metric(
        "perch_check_firing",
        "1 when the check has crossed its hold-down and alerted",
        "gauge",
    );
    e.metric(
        "perch_check_unhealthy_seconds",
        "Observed time the check has been confirmed unhealthy",
        "gauge",
    );
    e.metric(
        "perch_check_pending_for_seconds",
        "Configured hold-down before the check may fire",
        "gauge",
    );
    e.metric(
        "perch_check_suppressed",
        "1 when the check is inhibited by a broader failure",
        "gauge",
    );
    e.metric(
        "perch_check_confirmations",
        "Endpoints independently reporting this check unhealthy",
        "gauge",
    );

    for o in r.outcomes {
        // A `peers` hub's validator checks are observation, not its own.
        if !r.alerting.owns_check(&o.id) {
            continue;
        }
        let labels = [("check", o.id.as_str())];
        let verdict = match &o.verdict {
            Verdict::Healthy => 1.0,
            Verdict::Unhealthy(_) => 0.0,
            Verdict::Unknown(_) => -1.0,
        };
        e.value("perch_check_verdict", &labels, verdict);
        e.value(
            "perch_check_confirmations",
            &labels,
            o.tally.unhealthy as f64,
        );
        e.value(
            "perch_check_pending_for_seconds",
            &labels,
            o.cfg.pending_for.as_secs_f64(),
        );
        e.value(
            "perch_check_suppressed",
            &labels,
            r.suppressed.contains_key(&o.id) as u8 as f64,
        );
        if let Some(state) = r.states.get(&o.id) {
            e.value(
                "perch_check_firing",
                &labels,
                state.is_firing() as u8 as f64,
            );
            e.value(
                "perch_check_unhealthy_seconds",
                &labels,
                state.unhealthy_for().as_secs_f64(),
            );
        }
    }

    // --- validators ---
    // Taken as the best value any endpoint reported, matching how the checks
    // themselves read progress.
    e.metric(
        "perch_validator_last_vote_slot",
        "Highest last-vote slot reported for the validator",
        "gauge",
    );
    e.metric(
        "perch_validator_root_slot",
        "Highest root slot reported for the validator",
        "gauge",
    );
    e.metric(
        "perch_validator_credits",
        "Highest cumulative vote credits reported for the validator",
        "gauge",
    );
    e.metric(
        "perch_validator_delinquent",
        "1 when any endpoint reported the validator delinquent",
        "gauge",
    );
    e.metric(
        "perch_validator_balance_sol",
        "Account balance in SOL",
        "gauge",
    );
    e.metric(
        "perch_validator_leader_slots",
        "Leader slots assigned this epoch",
        "gauge",
    );
    e.metric(
        "perch_validator_blocks_produced",
        "Blocks produced this epoch",
        "gauge",
    );
    e.metric(
        "perch_validator_skip_percent",
        "Percentage of assigned leader slots that produced no block",
        "gauge",
    );

    // --- Alpenglow admission ---
    // From the most advanced endpoint that reported the feature accounts.
    let alpenglow = r
        .snapshots
        .iter()
        .filter_map(|s| Some((s.alpenglow.as_ref()?, crate::checks::position(s)?)))
        .filter(|(_, p)| p.slots_in_epoch > 0)
        .max_by_key(|(_, p)| p.absolute_slot);
    e.metric(
        "perch_alpenglow_phase",
        "Alpenglow on this cluster: 0 not scheduled, 1 activates at the next epoch boundary, 2 active",
        "gauge",
    );
    e.metric(
        "perch_vat_per_epoch_sol",
        "Validator Admission Ticket burned from each vote account per epoch under Alpenglow",
        "gauge",
    );
    e.metric(
        "perch_vote_account_minimum_sol",
        "Balance a vote account must hold at the next epoch boundary to be admitted (rent-exempt plus one VAT)",
        "gauge",
    );
    if let Some((cluster, pos)) = alpenglow {
        let req = crate::alpenglow::requirement(cluster, &pos);
        let phase = match req.phase {
            crate::alpenglow::Phase::NotScheduled => 0.0,
            crate::alpenglow::Phase::ActivatesAtNextBoundary => 1.0,
            crate::alpenglow::Phase::Active => 2.0,
        };
        e.value("perch_alpenglow_phase", &[], phase);
        e.value("perch_vat_per_epoch_sol", &[], lamports_to_sol(req.vat_lamports));
        e.value("perch_vote_account_minimum_sol", &[], lamports_to_sol(req.minimum_lamports()));
    }
    e.metric(
        "perch_validator_vote_account_balance_sol",
        "Vote account balance in SOL. Under Alpenglow this pays the VAT every epoch.",
        "gauge",
    );
    e.metric(
        "perch_validator_vote_income_sol",
        "Commission paid into the vote account for the last completed epoch; absent when no endpoint keeps that history",
        "gauge",
    );
    e.metric(
        "perch_validator_vote_net_sol_per_epoch",
        "Commission income minus VAT per epoch. Negative is a vote account that drains under Alpenglow.",
        "gauge",
    );
    e.metric(
        "perch_validator_vote_runway_epochs",
        "Epoch boundaries the vote account still passes at its current net drain; absent when it is not draining",
        "gauge",
    );
    e.metric(
        "perch_validator_bls_registered",
        "1 when the vote account has a BLS public key, 0 when it does not; absent when no endpoint reports it",
        "gauge",
    );

    let mut identities: Vec<&String> = r
        .snapshots
        .iter()
        .flat_map(|s| s.validators.keys())
        .collect();
    identities.sort();
    identities.dedup();

    for identity in identities {
        let label = r
            .validator_labels
            .get(identity)
            .map(String::as_str)
            .unwrap_or(identity.as_str());
        let labels = [("identity", identity.as_str()), ("validator", label)];
        let infos: Vec<_> = r
            .snapshots
            .iter()
            .filter_map(|s| s.validators.get(identity))
            .collect();

        if let Some(v) = infos.iter().filter_map(|o| o.info()).map(|i| i.last_vote).max() {
            e.value("perch_validator_last_vote_slot", &labels, v as f64);
        }
        if let Some(v) = infos.iter().filter_map(|o| o.info()).map(|i| i.root_slot).max() {
            e.value("perch_validator_root_slot", &labels, v as f64);
        }
        if let Some(v) = infos
            .iter()
            .filter_map(|o| o.info())
            .map(|i| i.total_credits())
            .max()
        {
            e.value("perch_validator_credits", &labels, v as f64);
        }
        let delinquent = infos.iter().any(|o| {
            matches!(o, crate::snapshot::ValidatorObservation::Delinquent(_))
        });
        e.value(
            "perch_validator_delinquent",
            &labels,
            delinquent as u8 as f64,
        );

        if let Some(bp) = r
            .snapshots
            .iter()
            .filter_map(|s| s.block_production.get(identity))
            .max_by_key(|b| b.leader_slots)
        {
            e.value(
                "perch_validator_leader_slots",
                &labels,
                bp.leader_slots as f64,
            );
            e.value(
                "perch_validator_blocks_produced",
                &labels,
                bp.blocks_produced as f64,
            );
            e.value(
                "perch_validator_skip_percent",
                &labels,
                bp.skip_percent(),
            );
        }

        let votes: Vec<_> = r.snapshots.iter().filter_map(|s| s.vote_states.get(identity)).collect();
        if let Some(lamports) = votes.iter().map(|v| v.lamports).max() {
            e.value("perch_validator_vote_account_balance_sol", &labels, lamports_to_sol(lamports));
        }
        let income = crate::checks::income_for(r.snapshots, identity);
        if let Some(i) = income {
            e.value("perch_validator_vote_income_sol", &labels, lamports_to_sol(i));
        }
        if let (Some((cluster, pos)), Some(vote)) = (alpenglow, votes.iter().max_by_key(|v| v.lamports)) {
            let req = crate::alpenglow::requirement(cluster, &pos);
            let run = crate::alpenglow::runway(vote, &req, income);
            e.value("perch_validator_vote_net_sol_per_epoch", &labels, run.net_per_epoch as f64 / 1e9);
            if let Some(n) = run.boundaries {
                e.value("perch_validator_vote_runway_epochs", &labels, n as f64);
            }
        }
        use crate::alpenglow::Bls;
        if votes.iter().any(|v| v.bls == Bls::Registered) {
            e.value("perch_validator_bls_registered", &labels, 1.0);
        } else if votes.iter().any(|v| v.bls == Bls::Missing) {
            e.value("perch_validator_bls_registered", &labels, 0.0);
        }

        if let Some(lamports) = r
            .snapshots
            .iter()
            .filter_map(|s| s.identity_balances.get(identity).copied().flatten())
            .max()
        {
            e.value(
                "perch_validator_balance_sol",
                &[
                    ("identity", identity.as_str()),
                    ("validator", label),
                    ("account", "identity"),
                ],
                lamports_to_sol(lamports),
            );
        }

    }

    // --- disks ---
    if !r.host_snapshots.is_empty() {
        e.metric(
            "perch_host_scrape_ok",
            "1 when node_exporter answered in the last cycle",
            "gauge",
        );
        for h in r.host_snapshots {
            e.value(
                "perch_host_scrape_ok",
                &[("host", &h.host)],
                h.is_usable() as u8 as f64,
            );
        }

        e.metric(
            "perch_filesystem_avail_bytes",
            "Space available to unprivileged processes",
            "gauge",
        );
        e.metric(
            "perch_filesystem_size_bytes",
            "Total filesystem size",
            "gauge",
        );
        e.metric(
            "perch_filesystem_used_percent",
            "Percentage of the filesystem in use",
            "gauge",
        );
        e.metric(
            "perch_filesystem_inodes_used_percent",
            "Percentage of inodes in use; a filesystem can exhaust these with space to spare",
            "gauge",
        );
        e.metric(
            "perch_filesystem_readonly",
            "1 when the filesystem has been remounted read-only",
            "gauge",
        );

        for h in r.host_snapshots {
            let mut mounts: Vec<_> = h.filesystems.values().collect();
            mounts.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
            for fs in mounts {
                let labels = [
                    ("host", h.host.as_str()),
                    ("mountpoint", fs.mountpoint.as_str()),
                    ("device", fs.device.as_str()),
                ];
                e.value(
                    "perch_filesystem_avail_bytes",
                    &labels,
                    fs.avail_bytes as f64,
                );
                e.value(
                    "perch_filesystem_size_bytes",
                    &labels,
                    fs.size_bytes as f64,
                );
                e.value(
                    "perch_filesystem_used_percent",
                    &labels,
                    fs.used_percent(),
                );
                e.value(
                    "perch_filesystem_inodes_used_percent",
                    &labels,
                    fs.inodes_used_percent(),
                );
                e.value(
                    "perch_filesystem_readonly",
                    &labels,
                    fs.readonly as u8 as f64,
                );
            }
        }
    }

    if !r.peers.is_empty() {
        e.metric(
            "perch_peer_reachable",
            "1 when the peer's metrics endpoint answered",
            "gauge",
        );
        e.metric(
            "perch_peer_last_cycle_age_seconds",
            "How long ago the peer completed a cycle",
            "gauge",
        );
        e.metric(
            "perch_peer_visible",
            "1 when the peer could see the cluster in its last cycle",
            "gauge",
        );
        for p in r.peers {
            let labels = [("peer", p.name.as_str())];
            e.value(
                "perch_peer_reachable",
                &labels,
                p.reachable as u8 as f64,
            );
            if let Some(age) = p.last_cycle_age {
                e.value(
                    "perch_peer_last_cycle_age_seconds",
                    &labels,
                    age.as_secs_f64(),
                );
            }
            if let Some(v) = p.visible {
                e.value("perch_peer_visible", &labels, v as u8 as f64);
            }
        }
    }

    if !r.disk.projections().is_empty() {
        e.metric(
            "perch_filesystem_seconds_to_full",
            "Projected seconds until the filesystem fills, at the observed rate. Absent when not filling or when there is too little history to say.",
            "gauge",
        );
        e.metric(
            "perch_filesystem_fill_bytes_per_second",
            "Observed rate at which available space is being consumed",
            "gauge",
        );
        let mut keys: Vec<&String> = r.disk.projections().keys().collect();
        keys.sort();
        for key in keys {
            let Some((host, mountpoint)) = split_disk_key(key) else {
                continue;
            };
            let Some(Projection::Filling {
                time_to_full,
                bytes_per_sec,
            }) = r.disk.projections().get(key)
            else {
                // Deliberately emit nothing for NotFilling or Insufficient: a
                // sentinel like 0 or -1 would be graphed as a real value, and
                // "no data" is the honest rendering of "we cannot say".
                continue;
            };
            let labels = [("host", host), ("mountpoint", mountpoint)];
            e.value(
                "perch_filesystem_seconds_to_full",
                &labels,
                time_to_full.as_secs_f64(),
            );
            e.value(
                "perch_filesystem_fill_bytes_per_second",
                &labels,
                *bytes_per_sec,
            );
        }
    }

    e.out
}

#[cfg(test)]
static NO_LABELS: std::sync::LazyLock<HashMap<String, String>> =
    std::sync::LazyLock::new(HashMap::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        let mut e = Exposition::new();
        e.value("m", &[("check", "weird\"name\\here")], 1.0);
        assert!(e.out.contains(r#"check="weird\"name\\here""#), "got {}", e.out);
    }

    #[test]
    fn newlines_in_labels_cannot_break_the_exposition() {
        let mut e = Exposition::new();
        e.value("m", &[("check", "a\nb")], 1.0);
        assert_eq!(e.out.lines().count(), 1, "a label newline must not add a line");
    }

    #[test]
    fn unlabelled_metrics_render_bare() {
        let mut e = Exposition::new();
        e.value("perch_visible", &[], 1.0);
        assert_eq!(e.out.trim(), "perch_visible 1");
    }

    #[test]
    fn success_rate_of_an_unprobed_endpoint_is_zero_not_nan() {
        assert_eq!(EndpointHealth::default().success_rate(), 0.0);
    }

    #[test]
    fn success_rate_is_a_percentage_of_cycles() {
        let h = EndpointHealth {
            cycles: 8,
            usable: 6,
            transient_errors: 4,
            config_errors: 0,
        };
        assert_eq!(h.success_rate(), 75.0);
    }
}

#[cfg(test)]
mod notify_metrics {
    use super::*;
    use crate::notify::{ChannelCounts, NotifyCounts};

    fn empty_report(notify: NotifyCounts) -> String {
        let disk = DiskHistory::default();
        let states = HashMap::new();
        let health = HashMap::new();
        let suppressed = HashMap::new();
        render(&CycleReport {
            snapshots: &[],
            host_snapshots: &[],
            peers: &[],
            is_owner: true,
            disk: &disk,
            outcomes: &[],
            states: &states,
            endpoint_health: &health,
            suppressed: &suppressed,
            visible: true,
            silenced: false,
            cycle_duration: Duration::from_secs(1),
            unix_time: 1_700_000_000,
            maintenance_until: 0,
            start_time: 1_699_000_000,
            notify,
            maintenance_streak: 0,
            maintenance_awaiting_work: false,
            watchtower_name: "t",
            solana_cluster: "unpinned",
            validator_labels: &NO_LABELS,
            alerting: crate::config::Alerting::Always,
        })
    }

    #[test]
    fn a_lost_page_is_visible_to_a_scrape() {
        let out = empty_report(NotifyCounts {
            pagerduty: ChannelCounts {
                failed: 3,
                ..Default::default()
            },
            telegram: ChannelCounts::default(),
        });
        assert!(
            out.contains(r#"perch_notify_failures_total{channel="pagerduty"} 3"#),
            "a dropped page must be scrapeable, got:\n{out}"
        );
        assert!(out.contains(r#"perch_notify_failures_total{channel="telegram"} 0"#));
    }

    /// A never-tested channel must report 0, not absent. An absent series makes
    /// a staleness alert silently fail to match instead of firing.
    #[test]
    fn an_untested_channel_still_exports_a_zero() {
        let out = empty_report(NotifyCounts::default());
        assert!(out.contains(r#"perch_notify_self_test_timestamp_seconds{channel="pagerduty"} 0"#));
        assert!(out.contains(r#"perch_notify_self_test_timestamp_seconds{channel="telegram"} 0"#));
    }
}

#[cfg(test)]
mod compat_alias {
    use super::*;

    #[test]
    fn every_metric_line_gains_an_aliased_twin() {
        let src = "# HELP perch_visible help text\n# TYPE perch_visible gauge\nperch_visible 1\n";
        let out = with_compat_alias(src, "chimpstower");
        for expected in [
            "# HELP chimpstower_visible help text",
            "# TYPE chimpstower_visible gauge",
            "chimpstower_visible 1",
            "perch_visible 1",
        ] {
            assert!(out.contains(expected), "missing {expected} in:\n{out}");
        }
    }

    #[test]
    fn labels_survive_the_alias() {
        let out = with_compat_alias("perch_check_firing{check=\"vote:a\"} 1\n", "chimpstower");
        assert!(out.contains("chimpstower_check_firing{check=\"vote:a\"} 1"), "{out}");
    }

    /// Only perch's own metrics are aliased. A comment or a foreign line must
    /// not be duplicated, or the exposition stops being parseable.
    #[test]
    fn unrelated_lines_are_not_duplicated() {
        let out = with_compat_alias("# a bare comment\nnode_up 1\n", "chimpstower");
        assert_eq!(out.matches("node_up 1").count(), 1);
        assert_eq!(out.matches("# a bare comment").count(), 1);
    }
}

#[cfg(test)]
mod version_metric {
    use super::*;
    use crate::{notify::NotifyCounts, snapshot::NodeVersion};

    fn render_with(snaps: &[Snapshot]) -> String {
        let disk = DiskHistory::default();
        let (states, health, suppressed) = (HashMap::new(), HashMap::new(), HashMap::new());
        render(&CycleReport {
            snapshots: snaps,
            host_snapshots: &[],
            peers: &[],
            is_owner: true,
            disk: &disk,
            outcomes: &[],
            states: &states,
            endpoint_health: &health,
            suppressed: &suppressed,
            visible: true,
            silenced: false,
            cycle_duration: Duration::from_secs(1),
            unix_time: 1_700_000_000,
            maintenance_until: 0,
            start_time: 1_699_000_000,
            notify: NotifyCounts::default(),
            maintenance_streak: 0,
            maintenance_awaiting_work: false,
            watchtower_name: "t",
            solana_cluster: "unpinned",
            validator_labels: &NO_LABELS,
            alerting: crate::config::Alerting::Always,
        })
    }

    fn snap(endpoint: &str, version: Option<NodeVersion>) -> Snapshot {
        let mut s = Snapshot::empty_for_test(endpoint);
        s.version = version;
        s
    }

    #[test]
    fn a_local_endpoint_version_is_exported_with_labels() {
        let out = render_with(&[snap(
            "localhost",
            Some(NodeVersion { solana_core: "4.3.0-rc.1".into(), feature_set: 3383571666 }),
        )]);
        assert!(
            out.contains(r#"perch_node_version{endpoint="localhost",version="4.3.0-rc.1",feature_set="3383571666"} 1"#),
            "got:\n{out}"
        );
    }

    /// An endpoint that reported no version must emit no series at all, rather
    /// than a row claiming an empty version string.
    #[test]
    fn an_endpoint_without_a_version_emits_nothing() {
        let out = render_with(&[snap("publicnode", None)]);
        assert!(!out.contains("perch_node_version{"), "got:\n{out}");
    }
}

#[cfg(test)]
mod build_identity {
    use super::*;
    use crate::notify::NotifyCounts;

    /// Eight binaries shipped in one day all labelled 0.1.0. The commit is the
    /// label that actually distinguishes builds, so it must be exported.
    #[test]
    fn build_info_carries_version_and_commit() {
        let disk = DiskHistory::default();
        let (states, health, suppressed) = (HashMap::new(), HashMap::new(), HashMap::new());
        let out = render(&CycleReport {
            snapshots: &[], host_snapshots: &[], peers: &[], is_owner: true, disk: &disk,
            outcomes: &[], states: &states, endpoint_health: &health, suppressed: &suppressed,
            visible: true, silenced: false, cycle_duration: Duration::from_secs(1),
            unix_time: 1_700_000_000, maintenance_until: 0, start_time: 1_699_000_000,
            notify: NotifyCounts::default(), maintenance_streak: 0, maintenance_awaiting_work: false,
            watchtower_name: "t", solana_cluster: "unpinned", validator_labels: &HashMap::new(), alerting: crate::config::Alerting::Always,
        });
        let expected = format!(
            r#"perch_build_info{{version="{}",commit="{}"}} 1"#,
            env!("CARGO_PKG_VERSION"),
            crate::COMMIT
        );
        assert!(out.contains(&expected), "got:\n{out}");
        // COMMIT is a compile-time constant, so asserting it is non-empty is
        // vacuous; what matters is that the rendered line carries it.
        assert!(crate::BUILD.starts_with(concat!(env!("CARGO_PKG_VERSION"), " (")), "{}", crate::BUILD);
    }
}

#[cfg(test)]
mod alpenglow_metrics {
    use super::*;
    use crate::{
        alpenglow::{Bls, ClusterVat, FeatureState, VoteAccountState},
        notify::NotifyCounts,
        snapshot::{EpochInfo, ValidatorObservation, VoteAccountInfo},
    };

    fn render_with(snaps: &[Snapshot], labels: &HashMap<String, String>) -> String {
        let disk = DiskHistory::default();
        let (states, health, suppressed) = (HashMap::new(), HashMap::new(), HashMap::new());
        render(&CycleReport {
            snapshots: snaps,
            host_snapshots: &[],
            peers: &[],
            is_owner: true,
            disk: &disk,
            outcomes: &[],
            states: &states,
            endpoint_health: &health,
            suppressed: &suppressed,
            visible: true,
            silenced: false,
            cycle_duration: Duration::from_secs(1),
            unix_time: 1_700_000_000,
            maintenance_until: 0,
            start_time: 1_699_000_000,
            notify: NotifyCounts::default(),
            maintenance_streak: 0,
            maintenance_awaiting_work: false,
            watchtower_name: "t",
            solana_cluster: "testnet",
            validator_labels: labels,
            alerting: crate::config::Alerting::Always,
        })
    }

    fn snap(bls: Bls) -> Snapshot {
        let mut s = Snapshot::empty_for_test("a");
        s.epoch_info = Some(EpochInfo { absolute_slot: 4_320_100, epoch: 10, slot_index: 100, slots_in_epoch: 432_000 });
        s.validators.insert(
            "ID".into(),
            ValidatorObservation::Voting(VoteAccountInfo {
                vote_pubkey: "VOTE".into(),
                node_pubkey: "ID".into(),
                activated_stake: 1,
                commission: 5,
                last_vote: 4_320_090,
                root_slot: 4_320_060,
                epoch_credits: vec![(10, 5, 0)],
            }),
        );
        s.alpenglow = Some(ClusterVat {
            alpenglow: FeatureState::Active(0),
            slot_time: [FeatureState::Absent; 4],
            rent_lamports: 19_761_200,
        });
        s.vote_states.insert(
            "ID".into(),
            VoteAccountState { lamports: 6_481_200_000, bls, inflation_commission_bps: None, block_revenue_commission_bps: None },
        );
        s.vote_income.insert("ID".into(), 637_000_000);
        s
    }

    #[test]
    fn admission_inputs_are_exported() {
        let labels = HashMap::from([("ID".to_string(), "chimps-1".to_string())]);
        let out = render_with(&[snap(Bls::Registered)], &labels);
        for line in [
            "perch_alpenglow_phase 2",
            "perch_vat_per_epoch_sol 1.6",
            "perch_vote_account_minimum_sol 1.6197612",
            r#"perch_validator_vote_account_balance_sol{identity="ID",validator="chimps-1"} 6.4812"#,
            r#"perch_validator_bls_registered{identity="ID",validator="chimps-1"} 1"#,
            r#"perch_validator_vote_income_sol{identity="ID",validator="chimps-1"} 0.637"#,
            // 0.637 earned against a 1.6 SOL VAT at 400ms slots.
            r#"perch_validator_vote_net_sol_per_epoch{identity="ID",validator="chimps-1"} -0.963"#,
            // (6.4812 - 1.6198) / 0.963 = 5.05, plus the boundary passed now.
            r#"perch_validator_vote_runway_epochs{identity="ID",validator="chimps-1"} 6"#,
        ] {
            assert!(out.contains(line), "missing {line:?} in:\n{out}");
        }
    }

    /// A vote account that earns more than the VAT has no runway to report:
    /// "absent" is the honest rendering of "not draining", where a number
    /// would have to pretend to be infinity.
    #[test]
    fn a_vote_account_that_is_not_draining_exports_no_runway() {
        let mut s = snap(Bls::Registered);
        s.vote_income.insert("ID".into(), 2_000_000_000);
        let out = render_with(&[s], &HashMap::new());
        assert!(out.contains(r#"perch_validator_vote_net_sol_per_epoch{identity="ID",validator="ID"} 0.4"#), "got:\n{out}");
        assert!(!out.contains("perch_validator_vote_runway_epochs{"), "got:\n{out}");
    }

    /// No endpoint reporting the field must not read as "no key".
    #[test]
    fn an_unreported_bls_key_emits_no_series() {
        let out = render_with(&[snap(Bls::NotReported)], &HashMap::new());
        assert!(!out.contains("perch_validator_bls_registered{"), "got:\n{out}");
        let out = render_with(&[snap(Bls::Missing)], &HashMap::new());
        assert!(out.contains(r#"perch_validator_bls_registered{identity="ID",validator="ID"} 0"#), "got:\n{out}");
    }
}

//! Notification routing.
//!
//! Two tiers, and the tier is a property of the alert, not of the channel:
//! `Page` goes to PagerDuty *and* Telegram, `Notify` goes to Telegram only.
//! That split is the whole point -- the noisy-but-useful signals stay visible
//! without ever reaching the paging path.

pub mod pagerduty;
pub mod telegram;

use crate::config::{Notify as NotifyConfig, Severity};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cross-cycle counters for the notification path.
///
/// A page that fails every retry is logged and then gone. Without a counter
/// there is no way to tell, from outside the process, between "nothing needed
/// paging" and "something needed paging and none of it arrived". That second
/// case is the only failure a watchtower genuinely cannot afford to hide, so it
/// gets a number that a scrape can see.
#[derive(Debug, Default)]
pub struct NotifyStats {
    pub pagerduty: ChannelStats,
    pub telegram: ChannelStats,
}

#[derive(Debug, Default)]
pub struct ChannelStats {
    delivered: AtomicU64,
    failed: AtomicU64,
    last_success_unix: AtomicU64,
    self_test_failed: AtomicU64,
    last_self_test_unix: AtomicU64,
}

/// A plain-data read of [`ChannelStats`], so rendering never touches atomics.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChannelCounts {
    pub delivered: u64,
    pub failed: u64,
    pub last_success_unix: u64,
    pub self_test_failed: u64,
    pub last_self_test_unix: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NotifyCounts {
    pub pagerduty: ChannelCounts,
    pub telegram: ChannelCounts,
}

impl ChannelStats {
    fn record(&self, ok: bool) {
        if ok {
            self.delivered.fetch_add(1, Ordering::Relaxed);
            self.last_success_unix.store(now_unix(), Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_self_test(&self, ok: bool) {
        if ok {
            self.last_self_test_unix.store(now_unix(), Ordering::Relaxed);
        } else {
            self.self_test_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn counts(&self) -> ChannelCounts {
        ChannelCounts {
            delivered: self.delivered.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            last_success_unix: self.last_success_unix.load(Ordering::Relaxed),
            self_test_failed: self.self_test_failed.load(Ordering::Relaxed),
            last_self_test_unix: self.last_self_test_unix.load(Ordering::Relaxed),
        }
    }
}

impl NotifyStats {
    pub fn counts(&self) -> NotifyCounts {
        NotifyCounts {
            pagerduty: self.pagerduty.counts(),
            telegram: self.telegram.counts(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    Trigger,
    Resolve,
    /// Informational; never opens or closes a PagerDuty incident.
    Info,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    /// PagerDuty dedup key. Stable for the lifetime of one incident.
    pub key: String,
    pub title: String,
    pub body: String,
}

pub struct Notifier {
    pagerduty: Option<pagerduty::PagerDuty>,
    telegram: Option<telegram::Telegram>,
    source: String,
    dry_run: bool,
    stats: Arc<NotifyStats>,
}

impl Notifier {
    pub fn new(cfg: &NotifyConfig, source: String, dry_run: bool) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;

        let pagerduty = cfg
            .pagerduty
            .as_ref()
            .filter(|c| c.enabled)
            .map(|c| pagerduty::PagerDuty::new(client.clone(), c.integration_key.clone()));
        let telegram = cfg
            .telegram
            .as_ref()
            .filter(|c| c.enabled)
            .map(|c| telegram::Telegram::new(client, c.bot_token.clone(), c.chat_ids.clone()));

        if pagerduty.is_none() {
            warn!("PagerDuty is not configured; nothing will page");
        }
        match &telegram {
            None => warn!("Telegram is not configured; non-paging alerts will only be logged"),
            Some(t) => info!("Telegram configured for {} chat(s)", t.chat_count()),
        }

        Ok(Self {
            pagerduty,
            telegram,
            source,
            dry_run,
            stats: Arc::new(NotifyStats::default()),
        })
    }

    pub fn stats(&self) -> Arc<NotifyStats> {
        Arc::clone(&self.stats)
    }

    pub async fn dispatch(&self, alert: &Alert) {
        // The tier belongs in the log line: "something fired" and "someone was
        // woken up" are very different events to find in a postmortem.
        let tier = match alert.severity {
            Severity::Page => "PAGE",
            Severity::Notify => "NOTIFY",
            Severity::Log => "LOG",
        };
        match alert.kind {
            AlertKind::Trigger => {
                error!(key = %alert.key, "ALERT[{tier}] {}: {}", alert.title, alert.body)
            }
            AlertKind::Resolve => {
                info!(key = %alert.key, "RESOLVED[{tier}] {}", alert.title)
            }
            AlertKind::Info => info!(key = %alert.key, "{}: {}", alert.title, alert.body),
        }

        if self.dry_run {
            info!("dry run: not delivering {:?} to any channel", alert.kind);
            return;
        }

        // Telegram gets everything. A page that PagerDuty drops is still visible.
        if let Some(tg) = &self.telegram {
            let outcome = tg.send(alert, &self.source).await;
            self.stats.telegram.record(outcome.is_ok());
            if let Err(e) = outcome {
                // Delivery failure is logged, never propagated: a broken
                // notification channel must not take the watchtower down with it.
                error!("telegram delivery failed: {e:#}");
            }
        }

        if alert.severity != Severity::Page {
            return;
        }

        if let Some(pd) = &self.pagerduty {
            let outcome = pd.send(alert, &self.source).await;
            self.stats.pagerduty.record(outcome.is_ok());
            if let Err(e) = outcome {
                error!("pagerduty delivery failed: {e:#}");
                if let Some(tg) = &self.telegram {
                    let fallback = Alert {
                        kind: AlertKind::Info,
                        severity: Severity::Notify,
                        key: format!("{}-pd-failure", alert.key),
                        title: "PagerDuty delivery failed".into(),
                        body: format!(
                            "Could not deliver the page for {:?}: {e}. Treat the alert above as \
                             unacknowledged.",
                            alert.title
                        ),
                    };
                    let relayed = tg.send(&fallback, &self.source).await;
                    self.stats.telegram.record(relayed.is_ok());
                }
            }
        }
    }
}

/// How loud a self-test is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestMode {
    /// A real trigger and resolve on PagerDuty, a 🚨 on Telegram. For a human
    /// running `test-notify` who wants proof the phone actually rings.
    Loud,
    /// A change event on PagerDuty and an ℹ️ on Telegram. Exercises the same
    /// credentials and the same egress, opens no incident, pages nobody. This
    /// is the only mode the schedule may use.
    Quiet,
}

/// Outcome of a single channel during `test-notify`.
#[derive(Debug)]
pub struct ChannelResult {
    pub channel: &'static str,
    pub configured: bool,
    pub error: Option<String>,
}

impl Notifier {
    /// Send a real alert through the real code path, then resolve it.
    ///
    /// Deliberately not a mock: the failure modes worth catching are a wrong
    /// PagerDuty routing key, a bot that was never messaged, a chat id with the
    /// wrong sign, an egress firewall. None of those show up until something
    /// tries to deliver, and finding out during an incident is too late.
    /// `Loud` is for a human running `test-notify` who wants proof the phone
    /// rings. `Quiet` is for the schedule: a PagerDuty change event and a
    /// Telegram ℹ️, so the same credentials and egress are exercised weekly
    /// without an incident ever being opened.
    pub async fn self_test(&self, source: &str, mode: SelfTestMode) -> Vec<ChannelResult> {
        let key = format!("perch-test/{}", uuid::Uuid::new_v4());
        let mut results = Vec::new();

        let message = match mode {
            SelfTestMode::Loud => Alert {
                kind: AlertKind::Trigger,
                severity: Severity::Page,
                key: key.clone(),
                title: "perch test alert".into(),
                body: format!(
                    "Delivery test from {source}. Nothing is wrong. This incident resolves itself a moment after it opens."
                ),
            },
            SelfTestMode::Quiet => Alert {
                kind: AlertKind::Info,
                severity: Severity::Notify,
                key: key.clone(),
                title: "Delivery check".into(),
                body: format!(
                    "Weekly delivery check from {source}: this channel works. Nothing is wrong."
                ),
            },
        };

        if let Some(tg) = &self.telegram {
            let err = tg.send(&message, source).await.err().map(|e| format!("{e:#}"));
            self.stats.telegram.record_self_test(err.is_none());
            results.push(ChannelResult {
                channel: "telegram",
                configured: true,
                error: err,
            });
        } else {
            results.push(ChannelResult {
                channel: "telegram",
                configured: false,
                error: None,
            });
        }

        if let Some(pd) = &self.pagerduty {
            let mut err = match mode {
                SelfTestMode::Quiet => pd
                    .send_change(&format!("perch delivery check from {source}: nothing is wrong"), source)
                    .await
                    .err()
                    .map(|e| format!("{e:#}")),
                SelfTestMode::Loud => pd.send(&message, source).await.err().map(|e| format!("{e:#}")),
            };
            // Only resolve what actually opened, so a failure is not masked.
            if mode == SelfTestMode::Loud && err.is_none() {
                let resolve = Alert {
                    kind: AlertKind::Resolve,
                    severity: Severity::Page,
                    key,
                    title: "perch test alert".into(),
                    body: String::new(),
                };
                err = pd
                    .send(&resolve, source)
                    .await
                    .err()
                    .map(|e| format!("opened but could not resolve: {e:#}"));
            }
            self.stats.pagerduty.record_self_test(err.is_none());
            results.push(ChannelResult {
                channel: "pagerduty",
                configured: true,
                error: err,
            });
        } else {
            results.push(ChannelResult {
                channel: "pagerduty",
                configured: false,
                error: None,
            });
        }

        results
    }
}

/// Retry helper shared by the channels. Notification delivery is the one place
/// where giving up quietly is unacceptable, so transient HTTP failures here are
/// retried harder than RPC calls are.
pub(crate) async fn with_retries<F, Fut>(attempts: u32, mut f: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut last = None;
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(500u64 << (attempt - 1).min(4))).await;
        }
        match f().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!("notification attempt {} failed: {e:#}", attempt + 1);
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no delivery attempt was made")))
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    #[test]
    fn a_lost_notification_is_counted_not_forgotten() {
        let c = ChannelStats::default();
        c.record(true);
        c.record(false);
        c.record(false);
        let n = c.counts();
        assert_eq!(n.delivered, 1);
        assert_eq!(n.failed, 2, "a page that failed every retry must leave a number behind");
    }

    #[test]
    fn last_success_does_not_advance_on_failure() {
        let c = ChannelStats::default();
        c.record(true);
        let after_success = c.counts().last_success_unix;
        assert!(after_success > 0);
        c.record(false);
        assert_eq!(
            c.counts().last_success_unix,
            after_success,
            "a failure must not make the channel look freshly healthy"
        );
    }

    /// The whole point of the self-test metric is staleness detection. A failing
    /// test that still bumped the timestamp would report itself as verified.
    #[test]
    fn a_failed_self_test_leaves_the_timestamp_stale() {
        let c = ChannelStats::default();
        c.record_self_test(false);
        let n = c.counts();
        assert_eq!(n.last_self_test_unix, 0, "never verified, so the clock stays at zero");
        assert_eq!(n.self_test_failed, 1);
    }

    #[test]
    fn counts_are_reported_per_channel_independently() {
        let s = NotifyStats::default();
        s.pagerduty.record(false);
        s.telegram.record(true);
        let n = s.counts();
        assert_eq!(n.pagerduty.failed, 1);
        assert_eq!(n.telegram.failed, 0);
        assert_eq!(n.telegram.delivered, 1);
    }
}

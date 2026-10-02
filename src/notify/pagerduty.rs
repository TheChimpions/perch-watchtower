//! PagerDuty Events API v2.

use super::{with_retries, Alert, AlertKind};
use crate::config::Severity;
use anyhow::{bail, Result};
use serde_json::json;

const ENDPOINT: &str = "https://events.pagerduty.com/v2/enqueue";
const CHANGE_ENDPOINT: &str = "https://events.pagerduty.com/v2/change/enqueue";

/// Body of a change event. No `event_action`, no `dedup_key`: there is nothing
/// here that can open, update or resolve an incident, which is the point.
pub fn change_event_body(routing_key: &str, summary: &str, source: &str, timestamp: &str) -> serde_json::Value {
    json!({
        "routing_key": routing_key,
        "payload": {
            "summary": summary,
            "source": source,
            "timestamp": timestamp,
            "custom_details": { "kind": "perch-delivery-check" },
        },
    })
}

/// Derived from the alert tier rather than hardcoded, so the scheduled
/// self-test can reach PagerDuty as `info` and prove the path without opening a
/// critical incident every week.
fn pd_severity(s: Severity) -> &'static str {
    match s {
        Severity::Page => "critical",
        Severity::Notify => "warning",
        Severity::Log => "info",
    }
}

pub struct PagerDuty {
    client: reqwest::Client,
    routing_key: String,
}

impl PagerDuty {
    pub fn new(client: reqwest::Client, routing_key: String) -> Self {
        Self {
            client,
            routing_key,
        }
    }

    /// A change event: the same routing key and egress as an alert, recorded on
    /// the service timeline, and by design never an incident and never a page.
    ///
    /// Be clear about what a success here proves. The Events API is
    /// fire-and-forget: it answers 202 "processed" for any well-formed routing
    /// key, including a revoked one -- verified empirically, and equally true of
    /// alert events. A 202 proves the request left this box and PagerDuty took
    /// it. It does not prove the key still routes to a service; only the REST
    /// API can confirm that.
    pub async fn send_change(&self, summary: &str, source: &str) -> Result<()> {
        let body = change_event_body(
            &self.routing_key,
            summary,
            source,
            &chrono::Utc::now().to_rfc3339(),
        );
        with_retries(4, || {
            let client = self.client.clone();
            let body = body.clone();
            async move {
                let resp = client.post(CHANGE_ENDPOINT).json(&body).send().await?;
                let status = resp.status();
                if status.is_success() {
                    return Ok(());
                }
                let text = resp.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::BAD_REQUEST {
                    bail!("pagerduty rejected the change event (400): {text}");
                }
                bail!("pagerduty returned {status}: {text}")
            }
        })
        .await
    }

    pub async fn send(&self, alert: &Alert, source: &str) -> Result<()> {
        let action = match alert.kind {
            AlertKind::Trigger => "trigger",
            AlertKind::Resolve => "resolve",
            // Informational alerts never reach PagerDuty at all.
            AlertKind::Info => return Ok(()),
        };

        let mut body = json!({
            "routing_key": self.routing_key,
            "event_action": action,
            // Stable per incident, so a re-notify updates the open incident
            // instead of opening a second one, and a resolve closes the right one.
            "dedup_key": alert.key,
        });

        if alert.kind == AlertKind::Trigger {
            body["payload"] = json!({
                "summary": format!("{}: {}", alert.title, alert.body),
                "source": source,
                "severity": pd_severity(alert.severity),
                "component": "solana-validator",
                "custom_details": { "detail": alert.body },
            });
        }

        with_retries(4, || {
            let client = self.client.clone();
            let body = body.clone();
            async move {
                let resp = client.post(ENDPOINT).json(&body).send().await?;
                let status = resp.status();
                if status.is_success() {
                    return Ok(());
                }
                let text = resp.text().await.unwrap_or_default();
                // 400 means PagerDuty rejected the payload; retrying is futile.
                if status == reqwest::StatusCode::BAD_REQUEST {
                    bail!("pagerduty rejected the event (400): {text}");
                }
                bail!("pagerduty returned {status}: {text}")
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_real_page_is_critical() {
        assert_eq!(pd_severity(Severity::Page), "critical");
    }

    /// The scheduled self-test is a change event. PagerDuty opens an incident
    /// for a trigger of any severity -- an `info` trigger still paged the
    /// operator -- so the only shape that cannot page is one with no
    /// event_action at all.
    #[test]
    fn a_change_event_has_nothing_that_can_open_an_incident() {
        let b = change_event_body("k", "delivery check", "perch/x", "2026-09-22T00:00:00Z");
        assert!(b.get("event_action").is_none());
        assert!(b.get("dedup_key").is_none());
        assert_eq!(b["payload"]["summary"], "delivery check");
        assert_eq!(b["payload"]["source"], "perch/x");
    }
}

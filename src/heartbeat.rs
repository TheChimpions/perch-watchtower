//! Dead-man's switch.
//!
//! The failure mode this exists for: perch panics, is OOM-killed, or its
//! host dies, and you get silence. Silence from a watchtower is indistinguishable
//! from "everything is fine", which is the worst possible property for a paging
//! system to have. So perch checks in with an external service on every
//! healthy cycle, and that service pages if the check-ins stop.
//!
//! Works with anything that accepts an HTTP ping: Healthchecks.io, Better Stack,
//! Cronitor, Dead Man's Snitch, or a PagerDuty heartbeat integration.

use anyhow::{bail, Result};
use std::time::Duration;
use tracing::{debug, warn};

pub struct Heartbeat {
    client: reqwest::Client,
    url: String,
    fail_url: Option<String>,
    /// Only check in when we could actually see the cluster. With this off, the
    /// dead-man's switch would keep reporting healthy while perch was
    /// running but blind -- alive, but not doing its job.
    require_visibility: bool,
}

impl Heartbeat {
    pub fn new(
        url: String,
        fail_url: Option<String>,
        require_visibility: bool,
    ) -> Result<Self> {
        // Short timeout: a slow heartbeat endpoint must never delay a cycle.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            client,
            url,
            fail_url,
            require_visibility,
        })
    }

    pub async fn beat(&self, visible: bool) {
        let (url, kind) = if visible || !self.require_visibility {
            (Some(&self.url), "ok")
        } else {
            (self.fail_url.as_ref(), "fail")
        };

        let Some(url) = url else {
            // Blind, and no fail_url configured. Staying silent is the correct
            // signal: the external service's own grace period will notice.
            debug!("skipping heartbeat while blind (no fail_url configured)");
            return;
        };

        match self.ping(url).await {
            Ok(()) => debug!("heartbeat sent ({kind})"),
            // Never propagate: a broken heartbeat endpoint must not take down
            // the watchtower it is supposed to be watching.
            Err(e) => warn!("heartbeat ping failed: {e:#}"),
        }
    }

    async fn ping(&self, url: &str) -> Result<()> {
        let resp = self.client.get(url).send().await.map_err(crate::rpc::scrub)?;
        if !resp.status().is_success() {
            bail!("heartbeat endpoint returned {}", resp.status());
        }
        Ok(())
    }
}

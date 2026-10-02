//! A read-only status page, rendered from the same data as `perch status`.
//!
//! Deliberately not a dashboard: Grafana already does history and graphs far
//! better than anything hand-rolled here. This answers the question Grafana
//! cannot -- "what is true right now, and why is that check not firing" -- in a
//! browser rather than over SSH, and links out to Grafana for everything else.
//!
//! No JavaScript, no framework, no build step. It is served on the existing
//! metrics listener, which is unauthenticated, so it must stay on localhost or a
//! private interface.

use crate::{
    checks::CheckOutcome,
    config::Severity,
    node_exporter::HostSnapshot,
    peer::PeerStatus,
    snapshot::Snapshot,
    state::CheckState,
    verdict::Verdict,
};
use std::{collections::HashMap, fmt::Write as _, time::Duration};

/// Everything the page renders. Borrowed, so building it costs nothing when
/// nobody is looking.
pub struct PageData<'a> {
    pub name: &'a str,
    /// Needed so the disk markers use the same size-capped floor the checks do.
    pub disk_space: &'a crate::config::DiskSpaceCheckConfig,
    pub snapshots: &'a [Snapshot],
    pub host_snapshots: &'a [HostSnapshot],
    pub peers: &'a [PeerStatus],
    pub outcomes: &'a [CheckOutcome],
    pub states: &'a HashMap<String, CheckState>,
    pub suppressed: &'a HashMap<String, String>,
    pub visible: bool,
    pub silenced: bool,
    pub alerting: &'a str,
    pub stale_after: Duration,
    pub max_endpoint_lag: u64,
    pub grafana_url: Option<&'a str>,
    pub epoch_line: &'a str,
}

/// Label text and RPC errors are attacker-influenceable in the sense that they
/// come from remote endpoints, so nothing reaches the page unescaped.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn dur(d: Duration) -> String {
    humantime::format_duration(Duration::from_secs(d.as_secs())).to_string()
}

const CSS: &str = r#"
:root{--bg:#0f1115;--fg:#d8dee9;--dim:#7a8290;--line:#232833;--card:#161a22;
--ok:#4ea96b;--warn:#d0a215;--bad:#d05252;--info:#4a8fd0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 60px}
h1{font-size:18px;margin:0 0 2px;font-weight:600}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
margin:28px 0 8px;font-weight:600}
.sub{color:var(--dim);font-size:13px;margin-bottom:18px}
.banner{padding:12px 16px;border-radius:6px;margin:0 0 20px;font-weight:600;
display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.b-ok{background:rgba(78,169,107,.14);border:1px solid var(--ok);color:var(--ok)}
.b-bad{background:rgba(208,82,82,.14);border:1px solid var(--bad);color:var(--bad)}
.b-warn{background:rgba(208,162,21,.14);border:1px solid var(--warn);color:var(--warn)}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:6px;
overflow:hidden}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--dim);font-weight:600;padding:8px 12px;border-bottom:1px solid var(--line)}
td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:11px;
font-weight:600;letter-spacing:.04em}
.t-ok{background:rgba(78,169,107,.18);color:var(--ok)}
.t-bad{background:rgba(208,82,82,.18);color:var(--bad)}
.t-warn{background:rgba(208,162,21,.18);color:var(--warn)}
.t-dim{background:rgba(122,130,144,.15);color:var(--dim)}
.t-info{background:rgba(74,143,208,.18);color:var(--info)}
.dim{color:var(--dim)}
.num{text-align:right;font-variant-numeric:tabular-nums}
a{color:var(--info)}
footer{margin-top:36px;color:var(--dim);font-size:12px;
border-top:1px solid var(--line);padding-top:12px}
"#;

pub fn render(d: &PageData<'_>) -> String {
    let firing: Vec<&CheckOutcome> = d
        .outcomes
        .iter()
        .filter(|o| {
            d.states.get(&o.id).map(|s| s.is_firing()).unwrap_or(false)
                && !d.suppressed.contains_key(&o.id)
        })
        .collect();

    let mut h = String::with_capacity(16 * 1024);
    let _ = write!(
        h,
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=refresh content=15>\
         <title>{} — perch</title><style>{CSS}</style></head><body><div class=wrap>",
        esc(d.name)
    );

    let _ = write!(
        h,
        "<h1>{}</h1><div class=sub>perch {} · {} · alerting: {}</div>",
        esc(d.name),
        crate::BUILD,
        esc(d.epoch_line),
        esc(d.alerting)
    );

    // Headline. Firing beats blind beats silenced beats fine.
    let (cls, msg) = if !firing.is_empty() {
        ("b-bad", format!("{} check(s) firing", firing.len()))
    } else if !d.visible {
        ("b-bad", "BLIND — not enough endpoints answered; all checks frozen".into())
    } else if d.silenced {
        ("b-warn", "Paging silenced by a silence file".into())
    } else {
        ("b-ok", "All checks healthy".into())
    };
    let _ = write!(h, "<div class=\"banner {cls}\"><span>{}</span>", esc(&msg));
    if let Some(g) = d.grafana_url {
        let _ = write!(h, "<a href=\"{}\">open Grafana →</a>", esc(g));
    }
    h.push_str("</div>");

    if !firing.is_empty() {
        h.push_str("<h2>Firing</h2><table><tr><th>check</th><th>tier</th><th>detail</th></tr>");
        for o in &firing {
            let tier = match o.cfg.severity {
                Severity::Page => "<span class=\"tag t-bad\">PAGE</span>",
                Severity::Notify => "<span class=\"tag t-warn\">NOTIFY</span>",
                Severity::Log => "<span class=\"tag t-dim\">LOG</span>",
            };
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{tier}</td><td>{}</td></tr>",
                esc(&o.id),
                esc(o.verdict.detail().unwrap_or("-"))
            );
        }
        h.push_str("</table>");
    }

    // --- endpoints ---
    let best = d
        .snapshots
        .iter()
        .filter_map(|s| s.epoch_info.as_ref().map(|e| e.absolute_slot))
        .max();
    h.push_str("<h2>Endpoints</h2><table><tr><th></th><th>endpoint</th><th class=num>slot</th><th>note</th></tr>");
    for s in d.snapshots {
        let (tag, slot, note) = match (&s.epoch_info, best) {
            (Some(i), Some(b)) => {
                let lag = b.saturating_sub(i.absolute_slot);
                let note = if lag > d.max_endpoint_lag {
                    format!("<span class=dim>STALE — {lag} slots behind, answers discarded</span>")
                } else if lag > 0 {
                    format!("<span class=dim>{lag} behind</span>")
                } else {
                    "<span class=dim>current</span>".into()
                };
                let tag = if lag > d.max_endpoint_lag { "t-warn" } else { "t-ok" };
                (tag, i.absolute_slot.to_string(), note)
            }
            _ => {
                let why = s
                    .config_errors
                    .first()
                    .or_else(|| s.transient_errors.first())
                    .cloned()
                    .unwrap_or_else(|| "no answer".into());
                ("t-bad", "—".into(), format!("<span class=dim>{}</span>", esc(&why)))
            }
        };
        let label = if tag == "t-bad" { "DOWN" } else { "ok" };
        let _ = write!(
            h,
            "<tr><td><span class=\"tag {tag}\">{label}</span></td><td>{}</td>\
             <td class=num>{slot}</td><td>{note}</td></tr>",
            esc(&s.endpoint)
        );
    }
    h.push_str("</table>");

    // --- peers ---
    if !d.peers.is_empty() {
        h.push_str("<h2>Peers</h2><table><tr><th></th><th>peer</th><th class=num>pri</th><th>state</th></tr>");
        let mut sorted: Vec<&PeerStatus> = d.peers.iter().collect();
        sorted.sort_by_key(|p| p.priority);
        for p in sorted {
            let live = p.is_live(d.stale_after);
            let _ = write!(
                h,
                "<tr><td><span class=\"tag {}\">{}</span></td><td>{}</td>\
                 <td class=num>{}</td><td class=dim>{}</td></tr>",
                if live { "t-ok" } else { "t-bad" },
                if live { "ok" } else { "DOWN" },
                esc(&p.name),
                p.priority,
                esc(&p.describe(d.stale_after))
            );
        }
        h.push_str("</table>");
    }

    // --- disks ---
    if d.host_snapshots.iter().any(|x| x.is_usable()) {
        h.push_str("<h2>Disks</h2><table><tr><th></th><th>mount</th><th class=num>free</th>\
                    <th class=num>size</th><th class=num>used</th><th>note</th></tr>");
        for hs in d.host_snapshots {
            if let Some(e) = &hs.error {
                let _ = write!(
                    h,
                    "<tr><td><span class=\"tag t-bad\">DOWN</span></td><td>{}</td>\
                     <td colspan=4 class=dim>{}</td></tr>",
                    esc(&hs.host),
                    esc(e)
                );
                continue;
            }
            let mut ms: Vec<_> = hs.filesystems.values().collect();
            ms.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
            for fs in ms {
                let page_floor = d
                    .disk_space
                    .effective_floor(d.disk_space.page_free_gb, fs.size_gb());
                let warn_floor = d
                    .disk_space
                    .effective_floor(d.disk_space.warn_free_gb, fs.size_gb());
                let tag = if fs.readonly {
                    "t-bad"
                } else if fs.avail_gb() < page_floor {
                    "t-bad"
                } else if fs.avail_gb() < warn_floor {
                    "t-warn"
                } else {
                    "t-ok"
                };
                let label = if fs.readonly { "RO" } else { "ok" };
                let _ = write!(
                    h,
                    "<tr><td><span class=\"tag {tag}\">{label}</span></td>\
                     <td>{} <span class=dim>{}</span></td>\
                     <td class=num>{:.0} GB</td><td class=num>{:.0} GB</td>\
                     <td class=num>{:.1}%</td><td class=dim>{}</td></tr>",
                    esc(&fs.mountpoint),
                    esc(&hs.host),
                    fs.avail_gb(),
                    fs.size_gb(),
                    fs.used_percent(),
                    if fs.readonly { "READ-ONLY" } else { "" }
                );
            }
        }
        h.push_str("</table>");
    }

    // --- checks ---
    h.push_str("<h2>Checks</h2><table><tr><th>state</th><th>check</th><th>detail</th></tr>");
    let mut rows: Vec<&CheckOutcome> = d.outcomes.iter().collect();
    rows.sort_by_key(|o| match &o.verdict {
        Verdict::Unhealthy(_) => 0,
        Verdict::Unknown(_) => 1,
        Verdict::Healthy => 2,
    });
    for o in rows {
        let st = d.states.get(&o.id);
        let banked = st.map(|s| s.unhealthy_for()).unwrap_or(Duration::ZERO);
        let is_firing = st.map(|s| s.is_firing()).unwrap_or(false);

        let (tag, label, detail) = if let Some(cause) = d.suppressed.get(&o.id) {
            ("t-dim", "MUTED", format!("explained by {}", esc(cause)))
        } else if is_firing {
            (
                "t-bad",
                "FIRING",
                format!(
                    "{} <span class=dim>(for {})</span>",
                    esc(o.verdict.detail().unwrap_or("-")),
                    dur(banked)
                ),
            )
        } else {
            match &o.verdict {
                Verdict::Unhealthy(v) => (
                    "t-warn",
                    "ARMING",
                    format!(
                        "{} <span class=dim>({} of {} banked, fires in ~{})</span>",
                        esc(v),
                        dur(banked),
                        dur(o.cfg.pending_for),
                        dur(o.cfg.pending_for.saturating_sub(banked))
                    ),
                ),
                Verdict::Unknown(r) => (
                    "t-dim",
                    if o.warming_up { "WARMUP" } else { "FROZEN" },
                    format!("<span class=dim>{}</span>", esc(r)),
                ),
                Verdict::Healthy => (
                    "t-ok",
                    "ok",
                    format!(
                        "<span class=dim>{} endpoint(s) agree</span>",
                        o.tally.healthy
                    ),
                ),
            }
        };
        let _ = write!(
            h,
            "<tr><td><span class=\"tag {tag}\">{label}</span></td><td>{}</td><td>{detail}</td></tr>",
            esc(&o.id)
        );
    }
    h.push_str("</table>");

    h.push_str(
        "<footer>Refreshes every 15s. Read-only — this page performs no probes of its own, \
         it renders the last completed cycle. <a href=\"/metrics\">/metrics</a></footer>",
    );
    h.push_str("</div></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_from_remote_data() {
        // Endpoint names and RPC error text reach this page; a provider echoing
        // markup back must not be able to inject it.
        let out = esc(r#"<script>alert("x")</script> & co"#);
        assert!(!out.contains('<'), "{out}");
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&amp;"));
        assert!(out.contains("&quot;"));
    }

    #[test]
    fn durations_render_without_subsecond_noise() {
        assert_eq!(dur(Duration::from_millis(125_600)), "2m 5s");
    }
}

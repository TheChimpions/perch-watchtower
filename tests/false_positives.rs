//! End-to-end tests for the behaviour this watchtower exists to fix.
//!
//! These drive the real pipeline -- an actual HTTP request, real JSON-RPC
//! parsing, real check evaluation, real state machines -- against mock RPC
//! servers that misbehave in the ways the public endpoints actually misbehave.

use perch::{
    checks::{self, Progress},
    config::Config,
    rpc::Endpoint,
    snapshot::probe,
    state::{CheckState, Transition},
    verdict::Verdict,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const IDENTITY: &str = "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv";
const VOTE: &str = "3xPsGpzsAAiF4aU3jsEHcZtZHQVGKVCJqJ2bDYPHF6oy";
const INTERVAL: Duration = Duration::from_secs(60);

/// How a mock endpoint should answer.
#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    /// Healthy validator, voting, caught up.
    Healthy,
    /// Healthy responses, but the validator is in the delinquent list.
    Delinquent,
    /// HTTP 429, exactly like api.mainnet-beta.solana.com under load.
    RateLimited,
    /// HTTP 502 from a CDN in front of a struggling node.
    BadGateway,
    /// Accept the connection and never answer, producing "operation timed out".
    Hang,
    /// HTTP 200 carrying a Cloudflare error page instead of JSON.
    HtmlErrorPage,
}

/// A live chain moves between cycles. `tick` advances once per `getEpochInfo`,
/// i.e. once per probe cycle, and every other field is derived from it, so the
/// fixture stays internally consistent within a cycle.
fn healthy_body(method: &str, delinquent: bool, tick: u64) -> String {
    let slot = 312_874_910 + tick * 150;
    let credits = 41_900 + tick * 300;
    let account = format!(
        r#"{{"votePubkey":"{VOTE}","nodePubkey":"{IDENTITY}","activatedStake":5000000000000,
            "commission":8,"lastVote":{},"rootSlot":{},
            "epochCredits":[[820,{credits},0]]}}"#,
        slot - 10,
        slot - 42
    );
    let (current, delinq) = if delinquent {
        ("[]".to_string(), format!("[{account}]"))
    } else {
        (format!("[{account}]"), "[]".to_string())
    };

    let result = match method {
        "getGenesisHash" => r#""5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d""#.to_string(),
        "getEpochInfo" => format!(r#"{{"absoluteSlot":{slot},"epoch":820}}"#),
        "getVoteAccounts" => format!(r#"{{"current":{current},"delinquent":{delinq}}}"#),
        "getBalance" => format!(r#"{{"context":{{"slot":{slot}}},"value":25000000000}}"#),
        _ => "null".to_string(),
    };
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)
}

/// Spawn a mock RPC server and return its URL.
async fn spawn(behaviour: Behaviour) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tick = Arc::new(AtomicU64::new(0));

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let tick = Arc::clone(&tick);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                if behaviour == Behaviour::Hang {
                    // Hold the connection open without answering. The client's
                    // own timeout must be what ends this.
                    tokio::time::sleep(Duration::from_secs(120)).await;
                    return;
                }

                let method = request
                    .split(r#""method":""#)
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("")
                    .to_string();

                // One tick per cycle, claimed by the call that opens it.
                let tick = if method == "getEpochInfo" {
                    tick.fetch_add(1, Ordering::SeqCst)
                } else {
                    tick.load(Ordering::SeqCst).saturating_sub(1)
                };

                let (status, content_type, body) = match behaviour {
                    Behaviour::RateLimited => (
                        "429 Too Many Requests",
                        "application/json",
                        r#"{"error":"Too many requests"}"#.to_string(),
                    ),
                    Behaviour::BadGateway => {
                        ("502 Bad Gateway", "text/html", "<html>502</html>".to_string())
                    }
                    Behaviour::HtmlErrorPage => (
                        "200 OK",
                        "text/html",
                        "<!DOCTYPE html><html><body>Origin unreachable</body></html>".to_string(),
                    ),
                    Behaviour::Healthy => (
                        "200 OK",
                        "application/json",
                        healthy_body(&method, false, tick),
                    ),
                    Behaviour::Delinquent => (
                        "200 OK",
                        "application/json",
                        healthy_body(&method, true, tick),
                    ),
                    Behaviour::Hang => unreachable!(),
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    format!("http://{addr}")
}

fn config_for(urls: &[String], min_confirmations: usize) -> Config {
    let endpoints: String = urls
        .iter()
        .enumerate()
        .map(|(i, u)| {
            format!("[[endpoints]]\nname = \"rpc{i}\"\nurl = \"{u}\"\ntimeout = \"1s\"\nattempts = 1\n")
        })
        .collect();

    Config::parse(&format!(
        "{endpoints}\n\
         [quorum]\nmin_definite = 2\nmin_confirmations = {min_confirmations}\n\n\
         [[validators]]\nidentity = \"{IDENTITY}\"\nvote_account = \"{VOTE}\"\nlabel = \"chimps-1\"\n"
    ))
    .expect("test config should be valid")
}

async fn cycle(config: &Config, endpoints: &[Endpoint], progress: &mut Progress) -> Vec<checks::CheckOutcome> {
    let known = HashMap::new();
    let snapshots =
        futures::future::join_all(endpoints.iter().map(|e| probe(e, config, &known))).await;
    checks::evaluate(&snapshots, config, progress)
}

fn build_endpoints(config: &Config) -> Vec<Endpoint> {
    config
        .endpoints
        .iter()
        .map(|e| Endpoint::new(e.name.clone(), e.url.clone(), e.timeout, e.attempts).unwrap())
        .collect()
}

/// Replay one cycle's verdicts through the state machines for `cycles`
/// iterations of simulated time, collecting every non-quiet transition.
fn drive(
    outcomes: &[checks::CheckOutcome],
    states: &mut HashMap<String, CheckState>,
    cycles: u32,
    start: Instant,
) -> Vec<(String, Transition)> {
    let mut fired = Vec::new();
    for i in 0..cycles {
        let now = start + INTERVAL * i;
        for o in outcomes {
            let state = states.entry(o.id.clone()).or_default();
            let t = match &o.verdict {
                Verdict::Unhealthy(_) => state.on_unhealthy(&o.cfg, INTERVAL, now),
                Verdict::Healthy => state.on_healthy(&o.cfg, now),
                Verdict::Unknown(_) => state.on_unknown(Duration::from_secs(1200), now),
            };
            // A starvation notice is a watchtower-health message, not an alert
            // about the validator, so it does not count as "fired" here.
            if t != Transition::Quiet && t != Transition::Starved {
                fired.push((o.id.clone(), t));
            }
        }
    }
    fired
}

async fn assert_never_alerts(behaviour: Behaviour, label: &str) {
    let urls = vec![
        spawn(behaviour).await,
        spawn(behaviour).await,
        spawn(behaviour).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();

    let outcomes = cycle(&config, &endpoints, &mut progress).await;
    assert!(!outcomes.is_empty(), "{label}: no checks were evaluated");

    for o in &outcomes {
        assert!(
            matches!(o.verdict, Verdict::Unknown(_)),
            "{label}: check {} produced {:?}, but a transport failure must only \
             ever produce Unknown",
            o.id,
            o.verdict
        );
    }

    // Four hours of solid failure at a 60s interval.
    let mut states = HashMap::new();
    let fired = drive(&outcomes, &mut states, 240, Instant::now());
    assert!(
        fired.is_empty(),
        "{label}: {} alert(s) fired from pure transport failure: {fired:?}",
        fired.len()
    );
}

#[tokio::test]
async fn rate_limited_endpoints_never_alert() {
    // The exact shape of the reported problem: the public endpoint throttles,
    // upstream turns that into `Error: rpc-error: ...` and pages.
    assert_never_alerts(Behaviour::RateLimited, "429").await;
}

#[tokio::test]
async fn timeouts_never_alert() {
    // `error sending request for url (...): operation timed out`.
    assert_never_alerts(Behaviour::Hang, "timeout").await;
}

#[tokio::test]
async fn bad_gateways_never_alert_without_needing_a_suppression_flag() {
    // Upstream needs --ignore-http-bad-gateway for this one case; here it falls
    // out of the type, with no flag to forget to set.
    assert_never_alerts(Behaviour::BadGateway, "502").await;
}

#[tokio::test]
async fn html_error_pages_never_alert() {
    // A CDN returning 200 with an HTML body. Upstream's JSON decode error is a
    // client error and lands in `failures` like any other.
    assert_never_alerts(Behaviour::HtmlErrorPage, "html body").await;
}

#[tokio::test]
async fn a_single_lying_endpoint_cannot_page_you() {
    // One provider serving a stale or wrong vote account list, two healthy.
    let urls = vec![
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Healthy).await,
        spawn(Behaviour::Healthy).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();

    let outcomes = cycle(&config, &endpoints, &mut progress).await;
    let delinquency = outcomes
        .iter()
        .find(|o| o.id.starts_with("vote_delinquent:"))
        .expect("delinquency check should be evaluated");

    assert_eq!(
        delinquency.verdict,
        Verdict::Healthy,
        "two healthy endpoints must outvote one endpoint claiming delinquency"
    );

    let mut states = HashMap::new();
    let fired = drive(&outcomes, &mut states, 240, Instant::now());
    assert!(
        fired.iter().all(|(id, _)| !id.starts_with("vote_delinquent:")),
        "a single disagreeing endpoint paged: {fired:?}"
    );
}

#[tokio::test]
async fn a_real_delinquency_still_pages_after_the_hold_down() {
    // Suppressing noise is only worth anything if the real signal survives.
    let urls = vec![
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Delinquent).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();

    let outcomes = cycle(&config, &endpoints, &mut progress).await;
    let delinquency = outcomes
        .iter()
        .find(|o| o.id.starts_with("vote_delinquent:"))
        .expect("delinquency check should be evaluated");
    assert!(
        matches!(delinquency.verdict, Verdict::Unhealthy(_)),
        "three agreeing endpoints must confirm delinquency, got {:?}",
        delinquency.verdict
    );

    let start = Instant::now();
    let mut states = HashMap::new();

    // Delinquency is deliberately strict: nothing on the first observation...
    let early = drive(std::slice::from_ref(delinquency), &mut states, 1, start);
    assert!(early.is_empty(), "paged on a single observation: {early:?}");

    // ...and a page on the second, which is one minute of sustained,
    // corroborated delinquency. Lost rewards make waiting longer expensive, and
    // corroboration across endpoints already does the noise filtering.
    let late = drive(
        std::slice::from_ref(delinquency),
        &mut states,
        1,
        start + INTERVAL,
    );
    assert_eq!(
        late.len(),
        1,
        "a sustained real delinquency must page, got {late:?}"
    );
    assert_eq!(late[0].1, Transition::Firing);
}

#[tokio::test]
async fn flaky_endpoints_do_not_hide_a_real_delinquency() {
    // Two endpoints confirm delinquency, the third is rate limited. Quorum is
    // met by the two that answered, so the page still goes out.
    let urls = vec![
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::RateLimited).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();

    let outcomes = cycle(&config, &endpoints, &mut progress).await;
    let delinquency = outcomes
        .iter()
        .find(|o| o.id.starts_with("vote_delinquent:"))
        .unwrap();
    assert!(matches!(delinquency.verdict, Verdict::Unhealthy(_)));
    assert_eq!(delinquency.tally.unhealthy, 2);
    assert_eq!(delinquency.tally.unknown, 1);

    let mut states = HashMap::new();
    let fired = drive(std::slice::from_ref(delinquency), &mut states, 6, Instant::now());
    assert!(
        fired.iter().any(|(_, t)| *t == Transition::Firing),
        "a real delinquency must still page when one endpoint is throttled"
    );
}

#[tokio::test]
async fn a_healthy_validator_produces_no_alerts_at_all() {
    let urls = vec![
        spawn(Behaviour::Healthy).await,
        spawn(Behaviour::Healthy).await,
        spawn(Behaviour::Healthy).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();

    // Two cycles: the first establishes the progress baselines, the second has
    // real deltas to compare against.
    let _ = cycle(&config, &endpoints, &mut progress).await;
    let outcomes = cycle(&config, &endpoints, &mut progress).await;

    for o in &outcomes {
        assert!(
            !matches!(o.verdict, Verdict::Unhealthy(_)),
            "healthy fixture produced an unhealthy verdict for {}: {:?}",
            o.id,
            o.verdict
        );
    }
}

#[tokio::test]
async fn recovering_from_a_long_outage_does_not_page_instantly() {
    // The regression that duration-based hold-downs exist to prevent: blind for
    // a long time, then the first corroborated bad reading arrives. Wall-clock
    // thresholds would already be satisfied and page immediately.
    let urls = vec![
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Delinquent).await,
        spawn(Behaviour::Delinquent).await,
    ];
    let config = config_for(&urls, 2);
    let endpoints = build_endpoints(&config);
    let mut progress = Progress::default();
    let outcomes = cycle(&config, &endpoints, &mut progress).await;
    let delinquency = outcomes
        .iter()
        .find(|o| o.id.starts_with("vote_delinquent:"))
        .unwrap();

    let mut state = CheckState::default();
    let start = Instant::now();

    assert_eq!(
        state.on_unhealthy(&delinquency.cfg, INTERVAL, start),
        Transition::Quiet
    );
    for _ in 0..120 {
        assert_eq!(state.on_blind(), Transition::Quiet);
    }
    assert_eq!(
        state.on_unhealthy(&delinquency.cfg, INTERVAL, start + Duration::from_secs(7200)),
        Transition::Quiet,
        "two hours of blindness must not be cashed in as elapsed hold-down time"
    );
    assert_eq!(
        state.unhealthy_for(),
        Duration::ZERO,
        "evidence from before the gap should have expired, not accumulated"
    );
}

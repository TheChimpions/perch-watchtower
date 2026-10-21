//! Alpenglow admission, end to end: real HTTP, real JSON-RPC parsing, real
//! check evaluation, against a mock cluster.
//!
//! The mock enforces publicnode's limit of 10 accounts per
//! `getMultipleAccounts`. Eleven validators need 11 vote accounts; exceeding the limit is how the first version of this
//! check went Unknown on a live testnet endpoint every cycle.

use perch::{
    checks::{self, Progress},
    config::Config,
    rpc::Endpoint,
    snapshot::probe,
    verdict::Verdict,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SLOT: u64 = 4_320_100;

struct Validator {
    label: &'static str,
    identity: &'static str,
    vote: &'static str,
    vote_lamports: u64,
    bls: bool,
}

const fn healthy(label: &'static str, identity: &'static str, vote: &'static str) -> Validator {
    Validator { label, identity, vote, vote_lamports: 56_528_579_320_676, bls: true }
}

const VALIDATORS: [Validator; 11] = [
    Validator {
        label: "healthy",
        identity: "GdnSLrSSVBmCSxCC6Vy3KwkRRLAXhsFpqNHnHHTHHHvv",
        vote: "3xPsGpzsAAiF4aU3jsEHcZtZHQVGKVCJqJ2bDYPHF6oy",
        vote_lamports: 56_528_579_320_676,
        bls: true,
    },
    Validator {
        label: "underfunded",
        identity: "Underfunded111111111111111111111111111111111",
        vote: "UnderfundedVote11111111111111111111111111111",
        vote_lamports: 19_761_200,
        bls: true,
    },
    Validator {
        label: "no-bls",
        identity: "NoBLSKey1111111111111111111111111111111111",
        vote: "NoBLSKeyVote11111111111111111111111111111111",
        vote_lamports: 174_057_848_124_337,
        bls: false,
    },
    healthy("healthy-2", "Healthy2Id111111111111111111111111111111111", "Healthy2Vote1111111111111111111111111111111"),
    healthy("healthy-3", "Healthy3Id111111111111111111111111111111111", "Healthy3Vote1111111111111111111111111111111"),
    healthy("healthy-4", "Healthy4Id111111111111111111111111111111111", "Healthy4Vote1111111111111111111111111111111"),
    healthy("healthy-5", "Healthy5Id111111111111111111111111111111111", "Healthy5Vote1111111111111111111111111111111"),
    healthy("healthy-6", "Healthy6Id111111111111111111111111111111111", "Healthy6Vote1111111111111111111111111111111"),
    healthy("healthy-7", "Healthy7Id111111111111111111111111111111111", "Healthy7Vote1111111111111111111111111111111"),
    healthy("healthy-8", "Healthy8Id111111111111111111111111111111111", "Healthy8Vote1111111111111111111111111111111"),
    healthy("healthy-9", "Healthy9Id111111111111111111111111111111111", "Healthy9Vote1111111111111111111111111111111"),
];

/// What one mock endpoint was asked for.
#[derive(Default)]
struct Seen {
    /// The largest `getMultipleAccounts` batch.
    largest: AtomicUsize,
    /// Every account key requested, across batches.
    total: AtomicUsize,
    /// Some batch asked for a validator identity.
    identity: AtomicBool,
}

fn account_for(key: &str) -> Value {
    for v in &VALIDATORS {
        if key == v.vote {
            return json!({"lamports": v.vote_lamports, "data": {"parsed": {"type": "vote", "info": {
                "nodePubkey": v.identity,
                "commission": 5,
                "inflationRewardsCommissionBps": 500,
                "blockRevenueCommissionBps": 10000,
                "blsPubkeyCompressed": if v.bls { json!("BLSPUBKEYPLACEHOLDER") } else { Value::Null },
            }}}});
        }
    }
    Value::Null
}

fn answer(method: &str, params: &Value, seen: &Seen) -> (&'static str, String) {
    let result = match method {
        "getEpochInfo" => {
            json!({"absoluteSlot": SLOT, "epoch": 10, "slotIndex": 100, "slotsInEpoch": 432000})
        }
        "getVoteAccounts" => {
            // Filtered to one vote account when asked; the full listing otherwise,
            // which is what perch requests before it has learned the vote keys.
            let wanted = params[0]["votePubkey"].as_str();
            let current: Vec<Value> = VALIDATORS
                .iter()
                .filter(|v| wanted.is_none_or(|w| v.vote == w))
                .map(|v| json!({"votePubkey": v.vote, "nodePubkey": v.identity, "activatedStake": 5_000_000_000_000u64,
                                "commission": 5, "lastVote": SLOT - 2, "rootSlot": SLOT - 2,
                                "epochCredits": [[10, 1000, 0]]}))
                .collect();
            json!({"current": current, "delinquent": []})
        }
        "getMultipleAccounts" => {
            let keys = params[0].as_array().cloned().unwrap_or_default();
            seen.largest.fetch_max(keys.len(), Ordering::SeqCst);
            seen.total.fetch_add(keys.len(), Ordering::SeqCst);
            if keys.iter().any(|k| VALIDATORS.iter().any(|v| k.as_str() == Some(v.identity))) {
                seen.identity.store(true, Ordering::SeqCst);
            }
            if keys.len() > 10 {
                return (
                    "403 Forbidden",
                    r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Request blocked"},"id":1}"#.into(),
                );
            }
            let value: Vec<Value> = keys
                .iter()
                .map(|k| account_for(k.as_str().unwrap_or_default()))
                .collect();
            json!({"context": {"slot": SLOT}, "value": value})
        }
        "getMinimumBalanceForRentExemption" => json!(19_761_200),
        _ => Value::Null,
    };
    (
        "200 OK",
        json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string(),
    )
}

/// A mock endpoint; returns its URL and what it was asked for.
async fn spawn() -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let asked = Arc::new(Seen::default());
    let seen = Arc::clone(&asked);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut n = 0;
                // Read until the whole body has arrived.
                loop {
                    match socket.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
                            let (status, body) = answer(
                                req["method"].as_str().unwrap_or_default(),
                                &req["params"],
                                &seen,
                            );
                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            return;
                        }
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), asked)
}

fn config(urls: &[String]) -> Config {
    let mut toml = String::new();
    for (i, u) in urls.iter().enumerate() {
        toml.push_str(&format!(
            "[[endpoints]]\nname = \"rpc{i}\"\nurl = \"{u}\"\ntimeout = \"2s\"\nattempts = 1\n"
        ));
    }
    for v in &VALIDATORS {
        toml.push_str(&format!(
            "[[validators]]\nidentity = \"{}\"\nvote_account = \"{}\"\nlabel = \"{}\"\n",
            v.identity, v.vote, v.label
        ));
    }
    Config::parse(&toml).unwrap()
}

async fn evaluate() -> (Vec<checks::CheckOutcome>, Vec<Arc<Seen>>) {
    let (a, seen_a) = spawn().await;
    let (b, seen_b) = spawn().await;
    let cfg = config(&[a, b]);
    let endpoints: Vec<Endpoint> = cfg
        .endpoints
        .iter()
        .map(|e| Endpoint::new(e.name.clone(), e.url.clone(), Duration::from_secs(2), 1).unwrap())
        .collect();
    let known = HashMap::new();
    let snaps = futures::future::join_all(endpoints.iter().map(|e| probe(e, &cfg, &known))).await;
    (
        checks::evaluate(&snaps, &cfg, &mut Progress::default()),
        vec![seen_a, seen_b],
    )
}

fn find<'a>(out: &'a [checks::CheckOutcome], id: &str) -> &'a checks::CheckOutcome {
    out.iter()
        .find(|o| o.id == id)
        .unwrap_or_else(|| panic!("no outcome {id}"))
}

#[tokio::test]
async fn admission_is_judged_by_both_endpoints_despite_the_batch_limit() {
    let (out, seen) = evaluate().await;
    for s in &seen {
        assert!(
            s.largest.load(Ordering::SeqCst) <= 10,
            "a batch over 10 accounts was sent"
        );
        assert_eq!(s.total.load(Ordering::SeqCst), 11, "eleven vote accounts, so the batch had to split");
    }

    let under = find(&out, "vote_admission_critical:underfunded");
    assert!(
        matches!(&under.verdict, Verdict::Unhealthy(m) if m.contains("0.0198 SOL and needs 0.8198 SOL")),
        "{:?}",
        under.verdict
    );
    assert_eq!(
        under.tally.unhealthy, 2,
        "both endpoints must agree, not just one"
    );

    let no_bls = find(&out, "vote_admission_critical:no-bls");
    assert!(
        matches!(&no_bls.verdict, Verdict::Unhealthy(m) if m.contains("no BLS public key")),
        "{:?}",
        no_bls.verdict
    );
    assert_eq!(no_bls.tally.unhealthy, 2);

    assert_eq!(
        find(&out, "vote_admission_critical:healthy").verdict,
        Verdict::Healthy
    );
}

/// Under Alpenglow the identity pays for nothing that keeps it voting, so its
/// balance is neither fetched nor checked.
#[tokio::test]
async fn identity_balances_are_neither_fetched_nor_checked() {
    let (out, seen) = evaluate().await;
    for s in &seen {
        assert!(!s.identity.load(Ordering::SeqCst), "an identity account was requested");
    }
    assert!(!out.iter().any(|o| o.id.starts_with("identity_balance")));
}

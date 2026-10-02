//! Raw Solana JSON-RPC over reqwest.
//!
//! Deliberately no `solana-rpc-client` dependency. That crate collapses every
//! failure into an opaque `ClientError` whose `reqwest` variant is only reachable
//! for some errors, which is why upstream's only escape hatch is the very narrow
//! `--ignore-http-bad-gateway`. Owning the transport means we can classify every
//! failure mode precisely, and it decouples the watchtower from the validator's
//! agave version so a monitoring fix does not require rebuilding the validator.

use crate::verdict::Verdict;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, Clone, thiserror::Error)]
pub enum RpcError {
    /// Transport wobble, rate limiting, or a node that is momentarily unwell.
    /// Says nothing about the validator being monitored. Always becomes `Unknown`.
    #[error("transient: {0}")]
    Transient(String),

    /// The node gave an authoritative answer that we asked it something wrong:
    /// unknown method, bad params, malformed pubkey. This is a *watchtower*
    /// misconfiguration, not a validator fault. Surfaced loudly on the notify
    /// tier so it gets fixed, but it never pages and never counts as delinquency.
    #[error("config: {0}")]
    Config(String),

    /// The endpoint does not serve this method at all: JSON-RPC -32601, or a
    /// 401/403 wrapping it. A validator started without --full-rpc-api answers
    /// this way for getBlockProduction on every call, forever. That is a fact
    /// about the endpoint, not a fault in it or in us: learned once, said once,
    /// and the method is simply not asked of that endpoint again. Never counted
    /// as an error, because the other endpoints cover it -- and if none did, the
    /// check would starve and say so on its own.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl RpcError {
    pub fn into_verdict(self) -> Verdict {
        Verdict::unknown(self.to_string())
    }

    pub fn is_transient(&self) -> bool {
        matches!(self, RpcError::Transient(_))
    }
}

type RpcResult<T> = Result<T, RpcError>;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Instant,
};

/// Strip a request error's URL down to scheme, host and port.
///
/// reqwest puts the full request URL in its error text, and that text reaches
/// the journal and, through blindness and endpoint reports, Telegram. Providers
/// put API keys in the query (`?api-key=`) or the path (`/<token>/`); Telegram
/// puts the bot token in the path; a heartbeat URL *is* its secret. reqwest
/// redacts only `user:password@`. The host is kept: it is what makes the error
/// useful, and it is not a credential.
pub fn scrub(mut err: reqwest::Error) -> reqwest::Error {
    if let Some(url) = err.url_mut() {
        url.set_path("");
        url.set_query(None);
        url.set_fragment(None);
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }
    err
}

/// Classify a reqwest failure. Every transport-level outcome is transient --
/// there is no such thing as an HTTP error that proves a validator is delinquent.
fn classify_reqwest(err: &reqwest::Error) -> RpcError {
    let what = if err.is_timeout() {
        "operation timed out"
    } else if err.is_connect() {
        "connection failed"
    } else if err.is_decode() {
        "malformed response body"
    } else if err.is_redirect() {
        "too many redirects"
    } else if err.is_body() {
        "response body error"
    } else if err.is_request() {
        "request could not be sent"
    } else {
        "transport error"
    };
    RpcError::Transient(format!("{what} ({err})"))
}

/// Providers signal throttling inconsistently: some use 429, some use a 400 or
/// 403 whose body explains the real reason. Checking the text catches those.
fn looks_like_throttling(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    ["rate limit", "too many requests", "exceeded", "capacity", "try again", "throttl"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// HTTP statuses that mean "ask again later", not "your validator is broken".
fn classify_status(status: reqwest::StatusCode, body: &str) -> RpcError {
    let snippet: String = body.chars().take(180).collect();
    match status.as_u16() {
        // Rate limiting is the single largest source of upstream's false pages:
        // api.mainnet-beta.solana.com returns 429 under perfectly normal conditions.
        429 => RpcError::Transient(format!("rate limited (429): {snippet}")),
        408 | 425 => RpcError::Transient(format!("http {status}: {snippet}")),
        // Every 5xx, not just the 502 upstream special-cases.
        500..=599 => RpcError::Transient(format!("http {status}: {snippet}")),
        // 401/403 is a watchtower config problem worth telling the operator about,
        // but never a page. Two very different causes share the status, and the
        // wrong hint sends people hunting for an API key that was never the issue.
        401 | 403 if body.contains("-32601") || body.contains("Method not allowed") => {
            RpcError::Unsupported(format!(
                "http {status}: this endpoint refuses the method. A validator started with \
                 --private-rpc, or without --full-rpc-api, rejects the calls a watchtower \
                 needs even though the port is open. Reach it on its local RPC port over a \
                 private network instead of exposing it. {snippet}"
            ))
        }
        401 | 403 => RpcError::Config(format!(
            "http {status} (check the API key or the provider's IP allowlist): {snippet}"
        )),
        404 => RpcError::Config(format!("http 404 (check URL): {snippet}")),
        // Any other 4xx is the endpoint rejecting *us*: a wrong URL, an
        // unsupported method, a plan that does not cover this chain. Retrying
        // just wastes the cycle, so these are config errors -- unless the body
        // says the real reason was throttling.
        400..=499 if !looks_like_throttling(body) => {
            RpcError::Config(format!("http {status} (endpoint rejected the request): {snippet}"))
        }
        _ => RpcError::Transient(format!("http {status}: {snippet}")),
    }
}

/// JSON-RPC error codes. The Solana-specific ones in the -32000 block are almost
/// all "this node cannot serve you right now" rather than "the chain is broken".
fn classify_jsonrpc(code: i64, message: &str) -> RpcError {
    match code {
        // NodeUnhealthy / behind by N slots, BlockNotAvailable, BlockStatusNotAvailableYet,
        // MinContextSlotNotReached, internal error. All retryable.
        -32004 | -32005 | -32014 | -32016 | -32603 => {
            RpcError::Transient(format!("node unavailable ({code}): {message}"))
        }
        -32007 | -32009 => RpcError::Transient(format!("slot skipped ({code}): {message}")),
        -32011 => RpcError::Transient(format!("history unavailable ({code}): {message}")),
        -32019 => RpcError::Transient(format!("epoch rewards period active ({code}): {message}")),
        -32601 => RpcError::Unsupported(format!("method not supported by this endpoint: {message}")),
        -32602 => RpcError::Config(format!("invalid params: {message}")),
        -32600 | -32700 => RpcError::Config(format!("malformed request ({code}): {message}")),
        _ => {
            // Providers invent their own codes; some encode rate limits in the text.
            if looks_like_throttling(message) {
                RpcError::Transient(format!("provider throttling ({code}): {message}"))
            } else {
                RpcError::Transient(format!("rpc error {code}: {message}"))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorBody {
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Clone)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
    client: reqwest::Client,
    attempts: u32,
    /// Methods this endpoint has told us it does not serve. Shared across
    /// clones: a clone is the same endpoint, and should not have to learn twice.
    unsupported: Arc<Mutex<HashSet<String>>>,
    /// Answers that change on the scale of hours, keyed by method and params.
    cached: Arc<Mutex<HashMap<String, (Instant, Value)>>>,
}

impl Endpoint {
    pub fn new(name: String, url: String, timeout: Duration, attempts: u32) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // A fresh connection per cycle is cheap at a 60s interval and avoids
            // a half-dead pooled socket manufacturing a "timeout" every cycle.
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent(concat!("perch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            name,
            url,
            client,
            attempts: attempts.max(1),
            unsupported: Arc::new(Mutex::new(HashSet::new())),
            cached: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// `call`, but an answer younger than `ttl` is reused. For values like the
    /// rent minimum, which change only when a feature does: asking every cycle
    /// would spend an endpoint's quota on a number that has not moved.
    pub async fn call_cached(&self, method: &str, params: Value, ttl: Duration) -> RpcResult<Value> {
        let key = format!("{method} {params}");
        if let Ok(cache) = self.cached.lock() {
            if let Some((at, value)) = cache.get(&key) {
                if at.elapsed() < ttl {
                    return Ok(value.clone());
                }
            }
        }
        let value = self.call(method, params).await?;
        if let Ok(mut cache) = self.cached.lock() {
            cache.insert(key, (Instant::now(), value.clone()));
        }
        Ok(value)
    }

    pub fn is_unsupported(&self, method: &str) -> bool {
        self.unsupported
            .lock()
            .map(|set| set.contains(method))
            .unwrap_or(false)
    }

    /// Returns true the first time, so the caller can say so exactly once.
    pub fn mark_unsupported(&self, method: &str) -> bool {
        self.unsupported
            .lock()
            .map(|mut set| set.insert(method.to_string()))
            .unwrap_or(false)
    }

    pub fn unsupported_methods(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .unsupported
            .lock()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// For optional enrichment that not every endpoint can provide: the answer,
    /// or None, and *both* are remembered for `ttl`. Pruned history and
    /// unsupported methods are normal for public endpoints, so a refusal is
    /// neither logged as an endpoint error nor asked again every cycle.
    pub async fn call_optional(&self, method: &str, params: Value, ttl: Duration) -> Option<Value> {
        let key = format!("optional {method} {params}");
        if let Ok(cache) = self.cached.lock() {
            if let Some((at, value)) = cache.get(&key) {
                if at.elapsed() < ttl {
                    return (!value.is_null()).then(|| value.clone());
                }
            }
        }
        let value = match self.call(method, params).await {
            Ok(v) => v,
            Err(e) => {
                debug!(endpoint = %self.name, "{method} unavailable here: {e}");
                Value::Null
            }
        };
        if let Ok(mut cache) = self.cached.lock() {
            cache.insert(key, (Instant::now(), value.clone()));
        }
        (!value.is_null()).then_some(value)
    }

    /// One JSON-RPC call, retried on transient failure with exponential backoff
    /// and full jitter. Retrying *inside* a cycle is what keeps a single dropped
    /// packet from becoming a cycle-level failure in the first place.
    pub async fn call(&self, method: &str, params: Value) -> RpcResult<Value> {
        // Already told us no. Not worth a round trip, and not worth a log line.
        if self.is_unsupported(method) {
            return Err(RpcError::Unsupported(format!(
                "{method} is not served by {}",
                self.name
            )));
        }
        let mut last: RpcError = RpcError::Transient("no attempt made".into());

        for attempt in 0..self.attempts {
            if attempt > 0 {
                let base = 250u64.saturating_mul(1 << (attempt - 1).min(5));
                let delay = rand::thread_rng().gen_range(0..=base.min(4_000));
                debug!(
                    endpoint = %self.name, method, attempt,
                    "retrying after {delay}ms: {last}"
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self.call_once(method, &params).await {
                Ok(v) => return Ok(v),
                Err(RpcError::Unsupported(m)) => {
                    if self.mark_unsupported(method) {
                        tracing::info!(
                            endpoint = %self.name, method,
                            "endpoint does not serve this method; other endpoints will cover it \
                             and it will not be asked here again ({m})"
                        );
                    }
                    return Err(RpcError::Unsupported(m));
                }
                // Only transient failures are worth another attempt; a config
                // error will say the same thing every time.
                Err(e) if !e.is_transient() => return Err(e),
                Err(e) => last = e,
            }
        }

        warn!(endpoint = %self.name, method, "giving up after {} attempts: {last}", self.attempts);
        Err(last)
    }

    async fn call_once(&self, method: &str, params: &Value) -> RpcResult<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| classify_reqwest(&scrub(e)))?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| classify_reqwest(&scrub(e)))?;

        if !status.is_success() {
            return Err(classify_status(status, &text));
        }

        // A success status carrying an HTML error page is a proxy/CDN failing in
        // front of the RPC node. Transient, not a validator fault.
        let envelope: JsonRpcEnvelope = serde_json::from_str(&text).map_err(|e| {
            let snippet: String = text.chars().take(180).collect();
            RpcError::Transient(format!("unparseable response ({e}): {snippet}"))
        })?;

        if let Some(err) = envelope.error {
            return Err(classify_jsonrpc(err.code, &err.message));
        }

        envelope
            .result
            .ok_or_else(|| RpcError::Transient("response had neither result nor error".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_are_transient() {
        assert!(classify_status(reqwest::StatusCode::TOO_MANY_REQUESTS, "").is_transient());
    }

    #[test]
    fn every_5xx_is_transient_not_just_502() {
        for code in [500u16, 502, 503, 504, 520, 522, 524] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert!(
                classify_status(status, "").is_transient(),
                "http {code} should be transient"
            );
        }
    }

    #[test]
    fn plan_restrictions_are_config_not_retried_forever() {
        // Seen live from drpc: HTTP 400, "chain is not available on free plan".
        // Retrying this every cycle burns quota and never succeeds.
        let e = classify_status(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":{"message":"chain is not available on free plan, please upgrade"}}"#,
        );
        assert!(matches!(e, RpcError::Config(_)), "got {e}");
    }

    #[test]
    fn a_4xx_that_is_really_throttling_stays_transient() {
        let e = classify_status(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":"request rate limit exceeded"}"#,
        );
        assert!(e.is_transient(), "got {e}");
    }

    #[test]
    fn a_restricted_validator_rpc_says_so_instead_of_blaming_an_api_key() {
        // Observed live against a validator run with a restricted method set:
        // the port is open and answering, but every method a watchtower needs
        // comes back 403 / -32601.
        let e = classify_status(
            reqwest::StatusCode::FORBIDDEN,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not allowed"}}"#,
        );
        let msg = e.to_string();
        assert!(matches!(e, RpcError::Unsupported(_)), "a refused method is a fact, not a config error");
        assert!(msg.contains("--private-rpc"), "got: {msg}");
        assert!(!msg.contains("API key"), "misleading hint: {msg}");
    }

    #[test]
    fn a_plain_403_still_points_at_credentials() {
        let msg = classify_status(reqwest::StatusCode::FORBIDDEN, "forbidden").to_string();
        assert!(msg.contains("API key"), "got: {msg}");
    }

    #[test]
    fn auth_failures_are_config_not_transient() {
        assert!(matches!(
            classify_status(reqwest::StatusCode::UNAUTHORIZED, ""),
            RpcError::Config(_)
        ));
    }

    #[test]
    fn node_behind_is_transient() {
        assert!(classify_jsonrpc(-32005, "Node is behind by 512 slots").is_transient());
    }

    #[test]
    fn provider_throttle_text_is_transient() {
        assert!(classify_jsonrpc(-32099, "Rate limit exceeded, try again").is_transient());
    }

    #[test]
    fn bad_params_is_config() {
        assert!(matches!(
            classify_jsonrpc(-32602, "Invalid param: not a valid pubkey"),
            RpcError::Config(_)
        ));
    }

    #[test]
    fn every_rpc_error_degrades_to_unknown_never_unhealthy() {
        for e in [
            RpcError::Transient("operation timed out".into()),
            RpcError::Config("invalid params".into()),
        ] {
            assert!(matches!(e.into_verdict(), Verdict::Unknown(_)));
        }
    }
}

#[cfg(test)]
mod unsupported_methods {
    use super::*;

    fn endpoint() -> Endpoint {
        // Unroutable on purpose: any real attempt would come back Transient,
        // so an Unsupported result proves no network call was made.
        Endpoint::new("local".into(), "http://127.0.0.1:1".into(), Duration::from_millis(200), 1).unwrap()
    }

    /// The case that produced 355 "config errors" per report on every testnet
    /// box: a validator without --full-rpc-api refusing getBlockProduction.
    #[test]
    fn method_not_found_is_a_fact_about_the_endpoint_not_a_config_error() {
        let e = classify_jsonrpc(-32601, "Method not found");
        assert!(matches!(e, RpcError::Unsupported(_)), "got {e}");
        assert!(!e.is_transient());
    }

    #[test]
    fn learned_once_shared_across_clones() {
        let a = endpoint();
        assert!(!a.is_unsupported("getBlockProduction"));
        assert!(a.mark_unsupported("getBlockProduction"), "first time reports true");
        assert!(!a.mark_unsupported("getBlockProduction"), "second time reports false: say it once");
        let b = a.clone();
        assert!(b.is_unsupported("getBlockProduction"), "a clone is the same endpoint");
        assert_eq!(a.unsupported_methods(), vec!["getBlockProduction".to_string()]);
    }

    #[tokio::test]
    async fn a_remembered_method_is_not_asked_again() {
        let e = endpoint();
        e.mark_unsupported("getBlockProduction");
        match e.call("getBlockProduction", serde_json::json!([])).await {
            Err(RpcError::Unsupported(_)) => {}
            other => panic!("expected Unsupported without a network call, got {other:?}"),
        }
        // A method it has NOT refused still goes to the wire -- and here fails
        // transiently, which is the proof the short-circuit above was real.
        match e.call("getEpochInfo", serde_json::json!([])).await {
            Err(RpcError::Transient(_)) => {}
            other => panic!("expected a real (failed) attempt, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod scrub_tests {
    use super::scrub;

    /// Measured: with an endpoint like these down, both keys appeared verbatim
    /// in the journal, four times a cycle.
    #[tokio::test]
    async fn api_keys_in_the_query_or_path_never_reach_the_error_text() {
        let client = reqwest::Client::new();
        for url in [
            "http://127.0.0.1:1/?api-key=SUPERSECRET123",
            "http://127.0.0.1:1/rpc/PATHSECRET456/",
            "http://user:PASSWORDXYZ@127.0.0.1:1/bot123:TOKEN/sendMessage#frag",
        ] {
            let err = client.get(url).send().await.unwrap_err();
            let text = format!("{}", scrub(err));
            for secret in ["SUPERSECRET", "PATHSECRET", "PASSWORDXYZ", "TOKEN", "user", "frag"] {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
            assert!(text.contains("127.0.0.1:1"), "the host is what makes it debuggable: {text}");
        }
    }
}


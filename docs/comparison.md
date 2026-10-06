# perch vs agave-watchtower

`agave-watchtower` ships with every Agave release and is what most validators
run. This page compares the two feature by feature, says where agave-watchtower
is the better choice, and maps its flags onto perch's config.

Every claim about agave-watchtower is checked against its source at
[**v4.3.0**](https://github.com/anza-xyz/agave/tree/v4.3.0/watchtower), the
latest release when this was written, and links to the line it comes from. If a
newer release changes something here, please open an issue.


## The core difference

agave-watchtower asks each endpoint a set of questions every cycle and treats
an endpoint that fails to answer as a failure
([L513–523](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L513-L523)). With three `--urls` it needs a majority to agree
([L593](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L593)), so one flaky endpoint is outvoted. When a majority cannot be
reached, it alerts that the *watchtower* is unreliable ([L626–635](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L626-L635)), through
the same channels and at the same PagerDuty severity, `critical`
([nt L211](https://github.com/anza-xyz/agave/blob/v4.3.0/notifier/src/lib.rs#L211)), as a delinquent validator. With a single `--url`, any RPC error
does that. `--ignore-http-bad-gateway` suppresses HTTP 502 and nothing else
([L514–520](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L514-L520)).

perch treats a failure to answer as *unknown*, a separate type from unhealthy,
and there is no code path from unknown to a page. Losing sight of the cluster
is still reported, but as its own condition with its own, much longer
thresholds: Telegram at 5 minutes, a page at 20.

## At a glance

### Getting an alert right

| | agave-watchtower | perch |
|---|---|---|
| One endpoint times out, 429s or 5xxs | outvoted, if you run 3 `--urls` | ignored; that endpoint's answers are unknown |
| A majority of endpoints fail | pages "Watchtower is unreliable" after ~2 min | Telegram at 5 min, page at 20 min |
| Endpoints needed | exactly 1 or exactly 3 ([L98–110](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L98-L110)) | any number; quorum is configurable |
| An endpoint answering but stale | counted at full weight (slot range checked only at startup, [L561](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L561)) | discarded for that cycle when >300 slots behind the leader |
| Hold-down | one global count of consecutive failing cycles, default `>1` ([L128–134](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L128-L134), [L653](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L653)) | per check, in observed time; delinquency 60s, lag 3–5m, disks 10–15m |
| Evidence from before an outage | still counts toward the threshold | expires; the hold-down starts over |
| One healthy cycle mid-incident | resolves it and starts a new incident ([L670–690](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L670-L690)) | needs `clear_after` consecutive healthy cycles |
| Several failing checks | the first one found is reported ([L511](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L511)) | each check is tracked; symptoms are folded into their cause |
| Severity | everything is `critical` | per check: page (PagerDuty + Telegram), notify (Telegram), or log |
| Restart during an incident | the incident ID is in memory ([L600](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L600)), so the open PagerDuty incident is never resolved | state is persisted; the resolve lands on the original incident |
| Endpoint check fails at startup | exits ([L588–591](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L588-L591)); under systemd, a restart loop | warns and keeps running |

### What is monitored

| | agave-watchtower | perch |
|---|---|---|
| Validator delinquent | yes ([L444–449](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L444-L449)) | yes, corroborated |
| Vote account missing from the cluster | yes ([L450–456](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L450-L456)) | yes |
| Vote lag / root lag (slots behind) | no | yes |
| Vote credits not advancing | no | yes: catches "voting but not landing" |
| Skipped leader slots | no | yes, warn then page |
| Identity balance | yes, below 10 SOL ([L145–152](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L145-L152)) | yes, two bands (3 SOL notify, 0.5 SOL page), in epochs of voting left |
| Vote account VAT balance (Alpenglow) | yes, once Alpenglow is active ([L346–363](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L346-L363), [L467–500](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L467-L500)) | yes, against the next boundary, with runway in epochs, and readiness shown before Alpenglow is scheduled |
| BLS key registered (Alpenglow) | no | yes: a vote account without one is excluded whatever its balance |
| Identity balance under Alpenglow | still alerts below 10 SOL | stops paging: votes no longer cost the identity anything |
| Commission changed | no | yes, pages immediately; compared in basis points, inflation and block revenue |
| Delegation program minimum version | no | yes, for the current and next epoch |
| Stake pool obligations (Vault invoices, JPool bond) | no | yes, found on-chain from the identity |
| Cluster making progress | yes: transaction count and blockhash ([L404–423](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L404-L423)) | yes: slot progress |
| Cluster active stake | yes, opt-in ([L160–176](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L160-L176)) | yes, opt-in, Telegram by default |
| Your own RPC node lagging | no | yes (`node_behind`) |
| Disks: free space, time-to-full, read-only, inodes | no | yes, via node_exporter |
| Validator machine hard down | only as "delinquent", if the watchtower runs elsewhere | yes: a peer reports the machine, corroborated by the cluster |
| The watchtower itself dying | silence | dead-man's switch (heartbeat), or a standby takes over |

### Alerts and delivery

| | agave-watchtower | perch |
|---|---|---|
| Channels | **Slack, Discord, PagerDuty, Telegram, Twilio SMS**, log ([nt L120–151](https://github.com/anza-xyz/agave/blob/v4.3.0/notifier/src/lib.rs#L120-L151)) | PagerDuty, Telegram |
| Several Telegram chats | no, one `TELEGRAM_CHAT_ID` | yes |
| Retries on a failed delivery | no; one attempt, then a log line ([nt L197–226](https://github.com/anza-xyz/agave/blob/v4.3.0/notifier/src/lib.rs#L197-L226)) | yes, with backoff; losses are counted in a metric |
| Proves the alert path works | no | `perch test-notify`, plus a scheduled quiet self-test |
| Context in the alert | the failing check's message | corroboration, symptoms, epoch, cluster-wide delinquency, and likely causes from the box's own logs |
| Planned maintenance | no; a restart pages you | `perch maint restart`, which clears itself when the validator is back |
| Repeat notifications | when the message text changes | per check, on a schedule you set |
| Epoch summary | no | optional, one message per validator per epoch |

### Running it

| | agave-watchtower | perch |
|---|---|---|
| Install | ships with Agave; already on your box | one static binary, `install.sh`, or `cargo build` |
| Configuration | CLI flags and environment variables | a TOML file, strictly validated (unknown keys are errors) |
| Metrics | datapoints to Solana's InfluxDB, if configured | Prometheus `/metrics`, plus a Grafana dashboard |
| "Why is this (not) firing?" | read the logs | `perch status` |
| Several machines | independent copies, each alerting | peers, with an explicit rule for who alerts |
| systemd unit | none shipped with it | shipped, sandboxed (`systemd-analyze security`: 1.2) |
| Secrets in error logs | failed requests are logged with their full URL, which can carry RPC API keys and the Telegram bot token ([L521](https://github.com/anza-xyz/agave/blob/v4.3.0/watchtower/src/main.rs#L521), [nt L223–225](https://github.com/anza-xyz/agave/blob/v4.3.0/notifier/src/lib.rs#L223-L225)) | URLs scrubbed to the host |

### The project

| | agave-watchtower | perch |
|---|---|---|
| License | Apache-2.0 | Apache-2.0 |
| Maintained by | Anza, as part of Agave | [TheChimpions](https://github.com/TheChimpions), a validator operator |
| Release cadence | with every Agave release | independent of the validator |
| Language | Rust | Rust |

## Where agave-watchtower is the better choice

- **You need Slack, Discord or SMS.** perch delivers only to PagerDuty and
  Telegram.
- **You want nothing extra installed.** agave-watchtower is already on every
  machine with Agave.
- **You want the monitor maintained by the client team**, versioned with the
  validator.

Running both is reasonable: agave-watchtower as a second opinion on a separate,
non-paging channel, and perch as the one that pages.

## Moving over

The secret names are the same, so an existing `PAGERDUTY_INTEGRATION_KEY`,
`TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` work unchanged in
`/etc/perch/env`.

| agave-watchtower | perch |
|---|---|
| `--url` / `--urls A B C` | one `[[endpoints]]` block per URL, any number |
| `--validator-identity PUBKEY` | `[[validators]] identity = "PUBKEY"` (also set `vote_account` and `label`) |
| `--minimum-validator-identity-balance 10` | `[checks.identity_balance] warn_sol`, `page_sol` |
| `--monitor-active-stake` | `[checks.cluster_stake] enabled = true` |
| `--active-stake-alert-threshold 80` | `[checks.cluster_stake] min_percent = 80.0` |
| `--interval 60` | `[watchtower] interval = "60s"` |
| `--unhealthy-threshold N` | `pending_for` on each check |
| `--rpc-timeout 30` | `timeout = "30s"` on each endpoint |
| `--acceptable-slot-range 50` | `[quorum] max_endpoint_lag_slots`, applied every cycle |
| `--ignore-http-bad-gateway` | not needed; no transport error can page |
| `--name-suffix X` | `[watchtower] name = "X"` |
| `SLACK_WEBHOOK`, `DISCORD_WEBHOOK`, `TWILIO_CONFIG` | not supported |
| address labels from the Solana CLI config | `label` on each validator |

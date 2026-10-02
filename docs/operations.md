# Running perch

Day-to-day use: maintenance, verifying alerting, reading alerts, status,
Grafana and metrics.

## Planned maintenance

Restarts are routine and should not page anyone:

```sh
perch maint restart        # or: perch maint restart 2h
```

```
MAINTENANCE: waiting for the validator to recover (deadline 2026-10-02T19:40:06Z)
Paging is suppressed. Monitoring resumes by itself once the validator is voting
and healthy again, or at the deadline; Telegram tells you either way.
```

`perch maint` takes the silence file's path from the same config the daemon
reads, and prints what it wrote as the daemon's own parser reads it back, so it
cannot report "suppressed" for a file perch never looks at. It reads only
`[silence] file`, not the secrets, so any user in the `perch` group can run it.

Arm it **before** you start. The window waits for the work to actually begin --
it will not resume while the validator is still healthy, so there is no race
between arming it and touching the box. Once something does go wrong, it starts
watching for recovery, and clears itself when the validator is genuinely back:

```
Back online — monitoring resumed: chimps-1 is voting and every check is
healthy again. Full paging is back on.
```

Two metrics make the wait legible rather than opaque:

| Metric | Meaning |
| --- | --- |
| `perch_maintenance_awaiting_work` | 1 while armed and nothing has gone wrong yet |
| `perch_maintenance_healthy_streak` | clean cycles banked toward resuming (2 resumes) |

Three deliberate properties:

- **It waits for the event, not a timer.** You never have to guess how long a
  restart will take — too short pages you mid-restart, too long leaves you
  unmonitored after recovery.
- **The deadline is a backstop, not the mechanism.** If the validator does not
  return, the window expires and paging resumes: a restart that never finishes is
  an outage, not maintenance.
- **It needs two clean cycles**, because a validator often looks briefly fine
  mid-restart before the next check catches up.

Recovery is judged only on the checks that show the validator voting. An earlier
version waited for *no* check to be inconclusive, which could never happen on a
freshly restarted watchtower — `disk_fill` is Unknown by design for its first 45
minutes, so maintenance would have hung in exactly the situation it exists for.

### Maintenance reaches the hub

A spoke **declares** its window in metrics, and the hub **remembers** it:

```
perch_maintenance_until_seconds 1789702913
```

This matters for the case that is otherwise broken. If only the validator process
restarts, the spoke's watchtower keeps running and the hub sees nothing wrong —
fine by accident. But if the **box reboots**, the watchtower dies with it, the
cluster confirms the validator stopped voting, and the hub pages for a dead
machine — with the maintenance flag sitting on the box that just went away.

So the hub caches each peer's last-seen declaration, and honours it even after
the peer disappears. An undeclared disappearance still pages; suppression
requires a declaration. The cache is persisted, because a hub restarting
mid-window would otherwise forget and page for a box that is deliberately down.

Plain timed silences work too: `perch maint 30m`, `perch maint off`, and `perch maint` to show state.
While a box is silenced its own checks go to the journal only -- nothing to
PagerDuty, nothing to Telegram. A 🚨 about a validator you just took down reads
as an alarm, and it is not one. The lifecycle messages still arrive -- "back
online, monitoring resumed" and "window expired, paging resumed" -- so the
timeline has its start and its end. If you want the middle too, set
`[silence] notify_while_silenced = true` and pages become Telegram notes
instead of being dropped.

## Verify your alerting before trusting it

"Is my PagerDuty key actually right" is the worst possible question to have
answered by a real incident:

```sh
sudo bash -c 'set -a; . /etc/perch/env; perch test-notify'
```

The secrets live in `/etc/perch/env`, which systemd loads for the service;
loading it the same way here tests the same values.

It sends a real alert through the real code path — not a mock — then resolves it.
A wrong key fails loudly:

```
telegram   OK
pagerduty  FAILED: pagerduty rejected the event (400): Invalid routing key
```

A channel you asked for that got switched off is a **failure**, not a neutral
"not configured": a tool for checking your alerting path must not report success
while a channel you wanted is dead.

An unusable secret **disables that channel and logs it**, rather than stopping
the watchtower. One that will not start monitors nothing, which is strictly worse
than one that cannot page. `--check-config` is stricter and exits non-zero, since
that is where you have explicitly asked to be told.

Telegram accepts several chats — a list, or a comma-separated env value, since an
env file cannot hold a TOML array:

```toml
chat_id = "env:TELEGRAM_CHAT_ID"     # TELEGRAM_CHAT_ID=123,-1001234567890
```

One bad chat does not silence the others; it reports which failed and delivers to
the rest.

### And then keep verifying it

`test-notify` proves the path works the day you run it. Credentials are revoked,
tokens rotate and egress rules change on days you are not running it, so perch
repeats the check on its own:

```toml
[notify.self_test]
enabled = true      # on by default
interval = "7d"     # clamped to a minimum of 1h
```

The scheduled test is deliberately quiet. On PagerDuty it sends a **change
event** -- same routing key, same egress, recorded on the service timeline, and
by design never an incident and never a page. On Telegram it sends an ℹ️ rather
than a 🚨. Run `test-notify` by hand when you want the loud version that proves
the phone actually rings.

Be honest about what the quiet test proves for PagerDuty. The Events API is
fire-and-forget: it answers 202 "processed" for any well-formed routing key,
including a revoked one -- and that is equally true of alert events, so a real
trigger would not have proved more. A passing test shows the request left the
box and PagerDuty accepted it. Confirming that the key still *routes* needs the
REST API. Telegram's test is stronger: its API rejects a bad token or chat
synchronously.

It is **on by default**, deliberately. An opt-in guard against invisible failure
tends to stay opted out — which is how a dead alerting path survives to the night
it matters. Set `enabled = false` to turn it off.

A never-tested instance waits one whole interval rather than testing at boot:
testing on startup would turn a crash loop into a page generator. The clock is
persisted, so a box that reboots often still reaches its interval.

Three metrics make the result visible:

| Metric | Read it as |
| --- | --- |
| `perch_notify_failures_total{channel}` | Notifications that failed every retry and were **lost** |
| `perch_notify_self_test_timestamp_seconds{channel}` | Last time this channel was proven to work |
| `perch_notify_self_test_failures_total{channel}` | Scheduled tests that failed |

A failing test bumps the failure counter and leaves the timestamp stale, so a
permanently broken channel can never look freshly verified.

### An epoch summary, so you know it is still looking

Once per finished epoch, one Telegram message per validator:

```
Epoch 1036 summary
chimpions-mainnet
  leader slots 42, produced 41, skipped 1 (2.4%)
  credits earned 5,618,429
  identity balance 18.80 SOL
  agave 4.2.2
```

The weekly self-test proves perch can deliver. This proves it is watching, and
answers "how did the epoch go" without opening a dashboard. It is sent by
whichever instance owns alerting for the validator -- the same rule as alerts --
so a fleet produces one summary per validator, not one per box that can see it.

```toml
[digest]
enabled = true
```

Block production is read on the last cycle before rollover, so a leader slot in
the final minute of an epoch can be missed. Credits come from the vote account's
own per-epoch history and are exact. A restart within a minute of a boundary
skips that epoch's summary rather than sending a partial one.

## Severity tiers

- `page` — PagerDuty **and** Telegram. Delinquency, vote/root lag, credit stall,
  critical identity balance, unexpected commission change, read-only filesystem,
  a machine confirmed down.
- `notify` — Telegram only. Warning-level balances, cluster-wide stake, cluster
  stall, endpoint reliability digests (only for a window in which an endpoint was less than perfect -- a clean window is silent), starved checks.
- `log` — logs only.

Every threshold and severity is per-check in the config.

## Alert context

Alerts carry what you need to triage without opening a laptop:

```
chimps-1 is delinquent
chimps-1 delinquent, last vote slot 312869910
Confirmed by 3 of the 3 endpoint(s) that answered; 0 of 3 could not answer.
Unhealthy for 1m.
Also observed: chimps-1 last vote is 5150 slots behind the cluster; ...
Epoch 820, 50.0% complete (slot 312874910).
Cluster: 3 of 1045 validators delinquent (0.4% of stake). The cluster is
otherwise healthy, so this looks specific to your validator.
```

That last line is the difference between a useful page and ten minutes of
guessing. It costs one `getVoteAccounts` listing per alert burst and nothing at
all while things are quiet, so unlike `checks.cluster_stake` it is safe on free
endpoints.

### Likely causes, from the box itself

On the validator's own machine, perch can also say *why*. When one of that
validator's checks fires, it reads the recent tail of the validator log and the
NIC link counters, and appends what it found:

```
Likely causes (this box, last 20m):
- eno1 lost link 1 time(s), most recently around 06:02 UTC (478 since boot)
- the box had no network route to its peers (default route missing): 231309 log line(s), 06:02–06:07 UTC
- the gateway was not answering ARP: 4683 log line(s), 06:00–06:07 UTC
```

It looks for panics, a full disk, file-descriptor exhaustion, no route to
peers, the gateway not answering ARP, an unreachable network, DNS failures, PoH
falling behind, waiting for supermajority, and restarts. It finds the right part
of the log by bisecting on timestamps, so a multi-gigabyte log costs a few small
reads. Matches are counted, never quoted: validator logs carry credentials.

```toml
[diagnose]
validator = "chimps-1"                       # a [[validators]] label on this box
log = "/home/sol/logs/agave-validator.log"   # the validator's --log file
```

The sandbox hides `/home`, so the log directory has to be exposed, read-only,
with a drop-in. See [SECURITY.md](../SECURITY.md#opting-in-to-more-access-diagnose).

## Alpenglow

Under Alpenglow a vote account has to qualify again at every epoch boundary,
and one that does not sits out the epoch after next. `vote_admission` watches
for that:

| | when | goes to |
|---|---|---|
| `vote_admission_critical` | the next boundary will exclude the validator: no BLS key, or less than rent-exempt plus one VAT | PagerDuty and Telegram |
| `vote_admission_warn` | at its net drain (VAT minus commission income), the vote account passes fewer than `warn_epochs` (3) more boundaries | Telegram |
| `vote_admission_warn`, before Alpenglow is scheduled | the vote account would not pass if it were: no BLS key, too little SOL, or a drain that would run it out within `warn_epochs` | Telegram |

**Income counts.** Commission is paid into the vote account at every boundary,
so a validator whose commission exceeds the VAT never runs short, however low
its balance, and one that earns less drains slowly. perch reads last epoch's
commission with `getInflationReward` and works out the net:

```
chimps-1's vote account holds 6.4812 SOL and loses about 0.36 SOL per epoch
(1.00 SOL VAT, 0.64 SOL commission income): about 16 epoch(s) left, roughly
3 weeks. Top it up before it falls under 1.0198 SOL.
```

At 5% commission the break-even is roughly 113k SOL of stake. Most public
endpoints prune the history this needs; one that keeps it is enough, and with
none, perch assumes no income and says so.

The same sentence appears in three other places, so the trend is visible long
before anything alerts:

- `perch status`, in a VOTE ACCOUNTS section
- the epoch summary's vote account line
- the Grafana Alpenglow row, as Income/epoch, Net/epoch and Epochs left

The page names the epoch that runs the check, roughly how long until it, the
shortfall, and the epoch that would be lost. Top up the vote account, or
register a BLS key, before the deadline; the check clears by itself on the next
cycle. Agave logs the same verdict locally as `VAT Health Check: Currently you
will fail the VAT check`, and `[diagnose]` picks that line up as a likely cause.

When Alpenglow is scheduled on a cluster, perch enforces it at the very next
boundary, as the runtime does. Once it is in force for the current epoch, the
identity no longer pays for votes, so `identity_balance` stops paging and keeps
only its Telegram warning.

See [design.md](design.md#which-balance-matters-before-and-after-alpenglow)
for the rules and where each one comes from in Agave.

## Seeing what it is doing

There is deliberately no web app. Grafana already does that job better, and a
web app on a host next to validator infrastructure is auth, TLS, sessions and a
patch cadence you do not need. (The metrics port serves a read-only HTML
snapshot at `/`, and nothing else.) Instead there are two surfaces, each for a different
question.

### `perch status` — what is true right now, and why

Grafana answers "what happened over the last week". It cannot answer "why is
this check not firing *right now*". That depends on live state, and it used to
mean grepping logs:

```
$ perch status

perch 1.0.0 (9d34f2d)  chimpions-mainnet
Epoch 820, 6.4% complete (slot 312877310)

ENDPOINTS
  ok   localhost    slot 312877310  current
  ok   rpc-b        slot 312877160  150 slots behind
  DOWN rpc-c        rate limited (429)

  visibility: OK  2/3 usable, 2 needed

DISKS
  ok   chimps-1-hw /              150.0 GB free of  210 GB  28.6% used
  LOW  chimps-1-hw /mnt/ledger     96.4 GB free of 2000 GB  95.2% used  0.8% inodes

PEERS
  ok   failover-hub  pri 1  ok, cycled 1s ago, visible

  alerting:   OWN SCOPE  this instance owns alerting for everything it watches

CHECKS
  ARMING vote_delinquent:chimps-1   page  delinquent, last vote 312869910
                                          (0s of 1m banked, fires in ~1m)
  MUTED  vote_lag:chimps-1          page  explained by vote_delinquent:chimps-1
  MUTED  root_lag:chimps-1          page  explained by vote_delinquent:chimps-1
  FROZEN disk_fill_critical:...     page  only 12m of history, need 45m
  ok     identity_balance_warn:...  notify 2 endpoint(s) agree

SILENCE    ACTIVE until 2999-01-01T00:00:00Z
STATE      /var/lib/perch/state.json (10 check(s), written 1s ago)
```

With `[[peers]]` configured it also prints who is alerting — the single most
important thing to get right, since a mistake means either duplicate pages or
nobody sending them:

```
PEERS
  ok   failover-box  pri 1  ok, cycled 1s ago, visible

  alerting:   standby  failover-box is the alerting instance
```

With `[[hosts]]` configured it also prints a DISKS section:

```
DISKS
  ok   chimps-1-box /              150.0 GB free of    210 GB   28.6% used
  LOW  chimps-1-box /mnt/ledger     96.4 GB free of   2000 GB   95.2% used  0.8% inodes
  RO   chimps-1-box /mnt/accounts  480.0 GB free of    500 GB    4.0% used  READ-ONLY
```

Read-only by construction: one probe, writes nothing, cannot perturb a live
incident. Works over SSH, which is how you reach that host anyway.

### Grafana

[`grafana/perch-dashboard.json`](../grafana/perch-dashboard.json) is a template:
it uses only perch's own metrics and assumes nothing about your Prometheus. There
is no job name to match, no labels to add, and no datasource to rename.

**Set it up.** Point Prometheus at each instance's metrics port:

```yaml
scrape_configs:
  - job_name: perch            # any name; the dashboard finds it
    static_configs:
      - targets: ['127.0.0.1:9469']
```

Then either import it (*Dashboards → New → Import*, upload the JSON, pick your
Prometheus), or provision it from a file:

```yaml
# /etc/grafana/provisioning/dashboards/perch.yml
apiVersion: 1
providers:
  - name: perch
    type: file
    options: {path: /var/lib/grafana/dashboards/perch}
```

Both are tested against a live Grafana and Prometheus.

**The selectors at the top:**

| | |
|---|---|
| Prometheus | which datasource to read |
| Job | the scrape job your perch targets are under, found automatically |
| Cluster | the cluster each instance is pinned to with `[watchtower] cluster` |
| Instance | perch instances, listed by scrape target; graphs and tables show each one's `[watchtower] name` |
| Validator | validators, by their configured `label` |

**What is on it,** top to bottom:

- **Fleet**: headline counts (instances up, checks firing, validators
  delinquent, instances blind, in maintenance, lost notifications) and a table
  with one row per instance: scrape health, visibility, checks firing, cycle
  age, alerting owner, silences, and the perch and validator versions.
- **Checks**: when each check was unhealthy or could not be evaluated, how far
  unhealthy checks are toward their hold-down, and what is firing now.
- **Validators**: vote and root distance from the cluster tip, delinquency,
  vote credits per hour, skip rate, identity balance, and leader slots this
  epoch.
- **RPC endpoints**: which endpoints answered, errors by kind, and how far each
  is behind the most advanced one.
- **Disks**: projected time to full, free space, space and inode use, and
  read-only remounts.
- **Watchtowers**: cycle age and duration, which instance owns alerting, and
  peers as each instance sees them.
- **Notifications**: what was delivered and lost, when, and how long since each
  channel was last proven by a self-test.

Lines on the graphs mark perch's *default* alert thresholds. If you changed a
threshold in your config, the line does not move with it.

Panels that are empty for a good reason say why: "Nothing firing", "No
[[hosts]] configured", "No self-test yet".

**Changing it.** The JSON is generated by
[`grafana/build_dashboard.py`](../grafana/build_dashboard.py); edit that and run
`python3 grafana/build_dashboard.py`. `cargo test` checks four things:

- the committed JSON matches the script's output
- no two panels overlap
- every metric it queries is one perch exports
- nothing in it is tied to one deployment

## Knowing what is running

`perch --version` prints the version and the commit it was built from:

```
perch 1.0.0 (9d34f2d)
```

The same string is the startup log line, the `status` header, and
`perch_build_info{version="1.0.0",commit="9d34f2d"}` on every instance, so a
fleet can be audited from Prometheus. Several binaries can share a version and
differ; the commit is what tells them apart. A checkout with uncommitted changes
builds as `-dirty`. Building from a tarball with no `.git` needs
`PERCH_COMMIT=<hash>` in the environment, or it reports `unknown` -- stated,
never guessed.

## Metrics

With `[metrics]` enabled, `http://127.0.0.1:9469/metrics` serves Prometheus text
format.

```
perch_check_verdict{check="..."}           1 healthy, 0 unhealthy, -1 unknown
perch_check_firing{check="..."}
perch_check_unhealthy_seconds{check="..."} how close a check came to firing
perch_check_suppressed{check="..."}        inhibited by a broader failure
perch_check_confirmations{check="..."}     endpoints independently agreeing
perch_endpoint_usable{endpoint="..."}
perch_endpoint_slot{endpoint="..."}
perch_endpoint_transient_errors_total{endpoint="..."}
perch_validator_last_vote_slot{identity="...",validator="..."}   every perch_validator_* series carries both
perch_validator_credits{identity="..."}
perch_validator_delinquent{identity="..."}
perch_validator_balance_sol{identity="...",account="identity"}
perch_validator_vote_account_balance_sol{identity="...",validator="..."}
perch_validator_bls_registered{identity="...",validator="..."}   1, 0, or absent if no endpoint reports it
perch_validator_vote_income_sol{...}       commission paid in for the last completed epoch
perch_validator_vote_net_sol_per_epoch{...}   income minus VAT; negative drains
perch_validator_vote_runway_epochs{...}    boundaries left at that rate; absent when not draining
perch_alpenglow_phase                      0 not scheduled, 1 activates next boundary, 2 active
perch_vat_per_epoch_sol
perch_vote_account_minimum_sol             rent-exempt plus one VAT, at the next boundary
perch_validator_leader_slots{identity="..."}
perch_validator_blocks_produced{identity="..."}
perch_validator_skip_percent{identity="..."}
perch_visible

perch_alerting_owner
perch_maintenance_until_seconds
perch_start_timestamp_seconds
perch_peer_reachable{peer="..."}
perch_peer_last_cycle_age_seconds{peer="..."}
perch_peer_visible{peer="..."}
perch_host_scrape_ok{host="..."}
perch_filesystem_avail_bytes{host="...",mountpoint="...",device="..."}
perch_filesystem_size_bytes{host="...",mountpoint="...",device="..."}

perch_build_info{version="...",commit="..."}  which perch
perch_watchtower_info{name="...",solana_cluster="..."}
                                           this instance's [watchtower] name and pinned cluster
perch_node_version{endpoint="...",version="...",feature_set="..."}
                                           which validator build, from a local
                                           endpoint only -- a public RPC would
                                           report its provider's build, not yours
perch_cycle_duration_seconds
perch_check_pending_for_seconds{check="..."}
perch_endpoint_config_errors_total{endpoint="..."}
perch_validator_root_slot{identity="..."}
perch_silenced
perch_maintenance_awaiting_work            1 while armed and work has not begun
perch_maintenance_healthy_streak           clean cycles banked toward resuming

perch_notify_deliveries_total{channel="..."}
perch_notify_failures_total{channel="..."}        lost after every retry
perch_notify_last_success_timestamp_seconds{channel="..."}
perch_notify_self_test_timestamp_seconds{channel="..."}
perch_notify_self_test_failures_total{channel="..."}
perch_filesystem_used_percent{host="...",mountpoint="..."}
perch_filesystem_inodes_used_percent{host="...",mountpoint="..."}
perch_filesystem_readonly{host="...",mountpoint="..."}
perch_filesystem_seconds_to_full{host="...",mountpoint="..."}
perch_filesystem_fill_bytes_per_second{host="...",mountpoint="..."}
```

`seconds_to_full` is perch's own least-squares projection — the exact value
the alert logic tests, so the graph cannot disagree with the page. It is absent
when the filesystem is not filling or there is too little history; absent is the
honest rendering of "we cannot tell", which a sentinel value would hide.

The `verdict` gauge is the one to graph: it keeps "we could not tell" visible as
its own state instead of collapsing it into healthy.

The endpoint is unauthenticated — keep it on localhost or a private interface.

### It checks its own assumptions at startup

Every serious failure this watchtower has had in production looked healthy from
its own outputs. Spokes reported their hub reachable while polling their own
metrics port. A maintenance script printed "paging suppressed" while writing to
a path nothing read. Units reported `active` with every sandbox directive
silently ignored. None of those are visible in the metrics, because the metrics
were exactly what a working system would produce.

So on start, perch says what it actually got:

```
INFO sandbox: root=read-only home=hidden proc=private capabilities=none seccomp=on
WARN startup check: peer "chimps-1-box" points at http://127.0.0.1:9469/metrics,
     which is this instance's own metrics endpoint. It is polling itself, so that
     peer will look alive even when it is gone.
```

It checks that no peer resolves to this instance's own listen address, that the
silence directory exists so maintenance mode can actually be declared, and
reports the sandbox as fact rather than as whatever the unit file requested.
`--check-config` runs the same checks.

### Renaming without an outage

`[metrics] compat_prefix = "old_name"` emits every metric a second time under a
second prefix. It exists so a fleet can be renamed one box at a time: peers speak
the metric protocol to each other, so a renamed instance and an un-renamed one
would otherwise declare each other down in both directions at once. Dashboards
and alert rules written against the old names keep working too.

Set it during a rollout, remove it once every box is across. Leaving it on is
harmless but doubles the exposition.

## Rules worth adding to Prometheus

Failure modes perch cannot detect about itself, because they need a view of
every instance at once:

```yaml
# With alerting = "always" or "peers", every instance owns a disjoint scope and
# should report 1. A zero means that instance has gone quiet and whatever it
# watches is unmonitored.
- alert: PerchInstanceNotAlerting
  expr: perch_alerting_owner == 0
  for: 15m
- alert: PerchStalled
  expr: time() - perch_last_cycle_timestamp_seconds > 600
  for: 5m
- alert: PerchTargetDown
  expr: up{job="perch"} == 0
  for: 10m
```

**Do not** alert on `sum(perch_alerting_owner) > 1` unless you are using
`auto` mode. With disjoint scopes the sum equals the instance count, so that rule
fires permanently — mine did, for thirteen hours, before anyone noticed.

```yaml
# Alerts are being produced but not delivered. Any recent incident should be
# treated as unacknowledged -- nobody was told.
- alert: PerchNotificationsFailing
  expr: increase(perch_notify_failures_total[15m]) > 0
  labels:
    severity: page
  annotations:
    summary: "{{ $labels.instance }} lost {{ $value }} notification(s) on {{ $labels.channel }}"

# The alerting path has not been proven to work in two intervals. Every check can
# look perfectly healthy while this is firing; that is the point of it.
- alert: PerchSelfTestStale
  expr: >
    perch_notify_self_test_timestamp_seconds > 0
    and (time() - perch_notify_self_test_timestamp_seconds) > 1209600
  for: 30m
  labels:
    severity: page
  annotations:
    summary: "{{ $labels.instance }} has not verified its {{ $labels.channel }} path in 14d"

# Catches the case the rule above cannot: a channel that has never once
# succeeded, so its timestamp is still zero.
- alert: PerchSelfTestFailing
  expr: increase(perch_notify_self_test_failures_total[8d]) > 0
  labels:
    severity: page
  annotations:
    summary: "{{ $labels.instance }} cannot deliver on {{ $labels.channel }}"
```

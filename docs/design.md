# How perch decides what to alert on

The reasoning behind perch's behaviour. For setting it up, see the
[quickstart](../README.md#quickstart); for running it, [operations](operations.md).

## Why

A watchtower's job is to wake you when the validator needs you, and only then.
The most common way watchtowers fail at it is by confusing *I could not find
out* with *something is wrong*.

agave-watchtower treats an endpoint that fails to answer as a failure. With
three endpoints a majority must agree, so one flaky provider is outvoted, but
once a majority cannot be reached it pages "Watchtower is unreliable", through
the same channels and at the same PagerDuty severity as a delinquent validator.
With one endpoint, any timeout does it. Two minutes of ordinary public-endpoint
flakiness is enough. The only mitigation it offers is `--ignore-http-bad-gateway`,
which covers HTTP 502 and nothing else.

perch makes that class of page impossible rather than merely configurable. The
[comparison](comparison.md) goes through both tools feature by feature, with
links to agave-watchtower's source.

## The design rule

Evidence about the **validator** and evidence about the **observability path**
are different types, and only the first can page you.

```rust
pub enum Verdict {
    Healthy,            // the endpoint answered, and things are fine
    Unhealthy(String),  // the endpoint answered, and things are broken
    Unknown(String),    // we do not know
}
```

Every transport outcome — timeout, 429, any 5xx, connection reset, unparseable
body, HTML error page from a CDN — becomes `Unknown`. There is no code path that
converts `Unknown` into `Unhealthy`. An RPC failure cannot alert you because the
type does not permit it, not because a flag is set.

Everything else follows from that: corroboration across endpoints, hold-downs
that only count time spent actually looking, one page per event, and state that
survives a restart. The sections below explain each; the
[comparison](comparison.md) shows what they change in practice.

### Corroboration

Each cycle every endpoint is probed independently and produces its own verdict
per check. A check may only fire when at least `min_confirmations` endpoints
independently agree *and* no larger group disagrees. A single provider serving a
stale vote-account list cannot page you.

### Stale endpoints are discarded, not trusted

An endpoint that is frozen or far behind still *answers*. It reports an old
`lastVote` against its own old slot, computes a small lag, and votes Healthy —
outvoting endpoints that can see the real problem. Any endpoint more than
`max_endpoint_lag_slots` (default 300, ~2 minutes) behind the most advanced
endpoint in the cycle has everything it said discarded. This is what makes it
safe to mix endpoints of different quality.

### Hold-downs measured in observed time

`pending_for` accumulates only across cycles that produced a definite answer, and
each observation credits at most one interval. This is the difference that
matters after an outage: a wall-clock threshold would already be satisfied when
visibility returns, and the first bad reading would page immediately.

### One event, one page

A delinquent validator is necessarily also a validator whose last vote is stale,
whose root slot is stale, and whose credits have stopped. Without inhibition,
an early perch build opened **four** PagerDuty incidents for that single event. Prometheus
solves this with `inhibit_rules`; perch does the same, keyed per validator:

```
cluster_stalled       inhibits  every validator vote/lag check
vote_account_missing  inhibits  vote_delinquent, vote_lag, root_lag, vote_stalled
vote_delinquent       inhibits  vote_lag, root_lag, vote_stalled
```

The surviving alert lists the suppressed symptoms in its body, so you lose
nothing. Inhibition is computed from *confirmed verdicts*, never from merely
inconclusive ones, and never crosses validators. Unrelated checks are never
inhibited — a commission change, which may mean a compromised identity, is never
masked by delinquency.

### Restarts do not orphan incidents

Alert state is persisted every cycle. Without it, restarting during an incident
loses the PagerDuty dedup key: the eventual resolve goes out under a fresh UUID
PagerDuty has never seen, and the real incident stays open forever. A restart
also does not re-announce firing checks, does not shorten any hold-down, and a
corrupt or version-mismatched state file starts clean rather than refusing to
boot.

### A watchtower that can die silently is not finished

If perch panics, is OOM-killed, or its host dies, you get silence — which
looks exactly like everything being fine. It checks in with an external service
(Healthchecks.io, Better Stack, Cronitor, Dead Man's Snitch, PagerDuty
heartbeat) on every cycle, and by default only when it could actually see the
cluster, so the switch reports "working" rather than merely "running".

### An alert nobody receives is not an alert

Every check answers "is the validator healthy". None of them answer the question
that decides whether any of it matters: *if it were broken, could anyone be
told?*

A revoked routing key, a rotated bot token or a new egress rule leaves every
check reporting healthy while nothing can leave the box. Perch would show zero
alerts firing and page nobody, and you would find out during the outage.

So perch counts its own deliveries, and on a schedule it sends a real message
down the real path: a PagerDuty change event and a Telegram ℹ️. That proves the
routing key and the egress without opening an incident or waking anyone. See
[verifying alerting](operations.md#verify-your-alerting-before-trusting-it).

### Disks

A full disk is one of the most common ways a validator dies, and RPC exposes
nothing about the filesystem. perch scrapes node_exporter on each
validator over the private network.

**A percentage threshold is the wrong primary signal.** 85% of a 4TB disk is
600GB of headroom; 85% of a 500GB disk is 75GB. Since the ledger and accounts
database grow continuously, what matters is how long you have. So the paging
signal is **projected time-to-full**, with a free-space floor as the backstop:

```
chimps-1-box /mnt/ledger is filling up
/mnt/ledger has 96.4 GB free and is filling at 18.2 GB/hour; projected full in 5h 18m
```

Free space on a validator is a sawtooth — snapshots accumulate, then get purged —
so the slope is fitted by least squares over a multi-hour window rather than
taken from the last two samples, which would alternate between "full in minutes"
and "never". Below `min_history` the check reports **unknown**, not healthy: "we
have not been watching long enough" is not "fine", and unknown never pages.

**The free-space floor scales with the device.** An absolute floor is right for a
multi-terabyte ledger disk and absurd for a 1 GB `/boot`, which can never have
40 GB free and would alert forever. The effective floor is whichever is smaller:
the configured absolute value, or `max_floor_percent` (default 25%) of the
filesystem.

| filesystem | configured | effective |
|---|---|---|
| 4 TB ledger | 40 GB | **40 GB** — absolute governs |
| 988 MB `/boot` | 40 GB | **0.24 GB** — the cap governs |

Also checked: a filesystem remounted **read-only** (how a disk usually fails
under a validator — immediate page, no hold-down), and **inode exhaustion**,
which can happen with space to spare.

### One page, even across layers

Link a host to the validator it runs:

```toml
[[hosts]]
name = "chimps-1-box"
url = "http://10.0.0.5:9100/metrics"
validator = "chimps-1"
```

Now a full or read-only ledger disk explains the delinquency it causes. Measured
against the real binary, a read-only `/mnt/ledger` on a delinquent validator
produces exactly one page:

```
chimps-1-box /mnt/ledger is read-only
/mnt/ledger (/dev/nvme1n1) has been remounted read-only, which is how a failing
disk usually presents
Also observed: chimps-1 delinquent, last vote slot 312869910; chimps-1 last vote
is 5150 slots behind the cluster; ...
```

Six checks suppressed, one page, naming the cause rather than the symptom.
Without the link, disk problems inhibit nothing — there is nothing to say whose
disk it is, so suppressing a delinquency would be a guess.

### Validator health is strict; RPC trouble is patient

Delinquency fires in 60
seconds. Everything describing the *monitoring path* — blindness, `node_behind`,
`peer_down` — waits ten minutes or more. A test asserts every RPC-side threshold
stays at least 5× more patient than delinquency, so that asymmetry cannot erode
by accident.

Delinquency can afford to be strict because it already requires
`min_confirmations` independent endpoints to agree. The hold-down is not carrying
the false-positive load, so making it long bought almost no accuracy and cost
minutes of a real outage — which is lost block rewards.

### Which balance matters, before and after Alpenglow

**Before Alpenglow, the identity.** It pays for every vote transaction,
currently about **2 SOL per epoch**. When it empties, the validator stops voting
and goes delinquent. That is the load-bearing balance, and the alert says so:

```
chimps-1 identity balance is 0.800 SOL (floor 1 SOL), about 0.4 more epoch(s)
of voting at 2 SOL/epoch -- an empty identity cannot vote and goes delinquent
```

Two bands, and it says each thing once. Telegram when it drops below 3 SOL —
roughly 1.5 epochs of voting left — and a page below 0.5 SOL, about a quarter of
an epoch. `renotify_after = "0s"` is the default here: a balance draining over
days does not change between one 30-minute message and the next, and repeating
it is how an alert becomes something you skim past. PagerDuty owns escalation
once the paging band is crossed.

The vote account, meanwhile, only needs to stay rent-exempt. Its balance tracks
when rewards were last withdrawn: across one real fleet it read anything from
0.035 to 52,412 SOL among healthy validators.

**Under Alpenglow, the vote account.** Votes stop being transactions, so the
identity stops paying for them. On five testnet validators the identity fell
about 1.9 SOL a day until the switch to Alpenglow, and has risen slowly since,
on block fees alone. An empty identity no longer stops a validator voting, so
`identity_balance` stops paging once Alpenglow governs the current epoch and
drops to a single Telegram band.

The vote account takes over (SIMD-0357). At the first slot of every epoch N+1
the runtime decides which vote accounts take part in epoch N+2, and admits only
those that

1. have a BLS public key registered,
2. hold at least the rent-exempt minimum plus one epoch's Validator Admission
   Ticket (VAT), and
3. rank among the 2,000 most-staked accounts that pass 1 and 2.

Admitted accounts then have the VAT burned. The check runs before rewards are
calculated, so commission paid at that boundary does not count toward it. An
account that fails cannot vote or produce blocks for an epoch, and earns no
rewards for it.

`vote_admission` evaluates 1 and 2 against the next boundary, from public RPC:
the feature accounts (Alpenglow, and the slot-time reductions that set the VAT),
the vote account, and the rent minimum. It pages when the next boundary would
exclude the validator, and sends a Telegram warning when the balance covers
fewer than three more boundaries with no income:

```
chimps-1 will fail the VAT check at the start of epoch 1050, in about 17h: its
vote account holds 0.0198 SOL and needs 0.8198 SOL (rent-exempt 0.0198 plus one
epoch's VAT 0.80): 0.8000 SOL short. It will be unable to vote or produce
blocks in epoch 1051.
```

Three details decide whether that is right:

- **Scheduled is enforced immediately.** Feature activation runs before epoch
  stakes are computed, so the boundary that activates Alpenglow already
  applies the check. perch treats a scheduled (pending) feature account as
  enforced at the next boundary, and before anything is scheduled it reports
  readiness on Telegram: a vote account with no BLS key, or one too poor to
  pass, is flagged while there is still time.
- **The VAT follows the slot time.** It is 1.6 SOL at 400ms slots and falls
  with each reduction (1.4, 1.2, 1.0, 0.8 SOL at 350, 300, 250 and 200ms). A
  reduction takes effect the epoch after it activates. At the time of writing
  that makes it 1.0 SOL on mainnet and 0.8 SOL on testnet.
- **"Not reported" is not "missing".** An RPC node too old to report BLS keys
  reads as unknown, never as a validator without one.

The 2,000-account cap is not evaluated. It needs every other vote account's key
and balance, and both clusters are far below it: mainnet has under 700 staked
vote accounts.

### Nodes you operate, versus data sources

Mark your own RPC so it is *checked*, not merely used:

```toml
[[endpoints]]
name    = "localhost"
url     = "http://127.0.0.1:8899"
monitor = true
```

A validator's own RPC answering but lagging is invisible to every other check —
`find_stale` quietly discards it, and on a non-voting failover spare there is no
vote account to go delinquent. Without this, a spare that crashed or fell hours
behind looks exactly like a healthy one.

### Blindness is its own alert

Suppressing noise must not become silently ignoring an outage. If fewer than
`min_definite` endpoints answer, all checks freeze — and that state is itself
reported: Telegram at 5 minutes, PagerDuty at 20. Long enough that ordinary
provider flakiness never reaches it.

Likewise, if the cluster is visible but one check stays inconclusive past the
blindness page threshold, that check is reported once as starved — a frozen check
nobody knows about is worse than a noisy one.

### Delegation program compliance

The Solana Foundation Delegation Program publishes a minimum validator version
per upcoming epoch. Fall below it and the foundation's stake leaves. Perch polls
that schedule and compares it to the version the local node reports, in two
non-overlapping bands:

- **`sfdp_version_warn`** — you meet today's floor, but the *next* epoch raises
  it above your version. Telegram, roughly an epoch to act.
- **`sfdp_version_critical`** — you are below the floor for the epoch that has
  **already started**. Stake is at risk now, so this pages.

```
chimpions-mainnet runs agave 4.2.2; the delegation program requires >= 4.3.0
from epoch 1042, the next one. Upgrade before it starts to keep foundation stake.
```

Only the very next epoch warns. A floor three epochs out is real but not yet
actionable, and warning for days is how a useful alert becomes wallpaper.

```toml
[checks.sfdp_version]
enabled = true
severity = "page"          # the critical band; warn is always notify
poll_interval = "1h"       # floored at 5m
announce_changes = false   # true on one box per cluster
```

Version comparison is real semver, so `4.3.0-rc.0 < 4.3.0-rc.1 < 4.3.0` — a
release candidate does **not** satisfy a floor of the release, which is exactly
what a hand-rolled string comparison gets wrong. The check reads Unknown, never
unhealthy, when the foundation API is unreachable, the cluster is not covered,
or the local node's identity cannot be determined.

## What is actually hard about this

The plumbing — tri-state verdicts, corroboration, hold-downs, inhibition — is the
easy part, and it was right early. Every false positive in production came from
choosing the wrong thing to measure:

- A free-space floor with no relationship to device size, so a 1 GB `/boot` was
  permanently critical.
- Monitoring the vote account balance, which tracks treasury operations rather
  than health.
- A delinquency hold-down tuned as though corroboration did not already exist,
  so a real outage was reported minutes late.

In each case the machinery worked perfectly and reported exactly what it was told
to care about. If you adapt this, expect your thresholds to be wrong before your
logic is, and expect the corrections to come from operators rather than tests.

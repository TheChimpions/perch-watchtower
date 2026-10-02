# Deploying perch

Layouts, RPC endpoints, clusters and disk monitoring. Start with the
[quickstart](../README.md#quickstart); come here when you outgrow it.

## Layouts

perch runs perfectly well as a single instance. Everything below is
opt-in, and none of it needs a service, an account, or anything outside your own
machines. Ready-to-copy configs are in [`examples/`](../examples/).

| layout | what it is | you need |
|---|---|---|
| [1 standalone](../examples/1-standalone.toml) | one watchtower, anywhere | one machine |
| [2 on validator](../examples/2-on-validator.toml) | one per validator, each owning itself | nothing extra |
| [3 hub on failover](../examples/3-hub-on-failover.toml) | optional supervisor | a failover box |
| [4 redundant pair](../examples/4-redundant-pair.toml) | two full watchtowers, one alerts | two machines |

**Start with layout 1.** One instance on your failover box or any spare machine,
monitoring every validator remotely. That is a complete, useful setup.

**Layout 2** puts an instance on each validator so it can watch local disks over
localhost and own its own validator. Duplication is prevented by scope: each
instance lists only its own validator, so it is the only thing that can alert
about it. Nothing to elect, nothing central.

**Layout 3 is the only piece that needs a second machine**, and it buys exactly
one thing: detecting a validator box going *hard down*. An instance cannot
report its own machine dying. The hub notices the silence, checks the cluster,
and pages only if that validator has also stopped voting — silence alone is
Telegram, because silence could equally be a network blip. Layouts 2 and 3
together also mean each side reports the other's death.

**Layout 4** is for two machines that both watch everything. Because they share
a scope they would otherwise both page for the same event, so priority decides
which one speaks and the other takes over if it goes quiet. Only use it when the
scopes genuinely overlap.

### Without a hub

You should know precisely what you are giving up:

- Every validator, disk, balance and cluster check works identically.
- You lose detection of a machine going **hard down** — the watchtower dies with
  it and cannot report its own death.
- Cover that with `[heartbeat]`, which pings Healthchecks.io, Better Stack,
  Cronitor or Dead Man's Snitch every cycle. Free tiers are ample, and it is
  worth configuring in *every* layout, hub or not.

The difference: a heartbeat service pages whenever pings stop, including for
network blips. A hub pages only when silence is corroborated by the cluster.
Both work; the hub is quieter.

### How the modes fit together

`role` controls what is **observed**; `alerting` controls what is **reported**.

| `alerting` | reports | use for |
|---|---|---|
| `always` *(default)* | everything it watches, deferring to nobody | layouts 1 and 2 |
| `peers` | peer liveness only | the hub in layout 3 |
| `auto` | everything, but only while it holds priority | layout 4 |
| `never` | nothing | a pure data source |

`always` and `peers` ignore priority entirely — their scopes are disjoint, so
there is nothing to arbitrate. Only `auto` uses it.

Peer checks derive their dedup key from the peer's name alone, so several
instances reporting the same dead peer open one incident rather than several.
And peer health is tri-state like everything else: a peer that is reachable but
has not finished its first cycle is **starting**, not down. Instances expose
`perch_start_timestamp_seconds` so a boot is distinguishable from a wedge —
without it, a restarted instance plus an unrelated delinquency was enough to
declare a healthy machine hard down.

## Do not wire this to failover

This decides who *notifies*, and nothing else.

Solana failover means moving the identity keypair. If two machines run the same
identity at once you get double-voting and duplicate block production. A
monitor's opinion is exactly the wrong trigger for that: the partition case above
makes each side believe the other is dead. Both act, and now two machines vote
with one identity.

perch detects and pages. Real failover needs fencing or consensus, which is
a different kind of system.

## RPC endpoints: you do not need a paid plan

perch issues **4 calls per cycle per endpoint** for one validator —
`getEpochInfo`; `getVoteAccounts` filtered to your vote account and
`getBlockProduction`, each per validator; and `getMultipleAccounts` for the
vote accounts, identity balances and Alpenglow feature accounts, ten accounts
per call (the most publicnode accepts), which is one call for a single
validator. At a 60-second interval that is 5,760/day, ~173,000/month per
endpoint. Three options, in order of preference:

**1. Your own validator's RPC — free, unlimited, best signal.** Bind it to
localhost or a private interface and reach it from the monitoring host over
WireGuard/Tailscale; do not expose 8899 publicly. The default method set
(no `--full-rpc-api` needed) already covers every call perch makes.

Never make this your only endpoint. A wedged validator cannot be trusted to
report on itself — which is exactly what the stale-endpoint rule above catches.

**2. Free tiers, signup but $0** — Helius, QuickNode, Alchemy, Triton. 173k
calls/month is a small fraction of all of them, and you get dedicated quota.

**3. No signup at all.** These three were verified working against the exact
calls perch makes, and ship as the defaults in `examples/1-standalone.toml` and `config.example.toml`:

| endpoint | |
|---|---|
| `https://api.mainnet-beta.solana.com` | works, rate limited |
| `https://solana-rpc.publicnode.com` | works |
| `https://solana.leorpc.com/?api_key=FREE` | works |

They *will* intermittently fail. That is the case perch is built to
absorb rather than page you for — a fully-free three-endpoint setup runs clean.

Checked at the same time and **not** usable: ankr, drpc, 1rpc, rpcpool public
(403/400 without a key), onfinality and tatum (429 immediately), omniatech
(521), blockeden (402).

Three **independent** providers is the recommended minimum: two so a bad one can
be outvoted, three so you keep a quorum when one is in maintenance. Three URLs
behind the same provider fail together and buy you nothing.

Two settings matter for staying inside free quota:

- **Set `vote_account`** per validator. It selects the filtered
  `getVoteAccounts` query (a few hundred bytes) over the full multi-megabyte
  listing.
- **Leave `checks.cluster_stake` off** (the default). It is the one check that forces the
  full listing every cycle, and the fastest way to get throttled.

## Configuration is validated strictly

At startup, unknown keys are rejected so a
typo cannot silently disable a check, and a quorum that could never be satisfied
is a startup error rather than silent permanent muting.

```sh
perch --check-config
perch --once --dry-run
```

`--dry-run` evaluates everything and logs what it would send without delivering.

## Running mainnet and testnet

Nothing is hardcoded to mainnet — the cluster comes from whatever your endpoints
report. Verified live against testnet (epoch 1033) and devnet (epoch 1156).

**Pin the cluster in every config:**

```toml
[watchtower]
cluster = "testnet"   # mainnet-beta | testnet | devnet | <genesis hash>
```

Endpoints are already cross-checked against each other, so a config that *mixes*
clusters is refused:

```
Error: endpoints testnet-labs and OOPS-mainnet disagree on the genesis hash
(4uhcVJyU9... vs 5eykt4Us...); they are pointed at different clusters
```

The pin catches the other mistake — the one you actually make when you run both —
where every endpoint agrees but they are all the *wrong* cluster:

```
Error: endpoint testnet-labs is on genesis 4uhcVJyU9..., but watchtower.cluster
pins 5eykt4Us.... The endpoints are pointed at a different cluster than the one
this config is written for.
```

Unpinned, that failure mode surfaces as a 3am page for a "missing" vote account.

**Free testnet endpoints**, verified working against the calls perch makes:

| endpoint | |
|---|---|
| `https://api.testnet.solana.com` | works |
| `https://solana-testnet-rpc.publicnode.com` | works |

**Tune testnet down.** It is a test network: it restarts on purpose, and at the
time of writing 36 of 487 validators (7.4%) were delinquent with active stake at
92%. Mainnet-tuned thresholds will page you for normal testnet behaviour. Unless
you are specifically on the hook for testnet uptime, set the validator checks to
`severity = "notify"` so it reports to Telegram and never to PagerDuty, and lower
`checks.cluster_stake.min_percent` or leave that check disabled.

**Running both on one host** — give each instance its own:

```toml
[watchtower]
name = "chimps-testnet"     # appears in every notification
[state]
file = "/var/lib/perch/testnet.json"
[metrics]
listen = "127.0.0.1:9470"   # 9469 is taken by the mainnet instance
```

Sharing a state file would cross-contaminate incident keys. Sharing a port fails
loudly at startup (`Address already in use`), which is the right outcome. Run
them as two systemd units with separate `EnvironmentFile`s so each can route to
its own PagerDuty service.

## Disk monitoring: node_exporter

Required only for the disk checks; omit `[[hosts]]` and they do not run.

```sh
# Debian/Ubuntu
sudo apt-get install -y prometheus-node-exporter

# or upstream
curl -sL https://github.com/prometheus/node_exporter/releases/download/v1.8.2/\
node_exporter-1.8.2.linux-amd64.tar.gz | tar xz
sudo install -m0755 node_exporter-*/node_exporter /usr/local/bin/
```

Bind it to the **private interface only** — never `0.0.0.0`. node_exporter is
unauthenticated and leaks a great deal about the host:

```
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=10.0.0.5:9100 \
  --collector.filesystem
```

Reach it from the monitoring host over the same WireGuard/Tailscale path you use
for the validator's local RPC. A scrape that fails is `Unknown` — it freezes the
disk checks and never pages — and an exporter that stays unreachable is
eventually reported as a starved check.

## Sandboxing

The shipped unit is a system unit with a strict sandbox, and the directives are
silently ignored in a `systemctl --user` unit. What it enforces, what it does
not, and how to verify it on your machine are in [SECURITY.md](../SECURITY.md).

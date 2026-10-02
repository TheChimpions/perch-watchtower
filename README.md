# perch

**An open-source Solana validator watchtower that pages you when your
validator is in trouble, not when an RPC endpoint times out.**

[![CI](https://github.com/TheChimpions/perch-watchtower/actions/workflows/ci.yml/badge.svg)](https://github.com/TheChimpions/perch-watchtower/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

perch is Apache-2.0, written in Rust, and runs entirely on your own machines.
There is no account to create, no hosted service, and no telemetry. It is built
and run in production by a validator operator, and much of its behaviour exists
because a real incident demanded it.

```
🚨 chimps-1 is delinquent
chimps-1 delinquent, last vote slot 451878028
Confirmed by 2 of the 2 endpoint(s) that answered; 1 of 3 could not answer.
Unhealthy for 1m.
Also observed: chimps-1 last vote is 1393 slots behind the cluster (limit 200); ...
Epoch 1046, 1.7% complete (slot 451879421).
Cluster: 12 of 683 validators delinquent (0.1% of stake). The cluster is
otherwise healthy, so this looks specific to your validator.
Likely causes (this box, last 20m):
- eno1 lost link 1 time(s), most recently around 06:02 UTC (478 since boot)
- the box had no network route to its peers (default route missing): 231309 log line(s), 06:02–06:07 UTC
```

One page for one event, confirmed by independent endpoints, with the symptoms
folded in. It says whether the problem is yours or the whole cluster's, and on
the validator's own box, what its logs say went wrong.

## Open source

- **Apache-2.0**, the same license as Agave and jito-solana, with an express
  patent grant. Every dependency is under a permissive license; nothing is
  copyleft.
- **One Rust crate, no services.** The binary, its systemd unit, an annotated
  reference config and a Grafana dashboard are everything there is.
- **Nothing to sign up for.** It works with free public RPC endpoints, your own
  node, or any provider, and alerts through your own PagerDuty and Telegram.
- **Built in the open.** Issues and pull requests are welcome; see
  [Contributing](#contributing).

## Why you can trust it

**It does not cry wolf.** Every RPC outcome is one of three things: healthy,
unhealthy, or *unknown*. A timeout, 429, 5xx or a CDN's HTML error page is
unknown, and there is no code path from unknown to a page. A check fires only
when several independent endpoints agree, after a hold-down that counts only
time spent actually looking. The integration tests run the real pipeline against
endpoints that rate-limit, hang, return 502s and serve HTML error pages, and
assert that four hours of it produce zero alerts, while a real, corroborated
delinquency still pages.

**It does not go quiet without telling you.** If perch cannot see the cluster,
it says so, on its own schedule. If it dies, a heartbeat service pages. A weekly
self-test sends a real message down each alert channel, so a rotated Telegram
token or a blocked egress shows up before an incident does, and every lost
delivery is counted in a metric. If a whole machine
goes down, a peer instance reports it.

**It is safe to run next to your validator.**

- It never holds a keypair and never signs or sends a transaction; it calls
  ten read-only RPC methods.
- It runs as an unprivileged user with no capabilities, `/home` hidden, other
  processes invisible, a read-only filesystem apart from its own state
  directory, and no ability to start another program. All of that is enforced
  by the kernel. `systemd-analyze security` rates the unit 1.2 out of 10.
- It listens on one port, `127.0.0.1:9469`, read-only.
- It talks only to what you configure (RPC endpoints, node_exporter hosts,
  peers, alert channels, heartbeat), plus an hourly read of the Solana
  Foundation's public minimum-version schedule.
- Secrets never reach logs or alerts. Request URLs are scrubbed to the host
  before any error is written.

**You can check all of it.** Releases are static binaries with published
checksums and signed build provenance, built from the tagged commit by a public
workflow. [SECURITY.md](SECURITY.md) lists exactly what perch can read, write
and connect to, what the sandbox does not restrict, and the commands to verify
each claim on your own machine.

## Features

**Validator health.** Delinquency, vote and root lag, stalled vote credits,
skipped leader slots, identity balance in epochs of voting left, unexpected
commission changes, and the delegation program's minimum version for this epoch
and the next.

**Ready for Alpenglow.** Whether each vote account will be admitted at the next
epoch boundary: a BLS key registered, and enough SOL for rent plus the VAT, with
the deadline and the epoch at stake in the page. It counts the commission each
vote account earns against the VAT, so you see which accounts drain and how many
weeks they have. Before Alpenglow is scheduled, `perch status` and Grafana show
which validators are not ready, without notifying; once it is, the identity
balance stops paging, because votes no longer cost the identity anything.

**Infrastructure.** Disk free space, projected time-to-full, read-only
remounts and inode exhaustion via node_exporter. Your own RPC node falling
behind. A validator machine going hard down, reported by a peer and confirmed by
the cluster.

**Alerts worth reading.** PagerDuty for pages, Telegram for everything, with
per-check severity. Related symptoms are folded into one alert. Each alert says
whether the cluster is having the same problem, and on the validator's box, the
likely cause from its logs and network links. Resolves land on the original
PagerDuty incident, even across restarts.

**Operations.** `perch maint restart` before planned work, which resumes
paging by itself once the validator is back. `perch status` shows why any check
is or is not firing. `perch test-notify` proves the alert path end to end. An
optional per-epoch summary.

**Fleets.** One instance per validator, a hub on your failover box, or a
redundant pair, with an explicit rule for which instance speaks so you never get
duplicate pages. Mainnet and testnet side by side.

**Observability.** Prometheus metrics for every check, endpoint, validator,
disk and notification channel, and a ready-made Grafana dashboard.

| check | tier | fires after | notes |
|---|---|---|---|
| `vote_delinquent` | page | 60s | strict on purpose; corroboration does the filtering |
| `vote_lag` / `root_lag` | page | 3m / 5m | slots behind the cluster tip |
| `vote_stalled` | page | 5m | credits not advancing: catches voting-but-not-landing |
| `skip_rate` | notify / page | 20m | leader slots assigned vs blocks produced |
| `identity_balance` | notify / page | 15m | the balance that pays for votes, until Alpenglow |
| `vote_admission` | notify / page | 10m | Alpenglow: BLS key and VAT balance for the next epoch boundary |
| `commission_changed` | page | immediate | an unexpected change is a hijacked-identity signal |
| `sfdp_version` | notify / page | — | below the delegation program's minimum version |
| `node_behind` | page | 15m | a node *you operate* lagging or unreachable |
| `disk_space` / `disk_fill` | notify / page | 10m / 15m | free-space floor and projected time-to-full |
| `disk_readonly` | page | immediate | how a disk usually fails under a validator |
| `peer_down` / `machine_down` | notify / page | 10m / 3m | another perch went silent; paged only if its validator also stopped voting |
| `cluster_stake` / `cluster_stalled` | notify | 10m / 3m | not yours to fix at 3am |

`page` goes to PagerDuty and Telegram, `notify` to Telegram only. Every
threshold and tier can be changed per check.

## perch vs agave-watchtower

agave-watchtower ships with Agave and is what most validators run. The short
version, checked against its v4.3.0 source:

| | agave-watchtower | perch |
|---|---|---|
| A majority of RPC endpoints fail | pages "Watchtower is unreliable" after ~2 min | reported separately: Telegram at 5 min, page at 20 |
| Endpoints | exactly 1 or 3 | any number, with configurable quorum |
| Severity | everything is critical | page, notify or log, per check |
| Vote and root lag, credit stalls, skip rate | no | yes |
| Commission changes, delegation-program version | no | yes |
| Disks, own-node lag, machine down | no | yes |
| Planned maintenance | pages you | `perch maint restart` |
| Restart during an incident | PagerDuty incident left open | resolved on the original incident |
| Watchtower dies | silence | heartbeat, or a standby takes over |
| Proves its alert path works | no | test-notify and a weekly self-test |
| Metrics | InfluxDB datapoints | Prometheus and a Grafana dashboard |
| Alpenglow admission: VAT balance | yes, once active | yes, plus BLS key, net runway, and readiness shown before activation |
| Alert channels | **Slack, Discord, PagerDuty, Telegram, Twilio SMS** | PagerDuty, Telegram |
| Install | **already there with Agave** | one static binary |

agave-watchtower wins on the bold rows. [docs/comparison.md](docs/comparison.md)
has the full comparison, a link to the source line behind every claim, and a
flag-by-flag map for moving over. The secret names are the same, so your
existing environment file works as is.

## Quickstart

About ten minutes on any Linux machine with systemd, x86_64 or aarch64. Start on
your failover box or any spare machine: one instance can watch every validator
you run, remotely.

### 1. Install

```sh
curl -fsSLO https://github.com/TheChimpions/perch-watchtower/releases/latest/download/install.sh
less install.sh          # it runs as root; read it first
sudo bash install.sh
```

The installer downloads the static binary for your architecture and refuses it
if the checksum does not match. It creates an unprivileged `perch` user,
installs `/etc/perch/config.toml` and the sandboxed systemd unit, and adds you
to the `perch` group. It does not start anything. Re-running it upgrades
perch and leaves your config alone. To build from a checkout instead:
`sudo bash scripts/install.sh --from-source`.

### 2. Tell it which validator to watch

Edit `/etc/perch/config.toml` and fill in your validator:

```toml
[[validators]]
identity     = "YOUR_IDENTITY_PUBKEY"
vote_account = "YOUR_VOTE_PUBKEY"
label        = "chimps-1"          # the name used in alerts
```

The starter config already lists three free RPC endpoints that need no signup.
perch is built to absorb their occasional failures, and
[docs/deployment.md](docs/deployment.md#rpc-endpoints-you-do-not-need-a-paid-plan)
covers swapping in your own. Every other option is documented in
`/etc/perch/config.example.toml`.

### 3. Tell it where to send alerts

Secrets go in `/etc/perch/env`, which only root can read. Fill in whichever
channels you use:

```sh
sudo nano /etc/perch/env
```

- **Telegram** (recommended; this is where everything goes). Message
  [@BotFather](https://t.me/BotFather), send `/newbot`, and copy the token into
  `TELEGRAM_BOT_TOKEN`. Send your new bot any message, or add it to a group, then
  open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `"chat":{"id":…}`
  into `TELEGRAM_CHAT_ID`. Group ids are negative; several ids can be separated
  with commas.
- **PagerDuty** (for pages that should wake you). In a service, go to
  *Integrations → Add integration → Events API V2* and copy the integration key
  into `PAGERDUTY_INTEGRATION_KEY`.
- **Heartbeat** (strongly recommended). Tells you if perch itself dies. Create a
  check at [healthchecks.io](https://healthchecks.io) with a 1-minute period and
  a 3-minute grace, and copy its ping URL into `HEARTBEAT_URL`.

Use a bot and an integration key dedicated to perch, so either can be revoked
on its own.

Not using one of them? Delete its section (`[notify.pagerduty]`,
`[notify.telegram]` or `[heartbeat]`) from `config.toml`. A channel that is
configured but has no secret is switched off. perch keeps monitoring, but
`--check-config` fails, because a channel you asked for that cannot deliver is
exactly what you want to hear about.

### 4. Check it, then start it

```sh
# Validate the config, with the secrets loaded the way systemd will load them
sudo bash -c 'set -a; . /etc/perch/env; perch --check-config'

# Send a real alert through every channel. On PagerDuty this opens a real
# incident (your phone rings) and resolves it a moment later. Add --quiet for a
# change event and an info message that page nobody.
sudo bash -c 'set -a; . /etc/perch/env; perch test-notify'

sudo systemctl enable --now perch
journalctl -u perch -f
```

The first lines say what perch got:

```
INFO perch 1.0.0 (9d34f2d) starting: 3 endpoint(s), 1 validator(s), 60s interval
INFO sandbox: root=read-only home=hidden proc=private capabilities=none seccomp=on
INFO cycle complete: 3/3 endpoint(s) usable, ... visibility ok, 0 check(s) firing
```

At any time, `perch status` shows every check, why it is or is not firing, and
how close it is.

### 5. Before planned work

```sh
perch maint restart      # suppress paging until the validator is back (1h deadline)
perch maint 30m          # plain timed silence
perch maint off
```

`maint restart` waits for the validator to actually go down, then resumes paging
on its own once it is voting and healthy again. Log out and back in once after
installing so the `perch` group membership takes effect.

### Next steps

- **Watch disks** and get the best signal by running an instance on each
  validator: [layouts](docs/deployment.md#layouts), with ready-to-copy configs
  in [`examples/`](examples/).
- **Get told when a validator machine dies** by adding a hub on your failover
  box: [layout 3](examples/3-hub-on-failover.toml).
- **Graph it**: [Grafana dashboard and metrics](docs/operations.md#grafana).
- **Testnet as well**: [running both](docs/deployment.md#running-mainnet-and-testnet).

## Documentation

| | |
|---|---|
| [docs/comparison.md](docs/comparison.md) | perch vs agave-watchtower, feature by feature, and how to move over |
| [docs/deployment.md](docs/deployment.md) | layouts, RPC endpoints, mainnet and testnet, disk monitoring |
| [docs/operations.md](docs/operations.md) | maintenance, verifying alerts, alert context, `perch status`, Grafana, metrics, Prometheus rules |
| [docs/design.md](docs/design.md) | why it behaves the way it does |
| [SECURITY.md](SECURITY.md) | the security model, and how to check it |
| [config.example.toml](config.example.toml) | every option, annotated |

## Contributing

Bug reports, false positives, missed alerts and pull requests are all welcome.
A report of perch paging when it should not have, or staying quiet when it
should have spoken, is the most useful thing you can send: include the alert
text and `perch status` output if you can.

- `cargo test` must pass. It needs no network and no RPC endpoint.
- A behaviour change comes with a test, and a test that guards against a past
  failure says what that failure was.
- An RPC failure must never become a page. That rule is the point of the
  project.
- Report security problems privately: see [SECURITY.md](SECURITY.md).

## Building from source

```sh
cargo build --release --locked
cargo test
```

Rust 1.85 or newer. `Cargo.lock` is committed so a build gets exactly the
reviewed dependency versions. The test suite runs fully offline. Its
integration tests run the real pipeline (actual HTTP, real JSON-RPC parsing,
real state machines) against mock endpoints that rate-limit, hang, return 502s
and serve HTML error pages. They assert that four hours of that produce zero
alerts, while a genuine corroborated delinquency still pages.

`perch --version` prints the version and the commit it was built from, and every
instance exports the same string as `perch_build_info`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

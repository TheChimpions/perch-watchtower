# perch

**A Solana validator watchtower that pages you when your validator is in trouble, not when an RPC endpoint times out.**

[![CI](https://github.com/TheChimpions/perch-watchtower/actions/workflows/ci.yml/badge.svg)](https://github.com/TheChimpions/perch-watchtower/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

One static Rust binary, Apache-2.0, running on your own machines. No account, no hosted service, no telemetry. It alerts through your own PagerDuty and Telegram, works with free public RPC endpoints, and is run in production by a validator operator.

```
🚨 [mainnet] chimps-1 is delinquent
chimps-1 delinquent, last vote slot 451878028
Confirmed by 2 of the 2 endpoint(s) that answered; 1 of 3 could not answer.
Also observed: chimps-1 last vote is 1393 slots behind the cluster (limit 200); ...
Cluster: 12 of 683 validators delinquent (0.1% of stake). The cluster is
otherwise healthy, so this looks specific to your validator.
Likely causes (this box, last 20m):
- eno1 lost link 1 time(s), most recently around 06:02 UTC
```

One page for one event, confirmed by independent endpoints, with the symptoms folded in and, on the validator's own box, what its logs say went wrong. An RPC timeout, 429, 5xx or HTML error page is _unknown_, never a page: the integration tests run four hours of rate-limiting, hanging and 502s through the real pipeline and assert zero alerts.

## Install

About ten minutes on any Linux machine with systemd (x86_64 or aarch64). One instance can watch every validator you run, remotely; start on your failover box or any spare machine.

**1. Install the binary and the sandboxed service.**

```sh
curl -fsSLO https://github.com/TheChimpions/perch-watchtower/releases/latest/download/install.sh
less install.sh          # it runs as root; read it first
sudo bash install.sh
```

The installer verifies the download against the published checksum, creates an unprivileged `perch` user, installs `/etc/perch/config.toml` and the systemd unit, and adds you to the `perch` group. It starts nothing. Re-running it upgrades perch and leaves your config alone. From a checkout: `sudo bash scripts/install.sh --from-source`.

**2. Name your validator** in `/etc/perch/config.toml`:

```toml
[[validators]]
identity     = "YOUR_IDENTITY_PUBKEY"
vote_account = "YOUR_VOTE_PUBKEY"
label        = "chimps-1"          # the name used in alerts
```

The starter config lists three free RPC endpoints that need no signup. Every other option is documented in `/etc/perch/config.example.toml`.

**3. Put secrets in `/etc/perch/env`** (root only; perch itself cannot read it):

- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`: message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the token. Message the bot once, then read your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`. Group ids are negative; several ids can be comma-separated. Everything goes here.
- `PAGERDUTY_INTEGRATION_KEY`: a service's _Integrations → Events API V2_ key. Pages that should wake you go here.
- `HEARTBEAT_URL`: a [healthchecks.io](https://healthchecks.io) check with a 1-minute period and 3-minute grace. This is what tells you perch itself died.

Give perch its own bot and its own integration key, so either can be revoked alone. Delete the section of any channel you do not use (`[notify.pagerduty]`, `[notify.telegram]`, `[heartbeat]`); a channel that is configured but has no secret fails `--check-config`, on purpose.

**4. Check it, then start it.**

```sh
sudo bash -c 'set -a; . /etc/perch/env; perch --check-config'
sudo bash -c 'set -a; . /etc/perch/env; perch test-notify'   # real alert on every channel; --quiet pages nobody
sudo systemctl enable --now perch
journalctl -u perch -f
```

```
INFO perch 1.4.2 (…) starting: 3 endpoint(s), 1 validator(s), 60s interval
INFO sandbox: root=read-only home=hidden proc=private capabilities=none seccomp=on
INFO cycle complete: 3/3 endpoint(s) usable, ... visibility ok, 0 check(s) firing
```

`perch status` shows every check and why it is or is not firing. Log out and in once so the `perch` group takes effect.

**5. Before planned work:**

```sh
perch maint restart            # hold paging until the validator is back (1h deadline)
perch maint cluster-restart    # hold everything through a cluster restart (12h)
perch maint 30m                # plain timed silence
perch maint off
```

**Next:** an instance on each validator box watches its disks and reads its log ([layouts](docs/deployment.md#layouts), [examples/](examples/)); a hub on the failover box reports a machine that goes hard down ([layout 3](examples/3-hub-on-failover.toml)); [Grafana](docs/operations.md#grafana); [mainnet and testnet together](docs/deployment.md#running-mainnet-and-testnet).

## Security

perch runs next to validators, so the question that matters is what it could do if it were compromised. The full answer, with the command to verify each line on your own machine, is in [SECURITY.md](SECURITY.md).

- **It never holds a keypair and never signs or sends a transaction.** It calls twelve read-only RPC methods, all listed in SECURITY.md.
- **The kernel enforces the rest.** It runs as an unprivileged user with no capabilities, `/home` hidden, other processes invisible, a read-only filesystem apart from its own state directory, and no ability to start another program. `systemd-analyze security` rates the unit 1.2 out of 10.
- **It listens on one port**, `127.0.0.1:9469`, read-only metrics. Keep it on localhost or a private network.
- **It talks only to what you configure**: your RPC endpoints, node_exporter hosts, peers, alert channels and heartbeat, plus an hourly read of the Solana Foundation's public minimum-version schedule.
- **Secrets stay out of logs and alerts.** Request URLs are cut to the host before an error is written anywhere, and there is a test that sends secrets in the query, path and userinfo and asserts none reach the error text.
- **Releases are verifiable.** Static binaries built from the tagged commit by a public workflow, with checksums and signed build provenance: `gh attestation verify perch-x86_64-unknown-linux-musl.tar.gz -R TheChimpions/perch-watchtower`.

Report vulnerabilities privately through the repository's Security tab.

## What it checks

| check                               | tier          | fires after    | notes                                                                      |
| ----------------------------------- | ------------- | -------------- | -------------------------------------------------------------------------- |
| `vote_delinquent`                   | page          | 60s            | strict on purpose; corroboration does the filtering                        |
| `vote_lag`                          | page          | 3m             | last vote slots behind the cluster tip                                     |
| `vote_stalled`                      | page          | 5m             | credits not advancing: catches voting-but-not-landing                      |
| `skip_rate`                         | notify / page | 20m            | leader slots assigned vs blocks produced                                   |
| `vote_admission`                    | notify / page | 10m            | Alpenglow: BLS key and VAT balance for the next epoch boundary             |
| `commission_changed`                | page          | immediate      | an unexpected change is a hijacked-identity signal                         |
| `sfdp_version`                      | notify / page | —              | below the delegation program's minimum version                             |
| `vault_invoices`                    | notify / page | 15m            | unpaid Vault invoices: 6 notify, 9 page, removal at 10                     |
| `jpool_bond`                        | notify / page | 15m            | below JPool's security requirement, or under a week of runway              |
| `node_behind`                       | page          | 15m            | a node _you operate_ lagging or unreachable                                |
| `disk_space` / `disk_fill`          | notify / page | 10m / 15m      | free-space floor and projected time-to-full                                |
| `disk_readonly` / `disk_missing`    | page          | immediate / 2m | how disks fail under a validator                                           |
| `peer_down` / `machine_down`        | notify / page | 10m / 3m       | another perch went silent; paged only if its validator also stopped voting |
| `cluster_stake` / `cluster_stalled` | notify        | 10m / 3m       | not yours to fix at 3am                                                    |

`page` goes to PagerDuty and Telegram, once per incident; `notify` to Telegram only. Every threshold and tier is per check. Related symptoms fold into one alert, every alert is tagged with its cluster, and resolves land on the original PagerDuty incident even across restarts.

Compared with agave-watchtower, perch adds corroboration, severities, lag, credit, skip-rate, disk, machine-down and stake-pool checks, maintenance windows, a heartbeat and a self-test; agave-watchtower has more alert channels and ships with Agave. [docs/comparison.md](docs/comparison.md) has the line-by-line comparison and a flag map for moving over.

## Documentation

|                                            |                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| [SECURITY.md](SECURITY.md)                 | the security model, and how to check it                                        |
| [docs/deployment.md](docs/deployment.md)   | layouts, RPC endpoints, mainnet and testnet, disk monitoring                   |
| [docs/operations.md](docs/operations.md)   | maintenance, verifying alerts, alert context, `perch status`, Grafana, metrics |
| [docs/design.md](docs/design.md)           | why it behaves the way it does                                                 |
| [docs/comparison.md](docs/comparison.md)   | perch vs agave-watchtower                                                      |
| [config.example.toml](config.example.toml) | every option, annotated                                                        |

## Contributing

A report of perch paging when it should not have, or staying quiet when it should have spoken, is the most useful thing you can send; include the alert text and `perch status` output.

- `cargo test` must pass. It needs no network.
- A behaviour change comes with a test, and a test that guards against a past failure says what that failure was.
- An RPC failure must never become a page.
- To release, bump `version` in `Cargo.toml` and `Cargo.lock` in the PR; merging to `main` builds, tags and publishes. Do not create tags or releases by hand.

## Building from source

```sh
cargo build --release --locked
cargo test
```

Rust 1.85 or newer. `perch --version` prints the version and commit, and every instance exports the same string as `perch_build_info`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

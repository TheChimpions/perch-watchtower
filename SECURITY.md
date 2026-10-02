# Security

perch runs next to validators, so the useful question is not "is it secure" but
"what could it do if it were compromised". This document answers that
precisely: what perch can reach, what it cannot, which of those are promises
about the source and which are enforced by the kernel, and how to check each
one on your own machine.

## Reporting a vulnerability

Use **Report a vulnerability** on the repository's Security tab (GitHub private
vulnerability reporting). Please do not open a public issue.

## The short version

| | |
|---|---|
| Holds a keypair | **No.** It has no code to load one, and `/home` is hidden from it. |
| Signs or sends transactions | **No.** It calls ten read-only RPC methods, listed below. |
| Runs other programs | **No**, and the kernel enforces it (`NoExecPaths=/`). |
| Writes to the system | **One directory**, `/var/lib/perch`. Everything else is read-only. |
| Runs as root | **No.** A dedicated `perch` user with no shell, no home and no capabilities. |
| Listens on the network | **One port**, `127.0.0.1:9469` by default, read-only metrics. |
| Phones home | **No.** No telemetry, no update check, no crash reporting. |
| Can reach the internet | **Yes.** It has to: RPC endpoints and alert channels are arbitrary URLs. |

`systemd-analyze security perch` rates the shipped unit **1.2** on a scale where
10 is unconfined (measured on Ubuntu 24.04).

## What perch sends, and to whom

Every outbound connection perch makes, and nothing else:

| Destination | When | What is sent |
|---|---|---|
| Your `[[endpoints]]` | every cycle | JSON-RPC `getEpochInfo`; per validator `getVoteAccounts` (filtered to your vote account) and `getBlockProduction` (identity); `getMultipleAccounts`, in batches of 10, for every validator's vote account and identity plus five public feature accounts (Alpenglow and the slot-time reductions). Hourly, `getMinimumBalanceForRentExemption`, and `getInflationReward` for your vote accounts' commission in the last completed epoch. Once at startup, `getGenesisHash`. Local endpoints only: `getVersion`, `getIdentity`. If an endpoint will not serve `getMultipleAccounts`, `getBalance` per identity instead. When an alert fires: one unfiltered `getVoteAccounts`, for cluster context. All public pubkeys; no secrets. |
| Your `[[hosts]]` | every cycle | `GET /metrics` on node_exporter. |
| Your `[[peers]]` | every cycle | `GET /metrics` on another perch. |
| `api.telegram.org` | when alerting; weekly self-test | The alert text. The bot token is part of the URL, as Telegram requires. |
| `events.pagerduty.com` | page-tier alerts; weekly self-test | The alert, and the integration key, in the request body. |
| Your `[heartbeat] url` | every cycle, if configured | A bare `GET`. |
| `api.solana.org` | hourly, if the cluster is pinned to mainnet-beta or testnet | `?cluster=<name>`, to fetch the delegation program's minimum version. Turn it off with `[checks.sfdp_version] enabled = false`. |

**What alerts contain.** Telegram and PagerDuty are third parties, so it is
worth knowing what reaches them: validator labels and pubkeys, slot numbers,
balances, peer and host names, and error descriptions. Error text has request
URLs scrubbed to scheme, host and port first, because providers put API keys in
the query (`?api-key=`) or path, and Telegram puts its bot token in the path.
With `[diagnose]` on, alerts include *counts* of matched validator-log lines,
never the lines themselves: validator logs carry credentials (metrics URLs with
passwords in them).

**Secrets in logs.** Secrets are never logged. When an `env:` reference cannot
be resolved the log names the variable, not its value. Request URLs in errors
are scrubbed as described above; there is a test that sends requests carrying
query-string, path and userinfo secrets and asserts none of them reach the
error text.

## What perch listens on

One TCP listener, `[metrics] listen`, default **`127.0.0.1:9469`**:

- `GET /metrics`: Prometheus text.
- `GET /`: the same state as a small HTML page.

It has no authentication, accepts no input beyond the request path, and has no
endpoint that changes anything. It does reveal things: validator pubkeys,
balances, endpoint *names* (never URLs), peer names, software versions, and
whether a maintenance window is active. **Keep it on localhost or a private
interface.** For a hub to reach it, use a private network (WireGuard,
Tailscale) or an SSH tunnel, never `0.0.0.0` on a public address.

## What perch can read and write

| Path | Access | Why |
|---|---|---|
| `/etc/perch/config.toml` | read | Configuration. Mode 0640, `root:perch`. |
| `/etc/perch/env` | **none** | Secrets. Mode 0600, `root:root`. systemd reads it as root and passes the values in as environment variables; the perch process cannot open the file. |
| `/var/lib/perch/state.json` | read, write | Alert state, so a restart does not orphan an open incident. Written atomically, mode 0640 so `perch status` works for the `perch` group. Holds check states and incident keys, no secrets. |
| `/var/lib/perch/maint/silence` | read, delete | Maintenance windows. Written by `perch maint`; perch deletes it when a window ends. |
| `/proc/self/{status,mountinfo}` | read | The startup sandbox self-report. |
| `/sys/class/net/*/carrier_down_count` | read | Only with `[diagnose]`: link-flap counts. |
| The validator log | read | Only with `[diagnose]`, and only after you bind-mount its directory in. |
| `/home`, `/root`, `/run/user` | **none** | Hidden by `ProtectHome=true`. |
| Every other path | read-only, subject to normal file permissions | `ProtectSystem=strict`. |

That last row matters for keypairs. `ProtectSystem=strict` makes the rest of
the system read-only, not invisible, so a keypair kept *outside* `/home` is
protected by its file permissions. `solana-keygen` writes keypairs as 0600, and
the `perch` user cannot read a 0600 file owned by `sol`. Check that this holds
for yours (see below), and if a keypair is world-readable, fix the file. If you
want a second layer anyway, a drop-in can hide the directory outright:

```ini
# /etc/systemd/system/perch.service.d/keys.conf
[Service]
InaccessiblePaths=/mnt/ledger/keys
```

## What the sandbox enforces

These are directives in [`perch.service`](perch.service). Each is enforced by
the kernel, not by perch's own code:

| Directive | Effect |
|---|---|
| `User=perch` | Unprivileged system user: no shell, no home, no sudo. |
| `CapabilityBoundingSet=` (empty) | No Linux capabilities, ever. It cannot bind low ports, change file ownership, or bypass permissions. |
| `NoNewPrivileges=true` | No path back to root through setuid binaries. |
| `NoExecPaths=/`, `ExecPaths=/usr/local/bin/perch /usr/lib /lib` | Cannot execute a shell, `curl`, `solana`, or anything else. |
| `ProtectSystem=strict`, `ReadWritePaths=/var/lib/perch` | The entire filesystem is read-only except perch's state directory. |
| `ProtectHome=true` | `/home`, `/root` and `/run/user` are empty and inaccessible. |
| `PrivateTmp=true`, `PrivateDevices=true` | Its own `/tmp`; no access to disks or other devices. |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other processes, the validator included, are invisible. It cannot read their command lines, environments or memory, or signal them. |
| `RestrictAddressFamilies=AF_INET AF_INET6` | IP sockets only. No Unix sockets, so no Docker socket, D-Bus, or any local control socket. |
| `SystemCallFilter=@system-service` minus `@privileged @resources @obsolete` | A seccomp allow-list of ordinary service syscalls. |
| `MemoryDenyWriteExecute=true` | No memory that is both writable and executable, which blocks most code-injection techniques. |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | Cannot change kernel settings, load modules, read the kernel log, or change the clock or hostname. |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `RemoveIPC` | Closes the remaining escalation and persistence routes. |
| `CPUQuota=20%`, `MemoryMax=192M`, `TasksMax=64`, `Nice=19`, `IOSchedulingClass=idle` | A bug cannot starve the validator of CPU, memory or disk I/O. |

### What it does not restrict, and why

- **Outbound network.** RPC endpoints, alert channels and heartbeat services
  are arbitrary URLs, so there is no fixed list to allow. A compromised perch
  could send what it can read to anywhere on the internet. In practice that is
  its config and the secrets passed to it: the PagerDuty integration key, the
  Telegram bot token and any RPC API keys. **Give perch its own Telegram bot
  and its own PagerDuty integration**, so that a leak can be revoked without
  touching anything else. If your endpoints are fixed, you can add
  `IPAddressAllow=`/`IPAddressDeny=` in a drop-in.
- **Reading world-readable files outside `/home`**, covered above.

### Sandboxing only works as a system unit

The directives above are silently ignored in a `systemctl --user` unit: an
unprivileged service manager cannot set up the namespaces or drop capabilities,
and the unit starts anyway with no isolation at all. `install.sh` installs a
system unit. perch also reports at startup the sandbox it actually got, not
the one its unit file asked for:

```
INFO sandbox: root=read-only home=hidden proc=private capabilities=none seccomp=on
```

If that line says `writable`, `visible`, `shared`, `retained` or `off`, the
sandbox did not apply.

## Check it yourself

On a running install:

```sh
# The sandbox perch reports for itself
journalctl -u perch | grep sandbox

# systemd's own assessment (lower is better)
systemd-analyze security perch

# What perch can see of /home: should list nothing
PID=$(systemctl show -p MainPID --value perch)
sudo ls -la /proc/$PID/root/home/

# No capabilities, seccomp on, no new privileges
sudo grep -E '^(CapBnd|NoNewPrivs|Seccomp):' /proc/$PID/status
# CapBnd: 0000000000000000   NoNewPrivs: 1   Seccomp: 2

# Your keypairs must not be readable by the perch user (want: Permission denied)
sudo -u perch cat /path/to/validator-keypair.json

# The secrets file must not be readable by the perch user (want: Permission denied)
sudo -u perch cat /etc/perch/env

# The only listener
sudo ss -ltnp | grep perch
```

## Opting in to more access: `[diagnose]`

`[diagnose]` reads the validator's log so alerts can name a likely cause. It is
off by default and needs two deliberate changes in a drop-in:

```ini
# /etc/systemd/system/perch.service.d/diagnose.conf
[Service]
ProtectHome=tmpfs
BindReadOnlyPaths=/home/sol/logs
```

`ProtectHome=tmpfs` replaces `/home` with an empty directory, and the bind
mount exposes the log directory inside it, read-only. Nothing else under
`/home` becomes visible: tested with a keypair in `/home/sol` next to
`/home/sol/logs`, perch could read the log and could not see the keypair. The
startup line then reports `home=empty` instead of `home=hidden`.

## Supply chain

- **Dependencies.** 143 crates in the Linux build graph, every one under a
  permissive license (MIT, Apache-2.0, ISC, BSD, Zlib, Unicode-3.0,
  CDLA-Permissive-2.0 for the bundled CA roots), none copyleft. `Cargo.lock` is
  committed, and builds use `--locked`, so a release builds against exactly
  the reviewed versions.
- **TLS** is rustls. There is no OpenSSL and no system TLS library.
- **Release binaries** are statically linked (musl) and built by
  [`.github/workflows/release.yml`](.github/workflows/release.yml) from the
  tagged commit. Every third-party action in it is pinned to a full commit SHA.
- **Checksums.** Each release publishes `SHA256SUMS`. `install.sh` refuses to
  install a download that does not match.
- **Provenance.** Each release archive carries a signed GitHub build-provenance
  attestation. It proves that the file was built by this repository's workflow
  from a specific commit:

  ```sh
  gh attestation verify perch-x86_64-unknown-linux-musl.tar.gz -R TheChimpions/perch-watchtower
  ```

- **The installer runs as root**, once. Download it, read it (it is about 150
  lines), then run it. It creates the `perch` user and the directories above,
  installs the binary and the unit, and never overwrites an existing config or
  secrets file. It does not start the service.
- **Building from source** needs nothing beyond `cargo build --release
  --locked` on Rust 1.85 or newer. `install.sh --from-source` builds as the
  invoking user, not root.

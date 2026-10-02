# Deployment layouts

Pick the one that matches your setup. Every layout works on its own — **the hub
is entirely optional**, and nothing here requires a service, an account, or
anything outside your own machines.

| file | what it is | you need |
|---|---|---|
| `1-standalone.toml` | One watchtower, anywhere | one machine |
| `2-on-validator.toml` | A watchtower on each validator, owning itself | nothing extra |
| `3-hub-on-failover.toml` | Optional supervisor on the failover box | a failover box |
| `4-redundant-pair.toml` | Two full watchtowers, one alerts at a time | two machines |

## Which to use

**Just starting?** `1-standalone.toml` on your failover box, or anywhere that
isn't a validator. It monitors every validator remotely and needs nothing else.
This is a complete, useful setup.

**Want disk monitoring, or the best signal?** `2-on-validator.toml`, one per
validator. Each instance owns its own validator and watches its own disks over
localhost. It alerts you directly — there is no central anything.

**Want to be told when a validator machine goes hard down?** Add
`3-hub-on-failover.toml`. This is the one thing an instance cannot do for
itself: when the machine dies, so does its watchtower. The hub notices the
silence, checks the cluster, and pages only if the validator has also stopped
voting. Layouts 2 and 3 together are the full picture, and each reports the
other's death.

**Two machines, no strong opinions?** `4-redundant-pair.toml`. Both watch
everything, only one alerts, the other takes over if it goes quiet.

## Without a hub

You are not missing much, and you should know exactly what:

- Every validator, disk, balance and cluster check works identically.
- What you lose is detection of a machine going **hard down** — the watchtower
  dies with it and cannot report its own death.
- Cover that with `[heartbeat]` instead. It pings Healthchecks.io, Better
  Stack, Cronitor or Dead Man's Snitch on every cycle, and they alert when the
  pings stop. Free tiers are ample. This is worth configuring in every layout,
  hub or not.

The difference: a heartbeat service pages whenever pings stop, including for
network blips. A hub pages only when silence is corroborated by the cluster
reporting that validator stopped voting. Both are useful; the hub is quieter.

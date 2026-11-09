# How dfw works

This explains what dfw does inside the host. The rule syntax and day-to-day
use are in the [README](../README.md).

## Guarantees

- A container on a filtered network can send or receive nothing outside its
  rules, from its first packet, at boot and while dfw restarts. The two
  exceptions are a root user on the host changing the table (repaired at
  once) and connections that already existed when dfw was enabled (cut by
  `dfw enable`).
- No failure opens anything beyond the rules last applied: new containers
  stay blocked, and others keep the rules they had.
- A rule that can't be parsed or resolved never widens access.
- Editing the rules files changes nothing until the administrator runs
  `dfw apply`, or `dfw run` restarts. Either way, connections the new rules
  don't allow are cut.
- IPv4 and IPv6 are both covered.
- Networks not named by a `network` line are left as Docker made them.

Out of scope: Swarm, overlay, macvlan and ipvlan networks as filtered
networks; rootless or Snap Docker; filtering by domain name or content;
traffic between two filtered networks, which Docker already isolates; and
anyone with Docker API access or root on the host.

## Components

One static Go binary, `dfw`, with no third-party modules. The kernel enforces
every rule; dfw only manages one nftables table, `bridge fw`, through the
system's `nft` and `conntrack` tools.

| | `dfw init` | `dfw run` |
|---|---|---|
| **Job** | Load the base table if it is missing or damaged | Keep the table in line with the rules and Docker |
| **Started by** | `ExecStartPre=` in a `docker.service` drop-in, ordered after `nftables.service` | `dfw.service`, after `docker.service`, `Restart=always` |
| **If it fails** | Docker doesn't start | Existing rules stay; new containers stay blocked |

Because `dfw init` runs before every Docker start, at boot or on socket
activation, Docker never runs without the table. It has its own 60-second
timeout and leaves an intact table untouched, so containers keep their rules
when Docker restarts. Nothing removes the table except `dfw disable`.

The other commands are `dfw plan [FILE]` (read-only review), `dfw enable`,
`dfw apply`, `dfw disable`, `dfw active` (used by the package's `prerm`) and
`dfw version`.

## The base table

Every frame from a container enters its bridge on the container's veth, and
every frame to it leaves on that veth. Two base chains at priority −150,
after bridge conntrack (−200) and before `br_netfilter` (0), therefore see
all container traffic:

```
table bridge fw {
  set open_bridges { type ifname }          # bridges dfw leaves alone
  map out_by_port { type iface_index : verdict }
  map in_by_port  { type iface_index : verdict }

  chain from_container {
    type filter hook prerouting priority -150; policy accept;
    iif vmap @out_by_port
    iifname "veth*" meta ibrname != @open_bridges counter drop
  }
  chain to_container {
    type filter hook postrouting priority -150; policy accept;
    oif vmap @in_by_port
    oifname "veth*" meta obrname != @open_bridges counter drop
  }
}
```

A veth with no entry in the maps is dropped unless its bridge is in
`open_bridges`. That is what blocks a new container from its first packet:
Docker attaches the veth before the container runs, and nothing passes until
dfw adds the veth to the maps. A veth not yet on a bridge carries nothing
beyond the host.

The maps are keyed by interface index, not name, so a restarted container
gets a new key and can't inherit old rules. Veths of a filtered container on
an unfiltered network map to `drop`.

Because the chains run before Docker's DNAT, outbound rules see the address
the container dials. Inbound rules see the client as it arrives: external
clients of a published port keep their address, and clients through
`docker-proxy` arrive from the network gateway.

## Other networks

dfw can't tell which bridges are filtered until Docker says so, and at boot
Docker isn't running yet. So the table blocks veths on every bridge except
those in `open_bridges`, the bridges dfw knows are not filtered.

While `dfw run` is up, a new bridge named the way Docker names a network's
bridge by default (`br-` and 12 hex digits) stays blocked until Docker lists
its network, since Docker creates the bridge first. A bridge with any other
name may also be a filtered network's (with a custom
`com.docker.network.bridge.name`), so it is opened only once it has stayed
unlisted for a second, about two seconds after it appears. Bridges already
open when `dfw run` starts stay open.

`dfw run` updates the set as bridges and networks come and go, and saves it
in `/var/lib/dfw/open-bridges` with the `network` lines it was made for. At
boot, `dfw init` loads the saved bridges only if those lines match the
current rules; otherwise every bridge stays blocked until `dfw run` starts.

## Per-container chains

For each container on a filtered network, `dfw run` creates chains
`c<id>_out` and `c<id>_in` with their sets, and points the container's veths
on filtered networks at them (one veth per network, same chains).

`c<id>_out`, in order:

1. Drop anything but ARP, IPv4 and IPv6, and frames whose source MAC, IP or
   ARP sender isn't the container's own on that port.
2. Accept the container's own ARP, at most its plain size. Accept IPv6
   neighbour discovery only from its own addresses, with hop limit 255, at
   most 32 bytes (one link-layer address option), to link-local, link-local
   multicast (`ff02::/16`) or on-link destinations. So neither is routed or
   carries a payload.
3. Drop connections marked as refused (below).
4. Accept `ct state established,related`; drop anything else that isn't
   `new`.
5. Accept new connections matching the outbound allow sets.
6. Count and drop.

`c<id>_in` is the same without the source checks (it accepts any ARP and any
neighbour discovery with hop limit 255), plus a drop for IP frames
not addressed to the container, so frames the bridge floods to every port
can't reach the wrong container as "established". Its last rule marks the
connection as refused, then drops it.

Allow sets are per container and per family: addresses and ranges for any
protocol, address · protocol · port for port rules, and addresses for
`:icmp`. Container names are resolved through the Docker API, never DNS.

**Refused connections:** routed traffic to a published port is confirmed by
conntrack before the bridge drops it, so a compromised container could
otherwise answer a refused SYN and have the flow count as established. dfw
sets bit `0x40000000` of the conntrack mark on connections a container's
inbound chain refuses, and drops marked connections both ways. Each time
the table changes, it deletes the marked connections, so ones the new rules
allow can start at once; the rest are refused and marked again.

## Resolving rules

- `[name]` is every running container on the filtered networks with that
  container or compose service name, with all its filtered addresses. No
  match resolves to nothing, which `dfw plan` reports.
- Zones are computed per container. `host` is the host's own addresses plus
  the gateways of the container's filtered networks; `lan`, `rfc1918` and
  `internet` exclude it. `internet` also excludes loopback, link-local,
  multicast, 100.64.0.0/10, unroutable ranges and the IPv6 ranges that embed
  IPv4 (which could otherwise reach `lan` or `host`).
- `dns` is the container's upstream servers on port 53, taken from settings
  the host's administrator controls: the container's `dns:` option, else
  `daemon.json`, else the host's resolv.conf (and, behind a loopback stub,
  the systemd-resolved upstreams). Never the container's own resolv.conf,
  which it can write. Loopback servers are reached by Docker from the host,
  so they can't be filtered and aren't included. On Docker's default
  `bridge` network, which has no embedded resolver, Docker falls back to
  8.8.8.8 and 8.8.4.4 when no other server is left, and so does dfw.

## The `dfw run` loop

A single goroutine handles events one at a time:

1. It reads `GET /events` from `/var/run/docker.sock` (only `GET` endpoints
   are used) and coalesces bursts into one reconcile.
2. It reconciles fully at start, on reconnecting to Docker, on `SIGHUP` (sent
   by `dfw apply` through `systemctl reload`), when a bridge appears or
   disappears, every 30 seconds, and 2 seconds after a failure.
3. A reconcile reads the containers on the filtered networks, finds their
   veths, resolves the rules, renders the whole table and applies it as one
   `nft -f` transaction (`add table; delete table; table {...}`). This is
   atomic and repairs any drift.
4. It reads the table back with `nft -j list table` and compares it with what
   was intended.
5. Before a veth new to the rules is opened, the tracked connections of its
   addresses are deleted with `conntrack -D`, so a dead container's
   `established` entry can't reach a new one that reuses the IP. If that
   fails, the container stays blocked and it is retried.
6. Once the new table is in place, connections that lost their permission
   are cut. If only single peer addresses were removed, only the connections
   between the container and those addresses are cut; for anything wider,
   all the container's connections are, and allowed ones reconnect. A
   container that is gone has all its connections cut. If a cut fails, it is
   retried on every reconcile; until then the connection survives,
   and `dfw apply` keeps waiting (up to 30 s).
7. It subscribes to nftables change notifications (`NFNLGRP_NFTABLES`). If
   the table changes or disappears outside dfw, it restores it within a
   second (repairs are at most one per second), and the 30-second reconcile
   checks it too.

`nft` is called by absolute path with the ruleset on stdin. The ruleset holds
only values already parsed into typed form (addresses, prefixes, integers,
hex container IDs, interface indexes), plus the names of the bridges in
`open_bridges`, which are written only if they consist of letters, digits,
`-`, `_` and `.` (at most 15). No other text from the rules files or from
Docker is copied into it.

Veths are found through netlink namespace IDs: `RTM_GETNSID` for the
container's PID (assigning an ID with `RTM_NEWNSID` if it has none), then
`RTM_GETLINK` with `IFLA_TARGET_NETNSID` to read the container's interfaces,
matched to its endpoints by MAC, and their peer indexes on the host. dfw never enters a container's namespace, and checks
the container's identity again afterwards in case the PID was reused.

`dfw.service` runs with `CapabilityBoundingSet=CAP_NET_ADMIN` only,
`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `NoNewPrivileges=yes`,
`ProtectSystem=strict` (state in `/var/lib/dfw`), a system-call filter and
systemd's other sandboxing options.

## Which rules are in force

- A running `dfw run` never reads the rules files on its own. `dfw apply`
  validates them, refuses if any line has an error, saves them as the active
  rules in `/var/lib/dfw/rules.json`, sends `SIGHUP` to `dfw run`, and waits
  up to 30 seconds for it to confirm through `/var/lib/dfw/applied`. `dfw run`
  confirms only once the table holds the rules and every connection that lost
  its permission is cut. `dfw apply` refuses if `dfw.service` isn't running.
- When `dfw run` starts, it makes the files the active rules if they are
  valid; otherwise it logs the errors and keeps the active ones. A typo saved
  before a reboot changes nothing.
- Its first apply compares each container's sets with the table it started
  with. A container whose sets lost anything (edited rules, a peer renamed or
  readdressed while `dfw run` was down) has all its connections cut, and
  allowed ones reconnect. If the rules in force were never confirmed (an
  earlier `dfw run` or `dfw enable` stopped before its cuts were done), every
  container's are, as `dfw enable` does.

## Enabling and disabling

`dfw enable` refuses if `dfw.service` is already running (that is
`dfw apply`'s job) or if the rules have errors. Otherwise it saves them as
the active rules and does what `dfw init --live` does: it loads the base
table and every container's rules in one transaction, then deletes the
tracked connections of every filtered container, so forbidden ones are cut
and allowed ones reconnect. It then writes the `docker.service` drop-in and enables and starts
`dfw.service`.

`dfw disable` stops and disables `dfw.service`, removes the drop-in, then
deletes the table.

Image builds on a filtered network don't work: their ports have no container
behind them and stay blocked.

## Failure behaviour

| Event | Result |
|---|---|
| `dfw init` fails | Docker doesn't start |
| `dfw run` is down, or the Docker socket is unavailable | Running containers keep their rules. New containers on filtered networks, and on networks created meanwhile, stay blocked. Peer IP changes aren't picked up. `dfw run` retries |
| A ruleset is rejected | The previous table stays in force: new containers stay blocked, others keep their previous rules, including permissions being removed. Retried; `dfw apply` reports a timeout |
| Cutting connections fails | A new container stays blocked; a connection that lost its permission survives until a retry succeeds, and `dfw apply` waits for that, reporting a timeout after 30 s |
| The rules files have errors | `dfw apply` and `dfw enable` refuse; at start, the rules last applied are kept |
| Root deletes or changes the table (`nft flush ruleset`, restarting `nftables.service`) | Restored as soon as the change notification arrives; containers are unfiltered for that moment |
| A filtered container is also on an unfiltered bridge network | Its veth there maps to `drop`, unfiltered only until Docker reports the container. Logged as an error on every reconcile. On macvlan, ipvlan or overlay it can't be dropped |
| Privileged container | Filtered at its veth, but can escape to the host |

Docker reports a starting container about a second after its process starts,
and dfw can only open its allowed traffic then. Dropped TCP connection
attempts are retried after about a second.

## Package

`dfw`, for amd64 and arm64. `Depends: nftables, conntrack`,
`Recommends: docker-ce | docker.io`. It installs `/usr/sbin/dfw`,
`dfw.service`, `/etc/dfw/rules` (a conffile with commented examples) and
`/usr/lib/modules-load.d/dfw.conf` (loads `nf_conntrack_bridge`).

- **Install** activates nothing, even after a reboot.
- **Upgrade** restarts `dfw.service` only if it is running. The table stays
  in the kernel throughout, so no allowed connection drops.
- **Remove** is refused while dfw is active, since the drop-in would point at
  a missing binary.

## Tests

- `go test ./...`: rule parsing (malformed input included), zone expansion,
  range arithmetic, and generated rulesets compared with golden files and, as
  root, loaded into the real `nft`.
- `test/gate.sh`: checks the kernel and Docker behaviour dfw depends on
  (`ct state` in a bridge table, the addresses the chains see, first packets
  never escaping, DNS through the veth).
- `test/integration.sh` and `test/reboot.sh`: end-to-end behaviour, including
  every guarantee above, across reboots, upgrades and package removal.

All three scripts need root on a disposable Debian 13 machine;
`test/vm.sh` creates one.

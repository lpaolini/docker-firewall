# dfw: a firewall for the containers on chosen Docker networks

`dfw` controls which connections may go in and out of the containers on the
Docker networks you name, with rules kept in one file. The kernel enforces
every rule, in an nftables table on the ports of those networks' bridges. A new container
is blocked from its first packet until its rules are in place, and a
container that no rule mentions has no network access. Other networks are
left alone.

The requirements are in [docs/rules.md](docs/rules.md). The enforcement design,
including its threat model and the reasons behind each choice, is in
[docs/design.md](docs/design.md).

## Requirements

- Debian 13 (trixie), with Docker from Debian (`docker.io`) or Docker's own
  repository (`docker-ce`).
- A kernel with `CONFIG_NF_CONNTRACK_BRIDGE`. Debian's kernels have it.
  Amazon Linux 2023's kernel does not, so dfw can't run there.
- The filtered networks must use Docker's bridge driver.

## Install

Add the signed APT repository and install the package:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://lpaolini.github.io/docker-firewall/public.key | sudo gpg --dearmor -o /etc/apt/keyrings/dfw.gpg
echo "deb [signed-by=/etc/apt/keyrings/dfw.gpg] https://lpaolini.github.io/docker-firewall stable main" | sudo tee /etc/apt/sources.list.d/dfw.list
sudo apt update
sudo apt install dfw
```

Or download the package for your architecture from a
[GitHub release](https://github.com/lpaolini/docker-firewall/releases), check
it against the published checksums, and install it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./dfw_0.1.0_amd64.deb
```

Installing activates nothing and changes no traffic, even after a reboot.

### Development builds

Every push to the `dev` branch is published to a separate `dev` channel of
the same repository. To try it on a test host, use `dev` instead of `stable`
in the source line. Development versions look like `0.1.0+dev5.gabc1234`
(5 commits after `v0.1.0`): newer than that release, older than the next one.

## Rules

The rules are in `/etc/dfw/rules`, followed by `/etc/dfw/rules.d/*.rules` in
name order, read as one file:

```
network fw

allow [foo] -> [bar]:5432/tcp
allow [foo] -> internet
allow [foo] -> rfc1918
allow internet -> [bar]:443/tcp
allow [bar] -> 10.10.20.20
allow [bar] -> 10.10.30.0/24
```

`network` names a Docker network dfw filters; repeat it to filter several.
Containers on any of them are filtered by the same rules. Here
`foo` may reach `bar` on TCP port 5432, the internet and private IPv4
addresses, and nothing else;
`bar` accepts TCP 443 from the internet and 5432 from `foo`, and may reach
10.10.20.20 and 10.10.30.0/24. Every other container on `fw` is cut off.

Each rule is `allow SOURCE -> DESTINATION`. Either side can be a
comma-separated list, and the destination may have `:port`, `:port/proto` or
`:icmp`:

| Endpoint | Meaning |
|---|---|
| `[name]` | The running containers on the filtered networks with that container name or compose service name (all replicas, all their filtered networks' addresses). A name that matches nothing allows nothing. The brackets keep names apart from the other targets: `[internet]` is a container |
| `10.1.2.3`, `2001:db8::1` | One address. Write IPv6 in brackets when a port follows: `[2001:db8::1]:443` (brackets with a colon inside are an address, without one a container) |
| `10.0.0.0/8`, `fd00::/8` | A subnet. Host bits must be zero |
| `internet` | Everything except `lan`, `host`, loopback, link-local, multicast, 100.64.0.0/10, unroutable ranges, and the IPv6 ranges that carry IPv4 addresses (`::ffff:0:0/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`). As a destination it includes `dns` |
| `rfc1918` | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, except `host` |
| `lan` | `rfc1918` plus fc00::/7, except `host` |
| `host` | The host's own addresses and the gateways of the container's filtered networks |
| `dns` | Destination only: the container's upstream DNS servers, port 53. Taken from the container's `dns:` option, else `"dns"` in `/etc/docker/daemon.json`, else the host's resolv.conf; never from the container's own resolv.conf, which it can write |

- **One side must be a container.** A rule between two names opens the
  source's outbound and the destination's inbound at once.
- **A rule opens one direction.** Connections go from the source to the
  destination; their replies are allowed, nothing else is.
- `port` is the destination's port. With a port and no `proto`, both TCP and
  UDP apply. `:icmp` allows ICMP only (ICMPv6 to IPv6 addresses), all types,
  for example `allow [foo] -> internet:icmp` to let `foo` ping. With neither,
  every protocol applies, including ICMP.
- **Sources are addresses as they arrive.** External clients of a published
  port keep their real address, so `allow internet -> [bar]:443/tcp` works for
  them. Clients through `docker-proxy` (`127.0.0.1` publishes, IPv6 clients)
  arrive from the network gateway and match `host`. Reaching another
  container through the host's published port is not supported: use its name.
- **Edits take effect with `dfw apply`.** Saving the files changes nothing on
  a running system. `sudo dfw apply` checks them, refuses if they have any
  error, and otherwise applies them at once, cutting connections that lost
  their permission; it returns when dfw has confirmed. No container needs
  recreating. `dfw plan` notes when the files differ from the rules applied.
- **At start, valid rules are applied.** When `dfw.service` starts (at boot,
  or after a restart or an upgrade), it applies the files if they are valid.
  If they have errors, it logs them and keeps using the rules last applied,
  which it saves in `/var/lib/dfw/rules.json`.
- The EC2 metadata service is link-local, so it is reachable only if listed:
  `allow [foo] -> 169.254.169.254:80/tcp`.

## Turning it on

Loading the table immediately cuts off every container on the networks that
no rule mentions, so review first:

1. Create the networks, if they don't exist, and attach the containers.
2. Write `/etc/dfw/rules`. Check a draft with `sudo dfw plan FILE`. The
   installed file has commented examples.
3. Run `sudo dfw plan`. It shows the errors in the rules, each container on
   the filtered networks with its rules, names that match no container, and
   containers that are also on unfiltered networks.
4. Run `sudo dfw enable`. It refuses if the rules have errors. It loads the
   base table and every container's rules in one
   transaction, cuts the containers' tracked connections so that only allowed
   ones come back (expect a brief interruption), installs a `docker.service`
   drop-in that loads the base table before Docker starts, and starts
   `dfw.service`.

After that, edit the files and run `sudo dfw apply` (`dfw enable` does the
same once dfw is running).

`dfw disable` stops the service, removes the drop-in and deletes the table.
It is the only command that opens the containers.

## Operation

- `journalctl -u dfw` shows errors (on every reconcile, for anything left
  unprotected or not as configured) and warnings (once, when they first
  appear).
- dfw sets bit `0x40000000` of the conntrack mark on connections a
  container's inbound rules refuse, and drops marked connections both ways.
  Don't use that bit for anything else.
- `sudo nft list table bridge fw` shows the rules. Each container has chains
  `c<id>_out` and `c<id>_in`, and the last rule of each counts its drops. The
  set `open_bridges` lists the bridges dfw leaves alone.
- If `dfw.service` stops, containers keep their rules and new containers on
  the filtered networks stay blocked until it is back.
- If something deletes or changes the table (`nft flush ruleset`, a restart
  of `nftables.service`), dfw is notified by the kernel and restores it at
  once, in one transaction.

### Several networks

Each `network` line adds a network; every container on any of them gets the
rules that name it, on each of its filtered networks. Traffic between two
filtered networks needs a rule like any other, but dfw doesn't add a
firewall between networks: Docker isolates its bridge networks from each
other, and dfw leaves that as it is. So `allow [a] -> [b]` with `a` and `b`
on different networks allows nothing in practice; attach them to a common
filtered network.

### How the other networks are left alone

dfw can't know which bridges belong to the filtered networks until Docker
tells it, and at boot Docker isn't running yet. So dfw works the other way
round: a veth on any bridge is blocked unless dfw knows that bridge is not a
filtered network's, and lists it in `open_bridges`. dfw keeps that list up to
date as bridges and networks come and go, and records it in
`/var/lib/dfw/open-bridges` so that the table loaded at boot leaves the same
bridges open. In practice:

- A network created while dfw runs is opened within moments of its creation.
- While `dfw.service` is down, containers on a newly created network are
  blocked until it is back.
- If the record is missing, or was made for other `network` lines, every
  bridge stays blocked at boot until `dfw.service` starts.

## Limitations

- **A container on a filtered network and an unfiltered one** has all its
  traffic on the unfiltered network dropped once dfw sees it, and dfw logs an
  error on every reconcile. In the second or so after it starts, before
  Docker reports it, its traffic there is not filtered. Keep filtered
  containers on filtered networks only. On a macvlan, ipvlan or
  overlay network, dfw can't drop it at all.
- **Privileged containers** are filtered at their veth but can escape to the
  host.
- **DNS through a host resolver.** When the host uses a loopback resolver such
  as systemd-resolved, Docker sends containers' lookups from the host, where
  they can't be filtered. A container without `internet` could then tunnel
  data out through DNS. Configure a non-loopback upstream (for example
  `dns:` in compose or `"dns"` in `daemon.json`) to close this. `dfw` warns
  about each container affected.
- **Start-up delay:** a container's allowed traffic opens shortly after it
  starts: dfw can only act once Docker reports the container as running,
  which Docker does up to about a second after its process starts. Dropped
  TCP connection attempts are retried automatically after about a second;
  apps with short timeouts or no retry must handle this themselves.
- Root on the host can always change the table; dfw repairs it, but the
  containers are unfiltered for that moment.
- Anyone with access to the Docker API can attach containers to the networks
  or name them as a rule expects. They already control the host.

## Uninstall

```sh
sudo dfw disable
sudo apt remove dfw
```

Removal is refused while dfw is active.

## Development

There are no third-party Go modules. Unit tests:

```sh
go test ./...
```

`test/gate.sh` is the gate test from the design, `test/integration.sh` the
acceptance tests and `test/reboot.sh` the reboot scenarios. They need root on
a disposable Debian 13 machine with Docker, because they change the kernel's
ruleset. `test/vm.sh up docker-ce` (or `docker.io`) creates one in QEMU, in a
container, so you never run them against a real host's kernel. Results are in
[docs/gate-results.md](docs/gate-results.md). Build the package with
`dpkg-buildpackage -b -us -uc` (add `-a arm64 -d` to cross-build).

## License

MIT. See [LICENSE](LICENSE).

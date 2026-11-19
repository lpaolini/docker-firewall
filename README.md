![dfw](docs/images/teaser.png)

# `dfw` — No fuss. No nonsense. No exceptions.

*An MIT-licensed Docker firewall that quietly gets the job done.*

Docker containers on a bridge network are, by default, free to talk to each
other and to reach any destination outside.

`dfw` lets you control which inbound and outbound connections each container
may establish, using simple firewall rules. Only the networks named in the
rules are filtered; all others keep Docker's default behaviour.

The kernel enforces the rules, in an nftables table on the networks' bridge
ports. A new container is blocked from its first packet until its rules are
in place, and a container that no rule mentions has no network access.

[docs/how-it-works.md](docs/how-it-works.md) explains the mechanism.

## Requirements

To run:

- Debian 13 (trixie), amd64 or arm64.
- Docker from Debian (`docker.io`) or from Docker (`docker-ce`). Filtered
  networks must use the bridge driver.
- A kernel with `CONFIG_NF_CONNTRACK_BRIDGE` and `CONFIG_NFT_BRIDGE_META`
  (Debian's has both).
- `nftables` and `conntrack`, installed as package dependencies.

To build:

- Go 1.24 or later (`golang-go` in Debian 13). Standard library only.
- `debhelper`, for the Debian package.

## Install

From the signed APT repository:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://lpaolini.github.io/apt/public.key | sudo gpg --dearmor -o /etc/apt/keyrings/lpaolini.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/lpaolini.gpg] https://lpaolini.github.io/apt stable main" | sudo tee /etc/apt/sources.list.d/lpaolini.list
sudo apt update
sudo apt install dfw
```

Or from a [GitHub release](https://github.com/lpaolini/docker-firewall/releases):

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./dfw_0.1.4_amd64.deb
```

Installing changes no traffic, even after a reboot, until you run
`dfw enable`.

### Development builds

Every push to the `dev` branch is published to the repository's `dev`
channel. To use it on a test host:

```sh
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/lpaolini.gpg] https://lpaolini.github.io/apt dev main" | sudo tee /etc/apt/sources.list.d/lpaolini-dev.list
sudo apt update && sudo apt upgrade
```

Versions look like `0.1.0+dev5.gabc1234`: 5 commits after `v0.1.0`, so newer
than that release and older than the next. To return to stable, delete
`lpaolini-dev.list`, run `sudo apt update`, and install the stable version
explicitly, for example `sudo apt install dfw=0.1.4` (apt never downgrades
on its own).

## Rules

dfw reads `/etc/dfw/rules`, then `/etc/dfw/rules.d/*.rules` in name order, as
one file. `#` starts a comment that runs to the end of the line, on a line of
its own or after a rule:

```
network web

allow internet -> [reverse-proxy]:80/tcp, [reverse-proxy]:443/tcp
allow [reverse-proxy] -> [web-server]:8080/tcp, [api-gateway]:3000/tcp
allow [reverse-proxy] -> internet:443/tcp, dns   # renew TLS certificates
allow [api-gateway] -> [database]:5432/tcp
allow [api-gateway] -> 10.10.20.20:8443/tcp      # a payment service on the LAN
allow 10.10.30.0/24 -> [database]:5432/tcp       # admins on the office subnet
```

`network` names a Docker network to filter; repeat it for several. The same
rules apply to containers on all of them. Here:

- Only `reverse-proxy` takes connections from the internet, on TCP 80 and
  443. It forwards them to `web-server` and `api-gateway`, and may reach
  HTTPS servers on the internet and look up names, to renew its
  certificates.
- `api-gateway` takes requests from `reverse-proxy` only. It may query
  `database` and call one service on the LAN, 10.10.20.20, on TCP 8443.
- `database` takes connections from `api-gateway` and from the office subnet
  10.10.30.0/24, on TCP 5432.
- `web-server` and `database` can't open any connection: no rule has them
  as a source.

Every other container on `web` is cut off.

Each rule is `allow SOURCE -> DESTINATION`. Either side may be a
comma-separated list. The destination may end in `:port`, `:port/tcp`,
`:port/udp` or `:icmp`.

| Endpoint | Meaning |
|---|---|
| `[name]` | Running containers on the filtered networks with that container or compose service name: all replicas, all their filtered addresses. A name that matches nothing allows nothing. `[internet]` is a container, not the zone. A service name counts only on containers named the way Compose names them, `<project>-<service>-<N>` (see [how it works](docs/how-it-works.md#resolving-rules)) |
| `10.1.2.3`, `2001:db8::1` | One address. Bracket IPv6 before a port: `[2001:db8::1]:443` |
| `10.0.0.0/8`, `fd00::/8` | A subnet, with host bits zero |
| `10.0.0.5-10.0.0.20`, `fd00::1-fd00::ff` | An inclusive range of one family. Bracket IPv6 before a port: `[fd00::1-fd00::ff]:443`. A range must lie wholly inside or wholly outside each private and special block (those of `lan` and the ones `internet` leaves out), so `9.255.255.0-10.0.0.5` is refused: split it at the edge |
| `internet` | Everything except `lan`, `host`, loopback, link-local, multicast, 100.64.0.0/10, unroutable ranges and IPv6 ranges that embed IPv4 (`::ffff:0:0/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`). As a destination it includes `dns` |
| `rfc1918` | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, except `host` |
| `lan` | `rfc1918` plus fc00::/7, except `host` |
| `host` | The host's own addresses and the gateways of the container's filtered networks |
| `any` | Every IPv4 and IPv6 address: all the zones above and the ranges `internet` leaves out. `allow [foo] -> any` gives `foo` the outbound access it has without dfw |
| `dns` | Destination only, no port: the container's upstream DNS servers on port 53, from its `dns:` option, else `"dns"` in `/etc/docker/daemon.json`, else the host's resolv.conf (never the container's own) |

- **One side must be a container.** A rule between two containers opens the
  source's outbound and the destination's inbound.
- **Rules are one-way.** Connections go from source to destination; only
  their replies come back.
- **Ports are destination ports.** A port without a protocol means TCP and
  UDP. `:icmp` means ping: ICMP echo requests (ICMPv6 for IPv6), so
  `allow [foo] -> internet:icmp` lets `foo` ping. ICMP errors about an
  allowed connection, such as "fragmentation needed", always pass. No port
  means every protocol, all ICMP included.
- **Sources are matched as they arrive.** External clients of a published
  port keep their address, so `allow internet -> [bar]:443/tcp` works.
  Clients through `docker-proxy` (`127.0.0.1` publishes, IPv6 clients) arrive
  from the gateway and match `host`. To reach another container, use its
  name, not the host's published port.
- **Edits need `sudo dfw apply`.** It refuses rules with errors; otherwise it
  applies them at once and cuts connections that lost permission. It returns
  once dfw confirms both, or fails after 30 seconds (see `journalctl -u dfw`).
  No container is recreated. `dfw check` says when the files differ from the
  applied rules.
- **At start, `dfw.service` applies the files if they are valid**, and cuts
  the connections of containers that lost a permission, by edited rules or
  by Docker changes made while it was down, so only allowed ones resume.
  Otherwise it logs the errors and keeps the last applied rules,
  saved in `/var/lib/dfw/rules.json`.
- The EC2 metadata service is link-local, so it needs its own rule:
  `allow [foo] -> 169.254.169.254:80/tcp`.

## Turning it on

Enabling immediately cuts off every container on the filtered networks that
no rule mentions, so review first:

1. Create the networks and attach the containers.
2. Write `/etc/dfw/rules` (the installed file has commented examples). Check
   a draft with `sudo dfw check FILE`.
3. Run `sudo dfw check`. It lists rule errors, kernel modules dfw needs but
   can't find, each container with its rules, names that match no
   container, containers also on unfiltered networks, and bridges it will
   block because a filtered network doesn't exist yet.
4. Run `sudo dfw enable`. It refuses rules with errors, or a kernel without
   the modules dfw needs. Otherwise it loads the table with every
   container's rules in one transaction, cuts tracked connections so only
   allowed ones resume (a brief interruption), installs a `docker.service`
   drop-in that loads the base table before Docker starts, and starts
   `dfw.service`.

From then on, edit the files and run `sudo dfw apply`; `dfw enable` refuses
while dfw is running. `sudo dfw disable`
stops the service, removes the drop-in and deletes the table; it is the only
command that opens the containers.

## Operation

- `journalctl -u dfw` shows errors (repeated on every reconcile while they
  last) and warnings (logged once).
- `sudo nft list table bridge fw` shows the table. Each container has chains
  `c<id>_out` and `c<id>_in`, whose last rule counts drops. The set
  `open_bridges` lists the bridges dfw leaves alone.
- dfw uses bit `0x40000000` of the conntrack mark for connections refused by
  a container's inbound rules. Don't use it for anything else.
- If `dfw.service` stops, containers keep their rules, and new containers on
  filtered networks stay blocked until it is back.
- If the table is deleted or changed (`nft flush ruleset`, restarting
  `nftables.service`), the kernel notifies dfw, which restores it at once.

### Multiple networks

A container gets its rules on each filtered network it is on. dfw adds no
firewall between networks: Docker already isolates bridge networks from each
other. So `allow [a] -> [b]`, with `a` and `b` on different networks, allows
nothing in practice; put them on a common filtered network.

### Network settings

dfw reads each container's addresses from Docker, so a filtered bridge
network's addressing doesn't matter: custom subnets, `--ip-range`,
`--gateway`, `--aux-address`, fixed `--ip`, IPv6 and IPv6-only
(`--ipv4=false`) networks all work, whatever IPAM driver assigned the
addresses. `host` includes the network's gateway, wherever it is.

With `com.docker.network.bridge.gateway_mode_ipv4=routed` (or `_ipv6`, or
`nat-unprotected`), clients reach containers at their own addresses, without
NAT. dfw filters that traffic like any other, and sees the client's real
address.

A container that uses another's network (`--network container:NAME`, or
`network_mode: service:NAME` in compose) has no network of its own: its
traffic gets the rules of the container whose network it uses, and rules
naming it match nothing. `dfw check` says which container to name instead.

### How other networks are left alone

At boot, Docker isn't running yet, so dfw can't tell which bridges belong to
filtered networks. It therefore blocks veths on every bridge except those in
`open_bridges`: bridges it knows are not filtered. It keeps that set current
as networks come and go, and saves it in `/var/lib/dfw/open-bridges` so the
table loaded at boot opens the same bridges. As a result:

- A network created while dfw runs is opened within moments. A bridge Docker
  doesn't list (libvirt, LXC) is opened only while every `network` line names
  an existing network; until then it stays blocked and dfw logs a warning.
- While `dfw.service` is down, containers on a newly created network are
  blocked until it is back.
- If the saved set is missing, or was made for other `network` lines, every
  bridge stays blocked at boot until `dfw.service` starts.

## Limitations

- **Containers on both a filtered and an unfiltered network** have their
  traffic on the unfiltered one dropped once dfw sees them, and dfw logs an
  error. In the second or so before Docker reports them, that traffic is not
  filtered. On a macvlan, ipvlan or overlay network, dfw can't drop it at
  all. Keep filtered containers on filtered networks only.
- **Privileged containers** are filtered at their veth but can escape to the
  host.
- **DNS through a loopback host resolver** (such as systemd-resolved) is
  sent by Docker from the host, where dfw can't filter it, so a container
  without `internet` could tunnel data out through DNS. Set a non-loopback
  upstream (`dns:` in compose or `"dns"` in `daemon.json`). dfw warns about
  each affected container.
- **Start-up delay.** A container's allowed traffic opens only once Docker
  reports it running, up to about a second after its process starts. TCP
  retries a dropped connection after about a second; apps with short
  timeouts or no retry must cope on their own.
- Root on the host can change the table. dfw repairs it, but containers are
  unfiltered for that moment.
- Anyone with Docker API access can attach containers to the networks or give
  them the names rules expect. They already control the host.

## Uninstall

```sh
sudo dfw disable
sudo apt remove dfw
```

Removal is refused while dfw is active.

## Development

```sh
go test ./...
```

`test/gate.sh` checks the kernel and Docker behaviour dfw relies on,
`test/integration.sh` runs the acceptance tests and `test/reboot.sh` the
reboot scenarios. They change the kernel's ruleset, so they need root on a
disposable Debian 13 machine with Docker: `test/vm.sh up docker-ce` (or
`docker.io`) creates one in QEMU, inside a container.

Build the package with `dpkg-buildpackage -b -us -uc` (add `-a arm64 -d` to
cross-build).

## License

MIT. See [LICENSE](LICENSE).

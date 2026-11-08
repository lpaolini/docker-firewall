package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"dfw/internal/docker"
	"dfw/internal/netlink"
	"dfw/internal/nft"
	"dfw/internal/rules"
)

// ctr is a running container on the filtered networks, as dfw sees it.
type ctr struct {
	info     *docker.Container
	name     string
	service  string // compose service, if any
	in, out  []rules.Entry
	ports    []nft.Port // its veths on the filtered networks
	blocked  []int      // its veths on other networks, always dropped
	addrs    []netip.Addr
	gateways []netip.Addr
	dns      []netip.Addr
	errors   []string // things that leave it unprotected or not as configured
	warnings []string
}

// world is one snapshot of everything rules depend on.
type world struct {
	cfg       rules.Config
	bridges   map[string]string // filtered network -> its bridge device, for those that exist
	open      []string
	ctrs      []*ctr
	hostAddrs []netip.Addr
	links     []netlink.Link
	unknown   []netlink.Link // ports of filtered bridges with no container behind them
	problems  []string       // containers or networks that couldn't be handled
}

// gather reads Docker and the kernel. It fails only if they can't be read.
func gather(ctx context.Context, dc *docker.Client, cfg rules.Config) (*world, error) {
	nets, err := dc.Networks(ctx)
	if err != nil {
		return nil, err
	}
	w := &world{cfg: cfg}
	var ids []string
	if slices.ContainsFunc(nets, func(n docker.Network) bool { return slices.Contains(cfg.Networks, n.Name) }) {
		if ids, err = dc.Running(ctx, cfg.Networks); err != nil {
			return nil, err
		}
	}
	// After the container list, so it holds every listed container's veths.
	if w.links, err = netlink.Links(-1); err != nil {
		return nil, err
	}
	fwIndex, drivers := w.classify(nets)
	if w.hostAddrs, err = hostAddrs(); err != nil {
		return nil, err
	}
	var daemon struct{ DNS []string }
	if b, err := os.ReadFile(daemonJSON); err == nil && json.Unmarshal(b, &daemon) != nil {
		daemon.DNS = nil
	}
	for _, id := range ids {
		c, err := w.container(ctx, dc, id, drivers, daemon.DNS)
		if err != nil {
			var se *docker.StatusError
			if !errors.As(err, &se) || se.Code != 404 { // 404: gone since the list
				// Leave it out: it stays blocked, and peers don't see it.
				w.problems = append(w.problems, fmt.Sprintf("container %.12s can't be read, so it stays blocked: %v", id, err))
			}
			continue
		}
		if c != nil {
			w.ctrs = append(w.ctrs, c)
		}
	}
	slices.SortFunc(w.ctrs, func(a, b *ctr) int { return strings.Compare(a.info.ID, b.info.ID) })
	mapped := map[int]bool{}
	for _, c := range w.ctrs {
		for _, p := range c.ports {
			mapped[p.Ifindex] = true
		}
	}
	for _, l := range w.links {
		if l.Kind == "veth" && fwIndex[l.Master] && !mapped[l.Index] {
			w.unknown = append(w.unknown, l)
		}
	}
	return w, nil
}

// classify records the filtered networks' bridges and sorts the host's
// bridges: it returns the indexes of the filtered networks' bridges, and puts
// those to leave alone in w.open. It also returns the drivers by network ID.
func (w *world) classify(nets []docker.Network) (fwIndex map[int]bool, drivers map[string]string) {
	w.bridges, drivers = map[string]string{}, map[string]string{}
	fw, listed := map[string]bool{}, map[string]bool{}
	for _, n := range nets {
		drivers[n.ID] = n.Driver
		filtered := slices.Contains(w.cfg.Networks, n.Name)
		if n.Driver != "bridge" {
			if filtered {
				w.problems = append(w.problems, fmt.Sprintf("network %s uses the %s driver; dfw can filter only bridge networks", n.Name, n.Driver))
				w.bridges[n.Name] = ""
			}
			continue
		}
		b := n.Options["com.docker.network.bridge.name"]
		if b == "" && len(n.ID) >= 12 {
			b = "br-" + n.ID[:12]
		}
		if filtered {
			w.bridges[n.Name], fw[b] = b, true
		} else {
			listed[b] = true
		}
	}
	fwIndex = map[int]bool{}
	for _, l := range w.links {
		switch {
		case l.Kind != "bridge":
		case fw[l.Name]:
			fwIndex[l.Index] = true
		case !listed[l.Name] && dockerBridge(l.Name):
			// Docker creates a network's bridge before it lists the network,
			// which may be a filtered one: keep it blocked until it is listed.
			// shortcut: a filtered network with a custom bridge.name is still
			// opened in that moment; if needed, open unlisted bridges only once
			// a second reconcile still sees them unlisted.
		case nft.ValidIfname(l.Name):
			w.open = append(w.open, l.Name)
		default:
			w.problems = append(w.problems, fmt.Sprintf("bridge %q has a name dfw can't write into rules, so its veths stay blocked", l.Name))
		}
	}
	slices.Sort(w.open)
	w.open = slices.Compact(w.open)
	return fwIndex, drivers
}

// dockerBridge reports whether name is the bridge name Docker gives a network
// by default: br- and the start of its ID.
func dockerBridge(name string) bool {
	id, ok := strings.CutPrefix(name, "br-")
	_, err := hex.DecodeString(id)
	return ok && len(id) == 12 && err == nil
}

// missing returns the filtered networks that don't exist.
func (w *world) missing() []string {
	var out []string
	for _, n := range w.cfg.Networks {
		if _, ok := w.bridges[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}

func (w *world) container(ctx context.Context, dc *docker.Client, id string, drivers map[string]string, daemonDNS []string) (*ctr, error) {
	cfg := w.cfg
	info, err := dc.Inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	var filtered, others []string
	for name := range info.NetworkSettings.Networks {
		if slices.Contains(cfg.Networks, name) {
			filtered = append(filtered, name)
		} else {
			others = append(others, name) // reported below
		}
	}
	if !info.State.Running || !nft.ValidID(info.ID) || len(filtered) == 0 {
		return nil, nil
	}
	slices.Sort(filtered)
	slices.Sort(others)
	c := &ctr{info: info, name: strings.TrimPrefix(info.Name, "/"), service: info.Config.Labels["com.docker.compose.service"]}
	c.in, c.out = cfg.For(c.name, c.service)
	if info.HostConfig.Privileged {
		c.warnings = append(c.warnings, "is privileged: filtered at its veth, but it can escape to the host")
	}
	for _, n := range filtered {
		ep := info.NetworkSettings.Networks[n]
		for _, s := range []string{ep.IPAddress, ep.GlobalIPv6Address} {
			if a, err := netip.ParseAddr(s); err == nil {
				c.addrs = append(c.addrs, a)
			}
		}
		for _, s := range []string{ep.Gateway, ep.IPv6Gateway} {
			if a, err := netip.ParseAddr(s); err == nil {
				c.gateways = append(c.gateways, a)
			}
		}
	}

	ports, err := findPorts(info, append(slices.Clone(filtered), others...), w.links)
	if err != nil {
		c.errors = append(c.errors, "can't find its veths, so it stays blocked: "+err.Error())
	}
	for _, n := range filtered {
		if p, ok := ports[n]; ok {
			c.ports = append(c.ports, p)
		} else if err == nil {
			c.errors = append(c.errors, "no veth found on network "+n+", so it stays blocked there")
		}
	}
	for _, n := range others {
		d := drivers[info.NetworkSettings.Networks[n].NetworkID]
		switch p, ok := ports[n]; {
		case d != "bridge":
			c.errors = append(c.errors, fmt.Sprintf("is also on network %s (%s driver), which dfw can't filter: NOT FILTERED there", n, d))
		case ok:
			c.blocked = append(c.blocked, p.Ifindex)
			c.errors = append(c.errors, fmt.Sprintf("is also on network %s, which dfw doesn't filter: all its traffic there is dropped", n))
		case err == nil:
			c.errors = append(c.errors, fmt.Sprintf("is also on network %s, but its veth there wasn't found: NOT FILTERED there", n))
		}
	}
	if len(c.ports)+len(c.blocked) > 0 {
		if again, err := dc.Inspect(ctx, id); err != nil || !again.State.Running ||
			again.State.Pid != info.State.Pid || again.State.StartedAt != info.State.StartedAt {
			return nil, nil // it stopped or restarted meanwhile; the next event covers it
		}
	}
	var viaHost []string
	c.dns, viaHost = upstreamDNS(info, daemonDNS)
	if len(viaHost) > 0 && len(c.out) > 0 {
		c.warnings = append(c.warnings, "DNS lookups go through the host's resolver "+strings.Join(viaHost, ", ")+" and can't be filtered")
	}
	if len(c.dns) == 0 && usesDNS(c.out) {
		c.warnings = append(c.warnings, "the dns target has no upstream servers that can be filtered, so it allows nothing")
	}
	if len(c.in)+len(c.out) == 0 {
		c.warnings = append(c.warnings, "no rule mentions it: no network access")
	}
	return c, nil
}

// findPorts finds the host side of the container's veth on each network, by
// MAC, without entering its namespace: the host reads the container's links
// through the namespace ID it already uses for the veth peers.
func findPorts(info *docker.Container, networks []string, host []netlink.Link) (map[string]nft.Port, error) {
	nsid, err := netlink.NsidOfPid(info.State.Pid)
	if err != nil {
		return nil, err
	}
	inside, err := netlink.Links(nsid)
	if err != nil {
		return nil, err
	}
	byIndex := map[int]netlink.Link{}
	for _, l := range host {
		byIndex[l.Index] = l
	}
	ports := map[string]nft.Port{}
	for _, name := range networks {
		ep := info.NetworkSettings.Networks[name]
		mac, err := net.ParseMAC(ep.MacAddress)
		if err != nil {
			continue
		}
		for _, l := range inside {
			if l.Kind != "veth" || !bytes.Equal(l.MAC, mac) {
				continue
			}
			h, ok := byIndex[l.Peer]
			if !ok || h.Kind != "veth" || h.Master == 0 || h.PeerNetns != nsid || h.Peer != l.Index {
				continue
			}
			p := nft.Port{Ifindex: h.Index, MAC: mac}
			p.IPv4, _ = netip.ParseAddr(ep.IPAddress)
			if a, err := netip.ParseAddr(ep.GlobalIPv6Address); err == nil {
				p.IPv6 = a
				p.Subnet6, _ = a.Prefix(ep.GlobalIPv6PrefixLen)
			}
			ports[name] = p
		}
	}
	return ports, nil
}

// upstreamDNS returns the servers a container's lookups go to through its
// own veth, and those Docker reaches from the host instead. It reads only
// what the host's administrator controls, never the container's resolv.conf,
// which the container can write. Like Docker, it takes the container's --dns
// option, else daemon.json's "dns" (daemonDNS), else the host's resolv.conf
// (and the systemd-resolved upstreams behind a loopback stub).
func upstreamDNS(info *docker.Container, daemonDNS []string) (direct []netip.Addr, viaHost []string) {
	servers := info.HostConfig.DNS
	if len(servers) == 0 {
		servers = daemonDNS
	}
	if len(servers) == 0 {
		servers = nameservers(hostResolvConf)
		for _, s := range servers {
			if a, err := netip.ParseAddr(s); err == nil && a.IsLoopback() {
				servers = append(servers, nameservers(resolvedConf)...)
				break
			}
		}
	}
	for _, s := range servers {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
		case a.IsLoopback():
			viaHost = append(viaHost, s)
		default:
			direct = append(direct, a.WithZone(""))
		}
	}
	if _, ok := info.NetworkSettings.Networks["bridge"]; ok {
		// The default bridge has no embedded resolver: Docker drops loopback
		// servers and falls back to Google's when none are left.
		viaHost = nil
		if len(direct) == 0 {
			direct = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}
		}
	}
	return direct, viaHost
}

var (
	daemonJSON     = "/etc/docker/daemon.json"
	hostResolvConf = "/etc/resolv.conf"
	resolvedConf   = "/run/systemd/resolve/resolv.conf"
)

func nameservers(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

func usesDNS(es []rules.Entry) bool {
	for _, e := range es {
		if e.Zone == rules.ZoneDNS {
			return true
		}
	}
	return false
}

func hostAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("host addresses: %w", err)
	}
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && !ip.Unmap().IsLoopback() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// ruleset resolves every container's rules into table contents.
func (w *world) ruleset() nft.Ruleset {
	var peers []rules.Peer
	for _, c := range w.ctrs {
		peers = append(peers, rules.Peer{Name: c.name, Service: c.service, Addrs: c.addrs})
	}
	rs := nft.Ruleset{Open: w.open}
	for _, c := range w.ctrs {
		rs.Blocked = append(rs.Blocked, c.blocked...)
		if len(c.ports) == 0 {
			continue
		}
		env := rules.Env{Peers: peers, HostAddrs: w.hostAddrs, Gateways: c.gateways, DNS: c.dns}
		rs.Containers = append(rs.Containers, nft.Container{
			ID: c.info.ID, Ports: c.ports,
			In: rules.Resolve(c.in, env, false), Out: rules.Resolve(c.out, env, true),
		})
	}
	return rs
}

// unmatched returns the names in the rules that match no running container
// on the filtered networks, with where each is first used.
func (w *world) unmatched() []string {
	var out []string
	for name, pos := range w.cfg.Names() {
		found := false
		for _, c := range w.ctrs {
			if name == c.name || name == c.service {
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: [%s] matches no running container on the filtered networks", pos, name))
		}
	}
	slices.Sort(out)
	return out
}

// ifnames maps interface names to indexes, to read nft's listings.
func ifnames(links []netlink.Link) map[string]int {
	m := map[string]int{}
	for _, l := range links {
		m[l.Name] = l.Index
	}
	return m
}

package rules

import (
	"net/netip"
	"slices"
)

// Peer is a running container on the filtered networks, that names in rules
// can refer to.
type Peer struct {
	Name, Service string
	Addrs         []netip.Addr // on the filtered networks
}

// Env is what resolving one container's rules depends on.
type Env struct {
	Peers     []Peer       // all running containers on the filtered networks
	HostAddrs []netip.Addr // the host's own addresses
	Gateways  []netip.Addr // gateways of the container's filtered networks
	DNS       []netip.Addr // the container's upstream DNS servers
}

// PortKey is a protocol and port.
type PortKey struct {
	Proto uint8
	Port  uint16
}

// Allow is a resolved allow-list. Addresses are normalized ranges, IPv4 first.
type Allow struct {
	Any   []Range             // every protocol and port
	Ports map[PortKey][]Range // one protocol and port
	ICMP  []Range             // ICMP (to IPv4) and ICMPv6 (to IPv6)
}

// Fixed zone contents (design.md, section 5.1).
var (
	lanRanges     = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
	rfc1918Ranges = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	// Never part of internet. Beyond the design's list this adds 0.0.0.0/8,
	// 240.0.0.0/4 (with broadcast) and ::/96, which are not routable, and the
	// IPv6 ranges that carry IPv4 addresses (mapped, NAT64, 6to4), through
	// which internet could reach lan or host addresses.
	notInternet = prefixes("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10",
		"224.0.0.0/4", "ff00::/8", "100.64.0.0/10", "0.0.0.0/8", "240.0.0.0/4",
		"::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16")
	everything = prefixes("0.0.0.0/0", "::/0")
)

func prefixes(ss ...string) []Range {
	var rs []Range
	for _, s := range ss {
		rs = append(rs, PrefixRange(netip.MustParsePrefix(s)))
	}
	return Normalize(rs)
}

func addrs(as []netip.Addr) []Range {
	var rs []Range
	for _, a := range as {
		if a.IsValid() {
			rs = append(rs, AddrRange(a.Unmap()))
		}
	}
	return Normalize(rs)
}

// Zone returns the ranges of a zone other than dns.
func Zone(zone string, env Env) []Range {
	host := addrs(append(slices.Clone(env.HostAddrs), env.Gateways...))
	switch zone {
	case ZoneHost:
		return host
	case ZoneLAN:
		return Subtract(lanRanges, host)
	case ZoneRFC1918:
		return Subtract(rfc1918Ranges, host)
	case ZoneInternet:
		return Subtract(everything, append(append(slices.Clone(lanRanges), notInternet...), host...))
	}
	return nil
}

// Resolve turns entries into an allow-list: destinations when out is true,
// sources otherwise. Names with no running match resolve to nothing.
func Resolve(entries []Entry, env Env, out bool) Allow {
	a := Allow{Ports: map[PortKey][]Range{}}
	add := func(rs []Range, port uint16, protos []uint8) {
		switch {
		case len(protos) == 0:
			a.Any = append(a.Any, rs...)
			return
		case protos[0] == ICMP:
			a.ICMP = append(a.ICMP, rs...)
			return
		}
		for _, p := range protos {
			k := PortKey{p, port}
			a.Ports[k] = append(a.Ports[k], rs...)
		}
	}
	dns := addrs(env.DNS)
	for _, e := range entries {
		switch {
		case e.Prefix.IsValid():
			add([]Range{PrefixRange(e.Prefix)}, e.Port, e.Protos)
		case e.Zone == ZoneDNS:
			add(dns, 53, []uint8{TCP, UDP})
		case e.Zone != "":
			add(Zone(e.Zone, env), e.Port, e.Protos)
			// internet includes dns: the container gains nothing from it.
			if out && e.Zone == ZoneInternet && (len(e.Protos) == 0 || e.Port == 53) {
				protos := e.Protos
				if len(protos) == 0 {
					protos = []uint8{TCP, UDP}
				}
				add(dns, 53, protos)
			}
		default:
			add(addrs(peerAddrs(e.Name, env)), e.Port, e.Protos)
		}
	}
	a.Any = Normalize(a.Any)
	a.ICMP = Subtract(a.ICMP, a.Any) // normalizes too
	for k, rs := range a.Ports {
		// A port rule inside an address-only rule adds nothing.
		if rs = Subtract(rs, a.Any); len(rs) > 0 {
			a.Ports[k] = rs
		} else {
			delete(a.Ports, k)
		}
	}
	return a
}

// peerAddrs finds the containers with that name or compose service. All
// replicas count.
func peerAddrs(name string, env Env) []netip.Addr {
	var out []netip.Addr
	for _, p := range env.Peers {
		if p.Name == name || p.Service == name {
			out = append(out, p.Addrs...)
		}
	}
	return out
}

// Removed returns the addresses that old allowed and new doesn't, for any
// protocol or port. Used to cut connections that lost their permission.
func Removed(old, new Allow) []Range {
	var lost []Range
	lost = append(lost, Subtract(old.Any, new.Any)...)
	lost = append(lost, Subtract(old.ICMP, append(slices.Clone(new.Any), new.ICMP...))...)
	for k, rs := range old.Ports {
		lost = append(lost, Subtract(rs, append(slices.Clone(new.Any), new.Ports[k]...))...)
	}
	return Normalize(lost)
}

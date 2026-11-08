// Package rules parses dfw's rules files and resolves them into address sets.
package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Zones.
const (
	ZoneInternet = "internet"
	ZoneLAN      = "lan"
	ZoneHost     = "host"
	ZoneDNS      = "dns"
	ZoneRFC1918  = "rfc1918"
)

// Protocols. ICMP stands for ICMP to IPv4 addresses and ICMPv6 to IPv6 ones.
const (
	ICMP uint8 = 1
	TCP  uint8 = 6
	UDP  uint8 = 17
)

// Entry is one endpoint of an allow rule: target[:port[/proto]]. A target
// is a zone, an address or subnet (IPv6 in brackets when a port follows), or
// a container in brackets: [name].
type Entry struct {
	Prefix netip.Prefix // set when the target is an address or subnet
	Zone   string       // set when the target is a zone
	Name   string       // set when the target is a service or container name
	Port   uint16       // 0 with no Protos means every port and protocol
	Protos []uint8      // TCP and/or UDP with a Port, or ICMP alone
}

func (e Entry) String() string {
	t := e.Zone
	if e.Name != "" {
		t = "[" + e.Name + "]"
	}
	if e.Prefix.IsValid() {
		t = e.Prefix.String()
		if e.Prefix.IsSingleIP() {
			t = e.Prefix.Addr().String()
		}
		if e.Prefix.Addr().Is6() && len(e.Protos) > 0 {
			t = "[" + t + "]"
		}
	}
	if e.IsICMP() {
		return t + ":icmp"
	}
	if e.Port == 0 {
		return t
	}
	t += ":" + strconv.Itoa(int(e.Port))
	if len(e.Protos) == 1 {
		t += "/" + ProtoName(e.Protos[0])
	}
	return t
}

// Parse parses a comma-separated list of target[:port[/proto]]. An empty
// value is an empty list. Any bad entry fails the whole list.
func Parse(s string) ([]Entry, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []Entry
	for _, item := range strings.Split(s, ",") {
		e, err := parseEntry(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("%q: %w", strings.TrimSpace(item), err)
		}
		out = append(out, e)
	}
	return out, nil
}

func parseEntry(s string) (Entry, error) {
	var e Entry
	if s == "" {
		return e, fmt.Errorf("empty entry")
	}
	target, portSpec, hasPort := s, "", false
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return e, fmt.Errorf("missing ]")
		}
		target, portSpec = s[1:end], s[end+1:]
		if portSpec != "" {
			if !strings.HasPrefix(portSpec, ":") {
				return e, fmt.Errorf("expected :port after ]")
			}
			portSpec, hasPort = portSpec[1:], true
		}
		if !strings.Contains(target, ":") {
			// A container: names never contain ":", IPv6 addresses always do.
			if !validName(target) {
				return e, fmt.Errorf("bad container name [%s]", target)
			}
			e.Name = target
		}
	} else if strings.Count(s, ":") == 1 {
		i := strings.IndexByte(s, ':')
		target, portSpec, hasPort = s[:i], s[i+1:], true
	}

	if e.Name == "" {
		if err := e.parseTarget(target); err != nil {
			return e, err
		}
	}
	if !hasPort {
		return e, nil
	}
	if e.Zone == ZoneDNS {
		return e, fmt.Errorf("dns takes no port: it is port 53")
	}
	if strings.EqualFold(portSpec, "icmp") {
		e.Protos = []uint8{ICMP}
		return e, nil
	}
	portStr, proto, hasProto := strings.Cut(portSpec, "/")
	p, err := parsePort(portStr)
	if err != nil {
		return e, err
	}
	e.Port = p
	switch {
	case !hasProto:
		e.Protos = []uint8{TCP, UDP}
	case strings.EqualFold(proto, "tcp"):
		e.Protos = []uint8{TCP}
	case strings.EqualFold(proto, "udp"):
		e.Protos = []uint8{UDP}
	default:
		return e, fmt.Errorf("protocol must be tcp or udp (or write :icmp alone)")
	}
	return e, nil
}

func (e *Entry) parseTarget(t string) error {
	switch t {
	case ZoneInternet, ZoneLAN, ZoneHost, ZoneDNS, ZoneRFC1918:
		e.Zone = t
		return nil
	case "":
		return fmt.Errorf("missing target")
	}
	if strings.ContainsAny(t, ":/") || isAddrLike(t) {
		var p netip.Prefix
		var err error
		if strings.Contains(t, "/") {
			p, err = netip.ParsePrefix(t)
			if err == nil && p != p.Masked() {
				return fmt.Errorf("subnet %s has host bits set (did you mean %s?)", t, p.Masked())
			}
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(t)
			if a.Zone() != "" {
				return fmt.Errorf("bad address %s", t)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if err != nil {
			return fmt.Errorf("bad address: %v", err)
		}
		if p.Addr().Is4In6() {
			return fmt.Errorf("bad address %s", t)
		}
		e.Prefix = p
		return nil
	}
	if validName(t) {
		return fmt.Errorf("unknown target %s (write containers in brackets: [%s])", t, t)
	}
	return fmt.Errorf("bad target %q", t)
}

// isAddrLike reports whether s has only digits and dots, so it can't be a name.
func isAddrLike(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.") == ""
}

// validName follows Docker's container name rule: [a-zA-Z0-9][a-zA-Z0-9_.-]*.
func validName(s string) bool {
	if len(s) > 255 {
		return false
	}
	for i, c := range s {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '_' && c != '.' && c != '-') {
			return false
		}
	}
	return true
}

func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("bad port %q", s)
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

// ProtoName returns "tcp" or "udp", or the protocol number.
func ProtoName(p uint8) string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

// IsICMP reports whether e allows only ICMP.
func (e Entry) IsICMP() bool { return len(e.Protos) == 1 && e.Protos[0] == ICMP }

// Matches reports whether e names a container with this name or compose
// service.
func (e Entry) Matches(name, service string) bool {
	return e.Name != "" && (e.Name == name || e.Name == service)
}

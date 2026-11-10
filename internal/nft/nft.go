// Package nft renders dfw's bridge table as nft text, applies it with the
// nft tool, and checks what the kernel holds against what was intended.
package nft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"dfw/internal/rules"
)

// Table identity and placement. Priority -150 runs after bridge conntrack
// (-200) and before br_netfilter (0), so chains see the addresses a container
// actually sends to, before Docker's NAT (gate test, questions 1 and 2).
const (
	Family   = "bridge"
	Table    = "fw"
	Priority = -150
)

// Path of the nft tool. Never looked up in $PATH.
var Path = "/usr/sbin/nft"

// Port is one of a container's veths, with the identity it may send as.
type Port struct {
	Ifindex int // host side of the veth
	MAC     net.HardwareAddr
	IPv4    netip.Addr   // invalid if none
	IPv6    netip.Addr   // invalid if none
	Subnet6 netip.Prefix // the on-link IPv6 subnet, if any
}

// Denied marks connections that a container's inbound chain refused. Routed
// traffic (to a published port) is confirmed by conntrack before the bridge
// sees it, so without the mark a refused connection would still be tracked,
// and a reply from the container would count as established.
const Denied = "0x40000000"

// LinkLocal returns the EUI-64 link-local address the kernel derives from mac.
func LinkLocal(mac net.HardwareAddr) netip.Addr {
	b := [16]byte{0: 0xfe, 1: 0x80}
	if len(mac) == 6 {
		copy(b[8:], []byte{mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]})
	}
	return netip.AddrFrom16(b)
}

// Container is everything the table holds for one container.
type Container struct {
	ID      string // full hex ID
	Ports   []Port
	In, Out rules.Allow
}

// Key is the container's prefix for chain and set names.
func Key(id string) string { return "c" + id[:16] }

// ValidID reports whether id is safe to use in names.
func ValidID(id string) bool {
	if len(id) < 16 {
		return false
	}
	_, err := hex.DecodeString(id[:16])
	return err == nil && strings.ToLower(id) == id
}

type set struct {
	name, typ string
	interval  bool
	elems     []string
}

// sets returns a container's named sets in a fixed order.
func sets(c Container) []set {
	k := Key(c.ID)
	mac := set{name: k + "_mac", typ: "iface_index . ether_addr"}
	arp := set{name: k + "_arp", typ: "iface_index . ether_addr . ipv4_addr"}
	ip4 := set{name: k + "_ip4", typ: "iface_index . ipv4_addr"}
	ip6 := set{name: k + "_ip6", typ: "iface_index . ipv6_addr"}
	nd := set{name: k + "_nd", typ: "iface_index . ipv6_addr"}
	ndd := set{name: k + "_ndd", typ: "iface_index . ipv6_addr", interval: true}
	for _, p := range c.Ports {
		i := strconv.Itoa(p.Ifindex)
		m := p.MAC.String()
		mac.elems = append(mac.elems, i+" . "+m)
		if p.IPv4.IsValid() {
			arp.elems = append(arp.elems, i+" . "+m+" . "+p.IPv4.String())
			ip4.elems = append(ip4.elems, i+" . "+p.IPv4.String())
		}
		// Neighbour discovery: as itself, to link-local and multicast
		// addresses, or on its own subnet. Never routed beyond the bridge.
		nd.elems = append(nd.elems, i+" . "+LinkLocal(p.MAC).String())
		ndd.elems = append(ndd.elems, i+" . fe80::/10", i+" . ff02::/16")
		if p.IPv6.IsValid() {
			ip6.elems = append(ip6.elems, i+" . "+p.IPv6.String())
			nd.elems = append(nd.elems, i+" . "+p.IPv6.String())
			if p.Subnet6.IsValid() {
				ndd.elems = append(ndd.elems, i+" . "+rules.PrefixRange(p.Subnet6).String())
			}
		}
	}
	out := []set{mac, arp, ip4, ip6, nd, ndd}
	for _, d := range []struct {
		dir string
		a   rules.Allow
	}{{"o", c.Out}, {"i", c.In}} {
		any4, any6 := rules.Split(d.a.Any)
		s4 := set{name: k + "_" + d.dir + "4", typ: "ipv4_addr", interval: true, elems: strs(any4, "")}
		s6 := set{name: k + "_" + d.dir + "6", typ: "ipv6_addr", interval: true, elems: strs(any6, "")}
		p4 := set{name: k + "_" + d.dir + "4p", typ: "ipv4_addr . inet_proto . inet_service", interval: true}
		p6 := set{name: k + "_" + d.dir + "6p", typ: "ipv6_addr . inet_proto . inet_service", interval: true}
		keys := make([]rules.PortKey, 0, len(d.a.Ports))
		for pk := range d.a.Ports {
			keys = append(keys, pk)
		}
		slices.SortFunc(keys, func(a, b rules.PortKey) int {
			return int(a.Proto)<<16 + int(a.Port) - int(b.Proto)<<16 - int(b.Port)
		})
		for _, pk := range keys {
			v4, v6 := rules.Split(d.a.Ports[pk])
			suffix := " . " + rules.ProtoName(pk.Proto) + " . " + strconv.Itoa(int(pk.Port))
			p4.elems = append(p4.elems, strs(v4, suffix)...)
			p6.elems = append(p6.elems, strs(v6, suffix)...)
		}
		icmp4, icmp6 := rules.Split(d.a.ICMP)
		i4 := set{name: k + "_" + d.dir + "4i", typ: "ipv4_addr", interval: true, elems: strs(icmp4, "")}
		i6 := set{name: k + "_" + d.dir + "6i", typ: "ipv6_addr", interval: true, elems: strs(icmp6, "")}
		out = append(out, s4, p4, s6, p6, i4, i6)
	}
	return out
}

func strs(rs []rules.Range, suffix string) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String() + suffix
	}
	return out
}

// chains returns a container's two chains (docs/how-it-works.md).
func chains(c Container) (out, in []string) {
	k := Key(c.ID)
	// ARP and neighbour discovery pass without rules, so they are held to
	// their plain size and can't carry data: ARP to its 28 bytes (46 with
	// padding), ND to 24 bytes and one 8-byte link-layer address option.
	out = []string{
		"ether type != { arp, ip, ip6 } drop",
		"iif . ether saddr != @" + k + "_mac drop",
		"ether type arp meta length <= 46 iif . arp saddr ether . arp saddr ip @" + k + "_arp accept",
		"ether type arp drop",
		"icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 ip6 length <= 32 iif . ip6 saddr @" + k + "_nd iif . ip6 daddr @" + k + "_ndd accept",
		"icmpv6 type nd-neighbor-advert ip6 hoplimit 255 ip6 length <= 32 iif . ip6 saddr @" + k + "_nd iif . icmpv6 taddr @" + k + "_nd iif . ip6 daddr @" + k + "_ndd accept",
		"ether type ip iif . ip saddr != @" + k + "_ip4 drop",
		"ether type ip6 iif . ip6 saddr != @" + k + "_ip6 drop",
		"ct mark & " + Denied + " != 0 drop",
		"ct state established,related accept",
		"ct state != new drop",
		"ip daddr @" + k + "_o4 accept",
		"ip daddr . meta l4proto . th dport @" + k + "_o4p accept",
		"ip6 daddr @" + k + "_o6 accept",
		"ip6 daddr . meta l4proto . th dport @" + k + "_o6p accept",
		"meta l4proto icmp ip daddr @" + k + "_o4i accept",
		"meta l4proto ipv6-icmp ip6 daddr @" + k + "_o6i accept",
		"counter drop",
	}
	in = []string{
		"ether type != { arp, ip, ip6 } drop",
		"ether type arp accept",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept",
		// Frames flooded to every port must not reach the wrong container.
		"ether type ip oif . ip daddr != @" + k + "_ip4 drop",
		"ether type ip6 oif . ip6 daddr != @" + k + "_ip6 drop",
		"ct mark & " + Denied + " != 0 drop",
		"ct state established,related accept",
		"ct state != new drop",
		"ip saddr @" + k + "_i4 accept",
		"ip saddr . meta l4proto . th dport @" + k + "_i4p accept",
		"ip6 saddr @" + k + "_i6 accept",
		"ip6 saddr . meta l4proto . th dport @" + k + "_i6p accept",
		"meta l4proto icmp ip saddr @" + k + "_i4i accept",
		"meta l4proto ipv6-icmp ip6 saddr @" + k + "_i6i accept",
		"ct mark set ct mark | " + Denied + " counter drop",
	}
	return out, in
}

var baseChains = []struct{ name, hook, dir, match string }{
	{"from_container", "prerouting", "out", "iif"},
	{"to_container", "postrouting", "in", "oif"},
}

// Ruleset is everything dfw's table holds.
type Ruleset struct {
	// Open lists the bridges dfw leaves alone: every bridge but the filtered
	// networks'. A veth on any other bridge is blocked unless a container's
	// chains claim it, so a bridge dfw hasn't seen yet starts out blocked.
	Open []string
	// Blocked lists veths that are always dropped: those of filtered
	// containers on other networks.
	Blocked    []int
	Containers []Container
	// Peers lists the addresses of every container on the filtered networks.
	// A container's frames reach its peers through the bridge, never through
	// the host, so a frame the host sends into a veth from one of these
	// addresses is spoofed: from_host drops it. Otherwise a LAN host could
	// send to a published port as a peer the inbound rules trust.
	Peers []netip.Addr
}

// ValidIfname reports whether name is a safe interface name to write into
// a ruleset.
func ValidIfname(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func portMap(t Ruleset, dir string) []string {
	var els []string
	for _, c := range t.Containers {
		for _, p := range c.Ports {
			els = append(els, fmt.Sprintf("%d : jump %s_%s", p.Ifindex, Key(c.ID), dir))
		}
	}
	for _, i := range t.Blocked {
		els = append(els, fmt.Sprintf("%d : drop", i))
	}
	return els
}

// peerSets returns the sets from_host checks sources against.
func peerSets(t Ruleset) []set {
	var rs []rules.Range
	for _, a := range t.Peers {
		if a.IsValid() {
			rs = append(rs, rules.AddrRange(a.Unmap()))
		}
	}
	v4, v6 := rules.Split(rules.Normalize(rs))
	return []set{
		{name: "peers4", typ: "ipv4_addr", interval: true, elems: strs(v4, "")},
		{name: "peers6", typ: "ipv6_addr", interval: true, elems: strs(v6, "")},
	}
}

// fromHost is the chain for frames the host sends into a bridge: routed,
// such as to a published port, or its own.
var fromHost = []string{
	`oifname "veth*" ip saddr @peers4 counter drop`,
	`oifname "veth*" ip6 saddr @peers6 counter drop`,
}

func openBridges(t Ruleset) []string {
	var els []string
	for _, b := range t.Open {
		if ValidIfname(b) {
			els = append(els, `"`+b+`"`)
		}
	}
	return els
}

// Render returns one nft transaction that replaces the whole table. nft
// applies a file atomically, so packets see either the old table or the new
// one, never a gap.
func Render(t Ruleset) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("add table %s %s\ndelete table %s %s\ntable %s %s {\n", Family, Table, Family, Table, Family, Table)
	w("\tset open_bridges {\n\t\ttype ifname\n")
	writeElems(&b, openBridges(t))
	w("\t}\n")
	for _, s := range peerSets(t) {
		writeSet(&b, s)
	}
	for _, bc := range baseChains {
		w("\tmap %s_by_port {\n\t\ttype iface_index : verdict\n", bc.dir)
		writeElems(&b, portMap(t, bc.dir))
		w("\t}\n")
	}
	for _, bc := range baseChains {
		w("\tchain %s {\n\t\ttype filter hook %s priority %d; policy accept;\n", bc.name, bc.hook, Priority)
		w("\t\t%s vmap @%s_by_port\n", bc.match, bc.dir)
		w("\t\t%sname \"veth*\" meta %cbrname != @open_bridges counter drop\n\t}\n", bc.match, bc.match[0])
	}
	w("\tchain from_host {\n\t\ttype filter hook output priority %d; policy accept;\n", Priority)
	for _, r := range fromHost {
		w("\t\t%s\n", r)
	}
	w("\t}\n")
	for _, c := range t.Containers {
		for _, s := range sets(c) {
			writeSet(&b, s)
		}
		out, in := chains(c)
		for _, ch := range []struct {
			dir   string
			rules []string
		}{{"out", out}, {"in", in}} {
			w("\tchain %s_%s {\n", Key(c.ID), ch.dir)
			for _, r := range ch.rules {
				w("\t\t%s\n", r)
			}
			w("\t}\n")
		}
	}
	w("}\n")
	return b.String()
}

func writeSet(b *strings.Builder, s set) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n", s.name, s.typ)
	if s.interval {
		b.WriteString("\t\tflags interval\n")
	}
	writeElems(b, s.elems)
	b.WriteString("\t}\n")
}

func writeElems(b *strings.Builder, els []string) {
	if len(els) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(els, ",\n\t\t\t     "))
	}
}

// ErrNoTable means the table doesn't exist.
var ErrNoTable = errors.New("table bridge fw does not exist")

func run(stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, Path, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if strings.Contains(msg, "No such file or directory") && slices.Contains(args, "table") {
			return nil, ErrNoTable
		}
		return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, msg)
	}
	return out.Bytes(), nil
}

// Apply loads ruleset text as one transaction.
func Apply(text string) error {
	_, err := run(text, "-f", "-")
	return err
}

// Delete removes the table.
func Delete() error {
	_, err := run("", "delete", "table", Family, Table)
	return err
}

// State is the table as the kernel holds it.
type State struct {
	Chains map[string]Chain
	Sets   map[string][]string // sets and maps: canonical elements, sorted
	Rules  string              // fingerprint of every rule, ignoring counters
}

// Chain is one chain's properties.
type Chain struct {
	Hook   string
	Prio   int
	Policy string
	Rules  int
}

// List reads the table from the kernel. ifnames maps interface names, which
// nft prints instead of indexes, back to indexes.
func List(ifnames map[string]int) (*State, error) {
	out, err := run("", "-j", "list", "table", Family, Table)
	if err != nil {
		return nil, err
	}
	return parseState(out, ifnames)
}

func parseState(js []byte, ifnames map[string]int) (*State, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	st := &State{Chains: map[string]Chain{}, Sets: map[string][]string{}}
	h := sha256.New()
	for _, obj := range doc.Nftables {
		switch {
		case obj["chain"] != nil:
			var c struct {
				Name, Hook, Policy string
				Prio               int
			}
			if err := json.Unmarshal(obj["chain"], &c); err != nil {
				return nil, err
			}
			ch := st.Chains[c.Name]
			ch.Hook, ch.Prio, ch.Policy = c.Hook, c.Prio, c.Policy
			st.Chains[c.Name] = ch
		case obj["rule"] != nil:
			var r struct {
				Chain string
				Expr  any
			}
			if err := json.Unmarshal(obj["rule"], &r); err != nil {
				return nil, err
			}
			ch := st.Chains[r.Chain]
			ch.Rules++
			st.Chains[r.Chain] = ch
			b, _ := json.Marshal(stripCounters(r.Expr))
			fmt.Fprintf(h, "%s\x00%s\n", r.Chain, b)
		case obj["set"] != nil || obj["map"] != nil:
			raw := obj["set"]
			if raw == nil {
				raw = obj["map"]
			}
			var s struct {
				Name string
				Elem []any
			}
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, err
			}
			els := []string{}
			for _, e := range s.Elem {
				if n, ok := e.(string); ok && s.Name == "open_bridges" {
					els = append(els, `"`+n+`"`) // interface names, not indexes
				} else {
					els = append(els, canon(e, ifnames))
				}
			}
			slices.Sort(els)
			st.Sets[s.Name] = els
		}
	}
	st.Rules = hex.EncodeToString(h.Sum(nil))
	return st, nil
}

func stripCounters(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == "counter" {
				t[k] = nil
			} else {
				t[k] = stripCounters(x)
			}
		}
	case []any:
		for i, x := range t {
			t[i] = stripCounters(x)
		}
	}
	return v
}

// canon renders a JSON set element in the same text form Render writes.
func canon(v any, ifnames map[string]int) string {
	switch t := v.(type) {
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case string:
		if a, err := netip.ParseAddr(t); err == nil {
			return rules.AddrRange(a).String()
		}
		if t == "tcp" || t == "udp" {
			return t
		}
		if i, ok := ifnames[t]; ok {
			return strconv.Itoa(i)
		}
		return t
	case []any: // map element: [key, verdict]
		if len(t) == 2 {
			if m, ok := t[1].(map[string]any); ok {
				for verdict, x := range m {
					tm, _ := x.(map[string]any)
					target, _ := tm["target"].(string)
					if target == "" {
						return canon(t[0], ifnames) + " : " + verdict
					}
					return canon(t[0], ifnames) + " : " + verdict + " " + target
				}
			}
		}
	case map[string]any:
		if x, ok := t["elem"]; ok {
			return canon(x.(map[string]any)["val"], ifnames)
		}
		if x, ok := t["concat"].([]any); ok {
			parts := make([]string, len(x))
			for i, p := range x {
				parts[i] = canon(p, ifnames)
			}
			return strings.Join(parts, " . ")
		}
		if x, ok := t["prefix"].(map[string]any); ok {
			a, err := netip.ParseAddr(fmt.Sprint(x["addr"]))
			if err == nil {
				return rules.PrefixRange(netip.PrefixFrom(a, int(x["len"].(float64)))).String()
			}
		}
		if x, ok := t["range"].([]any); ok && len(x) == 2 {
			lo, err1 := netip.ParseAddr(fmt.Sprint(x[0]))
			hi, err2 := netip.ParseAddr(fmt.Sprint(x[1]))
			if err1 == nil && err2 == nil {
				return rules.Range{Lo: lo, Hi: hi}.String()
			}
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Intended returns the state Render(t) should produce, apart from the rule
// fingerprint.
func Intended(t Ruleset) *State {
	st := &State{Chains: map[string]Chain{}, Sets: map[string][]string{}}
	open := openBridges(t)
	slices.Sort(open)
	st.Sets["open_bridges"] = append([]string{}, open...)
	for _, bc := range baseChains {
		st.Chains[bc.name] = Chain{Hook: bc.hook, Prio: Priority, Policy: "accept", Rules: 2}
		els := portMap(t, bc.dir)
		slices.Sort(els)
		st.Sets[bc.dir+"_by_port"] = append([]string{}, els...)
	}
	st.Chains["from_host"] = Chain{Hook: "output", Prio: Priority, Policy: "accept", Rules: len(fromHost)}
	addSets(st, peerSets(t))
	for _, c := range t.Containers {
		addSets(st, sets(c))
		out, in := chains(c)
		st.Chains[Key(c.ID)+"_out"] = Chain{Rules: len(out)}
		st.Chains[Key(c.ID)+"_in"] = Chain{Rules: len(in)}
	}
	return st
}

func addSets(st *State, ss []set) {
	for _, s := range ss {
		els := append([]string{}, s.elems...)
		slices.Sort(els)
		st.Sets[s.name] = els
	}
}

// Diff describes how have differs from want, ignoring the rule fingerprint.
// It returns "" when they match.
func Diff(want, have *State) string {
	var d []string
	for name, c := range want.Chains {
		if h, ok := have.Chains[name]; !ok {
			d = append(d, "missing chain "+name)
		} else if h != c {
			d = append(d, fmt.Sprintf("chain %s is %+v, want %+v", name, h, c))
		}
	}
	for name := range have.Chains {
		if _, ok := want.Chains[name]; !ok {
			d = append(d, "unexpected chain "+name)
		}
	}
	for name, els := range want.Sets {
		if h, ok := have.Sets[name]; !ok {
			d = append(d, "missing set "+name)
		} else if !slices.Equal(h, els) {
			d = append(d, fmt.Sprintf("set %s holds %v, want %v", name, h, els))
		}
	}
	for name := range have.Sets {
		if _, ok := want.Sets[name]; !ok {
			d = append(d, "unexpected set "+name)
		}
	}
	slices.Sort(d)
	return strings.Join(d, "; ")
}

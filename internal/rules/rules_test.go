package rules

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	ok := map[string]string{
		"":                        "",
		"  ":                      "",
		"[b]:5432, 10.10.20.20":   "[b]:5432,10.10.20.20",
		"rfc1918":                 "rfc1918",
		"any, [any]:80":           "any,[any]:80",
		"[internet]":              "[internet]",
		"[my-svc_1.x]":            "[my-svc_1.x]",
		"internet":                "internet",
		"lan, host:8080/tcp":      "lan,host:8080/tcp",
		"dns":                     "dns",
		"10.0.0.0/8:53/udp":       "10.0.0.0/8:53/udp",
		"2001:db8::1":             "2001:db8::1",
		"[2001:db8::1]:443":       "[2001:db8::1]:443",
		"[2001:db8::/32]:443/TCP": "[2001:db8::/32]:443/tcp",
		"fd00::/8":                "fd00::/8",
		"[my-svc_1.x]:1/udp":      "[my-svc_1.x]:1/udp",
		"[web]:65535":             "[web]:65535",
		"[web]:icmp":              "[web]:icmp",
		"internet:ICMP":           "internet:icmp",
		"[2001:db8::/32]:icmp":    "[2001:db8::/32]:icmp",
		"10.0.0.1:icmp":           "10.0.0.1:icmp",
		"169.254.169.254:80/tcp":  "169.254.169.254:80/tcp",
		"[::1]":                   "::1",
	}
	for in, want := range ok {
		es, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		var got []string
		for _, e := range es {
			got = append(got, e.String())
		}
		if g := strings.Join(got, ","); g != want {
			t.Errorf("Parse(%q) = %q, want %q", in, g, want)
		}
	}
	bad := []string{
		"[a],", ",[a]", "[a],,[b]", "[b]:0", "[b]:65536", "[b]:-1", "[b]:+5", "[b]:5/icmp", "[b]:", ":53",
		"[b]/tcp", "10.0.0.1/8", "10.10.20", "1.2.3.4.5", "[2001:db8::1]80",
		"[2001:db8::1", "dns:53", "[-x]", "[a b]", "[a;b]", "fe80::1%eth0", "::ffff:1.2.3.4",
		"[b]:5432/tcp/udp", "[b]:123456", "*", "internet:1:2", "\"b\"",
		"b", "b:5432", "foo", "[]", "[b", "[b]x", "[10.0.0.1]:80x", "[[b]]",
	}
	for _, in := range bad {
		if es, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want error", in, es)
		}
	}
}

func rs(ss ...string) []Range {
	var out []Range
	for _, s := range ss {
		if lo, hi, ok := strings.Cut(s, "-"); ok {
			out = append(out, Range{netip.MustParseAddr(lo), netip.MustParseAddr(hi)})
		} else if strings.Contains(s, "/") {
			out = append(out, PrefixRange(netip.MustParsePrefix(s)))
		} else {
			out = append(out, AddrRange(netip.MustParseAddr(s)))
		}
	}
	return out
}

func str(r []Range) string { return fmt.Sprint(r) }

func TestRanges(t *testing.T) {
	cases := []struct{ got, want []Range }{
		{Normalize(rs("10.0.0.5", "10.0.0.0/30", "10.0.0.4", "::1", "10.0.0.6-10.0.0.9")), rs("10.0.0.0-10.0.0.9", "::1")},
		{Subtract(rs("10.0.0.0/8"), rs("10.1.0.0/16", "10.0.0.0")), rs("10.0.0.1-10.0.255.255", "10.2.0.0-10.255.255.255")},
		{Subtract(rs("0.0.0.0/0"), rs("0.0.0.0/1")), rs("128.0.0.0/1")},
		{Subtract(rs("0.0.0.0/0", "::/0"), rs("::/0")), rs("0.0.0.0/0")},
		{Subtract(rs("1.2.3.4"), rs("1.2.3.4")), nil},
		{Normalize(rs("255.255.255.255", "255.255.255.254")), rs("255.255.255.254/31")},
	}
	for i, c := range cases {
		if str(c.got) != str(c.want) {
			t.Errorf("%d: got %v want %v", i, c.got, c.want)
		}
	}
	if s := rs("10.0.0.0-10.0.0.255")[0].String(); s != "10.0.0.0/24" {
		t.Errorf("String = %s", s)
	}
	if s := rs("10.0.0.1-10.0.0.2")[0].String(); s != "10.0.0.1-10.0.0.2" {
		t.Errorf("String = %s", s)
	}
}

func TestZones(t *testing.T) {
	env := Env{
		HostAddrs: []netip.Addr{netip.MustParseAddr("10.0.2.15"), netip.MustParseAddr("2001:db8::15")},
		Gateways:  []netip.Addr{netip.MustParseAddr("172.18.0.1")},
		DNS:       []netip.Addr{netip.MustParseAddr("10.0.2.3")},
	}
	inet := Zone(ZoneInternet, env)
	lan := Zone(ZoneLAN, env)
	host := Zone(ZoneHost, env)
	priv := Zone(ZoneRFC1918, env)
	for a, want := range map[string]bool{"10.0.0.1": true, "172.31.0.1": true, "192.168.1.1": true,
		"10.0.2.15": false, "172.18.0.1": false, "fd00::1": false, "8.8.8.8": false, "100.64.0.1": false} {
		if Contains(priv, netip.MustParseAddr(a)) != want {
			t.Errorf("rfc1918 contains %s: %v, want %v", a, !want, want)
		}
	}
	in := func(z []Range, a string) bool { return Contains(z, netip.MustParseAddr(a)) }
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111", "2001:db8::16"} {
		if !in(inet, a) || in(lan, a) || in(host, a) {
			t.Errorf("%s should be internet only", a)
		}
	}
	for _, a := range []string{"10.0.0.1", "172.18.0.2", "192.168.1.1", "fd00::1"} {
		if in(inet, a) || !in(lan, a) {
			t.Errorf("%s should be lan only", a)
		}
	}
	for _, a := range []string{"10.0.2.15", "172.18.0.1", "2001:db8::15"} {
		if in(inet, a) || in(lan, a) || !in(host, a) {
			t.Errorf("%s should be host only", a)
		}
	}
	for _, a := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.1", "100.64.0.1", "::1", "fe80::1", "ff02::1", "255.255.255.255", "0.0.0.0",
		"::ffff:10.0.0.5", "64:ff9b::a00:5", "64:ff9b:1::1", "2002:a00:5::1", "::10.0.0.5"} {
		if in(inet, a) || in(lan, a) || in(host, a) {
			t.Errorf("%s should be in no zone", a)
		}
	}
}

func TestResolve(t *testing.T) {
	env := Env{
		Peers: []Peer{
			{Name: "p-b-1", Service: "b", Addrs: []netip.Addr{netip.MustParseAddr("172.18.0.3"), netip.MustParseAddr("fd00::3")}},
			{Name: "p-b-2", Service: "b", Addrs: []netip.Addr{netip.MustParseAddr("172.18.0.4")}},
			{Name: "solo", Addrs: []netip.Addr{netip.MustParseAddr("172.18.0.10")}},
		},
		DNS: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
	}
	es, _ := Parse("[b]:5432, 10.10.20.20, [solo]:80/tcp, [nobody], dns")
	a := Resolve(es, env, true)
	if str(a.Any) != str(rs("10.10.20.20")) {
		t.Errorf("Any = %v", a.Any)
	}
	if got := a.Ports[PortKey{TCP, 5432}]; str(got) != str(rs("172.18.0.3-172.18.0.4", "fd00::3")) {
		t.Errorf("b:5432 tcp = %v (every replica of service b)", got)
	}
	if got := a.Ports[PortKey{UDP, 5432}]; len(got) != 2 {
		t.Errorf("b:5432 udp = %v", got)
	}
	if got := a.Ports[PortKey{TCP, 80}]; str(got) != str(rs("172.18.0.10")) {
		t.Errorf("solo:80 = %v", got)
	}
	if got := a.Ports[PortKey{UDP, 53}]; str(got) != str(rs("192.168.1.1")) {
		t.Errorf("dns = %v", got)
	}
	if _, ok := a.Ports[PortKey{UDP, 80}]; ok {
		t.Errorf("solo:80/tcp leaked to udp")
	}

	es, _ = Parse("internet")
	a = Resolve(es, env, true)
	if got := a.Ports[PortKey{UDP, 53}]; str(got) != str(rs("192.168.1.1")) {
		t.Errorf("internet must include dns: %v", a.Ports)
	}
	if a = Resolve(es, env, false); len(a.Ports) != 0 {
		t.Errorf("inbound internet must not include the dns servers: %v", a.Ports)
	}
	es, _ = Parse("internet:icmp, 10.1.0.0/16:icmp, 10.1.2.3, [solo]:icmp")
	a = Resolve(es, env, true)
	if len(a.Ports) != 0 || str(a.Any) != str(rs("10.1.2.3")) || !Contains(a.ICMP, netip.MustParseAddr("1.1.1.1")) ||
		!Contains(a.ICMP, netip.MustParseAddr("172.18.0.10")) || Contains(a.ICMP, netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("icmp: any %v ports %v icmp %v (internet:icmp must not add dns, and Any covers 10.1.2.3)", a.Any, a.Ports, a.ICMP)
	}
	es, _ = Parse("internet:443/tcp")
	if a = Resolve(es, env, true); len(a.Ports) != 1 {
		t.Errorf("internet:443 must not include dns: %v", a.Ports)
	}
	es, _ = Parse("any, internet:443/tcp, 1.2.3.4:icmp")
	if a = Resolve(es, env, true); str(a.Any) != str(rs("0.0.0.0/0", "::/0")) || len(a.Ports) != 0 || len(a.ICMP) != 0 {
		t.Errorf("any must be every address and absorb the rest: %v %v %v", a.Any, a.Ports, a.ICMP)
	}
	es, _ = Parse("[p-b-2]")
	if a = Resolve(es, env, true); str(a.Any) != str(rs("172.18.0.4")) {
		t.Errorf("a container name matches only that container: %v", a.Any)
	}
}

func TestParseConfig(t *testing.T) {
	c := ParseConfig([]File{{"rules", `
# example from the README
network fw
allow [foo] -> [bar]:5432/tcp
allow [foo] -> internet
allow [foo] -> rfc1918
allow internet -> [bar]:443/tcp   # trailing comment
allow [bar] -> 10.10.20.20
	allow   [bar]->10.10.30.0/24
allow [a], [b] -> [c]:80, [2001:db8::1]:443
`}, {"rules.d/x.rules", "network fw\n"}})
	if len(c.Errors) != 0 || strings.Join(c.Networks, ",") != "fw" || len(c.Rules) != 7 {
		t.Fatalf("errors %v, networks %q, %d rules", c.Errors, c.Networks, len(c.Rules))
	}
	if c := ParseConfig([]File{{"r", "network b\nnetwork a\nnetwork b\nallow [x] -> [y]:icmp"}}); len(c.Errors) != 0 ||
		strings.Join(c.Networks, ",") != "a,b" || !c.Rules[0].To[0].IsICMP() {
		t.Errorf("several networks: %v %v", c.Networks, c.Errors)
	}
	if c.Rules[3].Pos != "rules:7" {
		t.Errorf("pos = %s", c.Rules[2].Pos)
	}
	bad := []string{
		"allow [foo]",
		"allow [foo] ->",
		"allow -> [bar]",
		"allow [foo]:80 -> [bar]",
		"allow internet -> 10.0.0.1",
		"allow dns -> [bar]",
		"allow [foo] -> [bar]:0",
		"allow [foo]:icmp -> [bar]",
		"allow [foo] -> [bar]:icmp/tcp",
		"allow [foo] -> dns:icmp",
		"allow [foo] -> [bar], oops:",
		"allow foo -> [bar]",
		"allow [foo] -> bar:5432",
		"deny [foo] -> [bar]",
		"network",
		"network a b",
		"allow[foo] -> [bar]",
	}
	for _, line := range bad {
		c := ParseConfig([]File{{"r", "network fw\n" + line}})
		if len(c.Errors) != 1 || len(c.Rules) != 0 || !strings.HasPrefix(c.Errors[0], "r:2: ") {
			t.Errorf("%q: errors %q, rules %v", line, c.Errors, c.Rules)
		}
	}
	if c := ParseConfig([]File{{"r", "allow [a] -> [b]"}}); len(c.Errors) != 1 || len(c.Rules) != 1 {
		t.Errorf("a missing network line is an error: %v", c.Errors)
	}
}

func TestFor(t *testing.T) {
	c := ParseConfig([]File{{"r", `network fw
allow [foo] -> [bar]:5432/tcp
allow [foo] -> internet
allow internet -> [bar]:443/tcp
allow [bar] -> 10.10.20.20
allow [foo], 10.1.0.0/16 -> [bar]
`}})
	join := func(es []Entry) string {
		var s []string
		for _, e := range es {
			s = append(s, e.String())
		}
		return strings.Join(s, " ")
	}
	in, out := c.For("p-foo-1", "foo")
	if join(in) != "" || join(out) != "[bar]:5432/tcp internet [bar]" {
		t.Errorf("foo: in %q out %q", join(in), join(out))
	}
	in, out = c.For("bar", "")
	if join(in) != "[foo]:5432/tcp internet:443/tcp [foo] 10.1.0.0/16" || join(out) != "10.10.20.20" {
		t.Errorf("bar: in %q out %q", join(in), join(out))
	}
	in, out = c.For("other", "x")
	if len(in)+len(out) != 0 {
		t.Errorf("other: in %v out %v", in, out)
	}
	if n := c.Names(); len(n) != 2 || n["bar"] != "r:2" {
		t.Errorf("Names = %v", n)
	}
}

func TestRemoved(t *testing.T) {
	old := Allow{Any: rs("1.1.1.1", "2.2.2.2"), Ports: map[PortKey][]Range{{TCP, 80}: rs("3.3.3.3", "4.4.4.4")}}
	new := Allow{Any: rs("1.1.1.1", "4.4.4.4"), Ports: map[PortKey][]Range{{TCP, 80}: rs("3.3.3.3")}}
	if got := Removed(old, new); str(got) != str(rs("2.2.2.2")) {
		t.Errorf("Removed = %v", got)
	}
	old.ICMP, new.ICMP = rs("5.5.5.5", "6.6.6.6", "4.4.4.4"), rs("6.6.6.6")
	if got := Removed(old, new); str(got) != str(rs("2.2.2.2", "5.5.5.5")) {
		t.Errorf("Removed with ICMP = %v", got)
	}
}

// Contains reports whether a lies in one of rs.
func Contains(rs []Range, a netip.Addr) bool {
	for _, r := range rs {
		if r.Lo.BitLen() == a.BitLen() && r.Lo.Compare(a) <= 0 && a.Compare(r.Hi) <= 0 {
			return true
		}
	}
	return false
}

// TestSubtractBrute checks Subtract against address-by-address membership on
// random ranges of both families.
func TestSubtractBrute(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	addr := func(v6 bool, n int) netip.Addr {
		if v6 {
			return netip.AddrFrom16([16]byte{0: 0xfd, 15: byte(n)})
		}
		return netip.AddrFrom4([4]byte{10, 0, 0, byte(n)})
	}
	ranges := func() []Range {
		var rs []Range
		for range rnd.IntN(6) {
			v6, lo := rnd.IntN(2) == 0, rnd.IntN(64)
			rs = append(rs, Range{addr(v6, lo), addr(v6, lo+rnd.IntN(8))})
		}
		return rs
	}
	for i := range 2000 {
		rs, cut := ranges(), ranges()
		got := Subtract(rs, cut)
		for _, v6 := range []bool{false, true} {
			for n := range 72 {
				a := addr(v6, n)
				if want := Contains(rs, a) && !Contains(cut, a); Contains(got, a) != want {
					t.Fatalf("%d: Subtract(%v, %v) = %v: %s in it is %v, want %v", i, rs, cut, got, a, !want, want)
				}
			}
		}
		if n := Normalize(got); str(n) != str(got) {
			t.Fatalf("%d: Subtract(%v, %v) = %v, not normalized", i, rs, cut, got)
		}
	}
}

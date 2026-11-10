package main

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"dfw/internal/docker"
	"dfw/internal/netlink"
	"dfw/internal/nft"
	"dfw/internal/rules"
)

func TestClassify(t *testing.T) {
	bridge := func(i int, name string) netlink.Link { return netlink.Link{Index: i, Name: name, Kind: "bridge"} }
	w := &world{cfg: rules.Config{Networks: []string{"fw"}}, links: []netlink.Link{
		bridge(1, "docker0"),
		bridge(2, "br-aaaaaaaaaaaa"), // fw
		bridge(3, "br-bbbbbbbbbbbb"), // free
		bridge(4, "br-cccccccccccc"), // created, not listed yet: may become fw
		bridge(5, "virbr0"),          // not Docker's
		{Index: 6, Name: "veth1", Kind: "veth", Master: 2},
	}}
	nets := []docker.Network{
		{ID: "d0", Name: "bridge", Driver: "bridge", Options: map[string]string{"com.docker.network.bridge.name": "docker0"}},
		{ID: "aaaaaaaaaaaa1234", Name: "fw", Driver: "bridge"},
		{ID: "bbbbbbbbbbbb1234", Name: "free", Driver: "bridge"},
	}
	fw, drivers := w.classify(nets)
	if want := []string{"br-bbbbbbbbbbbb", "docker0", "virbr0"}; !slices.Equal(w.open, want) {
		t.Errorf("open = %v, want %v", w.open, want)
	}
	if len(w.unlisted) != 1 || w.unlisted[0].Name != "virbr0" {
		t.Errorf("unlisted = %v, want virbr0 only", w.unlisted)
	}
	if len(fw) != 1 || !fw[2] {
		t.Errorf("filtered bridges = %v, want index 2", fw)
	}
	if w.bridges["fw"] != "br-aaaaaaaaaaaa" || drivers["d0"] != "bridge" {
		t.Errorf("bridges = %v, drivers = %v", w.bridges, drivers)
	}
	if want := map[string]int{"d0": 1, "aaaaaaaaaaaa1234": 2, "bbbbbbbbbbbb1234": 3}; !maps.Equal(w.bridgeOf, want) {
		t.Errorf("bridgeOf = %v, want %v", w.bridgeOf, want)
	}
}

func TestMatchPorts(t *testing.T) {
	mac1, _ := net.ParseMAC("02:42:0a:00:00:02")
	mac2, _ := net.ParseMAC("02:42:0a:01:00:02")
	const nsid = 5
	var info docker.Container
	info.NetworkSettings.Networks = map[string]docker.Endpoint{
		"fw": {NetworkID: "n1", MacAddress: mac1.String(), IPAddress: "10.0.0.2",
			GlobalIPv6Address: "fd00::2", GlobalIPv6PrefixLen: 64},
		"other": {NetworkID: "n2", MacAddress: mac2.String(), IPAddress: "10.1.0.2"},
	}
	// eth0 (2) on fw's bridge (100) through veth 10, eth1 (3) on other's (101)
	// through veth 11.
	fixture := func() ([]netlink.Link, map[int]netlink.Link, map[string]int) {
		inside := []netlink.Link{
			{Index: 1, Name: "lo"},
			{Index: 2, Kind: "veth", MAC: mac1, Peer: 10},
			{Index: 3, Kind: "veth", MAC: mac2, Peer: 11},
		}
		byIndex := map[int]netlink.Link{
			10: {Index: 10, Kind: "veth", Master: 100, PeerNetns: nsid, Peer: 2},
			11: {Index: 11, Kind: "veth", Master: 101, PeerNetns: nsid, Peer: 3},
		}
		return inside, byIndex, map[string]int{"n1": 100, "n2": 101}
	}
	for _, tc := range []struct {
		name  string
		edit  func(inside []netlink.Link, byIndex map[int]netlink.Link, bridgeOf map[string]int)
		fw    int // host veth found for fw, or 0
		other int
	}{
		{"as Docker set it up", func([]netlink.Link, map[int]netlink.Link, map[string]int) {}, 10, 11},
		{"MACs swapped inside", func(in []netlink.Link, _ map[int]netlink.Link, _ map[string]int) {
			in[1].MAC, in[2].MAC = mac2, mac1
		}, 0, 0},
		{"host side on another bridge", func(_ []netlink.Link, h map[int]netlink.Link, _ map[string]int) {
			l := h[10]
			l.Master = 101
			h[10] = l
		}, 0, 11},
		{"network's bridge unknown", func(_ []netlink.Link, _ map[int]netlink.Link, b map[string]int) {
			delete(b, "n1")
		}, 0, 11},
		{"host side not attached", func(_ []netlink.Link, h map[int]netlink.Link, b map[string]int) {
			l := h[10]
			l.Master, b["n1"] = 0, 0
			h[10] = l
		}, 0, 11},
		{"peer in another namespace", func(_ []netlink.Link, h map[int]netlink.Link, _ map[string]int) {
			l := h[10]
			l.PeerNetns = nsid + 1
			h[10] = l
		}, 0, 11},
		{"host side's peer is another link", func(_ []netlink.Link, h map[int]netlink.Link, _ map[string]int) {
			l := h[10]
			l.Peer = 3
			h[10] = l
		}, 0, 11},
		{"host side not a veth", func(_ []netlink.Link, h map[int]netlink.Link, _ map[string]int) {
			l := h[10]
			l.Kind = "dummy"
			h[10] = l
		}, 0, 11},
		{"inside link not a veth", func(in []netlink.Link, _ map[int]netlink.Link, _ map[string]int) {
			in[1].Kind = "macvlan"
		}, 0, 11},
	} {
		inside, byIndex, bridgeOf := fixture()
		tc.edit(inside, byIndex, bridgeOf)
		ports := matchPorts(&info, []string{"fw", "other"}, nsid, inside, byIndex, bridgeOf)
		if got := ports["fw"].Ifindex; got != tc.fw {
			t.Errorf("%s: fw on veth %d, want %d", tc.name, got, tc.fw)
		}
		if got := ports["other"].Ifindex; got != tc.other {
			t.Errorf("%s: other on veth %d, want %d", tc.name, got, tc.other)
		}
	}
	inside, byIndex, bridgeOf := fixture()
	p := matchPorts(&info, []string{"fw"}, nsid, inside, byIndex, bridgeOf)["fw"]
	if p.IPv4.String() != "10.0.0.2" || p.IPv6.String() != "fd00::2" || p.Subnet6.String() != "fd00::/64" || p.MAC.String() != mac1.String() {
		t.Errorf("fw port = %+v", p)
	}
}

func TestBootRuleset(t *testing.T) {
	dir := t.TempDir()
	rulesPath, rulesDir = filepath.Join(dir, "rules"), filepath.Join(dir, "rules.d")
	activeFile, stateFile = filepath.Join(dir, "rules.json"), filepath.Join(dir, "open-bridges")
	write := func(text string) {
		if err := os.WriteFile(rulesPath, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("network fw\n")
	if err := saveOpen([]string{"fw"}, []string{"docker0", "br-bbbbbbbbbbbb"}); err != nil {
		t.Fatal(err)
	}
	if got := bootRuleset().Open; !slices.Equal(got, []string{"docker0", "br-bbbbbbbbbbbb"}) {
		t.Errorf("open = %v, want the recorded bridges", got)
	}
	// A record made for other networks opens nothing.
	write("network fw\nnetwork two\n")
	if got := bootRuleset().Open; len(got) != 0 {
		t.Errorf("open = %v for a record of other networks, want none", got)
	}
	// Invalid edited rules fall back to the active ones; none: nothing opens.
	write("network fw\nbogus\n")
	if got := bootRuleset().Open; len(got) != 0 {
		t.Errorf("open = %v with invalid rules and no active ones, want none", got)
	}
	if _, err := saveActive([]rules.File{{Name: "rules", Text: "network fw\n"}}); err != nil {
		t.Fatal(err)
	}
	if got := bootRuleset().Open; len(got) != 2 {
		t.Errorf("open = %v with invalid rules, want the active rules' record", got)
	}
}

// TestUpstreamDNS checks which servers the dns target opens: only what the
// host's administrator set, never the container's own resolv.conf.
func TestUpstreamDNS(t *testing.T) {
	dir := t.TempDir()
	hostResolvConf, resolvedConf = filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "resolved.conf")
	daemonJSON = filepath.Join(dir, "daemon.json")
	write := func(path, text string) {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(resolvedConf, "nameserver 192.168.1.1\nnameserver fe80::1%eth0\n")
	ctr := func(dns []string, networks ...string) *docker.Container {
		c := &docker.Container{}
		c.HostConfig.DNS = dns
		c.NetworkSettings.Networks = map[string]docker.Endpoint{}
		for _, n := range networks {
			c.NetworkSettings.Networks[n] = docker.Endpoint{}
		}
		return c
	}
	for _, tc := range []struct {
		name, resolv string
		ctr          *docker.Container
		daemon       string // daemon.json
		direct, via  string
	}{
		{"--dns wins", "nameserver 10.0.0.53\n", ctr([]string{"9.9.9.9"}, "fw"), `{"dns": ["1.1.1.1"]}`, "[9.9.9.9]", "[]"},
		{"daemon.json next", "nameserver 10.0.0.53\n", ctr(nil, "fw"), `{"dns": ["1.1.1.1", "bad"]}`, "[1.1.1.1]", "[]"},
		{"host resolv.conf last", "nameserver 10.0.0.53\n", ctr(nil, "fw"), `{}`, "[10.0.0.53]", "[]"},
		{"unreadable daemon.json: host resolv.conf", "nameserver 10.0.0.53\n", ctr(nil, "fw"), `{"dns": [`, "[10.0.0.53]", "[]"},
		{"loopback stub: its upstreams, stub via host", "nameserver 127.0.0.53\n", ctr(nil, "fw"), ``, "[192.168.1.1 fe80::1]", "[127.0.0.53]"},
		{"default bridge falls back to Google", "nameserver 127.0.0.1\n", ctr([]string{"127.0.0.1"}, "bridge"), ``, "[8.8.8.8 8.8.4.4]", "[]"},
	} {
		write(hostResolvConf, tc.resolv)
		write(daemonJSON, tc.daemon)
		direct, via := upstreamDNS(tc.ctr, defaultDNS())
		if fmt.Sprint(direct) != tc.direct || fmt.Sprint(via) != tc.via {
			t.Errorf("%s: direct %v via host %v, want %s %s", tc.name, direct, via, tc.direct, tc.via)
		}
	}
}

// TestHoldUnlisted checks that a bridge Docker doesn't list stays blocked
// while a filtered network is missing, as it may be that network's.
func TestHoldUnlisted(t *testing.T) {
	br := func(i int, name string) netlink.Link { return netlink.Link{Index: i, Name: name, Kind: "bridge"} }
	world := func(missing bool) *world {
		w := &world{cfg: rules.Config{Networks: []string{"fw"}}, bridges: map[string]string{},
			open: []string{"docker0", "lxcbr0", "virbr1"}, unlisted: []netlink.Link{br(5, "lxcbr0"), br(6, "virbr1")}}
		if !missing {
			w.bridges["fw"] = "br-aaaaaaaaaaaa"
		}
		return w
	}
	w := world(true)
	cleared := w.holdUnlisted(map[int]bool{5: true})
	if !slices.Equal(w.open, []string{"docker0", "lxcbr0"}) || !slices.Equal(w.held, []string{"virbr1"}) {
		t.Errorf("fw missing: open %v held %v, want virbr1 held", w.open, w.held)
	}
	w = world(false)
	cleared = w.holdUnlisted(cleared)
	if len(w.open) != 3 || len(w.held) != 0 || !cleared[6] {
		t.Errorf("fw exists: open %v held %v, want all open", w.open, w.held)
	}
	w = world(true)
	w.unlisted[1].Index = 7 // virbr1 deleted and created again
	if w.holdUnlisted(cleared); !slices.Equal(w.held, []string{"virbr1"}) {
		t.Errorf("a recreated bridge: held %v, want it judged again", w.held)
	}
}

// TestLostSince checks which containers dfw run cuts after a restart: those
// whose sets lost anything, not those that kept or gained.
func TestLostSince(t *testing.T) {
	mac, _ := net.ParseMAC("02:42:0a:c9:fa:02")
	c := func(out ...string) nft.Container {
		var rs []rules.Range
		for _, a := range out {
			rs = append(rs, rules.AddrRange(netip.MustParseAddr(a)))
		}
		return nft.Container{ID: "0123456789abcdef0123456789abcdef", Out: rules.Allow{Any: rules.Normalize(rs)},
			Ports: []nft.Port{{Ifindex: 11, MAC: mac, IPv4: netip.MustParseAddr("10.0.0.2")}}}
	}
	prev := nft.Intended(nft.Ruleset{Containers: []nft.Container{c("1.1.1.1", "2.2.2.2")}})
	for _, tc := range []struct {
		c    nft.Container
		lost bool
	}{
		{c("1.1.1.1", "2.2.2.2"), false},
		{c("1.1.1.1", "2.2.2.2", "3.3.3.3"), false},
		{c("1.1.1.1"), true},
	} {
		if lostSince(prev, tc.c) != tc.lost {
			t.Errorf("out %v: lost = %v, want %v", tc.c.Out.Any, !tc.lost, tc.lost)
		}
	}
	other := c()
	other.ID = "fedcba9876543210fedcba9876543210"
	if lostSince(prev, other) {
		t.Errorf("a container new to the table has lost nothing")
	}
}

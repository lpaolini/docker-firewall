package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

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
	if !slices.Equal(w.unlisted, []string{"virbr0"}) {
		t.Errorf("unlisted = %v, want virbr0 only", w.unlisted)
	}
	if len(fw) != 1 || !fw[2] {
		t.Errorf("filtered bridges = %v, want index 2", fw)
	}
	if w.bridges["fw"] != "br-aaaaaaaaaaaa" || drivers["d0"] != "bridge" {
		t.Errorf("bridges = %v, drivers = %v", w.bridges, drivers)
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
		daemon       []string
		direct, via  string
	}{
		{"--dns wins", "nameserver 10.0.0.53\n", ctr([]string{"9.9.9.9"}, "fw"), []string{"1.1.1.1"}, "[9.9.9.9]", "[]"},
		{"daemon.json next", "nameserver 10.0.0.53\n", ctr(nil, "fw"), []string{"1.1.1.1", "bad"}, "[1.1.1.1]", "[]"},
		{"host resolv.conf last", "nameserver 10.0.0.53\n", ctr(nil, "fw"), nil, "[10.0.0.53]", "[]"},
		{"loopback stub: its upstreams, stub via host", "nameserver 127.0.0.53\n", ctr(nil, "fw"), nil, "[192.168.1.1 fe80::1]", "[127.0.0.53]"},
		{"default bridge falls back to Google", "nameserver 127.0.0.1\n", ctr([]string{"127.0.0.1"}, "bridge"), nil, "[8.8.8.8 8.8.4.4]", "[]"},
	} {
		write(hostResolvConf, tc.resolv)
		direct, via := upstreamDNS(tc.ctr, tc.daemon)
		if fmt.Sprint(direct) != tc.direct || fmt.Sprint(via) != tc.via {
			t.Errorf("%s: direct %v via host %v, want %s %s", tc.name, direct, via, tc.direct, tc.via)
		}
	}
}

// TestHoldUnlisted checks that a bridge Docker doesn't list opens only once it
// stays unlisted, as a filtered network's bridge may not be listed yet.
func TestHoldUnlisted(t *testing.T) {
	r := &runner{opened: map[string]time.Time{"lxcbr0": {}}}
	w := &world{open: []string{"docker0", "lxcbr0", "virbr1"}, unlisted: []string{"lxcbr0", "virbr1"}}
	if !r.holdUnlisted(w) || !slices.Equal(w.open, []string{"docker0", "lxcbr0"}) {
		t.Errorf("open = %v, want the new virbr1 held", w.open)
	}
	r.opened["virbr1"] = time.Now().Add(-unlistedWait)
	w = &world{open: []string{"docker0", "virbr1"}, unlisted: []string{"virbr1"}}
	if r.holdUnlisted(w) || !slices.Equal(w.open, []string{"docker0", "virbr1"}) {
		t.Errorf("open = %v, want virbr1 open once it stayed unlisted", w.open)
	}
	if _, ok := r.opened["lxcbr0"]; ok {
		t.Errorf("a bridge that is gone is still remembered")
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

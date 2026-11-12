package nft

import (
	"flag"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"dfw/internal/rules"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sample() Ruleset {
	mac, _ := net.ParseMAC("02:42:0a:c9:fa:02")
	mac2, _ := net.ParseMAC("02:42:0a:c9:fb:02")
	env := rules.Env{
		Peers: []rules.Peer{{Name: "p-b-1", Service: "b",
			Addrs: []netip.Addr{netip.MustParseAddr("10.201.250.3"), netip.MustParseAddr("fd00:250::3")}}},
		HostAddrs: []netip.Addr{netip.MustParseAddr("10.0.2.15")},
		Gateways:  []netip.Addr{netip.MustParseAddr("10.201.250.1"), netip.MustParseAddr("fd00:250::1")},
		DNS:       []netip.Addr{netip.MustParseAddr("10.0.2.3")},
	}
	out, _ := rules.Parse("[b]:5432, 10.10.20.20, internet, [2001:db8::/32]:443/tcp, 10.20.0.0/16:icmp")
	in, _ := rules.Parse("[b]:8080/tcp, host:80, lan:icmp")
	return Ruleset{Open: []string{"docker0", "br-0123456789ab"}, Blocked: []int{14}, Containers: []Container{
		{
			ID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Ports: []Port{
				{Ifindex: 11, MAC: mac, IPv4: netip.MustParseAddr("10.201.250.2"), IPv6: netip.MustParseAddr("fd00:250::2"),
					Subnet6: netip.MustParsePrefix("fd00:250::/64")},
				{Ifindex: 12, MAC: mac2, IPv4: netip.MustParseAddr("10.201.251.2")},
			},
			In: rules.Resolve(in, env, false), Out: rules.Resolve(out, env, true),
		},
		{
			ID:    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			Ports: []Port{{Ifindex: 13, MAC: mac, IPv4: netip.MustParseAddr("10.201.250.9")}},
		},
	}, Peers: []netip.Addr{
		netip.MustParseAddr("10.201.250.2"), netip.MustParseAddr("fd00:250::2"), netip.MustParseAddr("10.201.251.2"),
		netip.MustParseAddr("10.201.250.9"), netip.MustParseAddr("10.201.250.3"), netip.MustParseAddr("fd00:250::3"),
	}}
}

func TestRenderGolden(t *testing.T) {
	for name, tb := range map[string]Ruleset{"base": {}, "sample": sample()} {
		got := Render(tb)
		path := "testdata/" + name + ".nft"
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s: Render differs from %s (run go test -update to accept):\n%s", name, path, got)
		}
		// The generated text must be valid for the real nft, when available.
		if os.Geteuid() == 0 {
			if _, err := os.Stat(Path); err == nil {
				if err := Check(got); err != nil {
					t.Errorf("%s: nft --check: %v", name, err)
				}
			}
		}
	}
}

// TestApplyAndVerify loads the sample into the kernel and reads it back.
// It changes the host's ruleset, so it runs only with DFW_TEST_APPLY=1 on
// a disposable machine.
func TestApplyAndVerify(t *testing.T) {
	if os.Getenv("DFW_TEST_APPLY") != "1" {
		t.Skip("set DFW_TEST_APPLY=1 to load rules into the kernel")
	}
	defer Delete()
	cs := sample()
	if err := Apply(Render(cs)); err != nil {
		t.Fatal(err)
	}
	// nft prints an index as the name of the host interface that has it,
	// as dfw run's callers map back through netlink.
	st, err := List(hostIfnames(t))
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(Intended(cs), st); d != "" {
		t.Fatalf("kernel differs from intent: %s", d)
	}
	// Changing one element must show up as a difference.
	if d := Diff(Intended(Ruleset{Open: cs.Open[1:], Blocked: cs.Blocked, Containers: cs.Containers}), st); d == "" {
		t.Fatal("Diff missed a changed bridge set")
	}
	cs.Containers[0].Out.Any = cs.Containers[0].Out.Any[1:]
	if d := Diff(Intended(cs), st); d == "" {
		t.Fatal("Diff missed a changed set")
	}
	fp := st.Rules
	if err := Apply("add rule bridge fw from_container accept\n"); err != nil {
		t.Fatal(err)
	}
	st2, _ := List(hostIfnames(t))
	if st2.Rules == fp || Diff(Intended(sample()), st2) == "" {
		t.Fatal("an added rule was not detected")
	}
}

// TestMissingErrors reads nft's errors as a Raspberry Pi OS 6.18 kernel gives
// them, from a stand-in nft, and treats any other failure as an error.
func TestMissingErrors(t *testing.T) {
	defer func(p string) { Path = p }(Path)
	fake := func(script string) {
		Path = t.TempDir() + "/nft"
		if err := os.WriteFile(Path, []byte("#!/bin/sh\nin=$(cat)\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake(`case "$in" in
*ibrname*) echo 'Error: Could not process rule: Operation not supported' >&2; exit 1;;
*"ct state"*) echo 'Error: Could not process rule: Protocol error' >&2; exit 1;;
esac
`)
	miss, err := Missing()
	if err != nil || len(miss) != 2 || miss[0].Name != "nft_meta_bridge" || miss[1].Name != "nf_conntrack_bridge" {
		t.Fatalf("got %v, %v; want both modules missing", miss, err)
	}
	fake("echo 'Error: Could not process rule: Operation not permitted' >&2; exit 1\n")
	if miss, err := Missing(); err == nil {
		t.Fatalf("got %v and no error for a failure that isn't a missing module", miss)
	}
}

// TestMissing probes the kernel, which must have every module (Debian's and
// Ubuntu's do). It runs with the other kernel tests.
func TestMissing(t *testing.T) {
	if os.Getenv("DFW_TEST_APPLY") != "1" {
		t.Skip("set DFW_TEST_APPLY=1 to probe the kernel")
	}
	miss, err := Missing()
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) > 0 {
		t.Fatalf("kernel lacks %v", miss)
	}
}

func hostIfnames(t *testing.T) map[string]int {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int{}
	for _, i := range ifs {
		m[i.Name] = i.Index
	}
	return m
}

func TestValidID(t *testing.T) {
	for id, ok := range map[string]bool{
		"0123456789abcdef":  true,
		"0123456789abcde":   false,
		"0123456789ABCDEF":  false,
		"0123456789abcdeg0": false,
		"0123456789abcd;f":  false,
	} {
		if ValidID(id) != ok {
			t.Errorf("ValidID(%q) = %v", id, !ok)
		}
	}
}

func TestValidIfname(t *testing.T) {
	for name, ok := range map[string]bool{
		"docker0": true, "br-0123456789ab": true, "cni-podman0": true, "": false,
		"0123456789abcdef": false, `a"b`: false, "a b": false, "a}": false,
	} {
		if ValidIfname(name) != ok {
			t.Errorf("ValidIfname(%q) = %v", name, !ok)
		}
	}
	// Unsafe names are left out, so their bridge stays blocked.
	if r := Render(Ruleset{Open: []string{`x" accept`}}); strings.Contains(r, "accept\"") {
		t.Errorf("unsafe name rendered:\n%s", r)
	}
}

func TestLinkLocal(t *testing.T) {
	mac, _ := net.ParseMAC("02:42:0a:d2:00:05")
	if got := LinkLocal(mac).String(); got != "fe80::42:aff:fed2:5" {
		t.Errorf("LinkLocal = %s", got)
	}
}

// Check validates ruleset text without applying it.
func Check(text string) error {
	_, err := run(text, "--check", "-f", "-")
	return err
}

// TestParseState checks that a real nft listing of the sample (recorded with
// nft 1.1.3: unshare -rn sh -c 'nft -f testdata/sample.nft &&
// nft -j list table bridge fw') reads back as intended, without root.
func TestParseState(t *testing.T) {
	js, err := os.ReadFile("testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := parseState(js, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(Intended(sample()), st); d != "" {
		t.Fatalf("listing differs from intent: %s", d)
	}
	changed := sample()
	changed.Containers[0].Out.Any = changed.Containers[0].Out.Any[1:]
	if Diff(Intended(changed), st) == "" {
		t.Fatal("Diff missed a changed set")
	}
}

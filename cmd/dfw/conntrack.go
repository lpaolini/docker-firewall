package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"

	"dfw/internal/nft"
	"dfw/internal/rules"
)

// conntrackPath is never looked up in $PATH.
var conntrackPath = "/usr/sbin/conntrack"

// ctDelete runs conntrack -D with the given filters. Finding nothing to
// delete is not an error.
func ctDelete(a netip.Addr, filters ...string) error {
	fam := "ipv4"
	if a.Is6() {
		fam = "ipv6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, conntrackPath, append([]string{"-D", "-f", fam}, filters...)...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), " 0 flow entries") {
		return fmt.Errorf("conntrack -D %s: %v: %s", strings.Join(filters, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cutAddr deletes every tracked connection to or from a.
func cutAddr(a netip.Addr) error {
	var first error
	for _, f := range []string{"--orig-src", "--orig-dst", "--reply-src", "--reply-dst"} {
		if err := ctDelete(a, f, a.String()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// cutPair deletes tracked connections between a and b in either direction.
func cutPair(a, b netip.Addr) error {
	var first error
	x, y := a.String(), b.String()
	for _, f := range [][]string{
		{"--orig-src", x, "--orig-dst", y}, {"--orig-src", y, "--orig-dst", x},
		{"--reply-src", x, "--reply-dst", y}, {"--reply-src", y, "--reply-dst", x},
	} {
		if err := ctDelete(a, f...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// cutRefused deletes every connection marked as refused (nft.Denied).
func cutRefused() error {
	var first error
	for _, a := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		if err := ctDelete(a, "--mark", nft.Denied+"/"+nft.Denied); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		logf("error: %v; will retry", first)
	}
	return first
}

// cut deletes a's connections, and retries later if that fails.
func (r *runner) cut(a netip.Addr) {
	if err := cutAddr(a); err != nil {
		logf("error: %v; will retry", err)
		r.pending[a] = true
	}
}

func portAddrs(c nft.Container) []netip.Addr {
	var out []netip.Addr
	for _, p := range c.Ports {
		for _, a := range []netip.Addr{p.IPv4, p.IPv6} {
			if a.IsValid() {
				out = append(out, a)
			}
		}
	}
	return out
}

// cutRevoked deletes connections that old allowed and new doesn't. Where a
// single peer address was removed only that pair is cut; for anything wider,
// or if that fails, all of the container's connections are cut, and allowed
// ones reconnect.
func (r *runner) cutRevoked(old, new nft.Container) {
	lost := rules.Normalize(append(rules.Removed(old.Out, new.Out), rules.Removed(old.In, new.In)...))
	if len(lost) == 0 {
		return
	}
	own := portAddrs(new)
	// Only addresses of a family the container has can be its peers.
	lost = slices.DeleteFunc(lost, func(x rules.Range) bool {
		return !slices.ContainsFunc(own, func(a netip.Addr) bool { return a.Is4() == x.Is4() })
	})
	all := slices.ContainsFunc(lost, func(x rules.Range) bool { return x.Lo != x.Hi })
	for _, x := range lost {
		for _, a := range own {
			if !all && a.Is4() == x.Is4() && cutPair(a, x.Lo) != nil {
				all = true
			}
		}
	}
	if all {
		for _, a := range own {
			r.cut(a)
		}
	}
}

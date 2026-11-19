package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"dfw/internal/docker"
	"dfw/internal/nft"
	"dfw/internal/rules"
)

// testWorld puts running containers, given as "name@network@address", in a
// world under the rules text. A container counts as filtered only on the
// networks the rules name, as gather sees it.
func testWorld(text string, ctrs ...string) *world {
	cfg := rules.ParseConfig([]rules.File{{Name: "rules", Text: text}})
	w := &world{cfg: cfg}
	for i, s := range ctrs {
		f := strings.Split(s, "@")
		a := netip.MustParseAddr(f[2])
		info := &docker.Container{ID: fmt.Sprintf("%016x", i+1) + strings.Repeat("0", 48)}
		info.NetworkSettings.Networks = map[string]docker.Endpoint{f[1]: {IPAddress: a.String()}}
		filtered := false
		for _, n := range cfg.Networks {
			filtered = filtered || n == f[1]
		}
		if !filtered {
			continue
		}
		c := &ctr{info: info, name: f[0], addrs: []netip.Addr{a}, ports: []nft.Port{{Ifindex: 10 + i, IPv4: a}}}
		c.in, c.out = cfg.For(c.name, "")
		w.ctrs = append(w.ctrs, c)
	}
	return w
}

func TestDiff(t *testing.T) {
	ctrs := []string{"proxy@web@10.0.0.2", "api@web@10.0.0.3", "db@web@10.0.0.4", "metrics@admin@10.1.0.2", "idle@web@10.0.0.5"}
	was := testWorld(`network web
allow internet -> [proxy]:443/tcp
allow [proxy] -> [api]:3000/tcp
allow [api] -> [db]:5432/tcp, 10.10.20.20:8443/tcp
allow 10.10.30.0/24 -> [db]:5432/tcp
`, ctrs...)
	now := testWorld(`network web
network admin
allow internet -> [proxy]:443/tcp
allow [proxy] -> [api]:3000/tcp
allow [api] -> [db]:5432/tcp, 10.10.20.21:8443/tcp
allow [metrics] -> [api]:9100/tcp
allow 10.10.30.0/24 -> [proxy]:22/tcp
`, ctrs...)
	want := `+ network admin

[api]
  + in  [metrics]      9100/tcp
  - out 10.10.20.20    8443/tcp
  + out 10.10.20.21    8443/tcp

[db]
  - in  10.10.30.0/24  5432/tcp

[metrics]
  + out [api]          9100/tcp

[proxy]
  + in  10.10.30.0/24  22/tcp

4 containers change
`
	if got := diff(was, now); got != want {
		t.Errorf("diff =\n%s\nwant\n%s", got, want)
	}

	back := `- network admin

[api]
  - in  [metrics]      9100/tcp
  - out 10.10.20.21    8443/tcp
  + out 10.10.20.20    8443/tcp

[db]
  + in  10.10.30.0/24  5432/tcp

[metrics]
  - out [api]          9100/tcp

[proxy]
  - in  10.10.30.0/24  22/tcp

4 containers change
`
	if got := diff(now, was); got != back {
		t.Errorf("diff back =\n%s\nwant\n%s", got, back)
	}
	if got := diff(now, now); got != "no running container's rules change\n" {
		t.Errorf("no change: %q", got)
	}
	// A container that started between the two reads is no change.
	later := testWorld(`network web
allow [late] -> internet
`, append(ctrs, "late@web@10.0.0.9")...)
	if got := diff(testWorld("network web\nallow [late] -> internet\n", ctrs...), later); got != "no running container's rules change\n" {
		t.Errorf("a container started meanwhile: %q", got)
	}
}

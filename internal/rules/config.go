package rules

import (
	"fmt"
	"slices"
	"strings"
)

// Config is the parsed rules: which networks dfw filters, and what may pass.
type Config struct {
	Networks []string // sorted, no duplicates
	Rules    []Rule
	Errors   []string // "file:line: message"; such a line grants nothing
}

// Rule is one allow line: traffic from any of From to any of To.
type Rule struct {
	Pos      string // file:line
	From, To []Entry
}

// File is one rules file's name and contents.
type File struct {
	Name, Text string
}

// ParseConfig parses rules files, in order, as one configuration:
//
//	network NAME                (one or more)
//	allow SOURCE[, SOURCE...] -> DESTINATION[:PORT[/PROTO]|:icmp][, ...]
//
// "#" starts a comment. A line with an error is skipped and reported.
func ParseConfig(files []File) Config {
	var c Config
	for _, f := range files {
		for i, line := range strings.Split(f.Text, "\n") {
			c.parseLine(fmt.Sprintf("%s:%d", f.Name, i+1), line)
		}
	}
	slices.Sort(c.Networks)
	c.Networks = slices.Compact(c.Networks)
	if len(c.Networks) == 0 {
		c.Errors = append(c.Errors, "no \"network NAME\" line: dfw doesn't know which network to filter")
	}
	return c
}

func (c *Config) parseLine(pos, line string) {
	fail := func(format string, a ...any) {
		c.Errors = append(c.Errors, pos+": "+fmt.Sprintf(format, a...))
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	words := strings.Fields(line)
	if len(words) == 0 {
		return
	}
	switch words[0] {
	case "network":
		if len(words) != 2 || !validName(words[1]) {
			fail("expected: network NAME")
		} else {
			c.Networks = append(c.Networks, words[1])
		}
	case "allow":
		src, dst, ok := strings.Cut(line[len("allow"):], "->")
		if !ok {
			fail("expected: allow SOURCE -> DESTINATION[:PORT[/PROTO]]")
			return
		}
		from, err := Parse(src)
		if err != nil {
			fail("source %v", err)
			return
		}
		to, err := Parse(dst)
		if err != nil {
			fail("destination %v", err)
			return
		}
		if len(from) == 0 || len(to) == 0 {
			fail("expected: allow SOURCE -> DESTINATION[:PORT[/PROTO]]")
			return
		}
		for _, f := range from {
			switch {
			case len(f.Protos) != 0:
				fail("source %s: the port or protocol belongs to the destination", f)
				return
			case f.Zone == ZoneDNS:
				fail("dns can only be a destination")
				return
			}
			for _, t := range to {
				if f.Name == "" && t.Name == "" {
					fail("%s -> %s: one side must be a container", f, t)
					return
				}
			}
		}
		c.Rules = append(c.Rules, Rule{Pos: pos, From: from, To: to})
	default:
		fail("unknown statement %q: expected network or allow", words[0])
	}
}

// For returns what the rules let a container with this name and compose
// service accept (in) and send (out). Inbound entries carry the
// container's own port.
func (c Config) For(name, service string) (in, out []Entry) {
	for _, r := range c.Rules {
		for _, f := range r.From {
			for _, t := range r.To {
				if f.Matches(name, service) {
					out = append(out, t)
				}
				if t.Matches(name, service) {
					e := f
					e.Port, e.Protos = t.Port, t.Protos
					in = append(in, e)
				}
			}
		}
	}
	return in, out
}

// Names returns every container name the rules mention, with the position
// of its first use.
func (c Config) Names() map[string]string {
	m := map[string]string{}
	for _, r := range c.Rules {
		for _, e := range append(append([]Entry{}, r.From...), r.To...) {
			if _, ok := m[e.Name]; e.Name != "" && !ok {
				m[e.Name] = r.Pos
			}
		}
	}
	return m
}

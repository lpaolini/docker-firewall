package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"dfw/internal/docker"
	"dfw/internal/rules"
)

// cmdDiff shows what dfw apply would change: how the rules being edited (or
// file) differ from the active ones in what they give each running
// container. Changes nothing.
func cmdDiff(file string) error {
	if !isActive() {
		return errors.New("dfw is not enabled, so no rules are in force; dfw check shows what dfw enable would apply")
	}
	old, _, err := loadActive()
	if err != nil {
		return fmt.Errorf("can't read the active rules: %w", err)
	}
	for _, e := range old.Errors { // only if a dfw version that read them differently applied them
		fmt.Printf("warning: the active rules: %s\n", e)
	}
	files, err := readRules(file)
	if err != nil {
		return err
	}
	cfg := rules.ParseConfig(files)
	if len(cfg.Errors) > 0 {
		for _, e := range cfg.Errors {
			fmt.Printf("ERROR %s\n", e)
		}
		return fmt.Errorf("the rules have %d errors, which dfw apply refuses", len(cfg.Errors))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dc := docker.New(dockerSock)
	was, err := gather(ctx, dc, old, nil)
	if err != nil {
		return err
	}
	now, err := gather(ctx, dc, cfg, was.byID())
	if err != nil {
		return err
	}
	fmt.Print(diff(was, now))
	return nil
}

func (w *world) byID() map[string]*ctr {
	m := map[string]*ctr{}
	for _, c := range w.ctrs {
		m[c.info.ID] = c
	}
	return m
}

// diff describes what changes from world was (the active rules) to now (the
// edited ones), both read from the same Docker. A container filtered under
// only one of them gets all its rules added or removed.
func diff(was, now *world) string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	for _, n := range was.cfg.Networks {
		if !slices.Contains(now.cfg.Networks, n) {
			p("- network %s\n", n)
		}
	}
	for _, n := range now.cfg.Networks {
		if !slices.Contains(was.cfg.Networks, n) {
			p("+ network %s\n", n)
		}
	}
	before, after := was.byID(), now.byID()
	all := slices.Clone(now.ctrs)
	for id, c := range before {
		if after[id] == nil {
			all = append(all, c)
		}
	}
	slices.SortFunc(all, func(a, b *ctr) int { return strings.Compare(a.name, b.name) })
	width := 0
	for _, w := range []*world{was, now} {
		for _, c := range w.ctrs {
			for _, e := range append(slices.Clone(c.in), c.out...) {
				peer, _ := peerPort(e)
				width = max(width, len(peer))
			}
		}
	}
	changed := 0
	for _, c := range all {
		o, n := before[c.info.ID], after[c.info.ID]
		// Missing from a read under rules that filter its network: it
		// started or stopped between the two reads.
		if o == nil && onAny(c, was.cfg.Networks) || n == nil && onAny(c, now.cfg.Networks) {
			continue
		}
		if o == nil {
			o = &ctr{}
		}
		if n == nil {
			n = &ctr{}
		}
		var body string
		for _, x := range []struct {
			dir      string
			was, now []rules.Entry
		}{{"in", o.in, n.in}, {"out", o.out, n.out}} {
			for _, sign := range []string{"-", "+"} {
				es := lines(x.now, x.was)
				if sign == "+" {
					es = lines(x.was, x.now)
				}
				for _, e := range es {
					peer, port := peerPort(e)
					body += fmt.Sprintf("  %s %-3s %-*s  %s\n", sign, x.dir, width, peer, port)
				}
			}
		}
		if body != "" {
			changed++
			p("\n[%s]\n%s", c.name, body)
		}
	}
	switch changed {
	case 0:
		p("\nno running container's rules change\n")
	case 1:
		p("\n1 container changes\n")
	default:
		p("\n%d containers change\n", changed)
	}
	return strings.TrimPrefix(b.String(), "\n")
}

// lines returns the entries of es not in except, each once, as check shows
// them: by the other end and the port.
func lines(except, es []rules.Entry) []rules.Entry {
	key := func(e rules.Entry) string {
		peer, port := peerPort(e)
		return peer + " " + port
	}
	skip := map[string]bool{}
	for _, e := range except {
		skip[key(e)] = true
	}
	var out []rules.Entry
	for _, e := range es {
		if k := key(e); !skip[k] {
			skip[k] = true
			out = append(out, e)
		}
	}
	return out
}

// onAny reports whether c is on any of the networks.
func onAny(c *ctr, networks []string) bool {
	for n := range c.info.NetworkSettings.Networks {
		if slices.Contains(networks, n) {
			return true
		}
	}
	return false
}

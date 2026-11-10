package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dfw/internal/docker"
	"dfw/internal/netlink"
	"dfw/internal/nft"
	"dfw/internal/rules"
)

const (
	reconcileEvery = 30 * time.Second
	restoreGap     = time.Second // minimum time between repeated repairs
	retryAfter     = 2 * time.Second
)

type runner struct {
	dc      *docker.Client
	cfg     *rules.Config            // rules in use; nil until the active rules were read
	cfgHash string                   // hash of the active rules in cfg
	applied map[string]nft.Container // by container ID
	cutAll  bool                     // cut every container's connections after the next apply
	prev    *nft.State               // the table dfw run started with, until the first apply
	cleared map[int]bool             // unlisted bridges known not to be a filtered network's
	unmark  bool                     // refused connections still need deleting
	rs      nft.Ruleset              // as last applied
	text    string                   // ruleset text last applied
	fp      string                   // rule fingerprint after the last apply
	ok      bool                     // the kernel matched rs after the last apply
	known   map[int]bool             // veths that have had rules
	pending map[netip.Addr]bool      // addresses whose connections still need cutting
	logged  map[string]bool          // warnings logged, to log only new ones
	strays  map[int]time.Time        // filtered-bridge ports with no container: first seen
	lastFix time.Time
}

func cmdRun() error {
	// If the active rules were never confirmed (an earlier dfw run or dfw
	// enable stopped before its cuts were done), the table may allow
	// connections they don't: cut them all once the rules are in, and allowed
	// ones reconnect.
	_, hash, err := loadActive()
	cutAll := err != nil || readApplied() != hash
	// At start, the rules being edited are applied if they are valid. After
	// that, only dfw apply changes them.
	if errs := refreshActive(); len(errs) > 0 {
		for _, e := range errs {
			logf("error: rules: %s", e)
		}
		logf("error: the rules in %s have errors, so the rules last applied are used", filepath.Dir(rulesPath))
	}
	dc := docker.New(dockerSock)
	r := &runner{dc: dc, applied: map[string]nft.Container{}, known: map[int]bool{},
		logged: map[string]bool{}, strays: map[int]time.Time{}, pending: map[netip.Addr]bool{},
		cutAll: cutAll, cleared: map[int]bool{}}

	// Veths already in the table were filtered by an earlier dfw run, so their
	// connections were allowed by the table then; the first apply cuts those
	// of containers whose sets lost anything since (edited rules, a renamed
	// peer, a changed address). Any other veth is new to the rules.
	links, err := netlink.Links(-1)
	if err != nil {
		return err
	}
	st, err := nft.List(ifnames(links))
	switch {
	case errors.Is(err, nft.ErrNoTable):
		// Nothing was filtered meanwhile: cut whatever started then.
		logf("warning: the table is missing; dfw init should have created it. Creating it now with every container blocked")
		r.cutAll = true
		if err := nft.Apply(nft.Render(bootRuleset())); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		r.prev = st
		for _, l := range links {
			if slices.Contains(st.Sets["open_bridges"], `"`+l.Name+`"`) {
				r.cleared[l.Index] = true // open already
			}
		}
		for _, e := range st.Sets["out_by_port"] {
			if f := strings.Fields(e); len(f) == 4 && f[2] == "jump" {
				if i, err := strconv.Atoi(f[0]); err == nil {
					r.known[i] = true
				}
			}
		}
	}

	poke := make(chan struct{}, 1)
	notify := func() {
		select {
		case poke <- struct{}{}:
		default:
		}
	}
	nftChanged := make(chan struct{}, 1)
	go func() {
		err := netlink.WatchNftables(nft.Table, func() {
			select {
			case nftChanged <- struct{}{}:
			default:
			}
		})
		logf("error: nftables watch stopped: %v; relying on the %v reconcile", err, reconcileEvery)
	}()
	go func() {
		err := netlink.WatchBridges(notify)
		logf("error: bridge watch stopped: %v; new bridges stay blocked until the %v reconcile", err, reconcileEvery)
	}()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			notify()
		}
	}()

	if v, err := dc.Version(context.Background()); err == nil {
		checkDockerVersion(v.Version)
	}
	logf("dfw run started")

	var events chan docker.Event
	tick := time.NewTicker(reconcileEvery)
	retry := time.NewTimer(retryAfter)
	retry.Stop()
	var recheck <-chan time.Time
	for {
		if events == nil {
			ch := make(chan docker.Event, 64)
			if err := dc.Events(context.Background(), ch); err != nil {
				logf("error: %v; retrying", err)
				retry.Reset(retryAfter)
			} else {
				events = ch
				if r.reconcile() { // catch up on anything missed while disconnected
					retry.Reset(retryAfter)
				}
			}
		}
		select {
		case _, open := <-events:
			if !open {
				logf("warning: Docker event stream ended; reconnecting")
				events = nil
				continue
			}
			// Coalesce a burst of events into one reconcile.
			for drained := false; !drained; {
				select {
				case _, open = <-events:
					if !open {
						events, drained = nil, true
					}
				default:
					drained = true
				}
			}
			if r.reconcile() {
				retry.Reset(retryAfter)
			}
		case <-poke:
			if r.reconcile() {
				retry.Reset(retryAfter)
			}
		case <-nftChanged:
			if wait := restoreGap - time.Since(r.lastFix); wait > 0 {
				recheck = time.After(wait)
				continue
			}
			r.check()
		case <-recheck:
			recheck = nil
			r.check()
		case <-tick.C:
			if r.reconcile() {
				retry.Reset(retryAfter)
			}
			r.check()
		case <-retry.C:
			if events != nil && r.reconcile() {
				retry.Reset(retryAfter)
			}
		}
	}
}

// config reads the active rules, the ones last validated. If they
// can't be read, the rules last read keep applying. It returns nil while no
// rules were ever read.
func (r *runner) config() *rules.Config {
	cfg, hash, err := loadActive()
	switch {
	case err != nil && r.cfg != nil:
		logf("error: can't read the active rules (%v); the rules last read still apply", err)
	case err != nil:
		logf("error: can't read the active rules (%v); fix %s and run dfw apply", err, rulesPath)
	case len(cfg.Errors) > 0: // also when it names no network
		// dfw never saves such rules; someone edited the copy.
		logf("error: the active rules in %s are not valid (%s); the rules last read still apply", activeFile, strings.Join(cfg.Errors, "; "))
	default:
		r.cfg, r.cfgHash = &cfg, hash
	}
	return r.cfg
}

// markApplied tells dfw apply that the active rules are in force: in the
// table, with every connection that lost its permission cut.
// It rewrites the file whenever it differs, since it is deleted before each
// change to the table.
func (r *runner) markApplied() {
	if r.busy() || r.cfgHash == "" || !r.ok {
		return
	}
	if err := writeAtomic(appliedFile, []byte(r.cfgHash+"\n")); err != nil {
		logf("warning: can't record that the rules are applied: %v", err)
	}
}

// busy reports whether connections still need cutting.
func (r *runner) busy() bool { return len(r.pending) > 0 || r.unmark }

// reconcile brings the table in line with the rules and Docker. It returns
// true when something failed that should be retried soon.
func (r *runner) reconcile() (retry bool) {
	for a := range r.pending {
		if err := cutAddr(a); err == nil {
			delete(r.pending, a)
		}
	}
	if r.unmark {
		r.unmark = cutRefused() != nil
	}
	cfg := r.config()
	if cfg == nil {
		logf("error: no active rules, so the table is left as it is")
		return true
	}
	w, err := gather(context.Background(), r.dc, *cfg)
	if err != nil {
		logf("error: can't read Docker, keeping the current rules: %v", err)
		return true
	}
	r.cleared = w.holdUnlisted(r.cleared)
	r.report(w)
	rs := w.ruleset()
	// A veth new to the rules may have an IP whose old connections are still
	// tracked. Cut them while it is still blocked, so none can be reused; if
	// that fails, it stays blocked and is retried.
	ready := rs.Containers[:0:0]
	for _, c := range rs.Containers {
		ok := true
		for _, p := range c.Ports {
			if !r.known[p.Ifindex] {
				for _, a := range []netip.Addr{p.IPv4, p.IPv6} {
					if a.IsValid() {
						if err := cutAddr(a); err != nil {
							logf("error: %v; container %.12s stays blocked until it succeeds", err, c.ID)
							ok, retry = false, true
						}
					}
				}
			}
		}
		if ok {
			ready = append(ready, c)
		}
	}
	rs.Containers = ready
	text := nft.Render(rs)
	if text == r.text && r.ok {
		r.markApplied()
		return retry || r.busy()
	}
	// The new table may revoke permissions whose connections are cut only
	// after it is in. Until then, the rules must not count as confirmed, so
	// that a dfw run restarting in between cuts everything.
	if err := os.Remove(appliedFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("error: can't clear the confirmation, so the previous rules stay in force: %v", err)
		return true
	}
	start := time.Now()
	switch loaded, err := r.apply(text, rs); {
	case !loaded:
		logf("error: applying rules failed; the previous rules stay in force, and new containers stay blocked, until the next try: %v", err)
		return true
	case err != nil:
		// The new table is in force, so its revocations are cut below.
		logf("error: the rules were loaded, but the table doesn't read back as intended; retrying: %v", err)
		retry = true
	default:
		logf("rules applied for %d containers on networks %s in %v", len(rs.Containers), strings.Join(cfg.Networks, ", "), time.Since(start).Round(time.Millisecond))
	}
	if err := saveOpen(cfg.Networks, rs.Open); err != nil {
		logf("warning: can't record the open bridges for the next boot: %v", err)
	}
	next, known := map[string]nft.Container{}, map[int]bool{}
	for _, c := range rs.Containers {
		next[c.ID] = c
		for _, p := range c.Ports {
			known[p.Ifindex] = true
		}
	}
	r.known = known
	for id, old := range r.applied {
		if c, ok := next[id]; ok {
			r.cutRevoked(old, c)
		} else {
			for _, a := range portAddrs(old) {
				r.cut(a)
			}
		}
	}
	for _, c := range next {
		if r.cutAll || r.prev != nil && lostSince(r.prev, c) {
			for _, a := range portAddrs(c) {
				r.cut(a)
			}
		}
	}
	r.cutAll, r.prev = false, nil
	// A refused connection stays marked, and dropped, for as long as it is
	// tracked. Delete those, so that ones the new table allows can start; the
	// others are refused and marked again.
	r.unmark = cutRefused() != nil
	r.applied = next
	r.markApplied()
	return retry || r.busy()
}

// lostSince reports whether c's sets in the table prev lack anything they
// held there. An element is a whole range, so a range merely widened counts
// as lost too, which only cuts more than needed.
func lostSince(prev *nft.State, c nft.Container) bool {
	k := nft.Key(c.ID) + "_"
	for name, els := range nft.Intended(nft.Ruleset{Containers: []nft.Container{c}}).Sets {
		if !strings.HasPrefix(name, k) {
			continue
		}
		for _, e := range prev.Sets[name] {
			if !slices.Contains(els, e) {
				return true
			}
		}
	}
	return false
}

// apply loads text and confirms the kernel holds what was intended. loaded
// reports whether the table was replaced, even if the check then failed.
func (r *runner) apply(text string, rs nft.Ruleset) (loaded bool, err error) {
	r.ok = false
	r.lastFix = time.Now()
	if err := nft.Apply(text); err != nil {
		return false, err
	}
	r.text, r.rs = text, rs
	st, err := verify(rs)
	if err != nil {
		return true, err
	}
	r.fp, r.ok = st.Rules, true
	return true, nil
}

// check repairs the table if anything but dfw changed it.
func (r *runner) check() {
	links, err := netlink.Links(-1)
	if err != nil {
		logf("error: %v", err)
		return
	}
	st, err := nft.List(ifnames(links))
	why := ""
	switch {
	case errors.Is(err, nft.ErrNoTable) && r.text == "":
		// No rules computed yet (no rules or Docker unreachable). Connections
		// may have started while the table was gone: the first apply cuts them.
		logf("warning: the table was deleted; restoring it with every container blocked until dfw can compute the rules")
		r.cutAll = true
		boot := bootRuleset()
		if _, err := r.apply(nft.Render(boot), boot); err != nil {
			logf("error: restoring the table failed: %v", err)
		}
		r.text = "" // still nothing computed
		return
	case r.text == "":
		return
	case errors.Is(err, nft.ErrNoTable):
		why = "the table was deleted"
	case err != nil:
		logf("error: %v", err)
		return
	default:
		if d := nft.Diff(nft.Intended(r.rs), st); d != "" {
			why = d
		} else if st.Rules != r.fp && r.ok {
			why = "rules were changed"
		}
	}
	if why == "" {
		return
	}
	logf("warning: table changed outside dfw (%s); restoring it", why)
	// While the table was gone or changed, connections the rules don't allow
	// may have started, and once it is back they pass as established: cut
	// every container's, and allowed ones reconnect. Not when the last apply
	// didn't read back as intended, since the difference may then be dfw's
	// own and every check would cut everything. Until the cuts are done, the
	// rules don't count as confirmed, so a restart in between cuts them.
	if r.ok || errors.Is(err, nft.ErrNoTable) {
		r.cutAll = true
		if err := os.Remove(appliedFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			logf("error: can't clear the confirmation: %v", err)
		}
	}
	loaded, err := r.apply(r.text, r.rs)
	if err != nil {
		logf("error: restoring the table failed: %v", err)
	}
	if loaded && r.cutAll {
		for _, c := range r.applied {
			for _, a := range portAddrs(c) {
				r.cut(a)
			}
		}
		r.cutAll = false
		r.markApplied()
	}
}

// report logs problems: errors on every reconcile, so they are never
// silent; warnings once, when they first appear.
func (r *runner) report(w *world) {
	now := map[string]bool{}
	warn := func(format string, a ...any) {
		msg := fmt.Sprintf("warning: "+format, a...)
		if now[msg] = true; !r.logged[msg] {
			logf("%s", msg)
		}
	}
	for _, n := range w.missing() {
		warn("network %s doesn't exist; its containers will be filtered once it does", n)
	}
	for _, b := range w.held {
		warn("bridge %s is blocked until every filtered network exists, since it may be one's", b)
	}
	for _, p := range w.problems {
		logf("error: %s", p)
	}
	for _, c := range w.ctrs {
		for _, e := range c.errors {
			logf("error: container %s: %s", c.name, e)
		}
		for _, e := range c.warnings {
			warn("container %s: %s", c.name, e)
		}
	}
	for _, u := range w.unmatched() {
		warn("rules: %s", u)
	}
	// A starting container's veth briefly has no container behind it.
	seen := map[int]time.Time{}
	for _, l := range w.unknown {
		first, ok := r.strays[l.Index]
		if !ok {
			first = time.Now()
		}
		seen[l.Index] = first
		if time.Since(first) > 10*time.Second {
			warn("port %s (index %d) of a filtered network has no container behind it and is blocked", l.Name, l.Index)
		}
	}
	r.strays, r.logged = seen, now
}

// Docker major versions the gate test passed on.
var gateTested = []string{"26", "29"}

func checkDockerVersion(v string) {
	major, _, _ := strings.Cut(v, ".")
	if !slices.Contains(gateTested, major) {
		logf("warning: Docker %s has not been gate-tested (tested majors: %s)", v, strings.Join(gateTested, ", "))
	}
}

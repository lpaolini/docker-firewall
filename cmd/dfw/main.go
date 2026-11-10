// Command dfw filters the traffic of the containers on chosen Docker networks,
// with allow rules from /etc/dfw/rules. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"dfw/internal/docker"
	"dfw/internal/netlink"
	"dfw/internal/nft"
	"dfw/internal/rules"
)

var (
	version    = "dev"
	dockerSock = "/var/run/docker.sock"
	dropIn     = "/etc/systemd/system/docker.service.d/dfw.conf"
	systemctl  = "/usr/bin/systemctl"
)

const dropInText = `# Written by "dfw enable"; removed by "dfw disable".
# Loads dfw's base table before Docker starts, so no container is ever
# unfiltered. If it fails, Docker does not start.
[Unit]
After=nftables.service

[Service]
ExecStartPre=/usr/sbin/dfw init
`

const usage = `usage: dfw <command>

  check [FILE]   check the rules in a specified file or all
  apply          apply all rules
  enable         start filtering
  disable        stop filtering
  version        print the version

See dfw(8).
`

func logf(format string, a ...any) { log.Printf(format, a...) }

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(args)
	if fs.NArg() > 1 || fs.NArg() == 1 && cmd != "check" {
		fs.Usage()
		os.Exit(2)
	}
	var err error
	switch cmd {
	case "run":
		err = cmdRun()
	case "init":
		err = cmdInit()
	case "check":
		var errs int
		if errs, _, err = cmdCheck(fs.Arg(0)); err == nil && errs > 0 {
			os.Exit(1)
		}
	case "enable":
		err = cmdEnable()
	case "apply":
		err = cmdApply()
	case "disable":
		err = cmdDisable()
	case "active":
		if !isActive() {
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		logf("error: %v", err)
		os.Exit(1)
	}
}

// cmdInit loads the base table if it is missing or damaged. It never touches
// an intact table, so containers keep their rules when Docker restarts.
func cmdInit() error {
	// docker.service may have no start timeout, so enforce our own.
	t := time.AfterFunc(60*time.Second, func() {
		logf("error: dfw init timed out")
		os.Exit(1)
	})
	defer t.Stop()
	links, err := netlink.Links(-1)
	if err != nil {
		return err
	}
	st, err := nft.List(ifnames(links))
	if err == nil && baseIntact(st) {
		return nil
	}
	if err != nil && !errors.Is(err, nft.ErrNoTable) {
		return err
	}
	if err == nil {
		logf("warning: the base table is damaged; replacing it, which blocks every container until dfw run fills it in")
	}
	if err := nft.Apply(nft.Render(bootRuleset())); err != nil {
		return err
	}
	// Only the base: dfw run may already have filled the table in again.
	if st, err = nft.List(ifnames(links)); err != nil {
		return err
	}
	if !baseIntact(st) {
		return errors.New("the base table did not load as intended")
	}
	return nil
}

// verify confirms the kernel's table is what rs intends.
func verify(rs nft.Ruleset) (*nft.State, error) {
	links, err := netlink.Links(-1)
	if err != nil {
		return nil, err
	}
	st, err := nft.List(ifnames(links))
	if err != nil {
		return nil, err
	}
	if d := nft.Diff(nft.Intended(rs), st); d != "" {
		return nil, errors.New("the kernel's table differs from what was applied: " + d)
	}
	return st, nil
}

func baseIntact(st *nft.State) bool {
	want := nft.Intended(nft.Ruleset{})
	for name, c := range want.Chains {
		if st.Chains[name] != c {
			return false
		}
	}
	for name := range want.Sets {
		if _, ok := st.Sets[name]; !ok {
			return false
		}
	}
	return true
}

// initLive loads the base table and every running container's rules in one
// transaction, then cuts all tracked connections of the filtered containers
// so that only allowed ones come back.
func initLive() error {
	cfg, hash, err := loadActive()
	if err != nil {
		return err
	}
	if len(cfg.Errors) > 0 { // also when it names no network
		return fmt.Errorf("the active rules in %s have errors, nothing was changed: %s", activeFile, strings.Join(cfg.Errors, "; "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	w, err := gather(ctx, docker.New(dockerSock), cfg, nil)
	if err != nil {
		return fmt.Errorf("can't read Docker, nothing was changed: %w", err)
	}
	w.holdUnlisted(nil)
	rs := w.ruleset()
	// Until every connection is cut below, dfw run must not count the rules
	// as confirmed.
	if err := os.Remove(appliedFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := nft.Apply(nft.Render(rs)); err != nil {
		return err
	}
	if _, err := verify(rs); err != nil {
		return err
	}
	if err := saveOpen(cfg.Networks, rs.Open); err != nil {
		return err
	}
	failed := 0
	for _, c := range w.ctrs {
		for _, a := range c.addrs {
			if err := cutAddr(a); err != nil {
				logf("error: %v", err)
				failed++
			}
		}
	}
	if failed > 0 {
		return fmt.Errorf("rules are loaded, but connections of %d addresses could not be cut, so forbidden ones may survive; run it again", failed)
	}
	// Every connection was cut under these rules, so dfw run needn't again.
	if err := writeAtomic(appliedFile, []byte(hash+"\n")); err != nil {
		return err
	}
	logf("loaded rules for %d containers on networks %s and cut their existing connections", len(rs.Containers), strings.Join(cfg.Networks, ", "))
	return nil
}

// cmdCheck prints the rules and what each running container on the filtered
// networks would get. It returns the number of errors in the rules and the
// files it read.
func cmdCheck(file string) (int, []rules.File, error) {
	files, err := readRules(file)
	if err != nil {
		return 0, nil, err
	}
	cfg := rules.ParseConfig(files)
	if file == "" && serviceActive() && !sameAsActive(files) {
		fmt.Println("note: the rules differ from those applied; run dfw apply to apply them")
	}
	for _, e := range cfg.Errors {
		fmt.Printf("ERROR %s\n", e)
	}
	if len(cfg.Networks) == 0 {
		return len(cfg.Errors), files, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dc := docker.New(dockerSock)
	w, err := gather(ctx, dc, cfg, nil)
	if err != nil {
		return 0, nil, err
	}
	if v, err := dc.Version(ctx); err == nil {
		checkDockerVersion(v.Version)
	}
	for _, n := range cfg.Networks {
		if b, ok := w.bridges[n]; ok {
			fmt.Printf("network %s (bridge %s)\n", n, b)
		} else {
			fmt.Printf("warning: network %s doesn't exist; its containers will be filtered once it does\n", n)
		}
	}
	// As dfw enable would judge them; a running dfw keeps open those it
	// already opened.
	w.holdUnlisted(nil)
	for _, b := range w.held {
		fmt.Printf("warning: bridge %s, which Docker doesn't list, is blocked until every filtered network exists, since it may be one's\n", b)
	}

	model := map[string]nft.Container{}
	for _, c := range w.ruleset().Containers {
		model[c.ID] = c
	}
	for _, c := range w.ctrs {
		fmt.Printf("\n%s\n", c.name)
		for _, p := range c.ports {
			line := fmt.Sprintf("  port   index %d  %s ", p.Ifindex, p.MAC)
			for _, a := range []netip.Addr{p.IPv4, p.IPv6} {
				if a.IsValid() {
					line += " " + a.String()
				}
			}
			fmt.Println(line)
		}
		show := func(dir string, es []rules.Entry, a rules.Allow) {
			if len(es) == 0 {
				return
			}
			var s []string
			for _, e := range es {
				s = append(s, e.String())
			}
			fmt.Printf("  %-6s %s\n", dir, strings.Join(s, ", "))
			if len(a.Any) > 0 {
				fmt.Printf("         any protocol: %s\n", short(a.Any))
			}
			for k, rs := range a.Ports {
				fmt.Printf("         %s/%d: %s\n", rules.ProtoName(k.Proto), k.Port, short(rs))
			}
			if len(a.ICMP) > 0 {
				fmt.Printf("         icmp: %s\n", short(a.ICMP))
			}
		}
		m := model[c.info.ID]
		show("in", c.in, m.In)
		show("out", c.out, m.Out)
		for _, e := range c.errors {
			fmt.Printf("  ERROR   %s\n", e)
		}
		for _, e := range c.warnings {
			fmt.Printf("  warning %s\n", e)
		}
	}
	for _, p := range w.problems {
		fmt.Printf("ERROR %s\n", p)
	}
	if u := w.unmatched(); len(u) > 0 {
		fmt.Println()
		for _, x := range u {
			fmt.Printf("warning %s\n", x)
		}
	}
	if len(w.unknown) > 0 {
		fmt.Println("\nports of filtered networks with no container behind them (blocked):")
		for _, l := range w.unknown {
			fmt.Printf("  %s (index %d)\n", l.Name, l.Index)
		}
	}
	fmt.Printf("\n%d containers on networks %s, %d errors in the rules\n", len(w.ctrs), strings.Join(cfg.Networks, ", "), len(cfg.Errors))
	return len(cfg.Errors), files, nil
}

func short(rs []rules.Range) string {
	var s []string
	for i, r := range rs {
		if i == 8 {
			s = append(s, fmt.Sprintf("... (%d ranges)", len(rs)))
			break
		}
		s = append(s, r.String())
	}
	return strings.Join(s, " ")
}

// checkRules prints what check prints and returns the rules being edited if they
// can be applied: exactly the files it checked, not a later read.
func checkRules() ([]rules.File, error) {
	errs, files, err := cmdCheck("")
	if err != nil {
		return nil, err
	}
	if errs > 0 { // also when they name no network
		return nil, fmt.Errorf("the rules have %d errors; nothing was changed", errs)
	}
	return files, nil
}

func cmdEnable() error {
	if serviceActive() {
		return errors.New("dfw is already enabled; use dfw apply to apply edited rules")
	}
	files, err := checkRules()
	if err != nil {
		return err
	}
	if _, err := saveActive(files); err != nil {
		return err
	}
	if err := initLive(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dropIn), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dropIn, []byte(dropInText), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "dfw.service"}} {
		if err := systemd(args...); err != nil {
			return err
		}
	}
	logf("dfw is enabled")
	return nil
}

// cmdApply makes the running dfw apply the edited rules, and waits until it
// has.
func cmdApply() error {
	if !serviceActive() {
		return errors.New("dfw.service is not running; use dfw enable")
	}
	files, err := checkRules()
	if err != nil {
		return err
	}
	if sameAsActive(files) {
		logf("the rules are already the active ones; reapplying")
	}
	// dfw run writes it again once these rules are in force; an old copy
	// must not count as that.
	if err := os.Remove(appliedFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hash, err := saveActive(files)
	if err != nil {
		return err
	}
	if err := systemd("reload", "dfw.service"); err != nil {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if readApplied() == hash {
			logf("rules applied")
			return nil
		}
	}
	return errors.New("dfw run has not confirmed the new rules within 30 s; see journalctl -u dfw")
}

func serviceActive() bool {
	return exec.Command(systemctl, "is-active", "-q", "dfw.service").Run() == nil
}

func cmdDisable() error {
	if err := systemd("disable", "--now", "dfw.service"); err != nil {
		return err
	}
	if err := os.Remove(dropIn); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := systemd("daemon-reload"); err != nil {
		return err
	}
	if err := nft.Delete(); err != nil && !errors.Is(err, nft.ErrNoTable) {
		return err
	}
	logf("dfw is disabled; containers are no longer filtered")
	return nil
}

func systemd(args ...string) error {
	out, err := exec.Command(systemctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isActive() bool {
	if _, err := os.Stat(dropIn); err == nil {
		return true
	}
	_, err := nft.List(nil)
	return !errors.Is(err, nft.ErrNoTable)
}

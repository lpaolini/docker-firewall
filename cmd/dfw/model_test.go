package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"dfw/internal/docker"
	"dfw/internal/netlink"
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

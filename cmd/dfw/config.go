package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"dfw/internal/nft"
	"dfw/internal/rules"
)

var (
	// What the administrator edits. It is applied when dfw run starts, if
	// valid, and on a live system only by dfw apply.
	rulesPath = "/etc/dfw/rules"
	rulesDir  = "/etc/dfw/rules.d"
	// activeFile is the copy of the rules last validated and applied: the
	// rules dfw run uses.
	activeFile = "/var/lib/dfw/rules.json"
	// appliedFile holds the hash of the active rules once dfw run has put
	// them in the table, so that dfw apply can wait for it.
	appliedFile = "/var/lib/dfw/applied"
	// stateFile remembers which bridges to leave open, for dfw init at boot,
	// before Docker can be asked.
	stateFile = "/var/lib/dfw/open-bridges"
)

// readRules reads the rules being edited: the file only if one is given,
// else the main rules file and then rules.d/*.rules in name order.
func readRules(only string) ([]rules.File, error) {
	paths := []string{rulesPath}
	if only != "" {
		paths = []string{only}
	} else {
		more, _ := filepath.Glob(filepath.Join(rulesDir, "*.rules"))
		slices.Sort(more)
		paths = append(paths, more...)
	}
	var files []rules.File
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		files = append(files, rules.File{Name: p, Text: string(b)})
	}
	return files, nil
}

// refreshActive makes the rules being edited the active rules, if they are
// valid. Otherwise it returns their problems and the active rules stay.
func refreshActive() []string {
	files, err := readRules("")
	if err != nil {
		return []string{err.Error()}
	}
	if cfg := rules.ParseConfig(files); len(cfg.Errors) > 0 {
		return cfg.Errors
	}
	if _, err := saveActive(files); err != nil {
		return []string{err.Error()}
	}
	return nil
}

// saveActive makes files the active rules and returns their hash.
func saveActive(files []rules.File) (string, error) {
	b, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return "", err
	}
	return hashOf(b), writeAtomic(activeFile, b)
}

// loadActive reads the active rules and their hash.
func loadActive() (rules.Config, string, error) {
	b, err := os.ReadFile(activeFile)
	if err != nil {
		return rules.Config{}, "", err
	}
	var files []rules.File
	if err := json.Unmarshal(b, &files); err != nil {
		return rules.Config{}, "", err
	}
	return rules.ParseConfig(files), hashOf(b), nil
}

// sameAsActive reports whether files are the active rules.
func sameAsActive(files []rules.File) bool {
	b, err1 := json.MarshalIndent(files, "", "  ")
	old, err2 := os.ReadFile(activeFile)
	return err1 == nil && err2 == nil && bytes.Equal(b, old)
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func readApplied() string {
	b, _ := os.ReadFile(appliedFile)
	return strings.TrimSpace(string(b))
}

func writeAtomic(path string, b []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// saveOpen records the bridges to leave open while networks are the
// filtered ones.
func saveOpen(networks []string, open []string) error {
	var b bytes.Buffer
	b.WriteString(recordHeader(networks) + "\n")
	for _, o := range open {
		b.WriteString(o + "\n")
	}
	return writeAtomic(stateFile, b.Bytes())
}

func recordHeader(networks []string) string { return "networks " + strings.Join(networks, " ") }

// bootRuleset is the base table to load when Docker can't be asked: no
// container has rules, and only the bridges recorded for the networks dfw
// will filter are open: those of the rules being edited if they are valid
// (dfw run applies them when it starts), else of the active rules. If none
// can be read, or the record is for other networks, every bridge is blocked.
func bootRuleset() nft.Ruleset {
	var cfg rules.Config
	if files, err := readRules(""); err == nil {
		cfg = rules.ParseConfig(files)
	}
	if len(cfg.Errors) > 0 || len(cfg.Networks) == 0 {
		var err error
		if cfg, _, err = loadActive(); err != nil {
			return nft.Ruleset{}
		}
	}
	if len(cfg.Networks) == 0 {
		return nft.Ruleset{}
	}
	b, err := os.ReadFile(stateFile)
	if err != nil {
		return nft.Ruleset{}
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != recordHeader(cfg.Networks) {
		return nft.Ruleset{}
	}
	return nft.Ruleset{Open: lines[1:]}
}

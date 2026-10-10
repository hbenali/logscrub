package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/config"
)

const good = `
disable = ["phone"]
enable  = ["phone"]

[[allow]]
exact = ["Noreply@Example.com"]
regex = ['^10\.0\.']

[[rule]]
id    = "ticket-token"
regex = 'TKT-([A-Z0-9]{16})'
group = 1
`

func TestParseGood(t *testing.T) {
	c, err := config.Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	allow, rules, err := c.Compile()
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]bool{
		"noreply@example.com": true, // exact, case-insensitive
		"10.0.4.4":            true, // regex
		"192.168.0.1":         false,
	} {
		if got := allow([]byte(in)); got != want {
			t.Errorf("allow(%q) = %v, want %v", in, got, want)
		}
	}
	if len(rules) != 1 || rules[0].ID != "ticket-token" || rules[0].Desc == "" {
		t.Errorf("rules = %+v", rules)
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"unknown top-level key": `colour = "red"`,
		"unknown key in rule":   "[[rule]]\nid='a'\nregex='x'\nflavour='y'",
		"bad toml":              `disable = [`,
		"bad regex":             "[[rule]]\nid='a'\nregex='('",
		"bad allow regex":       "[[allow]]\nregex=['(']",
		"empty-matching regex":  "[[rule]]\nid='a'\nregex='x*'",
		"missing group":         "[[rule]]\nid='a'\nregex='x'\ngroup=2",
		"bad id":                "[[rule]]\nid='Bad ID'\nregex='x'",
		"builtin id clash":      "[[rule]]\nid='email'\nregex='x'",
		"duplicate id":          "[[rule]]\nid='a'\nregex='x'\n[[rule]]\nid='a'\nregex='y'",
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse(text); err == nil {
				t.Errorf("accepted %q", text)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logscrub.toml")
	if err := os.WriteFile(p, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(filepath.Join(dir, "missing.toml")); err == nil {
		t.Error("missing file accepted")
	}
	big := filepath.Join(dir, "big.toml")
	if err := os.WriteFile(big, []byte("# "+strings.Repeat("x", 2<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("oversized config: %v", err)
	}
}

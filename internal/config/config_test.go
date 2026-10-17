package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/config"
	"github.com/hbenali/logscrub/internal/scrub"
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

func TestMaskKeys(t *testing.T) {
	c, err := config.Parse(`mask_keys = ["pin", "OTP", "card.number"]`)
	if err != nil {
		t.Fatal(err)
	}
	_, rules, err := c.Compile()
	if err != nil || len(rules) != 1 || rules[0].ID != config.MaskKeysID {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	cases := []struct{ in, want string }{
		{"pin=1234", "pin=[REDACTED:custom-key]"},
		{`{"user_pin": "9876", "otp":654321}`, `{"user_pin": "[REDACTED:custom-key]", "otp":[REDACTED:custom-key]}`},
		{`{"Card.Number":"4111"}`, `{"Card.Number":"[REDACTED:custom-key]"}`},
		{"  - otp: 112233", "  - otp: [REDACTED:custom-key]"},
		{`OTP='abc'`, `OTP='[REDACTED:custom-key]'`},
		// not keys ending in a listed name, or no real value
		{"pincode=1234 pins=3 max_pin_tries=5", "pincode=1234 pins=3 max_pin_tries=5"},
		{"pin=null otp=${OTP} pin=", "pin=null otp=${OTP} pin="},
		{"please enter your pin: now", "please enter your pin: now"}, // prose, not YAML-looking
	}
	for _, tc := range cases {
		for _, noPre := range []bool{false, true} {
			var out bytes.Buffer
			s := scrub.New(scrub.Options{Detectors: rules, NoPrefilter: noPre})
			if err := s.Run(strings.NewReader(tc.in), &out); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Errorf("noPrefilter=%v\n in:   %q\n got:  %q\n want: %q", noPre, tc.in, out.String(), tc.want)
			}
		}
	}
}

func TestMaskKeysRejects(t *testing.T) {
	tests := map[string]string{
		"empty name":      `mask_keys = [""]`,
		"regex metachar":  `mask_keys = ["a.*"]`,
		"space":           `mask_keys = ["my pin"]`,
		"too long":        `mask_keys = ["` + strings.Repeat("a", 65) + `"]`,
		"id taken":        "mask_keys = ['pin']\n[[rule]]\nid='custom-key'\nregex='x'",
		"too many":        "mask_keys = [" + strings.Repeat(`"a",`, 201) + "]",
		"not an array":    `mask_keys = "pin"`,
		"array of tables": "[[mask_keys]]\nname='pin'",
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse(text); err == nil {
				t.Errorf("accepted %q", text)
			}
		})
	}
}

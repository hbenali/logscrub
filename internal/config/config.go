// Package config loads the optional TOML rules file: detectors to enable or
// disable, an allow-list, and custom regexp rules. The file is data, not code,
// parsed strictly, and custom patterns are RE2, so they are linear-time too.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/hbenali/logscrub/internal/detect"
)

const maxConfigBytes = 1 << 20

// Config is the parsed file.
type Config struct {
	Enable  []string `toml:"enable"`
	Disable []string `toml:"disable"`
	Allow   []Allow  `toml:"allow"`
	Rules   []Rule   `toml:"rule"`
}

// Allow lists text that must never be masked.
type Allow struct {
	Exact []string `toml:"exact"` // compared case-insensitively
	Regex []string `toml:"regex"` // unanchored; add ^ and $ to anchor
}

// Rule is a custom detector.
type Rule struct {
	ID        string `toml:"id"`
	Desc      string `toml:"desc"`
	Regex     string `toml:"regex"`
	Group     int    `toml:"group"`
	Pseudonym bool   `toml:"pseudonym"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Load reads and validates a rules file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the user's --config argument
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(raw) > maxConfigBytes {
		return nil, errors.New("config: file is larger than 1 MiB")
	}
	return Parse(string(raw))
}

// Parse validates rules file text.
func Parse(text string) (*Config, error) {
	var c Config
	md, err := toml.Decode(text, &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown key(s): %s", strings.Join(keys, ", "))
	}
	if _, _, err := c.Compile(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Compile builds the allow-list function and the custom detectors.
func (c *Config) Compile() (allow func([]byte) bool, rules []*detect.Detector, err error) {
	var exact []string
	var res []*regexp.Regexp
	for i, a := range c.Allow {
		exact = append(exact, a.Exact...)
		for _, r := range a.Regex {
			re, cerr := regexp.Compile(r)
			if cerr != nil {
				return nil, nil, fmt.Errorf("config: allow[%d] regex: %w", i, cerr)
			}
			res = append(res, re)
		}
	}
	if len(exact) > 0 || len(res) > 0 {
		allow = func(secret []byte) bool {
			s := string(secret)
			for _, e := range exact {
				if strings.EqualFold(s, e) {
					return true
				}
			}
			for _, re := range res {
				if re.MatchString(s) {
					return true
				}
			}
			return false
		}
	}

	seen := map[string]bool{}
	for i, r := range c.Rules {
		switch {
		case !idPattern.MatchString(r.ID):
			return nil, nil, fmt.Errorf("config: rule[%d]: id must match %s", i, idPattern)
		case detect.ByID(r.ID) != nil:
			return nil, nil, fmt.Errorf("config: rule %q: id clashes with a built-in detector", r.ID)
		case seen[r.ID]:
			return nil, nil, fmt.Errorf("config: rule %q is defined twice", r.ID)
		}
		seen[r.ID] = true
		re, cerr := regexp.Compile(r.Regex)
		if cerr != nil {
			return nil, nil, fmt.Errorf("config: rule %q regex: %w", r.ID, cerr)
		}
		if r.Group < 0 || r.Group > re.NumSubexp() {
			return nil, nil, fmt.Errorf("config: rule %q: group %d does not exist in the regex", r.ID, r.Group)
		}
		if re.MatchString("") {
			return nil, nil, fmt.Errorf("config: rule %q: regex matches the empty string", r.ID)
		}
		desc := r.Desc
		if desc == "" {
			desc = "custom rule"
		}
		rules = append(rules, &detect.Detector{
			ID: r.ID, Desc: desc, Patterns: []*regexp.Regexp{re},
			Groups: []int{r.Group}, Pseudonym: r.Pseudonym,
		})
	}
	return allow, rules, nil
}

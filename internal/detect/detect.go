// Package detect defines the built-in detectors: RE2 patterns (linear time, so
// hostile input cannot trigger ReDoS) plus optional validators that reject
// look-alikes after a pattern matched.
package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// MarkerPrefix starts every replacement. Matches that already begin with it
// are skipped, which keeps scrubbing idempotent.
const MarkerPrefix = "[REDACTED:"

// Detector finds one kind of secret.
type Detector struct {
	ID   string
	Desc string
	// Patterns are tried independently; their matches are merged.
	Patterns []*regexp.Regexp
	// Groups lists submatch indexes to mask, in order of preference. The first
	// group that participated in the match is masked. Empty means the whole match.
	Groups []int
	// Validate, if set, is called with the text that would be masked and may
	// reject it.
	Validate func(secret []byte) bool
	// Check, if set, sees the whole line and the span that would be masked, for
	// context RE2 cannot express (no lookaround): "not part of a longer number".
	Check func(line []byte, start, end int) bool

	// Optional marks a detector that is off unless enabled explicitly.
	Optional bool
	// Pseudonym detectors get stable HMAC tags in pseudonym mode instead of a
	// fixed marker. Canonical, if set, normalises the text before hashing so
	// that equal values (Bob@X.org and bob@x.org) share a tag.
	Pseudonym bool
	Canonical func(secret []byte) []byte

	// Prefilter: the detector only runs on lines that contain one of Hints
	// (matched case-insensitively when FoldHints is set) and for which Pre, if
	// set, returns true. It is purely an optimisation: it must never exclude a
	// line the patterns could match (a test checks that).
	Hints     []string
	FoldHints bool
	Pre       func(line []byte) bool
}

// Marker returns the replacement text for this detector.
func (d *Detector) Marker() string { return MarkerPrefix + d.ID + "]" }

// All returns the built-in detectors in priority order: when two matches cover
// the same span the earlier detector wins, so specific token formats come
// before the generic context-based ones.
func All() []*Detector {
	return []*Detector{
		awsAccessKey(),
		githubToken(),
		gitlabToken(),
		slackToken(),
		stripeKey(),
		jwt(),
		privateKey(),
		urlCredentials(),
		bearerToken(),
		awsSecretKey(),
		kvSecret(),
		email(),
		ipv4(),
		ipv6(),
		creditCard(),
		phone(),
	}
}

// Defaults returns the detectors that are on unless disabled (everything not
// marked Optional).
func Defaults() []*Detector {
	var out []*Detector
	for _, d := range All() {
		if !d.Optional {
			out = append(out, d)
		}
	}
	return out
}

// ByID looks up a built-in detector.
func ByID(id string) *Detector {
	for _, d := range All() {
		if d.ID == id {
			return d
		}
	}
	return nil
}

func awsAccessKey() *Detector {
	return &Detector{
		ID:    "aws-access-key",
		Desc:  "AWS access key id (AKIA/ASIA/... + 16 characters)",
		Hints: []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b`),
		},
	}
}

func githubToken() *Detector {
	return &Detector{
		ID:    "github-token",
		Desc:  "GitHub token (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)",
		Hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b`),
		},
	}
}

func gitlabToken() *Detector {
	return &Detector{
		ID:    "gitlab-token",
		Desc:  "GitLab personal access token (glpat-)",
		Hints: []string{"glpat-"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
		},
	}
}

func slackToken() *Detector {
	return &Detector{
		ID:    "slack-token",
		Desc:  "Slack token (xox?-) or incoming webhook URL",
		Hints: []string{"xox", "hooks.slack.com"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
			regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
		},
	}
}

func stripeKey() *Detector {
	return &Detector{
		ID:    "stripe-key",
		Desc:  "Stripe live key (sk_live_, rk_live_, pk_live_)",
		Hints: []string{"_live_"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:sk|rk|pk)_live_[A-Za-z0-9]{16,}`),
		},
	}
}

func jwt() *Detector {
	return &Detector{
		ID:    "jwt",
		Desc:  "JSON Web Token (header must decode to JSON)",
		Hints: []string{"eyJ"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`),
		},
		Validate: validJWT,
	}
}

// PrivateKeyBegin and PrivateKeyEnd delimit PEM private key blocks. The engine
// uses them to mask blocks that span lines.
var (
	PrivateKeyBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	PrivateKeyEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
)

func privateKey() *Detector {
	return &Detector{
		ID:    "private-key",
		Desc:  "PEM private key block (may span lines)",
		Hints: []string{"PRIVATE KEY"},
		Patterns: []*regexp.Regexp{
			// Complete block on one line (for example JSON with escaped newlines).
			regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`),
		},
	}
}

func urlCredentials() *Detector {
	return &Detector{
		ID:    "url-credentials",
		Desc:  "user:password in a URL (scheme://user:pass@host)",
		Hints: []string{"://"},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://([^\s/?#@:]+:[^\s/?#@]+)@`),
		},
		Groups: []int{1},
	}
}

func bearerToken() *Detector {
	return &Detector{
		ID:        "bearer-token",
		Desc:      "credential in an Authorization header, or a long Bearer token",
		Hints:     []string{"bearer", "authorization"},
		FoldHints: true,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|negotiate)\s+([^\s"',;]+)`),
			regexp.MustCompile(`\b[Bb]earer\s+([A-Za-z0-9._~+/-]{20,}=*)`),
		},
		Groups: []int{1},
	}
}

func awsSecretKey() *Detector {
	return &Detector{
		ID:        "aws-secret-key",
		Desc:      "40-character AWS secret key after an aws_secret_access_key style name",
		Hints:     []string{"aws"},
		FoldHints: true,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40,})`),
		},
		Groups:   []int{1},
		Validate: func(b []byte) bool { return len(b) == 40 },
	}
}

// kvKey matches a name that ends in a secret-ish word. Requiring the word at
// the end avoids max_tokens=100, token_count=3 and similar counters.
const kvKey = `[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key)`

// kvValue matches a double-quoted (with escapes), single-quoted or bare value.
const kvValue = `(?:"((?:[^"\\]|\\.)+)"|'([^']+)'|([^\s"',;&)\]}]+))`

func kvSecret() *Detector {
	return &Detector{
		ID:        "kv-secret",
		Desc:      "value of password=, token=, api_key=, \"secret\": ... style pairs",
		Hints:     []string{"password", "passwd", "passphrase", "secret", "token", "key"},
		FoldHints: true,
		Patterns: []*regexp.Regexp{
			// name=value anywhere; "name": value (JSON, quoted YAML);
			// name: value only on a YAML-looking line, so prose such as
			// "failed to refresh token: connection refused" is left alone.
			regexp.MustCompile(`(?i)(?:` + kvKey + `["']?\s*=\s*|["']` + kvKey + `["']\s*:\s*|^\s*-?\s*` + kvKey + `\s*:\s+)` + kvValue),
		},
		Groups:   []int{1, 2, 3},
		Validate: validKVValue,
	}
}

// validKVValue rejects empty values, literals and template placeholders.
func validKVValue(v []byte) bool {
	s := strings.ToLower(string(bytes.TrimSpace(v)))
	switch s {
	case "", "null", "nil", "none", "true", "false", "undefined", "unset", "redacted", "masked", "hidden":
		return false
	}
	if strings.Trim(s, "*x•.-") == "" {
		return false
	}
	switch s[0] {
	case '$', '{', '%', '<', '[':
		return false
	}
	return true
}

func validJWT(tok []byte) bool {
	parts := bytes.Split(tok, []byte{'.'})
	if len(parts) != 3 {
		return false
	}
	var header map[string]any
	if err := decodeSegment(parts[0], &header); err != nil {
		return false
	}
	if _, ok := header["alg"]; !ok {
		return false
	}
	var payload any
	return decodeSegment(parts[1], &payload) == nil
}

func decodeSegment(seg []byte, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(seg), "="))
	if err != nil {
		return fmt.Errorf("segment is not base64url: %w", err)
	}
	return json.Unmarshal(raw, into)
}

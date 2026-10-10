package scrub_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

func TestPIIDetectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"email", "contact Bob.Smith+tag@Example.org.", "contact [REDACTED:email]."},
		{"email in brackets", "<bob@example.org>", "<[REDACTED:email]>"},
		{"ssh url userinfo", "ssh://git@github.com/x", "ssh://git@github.com/x"},
		{"scp remote", "git@github.com:me/r.git", "git@github.com:me/r.git"},
		{"file with @2x", "icon@2x.png", "icon@2x.png"},
		{"no tld", "user@localhost", "user@localhost"},

		{"ipv4", "from 192.168.1.10:443 ok", "from [REDACTED:ipv4]:443 ok"},
		{"ipv4 sentence end", "ip=8.8.8.8.", "ip=[REDACTED:ipv4]."},
		{"two ipv4", "1.1.1.1 2.2.2.2", "[REDACTED:ipv4] [REDACTED:ipv4]"},
		{"ipv4 octet too big", "256.1.1.1", "256.1.1.1"},
		{"ipv4 leading zero", "01.02.03.04", "01.02.03.04"},
		{"ipv4 five parts", "1.2.3.4.5", "1.2.3.4.5"},
		{"ipv4 loopback", "127.0.0.1 0.0.0.0", "127.0.0.1 0.0.0.0"},
		{"ipv4 user agent", "Chrome/126.0.0.0", "Chrome/126.0.0.0"},
		{"ipv4 url host", "http://10.0.0.5/x", "http://[REDACTED:ipv4]/x"},

		{"ipv6", "peer fe80::1ff:fe23:4567:890a up", "peer [REDACTED:ipv6] up"},
		{"ipv6 documentation", "[2001:db8::1]:443", "[[REDACTED:ipv6]]:443"},
		{"ipv6 full", "2001:0db8:0000:0000:0000:ff00:0042:8329", "[REDACTED:ipv6]"},
		{"ipv6 loopback", "[::1]:80", "[::1]:80"},
		{"time of day", "at 12:30:45", "at 12:30:45"},
		{"mac address", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"cpp scope", "std::vector Foo::bar a::b", "std::vector Foo::bar a::b"},

		{"visa", "card 4111 1111 1111 1111 paid", "card [REDACTED:credit-card] paid"},
		{"visa dashes", "4111-1111-1111-1111", "[REDACTED:credit-card]"},
		{"mastercard", "5555555555554444", "[REDACTED:credit-card]"},
		{"amex", "3782 822463 10005", "[REDACTED:credit-card]"},
		{"luhn failure", "4111111111111112", "4111111111111112"},
		{"unknown issuer", "1234567812345670", "1234567812345670"},
		{"too long digit run", "41111111111111111111", "41111111111111111111"},
		{"inside hex id", "id=a4111111111111111", "id=a4111111111111111"},
		{"epoch millis", "1791655406123", "1791655406123"},

		{"phone is opt-in", "call +14155550123", "call +14155550123"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOptionalPhone(t *testing.T) {
	out, _ := run(t, scrub.Options{Detectors: detect.All()}, "call +14155550123, not +123 or x+14155550123\n")
	if out != "call [REDACTED:phone], not +123 or x+14155550123\n" {
		t.Errorf("got %q", out)
	}
}

var tagRe = regexp.MustCompile(`\[(email|ipv4|ipv6):[a-z2-7]{8}\]`)

func runKey(t *testing.T, key, in string) string {
	t.Helper()
	out, _ := run(t, scrub.Options{Key: []byte(key)}, in)
	return out
}

func TestPseudonymsAreStableAndKeyed(t *testing.T) {
	const key1, key2 = "0123456789abcdef-one", "0123456789abcdef-two"
	in := "a bob@x.org 10.1.2.3 | 10.1.2.3 | other@x.org 10.9.9.9 | BOB@X.ORG\n"

	out := runKey(t, key1, in)
	tags := tagRe.FindAllString(out, -1)
	if len(tags) != 6 {
		t.Fatalf("want 6 tags, got %d in %q", len(tags), out)
	}
	if tags[0] != tags[5] {
		t.Errorf("email case should not change the tag: %v", tags)
	}
	if tags[1] != tags[2] {
		t.Errorf("same IP got different tags: %v", tags)
	}
	if tags[1] == tags[4] || tags[0] == tags[3] {
		t.Errorf("different values share a tag: %v", tags)
	}
	if again := runKey(t, key1, in); again != out {
		t.Errorf("same key must give identical output")
	}
	if other := runKey(t, key2, in); other == out {
		t.Errorf("a different key must give different tags")
	}
	if strings.Contains(out, "bob") || strings.Contains(out, "10.1.2.3") {
		t.Errorf("value leaked into pseudonym output: %q", out)
	}
	// Idempotent: tags are not themselves maskable.
	if twice := runKey(t, key1, out); twice != out {
		t.Errorf("second pass changed the output")
	}
}

func TestSecretsKeepMarkersInPseudonymMode(t *testing.T) {
	out := runKey(t, "0123456789abcdef-one", "password=hunter2 "+ghToken+" 10.1.2.3\n")
	if !strings.Contains(out, "password=[REDACTED:kv-secret]") || strings.Contains(out, ghToken) {
		t.Errorf("secret handling changed: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:github-token]") {
		t.Errorf("tokens must keep fixed markers (a stable tag would be a fingerprint): %q", out)
	}
	if strings.Contains(out, "[REDACTED:ipv4]") {
		t.Errorf("ipv4 should be pseudonymised: %q", out)
	}
}

func TestIPv6PseudonymIgnoresFormatting(t *testing.T) {
	a := runKey(t, "0123456789abcdef-one", "2001:db8::1\n")
	b := runKey(t, "0123456789abcdef-one", "2001:0DB8:0:0:0:0:0:1\n")
	if a != b {
		t.Errorf("same address, different tags: %q vs %q", a, b)
	}
}

func TestAllowList(t *testing.T) {
	allow := func(b []byte) bool { return string(b) == "10.0.0.1" }
	out, res := run(t, scrub.Options{Allow: allow}, "10.0.0.1 10.0.0.2\n")
	if out != "10.0.0.1 [REDACTED:ipv4]\n" || res.Counts["ipv4"] != 1 {
		t.Errorf("got %q %v", out, res.Counts)
	}
}

// The prefilter is only an optimisation: with and without it the output must
// be identical, including for tricky Unicode that regexp case folding accepts.
func TestPrefilterDoesNotChangeOutput(t *testing.T) {
	inputs := []string{
		dirty(),
		"paſſword=hunter2 TOKEN=abc Key=v api_Key=abc123\n",
		"Authorization: BEARER abcdefghij0123456789 AUTHORIZATION=basic dXNlcg==\n",
		"AWS_SECRET_ACCESS_KEY=" + awsSecret + "\n",
		"mail a@b.org ip 8.8.4.4 v6 2001:db8::5 card 4111111111111111 +14155550123\n",
		"",
	}
	files, _ := filepath.Glob("../../testdata/clean/*")
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // globbing our own testdata
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, string(b))
	}
	for i, in := range inputs {
		with, _ := run(t, scrub.Options{Detectors: detect.All()}, in)
		without, _ := run(t, scrub.Options{Detectors: detect.All(), NoPrefilter: true}, in)
		if with != without {
			t.Errorf("input %d: prefilter changed the output:\n%s", i, firstDiff(without, with))
		}
	}
}

func TestFoldedHintsAreLowercase(t *testing.T) {
	for _, d := range detect.All() {
		if !d.FoldHints {
			continue
		}
		for _, h := range d.Hints {
			if h != strings.ToLower(h) {
				t.Errorf("%s: hint %q must be lowercase when FoldHints is set", d.ID, h)
			}
		}
	}
}

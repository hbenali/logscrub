package scrub_test

import (
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// rep builds a deterministic string of n characters from a pattern.
func rep(pattern string, n int) string {
	return strings.Repeat(pattern, n/len(pattern)+1)[:n]
}

// Test tokens are assembled from pieces so no secret scanner flags this file.
var (
	tDocker    = "dckr_" + "pat_" + rep("AbCdEf9_", 27)
	tAnthropic = "sk-" + "ant-" + "api03-" + rep("aB3dE-", 60)
	tOpenAI    = "sk-" + "proj-" + rep("aB3dE_", 60)
	tOpenAIOld = "sk-" + rep("aB3dE7", 48)
	tGoogle    = "AI" + "za" + rep("Sy1A", 35)
	tNPM       = "npm" + "_" + rep("aB3d", 36)
	tPyPI      = "pypi-" + "AgEIcHlwaS5vcmc" + rep("aB3d_", 60)
	tSendGrid  = "SG" + "." + rep("aB3d", 22) + "." + rep("xY9z", 43)
	tHF        = "hf" + "_" + rep("aB3d", 34)
	tShopify   = "shp" + "at_" + rep("a1b2", 32)
	tDO        = "dop" + "_v1_" + rep("a1b2", 64)
	tVault     = "hvs" + "." + rep("aB3d", 24)
	tAge       = "AGE-SECRET-" + "KEY-1" + rep("Q7W8", 58)
	tTelegram  = "123456789" + ":" + "AA" + rep("aB3d", 33)
	tAzure     = "AccountKey" + "=" + rep("aB3d+/", 86) + "=="
)

func TestProviderTokens(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"dockerhub", "login " + tDocker, "login [REDACTED:dockerhub-token]"},
		{"anthropic", "key=" + tAnthropic, "key=[REDACTED:anthropic-key]"},
		{"openai project", "OPENAI " + tOpenAI + " end", "OPENAI [REDACTED:openai-key] end"},
		{"openai legacy", tOpenAIOld, "[REDACTED:openai-key]"},
		{"google", "k " + tGoogle, "k [REDACTED:google-api-key]"},
		{"npm", tNPM, "[REDACTED:npm-token]"},
		{"pypi", tPyPI, "[REDACTED:pypi-token]"},
		{"sendgrid", tSendGrid, "[REDACTED:sendgrid-key]"},
		{"huggingface", tHF, "[REDACTED:huggingface-token]"},
		{"shopify", tShopify, "[REDACTED:shopify-token]"},
		{"digitalocean", tDO, "[REDACTED:digitalocean-token]"},
		{"vault", tVault, "[REDACTED:vault-token]"},
		{"age", tAge, "[REDACTED:age-key]"},
		{"telegram", "bot " + tTelegram, "bot [REDACTED:telegram-token]"},
		{"azure storage", "DefaultEndpointsProtocol=https;" + tAzure + ";EndpointSuffix=core", "DefaultEndpointsProtocol=https;AccountKey=[REDACTED:azure-storage-key];EndpointSuffix=core"},

		{"too short", "dckr_pat_abc sk-ant-short AIzaShort npm_short hf_x", "dckr_pat_abc sk-ant-short AIzaShort npm_short hf_x"},
		{"look-alikes", "scikit-learn sk-learn risk-assessment-checklist-for-the-team", "scikit-learn sk-learn risk-assessment-checklist-for-the-team"},
		{"inside a word", "task-" + rep("a1", 50), "task-" + rep("a1", 50)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCookiesSessionsAndCredentials(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"cookie header", "Cookie: sid=abc123; theme=dark", "Cookie: [REDACTED:cookie]"},
		{"set-cookie", "Set-Cookie: session=xyz; Path=/; HttpOnly", "Set-Cookie: [REDACTED:cookie]"},
		{"json cookie", `{"cookie": "a=b; c=d", "x": 1}`, `{"cookie": "[REDACTED:cookie]", "x": 1}`},
		{"cookie word only", "cookie consent: accepted cookie=1 Cookie: none", "cookie consent: accepted cookie=1 Cookie: none"},
		{"session id", "JSESSIONID=ABCD1234EF session_id=3f2a9c", "JSESSIONID=[REDACTED:kv-secret] session_id=[REDACTED:kv-secret]"},
		{"credentials", `"credentials": "abcd1234"`, `"credentials": "[REDACTED:kv-secret]"`},
		{"credentials file", "credentials_file=/etc/app/credentials.json", "credentials_file=/etc/app/credentials.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIBANAndHomePaths(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"german iban", "pay DE89370400440532013000 now", "pay [REDACTED:iban] now"},
		{"spaced iban", "GB82 WEST 1234 5698 7654 32", "[REDACTED:iban]"},
		{"tunisian iban", "TN5910006035183598478831", "[REDACTED:iban]"},
		{"bad checksum", "DE89370400440532013001", "DE89370400440532013001"},
		{"wrong length", "DE8937040044053201300", "DE8937040044053201300"},
		{"random code", "AB12CD34EF56GH78IJ90", "AB12CD34EF56GH78IJ90"},
		{"inside a word", "xDE89370400440532013000", "xDE89370400440532013000"},

		{"linux home", "/home/alice/project/main.go", "/home/[REDACTED:home-path]/project/main.go"},
		{"mac home", "open /Users/Bob.Smith/Library", "open /Users/[REDACTED:home-path]/Library"},
		{"windows home", `C:\Users\carol\Documents`, `C:\Users\[REDACTED:home-path]\Documents`},
		{"windows escaped", `"C:\\Users\\carol\\x"`, `"C:\\Users\\[REDACTED:home-path]\\x"`},
		{"role names", "/home/runner/work /home/ubuntu/.ssh " + `C:\Users\Public\x`, "/home/runner/work /home/ubuntu/.ssh " + `C:\Users\Public\x`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOptInDetectors(t *testing.T) {
	// Not in the default set.
	if out := scrubStr(t, "123-45-6789 aa:bb:cc:dd:ee:ff "+rep("Zk3Fq9Xw", 32)); strings.Contains(out, "REDACTED") {
		t.Errorf("opt-in detectors ran by default: %q", out)
	}
	tests := []struct{ name, in, want string }{
		{"ssn", "ssn 123-45-6789 ok", "ssn [REDACTED:us-ssn] ok"},
		{"ssn invalid area", "000-12-3456 666-12-3456 900-12-3456", "000-12-3456 666-12-3456 900-12-3456"},
		{"ssn inside longer number", "123-45-67890 1123-45-6789", "123-45-67890 1123-45-6789"},
		{"mac", "hwaddr AA:bb:cc:dd:ee:ff end", "hwaddr [REDACTED:mac-address] end"},
		{"mac dashes", "aa-bb-cc-dd-ee-ff", "[REDACTED:mac-address]"},
		{"high entropy", "secret-ish Zk3Fq9Xw2LmN8pR4tV7yB1cD5hJ0sGa done", "secret-ish [REDACTED:high-entropy] done"},
		{"hash is not entropy", "0f4c1d2e9a7b3c5d6e8f9a0b1c2d3e4f5a6b7c8d 3f8a1c2e-9b7d-4e51-8a3c-0d2f6b9e1a44", "0f4c1d2e9a7b3c5d6e8f9a0b1c2d3e4f5a6b7c8d 3f8a1c2e-9b7d-4e51-8a3c-0d2f6b9e1a44"},
		{"words are not entropy", "CamelCaseJavaClassNameWithoutDigitsFactory kubernetes-deployment-abc123-xyz789-replica", "CamelCaseJavaClassNameWithoutDigitsFactory kubernetes-deployment-abc123-xyz789-replica"},
		{"path segment", "/var/lib/Zk3Fq9Xw2LmN8pR4tV7yB1cD5hJ0sGa/data", "/var/lib/Zk3Fq9Xw2LmN8pR4tV7yB1cD5hJ0sGa/data"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := run(t, scrub.Options{Detectors: detect.All()}, tc.in)
			if out != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, out, tc.want)
			}
		})
	}
}

func TestPseudonymsForNewPII(t *testing.T) {
	out := runKey(t, "0123456789abcdef-one", "/home/alice/a /home/ALICE/b DE89370400440532013000 DE89 3704 0044 0532 0130 00\n")
	tags := regexpFind(out, `\[(?:home-path|iban):[a-z2-7]{8}\]`)
	if len(tags) != 4 || tags[0] != tags[1] || tags[2] != tags[3] || tags[0] == tags[2] {
		t.Errorf("tags = %v in %q", tags, out)
	}
}

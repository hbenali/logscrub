package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Assembled from pieces so the file does not look like a leaked secret.
var ghToken = "ghp" + "_" + strings.Repeat("a1B2c3", 6)

func exec(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestFilterStdin(t *testing.T) {
	code, out, _ := exec(t, "password=hunter2\n")
	if code != exitOK || out != "password=[REDACTED:kv-secret]\n" {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestCheckExitCodes(t *testing.T) {
	code, out, _ := exec(t, "password=hunter2\n", "--check")
	if code != exitFound || out != "" {
		t.Errorf("dirty input: code=%d stdout=%q", code, out)
	}
	if code, out, _ := exec(t, "all fine\n", "--check"); code != exitOK || out != "" {
		t.Errorf("clean input: code=%d stdout=%q", code, out)
	}
}

func TestReportNeverContainsSecrets(t *testing.T) {
	in := "token=" + ghToken + "\npassword=hunter2\n"
	code, out, errOut := exec(t, in, "--check", "--report")
	if code != exitFound {
		t.Fatalf("code=%d", code)
	}
	for _, s := range []string{out, errOut} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, ghToken) {
			t.Errorf("secret in report output: %q", s)
		}
	}
	if !strings.Contains(out, "github-token") || !strings.Contains(out, "total") {
		t.Errorf("report missing counts: %q", out)
	}
	// Without --check the filtered text goes to stdout and the report to stderr.
	_, out, errOut = exec(t, in, "--report")
	if !strings.Contains(out, "[REDACTED:github-token]") || !strings.Contains(errOut, "total") {
		t.Errorf("stdout=%q stderr=%q", out, errOut)
	}
}

func TestFilesAndStdinDash(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log")
	if err := os.WriteFile(f, []byte("secret=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "token=xyz\n", f, "-")
	want := "secret=[REDACTED:kv-secret]\ntoken=[REDACTED:kv-secret]\n"
	if code != exitOK || out != want {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestMissingFileErrorHasNoInput(t *testing.T) {
	code, _, errOut := exec(t, "", filepath.Join(t.TempDir(), "nope.log"))
	if code != exitIOFail || !strings.Contains(errOut, "no such file") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestDisableAndUnknownDetector(t *testing.T) {
	_, out, _ := exec(t, "password=hunter2\n", "--disable", "kv-secret")
	if out != "password=hunter2\n" {
		t.Errorf("disabled detector still ran: %q", out)
	}
	if code, _, errOut := exec(t, "", "--disable", "nope"); code != exitUsage || !strings.Contains(errOut, "unknown detector") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := exec(t, "", "--max-line-bytes", "10"); code != exitUsage {
		t.Errorf("tiny --max-line-bytes accepted")
	}
}

func TestListAndVersion(t *testing.T) {
	if _, out, _ := exec(t, "", "--list-detectors"); !strings.Contains(out, "kv-secret") {
		t.Errorf("list: %q", out)
	}
	if _, out, _ := exec(t, "", "--version"); !strings.HasPrefix(out, "logscrub ") {
		t.Errorf("version: %q", out)
	}
}

func TestUnscannableLineExitsWithIOError(t *testing.T) {
	in := "password=" + strings.Repeat("S3cr3tVal", 1<<17) + "\n"
	code, out, errOut := exec(t, in, "--max-line-bytes", "1024")
	if code != exitIOFail || strings.Contains(out+errOut, "S3cr3t") {
		t.Errorf("code=%d, input echoed=%v", code, strings.Contains(out+errOut, "S3cr3t"))
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPseudonymMode(t *testing.T) {
	keyA := writeFile(t, "a.key", "0123456789abcdef-A\n")
	keyB := writeFile(t, "b.key", "0123456789abcdef-B\n")
	in := "bob@example.org 10.1.2.3 bob@example.org\n"

	_, a1, _ := exec(t, in, "--mode", "pseudonym", "--key-file", keyA)
	_, a2, _ := exec(t, in, "--mode", "pseudonym", "--key-file", keyA)
	_, b, _ := exec(t, in, "--mode", "pseudonym", "--key-file", keyB)
	if a1 != a2 || a1 == b {
		t.Errorf("tags must be stable per key and differ across keys:\n%q\n%q\n%q", a1, a2, b)
	}
	if strings.Contains(a1, "bob") || strings.Contains(a1, "10.1.2.3") || strings.Count(a1, "[email:") != 2 {
		t.Errorf("output = %q", a1)
	}
	// No key: random per run, but still stable inside the run.
	_, r, _ := exec(t, in, "--mode", "pseudonym")
	f := strings.Fields(r)
	if len(f) != 3 || f[0] != f[2] {
		t.Errorf("random-key output = %q", r)
	}
}

func TestPseudonymKeySources(t *testing.T) {
	t.Setenv("LOGSCRUB_KEY", "0123456789abcdef-env")
	if code, out, _ := exec(t, "bob@example.org\n", "--mode", "pseudonym"); code != exitOK || !strings.HasPrefix(out, "[email:") {
		t.Errorf("env key: code=%d out=%q", code, out)
	}
	short := writeFile(t, "short.key", "tooshort")
	for _, args := range [][]string{
		{"--mode", "pseudonym", "--key-file", short},
		{"--mode", "pseudonym", "--key-file", filepath.Join(t.TempDir(), "nope")},
		{"--mode", "bogus"},
		{"--key-file", short}, // a key without pseudonym mode is a mistake
	} {
		if code, _, _ := exec(t, "x\n", args...); code != exitUsage {
			t.Errorf("%v: code=%d, want %d", args, code, exitUsage)
		}
	}
}

func TestConfigFile(t *testing.T) {
	cfg := writeFile(t, "logscrub.toml", `
disable = ["email"]
enable  = ["phone"]

[[allow]]
exact = ["10.0.0.1"]

[[rule]]
id    = "ticket-token"
regex = 'TKT-[A-Z0-9]{8}'
`)
	in := "bob@example.org 10.0.0.1 10.0.0.2 +14155550123 TKT-ABCD1234\n"
	code, out, errOut := exec(t, in, "--config", cfg)
	want := "bob@example.org 10.0.0.1 [REDACTED:ipv4] [REDACTED:phone] [REDACTED:ticket-token]\n"
	if code != exitOK || out != want {
		t.Errorf("code=%d out=%q err=%q", code, out, errOut)
	}
	// Command-line flags win over the file.
	_, out, _ = exec(t, in, "--config", cfg, "--enable", "email", "--disable", "phone")
	if !strings.Contains(out, "[REDACTED:email]") || !strings.Contains(out, "+14155550123") {
		t.Errorf("flags should override the config: %q", out)
	}
}

func TestBadConfigIsUsageError(t *testing.T) {
	bad := writeFile(t, "bad.toml", "colour = 'red'\n")
	code, out, errOut := exec(t, "x\n", "--config", bad)
	if code != exitUsage || out != "" || !strings.Contains(errOut, "unknown key") {
		t.Errorf("code=%d out=%q err=%q", code, out, errOut)
	}
	if code, _, _ := exec(t, "x\n", "--config", filepath.Join(t.TempDir(), "missing.toml")); code != exitUsage {
		t.Errorf("missing config: code=%d", code)
	}
}

func TestListShowsOptionalDetectors(t *testing.T) {
	_, out, _ := exec(t, "", "--list-detectors")
	if !strings.Contains(out, "phone") || !strings.Contains(out, "(off by default)") {
		t.Errorf("list: %q", out)
	}
}

func TestServeRefusesRemoteBindAndBadArguments(t *testing.T) {
	cfg := writeFile(t, "bad.toml", "colour = 'red'\n")
	short := writeFile(t, "short.key", "tooshort")
	tests := map[string][]string{
		"non-loopback without opt-in": {"serve", "--addr", "0.0.0.0:0"},
		"unexpected argument":         {"serve", "extra"},
		"bad config":                  {"serve", "--config", cfg},
		"short key":                   {"serve", "--key-file", short},
		"tiny body limit":             {"serve", "--max-body-bytes", "10"},
	}
	for name, args := range tests {
		code, out, errOut := exec(t, "", args...)
		if code == exitOK || out != "" {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, out, errOut)
		}
	}
	code, _, errOut := exec(t, "", "serve", "--addr", "0.0.0.0:0")
	if code != exitIOFail || !strings.Contains(errOut, "allow-remote") {
		t.Errorf("remote bind: code=%d stderr=%q", code, errOut)
	}
}

func TestServeHelp(t *testing.T) {
	code, _, errOut := exec(t, "", "serve", "-h")
	if code != exitOK || !strings.Contains(errOut, "--allow-remote") && !strings.Contains(errOut, "-allow-remote") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

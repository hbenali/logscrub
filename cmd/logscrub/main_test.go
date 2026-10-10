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

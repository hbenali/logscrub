package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const secretValue = "hunter2-S3CRET"

func TestJSONReportHasLocationsButNeverTheText(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, "a.log", "ok line\nuser=bob@example.org password="+secretValue+"\n")
	b := writeFile(t, "b.log", "10.1.2.3 here\n")
	_ = dir
	code, out, errOut := exec(t, "", "--check", "--report", "--report-format", "json", a, b)
	if code != exitFound {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if strings.Contains(out, secretValue) || strings.Contains(out, "bob@example.org") || strings.Contains(out, "10.1.2.3") {
		t.Fatalf("the report contains matched text: %s", out)
	}
	var rep struct {
		Total    int            `json:"total"`
		Counts   map[string]int `json:"counts"`
		Findings []struct {
			File       string `json:"file"`
			Line       int64  `json:"line"`
			Column     int64  `json:"column"`
			ByteOffset int64  `json:"byte_offset"`
			ByteLength int64  `json:"byte_length"`
			Detector   string `json:"detector"`
		} `json:"findings"`
		Truncated bool `json:"findings_truncated"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep.Total != 3 || len(rep.Findings) != 3 || rep.Truncated {
		t.Fatalf("report = %+v", rep)
	}
	var sawEmail, sawIP bool
	for _, f := range rep.Findings {
		switch f.Detector {
		case "email":
			sawEmail = f.File == a && f.Line == 2 && f.Column == 6 && f.ByteLength == int64(len("bob@example.org"))
		case "ipv4":
			sawIP = f.File == b && f.Line == 1 && f.Column == 1
		}
	}
	if !sawEmail || !sawIP {
		t.Errorf("locations are wrong: %+v", rep.Findings)
	}
}

func TestSARIFReport(t *testing.T) {
	code, out, _ := exec(t, "line\nuser=bob@example.org\n", "--check", "--report", "--report-format", "sarif")
	if code != exitFound || strings.Contains(out, "bob@example.org") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine  int `json:"startLine"`
							ByteOffset int `json:"byteOffset"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "logscrub" || len(doc.Runs[0].Tool.Driver.Rules) < 20 {
		t.Fatalf("bad SARIF header: %+v", doc)
	}
	r := doc.Runs[0].Results
	if len(r) != 1 || r[0].RuleID != "email" {
		t.Fatalf("results = %+v", r)
	}
	loc := r[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "stdin" || loc.Region.StartLine != 2 || loc.Region.ByteOffset != len("line\nuser=") {
		t.Errorf("location = %+v", loc)
	}
}

func TestReportFormatValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--report-format", "xml", "--report"},
		{"--report-format", "json"}, // needs --report
	} {
		if code, _, _ := exec(t, "x\n", args...); code != exitUsage {
			t.Errorf("%v: code=%d, want %d", args, code, exitUsage)
		}
	}
	// A clean input still yields a valid, empty report.
	_, out, _ := exec(t, "nothing here\n", "--check", "--report", "--report-format", "json")
	var rep map[string]any
	if json.Unmarshal([]byte(out), &rep) != nil || rep["total"] != float64(0) {
		t.Errorf("empty report = %s", out)
	}
}

func TestOutputFileIsAtomicAndSafe(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.log")
	if err := os.WriteFile(in, []byte("password="+secretValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "clean.log")

	code, stdout, errOut := exec(t, "", "-o", out, in)
	if code != exitOK || stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, errOut)
	}
	got, _ := os.ReadFile(out) //nolint:gosec // test file
	if string(got) != "password=[REDACTED:kv-secret]\n" {
		t.Errorf("output file = %q", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".logscrub-*")); len(entries) != 0 {
		t.Errorf("temporary files left behind: %v", entries)
	}

	// Refuses to overwrite its own input, and the input stays intact.
	if code, _, errOut := exec(t, "", "--output", in, in); code != exitUsage || !strings.Contains(errOut, "also an input") {
		t.Errorf("same file: code=%d stderr=%q", code, errOut)
	}
	if b, _ := os.ReadFile(in); !strings.Contains(string(b), secretValue) { //nolint:gosec // test file
		t.Errorf("the input was modified: %q", b)
	}
	if code, _, _ := exec(t, "", "--output", dir, in); code != exitUsage {
		t.Errorf("directory target: code=%d", code)
	}
	if code, _, _ := exec(t, "", "--check", "--output", out, in); code != exitUsage {
		t.Errorf("--check with --output: code=%d", code)
	}
}

func TestFailedRunLeavesTheOutputUntouched(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "clean.log")
	if err := os.WriteFile(out, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ := exec(t, "", "-o", out, filepath.Join(dir, "missing.log"))
	if code != exitIOFail {
		t.Errorf("code=%d", code)
	}
	if b, _ := os.ReadFile(out); string(b) != "previous\n" { //nolint:gosec // test file
		t.Errorf("a failed run replaced the output: %q", b)
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".logscrub-*")); len(entries) != 0 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestUserConfigIsLoadedButNotFromTheCurrentDirectory(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	if err := os.MkdirAll(filepath.Join(cfgDir, "logscrub"), 0o750); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(cfgDir, "logscrub", "config.toml")
	if err := os.WriteFile(user, []byte("disable = [\"email\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := exec(t, "bob@example.org\n"); out != "bob@example.org\n" {
		t.Errorf("the user config was not applied: %q", out)
	}
	if _, out, _ := exec(t, "bob@example.org\n", "--no-config"); out != "[REDACTED:email]\n" {
		t.Errorf("--no-config still read it: %q", out)
	}

	// A config in the working directory must never be picked up: an allow-list
	// in an untrusted checkout could make logscrub leak.
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, ".logscrub.toml"), []byte("[[allow]]\nregex = ['.*']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no user config now
	if _, out, _ := exec(t, "bob@example.org\n"); out != "[REDACTED:email]\n" {
		t.Errorf("a config in the current directory was loaded: %q", out)
	}
}

func TestWorldWritableUserConfigIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix permission bits")
	}
	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	p := filepath.Join(cfgDir, "logscrub", "config.toml")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("disable = [\"email\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	code, out, errOut := exec(t, "bob@example.org\n")
	if code != exitUsage || out != "" || !strings.Contains(errOut, "world-writable") {
		t.Errorf("code=%d out=%q stderr=%q", code, out, errOut)
	}
	if code, _, _ := exec(t, "bob@example.org\n", "--no-config"); code != exitOK {
		t.Errorf("--no-config should bypass it: code=%d", code)
	}
}

// ---- completions ----

var helpFlag = regexp.MustCompile(`(?m)^\s+-([a-z][a-z-]*)`)

func flagsOf(t *testing.T, args ...string) []string {
	t.Helper()
	_, _, help := exec(t, "", append(args, "-h")...)
	var names []string
	for _, m := range helpFlag.FindAllStringSubmatch(help, -1) {
		names = append(names, m[1])
	}
	if len(names) < 5 {
		t.Fatalf("could not read the flags from: %s", help)
	}
	return names
}

func TestCompletionsMentionEveryFlag(t *testing.T) {
	for shell, file := range completionFiles {
		body, err := completionFS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		script := string(body)
		for _, set := range [][]string{flagsOf(t), flagsOf(t, "serve")} {
			for _, name := range set {
				want := "--" + name
				if len(name) == 1 {
					want = "-" + name
				}
				if shell == "fish" {
					want = "-l " + name
					if len(name) == 1 {
						want = "-s " + name
					}
				}
				if !strings.Contains(script, want) {
					t.Errorf("%s completion does not mention flag %q (looked for %q)", shell, name, want)
				}
			}
		}
	}
}

func TestCompletionSubcommand(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, _ := exec(t, "", "completion", shell)
		if code != exitOK || !strings.Contains(out, "logscrub") {
			t.Errorf("%s: code=%d out=%.40q", shell, code, out)
		}
	}
	for _, args := range [][]string{{"completion"}, {"completion", "powershell"}, {"completion", "bash", "extra"}} {
		if code, _, _ := exec(t, "", args...); code != exitUsage {
			t.Errorf("%v: code=%d, want %d", args, code, exitUsage)
		}
	}
}

func TestCompletionScriptsParse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are checked on Unix; Windows path handling differs between shells")
	}
	for shell, args := range map[string][]string{"bash": {"-n"}, "zsh": {"-n"}, "fish": {"--no-execute"}} {
		path, err := osexec.LookPath(shell)
		if err != nil {
			t.Logf("%s is not installed; skipping its syntax check", shell)
			continue
		}
		_, out, _ := exec(t, "", "completion", shell)
		script := writeFile(t, "completion."+shell, out)
		cmd := osexec.Command(path, append(args, script)...) //nolint:gosec // fixed shell names, test only
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s rejects the completion script: %v\n%s", shell, err, b)
		}
	}
}

// The man page must document every flag the program has.
func TestManPageMentionsEveryFlag(t *testing.T) {
	page, err := os.ReadFile("../../docs/man/logscrub.1")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(page), `\-`, "-")
	for _, set := range [][]string{flagsOf(t), flagsOf(t, "serve")} {
		for _, name := range set {
			want := "--" + name
			if len(name) == 1 {
				want = "-" + name
			}
			if !strings.Contains(text, want) {
				t.Errorf("docs/man/logscrub.1 does not document %q", want)
			}
		}
	}
	for _, d := range []string{"completion", "serve", "LOGSCRUB_KEY"} {
		if !strings.Contains(text, d) {
			t.Errorf("man page does not mention %q", d)
		}
	}
}

func TestManPageHasNoRoffWarnings(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("groff warnings are checked on Linux (other platforms ship other groff versions)")
	}
	groff, err := osexec.LookPath("groff")
	if err != nil {
		t.Skip("groff is not installed")
	}
	cmd := osexec.Command(groff, "-man", "-ww", "-z", "../../docs/man/logscrub.1") //nolint:gosec // fixed arguments, test only
	if b, err := cmd.CombinedOutput(); err != nil || len(strings.TrimSpace(string(b))) != 0 {
		t.Errorf("groff: %v\n%s", err, b)
	}
}

// ---- serve access token ----

func TestServeToken(t *testing.T) {
	t.Setenv("LOGSCRUB_TOKEN", "")
	file := writeFile(t, "token.txt", "abcdef0123456789-token\n")
	short := writeFile(t, "short.txt", "short\n")

	if tok, gen, err := serveToken(false, ""); tok != "" || gen || err != nil {
		t.Errorf("loopback, none: %q %v %v", tok, gen, err)
	}
	tok, gen, err := serveToken(true, "")
	if err != nil || !gen || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(tok) {
		t.Errorf("--allow-remote should generate a 128-bit token: %q %v %v", tok, gen, err)
	}
	if tok2, _, _ := serveToken(true, ""); tok2 == tok {
		t.Error("generated tokens repeat")
	}
	if tok, gen, err := serveToken(true, file); tok != "abcdef0123456789-token" || gen || err != nil {
		t.Errorf("file: %q %v %v", tok, gen, err)
	}
	t.Setenv("LOGSCRUB_TOKEN", "0123456789abcdef-env")
	if tok, gen, err := serveToken(false, ""); tok != "0123456789abcdef-env" || gen || err != nil {
		t.Errorf("env: %q %v %v", tok, gen, err)
	}
	if _, _, err := serveToken(false, short); err == nil {
		t.Error("a short token was accepted")
	}
}

// A real server started through the CLI with --allow-remote: the printed URL
// carries a working token, and the API refuses requests without it.
func TestServeAllowRemoteRequiresAndPrintsAToken(t *testing.T) {
	t.Setenv("LOGSCRUB_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var log lockedBuffer
	done := make(chan int, 1)
	go func() {
		done <- runServe(ctx, []string{"--addr", "127.0.0.1:0", "--allow-remote", "--no-config"}, &log)
	}()

	var base, token string
	for i := 0; i < 300 && token == ""; i++ {
		if m := regexp.MustCompile(`open (http://\S+?)/#token=([0-9a-f]{32})`).FindStringSubmatch(log.String()); m != nil {
			base, token = m[1], m[2]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if token == "" {
		t.Fatalf("no token URL in the start-up output: %q", log.String())
	}
	get := func(auth string) int {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/detectors", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(""); code != http.StatusUnauthorized {
		t.Errorf("without the token: %d", code)
	}
	if code := get("Bearer " + token); code != http.StatusOK {
		t.Errorf("with the printed token: %d", code)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

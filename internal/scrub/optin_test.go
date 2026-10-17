package scrub_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// optIn returns the built-ins plus the named opt-in detectors.
func optIn(t *testing.T, ids ...string) []*detect.Detector {
	t.Helper()
	out := detect.Defaults()
	for _, id := range ids {
		d := detect.ByID(id)
		if d == nil {
			t.Fatalf("no detector %q", id)
		}
		out = append(out, d)
	}
	return out
}

func TestUsernameDetector(t *testing.T) {
	const m = "[REDACTED:username]"
	tests := []struct{ name, in, want string }{
		{"key value", "login ok user=alice ip", "login ok user=" + m + " ip"},
		{"username key", "username: Bob.Smith done", "username: " + m + " done"},
		{"json", `{"user":"carol","n":1}`, `{"user":"` + m + `","n":1}`},
		{"json username single quotes", `{'username': 'dave'}`, `{'username': '` + m + `'}`},
		{"sshd accepted", "Accepted publickey for erin from 10.0.0.1 port 22", "Accepted publickey for " + m + " from [REDACTED:ipv4] port 22"},
		{"sshd failed invalid", "Failed password for invalid user frank from 10.0.0.1", "Failed password for invalid user " + m + " from [REDACTED:ipv4]"},
		{"sshd invalid user", "Invalid user grace from 1.2.3.4", "Invalid user " + m + " from [REDACTED:ipv4]"},
		{"pam", "session opened for user heidi(uid=1000) by", "session opened for user " + m + "(uid=1000) by"},
		{"sudo", "sudo:    ivan : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls", "sudo:    " + m + " : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls"},

		// look-alikes that must stay
		{"role account", "user=root user=runner username=www-data", "user=root user=runner username=www-data"},
		{"placeholder", "user=unknown user: anonymous user=null user=${USER} user=<name>", "user=unknown user: anonymous user=null user=${USER} user=<name>"},
		{"key must end in user", "superuser=alice max_users=5 user_count=3 userid=7", "superuser=alice max_users=5 user_count=3 userid=7"},
		{"prose", "waiting for data from server; the user logged in", "waiting for data from server; the user logged in"},
		{"for from without sshd", "waiting for results from queue", "waiting for results from queue"},
		{"number", "user=12345", "user=12345"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := run(t, scrub.Options{Detectors: optIn(t, "username")}, tc.in)
			if out != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, out, tc.want)
			}
		})
	}
	// Off by default.
	if out, _ := run(t, scrub.Options{}, "user=alice"); out != "user=alice" {
		t.Errorf("username must be opt-in, got %q", out)
	}
}

func TestHostnameDetector(t *testing.T) {
	const m = "[REDACTED:hostname]"
	tests := []struct{ name, in, want string }{
		{"fqdn", "connect db1.corp.example.com:5432 ok", "connect " + m + ":5432 ok"},
		{"internal", "to build-7.internal.", "to " + m + "."},
		{"url", "GET https://api.example.io/v1/x", "GET https://" + m + "/v1/x"},
		{"upper", "HOST=DB1.EXAMPLE.COM", "HOST=" + m},
		{"country", "mail.example.tn", m},

		// look-alikes that must stay
		{"go file", "main.go util.py lib.rs README.md run.sh a.so", "main.go util.py lib.rs README.md run.sh a.so"},
		{"call", "fmt.Println os.Exit io.Copy(w, r) strings.Builder", "fmt.Println os.Exit io.Copy(w, r) strings.Builder"},
		{"version", "v1.2.3 2026.10.10 8.0.1", "v1.2.3 2026.10.10 8.0.1"},
		{"no tld", "localhostx.foo.bar", "localhostx.foo.bar"},
		{"longer dotted", "a.example.com.evil2", "a.example.com.evil2"},
		{"node", "process.env.NODE_ENV config.json", "process.env.NODE_ENV config.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := run(t, scrub.Options{Detectors: optIn(t, "hostname")}, tc.in)
			if out != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, out, tc.want)
			}
		})
	}
	if out, _ := run(t, scrub.Options{}, "db1.example.com"); out != "db1.example.com" {
		t.Errorf("hostname must be opt-in, got %q", out)
	}
}

func TestNewPseudonymKinds(t *testing.T) {
	opts := scrub.Options{Detectors: optIn(t, "username", "hostname"), Key: []byte("0123456789abcdef-one")}
	out, _ := run(t, opts, "user=alice host=Db1.Example.com user=ALICE host=db1.example.com other=web.example.com\n")
	tags := regexpFind(out, `\[(?:username|hostname):[a-z2-7]{8}\]`)
	if len(tags) != 5 || tags[0] != tags[2] || tags[1] != tags[3] || tags[1] == tags[4] || tags[0] == tags[1] {
		t.Errorf("tags = %v in %q", tags, out)
	}
}

// The clean corpus holds no login names, so username must leave all of it
// alone. (hostname is not held to this: the corpus legitimately mentions
// github.com and example.com, which that detector is meant to find.)
func TestUsernameLeavesCleanCorpusAlone(t *testing.T) {
	for _, f := range cleanFiles(t) {
		out, res := run(t, scrub.Options{Detectors: optIn(t, "username")}, f.text)
		if out != f.text {
			t.Errorf("username changed %s (counts %v):\n%s", f.name, res.Counts, firstDiff(f.text, out))
		}
	}
}

type cleanFile struct{ name, text string }

func cleanFiles(t *testing.T) []cleanFile {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/clean/*")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no corpus files (err=%v)", err)
	}
	var out []cleanFile
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // globbing our own testdata
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, cleanFile{filepath.Base(p), string(b)})
	}
	return out
}

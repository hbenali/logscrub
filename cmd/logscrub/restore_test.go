package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

const (
	pseudoKey = "0123456789abcdef-test-key"
	pseudoLog = "login bob@example.org from 203.0.113.7 password=" + secretValue + "\nretry bob@example.org\n"
)

func TestMapFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "map.json")
	t.Setenv("LOGSCRUB_KEY", pseudoKey)

	code, scrubbed, errOut := exec(t, pseudoLog, "--mode", "pseudonym", "--map-file", m)
	if code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if strings.Contains(scrubbed, "bob@example.org") || strings.Contains(scrubbed, "203.0.113.7") || strings.Contains(scrubbed, secretValue) {
		t.Fatalf("scrubbed output still holds data: %q", scrubbed)
	}
	if st, err := os.Stat(m); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("map file: %v mode %v", err, st)
	}
	// The map holds the personal data it must, and never a secret.
	raw := read(t, m)
	if !strings.Contains(raw, "bob@example.org") || !strings.Contains(raw, "203.0.113.7") {
		t.Errorf("map misses entries: %s", raw)
	}
	if strings.Contains(raw, secretValue) {
		t.Errorf("a secret was written to the map file: %s", raw)
	}

	code, restored, errOut := exec(t, scrubbed, "restore", "--map-file", m)
	want := strings.Replace(pseudoLog, secretValue, "[REDACTED:kv-secret]", 1)
	if code != exitOK || restored != want || errOut != "" {
		t.Fatalf("code=%d stderr=%q\n got: %q\nwant: %q", code, errOut, restored, want)
	}
}

func TestMapFileAccumulatesAcrossRuns(t *testing.T) {
	m := filepath.Join(t.TempDir(), "map.json")
	t.Setenv("LOGSCRUB_KEY", pseudoKey)
	_, one, _ := exec(t, "a alice@example.org\n", "--mode", "pseudonym", "--map-file", m)
	_, two, _ := exec(t, "b carol@example.org\n", "--mode", "pseudonym", "--map-file", m)
	_, back, _ := exec(t, one+two, "restore", "--map-file", m)
	if back != "a alice@example.org\nb carol@example.org\n" {
		t.Errorf("restored = %q", back)
	}
}

func TestRestoreLeavesUnknownTagsAndMarkers(t *testing.T) {
	m := filepath.Join(t.TempDir(), "map.json")
	write(t, m, `{"version":1,"entries":{"[email:aaaaaaaa]":"x@y.org"}}`, 0o600)
	in := "[email:aaaaaaaa] [email:bbbbbbbb] [REDACTED:kv-secret] [email:AAAAAAAA]\n"
	code, out, errOut := exec(t, in, "restore", "--map-file", m)
	if code != exitOK || out != "x@y.org [email:bbbbbbbb] [REDACTED:kv-secret] [email:AAAAAAAA]\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !strings.Contains(errOut, "1 tag(s) were not in the map") {
		t.Errorf("stderr = %q", errOut)
	}
}

// A tag split across two reads must still be restored.
func TestRestoreStreamTagSplitAcrossReads(t *testing.T) {
	m := map[string]string{"[email:abcdefgh]": "bob@example.org"}
	in := strings.Repeat("filler ", 30000) + "[email:abcdefgh] and [email:abcdefgh]"
	var out bytes.Buffer
	n, unknown, err := restoreStream(iotest.OneByteReader(strings.NewReader(in)), &out, m)
	if err != nil || n != 2 || unknown != 0 {
		t.Fatalf("n=%d unknown=%d err=%v", n, unknown, err)
	}
	if !strings.HasSuffix(out.String(), "bob@example.org and bob@example.org") {
		t.Errorf("tail = %q", out.String()[len(out.String())-60:])
	}
	// Reads that end mid-tag at every offset.
	short := "x [email:abcdefgh] y"
	for cut := 0; cut <= len(short); cut++ {
		r := io.MultiReader(strings.NewReader(short[:cut]), strings.NewReader(short[cut:]))
		var b bytes.Buffer
		if _, _, err := restoreStream(iotest.HalfReader(r), &b, m); err != nil || b.String() != "x bob@example.org y" {
			t.Errorf("cut %d: %q, %v", cut, b.String(), err)
		}
	}
}

func TestMapFileRules(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "map.json")
	t.Setenv("LOGSCRUB_KEY", pseudoKey)
	for _, args := range [][]string{
		{"--map-file", m}, // marker mode: nothing to map
		{"--mode", "pseudonym", "--check", "--map-file", m}, // --check writes nothing
		{"restore"},                        // map is required
		{"restore", "--map-file", m, "-i"}, // -i needs files
	} {
		if code, _, _ := exec(t, "x\n", args...); code != exitUsage {
			t.Errorf("%v: code=%d, want %d", args, code, exitUsage)
		}
	}
	if _, err := os.Stat(m); err == nil {
		t.Error("a map file was created by a rejected command line")
	}
	write(t, m, "not json", 0o600)
	if code, _, _ := exec(t, "x\n", "restore", "--map-file", m); code != exitUsage {
		t.Errorf("garbage map: code=%d", code)
	}
	write(t, m, `{"version":1,"entries":{}}`, 0o600)
	if err := os.Chmod(m, 0o666); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" { // no permission bits to refuse on
		return
	}
	if code, _, errOut := exec(t, "x\n", "restore", "--map-file", m); code != exitUsage || !strings.Contains(errOut, "writable") {
		t.Errorf("writable map: code=%d stderr=%q", code, errOut)
	}
}

func TestMapFileWithInPlaceAndRecursive(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOGSCRUB_KEY", pseudoKey)
	log := filepath.Join(root, "a.log")
	m := filepath.Join(root, "map.json") // inside the walked tree on purpose
	write(t, log, pseudoLog, 0o600)

	if code, _, errOut := exec(t, "", "-r", "-i", "--mode", "pseudonym", "--map-file", m, root); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if strings.Contains(read(t, log), "bob@example.org") {
		t.Fatal("log was not pseudonymised")
	}
	if !strings.Contains(read(t, m), "bob@example.org") {
		t.Fatal("the map file was scrubbed or not written")
	}
	// A second run must not touch the map either, and restoring in place works.
	if code, _, errOut := exec(t, "", "restore", "--map-file", m, "-i", log); code != exitOK {
		t.Fatalf("restore: code=%d stderr=%q", code, errOut)
	}
	want := strings.Replace(pseudoLog, secretValue, "[REDACTED:kv-secret]", 1)
	if read(t, log) != want {
		t.Errorf("restored file = %q", read(t, log))
	}
	var mf map[string]any
	if err := json.Unmarshal([]byte(read(t, m)), &mf); err != nil {
		t.Errorf("map is no longer JSON: %v", err)
	}
}

func TestRestoreOutputFileAndGzip(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "map.json")
	write(t, m, `{"version":1,"entries":{"[email:aaaaaaaa]":"x@y.org"}}`, 0o600)
	in := filepath.Join(dir, "in.log.gz")
	if err := os.WriteFile(in, gz(t, "to [email:aaaaaaaa]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.log.gz")
	if code, _, errOut := exec(t, "", "restore", "--map-file", m, "-o", out, in); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if got := gunzip(t, []byte(read(t, out))); got != "to x@y.org\n" {
		t.Errorf("out = %q", got)
	}
}

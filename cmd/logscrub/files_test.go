package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path the test built
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gz(t *testing.T, text string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gunzip(t *testing.T, raw []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	dirtyLine = "password=" + secretValue + "\n"
	cleanLine = "password=[REDACTED:kv-secret]\n"
)

func TestInPlaceRewritesAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log")
	write(t, f, "ok\n"+dirtyLine, 0o600)
	if err := os.Chmod(f, 0o400); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec(t, "", "-i", f)
	if code != exitOK || out != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if got := read(t, f); got != "ok\n"+cleanLine {
		t.Errorf("file = %q", got)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o400 {
		t.Errorf("mode = %v, want 0400", st.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".logscrub-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestInPlaceLeavesCleanFilesAlone(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "clean.log")
	write(t, f, "nothing here\n", 0o600)
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := exec(t, "", "-i", "--backup-suffix", ".bak", f); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	st, _ := os.Stat(f)
	if !st.ModTime().Equal(old) {
		t.Errorf("a file with nothing to mask was rewritten (mtime %v)", st.ModTime())
	}
	if _, err := os.Stat(f + ".bak"); err == nil {
		t.Error("a backup was made for an unchanged file")
	}
}

func TestInPlaceBackup(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log")
	write(t, f, dirtyLine, 0o600)
	if code, _, errOut := exec(t, "", "-i", "--backup-suffix", ".bak", f); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if read(t, f) != cleanLine || read(t, f+".bak") != dirtyLine {
		t.Errorf("file=%q backup=%q", read(t, f), read(t, f+".bak"))
	}
	// An existing backup is never overwritten: the run fails and the file is untouched.
	write(t, f, dirtyLine, 0o600)
	code, _, errOut := exec(t, "", "-i", "--backup-suffix", ".bak", f)
	if code != exitIOFail || !strings.Contains(errOut, "backup") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	if read(t, f) != dirtyLine {
		t.Error("the file changed although its backup could not be made")
	}
}

func TestFileFlagValidation(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log")
	write(t, f, dirtyLine, 0o600)
	for _, args := range [][]string{
		{"-i"},
		{"-i", "-"},
		{"-i", "--check", f},
		{"-i", "-o", filepath.Join(dir, "x"), f},
		{"--backup-suffix", ".bak", f},
		{"-i", "--backup-suffix", "../x", f},
		{"--include", "*.log", f},
		{"-r"},
		{"-r", "--include", "[", dir},
		{dir},
	} {
		if code, _, _ := exec(t, "", args...); code != exitUsage {
			t.Errorf("%v: code=%d, want %d", args, code, exitUsage)
		}
	}
	if read(t, f) != dirtyLine {
		t.Error("a rejected command line modified the file")
	}
}

func TestInPlaceFailureLeavesFileAndContinues(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.log")
	good := filepath.Join(dir, "good.log")
	// One unbroken value longer than the memory bound: the engine refuses it.
	huge := "password=" + strings.Repeat("S3cr3tVal", 1<<17) + "\n"
	write(t, bad, huge, 0o600)
	write(t, good, dirtyLine, 0o600)
	code, _, errOut := exec(t, "", "-i", "--max-line-bytes", "1024", bad, good)
	if code != exitIOFail || !strings.Contains(errOut, "bad.log") {
		t.Fatalf("code=%d stderr=%.200q", code, errOut)
	}
	if strings.Contains(errOut, `\n`) || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("error line is not newline-terminated: %q", errOut)
	}
	if read(t, bad) != huge {
		t.Error("the file that failed was modified")
	}
	if read(t, good) != cleanLine {
		t.Errorf("the other file was not processed: %q", read(t, good))
	}
}

func TestInPlaceThroughSymlinkRewritesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "link.log")
	write(t, target, dirtyLine, 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if code, _, errOut := exec(t, "", "-i", link); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if read(t, target) != cleanLine {
		t.Errorf("target = %q", read(t, target))
	}
}

func TestRecursiveWalk(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.log"), dirtyLine, 0o600)
	write(t, filepath.Join(root, "sub", "b.log"), dirtyLine, 0o600)
	write(t, filepath.Join(root, "sub", "c.txt"), dirtyLine, 0o600)
	write(t, filepath.Join(root, ".git", "config"), dirtyLine, 0o600)
	write(t, filepath.Join(root, "skipme", "d.log"), dirtyLine, 0o600)
	write(t, filepath.Join(root, "bin.dat"), "pk\x00\x01"+dirtyLine, 0o600)
	outside := filepath.Join(t.TempDir(), "outside.log")
	write(t, outside, dirtyLine, 0o600)
	if err := os.Symlink(outside, filepath.Join(root, "link.log")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}

	code, out, errOut := exec(t, "", "-r", "--exclude", "skipme", "--include", "*.log,*.txt,*.dat", root)
	if code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if got := strings.Count(out, cleanLine); got != 3 { // a.log, sub/b.log, sub/c.txt
		t.Errorf("masked %d lines, want 3:\n%s", got, out)
	}
	if strings.Contains(out, secretValue) {
		t.Error("secret reached stdout")
	}
	if !strings.Contains(errOut, "skipped 1 binary file") {
		t.Errorf("stderr = %q", errOut)
	}

	code, _, errOut = exec(t, "", "-r", "-i", "--include", "*.txt", root)
	if code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if read(t, filepath.Join(root, "sub", "c.txt")) != cleanLine {
		t.Error("c.txt was not rewritten")
	}
	for _, p := range []string{"a.log", "sub/b.log", ".git/config", "skipme/d.log"} {
		if read(t, filepath.Join(root, p)) != dirtyLine {
			t.Errorf("%s was modified", p)
		}
	}
	if read(t, outside) != dirtyLine {
		t.Error("a symlink was followed out of the tree")
	}
}

func TestRecursiveSkipsBackups(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.log"), dirtyLine, 0o600)
	for i := 0; i < 2; i++ { // the second run must not touch a.log.bak
		if code, _, errOut := exec(t, "", "-r", "-i", "--backup-suffix", ".bak", root); code != exitOK {
			t.Fatalf("run %d: code=%d stderr=%q", i, code, errOut)
		}
	}
	if read(t, filepath.Join(root, "a.log.bak")) != dirtyLine {
		t.Error("the backup was scrubbed or lost")
	}
}

func TestGzipInputIsReadTransparently(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log.gz")
	if err := os.WriteFile(f, gz(t, "ok\n"+dirtyLine), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec(t, "", f)
	if code != exitOK || out != "ok\n"+cleanLine {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, errOut)
	}
	code, out, _ = exec(t, string(gz(t, dirtyLine)))
	if code != exitOK || out != cleanLine {
		t.Errorf("stdin: code=%d out=%q", code, out)
	}
}

func TestGzipInPlaceAndOutput(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log.gz")
	if err := os.WriteFile(f, gz(t, dirtyLine), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "clean.log.gz")
	if code, _, errOut := exec(t, "", "-o", out, f); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if got := gunzip(t, []byte(read(t, out))); got != cleanLine {
		t.Errorf("-o .gz content = %q", got)
	}
	if code, _, errOut := exec(t, "", "-i", f); code != exitOK {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if got := gunzip(t, []byte(read(t, f))); got != cleanLine {
		t.Errorf("in-place .gz content = %q", got)
	}
}

func TestTruncatedGzipFailsAndKeepsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log.gz")
	raw := gz(t, strings.Repeat(dirtyLine, 2000))
	raw = raw[:len(raw)/2]
	if err := os.WriteFile(f, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := exec(t, "", "-i", f)
	if code != exitIOFail || strings.Contains(errOut, secretValue) {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	if read(t, f) != string(raw) {
		t.Error("a truncated archive was modified")
	}
}

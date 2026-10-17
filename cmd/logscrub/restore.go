package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// The mapping file turns pseudonymisation into a reversible step: while
// scrubbing in pseudonym mode, --map-file records which text each tag stands
// for, and `logscrub restore` puts it back. The file holds exactly the
// personal data that was removed, so it is written with mode 0600 and only
// detectors marked Pseudonym (emails, IPs, ...) ever appear in it: secrets get
// fixed markers and are never recorded.

const (
	mapVersion    = 1
	maxMapBytes   = 256 << 20
	maxMapEntries = 2_000_000
)

type pseudoMap struct {
	entries map[string]string
	dirty   bool
	full    bool
}

type mapFile struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"`
}

// loadPseudoMap reads path; a missing file is an empty map, so one file can
// accumulate across runs.
func loadPseudoMap(path string) (*pseudoMap, error) {
	m := &pseudoMap{entries: map[string]string{}}
	f, err := os.Open(path) //nolint:gosec // the path is the user's --map-file argument
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("refusing %s: it is group- or world-writable (chmod go-w)", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxMapBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if len(raw) > maxMapBytes {
		return nil, errors.New("map file is larger than 256 MiB")
	}
	var mf mapFile
	if err := json.Unmarshal(raw, &mf); err != nil {
		return nil, fmt.Errorf("%s is not a logscrub map file: %w", path, err)
	}
	if mf.Version != mapVersion {
		return nil, fmt.Errorf("%s: unsupported map file version %d", path, mf.Version)
	}
	if mf.Entries != nil {
		m.entries = mf.Entries
	}
	return m, nil
}

// record remembers tag -> original. The first original wins, so two spellings
// that share a tag (Bob@X.org, bob@x.org) restore to the first one seen.
func (m *pseudoMap) record(tag string, original []byte) {
	if _, ok := m.entries[tag]; ok {
		return
	}
	if len(m.entries) >= maxMapEntries {
		m.full = true
		return
	}
	m.entries[tag] = string(original)
	m.dirty = true
}

// save writes the map atomically with mode 0600, only if it changed.
func (m *pseudoMap) save(path string) error {
	if m.full {
		return fmt.Errorf("more than %d distinct values: the map file would be incomplete", maxMapEntries)
	}
	if !m.dirty {
		return nil
	}
	t, err := newAtomicFile(path, nil)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(t)
	enc.SetIndent("", "  ")
	if err := enc.Encode(mapFile{Version: mapVersion, Entries: m.entries}); err != nil {
		t.Abort()
		return fmt.Errorf("map file: %w", err)
	}
	if err := t.Commit(); err != nil {
		return err
	}
	m.dirty = false
	return nil
}

// tagPattern matches what pseudonym mode writes: [detector-id:8 base32 chars].
// [REDACTED:id] never matches (upper case, wrong length).
var tagPattern = regexp.MustCompile(`\[[a-z][a-z0-9-]{0,31}:[a-z2-7]{8}\]`)

// maxTagLen is the longest possible tag; a chunk boundary is never placed
// inside one.
const maxTagLen = 1 + 32 + 1 + 8 + 1

// restoreStream copies r to w replacing every tag found in m. It returns the
// number of tags restored and of tags that were not in the map (left as they
// are). Memory use does not depend on line length.
func restoreStream(r io.Reader, w io.Writer, m map[string]string) (restored, unknown int, err error) {
	buf := make([]byte, 0, 128<<10)
	tmp := make([]byte, 64<<10)
	for {
		k, rerr := r.Read(tmp)
		buf = append(buf, tmp[:k]...)
		cut := len(buf)
		if rerr == nil {
			// Hold back an opening bracket near the end: its tag may continue
			// in the next read.
			if i := bytes.LastIndexByte(buf, '['); i >= 0 && len(buf)-i < maxTagLen && !bytes.Contains(buf[i:], []byte{']'}) {
				cut = i
			}
		}
		out := tagPattern.ReplaceAllFunc(buf[:cut], func(tag []byte) []byte {
			if orig, ok := m[string(tag)]; ok {
				restored++
				return []byte(orig)
			}
			unknown++
			return tag
		})
		if _, werr := w.Write(out); werr != nil {
			return restored, unknown, fmt.Errorf("%w", werr)
		}
		buf = append(buf[:0], buf[cut:]...)
		switch {
		case rerr == nil:
		case errors.Is(rerr, io.EOF):
			return restored, unknown, nil
		default:
			return restored, unknown, fmt.Errorf("read: %w", rerr)
		}
	}
}

// runRestore is `logscrub restore --map-file FILE [-o FILE | -i] [file ...]`.
func runRestore(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logscrub restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mapPath := fs.String("map-file", "", "map file written by --map-file while scrubbing (required)")
	output := fs.String("output", "", "write the restored text to this file (atomically, mode 0600); gzip-compressed if it ends in .gz")
	fs.StringVar(output, "o", "", "short for --output")
	inPlace := fs.Bool("in-place", false, "rewrite each file with the original text put back")
	fs.BoolVar(inPlace, "i", false, "short for --in-place")
	backup := fs.String("backup-suffix", "", "with --in-place: keep the pseudonymised original under this suffix")
	fs.Usage = func() {
		outf(stderr, `Usage: logscrub restore --map-file FILE [flags] [file ...]

Replaces the pseudonym tags ([email:k3x9p2qa]) written by "logscrub --mode pseudonym
--map-file FILE" with the text they stood for. Tags that are not in the map are left
alone. The output contains personal data again: handle it like the original.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	switch {
	case *mapPath == "":
		outf(stderr, "logscrub restore: --map-file is required\n")
		return exitUsage
	case *inPlace && *output != "":
		outf(stderr, "logscrub restore: --in-place and --output cannot be combined\n")
		return exitUsage
	case *inPlace && fs.NArg() == 0:
		outf(stderr, "logscrub restore: --in-place needs at least one file\n")
		return exitUsage
	case *backup != "" && !*inPlace:
		outf(stderr, "logscrub restore: --backup-suffix needs --in-place\n")
		return exitUsage
	case strings.ContainsAny(*backup, `/\`):
		outf(stderr, "logscrub restore: --backup-suffix must not contain a path separator\n")
		return exitUsage
	}
	for _, a := range fs.Args() {
		if a == "-" && *inPlace {
			outf(stderr, "logscrub restore: --in-place cannot rewrite standard input\n")
			return exitUsage
		}
	}
	m, err := loadPseudoMap(*mapPath)
	if err != nil {
		outf(stderr, "logscrub restore: %v\n", err)
		return exitUsage
	}
	files, err := expandInputs(fs.Args(), false, walkOptions{})
	if err != nil {
		outf(stderr, "logscrub restore: %v\n", err)
		return exitUsage
	}
	if len(files) == 0 {
		files = []inputFile{{path: "-"}}
	}

	var restored, unknown int
	t := func(r io.Reader, w io.Writer) (int, error) {
		a, b, err := restoreStream(r, w, m.entries)
		restored += a
		unknown += b
		return a, err
	}
	var code int
	skipped := 0
	if *inPlace {
		code = rewriteAll(files, *backup, stderr, &skipped, func(inputFile) {}, nil, t)
	} else {
		code = restoreToOutput(files, *output, stdin, stdout, stderr, t)
	}
	if unknown > 0 {
		outf(stderr, "logscrub restore: %d tag(s) were not in the map file and were left as they are\n", unknown)
	}
	return code
}

// restoreToOutput runs t over every input into stdout or the --output file.
func restoreToOutput(files []inputFile, output string, stdin io.Reader, stdout, stderr io.Writer, t transform) int {
	out := stdout
	var target *atomicFile
	var gz *gzipOutput
	if output != "" {
		var err error
		if target, err = newAtomicFile(output, inputPaths(files)); err != nil {
			outf(stderr, "logscrub restore: %v\n", err)
			return exitUsage
		}
		out = target
		if strings.HasSuffix(output, ".gz") {
			gz = newGzipOutput(target)
			out = gz
		}
	}
	code := exitOK
	for _, f := range files {
		src, err := openSource(f.path, stdin)
		if err == nil {
			_, err = t(src.r, out)
			src.Close()
		}
		if err != nil {
			outf(stderr, "logscrub restore: %v\n", err)
			code = exitIOFail
			break
		}
	}
	if gz != nil && code == exitOK {
		if err := gz.Close(); err != nil {
			outf(stderr, "logscrub restore: --output: %v\n", err)
			code = exitIOFail
		}
	}
	if target != nil {
		if code == exitOK {
			if err := target.Commit(); err != nil {
				outf(stderr, "logscrub restore: %v\n", err)
				code = exitIOFail
			}
		} else {
			target.Abort()
		}
	}
	return code
}

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hbenali/logscrub/internal/scrub"
)

// vcsDirs are never walked by --recursive: they hold packed objects, and a
// rewritten object database is corruption, not cleaning.
var vcsDirs = map[string]bool{".git": true, ".hg": true, ".svn": true}

// binarySniff is how much of a file --recursive reads to decide it is binary.
const binarySniff = 8000

// source is one input, already decompressed when it was gzip.
type source struct {
	r    *bufio.Reader
	gz   bool
	file *os.File // nil for stdin
}

func (s *source) Close() {
	if s.file != nil {
		_ = s.file.Close() // read-only: a close error cannot lose data
	}
}

// openSource opens name ("-" is stdin) and transparently decompresses gzip,
// recognised by its magic bytes rather than the file name.
func openSource(name string, stdin io.Reader) (*source, error) {
	src := &source{}
	raw := io.Reader(stdin)
	if name != "-" {
		f, err := os.Open(name) //nolint:gosec // opening the path the user asked for is the job
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		src.file, raw = f, f
	}
	br := bufio.NewReaderSize(raw, 64<<10)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			src.Close()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		src.gz = true
		br = bufio.NewReaderSize(zr, 64<<10)
	}
	src.r = br
	return src, nil
}

// looksBinary reports whether the start of the (decompressed) stream holds a
// NUL byte. It only peeks, so nothing is consumed.
func (s *source) looksBinary() bool {
	head, _ := s.r.Peek(binarySniff)
	return bytes.IndexByte(head, 0) >= 0
}

// inputFile is one file to process. walked is true when --recursive found it
// (explicitly named files are always processed, even if they look binary).
type inputFile struct {
	path   string
	walked bool
}

// walkOptions are the --recursive filters.
type walkOptions struct {
	include, exclude []string
	skipSuffix       string // a backup suffix: backups hold the unmasked text
}

// expandInputs turns the command-line arguments into files. A directory is an
// error unless recursive is set. Symbolic links met while walking are skipped:
// following them could rewrite files outside the tree, or loop.
func expandInputs(args []string, recursive bool, w walkOptions) ([]inputFile, error) {
	var out []inputFile
	for _, a := range args {
		if a == "-" {
			out = append(out, inputFile{path: a})
			continue
		}
		st, err := os.Stat(a)
		if err != nil || !st.IsDir() { // a missing file fails later, as an I/O error
			out = append(out, inputFile{path: a})
			continue
		}
		if !recursive {
			return nil, fmt.Errorf("%s is a directory (use --recursive)", a)
		}
		err = filepath.WalkDir(a, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if p != a && (vcsDirs[d.Name()] || matchAny(w.exclude, d.Name())) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() { // symlinks, sockets, devices
				return nil
			}
			name := d.Name()
			switch {
			case matchAny(w.exclude, name),
				len(w.include) > 0 && !matchAny(w.include, name),
				w.skipSuffix != "" && strings.HasSuffix(name, w.skipSuffix):
				return nil
			}
			out = append(out, inputFile{path: p, walked: true})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}
	return out, nil
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}
	return false
}

// gzipOutput wraps w so that what is written is gzip-compressed; Close
// flushes the trailer and must be called before the file is committed.
type gzipOutput struct{ zw *gzip.Writer }

func newGzipOutput(w io.Writer) *gzipOutput { return &gzipOutput{zw: gzip.NewWriter(w)} }

func (g *gzipOutput) Write(p []byte) (int, error) { return g.zw.Write(p) }
func (g *gzipOutput) Close() error                { return g.zw.Close() }

// checkFileFlags validates the combinations of the file-handling flags and
// returns a usage message, or "" when they are fine.
func checkFileFlags(args []string, inPlace, recursive, check bool, output, backup string, w walkOptions) string {
	switch {
	case inPlace && check:
		return "--in-place and --check cannot be combined (--check writes nothing)"
	case inPlace && output != "":
		return "--in-place and --output cannot be combined"
	case inPlace && len(args) == 0:
		return "--in-place needs at least one file"
	case backup != "" && !inPlace:
		return "--backup-suffix needs --in-place"
	case backup != "" && strings.ContainsAny(backup, `/\`):
		return "--backup-suffix must not contain a path separator"
	case !recursive && (len(w.include) > 0 || len(w.exclude) > 0):
		return "--include and --exclude need --recursive"
	case recursive && len(args) == 0:
		return "--recursive needs at least one directory or file"
	}
	if inPlace {
		for _, a := range args {
			if a == "-" {
				return "--in-place cannot rewrite standard input"
			}
		}
	}
	for _, g := range append(append([]string{}, w.include...), w.exclude...) {
		if _, err := filepath.Match(g, ""); err != nil {
			return fmt.Sprintf("bad glob %q: %v", g, err)
		}
	}
	return ""
}

func inputPaths(files []inputFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

// scrubInPlace rewrites each file next to itself: the cleaned text goes to a
// temporary file in the same directory, which replaces the original only if
// something was masked. A file that fails is reported and left as it was; the
// others are still processed. It returns the exit code.
func scrubInPlace(s *scrub.Scrubber, col *collector, files []inputFile, suffix string, stderr io.Writer, skipped *int) int {
	code := exitOK
	for _, f := range files {
		col.file = f.path
		if err := rewriteFile(s, f, suffix, skipped); err != nil {
			outf(stderr, "logscrub: %s: %v\n", f.path, err)
			code = exitIOFail
		}
	}
	return code
}

func rewriteFile(s *scrub.Scrubber, f inputFile, suffix string, skipped *int) error {
	path := f.path
	if !f.walked { // an explicit symlink: rewrite what it points to, not the link
		p, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		path = p
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	src, err := openSource(path, nil)
	if err != nil {
		return err
	}
	defer src.Close()
	if f.walked && src.looksBinary() {
		*skipped++
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".logscrub-*")
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	var w io.Writer = tmp
	var gz *gzipOutput
	if src.gz {
		gz = newGzipOutput(tmp)
		w = gz
	}
	before := s.Result().Total()
	if err := s.Run(src.r, w); err != nil {
		return err
	}
	if s.Result().Total() == before {
		return nil // nothing to mask: leave the file (and its mtime) alone
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		return fmt.Errorf("%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w", err)
	}
	if suffix != "" {
		// A hard link keeps the original bytes under the new name; it fails
		// rather than overwrite an existing backup.
		if err := os.Link(path, path+suffix); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("%w", err)
	}
	committed = true
	return nil
}

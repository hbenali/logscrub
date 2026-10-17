// Command logscrub masks secrets and personal data in logs.
//
//	some-command | logscrub > clean.log
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// Set by -ldflags -X at release time.
var version, commit string

// Exit codes.
const (
	exitOK     = 0
	exitFound  = 1 // --check found something
	exitUsage  = 2
	exitIOFail = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return runServeSignals(args[1:], stderr)
		case "restore":
			return runRestore(args[1:], stdin, stdout, stderr)
		case "completion":
			return runCompletion(args[1:], stdout, stderr)
		}
	}
	fs := flag.NewFlagSet("logscrub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		check       = fs.Bool("check", false, "write nothing; exit 1 if anything would be masked")
		report      = fs.Bool("report", false, "print counts per detector (never the matched text)")
		enable      = fs.String("enable", "", "comma-separated detector ids to add to the defaults")
		disable     = fs.String("disable", "", "comma-separated detector ids to turn off")
		list        = fs.Bool("list-detectors", false, "list detector ids and exit")
		showVersion = fs.Bool("version", false, "print version and exit")
		maxLine     = fs.Int("max-line-bytes", scrub.DefaultMaxLineBytes, "longest line scanned in one piece")
		maxKeyLines = fs.Int("max-private-key-lines", scrub.DefaultMaxPrivateKeyLines, "longest private key block masked line by line")
		mode        = fs.String("mode", "marker", "marker: [REDACTED:id]; pseudonym: stable tags for emails and IPs")
		keyFile     = fs.String("key-file", "", "file holding the pseudonym HMAC key (or set LOGSCRUB_KEY); default: random per run")
		configPath  = fs.String("config", "", "TOML rules file (enable/disable, allow-list, custom rules)")
		noConfig    = fs.Bool("no-config", false, "do not read the per-user config file")
		format      = fs.String("report-format", "text", "format of --report: text, json or sarif (locations only, never the matched text)")
		output      = fs.String("output", "", "write the cleaned text to this file (atomically, mode 0600) instead of stdout; gzip-compressed if it ends in .gz")
		mapPath     = fs.String("map-file", "", "with --mode pseudonym: record which text each tag stands for (mode 0600; sensitive) so `logscrub restore` can reverse it")
		inPlace     = fs.Bool("in-place", false, "rewrite each file with its cleaned text (atomically; files with nothing to mask are left untouched)")
		backup      = fs.String("backup-suffix", "", "with --in-place: keep the original next to the file under this suffix (for example .bak; it still holds the secrets)")
		recursive   = fs.Bool("recursive", false, "descend into directories (symlinks, .git/.hg/.svn and binary files are skipped)")
		include     = fs.String("include", "", "with --recursive: comma-separated file name globs to process (default: all)")
		exclude     = fs.String("exclude", "", "with --recursive: comma-separated file or directory name globs to skip")
	)
	fs.StringVar(output, "o", "", "short for --output")
	fs.BoolVar(inPlace, "i", false, "short for --in-place")
	fs.BoolVar(recursive, "r", false, "short for --recursive")
	fs.Usage = func() {
		outf(stderr, `Usage: logscrub [flags] [file ...]
       logscrub serve [flags]      (local web UI; see logscrub serve -h)
       logscrub restore --map-file FILE [file ...]   (put pseudonymised text back)
       logscrub completion bash|zsh|fish

Reads files (or stdin when none, or "-") and writes the text with secrets masked.
gzip input is detected and read transparently.
Pattern matching cannot find every secret: review the output before sharing it.

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

	if *showVersion {
		outf(stdout, "logscrub %s (%s)\n", orUnknown(version), orUnknown(commit))
		return exitOK
	}
	if *list {
		for _, d := range detect.All() {
			state := ""
			if d.Optional {
				state = " (off by default)"
			}
			outf(stdout, "%-20s %s%s\n", d.ID, d.Desc, state)
		}
		return exitOK
	}
	if *maxLine < 1024 {
		outf(stderr, "logscrub: --max-line-bytes must be at least 1024\n")
		return exitUsage
	}
	if *maxKeyLines < 1 {
		outf(stderr, "logscrub: --max-private-key-lines must be at least 1\n")
		return exitUsage
	}

	switch *format {
	case "text", "json", "sarif":
	default:
		outf(stderr, "logscrub: unknown --report-format %q (text, json or sarif)\n", *format)
		return exitUsage
	}
	if *output != "" && *check {
		outf(stderr, "logscrub: --output and --check cannot be combined (--check writes nothing)\n")
		return exitUsage
	}
	if *format != "text" && !*report {
		outf(stderr, "logscrub: --report-format needs --report\n")
		return exitUsage
	}
	if *mapPath != "" && (*mode != "pseudonym" || *check) {
		outf(stderr, "logscrub: --map-file needs --mode pseudonym and cannot be combined with --check\n")
		return exitUsage
	}
	walk := walkOptions{include: splitList(*include), exclude: splitList(*exclude), skipSuffix: *backup}
	if msg := checkFileFlags(fs.Args(), *inPlace, *recursive, *check, *output, *backup, walk); msg != "" {
		outf(stderr, "logscrub: %s\n", msg)
		return exitUsage
	}

	cfg, err := loadConfig(*configPath, *noConfig)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	allow, rules, err := cfg.Compile()
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	dets, err := selectDetectors(rules, cfg.Enable, cfg.Disable, splitList(*enable), splitList(*disable))
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	key, err := pseudonymKey(*mode, *keyFile)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}

	var files []inputFile
	if len(fs.Args()) > 0 {
		if files, err = expandInputs(fs.Args(), *recursive, walk); err != nil {
			outf(stderr, "logscrub: %v\n", err)
			return exitUsage
		}
	}

	if *mapPath != "" {
		files = dropFile(files, *mapPath) // the map holds the originals: never scrub it
	}

	out := io.Writer(stdout)
	var target *atomicFile
	var gz *gzipOutput
	switch {
	case *check:
		out = io.Discard
	case *output != "":
		target, err = newAtomicFile(*output, inputPaths(files))
		if err != nil {
			outf(stderr, "logscrub: %v\n", err)
			return exitUsage
		}
		out = target
		if strings.HasSuffix(*output, ".gz") {
			gz = newGzipOutput(target)
			out = gz
		}
	}

	col := &collector{}
	opts := scrub.Options{Detectors: dets, MaxLineBytes: *maxLine, MaxPrivateKeyLines: *maxKeyLines, Key: key, Allow: allow}
	var pmap *pseudoMap
	if *mapPath != "" {
		if pmap, err = loadPseudoMap(*mapPath); err != nil {
			outf(stderr, "logscrub: %v\n", err)
			return exitUsage
		}
		opts.OnPseudonym = pmap.record
	}
	saveMap := func() error {
		if pmap == nil {
			return nil
		}
		return pmap.save(*mapPath)
	}
	if *report && *format != "text" {
		opts.Observe = col.observe
	}
	s := scrub.New(opts)

	code := exitOK
	skipped := 0
	if *inPlace {
		code = scrubInPlace(s, col, files, *backup, stderr, &skipped, saveMap)
	} else if err := scrubInputs(s, col, files, stdin, out, &skipped); err != nil {
		// Messages from the engine and from os never contain input text.
		outf(stderr, "logscrub: %v\n", err)
		code = exitIOFail
	}
	if gz != nil && code == exitOK {
		if err := gz.Close(); err != nil {
			outf(stderr, "logscrub: --output: %v\n", err)
			code = exitIOFail
		}
	}
	if skipped > 0 {
		outf(stderr, "logscrub: skipped %d binary file(s)\n", skipped)
	}
	if target != nil {
		if code == exitOK {
			// The map must be on disk before the pseudonymised file replaces anything.
			if err := saveMap(); err != nil {
				outf(stderr, "logscrub: --map-file: %v\n", err)
				code = exitIOFail
			} else if err := target.Commit(); err != nil {
				outf(stderr, "logscrub: %v\n", err)
				code = exitIOFail
			}
		} else {
			target.Abort()
		}
	}

	if code == exitOK {
		if err := saveMap(); err != nil { // stdout output: nothing to hold back
			outf(stderr, "logscrub: --map-file: %v\n", err)
			code = exitIOFail
		}
	}
	res := s.Result()
	for _, w := range res.Warnings {
		outf(stderr, "logscrub: warning: %s\n", w)
	}
	if *report {
		dest := stderr
		if *check {
			dest = stdout
		}
		printReport(dest, *format, res, col, dets)
	}
	if code == exitOK && *check && res.Total() > 0 {
		code = exitFound
	}
	return code
}

// stdinName labels standard input in reports.
const stdinName = "<stdin>"

func scrubInputs(s *scrub.Scrubber, col *collector, files []inputFile, stdin io.Reader, out io.Writer, skipped *int) error {
	if len(files) == 0 {
		files = []inputFile{{path: "-"}}
	}
	for _, f := range files {
		col.file = f.path
		if f.path == "-" {
			col.file = stdinName
		}
		if err := scrubOne(s, f, stdin, out, skipped); err != nil {
			return err
		}
	}
	return nil
}

func scrubOne(s *scrub.Scrubber, f inputFile, stdin io.Reader, out io.Writer, skipped *int) error {
	src, err := openSource(f.path, stdin)
	if err != nil {
		return err
	}
	defer src.Close()
	if f.walked && src.looksBinary() {
		*skipped++
		return nil
	}
	return s.Run(src.r, out)
}

// selectDetectors starts from the built-ins that are on by default plus the
// custom rules, then applies the config's enable/disable lists and finally the
// command-line ones, so flags win over the file.
func selectDetectors(rules []*detect.Detector, lists ...[]string) ([]*detect.Detector, error) {
	all := append(detect.All(), rules...)
	on := map[string]bool{}
	for _, d := range all {
		on[d.ID] = !d.Optional
	}
	// lists alternate: config enable, config disable, flag enable, flag disable
	for i, ids := range lists {
		for _, id := range ids {
			if _, known := on[id]; !known {
				return nil, fmt.Errorf("unknown detector %q (see --list-detectors)", id)
			}
			on[id] = i%2 == 0
		}
	}
	var out []*detect.Detector
	for _, d := range all {
		if on[d.ID] {
			out = append(out, d)
		}
	}
	return out, nil
}

// pseudonymKey returns the HMAC key for pseudonym mode, nil for marker mode.
// The key is never taken from argv (it would show up in ps).
func pseudonymKey(mode, keyFile string) ([]byte, error) {
	switch mode {
	case "marker":
		if keyFile != "" {
			return nil, errors.New("--key-file only applies to --mode pseudonym")
		}
		return nil, nil
	case "pseudonym":
	default:
		return nil, fmt.Errorf("unknown --mode %q (marker or pseudonym)", mode)
	}
	var key []byte
	switch {
	case keyFile != "":
		raw, err := readSmallFile(keyFile)
		if err != nil {
			return nil, err
		}
		key = bytes.TrimRight(raw, "\r\n")
	case os.Getenv("LOGSCRUB_KEY") != "":
		key = []byte(os.Getenv("LOGSCRUB_KEY"))
	default:
		// No key given: tags are stable within this run only.
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("random key: %w", err)
		}
	}
	if len(key) < minKeyBytes {
		return nil, fmt.Errorf("the pseudonym key must be at least %d bytes", minKeyBytes)
	}
	return key, nil
}

const minKeyBytes = 16

func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the user's --key-file argument
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if len(raw) > 4096 {
		return nil, errors.New("key file is larger than 4 KiB")
	}
	return raw, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// outf writes diagnostics and help; a failed write to a closed pipe is not worth reporting.
func outf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

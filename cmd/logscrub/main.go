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
	"sort"
	"strings"

	"github.com/hbenali/logscrub/internal/config"
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
	if len(args) > 0 && args[0] == "serve" {
		return runServeSignals(args[1:], stderr)
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
		mode        = fs.String("mode", "marker", "marker: [REDACTED:id]; pseudonym: stable tags for emails and IPs")
		keyFile     = fs.String("key-file", "", "file holding the pseudonym HMAC key (or set LOGSCRUB_KEY); default: random per run")
		configPath  = fs.String("config", "", "TOML rules file (enable/disable, allow-list, custom rules)")
	)
	fs.Usage = func() {
		outf(stderr, `Usage: logscrub [flags] [file ...]
       logscrub serve [flags]      (local web UI; see logscrub serve -h)

Reads files (or stdin when none, or "-") and writes the text with secrets masked.
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
			outf(stdout, "%-16s %s%s\n", d.ID, d.Desc, state)
		}
		return exitOK
	}
	if *maxLine < 1024 {
		outf(stderr, "logscrub: --max-line-bytes must be at least 1024\n")
		return exitUsage
	}

	var cfg config.Config
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			outf(stderr, "logscrub: %v\n", err)
			return exitUsage
		}
		cfg = *c
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

	out := io.Writer(stdout)
	if *check {
		out = io.Discard
	}
	s := scrub.New(scrub.Options{Detectors: dets, MaxLineBytes: *maxLine, Key: key, Allow: allow})

	code := exitOK
	if err := scrubInputs(s, fs.Args(), stdin, out); err != nil {
		// Messages from the engine and from os never contain input text.
		outf(stderr, "logscrub: %v\n", err)
		code = exitIOFail
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
		printReport(dest, res)
	}
	if code == exitOK && *check && res.Total() > 0 {
		code = exitFound
	}
	return code
}

func scrubInputs(s *scrub.Scrubber, files []string, stdin io.Reader, out io.Writer) error {
	if len(files) == 0 {
		return s.Run(stdin, out)
	}
	for _, name := range files {
		if err := scrubOne(s, name, stdin, out); err != nil {
			return err
		}
	}
	return nil
}

func scrubOne(s *scrub.Scrubber, name string, stdin io.Reader, out io.Writer) error {
	if name == "-" {
		return s.Run(stdin, out)
	}
	f, err := os.Open(name) //nolint:gosec // opening the path the user asked for is the job
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	defer func() { _ = f.Close() }() // read-only: a close error cannot lose data
	return s.Run(f, out)
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

func printReport(w io.Writer, res *scrub.Result) {
	ids := make([]string, 0, len(res.Counts))
	for id := range res.Counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		outf(w, "%-16s %d\n", id, res.Counts[id])
	}
	outf(w, "%-16s %d\n", "total", res.Total())
}

// outf writes diagnostics and help; a failed write to a closed pipe is not worth reporting.
func outf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

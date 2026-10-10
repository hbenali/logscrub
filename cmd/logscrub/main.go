// Command logscrub masks secrets and personal data in logs.
//
//	some-command | logscrub > clean.log
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
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
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: logscrub [flags] [file ...]

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
		fmt.Fprintf(stdout, "logscrub %s (%s)\n", orUnknown(version), orUnknown(commit))
		return exitOK
	}
	if *list {
		for _, d := range detect.All() {
			fmt.Fprintf(stdout, "%-16s %s\n", d.ID, d.Desc)
		}
		return exitOK
	}
	if *maxLine < 1024 {
		fmt.Fprintln(stderr, "logscrub: --max-line-bytes must be at least 1024")
		return exitUsage
	}

	dets, err := selectDetectors(*enable, *disable)
	if err != nil {
		fmt.Fprintf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}

	var out io.Writer = stdout
	if *check {
		out = io.Discard
	}
	s := scrub.New(scrub.Options{Detectors: dets, MaxLineBytes: *maxLine})

	code := exitOK
	if err := scrubInputs(s, fs.Args(), stdin, out); err != nil {
		// Messages from the engine and from os never contain input text.
		fmt.Fprintf(stderr, "logscrub: %v\n", err)
		code = exitIOFail
	}

	res := s.Result()
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "logscrub: warning: %s\n", w)
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
	defer f.Close()
	return s.Run(f, out)
}

func selectDetectors(enable, disable string) ([]*detect.Detector, error) {
	off := map[string]bool{}
	for _, id := range splitList(disable) {
		if detect.ByID(id) == nil {
			return nil, fmt.Errorf("unknown detector %q (see --list-detectors)", id)
		}
		off[id] = true
	}
	for _, id := range splitList(enable) {
		if detect.ByID(id) == nil {
			return nil, fmt.Errorf("unknown detector %q (see --list-detectors)", id)
		}
	}
	var out []*detect.Detector
	for _, d := range detect.All() {
		if !off[d.ID] {
			out = append(out, d)
		}
	}
	return out, nil
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
		fmt.Fprintf(w, "%-16s %d\n", id, res.Counts[id])
	}
	fmt.Fprintf(w, "%-16s %d\n", "total", res.Total())
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

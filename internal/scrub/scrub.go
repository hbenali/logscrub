// Package scrub is the streaming engine: it reads text, masks whatever the
// detectors find and writes the result, in memory bounded by the longest
// permitted line.
//
// Error values never contain input text.
package scrub

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/hbenali/logscrub/internal/detect"
)

// Defaults for Options.
const (
	DefaultMaxLineBytes       = 1 << 20
	DefaultMaxPrivateKeyLines = 200
	defaultReadBuffer         = 64 << 10
	defaultOverlap            = 16 << 10
)

// ErrLineTooLong is returned when a line cannot be scanned within the memory
// bound. The engine fails instead of emitting text it could not scan.
var ErrLineTooLong = errors.New("scrub: line too long to scan safely")

// Options configures a Scrubber. Zero values select the defaults.
type Options struct {
	Detectors          []*detect.Detector
	MaxLineBytes       int
	MaxPrivateKeyLines int

	// Tuning knobs, exposed for tests. Overlap should be at least the longest
	// secret you expect; matches longer than it may be split at a window edge.
	ReadBufferSize int
	Overlap        int
}

// Result summarises one run. It holds counts only, never matched text.
type Result struct {
	Counts   map[string]int
	Warnings []string
}

// Total is the number of masked items.
func (r *Result) Total() int {
	n := 0
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// Scrubber masks secrets in a stream. It is not safe for concurrent use.
type Scrubber struct {
	dets     []*detect.Detector
	markers  []string
	maxLine  int
	maxPKLns int
	bufSize  int
	overlap  int

	res Result

	pkEnabled  bool
	inBlock    bool
	blockLines int
}

// New builds a Scrubber.
func New(o Options) *Scrubber {
	s := &Scrubber{
		dets:     o.Detectors,
		maxLine:  orDefault(o.MaxLineBytes, DefaultMaxLineBytes),
		maxPKLns: orDefault(o.MaxPrivateKeyLines, DefaultMaxPrivateKeyLines),
		bufSize:  orDefault(o.ReadBufferSize, defaultReadBuffer),
	}
	s.overlap = orDefault(o.Overlap, min(defaultOverlap, s.maxLine/4))
	if s.overlap < 1 {
		s.overlap = 1
	}
	for _, d := range s.dets {
		s.markers = append(s.markers, d.Marker())
		if d.ID == "private-key" {
			s.pkEnabled = true
		}
	}
	s.res.Counts = map[string]int{}
	return s
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Result returns the counts collected so far.
func (s *Scrubber) Result() *Result { return &s.res }

// Run copies r to w with secrets masked. It can be called once per input;
// counts accumulate across calls and a private key block never spans inputs.
func (s *Scrubber) Run(r io.Reader, w io.Writer) error {
	s.inBlock = false
	br := bufio.NewReaderSize(r, s.bufSize)
	bw := bufio.NewWriterSize(w, defaultReadBuffer)

	var pending []byte // bytes of the current line not yet emitted
	for {
		chunk, err := br.ReadSlice('\n')
		pending = append(pending, chunk...)
		switch {
		case err == nil:
			if herr := s.handleLine(pending, bw); herr != nil {
				return herr
			}
			pending = pending[:0]
		case errors.Is(err, bufio.ErrBufferFull):
			if len(pending) >= s.maxLine {
				var ferr error
				if pending, ferr = s.flushWindow(pending, bw); ferr != nil {
					return ferr
				}
			}
		case errors.Is(err, io.EOF):
			if len(pending) > 0 {
				if herr := s.handleLine(pending, bw); herr != nil {
					return herr
				}
			}
			return bw.Flush()
		default:
			return fmt.Errorf("scrub: read: %w", err)
		}
	}
}

// handleLine processes one complete line (possibly without a final newline).
func (s *Scrubber) handleLine(line []byte, w *bufio.Writer) error {
	body, eol := splitEOL(line)

	if s.inBlock {
		loc := detect.PrivateKeyEnd.FindIndex(body)
		if loc == nil {
			s.blockLines++
			if s.blockLines >= s.maxPKLns {
				s.inBlock = false
				s.res.Warnings = append(s.res.Warnings, fmt.Sprintf(
					"private key block longer than %d lines: the rest of it is not masked", s.maxPKLns))
			}
			return nil // the line is part of the key: dropped
		}
		s.inBlock = false
		return s.emit(body[loc[1]:], eol, w)
	}

	if loc := detect.PrivateKeyBegin.FindIndex(body); s.pkEnabled && loc != nil &&
		!detect.PrivateKeyEnd.Match(body[loc[1]:]) {
		// A block opens here and does not close on this line: mask from the
		// BEGIN marker on, and swallow lines until the END marker.
		if err := s.emit(body[:loc[0]], nil, w); err != nil {
			return err
		}
		s.count("private-key")
		s.inBlock, s.blockLines = true, 0
		_, err := w.WriteString(detect.MarkerPrefix + "private-key]")
		return err
	}
	return s.emit(body, eol, w)
}

// emit scrubs a whole segment and writes it followed by eol.
func (s *Scrubber) emit(seg, eol []byte, w *bufio.Writer) error {
	ms := s.findMatches(seg)
	if err := s.writeReplaced(seg, ms, w); err != nil {
		return err
	}
	_, err := w.Write(eol)
	return err
}

// flushWindow handles a line that does not fit in MaxLineBytes: it scans the
// buffered part, emits everything that cannot be affected by later input and
// returns the rest to be carried over.
func (s *Scrubber) flushWindow(buf []byte, w *bufio.Writer) ([]byte, error) {
	ms := s.findMatches(buf)
	cut := len(buf) - s.overlap
	for _, m := range ms {
		// Use the whole match, not just the masked part: cutting between a
		// key and its value would leave a value no pattern recognises.
		if m.from < cut && m.end > cut {
			cut = m.from
		}
	}
	if cut <= 0 {
		if len(buf) >= 4*s.maxLine {
			return buf, ErrLineTooLong
		}
		return buf, nil // grow and retry with more context
	}
	head := ms[:0:0]
	for _, m := range ms {
		if m.end <= cut {
			head = append(head, m)
		}
	}
	if err := s.writeReplaced(buf[:cut], head, w); err != nil {
		return buf, err
	}
	n := copy(buf, buf[cut:])
	return buf[:n], nil
}

func splitEOL(line []byte) (body, eol []byte) {
	switch {
	case bytes.HasSuffix(line, []byte("\r\n")):
		return line[:len(line)-2], line[len(line)-2:]
	case bytes.HasSuffix(line, []byte("\n")):
		return line[:len(line)-1], line[len(line)-1:]
	}
	return line, nil
}

type match struct {
	start, end int // span that is replaced
	from       int // start of the whole regexp match, including context such as the key
	det        int
}

// findMatches returns non-overlapping matches sorted by position. Overlaps are
// resolved by earlier start, then longer span, then detector priority.
func (s *Scrubber) findMatches(b []byte) []match {
	var all []match
	for di, d := range s.dets {
		for _, re := range d.Patterns {
			for _, loc := range re.FindAllSubmatchIndex(b, -1) {
				start, end := spanOf(loc, d.Groups)
				if start < 0 || start >= end {
					continue
				}
				secret := b[start:end]
				if bytes.HasPrefix(secret, []byte(detect.MarkerPrefix)) {
					continue
				}
				if d.Validate != nil && !d.Validate(secret) {
					continue
				}
				all = append(all, match{start, end, loc[0], di})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		a, c := all[i], all[j]
		if a.start != c.start {
			return a.start < c.start
		}
		if a.end != c.end {
			return a.end > c.end
		}
		return a.det < c.det
	})
	out := all[:0]
	last := -1
	for _, m := range all {
		if m.start < last {
			continue
		}
		out = append(out, m)
		last = m.end
	}
	return out
}

func spanOf(loc, groups []int) (int, int) {
	if len(groups) == 0 {
		return loc[0], loc[1]
	}
	for _, g := range groups {
		if 2*g+1 < len(loc) && loc[2*g] >= 0 {
			return loc[2*g], loc[2*g+1]
		}
	}
	return -1, -1
}

func (s *Scrubber) writeReplaced(b []byte, ms []match, w *bufio.Writer) error {
	pos := 0
	for _, m := range ms {
		if _, err := w.Write(b[pos:m.start]); err != nil {
			return err
		}
		if _, err := w.WriteString(s.markers[m.det]); err != nil {
			return err
		}
		s.count(s.dets[m.det].ID)
		pos = m.end
	}
	_, err := w.Write(b[pos:])
	return err
}

func (s *Scrubber) count(id string) { s.res.Counts[id]++ }

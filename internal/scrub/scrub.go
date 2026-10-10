// Package scrub is the streaming engine: it reads text, masks whatever the
// detectors find and writes the result, in memory bounded by the longest
// permitted line.
//
// Error values never contain input text.
package scrub

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

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

	// Key switches pseudonym mode on: detectors marked Pseudonym are replaced
	// by a stable HMAC-SHA256 tag instead of a fixed marker.
	Key []byte
	// Allow, if set, is asked about every candidate; true leaves it unmasked.
	Allow func(secret []byte) bool
	// Observe, if set, is called for every replacement (used by the web UI to
	// highlight what would be masked). It must not retain the Span's strings
	// beyond what it needs; it never sees the masked text itself.
	Observe func(Span)

	// Tuning knobs, exposed for tests. Overlap should be at least the longest
	// secret you expect; matches longer than it may be split at a window edge.
	ReadBufferSize int
	Overlap        int
	NoPrefilter    bool
}

// Span is one replacement, as byte offsets into the input stream: the input
// bytes [Start, End) were replaced by Replacement. Spans are reported in
// order and never overlap; applying them to the input reproduces the output.
//
// Line and Column locate the start (1-based; Column counts bytes) and EndLine
// the line of the last byte, which differs from Line only for private key
// blocks that span lines.
type Span struct {
	Start, End  int64
	Line        int64
	Column      int64
	EndLine     int64
	Detector    string
	Replacement string
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
	hints    [][][]byte
	needFold bool
	key      []byte
	allow    func([]byte) bool
	noPre    bool
	observe  func(Span)
	maxLine  int
	maxPKLns int
	bufSize  int
	overlap  int

	res Result

	pkEnabled  bool
	inBlock    bool
	blockLines int
	blockStart int64

	lineNo, lineStart       int64 // position of the line being processed
	blockLine, blockLineBeg int64 // where the open private key block started
}

// New builds a Scrubber.
func New(o Options) *Scrubber {
	s := &Scrubber{
		dets:     o.Detectors,
		maxLine:  orDefault(o.MaxLineBytes, DefaultMaxLineBytes),
		maxPKLns: orDefault(o.MaxPrivateKeyLines, DefaultMaxPrivateKeyLines),
		bufSize:  orDefault(o.ReadBufferSize, defaultReadBuffer),
	}
	s.key, s.allow, s.noPre, s.observe = o.Key, o.Allow, o.NoPrefilter, o.Observe
	s.overlap = orDefault(o.Overlap, min(defaultOverlap, s.maxLine/4))
	if s.overlap < 1 {
		s.overlap = 1
	}
	for _, d := range s.dets {
		s.markers = append(s.markers, d.Marker())
		var hs [][]byte
		for _, h := range d.Hints {
			hs = append(hs, []byte(h))
		}
		s.hints = append(s.hints, hs)
		s.needFold = s.needFold || (d.FoldHints && len(d.Hints) > 0)
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
	var base int64     // stream offset of pending[0]
	s.lineNo, s.lineStart = 1, 0
	for {
		chunk, err := br.ReadSlice('\n')
		pending = append(pending, chunk...)
		switch {
		case err == nil:
			if herr := s.handleLine(pending, base, bw); herr != nil {
				return herr
			}
			base += int64(len(pending))
			pending = pending[:0]
			s.lineNo++
			s.lineStart = base
		case errors.Is(err, bufio.ErrBufferFull):
			if len(pending) >= s.maxLine {
				rest, cut, ferr := s.flushWindow(pending, base, bw)
				if ferr != nil {
					return ferr
				}
				pending = rest
				base += int64(cut)
			}
		case errors.Is(err, io.EOF):
			if len(pending) > 0 {
				if herr := s.handleLine(pending, base, bw); herr != nil {
					return herr
				}
				base += int64(len(pending))
			}
			if s.inBlock { // a key block that never ended runs to the end of input
				s.reportBlock(base, "private-key", detect.MarkerPrefix+"private-key]")
			}
			return bw.Flush()
		default:
			return fmt.Errorf("scrub: read: %w", err)
		}
	}
}

var privateKeyHint = []byte("PRIVATE KEY")

// handleLine processes one complete line (possibly without a final newline);
// base is the stream offset of line[0].
func (s *Scrubber) handleLine(line []byte, base int64, w *bufio.Writer) error {
	body, eol := splitEOL(line)

	if s.inBlock {
		loc := detect.PrivateKeyEnd.FindIndex(body)
		if loc == nil {
			s.blockLines++
			if s.blockLines >= s.maxPKLns {
				s.inBlock = false
				s.reportBlock(base+int64(len(line)), "private-key", detect.MarkerPrefix+"private-key]")
				s.res.Warnings = append(s.res.Warnings, fmt.Sprintf(
					"private key block longer than %d lines: the rest of it is not masked", s.maxPKLns))
			}
			return nil // the line is part of the key: dropped
		}
		s.inBlock = false
		s.reportBlock(base+int64(loc[1]), "private-key", detect.MarkerPrefix+"private-key]")
		return s.emit(body[loc[1]:], eol, base+int64(loc[1]), w)
	}

	if !s.pkEnabled || !bytes.Contains(body, privateKeyHint) {
		return s.emit(body, eol, base, w)
	}
	if loc := detect.PrivateKeyBegin.FindIndex(body); loc != nil &&
		!detect.PrivateKeyEnd.Match(body[loc[1]:]) {
		// A block opens here and does not close on this line: mask from the
		// BEGIN marker on, and swallow lines until the END marker.
		if err := s.emit(body[:loc[0]], nil, base, w); err != nil {
			return err
		}
		s.count("private-key")
		s.inBlock, s.blockLines, s.blockStart = true, 0, base+int64(loc[0])
		s.blockLine, s.blockLineBeg = s.lineNo, s.lineStart
		_, err := w.WriteString(detect.MarkerPrefix + "private-key]")
		return err
	}
	return s.emit(body, eol, base, w)
}

// emit scrubs a whole segment, starting at stream offset base, and writes it
// followed by eol.
func (s *Scrubber) emit(seg, eol []byte, base int64, w *bufio.Writer) error {
	ms := s.findMatches(seg)
	if err := s.writeReplaced(seg, ms, base, w); err != nil {
		return err
	}
	_, err := w.Write(eol)
	return err
}

// flushWindow handles a line that does not fit in MaxLineBytes: it scans the
// buffered part, emits everything that cannot be affected by later input and
// returns the rest to be carried over, with the number of bytes consumed.
func (s *Scrubber) flushWindow(buf []byte, base int64, w *bufio.Writer) (rest []byte, consumed int, err error) {
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
			return buf, 0, ErrLineTooLong
		}
		return buf, 0, nil // grow and retry with more context
	}
	head := ms[:0:0]
	for _, m := range ms {
		if m.end <= cut {
			head = append(head, m)
		}
	}
	if err := s.writeReplaced(buf[:cut], head, base, w); err != nil {
		return buf, 0, err
	}
	n := copy(buf, buf[cut:])
	return buf[:n], cut, nil
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
	var lower []byte
	if s.needFold && !s.noPre {
		lower = foldLower(b)
	}
	for di, d := range s.dets {
		if !s.noPre && !s.wants(di, b, lower) {
			continue
		}
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
				if d.Check != nil && !d.Check(b, start, end) {
					continue
				}
				if s.allow != nil && s.allow(secret) {
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

// wants is the prefilter: can detector di possibly match this line?
func (s *Scrubber) wants(di int, b, lower []byte) bool {
	d := s.dets[di]
	if hs := s.hints[di]; len(hs) > 0 {
		hay := b
		if d.FoldHints {
			hay = lower
		}
		found := false
		for _, h := range hs {
			if bytes.Contains(hay, h) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return d.Pre == nil || d.Pre(b)
}

// foldLower lowercases ASCII and maps the two non-ASCII characters Go's
// case-insensitive regexps fold onto ASCII letters (U+017F to s, U+212A to k),
// so a hint test agrees with what a (?i) pattern would match.
func foldLower(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+'a'-'A')
		case c == 0xC5 && i+1 < len(b) && b[i+1] == 0xBF:
			out = append(out, 's')
			i++
		case c == 0xE2 && i+2 < len(b) && b[i+1] == 0x84 && b[i+2] == 0xAA:
			out = append(out, 'k')
			i += 2
		default:
			out = append(out, c)
		}
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

func (s *Scrubber) writeReplaced(b []byte, ms []match, base int64, w *bufio.Writer) error {
	pos := 0
	for _, m := range ms {
		if _, err := w.Write(b[pos:m.start]); err != nil {
			return err
		}
		rep := s.replacement(m.det, b[m.start:m.end])
		if _, err := w.WriteString(rep); err != nil {
			return err
		}
		s.count(s.dets[m.det].ID)
		s.report(base+int64(m.start), base+int64(m.end), s.dets[m.det].ID, rep)
		pos = m.end
	}
	_, err := w.Write(b[pos:])
	return err
}

// replacement is the marker, or in pseudonym mode a stable tag derived from
// HMAC-SHA256(key, id || 0 || canonical value) for detectors that opt in.
func (s *Scrubber) replacement(di int, secret []byte) string {
	d := s.dets[di]
	if s.key == nil || !d.Pseudonym {
		return s.markers[di]
	}
	canon := secret
	if d.Canonical != nil {
		canon = d.Canonical(secret)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(d.ID))
	mac.Write([]byte{0})
	mac.Write(canon)
	tag := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)))[:8]
	return "[" + d.ID + ":" + tag + "]"
}

func (s *Scrubber) report(start, end int64, id, replacement string) {
	if s.observe != nil {
		s.observe(Span{
			Start: start, End: end, Line: s.lineNo, Column: start - s.lineStart + 1, EndLine: s.lineNo,
			Detector: id, Replacement: replacement,
		})
	}
}

// reportBlock reports a private key block that began on an earlier line.
func (s *Scrubber) reportBlock(end int64, id, replacement string) {
	if s.observe != nil {
		s.observe(Span{
			Start: s.blockStart, End: end, Line: s.blockLine, Column: s.blockStart - s.blockLineBeg + 1, EndLine: s.lineNo,
			Detector: id, Replacement: replacement,
		})
	}
}

func (s *Scrubber) count(id string) { s.res.Counts[id]++ }

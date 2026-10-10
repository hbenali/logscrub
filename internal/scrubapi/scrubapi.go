// Package scrubapi is the request/response layer shared by the local web
// server (internal/serve) and the in-browser WebAssembly demo: one request
// (text, detector ids, mode) in, one response (cleaned text, match spans,
// counts) out. Keeping it in one place means the two front ends cannot drift.
//
// Error messages never contain the request's text.
package scrubapi

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// MaxSpans bounds the spans returned for highlighting; counts stay exact.
const MaxSpans = 100000

// Request is one scrub request.
type Request struct {
	Text string `json:"text"`
	// Detectors lists the ids to run; nil means the configured defaults, and an
	// empty list means none.
	Detectors []string `json:"detectors"`
	Mode      string   `json:"mode"` // "", "marker" or "pseudonym"
}

// Span is one replacement, as UTF-8 byte offsets into the request text.
type Span struct {
	Start       int64  `json:"start"`
	End         int64  `json:"end"`
	Detector    string `json:"detector"`
	Replacement string `json:"replacement"`
}

// Response is the result of a scrub request.
type Response struct {
	Output         string         `json:"output"`
	Spans          []Span         `json:"spans"`
	SpansTruncated bool           `json:"spansTruncated"`
	Counts         map[string]int `json:"counts"`
	Warnings       []string       `json:"warnings"`
}

// Error is a failure with the HTTP status the web server should use.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// DetectorInfo describes a detector for the UI's checkbox list.
type DetectorInfo struct {
	ID        string `json:"id"`
	Desc      string `json:"desc"`
	Optional  bool   `json:"optional"`
	Pseudonym bool   `json:"pseudonym"`
	Default   bool   `json:"default"`
}

// Config is the server-side (or page-side) setup a request runs against.
type Config struct {
	Detectors          []*detect.Detector // everything that may be offered
	DefaultOn          []string           // ids that start checked
	Allow              func([]byte) bool
	Key                []byte // HMAC key for pseudonym mode; nil disables the mode
	MaxTextBytes       int64
	MaxLineBytes       int
	MaxPrivateKeyLines int
}

// Infos lists the detectors for the UI.
func (c *Config) Infos() []DetectorInfo {
	on := map[string]bool{}
	for _, id := range c.DefaultOn {
		on[id] = true
	}
	out := make([]DetectorInfo, 0, len(c.Detectors))
	for _, d := range c.Detectors {
		out = append(out, DetectorInfo{d.ID, d.Desc, d.Optional, d.Pseudonym, on[d.ID]})
	}
	return out
}

func (c *Config) pick(ids []string) ([]*detect.Detector, *Error) {
	if ids == nil {
		ids = c.DefaultOn
	}
	byID := make(map[string]bool, len(c.Detectors))
	for _, d := range c.Detectors {
		byID[d.ID] = true
	}
	want := map[string]bool{}
	for _, id := range ids {
		if !byID[id] {
			return nil, &Error{http.StatusBadRequest, "unknown detector id"}
		}
		want[id] = true
	}
	var out []*detect.Detector
	for _, d := range c.Detectors { // keep priority order
		if want[d.ID] {
			out = append(out, d)
		}
	}
	return out, nil
}

// Run scrubs req.Text.
func (c *Config) Run(req Request) (*Response, *Error) {
	if c.MaxTextBytes > 0 && int64(len(req.Text)) > c.MaxTextBytes {
		return nil, &Error{http.StatusRequestEntityTooLarge, fmt.Sprintf("text is larger than %d bytes", c.MaxTextBytes)}
	}
	dets, perr := c.pick(req.Detectors)
	if perr != nil {
		return nil, perr
	}
	var key []byte
	switch req.Mode {
	case "", "marker":
	case "pseudonym":
		if c.Key == nil {
			return nil, &Error{http.StatusBadRequest, "pseudonym mode is not available (no key)"}
		}
		key = c.Key
	default:
		return nil, &Error{http.StatusBadRequest, "mode must be marker or pseudonym"}
	}

	spans := []Span{}
	truncated := false
	sc := scrub.New(scrub.Options{
		Detectors: dets, MaxLineBytes: c.MaxLineBytes, MaxPrivateKeyLines: c.MaxPrivateKeyLines, Key: key, Allow: c.Allow,
		Observe: func(sp scrub.Span) {
			if len(spans) >= MaxSpans {
				truncated = true
				return
			}
			spans = append(spans, Span{sp.Start, sp.End, sp.Detector, sp.Replacement})
		},
	})
	var out bytes.Buffer
	if err := sc.Run(strings.NewReader(req.Text), &out); err != nil {
		if errors.Is(err, scrub.ErrLineTooLong) {
			return nil, &Error{http.StatusUnprocessableEntity, "a line is too long to scan safely"}
		}
		return nil, &Error{http.StatusInternalServerError, "scrubbing failed"}
	}
	res := sc.Result()
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	counts := res.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	return &Response{Output: out.String(), Spans: spans, SpansTruncated: truncated, Counts: counts, Warnings: warnings}, nil
}

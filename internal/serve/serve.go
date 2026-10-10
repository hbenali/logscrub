// Package serve is the local web UI: paste or drop a log, see what would be
// masked, download the cleaned text. The text is processed in memory by the
// same engine as the CLI and is never written to disk or logged; the page
// loads nothing from anywhere else (strict CSP, no CDN, no analytics).
//
// The server is reachable from every web page the user visits, so it defends
// itself: loopback bind by default, Host checks against DNS rebinding, Origin
// and Content-Type checks against cross-site requests, size and concurrency
// limits.
package serve

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

//go:embed web
var webFS embed.FS

// Defaults for Options.
const (
	DefaultAddr         = "127.0.0.1:8080"
	DefaultMaxBodyBytes = 10 << 20
	defaultConcurrency  = 4
	maxSpans            = 100000
)

// Options configures the server. Zero values select the defaults.
type Options struct {
	Addr string
	// AllowRemote permits binding a non-loopback address. The UI has no
	// authentication, so this is a deliberate act.
	AllowRemote  bool
	MaxBodyBytes int64
	MaxLineBytes int
	Concurrency  int

	// Detectors are all the detectors the UI may offer (built-ins and custom
	// rules); DefaultOn lists the ids that start checked.
	Detectors []*detect.Detector
	DefaultOn []string
	Allow     func([]byte) bool
	// Key is the HMAC key for pseudonym mode. It stays on the server.
	Key     []byte
	Version string
}

func (o *Options) fill() {
	if o.Addr == "" {
		o.Addr = DefaultAddr
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.Concurrency <= 0 {
		o.Concurrency = defaultConcurrency
	}
}

// Run serves until ctx is cancelled. Progress and errors go to logw; request
// bodies and masked text never do.
func Run(ctx context.Context, o Options, logw io.Writer) error {
	o.fill()
	host, _, err := net.SplitHostPort(o.Addr)
	if err != nil {
		return fmt.Errorf("serve: bad --addr %q: %w", o.Addr, err)
	}
	loopback := isLoopbackHost(host)
	if !loopback && !o.AllowRemote {
		return fmt.Errorf("serve: %q is not a loopback address and the UI has no authentication; pass --allow-remote if you really mean it", o.Addr)
	}
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer func() { _ = ln.Close() }()

	h := NewHandler(o, allowedHosts(ln.Addr().String(), loopback), !loopback)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(logw, "logscrub: ", 0),
	}
	if _, err := fmt.Fprintf(logw, "logscrub: web UI on http://%s (text is processed in memory by this process and goes nowhere else)\n", ln.Addr()); err != nil {
		return err
	}
	if !loopback {
		_, _ = fmt.Fprintln(logw, "logscrub: warning: listening on a non-loopback address; the UI has no authentication")
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// allowedHosts lists the Host header values accepted for a loopback bind. A
// DNS-rebinding page reaches the server under its own name, which is not in
// this list.
func allowedHosts(listen string, loopback bool) map[string]bool {
	host, port, _ := net.SplitHostPort(listen)
	set := map[string]bool{}
	add := func(h string) {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		set[strings.ToLower(h+":"+port)] = true
		if port == "80" {
			set[strings.ToLower(h)] = true
		}
	}
	add(host)
	if loopback {
		add("localhost")
		add("127.0.0.1")
		add("::1")
	}
	return set
}

// asset is an embedded file, loaded once at start-up.
type asset struct {
	contentType string
	body        []byte
}

type server struct {
	o        Options
	hosts    map[string]bool
	anyHost  bool
	sem      chan struct{}
	static   map[string]asset // URL path -> file; the only files ever served
	byID     map[string]*detect.Detector
	defaults map[string]bool
}

// NewHandler builds the HTTP handler. hosts is the set of accepted Host header
// values (lower case, with port); anyHost accepts every Host, for deliberate
// remote binds (the Origin must still match the Host).
func NewHandler(o Options, hosts map[string]bool, anyHost bool) http.Handler {
	o.fill()
	s := &server{
		o: o, hosts: hosts, anyHost: anyHost,
		sem:      make(chan struct{}, o.Concurrency),
		static:   loadAssets(),
		byID:     map[string]*detect.Detector{},
		defaults: map[string]bool{},
	}
	for _, d := range o.Detectors {
		s.byID[d.ID] = d
	}
	for _, id := range o.DefaultOn {
		s.defaults[id] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detectors", s.handleDetectors)
	mux.HandleFunc("/api/scrub", s.handleScrub)
	mux.HandleFunc("/", s.handleStatic)
	return s.protect(mux)
}

// contentSecurityPolicy lets the page load only its own files and talk only to
// this server.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// protect sets the security headers on every response (errors included) and
// rejects requests with an unexpected Host.
func (s *server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		if !s.anyHost && !s.hosts[strings.ToLower(r.Host)] {
			writeError(w, http.StatusForbidden, "unexpected Host header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loadAssets reads the fixed set of embedded files. Requests never choose a
// file name: they only look up a path in this map.
func loadAssets() map[string]asset {
	files := []struct{ path, name, contentType string }{
		{"/", "index.html", "text/html; charset=utf-8"},
		{"/index.html", "index.html", "text/html; charset=utf-8"},
		{"/app.js", "app.js", "text/javascript; charset=utf-8"},
		{"/style.css", "style.css", "text/css; charset=utf-8"},
	}
	out := make(map[string]asset, len(files))
	for _, f := range files {
		body, err := fs.ReadFile(webFS, "web/"+f.name)
		if err != nil {
			panic(err) // the embedded tree is fixed at build time
		}
		out[f.path] = asset{f.contentType, body}
	}
	return out
}

func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a, ok := s.static[r.URL.Path]
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	_, _ = w.Write(a.body)
}

type detectorInfo struct {
	ID        string `json:"id"`
	Desc      string `json:"desc"`
	Optional  bool   `json:"optional"`
	Pseudonym bool   `json:"pseudonym"`
	Default   bool   `json:"default"`
}

func (s *server) handleDetectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	infos := make([]detectorInfo, 0, len(s.o.Detectors))
	for _, d := range s.o.Detectors {
		infos = append(infos, detectorInfo{d.ID, d.Desc, d.Optional, d.Pseudonym, s.defaults[d.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"detectors":    infos,
		"maxBodyBytes": s.o.MaxBodyBytes,
		"version":      s.o.Version,
	})
}

type scrubRequest struct {
	Text      string   `json:"text"`
	Detectors []string `json:"detectors"`
	Mode      string   `json:"mode"`
}

type spanOut struct {
	Start       int64  `json:"start"`
	End         int64  `json:"end"`
	Detector    string `json:"detector"`
	Replacement string `json:"replacement"`
}

func (s *server) handleScrub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if msg := s.checkOrigin(r); msg != "" {
		writeError(w, http.StatusForbidden, msg)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "busy: too many requests in flight")
		return
	}

	// JSON escaping can inflate the text, so allow some headroom on the raw
	// body and enforce the real limit on the decoded text below.
	r.Body = http.MaxBytesReader(w, r.Body, 2*s.o.MaxBodyBytes+(64<<10))
	var req scrubRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if int64(len(req.Text)) > s.o.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("text is larger than %d bytes", s.o.MaxBodyBytes))
		return
	}

	dets, err := s.pickDetectors(req.Detectors)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var key []byte
	switch req.Mode {
	case "", "marker":
	case "pseudonym":
		if s.o.Key == nil {
			writeError(w, http.StatusBadRequest, "pseudonym mode is not available (no key)")
			return
		}
		key = s.o.Key
	default:
		writeError(w, http.StatusBadRequest, "mode must be marker or pseudonym")
		return
	}

	var spans []spanOut
	truncated := false
	sc := scrub.New(scrub.Options{
		Detectors: dets, MaxLineBytes: s.o.MaxLineBytes, Key: key, Allow: s.o.Allow,
		Observe: func(sp scrub.Span) {
			if len(spans) >= maxSpans {
				truncated = true
				return
			}
			spans = append(spans, spanOut{sp.Start, sp.End, sp.Detector, sp.Replacement})
		},
	})
	var out bytes.Buffer
	if err := sc.Run(strings.NewReader(req.Text), &out); err != nil {
		if errors.Is(err, scrub.ErrLineTooLong) {
			writeError(w, http.StatusUnprocessableEntity, "a line is too long to scan safely")
			return
		}
		writeError(w, http.StatusInternalServerError, "scrubbing failed")
		return
	}
	res := sc.Result()
	if spans == nil {
		spans = []spanOut{}
	}
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"output":         out.String(),
		"spans":          spans,
		"spansTruncated": truncated,
		"counts":         res.Counts,
		"warnings":       warnings,
	})
}

func (s *server) pickDetectors(ids []string) ([]*detect.Detector, error) {
	if ids == nil {
		for _, d := range s.o.Detectors {
			if s.defaults[d.ID] {
				ids = append(ids, d.ID)
			}
		}
	}
	want := map[string]bool{}
	for _, id := range ids {
		if _, ok := s.byID[id]; !ok {
			return nil, errors.New("unknown detector id")
		}
		want[id] = true
	}
	var out []*detect.Detector
	for _, d := range s.o.Detectors { // keep priority order
		if want[d.ID] {
			out = append(out, d)
		}
	}
	return out, nil
}

// checkOrigin returns an error message if the request did not come from this
// page. Browsers always send Origin on a cross-origin POST.
func (s *server) checkOrigin(r *http.Request) string {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return "cross-site request refused"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return "missing Origin header"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || !strings.EqualFold(u.Host, r.Host) {
		return "cross-origin request refused"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError never includes request content.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

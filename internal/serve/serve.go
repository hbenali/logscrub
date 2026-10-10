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
	"context"
	"crypto/subtle"
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
	"github.com/hbenali/logscrub/internal/scrubapi"
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
	// MaxPrivateKeyLines bounds how many lines of an unterminated private key
	// block are masked (the scrub package default when zero).
	MaxPrivateKeyLines int
	Concurrency        int

	// Detectors are all the detectors the UI may offer (built-ins and custom
	// rules); DefaultOn lists the ids that start checked.
	Detectors []*detect.Detector
	DefaultOn []string
	Allow     func([]byte) bool
	// Key is the HMAC key for pseudonym mode. It stays on the server.
	Key     []byte
	Version string

	// Token, if set, must accompany every API request as "Authorization:
	// Bearer TOKEN". A non-loopback bind requires one (the CLI generates it).
	// ShowToken makes the start-up message print a URL carrying the token in its
	// fragment, which browsers never send to a server.
	Token     string
	ShowToken bool
}

// MinTokenBytes is the shortest accepted access token.
const MinTokenBytes = 16

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
		return fmt.Errorf("serve: %q is not a loopback address; pass --allow-remote (an access token is then required)", o.Addr)
	}
	if o.Token != "" && len(o.Token) < MinTokenBytes {
		return fmt.Errorf("serve: the access token must be at least %d characters", MinTokenBytes)
	}
	if !loopback && o.Token == "" {
		return errors.New("serve: a non-loopback address needs an access token")
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
	shown := displayAddr(ln.Addr().String())
	if _, err := fmt.Fprintf(logw, "logscrub: web UI on http://%s (text is processed in memory by this process and goes nowhere else)\n", shown); err != nil {
		return err
	}
	if o.Token != "" {
		if o.ShowToken {
			_, _ = fmt.Fprintf(logw, "logscrub: access token required; open http://%s/#token=%s\n", shown, o.Token)
		} else {
			_, _ = fmt.Fprintln(logw, "logscrub: access token required (it was supplied by you and is not printed)")
		}
	}
	if !loopback {
		_, _ = fmt.Fprintln(logw, "logscrub: warning: this is plain HTTP, so the token and your text cross the network unencrypted; use an SSH tunnel or a TLS reverse proxy")
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

// displayAddr turns a listen address into one a person can open: a bind on all
// interfaces ([::] or 0.0.0.0) is shown as localhost.
func displayAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return net.JoinHostPort("localhost", port)
	}
	return listen
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
	o       Options
	hosts   map[string]bool
	anyHost bool
	sem     chan struct{}
	static  map[string]asset // URL path -> file; the only files ever served
	api     *scrubapi.Config
}

// NewHandler builds the HTTP handler. hosts is the set of accepted Host header
// values (lower case, with port); anyHost accepts every Host, for deliberate
// remote binds (the Origin must still match the Host).
func NewHandler(o Options, hosts map[string]bool, anyHost bool) http.Handler {
	o.fill()
	s := &server{
		o: o, hosts: hosts, anyHost: anyHost,
		sem:    make(chan struct{}, o.Concurrency),
		static: loadAssets(),
		api: &scrubapi.Config{
			Detectors: o.Detectors, DefaultOn: o.DefaultOn, Allow: o.Allow, Key: o.Key,
			MaxTextBytes: o.MaxBodyBytes, MaxLineBytes: o.MaxLineBytes, MaxPrivateKeyLines: o.MaxPrivateKeyLines,
		},
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

// authorized checks the access token, in constant time. With no token
// configured everything is allowed (loopback use).
func (s *server) authorized(r *http.Request) bool {
	if s.o.Token == "" {
		return true
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.o.Token)) == 1
}

func (s *server) denyUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "missing or wrong access token")
}

func (s *server) handleDetectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(r) {
		s.denyUnauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"detectors":    s.api.Infos(),
		"maxBodyBytes": s.o.MaxBodyBytes,
		"version":      s.o.Version,
	})
}

func (s *server) handleScrub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(r) {
		s.denyUnauthorized(w)
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
	var req scrubapi.Request
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
	res, aerr := s.api.Run(req)
	if aerr != nil {
		writeError(w, aerr.Status, aerr.Message)
		return
	}
	writeJSON(w, http.StatusOK, res)
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

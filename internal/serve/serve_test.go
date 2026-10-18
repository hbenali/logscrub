package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/hbenali/logscrub/internal/detect"
)

const (
	testHost  = "127.0.0.1:8080"
	testKey   = "0123456789abcdef-test-key"
	canary    = "S3CRETCANARY"
	jsonCType = "application/json"
)

// TestMain fails the package if a test leaves a goroutine behind (a server
// that does not shut down, a handler stuck on a channel).
func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func newOptions() Options {
	var on []string
	for _, d := range detect.Defaults() {
		on = append(on, d.ID)
	}
	return Options{Detectors: detect.All(), DefaultOn: on, Key: []byte(testKey), MaxBodyBytes: 1 << 20, Concurrency: 2}
}

func handler(o Options) http.Handler {
	return NewHandler(o, map[string]bool{testHost: true, "localhost:8080": true}, false)
}

// post builds a same-origin scrub request, the way the page sends it.
func post(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/scrub", strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Origin", "http://"+testHost)
	r.Header.Set("Content-Type", jsonCType)
	return r
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func get(path, host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = host
	return r
}

type scrubResp struct {
	Output         string `json:"output"`
	Spans          []span `json:"spans"`
	SpansTruncated bool   `json:"spansTruncated"`
	Counts         map[string]int
	Warnings       []string
}

type span struct {
	Start, End  int64
	Detector    string
	Replacement string
}

func decode(t *testing.T, w *httptest.ResponseRecorder) scrubResp {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var r scrubResp
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScrubRoundTripWithMultibyteOffsets(t *testing.T) {
	text := "héllo 日本語 bob@example.org\npassword=hunter2\n"
	b, _ := json.Marshal(map[string]any{"text": text})
	res := decode(t, do(handler(newOptions()), post(string(b))))

	if strings.Contains(res.Output, "hunter2") || strings.Contains(res.Output, "bob@") {
		t.Errorf("output not scrubbed: %q", res.Output)
	}
	// Spans are byte offsets: they must point at the matched bytes and rebuild
	// the output.
	var rebuilt strings.Builder
	pos := int64(0)
	got := map[string]string{}
	for _, s := range res.Spans {
		got[s.Detector] = text[s.Start:s.End]
		rebuilt.WriteString(text[pos:s.Start] + s.Replacement)
		pos = s.End
	}
	rebuilt.WriteString(text[pos:])
	if rebuilt.String() != res.Output {
		t.Errorf("spans do not rebuild the output:\n%q\n%q", rebuilt.String(), res.Output)
	}
	if got["email"] != "bob@example.org" || got["kv-secret"] != "hunter2" {
		t.Errorf("spans point at %v", got)
	}
	if res.Counts["email"] != 1 || res.Counts["kv-secret"] != 1 {
		t.Errorf("counts = %v", res.Counts)
	}
}

func TestDetectorSelectionAndModes(t *testing.T) {
	h := handler(newOptions())
	run := func(body string) scrubResp { return decode(t, do(h, post(body))) }

	// phone is opt-in: not in the defaults, applied when asked for.
	if out := run(`{"text":"call +14155550123"}`).Output; out != "call +14155550123" {
		t.Errorf("default run masked phone: %q", out)
	}
	if out := run(`{"text":"call +14155550123","detectors":["phone"]}`).Output; out != "call [REDACTED:phone]" {
		t.Errorf("explicit phone: %q", out)
	}
	// An empty list means no detector at all, not "the defaults".
	if out := run(`{"text":"password=hunter2","detectors":[]}`).Output; out != "password=hunter2" {
		t.Errorf("empty detector list masked: %q", out)
	}
	p := run(`{"text":"10.1.2.3 and 10.1.2.3 password=hunter2","mode":"pseudonym"}`).Output
	if m := regexp.MustCompile(`^\[ipv4:([a-z2-7]{8})\] and \[ipv4:([a-z2-7]{8})\] password=\[REDACTED:kv-secret\]$`).FindStringSubmatch(p); m == nil || m[1] != m[2] {
		t.Errorf("pseudonym output = %q", p)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := handler(newOptions())
	reqs := map[string]*http.Request{
		"index":      get("/", testHost),
		"asset":      get("/app.js", testHost),
		"not found":  get("/nope", testHost),
		"api":        get("/api/detectors", testHost),
		"bad host":   get("/", "evil.example"),
		"bad method": httptest.NewRequest(http.MethodDelete, "/", nil),
		"bad origin": func() *http.Request { r := post("{}"); r.Header.Set("Origin", "http://evil.example"); return r }(),
	}
	reqs["bad method"].Host = testHost
	for name, r := range reqs {
		w := do(h, r)
		hd := w.Header()
		csp := hd.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s (status %d): CSP lacks %q: %q", name, w.Code, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe") || strings.Contains(csp, "http") || strings.Contains(csp, "*") {
			t.Errorf("%s: CSP is too loose: %q", name, csp)
		}
		for k, v := range map[string]string{
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
			"Cache-Control": "no-store", "X-Frame-Options": "DENY",
		} {
			if hd.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", name, k, hd.Get(k), v)
			}
		}
		if hd.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: must not send CORS headers", name)
		}
	}
}

// DNS rebinding: a page on evil.example resolving to 127.0.0.1 reaches the
// server with its own Host header.
func TestHostCheck(t *testing.T) {
	h := handler(newOptions())
	for _, host := range []string{"evil.example", "evil.example:8080", "127.0.0.1", "127.0.0.1:9999", "", "localhost.evil.example:8080"} {
		for _, path := range []string{"/", "/api/detectors", "/app.js"} {
			if w := do(h, get(path, host)); w.Code != http.StatusForbidden {
				t.Errorf("Host %q %s: status %d, want 403", host, path, w.Code)
			}
		}
		r := post(`{"text":"x"}`)
		r.Host = host
		r.Header.Set("Origin", "http://"+host)
		if w := do(h, r); w.Code != http.StatusForbidden {
			t.Errorf("Host %q POST: status %d, want 403", host, w.Code)
		}
	}
	for _, host := range []string{testHost, "LOCALHOST:8080"} {
		if w := do(h, get("/", host)); w.Code != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, w.Code)
		}
	}
}

// Cross-site request forgery: any web page can POST to localhost.
func TestOriginAndContentTypeChecks(t *testing.T) {
	h := handler(newOptions())
	mk := func(mut func(*http.Request)) int {
		r := post(`{"text":"password=x"}`)
		mut(r)
		return do(h, r).Code
	}
	tests := []struct {
		name string
		mut  func(*http.Request)
		want int
	}{
		{"same origin", func(*http.Request) {}, 200},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"other site", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, 403},
		{"other port", func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:9999") }, 403},
		{"https origin", func(r *http.Request) { r.Header.Set("Origin", "https://"+testHost) }, 403},
		{"cross-site fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"same-site fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, 403},
		{"same-origin fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }, 200},
		{"form content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 415},
		{"text/plain simple request", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"no content type", func(r *http.Request) { r.Header.Del("Content-Type") }, 415},
		{"json with charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, 200},
	}
	for _, tc := range tests {
		if got := mk(tc.mut); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		r := httptest.NewRequest(m, "/api/scrub", nil)
		r.Host = testHost
		if w := do(h, r); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/scrub: status %d, want 405", m, w.Code)
		}
	}
}

func TestRequestValidationAndNoEchoOfInput(t *testing.T) {
	h := handler(newOptions())
	bad := map[string]string{
		"unknown field":    `{"text":"x","extra":"` + canary + `"}`,
		"trailing data":    `{"text":"x"} {"text":"` + canary + `"}`,
		"not json":         canary,
		"unknown detector": `{"text":"x","detectors":["` + canary + `"]}`,
		"unknown mode":     `{"text":"x","mode":"` + canary + `"}`,
		"wrong type":       `{"text":["` + canary + `"]}`,
	}
	for name, body := range bad {
		w := do(h, post(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, w.Code)
		}
		if strings.Contains(w.Body.String(), canary) {
			t.Errorf("%s: the error response echoes request content: %s", name, w.Body.String())
		}
	}
	o := newOptions()
	o.Key = nil
	if w := do(handler(o), post(`{"text":"x","mode":"pseudonym"}`)); w.Code != http.StatusBadRequest {
		t.Errorf("pseudonym without a key: status %d", w.Code)
	}
}

func TestSizeLimits(t *testing.T) {
	o := newOptions()
	o.MaxBodyBytes = 1024
	h := handler(o)
	if w := do(h, post(`{"text":"`+strings.Repeat("a", 2000)+`"}`)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("text over the limit: status %d, want 413", w.Code)
	}
	huge := io.MultiReader(strings.NewReader(`{"text":"`), strings.NewReader(strings.Repeat("a", 1<<20)))
	r := post("")
	r.Body = io.NopCloser(huge)
	if w := do(h, r); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("raw body over the limit: status %d, want 413", w.Code)
	}
	if w := do(h, post(`{"text":"`+strings.Repeat("a", 1024)+`"}`)); w.Code != http.StatusOK {
		t.Errorf("text at the limit: status %d, want 200", w.Code)
	}
}

func TestLongLineIsRefusedNotPassedThrough(t *testing.T) {
	o := newOptions()
	o.MaxLineBytes = 1024
	b, _ := json.Marshal(map[string]string{"text": "password=" + strings.Repeat("S3cr3tVal", 30000)})
	w := do(handler(o), post(string(b)))
	if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), "S3cr3t") {
		t.Errorf("status %d body %q", w.Code, w.Body.String())
	}
}

// startedReader reports when the handler first reads the body. The handler
// takes its concurrency slot before reading, so from then on the slot is held.
type startedReader struct {
	io.Reader
	once    sync.Once
	started chan struct{}
}

func (r *startedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.Reader.Read(p)
}

func TestConcurrencyLimit(t *testing.T) {
	o := newOptions()
	o.Concurrency = 1
	h := handler(o)

	pr, pw := io.Pipe()
	sr := &startedReader{Reader: pr, started: make(chan struct{})}
	slow := post("")
	slow.Body = io.NopCloser(sr)
	done := make(chan int, 1)
	go func() { done <- do(h, slow).Code }()

	select {
	case <-sr.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow request never reached the handler")
	}
	w := do(h, post(`{"text":"x"}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d while the only slot is held, want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}

	_, _ = pw.Write([]byte(`{"text":"x"}`))
	_ = pw.Close()
	if code := <-done; code != http.StatusOK {
		t.Errorf("the slow request ended with %d", code)
	}
	if w := do(h, post(`{"text":"x"}`)); w.Code != http.StatusOK {
		t.Errorf("slot was not released: %d", w.Code)
	}
}

func TestDetectorsEndpointAndStaticFiles(t *testing.T) {
	h := handler(newOptions())
	var info struct {
		Detectors []struct {
			ID       string
			Optional bool
			Default  bool
		}
		MaxBodyBytes int64
	}
	w := do(h, get("/api/detectors", testHost))
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || len(info.Detectors) < 10 || info.MaxBodyBytes != 1<<20 {
		t.Fatalf("detectors: %v %s", err, w.Body.String())
	}
	for _, d := range info.Detectors {
		if d.ID == "phone" && (!d.Optional || d.Default) {
			t.Errorf("phone should be opt-in: %+v", d)
		}
	}
	for path, ct := range map[string]string{"/": "text/html", "/app.js": "text/javascript", "/style.css": "text/css"} {
		w := do(h, get(path, testHost))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), ct) || w.Body.Len() == 0 {
			t.Errorf("%s: status %d type %q", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/nope", "/go.mod", "/index.html/x", "/web/app.js", "/app.js/"} {
		if w := do(h, get(path, testHost)); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host = testHost
	if w := do(h, r); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d", w.Code)
	}
}

// The page must stay self-contained and must never turn log text into markup.
func TestAssetsAreSelfContainedAndSafe(t *testing.T) {
	h := handler(newOptions())
	forbidden := map[string]*regexp.Regexp{
		"external URL":       regexp.MustCompile(`(?i)(https?:)?//[a-z0-9-]+\.[a-z]{2,}`),
		"inline script":      regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]`),
		"inline style attr":  regexp.MustCompile(`(?i)\sstyle\s*=`),
		"inline style tag":   regexp.MustCompile(`(?i)<style`),
		"event handler attr": regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		"HTML injection API": regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setAttribute\(\s*['"]style`),
		"web storage":        regexp.MustCompile(`localStorage|sessionStorage|indexedDB`),
		"other transports":   regexp.MustCompile(`WebSocket|EventSource|sendBeacon|XMLHttpRequest|importScripts`),
	}
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		body := do(h, get(path, testHost)).Body.String()
		for what, re := range forbidden {
			if loc := re.FindStringIndex(body); loc != nil {
				t.Errorf("%s contains %s: %q", path, what, body[max(0, loc[0]-20):min(len(body), loc[1]+20)])
			}
		}
	}
	// Every fetch goes to a same-origin path.
	js := do(h, get("/app.js", testHost)).Body.String()
	for _, m := range regexp.MustCompile(`fetch\(([^,)]+)`).FindAllStringSubmatch(js, -1) {
		if !regexp.MustCompile(`^'/api/[a-z]+'$`).MatchString(strings.TrimSpace(m[1])) {
			t.Errorf("fetch target %q is not a fixed local path", m[1])
		}
	}
}

func TestAllowedHosts(t *testing.T) {
	lo := allowedHosts("127.0.0.1:8080", true)
	for _, h := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		if !lo[h] {
			t.Errorf("%q should be accepted", h)
		}
	}
	if lo["127.0.0.1"] || lo["localhost"] {
		t.Error("the bare host must not be accepted off port 80")
	}
	if !allowedHosts("127.0.0.1:80", true)["127.0.0.1"] {
		t.Error("bare host should be accepted on port 80")
	}
	if v6 := allowedHosts("[::1]:9000", true); !v6["[::1]:9000"] {
		t.Errorf("ipv6 literal: %v", v6)
	}
}

func TestRunRefusesNonLoopbackWithoutOptIn(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:0", ":0", "example.org:0"} {
		// The timeout turns "the refusal is missing and a server started" into
		// a failure instead of a hang.
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := Run(ctx, Options{Addr: addr}, io.Discard)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "allow-remote") {
			t.Errorf("Run(%q) = %v, want a refusal mentioning --allow-remote", addr, err)
		}
	}
	if err := Run(context.Background(), Options{Addr: "not an address"}, io.Discard); err == nil {
		t.Error("bad address accepted")
	}
}

// A real server, a real TCP connection and a spoofed Host header.
func TestRunServesAndShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var log syncBuffer
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, newOptions().withAddr("127.0.0.1:0"), &log) }()

	var base string
	for i := 0; i < 200 && base == ""; i++ {
		if m := regexp.MustCompile(`http://(\S+)`).FindStringSubmatch(log.String()); m != nil {
			base = m[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if base == "" {
		t.Fatalf("server did not announce itself: %q", log.String())
	}
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("GET /: %d, CSP %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	req.Host = "evil.example"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("rebinding-style Host: status %d, want 403", resp.StatusCode)
	}

	// A client's idle or pre-dialed connections that never sent a request keep a
	// graceful shutdown waiting (net/http only closes such a connection after 5 s),
	// which is as long as this test waits. Go 1.27 does this often.
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if strings.Contains(log.String(), "password") {
		t.Errorf("log mentions request content: %q", log.String())
	}
}

func (o Options) withAddr(a string) Options { o.Addr = a; return o }

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ---- access token ----

const accessToken = "0123456789abcdef-access"

func tokenHandler() http.Handler {
	o := newOptions()
	o.Token = accessToken
	return handler(o)
}

func withBearer(r *http.Request, value string) *http.Request {
	if value != "" {
		r.Header.Set("Authorization", value)
	}
	return r
}

func TestTokenIsRequiredForTheAPIOnly(t *testing.T) {
	h := tokenHandler()
	bad := map[string]string{
		"missing":         "",
		"wrong":           "Bearer wrong-token-value-1234",
		"prefix only":     "Bearer " + accessToken[:10],
		"longer":          "Bearer " + accessToken + "x",
		"lower-case word": "bearer " + accessToken,
		"basic scheme":    "Basic " + accessToken,
		"no scheme":       accessToken,
		"empty token":     "Bearer ",
	}
	for name, auth := range bad {
		for _, mk := range []func() *http.Request{
			func() *http.Request { return get("/api/detectors", testHost) },
			func() *http.Request { return post(`{"text":"password=hunter2"}`) },
		} {
			r := withBearer(mk(), auth)
			w := do(h, r)
			if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s: %s %s -> %d, want 401 with WWW-Authenticate", name, r.Method, r.URL.Path, w.Code)
			}
			if strings.Contains(w.Body.String(), accessToken) || strings.Contains(w.Body.String(), "hunter2") {
				t.Errorf("%s: the 401 body leaks something: %s", name, w.Body.String())
			}
		}
	}
	ok := "Bearer " + accessToken
	if w := do(h, withBearer(get("/api/detectors", testHost), ok)); w.Code != http.StatusOK {
		t.Errorf("detectors with the token: %d", w.Code)
	}
	if res := decode(t, do(h, withBearer(post(`{"text":"password=hunter2"}`), ok))); strings.Contains(res.Output, "hunter2") {
		t.Errorf("scrub with the token did not scrub: %q", res.Output)
	}
	// The page itself holds nothing sensitive and must load so it can ask for the token.
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		if w := do(h, get(path, testHost)); w.Code != http.StatusOK {
			t.Errorf("%s without a token: %d, want 200", path, w.Code)
		}
	}
}

func TestTokenDoesNotWeakenOtherChecks(t *testing.T) {
	h := tokenHandler()
	ok := "Bearer " + accessToken
	r := withBearer(post(`{"text":"x"}`), ok)
	r.Header.Set("Origin", "http://evil.example")
	if w := do(h, r); w.Code != http.StatusForbidden {
		t.Errorf("a valid token must not bypass the Origin check: %d", w.Code)
	}
	r = withBearer(get("/api/detectors", "evil.example"), ok)
	if w := do(h, r); w.Code != http.StatusForbidden {
		t.Errorf("a valid token must not bypass the Host check: %d", w.Code)
	}
}

func TestNoTokenMeansOpenOnLoopback(t *testing.T) {
	if w := do(handler(newOptions()), get("/api/detectors", testHost)); w.Code != http.StatusOK {
		t.Errorf("no token configured: %d", w.Code)
	}
}

func TestRunTokenRules(t *testing.T) {
	short := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		return Run(ctx, newOptions().withAddr("127.0.0.1:0").withToken("short"), io.Discard)
	}
	if err := short(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Errorf("short token: %v", err)
	}
	remote := func(o Options) error {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		return Run(ctx, o, io.Discard)
	}
	noToken := newOptions().withAddr("0.0.0.0:0")
	noToken.AllowRemote = true
	if err := remote(noToken); err == nil || !strings.Contains(err.Error(), "access token") {
		t.Errorf("remote bind without a token must be refused: %v", err)
	}
}

func TestStartupMessageAndTokenPrinting(t *testing.T) {
	runAndRead := func(o Options) string {
		ctx, cancel := context.WithCancel(context.Background())
		var log syncBuffer
		errc := make(chan error, 1)
		go func() { errc <- Run(ctx, o, &log) }()
		for i := 0; i < 200 && !strings.Contains(log.String(), "web UI on"); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if err := <-errc; err != nil {
			t.Errorf("Run returned %v after cancel", err)
		}
		return log.String()
	}
	o := newOptions().withAddr("127.0.0.1:0").withToken(accessToken)
	o.ShowToken = true
	if out := runAndRead(o); !strings.Contains(out, "/#token="+accessToken) {
		t.Errorf("a generated token should be shown in a fragment URL: %q", out)
	}
	o.ShowToken = false
	if out := runAndRead(o); strings.Contains(out, accessToken) || !strings.Contains(out, "access token required") {
		t.Errorf("a user-supplied token must not be printed: %q", out)
	}
}

func (o Options) withToken(t string) Options { o.Token = t; return o }

// Regression guards for what the axe audit found: every form control needs an
// accessible name, and the token form must be a landmark.
func TestFormControlsHaveAccessibleNames(t *testing.T) {
	page := do(handler(newOptions()), get("/", testHost)).Body.String()
	for _, tc := range []struct{ what, re string }{
		{"the log textarea is labelled by its heading", `<textarea id="input"[^>]*aria-labelledby="in-h"`},
		{"the token form is a named landmark", `<form id="tokenform"[^>]*aria-labelledby="token-h"`},
		{"the token input has a label", `<label for="token">`},
		{"the tabs form a tablist", `role="tablist"`},
		{"the status is announced", `role="status"[^>]*aria-live="polite"`},
		{"errors are announced", `role="alert"`},
		{"the page language is set", `<html lang="en">`},
	} {
		if !regexp.MustCompile(tc.re).MatchString(page) {
			t.Errorf("%s: no match for %s", tc.what, tc.re)
		}
	}
	js := do(handler(newOptions()), get("/app.js", testHost)).Body.String()
	for _, key := range []string{"ArrowRight", "ArrowLeft", "Home", "End"} {
		if !strings.Contains(js, "'"+key+"'") {
			t.Errorf("the tabs do not handle the %s key", key)
		}
	}
}

func TestDisplayAddrIsOpenable(t *testing.T) {
	for in, want := range map[string]string{
		"[::]:8080":          "localhost:8080",
		"0.0.0.0:80":         "localhost:80",
		"127.0.0.1:8080":     "127.0.0.1:8080",
		"[::1]:9":            "[::1]:9",
		"[2001:db8::1]:9000": "[2001:db8::1]:9000",
		"192.0.2.7:8080":     "192.0.2.7:8080",
		"not an address":     "not an address",
	} {
		if got := displayAddr(in); got != want {
			t.Errorf("displayAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

package scrub_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// Test secrets are assembled from pieces so that this file does not itself
// trip secret scanners (GitHub push protection, gitleaks) or look like a leak.
var (
	awsKey    = "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken   = "ghp" + "_" + strings.Repeat("a1B2c3", 6)
	glToken   = "glpat" + "-" + "abcdefghij0123456789"
	slackTok  = "xoxb" + "-" + "123456789012-abcdefghijkl"
	stripeKey = "sk" + "_live_" + "abcdefghij0123456789"
	jwtTok    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
	pemBegin  = "-----BEGIN " + "RSA PRIVATE KEY-----"
	pemEnd    = "-----END " + "RSA PRIVATE KEY-----"
)

func run(t *testing.T, o scrub.Options, in string) (string, *scrub.Result) {
	t.Helper()
	if o.Detectors == nil {
		o.Detectors = detect.Defaults()
	}
	s := scrub.New(o)
	var out bytes.Buffer
	if err := s.Run(strings.NewReader(in), &out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out.String(), s.Result()
}

func scrubStr(t *testing.T, in string) string {
	t.Helper()
	out, _ := run(t, scrub.Options{}, in)
	return out
}

func TestDetectors(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"aws access key", "key " + awsKey + " end", "key [REDACTED:aws-access-key] end"},
		{"aws secret key", "aws_secret_access_key = " + awsSecret, "aws_secret_access_key = [REDACTED:aws-secret-key]"},
		{"aws secret wrong length", "aws_secret_access_key=short", "aws_secret_access_key=[REDACTED:kv-secret]"},
		{"github token", "token " + ghToken + ".", "token [REDACTED:github-token]."},
		{"github token in kv", "GITHUB_TOKEN=" + ghToken, "GITHUB_TOKEN=[REDACTED:github-token]"},
		{"gitlab token", "x " + glToken, "x [REDACTED:gitlab-token]"},
		{"slack token", "x " + slackTok, "x [REDACTED:slack-token]"},
		{"slack webhook", "https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/abcdEFGH1234", "[REDACTED:slack-token]"},
		{"stripe key", "k=" + stripeKey, "k=[REDACTED:stripe-key]"},
		{"stripe test key is left alone", "k=" + "sk" + "_test_" + "abcdefghij0123456789", "k=" + "sk" + "_test_" + "abcdefghij0123456789"},
		{"jwt", "t " + jwtTok + " z", "t [REDACTED:jwt] z"},
		{"not a jwt", "eyJhbGciOi.notjson12.abcdef", "eyJhbGciOi.notjson12.abcdef"},
		{"bearer header", "Authorization: Bearer abc.DEF-123_xyz", "Authorization: Bearer [REDACTED:bearer-token]"},
		{"basic header", `"Authorization": "Basic dXNlcjpwYXNz"`, `"Authorization": "Basic [REDACTED:bearer-token]"`},
		{"long bearer without header", "got Bearer " + strings.Repeat("a", 30), "got Bearer [REDACTED:bearer-token]"},
		{"short bearer prose", "bearer authentication is used", "bearer authentication is used"},
		{"url credentials", "connect postgres://app:s3cret@db:5432/x", "connect postgres://[REDACTED:url-credentials]@db:5432/x"},
		{"url without password", "ssh://git@github.com/x/y", "ssh://git@github.com/x/y"},
		{"url with port", "http://host:8080/path@x", "http://host:8080/path@x"},
		{"kv equals", "password=hunter2 user=bob", "password=[REDACTED:kv-secret] user=bob"},
		{"kv quoted", `db_password = "p@ss word"`, `db_password = "[REDACTED:kv-secret]"`},
		{"kv single quoted", "api_key='abc123'", "api_key='[REDACTED:kv-secret]'"},
		{"kv json", `{"client_secret": "abc\"def", "x": 1}`, `{"client_secret": "[REDACTED:kv-secret]", "x": 1}`},
		{"kv query string", "GET /cb?access_token=abc123&state=x", "GET /cb?access_token=[REDACTED:kv-secret]&state=x"},
		{"kv yaml line", "  password: hunter2", "  password: [REDACTED:kv-secret]"},
		{"kv prose colon", "failed to refresh token: connection refused", "failed to refresh token: connection refused"},
		{"kv counters", "max_tokens=100 token_count=3 tokens_used=5", "max_tokens=100 token_count=3 tokens_used=5"},
		{"kv literals", "password=null secret=false token=<token> pass=${PASS}", "password=null secret=false token=<token> pass=${PASS}"},
		{"kv empty", "password=\nnext", "password=\nnext"},
		{"kv spaced", "password= next", "password= [REDACTED:kv-secret]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPrivateKeyBlocks(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			"multi-line with prefix and suffix",
			"before " + pemBegin + "\nMIIEow\nIBAAKC\n" + pemEnd + " after\nnext\n",
			"before [REDACTED:private-key] after\nnext\n",
		},
		{
			"CRLF",
			pemBegin + "\r\nMIIEow\r\n" + pemEnd + "\r\nnext\r\n",
			"[REDACTED:private-key]\r\nnext\r\n",
		},
		{
			"one line with escaped newlines",
			`{"key":"` + pemBegin + `\nMIIEow\n` + pemEnd + `"}` + "\n",
			`{"key":"[REDACTED:private-key]"}` + "\n",
		},
		{
			"unterminated at EOF",
			"x\n" + pemBegin + "\nMIIEow\n",
			"x\n[REDACTED:private-key]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubStr(t, tc.in); got != tc.want {
				t.Errorf("\n got:  %q\n want: %q", got, tc.want)
			}
		})
	}

	t.Run("block over the line limit is reported", func(t *testing.T) {
		in := pemBegin + "\n" + strings.Repeat("MIIEow\n", 10) + pemEnd + "\n"
		out, res := run(t, scrub.Options{MaxPrivateKeyLines: 3}, in)
		if !strings.HasPrefix(out, "[REDACTED:private-key]") {
			t.Errorf("block start not masked: %q", out)
		}
		if len(res.Warnings) != 1 {
			t.Errorf("want 1 warning, got %v", res.Warnings)
		}
	})

	t.Run("block state does not span runs", func(t *testing.T) {
		s := scrub.New(scrub.Options{Detectors: detect.Defaults()})
		var out bytes.Buffer
		if err := s.Run(strings.NewReader(pemBegin+"\nMIIEow\n"), &out); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		if err := s.Run(strings.NewReader("plain line\n"), &out); err != nil {
			t.Fatal(err)
		}
		if out.String() != "plain line\n" {
			t.Errorf("second input swallowed: %q", out.String())
		}
	})

	t.Run("disabled detector leaves keys alone", func(t *testing.T) {
		var dets []*detect.Detector
		for _, d := range detect.Defaults() {
			if d.ID != "private-key" {
				dets = append(dets, d)
			}
		}
		in := pemBegin + "\nMIIEow\n" + pemEnd + "\n"
		if out, _ := run(t, scrub.Options{Detectors: dets}, in); out != in {
			t.Errorf("changed: %q", out)
		}
	})
}

func TestOverlapPriority(t *testing.T) {
	// The same span matches github-token and kv-secret: the specific one wins.
	out, res := run(t, scrub.Options{}, "token="+ghToken+"\n")
	if out != "token=[REDACTED:github-token]\n" {
		t.Errorf("got %q", out)
	}
	if res.Counts["github-token"] != 1 || res.Counts["kv-secret"] != 0 {
		t.Errorf("counts = %v", res.Counts)
	}
}

func TestLineEndingsPreserved(t *testing.T) {
	for _, in := range []string{"a\nb\n", "a\r\nb\r\n", "a\nb", "a\r\nb", "\n\n", "", "no newline"} {
		if got := scrubStr(t, in); got != in {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

// The "must not change" corpus: realistic logs full of look-alikes. A false
// positive is a bug; add the line here before fixing the detector.
func TestCleanCorpusUnchanged(t *testing.T) {
	files, err := filepath.Glob("../../testdata/clean/*")
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files found (err=%v)", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			in, err := os.ReadFile(f) //nolint:gosec // f comes from globbing our own testdata
			if err != nil {
				t.Fatal(err)
			}
			out, res := run(t, scrub.Options{}, string(in))
			if out != string(in) {
				t.Errorf("corpus file changed (counts %v):\n%s", res.Counts, firstDiff(string(in), out))
			}
		})
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return "- " + al[i] + "\n+ " + bl[i]
		}
	}
	return "length differs"
}

// dirty is a mixed document exercising every detector, built from the test
// secrets above.
func dirty() string {
	return strings.Join([]string{
		"2026-10-10 INFO start user=bob password=hunter2 key=" + awsKey,
		"2026-10-10 DEBUG gh " + ghToken + " gl " + glToken,
		"Authorization: Bearer " + jwtTok,
		"dsn postgres://app:s3cret@db/x slack " + slackTok,
		pemBegin,
		"MIIEowIBAAKCAQEA",
		pemEnd,
		`{"api_key":"abc123","stripe":"` + stripeKey + `"}`,
		"done",
	}, "\n") + "\n"
}

func TestIdempotent(t *testing.T) {
	once := scrubStr(t, dirty())
	if twice := scrubStr(t, once); twice != once {
		t.Errorf("second pass changed the output:\n%s", firstDiff(once, twice))
	}
}

// After scrubbing, no detector may find anything left to mask.
func TestNoLeakAfterScrub(t *testing.T) {
	out, res := run(t, scrub.Options{}, dirty())
	for _, secret := range []string{"hunter2", awsKey, ghToken, glToken, jwtTok, "s3cret", slackTok, "MIIEow", stripeKey, "abc123"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q still present in output", secret)
		}
	}
	if _, again := run(t, scrub.Options{}, out); again.Total() != 0 {
		t.Errorf("re-scan still finds %v", again.Counts)
	}
	if res.Total() < 10 {
		t.Errorf("expected at least 10 matches, got %v", res.Counts)
	}
}

// Output must not depend on how the input is chunked by the reader or on the
// read-buffer size (an error message split across chunks was a real bug in
// frontail).
func TestChunkingInvariance(t *testing.T) {
	in := dirty() + strings.Repeat("filler line with nothing in it\n", 5)
	want := scrubStr(t, in)

	for _, size := range []int{16, 17, 32, 100, 4096} {
		s := scrub.New(scrub.Options{Detectors: detect.Defaults(), ReadBufferSize: size})
		var out bytes.Buffer
		if err := s.Run(iotest.OneByteReader(strings.NewReader(in)), &out); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Errorf("buffer size %d: output differs:\n%s", size, firstDiff(want, out.String()))
		}
	}
}

// Lines longer than MaxLineBytes are scanned in overlapping windows; a secret
// that straddles a window edge must still be masked.
func TestLongLinesSecretAtEveryOffset(t *testing.T) {
	const maxLine = 1024
	secret := "password=hunter2"
	for off := 0; off < 3*maxLine; off += 37 {
		line := strings.Repeat("x", off) + " " + secret + " " + strings.Repeat("y", 2*maxLine)
		out, _ := run(t, scrub.Options{MaxLineBytes: maxLine, ReadBufferSize: 64, Overlap: 256}, line+"\n")
		if strings.Contains(out, "hunter2") {
			t.Fatalf("secret leaked with %d bytes before it", off)
		}
		want := strings.Repeat("x", off) + " password=[REDACTED:kv-secret] " + strings.Repeat("y", 2*maxLine) + "\n"
		if out != want {
			t.Fatalf("offset %d: output differs from expected (len %d vs %d)", off, len(out), len(want))
		}
	}
}

func TestHugeLineWithoutSecretsIsStreamed(t *testing.T) {
	in := strings.Repeat("a", 1<<20) + "\n"
	out, res := run(t, scrub.Options{MaxLineBytes: 1 << 16}, in)
	if out != in || res.Total() != 0 {
		t.Errorf("huge clean line altered (total %d, len %d)", res.Total(), len(out))
	}
}

func TestUnscannableLineFailsWithoutLeakingInput(t *testing.T) {
	// One unbroken value far longer than the memory bound: the engine must
	// refuse rather than emit text it could not scan, and the error must not
	// quote the input.
	in := "password=" + strings.Repeat("S3cr3tVal", 1<<17) + "\n"
	s := scrub.New(scrub.Options{Detectors: detect.Defaults(), MaxLineBytes: 1024})
	var out bytes.Buffer
	err := s.Run(strings.NewReader(in), &out)
	if !errors.Is(err, scrub.ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
	if strings.Contains(err.Error(), "S3cr3t") {
		t.Errorf("error quotes input: %v", err)
	}
	if strings.Contains(out.String(), "S3cr3t") {
		t.Errorf("unscanned input was emitted")
	}
}

func TestBinaryBytesSurvive(t *testing.T) {
	in := "\x00\xff\xfe binary \x80\x81 password=hunter2 \x00\n"
	want := "\x00\xff\xfe binary \x80\x81 password=[REDACTED:kv-secret] \x00\n"
	if got := scrubStr(t, in); got != want {
		t.Errorf("got %q", got)
	}
}

func FuzzScrub(f *testing.F) {
	for _, s := range []string{dirty(), "password=x\n", pemBegin, "Bearer " + strings.Repeat("a", 40), "a://b:c@d", "\x00\xff"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		o := scrub.Options{Detectors: detect.All(), MaxLineBytes: 1024, ReadBufferSize: 16, Overlap: 256}
		var out bytes.Buffer
		if err := scrub.New(o).Run(bytes.NewReader(in), &out); err != nil {
			if errors.Is(err, scrub.ErrLineTooLong) {
				return
			}
			t.Fatalf("unexpected error: %v", err)
		}
		// The spans reported for the web UI must rebuild the output exactly.
		so, spans, serr := scrubWithSpans(o, string(in))
		if serr != nil {
			t.Fatalf("observed run failed: %v", serr)
		}
		if rebuilt, ok := applySpans(string(in), spans); !ok || rebuilt != so || so != out.String() {
			t.Fatalf("spans do not reproduce the output (ok=%v)", ok)
		}
		// The prefilter must never change what is masked.
		o.NoPrefilter = true
		var plain bytes.Buffer
		if err := scrub.New(o).Run(bytes.NewReader(in), &plain); err == nil && !bytes.Equal(plain.Bytes(), out.Bytes()) {
			t.Fatalf("prefilter changed the output")
		}
		// No leak after scrub: nothing is left for a second pass to mask.
		again := scrub.New(scrub.Options{Detectors: detect.All()})
		var out2 bytes.Buffer
		if err := again.Run(bytes.NewReader(out.Bytes()), &out2); err != nil {
			t.Fatalf("rescan: %v", err)
		}
		if again.Result().Total() != 0 {
			t.Fatalf("output still contains maskable text: %v", again.Result().Counts)
		}
	})
}

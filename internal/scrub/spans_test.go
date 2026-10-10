package scrub_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// scrubWithSpans runs the engine and returns the output and the observed spans.
func scrubWithSpans(o scrub.Options, in string) (string, []scrub.Span, error) {
	var spans []scrub.Span
	o.Observe = func(s scrub.Span) { spans = append(spans, s) }
	if o.Detectors == nil {
		o.Detectors = detect.All()
	}
	var out bytes.Buffer
	err := scrub.New(o).Run(strings.NewReader(in), &out)
	return out.String(), spans, err
}

// applySpans rebuilds the output from the input and the spans alone, which is
// what the web UI does to highlight matches. It returns false if the spans are
// out of order, overlapping or outside the input.
func applySpans(in string, spans []scrub.Span) (string, bool) {
	var b strings.Builder
	var pos int64
	for _, s := range spans {
		if s.Start < pos || s.End < s.Start || s.End > int64(len(in)) {
			return "", false
		}
		b.WriteString(in[pos:s.Start])
		b.WriteString(s.Replacement)
		pos = s.End
	}
	b.WriteString(in[pos:])
	return b.String(), true
}

func TestSpansReproduceOutput(t *testing.T) {
	long := strings.Repeat("x", 3000) + " password=hunter2 " + strings.Repeat("y", 3000) + " bob@example.org\n"
	docs := map[string]string{
		"dirty":          dirty(),
		"pii":            "mail bob@example.org ip 8.8.4.4 v6 2001:db8::5 card 4111111111111111 +14155550123\n",
		"unicode":        "héllo wörld 日本語 bob@example.org ünïcode password=pässword\n",
		"crlf":           "a=1\r\npassword=x\r\nb@c.org\r\n",
		"unterminated":   "x\n" + pemBegin + "\nMIIEow\n",
		"no final eol":   "token=abc",
		"private prefix": "before " + pemBegin + "\nMIIEow\n" + pemEnd + " after bob@example.org\n",
		"long line":      long,
		"empty":          "",
	}
	for name, in := range docs {
		t.Run(name, func(t *testing.T) {
			o := scrub.Options{}
			if name == "long line" {
				o = scrub.Options{MaxLineBytes: 1024, ReadBufferSize: 64, Overlap: 256}
			}
			out, spans, err := scrubWithSpans(o, in)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, ok := applySpans(in, spans)
			if !ok {
				t.Fatalf("spans are out of order or out of range: %+v", spans)
			}
			if rebuilt != out {
				t.Errorf("spans do not reproduce the output:\n%s", firstDiff(out, rebuilt))
			}
		})
	}
}

func TestSpanOffsetsPointAtTheMatchedBytes(t *testing.T) {
	in := "ünï 日本 bob@example.org ok\nsecond password=hunter2\n"
	_, spans, err := scrubWithSpans(scrub.Options{}, in)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range spans {
		got[s.Detector] = in[s.Start:s.End]
	}
	if got["email"] != "bob@example.org" || got["kv-secret"] != "hunter2" {
		t.Errorf("spans point at %v", got)
	}
}

func TestPrivateKeyLimitSpanCoversWholeBlock(t *testing.T) {
	in := pemBegin + "\n" + strings.Repeat("MIIEow\n", 6) + pemEnd + "\nafter\n"
	out, spans, err := scrubWithSpans(scrub.Options{MaxPrivateKeyLines: 3}, in)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt, ok := applySpans(in, spans); !ok || rebuilt != out {
		t.Errorf("rebuilt %q (ok=%v), output %q", rebuilt, ok, out)
	}
}

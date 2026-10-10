package scrubapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrubapi"
)

func config() *scrubapi.Config {
	var on []string
	for _, d := range detect.Defaults() {
		on = append(on, d.ID)
	}
	return &scrubapi.Config{Detectors: detect.All(), DefaultOn: on, Key: []byte("0123456789abcdef-key"), MaxTextBytes: 1 << 16}
}

func TestRunDefaultsAndSelection(t *testing.T) {
	c := config()
	res, err := c.Run(scrubapi.Request{Text: "bob@example.org +14155550123 password=hunter2\n"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "[REDACTED:email] +14155550123 password=[REDACTED:kv-secret]\n" {
		t.Errorf("defaults: %q", res.Output)
	}
	res, _ = c.Run(scrubapi.Request{Text: "+14155550123 bob@example.org", Detectors: []string{"phone"}})
	if res.Output != "[REDACTED:phone] bob@example.org" {
		t.Errorf("explicit selection: %q", res.Output)
	}
	res, _ = c.Run(scrubapi.Request{Text: "password=hunter2", Detectors: []string{}})
	if res.Output != "password=hunter2" {
		t.Errorf("an empty list must mean no detectors: %q", res.Output)
	}
}

func TestSpansRebuildTheOutput(t *testing.T) {
	in := "héllo bob@example.org 10.1.2.3 password=hunter2\n"
	res, err := config().Run(scrubapi.Request{Text: in})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	var pos int64
	for _, s := range res.Spans {
		b.WriteString(in[pos:s.Start] + s.Replacement)
		pos = s.End
	}
	b.WriteString(in[pos:])
	if b.String() != res.Output || len(res.Spans) != 3 || res.Counts["email"] != 1 {
		t.Errorf("spans=%+v counts=%v rebuilt=%q output=%q", res.Spans, res.Counts, b.String(), res.Output)
	}
	if res.Warnings == nil || res.Spans == nil {
		t.Error("warnings and spans must be empty lists, not null, for the page")
	}
}

func TestErrorsAreClassifiedAndNeverEchoInput(t *testing.T) {
	c := config()
	const canary = "S3CRETCANARY"
	cases := map[string]struct {
		req    scrubapi.Request
		status int
	}{
		"unknown detector": {scrubapi.Request{Text: "x", Detectors: []string{canary}}, http.StatusBadRequest},
		"unknown mode":     {scrubapi.Request{Text: "x", Mode: canary}, http.StatusBadRequest},
		"too large":        {scrubapi.Request{Text: canary + strings.Repeat("a", 1<<17)}, http.StatusRequestEntityTooLarge},
	}
	for name, tc := range cases {
		_, err := c.Run(tc.req)
		if err == nil || err.Status != tc.status {
			t.Errorf("%s: %+v, want status %d", name, err, tc.status)
			continue
		}
		if strings.Contains(err.Message, canary) {
			t.Errorf("%s: the error echoes the request: %q", name, err.Message)
		}
	}
	noKey := config()
	noKey.Key = nil
	if _, err := noKey.Run(scrubapi.Request{Text: "x", Mode: "pseudonym"}); err == nil || err.Status != http.StatusBadRequest {
		t.Errorf("pseudonym mode without a key: %+v", err)
	}
	long := config()
	long.MaxLineBytes = 1024
	long.MaxTextBytes = 0 // unlimited
	_, err := long.Run(scrubapi.Request{Text: "password=" + strings.Repeat("S3cr3tVal", 30000)})
	if err == nil || err.Status != http.StatusUnprocessableEntity || strings.Contains(err.Message, "S3cr3t") {
		t.Errorf("an unscannable line: %+v", err)
	}
}

func TestInfosMarkDefaultsAndOptionals(t *testing.T) {
	var sawPhoneOptOut, sawEmailOn bool
	for _, i := range config().Infos() {
		switch i.ID {
		case "phone":
			sawPhoneOptOut = i.Optional && !i.Default
		case "email":
			sawEmailOn = !i.Optional && i.Default && i.Pseudonym
		}
	}
	if !sawPhoneOptOut || !sawEmailOn {
		t.Errorf("infos: phone opt-in=%v email default=%v", sawPhoneOptOut, sawEmailOn)
	}
}

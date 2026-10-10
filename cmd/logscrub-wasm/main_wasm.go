//go:build js && wasm

// Command logscrub-wasm is the in-browser build of the engine, used by the
// demo page: the same detectors and the same request/response layer as the
// local server, running in the visitor's browser, so pasted text never leaves it.
package main

import (
	"crypto/rand"
	"encoding/json"
	"syscall/js"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
	"github.com/hbenali/logscrub/internal/scrubapi"
)

// Set by -ldflags -X.
var version = "dev"

// maxTextBytes bounds the demo's input: WebAssembly runs on the page's main
// thread, so a huge paste would freeze the tab.
const maxTextBytes = 2 << 20

func main() {
	key := make([]byte, 32) // per page load; tags are stable within it
	if _, err := rand.Read(key); err != nil {
		key = nil // pseudonym mode is then reported as unavailable
	}
	var defaults []string
	for _, d := range detect.Defaults() {
		defaults = append(defaults, d.ID)
	}
	cfg := &scrubapi.Config{
		Detectors: detect.All(), DefaultOn: defaults, Key: key,
		MaxTextBytes: maxTextBytes, MaxLineBytes: scrub.DefaultMaxLineBytes, MaxPrivateKeyLines: scrub.DefaultMaxPrivateKeyLines,
	}

	api := map[string]any{
		"version": version,
		// detectors() returns the detector list as JSON.
		"detectors": js.FuncOf(func(js.Value, []js.Value) any {
			return mustJSON(map[string]any{"detectors": cfg.Infos(), "maxBodyBytes": int64(maxTextBytes), "version": version})
		}),
		// scrub(requestJSON) returns {"status": N, "body": ...}.
		"scrub": js.FuncOf(func(_ js.Value, args []js.Value) any {
			if len(args) != 1 {
				return mustJSON(map[string]any{"status": 400, "body": map[string]string{"error": "invalid request"}})
			}
			var req scrubapi.Request
			if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
				return mustJSON(map[string]any{"status": 400, "body": map[string]string{"error": "invalid JSON request"}})
			}
			res, aerr := cfg.Run(req)
			if aerr != nil {
				return mustJSON(map[string]any{"status": aerr.Status, "body": map[string]string{"error": aerr.Message}})
			}
			return mustJSON(map[string]any{"status": 200, "body": res})
		}),
	}
	js.Global().Set("logscrub", js.ValueOf(api))
	select {} // keep the runtime alive for calls from the page
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"status":500,"body":{"error":"encoding failed"}}`
	}
	return string(b)
}

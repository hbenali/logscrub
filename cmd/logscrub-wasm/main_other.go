//go:build !(js && wasm)

// Command logscrub-wasm only does something when built for the browser:
// GOOS=js GOARCH=wasm go build ./cmd/logscrub-wasm (see scripts/build-demo.sh).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "logscrub-wasm: build with GOOS=js GOARCH=wasm; see scripts/build-demo.sh")
	os.Exit(2)
}

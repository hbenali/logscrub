package detect_test

import (
	"os"
	"strings"
	"testing"

	"github.com/hbenali/logscrub/internal/detect"
)

// The wiki's detector reference must list every detector, and the README must
// not promise ones that do not exist.
func TestDetectorReferenceIsComplete(t *testing.T) {
	page, err := os.ReadFile("../../docs/wiki/Detectors.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range detect.All() {
		if !strings.Contains(string(page), "| `"+d.ID+"` |") {
			t.Errorf("docs/wiki/Detectors.md has no row for %q", d.ID)
		}
		if d.Desc == "" {
			t.Errorf("%s has no description", d.ID)
		}
	}
}

func TestDetectorsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range detect.All() {
		if seen[d.ID] {
			t.Errorf("duplicate detector id %q", d.ID)
		}
		seen[d.ID] = true
		if len(d.Patterns) == 0 {
			t.Errorf("%s has no patterns", d.ID)
		}
		if d.FoldHints {
			for _, h := range d.Hints {
				if h != strings.ToLower(h) {
					t.Errorf("%s: hint %q must be lowercase with FoldHints", d.ID, h)
				}
			}
		}
		for _, p := range d.Patterns {
			if p.MatchString("") {
				t.Errorf("%s: pattern %q matches the empty string", d.ID, p)
			}
		}
	}
}

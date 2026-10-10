package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
)

// maxFindings bounds the memory used to list findings; counts stay exact.
const maxFindings = 100000

// finding is one match, located but never quoted: reports must not contain the
// text that was found.
type finding struct {
	File       string `json:"file"`
	Line       int64  `json:"line"`
	Column     int64  `json:"column"` // 1-based, counted in bytes
	EndLine    int64  `json:"end_line,omitempty"`
	ByteOffset int64  `json:"byte_offset"`
	ByteLength int64  `json:"byte_length"`
	Detector   string `json:"detector"`
}

// collector gathers findings through scrub.Options.Observe.
type collector struct {
	file      string
	findings  []finding
	truncated bool
}

func (c *collector) observe(sp scrub.Span) {
	if len(c.findings) >= maxFindings {
		c.truncated = true
		return
	}
	f := finding{
		File: c.file, Line: sp.Line, Column: sp.Column, ByteOffset: sp.Start,
		ByteLength: sp.End - sp.Start, Detector: sp.Detector,
	}
	if sp.EndLine != sp.Line {
		f.EndLine = sp.EndLine
	}
	c.findings = append(c.findings, f)
}

func printReport(w io.Writer, format string, res *scrub.Result, c *collector, dets []*detect.Detector) {
	switch format {
	case "json":
		printJSONReport(w, res, c)
	case "sarif":
		printSARIFReport(w, c, dets)
	default:
		printTextReport(w, res)
	}
}

func printTextReport(w io.Writer, res *scrub.Result) {
	ids := make([]string, 0, len(res.Counts))
	for id := range res.Counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		outf(w, "%-20s %d\n", id, res.Counts[id])
	}
	outf(w, "%-20s %d\n", "total", res.Total())
}

func printJSONReport(w io.Writer, res *scrub.Result, c *collector) {
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	counts := res.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	findings := c.findings
	if findings == nil {
		findings = []finding{}
	}
	writeJSON(w, map[string]any{
		"version":            orUnknown(version),
		"total":              res.Total(),
		"counts":             counts,
		"findings":           findings,
		"findings_truncated": c.truncated,
		"warnings":           warnings,
	})
}

// printSARIFReport writes SARIF 2.1.0, which GitHub code scanning and most CI
// systems understand. Locations are lines and byte offsets; the text that was
// found is never included.
func printSARIFReport(w io.Writer, c *collector, dets []*detect.Detector) {
	rules := make([]map[string]any, 0, len(dets))
	for _, d := range dets {
		rules = append(rules, map[string]any{
			"id":               d.ID,
			"shortDescription": map[string]string{"text": d.Desc},
		})
	}
	results := make([]map[string]any, 0, len(c.findings))
	for _, f := range c.findings {
		uri := f.File
		if uri == stdinName {
			uri = "stdin"
		}
		region := map[string]any{"startLine": f.Line, "byteOffset": f.ByteOffset, "byteLength": f.ByteLength}
		if f.EndLine != 0 {
			region["endLine"] = f.EndLine
		}
		results = append(results, map[string]any{
			"ruleId":  f.Detector,
			"level":   "warning",
			"message": map[string]string{"text": f.Detector + " would be masked"},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": uri},
					"region":           region,
				},
			}},
		})
	}
	writeJSON(w, map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "logscrub",
				"version":        orUnknown(version),
				"informationUri": "https://github.com/hbenali/logscrub",
				"rules":          rules,
			}},
			"results": results,
		}},
	})
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		outf(w, "%s\n", fmt.Sprintf(`{"error": %q}`, "could not encode the report"))
	}
}

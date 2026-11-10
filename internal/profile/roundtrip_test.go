package profile

import (
	"bytes"
	"strings"
	"testing"
)

// rtBase is a valid JSONC profile carrying unknown members at the top level
// and inside an entry. Every round-trip variant in TestRoundTripVariants is
// derived from it.
const rtBase = `{
  // header
  "schema_version": "2.0",
  "name": "rt",
  "title": "Round Trip",
  "vendor": "Test",
  "applies_to": {
    "os": ["linux"]
  },
  "roots": {
    "home": "/tmp/packout-rt"
  },
  "entries": [
    {
      "id": "a",
      "kind": "file",
      "root": "home",
      "path": "a",
      "layer": "L2",
      "secret": "none",
      "extractor": "none",
      "signals": [
        {"src": "observed_behavior", "note": "n"}
      ],
      "future_entry": {"nested": [1, 2, 3]},
      "selftest_exempt": "roundtrip"
    }
  ],
  "future_top": {"alpha": true, "beta": [1, 2]},
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    "fixtures": {"home": "fixtures/home"},
    "expect": [
      {"entry": "a", "root": "home", "match": "a"}
    ],
    "budget": {"wall_ms": 1000}
  }
}
`

func TestInPlaceEditPreservesEverythingElse(t *testing.T) {
	src := strings.Replace(
		strings.Replace(rtBase, `"linux"]`, `"linux",]`, 1),
		`"beta": [1, 2]`, `"beta": [1, 2,]`, 1)
	p, err := LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	out, err := p.Patch([]byte(`[{"op":"replace","path":"/vendor","value":"Changed"}]`))
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	want := strings.Replace(src, `"vendor": "Test"`, `"vendor": "Changed"`, 1)
	if !bytes.Equal(out, []byte(want)) {
		t.Fatalf("in-place edit changed more than the target\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

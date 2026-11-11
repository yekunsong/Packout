package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"packout/profiles"
)

func TestBuiltinLoadValidate(t *testing.T) {
	names := BuiltinNames()
	if len(names) != 2 {
		t.Fatalf("expected two built-ins, got %v", names)
	}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			p, err := Builtin(name)
			if err != nil {
				t.Fatalf("Builtin(%q): %v", name, err)
			}
			if err := Validate(p); err != nil {
				t.Fatalf("Validate(%q): %v", name, err)
			}
			embedded, err := profiles.FS.ReadFile(name + ".jsonc")
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Pack(); !bytes.Equal(got, embedded) {
				t.Fatalf("%s: Pack is not byte-identical to the embedded source", name)
			}
		})
	}
}

func TestBuiltinSelfTest(t *testing.T) {
	for _, name := range BuiltinNames() {
		name := name
		t.Run(name, func(t *testing.T) {
			p, err := Builtin(name)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			res, err := RunSelfTest(p, dir)
			if err != nil {
				t.Fatalf("RunSelfTest: %v", err)
			}
			if !res.Passed {
				for _, f := range res.Failures {
					t.Errorf("failure: %v", f)
				}
				t.Fatalf("%s: selftest failed (%d checks)", name, res.Checks)
			}
			if res.Checks < len(p.Selftest.Expect) {
				t.Fatalf("%s: checks=%d, expects=%d", name, res.Checks, len(p.Selftest.Expect))
			}
			// Determinism: two runs on the same materialization agree.
			res2, err := RunSelfTest(p, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if res2.Checks != res.Checks || len(res2.Failures) != len(res.Failures) {
				t.Fatalf("%s: non-deterministic selftest", name)
			}
		})
	}
}

func TestBuiltinSessionEntries(t *testing.T) {
	p, err := Builtin("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"projects-transcripts": true, "projects-tool-results": true, "projects-subagents": true,
	}
	for _, e := range p.Entries {
		if want[e.ID] {
			delete(want, e.ID)
			if !e.Sessions {
				t.Errorf("%s: sessions = false, want true", e.ID)
			}
			if e.Kind != KindGlobGroup {
				t.Errorf("%s: kind = %s, want glob-group", e.ID, e.Kind)
			}
			if e.Root != "home" {
				t.Errorf("%s: root = %s, want home", e.ID, e.Root)
			}
			continue
		}
		if e.Sessions {
			t.Errorf("unexpected sessions marker on %s", e.ID)
		}
	}
	for id := range want {
		t.Errorf("entry %s missing from claude-code", id)
	}

	mem := findEntry(p, "projects-memory")
	if mem == nil {
		t.Fatal("projects-memory entry missing")
	}
	if mem.Kind != KindGlobGroup || mem.Root != "home" || mem.Layer != LayerL3 ||
		mem.Secret != SecretScan || mem.Extractor != ExtractorTemplate || mem.Priority != 15 ||
		mem.PathSemantics != PathMachineDerived || mem.DerivedFrom != DerivedRepoSlug ||
		mem.MaxBytesInline == nil || *mem.MaxBytesInline != 262144 ||
		mem.MaxBytesTotal == nil || *mem.MaxBytesTotal != 268435456 ||
		len(mem.Paths) != 1 || mem.Paths[0] != ".claude/projects/**/memory/**" {
		t.Fatalf("projects-memory entry drifted: %+v", mem)
	}
	if mem.Sessions {
		t.Error("projects-memory must not be a sessions entry")
	}
}

func findEntry(p *Profile, id string) *Entry {
	for _, e := range p.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func TestBuiltinUnknown(t *testing.T) {
	if _, err := Builtin("nope"); err == nil {
		t.Fatal("expected error for unknown built-in")
	}
}

func TestUnknownFieldExtraAndRoundTrip(t *testing.T) {
	p, err := LoadBytes([]byte(rtBase))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if got := string(p.Extra["future_top"]); got != `{"alpha":true,"beta":[1,2]}` {
		t.Fatalf("top-level Extra = %s", got)
	}
	if got := string(p.Entries[0].Extra["future_entry"]); got != `{"nested":[1,2,3]}` {
		t.Fatalf("entry Extra = %s", got)
	}
	if !bytes.Equal(p.Pack(), []byte(rtBase)) {
		t.Fatal("Pack differs from source")
	}
}

func TestRoundTripVariants(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"base", rtBase},
		{"crlf", strings.ReplaceAll(rtBase, "\n", "\r\n")},
		{"no_final_newline", strings.TrimSuffix(rtBase, "\n")},
		{"tabs", reindent(rtBase, "\t")},
		{"four_spaces", reindent(rtBase, "    ")},
		{"trailing_commas", strings.Replace(
			strings.Replace(
				strings.Replace(rtBase, `"linux"]`, `"linux",]`, 1),
				`"wall_ms": 1000}`, `"wall_ms": 1000,}`, 1),
			`"beta": [1, 2]`, `"beta": [1, 2,]`, 1)},
		{"block_comment", strings.Replace(rtBase, `  "name": "rt",`,
			"  /* block\n     comment */\n  \"name\": \"rt\",", 1)},
		{"line_comment_after_value", strings.Replace(rtBase, `"2.0",`, `"2.0", // version`, 1)},
		{"line_comment_before_key", strings.Replace(rtBase, `  "name"`,
			"  // before name\n  \"name\"", 1)},
		{"blank_lines", strings.Replace(rtBase, "\n  \"title\"", "\n\n\n  \"title\"", 1)},
		{"top_bottom_comments", "// top\n" + rtBase + "// bottom\n"},
		{"unicode_escape", strings.Replace(rtBase, `"vendor": "Test"`, `"vendor": "Tést"`, 1)},
		{"array_item_comments", strings.Replace(rtBase, `"beta": [1, 2]`,
			"\"beta\": [\n      1, /* mid */\n      2, // last\n    ]", 1)},
		{"key_order", strings.Replace(rtBase, `"future_top": {"alpha": true, "beta": [1, 2]}`,
			`"future_top": {"z": 1, "a": 2, "m": 3}`, 1)},
		{"aligned_whitespace", strings.Replace(rtBase, `"schema_version": `,
			`"schema_version":    `, 1)},
		{"crlf_comments", strings.ReplaceAll(strings.Replace(rtBase, `"2.0",`, `"2.0", // c`, 1), "\n", "\r\n")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p, err := LoadBytes([]byte(tc.src))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			if got := p.Pack(); !bytes.Equal(got, []byte(tc.src)) {
				t.Fatalf("round trip changed bytes\n--- got ---\n%s\n--- want ---\n%s", got, tc.src)
			}
		})
	}
}

func reindent(src, unit string) string {
	re := regexp.MustCompile(`(?m)^ +`)
	return re.ReplaceAllStringFunc(src, func(spaces string) string {
		n := len(spaces) / 2
		return strings.Repeat(unit, n)
	})
}

func TestBOMStripped(t *testing.T) {
	src := append([]byte{0xEF, 0xBB, 0xBF}, []byte(rtBase)...)
	p, err := LoadBytes(src)
	if err != nil {
		t.Fatalf("LoadBytes with BOM: %v", err)
	}
	if !bytes.Equal(p.Pack(), []byte(rtBase)) {
		t.Fatal("Pack should not contain the stripped BOM")
	}
}

func TestParseRejections(t *testing.T) {
	cases := []struct {
		name string
		src  string
		code string
	}{
		{"single_quote", `{'a': 1}`, "E-PRF-066"},
		{"unquoted_key", `{a: 1}`, "E-PRF-066"},
		{"bare_word", `{"a": yes}`, "E-PRF-066"},
		{"two_top_level", `{} {}`, "E-PRF-065"},
		{"top_level_array", `[{}]`, "E-PRF-065"},
		{"malformed", `{"a": }`, "E-PRF-063"},
		{"unclosed", `{`, "E-PRF-063"},
		{"duplicate_key", `{"schema_version":"2.0","name":"a","name":"b"}`, "E-PRF-064"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tc.src))
			requireCode(t, err, tc.code)
		})
	}

	// Invalid UTF-8 is rejected explicitly.
	_, err := LoadBytes([]byte{'{', 0xff, '}'})
	requireCode(t, err, "E-PRF-063")
}

func TestErrorPositions(t *testing.T) {
	// Duplicate key on line 1 with CJK bytes before it: column is a byte
	// column, so the two CJK characters count as six bytes.
	src := `{"schema_version":"2.0","name":"ok","notes":"你好","name":"dup"}`
	_, err := LoadBytes([]byte(src))
	requireCode(t, err, "E-PRF-064")
	pos := firstError(t, err).Pos
	wantCol := bytes.Index([]byte(src), []byte(`"name":"dup"`)) + 1
	if pos.Line != 1 || pos.Column != wantCol {
		t.Fatalf("position = %s, want 1:%d", pos, wantCol)
	}

	// Multiline: the duplicate is on line 4 at column 3.
	multi := "{\n  \"schema_version\": \"2.0\",\n  \"name\": \"a\",\n  \"name\": \"b\"\n}\n"
	_, err = LoadBytes([]byte(multi))
	requireCode(t, err, "E-PRF-064")
	pos = firstError(t, err).Pos
	if pos.Line != 4 || pos.Column != 3 {
		t.Fatalf("position = %s, want 4:3", pos)
	}

	// A validation diagnostic on an entry points at the entry object.
	entryLine := `    {"id": "a", "kind": "file", "root": "home", "path": "a", "layer": "L9", "secret": "none", "extractor": "none", "signals": [{"src": "observed_behavior", "note": "n"}]}`
	doc := "{\n  \"schema_version\": \"2.0\",\n  \"name\": \"pos\",\n  \"title\": \"T\",\n  \"applies_to\": {\"os\": [\"linux\"]},\n  \"roots\": {\"home\": \"/tmp/x\"},\n  \"entries\": [\n" + entryLine + "\n  ]\n}\n"
	_, err = LoadBytes([]byte(doc))
	requireCode(t, err, "E-PRF-006")
	pos = firstError(t, err).Pos
	if pos.Line != 8 || pos.Column != 5 {
		t.Fatalf("entry position = %s, want 8:5 (%v)", pos, firstError(t, err))
	}
}

func firstError(t *testing.T, err error) *Error {
	t.Helper()
	var errs Errors
	if !errors.As(err, &errs) || len(errs) == 0 {
		t.Fatalf("not a profile Errors: %v", err)
	}
	return errs[0]
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("expected Errors, got %T: %v", err, err)
	}
	if !errs.Has(code) {
		t.Fatalf("expected %s, got %v\n%s", code, errs.Codes(), err)
	}
}

// --- validation corpus -----------------------------------------------------

func baseProfileMap() map[string]any {
	return map[string]any{
		"schema_version":  "2.0",
		"name":            "t",
		"title":           "T",
		"applies_to":      map[string]any{"os": []any{"linux"}},
		"roots":           map[string]any{"home": "/tmp/packout-home"},
		"max_bytes_total": 1 << 30,
		"entries":         []any{baseEntryMap("a")},
		"selftest":        baseSelftestMap("a"),
	}
}

func baseEntryMap(id string) map[string]any {
	return map[string]any{
		"id":              id,
		"kind":            "file",
		"root":            "home",
		"path":            "a",
		"layer":           "L2",
		"secret":          "none",
		"extractor":       "none",
		"signals":         []any{map[string]any{"src": "observed_behavior", "note": "n"}},
		"selftest_exempt": "validation corpus",
	}
}

func baseSelftestMap(entry string) map[string]any {
	return map[string]any{
		"clock":    "2026-01-01T00:00:00Z",
		"fixtures": map[string]any{"home": "fixtures/home"},
		"expect": []any{map[string]any{
			"entry": entry, "root": "home", "match": "a",
		}},
		"budget": map[string]any{"wall_ms": 1000},
	}
}

func entryOf(m map[string]any) map[string]any {
	return m["entries"].([]any)[0].(map[string]any)
}

func selftestOf(m map[string]any) map[string]any {
	return m["selftest"].(map[string]any)
}

func loadMap(t *testing.T, m map[string]any) (*Profile, error) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return LoadBytes(b)
}

func TestBaseProfileIsValid(t *testing.T) {
	if _, err := loadMap(t, baseProfileMap()); err != nil {
		t.Fatalf("base profile should validate: %v", err)
	}
}

func TestValidationErrorCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
		mut  func(map[string]any)
	}{
		{"E-PRF-001", "E-PRF-001", func(m map[string]any) { delete(m, "schema_version") }},
		{"E-PRF-002", "E-PRF-002", func(m map[string]any) { m["schema_version"] = "3.0" }},
		{"E-PRF-003", "E-PRF-003", func(m map[string]any) { m["name"] = "Bad Name" }},
		{"E-PRF-004", "E-PRF-004", func(m map[string]any) {
			e := baseEntryMap("a")
			e["path"] = "b"
			m["entries"] = append(m["entries"].([]any), e)
		}},
		{"E-PRF-005", "E-PRF-005", func(m map[string]any) { entryOf(m)["kind"] = "weird" }},
		{"E-PRF-006", "E-PRF-006", func(m map[string]any) { entryOf(m)["layer"] = "L9" }},
		{"E-PRF-007", "E-PRF-007", func(m map[string]any) { entryOf(m)["secret"] = "bogus" }},
		{"E-PRF-008", "E-PRF-008", func(m map[string]any) { entryOf(m)["extractor"] = "bogus" }},
		{"E-PRF-009", "E-PRF-009", func(m map[string]any) { delete(entryOf(m), "path") }},
		{"E-PRF-010", "E-PRF-010", func(m map[string]any) { entryOf(m)["path"] = "a*b" }},
		{"E-PRF-011", "E-PRF-011", func(m map[string]any) { entryOf(m)["root"] = "nope" }},
		{"E-PRF-012", "E-PRF-012", func(m map[string]any) { entryOf(m)["path"] = "../x" }},
		{"E-PRF-013", "E-PRF-013", func(m map[string]any) { entryOf(m)["max_bytes_inline"] = 8388609 }},
		{"E-PRF-014", "E-PRF-014", func(m map[string]any) { entryOf(m)["max_depth"] = 99 }},
		{"E-PRF-015", "E-PRF-015", func(m map[string]any) { entryOf(m)["signals"] = []any{} }},
		{"E-PRF-016", "E-PRF-016", func(m map[string]any) {
			entryOf(m)["signals"] = []any{map[string]any{"src": "official_docs", "note": "n"}}
		}},
		{"E-PRF-017", "E-PRF-017", func(m map[string]any) { delete(m, "selftest") }},
		{"E-PRF-018", "E-PRF-018", func(m map[string]any) {
			delete(entryOf(m), "selftest_exempt")
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["entry"] = "zzz"
		}},
		{"E-PRF-021", "E-PRF-021", func(m map[string]any) {
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["match"] = "../escape"
		}},
		{"E-PRF-020", "E-PRF-020", func(m map[string]any) {
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["entry"] = "zzz"
		}},
		{"E-PRF-022", "E-PRF-022", func(m map[string]any) { entryOf(m)["follow_symlinks"] = true }},
		{"E-PRF-023", "E-PRF-023", func(m map[string]any) {
			e := baseEntryMap("b")
			m["entries"] = append(m["entries"].([]any), e)
		}},
		{"E-PRF-024", "E-PRF-024", func(m map[string]any) { entryOf(m)["expand"] = "aggregate" }},
		{"E-PRF-025", "E-PRF-025", func(m map[string]any) {
			entryOf(m)["redact"] = map[string]any{"key_pattern": []any{"x"}}
		}},
		{"E-PRF-026", "E-PRF-026", func(m map[string]any) {
			entryOf(m)["layer"] = "L3"
			entryOf(m)["unique_within"] = "root"
		}},
		{"E-PRF-027", "E-PRF-027", func(m map[string]any) {
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["root"] = "nope"
		}},
		{"E-PRF-028", "E-PRF-028", func(m map[string]any) { entryOf(m)["scan"] = "strict" }},
		{"E-PRF-030", "E-PRF-030", func(m map[string]any) {
			m["roots"] = map[string]any{"home": "relative/path"}
		}},
		{"E-PRF-032", "E-PRF-032", func(m map[string]any) { entryOf(m)["parts"] = []any{} }},
		{"E-PRF-033", "E-PRF-033", func(m map[string]any) {
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "p",
				"selector": map[string]any{
					"json_pointer": "/x", "line_pattern": "y",
				},
			}}
		}},
		{"E-PRF-034", "E-PRF-034", func(m map[string]any) {
			entryOf(m)["parts"] = []any{
				map[string]any{"id": "p1", "selector": map[string]any{"json_pointer": "/x"}},
				map[string]any{"id": "p2", "selector": map[string]any{"json_pointer": "/x"}},
			}
		}},
		{"E-PRF-035", "E-PRF-035", func(m map[string]any) {
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "uncovered", "selector": map[string]any{"json_pointer": "/x"},
			}}
		}},
		{"E-PRF-036", "E-PRF-036", func(m map[string]any) {
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "p", "path": "x", "selector": map[string]any{"json_pointer": "/x"},
			}}
		}},
		{"E-PRF-037", "E-PRF-037", func(m map[string]any) {
			e := map[string]any{
				"id": "ca", "kind": "catch-all", "root": "home", "path": "x",
				"layer": "L2", "secret": "none", "extractor": "none",
				"priority": -100, "signals": []any{},
			}
			m["entries"] = []any{e}
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["entry"] = "ca"
		}},
		{"E-PRF-038", "E-PRF-038", func(m map[string]any) {
			entryOf(m)["path_semantics"] = "machine_derived"
		}},
		{"E-PRF-039", "E-PRF-039", func(m map[string]any) {
			entryOf(m)["path_semantics"] = "machine_derived"
			entryOf(m)["derived_from"] = "git_worktree_of"
		}},
		{"E-PRF-040", "E-PRF-040", func(m map[string]any) { entryOf(m)["secret"] = "relogin" }},
		{"E-PRF-041", "E-PRF-041", func(m map[string]any) { entryOf(m)["secret"] = "restore" }},
		{"E-PRF-042", "E-PRF-042", func(m map[string]any) {
			entryOf(m)["secret"] = "scan"
			entryOf(m)["max_bytes_inline"] = 0
		}},
		{"E-PRF-043", "E-PRF-043", func(m map[string]any) {
			entryOf(m)["secret"] = "scan"
			entryOf(m)["extractor"] = "raw-ref"
		}},
		{"E-PRF-044", "E-PRF-044", func(m map[string]any) {
			entryOf(m)["kind"] = "dir"
			entryOf(m)["companions"] = []any{"-wal"}
		}},
		{"E-PRF-045", "E-PRF-045", func(m map[string]any) { entryOf(m)["companions"] = []any{"wal"} }},
		{"E-PRF-046", "E-PRF-046", func(m map[string]any) { entryOf(m)["priority"] = 5000 }},
		{"E-PRF-047", "E-PRF-047", func(m map[string]any) { entryOf(m)["unique_within"] = "global" }},
		{"E-PRF-048", "E-PRF-048", func(m map[string]any) { entryOf(m)["churn"] = "medium" }},
		{"E-PRF-049", "E-PRF-049", func(m map[string]any) { entryOf(m)["max_bytes_structure"] = 8388609 }},
		{"E-PRF-050", "E-PRF-050", func(m map[string]any) { delete(selftestOf(m), "budget") }},
		{"E-PRF-051", "E-PRF-051", func(m map[string]any) {
			selftestOf(m)["files"] = []any{map[string]any{"path": "/home/u/x", "size": 1}}
		}},
		{"E-PRF-052", "E-PRF-052", func(m map[string]any) { entryOf(m)["max_bytes_total"] = 2 << 30 }},
		{"E-PRF-057", "E-PRF-057", func(m map[string]any) {
			delete(entryOf(m), "selftest_exempt")
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "p", "selector": map[string]any{"json_pointer": "/x"},
			}}
		}},
		{"E-PRF-059", "E-PRF-059", func(m map[string]any) { entryOf(m)["path"] = "/other/x" }},
		{"E-PRF-060", "E-PRF-060", func(m map[string]any) {
			m["entries"] = []any{map[string]any{
				"id": "a", "kind": "named-location", "locator": "wincred:X",
				"probe": "keychain", "layer": "L2", "secret": "none",
				"extractor": "none", "selftest_exempt": "test",
			}}
		}},
		{"E-PRF-061", "E-PRF-061", func(m map[string]any) { entryOf(m)["side_effects"] = []any{"bogus"} }},
		{"E-PRF-062", "E-PRF-062", func(m map[string]any) { m["max_bytes_total"] = 0 }},
		{"E-PRF-067", "E-PRF-067", func(m map[string]any) {
			selftestOf(m)["files"] = []any{map[string]any{"path": "../x", "size": 1}}
		}},
		{"E-PRF-068", "E-PRF-068", func(m map[string]any) { entryOf(m)["parts_uncovered"] = "keep" }},
		{"E-PRF-069", "E-PRF-069", func(m map[string]any) {
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "p", "selector": map[string]any{"json_pointer": "/x"},
				"origin": "X", "origin_path_key": "x",
			}}
		}},
		{"E-PRF-070", "E-PRF-070", func(m map[string]any) {
			m["entries"] = []any{map[string]any{
				"id": "a", "kind": "catch-all", "root": "home", "scope": "subtree",
				"layer": "L2", "secret": "none", "extractor": "none",
				"priority": -100, "signals": []any{},
			}}
		}},
		{"E-PRF-071", "E-PRF-071", func(m map[string]any) {
			entryOf(m)["side_effects"] = []any{"shm_created"}
		}},
		{"E-PRF-072", "E-PRF-072", func(m map[string]any) {
			entryOf(m)["kind"] = "dir"
			entryOf(m)["parts"] = []any{map[string]any{
				"id": "p", "selector": map[string]any{"json_pointer": "/x"},
			}}
		}},
		{"E-PRF-073", "E-PRF-073", func(m map[string]any) {
			e := map[string]any{
				"id": "ca", "kind": "catch-all", "root": "home",
				"layer": "L2", "secret": "none", "extractor": "none",
				"priority": -100, "signals": []any{},
			}
			m["entries"] = []any{e}
			selftestOf(m)["expect"].([]any)[0].(map[string]any)["entry"] = "ca"
		}},
		{"E-PRF-074", "E-PRF-074", func(m map[string]any) { entryOf(m)["sessions"] = true }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m := baseProfileMap()
			tc.mut(m)
			_, err := loadMap(t, m)
			requireCode(t, err, tc.code)
		})
	}
}

func TestValidationEPRF019(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures", "home", "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := baseProfileMap()
	selftestOf(m)["expect"].([]any)[0].(map[string]any)["match"] = "missing.txt"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.jsonc")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	requireCode(t, err, "E-PRF-019")

	// A matching path is accepted.
	selftestOf(m)["expect"].([]any)[0].(map[string]any)["match"] = "a"
	b, _ = json.Marshal(m)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected valid profile: %v", err)
	}
}

func TestLoadFromDisk(t *testing.T) {
	for _, name := range BuiltinNames() {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "profiles", name+".jsonc")
			if _, err := os.Stat(path); err != nil {
				t.Skipf("profile not found at %s", path)
			}
			p, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s): %v", path, err)
			}
			res, err := RunSelfTest(p, t.TempDir())
			if err != nil {
				t.Fatalf("RunSelfTest: %v", err)
			}
			if !res.Passed {
				for _, f := range res.Failures {
					t.Errorf("%v", f)
				}
				t.Fatal("on-disk selftest failed")
			}
		})
	}
}

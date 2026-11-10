package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

// requirement 1: unknown fields survive Parse as AST members.
func TestUnknownFieldsPreserved(t *testing.T) {
	src, err := os.ReadFile("testdata/roundtrip.jsonc")
	if err != nil {
		t.Fatal(err)
	}
	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	future := findMember(&v, "future_field")
	if future == nil {
		t.Fatalf("unknown key 'future_field' missing from AST")
	}
	if findMember(future, "unknown_array") == nil {
		t.Fatalf("unknown nested key 'unknown_array' missing from AST")
	}
	if got := string(future.Pack()); !strings.Contains(got, `"nested": true`) {
		t.Fatalf("unknown subtree not value-exact: %q", got)
	}
	if got := v.Pack(); !bytes.Equal(got, src) {
		t.Errorf("Parse+Pack changed bytes with unknown fields present (orig %d, got %d)", len(src), len(got))
	}

	// Contrast: the stdlib struct path with no schema slot silently drops it.
	std, err := hujson.Standardize(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	type known struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var k known
	if err := json.Unmarshal(std, &k); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if k.Name != "quoted name" || k.Version != "1.2.3" {
		t.Errorf("known fields not decoded: %+v", k)
	}
	t.Log("unknown fields ('future_field', its nested subtree) live in the AST; struct decode has no slot for them")
}

// requirement 2: every value (including object member names) has offsets that
// convert to a 1-based line and byte column.
func TestValuePositions(t *testing.T) {
	src := []byte("{\n  \"name\": \"svc\",\n  \"port\": 8080\n}\n")
	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	missing := 0
	count := walkAllWithNames(&v, func(x *hujson.Value) {
		if x.StartOffset < 0 || x.EndOffset <= x.StartOffset || x.EndOffset > len(src) {
			missing++
			t.Errorf("bad offsets %d..%d for %q", x.StartOffset, x.EndOffset, src[safeStart(x.StartOffset):min(x.EndOffset, len(src))])
			return
		}
		line, col := posOf(src, x.StartOffset)
		if line <= 0 || col <= 0 {
			missing++
			t.Errorf("bad position %d:%d for %q", line, col, src[x.StartOffset:x.EndOffset])
		}
	})
	if missing > 0 {
		t.Fatalf("%d/%d values lack a usable position", missing, count)
	}

	// Exact spot check. Source line 2 is `  "name": "svc",`:
	//   '"name"' starts at byte offset 4 -> line 2, byte column 3.
	//   '"svc"'  starts at byte offset 12 -> line 2, byte column 11.
	name := findMember(&v, "name")
	key := memberKey(&v, "name")
	if key == nil || name == nil {
		t.Fatal("'name' member not found")
	}
	if gotL, gotC := posOf(src, key.StartOffset); gotL != 2 || gotC != 3 {
		t.Errorf("key position = %d:%d, want 2:3", gotL, gotC)
	}
	if gotL, gotC := posOf(src, name.StartOffset); gotL != 2 || gotC != 11 {
		t.Errorf("value position = %d:%d, want 2:11", gotL, gotC)
	}

	// hujson.Value.All/Range DOES traverse object member names: each
	// Member Name and Value are both yielded, interleaved, depth-first.
	allCount := 0
	v.Range(func(*hujson.Value) bool { allCount++; return true })
	t.Logf("checked %d values incl. member names; All()/Range() yielded %d (member names included)", count, allCount)
	if allCount != count {
		t.Errorf("All()/Range() yielded %d values, manual walk %d", allCount, count)
	}
}

// requirement 3: Parse -> Pack is byte-identical for every HuJSON feature.
// Standardize/Format are deliberately NOT used here; see TestRoundTripPaths.
func TestLosslessRoundTrip(t *testing.T) {
	full, err := os.ReadFile("testdata/roundtrip.jsonc")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, src string }{
		{"full sample", string(full)},
		{"trailing line comment spacing", "{\n  \"a\": 1   // keep my columns\n}\n"},
		{"block comment between members", "{\n  /* about b */\n  \"b\": 2\n}\n"},
		{"blank line between keys", "{\n  \"a\": 1,\n\n  \"b\": 2\n}\n"},
		{"line comment between keys", "{\n  \"a\": 1,\n  // about b\n  \"b\": 2\n}\n"},
		{"comment detached by blank line", "{\n  \"a\": 1,\n\n  // stands alone\n\n  \"b\": 2\n}\n"},
		{"key order preserved", "{\n  \"z\": 1,\n  \"a\": 2,\n  \"m\": 3\n}\n"},
		{"tab indentation", "{\n\t\"a\": 1,\n\t\"nested\": {\n\t\t\"b\": 2\n\t}\n}\n"},
		{"four-space indentation and alignment", "{\n    \"a\":    1,\n    \"bb\":   2\n}\n"},
		{"crlf line endings", "{\r\n  \"a\": 1,\r\n  \"b\": 2\r\n}\r\n"},
		{"no trailing newline", "{\"a\": 1}"},
		{"unicode escapes", "{\"a\": \"\\u4f60\\u597d\", \"emoji\": \"\\ud83d\\ude00\"}\n"},
		{"duplicate keys", "{\n  \"name\": \"first\",\n  \"name\": \"second\"\n}\n"},
		{"trailing comma in object and array", "{\n  \"a\": 1,\n  \"arr\": [1, 2,],\n}\n"},
		{"array item comments", "{\n  \"a\": [\n    1, // one\n    2  // two\n  ]\n}\n"},
		{"comment at end of file", "{\"a\": 1}\n// eof comment\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			v, err := hujson.Parse(bytes.Clone(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := v.Pack()
			if bytes.Equal(got, src) {
				t.Logf("byte-identical (%d bytes)", len(src))
				return
			}
			t.Errorf("not byte-identical (orig %d bytes, got %d):\n%s", len(src), len(got), lineDiff(src, got))
		})
	}
}

// core conclusion: which hujson path is lossless?
func TestRoundTripPaths(t *testing.T) {
	src := []byte("{\r\n  // note\r\n  \"a\": [1, 2,],\r\n}\r\n")

	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	packed := v.Pack()

	formatted, err := hujson.Format(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}

	clone := v.Clone()
	clone.Standardize()
	clonePacked := clone.Pack()
	if !bytes.Equal(clonePacked, std) {
		t.Logf("note: Parse+Clone+Standardize+Pack != hujson.Standardize bytes (orig %d, std %d, clone %d)",
			len(src), len(std), len(clonePacked))
	}

	t.Logf("src                = %q", src)
	t.Logf("Parse+Pack         = %q  identical=%v", packed, bytes.Equal(packed, src))
	t.Logf("Format(src)        = %q  identical=%v", formatted, bytes.Equal(formatted, src))
	t.Logf("Standardize(src)   = %q  identical=%v", std, bytes.Equal(std, src))
	t.Logf("Clone+Standardize  = %q  identical=%v", clonePacked, bytes.Equal(clonePacked, src))

	if !bytes.Equal(packed, src) {
		t.Errorf("Parse+Pack is not lossless: %q", packed)
	}
	if bytes.Equal(formatted, src) {
		t.Errorf("Format unexpectedly lossless; conclusion needs revisiting")
	}
	if bytes.Equal(std, src) {
		t.Errorf("Standardize unexpectedly lossless; conclusion needs revisiting")
	}
	if v.IsStandard() {
		t.Errorf("IsStandard reported true for HuJSON with comments/trailing comma")
	}
	// Standardize mutates in place and drops comments (they become spaces).
	v.Standardize()
	if bytes.Equal(v.Pack(), src) {
		t.Errorf("in-place Standardize preserved comments/trailing comma")
	}
	if strings.Contains(string(std), "//") {
		t.Errorf("Standardize output still contains comments: %q", std)
	}
	t.Logf("after in-place Standardize: %q", v.Pack())
}

// editing: mutate one literal and Pack; all trivia and CRLF must survive.
func TestEditPreservesTrivia(t *testing.T) {
	src := []byte("{\r\n  // keep me\r\n  \"name\": \"old\",\r\n  \"unknown\": [1, 2,],\r\n}\r\n")
	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	edited := &v
	val := findMember(edited, "name")
	if val == nil {
		t.Fatal("name not found")
	}
	val.Value = hujson.String("new")
	got := edited.Pack()
	want := bytes.Replace(src, []byte(`"old"`), []byte(`"new"`), 1)
	if !bytes.Equal(got, want) {
		t.Errorf("edit not surgical:\n%s", lineDiff(want, got))
	}
	t.Logf("edited only the value; comments/CRLF/trailing comma intact: %q", got)

	// Offsets go stale after a length-changing edit; UpdateOffsets repairs them.
	val.Value = hujson.String("a-much-longer-value")
	edited.UpdateOffsets()
	packed := edited.Pack()
	reparsed, err := hujson.Parse(packed)
	if err != nil {
		t.Fatalf("reparse edited output: %v", err)
	}
	wantOffsets := collectOffsets(&reparsed)
	gotOffsets := collectOffsets(edited)
	if fmt.Sprint(gotOffsets) != fmt.Sprint(wantOffsets) {
		t.Errorf("UpdateOffsets mismatch after length-changing edit:\n got  %v\n want %v", gotOffsets, wantOffsets)
	}
	t.Logf("UpdateOffsets after length-changing edit matches a fresh Parse")
}

// extra: duplicate keys.
func TestDuplicateKeys(t *testing.T) {
	src := []byte("{\n  \"name\": \"first\",\n  \"name\": \"second\"\n}\n")
	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("root is %T, want *hujson.Object", v.Value)
	}
	if len(obj.Members) != 2 {
		t.Fatalf("AST keeps %d members, want 2", len(obj.Members))
	}
	first := v.Find("/name")
	if first == nil {
		t.Fatal("Find(/name) returned nil")
	}
	if got := first.Value.(hujson.Literal).String(); got != "first" {
		t.Errorf("Find returns %s, want first occurrence \"first\"", got)
	}
	if got := v.Pack(); !bytes.Equal(got, src) {
		t.Errorf("duplicate-key round trip changed bytes: %q", got)
	}
	std, err := hujson.Standardize(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(std, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	t.Logf("hujson: no error, both members kept, Find returns first; json.Unmarshal(map): name=%q (last wins)", m["name"])
}

// extra: non-standard JSON (single quotes, unquoted keys) and what is accepted.
func TestNonStandardJSON(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{"single-quoted key", `{'a': 1}`, true},
		{"single-quoted value", `{"a": 'b'}`, true},
		{"unquoted key", `{a: 1}`, true},
		{"bare word value", `{"a": yes}`, true},
		{"trailing comma object", `{"a": 1,}`, false},
		{"trailing comma array", `[1, 2,]`, false},
		{"line comment", "{\"a\": 1} // ok\n", false},
		{"block comment", "/* x */ {\"a\": 1}", false},
		{"leading UTF-8 BOM", string(rune(0xFEFF)) + "{\"a\": 1}", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			v, err := hujson.Parse([]byte(tc.src))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected Parse error, got success: %q", v.Pack())
				}
				if !strings.Contains(err.Error(), "line ") || !strings.Contains(err.Error(), "column ") {
					t.Errorf("parse error lacks line/column: %v", err)
				}
				t.Logf("rejected with location: %v", err)
				return
			}
			if err != nil {
				t.Fatalf("unexpected Parse error: %v", err)
			}
			if got := v.Pack(); string(got) != tc.src {
				t.Errorf("accepted but not byte-identical: %q", got)
			}
			t.Logf("accepted, byte-identical")
		})
	}
}

// extra: line/column units for non-ASCII input.
func TestColumnUnit(t *testing.T) {
	src := []byte(`{"你好": 1}`)
	v, err := hujson.Parse(bytes.Clone(src))
	if err != nil {
		t.Fatal(err)
	}
	val := findMember(&v, "你好")
	if val == nil {
		t.Fatal("value not found")
	}
	line, byteCol := posOf(src, val.StartOffset)
	if line != 1 || byteCol != 12 {
		t.Errorf("position = %d:%d, want 1:12 (byte column)", line, byteCol)
	}
	runeCol := 1 + len([]rune(string(src[:val.StartOffset])))
	t.Logf("value at offset %d: line=%d byteCol=%d runeCol=%d; hujson positions are BYTE columns",
		val.StartOffset, line, byteCol, runeCol)
	if byteCol == runeCol {
		t.Errorf("expected byte and rune columns to differ for non-ASCII input")
	}
}

func lineDiff(want, got []byte) string {
	al, gl := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	var diff strings.Builder
	for i := 0; i < len(al) || i < len(gl); i++ {
		var a, g string
		if i < len(al) {
			a = al[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		mark := " "
		if a != g {
			mark = "!"
		}
		fmt.Fprintf(&diff, "%s %2d | orig %q\n%s    | got  %q\n", mark, i+1, a, mark, g)
	}
	return diff.String()
}

func posOf(src []byte, off int) (line, col int) {
	line = 1 + bytes.Count(src[:off], []byte("\n"))
	col = 1 + off - (bytes.LastIndexByte(src[:off], '\n') + 1)
	return line, col
}

func memberKey(v *hujson.Value, name string) *hujson.Value {
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	for i := range obj.Members {
		if memberName(obj.Members[i]) == name {
			return &obj.Members[i].Name
		}
	}
	return nil
}

func findMember(v *hujson.Value, name string) *hujson.Value {
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	for i := range obj.Members {
		if memberName(obj.Members[i]) == name {
			return &obj.Members[i].Value
		}
	}
	return nil
}

func memberName(m hujson.ObjectMember) string {
	lit, _ := m.Name.Value.(hujson.Literal)
	return lit.String()
}

// walkAllWithNames visits values AND object member names; All/Range skip names.
func walkAllWithNames(v *hujson.Value, fn func(*hujson.Value)) int {
	fn(v)
	n := 1
	switch x := v.Value.(type) {
	case *hujson.Object:
		for i := range x.Members {
			n += walkAllWithNames(&x.Members[i].Name, fn)
			n += walkAllWithNames(&x.Members[i].Value, fn)
		}
	case *hujson.Array:
		for i := range x.Elements {
			n += walkAllWithNames(&x.Elements[i], fn)
		}
	}
	return n
}

func collectOffsets(v *hujson.Value) []int {
	var out []int
	walkAllWithNames(v, func(x *hujson.Value) {
		out = append(out, x.StartOffset, x.EndOffset)
	})
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func safeStart(a int) int {
	if a < 0 {
		return 0
	}
	return a
}

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// requirement 1: unknown fields survive a decode into yaml.Node.
func TestUnknownFieldsPreserved(t *testing.T) {
	src := []byte("name: svc\nfuture_field:\n  nested: true\n")
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		t.Fatalf("decode into Node: %v", err)
	}
	if findKey(&doc, "future_field") == nil {
		t.Fatalf("unknown key 'future_field' missing from Node tree")
	}

	// Contrast: decoding straight into a struct drops unknown keys even with
	// KnownFields(false); the Node tree is the only place they survive.
	type known struct {
		Name string `yaml:"name"`
	}
	var k known
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(false)
	if err := dec.Decode(&k); err != nil {
		t.Fatalf("decode into struct: %v", err)
	}
	if k.Name != "svc" {
		t.Fatalf("known field not decoded: %q", k.Name)
	}
	t.Log("unknown fields present in Node; struct decode has no slot for them")
}

// requirement 2: every node carries a usable line and column.
func TestNodePositions(t *testing.T) {
	src, err := os.ReadFile("testdata/roundtrip.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	missing := 0
	walk(&doc, func(n *yaml.Node) {
		if n.Kind == yaml.DocumentNode {
			return
		}
		if n.Line <= 0 || n.Column <= 0 {
			missing++
			t.Errorf("node kind=%d value=%q has line=%d col=%d", n.Kind, n.Value, n.Line, n.Column)
		}
	})
	if missing > 0 {
		t.Fatalf("%d/%d nodes lack a position", missing, countNodes(&doc))
	}
	// Spot-check exact coordinates: "name" is line 3 col 1, its value line 3 col 7.
	key, val := findPair(&doc, "name")
	if key == nil {
		t.Fatal("key 'name' not found")
	}
	if key.Line != 3 || key.Column != 1 {
		t.Errorf("key 'name' position = %d:%d, want 3:1", key.Line, key.Column)
	}
	if val.Line != 3 || val.Column != 7 {
		t.Errorf("value position = %d:%d, want 3:7", val.Line, val.Column)
	}
	t.Logf("checked %d nodes; all have line/column, spot check 3:1 / 3:7 ok", countNodes(&doc))
}

// requirement 3: decode -> encode is byte-identical, comments/quotes/blocks kept.
// Each case asserts exact bytes; a line diff is printed on failure.
func TestLosslessRoundTrip(t *testing.T) {
	full, err := os.ReadFile("testdata/roundtrip.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, src string }{
		{"full sample", string(full)},
		{"trailing comment spacing", "a: 1   # keep my columns\n"},
		{"document start marker", "---\na: 1\n"},
		{"folded block scalar", "a: >-\n  folded one\n  folded two\n"},
		{"literal block chomping", "a: |-\n  kept no newline\n"},
		{"blank line between keys", "a: 1\n\nb: 2\n"},
		{"comment between keys", "a: 1\n# about b\nb: 2\n"},
		{"merge key", "base: &b\n  x: 1\nd:\n  <<: *b\n"},
		{"quoted key", "\"a b\": 1\n"},
		{"multi-line flow sequence", "a: [1,\n  2]\n"},
		{"sequence item comment", "- a # line comment\n- b\n"},
		{"unicode escape", "a: \"\\u4f60\\u597d\"" + "\n"},
		{"tab escape", "a: \"col\\there\"" + "\n"},
		{"comment detached by blank line", "a: 1\n\n# stands alone\n\nb: 2\n"},
		{"no trailing newline", "a: 1"},
		{"crlf line endings", "a: 1\r\nb: 2\r\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			var doc yaml.Node
			if err := yaml.Unmarshal(src, &doc); err != nil {
				t.Fatalf("decode: %v", err)
			}
			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			enc.SetIndent(2) // already the source's indent; give the encoder its best case
			if err := enc.Encode(&doc); err != nil {
				t.Fatalf("encode: %v", err)
			}
			if err := enc.Close(); err != nil {
				t.Fatalf("close encoder: %v", err)
			}
			got := buf.Bytes()
			if bytes.Equal(got, src) {
				t.Logf("byte-identical (%d bytes)", len(src))
				return
			}
			t.Errorf("not byte-identical (orig %d bytes, got %d):\n%s", len(src), len(got), lineDiff(src, got))
		})
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

// extra: duplicate keys.
func TestDuplicateKeys(t *testing.T) {
	src := []byte("name: first\nname: second\n")
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		t.Fatalf("decode into Node: %v", err)
	}
	if n := countKey(&doc, "name"); n != 2 {
		t.Errorf("Node keeps %d 'name' keys, want 2", n)
	}
	var m map[string]string
	mErr := yaml.Unmarshal(src, &m)
	t.Logf("decode into map: err=%v value=%q", mErr, m["name"])
	type cfg struct {
		Name string `yaml:"name"`
	}
	var c cfg
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(false)
	sErr := dec.Decode(&c)
	t.Logf("decode into struct, KnownFields(false): err=%v value=%q", sErr, c.Name)
	if mErr == nil || sErr == nil {
		t.Errorf("expected duplicate keys to be rejected on mapping decode; map err=%v struct err=%v", mErr, sErr)
	}
	if !strings.Contains(mErr.Error(), "already defined at line 1") {
		t.Errorf("duplicate-key error lacks the earlier definition location: %q", mErr)
	}
}

// extra: type-error location under KnownFields(false).
func TestTypeErrorLocationKnownFieldsFalse(t *testing.T) {
	src := []byte("name: svc\nport: \"abc\"\nfuture: 1\n")
	type cfg struct {
		Name string `yaml:"name"`
		Port int    `yaml:"port"`
	}
	for _, known := range []bool{false, true} {
		known := known
		t.Run(fmt.Sprintf("KnownFields=%v", known), func(t *testing.T) {
			dec := yaml.NewDecoder(bytes.NewReader(src))
			dec.KnownFields(known)
			var c cfg
			err := dec.Decode(&c)
			if err == nil {
				t.Fatalf("type error not reported")
			}
			var te *yaml.TypeError
			if errors.As(err, &te) {
				t.Logf("TypeError.Errors = %q", te.Errors)
			}
			msg := err.Error()
			t.Logf("full error: %q", msg)
			if !strings.Contains(msg, "line 2") {
				t.Errorf("error lacks line 2: %q", msg)
			}
			if !strings.Contains(msg, "abc") {
				t.Errorf("error does not identify the offending value: %q", msg)
			}
			if known && !strings.Contains(msg, "future") {
				t.Errorf("KnownFields(true) did not report unknown field: %q", msg)
			}
			if strings.Contains(msg, "column") || strings.Contains(msg, "col ") {
				t.Log("error includes a column")
			} else {
				t.Log("error has line only, no column")
			}
		})
	}
}

func findKey(n *yaml.Node, key string) *yaml.Node {
	k, _ := findPair(n, key)
	return k
}

// findPair returns the key and value nodes of the first matching mapping pair.
// In yaml.v3 a mapping's Content alternates key, value; the value is a sibling
// of the key, not a child of it.
func findPair(n *yaml.Node, key string) (k, v *yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i], n.Content[i+1]
			}
		}
	}
	for _, c := range n.Content {
		if kk, vv := findPair(c, key); kk != nil {
			return kk, vv
		}
	}
	return nil, nil
}

func countKey(n *yaml.Node, key string) int {
	count := 0
	walk(n, func(x *yaml.Node) {
		if x.Kind == yaml.ScalarNode && x.Value == key && x.Style == 0 {
			count++
		}
	})
	return count
}

func countNodes(n *yaml.Node) int {
	count := 0
	walk(n, func(*yaml.Node) { count++ })
	return count
}

// extra: what unit are Column values in? Non-ASCII keys matter for editors.
func TestColumnUnit(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("你好: 1\n"), &doc); err != nil {
		t.Fatal(err)
	}
	val := doc.Content[0].Content[1]
	// 1-based rune count is 5; a byte count would be 9, UTF-16 units 5 here.
	if val.Column != 5 {
		t.Errorf("value column = %d, want 5 (rune-counted)", val.Column)
	}
	t.Logf("columns are rune-counted (col=%d); astral chars count 1, Windows UTF-16 editors may count 2", val.Column)
}

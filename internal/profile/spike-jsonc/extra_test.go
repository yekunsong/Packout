package main

import (
	"bytes"
	"testing"

	"github.com/tailscale/hujson"
)

// extra: Value.Clone drops an EMPTY trailing-comma marker. A trailing comma is
// encoded as AfterExtra != nil on the last member/element; Parse sets that to a
// zero-length non-nil slice when nothing follows the comma, and Clone's
// copyBytes turns it into nil. Editing a clone therefore silently removes
// trailing commas (this test is expected to FAIL; it documents the defect).
func TestCloneTrailingComma(t *testing.T) {
	for _, src := range []string{`[1, 2,]`, `{"a": 1,}`, `{"a": [1,],}`} {
		v, err := hujson.Parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		got := string(v.Clone().Pack())
		t.Logf("src=%q clone.Pack=%q identical=%v", src, got, got == src)
		if got != src {
			t.Errorf("Clone lost trailing comma: %q -> %q", src, got)
		}
	}
	// A non-empty extra after the comma (whitespace/comment) survives Clone.
	src := `{"a": 1, }`
	v, err := hujson.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(v.Clone().Pack()); got != src {
		t.Errorf("Clone lost non-empty AfterExtra: %q -> %q", src, got)
	}
}

// extra: package-level hujson.Standardize mutates the caller's byte slice.
// Parse aliases b and standardize() overwrites comment bytes with spaces in
// place. Keep a copy (or work on ast.Clone()) if the original bytes are still
// needed for write-back.
func TestStandardizeMutatesInput(t *testing.T) {
	mk := func() []byte { return []byte("{\n  // comment\n  \"a\": 1,\n}\n") }
	src := mk()
	orig := bytes.Clone(src)
	std, err := hujson.Standardize(src)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(src, orig) {
		t.Errorf("expected observed in-place mutation of the caller's slice; src still %q", src)
	} else {
		t.Logf("input slice MUTATED in place: %q -> %q (returned std=%q)", orig, src, std)
	}

	// Cloning before the call protects the original.
	src2 := mk()
	orig2 := bytes.Clone(src2)
	if _, err := hujson.Standardize(bytes.Clone(src2)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src2, orig2) {
		t.Errorf("cloning before Standardize did not protect the caller slice: %q", src2)
	}

	// ast.Clone().Standardize() also leaves the original AST untouched.
	src3 := mk()
	ast, err := hujson.Parse(src3)
	if err != nil {
		t.Fatal(err)
	}
	before := ast.Pack()
	clone := ast.Clone()
	clone.Standardize()
	if !bytes.Equal(ast.Pack(), before) {
		t.Errorf("Standardize on a Clone mutated the original AST")
	}
}

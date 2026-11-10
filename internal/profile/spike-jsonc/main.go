// Command spike probes whether github.com/tailscale/hujson can back a profile
// parser that must preserve unknown fields, report value positions, and
// round-trip byte-for-byte. Run it with `go run . testdata/roundtrip.jsonc`.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

func main() {
	path := "testdata/roundtrip.jsonc"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	v, err := hujson.Parse(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	walk(&v, func(x *hujson.Value) {
		line, col := lineCol(src, x.StartOffset)
		kind := byte('?')
		if x.Value != nil {
			kind = byte(x.Value.Kind())
		}
		fmt.Printf("off=%3d..%3d line=%d col=%d kind=%q raw=%q\n",
			x.StartOffset, x.EndOffset, line, col, kind, src[x.StartOffset:x.EndOffset])
	})
	out := v.Pack()
	fmt.Printf("\nParse+Pack identical: %v (orig %d bytes, got %d)\n", bytes.Equal(out, src), len(src), len(out))
	std, err := hujson.Standardize(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("\n--- Standardize (comments become spaces) ---\n%s", std)
}

// walk visits v, every member name, every member value, and every array element.
// Note: hujson.Value.All/Range do NOT yield object member names.
func walk(v *hujson.Value, fn func(*hujson.Value)) {
	fn(v)
	switch x := v.Value.(type) {
	case *hujson.Object:
		for i := range x.Members {
			walk(&x.Members[i].Name, fn)
			walk(&x.Members[i].Value, fn)
		}
	case *hujson.Array:
		for i := range x.Elements {
			walk(&x.Elements[i], fn)
		}
	}
}

// lineCol mirrors hujson's internal lineColumn: 1-based line, 1-based BYTE column.
func lineCol(src []byte, off int) (line, col int) {
	line = 1 + bytes.Count(src[:off], []byte("\n"))
	col = 1 + off - (bytes.LastIndexByte(src[:off], '\n') + 1)
	return line, col
}

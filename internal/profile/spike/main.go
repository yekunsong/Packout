// Command spike probes whether gopkg.in/yaml.v3 can back a profile parser
// that must preserve unknown fields, report node positions, and round-trip
// byte-for-byte. Run it with `go run . testdata/roundtrip.yaml`.
package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	path := "testdata/roundtrip.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	walk(&doc, func(n *yaml.Node) {
		if n.Line > 0 {
			fmt.Printf("line=%d col=%d kind=%d tag=%s value=%q\n", n.Line, n.Column, n.Kind, n.Tag, n.Value)
		}
	})
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // already the source's indent; give the encoder its best case
	if err := enc.Encode(&doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := enc.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := buf.Bytes()
	fmt.Printf("\nround-trip identical: %v (orig %d bytes, got %d)\n", bytes.Equal(out, src), len(src), len(out))
	fmt.Printf("--- re-encoded ---\n%s", out)
}

func walk(n *yaml.Node, fn func(*yaml.Node)) {
	fn(n)
	for _, c := range n.Content {
		walk(c, fn)
	}
}

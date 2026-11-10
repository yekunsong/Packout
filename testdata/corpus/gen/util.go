package main

import (
	"path/filepath"
	"runtime"
	"strconv"
)

func itoa(i int) string { return strconv.Itoa(i) }

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}

// genDir is the directory holding this source file (stable under go run / go test).
func genDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

// corpusDir is testdata/corpus.
func corpusDir() string { return filepath.Join(genDir(), "..") }

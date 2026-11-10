//go:build !windows

package main

import "os"

func isReparse(info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }

// setSparse is only called on Windows; the Unix path uses os.Truncate.
func setSparse(string, int64) error { return nil }

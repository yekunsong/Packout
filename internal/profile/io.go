package profile

import (
	"io/fs"
	"os"
	"path/filepath"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func dirOf(path string) string { return filepath.Dir(path) }

func dirFS(dir string) fs.FS {
	if dir == "" {
		return nil
	}
	return os.DirFS(dir)
}

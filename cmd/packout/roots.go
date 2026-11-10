package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// writeRoots records each root instance's source path next to the manifest so
// that a later export can extract config files without the user retyping
// --root. It is deliberately not part of the manifest: the manifest stays
// machine-neutral, while this file is a local convenience.
func writeRoots(dir string, roots map[string]string) error {
	if len(roots) == 0 {
		return nil
	}
	names := make([]string, 0, len(roots))
	for name := range roots {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make(map[string]string, len(roots))
	for _, name := range names {
		out[name] = roots[name]
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	tmp := filepath.Join(dir, "roots.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "roots.json"))
}

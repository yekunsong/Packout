package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ctx is the builder handed to a case Build function. It records every path it
// creates so the finished tree can be compared against the declaration.
type Ctx struct {
	root string
	c    *Case
	exp  map[string]bool
}

func newCtx(root string, c *Case) *Ctx {
	x := &Ctx{root: root, c: c, exp: map[string]bool{}}
	for _, p := range c.Paths {
		x.exp[filepath.ToSlash(p)] = true
	}
	return x
}

// P maps a slash path below the case root to a host path.
func (x *Ctx) P(rel string) string {
	return filepath.Join(x.root, filepath.FromSlash(rel))
}

// Exp declares a path without creating it (used for dynamic names).
func (x *Ctx) Exp(rel string) { x.exp[filepath.ToSlash(rel)] = true }

func (x *Ctx) record(rel string) {
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	x.exp[rel] = true
	for {
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
		if parent == "." || parent == rel {
			return
		}
		rel = parent
		x.exp[rel] = true
	}
}

func (x *Ctx) Mkdir(rel string) error {
	x.record(rel)
	return os.MkdirAll(x.P(rel), 0o755)
}

func (x *Ctx) Write(rel, content string) error {
	return x.WriteBytes(rel, []byte(content))
}

func (x *Ctx) WriteBytes(rel string, content []byte) error {
	x.record(rel)
	if err := os.MkdirAll(filepath.Dir(x.P(rel)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(x.P(rel), content, 0o644)
}

func (x *Ctx) ensureHome() error {
	return x.Mkdir("home")
}

// abs returns the host-absolute path for rel.
func (x *Ctx) abs(rel string) string {
	// filepath.Abs would run GetFullPathName on Windows and eat trailing dots.
	return filepath.Join(x.root, filepath.FromSlash(rel))
}

// winLiteral prefixes an absolute path with the Win32 long-path marker.
func winLiteral(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	return `\\?\` + p
}

// runPS executes ../win/special.ps1 and maps its documented exit codes.
func runPS(action string, kv ...string) error {
	script, err := specialScript()
	if err != nil {
		return err
	}
	args := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", action}
	args = append(args, kv...)
	code, out, err := runPowerShell(args)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 2:
		return skipf("symlink_privilege")
	case 3:
		return skipf("attr_unsupported")
	case 4:
		return fmt.Errorf("win32 ate literal name: %s", out)
	}
	return fmt.Errorf("special.ps1 %s failed (exit %d): %s", action, code, out)
}

// walkFiles recursively stats everything below root without following links.
// It uses literal Win32 paths so trailing-dot/space and reserved names survive.
func walkFiles(root string, fn func(abs, rel string, info os.FileInfo) error) error {
	var rec func(abs, rel string) error
	rec = func(abs, rel string) error {
		entries, err := os.ReadDir(hostPath(abs))
		if err != nil {
			return err
		}
		for _, e := range entries {
			childAbs := filepath.Join(abs, e.Name())
			childRel := e.Name()
			if rel != "" {
				childRel = rel + "/" + e.Name()
			}
			info, err := os.Lstat(hostPath(childAbs))
			if err != nil {
				return err
			}
			if err := fn(childAbs, childRel, info); err != nil {
				return err
			}
			if info.IsDir() && !isReparse(info) {
				if err := rec(childAbs, childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return rec(root, "")
}

// freezeTimes stamps every regular file and directory with fixedMoment,
// deepest first so directory mtimes survive.
func freezeTimes(root string) error {
	var dirs, files []string
	if err := walkFiles(root, func(abs, rel string, info os.FileInfo) error {
		if isReparse(info) {
			return nil
		}
		if info.IsDir() {
			dirs = append(dirs, abs)
		} else {
			files = append(files, abs)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, p := range append(files, dirs...) {
		if err := os.Chtimes(hostPath(p), fixedTime, fixedTime); err != nil {
			return fmt.Errorf("chtimes %s: %w", p, err)
		}
	}
	return os.Chtimes(hostPath(root), fixedTime, fixedTime)
}

// snapshot describes one entry of a case tree without following links.
type snapshot struct {
	rel    string
	isDir  bool
	isLink bool
	size   int64
}

func walkTree(root string) ([]snapshot, error) {
	var out []snapshot
	err := walkFiles(root, func(abs, rel string, info os.FileInfo) error {
		out = append(out, snapshot{rel: rel, isDir: info.IsDir(), isLink: isReparse(info), size: info.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, err
}

// checkTree asserts the built tree is exactly what the case declared.
func checkTree(root string, expected map[string]bool) error {
	got, err := walkTree(root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s.rel] = true
		if !expected[s.rel] {
			return fmt.Errorf("undeclared path created: %s", s.rel)
		}
	}
	var missing []string
	for rel := range expected {
		if !seen[rel] {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("declared path not created: %s", strings.Join(missing, ", "))
	}
	return nil
}

// hashFile hashes the head and tail of large files, the whole file otherwise.
func hashFile(p string, size int64) (string, error) {
	f, err := os.Open(hostPath(p))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := newHash()
	const window = 64 << 10
	if size <= 2*window {
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
	} else {
		head := make([]byte, window)
		if _, err := io.ReadFull(f, head); err != nil {
			return "", err
		}
		h.Write(head)
		if _, err := f.Seek(size-window, io.SeekStart); err != nil {
			return "", err
		}
		tail := make([]byte, window)
		if _, err := io.ReadFull(f, tail); err != nil {
			return "", err
		}
		h.Write(tail)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// linkDir creates a directory link: junction on Windows (SPEC §9.2), symlink
// elsewhere so cross-platform cases still materialise.
func (x *Ctx) linkDir(rel, target string) error {
	x.record(rel)
	abs := x.abs(rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return runPS("junction", "-Path", abs, "-Target", target)
	}
	return os.Symlink(target, abs)
}

// symlinkAny creates a real symbolic link; on Windows it is the case-sensitive
// kind that may need developer mode (mapped to skip symlink_privilege).
func (x *Ctx) symlinkAny(rel, target string, dir bool) error {
	x.record(rel)
	abs := x.abs(rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		action := "symlink-file"
		if dir {
			action = "symlink-dir"
		}
		return runPS(action, "-Path", abs, "-Target", target)
	}
	return os.Symlink(target, abs)
}

func (x *Ctx) hardlink(rel, existingRel string) error {
	x.record(rel)
	abs := x.abs(rel)
	src := x.abs(existingRel)
	return os.Link(src, abs)
}

// sparse creates a genuinely sparse file of size bytes.
func (x *Ctx) sparse(rel string, size int64) error {
	x.record(rel)
	abs := x.abs(rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return setSparse(abs, size)
	}
	f, err := os.Create(abs)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Truncate(abs, size)
}

func (x *Ctx) literalFile(rel string, content []byte, expectSuffix string) error {
	x.record(rel)
	abs := x.abs(rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(hostPath(abs), content, 0o644); err != nil {
		return err
	}
	if expectSuffix == "" {
		return nil
	}
	// Verify through the directory, not through path parsing: this is where a
	// trailing dot/space or reserved name would have been eaten.
	entries, err := os.ReadDir(hostPath(filepath.Dir(abs)))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == expectSuffix {
			return nil
		}
	}
	return fmt.Errorf("win32 ate literal name %q in %s", expectSuffix, filepath.Dir(abs))
}

func (x *Ctx) mkdirLong(rel string) error {
	x.record(rel)
	abs := x.abs(rel)
	return os.MkdirAll(hostPath(abs), 0o755)
}

func (x *Ctx) readonly(rel string) error {
	abs := x.abs(rel)
	return os.Chmod(abs, 0o444)
}

func (x *Ctx) recallAttrs(rel string) error {
	return runPS("recall", "-Path", x.abs(rel))
}

func (x *Ctx) ads(rel, stream, value string) error {
	return runPS("ads", "-Path", x.abs(rel), "-Name", stream, "-Value", value)
}

func (x *Ctx) caseSensitive(rel string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return runPS("case-sensitive", "-Path", x.abs(rel))
}

// bestEffortShortName sets an 8.3 alias; failures are not fatal.
func (x *Ctx) bestEffortShortName(rel, name string) {
	if runtime.GOOS != "windows" {
		return
	}
	_ = runPS("shortname", "-Path", winLiteral(x.abs(rel)), "-Name", name)
}

// requireSQLite skips when the sqlite3 CLI is absent.
func requireSQLite() error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return skipf("no_sqlite3")
	}
	return nil
}

// hostPath returns a path the Win32 layer resolves literally. Trailing dots and
// spaces (C06), reserved names (C25) and deep paths (C23) only survive with the
// \?\ marker; elsewhere the path is returned unchanged.
func hostPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if !filepath.IsAbs(p) {
		a, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		p = a
	}
	return `\\?\` + p
}

func b64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		out.WriteByte(alphabet[n>>18&0x3f])
		out.WriteByte(alphabet[n>>12&0x3f])
		if rem > 1 {
			out.WriteByte(alphabet[n>>6&0x3f])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(alphabet[n&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

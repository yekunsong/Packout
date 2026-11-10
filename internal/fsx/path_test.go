//go:build unix

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsEmpty(t *testing.T) {
	_, err := Abs("")
	if err == nil {
		t.Fatal("Abs(\"\") = nil error")
	}
	if !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("error = %v, want ErrEmptyPath", err)
	}
	var pe *PathError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %T, want *PathError", err)
	}
	if pe.Op != "Abs" {
		t.Fatalf("op = %q, want Abs", pe.Op)
	}
}

func TestAbsCleans(t *testing.T) {
	wd := t.TempDir()
	got, err := Abs(filepath.Join(wd, "a", "..", "b"))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	want := filepath.Join(wd, "b")
	if got != want {
		t.Fatalf("Abs = %q, want %q", got, want)
	}
}

func TestAbsRelative(t *testing.T) {
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Abs("x/./y")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if want := filepath.Join(wd, "x", "y"); got != want {
		t.Fatalf("Abs = %q, want %q", got, want)
	}
}

func TestNormKeyFold(t *testing.T) {
	cases := []struct{ a, b string }{
		{"Straße", "STRASSE"},
		{"STRASSE", "strasse"},
		{"ΟΣ", "οσ"}, // Greek final sigma folds to sigma
		{"ΟΣ", "Ος"},
		{"/Data/APP", "/data/app"},
	}
	for _, c := range cases {
		if ga, gb := NormKey(c.a), NormKey(c.b); ga != gb {
			t.Errorf("NormKey(%q)=%q != NormKey(%q)=%q", c.a, ga, c.b, gb)
		}
	}
}

func TestNormKeyNFC(t *testing.T) {
	nfc := "café"
	nfd := "café"
	if NormKey(nfc) != NormKey(nfd) {
		t.Fatalf("NFC and NFD spellings differ: %q vs %q", NormKey(nfc), NormKey(nfd))
	}
}

func TestNormKeyAlwaysSlash(t *testing.T) {
	// Comparison keys use "/" on every platform, so a key from a Windows
	// spelling matches one composed elsewhere (D-034). Paths, not keys, keep
	// the native spelling.
	if got, want := NormKey(`C:\Users\A`), "c:/users/a"; got != want {
		t.Fatalf("NormKey = %q, want %q", got, want)
	}
	if got, want := NormKey(`\\srv\share\Dir`), "//srv/share/dir"; got != want {
		t.Fatalf("NormKey UNC = %q, want %q", got, want)
	}
}

func TestNormKeyPure(t *testing.T) {
	// NormKey is not Abs: it does not clean, so the caller must choose.
	if got := NormKey("/A/./b/"); got != "/a/./b/" {
		t.Fatalf("NormKey = %q, want /a/./b/", got)
	}
	if got := NormKey(""); got != "" {
		t.Fatalf("NormKey(\"\") = %q, want empty", got)
	}
}

func TestWithinSegments(t *testing.T) {
	cases := []struct {
		root, p string
		want    bool
	}{
		{"/data/app", "/data/app", true},
		{"/data/app", "/data/app/x", true},
		{"/data/app", "/data/app/x/y", true},
		{"/data/app/", "/data/app/x", true},
		{"/data/app", "/data/app/../app/x", true},
		{"/data/app", "/data/application", false},
		{"/data/app", "/data/app2", false},
		{"/data/app", "/data", false},
		{"/data/app", "/data/app-evil/x", false},
		{"/", "/", true},
		{"/", "/anything/at/all", true},
		{"/data", "/", false},
		{"/data", "", false},
		{"", "/data", false},
	}
	for _, c := range cases {
		if got := Within(c.root, c.p); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
}

func TestWithinSegmentsAreNotPrefixes(t *testing.T) {
	// INV-R02: a bare strings.HasPrefix would wrongly accept both.
	for _, p := range []string{"/home/u/proj-evil", "/home/u/proj2"} {
		if Within("/home/u/proj", p) {
			t.Errorf("Within wrongly accepted %q", p)
		}
	}
}

func TestSegments(t *testing.T) {
	cases := []struct {
		p    string
		want []string
	}{
		{"/", []string{"/"}},
		{"/a/b", []string{"/", "a", "b"}},
		{"/a//b/", []string{"/", "a", "b"}},
		{"a/b", []string{"a", "b"}},
		{"/a/./b", []string{"/", "a", "b"}},
		{"/a/../b", []string{"/", "b"}},
		{"", nil},
	}
	for _, c := range cases {
		got := Segments(c.p)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("Segments(%q) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestRel(t *testing.T) {
	cases := []struct {
		root, p, want string
	}{
		{"/a", "/a/b", "b"},
		{"/a/b", "/a", ".."},
		{"/a", "/a", "."},
		{"/a/b", "/a/c/d", "../c/d"},
	}
	for _, c := range cases {
		got, err := Rel(c.root, c.p)
		if err != nil {
			t.Errorf("Rel(%q,%q): %v", c.root, c.p, err)
			continue
		}
		if got != c.want {
			t.Errorf("Rel(%q,%q) = %q, want %q", c.root, c.p, got, c.want)
		}
	}
}

func TestRelRequiresAbs(t *testing.T) {
	if _, err := Rel("a", "/a"); !errors.Is(err, ErrNotAbs) {
		t.Fatalf("Rel relative root error = %v, want ErrNotAbs", err)
	}
	if _, err := Rel("/a", "b"); !errors.Is(err, ErrNotAbs) {
		t.Fatalf("Rel relative p error = %v, want ErrNotAbs", err)
	}
}

func TestIsRootish(t *testing.T) {
	cases := map[string]bool{
		"/":             true,
		"/home":         true,
		"/home/alice":   true,
		"/home/alice/x": false,
		"/var":          true,
		"/var/log":      false,
		"/data":         true,
		"/data/x":       false,
		"":              false,
	}
	for p, want := range cases {
		if got := IsRootish(p); got != want {
			t.Errorf("IsRootish(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestLstatDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	content := strings.Repeat("x", 5000)
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("target.txt", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	info, err := Lstat(link)
	if err != nil {
		t.Fatalf("Lstat(link): %v", err)
	}
	if !info.IsLink || !info.IsReparse {
		t.Fatalf("IsLink=%v IsReparse=%v, want both true", info.IsLink, info.IsReparse)
	}
	if info.IsDir {
		t.Fatal("IsDir = true, want false")
	}
	if info.LinkTarget != "target.txt" {
		t.Fatalf("LinkTarget = %q, want target.txt", info.LinkTarget)
	}
	if info.Size == int64(len(content)) {
		t.Fatalf("Size = %d equals target size; Lstat followed the link", info.Size)
	}
	if info.Mode&fs.ModeSymlink == 0 {
		t.Fatalf("Mode = %v, want ModeSymlink", info.Mode)
	}

	ti, err := Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if ti.IsLink {
		t.Fatal("regular target marked as link")
	}
}

func TestLstatAllocRegular(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(p, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Lstat(p)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Size != 8192 {
		t.Fatalf("Size = %d, want 8192", info.Size)
	}
	if info.Alloc <= 0 {
		t.Fatalf("Alloc = %d, want > 0", info.Alloc)
	}
	if info.FileID == "" {
		t.Fatal("FileID is empty")
	}
	if info.IsSparse {
		t.Fatalf("IsSparse = true for dense file (Alloc=%d Size=%d)", info.Alloc, info.Size)
	}
}

func TestLstatSparse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sparse.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 20); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsSparse {
		t.Fatalf("IsSparse = false for sparse file (Alloc=%d Size=%d)", info.Alloc, info.Size)
	}
	if info.Alloc >= info.Size {
		t.Fatalf("Alloc=%d >= Size=%d for sparse file", info.Alloc, info.Size)
	}
}

func TestLstatMissing(t *testing.T) {
	_, err := Lstat(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want fs.ErrNotExist", err)
	}
	var pe *PathError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %T, want *PathError", err)
	}
}

func TestLstatOpenEmpty(t *testing.T) {
	if _, err := Lstat(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Lstat(\"\") error = %v, want ErrEmptyPath", err)
	}
	if _, err := Open(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Open(\"\") error = %v, want ErrEmptyPath", err)
	}
}

func TestOpenFollowsAndFstatMatches(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	f, err := Open(link)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	fi, err := Fstat(f)
	if err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	li, err := Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size != 5 || fi.FileID != li.FileID {
		t.Fatalf("Fstat size=%d id=%q, want size=5 id=%q", fi.Size, fi.FileID, li.FileID)
	}
	if fi.IsLink {
		t.Fatal("Fstat of open target reports a link")
	}
}

func TestPathErrorFormatting(t *testing.T) {
	err := &PathError{Op: "Lstat", Path: "/x", Err: ErrEmptyPath}
	if !strings.Contains(err.Error(), "Lstat") || !strings.Contains(err.Error(), "/x") {
		t.Fatalf("Error() = %q, missing op or path", err.Error())
	}
	var nilErr *PathError
	if nilErr.Error() != "<nil>" {
		t.Fatalf("nil PathError = %q", nilErr.Error())
	}
}

//go:build windows

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormKeyWindowsSeparators(t *testing.T) {
	if NormKey(`C:/Users/Alice`) != NormKey(`c:\users\alice`) {
		t.Fatalf("separator/case normalization failed: %q vs %q",
			NormKey(`C:/Users/Alice`), NormKey(`c:\users\alice`))
	}
	if got, want := NormKey(`C:\Straße`), NormKey(`C:\STRASSE`); got != want {
		t.Fatalf("fold failed: %q vs %q", got, want)
	}
	// Keys always use "/", never the platform separator (D-034).
	if got, want := NormKey(`C:\a\b`), "c:/a/b"; got != want {
		t.Fatalf("NormKey key separator = %q, want %q", got, want)
	}
	if got, want := NormKey(`\\srv\share\Dir`), "//srv/share/dir"; got != want {
		t.Fatalf("NormKey UNC key = %q, want %q", got, want)
	}
}

func TestWithinWindows(t *testing.T) {
	cases := []struct {
		root, p string
		want    bool
	}{
		{`C:\Users\a`, `C:\Users\a`, true},
		{`C:\Users\a`, `C:\Users\a\Documents`, true},
		{`C:\Users\a`, `c:\users\A\documents`, true},
		{`C:\Users\a`, `C:\Users\ab`, false},
		{`C:\Users\a`, `C:\Users\a-evil`, false},
		{`C:\Users\a`, `C:\Users`, false},
		{`C:\`, `C:\anything`, true},
		{`C:\`, `D:\anything`, false},
		{`\\srv\share`, `\\srv\share`, true},
		{`\\srv\share`, `\\srv\share\dir`, true},
		{`\\srv\share\`, `\\srv\share\dir`, true},
		{`\\srv\share`, `\\srv\share-evil\dir`, false},
		{`\\srv\share`, `\\srv\share2`, false},
		{`\\srv\share2`, `\\srv\share\dir`, false},
		{`\\?\UNC\srv\share`, `\\?\UNC\srv\share\dir`, true},
		{`\\?\UNC\srv\share`, `\\?\UNC\srv\share2\dir`, false},
		{`\\?\C:\Users\a`, `\\?\C:\Users\a\Documents`, true},
		{`\\?\C:\Users\a`, `\\?\C:\Users\ab`, false},
		{`C:\Users\a`, `C:\Users\a\..\a\x`, true},
	}
	for _, c := range cases {
		if got := Within(c.root, c.p); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
}

func TestIsRootishWindows(t *testing.T) {
	cases := map[string]bool{
		`C:\`:                    true,
		`c:/`:                    true,
		`C:\Users`:               true,
		`C:\Users\alice`:         true,
		`C:\Users\alice\Desktop`: false,
		`C:\Windows`:             true,
		`C:\Windows\System32`:    false,
		`\\srv\share`:            true,
		`\\srv\share\`:           true,
		`\\srv\share\dir`:        false,
		`\\srv\share2`:           true,
		`\\?\UNC\srv\share`:      true,
		`\\?\UNC\srv\share\dir`:  false,
		`\\?\C:\Users\alice`:     true,
		`\\?\C:\Users\alice\x`:   false,
		`D:\`:                    true,
		`D:\data\x`:              false,
	}
	for p, want := range cases {
		if got := IsRootish(p); got != want {
			t.Errorf("IsRootish(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestSegmentsWindows(t *testing.T) {
	cases := []struct {
		p    string
		want []string
	}{
		{`C:\`, []string{`C:\`}},
		{`C:\a\b`, []string{`C:\`, "a", "b"}},
		{`C:/a//b/`, []string{`C:\`, "a", "b"}},
		{`C:a`, []string{"C:", "a"}},
		{`\\srv\share\dir`, []string{`\\srv\share\`, "dir"}},
	}
	for _, c := range cases {
		got := Segments(c.p)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("Segments(%q) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestClassifyAttributes(t *testing.T) {
	cases := []struct {
		name                                  string
		attrs, tag                            uint32
		isDir, isLink, isReparse, sparse, off bool
	}{
		{"plain", 0, 0, false, false, false, false, false},
		{"directory", attrDirectory, 0, true, false, false, false, false},
		{"symlink", attrReparsePoint, 0xA000000C, false, true, true, false, false},
		{"junction", attrReparsePoint | attrDirectory, 0xA0000003, true, false, true, false, false},
		{"sparse", attrSparseFile, 0, false, false, false, true, false},
		{"offline", attrOffline, 0, false, false, false, false, true},
		{"recall-on-open", attrRecallOnOpen, 0, false, false, false, false, true},
		{"recall-on-data-access", attrRecallOnDataAcce, 0, false, false, false, false, true},
		{"reparse-no-tag", attrReparsePoint, 0, false, false, true, false, false},
	}
	for _, c := range cases {
		d, l, r, s, o := classify(c.attrs, c.tag)
		if d != c.isDir || l != c.isLink || r != c.isReparse || s != c.sparse || o != c.off {
			t.Errorf("%s: got dir=%v link=%v reparse=%v sparse=%v offline=%v", c.name, d, l, r, s, o)
		}
	}
}

func TestPreparePath(t *testing.T) {
	got, err := preparePath(`C:\Users\a`)
	if err != nil {
		t.Fatal(err)
	}
	// The verbatim prefix is always added (D-034): it is what keeps trailing
	// dots and spaces from being stripped by Win32 path parsing.
	if got != `\\?\C:\Users\a` {
		t.Fatalf("short path = %q, want \\\\?\\C:\\Users\\a", got)
	}

	long := `C:\` + strings.Repeat("a", 300)
	got, err = preparePath(long)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, `\\?\C:\`) {
		t.Fatalf("long path = %q, want \\\\?\\ prefix", got)
	}

	unc := `\\server\share\` + strings.Repeat("a", 300)
	got, err = preparePath(unc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, `\\?\UNC\server\share\`) {
		t.Fatalf("long UNC = %q, want \\\\?\\UNC\\ prefix", got)
	}
}

func TestLstatWindows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Lstat(p)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.IsDir || info.IsLink || info.IsReparse {
		t.Fatalf("plain file flags dir=%v link=%v reparse=%v", info.IsDir, info.IsLink, info.IsReparse)
	}
	if info.Size != 11 {
		t.Fatalf("Size = %d, want 11", info.Size)
	}
	if info.FileID == "" {
		t.Fatal("FileID empty on Windows")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	li, err := Lstat(link)
	if err != nil {
		t.Fatalf("Lstat(link): %v", err)
	}
	if !li.IsLink || !li.IsReparse {
		t.Fatalf("link flags IsLink=%v IsReparse=%v", li.IsLink, li.IsReparse)
	}
	if li.LinkTarget == "" {
		t.Fatal("LinkTarget empty")
	}
}

func TestOpenShareDelete(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(p); err != nil {
		t.Fatalf("Remove while open: %v (FILE_SHARE_DELETE missing?)", err)
	}
}

func TestOpenWindowsFollowers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	f, err := Open(link)
	if err != nil {
		t.Fatalf("Open(link): %v", err)
	}
	defer f.Close()
	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	if string(buf[:n]) != "payload" {
		t.Fatalf("read %q, want payload", buf[:n])
	}
}

func TestLstatMissingWindows(t *testing.T) {
	_, err := Lstat(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want fs.ErrNotExist", err)
	}
}

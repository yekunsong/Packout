package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRelPathRejectsTraversalAndWindowsForms(t *testing.T) {
	bad := []string{
		"",
		"../../etc/passwd",
		"../x",
		"a/../b",
		"a/./b",
		".",
		"..",
		"/etc/passwd",
		"//home/user/x",
		`\\server\share\x`,
		`\\?\C:\x`,
		`.\x`,
		`C:evil`,
		`C:\evil`,
		`c:/x`,
		"a/b:stream",
		"a:b",
		"dir/file.",
		"dir/file ",
		"dir/ ",
		"a//b",
		"a/",
		"CON",
		"con.txt",
		"dir/NUL",
		"dir/COM1.log",
		"dir/LPT9",
		"a/b\x01c",
		"a/b?c",
		"a/b*c",
		"a/b|c",
		"a/b<c",
		"a/b>c",
		"a/b\"c",
		strings.Repeat("a", 256),
	}
	for _, p := range bad {
		if err := ValidateRelPath(p); err == nil {
			t.Errorf("accepted %q", p)
		} else if !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%q: wrong sentinel %v", p, err)
		}
	}
	good := []string{
		"manifest/x.jsonl",
		"config/home/.claude/settings.json",
		"a-b_c.1",
		"dir.with.dots/file",
		"x/y/z",
	}
	for _, p := range good {
		if err := ValidateRelPath(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
}

func TestValidateLinkTarget(t *testing.T) {
	bad := []struct{ entry, target string }{
		{"a/link", "/etc/passwd"},
		{"a/link", "../../outside"},
		{"link", "../x"},
		{"a/link", `C:\Windows`},
		{`a/link`, `\\host\share`},
		{"a/link", ""},
		{"a/link", "b\x00c"},
		{"a/link", "file."},
	}
	for _, c := range bad {
		if err := ValidateLinkTarget(c.entry, c.target); err == nil {
			t.Errorf("accepted %q -> %q", c.entry, c.target)
		}
	}
	good := []struct{ entry, target string }{
		{"a/link", "b"},
		{"a/link", "../b"},
		{"a/link", "../outside"},
		{"a/b/link", "../../outside"},
		{"a/b/link", "../../c"},
		{"a/link", "./b"},
		{"a/link", "sub/b"},
	}
	for _, c := range good {
		if err := ValidateLinkTarget(c.entry, c.target); err != nil {
			t.Errorf("rejected %q -> %q: %v", c.entry, c.target, err)
		}
	}
}

// rewriteSIG loads the package SIG, applies fn, and writes it back without
// recomputing the tree hash (structural path checks run before the hash).
func rewriteSIG(t *testing.T, dir string, fn func(*SIG)) {
	t.Helper()
	p := filepath.Join(dir, SIGName)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var sig SIG
	if err := json.Unmarshal(data, &sig); err != nil {
		t.Fatal(err)
	}
	fn(&sig)
	enc, err := json.Marshal(&sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, enc, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMaliciousEntryNamesRejected(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"C:evil",
		`\\host\share\x`,
		`\\?\C:\x`,
		"a/file:stream",
		"a/file.",
		"CON",
		"/etc/passwd",
	}
	src, _ := scanFixture(t)
	for _, evil := range cases {
		t.Run(fmt.Sprintf("%q", evil), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "pkg")
			mustExport(t, Config{SourceDir: src, OutDir: out})
			rewriteSIG(t, out, func(s *SIG) {
				s.Entries[0].Path = evil
				// Keep the entry set valid for the structural path check:
				// drop the original first entry so there is no duplicate.
				s.Entries = s.Entries[:1]
				s.EntryCount = 1
			})
			v, err := Verify(out)
			if err == nil {
				t.Fatalf("accepted %q", evil)
			}
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("%q: want ErrInvalidPath, got %v", evil, err)
			}
			if v.Conclusion != ConclusionFailed {
				t.Fatalf("conclusion %q", v.Conclusion)
			}
			// A fresh package still verifies: verify never writes.
			fresh := filepath.Join(t.TempDir(), "fresh")
			mustExport(t, Config{SourceDir: src, OutDir: fresh})
			mustVerify(t, fresh)
		})
	}
}

func TestSymlinkEscapeRejectedAtVerify(t *testing.T) {
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "a"), "a")
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})

	link := filepath.Join(out, ConfigDirName, "home", "link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatal(err)
	}
	rewriteSIG(t, out, func(s *SIG) {
		for i := range s.Entries {
			if s.Entries[i].Path == "config/home/link" {
				target := "/etc/passwd"
				s.Entries[i].LinkTarget = &target
			}
		}
	})
	if _, err := Verify(out); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("absolute symlink accepted: %v", err)
	}
}

func TestSymlinkInsideAndHardlink(t *testing.T) {
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "real.txt"), "same bytes")
	if err := os.Symlink("real.txt", filepath.Join(src, ConfigDirName, "home", "link.txt")); err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatal(err)
	}
	// The source tree copy records the symlink; the link target stays inside.
	if err := os.Link(filepath.Join(src, ConfigDirName, "home", "real.txt"),
		filepath.Join(src, ConfigDirName, "home", "hard.txt")); err != nil {
		t.Skipf("hardlinks unsupported: %v", err)
	}
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})

	sig, err := ReadSIG(out)
	if err != nil {
		t.Fatal(err)
	}
	var sawLink bool
	var hard *SIGEntry
	for i := range sig.Entries {
		e := &sig.Entries[i]
		switch e.Type {
		case TypeSymlink:
			if e.Path == "config/home/link.txt" && e.LinkTarget != nil && *e.LinkTarget == "real.txt" {
				sawLink = true
			}
		case TypeHardlink:
			hard = e
		}
	}
	if !sawLink || hard == nil {
		t.Fatalf("links not modelled explicitly: link=%v hard=%v", sawLink, hard)
	}
	mustVerify(t, out)

	// Break the hardlink: verify must notice the type change.
	hp := filepath.Join(out, filepath.FromSlash(hard.Path))
	if err := os.Remove(hp); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hp, "same bytes")
	if _, err := Verify(out); !errors.Is(err, ErrTampered) {
		t.Fatalf("broken hardlink accepted: %v", err)
	}
}

func TestDuplicateSIGEntriesRejected(t *testing.T) {
	src, _ := scanFixture(t)
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})
	rewriteSIG(t, out, func(s *SIG) {
		s.Entries = append(s.Entries, s.Entries[0])
		s.EntryCount = len(s.Entries)
	})
	if _, err := Verify(out); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("duplicate accepted: %v", err)
	}
}

func TestUnsignedIsNotOk(t *testing.T) {
	src, _ := scanFixture(t)
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})
	if err := os.Remove(filepath.Join(out, SIGName)); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Conclusion != ConclusionUnsigned {
		t.Fatalf("conclusion %q", v.Conclusion)
	}
	if v.Conclusion == "ok" || v.Conclusion == ConclusionHashOKUnverified {
		t.Fatal("unsigned must not claim hash coverage")
	}
}

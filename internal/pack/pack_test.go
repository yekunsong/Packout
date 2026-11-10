package pack

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExportVerifyRoundTrip(t *testing.T) {
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "settings.json"), `{"theme":"dark"}`)
	writeFile(t, filepath.Join(src, ReinstallDirName, "install.txt"), "reinstall here\n")
	writeFile(t, filepath.Join(src, ReportName), "<html>report</html>")
	out := filepath.Join(t.TempDir(), "pkg")

	res := mustExport(t, Config{SourceDir: src, OutDir: out})
	if res.TreeSHA256 == "" || res.Entries == 0 || res.Signed || res.Method != MethodSHA256Tree {
		t.Fatalf("unexpected result: %+v", res)
	}
	for _, want := range []string{ManifestDirName, ConfigDirName, ReinstallDirName, ReportName, SIGName} {
		if _, err := os.Lstat(filepath.Join(out, want)); err != nil {
			t.Fatalf("missing package entry %s: %v", want, err)
		}
	}

	v := mustVerify(t, out)
	if v.Conclusion != ConclusionHashOKUnverified {
		t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionHashOKUnverified)
	}
	if v.Conclusion == "ok" {
		t.Fatal("P0 must not conclude plain ok")
	}
	if !v.ManifestValid || v.Signed || v.TreeSHA256 != res.TreeSHA256 {
		t.Fatalf("unexpected verdict: %+v", v)
	}

	// The SIG must carry no machine metadata: relative paths only, and none of
	// the source's absolute root may leak.
	data, err := os.ReadFile(filepath.Join(out, SIGName))
	if err != nil {
		t.Fatal(err)
	}
	var sig SIG
	if err := json.Unmarshal(data, &sig); err != nil {
		t.Fatal(err)
	}
	if sig.Signed || sig.Format != PackageFormat || sig.Method != MethodSHA256Tree {
		t.Fatalf("bad SIG header: %+v", sig)
	}
	for _, e := range sig.Entries {
		if filepath.IsAbs(e.Path) || strings.HasPrefix(e.Path, "/") {
			t.Fatalf("absolute entry path %q", e.Path)
		}
	}
	if strings.Contains(string(data), filepath.ToSlash(src)) {
		t.Fatal("SIG leaked the scan source path")
	}
	if home, _ := os.UserHomeDir(); home != "" && strings.Contains(string(data), home) {
		t.Fatal("SIG leaked the home directory")
	}
}

func TestTamperedContentFailsAndNamesEntry(t *testing.T) {
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "settings.json"), `{"a":1}`)
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})

	target := filepath.Join(out, ConfigDirName, "home", "settings.json")
	if err := os.WriteFile(target, []byte(`{"a":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(out)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
	if v.Conclusion != ConclusionFailed {
		t.Fatalf("conclusion = %q", v.Conclusion)
	}
	found := false
	for _, p := range v.Problems {
		if p.Path == "config/home/settings.json" && p.Code == "sig-hash-mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entry not identified: %+v", v.Problems)
	}
}

func TestTamperSixWays(t *testing.T) {
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "a.txt"), "alpha")
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "b.txt"), "bravo")
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})

	t.Run("extra entry", func(t *testing.T) {
		cp := copyDir(t, out)
		writeFile(t, filepath.Join(cp, ConfigDirName, "home", "evil.txt"), "x")
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("extra entry accepted: %v", err)
		}
	})
	t.Run("removed entry", func(t *testing.T) {
		cp := copyDir(t, out)
		if err := os.Remove(filepath.Join(cp, ConfigDirName, "home", "a.txt")); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("missing entry accepted: %v", err)
		}
	})
	t.Run("mode", func(t *testing.T) {
		cp := copyDir(t, out)
		mode := fs.FileMode(0o600)
		if runtime.GOOS == "windows" {
			// Windows file modes only carry the read-only bit, so 0644 -> 0600
			// is invisible; clear write permission to observe a mode change.
			mode = 0o444
		}
		if err := os.Chmod(filepath.Join(cp, ConfigDirName, "home", "a.txt"), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("mode change accepted: %v", err)
		}
	})
	t.Run("renamed entry", func(t *testing.T) {
		cp := copyDir(t, out)
		if err := os.Rename(filepath.Join(cp, ConfigDirName, "home", "a.txt"), filepath.Join(cp, ConfigDirName, "home", "z.txt")); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("rename accepted: %v", err)
		}
	})
	t.Run("symlink swap", func(t *testing.T) {
		cp := copyDir(t, out)
		p := filepath.Join(cp, ConfigDirName, "home", "a.txt")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("b.txt", p); err != nil {
			if symlinkNeedsPrivilege(err) {
				t.Skipf("symlink needs privilege: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("type swap accepted: %v", err)
		}
	})
	t.Run("tree hash only", func(t *testing.T) {
		cp := copyDir(t, out)
		sigPath := filepath.Join(cp, SIGName)
		data, err := os.ReadFile(sigPath)
		if err != nil {
			t.Fatal(err)
		}
		var sig SIG
		if err := json.Unmarshal(data, &sig); err != nil {
			t.Fatal(err)
		}
		sig.TreeSHA256 = strings.Repeat("0", 64)
		enc, _ := json.Marshal(&sig)
		if err := os.WriteFile(sigPath, enc, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(cp); !errors.Is(err, ErrTampered) {
			t.Fatalf("tree hash change accepted: %v", err)
		}
	})
}

func TestEmptyAndUnsignedConclusion(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		v, err := Verify(dir)
		if !errors.Is(err, ErrEmptyPackage) || v.Conclusion != ConclusionEmpty {
			t.Fatalf("v=%+v err=%v", v, err)
		}
	})
	t.Run("manifest only is unsigned", func(t *testing.T) {
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
		if v.Conclusion != ConclusionUnsigned || !v.ManifestValid {
			t.Fatalf("v=%+v", v)
		}
	})
}

func TestDestNotEmptyNeedsForceAndDiffsFirst(t *testing.T) {
	src, _ := scanFixture(t)
	out := filepath.Join(t.TempDir(), "pkg")
	writeFile(t, filepath.Join(out, ManifestDirName, "stale.jsonl"), "old")

	res, err := Export(Config{SourceDir: src, OutDir: out})
	if !errors.Is(err, ErrDestNotEmpty) {
		t.Fatalf("want ErrDestNotEmpty, got %v", err)
	}
	if res == nil || res.Diff == nil || len(res.Diff.Removed) == 0 {
		t.Fatalf("diff not reported: %+v", res)
	}
	// Nothing was written.
	if _, err := os.Lstat(filepath.Join(out, SIGName)); err == nil {
		t.Fatal("SIG written despite refusing")
	}
	if data, _ := os.ReadFile(filepath.Join(out, ManifestDirName, "stale.jsonl")); string(data) != "old" {
		t.Fatal("existing file changed before force")
	}

	if _, err := Export(Config{SourceDir: src, OutDir: out, Force: true}); err != nil {
		t.Fatalf("force: %v", err)
	}
	if v := mustVerify(t, out); v.Conclusion != ConclusionHashOKUnverified {
		t.Fatalf("forced package does not verify: %+v", v)
	}
	if _, err := os.Lstat(filepath.Join(out, ManifestDirName, "stale.jsonl")); !os.IsNotExist(err) {
		t.Fatal("stale managed entry survived force")
	}
}

func TestLimitsAbortWithoutLanding(t *testing.T) {
	src, _ := scanFixture(t)
	for i := 0; i < 10; i++ {
		writeFile(t, filepath.Join(src, ConfigDirName, "home", "f"+string(rune('a'+i))), "x")
	}
	out := filepath.Join(t.TempDir(), "pkg")
	_, err := Export(Config{SourceDir: src, OutDir: out, Limits: Limits{MaxEntries: 5}})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want limit error, got %v", err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("destination exists after aborted export")
	}
	// Default limits accept the same package.
	mustExport(t, Config{SourceDir: src, OutDir: out})
}

func TestExpansionRatioLimit(t *testing.T) {
	src, _ := scanFixture(t)
	sparse := filepath.Join(src, ConfigDirName, "home", "sparse.bin")
	writeFile(t, sparse, "")
	f, err := os.OpenFile(sparse, os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8 << 20); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	out := filepath.Join(t.TempDir(), "pkg")
	_, err = Export(Config{SourceDir: src, OutDir: out, Limits: Limits{MaxExpansionRatio: 0.5}})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want ratio limit, got %v", err)
	}
}

func TestVerifyEntryLimit(t *testing.T) {
	src, _ := scanFixture(t)
	for i := 0; i < 6; i++ {
		writeFile(t, filepath.Join(src, ConfigDirName, "home", "f"+string(rune('a'+i))), "x")
	}
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})
	if _, err := VerifyWith(out, Limits{MaxEntries: 4}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("want limit error, got %v", err)
	}
	if _, err := Verify(out); err != nil {
		t.Fatal(err)
	}
}

func TestExportRejectsInvalidManifest(t *testing.T) {
	src, _ := scanFixture(t)
	// Remove the index so the manifest is incomplete.
	if err := os.Remove(filepath.Join(src, ManifestDirName, "manifest.index.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(Config{SourceDir: src, OutDir: filepath.Join(t.TempDir(), "p")}); err == nil {
		t.Fatal("invalid manifest accepted")
	}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy")
	if _, err := copyTree(src, dst, Limits{}); err != nil {
		t.Fatal(err)
	}
	// copyTree preserves the SIG; hardlinks in a tiny package are recreated
	// and content metadata matches, so the copy still verifies.
	return dst
}

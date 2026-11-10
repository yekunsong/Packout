//go:build windows

package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"packout/internal/manifest"
	"packout/internal/profile"
)

// winEnv builds a materialized fixture with one home root. It is standalone so
// the Linux test file (and its helpers) need not compile on Windows.
func winEnv(t *testing.T, entries string) (*env, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "home"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures", "home", ".keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `{"schema_version":"2.0","name":"test","title":"test profile","applies_to":{"os":["windows"]},
	  "roots":{"home":"/nonexistent-home","repo":"/nonexistent-repo"},
	  "entries":[` + entries + `],"selftest":{"clock":"2026-01-01T00:00:00Z",
	  "fixtures":{"home":"fixtures/home","repo":"fixtures/repo"},
	  "expect":[{"entry":"catch-home","root":"home","match":".keep"}],"budget":{"wall_ms":5000}}}`
	path := filepath.Join(dir, "profile.jsonc")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tree, err := profile.Materialize(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tree) })
	return &env{
		t: t, prof: p, tree: tree, out: filepath.Join(t.TempDir(), "out"),
		clock: fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}, tree
}

func TestWindowsJunctionLoop(t *testing.T) {
	e, tree := winEnv(t, `{"id":"cache","selftest_exempt":"x","kind":"dir","root":"home","path":".claude/cache","layer":"L0","secret":"none","extractor":"none","signals":[{"src":"observed_behavior","note":"cache"}]},
	  {"id":"catch-home","kind":"catch-all","root":"home","layer":"L2","secret":"none","extractor":"none","signals":[]}`)
	_ = tree
	dir := filepath.Join(e.tree, "home", ".claude", "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(dir, "loop"), dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v %s", err, out)
	}
	res, err := Run(context.Background(), e.cfg())
	if err != nil {
		t.Fatal(err)
	}
	units, err := manifest.Read(res.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, u := range units {
		if filepath.Base(u.Path) == "loop" {
			found++
			if !hasFlag(u, "junction") || u.LinkTarget == "" {
				t.Fatalf("junction flags/target = %v %q", u.RiskFlags, u.LinkTarget)
			}
		}
		if filepath.Base(u.Path) != "loop" && filepath.Base(filepath.Dir(u.Path)) == "loop" {
			t.Fatalf("descended into %s", u.Path)
		}
	}
	if found != 1 {
		t.Fatalf("loop units = %d", found)
	}
}

func TestWindowsPlaceholderNotHydrated(t *testing.T) {
	e, _ := winEnv(t, `{"id":"data","selftest_exempt":"x","kind":"file","root":"home","path":".claude/cloud.jsonl","layer":"L3","secret":"scan","extractor":"digest","signals":[{"src":"observed_behavior","note":"cloud"}]},
	  {"id":"catch-home","kind":"catch-all","root":"home","layer":"L2","secret":"none","extractor":"none","signals":[]}`)
	p := filepath.Join(e.tree, "home", ".claude", "cloud.jsonl")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(p))
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(windows.StringToUTF16Ptr(p), attrs|0x00001000); err != nil {
		t.Skipf("cannot set OFFLINE: %v", err)
	}
	res, err := Run(context.Background(), e.cfg())
	if err != nil {
		t.Fatal(err)
	}
	units, err := manifest.Read(res.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range units {
		if u.Entry != "data" {
			continue
		}
		if !hasFlag(u, "cloud_placeholder") || !hasFlag(u, "content_partial") {
			t.Fatalf("flags = %v", u.RiskFlags)
		}
		if u.Fingerprint.Value != nil || u.CID != nil {
			t.Fatal("placeholder fingerprint must be null")
		}
		return
	}
	t.Fatal("unit missing")
}

func TestWindowsOccupiedFile(t *testing.T) {
	e, _ := winEnv(t, `{"id":"data","selftest_exempt":"x","kind":"glob-group","root":"home","paths":[".claude/*.jsonl"],"layer":"L0","secret":"scan","extractor":"none","signals":[{"src":"observed_behavior","note":"data"}]},
	  {"id":"catch-home","kind":"catch-all","root":"home","layer":"L2","secret":"none","extractor":"none","signals":[]}`)
	dir := filepath.Join(e.tree, "home", ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(dir, "busy.jsonl")
	if err := os.WriteFile(occupied, []byte(`{"token":"sk-ant-abcdef"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.jsonl"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(occupied)
	h, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Skipf("exclusive open failed: %v", err)
	}
	defer windows.CloseHandle(h)
	res, err := Run(context.Background(), e.cfg())
	if err != nil {
		t.Fatal(err)
	}
	units, err := manifest.Read(res.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, u := range units {
		if filepath.Base(u.Path) == "busy.jsonl" {
			bad++
			if !hasFlag(u, "read_error") || u.Fingerprint.Value != nil {
				t.Fatalf("occupied unit = %+v", u)
			}
		}
	}
	if bad != 1 || res.ReadErrors == 0 {
		t.Fatalf("bad=%d readErrors=%d", bad, res.ReadErrors)
	}
}

var _ = runtime.GOOS

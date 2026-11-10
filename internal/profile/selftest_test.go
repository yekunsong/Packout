package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeProfileFile(t *testing.T, dir string, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.jsonc")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMaterialize(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixtures", "home")
	if err := os.MkdirAll(filepath.Join(fixture, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "hello.txt"), []byte("hello fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "sub", "nested.txt"), []byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := baseProfileMap()
	st := selftestOf(m)
	st["files"] = []any{map[string]any{"path": "home/gen.bin", "size": 48}}
	st["dirs"] = []any{"home/empty"}
	st["symlinks"] = []any{map[string]any{"path": "home/link", "target": "hello.txt"}}
	st["expect"] = []any{map[string]any{"entry": "a", "root": "home", "match": "hello.txt"}}

	path := writeProfileFile(t, dir, m)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	work, err := Materialize(p)
	if err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("Materialize needs symlink privilege: %v", err)
		}
		t.Fatalf("Materialize: %v", err)
	}
	defer os.RemoveAll(work)

	if data, err := os.ReadFile(filepath.Join(work, "home", "hello.txt")); err != nil || string(data) != "hello fixture\n" {
		t.Fatalf("fixture copy: %q, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(work, "home", "sub", "nested.txt")); err != nil || string(data) != "nested\n" {
		t.Fatalf("nested fixture copy: %q, %v", data, err)
	}
	info, err := os.Stat(filepath.Join(work, "home", "gen.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 48 {
		t.Fatalf("generated file size = %d, want 48", info.Size())
	}
	if info, err := os.Stat(filepath.Join(work, "home", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty dir: %v %v", info, err)
	}
	li, err := os.Lstat(filepath.Join(work, "home", "link"))
	if err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link is not a symlink: %v", li.Mode())
	}
	if target, err := os.Readlink(filepath.Join(work, "home", "link")); err != nil || target != "hello.txt" {
		t.Fatalf("readlink = %q, %v", target, err)
	}
	want, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if hi, err := os.Stat(filepath.Join(work, "home", "hello.txt")); err != nil {
		t.Fatal(err)
	} else if !hi.ModTime().Equal(want) {
		t.Fatalf("mtime = %v, want %v", hi.ModTime(), want)
	}
}

func TestRunSelfTestDetectsFailures(t *testing.T) {
	t.Run("wrong_layer", func(t *testing.T) {
		dir := t.TempDir()
		mkHome(t, dir, map[string]string{"a": "{}\n"})
		m := baseProfileMap()
		selftestOf(m)["expect"].([]any)[0].(map[string]any)["layer"] = "L9"
		p, err := Load(writeProfileFile(t, dir, m))
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunSelfTest(p, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			t.Fatal("expected failure")
		}
		if !strings.Contains(res.Failures[0].Message, "layer") {
			t.Fatalf("unexpected failure: %v", res.Failures[0])
		}
	})

	t.Run("expect_absent_violation", func(t *testing.T) {
		dir := t.TempDir()
		mkHome(t, dir, map[string]string{"a": "x\n"})
		m := baseProfileMap()
		selftestOf(m)["expect_absent"] = []any{map[string]any{"root": "home", "match": "a"}}
		p, err := Load(writeProfileFile(t, dir, m))
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunSelfTest(p, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			t.Fatal("expected expect_absent failure")
		}
	})

	t.Run("default_exclude_satisfies_absent", func(t *testing.T) {
		dir := t.TempDir()
		mkHome(t, dir, map[string]string{".git": "gitdir: /tmp/x\n", "a": "x\n"})
		m := baseProfileMap()
		selftestOf(m)["expect_absent"] = []any{map[string]any{"root": "home", "match": "**/.git"}}
		p, err := Load(writeProfileFile(t, dir, m))
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunSelfTest(p, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if !res.Passed {
			for _, f := range res.Failures {
				t.Errorf("%v", f)
			}
			t.Fatal("excluded .git must not be a Unit")
		}
	})

	t.Run("part_selector_missing", func(t *testing.T) {
		dir := t.TempDir()
		mkHome(t, dir, map[string]string{"a": "{}\n"})
		m := baseProfileMap()
		e := entryOf(m)
		delete(e, "selftest_exempt")
		e["parts"] = []any{map[string]any{
			"id": "p", "selector": map[string]any{"json_pointer": "/missing"},
		}}
		selftestOf(m)["expect"] = []any{map[string]any{
			"entry": "a", "part": "p", "root": "home", "match": "a",
		}}
		p, err := Load(writeProfileFile(t, dir, m))
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunSelfTest(p, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			t.Fatal("expected part selector failure")
		}
	})
}

func TestRunSelfTestPartSelectors(t *testing.T) {
	dir := t.TempDir()
	mkHome(t, dir, map[string]string{
		"a": `{"projects": {"D:/demo": {"history": []}}, "machineID": "x"}`,
	})
	m := baseProfileMap()
	e := entryOf(m)
	delete(e, "selftest_exempt")
	e["parts"] = []any{
		map[string]any{"id": "projects", "selector": map[string]any{"json_pointer": "/projects/*/history"}},
		map[string]any{"id": "machine", "selector": map[string]any{"json_pointer": "/machineID"}, "layer": "L4"},
	}
	selftestOf(m)["expect"] = []any{
		map[string]any{"entry": "a", "part": "projects", "root": "home", "match": "a"},
		map[string]any{"entry": "a", "part": "machine", "root": "home", "match": "a", "layer": "L4"},
	}
	p, err := Load(writeProfileFile(t, dir, m))
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunSelfTest(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		for _, f := range res.Failures {
			t.Errorf("%v", f)
		}
		t.Fatal("part selectors should be present")
	}
}

func mkHome(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	home := filepath.Join(dir, "fixtures", "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		target := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

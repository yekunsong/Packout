package scan

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

func builtinEnv(t *testing.T, name string) (*profile.Profile, string) {
	t.Helper()
	p, err := profile.Builtin(name)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := profile.Materialize(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tree) })
	return p, tree
}

func builtinConfig(t *testing.T, p *profile.Profile, tree, out string) Config {
	cfg := Config{
		Profile: p, OutDir: out, GOOS: runtime.GOOS,
		Clock: fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		Salt:  manifest.FixedSalt("00112233445566778899aabbccddeeff"),
	}
	for _, inst := range p.Selftest.FixtureOrder {
		cfg.Roots = append(cfg.Roots, RootBinding{
			Role: strings.Split(inst, "#")[0], Name: inst,
			Path: filepath.Join(tree, inst),
		})
	}
	return cfg
}

// TestBuiltinClaudeCodeFixture scans the shipped fixture tree end to end and
// asserts the engine-level invariants (residual, L5, unique promotion,
// companion/shm bookkeeping) without pinning every classification.
func TestBuiltinClaudeCodeFixture(t *testing.T) {
	p, tree := builtinEnv(t, "claude-code")
	out := filepath.Join(t.TempDir(), "out")
	res, err := Run(context.Background(), builtinConfig(t, p, tree, out))
	if err != nil {
		t.Fatal(err)
	}
	if res.Residual == 0 {
		t.Fatal("builtin fixture must expose residual paths")
	}
	m, err := manifest.ReadManifest(out)
	if err != nil {
		dumpBadLayers(t, out)
		t.Fatalf("%v\n%s", err, issues(t, out))
	}
	l5, promoted := 0, 0
	for _, u := range m.Units {
		if u.Layer == manifest.LayerL5 {
			l5++
		}
		// Paths are native-spelled; compare on a slash form so the check also
		// holds on Windows (D-034).
		if strings.HasSuffix(filepath.ToSlash(u.Path), ".claude/settings.local.json") && u.Layer == manifest.LayerL3 {
			promoted++
		}
		if u.Kind == manifest.KindCatchAll {
			if len(u.Signals) != 1 || u.Signals[0].Src != "filesystem_stat" {
				t.Fatalf("catch-all signals = %+v", u.Signals)
			}
		}
	}
	if l5 == 0 {
		t.Fatal("no L5 named-location unit")
	}
	if promoted != 2 {
		t.Fatalf("unique promotion units = %d, want 2", promoted)
	}
	if res.ReadErrors != 0 {
		t.Fatalf("read errors = %d\n%s", res.ReadErrors, issues(t, out))
	}

	// No fixture plaintext may leak. settings.json contains a fake token.
	raw, err := os.ReadFile(filepath.Join(out, "manifest.0001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join(tree, "home", ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range plainFakeSecrets(string(fixture)) {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("plaintext %q leaked", needle)
		}
	}
	if !res.Complete {
		t.Fatal("scan should be complete")
	}
}

var plainishRun = regexp.MustCompile(`[A-Za-z0-9_+/=\-]{20,}`)

func dumpBadLayers(t *testing.T, out string) {
	for _, rec := range readRaw(t, out) {
		if rec["type"] != "unit" {
			continue
		}
		layer, _ := rec["layer"].(string)
		if layer == "" {
			t.Logf("empty layer: entry=%v kind=%v path=%v part=%v", rec["entry"], rec["kind"], rec["path"], rec["part_id"])
		}
		sigs, _ := rec["signals"].([]any)
		for _, raw := range sigs {
			sig, _ := raw.(map[string]any)
			note, _ := sig["note"].(string)
			for _, tok := range plainishRun.FindAllString(note, -1) {
				hasL, hasD := false, false
				for _, r := range tok {
					if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
						hasL = true
					}
					if r >= '0' && r <= '9' {
						hasD = true
					}
				}
				if hasL && hasD {
					t.Errorf("plainish %q in %q (entry %v)", tok, note, rec["entry"])
				}
			}
		}
	}
}

func plainFakeSecrets(src string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(src, func(r rune) bool {
		return !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		if strings.HasPrefix(tok, "sk-ant-") || strings.HasPrefix(tok, "sk-fake") {
			out = append(out, tok)
		}
	}
	return out
}

// TestBuiltinCodexSQLiteSideEffect proves open_as: sqlite-ro creates -shm and
// that the shm is merged as a companion, never as a residual Unit.
func TestBuiltinCodexSQLiteSideEffect(t *testing.T) {
	p, tree := builtinEnv(t, "codex")
	// MaterializeTo makes zero-filled files; give the declared sqlite files a
	// real header so the engine recognizes them.
	for _, rel := range []string{"state_5.sqlite", "logs_2.sqlite", "thread_history_1.sqlite", "sqlite/queue_1.sqlite"} {
		path := filepath.Join(tree, "codex", filepath.FromSlash(rel))
		if err := os.WriteFile(path, []byte("SQLite format 3\x00payload"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "out")
	res, err := Run(context.Background(), builtinConfig(t, p, tree, out))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.ReadManifest(out)
	if err != nil {
		dumpBadLayers(t, out)
		t.Fatalf("%v\n%s", err, issues(t, out))
	}
	created := 0
	for _, u := range m.Units {
		for _, se := range u.SideEffects {
			if se == manifest.SideEffectShmCreate {
				created++
				if u.OpenAs != manifest.OpenAsSQLiteRO {
					t.Fatal("shm_created without sqlite-ro")
				}
			}
		}
		if strings.HasSuffix(u.Path, "-shm") && u.Entry == "residual" {
			t.Fatalf("shm became a residual unit: %s", u.Path)
		}
	}
	if created == 0 {
		t.Fatal("no shm_created side effect observed")
	}
	if _, err := os.Lstat(filepath.Join(tree, "codex", "state_5.sqlite-shm")); err != nil {
		t.Fatalf("state_5 -shm missing: %v", err)
	}
	if res.Residual == 0 {
		t.Fatal("codex fixture should still have residual paths")
	}
}

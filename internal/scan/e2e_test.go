package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/pack"
	"packout/internal/profile"
	"packout/internal/report"
)

// End-to-end test of the P0 pipeline: built-in profile -> materialized fake
// home -> scan -> render -> export -> verify.
//
// The fake home deliberately contains two projects in .claude.json and two
// matching slug directories. Per spec-profile-model §5.10/D-024 #3 the
// project-index part yields one origin per project key and those origins are
// backfilled onto the repo_slug units of the corresponding slug directory.

type e2eClock struct{}

func (e2eClock) Now() time.Time {
	return time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
}

const (
	e2eProjAlpha = "D:/Study/alpha"
	e2eProjBeta  = "D:/Study/beta"
	e2eSlugAlpha = "D--Study-alpha"
	e2eSlugBeta  = "D--Study-beta"

	e2eTokenSettings = "sk-ant-fake-SETTINGS-0123456789abcdef0123456789abcdef"
	e2eTokenHistory  = "sk-ant-fake-HISTORY-0123456789abcdef0123456789abcdef"
	e2eTokenMCP      = "sk-ant-fake-MCP-0123456789abcdef0123456789abcdef"
)

func e2eHasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func e2eWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// materializeFakeHome materializes the built-in claude-code fixture and then
// rewrites the pieces this test pins: .claude.json with two projects, two
// project slug directories, settings.local.json, history.jsonl and a few
// plugin files.
func materializeFakeHome(t *testing.T, p *profile.Profile) (tree, home string) {
	t.Helper()
	tree, err := profile.Materialize(p)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tree) })
	home = filepath.Join(tree, "home")

	claudeJSON := `{
  "machineID": "fake-machine-id-0001",
  "userID": "fake-user-id-0001",
  "projects": {
    "` + e2eProjAlpha + `": {
      "allowedTools": [],
      "history": [{"display": "alpha", "apiKey": "` + e2eTokenHistory + `"}]
    },
    "` + e2eProjBeta + `": {
      "allowedTools": [],
      "history": [{"display": "beta"}]
    }
  },
  "mcpServers": {
    "demo": {
      "command": "node",
      "env": {"DEMO_TOKEN": "` + e2eTokenMCP + `"}
    }
  },
  "cachedExperimentFeatures": {"example_flag": true}
}
`
	e2eWrite(t, filepath.Join(home, ".claude.json"), []byte(claudeJSON))

	e2eWrite(t, filepath.Join(home, ".claude", "settings.local.json"), []byte(`{
  "permissions": {"allow": []},
  "env": {"ANTHROPIC_API_KEY": "`+e2eTokenSettings+`"}
}
`))
	e2eWrite(t, filepath.Join(home, ".claude", "history.jsonl"), []byte(
		`{"display":"hello","apiKey":"`+e2eTokenSettings+`"}`+"\n"))

	// Two slug directories, each with a transcript so the projects-* glob
	// entries produce machine_derived (repo_slug) units.
	e2eWrite(t, filepath.Join(home, ".claude", "projects", e2eSlugAlpha, "session-a.jsonl"),
		[]byte(`{"type":"user","message":"alpha"}`+"\n"))
	e2eWrite(t, filepath.Join(home, ".claude", "projects", e2eSlugBeta, "session-b.jsonl"),
		[]byte(`{"type":"user","message":"beta"}`+"\n"))

	// Plugin files: the fixture already has plugins/, make the pinned set
	// explicit so the test does not depend on fixture details.
	e2eWrite(t, filepath.Join(home, ".claude", "plugins", "README.md"), []byte("plugins\n"))
	e2eWrite(t, filepath.Join(home, ".claude", "plugins", "known_marketplaces.json"),
		[]byte(`{"demo":{"url":"https://example.invalid/demo.git"}}`))
	e2eWrite(t, filepath.Join(home, ".claude", "plugins", "demo", "config.json"),
		[]byte(`{"display":"demo"}`))
	e2eWrite(t, filepath.Join(home, ".claude", "plugins", "demo", "heartbeat.json"),
		[]byte(`{"pid":1}`))
	return tree, home
}

// copyDirFiles copies the regular files directly inside src to dst (used to
// turn the scan output into a package source without dragging extra entries
// into manifest/).
func copyDirFiles(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, ent.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuiltinClaudeCodePipelineE2E(t *testing.T) {
	p, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	tree, home := materializeFakeHome(t, p)
	repo := filepath.Join(tree, "repo") // fixture repo has no .git -> not_versioned

	out := filepath.Join(t.TempDir(), "out")
	cfg := Config{
		Profile: p,
		OutDir:  out,
		Roots: []RootBinding{
			{Role: "home", Path: home},
			{Role: "repo", Path: repo},
		},
		GOOS:  runtime.GOOS,
		Clock: e2eClock{},
		Salt:  manifest.FixedSalt("00112233445566778899aabbccddeeff"),
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Complete {
		t.Fatal("scan did not complete")
	}
	m, err := manifest.ReadManifest(out)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}

	// --- L5, residual and not_versioned -----------------------------------
	l5 := 0
	for _, u := range m.Units {
		if u.Layer == manifest.LayerL5 {
			l5++
		}
	}
	if l5 == 0 {
		t.Error("expected at least one L5 (named-location) unit")
	}
	if res.Residual == 0 {
		t.Error("expected residual (catch-all) units, got 0")
	}
	unversioned := 0
	for _, u := range m.Units {
		if e2eHasFlag(u.RiskFlags, "not_versioned") {
			unversioned++
		}
	}
	if unversioned == 0 {
		t.Error("expected not_versioned units under the repo root without .git")
	}

	// --- .claude.json part split ------------------------------------------
	// machine-identity, user-identity each select one value; the two project
	// keys each yield one project-index origin; project-history expands the
	// two /projects/*/history values; mcp-servers one; cachedExperimentFeatures
	// is the single uncovered top-level key.
	wantParts := map[string]int{
		"machine-identity":     1,
		"user-identity":        1,
		"project-index":        2,
		"project-history":      2,
		"mcp-servers":          1,
		manifest.PartUncovered: 1,
	}
	gotParts := make(map[string]int)
	var indexUnits []manifest.Unit
	for _, u := range m.Units {
		if u.Entry != "claude-json" {
			continue
		}
		gotParts[u.PartID]++
		if u.PartID == "project-index" {
			indexUnits = append(indexUnits, u)
		}
	}
	if !reflect.DeepEqual(gotParts, wantParts) {
		t.Errorf("claude-json part split = %v, want %v", gotParts, wantParts)
	}

	// --- origin backfill ---------------------------------------------------
	wantOrigins := []string{e2eProjAlpha, e2eProjBeta}
	gotOrigins := make([]string, 0, len(indexUnits))
	for _, u := range indexUnits {
		if u.Origin == nil {
			t.Errorf("project-index unit %s has nil origin (want one per project key)", u.Path)
			continue
		}
		gotOrigins = append(gotOrigins, *u.Origin)
		if u.OriginPathKey == nil || *u.OriginPathKey != fsx.NormKey(*u.Origin) {
			gotKey := "<nil>"
			if u.OriginPathKey != nil {
				gotKey = *u.OriginPathKey
			}
			t.Errorf("project-index unit origin_path_key = %q, want %q", gotKey, fsx.NormKey(*u.Origin))
		}
	}
	sort.Strings(wantOrigins)
	sort.Strings(gotOrigins)
	if !reflect.DeepEqual(gotOrigins, wantOrigins) {
		t.Errorf("project-index origins = %v, want %v", gotOrigins, wantOrigins)
	}

	// The slug -> origin mapping must backfill the repo_slug units of each
	// matching project directory.
	for _, tc := range []struct{ project, slug string }{
		{e2eProjAlpha, e2eSlugAlpha},
		{e2eProjBeta, e2eSlugBeta},
	} {
		marker := "/.claude/projects/" + tc.slug + "/"
		units := 0
		for _, u := range m.Units {
			if !strings.Contains(filepath.ToSlash(u.Path), marker) {
				continue
			}
			units++
			if u.DerivedFrom == nil || *u.DerivedFrom != manifest.DerivedRepoSlug {
				continue
			}
			if u.Origin == nil || *u.Origin != tc.project {
				got := "<nil>"
				if u.Origin != nil {
					got = *u.Origin
				}
				t.Errorf("slug %s unit %s origin = %q, want %q", tc.slug, u.Path, got, tc.project)
			}
		}
		if units == 0 {
			t.Errorf("no units found under project slug %s", tc.slug)
		}
	}

	// --- report ------------------------------------------------------------
	var html bytes.Buffer
	if err := report.Render(&html, m, report.Options{IncludeSignals: true}); err != nil {
		t.Fatalf("report.Render: %v", err)
	}
	for _, tok := range []string{e2eTokenSettings, e2eTokenHistory, e2eTokenMCP} {
		if strings.Contains(html.String(), tok) {
			t.Errorf("report HTML contains plaintext fake token %q", tok)
		}
	}

	// --- pack export + verify ---------------------------------------------
	src := filepath.Join(t.TempDir(), "src")
	copyDirFiles(t, out, filepath.Join(src, "manifest"))
	if err := os.WriteFile(filepath.Join(src, pack.ReportName), html.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, pack.ConfigDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "pkg")
	exp, err := pack.Export(pack.Config{SourceDir: src, OutDir: pkg})
	if err != nil {
		t.Fatalf("pack.Export: %v", err)
	}
	if exp.Signed {
		t.Error("P0 export must be unsigned")
	}
	v, err := pack.Verify(pkg)
	if err != nil {
		t.Fatalf("pack.Verify: %v (verdict %+v)", err, v)
	}
	if v.Conclusion != pack.ConclusionUnsigned {
		t.Fatalf("verify conclusion = %q, want %q", v.Conclusion, pack.ConclusionUnsigned)
	}
}

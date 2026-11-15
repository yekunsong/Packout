package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type env struct {
	t     *testing.T
	prof  *profile.Profile
	tree  string
	out   string
	clock fixedClock
}

const testProfileHead = `{
  "schema_version": "2.0",
  "name": "test",
  "title": "test profile",
  "applies_to": {"os": ["windows","darwin","linux"]},
  "roots": {"home": "/nonexistent-home", "repo": "/nonexistent-repo"},
  "defaults": {},
  "entries": [`

const testProfileTail = `],
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    "fixtures": {"home": "fixtures/home", "repo": "fixtures/repo"},
    "expect": [{"entry": "catch-home", "root": "home", "match": ".keep"}],
    "budget": {"wall_ms": 5000}
  }
}`

func setup(t *testing.T, entries string) *env {
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
	src := testProfileHead + entries + testProfileTail
	path := filepath.Join(dir, "profile.jsonc")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	tree, err := os.MkdirTemp("", "pk")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.MaterializeTo(tree); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tree) })
	return &env{
		t: t, prof: p, tree: tree, out: filepath.Join(t.TempDir(), "out"),
		clock: fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
}

func (e *env) cfg() Config {
	return Config{
		Profile: e.prof,
		OutDir:  e.out,
		Roots: []RootBinding{
			{Role: "home", Path: filepath.Join(e.tree, "home")},
			{Role: "repo", Path: filepath.Join(e.tree, "repo")},
		},
		GOOS:  runtime.GOOS,
		Clock: e.clock,
		Salt:  manifest.FixedSalt("00112233445566778899aabbccddeeff"),
	}
}

func (e *env) run() *Result {
	e.t.Helper()
	res, err := Run(context.Background(), e.cfg())
	if err != nil {
		e.t.Fatalf("Run: %v", err)
	}
	return res
}

func (e *env) path(rel string) string {
	return filepath.Join(e.tree, filepath.FromSlash(rel))
}

func (e *env) write(rel, content string) {
	e.t.Helper()
	p := e.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// writeVerbatim writes a file whose name Win32 would otherwise normalize
// (trailing dot or space). Creation must bypass Win32 path parsing on Windows,
// or "trail." is stored as "trail" before the scanner ever sees it (D-034).
func (e *env) writeVerbatim(rel, content string) {
	e.t.Helper()
	p := e.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		p = `\\?\` + p
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// caseSensitiveDir creates dir and, on Windows, marks it case sensitive so
// "a" and "A" can coexist: NTFS is case insensitive by default and a second
// create would otherwise overwrite the first (D-034).
func caseSensitiveDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("fsutil.exe", "file", "setCaseSensitiveInfo", dir, "enable").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "is enabled") {
		// fsutil exits 0 even on failure (for example when the directory is
		// not empty), so inspect its output too.
		t.Skipf("fsutil setCaseSensitiveInfo unavailable: %v %s", err, out)
	}
}

func readRaw(t *testing.T, out string) []map[string]any {
	t.Helper()
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, ent := range entries {
		if !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(out, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, m)
		}
		f.Close()
	}
	return lines
}

func unitsOf(t *testing.T, out string) []manifest.Unit {
	t.Helper()
	m, err := manifest.ReadManifest(out)
	if err != nil {
		t.Fatalf("ReadManifest: %v\n%s", err, issues(t, out))
	}
	return m.Units
}

func issues(t *testing.T, out string) string {
	var b strings.Builder
	for _, is := range manifest.ValidateAll(out) {
		if is.Severity == manifest.SeverityError {
			b.WriteString(is.String())
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func byEntry(units []manifest.Unit, entry string) []manifest.Unit {
	var out []manifest.Unit
	for _, u := range units {
		if u.Entry == entry {
			out = append(out, u)
		}
	}
	return out
}

func hasFlag(u manifest.Unit, f string) bool {
	for _, x := range u.RiskFlags {
		if x == f {
			return true
		}
	}
	return false
}

const catchHome = `{"id":"catch-home","kind":"catch-all","root":"home","layer":"L2","secret":"none","extractor":"none","signals":[]}`

func TestC02MCPFakeToken(t *testing.T) {
	canary := "sk-ant-api03-C0RPUSCANARY0123456789abcdefXY"
	e := setup(t, `{
      "id":"repo-mcp-json","selftest_exempt":"integration","kind":"file","root":"repo","path":".mcp.json",
      "layer":"L2","secret":"scan","extractor":"template","priority":20,
      "signals":[{"src":"official_docs","note":"project mcp","url":"https://example.invalid"}]},
      `+catchHome)
	e.write("repo/.mcp.json", `{"mcpServers":{"alpha":{"command":"npx","env":{"TOKEN":"`+canary+`"}},"beta":{"command":"npx","env":{"TOKEN":"`+canary+`"}}}}`)
	e.run()
	units := unitsOf(t, e.out)
	got := byEntry(units, "repo-mcp-json")
	if len(got) != 1 {
		t.Fatalf("got %d units", len(got))
	}
	u := got[0]
	if u.Secret.Class != "scan" || u.Secret.HitCount != 2 || len(u.Secret.Hits) != 2 {
		t.Fatalf("secret = %+v", u.Secret)
	}
	for _, h := range u.Secret.Hits {
		if h.Kind != "known_prefix" || h.Class != "restore" || h.Prefix != "sk-ant-" {
			t.Fatalf("hit = %+v", h)
		}
	}
	if u.Secret.Hits[0].Locator != "/mcpServers/alpha/env/TOKEN" &&
		u.Secret.Hits[0].Locator != "/mcpServers/beta/env/TOKEN" {
		t.Fatalf("locator = %q", u.Secret.Hits[0].Locator)
	}
	if u.Secret.Hits[0].Fingerprint != u.Secret.Hits[1].Fingerprint {
		t.Fatal("equal values got different fingerprints")
	}
	raw, _ := os.ReadFile(filepath.Join(e.out, "manifest.0001.jsonl"))
	if strings.Contains(string(raw), canary) {
		t.Fatal("plaintext canary in manifest")
	}
	if hasFlag(u, "low_confidence") || u.Layer != manifest.LayerL2 {
		t.Fatalf("unexpected classification %+v", u)
	}
}

func TestC01GitignoredUnversioned(t *testing.T) {
	e := setup(t, `{
      "id":"settings-local-global","selftest_exempt":"integration","kind":"file","root":"home","path":".claude/settings.local.json",
      "layer":"L2","secret":"scan","extractor":"template","unique_within":"root","priority":20,
      "signals":[{"src":"observed_behavior","note":"global local settings"}]},
      {"id":"repo-settings-local","selftest_exempt":"integration","kind":"file","root":"repo","path":".claude/settings.local.json",
      "layer":"L2","secret":"scan","extractor":"template","unique_within":"root","priority":20,
      "signals":[{"src":"observed_behavior","note":"repo local settings"}]},
      `+catchHome)
	e.write("home/.config/git/ignore", "**/.claude/settings.local.json\n")
	e.write("home/.claude/settings.local.json", `{"permissions":{"allow":["Bash(ls)"]}}`)
	e.write("repo/.claude/settings.local.json", `{"permissions":{"allow":["Bash(ls)"]}}`)
	e.run()
	units := unitsOf(t, e.out)
	for _, entry := range []string{"settings-local-global", "repo-settings-local"} {
		got := byEntry(units, entry)
		if len(got) != 1 {
			t.Fatalf("%s: got %d units", entry, len(got))
		}
		if !hasFlag(got[0], "gitignored") {
			t.Fatalf("%s missing gitignored: %v", entry, got[0].RiskFlags)
		}
		if got[0].Layer != manifest.LayerL3 {
			t.Fatalf("%s layer = %s, want L3", entry, got[0].Layer)
		}
		if got[0].Secret.HitCount != 0 || got[0].Secret.Class != "scan" {
			t.Fatalf("%s secret = %+v", entry, got[0].Secret)
		}
	}
	if !hasFlag(byEntry(units, "repo-settings-local")[0], "not_versioned") {
		t.Fatal("repo unit missing not_versioned")
	}
}

func TestC03LinkDirectoryNoDescent(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"dir","root":"home","path":".claude/cache","layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/real.jsonl", "x")
	if err := os.Symlink(".", e.path("home/.claude/cache/loop")); err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
	e.run()
	units := unitsOf(t, e.out)
	loop := 0
	for _, u := range units {
		if strings.HasSuffix(u.Path, "loop") {
			loop++
			if !hasFlag(u, "symlink") {
				t.Fatalf("link flags = %v", u.RiskFlags)
			}
		}
		if strings.Contains(u.Path, "loop/") {
			t.Fatalf("descended into %s", u.Path)
		}
	}
	if loop != 1 {
		t.Fatalf("loop units = %d", loop)
	}
}

func TestC04SymlinkOutsideRoot(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"dir","root":"home","path":".claude/cache","layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("outside/secret-dir/note.txt", "outside")
	if err := os.MkdirAll(e.path("home/.claude/cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../outside/secret-dir", e.path("home/.claude/cache/to-outside")); err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
	e.run()
	units := unitsOf(t, e.out)
	var link *manifest.Unit
	for i := range units {
		if strings.HasSuffix(units[i].Path, "to-outside") {
			link = &units[i]
		}
		if strings.Contains(units[i].Path, "outside/secret-dir") {
			t.Fatalf("outside content emitted: %s", units[i].Path)
		}
	}
	if link == nil || !hasFlag(*link, "symlink") || !hasFlag(*link, "outside_root") {
		t.Fatalf("link = %+v", link)
	}
	if link.LinkTarget != "../../../outside/secret-dir" {
		t.Fatalf("link_target = %q", link.LinkTarget)
	}
}

func TestC05CaseCollision(t *testing.T) {
	e := setup(t, `{
      "id":"transcripts","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/projects/**/*.jsonl"],
      "layer":"L3","secret":"scan","extractor":"digest","opaque_content":true,
      "signals":[{"src":"observed_behavior","note":"transcripts"}]},
      `+catchHome)
	// The attribute can only be set while the directory is empty.
	caseSensitiveDir(t, e.path("home/.claude/projects/Demo"))
	e.write("home/.claude/projects/Demo/keep.txt", "keep")
	// Creation must be verbatim: Win32 lookup ignores case, so a plain
	// "A.jsonl" create would reopen and overwrite "a.jsonl" (D-034).
	e.writeVerbatim("home/.claude/projects/Demo/a.jsonl", "{}\n")
	e.writeVerbatim("home/.claude/projects/Demo/A.jsonl", "{}\n")
	e.run()
	// Duplicate ids are expected here (id is path_key-derived), so read raw.
	var got []map[string]any
	for _, rec := range readRaw(t, e.out) {
		if rec["type"] == "unit" && rec["entry"] == "transcripts" {
			got = append(got, rec)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d units", len(got))
	}
	if got[0]["path_key"] != got[1]["path_key"] {
		t.Fatal("path keys differ")
	}
	for _, u := range got {
		flags, _ := u["risk_flags"].([]any)
		ok := false
		for _, f := range flags {
			if f == "case_collision" {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("missing case_collision: %v", flags)
		}
	}
}

func TestC06TrailingDotSpace(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	for _, name := range []string{"trail.", "trail ", "trail.txt.", "lead.txt"} {
		e.writeVerbatim("home/.claude/cache/"+name, "x")
	}
	e.run()
	units := unitsOf(t, e.out)
	keys := make(map[string]bool)
	var suffixes []string
	for _, u := range units {
		if u.Entry == "cache" && u.Kind == manifest.KindFile {
			keys[u.PathKey] = true
			suffixes = append(suffixes, filepath.Base(u.Path))
		}
	}
	if len(suffixes) != 4 {
		t.Fatalf("got %d file units", len(suffixes))
	}
	sort.Strings(suffixes)
	want := []string{"lead.txt", "trail ", "trail.", "trail.txt."}
	if strings.Join(suffixes, "|") != strings.Join(want, "|") {
		t.Fatalf("names = %v", suffixes)
	}
	if len(keys) != 4 {
		t.Fatalf("path keys = %d", len(keys))
	}
}

func TestC07LongPath(t *testing.T) {
	dir := ""
	for i := 0; i < 30; i++ {
		dir += "dddddddd" + string(rune('a'+i%26)) + "/"
	}
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/"+dir+"deep.jsonl", "x")
	e.run()
	units := unitsOf(t, e.out)
	var found *manifest.Unit
	for i := range units {
		if strings.HasSuffix(units[i].Path, "deep.jsonl") {
			found = &units[i]
		}
	}
	if found == nil {
		t.Fatal("deep unit missing")
	}
	if len(found.Path) < 240 || !hasFlag(*found, "long_path") {
		t.Fatalf("path len %d flags %v", len(found.Path), found.RiskFlags)
	}
	if hasFlag(*found, "read_error") {
		t.Fatal("long path read failed")
	}
}

func TestC08ReadonlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("attrib handling is covered by fsx")
	}
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/ro.jsonl", "readonly\n")
	if err := os.Chmod(e.path("home/.claude/cache/ro.jsonl"), 0o444); err != nil {
		t.Fatal(err)
	}
	e.run()
	units := unitsOf(t, e.out)
	var got []manifest.Unit
	for _, u := range units {
		if u.Entry == "cache" && u.Kind == manifest.KindFile {
			got = append(got, u)
		}
	}
	if len(got) != 1 || hasFlag(got[0], "read_error") {
		t.Fatalf("units = %+v", got)
	}
	if got[0].Secret.Class != "none" {
		t.Fatalf("secret = %+v", got[0].Secret)
	}
}

func TestC09ReadErrorDoesNotAbort(t *testing.T) {
	if runtime.GOOS == "windows" || testIsRoot() {
		t.Skip("needs an unreadable file as non-root")
	}
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"scan","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/a-ok.jsonl", "ok")
	e.write("home/.claude/cache/b-occupied.jsonl", "secret")
	e.write("home/.claude/cache/c-ok.jsonl", "ok")
	if err := os.Chmod(e.path("home/.claude/cache/b-occupied.jsonl"), 0); err != nil {
		t.Fatal(err)
	}
	res := e.run()
	units := unitsOf(t, e.out)
	files := 0
	for _, u := range units {
		if u.Entry == "cache" && u.Kind == manifest.KindFile {
			files++
		}
	}
	if files != 3 {
		t.Fatalf("lost units: %d", files)
	}
	var bad *manifest.Unit
	for i := range units {
		if strings.Contains(units[i].Path, "b-occupied") {
			bad = &units[i]
		}
	}
	if bad == nil || !hasFlag(*bad, "read_error") || bad.Fingerprint.Value != nil {
		t.Fatalf("bad unit = %+v", bad)
	}
	if res.ReadErrors == 0 {
		t.Fatal("read error not counted")
	}
	if !res.Complete {
		t.Fatal("handled read_error must keep complete=true")
	}
}

func TestC10UniquePromotion(t *testing.T) {
	e := setup(t, `{
      "id":"repo-claude-md","selftest_exempt":"integration","kind":"file","root":"repo","path":"CLAUDE.md",
      "layer":"L2","secret":"none","extractor":"raw-ref","unique_within":"root","priority":10,
      "signals":[{"src":"observed_behavior","note":"rules"}]},
      `+catchHome)
	e.write("repo/CLAUDE.md", "# archive rules\n")
	e.run()
	units := unitsOf(t, e.out)
	promoted := false
	for _, u := range units {
		if !strings.HasSuffix(u.Path, "CLAUDE.md") {
			continue
		}
		if u.Layer != manifest.LayerL3 {
			t.Fatalf("layer = %s", u.Layer)
		}
		if hasFlag(u, "low_confidence") || hasFlag(u, "git_tracked") {
			t.Fatalf("flags = %v", u.RiskFlags)
		}
		hasRule := false
		for _, s := range u.Signals {
			if s.Src == "profile_rule" && strings.Contains(s.Note, "unique_within") {
				hasRule = true
			}
		}
		if !hasRule {
			t.Fatal("promotion signal missing")
		}
		promoted = true
	}
	if !promoted {
		t.Fatal("unit missing")
	}
}

func TestResidualCountAndShape(t *testing.T) {
	e := setup(t, catchHome)
	e.write("home/.claude/loose.txt", "loose")
	e.write("home/unrelated/leaf.txt", "leaf")
	e.write("home/.git/config", "git")
	res := e.run()
	if res.Residual != 3 {
		t.Fatalf("residual = %d, want 3 (.keep plus two dirs)", res.Residual)
	}
	units := unitsOf(t, e.out)
	for _, u := range byEntry(units, "catch-home") {
		if u.Kind != manifest.KindCatchAll || u.Layer != manifest.LayerL2 ||
			u.Confidence != 0.5 || u.ProposedAction != manifest.ActionKeep {
			t.Fatalf("shape = %+v", u)
		}
		if !hasFlag(u, "residual") || !hasFlag(u, "low_confidence") {
			t.Fatal("flags missing")
		}
		if len(u.Signals) != 1 || u.Signals[0].Src != "filesystem_stat" {
			t.Fatalf("signals = %+v", u.Signals)
		}
	}
	if len(byEntry(units, "catch-home")) != 3 {
		t.Fatal(".git should be excluded")
	}
}

func TestNamedLocationL5(t *testing.T) {
	e := setup(t, `{
      "id":"cred","selftest_exempt":"integration","kind":"named-location","os":["linux","darwin","windows"],
      "locator":"file:/PLACEHOLDER","probe":"file-probe","layer":"L5","secret":"relogin","extractor":"digest",
      "signals":[{"src":"official_docs","note":"credentials","url":"https://example.invalid"}]},
      `+catchHome)
	// Rewrite the profile's locator with the real materialized path. Slashes
	// keep it JSON-legal on Windows too (a single backslash would not be).
	credPath := filepath.ToSlash(e.path("home/.claude/.credentials.json"))
	e.write("home/.claude/.credentials.json", `{"a":1}`)
	srcFile := e.prof.File
	data, _ := os.ReadFile(srcFile)
	data = []byte(strings.ReplaceAll(string(data), "/PLACEHOLDER", credPath))
	if err := os.WriteFile(srcFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	e.prof = p
	e.run()
	units := unitsOf(t, e.out)
	got := byEntry(units, "cred")
	if len(got) != 1 {
		t.Fatalf("units = %d", len(got))
	}
	u := got[0]
	if u.Kind != manifest.KindNamedLocation || u.Layer != manifest.LayerL5 ||
		u.Root != "os" || u.ProposedAction != manifest.ActionRelogin {
		t.Fatalf("unit = %+v", u)
	}
	if hasFlag(u, "probe_unavailable") {
		t.Fatal("probe should succeed")
	}
	if u.SizeApparent != nil || u.FileID != nil {
		t.Fatal("named-location metadata should be null")
	}
}

func TestCompanionsMerge(t *testing.T) {
	e := setup(t, `{
      "id":"db","selftest_exempt":"integration","kind":"file","root":"home","path":".claude/state.sqlite",
      "layer":"L3","secret":"none","extractor":"digest","companions":["-wal","-shm"],"opaque_content":true,
      "signals":[{"src":"observed_behavior","note":"db"}]},
      `+catchHome)
	e.write("home/.claude/state.sqlite", "SQLite format 3\x00payload")
	e.write("home/.claude/state.sqlite-wal", "wal")
	e.write("home/.claude/state.sqlite-shm", "shm")
	e.run()
	units := unitsOf(t, e.out)
	got := byEntry(units, "db")
	if len(got) != 1 {
		t.Fatalf("units = %d", len(got))
	}
	if strings.Join(got[0].Companions, ",") != "-wal,-shm" {
		t.Fatalf("companions = %v", got[0].Companions)
	}
	for _, u := range units {
		if strings.HasSuffix(u.Path, "-wal") || strings.HasSuffix(u.Path, "-shm") {
			t.Fatalf("companion produced a separate unit: %s", u.Path)
		}
	}
	if got[0].SizeApparent == nil || *got[0].SizeApparent != int64(len("SQLite format 3\x00payload")+3+3) {
		t.Fatalf("size = %v", got[0].SizeApparent)
	}
}

func TestSQLiteShmSideEffect(t *testing.T) {
	e := setup(t, `{
      "id":"db","selftest_exempt":"integration","kind":"file","root":"home","path":".claude/state.sqlite",
      "layer":"L3","secret":"none","extractor":"digest","companions":["-wal","-shm"],
      "open_as":"sqlite-ro","side_effects":["shm_created"],"opaque_content":true,
      "signals":[{"src":"observed_behavior","note":"db"}]},
      `+catchHome)
	main := e.path("home/.claude/state.sqlite")
	e.write("home/.claude/state.sqlite", "SQLite format 3\x00payload")
	e.write("home/.claude/state.sqlite-wal", "wal")
	res := e.run()
	if _, err := os.Lstat(main + "-shm"); err != nil {
		t.Fatalf("-shm not created: %v", err)
	}
	units := unitsOf(t, e.out)
	if len(byEntry(units, "db")) != 1 {
		t.Fatal("main unit missing")
	}
	if res.Residual != 2 { // .keep plus the .claude directory itself
		t.Fatalf("residual = %d (companions must not be residual)", res.Residual)
	}
	for _, u := range unitsOf(t, e.out) {
		if strings.HasSuffix(u.Path, "-shm") || strings.HasSuffix(u.Path, "-wal") {
			t.Fatalf("companion residual: %s", u.Path)
		}
	}
	footer := readRaw(t, e.out)
	var stats map[string]any
	for _, rec := range footer {
		if rec["type"] == "footer" {
			stats, _ = rec["stats"].(map[string]any)
		}
	}
	if stats == nil {
		t.Fatal("no footer")
	}
	if se, _ := stats["side_effects"].(map[string]any); se == nil || se["shm_created"] != float64(1) {
		t.Fatalf("side_effects = %v", stats)
	}
}

func TestBudgetExhaustion(t *testing.T) {
	e := setup(t, `{
      "id":"data","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/data/**"],
      "layer":"L0","secret":"none","extractor":"none","opaque_content":true,"max_bytes_total":10,
      "signals":[{"src":"observed_behavior","note":"data"}]},
      `+catchHome)
	for i := 0; i < 4; i++ {
		e.write("home/.claude/data/f"+string(rune('a'+i))+".bin", "12345678")
	}
	e.run()
	m, err := manifest.ReadManifest(e.out)
	if err != nil {
		t.Fatalf("%v\n%s", err, issues(t, e.out))
	}
	budgetNotes := 0
	for _, n := range m.Notes {
		if n.Code == "budget_exceeded" {
			budgetNotes++
		}
	}
	if budgetNotes == 0 {
		t.Fatal("no budget_exceeded note")
	}
	meta := 0
	for _, u := range m.Units {
		if u.Entry == "data" && u.Fingerprint != nil && u.Fingerprint.Value == nil &&
			hasFlag(u, "content_partial") {
			meta++
		}
	}
	if meta == 0 {
		t.Fatal("no metadata-only unit after budget exhaustion")
	}
	files := 0
	for _, u := range m.Units {
		if u.Entry == "data" && u.Kind == manifest.KindFile {
			files++
		}
	}
	if files != 4 {
		t.Fatalf("budget truncated units: %d", files)
	}
}

func TestDeterministicOutput(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"scan","extractor":"digest",
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/a.jsonl", "{\"token\":\"sk-ant-abcdef1234567890\"}\n")
	e.write("home/.claude/cache/b.txt", "b\n")
	e.write("home/.claude/loose.txt", "loose\n")
	e.run()
	first := normalized(t, e.out)
	e.out = filepath.Join(t.TempDir(), "out2")
	e.run()
	second := normalized(t, e.out)
	if first != second {
		t.Fatal("two scans differ")
	}
}

func normalized(t *testing.T, out string) string {
	t.Helper()
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".jsonl") {
			names = append(names, ent.Name())
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"started_at", "ended_at", "scan_id"} {
				delete(m, k)
			}
			if in, ok := m["inputs"].(map[string]any); ok {
				delete(in, "secret_salt")
			}
			out, _ := json.Marshal(m)
			b.Write(out)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

type snapEntry struct {
	size  int64
	alloc int64
	mtime int64
}

func snapshot(t *testing.T, root string) map[string]snapEntry {
	t.Helper()
	out := make(map[string]snapEntry)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := fsx.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = snapEntry{size: info.Size, alloc: info.Alloc, mtime: info.ModTime.UnixNano()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNoTargetWrites(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/**"],
      "layer":"L0","secret":"scan","extractor":"digest",
      "signals":[{"src":"observed_behavior","note":"all"}]},
      `+catchHome)
	e.write("home/.claude/a.jsonl", "{\"token\":\"sk-ant-abcdef1234567890\"}\n")
	e.write("home/.claude/sub/b.txt", "b\n")
	e.write("home/loose.txt", "loose\n")
	before := snapshot(t, e.tree)
	e.run()
	after := snapshot(t, e.tree)
	if len(before) != len(after) {
		t.Fatalf("entry count changed %d -> %d", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("%s changed: %+v -> %+v", k, v, after[k])
		}
	}
}

func TestContextCancel(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"integration","kind":"glob-group","root":"home","paths":[".claude/**"],
      "layer":"L0","secret":"none","extractor":"none",
      "signals":[{"src":"observed_behavior","note":"all"}]},
      `+catchHome)
	e.write("home/.claude/a.txt", "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, e.cfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("cancelled scan must not be complete")
	}
}

// TestScale100k is skipped unless PACKOUT_SCALE=1. It measures the home-scale
// path (100,000 small files) instead of running in every CI pass.
func TestScale100k(t *testing.T) {
	if os.Getenv("PACKOUT_SCALE") != "1" {
		t.Skip("set PACKOUT_SCALE=1")
	}
	oldGC := debug.SetGCPercent(50)
	defer debug.SetGCPercent(oldGC)
	files, dirs := 100_000, 100
	if v := os.Getenv("PACKOUT_SCALE_FILES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("bad PACKOUT_SCALE_FILES %q", v)
		}
		files = n
	}
	e := setup(t, `{
      "id":"data","selftest_exempt":"x","kind":"glob-group","root":"home","paths":[".claude/data/**"],
      "layer":"L0","secret":"none","extractor":"none","aggregate_above":200000,
      "signals":[{"src":"observed_behavior","note":"scale"}]},
      `+catchHome)
	for d := 0; d < dirs; d++ {
		base := fmt.Sprintf("home/.claude/data/d%03d", d)
		if err := os.MkdirAll(e.path(base), 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < files/dirs; i++ {
			if err := os.WriteFile(e.path(fmt.Sprintf("%s/f%05d.txt", base, i)), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	res := e.run()
	elapsed := time.Since(start)
	var peak runtime.MemStats
	runtime.ReadMemStats(&peak)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("scan %d units in %s (%.0f files/s), total alloc %d MiB, heap-in-use at end %d MiB",
		res.Units, elapsed, float64(files)/elapsed.Seconds(),
		(after.TotalAlloc-before.TotalAlloc)>>20, peak.HeapAlloc>>20)
	if res.Units < int64(files) {
		t.Fatalf("units = %d, want >= %d", res.Units, files)
	}
}

func TestFollowSymlinksCycle(t *testing.T) {
	e := setup(t, `{
      "id":"cache","selftest_exempt":"x","kind":"glob-group","root":"home","paths":[".claude/cache/**"],
      "layer":"L0","secret":"none","extractor":"none","follow_symlinks":true,"max_depth":8,
      "signals":[{"src":"observed_behavior","note":"cache"}]},
      `+catchHome)
	e.write("home/.claude/cache/a.txt", "a")
	if err := os.Symlink(".", e.path("home/.claude/cache/loop")); err != nil {
		if symlinkNeedsPrivilege(err) {
			t.Skipf("symlink needs privilege: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
	cfg := e.cfg()
	cfg.FollowSymlinks = true
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Units > 20 {
		t.Fatalf("cycle exploded to %d units", res.Units)
	}
	found := false
	for _, u := range unitsOf(t, e.out) {
		if strings.HasSuffix(u.Path, "loop") {
			found = true
			if !hasFlag(u, "symlink_cycle") {
				t.Fatalf("loop flags = %v", u.RiskFlags)
			}
		}
	}
	if !found {
		t.Fatal("cycle link missing")
	}
}

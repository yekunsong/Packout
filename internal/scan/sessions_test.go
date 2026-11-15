package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yekunsong/Packout/internal/manifest"
)

const memoryEntry = `{
      "id":"projects-memory","selftest_exempt":"test","kind":"glob-group","root":"home",
      "paths":[".claude/projects/**/memory/**"],
      "layer":"L3","secret":"scan","extractor":"template","priority":15,
      "path_semantics":"machine_derived","derived_from":"repo_slug",
      "max_bytes_inline":262144,"max_bytes_total":268435456,
      "signals":[{"src":"observed_behavior","note":"memory"}]
    },
    `

func TestMemoryEntryMatchesBothDepthsOnly(t *testing.T) {
	e := setup(t, memoryEntry+catchHome)
	e.write("home/.claude/projects/D--demo/memory/MEMORY.md", "# memory\n")
	e.write("home/.claude/projects/D--demo/memory/notes/x.md", "# note\n")
	e.write("home/.claude/projects/D--demo/memory/notes/x.txt", "not memory\n")
	e.write("home/.claude/projects/D--demo/session-1.jsonl", "{}\n")
	res, err := Run(t.Context(), e.cfg())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Complete {
		t.Fatal("scan incomplete")
	}
	var got []string
	for _, u := range unitsOf(t, e.out) {
		if u.Entry != "projects-memory" || u.Kind != manifest.KindFile {
			continue
		}
		got = append(got, filepath.Base(u.Path))
	}
	// memory/** covers every depth below memory/, including the notes/ subdir.
	if len(got) != 3 {
		t.Fatalf("memory glob matched %v, want MEMORY.md, x.md and x.txt", got)
	}
	for _, name := range got {
		if name != "MEMORY.md" && name != "x.md" && name != "x.txt" {
			t.Fatalf("unexpected match %q", name)
		}
	}
	for _, u := range unitsOf(t, e.out) {
		if u.Entry == "projects-memory" && strings.HasSuffix(u.Path, ".jsonl") {
			t.Fatalf("memory entry matched a session transcript: %s", u.Path)
		}
	}
}

const sessionsEntry = `{
      "id":"sessions","selftest_exempt":"test","kind":"glob-group","root":"home",
      "paths":[".claude/projects/**/tool-results/**"],
      "layer":"L3","secret":"scan","extractor":"digest","sessions":true,"opaque_content":true,
      "max_bytes_inline":0,"max_bytes_total":1073741824,"aggregate_above":1,
      "signals":[{"src":"observed_behavior","note":"tool results"}]
    },
    `

func sessionsEnv(t *testing.T, names ...string) *env {
	t.Helper()
	e := setup(t, sessionsEntry+catchHome)
	for _, n := range names {
		e.write("home/.claude/projects/D--demo/tool-results/"+n, "blob "+n+"\n")
	}
	return e
}

func TestWithSessionsOffAggregates(t *testing.T) {
	e := sessionsEnv(t, "a.bin", "b.bin", "c.bin")
	e.run()
	got := byEntry(unitsOf(t, e.out), "sessions")
	if len(got) != 1 || got[0].AggregateCount == nil {
		t.Fatalf("aggregate_above should collapse 3 hits into one unit, got %d", len(got))
	}
}

func TestWithSessionsOnEmitsPerFile(t *testing.T) {
	e := sessionsEnv(t, "a.bin", "b.bin", "c.bin")
	cfg := e.cfg()
	cfg.WithSessions = true
	res, err := Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Complete {
		t.Fatal("scan incomplete")
	}
	units := unitsOf(t, e.out)
	got := byEntry(units, "sessions")
	files := 0
	for _, u := range got {
		if u.Kind != manifest.KindFile {
			continue
		}
		files++
		if u.AggregateCount != nil {
			t.Fatalf("per-file session unit %s is aggregated", u.Path)
		}
	}
	if files != 3 {
		t.Fatalf("per-file session units = %d, want 3", files)
	}

	raw := readRaw(t, e.out)
	opts, _ := raw[0]["inputs"].(map[string]any)["options"].(map[string]any)
	if opts["with_sessions"] != true {
		t.Fatalf("header options = %v, want with_sessions true", raw[0]["inputs"])
	}
	// max_bytes_inline is 0: these text files were not read at all, so they
	// must say content_not_read rather than calling every one binary.
	notRead := 0
	for _, rec := range raw {
		if rec["type"] != "note" || rec["entry"] != "sessions" {
			continue
		}
		switch rec["code"] {
		case "content_not_read":
			notRead++
		case "binary_presence_only":
			t.Fatalf("text session file noted as binary: %v", rec["detail"])
		}
	}
	if notRead != 3 {
		t.Fatalf("content_not_read notes = %d, want 3", notRead)
	}
}

func TestWithSessionsBudgetCapsRows(t *testing.T) {
	e := setup(t, `{
      "id":"sessions","selftest_exempt":"test","kind":"glob-group","root":"home",
      "paths":[".claude/projects/**/tool-results/**"],
      "layer":"L3","secret":"scan","extractor":"digest","sessions":true,"opaque_content":true,
      "max_bytes_inline":0,"max_bytes_total":1000,
      "signals":[{"src":"observed_behavior","note":"tool results"}]
    },
    `+catchHome)
	for i := 0; i < 10; i++ {
		e.write("home/.claude/projects/D--demo/tool-results/"+string(rune('a'+i))+".bin", strings.Repeat("z", 500))
	}
	cfg := e.cfg()
	cfg.WithSessions = true
	if _, err := Run(t.Context(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	units := unitsOf(t, e.out)
	files := 0
	noted := false
	for _, u := range units {
		if u.Entry == "sessions" && u.Kind == manifest.KindFile {
			files++
		}
	}
	for _, rec := range readRaw(t, e.out) {
		if rec["type"] == "note" && rec["code"] == "budget_exceeded" {
			noted = true
		}
	}
	if files < 1 || files >= 10 {
		t.Fatalf("budget did not cap session rows: %d rows", files)
	}
	if !noted {
		t.Fatal("missing budget_exceeded note")
	}
}

func TestWithSessionsFiftyThousandRows(t *testing.T) {
	if testing.Short() {
		t.Skip("creates 50k files")
	}
	e := setup(t, sessionsEntry+catchHome)
	dir := e.path("home/.claude/projects/D--demo/tool-results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50000; i++ {
		name := filepath.Join(dir, "f"+strings.Repeat("0", 6-len(itoa(i)))+itoa(i)+".bin")
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := e.cfg()
	cfg.WithSessions = true
	cfg.ShardUnits = 100000
	if _, err := Run(t.Context(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	files := 0
	for _, u := range unitsOf(t, e.out) {
		if u.Entry == "sessions" && u.Kind == manifest.KindFile {
			files++
		}
	}
	if files != 50000 {
		t.Fatalf("per-file rows = %d, want 50000", files)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

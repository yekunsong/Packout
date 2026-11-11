package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packout/internal/manifest"
	"packout/internal/profile"
)

const selectConfigEntry = `{
      "id":"settings-global","selftest_exempt":"test","kind":"file","root":"home",
      "path":".claude/settings.json","layer":"L2","secret":"none","extractor":"raw-ref",
      "signals":[{"src":"observed_behavior","note":"settings"}]},
    `

const selectSkillsEntry = `{
      "id":"skills","selftest_exempt":"test","kind":"dir","root":"home",
      "path":".claude/skills","layer":"L3","secret":"none","extractor":"raw-ref",
      "signals":[{"src":"observed_behavior","note":"skills"}]},
    `

// selectSessionsEntry is a sessions glob for two projects.
const selectSessionsEntry = `{
      "id":"projects-transcripts","selftest_exempt":"test","kind":"glob-group","root":"home",
      "paths":[".claude/projects/*/session-*.jsonl"],
      "layer":"L3","secret":"none","extractor":"digest","sessions":true,
      "max_bytes_inline":0,"max_bytes_total":1048576,
      "signals":[{"src":"observed_behavior","note":"transcripts"}]},
    `

func selectEnv(t *testing.T) *env {
	t.Helper()
	e := setup(t, selectConfigEntry+selectSkillsEntry+selectSessionsEntry+memoryEntry+catchHome)
	e.write("home/.claude/settings.json", "{}\n")
	e.write("home/.claude/skills/skill-a/SKILL.md", "# skill\n")
	e.write("home/.claude/projects/D--alpha/memory/MEMORY.md", "# memory\n")
	e.write("home/.claude/projects/D--alpha/session-old.jsonl", "{}\n")
	e.write("home/.claude/projects/D--alpha/session-new.jsonl", "{}\n")
	e.write("home/.claude/projects/D--beta/session-beta.jsonl", "{}\n")
	return e
}

func runSelect(t *testing.T, e *env, preset, include, exclude, since string, projects []string, max int, withSessions bool) *Result {
	t.Helper()
	sel, err := profile.ParseSelection(e.prof, preset, include, exclude, since, projects, max, withSessions)
	if err != nil {
		t.Fatalf("ParseSelection: %v", err)
	}
	cfg := e.cfg()
	cfg.Selection = sel
	cfg.WithSessions = withSessions || sel.CarriesSessions()
	res, err := Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func skippedNotes(t *testing.T, out, entry string) []manifest.Note {
	t.Helper()
	m, err := manifest.ReadManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []manifest.Note
	for _, n := range m.Notes {
		if n.Code == "selection_skipped" && (entry == "" || n.Entry == entry) {
			got = append(got, n)
		}
	}
	return got
}

func TestStandardPresetSkipsSessionsOnly(t *testing.T) {
	e := selectEnv(t)
	runSelect(t, e, "", "", "", "", nil, 0, false)
	units := unitsOf(t, e.out)
	if len(byEntry(units, "projects-memory")) == 0 {
		t.Error("standard must carry memory")
	}
	if len(byEntry(units, "skills")) == 0 {
		t.Error("standard must carry skills")
	}
	if got := byEntry(units, "projects-transcripts"); len(got) != 0 {
		t.Errorf("standard carried %d session units", len(got))
	}
	notes := skippedNotes(t, e.out, "projects-transcripts")
	if len(notes) != 1 {
		t.Fatalf("selection_skipped notes for sessions = %d, want exactly 1", len(notes))
	}
	if notes[0].Category != profile.CategorySessions || !strings.Contains(notes[0].Detail, "preset standard") {
		t.Fatalf("note = %+v", notes[0])
	}
	// Every unselected entry is explained exactly once.
	if all := skippedNotes(t, e.out, ""); len(all) != 1 {
		t.Fatalf("skipped entries = %d, want 1", len(all))
	}
}

func TestMinimalPresetDropsMemoryAndSkills(t *testing.T) {
	e := selectEnv(t)
	runSelect(t, e, "minimal", "", "", "", nil, 0, false)
	units := unitsOf(t, e.out)
	for _, entry := range []string{"projects-memory", "skills"} {
		if len(byEntry(units, entry)) != 0 {
			t.Errorf("minimal carried %s", entry)
		}
		if len(skippedNotes(t, e.out, entry)) == 0 {
			t.Errorf("no skip note for %s", entry)
		}
	}
	if len(byEntry(units, "settings-global")) == 0 {
		t.Error("minimal must carry config")
	}
}

func TestIncludeSessionsExcludeSkills(t *testing.T) {
	e := selectEnv(t)
	runSelect(t, e, "", "sessions", "skills", "", nil, 0, false)
	units := unitsOf(t, e.out)
	if len(byEntry(units, "projects-transcripts")) == 0 {
		t.Error("--include sessions did not add session units")
	}
	if len(byEntry(units, "skills")) != 0 {
		t.Error("--exclude skills did not drop skills")
	}
	notes := skippedNotes(t, e.out, "skills")
	if len(notes) != 1 || !strings.Contains(notes[0].Detail, "exclude") {
		t.Fatalf("exclude note = %+v", notes)
	}
}

func TestSessionsSinceFilter(t *testing.T) {
	e := selectEnv(t)
	old := time.Now().Add(-40 * 24 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	for _, p := range []string{
		"home/.claude/projects/D--alpha/session-old.jsonl",
		"home/.claude/projects/D--alpha/session-new.jsonl",
		"home/.claude/projects/D--beta/session-beta.jsonl",
	} {
		if err := os.Chtimes(e.path(p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(e.path("home/.claude/projects/D--alpha/session-new.jsonl"), newer, newer); err != nil {
		t.Fatal(err)
	}
	runSelect(t, e, "full", "", "", "7d", nil, 0, true)
	var got []string
	for _, u := range byEntry(unitsOf(t, e.out), "projects-transcripts") {
		got = append(got, filepath.Base(u.Path))
	}
	if len(got) != 1 || got[0] != "session-new.jsonl" {
		t.Fatalf("since filter kept %v", got)
	}
	notes := skippedNotes(t, e.out, "projects-transcripts")
	if len(notes) != 2 {
		t.Fatalf("since skip notes = %d, want 2", len(notes))
	}
}

func TestSessionsProjectFilter(t *testing.T) {
	e := selectEnv(t)
	runSelect(t, e, "full", "", "", "", []string{"D--alpha"}, 0, true)
	var got []string
	for _, u := range byEntry(unitsOf(t, e.out), "projects-transcripts") {
		got = append(got, filepath.Base(u.Path))
	}
	if len(got) != 2 {
		t.Fatalf("project filter kept %v, want the two alpha sessions", got)
	}
	notes := skippedNotes(t, e.out, "projects-transcripts")
	if len(notes) != 1 || !strings.Contains(notes[0].Detail, "D--beta") {
		t.Fatalf("project skip notes = %+v", notes)
	}
}

func TestSessionsMaxPerProjectKeepsNewest(t *testing.T) {
	e := selectEnv(t)
	old := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(e.path("home/.claude/projects/D--alpha/session-old.jsonl"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(e.path("home/.claude/projects/D--alpha/session-new.jsonl"), newer, newer); err != nil {
		t.Fatal(err)
	}
	runSelect(t, e, "full", "", "", "", nil, 1, true)
	var got []string
	for _, u := range byEntry(unitsOf(t, e.out), "projects-transcripts") {
		got = append(got, filepath.Base(u.Path))
	}
	if len(got) != 2 {
		t.Fatalf("max-per-project kept %v, want one per project", got)
	}
	for _, name := range got {
		if name == "session-old.jsonl" {
			t.Error("max-per-project kept the older alpha session")
		}
	}
	notes := skippedNotes(t, e.out, "projects-transcripts")
	if len(notes) != 1 || !strings.Contains(notes[0].Detail, "max-per-project") {
		t.Fatalf("max skip notes = %+v", notes)
	}
}

func TestHeaderRecordsOnlyNonDefaultSelection(t *testing.T) {
	e := selectEnv(t)
	runSelect(t, e, "", "", "", "", nil, 0, false)
	raw := readRaw(t, e.out)
	opts, _ := raw[0]["inputs"].(map[string]any)["options"].(map[string]any)
	if _, ok := opts["selection"]; ok {
		t.Fatalf("default selection written to header: %v", opts)
	}

	e2 := selectEnv(t)
	runSelect(t, e2, "full", "", "skills", "", nil, 0, true)
	raw = readRaw(t, e2.out)
	opts, _ = raw[0]["inputs"].(map[string]any)["options"].(map[string]any)
	sel, _ := opts["selection"].(map[string]any)
	if sel["preset"] != "full" {
		t.Fatalf("header selection = %v", opts["selection"])
	}
	if opts["with_sessions"] != true {
		t.Fatal("sessions-carrying selection must set with_sessions")
	}
}

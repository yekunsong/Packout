package profile

import (
	"strings"
	"testing"
	"time"
)

func selectTestProfile() *Profile {
	return &Profile{Name: "test", Entries: []*Entry{
		{ID: "settings-global", Kind: KindFile, Path: ".claude/settings.json", Layer: LayerL2},
		{ID: "projects-memory", Kind: KindGlobGroup, Paths: []string{".claude/projects/**/memory/**"}, Layer: LayerL3},
		{ID: "agents-md", Kind: KindFile, Path: ".codex/AGENTS.md", Layer: LayerL2},
		{ID: "projects-transcripts", Kind: KindGlobGroup, Paths: []string{".claude/projects/**/*.jsonl"}, Layer: LayerL3, Sessions: true},
		{ID: "sessions", Kind: KindGlobGroup, Paths: []string{".claude/sessions/**"}, Layer: LayerL0},
		{ID: "skills", Kind: KindDir, Path: ".claude/skills", Layer: LayerL3},
		{ID: "agents", Kind: KindDir, Path: ".claude/agents", Layer: LayerL3},
		{ID: "repo-commands", Kind: KindDir, Path: ".claude/commands", Layer: LayerL2},
		{ID: "repo-rules", Kind: KindGlobGroup, Paths: []string{".claude/rules/**"}, Layer: LayerL2},
		{ID: "history", Kind: KindFile, Path: ".claude/history.jsonl", Layer: LayerL3},
		{ID: "plugins-config", Kind: KindFile, Path: ".claude/plugins/config.json", Layer: LayerL2},
		{ID: "oauth-credential-store", Kind: KindNamedLocation, Layer: LayerL5},
		{ID: "home-residual", Kind: KindCatchAll, Path: ".claude", Layer: LayerL2},
	}}
}

func TestSelectionDefaultsToStandardWithoutSessions(t *testing.T) {
	p := selectTestProfile()
	s := NewSelection()
	if !s.IsDefault() {
		t.Fatal("NewSelection must be the header-omittable default")
	}
	for _, e := range p.Entries {
		ok, _ := s.Included(e)
		want := CategoryOf(e) != CategorySessions
		if ok != want {
			t.Errorf("entry %s included=%v, want %v (category %s)", e.ID, ok, want, CategoryOf(e))
		}
	}
	if s.CarriesSessions() {
		t.Error("standard must not carry sessions")
	}
}

func TestSelectionMinimalOnlyConfig(t *testing.T) {
	p := selectTestProfile()
	s, err := ParseSelection(p, "minimal", "", "", "", nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Entries {
		ok, reason := s.Included(e)
		if ok != (CategoryOf(e) == CategoryConfig) {
			t.Errorf("minimal entry %s included=%v category %s", e.ID, ok, CategoryOf(e))
		}
		if !ok && reason == "" {
			t.Errorf("skipped entry %s has no reason", e.ID)
		}
	}
	// catch-all stays in every preset.
	if ok, _ := s.Included(p.Entries[len(p.Entries)-1]); !ok {
		t.Error("catch-all must survive minimal")
	}
}

func TestSelectionFullIsWithSessionsAlias(t *testing.T) {
	p := selectTestProfile()
	a, err := ParseSelection(p, "", "", "", "", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSelection(p, "full", "", "", "", nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.Preset != PresetFull || b.Preset != PresetFull {
		t.Fatalf("with-sessions preset = %q, want full", a.Preset)
	}
	if !a.CarriesSessions() {
		t.Fatal("--with-sessions must carry sessions")
	}
}

func TestSelectionExplicitPresetWithSessionsDoesNotConflict(t *testing.T) {
	p := selectTestProfile()
	s, err := ParseSelection(p, "minimal", "", "", "", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Preset != PresetMinimal {
		t.Fatalf("preset = %q, want minimal kept", s.Preset)
	}
	ok, _ := s.Included(selectEntry(p, "projects-transcripts"))
	if !ok {
		t.Fatal("with-sessions must add sessions on top of an explicit preset")
	}
}

func TestSelectionIncludeThenExclude(t *testing.T) {
	p := selectTestProfile()
	s, err := ParseSelection(p, "minimal", " sessions , skills, sessions", "skills, L5", "", nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Include) != 2 || s.Include[0] != CategorySessions || s.Include[1] != CategorySkill {
		t.Fatalf("include = %v, want deduped [sessions skill]", s.Include)
	}
	if ok, _ := s.Included(selectEntry(p, "projects-transcripts")); !ok {
		t.Error("include sessions must add session entries")
	}
	if ok, reason := s.Included(selectEntry(p, "skills")); ok || !strings.Contains(reason, "exclude") {
		t.Errorf("exclude must win over include: ok=%v reason=%q", ok, reason)
	}
	if ok, _ := s.Included(selectEntry(p, "oauth-credential-store")); ok {
		t.Error("exclude L5 must drop L5 entries")
	}
	// memory is still excluded by the minimal preset.
	if ok, _ := s.Included(selectEntry(p, "projects-memory")); ok {
		t.Error("minimal preset must not include memory")
	}
}

func TestCategoryFromPaths(t *testing.T) {
	for _, tc := range []struct {
		e    *Entry
		want string
	}{
		{&Entry{ID: "x", Path: ".claude/skills/foo"}, CategorySkill},
		{&Entry{ID: "x", Paths: []string{".claude/agents/*.md"}}, CategoryAgent},
		{&Entry{ID: "x", Path: ".claude/commands"}, CategoryCommand},
		{&Entry{ID: "x", Path: ".claude/plugins/README.md"}, CategoryPlugin},
		{&Entry{ID: "agents-md", Path: ".codex/AGENTS.md"}, CategoryMemory},
		{&Entry{ID: "x", Path: ".claude/settings.json"}, CategoryConfig},
	} {
		if got := CategoryOf(tc.e); got != tc.want {
			t.Errorf("CategoryOf(%s) = %s, want %s", tc.e.ID+"/"+tc.e.Path, got, tc.want)
		}
	}
}

func TestSelectionUnknownValues(t *testing.T) {
	p := selectTestProfile()
	if _, err := ParseSelection(p, "huge", "", "", "", nil, 0, false); err == nil ||
		!strings.Contains(err.Error(), "minimal") {
		t.Fatalf("unknown preset err = %v, want value list", err)
	}
	_, err := ParseSelection(p, "", "nope", "", "", nil, 0, false)
	if err == nil || !strings.Contains(err.Error(), "settings-global") {
		t.Fatalf("unknown element err = %v, want entry id list", err)
	}
	if _, err := ParseSelection(p, "", "", "", "3w", nil, 0, false); err == nil ||
		!strings.Contains(err.Error(), "30d") {
		t.Fatalf("bad since err = %v, want allowed values", err)
	}
	if _, err := ParseSelection(p, "", "", "", "", nil, -1, false); err == nil {
		t.Fatal("negative max must fail")
	}
}

func TestSelectionSince(t *testing.T) {
	p := selectTestProfile()
	s, err := ParseSelection(p, "full", "", "", "7d", []string{"a", "b,a"}, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.SinceDuration(); d != 7*24*time.Hour {
		t.Fatalf("since = %v", d)
	}
	if len(s.SessionsProjects) != 2 || s.SessionsMaxPerProject != 3 {
		t.Fatalf("projects=%v max=%d", s.SessionsProjects, s.SessionsMaxPerProject)
	}
	if s.IsDefault() {
		t.Fatal("a filtered selection must not be treated as default")
	}
}

func TestSelectionMismatches(t *testing.T) {
	p := selectTestProfile()
	s := &Selection{Preset: PresetStandard, Include: []string{CategorySessions, "ghost"}}
	ms := s.Mismatches(p)
	if len(ms) != 1 || !strings.Contains(ms[0], "ghost") {
		t.Fatalf("mismatches = %v", ms)
	}
	empty := &Profile{Name: "empty"}
	found := false
	for _, w := range s.Mismatches(empty) {
		if strings.Contains(w, "ghost") {
			found = true
		}
	}
	if !found {
		t.Errorf("mismatch for ghost not reported on a profile without it: %v", s.Mismatches(empty))
	}
}

func selectEntry(p *Profile, id string) *Entry {
	for _, e := range p.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

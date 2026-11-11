package profile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entry categories used by --include/--exclude (task "预设/包含排除/会话过滤").
// A category is derived from the entry, never written in the profile; entry
// ids and layers are accepted as selector elements too.
const (
	CategoryConfig   = "config"
	CategoryMemory   = "memory"
	CategorySessions = "sessions"
	CategorySkill    = "skill"
	CategoryAgent    = "agent"
	CategoryCommand  = "command"
	CategoryRules    = "rules"
	CategoryHistory  = "history"
	CategoryPlugin   = "plugin"
)

// Presets. minimal carries only configuration, standard adds everything that
// is not session content (the default), full additionally carries sessions.
const (
	PresetMinimal  = "minimal"
	PresetStandard = "standard"
	PresetFull     = "full"
)

// SelectionSinceAll is the canonical --sessions-since value that disables the
// mtime filter.
const SelectionSinceAll = "all"

var categoryOrder = []string{
	CategoryConfig, CategoryMemory, CategorySessions, CategorySkill, CategoryAgent,
	CategoryCommand, CategoryRules, CategoryHistory, CategoryPlugin,
}

// presetCategories is the inclusion set each preset starts from. Categories
// outside every preset (skill, agent, command, rules, history, plugin) are
// only carried when named by --include.
// standard keeps the historical default (everything except session content),
// so only sessions need an explicit --include.
var presetCategories = map[string]map[string]bool{
	PresetMinimal: {CategoryConfig: true},
	PresetStandard: {
		CategoryConfig: true, CategoryMemory: true, CategorySkill: true,
		CategoryAgent: true, CategoryCommand: true, CategoryRules: true,
		CategoryHistory: true, CategoryPlugin: true,
	},
	PresetFull: {
		CategoryConfig: true, CategoryMemory: true, CategorySkill: true,
		CategoryAgent: true, CategoryCommand: true, CategoryRules: true,
		CategoryHistory: true, CategoryPlugin: true, CategorySessions: true,
	},
}

// categoryAliases accepts the plural spellings users naturally type.
var categoryAliases = map[string]string{
	"skills": CategorySkill, "agents": CategoryAgent, "commands": CategoryCommand,
	"plugins": CategoryPlugin, "histories": CategoryHistory,
}

// presets lists the accepted --preset values.
var presets = []string{PresetMinimal, PresetStandard, PresetFull}

// CategoryOf derives the selection category of e. Session-flagged entries and
// session-named ids win; memory is checked before agent so agents-md stays
// memory. Catch-all is configuration: the residual report is part of the
// configuration picture and must survive every preset.
func CategoryOf(e *Entry) string {
	if e == nil {
		return CategoryConfig
	}
	id := strings.ToLower(e.ID)
	if e.Sessions || strings.Contains(id, "session") {
		return CategorySessions
	}
	if strings.Contains(id, "memory") || strings.Contains(id, "claude-md") || strings.HasSuffix(id, "-md") {
		return CategoryMemory
	}
	// Paths are the stable signal; ids are only a fallback for entries whose
	// path lives under a root that does not spell the category.
	for _, c := range []struct{ needle, cat string }{
		{".claude/skills", CategorySkill},
		{".claude/agents", CategoryAgent},
		{".claude/commands", CategoryCommand},
		{"plugins", CategoryPlugin},
	} {
		if entryPathContains(e, c.needle) {
			return c.cat
		}
	}
	for _, c := range []struct{ needle, cat string }{
		{"skill", CategorySkill},
		{"agent", CategoryAgent},
		{"command", CategoryCommand},
		{"rule", CategoryRules},
		{"history", CategoryHistory},
		{"plugin", CategoryPlugin},
	} {
		if strings.Contains(id, c.needle) {
			return c.cat
		}
	}
	return CategoryConfig
}

// entryPathContains reports whether any declared path of e contains needle.
func entryPathContains(e *Entry, needle string) bool {
	check := func(p string) bool {
		return strings.Contains(strings.ReplaceAll(p, "\\", "/"), needle)
	}
	if check(e.Path) {
		return true
	}
	for _, p := range e.Paths {
		if check(p) {
			return true
		}
	}
	return false
}

// Selection is the resolved "what to carry" choice of one scan. It is built by
// ParseSelection (which validates every element against the profile) and
// recorded in the header only when it differs from the default.
type Selection struct {
	Preset                string
	Include               []string
	Exclude               []string
	SessionsSince         string // "all" or "<N>d"
	SessionsProjects      []string
	SessionsMaxPerProject int
}

// UsageError marks a selection problem that must map to exit code 3.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// NewSelection returns the default selection: standard preset, no filters.
func NewSelection() *Selection {
	return &Selection{Preset: PresetStandard, SessionsSince: SelectionSinceAll}
}

// IsDefault reports whether s can be omitted from the header.
func (s *Selection) IsDefault() bool {
	if s == nil {
		return true
	}
	return s.Preset == PresetStandard && len(s.Include) == 0 && len(s.Exclude) == 0 &&
		(s.SessionsSince == "" || s.SessionsSince == SelectionSinceAll) &&
		len(s.SessionsProjects) == 0 && s.SessionsMaxPerProject == 0
}

// WithSessions turns the selection into the documented --with-sessions alias
// of --preset full. A preset already given explicitly is kept and sessions is
// added on top instead, so the two flags do not conflict.
func (s *Selection) WithSessions(explicitPreset bool) {
	if explicitPreset {
		s.Include = appendUnique(s.Include, CategorySessions)
		return
	}
	s.Preset = PresetFull
}

// ParseSelection validates and normalises the raw CLI knobs against p.
func ParseSelection(p *Profile, preset, include, exclude, since string, projects []string, maxPerProject int, withSessions bool) (*Selection, error) {
	s := NewSelection()
	explicit := strings.TrimSpace(preset) != ""
	if explicit {
		v := strings.ToLower(strings.TrimSpace(preset))
		if !containsString(presets, v) {
			return nil, &UsageError{Msg: fmt.Sprintf("未知 preset %q；可用值：%s", preset, strings.Join(presets, ", "))}
		}
		s.Preset = v
	}
	inc, err := splitElements(include)
	if err != nil {
		return nil, err
	}
	s.Include = inc
	exc, err := splitElements(exclude)
	if err != nil {
		return nil, err
	}
	s.Exclude = exc
	if withSessions {
		s.WithSessions(explicit)
	}

	s.SessionsSince = SelectionSinceAll
	if v := strings.TrimSpace(since); v != "" {
		_, canonical, err := parseSince(v)
		if err != nil {
			return nil, err
		}
		s.SessionsSince = canonical
	}
	for _, pjt := range projects {
		for _, v := range strings.Split(pjt, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				s.SessionsProjects = appendUnique(s.SessionsProjects, v)
			}
		}
	}
	if maxPerProject < 0 {
		return nil, &UsageError{Msg: "--sessions-max-per-project 不得为负数"}
	}
	s.SessionsMaxPerProject = maxPerProject

	if err := s.validate(p); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Selection) validate(p *Profile) error {
	avail := availableElements(p)
	for _, group := range [][]string{s.Include, s.Exclude} {
		for _, elem := range group {
			if !matchElementAny(p, elem) {
				return &UsageError{Msg: fmt.Sprintf("未知选择元素 %q；可用值：%s", elem, strings.Join(avail, ", "))}
			}
		}
	}
	return nil
}

// effectivePreset defaults an empty header preset to standard.
func (s *Selection) effectivePreset() string {
	if s.Preset == "" {
		return PresetStandard
	}
	return s.Preset
}

func availableElements(p *Profile) []string {
	var out []string
	for _, e := range p.Entries {
		out = append(out, e.ID)
	}
	out = append(out, categoryOrder...)
	out = append(out, LayerL0, LayerL1, LayerL2, LayerL3, LayerL4, LayerL5)
	sort.Strings(out)
	return dedupeSorted(out)
}

func dedupeSorted(v []string) []string {
	out := v[:0]
	for i, x := range v {
		if i == 0 || v[i-1] != x {
			out = append(out, x)
		}
	}
	return out
}

// MatchElement reports whether elem selects e (entry id, category, or layer).
func MatchElement(e *Entry, elem string) bool {
	elem = normalizeElement(elem)
	if elem == "" {
		return false
	}
	if strings.EqualFold(elem, e.ID) || strings.EqualFold(elem, e.Layer) {
		return true
	}
	return CategoryOf(e) == elem
}

func normalizeElement(elem string) string {
	elem = strings.ToLower(strings.TrimSpace(elem))
	if c, ok := categoryAliases[elem]; ok {
		return c
	}
	return elem
}

func matchElementAny(p *Profile, elem string) bool {
	for _, e := range p.Entries {
		if MatchElement(e, elem) {
			return true
		}
	}
	return false
}

// Included reports whether e is carried and, when it is not, why.
func (s *Selection) Included(e *Entry) (bool, string) {
	if s == nil {
		return true, ""
	}
	cat := CategoryOf(e)
	ok := presetCategories[s.effectivePreset()][cat]
	for _, elem := range s.Include {
		if MatchElement(e, elem) {
			ok = true
			break
		}
	}
	reason := ""
	if !ok {
		reason = fmt.Sprintf("preset %s 未包含类别 %s", s.effectivePreset(), cat)
	}
	for _, elem := range s.Exclude {
		if MatchElement(e, elem) {
			ok = false
			if reason == "" {
				reason = fmt.Sprintf("被 --exclude %s 排除", normalizeElement(elem))
			}
			break
		}
	}
	return ok, reason
}

// CarriesSessions reports whether the selection takes any session content,
// and therefore needs the --with-sessions raw-copy semantics.
func (s *Selection) CarriesSessions() bool {
	if s == nil {
		return false
	}
	cat := presetCategories[s.effectivePreset()]
	if cat[CategorySessions] {
		return true
	}
	for _, elem := range s.Include {
		if elem == CategorySessions {
			return true
		}
	}
	return false
}

// SinceDuration returns the parsed --sessions-since window (0 for all).
func (s *Selection) SinceDuration() time.Duration {
	if s == nil || s.SessionsSince == "" || s.SessionsSince == SelectionSinceAll {
		return 0
	}
	d, _, err := parseSince(s.SessionsSince)
	if err != nil {
		return 0
	}
	return d
}

// Mismatches reports header selection elements that no longer exist in p.
// Export calls this to warn without failing: the package is executed from the
// header, not re-selected.
func (s *Selection) Mismatches(p *Profile) []string {
	if s == nil || p == nil {
		return nil
	}
	var out []string
	if _, ok := presetCategories[s.effectivePreset()]; !ok {
		out = append(out, fmt.Sprintf("header preset %q 未知", s.Preset))
	} else {
		for _, cat := range categoryOrder {
			if presetCategories[s.effectivePreset()][cat] && !containsCategory(p, cat) {
				out = append(out, fmt.Sprintf("header preset %s 期望类别 %s，但 profile 中无此类条目", s.effectivePreset(), cat))
			}
		}
	}
	for _, elem := range append(append([]string(nil), s.Include...), s.Exclude...) {
		if !matchElementAny(p, elem) {
			out = append(out, fmt.Sprintf("header 选择元素 %q 在 profile 中无匹配条目", elem))
		}
	}
	return out
}

func containsCategory(p *Profile, cat string) bool {
	for _, e := range p.Entries {
		if CategoryOf(e) == cat {
			return true
		}
	}
	return false
}

func parseSince(v string) (time.Duration, string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == SelectionSinceAll {
		return 0, SelectionSinceAll, nil
	}
	d, ok := strings.CutSuffix(v, "d")
	if !ok {
		return 0, "", &UsageError{Msg: fmt.Sprintf("未知 --sessions-since %q；可用值：7d, 30d, all", v)}
	}
	n, err := strconv.Atoi(d)
	if err != nil || n <= 0 {
		return 0, "", &UsageError{Msg: fmt.Sprintf("未知 --sessions-since %q；按 <N>d 给出天数，或 all", v)}
	}
	return time.Duration(n) * 24 * time.Hour, fmt.Sprintf("%dd", n), nil
}

func splitElements(list string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(list, ",") {
		v := normalizeElement(part)
		if v == "" {
			continue
		}
		out = appendUnique(out, v)
	}
	return out, nil
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

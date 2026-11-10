package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Failure is one failed selftest assertion.
type Failure struct {
	Kind    string // expect | expect_absent | part
	Index   int
	Entry   string
	Part    string
	Root    string
	Match   string
	Message string
}

// Error implements error.
func (f Failure) Error() string {
	var b strings.Builder
	b.WriteString(f.Kind)
	if f.Index >= 0 {
		fmt.Fprintf(&b, "[%d]", f.Index)
	}
	if f.Entry != "" {
		b.WriteString(" entry=")
		b.WriteString(f.Entry)
	}
	if f.Part != "" {
		b.WriteString(" part=")
		b.WriteString(f.Part)
	}
	if f.Root != "" {
		b.WriteString(" root=")
		b.WriteString(f.Root)
	}
	if f.Match != "" {
		fmt.Fprintf(&b, " match=%q", f.Match)
	}
	b.WriteString(": ")
	b.WriteString(f.Message)
	return b.String()
}

// Result is the outcome of a selftest run.
type Result struct {
	Passed   bool
	Checks   int
	Failures []Failure
	Dir      string // set when the caller supplied a workdir
}

// Materialize creates a temporary directory and materializes the profile's
// selftest fixtures into it. The caller owns the directory and should remove
// it when done.
func Materialize(p *Profile) (string, error) {
	dir, err := os.MkdirTemp("", "packout-selftest-")
	if err != nil {
		return "", err
	}
	if err := p.MaterializeTo(dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// MaterializeTo builds the fixture tree described by selftest into dir:
//
//   - selftest.fixtures copies each external directory (relative to the
//     profile) to <dir>/<instance>;
//   - selftest.files creates zero-filled files, dirs creates empty
//     directories and symlinks creates links, all with the instance name as
//     their first path segment;
//   - every created object's mtime is set to selftest.clock.
//
// Only the temporary tree is ever written: source fixtures are read-only
// (spec-profile §6.1).
func (p *Profile) MaterializeTo(dir string) error {
	if p.Selftest == nil {
		return errors.New("profile: selftest is missing")
	}
	if p.fixtureFS == nil {
		return errors.New("profile: no fixture filesystem (loaded from bytes)")
	}
	st := p.Selftest
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	instances := append([]string{}, st.FixtureOrder...)
	if len(instances) == 0 {
		for name := range st.Fixtures {
			instances = append(instances, name)
		}
		sort.Strings(instances)
	}
	for _, inst := range instances {
		src := strings.TrimSuffix(strings.ReplaceAll(st.Fixtures[inst], "\\", "/"), "/")
		if err := copyFixtureTree(p.fixtureFS, src, filepath.Join(dir, inst)); err != nil {
			return fmt.Errorf("profile: fixture %q: %w", inst, err)
		}
	}

	for _, f := range st.Files {
		target, err := materialPath(dir, f.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeZeroFile(target, f.Size); err != nil {
			return err
		}
	}
	for _, d := range st.Dirs {
		target, err := materialPath(dir, d)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
	}
	for _, s := range st.Symlinks {
		target, err := materialPath(dir, s.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(s.Target, target); err != nil && !os.IsExist(err) {
			return fmt.Errorf("profile: symlink %q: %w", s.Path, err)
		}
	}

	if clock, ok := parseClock(st.Clock); ok {
		return touchTree(dir, clock)
	}
	return nil
}

func materialPath(dir, raw string) (string, error) {
	segs, ok := splitRelPath(raw)
	if !ok {
		return "", fmt.Errorf("profile: unsafe selftest path %q", raw)
	}
	target := dir
	for _, seg := range segs {
		target = filepath.Join(target, seg)
	}
	return target, nil
}

func copyFixtureTree(fsys fs.FS, src, dst string) error {
	return fs.WalkDir(fsys, src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, src+"/")
		if rel == p {
			// The fixture root itself.
			return os.MkdirAll(dst, 0o755)
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func writeZeroFile(path string, size int64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func parseClock(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func touchTree(root string, clock time.Time) error {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return err
	}
	// Post-order: touching a directory before creating its children would be
	// undone by the child creation.
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Chtimes(paths[i], clock, clock); err != nil {
			return err
		}
	}
	return nil
}

// RunSelfTest materializes the fixture tree and evaluates every expect /
// expect_absent assertion. Operational failures (bad fixtures, I/O) return an
// error; assertion failures are reported in Result. workdir may be empty, in
// which case a temporary directory is used and removed afterwards.
func RunSelfTest(p *Profile, workdir string) (*Result, error) {
	if p.Selftest == nil {
		return nil, errors.New("profile: selftest is missing")
	}
	owned := false
	if workdir == "" {
		dir, err := os.MkdirTemp("", "packout-selftest-")
		if err != nil {
			return nil, err
		}
		workdir = dir
		owned = true
	} else if err := os.MkdirAll(workdir, 0o755); err != nil {
		return nil, err
	}
	if owned {
		defer os.RemoveAll(workdir)
	}
	if err := p.MaterializeTo(workdir); err != nil {
		return nil, err
	}
	return p.evaluate(workdir)
}

// --- evaluation ------------------------------------------------------------

type fixturePath struct {
	rel   string
	isDir bool
	abs   string
}

type fixtureInstance struct {
	name  string
	dir   string
	paths []fixturePath
}

func (p *Profile) evaluate(workdir string) (*Result, error) {
	st := p.Selftest
	instances := make(map[string]*fixtureInstance, len(st.Fixtures))
	for _, inst := range st.FixtureOrder {
		fi, err := loadInstance(workdir, inst)
		if err != nil {
			return nil, err
		}
		instances[inst] = fi
	}
	for inst := range st.Fixtures {
		if _, ok := instances[inst]; !ok {
			fi, err := loadInstance(workdir, inst)
			if err != nil {
				return nil, err
			}
			instances[inst] = fi
		}
	}

	res := &Result{Passed: true, Dir: workdir}

	for i, ex := range st.Expect {
		if !osApplies(ex.OS) {
			continue
		}
		res.Checks++
		root, ok := resolveExpectRoot(st, ex)
		if !ok {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect", Index: i, Entry: ex.Entry, Part: ex.Part,
				Root: ex.Root, Match: ex.Match, Message: "expect.root 未绑定",
			})
			continue
		}
		inst := instances[root]
		if inst == nil {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect", Index: i, Entry: ex.Entry, Part: ex.Part,
				Root: root, Match: ex.Match, Message: "fixture 实例不存在",
			})
			continue
		}
		target := p.entryByID(ex.Entry)
		if target == nil {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect", Index: i, Entry: ex.Entry, Root: root,
				Match: ex.Match, Message: "未知 entry",
			})
			continue
		}
		candidates := matchingPaths(inst, ex.Match)
		if len(candidates) == 0 {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect", Index: i, Entry: ex.Entry, Root: root,
				Match: ex.Match, Message: "fixture 中没有任何路径匹配",
			})
			continue
		}
		winners := 0
		for _, fp := range candidates {
			if !containsEntry(p.resolvePath(root, fp), target) {
				continue
			}
			winners++
			if msg := p.checkExpect(ex, target, root, fp, inst); msg != "" {
				res.Failures = append(res.Failures, Failure{
					Kind: "expect", Index: i, Entry: ex.Entry, Part: ex.Part,
					Root: root, Match: ex.Match, Message: msg,
				})
			}
		}
		if winners == 0 {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect", Index: i, Entry: ex.Entry, Root: root,
				Match: ex.Match, Message: "entry 未赢得该路径（被优先级或 catch-all 排除）",
			})
		}
	}

	for i, ab := range st.ExpectAbsent {
		res.Checks++
		root, ok := resolveExpectRootAbsent(st, ab)
		if !ok {
			res.Failures = append(res.Failures, Failure{
				Kind: "expect_absent", Index: i, Root: ab.Root, Match: ab.Match,
				Message: "expect_absent.root 未绑定",
			})
			continue
		}
		inst := instances[root]
		if inst == nil {
			continue
		}
		for _, fp := range matchingPaths(inst, ab.Match) {
			if defaultExcluded(fp.rel) {
				continue
			}
			if len(p.resolvePath(root, fp)) > 0 {
				res.Failures = append(res.Failures, Failure{
					Kind: "expect_absent", Index: i, Root: root, Match: ab.Match,
					Message: "本应不存在却会被产出为 Unit: " + fp.rel,
				})
			}
		}
	}

	res.Passed = len(res.Failures) == 0
	return res, nil
}

func loadInstance(workdir, inst string) (*fixtureInstance, error) {
	fi := &fixtureInstance{name: inst, dir: filepath.Join(workdir, inst)}
	err := filepath.WalkDir(fi.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == fi.dir {
			return nil
		}
		rel, err := filepath.Rel(fi.dir, p)
		if err != nil {
			return err
		}
		fi.paths = append(fi.paths, fixturePath{
			rel:   filepath.ToSlash(rel),
			isDir: d.IsDir(),
			abs:   p,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(fi.paths, func(i, j int) bool { return fi.paths[i].rel < fi.paths[j].rel })
	return fi, nil
}

func matchingPaths(inst *fixtureInstance, pattern string) []fixturePath {
	var out []fixturePath
	for _, fp := range inst.paths {
		if matchGlob(pattern, fp.rel) {
			out = append(out, fp)
		}
	}
	return out
}

func resolveExpectRoot(st *SelfTest, ex Expect) (string, bool) {
	if ex.Root != "" {
		if _, ok := st.Fixtures[ex.Root]; ok {
			return ex.Root, true
		}
		return "", false
	}
	first := ex.Match
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if _, ok := st.Fixtures[first]; ok {
		return first, true
	}
	return "", false
}

func resolveExpectRootAbsent(st *SelfTest, ab Absent) (string, bool) {
	if ab.Root != "" {
		if _, ok := st.Fixtures[ab.Root]; ok {
			return ab.Root, true
		}
		return "", false
	}
	first := ab.Match
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	if _, ok := st.Fixtures[first]; ok {
		return first, true
	}
	return "", false
}

func (p *Profile) entryByID(id string) *Entry {
	for _, e := range p.Entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func containsEntry(list []*Entry, e *Entry) bool {
	for _, x := range list {
		if x == e {
			return true
		}
	}
	return false
}

// resolvePath implements the winner selection of spec-profile §5.2.1:
// highest priority, then selector specificity; a tie keeps all winners. A
// catch-all only participates when no non-catch-all entry matched.
func (p *Profile) resolvePath(inst string, fp fixturePath) []*Entry {
	var regular, catches []*Entry
	for _, e := range p.Entries {
		if !entryOSApplies(e) {
			continue
		}
		if e.Kind == KindCatchAll {
			if p.catchAllCovers(e, inst, fp.rel) {
				catches = append(catches, e)
			}
			continue
		}
		if p.entryMatches(e, inst, fp.rel, fp.isDir) {
			regular = append(regular, e)
		}
	}
	if len(regular) > 0 {
		return maximalEntries(regular)
	}
	if len(catches) == 0 {
		return nil
	}
	sort.SliceStable(catches, func(i, j int) bool {
		return len(strings.Trim(catches[i].Under, "/")) > len(strings.Trim(catches[j].Under, "/"))
	})
	return catches[:1]
}

func entryOSApplies(e *Entry) bool {
	if len(e.OS) == 0 {
		return true
	}
	for _, o := range e.OS {
		if o == runtime.GOOS {
			return true
		}
	}
	return false
}

func (p *Profile) catchAllCovers(e *Entry, inst, rel string) bool {
	if e.Root != inst {
		return false
	}
	scope := e.Scope
	if scope == "" {
		scope = ScopeRoot
	}
	if scope == ScopeSubtree {
		return pathWithinDir(e.Under, rel)
	}
	for _, o := range p.Entries {
		if o == e || o.Kind != KindCatchAll || o.Root != inst {
			continue
		}
		s := o.Scope
		if s == "" {
			s = ScopeRoot
		}
		if s == ScopeSubtree && pathWithinDir(o.Under, rel) {
			return false
		}
	}
	return true
}

func (p *Profile) entryMatches(e *Entry, inst, rel string, isDir bool) bool {
	if e.Root != "" && e.Root != inst {
		return false
	}
	switch e.Kind {
	case KindFile:
		if e.Root == "" && isAbsTemplateValue(e.Path) {
			return absEntryMatches(e.Path, rel)
		}
		return strings.Trim(strings.ReplaceAll(e.Path, "\\", "/"), "/") == rel
	case KindDir:
		if e.Root == "" && isAbsTemplateValue(e.Path) {
			return false
		}
		return pathWithinDir(e.Path, rel)
	case KindGlobGroup:
		for _, pat := range e.Paths {
			if isAbsTemplateValue(pat) {
				if absEntryMatches(pat, rel) {
					return true
				}
				continue
			}
			if matchGlob(pat, rel) {
				return true
			}
		}
	case KindNamedLocation:
		loc, ok := e.Locator.ForOS(runtime.GOOS)
		if !ok || !strings.HasPrefix(loc, "file:") {
			return false
		}
		lp := strings.TrimPrefix(loc, "file:")
		lp = expandHomeToEmpty(lp)
		return strings.Trim(strings.ReplaceAll(lp, "\\", "/"), "/") == rel
	}
	return false
}

// absEntryMatches relates an absolute entry path to a fixture-relative path by
// expanding $HOME-like variables to the empty string; no built-in profile uses
// absolute entries, this keeps selftests expressible for user profiles.
func absEntryMatches(entryPath, rel string) bool {
	p := expandHomeToEmpty(entryPath)
	p = strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/")
	return p == rel
}

var homeVarRE = regexp.MustCompile(`\$\{HOME\}|\$HOME|%USERPROFILE%|%HOME%`)

func expandHomeToEmpty(p string) string { return homeVarRE.ReplaceAllString(p, "") }

func maximalEntries(cands []*Entry) []*Entry {
	best := cands[0]
	for _, e := range cands[1:] {
		if compareEntry(e, best) > 0 {
			best = e
		}
	}
	out := make([]*Entry, 0, len(cands))
	for _, e := range cands {
		if compareEntry(e, best) == 0 {
			out = append(out, e)
		}
	}
	return out
}

func compareEntry(a, b *Entry) int {
	if a.Priority != b.Priority {
		if a.Priority > b.Priority {
			return 1
		}
		return -1
	}
	sa, sb := selectorSpecificity(a), selectorSpecificity(b)
	if sa != sb {
		if sa > sb {
			return 1
		}
		return -1
	}
	return 0
}

// selectorSpecificity orders selectors: literal paths beat globs; among globs
// more literal segments, then a longer pattern, are more specific.
func selectorSpecificity(e *Entry) int {
	score := 0
	switch e.Kind {
	case KindFile, KindDir:
		score += 100000
	case KindGlobGroup:
		for _, p := range e.Paths {
			score += literalSegments(p)*1000 + len(p)
		}
	case KindNamedLocation:
		score += 100000
	}
	return score
}

func literalSegments(pattern string) int {
	n := 0
	for _, seg := range splitSlash(pattern) {
		if !containsGlob(seg) {
			n++
		}
	}
	return n
}

// --- assertion checking ----------------------------------------------------

func (p *Profile) checkExpect(ex Expect, e *Entry, root string, fp fixturePath, inst *fixtureInstance) string {
	var part *Part
	if ex.Part != "" {
		part = findPart(e, ex.Part)
		if part == nil {
			return "entry 没有该 part"
		}
		if !selectorPresent(part, fp.abs) {
			return "part selector 在文件中未命中"
		}
	}
	layer := p.effectiveLayer(e, part, inst)
	secret := e.Secret
	extractor := e.Extractor
	if part != nil {
		if part.Secret != "" {
			secret = part.Secret
		}
		if part.Extractor != "" {
			extractor = part.Extractor
		}
	}
	_ = extractor
	if ex.Layer != "" && ex.Layer != layer {
		return fmt.Sprintf("layer: 期望 %s，实际 %s", ex.Layer, layer)
	}
	if ex.Secret != "" && ex.Secret != secret {
		return fmt.Sprintf("secret: 期望 %s，实际 %s", ex.Secret, secret)
	}
	action := actionFor(layer, secret)
	if ex.Action != "" && ex.Action != action {
		return fmt.Sprintf("action: 期望 %s，实际 %s", ex.Action, action)
	}
	flags := p.riskFlags(e, part, layer, fp)
	if missing := missingFlags(ex.RiskFlags, flags); len(missing) > 0 {
		return fmt.Sprintf("risk_flags: 缺少 %v（实际 %v）", missing, flags)
	}
	confidence := 1.0
	if e.Kind == KindCatchAll {
		confidence = 0.5
	}
	if ex.Confidence != nil && *ex.Confidence != confidence {
		return fmt.Sprintf("confidence: 期望 %v，实际 %v", *ex.Confidence, confidence)
	}
	return ""
}

func (p *Profile) effectiveLayer(e *Entry, part *Part, inst *fixtureInstance) string {
	if part != nil && part.Layer != "" {
		return part.Layer
	}
	layer := e.Layer
	if e.UniqueWithin == "root" {
		count := 0
		for _, fp := range inst.paths {
			if p.entryMatches(e, inst.name, fp.rel, fp.isDir) {
				count++
			}
		}
		if count == 1 {
			return LayerL3
		}
	}
	return layer
}

func actionFor(layer, secret string) string {
	if secret == SecretRelogin {
		return "relogin"
	}
	switch layer {
	case LayerL0:
		return "delete"
	case LayerL1:
		return "reinstall"
	case LayerL5:
		return "relogin"
	default:
		return "keep"
	}
}

func (p *Profile) riskFlags(e *Entry, part *Part, layer string, fp fixturePath) []string {
	var flags []string
	if e.OpaqueContent {
		flags = append(flags, "opaque_content")
	}
	semantics := e.PathSemantics
	if part != nil && part.PathSemantics != "" {
		semantics = part.PathSemantics
	}
	if semantics == PathMachineDerived {
		flags = append(flags, "machine_derived_path")
	}
	if p.EffectiveExpand(e) == "aggregate" {
		flags = append(flags, "aggregated")
	}
	if layer == LayerL0 && len(e.NeededBy) > 0 {
		flags = append(flags, "deletion_cost")
	}
	if e.Kind == KindCatchAll {
		flags = append(flags, "residual", "low_confidence")
	}
	if fi, err := os.Lstat(fp.abs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		flags = append(flags, "symlink")
	}
	return flags
}

func missingFlags(want, have []string) []string {
	set := make(map[string]bool, len(have))
	for _, f := range have {
		set[f] = true
	}
	var missing []string
	for _, f := range want {
		if !set[f] {
			missing = append(missing, f)
		}
	}
	return missing
}

// --- part selector presence ------------------------------------------------

func selectorPresent(part *Part, file string) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	switch part.Selector.Kind {
	case "json_pointer":
		return jsonPointerPresent(data, part.Selector.Value)
	case "line_pattern":
		re, err := regexp.Compile(part.Selector.Value)
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if re.MatchString(strings.TrimSuffix(line, "\r")) {
				return true
			}
		}
		return false
	case "toml_section":
		return tomlSectionPresent(data, part.Selector.Value)
	}
	return false
}

func jsonPointerPresent(data []byte, pointer string) bool {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return false
	}
	if pointer == "" {
		return true
	}
	return pointerWalk(root, strings.Split(strings.TrimPrefix(pointer, "/"), "/"))
}

func pointerWalk(v any, segs []string) bool {
	if len(segs) == 0 {
		return true
	}
	seg := strings.ReplaceAll(strings.ReplaceAll(segs[0], "~1", "/"), "~0", "~")
	switch x := v.(type) {
	case map[string]any:
		if seg == "*" {
			for _, child := range x {
				if pointerWalk(child, segs[1:]) {
					return true
				}
			}
			return false
		}
		child, ok := x[seg]
		if !ok {
			return false
		}
		return pointerWalk(child, segs[1:])
	case []any:
		if seg == "*" {
			for _, child := range x {
				if pointerWalk(child, segs[1:]) {
					return true
				}
			}
			return false
		}
		idx, err := strconv.Atoi(seg)
		if err != nil || idx < 0 || idx >= len(x) {
			return false
		}
		return pointerWalk(x[idx], segs[1:])
	}
	return false
}

func tomlSectionPresent(data []byte, section string) bool {
	want := splitTOMLKey(section)
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if !strings.HasPrefix(t, "[") || strings.HasPrefix(t, "[[") {
			continue
		}
		end := strings.LastIndexByte(t, ']')
		if end < 0 {
			continue
		}
		got := splitTOMLKey(t[1:end])
		if len(got) != len(want) {
			continue
		}
		ok := true
		for i := range got {
			if want[i] != "*" && got[i] != want[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// splitTOMLKey splits a dotted TOML key path, respecting quoted segments.
func splitTOMLKey(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		seg := strings.TrimSpace(cur.String())
		seg = strings.Trim(seg, `'"`)
		out = append(out, seg)
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case '.':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

package profile

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"packout/internal/fsx"
)

var (
	validKinds = map[string]bool{
		KindFile: true, KindDir: true, KindGlobGroup: true,
		KindNamedLocation: true, KindCatchAll: true,
	}
	validLayers = map[string]bool{
		LayerL0: true, LayerL1: true, LayerL2: true,
		LayerL3: true, LayerL4: true, LayerL5: true,
	}
	validSecrets = map[string]bool{
		SecretNone: true, SecretScan: true, SecretReference: true,
		SecretRestore: true, SecretRelogin: true,
	}
	validExtractors = map[string]bool{
		ExtractorNone: true, ExtractorRawRef: true, ExtractorTemplate: true,
		ExtractorKeysOnly: true, ExtractorDigest: true,
	}
	validOS            = map[string]bool{"windows": true, "darwin": true, "linux": true}
	validScans         = map[string]bool{"default": true, "strict": true}
	validExpands       = map[string]bool{"per-file": true, "aggregate": true}
	validChurns        = map[string]bool{"low": true, "high": true}
	validPathSemantics = map[string]bool{
		PathLiteral: true, PathMachineDerived: true,
	}
	validDerivedFrom = map[string]bool{
		DerivedRepoSlug: true, DerivedGitWorktree: true, DerivedJSONPathKey: true,
	}
	validNeededBy = map[string]bool{
		"rewind": true, "statusline": true, "resume": true,
		"mcp": true, "daemon": true, "plugins": true,
	}
	validSideEffects = map[string]bool{"shm_created": true}
	validOpenAs      = map[string]bool{
		OpenAsNone: true, OpenAsText: true, OpenAsSQLiteRO: true,
	}
	validSignalSrc = map[string]bool{
		"official_docs": true, "observed_behavior": true,
		"repository_practice": true, "file_format": true, "vendor_policy": true,
	}
	validScope          = map[string]bool{ScopeRoot: true, ScopeSubtree: true}
	validPartsUncovered = map[string]bool{
		"keep": true, "note": true, "residual": true,
	}
	schemeProbe = map[string]string{
		"keychain": "keychain",
		"wincred":  "wincred",
		"env":      "env",
		"registry": "registry",
		"file":     "file-probe",
	}
)

var (
	nameRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	companionRE = regexp.MustCompile(`^-[A-Za-z0-9.]{1,15}$`)
)

// Validate runs the full spec-profile §9 rule set. Loading reports every
// attributable error instead of stopping at the first.
func Validate(p *Profile) error {
	v := &validator{p: p}
	v.profile()
	v.roots()
	v.entries()
	v.selftest()
	if len(v.errs) > 0 {
		return v.errs
	}
	p.Warnings = append(p.Warnings, v.warns...)
	return nil
}

type validator struct {
	p     *Profile
	errs  Errors
	warns Warnings
}

func (v *validator) errf(code string, pos Position, subject, format string, args ...any) {
	v.errs = append(v.errs, &Error{
		Code: code, File: v.p.File, Pos: pos, Subject: subject,
		Message: fmt.Sprintf(format, args...),
	})
}

func (v *validator) warnf(code string, pos Position, subject, format string, args ...any) {
	v.warns = append(v.warns, &Warning{
		Code: code, File: v.p.File, Pos: pos, Subject: subject,
		Message: fmt.Sprintf(format, args...),
	})
}

// --- profile-level ---------------------------------------------------------

func (v *validator) profile() {
	p := v.p

	if p.SchemaVersion == "" {
		v.errf("E-PRF-001", p.Defaults.Pos, "profile", "缺少 schema_version")
	} else {
		parts := strings.SplitN(p.SchemaVersion, ".", 2)
		if len(parts) != 2 || parts[0] != SchemaMajor {
			v.errf("E-PRF-002", Position{}, "profile",
				"不支持的 schema_version %q（本引擎支持 MAJOR %s）", p.SchemaVersion, SchemaMajor)
		}
	}
	if !nameRE.MatchString(p.Name) {
		v.errf("E-PRF-003", p.Defaults.Pos, "profile", "name 不合法: %q", p.Name)
	}
	if p.Title == "" {
		v.errf("E-PRF-063", p.Defaults.Pos, "profile", "缺少 title")
	}
	if len(p.AppliesTo.OS) == 0 {
		v.warnf("W-PRF-103", Position{}, "applies_to.os", "os 为空：仅 named-location 的 os 限定生效")
	}
	for _, osName := range p.AppliesTo.OS {
		if !validOS[osName] {
			v.warnf("W-PRF-102", Position{}, "applies_to.os", "未知 OS %q（降级）", osName)
		}
	}
	if p.MaxBytesTotal <= 0 || p.MaxBytesTotal > MaxBytesTotalCap {
		v.errf("E-PRF-062", Position{}, "profile",
			"max_bytes_total 必须在 1..%d 之间，实际 %d", MaxBytesTotalCap, p.MaxBytesTotal)
	}
	if p.Scan != "" && !validScans[p.Scan] {
		v.warnf("W-PRF-102", Position{}, "profile", "未知 scan %q（按 default 处理）", p.Scan)
	}
	if strings.Contains(p.Notes, "TODO verify") {
		v.warnf("W-PRF-121", Position{}, "profile", "notes 含 TODO verify，必须替换为 signal 或明确说明")
	}

	v.checkBudgets(nil, nil, "defaults", p.Defaults.Pos,
		p.Defaults.MaxBytesInline, p.Defaults.MaxBytesStructure, p.Defaults.MaxBytesTotal)
	if p.Defaults.MaxDepth != nil && (*p.Defaults.MaxDepth < 1 || *p.Defaults.MaxDepth > MaxDepthCap) {
		v.errf("E-PRF-014", p.Defaults.Pos, "defaults", "max_depth 必须在 1..64 之间")
	}
	if p.Defaults.Expand != "" && !validExpands[p.Defaults.Expand] {
		v.warnf("W-PRF-102", p.Defaults.Pos, "defaults", "未知 expand %q", p.Defaults.Expand)
	}
	if p.Defaults.Scan != "" && !validScans[p.Defaults.Scan] {
		v.warnf("W-PRF-102", p.Defaults.Pos, "defaults", "未知 scan %q", p.Defaults.Scan)
	}
	for _, ex := range p.Defaults.Exclude {
		if filepathIsAbsTemplate(ex) {
			v.warnf("W-PRF-104", p.Defaults.Pos, "defaults", "exclude 含绝对路径 %q", ex)
		}
	}
}

func (v *validator) roots() {
	if len(v.p.Roots) == 0 {
		v.errf("E-PRF-030", Position{}, "roots", "profile 必须至少声明一个 root")
		return
	}
	names := append([]string{}, v.p.RootOrder...)
	if len(names) == 0 {
		for name := range v.p.Roots {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	for _, name := range names {
		r := v.p.Roots[name]
		subj := "root " + name
		if r.PerOS != nil {
			for osName, tmpl := range r.PerOS {
				if !validOS[osName] {
					v.warnf("W-PRF-102", r.Pos, subj, "未知 OS %q", osName)
				}
				v.checkRootTemplate(tmpl, r.Pos, subj+" ("+osName+")")
			}
		} else {
			v.checkRootTemplate(r.Template, r.Pos, subj)
		}
	}
}

func (v *validator) checkRootTemplate(tmpl string, pos Position, subject string) {
	if tmpl == "" {
		v.errf("E-PRF-030", pos, subject, "root 模板为空，展开后不是绝对路径")
		return
	}
	if strings.ContainsAny(tmpl, "$%") {
		// Contains a variable and cannot be judged without the scan-time
		// environment; expansion errors are reported by the scanner (E-PRF-030).
		return
	}
	if !filepathIsAbsTemplate(tmpl) {
		v.errf("E-PRF-030", pos, subject, "root 展开后不是绝对路径: %q", tmpl)
	}
}

// --- entries ---------------------------------------------------------------

func (v *validator) entries() {
	ids := make(map[string]int)
	selectors := make(map[string]struct {
		priority int
		id       string
	})

	for i, e := range v.p.Entries {
		subj := entrySubject(i, e.ID)
		if e.Kind == KindCatchAll {
			if e.Layer == "" {
				e.Layer = LayerL2
			}
			if e.Secret == "" {
				e.Secret = SecretNone
			}
			if e.Extractor == "" {
				e.Extractor = ExtractorNone
			}
		}

		if e.ID == "" || !nameRE.MatchString(e.ID) {
			v.errf("E-PRF-063", e.Pos, subj, "id 不合法或缺失: %q", e.ID)
		} else if first, dup := ids[e.ID]; dup {
			v.errf("E-PRF-004", e.Pos, subj, "id 重复（首条为 entries[%d]）", first)
		} else {
			ids[e.ID] = i
		}

		if !validKinds[e.Kind] {
			v.errf("E-PRF-005", e.Pos, subj, "未知 kind %q，整份 profile 拒绝加载", e.Kind)
			continue
		}
		if !validLayers[e.Layer] {
			v.errf("E-PRF-006", e.Pos, subj, "layer 非法: %q", e.Layer)
		}
		if !validSecrets[e.Secret] {
			v.errf("E-PRF-007", e.Pos, subj, "secret 非法: %q", e.Secret)
		}
		if !validExtractors[e.Extractor] {
			v.errf("E-PRF-008", e.Pos, subj, "extractor 非法: %q", e.Extractor)
		}

		v.checkKindAndPath(e, subj)
		v.checkRootRef(e, subj)
		v.checkSignals(e, subj)
		if e.Priority < -1000 || e.Priority > 1000 {
			v.errf("E-PRF-046", e.Pos, subj, "priority 越界: %d", e.Priority)
		}
		v.checkBudgets(e, nil, subj, e.Pos, e.MaxBytesInline, e.MaxBytesStructure, e.MaxBytesTotal)
		v.checkExpandAndDepth(e, subj)
		v.checkCompanions(e, subj)
		v.checkOpenAs(e, subj)
		v.checkRedact(e, nil, e.Redact, e.Extractor, subj)
		v.checkSecretLayer(e, nil, subj)
		v.checkPathSemantics(e, nil, e.PathSemantics, e.DerivedFrom, e.Path, nil, nil, subj)
		v.checkParts(e, subj)
		v.checkCatchAll(e, subj)
		v.checkUniqueWithin(e, subj)
		v.checkPriorityConflict(e, subj, selectors)

		for _, nb := range e.NeededBy {
			if !validNeededBy[nb] {
				v.warnf("W-PRF-123", e.Pos, subj, "未知 needed_by %q（降级 unknown_enum）", nb)
			}
		}
		for _, ex := range e.Exclude {
			if filepathIsAbsTemplate(ex) {
				v.warnf("W-PRF-104", e.Pos, subj, "exclude 含绝对路径 %q", ex)
			}
		}
		if strings.Contains(e.Notes, "TODO verify") {
			v.warnf("W-PRF-121", e.Pos, subj, "notes 含 TODO verify")
		}
		if (e.Layer == LayerL3 || e.Layer == LayerL5) && e.Extractor == ExtractorNone {
			v.warnf("W-PRF-130", e.Pos, subj, "%s 条目的 extractor 为 none", e.Layer)
		}
	}

	v.checkCatchAllScopes()
}

func (v *validator) checkKindAndPath(e *Entry, subj string) {
	switch e.Kind {
	case KindFile, KindDir:
		if !e.PathSet || e.Path == "" {
			v.errf("E-PRF-009", e.Pos, subj, "kind %s 缺少 path", e.Kind)
		} else {
			if containsGlob(e.Path) {
				v.errf("E-PRF-010", e.Pos, subj, "kind %s 的 path 不得含 glob: %q", e.Kind, e.Path)
			}
			v.checkRelativeOrAbsolute(e.Path, e.Pos, subj)
		}
	case KindGlobGroup:
		if !e.PathsSet || len(e.Paths) == 0 {
			v.errf("E-PRF-009", e.Pos, subj, "glob-group 缺少 paths")
		}
		for _, p := range e.Paths {
			if p == "" {
				v.errf("E-PRF-012", e.Pos, subj, "paths 不得含空串")
				continue
			}
			v.checkRelativeOrAbsolute(p, e.Pos, subj)
		}
	case KindNamedLocation:
		if e.Locator.Value == "" && len(e.Locator.PerOS) == 0 {
			v.errf("E-PRF-009", e.Pos, subj, "named-location 缺少 locator")
		}
		v.checkProbe(e, subj)
	case KindCatchAll:
		if e.PathSet || e.PathsSet {
			v.errf("E-PRF-037", e.Pos, subj, "catch-all 不得写 path/paths")
		}
	}
}

func (v *validator) checkRelativeOrAbsolute(p string, pos Position, subj string) {
	if filepathIsAbsTemplate(p) || strings.HasPrefix(p, "$") || strings.HasPrefix(p, "%") {
		if containsGlob(p) {
			v.errf("E-PRF-010", pos, subj, "绝对路径不得含 glob: %q", p)
		}
		if hasDotDot(p) {
			v.errf("E-PRF-012", pos, subj, "绝对路径不得含 ..: %q", p)
		}
		return
	}
	if hasDotDot(p) {
		v.errf("E-PRF-012", pos, subj, "相对路径不得含 ..: %q", p)
	}
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func isReservedRoot(name string) bool {
	return name == "appdata" || name == "localappdata"
}

func baseRole(name string) string {
	if i := strings.IndexByte(name, '#'); i >= 0 {
		return name[:i]
	}
	return name
}

func (v *validator) rootDeclared(name string) bool {
	if _, ok := v.p.Roots[name]; ok {
		return true
	}
	role := baseRole(name)
	if _, ok := v.p.Roots[role]; ok {
		return true
	}
	return isReservedRoot(role)
}

func (v *validator) checkRootRef(e *Entry, subj string) {
	if e.Kind != KindCatchAll {
		abs := (e.PathSet && isAbsTemplateValue(e.Path)) || allAbsPaths(e.Paths)
		if e.Root == "" {
			if e.Kind != KindNamedLocation && !abs {
				v.errf("E-PRF-011", e.Pos, subj, "缺少 root")
			}
			return
		}
	}
	if e.Root != "" && !v.rootDeclared(e.Root) {
		v.errf("E-PRF-011", e.Pos, subj, "引用未声明的 root %q", e.Root)
		return
	}
	// Absolute path entries that also name a root must stay inside it
	// (E-PRF-059).
	if e.Root == "" {
		return
	}
	role := baseRole(e.Root)
	r, ok := v.p.Roots[role]
	if !ok {
		return
	}
	rootTmpl := r.ForOS(runtime.GOOS)
	if rootTmpl == "" {
		return
	}
	expandedRoot := expandTemplate(rootTmpl)
	if !filepathIsAbsTemplate(expandedRoot) {
		return
	}
	check := func(p string) {
		if p == "" || !isAbsTemplateValue(p) {
			return
		}
		expanded := expandTemplate(p)
		if filepathIsAbsTemplate(expanded) && !fsx.Within(expandedRoot, expanded) {
			v.errf("E-PRF-059", e.Pos, subj, "绝对路径 %q 不在 root %q 之内", p, e.Root)
		}
	}
	check(e.Path)
	for _, p := range e.Paths {
		check(p)
	}
}

func isAbsTemplateValue(s string) bool {
	return filepathIsAbsTemplate(s) || strings.HasPrefix(s, "$") || strings.HasPrefix(s, "%")
}

func allAbsPaths(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		if !isAbsTemplateValue(p) {
			return false
		}
	}
	return true
}

func (v *validator) checkSignals(e *Entry, subj string) {
	if e.Kind != KindCatchAll && len(e.Signals) == 0 {
		v.errf("E-PRF-015", e.Pos, subj, "signals 不得为空（catch-all 除外）")
	}
	v.checkSignalList(e.Signals, subj)
}

func (v *validator) checkSignalList(signals []Signal, subj string) {
	for _, s := range signals {
		if strings.TrimSpace(s.Note) == "" {
			v.errf("E-PRF-015", s.Pos, subj, "signal.note 不得为空")
		}
		if s.Src == "official_docs" && s.URL == "" {
			v.errf("E-PRF-016", s.Pos, subj, "official_docs signal 缺少 url")
		}
		if s.Src != "" && !validSignalSrc[s.Src] {
			v.warnf("W-PRF-102", s.Pos, subj, "未知 signal.src %q", s.Src)
		}
	}
}

func (v *validator) checkBudgets(e *Entry, part *Part, subj string, pos Position, inline, structure, total *int64) {
	if inline != nil {
		if *inline < 0 || *inline > MaxBytesInlineCap {
			v.errf("E-PRF-013", pos, subj, "max_bytes_inline 越界: %d", *inline)
		}
		if *inline > 1<<20 {
			v.warnf("W-PRF-111", pos, subj, "max_bytes_inline 大于 1 MiB: %d", *inline)
		}
	}
	if structure != nil && (*structure < 0 || *structure > MaxBytesStructureCap) {
		v.errf("E-PRF-049", pos, subj, "max_bytes_structure 越界: %d", *structure)
	}
	if total != nil {
		if *total <= 0 || *total > v.p.MaxBytesTotal {
			v.errf("E-PRF-052", pos, subj, "max_bytes_total 越界或大于 profile 值: %d", *total)
		}
	}
}

func (v *validator) checkExpandAndDepth(e *Entry, subj string) {
	if e.Expand != "" && !validExpands[e.Expand] {
		v.warnf("W-PRF-102", e.Pos, subj, "未知 expand %q", e.Expand)
	}
	if e.Kind == KindFile && v.p.EffectiveExpand(e) == "aggregate" {
		v.errf("E-PRF-024", e.Pos, subj, "kind: file 不能使用 expand: aggregate")
	}
	if e.MaxDepth != nil && (*e.MaxDepth < 1 || *e.MaxDepth > MaxDepthCap) {
		v.errf("E-PRF-014", e.Pos, subj, "max_depth 必须在 1..64 之间")
	}
	if e.FollowSymlinks != nil && *e.FollowSymlinks {
		if e.MaxDepth == nil && v.p.Defaults.MaxDepth == nil {
			v.errf("E-PRF-022", e.Pos, subj, "follow_symlinks: true 必须显式给 max_depth")
		}
		if v.p.EffectiveMaxDepth(e) > MaxDepthCap {
			v.errf("E-PRF-022", e.Pos, subj, "follow_symlinks: true 时 max_depth 不得大于 64")
		}
	}
	if e.Churn != "" && !validChurns[e.Churn] {
		v.errf("E-PRF-048", e.Pos, subj, "churn 非法: %q", e.Churn)
	}
}

func (v *validator) checkCompanions(e *Entry, subj string) {
	if len(e.Companions) == 0 {
		return
	}
	if e.Kind != KindFile && e.Kind != KindGlobGroup {
		v.errf("E-PRF-044", e.Pos, subj, "companions 只允许用于 file/glob-group")
	}
	seen := make(map[string]bool, len(e.Companions))
	for _, c := range e.Companions {
		if !companionRE.MatchString(c) {
			v.errf("E-PRF-045", e.Pos, subj, "companions 后缀非法: %q", c)
		}
		if seen[c] {
			v.errf("E-PRF-045", e.Pos, subj, "companions 后缀重复: %q", c)
		}
		seen[c] = true
	}
}

func (v *validator) checkOpenAs(e *Entry, subj string) {
	openAs := e.OpenAs
	if openAs == "" {
		openAs = OpenAsNone
	}
	if !validOpenAs[openAs] {
		v.errf("E-PRF-071", e.Pos, subj, "open_as 非法: %q", e.OpenAs)
		return
	}
	if openAs == OpenAsSQLiteRO && e.Kind != KindFile && e.Kind != KindGlobGroup {
		v.errf("E-PRF-071", e.Pos, subj, "open_as: sqlite-ro 只允许用于 file/glob-group")
	}
	for _, se := range e.SideEffects {
		if !validSideEffects[se] {
			v.errf("E-PRF-061", e.Pos, subj, "未知 side_effects %q", se)
			continue
		}
		if se == "shm_created" && openAs != OpenAsSQLiteRO {
			v.errf("E-PRF-071", e.Pos, subj, "side_effects: shm_created 需要 open_as: sqlite-ro")
		}
	}
}

func (v *validator) checkRedact(e *Entry, part *Part, r *Redact, extractor, subj string) {
	if extractor == "" {
		extractor = e.Extractor
	}
	if r != nil && extractor != ExtractorTemplate && extractor != ExtractorKeysOnly {
		v.errf("E-PRF-025", e.Pos, subj, "redact 只能用于 template/keys-only")
	}
	if r == nil && extractor == ExtractorTemplate {
		v.warnf("W-PRF-110", e.Pos, subj, "template 未声明 redact")
	}
}

func (v *validator) checkSecretLayer(e *Entry, part *Part, subj string) {
	layer := e.Layer
	secret := e.Secret
	extractor := e.Extractor
	opaque := e.OpaqueContent
	if part != nil {
		if part.Layer != "" {
			layer = part.Layer
		}
		if part.Secret != "" {
			secret = part.Secret
		}
		if part.Extractor != "" {
			extractor = part.Extractor
		}
	}
	if secret == SecretRelogin && layer != LayerL5 {
		v.errf("E-PRF-040", e.Pos, subj, "secret: relogin 必须搭配 L5（实际 %s）", layer)
	}
	if secret == SecretRestore && layer != LayerL3 {
		v.errf("E-PRF-041", e.Pos, subj, "secret: restore 必须搭配 L3（实际 %s）", layer)
	}
	if secret == SecretScan {
		inline := v.p.EffectiveMaxBytesInline(e, part)
		if (inline <= 0) && !opaque {
			v.errf("E-PRF-042", e.Pos, subj, "secret: scan 需要 max_bytes_inline > 0 或 opaque_content: true")
		}
		if opaque && inline == 0 {
			v.warnf("W-PRF-131", e.Pos, subj, "opaque_content+scan 且预算为 0：只记存在性")
		}
	}
	if secret != SecretNone && extractor == ExtractorRawRef {
		hasRedact := e.Redact != nil
		if part != nil {
			hasRedact = part.Redact != nil || e.Redact != nil
		}
		if !hasRedact {
			v.errf("E-PRF-043", e.Pos, subj, "含密条目使用 raw-ref 且无 redact")
		}
	}
	if e.Scan != "" {
		if !validScans[e.Scan] {
			v.warnf("W-PRF-102", e.Pos, subj, "未知 scan %q（按 default 处理）", e.Scan)
		}
		if secret != SecretScan {
			v.errf("E-PRF-028", e.Pos, subj, "scan 只允许用于 secret: scan 的条目")
		}
	}
}

func (v *validator) checkPathSemantics(e *Entry, part *Part, semantics, derived, entryPath string, origin, originKey *string, subj string) {
	if semantics == "" {
		semantics = PathLiteral
	}
	if !validPathSemantics[semantics] {
		v.warnf("W-PRF-102", e.Pos, subj, "未知 path_semantics %q", semantics)
	}
	if derived != "" && !validDerivedFrom[derived] {
		v.warnf("W-PRF-102", e.Pos, subj, "未知 derived_from %q", derived)
	}
	if semantics == PathMachineDerived && derived == "" {
		v.errf("E-PRF-038", e.Pos, subj, "machine_derived 必须给 derived_from")
	}
	if semantics == PathLiteral && derived != "" {
		v.errf("E-PRF-038", e.Pos, subj, "literal 不得给 derived_from")
	}
	if derived == DerivedGitWorktree && !isWorktreePath(entryPath) {
		v.errf("E-PRF-039", e.Pos, subj, "git_worktree_of 只能用于 .claude/worktrees/ 下的路径")
	}
	if origin != nil || originKey != nil {
		if semantics != PathMachineDerived {
			v.errf("E-PRF-069", e.Pos, subj, "origin 只能出现在 machine_derived 上")
		} else if origin == nil || originKey == nil {
			v.errf("E-PRF-069", e.Pos, subj, "origin_path_key 必须与 origin 同时给出")
		} else if fsx.NormKey(*origin) != *originKey {
			v.errf("E-PRF-069", e.Pos, subj, "origin_path_key 与 origin 的折叠结果不一致")
		}
	}
}

func (v *validator) checkParts(e *Entry, subj string) {
	if !e.PartsSet && e.PartsUncovered != "" {
		v.errf("E-PRF-068", e.Pos, subj, "parts_uncovered 只能用于带 parts 的条目")
	}
	if e.PartsUncovered != "" && !validPartsUncovered[e.PartsUncovered] {
		v.errf("E-PRF-068", e.Pos, subj, "parts_uncovered 非法: %q", e.PartsUncovered)
	}
	if !e.PartsSet {
		return
	}
	if e.Kind != KindFile {
		v.errf("E-PRF-072", e.Pos, subj, "parts 只允许用于 kind: file")
	}
	if len(e.Parts) == 0 {
		v.errf("E-PRF-032", e.Pos, subj, "parts 不得为空")
		return
	}

	selectorKind := ""
	ids := make(map[string]int)
	for i, part := range e.Parts {
		psubj := fmt.Sprintf("%s.parts[%d](%s)", subj, i, part.ID)
		if part.ID == "" || !nameRE.MatchString(part.ID) {
			v.errf("E-PRF-035", part.Pos, psubj, "part id 非法或缺失: %q", part.ID)
		} else if part.ID == PartUncovered {
			v.errf("E-PRF-035", part.Pos, psubj, "part id %q 为保留值", PartUncovered)
		} else if first, dup := ids[part.ID]; dup {
			v.errf("E-PRF-035", part.Pos, psubj, "part id 重复（首条为 parts[%d]）", first)
		} else {
			ids[part.ID] = i
		}
		if selectorKind == "" {
			selectorKind = part.Selector.Kind
		} else if part.Selector.Kind != "" && part.Selector.Kind != selectorKind {
			v.errf("E-PRF-033", part.Pos, psubj, "同一 entry 的 parts 必须使用同一种 selector")
		}

		if part.Layer != "" && !validLayers[part.Layer] {
			v.errf("E-PRF-006", part.Pos, psubj, "layer 非法: %q", part.Layer)
		}
		if part.Secret != "" && !validSecrets[part.Secret] {
			v.errf("E-PRF-007", part.Pos, psubj, "secret 非法: %q", part.Secret)
		}
		if part.Extractor != "" && !validExtractors[part.Extractor] {
			v.errf("E-PRF-008", part.Pos, psubj, "extractor 非法: %q", part.Extractor)
		}
		v.checkSignalList(part.Signals, psubj)
		v.checkBudgets(e, part, psubj, part.Pos, part.MaxBytesInline, part.MaxBytesStructure, nil)
		v.checkRedact(e, part, part.Redact, part.Extractor, psubj)
		v.checkSecretLayer(e, part, psubj)
		v.checkPathSemantics(e, part, effectiveSemantics(e, part), effectiveDerived(e, part), e.Path, part.Origin, part.OriginPathKey, psubj)
	}
	v.checkPartOverlap(e, subj)
}

func effectiveSemantics(e *Entry, part *Part) string {
	if part != nil && part.PathSemantics != "" {
		return part.PathSemantics
	}
	return e.PathSemantics
}

func effectiveDerived(e *Entry, part *Part) string {
	if part != nil && part.DerivedFrom != "" {
		return part.DerivedFrom
	}
	return e.DerivedFrom
}

// checkPartOverlap implements E-PRF-034: pointers/sections may not select the
// same value, with the sole exception of a strictly-ancestor keys-only part
// (D-021 第 6 条).
func (v *validator) checkPartOverlap(e *Entry, subj string) {
	for i := 0; i < len(e.Parts); i++ {
		for j := i + 1; j < len(e.Parts); j++ {
			a, b := e.Parts[i], e.Parts[j]
			if a.Selector.Kind == "" || a.Selector.Kind != b.Selector.Kind {
				continue
			}
			if a.Selector.Kind == "line_pattern" {
				continue // overlap cannot be decided statically
			}
			if selectorsOverlap(a, b) {
				v.errf("E-PRF-034", b.Pos,
					fmt.Sprintf("%s.parts[%d](%s)", subj, j, b.ID),
					"part selector 与 parts[%d](%s) 重叠", i, a.ID)
			}
		}
	}
}

func selectorsOverlap(a, b *Part) bool {
	as := pointerSegments(a.Selector)
	bs := pointerSegments(b.Selector)
	short, long := as, bs
	shortPart, longPart := a, b
	if len(bs) < len(as) {
		short, long = bs, as
		shortPart, longPart = b, a
	}
	_ = longPart
	if len(short) == len(long) {
		for i := range short {
			if short[i] != long[i] && short[i] != "*" && long[i] != "*" {
				return false
			}
		}
		return true
	}
	for i := range short {
		if short[i] != long[i] && short[i] != "*" && long[i] != "*" {
			return false
		}
	}
	// Strict ancestor. Allowed only when the ancestor is keys-only.
	return shortPart.Extractor != ExtractorKeysOnly
}

func pointerSegments(sel Selector) []string {
	s := sel.Value
	if sel.Kind == "json_pointer" {
		s = strings.TrimPrefix(s, "/")
	}
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

func (v *validator) checkCatchAll(e *Entry, subj string) {
	if e.Kind != KindCatchAll {
		if e.ScopeSet || e.UnderSet {
			v.errf("E-PRF-070", e.Pos, subj, "scope/under 只允许用于 catch-all")
		}
		return
	}
	if e.Root == "" {
		v.errf("E-PRF-037", e.Pos, subj, "catch-all 缺少 root")
	}
	if e.PrioritySet {
		v.errf("E-PRF-073", e.Pos, subj, "catch-all 禁止写 priority（只在残留遍求值，不参与优先级裁决）")
	}
	scope := e.Scope
	if scope == "" {
		scope = ScopeRoot
	}
	if !validScope[scope] {
		v.errf("E-PRF-070", e.Pos, subj, "scope 非法: %q", e.Scope)
		return
	}
	if scope == ScopeRoot && e.UnderSet {
		v.errf("E-PRF-070", e.Pos, subj, "scope: root 不得写 under")
	}
	if scope == ScopeSubtree {
		if !e.UnderSet || e.Under == "" {
			v.errf("E-PRF-070", e.Pos, subj, "scope: subtree 必须写 under")
		} else {
			if containsGlob(e.Under) {
				v.errf("E-PRF-070", e.Pos, subj, "under 不得含 glob: %q", e.Under)
			}
			if hasDotDot(e.Under) {
				v.errf("E-PRF-070", e.Pos, subj, "under 不得含 ..: %q", e.Under)
			}
			if filepathIsAbsTemplate(e.Under) {
				v.errf("E-PRF-070", e.Pos, subj, "under 必须是相对 root 的路径: %q", e.Under)
			}
			if _, ok := splitRelPath(e.Under); !ok && !containsGlob(e.Under) && !hasDotDot(e.Under) {
				v.errf("E-PRF-070", e.Pos, subj, "under 非法: %q", e.Under)
			}
		}
	}
}

func (v *validator) checkCatchAllScopes() {
	groups := make(map[string][]*Entry)
	for _, e := range v.p.Entries {
		if e.Kind != KindCatchAll || e.Root == "" {
			continue
		}
		groups[e.Root] = append(groups[e.Root], e)
	}
	for _, list := range groups {
		whole := 0
		var subs []*Entry
		for _, e := range list {
			scope := e.Scope
			if scope == "" {
				scope = ScopeRoot
			}
			if scope == ScopeRoot {
				whole++
				if whole > 1 {
					v.errf("E-PRF-037", e.Pos, "catch-all("+e.ID+")",
						"同一 root 只允许一条 whole-root catch-all")
				}
			} else {
				subs = append(subs, e)
			}
		}
		for i := 0; i < len(subs); i++ {
			for j := i + 1; j < len(subs); j++ {
				if underPrefix(subs[i].Under, subs[j].Under) || underPrefix(subs[j].Under, subs[i].Under) {
					v.errf("E-PRF-037", subs[j].Pos, "catch-all("+subs[j].ID+")",
						"catch-all 的 under %q 与 %q 重叠", subs[i].Under, subs[j].Under)
				}
			}
		}
	}
}

func (v *validator) checkUniqueWithin(e *Entry, subj string) {
	if e.UniqueWithin == "" {
		return
	}
	if e.Kind == KindCatchAll {
		v.errf("E-PRF-047", e.Pos, subj, "catch-all 禁止使用 unique_within")
		return
	}
	if e.UniqueWithin != "root" {
		v.errf("E-PRF-047", e.Pos, subj, "unique_within 只接受 \"root\"，实际 %q", e.UniqueWithin)
	}
	if e.Layer != LayerL2 {
		v.errf("E-PRF-026", e.Pos, subj, "unique_within 只允许用于 L2 条目（实际 %s）", e.Layer)
	}
}

func (v *validator) checkPriorityConflict(e *Entry, subj string, seen map[string]struct {
	priority int
	id       string
}) {
	if e.Kind == KindCatchAll {
		return
	}
	key := selectorKey(e)
	if key == "" {
		return
	}
	if prev, ok := seen[key]; ok && prev.priority == e.Priority {
		v.errf("E-PRF-023", e.Pos, subj,
			"selector 与 %q 完全相同且 priority 相同（%d）", prev.id, e.Priority)
		return
	}
	if _, ok := seen[key]; !ok {
		seen[key] = struct {
			priority int
			id       string
		}{e.Priority, e.ID}
	}
}

func selectorKey(e *Entry) string {
	switch e.Kind {
	case KindFile, KindDir:
		return e.Kind + "|" + e.Root + "|" + strings.ReplaceAll(e.Path, "\\", "/")
	case KindGlobGroup:
		paths := append([]string{}, e.Paths...)
		sort.Strings(paths)
		return e.Kind + "|" + e.Root + "|" + strings.Join(paths, "\x00")
	case KindCatchAll:
		scope := e.Scope
		if scope == "" {
			scope = ScopeRoot
		}
		return "catch-all|" + e.Root + "|" + scope + "|" + e.Under
	}
	return ""
}

func (v *validator) checkProbe(e *Entry, subj string) {
	if e.Locator.PerOS == nil && e.Probe.PerOS == nil {
		probe, has := e.Probe.ForOS(runtime.GOOS)
		v.checkProbeOne(e, subj, e.Locator.Value, probe, has)
		return
	}
	for _, goos := range OSNames {
		loc, ok := e.Locator.ForOS(goos)
		if !ok {
			continue
		}
		probe, has := e.Probe.ForOS(goos)
		v.checkProbeOne(e, subj, loc, probe, has)
	}
}

func (v *validator) checkProbeOne(e *Entry, subj, loc, probe string, hasProbe bool) {
	if loc == "" {
		return
	}
	scheme := loc
	if i := strings.IndexByte(scheme, ':'); i >= 0 {
		scheme = scheme[:i]
	} else {
		v.errf("E-PRF-060", e.Pos, subj, "locator 缺少 scheme: %q", loc)
		return
	}
	want, known := schemeProbe[scheme]
	if !known {
		v.errf("E-PRF-060", e.Pos, subj, "未知 locator scheme %q", scheme)
		return
	}
	if hasProbe && probe != want {
		v.errf("E-PRF-060", e.Pos, subj, "probe %q 与 scheme %q 不一致", probe, scheme)
	}
	if scheme == "file" {
		p := strings.TrimPrefix(loc, "file:")
		if !isAbsTemplateValue(p) {
			v.errf("E-PRF-060", e.Pos, subj, "file: locator 必须是绝对路径模板: %q", p)
		}
	}
}

// isWorktreePath reports whether p is exactly or below .claude/worktrees.
func isWorktreePath(p string) bool {
	p = "/" + strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/") + "/"
	return strings.Contains(p, "/.claude/worktrees/")
}

// --- selftest --------------------------------------------------------------

func (v *validator) selftest() {
	st := v.p.Selftest
	if st == nil || len(st.Expect) == 0 {
		v.errf("E-PRF-017", Position{}, "selftest", "缺少 selftest 或 expect")
		return
	}
	if st.Budget == nil || st.Budget.WallMS <= 0 {
		pos := st.Pos
		if st.Budget != nil {
			pos = st.Budget.Pos
		}
		v.errf("E-PRF-050", pos, "selftest.budget", "预算缺失或 wall_ms 非正")
	}

	bindings := make(map[string]string)
	for _, inst := range st.FixtureOrder {
		val := st.Fixtures[inst]
		if filepathIsAbsTemplate(val) || isWindowsAbsValue(val) {
			v.errf("E-PRF-051", st.Pos, "selftest.fixtures["+inst+"]",
				"fixture 路径不得是绝对路径: %q", val)
			continue
		}
		if _, ok := splitRelPath(val); !ok {
			v.errf("E-PRF-067", st.Pos, "selftest.fixtures["+inst+"]",
				"fixture 路径必须是 profile 内相对路径: %q", val)
			continue
		}
		if prev, dup := bindings[val]; dup {
			v.errf("E-PRF-027", st.Pos, "selftest.fixtures["+inst+"]",
				"外部目录 %q 已绑定到 root %q", val, prev)
		} else {
			bindings[val] = inst
		}
	}

	for _, f := range st.Files {
		v.checkSelftestPath(st, f.Path, f.Pos, "selftest.files")
		if f.Size < 0 {
			v.errf("E-PRF-067", f.Pos, "selftest.files", "size 不得为负: %d", f.Size)
		}
	}
	for _, d := range st.Dirs {
		v.checkSelftestPath(st, d, st.Pos, "selftest.dirs")
	}
	for _, s := range st.Symlinks {
		v.checkSelftestPath(st, s.Path, s.Pos, "selftest.symlinks")
		if s.Target == "" {
			v.errf("E-PRF-067", s.Pos, "selftest.symlinks", "target 不得为空")
		}
	}

	paths, havePaths := v.fixturePaths(st)

	entryByID := make(map[string]*Entry, len(v.p.Entries))
	for _, e := range v.p.Entries {
		entryByID[e.ID] = e
	}
	entriesCovered := make(map[string]bool)
	partsCovered := make(map[string]map[string]bool)

	for i, ex := range st.Expect {
		subj := fmt.Sprintf("selftest.expect[%d]", i)
		e := entryByID[ex.Entry]
		if ex.Entry == "" || e == nil {
			v.errf("E-PRF-020", ex.Pos, subj, "引用不存在的 entry %q", ex.Entry)
			continue
		}
		entriesCovered[ex.Entry] = true
		if ex.Part != "" {
			if findPart(e, ex.Part) == nil {
				v.errf("E-PRF-057", ex.Pos, subj, "entry %q 没有 part %q", ex.Entry, ex.Part)
			} else {
				if partsCovered[ex.Entry] == nil {
					partsCovered[ex.Entry] = make(map[string]bool)
				}
				partsCovered[ex.Entry][ex.Part] = true
			}
		}
		root, ok := v.expectRoot(st, i, ex)
		if !ok {
			v.errf("E-PRF-027", ex.Pos, subj, "expect.root 未绑定到 selftest.fixtures: %q", ex.Root)
			continue
		}
		if ex.Match == "" {
			v.errf("E-PRF-019", ex.Pos, subj, "expect.match 为空或引用不存在的 fixture 路径")
			continue
		}
		if filepathIsAbsTemplate(ex.Match) || isWindowsAbsValue(ex.Match) || hasDotDot(ex.Match) {
			v.errf("E-PRF-021", ex.Pos, subj, "expect.match 越出 fixture 根: %q", ex.Match)
			continue
		}
		if havePaths && osApplies(ex.OS) {
			found := false
			for _, rel := range paths[root] {
				if matchGlob(ex.Match, rel) {
					found = true
					break
				}
			}
			if !found {
				v.errf("E-PRF-019", ex.Pos, subj, "expect.match %q 找不到对应的 fixture 路径", ex.Match)
			}
		}
	}

	for i, e := range v.p.Entries {
		subj := entrySubject(i, e.ID)
		if e.SelftestExempt != "" {
			continue
		}
		if !entriesCovered[e.ID] {
			if e.Kind == KindCatchAll {
				v.warnf("W-PRF-124", e.Pos, subj, "catch-all 未被 selftest 覆盖")
			} else {
				v.errf("E-PRF-018", e.Pos, subj, "entry 未被 selftest 覆盖且无 selftest_exempt")
			}
		}
		for _, part := range e.Parts {
			if !partsCovered[e.ID][part.ID] {
				v.errf("E-PRF-057", part.Pos, subj,
					"part %q 未被 selftest 覆盖（entry 未 selftest_exempt）", part.ID)
			}
		}
	}
}

func findPart(e *Entry, id string) *Part {
	for _, p := range e.Parts {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (v *validator) checkSelftestPath(st *SelfTest, raw string, pos Position, what string) {
	if raw == "" {
		v.errf("E-PRF-067", pos, what, "路径不得为空")
		return
	}
	if filepathIsAbsTemplate(raw) || isWindowsAbsValue(raw) {
		v.errf("E-PRF-051", pos, what, "selftest 不得使用绝对路径: %q", raw)
		return
	}
	segs, ok := splitRelPath(raw)
	if !ok {
		v.errf("E-PRF-067", pos, what, "selftest 路径必须是 profile 内相对路径: %q", raw)
		return
	}
	if _, bound := st.Fixtures[segs[0]]; !bound {
		v.errf("E-PRF-027", pos, what, "路径首段 %q 不是 selftest.fixtures 的实例名", segs[0])
	}
}

func isWindowsAbsValue(p string) bool {
	return len(p) >= 3 && isASCIIAlpha(p[0]) && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

// expectRoot resolves an expect.root, applying the repo/-prefix fallback with
// W-PRF-106 (spec-profile §6.2).
func (v *validator) expectRoot(st *SelfTest, index int, ex Expect) (string, bool) {
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
		v.warnf("W-PRF-106", ex.Pos, fmt.Sprintf("selftest.expect[%d]", index),
			"expect 缺少 root，按前缀推断为 %q", first)
		return first, true
	}
	return "", false
}

// fixturePaths lists the files/dirs/dirs that materialization will produce,
// per fixture instance. It returns ok=false when no fixture filesystem is
// available (LoadBytes).
func (v *validator) fixturePaths(st *SelfTest) (map[string][]string, bool) {
	if v.p.fixtureFS == nil {
		return nil, false
	}
	out := make(map[string][]string, len(st.Fixtures))
	for _, inst := range st.FixtureOrder {
		root := strings.ReplaceAll(st.Fixtures[inst], "\\", "/")
		root = strings.TrimSuffix(root, "/")
		prefix := root + "/"
		walkErr := fs.WalkDir(v.p.fixtureFS, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(p, prefix)
			if rel == p {
				return nil // the fixture root itself
			}
			out[inst] = append(out[inst], rel)
			return nil
		})
		if walkErr != nil {
			out[inst] = nil
		}
	}
	add := func(raw string) {
		segs, ok := splitRelPath(raw)
		if !ok || len(segs) < 2 {
			return
		}
		inst := segs[0]
		if _, bound := st.Fixtures[inst]; !bound {
			return
		}
		out[inst] = append(out[inst], strings.Join(segs[1:], "/"))
	}
	for _, f := range st.Files {
		add(f.Path)
	}
	for _, d := range st.Dirs {
		add(d)
	}
	for _, s := range st.Symlinks {
		add(s.Path)
	}
	for inst := range out {
		sort.Strings(out[inst])
	}
	return out, true
}

func osApplies(oss []string) bool {
	if len(oss) == 0 {
		return true
	}
	for _, o := range oss {
		if o == runtime.GOOS {
			return true
		}
	}
	return false
}

// --- environment expansion -------------------------------------------------

// maxExpandDepth bounds recursive expansion. It only has to be larger than
// any realistic nesting of defaults; it exists to stop A=${B}, B=${A}.
// Expansion was exactly-once before D-033, which left "$HOME/.config" literal
// when "${XDG_CONFIG_HOME:-$HOME/.config}" was used with XDG unset.
const maxExpandDepth = 16

func isVarStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isVarChar(c byte) bool {
	return isVarStart(c) || (c >= '0' && c <= '9')
}

// scanPercentVar parses %NAME% at s[0]=='%'. n is 0 when there is no complete
// token (a bare percent stays literal).
func scanPercentVar(s string) (name string, n int) {
	if len(s) < 3 || !isVarStart(s[1]) {
		return "", 0
	}
	i := 2
	for i < len(s) && isVarChar(s[i]) {
		i++
	}
	if i >= len(s) || s[i] != '%' {
		return "", 0
	}
	return s[1:i], i + 1
}

// scanDollarVar parses $NAME or ${NAME}, ${NAME:-default} and ${NAME-default}
// at s[0]=='$'. The default may itself contain ${...}. n is 0 when the text is
// not a complete token, so malformed templates stay literal.
func scanDollarVar(s string) (name, def string, hasDef, colon bool, n int) {
	if len(s) < 2 {
		return "", "", false, false, 0
	}
	if s[1] != '{' {
		if !isVarStart(s[1]) {
			return "", "", false, false, 0
		}
		i := 2
		for i < len(s) && isVarChar(s[i]) {
			i++
		}
		return s[1:i], "", false, false, i
	}
	if len(s) < 4 || !isVarStart(s[2]) {
		return "", "", false, false, 0
	}
	i := 3
	for i < len(s) && isVarChar(s[i]) {
		i++
	}
	name = s[2:i]
	if i < len(s) && s[i] == '}' {
		return name, "", false, false, i + 1
	}
	switch {
	case i+1 < len(s) && s[i] == ':' && s[i+1] == '-':
		hasDef, colon = true, true
		i += 2
	case i < len(s) && s[i] == '-':
		hasDef = true
		i++
	default:
		return "", "", false, false, 0
	}
	// Find the matching close brace; nested ${...} counts as one.
	start := i
	depth := 0
	for i < len(s) {
		if s[i] == '}' {
			if depth == 0 {
				return name, s[start:i], hasDef, colon, i + 1
			}
			depth--
		} else if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			depth++
			i++
		}
		i++
	}
	return "", "", false, false, 0
}

// expandVar resolves one variable occurrence. A set variable is expanded
// recursively. A missing one uses def when present, else UnresolvedError.
func expandVar(name, def string, hasDef, colon bool, depth int) (string, error) {
	val, ok := os.LookupEnv(name)
	if hasDef && (!ok || (colon && val == "")) {
		return expandTemplateDepth(def, depth+1)
	}
	if !ok {
		return "", &UnresolvedError{Var: name}
	}
	return expandTemplateDepth(val, depth+1)
}

func expandTemplateDepth(s string, depth int) (string, error) {
	if depth > maxExpandDepth {
		return "", &DepthError{Limit: maxExpandDepth}
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' {
			if name, n := scanPercentVar(s[i:]); n > 0 {
				v, err := expandVar(name, "", false, false, depth)
				if err != nil {
					return "", err
				}
				b.WriteString(v)
				i += n
				continue
			}
		}
		if s[i] == '$' {
			name, def, hasDef, colon, n := scanDollarVar(s[i:])
			if n > 0 {
				v, err := expandVar(name, def, hasDef, colon, depth)
				if err != nil {
					return "", err
				}
				b.WriteString(v)
				i += n
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), nil
}

// expandTemplate is the internal, one-argument form used by validation. It
// keeps the unexpanded text when a variable is unresolved because validation
// must not depend on this machine's environment.
func expandTemplate(s string) string {
	out, err := expandTemplateDepth(s, 0)
	if err != nil {
		return s
	}
	return out
}

// ExpandTemplate expands the root/absolute-path variable syntax of
// spec-profile §4.1 recursively: %VAR%, $VAR, ${VAR}, ${VAR:-default} and
// ${VAR-default}. Expansion repeats on every substituted value (bounded by
// maxExpandDepth), so a default such as $HOME/.config is expanded too. It is
// the single implementation used by validation and by the scan engine.
//
// A variable that is unset and has no default yields *UnresolvedError (test
// with errors.Is(err, ErrUnresolved)); runaway recursion yields *DepthError.
// Callers decide whether that is fatal or becomes a root_unresolved status.
func ExpandTemplate(s string) (string, error) { return expandTemplateDepth(s, 0) }

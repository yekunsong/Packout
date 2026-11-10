package profile

import (
	"encoding/json"
	"io/fs"

	"github.com/tailscale/hujson"
)

// Schema version supported by this implementation (spec-profile §7.1).
const (
	SchemaMajor = "2"
	SchemaMinor = "0"
	Schema      = SchemaMajor + "." + SchemaMinor
)

// Default budgets (spec-profile §5.8, D-021 第 10 条).
const (
	DefaultMaxBytesInline    int64 = 65536
	DefaultMaxBytesStructure int64 = 262144
	DefaultMaxBytesTotal     int64 = 128 << 30 // 128 GiB
	MaxBytesTotalCap         int64 = 4 << 40   // 4 TiB
	MaxBytesInlineCap        int64 = 8388608
	MaxBytesStructureCap     int64 = 8388608
	DefaultMaxDepth                = 32
	MaxDepthCap                    = 64
	DefaultAggregateAbove          = 10000
)

// Kind values (spec-profile §5.2).
const (
	KindFile          = "file"
	KindDir           = "dir"
	KindGlobGroup     = "glob-group"
	KindNamedLocation = "named-location"
	KindCatchAll      = "catch-all"
)

// Layer values (spec-profile §5.3).
const (
	LayerL0 = "L0"
	LayerL1 = "L1"
	LayerL2 = "L2"
	LayerL3 = "L3"
	LayerL4 = "L4"
	LayerL5 = "L5"
)

// Secret values (spec-profile §5.4).
const (
	SecretNone      = "none"
	SecretScan      = "scan"
	SecretReference = "reference"
	SecretRestore   = "restore"
	SecretRelogin   = "relogin"
)

// Extractor values (spec-profile §5.6).
const (
	ExtractorNone     = "none"
	ExtractorRawRef   = "raw-ref"
	ExtractorTemplate = "template"
	ExtractorKeysOnly = "keys-only"
	ExtractorDigest   = "digest"
)

// Path semantics (spec-profile §5.10).
const (
	PathLiteral        = "literal"
	PathMachineDerived = "machine_derived"
)

// Derived-from values.
const (
	DerivedRepoSlug    = "repo_slug"
	DerivedGitWorktree = "git_worktree_of"
	DerivedJSONPathKey = "json_path_key"
)

// PartUncovered is the reserved part id used by parts_uncovered: keep
// (D-024 第 1 条).
const PartUncovered = "uncovered"

// Catch-all scopes.
const (
	ScopeRoot    = "root"
	ScopeSubtree = "subtree"
)

// OpenAs values.
const (
	OpenAsNone     = "none"
	OpenAsText     = "text"
	OpenAsSQLiteRO = "sqlite-ro"
)

// Profile is a parsed and validated profile (spec-profile §3).
//
// Unknown members are retained twice: the original hujson AST still contains
// them at their original byte positions (Pack restores them verbatim), and
// Extra exposes them as standardized JSON for programmatic consumers. Write
// back through Pack, which never reformats the file (D-019).
type Profile struct {
	SchemaVersion string
	Name          string
	Title         string
	Vendor        string
	Notes         string
	AppliesTo     AppliesTo
	Roots         map[string]Root
	RootOrder     []string
	Defaults      Defaults
	MaxBytesTotal int64
	Scan          string
	Entries       []*Entry
	Selftest      *SelfTest

	Extra    map[string]json.RawMessage
	Warnings Warnings

	File string // display name of the source, for diagnostics

	baseDir   string
	fixtureFS fs.FS
	ast       hujson.Value
	src       []byte
}

// AppliesTo limits a profile to a set of operating systems. An empty list is
// legal and means that only named-location os limits apply (spec-profile §3.1).
type AppliesTo struct {
	OS []string
}

// Root is either a single path template or a per-OS map (spec-profile §4.1).
type Root struct {
	Template string
	PerOS    map[string]string
	Pos      Position
}

// ForOS returns the template for goos, preferring the per-OS map.
func (r Root) ForOS(goos string) string {
	if r.PerOS != nil {
		return r.PerOS[goos]
	}
	return r.Template
}

// Defaults are the profile-level entry defaults (spec-profile §3.1, §5.8).
type Defaults struct {
	MaxBytesInline    *int64
	MaxBytesStructure *int64
	MaxBytesTotal     *int64
	FollowSymlinks    *bool
	Expand            string
	MaxDepth          *int
	Exclude           []string
	Scan              string
	Pos               Position
}

// Entry is one declaration inside a profile (spec-profile §5).
type Entry struct {
	ID        string
	Kind      string
	Root      string
	Path      string
	Paths     []string
	Locator   Locator
	Probe     Probe
	OS        []string
	Layer     string
	Secret    string
	Extractor string
	Scan      string
	Signals   []Signal
	Priority  int

	Parts          []*Part
	PartsUncovered string
	PathSemantics  string
	DerivedFrom    string
	Churn          string
	NeededBy       []string
	Companions     []string
	SideEffects    []string
	OpenAs         string
	OpaqueContent  bool

	MaxBytesInline    *int64
	MaxBytesStructure *int64
	MaxBytesTotal     *int64
	Expand            string
	MaxDepth          *int
	Exclude           []string
	FollowSymlinks    *bool
	DedupeTargets     *bool
	CaseSensitive     *bool
	UniqueWithin      string
	AggregateAbove    *int
	ExportGroup       string
	Notes             string
	Redact            *Redact
	SelftestExempt    string

	Scope string
	Under string

	Extra map[string]json.RawMessage
	Pos   Position

	// presence flags for fields whose absence differs from a zero value.
	PathSet     bool
	PathsSet    bool
	PrioritySet bool
	PartsSet    bool
	ScopeSet    bool
	UnderSet    bool
}

// Signal explains why an entry has its classification (spec-profile §5.7).
type Signal struct {
	Src  string
	Note string
	URL  string
	Pos  Position
}

// Locator is the named-location address, either one URI or per OS
// (spec-profile §5.5).
type Locator struct {
	Value string
	PerOS map[string]string
}

// ForOS returns the locator for goos.
func (l Locator) ForOS(goos string) (string, bool) {
	if l.PerOS != nil {
		s, ok := l.PerOS[goos]
		return s, ok
	}
	if l.Value == "" {
		return "", false
	}
	return l.Value, true
}

// Probe is the named-location probe override (spec-profile §5.5).
type Probe struct {
	Value string
	PerOS map[string]string
}

// ForOS returns the probe for goos.
func (p Probe) ForOS(goos string) (string, bool) {
	if p.PerOS != nil {
		s, ok := p.PerOS[goos]
		return s, ok
	}
	if p.Value == "" {
		return "", false
	}
	return p.Value, true
}

// Redact carries template/keys-only redaction selectors (spec-profile §5.6).
type Redact struct {
	JSONPointer []string
	KeyPattern  []string
	TOMLSection []string
	Replacement string
	Pos         Position
}

// Selector is a part selector (spec-profile §5.9): exactly one kind.
type Selector struct {
	Kind  string // json_pointer | line_pattern | toml_section
	Value string
	Pos   Position
}

// Part is a file-internal slice of an entry (spec-profile §5.9).
type Part struct {
	ID        string
	Selector  Selector
	Layer     string
	Secret    string
	Extractor string
	Signals   []Signal
	Redact    *Redact

	MaxBytesInline    *int64
	MaxBytesStructure *int64
	NeededBy          []string
	Notes             string
	PathSemantics     string
	DerivedFrom       string
	Origin            *string
	OriginPathKey     *string

	Extra map[string]json.RawMessage
	Pos   Position
}

// SelfTest is the profile's offline fixture and assertion block
// (spec-profile §6).
type SelfTest struct {
	Clock        string
	Fixtures     map[string]string
	FixtureOrder []string
	Files        []FileSpec
	Dirs         []string
	Symlinks     []SymlinkSpec
	Expect       []Expect
	ExpectAbsent []Absent
	Budget       *Budget
	Extra        map[string]json.RawMessage
	Pos          Position
}

// FileSpec creates a zero-filled file of Size bytes (spec-profile §6.1).
type FileSpec struct {
	Path string
	Size int64
	Pos  Position
}

// SymlinkSpec creates a symlink (spec-profile §6.1).
type SymlinkSpec struct {
	Path   string
	Target string
	Pos    Position
}

// Expect is one positive selftest assertion (spec-profile §6.1).
type Expect struct {
	Entry      string
	Part       string
	Root       string
	Match      string
	OS         []string
	Layer      string
	Secret     string
	Action     string
	RiskFlags  []string
	Confidence *float64
	Pos        Position
}

// Absent is one negative selftest assertion (spec-profile §6.1).
type Absent struct {
	Root  string
	Match string
	Pos   Position
}

// Budget bounds a selftest run (spec-profile §6.1).
type Budget struct {
	WallMS    int64
	MaxRSSMiB int64
	Pos       Position
}

// Pack serializes the profile's AST. When nothing was edited it is
// byte-for-byte identical to the loaded input (minus a stripped UTF-8 BOM).
// Unknown members are part of the AST and therefore written back in their
// original position, after the recognized members around them.
//
// Pack must not be replaced with Clone/Format/Standardize round-trips: Clone
// drops trailing commas and Format/Standardize reformat the file (D-019).
func (p *Profile) Pack() []byte { return p.ast.Pack() }

// Patch applies an RFC 6902 JSON Patch to the AST in place and returns the
// packed result. Only the targeted nodes change: comments, whitespace, trailing
// commas and unknown members elsewhere stay byte-for-byte identical (D-019).
// The typed projection is not re-decoded; reload the result to get an updated
// Profile.
func (p *Profile) Patch(patch []byte) ([]byte, error) {
	if err := p.ast.Patch(patch); err != nil {
		return nil, err
	}
	p.ast.UpdateOffsets()
	return p.ast.Pack(), nil
}

// Source returns a copy of the bytes the AST was parsed from (BOM stripped).
func (p *Profile) Source() []byte {
	out := make([]byte, len(p.src))
	copy(out, p.src)
	return out
}

// EffectiveMaxBytesInline resolves the inline budget for an entry/part.
func (p *Profile) EffectiveMaxBytesInline(e *Entry, part *Part) int64 {
	if part != nil && part.MaxBytesInline != nil {
		return *part.MaxBytesInline
	}
	if e != nil && e.MaxBytesInline != nil {
		return *e.MaxBytesInline
	}
	if p.Defaults.MaxBytesInline != nil {
		return *p.Defaults.MaxBytesInline
	}
	return DefaultMaxBytesInline
}

// EffectiveMaxBytesStructure resolves the structure-only budget.
func (p *Profile) EffectiveMaxBytesStructure(e *Entry, part *Part) int64 {
	if part != nil && part.MaxBytesStructure != nil {
		return *part.MaxBytesStructure
	}
	if e != nil && e.MaxBytesStructure != nil {
		return *e.MaxBytesStructure
	}
	if p.Defaults.MaxBytesStructure != nil {
		return *p.Defaults.MaxBytesStructure
	}
	return DefaultMaxBytesStructure
}

// EffectiveMaxBytesTotal resolves the per-entry cumulative budget.
func (p *Profile) EffectiveMaxBytesTotal(e *Entry) int64 {
	if e != nil && e.MaxBytesTotal != nil {
		return *e.MaxBytesTotal
	}
	if p.Defaults.MaxBytesTotal != nil {
		return *p.Defaults.MaxBytesTotal
	}
	if p.MaxBytesTotal > 0 {
		return p.MaxBytesTotal / 16
	}
	return DefaultMaxBytesTotal / 16
}

// EffectiveExpand resolves expand for an entry.
func (p *Profile) EffectiveExpand(e *Entry) string {
	if e != nil && e.Expand != "" {
		return e.Expand
	}
	if p.Defaults.Expand != "" {
		return p.Defaults.Expand
	}
	return "per-file"
}

// EffectiveMaxDepth resolves max_depth for an entry.
func (p *Profile) EffectiveMaxDepth(e *Entry) int {
	if e != nil && e.MaxDepth != nil {
		return *e.MaxDepth
	}
	if p.Defaults.MaxDepth != nil {
		return *p.Defaults.MaxDepth
	}
	return DefaultMaxDepth
}

// EffectiveScan resolves the scan policy for an entry.
func (p *Profile) EffectiveScan(e *Entry) string {
	if e != nil && e.Scan != "" {
		return e.Scan
	}
	if p.Defaults.Scan != "" {
		return p.Defaults.Scan
	}
	if p.Scan != "" {
		return p.Scan
	}
	return "default"
}

// EffectiveExclude returns the default exclude list plus entry additions.
func (p *Profile) EffectiveExclude(e *Entry) []string {
	out := append([]string{}, DefaultExclude...)
	out = append(out, p.Defaults.Exclude...)
	if e != nil {
		out = append(out, e.Exclude...)
	}
	return out
}

// DefaultExclude is the fixed exclusion set (spec-profile §4.6). Both .git
// forms must be present: in a worktree .git is a regular file (D-013).
var DefaultExclude = []string{
	"**/node_modules/**",
	"**/.git",
	"**/.git/**",
}

// OSNames are the operating systems understood by applies_to and per-OS maps.
var OSNames = []string{"windows", "darwin", "linux"}

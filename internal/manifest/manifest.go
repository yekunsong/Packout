// Package manifest implements the packout manifest format (spec-manifest v2.0):
// a directory of JSONL shards containing a header, units, notes and a footer,
// plus a manifest.index.json that makes the directory certifiably complete.
//
// The package is the project's central data contract. It owns the record
// shapes, the fixed field order, the streaming writer, the reader and the
// structural validator. It deliberately depends only on the standard library
// and golang.org/x/text (through internal/fsx); it must never import
// internal/scan (D-005).
//
// Design rules that callers must not work around:
//
//   - Field order is explicit and hand-written (spec §1, §4.1). Go's struct
//     tag ordering is not relied upon for output.
//   - Units are streamed. A Writer holds at most one shard buffer; shards are
//     written as <name>.tmp, fsynced and renamed atomically (spec §2, §8).
//   - A manifest without a footer or without an index is incomplete
//     (E-MAN-030). Abort therefore leaves the .tmp file and never writes an
//     index; a Writer refuses to start on top of an existing index so an
//     abort can never damage a complete artifact.
//   - Unknown fields are preserved in Extra and written after the known
//     fields, so a newer minor version survives a read/write cycle (§7).
//   - No field ever carries plaintext secret material (§9).
package manifest

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

// Format constants from spec-manifest v2.0.
const (
	// Version is the manifest MAJOR.MINOR version this package writes.
	Version = "2.0"
	// SupportedMajor is the highest MAJOR this reader accepts (E-MAN-040).
	SupportedMajor = 2

	// DefaultShardUnits and DefaultShardBytes are the provisional rotation
	// thresholds (§2, D-011 §9). A header may override both.
	DefaultShardUnits = 50_000
	DefaultShardBytes = 64 << 20

	// MaxLineBytes is the hard per-line limit (§1, E-MAN-002).
	MaxLineBytes = 64 << 10
	// MaxNoteBytes bounds notes and signal notes (§4.1, §5.1).
	MaxNoteBytes = 512
)

// Record type discriminators (§3).
const (
	TypeHeader = "header"
	TypeUnit   = "unit"
	TypeNote   = "note"
	TypeFooter = "footer"
)

// Kinds of a Unit (§4.1).
const (
	KindFile          = "file"
	KindDir           = "dir"
	KindGlobGroup     = "glob-group"
	KindNamedLocation = "named-location"
	KindCatchAll      = "catch-all"
)

// Layers in ascending order (§5.2).
const (
	LayerL0 = "L0"
	LayerL1 = "L1"
	LayerL2 = "L2"
	LayerL3 = "L3"
	LayerL4 = "L4"
	LayerL5 = "L5"
)

// Proposed actions (§4.1).
const (
	ActionKeep      = "keep"
	ActionDelete    = "delete"
	ActionReinstall = "reinstall"
	ActionTemplate  = "template"
	ActionMigrate   = "migrate"
	ActionRebind    = "rebind"
	ActionRelogin   = "relogin"
)

// Secret classes (§4.3), ordered from least to most conservative.
const (
	SecretNone      = "none"
	SecretScan      = "scan"
	SecretReference = "reference"
	SecretRestore   = "restore"
	SecretRelogin   = "relogin"
)

// Path semantics (§4.9).
const (
	SemanticsLiteral        = "literal"
	SemanticsMachineDerived = "machine_derived"
)

// Derived path origins and other fixed enum values (§4.9, §4.10, §4.12).
const (
	DerivedRepoSlug     = "repo_slug"
	DerivedGitWorktree  = "git_worktree_of"
	DerivedJSONPathKey  = "json_path_key"
	PartUncovered       = "uncovered"
	SideEffectShmCreate = "shm_created"
	OpenAsNone          = "none"
	OpenAsText          = "text"
	OpenAsSQLiteRO      = "sqlite-ro"
)

// Sentinel errors returned by the package.
var (
	// ErrIncomplete means the manifest directory is not a complete artifact
	// (missing footer, missing index, or inconsistent shard accounting).
	ErrIncomplete = errors.New("manifest: incomplete manifest")
	// ErrOutputExists means an existing manifest.index.json would be replaced.
	ErrOutputExists = errors.New("manifest: output already contains a manifest index")
	// ErrAborted is returned by operations after Abort.
	ErrAborted = errors.New("manifest: writer aborted")
	// ErrClosed is returned by writes after Close.
	ErrClosed = errors.New("manifest: writer closed")
	// ErrLineTooLong means one record exceeds MaxLineBytes.
	ErrLineTooLong = errors.New("manifest: record exceeds 64 KiB")
)

// layerOrder is the canonical layer order and the base for risk-flag order.
var layerOrder = []string{LayerL0, LayerL1, LayerL2, LayerL3, LayerL4, LayerL5}

// riskFlagOrder is the fixed order of §4.6. Unknown flags are preserved after
// the known ones, sorted by byte order for deterministic output.
var riskFlagOrder = []string{
	"gitignored", "git_tracked", "not_versioned", "symlink", "symlink_cycle",
	"junction", "hardlink_multi", "sparse", "cloud_placeholder", "long_path",
	"case_collision", "readonly_volume", "encrypted_efs", "oversized",
	"content_partial", "opaque_content", "read_error", "probe_unavailable",
	"low_confidence", "unknown_enum", "id_collision", "aggregated", "residual",
	"outside_root", "machine_derived_path", "slug_collision", "deletion_cost",
}

// neededByOrder is the fixed order of §4.11.
var neededByOrder = []string{"rewind", "statusline", "resume", "mcp", "daemon", "plugins"}

// signalSourceOrder is the fixed signal source order of §5.1.
var signalSourceOrder = []string{
	"profile_rule", "user_override",
	"filesystem_stat", "link_count", "cloud_placeholder", "probe_result",
	"git_tracked", "gitignore_hit",
	"file_format", "content_match", "secret_prefix", "secret_entropy",
	"official_docs",
}

// noteCodeOrder lists the fixed note codes of §3.2. Unknown codes are
// preserved (the note code enum is MINOR-extensible).
var noteCodeOrder = []string{
	"probe_unavailable", "permission_denied", "budget_exceeded", "profile_skipped",
	"path_too_long", "read_error", "aggregated", "part_overlap", "part_missing",
	"part_uncovered", "binary_presence_only", "content_not_read", "companion_missing",
	"target_duplicate", "side_effect_unexpected", "priority_tie",
	"residual_deduplicated", "depth_truncated", "root_unresolved", "empty_glob",
	"ads_stream", "selection_skipped",
}

// Header is the first line of the manifest's first shard (§3.1).
type Header struct {
	ManifestVersion string
	ScanID          string
	ScanSegment     ScanSegment
	StartedAt       time.Time
	Tool            string
	Host            Host
	Inputs          Inputs
	ShardUnits      int
	ShardBytes      int64
	Roots           []Root

	// Extra preserves unknown (newer-minor) fields.
	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// ScanSegment makes concurrent/later segments byte-spliceable (§2).
type ScanSegment struct {
	Parent     *string
	SegmentSeq int
	FirstShard int

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// Host describes the machine without identifying the user (§3.1).
type Host struct {
	OS              string
	OSVersion       string
	Arch            string
	CaseSensitivity string
	PathFoldVersion string
	VolumeIDs       []VolumeID

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// VolumeID identifies a filesystem volume by root path and serial.
type VolumeID struct {
	Root   string
	Serial string

	Extra      map[string][]byte
	extraOrder []string
}

// Inputs records the scan's non-secret salt and the profiles used.
type Inputs struct {
	SecretSaltMode string
	SecretSalt     string
	Profiles       []ProfileRef
	Options        *InputOptions

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// ProfileRef pins one profile by name, version and content digest.
type ProfileRef struct {
	Name    string
	Version string
	SHA256  string

	Extra      map[string][]byte
	extraOrder []string
}

// InputOptions holds scan options that affect the corpus.
type InputOptions struct {
	FollowSymlinks bool
	// WithSessions marks a scan made with --with-sessions: session-flagged
	// entries were emitted per file and export must keep their raw bytes.
	WithSessions bool
	// Selection records a non-default preset/include/exclude/session filter
	// choice. Consumers (export, report) execute it from the header and never
	// re-select. Default selections omit it entirely.
	Selection *Selection

	Extra      map[string][]byte
	extraOrder []string
}

// Selection is the header form of the scan's "what to carry" choice
// (manifest §3.1). Only non-default fields are written.
type Selection struct {
	Preset                string
	Include               []string
	Exclude               []string
	SessionsSince         string
	SessionsProjects      []string
	SessionsMaxPerProject int

	Extra      map[string][]byte
	extraOrder []string
}

// Root is one declared scan root instance (§3.1).
type Root struct {
	Name     string
	Role     string
	Instance int
	Origin   string
	Path     string
	Profile  string

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// Unit is one conclusion (§4.1). Field order is fixed by the spec table; the
// encoder in encode.go is the single source of truth for output order.
type Unit struct {
	Type             string
	SchemaVersion    string
	ID               string
	CID              *string
	Path             string
	PathKey          string
	Root             string
	PathSemantics    string
	DerivedFrom      *string
	Origin           *string
	OriginPathKey    *string
	Profile          string
	Entry            string
	PartID           string
	Kind             string
	Layer            string
	Confidence       float64
	Signals          []Signal
	Secret           *Secret
	ContainsSecret   *bool
	MayContainSecret *bool
	SizeApparent     *int64
	SizeAlloc        *int64
	MTime            *time.Time
	FileID           *FileID
	Fingerprint      *Fingerprint
	Owner            *Owner
	ACL              *ACL
	SizeEstimated    bool
	AggregateCount   *int64
	ProposedAction   string
	RiskFlags        []string
	NeededBy         []string
	Companions       []string
	SideEffects      []string
	OpenAs           string
	OpaqueContent    bool
	LinkTarget       string
	SecretRef        string
	Notes            string

	// RootIndex is an in-memory ordering hint: the position of Root in the
	// header's roots array. It is never serialized. SortWithRoots fills it.
	RootIndex int `json:"-"`

	// Extra preserves unknown (newer-minor) fields. Values are raw JSON and
	// are written after every known field, in original input order.
	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool

	// confidenceRaw retains the input spelling so the validator can enforce
	// "at most three decimal places" (E-MAN-014) without float formatting.
	confidenceRaw string
	// aliases records old enum names mapped while reading (W-MAN-116 etc.).
	aliases []string
}

// Signal is one evidence line (§5.1).
type Signal struct {
	Src  string
	Note string
	URL  *string

	Extra      map[string][]byte
	extraOrder []string
}

// Secret is the per-unit secret summary (§4.3).
type Secret struct {
	Class     string
	Hits      []SecretHit
	HitCount  int
	Truncated bool

	Extra      map[string][]byte
	extraOrder []string
}

// SecretHit is one detected position; it never contains plaintext.
type SecretHit struct {
	Kind        string
	Class       string
	Locator     string
	Prefix      string
	Fingerprint string
	HitID       string

	Extra      map[string][]byte
	extraOrder []string
}

// FileID is the platform file identity (§4.4).
type FileID struct {
	VolumeSerial string
	Index        string
	// ReparseTag is null, a numeric Windows tag, or "symlink" on POSIX.
	ReparseTag []byte

	Extra      map[string][]byte
	extraOrder []string
}

// Fingerprint is a content or structure digest (§4.5).
//
// Scope is one of full, head-tail, keys, aggregate, shape, or "" for the
// JSON null scope. Value is nil exactly when the digest could not be computed.
type Fingerprint struct {
	Algo  string
	Scope string
	Value *string

	Extra      map[string][]byte
	extraOrder []string
}

// Owner is a SID or uid:gid pair (§4.8).
type Owner struct {
	Kind  string
	Value string

	Extra      map[string][]byte
	extraOrder []string
}

// ACL is a digest of the normalized DACL (§4.8).
type ACL struct {
	Algo      string
	Value     string
	Entries   int
	Truncated bool

	Extra      map[string][]byte
	extraOrder []string
}

// Note is a non-conclusion annotation (§3.2).
type Note struct {
	Type        string
	ScanID      string
	Code        string
	Profile     string
	Entry       string
	Category    string
	PartID      string
	Detail      string
	Companions  []string
	SideEffects []string

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// Footer is the last line of the manifest's last shard (§3.3).
type Footer struct {
	Type            string
	ManifestVersion string
	ScanID          string
	EndedAt         time.Time
	Units           int64
	Shards          int
	Stats           Stats
	Complete        bool
	Errors          int64

	Extra      map[string][]byte
	extraOrder []string
	present    map[string]bool
}

// Stats holds per-layer unit counts and side-effect counts (§3.3).
type Stats struct {
	L0       int64
	L1       int64
	L2       int64
	L3       int64
	L4       int64
	L5       int64
	Residual int64
	// SideEffects counts observed side effects; zero entries are omitted.
	SideEffects map[string]int64

	Extra      map[string][]byte
	extraOrder []string
}

// CurrentPathFoldVersion reports the x/text module version and Unicode version
// of this build, for header.path_fold_version (§3.1, §6.3).
func CurrentPathFoldVersion() string {
	ver := "devel"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "golang.org/x/text" {
				ver = d.Version
				break
			}
		}
	}
	return fmt.Sprintf("x/text@%s (unicode %s)", ver, norm.Version)
}

// PathFoldVersionMatches reports whether a header version string was produced
// by this build. A mismatch downgrades key checks to W-MAN-113 (§6.3).
func PathFoldVersionMatches(headerVersion string) bool {
	return headerVersion == CurrentPathFoldVersion()
}

// majorOf parses the MAJOR component of a MAJOR.MINOR version.
func majorOf(v string) (int, bool) {
	i := strings.IndexByte(v, '.')
	if i <= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(v[:i])
	if err != nil || n < 0 {
		return 0, false
	}
	if _, err := strconv.Atoi(v[i+1:]); err != nil {
		return 0, false
	}
	return n, true
}

// Doc is the complete in-memory document produced by ReadManifest: header,
// units, notes, footer and index. It is the type reported on by internal/report.
// The alias is additive; the on-disk format is unchanged.
type Doc = Manifest

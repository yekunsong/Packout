// Package scan implements the bounded, deterministic two-pass walker of
// docs/design-scan.md. It expands profile declarations, reads only what the
// budgets allow, and streams conclusions into a manifest.Writer. It never
// writes the target tree; the single exception is the declared sqlite
// -shm side effect of open_as: sqlite-ro.
package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"packout/internal/classify"
	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
)

// Config drives one scan. Profile and OutDir are required.
type Config struct {
	Profile *profile.Profile
	OutDir  string

	// Roots binds profile roles to concrete paths. An empty Path uses the
	// profile template; an empty Name uses the role (then role#2, role#3...).
	Roots []RootBinding

	GOOS string // defaults to runtime.GOOS
	Arch string // defaults to runtime.GOARCH

	Clock manifest.Clock
	Salt  manifest.SaltSource

	// Jobs bounds parallel file hashing; <= 0 takes min(GOMAXPROCS, 16).
	Jobs int

	FollowSymlinks bool
	// WithSessions emits profile entries flagged sessions: true per file
	// instead of by max_bytes_total/aggregate_above, and records the marker
	// in the header so export keeps their raw bytes.
	WithSessions bool
	// Selection decides which entries become units. Nil means "take every
	// entry" (the pre-selection behaviour, used by tests and embedders).
	Selection  *profile.Selection
	ShardUnits int
	ShardBytes int64
	Tool       string
}

// RootBinding is one --root role=PATH instance.
type RootBinding struct {
	Role   string
	Name   string
	Path   string
	Origin string
}

// ErrConfig marks errors that should map to exit code 3 (bad arguments or
// profile/root configuration). Per-entry failures never return an error.
var ErrConfig = errors.New("scan: configuration error")

// Result is the aggregate outcome of a successful Run.
type Result struct {
	// Roots maps each root instance name to the absolute source path used for
	// this scan. Exported so a later `export` can extract config without the
	// user retyping --root.
	Roots      map[string]string
	OutDir     string
	Units      int64
	Residual   int64
	ReadErrors int64
	Notes      int64
	Shards     int
	Complete   bool
}

// ExitCode is the design-scan exit code for a finished run: 0 for a complete
// corpus (handled read_error included), 2 when the run is incomplete.
func (r *Result) ExitCode() int {
	if r != nil && r.Complete {
		return 0
	}
	return 2
}

type rootInstance struct {
	name     string
	role     string
	path     string
	origin   string
	instance int
	order    int
}

type scanner struct {
	cfg   Config
	roots []rootInstance
	units []manifest.Unit
	notes []manifest.Note

	w         *manifest.Writer
	scanID    string
	salt      []byte
	covered   map[string]bool
	total     map[string]int64
	errs      int64
	profVer   string
	goos      string
	complete  bool
	rootNotes []manifest.Note
	churn     map[string]manifest.Fingerprint
	ignore    map[string][]gitRule
	gitSeen   map[string]bool
	signals   map[*profile.Entry][]manifest.Signal
	// budgetNoted dedupes the one-per-entry budget note in sessions mode.
	budgetNoted map[string]bool
	jobs        int
	// mu guards hits, matches, errs and the per-declaration seen maps while
	// glob walks run concurrently; notesMu guards the note slice.
	mu      sync.Mutex
	notesMu sync.Mutex

	// results of declaration pass, keyed by folded path.
	hits map[string][]candidate
}

type candidate struct {
	entry *profile.Entry
	root  *rootInstance
	path  string
	rel   string
	info  *fsx.Info
	cycle bool
}

// Run executes the scan. Fatal configuration/writer errors return an error.
// Per-entry failures are recorded as read_error units and do not abort.
func Run(ctx context.Context, cfg Config) (res *Result, err error) {
	if cfg.Profile == nil {
		return nil, fmt.Errorf("%w: profile is required", ErrConfig)
	}
	if cfg.OutDir == "" {
		return nil, fmt.Errorf("%w: output directory is required", ErrConfig)
	}
	s := &scanner{
		cfg:         cfg,
		goos:        cfg.GOOS,
		covered:     make(map[string]bool),
		total:       make(map[string]int64),
		hits:        make(map[string][]candidate),
		churn:       make(map[string]manifest.Fingerprint),
		ignore:      make(map[string][]gitRule),
		gitSeen:     make(map[string]bool),
		signals:     make(map[*profile.Entry][]manifest.Signal),
		budgetNoted: make(map[string]bool),
		complete:    true,
	}
	if s.goos == "" {
		s.goos = runtime.GOOS
	}
	s.jobs = normalizeJobs(cfg.Jobs)
	var w *manifest.Writer
	defer func() {
		if r := recover(); r != nil {
			if w != nil {
				w.Abort()
			}
			res = nil
			err = fmt.Errorf("%w: panic: %v", ErrConfig, r)
		}
	}()

	if err := s.resolveRoots(); err != nil {
		return nil, err
	}
	if len(s.roots) == 0 {
		return nil, fmt.Errorf("%w: no root resolved", ErrConfig)
	}
	s.salt = s.chooseSalt()
	s.profVer = profileVersion(cfg.Profile)

	hdr := s.header()
	w, err = manifest.NewWriter(cfg.OutDir, hdr, writerOptions(cfg)...)
	if err != nil {
		return nil, err
	}
	s.w = w
	s.scanID = w.ScanID()
	for _, n := range s.rootNotes {
		s.addNote(n)
	}

	s.declarePass(ctx)
	s.residualPass(ctx)

	s.classify()

	units := s.units
	roots := make([]manifest.Root, len(s.roots))
	for i, r := range s.roots {
		roots[i] = manifest.Root{Name: r.name}
	}
	manifest.SortWithRoots(units, roots)
	for i := range units {
		if err := w.WriteUnit(&units[i]); err != nil {
			w.Abort()
			return nil, err
		}
	}
	w.SetComplete(s.complete, 0)
	s.writeNotes()
	if err := w.Close(); err != nil {
		return nil, err
	}
	rootsMap := make(map[string]string, len(s.roots))
	for _, r := range s.roots {
		rootsMap[r.name] = r.path
	}
	return &Result{
		OutDir:     cfg.OutDir,
		Roots:      rootsMap,
		Units:      w.Units(),
		Residual:   countResidual(units),
		ReadErrors: s.errs,
		Notes:      int64(len(s.notes)),
		Shards:     w.Shards(),
		Complete:   s.complete,
	}, nil
}

// normalizeJobs resolves the global --jobs knob: default min(GOMAXPROCS, 16).
func normalizeJobs(n int) int {
	if n > 0 {
		return n
	}
	n = runtime.GOMAXPROCS(0)
	if n > 16 {
		n = 16
	}
	if n < 1 {
		n = 1
	}
	return n
}

func writerOptions(cfg Config) []manifest.Option {
	var opts []manifest.Option
	if cfg.Clock != nil {
		opts = append(opts, manifest.WithClock(cfg.Clock))
	}
	if cfg.Salt != nil {
		opts = append(opts, manifest.WithSalt(cfg.Salt))
	}
	return opts
}

func (s *scanner) chooseSalt() []byte {
	if s.cfg.Salt != nil {
		if v, err := s.cfg.Salt.Salt(); err == nil {
			return []byte(v)
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return []byte("packout-salt")
	}
	return []byte(hex.EncodeToString(b[:]))
}

func profileVersion(p *profile.Profile) string {
	if p.SchemaVersion != "" {
		return p.SchemaVersion
	}
	return profile.Schema
}

func profileDigest(p *profile.Profile) string {
	sum := sha256.Sum256(p.Source())
	return hex.EncodeToString(sum[:])
}

func (s *scanner) header() manifest.Header {
	host := manifest.Host{OS: s.goos, Arch: s.cfg.Arch}
	if host.Arch == "" {
		host.Arch = runtime.GOARCH
	}
	if s.goos == "windows" || s.goos == "darwin" {
		host.CaseSensitivity = "insensitive"
	} else {
		host.CaseSensitivity = "sensitive"
	}
	mode := "random"
	if s.cfg.Salt != nil {
		mode = "stable"
	}
	tool := s.cfg.Tool
	if tool == "" {
		tool = "packout/0.1.0"
	}
	roots := make([]manifest.Root, len(s.roots))
	for i, r := range s.roots {
		origin := r.origin
		if origin == "" {
			origin = "profile"
		}
		roots[i] = manifest.Root{
			Name: r.name, Role: r.role, Instance: r.instance,
			Origin: origin, Path: r.path, Profile: s.cfg.Profile.Name,
		}
	}
	opts := &manifest.InputOptions{
		FollowSymlinks: s.cfg.FollowSymlinks,
		WithSessions:   s.cfg.WithSessions,
	}
	if sel := s.cfg.Selection; sel != nil && !sel.IsDefault() {
		opts.Selection = &manifest.Selection{
			Preset:                sel.Preset,
			Include:               append([]string(nil), sel.Include...),
			Exclude:               append([]string(nil), sel.Exclude...),
			SessionsSince:         sel.SessionsSince,
			SessionsProjects:      append([]string(nil), sel.SessionsProjects...),
			SessionsMaxPerProject: sel.SessionsMaxPerProject,
		}
	}
	return manifest.Header{
		ManifestVersion: manifest.Version,
		Tool:            tool,
		Host:            host,
		Inputs: manifest.Inputs{
			SecretSaltMode: mode,
			SecretSalt:     string(s.salt),
			Profiles: []manifest.ProfileRef{{
				Name: s.cfg.Profile.Name, Version: profileVersion(s.cfg.Profile),
				SHA256: profileDigest(s.cfg.Profile),
			}},
			Options: opts,
		},
		ShardUnits: s.cfg.ShardUnits,
		ShardBytes: s.cfg.ShardBytes,
		Roots:      roots,
	}
}

func (s *scanner) classify() {
	unique := make(map[string]bool)
	for _, e := range s.cfg.Profile.Entries {
		if e.UniqueWithin != "" {
			unique[e.ID] = true
		}
	}
	units := s.backfillRepoSlugs(s.units)
	units = classify.Resolve(units)
	units = classify.ApplyUniqueness(units, classify.UniquenessScope{Mode: "root", Entries: unique})
	units = classify.EnforceConfidence(units)
	units = classify.MarkDeletionCost(units)
	s.markCaseCollisions(units)
	s.markIDCollisions(units)
	s.units = units
}

// markIDCollisions keeps the first unit for an id and flags the later ones.
func (s *scanner) markIDCollisions(units []manifest.Unit) {
	seen := make(map[string]bool, len(units))
	for i := range units {
		if seen[units[i].ID] {
			units[i].RiskFlags = appendFlag(units[i].RiskFlags, "id_collision")
			// Fold the on-disk spelling in so the later id is unique even
			// when path_key folds two case variants together.
			units[i].ID = manifest.UnitID(units[i].Root, units[i].Profile,
				units[i].Entry, units[i].PartID+"\x00"+units[i].Path, units[i].PathKey)
			continue
		}
		seen[units[i].ID] = true
	}
}

// backfillRepoSlugs builds the profile-local json_path_key -> repo_slug map
// from project-index origins and fills repo_slug units (D-024 #3).
func (s *scanner) backfillRepoSlugs(units []manifest.Unit) []manifest.Unit {
	slugs := make(map[string][]string)
	for i := range units {
		u := &units[i]
		if u.Origin == nil || u.DerivedFrom == nil || *u.DerivedFrom != manifest.DerivedJSONPathKey {
			continue
		}
		slug := slugify(*u.Origin)
		if slug == "" {
			continue
		}
		seen := false
		for _, o := range slugs[slug] {
			if o == *u.Origin {
				seen = true
			}
		}
		if !seen {
			slugs[slug] = append(slugs[slug], *u.Origin)
		}
	}
	if len(slugs) == 0 {
		return units
	}
	for i := range units {
		u := &units[i]
		if u.DerivedFrom == nil || *u.DerivedFrom != manifest.DerivedRepoSlug || u.Origin != nil {
			continue
		}
		slug := slugSegment(u.Path)
		origins := slugs[slug]
		if len(origins) == 0 {
			continue
		}
		origin := origins[0]
		key := fsx.NormKey(origin)
		u.Origin = &origin
		u.OriginPathKey = &key
		if len(origins) > 1 {
			u.RiskFlags = appendFlag(u.RiskFlags, "slug_collision")
			s.addNote(manifest.Note{Code: "slug_collision", Entry: u.Entry,
				Detail: fmt.Sprintf("slug %s 对应多个 origin: %s", slug, strings.Join(origins, ", "))})
		}
	}
	return units
}

func slugify(origin string) string {
	r := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "_", "-", ".", "-")
	return r.Replace(origin)
}

// slugSegment returns the path component directly below "projects".
func slugSegment(p string) string {
	segs := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	for i, seg := range segs {
		if seg == "projects" && i+1 < len(segs) {
			return segs[i+1]
		}
	}
	return ""
}

// markCaseCollisions flags paths whose folded key is shared by two spellings.
func (s *scanner) markCaseCollisions(units []manifest.Unit) {
	paths := make(map[string]map[string]bool)
	for i := range units {
		if units[i].PathKey == "" {
			continue
		}
		if paths[units[i].PathKey] == nil {
			paths[units[i].PathKey] = make(map[string]bool)
		}
		paths[units[i].PathKey][units[i].Path] = true
	}
	for i := range units {
		if len(paths[units[i].PathKey]) > 1 {
			units[i].RiskFlags = appendFlag(units[i].RiskFlags, "case_collision")
		}
	}
}

func countResidual(units []manifest.Unit) int64 {
	var n int64
	for i := range units {
		if units[i].Kind == manifest.KindCatchAll {
			n++
		}
	}
	return n
}

func (s *scanner) addNote(n manifest.Note) {
	s.notesMu.Lock()
	defer s.notesMu.Unlock()
	n.Type = manifest.TypeNote
	n.ScanID = s.scanID
	if n.Profile == "" {
		n.Profile = s.cfg.Profile.Name
	}
	s.notes = append(s.notes, n)
}

func (s *scanner) writeNotes() {
	sort.SliceStable(s.notes, func(i, j int) bool {
		a, b := &s.notes[i], &s.notes[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Entry != b.Entry {
			return a.Entry < b.Entry
		}
		if a.PartID != b.PartID {
			return a.PartID < b.PartID
		}
		return a.Detail < b.Detail
	})
	for i := range s.notes {
		_ = s.w.WriteNote(&s.notes[i])
	}
}

func appendFlag(flags []string, f string) []string {
	for _, x := range flags {
		if x == f {
			return flags
		}
	}
	return append(flags, f)
}

func (s *scanner) entryApplies(e *profile.Entry) bool {
	if e.Kind == profile.KindCatchAll {
		return false
	}
	if len(e.OS) > 0 {
		ok := false
		for _, o := range e.OS {
			if o == s.goos {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// entryRoots returns every instance an entry applies to.
func (s *scanner) entryRoots(e *profile.Entry) []*rootInstance {
	if e.Root == "" {
		return []*rootInstance{nil} // absolute entry
	}
	var out []*rootInstance
	for i := range s.roots {
		r := &s.roots[i]
		if e.Root == r.role || e.Root == r.name {
			out = append(out, r)
		}
	}
	return out
}

// absPath expands an absolute path template and preserves it as the on-disk
// spelling (only clean/absolutize, never case-fold).
func absPath(tmpl string) (string, error) {
	expanded, err := profile.ExpandTemplate(tmpl)
	if err != nil {
		return "", err
	}
	return fsx.Abs(filepath.FromSlash(expanded))
}

func joinRoot(root, rel string) string {
	return filepath.Join(root, filepath.FromSlash(rel))
}

func slashRel(root, p string) string {
	r, err := fsx.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

func pathKey(p string) string { return fsx.NormKey(p) }

func containsPath(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

func joinStrings(v []string) string { return strings.Join(v, ",") }

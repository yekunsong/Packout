package manifest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"packout/internal/fsx"
)

// Severity levels of §11.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Issue is one validation finding.
type Issue struct {
	Code     string
	Severity string
	Message  string
	Shard    string
	Line     int
}

// String renders an issue in a stable, log-friendly form.
func (i Issue) String() string {
	loc := i.Shard
	if i.Line > 0 {
		loc = fmt.Sprintf("%s:%d", i.Shard, i.Line)
	}
	if loc == "" {
		return fmt.Sprintf("%s %s: %s", i.Severity, i.Code, i.Message)
	}
	return fmt.Sprintf("%s %s %s: %s", loc, i.Severity, i.Code, i.Message)
}

// ValidationError carries every finding; by default it is returned only when
// at least one error-severity issue exists.
type ValidationError struct{ Issues []Issue }

// Error implements error.
func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "manifest: validation failed"
	}
	var b strings.Builder
	b.WriteString("manifest: validation failed")
	n := 0
	for _, is := range e.Issues {
		if is.Severity != SeverityError {
			continue
		}
		if n == 5 {
			b.WriteString("; …")
			break
		}
		b.WriteString("; ")
		b.WriteString(is.Code)
		if is.Message != "" {
			b.WriteString(": ")
			b.WriteString(is.Message)
		}
		n++
	}
	return b.String()
}

// HasErrors reports whether the collected issues contain an error.
func (e *ValidationError) HasErrors() bool {
	if e == nil {
		return false
	}
	for _, is := range e.Issues {
		if is.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Manifest is a complete, structurally validated manifest.
type Manifest struct {
	Header Header
	Units  []Unit
	Notes  []Note
	Footer Footer
	Index  *Index
}

// Read returns the units of a complete manifest in file order. An incomplete
// or structurally invalid manifest yields an error. Notes and headers are
// available through ReadManifest.
func Read(dir string) ([]Unit, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return nil, err
	}
	return m.Units, nil
}

// ReadManifest loads and validates a complete manifest. It fails unless the
// directory has a footer and an index whose counts agree with the files
// (E-MAN-030).
func ReadManifest(dir string) (*Manifest, error) {
	l := &loader{dir: dir}
	l.load()
	if l.hasErrors() {
		return nil, &ValidationError{Issues: l.issues}
	}
	m := &Manifest{Units: l.units, Notes: l.notes, Index: l.index}
	if l.header != nil {
		m.Header = *l.header
	}
	if l.footer != nil {
		m.Footer = *l.footer
	}
	return m, nil
}

// ValidateAll returns every finding (errors and warnings) for dir.
func ValidateAll(dir string) []Issue {
	l := &loader{dir: dir}
	l.load()
	return l.issues
}

// Validate checks a manifest directory. It returns a *ValidationError when at
// least one error-severity issue exists; warning-only manifests pass. Use
// ValidateAll for a strict/warning report.
func Validate(dir string) error {
	issues := ValidateAll(dir)
	for _, is := range issues {
		if is.Severity == SeverityError {
			return &ValidationError{Issues: issues}
		}
	}
	return nil
}

// ---- loader ---------------------------------------------------------------

type unitLoc struct {
	shard string
	line  int
}

type loader struct {
	dir    string
	issues []Issue

	header  *Header
	footer  *Footer
	index   *Index
	units   []Unit
	notes   []Note
	unitLoc []unitLoc

	shards     []string
	shardUnits map[string]int64
	shardBytes map[string]int64
}

func (l *loader) add(sev, code, shard string, line int, format string, args ...any) {
	l.issues = append(l.issues, Issue{
		Code: code, Severity: sev, Shard: shard, Line: line,
		Message: fmt.Sprintf(format, args...),
	})
}

func (l *loader) errf(shard string, line int, code, format string, args ...any) {
	l.add(SeverityError, code, shard, line, format, args...)
}

func (l *loader) warnf(shard string, line int, code, format string, args ...any) {
	l.add(SeverityWarning, code, shard, line, format, args...)
}

func (l *loader) hasErrors() bool {
	for _, is := range l.issues {
		if is.Severity == SeverityError {
			return true
		}
	}
	return false
}

func (l *loader) load() {
	l.shardUnits = make(map[string]int64)
	l.shardBytes = make(map[string]int64)

	if _, err := os.Stat(filepath.Join(l.dir, ".lock")); err == nil {
		l.errf("", 0, "E-MAN-031", "unreleased .lock in %s", l.dir)
	}

	if data, err := os.ReadFile(filepath.Join(l.dir, "manifest.index.json")); err == nil {
		var idx Index
		if err := json.Unmarshal(data, &idx); err != nil {
			l.errf("manifest.index.json", 0, "E-MAN-030", "index is not valid JSON: %v", err)
		} else {
			l.index = &idx
		}
	}

	shards, err := l.shardNames()
	if err != nil {
		l.errf("", 0, "E-MAN-030", "cannot list shards: %v", err)
		return
	}
	l.shards = shards
	if len(shards) == 0 {
		l.errf("", 0, "E-MAN-030", "no manifest shards")
		return
	}

	var lastRecordType, lastShard string
	var lastLine int
	for si, name := range shards {
		path := filepath.Join(l.dir, name)
		f, err := os.Open(path)
		if err != nil {
			l.errf(name, 0, "E-MAN-030", "shard cannot be opened: %v", err)
			continue
		}
		// A shard with zero units is legal (an empty scan) and must still be
		// accounted for, otherwise checkIndex reports it as missing.
		l.shardUnits[name] = 0
		st, _ := f.Stat()
		if st != nil {
			l.shardBytes[name] = st.Size()
		}
		br := bufio.NewReaderSize(f, 256<<10)
		line := 0
		for {
			raw, readErr := br.ReadString('\n')
			if len(raw) > 0 {
				line++
				text := strings.TrimSuffix(raw, "\n")
				text = strings.TrimSuffix(text, "\r")
				if len(text)+1 > MaxLineBytes {
					l.errf(name, line, "E-MAN-002", "line exceeds %d bytes", MaxLineBytes)
				} else if text == "" {
					l.errf(name, line, "E-MAN-002", "empty line")
				} else {
					typ, hasType := recordType(text)
					if !json.Valid([]byte(text)) {
						l.errf(name, line, "E-MAN-002", "record is not valid JSON")
						lastRecordType, lastShard, lastLine = "<invalid>", name, line
					} else if !hasType {
						l.errf(name, line, "E-MAN-004", "record has no type")
						lastRecordType, lastShard, lastLine = "<untyped>", name, line
					} else {
						lastRecordType, lastShard, lastLine = typ, name, line
						switch typ {
						case TypeHeader:
							if si == 0 && line == 1 {
								if l.header != nil {
									l.errf(name, line, "E-MAN-001", "duplicate header")
								} else {
									var h Header
									if err := json.Unmarshal([]byte(text), &h); err != nil {
										l.errf(name, line, "E-MAN-002", "header: %v", err)
									} else {
										l.header = &h
									}
								}
							} else {
								l.errf(name, line, "E-MAN-001", "header must be the first line of shard 1")
							}
						case TypeUnit:
							var u Unit
							if err := json.Unmarshal([]byte(text), &u); err != nil {
								l.errf(name, line, "E-MAN-002", "unit: %v", err)
								break
							}
							l.units = append(l.units, u)
							l.unitLoc = append(l.unitLoc, unitLoc{shard: name, line: line})
							l.shardUnits[name]++
						case TypeNote:
							var n Note
							if err := json.Unmarshal([]byte(text), &n); err != nil {
								l.errf(name, line, "E-MAN-002", "note: %v", err)
								break
							}
							if !n.present["scan_id"] || n.ScanID == "" {
								l.errf(name, line, "E-MAN-005", "note missing required field scan_id")
							}
							if !n.present["code"] || n.Code == "" {
								l.errf(name, line, "E-MAN-005", "note missing required field code")
							}
							l.notes = append(l.notes, n)
						case TypeFooter:
							if l.footer != nil {
								l.errf(name, line, "E-MAN-030", "duplicate footer")
								break
							}
							var ft Footer
							if err := json.Unmarshal([]byte(text), &ft); err != nil {
								l.errf(name, line, "E-MAN-002", "footer: %v", err)
								break
							}
							l.footer = &ft
						default:
							l.errf(name, line, "E-MAN-004", "unknown record type %q", typ)
						}
					}
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				l.errf(name, line+1, "E-MAN-002", "read error: %v", readErr)
				break
			}
		}
		f.Close()
		if si == 0 && line == 0 {
			l.errf(name, 1, "E-MAN-001", "first shard is empty")
		}
		if si == 0 && l.header == nil && line > 0 {
			l.errf(name, 1, "E-MAN-001", "first line is not a header")
		}
	}

	if l.footer != nil && (lastRecordType != TypeFooter || lastShard != l.shards[len(l.shards)-1]) {
		l.errf(lastShard, lastLine, "E-MAN-030", "footer is not the last line of the last shard")
	}
	if l.footer == nil {
		l.errf(lastShard, lastLine, "E-MAN-030", "missing footer")
	}
	if l.header == nil {
		l.errf(l.shards[0], 1, "E-MAN-001", "missing header")
	}

	l.checkIndex()
	l.checkHeader()
	l.checkFooter()
	l.checkUnits()
}

// shardNames returns the shard files in scan order. The index is authoritative
// when present; otherwise names are discovered and sorted by numeric suffix.
func (l *loader) shardNames() ([]string, error) {
	if l.index != nil {
		out := make([]string, 0, len(l.index.Shards))
		for _, s := range l.index.Shards {
			if s.Name == "" || filepath.Base(s.Name) != s.Name {
				l.errf("manifest.index.json", 0, "E-MAN-030", "invalid shard name %q", s.Name)
				continue
			}
			out = append(out, s.Name)
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := shardSeq(e.Name()); ok {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		si, _ := shardSeq(names[i])
		sj, _ := shardSeq(names[j])
		return si < sj
	})
	return names, nil
}

func shardSeq(name string) (int, bool) {
	const prefix = "manifest."
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".jsonl") {
		return 0, false
	}
	num := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".jsonl")
	if len(num) < 4 {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// recordType extracts the type discriminator from a raw, already validated
// JSON line. The second result is false when the type key is missing.
func recordType(line string) (string, bool) {
	var probe struct {
		Type *string `json:"type"`
	}
	if err := json.Unmarshal([]byte(line), &probe); err != nil {
		return "", false
	}
	if probe.Type == nil {
		return "", false
	}
	return *probe.Type, true
}

func (l *loader) checkIndex() {
	if l.index == nil {
		l.errf("", 0, "E-MAN-030", "missing manifest.index.json")
		return
	}
	idx := l.index
	if len(idx.Shards) != len(l.shards) {
		l.errf("manifest.index.json", 0, "E-MAN-030", "index lists %d shards, found %d", len(idx.Shards), len(l.shards))
	}
	for _, s := range idx.Shards {
		actualUnits, ok := l.shardUnits[s.Name]
		if !ok {
			l.errf("manifest.index.json", 0, "E-MAN-030", "index names missing shard %s", s.Name)
			continue
		}
		if s.Units != actualUnits {
			l.errf("manifest.index.json", 0, "E-MAN-030", "shard %s units %d, actual %d", s.Name, s.Units, actualUnits)
		}
		if bytes, ok := l.shardBytes[s.Name]; ok && s.Bytes != bytes {
			l.errf("manifest.index.json", 0, "E-MAN-030", "shard %s bytes %d, actual %d", s.Name, s.Bytes, bytes)
		}
		if s.SHA256 != "" {
			if sum, err := fileSHA256(filepath.Join(l.dir, s.Name)); err == nil && sum != s.SHA256 {
				l.errf("manifest.index.json", 0, "E-MAN-030", "shard %s sha256 mismatch", s.Name)
			}
		}
	}
	// Segment continuity (§2, E-MAN-042). A directory may contain only a
	// continuation segment, so segment 0 is not required to have seq 0; its
	// parent presence is what distinguishes the cases.
	for i, seg := range idx.Segments {
		if i == 0 {
			if seg.Parent == nil && seg.SegmentSeq != 0 {
				l.errf("manifest.index.json", 0, "E-MAN-042", "first segment_seq is %d but has no parent", seg.SegmentSeq)
			}
			if seg.Parent != nil && seg.SegmentSeq == 0 {
				l.errf("manifest.index.json", 0, "E-MAN-042", "first segment has a parent but segment_seq 0")
			}
			continue
		}
		prev := idx.Segments[i-1]
		if seg.SegmentSeq != prev.SegmentSeq+1 {
			l.errf("manifest.index.json", 0, "E-MAN-042", "segment_seq %d is not contiguous", seg.SegmentSeq)
		}
		if seg.Parent == nil {
			l.errf("manifest.index.json", 0, "E-MAN-042", "continuation segment lacks parent")
		}
		if want := prev.FirstShard + len(prev.Shards); seg.FirstShard != want {
			l.errf("manifest.index.json", 0, "E-MAN-042", "segment %d first_shard %d, expected %d", i, seg.FirstShard, want)
		}
	}
	if l.header != nil && len(idx.Segments) > 0 {
		first := idx.Segments[0]
		if l.header.ScanSegment.FirstShard != first.FirstShard || l.header.ScanSegment.SegmentSeq != first.SegmentSeq {
			l.errf("manifest.index.json", 0, "E-MAN-042", "header scan_segment does not match index segment")
		}
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (l *loader) checkHeader() {
	h := l.header
	if h == nil {
		return
	}
	for _, is := range checkHeaderRequired(h) {
		is.Shard = l.shards[0]
		l.issues = append(l.issues, is)
	}
	if major, ok := majorOf(h.ManifestVersion); !ok {
		l.errf(l.shards[0], 1, "E-MAN-040", "invalid manifest_version %q", h.ManifestVersion)
	} else if major > SupportedMajor {
		l.errf(l.shards[0], 1, "E-MAN-040", "manifest MAJOR %d newer than supported %d", major, SupportedMajor)
	}
	switch h.Inputs.SecretSaltMode {
	case "random", "stable":
	default:
		l.errf(l.shards[0], 1, "E-MAN-043", "invalid secret_salt_mode %q", h.Inputs.SecretSaltMode)
	}
	if h.Host.PathFoldVersion == "" {
		l.errf(l.shards[0], 1, "E-MAN-026", "header missing path_fold_version")
	} else if !PathFoldVersionMatches(h.Host.PathFoldVersion) {
		l.warnf(l.shards[0], 1, "W-MAN-113", "path_fold_version %q differs from this build %q", h.Host.PathFoldVersion, CurrentPathFoldVersion())
	}
	if h.ScanSegment.FirstShard < 1 {
		l.errf(l.shards[0], 1, "E-MAN-042", "scan_segment.first_shard must be >= 1")
	}
	if h.ScanSegment.SegmentSeq > 0 && h.ScanSegment.Parent == nil {
		l.errf(l.shards[0], 1, "E-MAN-042", "scan_segment.parent required for segment_seq > 0")
	}
	if h.ScanSegment.SegmentSeq == 0 && h.ScanSegment.Parent != nil {
		l.errf(l.shards[0], 1, "E-MAN-042", "scan_segment.parent must be null for segment_seq 0")
	}
	if h.ShardUnits <= 0 {
		l.errf(l.shards[0], 1, "E-MAN-005", "shard_units must be positive")
	}
	if h.ShardBytes <= 0 {
		l.errf(l.shards[0], 1, "E-MAN-005", "shard_bytes must be positive")
	}
}

func (l *loader) checkFooter() {
	f := l.footer
	if f == nil {
		return
	}
	shard := l.shards[len(l.shards)-1]
	req := []struct {
		key string
		ok  bool
	}{
		{"manifest_version", f.ManifestVersion != ""},
		{"scan_id", f.ScanID != ""},
		{"ended_at", !f.EndedAt.IsZero()},
		{"stats", f.present["stats"] || f.Stats.L0+f.Stats.L1+f.Stats.L2+f.Stats.L3+f.Stats.L4+f.Stats.L5+f.Stats.Residual > 0},
	}
	for _, r := range req {
		if !f.present[r.key] && !r.ok {
			l.errf(shard, 0, "E-MAN-005", "footer missing required field %s", r.key)
		}
	}
	if !f.present["units"] {
		l.errf(shard, 0, "E-MAN-005", "footer missing required field units")
	}
	if !f.present["shards"] {
		l.errf(shard, 0, "E-MAN-005", "footer missing required field shards")
	}
	if !f.present["complete"] {
		l.errf(shard, 0, "E-MAN-005", "footer missing required field complete")
	}
	if l.header != nil && f.ManifestVersion != l.header.ManifestVersion {
		l.errf(shard, 0, "E-MAN-023", "footer manifest_version %q != header %q", f.ManifestVersion, l.header.ManifestVersion)
	}
	if n := int64(len(l.units)); f.Units != n {
		l.errf(shard, 0, "E-MAN-041", "footer units %d, actual %d", f.Units, n)
	}
	if f.Shards != len(l.shards) {
		l.errf(shard, 0, "E-MAN-030", "footer shards %d, actual %d", f.Shards, len(l.shards))
	}
	catchAll := int64(0)
	for i := range l.units {
		if l.units[i].Kind == KindCatchAll {
			catchAll++
		}
	}
	if f.Stats.Residual != catchAll {
		l.errf(shard, 0, "E-MAN-059", "stats.residual %d, catch-all units %d", f.Stats.Residual, catchAll)
	}
	if l.index != nil {
		if l.index.Residual != f.Stats.Residual {
			l.errf("manifest.index.json", 0, "E-MAN-059", "index residual %d != footer residual %d", l.index.Residual, f.Stats.Residual)
		}
		if l.index.Units != f.Units {
			l.errf("manifest.index.json", 0, "E-MAN-030", "index units %d != footer units %d", l.index.Units, f.Units)
		}
	}
	if f.Stats.Residual > 0 {
		l.warnf(shard, 0, "W-MAN-114", "%d residual units were not declared by any entry", f.Stats.Residual)
	}
}

func (l *loader) checkUnits() {
	if len(l.units) == 0 {
		return
	}
	ids := make(map[string]bool, len(l.units))
	keys := make(map[string]bool, len(l.units))
	paths := make(map[string]bool, len(l.units))
	rootNames := make(map[string]bool)
	if l.header != nil {
		for _, r := range l.header.Roots {
			rootNames[r.Name] = true
		}
	}
	profileByPath := make(map[string]string)
	foldVersionOK := l.header != nil && PathFoldVersionMatches(l.header.Host.PathFoldVersion)

	for i := range l.units {
		u := &l.units[i]
		loc := l.unitLoc[i]
		l.validateUnit(u, loc, ids, keys, paths, rootNames, foldVersionOK)
		if p, ok := profileByPath[u.PathKey]; ok && p != u.Profile {
			l.warnf(loc.shard, loc.line, "W-MAN-111", "path_key %q hit by profiles %q and %q", u.PathKey, p, u.Profile)
		} else if !ok {
			profileByPath[u.PathKey] = u.Profile
		}
	}

	// E-MAN-063: a companion suffix must not appear as an independent unit.
	for i := range l.units {
		u := &l.units[i]
		if len(u.Companions) == 0 {
			continue
		}
		for _, suffix := range u.Companions {
			candidate := u.Path + suffix
			if paths[candidate] {
				loc := l.unitLoc[i]
				l.errf(loc.shard, loc.line, "E-MAN-063", "companion %q of %q exists as an independent unit", suffix, u.Path)
			}
		}
	}
}

// validateUnit applies every per-unit E-MAN rule that does not require the
// profile definition (E-MAN-052 and the descendant recomputations of
// E-MAN-053/054 are therefore structural only).
func (l *loader) validateUnit(u *Unit, loc unitLoc, ids, keys, paths, rootNames map[string]bool, foldVersionOK bool) {
	errf := func(code, format string, args ...any) { l.errf(loc.shard, loc.line, code, format, args...) }
	warnf := func(code, format string, args ...any) { l.warnf(loc.shard, loc.line, code, format, args...) }

	// E-MAN-005 required fields.
	for _, key := range unitRequiredFields {
		if !u.present[key] {
			errf("E-MAN-005", "unit missing required field %s", key)
		}
	}

	// E-MAN-004 / E-MAN-010.
	if !isKnownKind(u.Kind) {
		errf("E-MAN-010", "invalid kind %q", u.Kind)
	}
	if !containsString(layerOrder, u.Layer) {
		errf("E-MAN-010", "invalid layer %q", u.Layer)
	}
	if !isKnownAction(u.ProposedAction) {
		errf("E-MAN-010", "invalid proposed_action %q", u.ProposedAction)
	}

	// E-MAN-006.
	if !unitIDPattern.MatchString(u.ID) {
		errf("E-MAN-006", "id %q does not match u_<26 Crockford chars>", u.ID)
	}
	if ids[u.ID] {
		errf("E-MAN-003", "duplicate id %q", u.ID)
	}
	ids[u.ID] = true

	// E-MAN-025 uniqueness.
	key := uniquenessKey(u)
	if keys[key] {
		errf("E-MAN-025", "duplicate unit key %q", key)
	}
	keys[key] = true
	paths[u.Path] = true

	// E-MAN-011/012/013.
	if len(u.Signals) == 0 && u.Kind != KindCatchAll {
		errf("E-MAN-011", "signals must not be empty")
	}
	for si, s := range u.Signals {
		if s.Src == "" || s.Note == "" {
			errf("E-MAN-012", "signal %d missing src or note", si)
		}
		if s.Src == "official_docs" && (s.URL == nil || *s.URL == "") {
			errf("E-MAN-013", "official_docs signal %d missing url", si)
		}
		if len(s.Note) > MaxNoteBytes {
			errf("E-MAN-012", "signal %d note exceeds %d bytes", si, MaxNoteBytes)
		}
		if s.Src == "user_override" {
			warnf("W-MAN-112", "unit carries a user_override signal")
		}
		if containsPlaintextish(s.Note) {
			errf("E-MAN-017", "signal %d note looks like plaintext credential material", si)
		}
	}

	// E-MAN-014/015.
	if u.Confidence < 0 || u.Confidence > 1 || math.IsNaN(u.Confidence) {
		errf("E-MAN-014", "confidence %v outside [0,1]", u.Confidence)
	}
	if decimals(u.confidenceRaw) > 3 {
		errf("E-MAN-014", "confidence %q has more than three decimal places", u.confidenceRaw)
	}
	if u.Confidence < 0.9 && u.ProposedAction != ActionKeep {
		errf("E-MAN-015", "confidence %.3f < 0.9 requires proposed_action keep", u.Confidence)
	}
	if u.Confidence < 0.9 && !containsString(u.RiskFlags, "low_confidence") {
		warnf("W-MAN-110", "confidence %.3f < 0.9 without low_confidence flag", u.Confidence)
	}

	// Secret shape (§4.3, E-MAN-016/018).
	if u.Secret != nil {
		if !isKnownSecretClass(u.Secret.Class) {
			errf("E-MAN-010", "invalid secret.class %q", u.Secret.Class)
		}
		if (u.Secret.Class == SecretRestore || u.Secret.Class == SecretRelogin) && u.Confidence < 0.95 {
			errf("E-MAN-016", "secret.class %q requires confidence >= 0.95", u.Secret.Class)
		}
		if u.Secret.Class != SecretNone && len(u.Secret.Hits) > 0 {
			for hi, h := range u.Secret.Hits {
				if h.Locator == "" {
					errf("E-MAN-018", "secret hit %d missing locator", hi)
				}
				if len(h.Prefix) > 7 {
					errf("E-MAN-017", "secret hit %d prefix %q exceeds 7 bytes", hi, h.Prefix)
				}
				if h.Fingerprint != "" && !secretFPPattern.MatchString(h.Fingerprint) {
					errf("E-MAN-018", "secret hit %d fingerprint %q has invalid format", hi, h.Fingerprint)
				}
			}
		}
	}

	// Sizes (§4.4, E-MAN-019/022).
	sparse := containsString(u.RiskFlags, "sparse")
	if u.SizeAlloc != nil && *u.SizeAlloc < 0 {
		errf("E-MAN-019", "size_alloc is negative")
	}
	if u.SizeApparent != nil && u.SizeAlloc != nil && !sparse &&
		*u.SizeApparent > 0 && *u.SizeAlloc*2 < *u.SizeApparent {
		errf("E-MAN-019", "size_alloc %d is less than half of size_apparent %d", *u.SizeAlloc, *u.SizeApparent)
	}
	if u.FileID != nil && len(u.FileID.ReparseTag) > 0 && !isJSONNull(u.FileID.ReparseTag) {
		if u.FileID.VolumeSerial == "" || u.FileID.Index == "" {
			errf("E-MAN-022", "reparse_tag set but file_id is incomplete")
		}
		if !validReparseTag(u.FileID.ReparseTag) {
			errf("E-MAN-051", "reparse_tag must be a number or \"symlink\"")
		}
	}

	// Path (§6, E-MAN-007/008/021/065) and path_key (§6.3, E-MAN-009/026).
	named, scheme := namedLocation(u.Path)
	if named {
		if !allowedNamedSchemes[scheme] {
			errf("E-MAN-021", "named-location scheme %q is not allowed", scheme)
		}
	} else {
		if !isAbsolutePath(u.Path) {
			errf("E-MAN-007", "path %q is not absolute", u.Path)
		}
		if strings.HasPrefix(u.Path, `\\?\`) || strings.HasPrefix(u.Path, `//?/`) {
			errf("E-MAN-065", "path contains a \\\\?\\ prefix")
		}
		if hasDotComponent(u.Path) {
			errf("E-MAN-008", "path contains a . component")
		}
		if hasParentComponent(u.Path) {
			errf("E-MAN-065", "path contains a .. component")
		}
		if hasTrailingSeparator(u.Path) && !isPathRoot(u.Path) {
			errf("E-MAN-008", "path has a trailing separator")
		}
		if u.Root == "external" && l.header != nil {
			uk := expectedPathKey(u.Path)
			for _, r := range l.header.Roots {
				if r.Path == "" {
					continue
				}
				if keyWithin(expectedPathKey(r.Path), uk) {
					errf("E-MAN-065", "root external but path is inside declared root %q", r.Name)
					break
				}
			}
		}
	}
	expectedKey := expectedPathKey(u.Path)
	if expectedKey != "" && expectedKey != u.PathKey {
		if foldVersionOK {
			errf("E-MAN-009", "path_key %q does not match folded path %q", u.PathKey, expectedKey)
		} else {
			warnf("W-MAN-113", "path_key %q differs from this build's fold %q", u.PathKey, expectedKey)
		}
	}
	if u.Root != "" && u.Root != "os" && u.Root != "external" && !rootNames[u.Root] {
		errf("E-MAN-060", "root %q is not declared in header roots", u.Root)
	}

	// path_semantics / origin (§4.9, E-MAN-058/069).
	switch u.PathSemantics {
	case SemanticsLiteral:
		if u.DerivedFrom != nil {
			errf("E-MAN-058", "literal unit must have derived_from null")
		}
		if u.Origin != nil || u.OriginPathKey != nil {
			errf("E-MAN-069", "origin fields are only allowed on machine_derived units")
		}
	case SemanticsMachineDerived:
		if u.DerivedFrom == nil || *u.DerivedFrom == "" {
			errf("E-MAN-058", "machine_derived unit missing derived_from")
		}
		if !containsString(u.RiskFlags, "machine_derived_path") {
			warnf("W-MAN-115", "machine_derived unit missing machine_derived_path flag")
		}
	default:
		errf("E-MAN-058", "invalid path_semantics %q", u.PathSemantics)
	}
	if (u.Origin == nil) != (u.OriginPathKey == nil) {
		errf("E-MAN-069", "origin and origin_path_key must both be null or both be set")
	}
	if u.Origin != nil && u.OriginPathKey != nil {
		if u.PathSemantics != SemanticsMachineDerived {
			errf("E-MAN-069", "origin is only allowed on machine_derived units")
		}
		if fsx.NormKey(*u.Origin) != *u.OriginPathKey {
			errf("E-MAN-069", "origin_path_key %q does not match origin fold", *u.OriginPathKey)
		}
	}

	// schema_version (E-MAN-023).
	if l.header != nil && u.SchemaVersion != l.header.ManifestVersion {
		errf("E-MAN-023", "schema_version %q != header %q", u.SchemaVersion, l.header.ManifestVersion)
	}

	// proposed_action compatibility (E-MAN-024).
	if u.ProposedAction != ActionKeep && !actionAllowed(u.Layer, u.ProposedAction) {
		errf("E-MAN-024", "proposed_action %q is not allowed on layer %q", u.ProposedAction, u.Layer)
	}

	// fingerprint / cid (E-MAN-028/067).
	aggregate := isAggregate(u)
	if u.Fingerprint != nil {
		switch u.Fingerprint.Scope {
		case "full", "head-tail", "keys", "aggregate", "shape", "":
		default:
			errf("E-MAN-010", "invalid fingerprint.scope %q", u.Fingerprint.Scope)
		}
		if u.Fingerprint.Scope == "" && u.Fingerprint.Value != nil {
			errf("E-MAN-067", "null fingerprint scope requires a null value")
		}
		if u.Fingerprint.Scope == "keys" && u.Fingerprint.Value == nil {
			errf("E-MAN-067", "keys fingerprint scope requires a value")
		}
		if u.Fingerprint.Algo != "sha256" {
			errf("E-MAN-010", "unsupported fingerprint algo %q", u.Fingerprint.Algo)
		}
	}
	expectedCID := CID(u.Fingerprint)
	if expectedCID == nil {
		if u.CID != nil {
			errf("E-MAN-028", "cid must be null for this fingerprint")
		}
	} else {
		if u.CID == nil {
			errf("E-MAN-028", "cid is required for a non-null fingerprint value")
		} else if *u.CID != *expectedCID {
			errf("E-MAN-028", "cid %q does not match fingerprint (expected %q)", *u.CID, *expectedCID)
		}
	}
	if u.CID != nil && !cidPattern.MatchString(*u.CID) {
		errf("E-MAN-028", "cid %q has invalid format", *u.CID)
	}

	// aggregate shape (E-MAN-029/053/054).
	if aggregate {
		if u.AggregateCount == nil {
			errf("E-MAN-029", "aggregate unit missing aggregate_count")
		} else if *u.AggregateCount < 0 {
			errf("E-MAN-029", "aggregate_count is negative")
		}
		if !containsString(u.RiskFlags, "aggregated") {
			errf("E-MAN-029", "aggregate unit missing aggregated risk flag")
		}
		if u.ContainsSecret == nil || u.MayContainSecret == nil {
			errf("E-MAN-053", "aggregate unit missing contains_secret/may_contain_secret")
		}
		if u.Secret != nil && len(u.Secret.Hits) > 0 {
			errf("E-MAN-053", "aggregate unit must not carry secret hits")
		}
		if u.ContainsSecret != nil && *u.ContainsSecret && u.Secret != nil && u.Secret.Class == SecretNone {
			errf("E-MAN-053", "contains_secret is true but secret.class is none")
		}
		if u.Fingerprint != nil && u.Fingerprint.Scope != "aggregate" && u.Fingerprint.Scope != "" {
			errf("E-MAN-054", "aggregate fingerprint scope must be aggregate")
		}
		if u.Kind != KindCatchAll && !hasSignalSource(u.Signals, "content_match") && !hasSignalSource(u.Signals, "filesystem_stat") {
			errf("E-MAN-054", "aggregate unit needs a content_match or filesystem_stat signal")
		}
	}

	// catch-all shape (E-MAN-055/064/068).
	if u.Kind == KindCatchAll {
		if !containsString(u.RiskFlags, "residual") || !containsString(u.RiskFlags, "low_confidence") {
			errf("E-MAN-055", "catch-all unit must carry residual and low_confidence")
		}
		if u.ProposedAction != ActionKeep {
			errf("E-MAN-055", "catch-all proposed_action must be keep")
		}
		if u.Layer != LayerL2 {
			errf("E-MAN-055", "catch-all layer must be L2")
		}
		if u.Confidence != 0.5 {
			errf("E-MAN-064", "catch-all confidence must be 0.500")
		}
		residualSignals := 0
		for _, s := range u.Signals {
			if s.Src == "filesystem_stat" && s.Note != "" {
				residualSignals++
			}
		}
		if residualSignals != 1 {
			errf("E-MAN-068", "catch-all needs exactly one injected residual signal, found %d", residualSignals)
		}
		if len(u.Signals) > 1 {
			warnf("W-MAN-117", "catch-all carries %d extra signals", len(u.Signals)-1)
		}
	}

	// part unit (E-MAN-061; the uncovered row is exempt).
	if u.PartID != "" && u.PartID != PartUncovered {
		if u.SizeAlloc != nil {
			errf("E-MAN-061", "part unit size_alloc must be null")
		}
		if u.FileID == nil {
			errf("E-MAN-061", "part unit requires file_id")
		}
		if u.Fingerprint != nil && u.Fingerprint.Scope != "full" && u.Fingerprint.Scope != "keys" && u.Fingerprint.Scope != "" {
			errf("E-MAN-061", "part unit fingerprint scope must be full, keys or null")
		}
	}

	// size_estimated (E-MAN-027).
	if u.SizeEstimated {
		if u.SizeApparent == nil {
			errf("E-MAN-027", "size_estimated requires size_apparent")
		}
		if u.Kind != KindNamedLocation && !aggregate {
			errf("E-MAN-027", "size_estimated is only allowed on named-location or aggregate units")
		}
	}

	// needed_by (§4.11, E-MAN-057/062).
	if !orderedSubset(u.NeededBy, neededByOrder) {
		errf("E-MAN-057", "needed_by values are out of order")
	}
	for _, v := range u.NeededBy {
		if !containsString(neededByOrder, v) {
			warnf("W-MAN-102", "unknown needed_by value %q", v)
		}
	}
	if u.Layer == LayerL0 && len(u.NeededBy) > 0 && !containsString(u.RiskFlags, "deletion_cost") {
		errf("E-MAN-062", "L0 unit consumed by a feature needs deletion_cost")
	}

	// risk_flags / enums (W-MAN-102).
	for _, f := range u.RiskFlags {
		if !containsString(riskFlagOrder, f) {
			warnf("W-MAN-102", "unknown risk flag %q", f)
		}
	}
	for _, a := range u.aliases {
		switch a {
		case "unversioned_repo":
			warnf("W-MAN-116", "old risk flag unversioned_repo mapped to not_versioned")
		case "binary":
			warnf("W-MAN-102", "old risk flag binary mapped to opaque_content")
		}
	}

	// companions / side effects (§4.12, E-MAN-056/070).
	for _, se := range u.SideEffects {
		if se != SideEffectShmCreate {
			errf("E-MAN-056", "unknown side effect %q", se)
		}
	}
	switch u.OpenAs {
	case "", OpenAsNone, OpenAsText, OpenAsSQLiteRO:
	default:
		errf("E-MAN-070", "invalid open_as %q", u.OpenAs)
	}
	if containsString(u.SideEffects, SideEffectShmCreate) && u.OpenAs != OpenAsSQLiteRO {
		errf("E-MAN-070", "shm_created requires open_as sqlite-ro")
	}

	// owner / acl (§4.8, E-MAN-051).
	if u.Owner != nil {
		switch u.Owner.Kind {
		case "sid":
			if !strings.HasPrefix(u.Owner.Value, "S-1-") {
				errf("E-MAN-051", "owner sid value %q is invalid", u.Owner.Value)
			}
		case "uid-gid":
			if !uidGidPattern.MatchString(u.Owner.Value) {
				errf("E-MAN-051", "owner uid-gid value %q is invalid", u.Owner.Value)
			}
		default:
			errf("E-MAN-051", "owner kind %q is invalid", u.Owner.Kind)
		}
	}
	if u.ACL != nil {
		if u.ACL.Algo != "sha256" {
			errf("E-MAN-051", "acl algo %q is invalid", u.ACL.Algo)
		}
		if u.ACL.Value == "" || !hexPattern.MatchString(u.ACL.Value) {
			errf("E-MAN-051", "acl value is not hex")
		}
		if u.ACL.Entries < 0 {
			errf("E-MAN-051", "acl entries is negative")
		}
	}

	// link_target (E-MAN-066): the manifest keeps the on-disk form; an
	// extended-length prefix would prove the writer absolutized/normalized it.
	if strings.HasPrefix(u.LinkTarget, `\\?\`) {
		errf("E-MAN-066", "link_target must keep the on-disk relative form")
	}

	// secret_ref (§9.4, E-MAN-050).
	if u.SecretRef != "" && !secretRefPattern.MatchString(u.SecretRef) {
		errf("E-MAN-050", "secret_ref %q has invalid format", u.SecretRef)
	}

	// notes length (§4.1).
	if len(u.Notes) > MaxNoteBytes {
		errf("E-MAN-012", "notes exceeds %d bytes", MaxNoteBytes)
	}
	if containsPlaintextish(u.Notes) {
		errf("E-MAN-017", "notes looks like plaintext credential material")
	}
	if named {
		opaque := opaquePart(u.Path)
		if scheme, _, ok := strings.Cut(u.Path, ":"); ok && strings.EqualFold(scheme, "file") {
			// For a file locator the opaque part is a whole path; the
			// separators would otherwise glue it into one long high-entropy
			// token run and flag every real Windows path (D-034). Only the
			// file name can plausibly be plaintext credential material.
			opaque = opaque[strings.LastIndexAny(opaque, `/\`)+1:]
		}
		if containsPlaintextish(opaque) {
			errf("E-MAN-017", "named-location opaque part looks like plaintext credential material")
		}
	}
	for _, v := range u.Extra {
		if containsPlaintextish(string(v)) {
			errf("E-MAN-017", "unknown field value looks like plaintext credential material")
		}
	}

	// W-MAN-101 unknown fields.
	if len(u.Extra) > 0 {
		warnf("W-MAN-101", "unit has %d unknown field(s) from a newer version", len(u.Extra))
	}
}

var (
	unitIDPattern    = regexp.MustCompile(`^u_[0-9A-HJKMNP-TV-Z]{26}$`)
	cidPattern       = regexp.MustCompile(`^c_[0-9A-HJKMNP-TV-Z]{26}$`)
	secretRefPattern = regexp.MustCompile(`^secrets\.age#h_[0-9A-HJKMNP-TV-Z]{20}$`)
	secretFPPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{8,64}$`)
	uidGidPattern    = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
	hexPattern       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

var unitRequiredFields = []string{
	"type", "schema_version", "id", "cid", "path", "path_key", "root",
	"path_semantics", "derived_from", "profile", "entry", "kind", "layer",
	"confidence", "signals", "secret", "size_apparent", "size_alloc", "mtime",
	"file_id", "fingerprint", "proposed_action", "risk_flags",
}

func isKnownKind(k string) bool {
	switch k {
	case KindFile, KindDir, KindGlobGroup, KindNamedLocation, KindCatchAll:
		return true
	}
	return false
}

func isKnownSecretClass(c string) bool {
	switch c {
	case SecretNone, SecretScan, SecretReference, SecretRestore, SecretRelogin:
		return true
	}
	return false
}

func isAggregate(u *Unit) bool {
	return u.AggregateCount != nil || containsString(u.RiskFlags, "aggregated")
}

func hasSignalSource(signals []Signal, src string) bool {
	for _, s := range signals {
		if s.Src == src {
			return true
		}
	}
	return false
}

func actionAllowed(layer, action string) bool {
	switch layer {
	case LayerL0:
		return action == ActionDelete
	case LayerL1:
		return action == ActionReinstall
	case LayerL2:
		return action == ActionTemplate || action == ActionMigrate
	case LayerL3:
		return action == ActionMigrate
	case LayerL4:
		return action == ActionRebind
	case LayerL5:
		return action == ActionRelogin
	}
	return false
}

// uniquenessKey implements E-MAN-025, including the part_id:uncovered case and
// the file_id fallback.
func uniquenessKey(u *Unit) string {
	part := u.PartID
	if u.OriginPathKey != nil {
		// Machine-derived rows (uncovered or wildcard part selections) are
		// distinguished by their source key, not by the physical path.
		return strings.Join([]string{u.Profile, u.Entry, part, *u.OriginPathKey}, "\x00")
	}
	if u.FileID != nil && u.FileID.VolumeSerial != "" && u.FileID.Index != "" {
		return strings.Join([]string{u.Profile, u.Entry, part, u.FileID.VolumeSerial, u.FileID.Index}, "\x00")
	}
	return strings.Join([]string{u.Profile, u.Entry, part, u.PathKey}, "\x00")
}

func decimals(raw string) int {
	i := strings.IndexByte(raw, '.')
	if i < 0 {
		return 0
	}
	j := i + 1
	for j < len(raw) && raw[j] >= '0' && raw[j] <= '9' {
		j++
	}
	return j - i - 1
}

func orderedSubset(values, order []string) bool {
	last := -1
	for _, v := range values {
		pos := -1
		for i, o := range order {
			if o == v {
				pos = i
				break
			}
		}
		if pos < 0 {
			continue // unknown values are appended, not part of the fixed order
		}
		if pos < last {
			return false
		}
		last = pos
	}
	return true
}

// ---- path helpers ---------------------------------------------------------

var allowedNamedSchemes = map[string]bool{
	"keychain": true, "wincred": true, "env": true, "registry": true, "file": true,
}

var schemePattern = regexp.MustCompile(`^([a-z][a-z0-9+.-]*):(.*)$`)

func namedLocation(p string) (bool, string) {
	m := schemePattern.FindStringSubmatch(p)
	if m == nil {
		return false, ""
	}
	return true, m[1]
}

func opaquePart(p string) string {
	if i := strings.IndexByte(p, ':'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// expectedPathKey reproduces §6.3 for literal paths and §6.4 for
// named-locations. It returns "" when the path is too malformed to fold.
func expectedPathKey(p string) string {
	if named, _ := namedLocation(p); named {
		opaque := strings.Join(strings.Fields(opaquePart(p)), " ")
		return strings.ToLower(p[:strings.IndexByte(p, ':')]) + ":" + fsx.NormKey(opaque)
	}
	if p == "" {
		return ""
	}
	return fsx.NormKey(p)
}

func isAbsolutePath(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' {
		return true
	}
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && isASCIILetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return false
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func pathComponents(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
}

func hasDotComponent(p string) bool {
	for _, c := range pathComponents(p) {
		if c == "." {
			return true
		}
	}
	return false
}

func hasParentComponent(p string) bool {
	for _, c := range pathComponents(p) {
		if c == ".." {
			return true
		}
	}
	return false
}

func hasTrailingSeparator(p string) bool {
	if p == "" {
		return false
	}
	c := p[len(p)-1]
	return c == '/' || c == '\\'
}

func isPathRoot(p string) bool {
	if p == "/" {
		return true
	}
	if len(p) == 3 && isASCIILetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, `\\`) && hasTrailingSeparator(p) {
		parts := pathComponents(p)
		return len(parts) == 2
	}
	return false
}

// keyWithin compares two folded keys segment-wise. Keys always use "/" as the
// separator (fsx.NormKey, D-034). It never treats "C:\\foo" as containing
// "C:\\foobar" (section 6.2).
func keyWithin(rootKey, pathKey string) bool {
	if rootKey == "" || pathKey == "" {
		return false
	}
	rootKey = strings.TrimRight(rootKey, "/") + "/"
	return len(pathKey) >= len(rootKey) && strings.HasPrefix(pathKey, rootKey)
}

func validReparseTag(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	if s == `"symlink"` {
		return true
	}
	if s == "" {
		return false
	}
	_, err := strconv.ParseUint(s, 0, 64)
	return err == nil
}

// ---- plaintext heuristic (§11.1) -----------------------------------------

var knownSecretRun = regexp.MustCompile(
	`(?:^|[^A-Za-z0-9])(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[bp]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{10,})`)

var tokenRunPattern = regexp.MustCompile(`[A-Za-z0-9_+/=\-]{20,}`)

// containsPlaintextish flags known credential prefixes and long high-entropy
// runs. It is deliberately conservative: false positives are errors here, so
// the entropy threshold is set at 4.0 bits/byte and runs must contain both
// letters and digits.
func containsPlaintextish(s string) bool {
	if s == "" {
		return false
	}
	if knownSecretRun.MatchString(s) {
		return true
	}
	for _, run := range tokenRunPattern.FindAllString(s, -1) {
		if entropy(run) >= 4.2 && hasLetter(run) && hasDigit(run) {
			return true
		}
	}
	return false
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if isASCIILetter(s[i]) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ---- writer-side required checks -----------------------------------------

// checkUnitRequired enforces the fields the spec marks as required before a
// unit is serialized. The writer never silently drops a missing conclusion.
func checkUnitRequired(u *Unit) error {
	missing := func(name string) error {
		return fmt.Errorf("manifest: E-MAN-005 unit missing required field %s", name)
	}
	switch {
	case u.SchemaVersion == "":
		return missing("schema_version")
	case u.ID == "":
		return missing("id")
	case u.Path == "":
		return missing("path")
	case u.PathKey == "":
		return missing("path_key")
	case u.Root == "":
		return missing("root")
	case u.PathSemantics == "":
		return missing("path_semantics")
	case u.Profile == "":
		return missing("profile")
	case u.Entry == "":
		return missing("entry")
	case !isKnownKind(u.Kind):
		return fmt.Errorf("manifest: E-MAN-010 invalid kind %q", u.Kind)
	case !containsString(layerOrder, u.Layer):
		return fmt.Errorf("manifest: E-MAN-010 invalid layer %q", u.Layer)
	case u.Secret == nil:
		return missing("secret")
	case len(u.Signals) == 0:
		return missing("signals")
	case u.ProposedAction == "":
		return missing("proposed_action")
	}
	return nil
}

// checkHeaderRequired reports missing required header fields of §3.1. It works
// both for decoded headers (using presence maps) and for programmatically
// built headers, where an empty required value is equally invalid.
func checkHeaderRequired(h *Header) []Issue {
	var out []Issue
	add := func(key string) {
		out = append(out, Issue{
			Code: "E-MAN-005", Severity: SeverityError,
			Message: "header missing required field " + key,
		})
	}
	top := []struct {
		key string
		ok  bool
	}{
		{"manifest_version", h.ManifestVersion != ""},
		{"scan_id", h.ScanID != ""},
		{"tool", h.Tool != ""},
		{"shard_units", h.ShardUnits > 0},
		{"shard_bytes", h.ShardBytes > 0},
		{"roots", len(h.Roots) > 0},
		{"started_at", !h.StartedAt.IsZero()},
	}
	for _, f := range top {
		if !h.present[f.key] && !f.ok {
			add(f.key)
		} else if !f.ok {
			add(f.key)
		}
	}
	if h.present != nil && !h.present["scan_segment"] {
		add("scan_segment")
	}
	if h.ScanSegment.present != nil {
		for _, key := range []string{"parent", "segment_seq", "first_shard"} {
			if !h.ScanSegment.present[key] {
				add("scan_segment." + key)
			}
		}
	} else if h.ScanSegment.FirstShard == 0 {
		add("scan_segment.first_shard")
	}
	hostReq := []struct {
		key string
		ok  bool
	}{
		{"os", h.Host.OS != ""},
		{"arch", h.Host.Arch != ""},
		{"case_sensitivity", h.Host.CaseSensitivity != ""},
		{"path_fold_version", h.Host.PathFoldVersion != ""},
	}
	for _, f := range hostReq {
		if h.present != nil && !h.Host.present[f.key] {
			add("host." + f.key)
		} else if !f.ok {
			add("host." + f.key)
		}
	}
	inReq := []struct {
		key string
		ok  bool
	}{
		{"secret_salt_mode", h.Inputs.SecretSaltMode != ""},
		{"secret_salt", h.Inputs.SecretSalt != ""},
		{"profiles", h.Inputs.Profiles != nil},
	}
	for _, f := range inReq {
		if h.present != nil && !h.Inputs.present[f.key] {
			add("inputs." + f.key)
		} else if !f.ok {
			add("inputs." + f.key)
		}
	}
	for i, r := range h.Roots {
		for _, key := range []string{"name", "role", "instance", "origin", "path", "profile"} {
			if !r.present[key] {
				if key == "instance" && r.Instance != 0 {
					continue
				}
				if key != "instance" && rootValue(r, key) != "" {
					continue
				}
				out = append(out, Issue{
					Code: "E-MAN-005", Severity: SeverityError,
					Message: fmt.Sprintf("roots[%d] missing required field %s", i, key),
				})
			}
		}
	}
	return out
}

func rootValue(r Root, key string) string {
	switch key {
	case "name":
		return r.Name
	case "role":
		return r.Role
	case "origin":
		return r.Origin
	case "path":
		return r.Path
	case "profile":
		return r.Profile
	}
	return ""
}

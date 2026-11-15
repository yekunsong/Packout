package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/yekunsong/Packout/internal/fsx"
)

// Package format constants. SIG.json is the package's own manifest; it is the
// only file excluded from its own coverage.
const (
	// SIGName is the signature file inside a package.
	SIGName = "SIG.json"
	// PackageFormat identifies the package layout.
	PackageFormat = "packout-package"
	// FormatVersion is the P0 package format version covered by the hash.
	FormatVersion = 1
	// MethodSHA256Tree is the only P0 method: a SHA-256 over the normalized
	// whole-package tree. P0 has no signing key (D-008 §7).
	MethodSHA256Tree = "sha256-tree"
	// MaxSIGBytes bounds the SIG document so a malicious package cannot make
	// verify allocate unbounded memory before the entry limit applies.
	MaxSIGBytes = 256 << 20
)

// Entry kinds in a normalized package tree.
const (
	TypeFile     = "file"
	TypeDir      = "dir"
	TypeSymlink  = "symlink"
	TypeHardlink = "hardlink"
)

// SIGEntry is one normalized tree entry. Nil pointers render as JSON null so
// every field INV-C05 names is explicitly present, even when not applicable.
type SIGEntry struct {
	Type       string  `json:"type"`
	Path       string  `json:"path"`
	Mode       *string `json:"mode"`
	LinkTarget *string `json:"link_target"`
	Size       *int64  `json:"size"`
	SHA256     *string `json:"sha256"`
}

// SIG is the SIG.json document.
//
// Signed is always false: signatures live in the sibling SIG.json.minisig
// (D-043), not in SIG. Without that file verify says "hash-ok, unverified";
// SIG alone never authenticates the sender (INV-C06).
type SIG struct {
	Format        string     `json:"format"`
	FormatVersion int        `json:"format_version"`
	Method        string     `json:"method"`
	Signed        bool       `json:"signed"`
	TreeSHA256    string     `json:"tree_sha256"`
	EntryCount    int        `json:"entry_count"`
	TotalBytes    int64      `json:"total_bytes"`
	Entries       []SIGEntry `json:"entries"`
}

// NewSIG builds a SIG from already-normalized entries and computes the tree
// hash. Entries are copied and sorted by path (byte order), which is the
// canonical order for hashing.
func NewSIG(entries []SIGEntry) (*SIG, error) {
	cp := append([]SIGEntry(nil), entries...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Path < cp[j].Path })
	s := &SIG{
		Format:        PackageFormat,
		FormatVersion: FormatVersion,
		Method:        MethodSHA256Tree,
		Signed:        false,
		EntryCount:    len(cp),
		Entries:       cp,
	}
	seen := make(map[string]bool, len(cp))
	for i := range cp {
		e := &cp[i]
		if seen[e.Path] {
			return nil, fmt.Errorf("%w: duplicate entry %q", ErrInvalidPath, e.Path)
		}
		seen[e.Path] = true
		if err := validateSIGEntry(e); err != nil {
			return nil, err
		}
		if e.Type == TypeFile {
			s.TotalBytes += *e.Size
		}
	}
	s.TreeSHA256 = treeHash(s.FormatVersion, cp)
	return s, nil
}

func validateSIGEntry(e *SIGEntry) error {
	if err := ValidateRelPath(e.Path); err != nil {
		return err
	}
	switch e.Type {
	case TypeDir:
		if e.Mode == nil {
			return fmt.Errorf("%w: %q: dir without mode", ErrInvalidPath, e.Path)
		}
		if e.Size != nil || e.SHA256 != nil || e.LinkTarget != nil {
			return fmt.Errorf("%w: %q: dir carries file fields", ErrInvalidPath, e.Path)
		}
	case TypeFile:
		if e.Mode == nil || e.Size == nil || e.SHA256 == nil {
			return fmt.Errorf("%w: %q: file missing mode, size or sha256", ErrInvalidPath, e.Path)
		}
		if e.LinkTarget != nil {
			return fmt.Errorf("%w: %q: file carries link_target", ErrInvalidPath, e.Path)
		}
		if *e.Size < 0 || !validSHA256(*e.SHA256) {
			return fmt.Errorf("%w: %q: invalid size or sha256", ErrInvalidPath, e.Path)
		}
	case TypeSymlink:
		if e.LinkTarget == nil {
			return fmt.Errorf("%w: %q: symlink without target", ErrInvalidPath, e.Path)
		}
		if e.Size != nil || e.SHA256 != nil || e.Mode != nil {
			return fmt.Errorf("%w: %q: symlink carries file fields", ErrInvalidPath, e.Path)
		}
		if err := ValidateLinkTarget(e.Path, *e.LinkTarget); err != nil {
			return err
		}
	case TypeHardlink:
		if e.LinkTarget == nil || e.SHA256 == nil || e.Size == nil || e.Mode == nil {
			return fmt.Errorf("%w: %q: hardlink missing target, sha256, size or mode", ErrInvalidPath, e.Path)
		}
		if err := ValidateHardlinkTarget(e.Path, *e.LinkTarget); err != nil {
			return err
		}
		if *e.Size < 0 || !validSHA256(*e.SHA256) {
			return fmt.Errorf("%w: %q: invalid size or sha256", ErrInvalidPath, e.Path)
		}
	default:
		return fmt.Errorf("%w: %q: unknown entry type %q", ErrInvalidPath, e.Path, e.Type)
	}
	return nil
}

func validSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// treeHash is the canonical digest INV-C05 requires: format version plus, for
// every entry, type, relative path, permissions, link target, size and content
// hash. Fields are tab separated; validation forbids tabs and newlines in
// paths and targets, and "-" denotes null. Entries are in path order.
func treeHash(version int, entries []SIGEntry) string {
	h := sha256.New()
	io.WriteString(h, PackageFormat)
	h.Write([]byte{0})
	io.WriteString(h, strconv.Itoa(version))
	h.Write([]byte{'\n'})
	for _, e := range entries {
		io.WriteString(h, e.Type)
		h.Write([]byte{'\t'})
		io.WriteString(h, e.Path)
		h.Write([]byte{'\t'})
		io.WriteString(h, opt(e.Mode))
		h.Write([]byte{'\t'})
		io.WriteString(h, opt(e.LinkTarget))
		h.Write([]byte{'\t'})
		if e.Size != nil {
			io.WriteString(h, strconv.FormatInt(*e.Size, 10))
		} else {
			h.Write([]byte{'-'})
		}
		h.Write([]byte{'\t'})
		io.WriteString(h, opt(e.SHA256))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func opt(p *string) string {
	if p == nil {
		return "-"
	}
	return *p
}

// Encode serializes SIG deterministically (struct field order, no whitespace)
// with a trailing newline.
func (s *SIG) Encode() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeSIG parses and structurally validates a SIG document. Unknown fields
// are rejected: an unexpected field could silently change what a newer writer
// believed was covered.
func DecodeSIG(data []byte) (*SIG, error) {
	if len(data) > MaxSIGBytes {
		return nil, fmt.Errorf("%w: SIG exceeds %d bytes", ErrLimitExceeded, MaxSIGBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s SIG
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: SIG: %v", ErrUnsupportedFormat, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%w: SIG: trailing data", ErrUnsupportedFormat)
	}
	if s.Format != PackageFormat {
		return nil, fmt.Errorf("%w: format %q", ErrUnsupportedFormat, s.Format)
	}
	if s.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("%w: format_version %d", ErrUnsupportedFormat, s.FormatVersion)
	}
	if s.Method != MethodSHA256Tree {
		return nil, fmt.Errorf("%w: method %q", ErrUnsupportedFormat, s.Method)
	}
	if s.Signed {
		return nil, fmt.Errorf("%w: signed packages are P1", ErrUnsupportedFormat)
	}
	if s.EntryCount != len(s.Entries) {
		return nil, fmt.Errorf("%w: entry_count %d != len(entries) %d", ErrUnsupportedFormat, s.EntryCount, len(s.Entries))
	}
	if !validSHA256(s.TreeSHA256) {
		return nil, fmt.Errorf("%w: invalid tree_sha256", ErrUnsupportedFormat)
	}
	seen := make(map[string]bool, len(s.Entries))
	var total int64
	for i := range s.Entries {
		e := &s.Entries[i]
		if seen[e.Path] {
			return nil, fmt.Errorf("%w: duplicate entry %q", ErrInvalidPath, e.Path)
		}
		seen[e.Path] = true
		if err := validateSIGEntry(e); err != nil {
			return nil, err
		}
		if e.Type == TypeFile {
			total += *e.Size
		}
	}
	if total != s.TotalBytes {
		return nil, fmt.Errorf("%w: total_bytes %d != sum of file sizes %d", ErrUnsupportedFormat, s.TotalBytes, total)
	}
	return &s, nil
}

// ReadSIG reads SIG.json from dir.
func ReadSIG(dir string) (*SIG, error) {
	p := dir + string(os.PathSeparator) + SIGName
	fi, lerr := fsx.Lstat(p)
	if lerr != nil {
		return nil, lerr
	}
	if fi.IsLink || fi.IsReparse || !fi.Mode.IsRegular() {
		return nil, fmt.Errorf("%w: SIG is not a plain regular file", ErrUnsupportedFormat)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSIGBytes+1))
	if err != nil {
		return nil, err
	}
	return DecodeSIG(data)
}

// CompareSIG returns entry-level differences between want (SIG) and got
// (the actual tree). An empty result means the trees match.
func CompareSIG(want, got *SIG) []Problem {
	var out []Problem
	wantByPath := make(map[string]*SIGEntry, len(want.Entries))
	for i := range want.Entries {
		wantByPath[want.Entries[i].Path] = &want.Entries[i]
	}
	gotByPath := make(map[string]*SIGEntry, len(got.Entries))
	for i := range got.Entries {
		gotByPath[got.Entries[i].Path] = &got.Entries[i]
	}
	for i := range want.Entries {
		w := &want.Entries[i]
		g, ok := gotByPath[w.Path]
		if !ok {
			out = append(out, Problem{Code: "sig-missing-entry", Path: w.Path, Detail: "listed in SIG but absent on disk"})
			continue
		}
		if p := compareEntry(w, g); p != nil {
			out = append(out, *p)
		}
	}
	for i := range got.Entries {
		g := &got.Entries[i]
		if _, ok := wantByPath[g.Path]; !ok {
			out = append(out, Problem{Code: "sig-extra-entry", Path: g.Path, Detail: "on disk but not covered by SIG"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func compareEntry(w, g *SIGEntry) *Problem {
	mk := func(code, detail string) *Problem {
		return &Problem{Code: code, Path: w.Path, Detail: detail}
	}
	if w.Type != g.Type {
		return mk("sig-type-mismatch", "SIG "+w.Type+" vs disk "+g.Type)
	}
	if opt(w.Mode) != opt(g.Mode) {
		return mk("sig-mode-mismatch", "SIG "+opt(w.Mode)+" vs disk "+opt(g.Mode))
	}
	if opt(w.LinkTarget) != opt(g.LinkTarget) {
		return mk("sig-link-mismatch", "SIG "+opt(w.LinkTarget)+" vs disk "+opt(g.LinkTarget))
	}
	if (w.Size == nil) != (g.Size == nil) || (w.Size != nil && *w.Size != *g.Size) {
		return mk("sig-size-mismatch", "size differs from SIG")
	}
	if opt(w.SHA256) != opt(g.SHA256) {
		return mk("sig-hash-mismatch", "content digest differs from SIG")
	}
	return nil
}

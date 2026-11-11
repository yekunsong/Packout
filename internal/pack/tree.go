package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"packout/internal/fsx"
)

// Limits bound an export or verify pass (C-10). Zero values take defaults.
type Limits struct {
	// MaxEntries bounds the number of tree entries including directories.
	MaxEntries int
	// MaxTotalBytes bounds the sum of apparent file sizes ("expanded total").
	MaxTotalBytes int64
	// MaxExpansionRatio bounds apparent bytes divided by allocated bytes.
	// P0 packages are uncompressed directories, so for dense files the ratio
	// is about 1; sparse or size-inflated packages exceed it.
	MaxExpansionRatio float64
}

// Default limits. They are deliberately far above a realistic home directory
// package but small enough to stop a bomb.
const (
	DefaultMaxEntries      = 200_000
	DefaultMaxTotalBytes   = 16 << 30 // 16 GiB
	DefaultMaxExpansion    = 1000.0
	ratioSlackWhenNoAlloc  = 1
	readChunkSize          = 128 << 10
	unsupportedEntryDetail = "device, FIFO, socket or junction"
)

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if l.MaxExpansionRatio <= 0 {
		l.MaxExpansionRatio = DefaultMaxExpansion
	}
	return l
}

type walkState struct {
	limits     Limits
	excludeSIG bool
	entries    []SIGEntry
	total      int64
	alloc      int64
	seenFile   map[string]string // FileID -> first path
}

// scanTree walks root without following any link or reparse point and returns
// a normalized, path-sorted entry list. Every name is validated before it is
// used. Limits abort the walk as soon as they are crossed, never truncate.
func scanTree(root string, limits Limits, excludeSIG bool) ([]SIGEntry, error) {
	limits = limits.withDefaults()
	info, err := fsx.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir {
		return nil, fmt.Errorf("%w: root is not a directory", ErrUnsupportedEntry)
	}
	if info.IsReparse {
		return nil, fmt.Errorf("%w: root is a reparse point", ErrUnsupportedEntry)
	}
	st := &walkState{limits: limits, seenFile: make(map[string]string), excludeSIG: excludeSIG}
	if err := st.walk(root, ""); err != nil {
		return nil, err
	}
	sort.Slice(st.entries, func(i, j int) bool { return st.entries[i].Path < st.entries[j].Path })
	if st.total > st.limits.MaxTotalBytes {
		return nil, fmt.Errorf("%w: %d bytes > limit %d", ErrLimitExceeded, st.total, st.limits.MaxTotalBytes)
	}
	if st.total > 0 {
		den := st.alloc
		if den < ratioSlackWhenNoAlloc {
			den = ratioSlackWhenNoAlloc
		}
		ratio := float64(st.total) / float64(den)
		if ratio > st.limits.MaxExpansionRatio {
			return nil, fmt.Errorf("%w: expansion ratio %.1f > limit %.1f (%d apparent / %d allocated bytes)",
				ErrLimitExceeded, ratio, st.limits.MaxExpansionRatio, st.total, den)
		}
	}
	return st.entries, nil
}

func (st *walkState) walk(dir, relDir string) error {
	children, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	// os.ReadDir already sorts by name, but do not rely on it.
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, de := range children {
		rel := de.Name()
		if relDir != "" {
			rel = relDir + "/" + rel
		}
		if err := ValidateRelPath(rel); err != nil {
			return err
		}
		if st.excludeSIG && (rel == SIGName || rel == MinisigName) {
			continue // neither is covered by the tree (no self-reference)
		}
		st.entries = append(st.entries, SIGEntry{}) // reserve one slot per entry
		if len(st.entries) > st.limits.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrLimitExceeded, st.limits.MaxEntries)
		}
		idx := len(st.entries) - 1

		full, err := safeJoin(dir, de.Name())
		if err != nil {
			return err
		}
		info, err := fsx.Lstat(full)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir:
			if info.IsReparse {
				return fmt.Errorf("%w: %q is a junction/reparse directory", ErrUnsupportedEntry, rel)
			}
			m := modeString(info.Mode)
			st.entries[idx] = SIGEntry{Type: TypeDir, Path: rel, Mode: &m}
			if err := st.walk(full, rel); err != nil {
				return err
			}
		case info.IsLink:
			target := info.LinkTarget
			if target == "" {
				target, err = os.Readlink(full)
				if err != nil {
					return err
				}
			}
			if err := ValidateLinkTarget(rel, target); err != nil {
				return err
			}
			t := target
			st.entries[idx] = SIGEntry{Type: TypeSymlink, Path: rel, LinkTarget: &t}
		case info.Mode.IsRegular():
			if err := st.addFile(idx, full, rel, info); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %q is a %s", ErrUnsupportedEntry, rel, unsupportedEntryDetail)
		}
	}
	return nil
}

func (st *walkState) addFile(idx int, full, rel string, info *fsx.Info) error {
	m := modeString(info.Mode)
	if info.FileID != "" {
		if primary, ok := st.seenFile[info.FileID]; ok {
			sha := primarySHA(st.entries, primary)
			size := primarySize(st.entries, primary)
			t := primary
			st.entries[idx] = SIGEntry{Type: TypeHardlink, Path: rel, Mode: &m, LinkTarget: &t, Size: &size, SHA256: &sha}
			return nil
		}
		st.seenFile[info.FileID] = rel
	}
	if info.Size > 0 && st.total > st.limits.MaxTotalBytes-info.Size {
		return fmt.Errorf("%w: %d bytes > limit %d", ErrLimitExceeded, st.total+info.Size, st.limits.MaxTotalBytes)
	}
	sha, err := hashFile(full, info.Size)
	if err != nil {
		return err
	}
	size := info.Size
	st.total += size
	st.alloc += info.Alloc
	st.entries[idx] = SIGEntry{Type: TypeFile, Path: rel, Mode: &m, Size: &size, SHA256: &sha}
	return nil
}

func primarySHA(entries []SIGEntry, path string) string {
	for i := range entries {
		if entries[i].Path == path && entries[i].SHA256 != nil {
			return *entries[i].SHA256
		}
	}
	return ""
}

func primarySize(entries []SIGEntry, path string) int64 {
	for i := range entries {
		if entries[i].Path == path && entries[i].Size != nil {
			return *entries[i].Size
		}
	}
	return 0
}

// hashFile streams one file and enforces that the bytes read equal the size
// observed by Lstat, so a file growing or shrinking mid-read cannot produce a
// SIG that later disagrees with itself.
func hashFile(path string, want int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, readChunkSize)
	var n int64
	for {
		got, rerr := f.Read(buf)
		if got > 0 {
			n += int64(got)
			if n > want {
				return "", fmt.Errorf("%w: %q grew while hashing", ErrInvalidPath, path)
			}
			h.Write(buf[:got])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	if n != want {
		return "", fmt.Errorf("%w: %q size changed while hashing (%d != %d)", ErrInvalidPath, path, n, want)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyTree copies src into dst preserving type, permission bits, symlinks and
// hardlinks. It scans src first, so every name is validated before the first
// byte is written.
func copyTree(src, dst string, limits Limits) (int, error) {
	entries, err := scanTree(src, limits, false)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return 0, err
	}
	for i := range entries {
		e := &entries[i]
		target, err := safeJoin(dst, e.Path)
		if err != nil {
			return 0, err
		}
		switch e.Type {
		case TypeDir:
			if err := os.Mkdir(target, fs.FileMode(parseMode(*e.Mode))); err != nil && !os.IsExist(err) {
				return 0, err
			}
		case TypeSymlink:
			if err := os.Symlink(*e.LinkTarget, target); err != nil {
				return 0, err
			}
		case TypeFile:
			if err := copyFile(filepath.Join(src, filepath.FromSlash(e.Path)), target, fs.FileMode(parseMode(*e.Mode))); err != nil {
				return 0, err
			}
		case TypeHardlink:
			primary, err := safeJoin(dst, *e.LinkTarget)
			if err != nil {
				return 0, err
			}
			if err := os.Link(primary, target); err != nil {
				// Fall back to a copy; verify will then see a regular file,
				// which is still valid package content.
				if cerr := copyFile(filepath.Join(src, filepath.FromSlash(e.Path)), target, fs.FileMode(parseMode(*e.Mode))); cerr != nil {
					return 0, cerr
				}
			}
		}
	}
	return len(entries), nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ParseMode parses a SIG mode string ("0644"). Invalid input yields 0644.
func ParseMode(s string) fs.FileMode { return fs.FileMode(parseMode(s)) }

func parseMode(s string) uint32 {
	var v uint32
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return 0o644
		}
		v = v*8 + uint32(s[i]-'0')
	}
	return v
}

// listNames returns the top-level names of dir, sorted.
func listNames(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(des))
	for i, de := range des {
		names[i] = de.Name()
	}
	sort.Strings(names)
	return names, nil
}

func isDirEmpty(dir string) (bool, error) {
	names, err := listNames(dir)
	if err != nil {
		return false, err
	}
	return len(names) == 0, nil
}

// hasTopPrefix reports whether rel lives under one of tops (or equals one).
func hasTopPrefix(rel string, tops map[string]bool) bool {
	top := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		top = rel[:i]
	}
	return tops[top]
}

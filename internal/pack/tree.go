package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yekunsong/Packout/internal/fsx"
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
	readChunkSize          = 64 << 10
	parallelThreshold      = 32
	unsupportedEntryDetail = "device, FIFO, socket or junction"
)

// defaultJobs is the global concurrency default: min(GOMAXPROCS, 16).
func defaultJobs() int {
	n := runtime.GOMAXPROCS(0)
	if n > 16 {
		n = 16
	}
	if n < 1 {
		n = 1
	}
	return n
}

func normalizeJobs(n int) int {
	if n <= 0 {
		return defaultJobs()
	}
	return n
}

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

	// Parallel hashing. tasks are files to hash after the walk; hardlinks
	// take the digest of their primary once every worker is done. errAt is
	// keyed by entry index so errors report in input order.
	jobs      int
	tasks     []hashTask
	hardlinks []int
	byPath    map[string]int
	errAt     map[int]error
	failIdx   int
}

type hashTask struct {
	idx  int
	path string
	want int64
}

// scanTree walks root without following any link or reparse point and returns
// a normalized, path-sorted entry list. Every name is validated before it is
// used. Limits abort the walk as soon as they are crossed, never truncate.
func scanTree(root string, limits Limits, excludeSIG bool, jobs int) ([]SIGEntry, error) {
	limits = limits.withDefaults()
	jobs = normalizeJobs(jobs)
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
	st := &walkState{
		limits: limits, seenFile: make(map[string]string), excludeSIG: excludeSIG,
		jobs: jobs, byPath: make(map[string]int), errAt: make(map[int]error),
	}
	walkErr := st.walk(root, "")
	st.hashAll(jobs <= 1 || len(st.tasks) < parallelThreshold)
	if err := st.pickError(walkErr); err != nil {
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
		st.failIdx = idx

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
			// The primary may still be unhashed; both fields are filled after
			// the hash pass. Its size is already known.
			p := primary
			size := info.Size
			if pi, ok := st.byPath[primary]; ok {
				size = *st.entries[pi].Size
			}
			st.entries[idx] = SIGEntry{Type: TypeHardlink, Path: rel, Mode: &m, LinkTarget: &p, Size: &size}
			st.hardlinks = append(st.hardlinks, idx)
			return nil
		}
		st.seenFile[info.FileID] = rel
	}
	if info.Size > 0 && st.total > st.limits.MaxTotalBytes-info.Size {
		return fmt.Errorf("%w: %d bytes > limit %d", ErrLimitExceeded, st.total+info.Size, st.limits.MaxTotalBytes)
	}
	size := info.Size
	st.total += size
	st.alloc += info.Alloc
	st.entries[idx] = SIGEntry{Type: TypeFile, Path: rel, Mode: &m, Size: &size}
	st.byPath[rel] = idx
	st.tasks = append(st.tasks, hashTask{idx: idx, path: full, want: size})
	return nil
}

// hashAll hashes every collected file, serially when there are few of them or
// when jobs is 1, otherwise with a bounded worker pool. Workers stop taking new
// tasks after the first failure so a bad tree exits early; the earliest error
// in input order is the one reported. Hardlink digests are filled afterwards
// from their primary.
func (st *walkState) hashAll(serial bool) {
	var failed atomic.Bool
	var mu sync.Mutex
	hashOne := func(i int, buf []byte) bool {
		t := &st.tasks[i]
		sha, err := hashFileBuf(t.path, t.want, buf)
		if err != nil {
			mu.Lock()
			st.errAt[t.idx] = err
			mu.Unlock()
			failed.Store(true)
			return false
		}
		st.entries[t.idx].SHA256 = &sha
		return true
	}
	if serial {
		buf := make([]byte, readChunkSize)
		for i := range st.tasks {
			if !hashOne(i, buf) {
				break
			}
		}
	} else {
		jobs := st.jobs
		if jobs > len(st.tasks) {
			jobs = len(st.tasks)
		}
		var next atomic.Int64
		var wg sync.WaitGroup
		for w := 0; w < jobs; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, readChunkSize)
				for !failed.Load() {
					i := int(next.Add(1)) - 1
					if i >= len(st.tasks) {
						return
					}
					hashOne(i, buf)
				}
			}()
		}
		wg.Wait()
	}
	if len(st.errAt) > 0 {
		return
	}
	for _, idx := range st.hardlinks {
		target := st.entries[idx].LinkTarget
		if target == nil {
			continue
		}
		if pi, ok := st.byPath[*target]; ok && st.entries[pi].SHA256 != nil {
			st.entries[idx].SHA256 = st.entries[pi].SHA256
		}
	}
}

// pickError returns the earliest error in input order. A walk error sits at
// failIdx, so any hash failure of an earlier entry wins over it.
func (st *walkState) pickError(walkErr error) error {
	best, found := -1, false
	for idx := range st.errAt {
		if !found || idx < best {
			best, found = idx, true
		}
	}
	if walkErr != nil {
		if !found || best >= st.failIdx {
			return walkErr
		}
	}
	if found {
		return st.errAt[best]
	}
	return nil
}

// hashFile streams one file and enforces that the bytes read equal the size
// observed by Lstat, so a file growing or shrinking mid-read cannot produce a
// SIG that later disagrees with itself.
func hashFile(path string, want int64) (string, error) {
	return hashFileBuf(path, want, make([]byte, readChunkSize))
}

// hashFileBuf is hashFile with a caller-owned buffer so pooled workers do not
// allocate one per file.
func hashFileBuf(path string, want int64, buf []byte) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
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
func copyTree(src, dst string, limits Limits, jobs int) (int, error) {
	jobs = normalizeJobs(jobs)
	entries, err := scanTree(src, limits, false, jobs)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return 0, err
	}
	// Directories and symlinks first so every file parent exists, then files
	// in parallel, then hardlinks (their primary is guaranteed to exist).
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
		}
	}
	if err := copyFiles(src, dst, entries, jobs); err != nil {
		return 0, err
	}
	for i := range entries {
		e := &entries[i]
		if e.Type != TypeHardlink {
			continue
		}
		target, err := safeJoin(dst, e.Path)
		if err != nil {
			return 0, err
		}
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
	return len(entries), nil
}

// copyFiles copies the regular files of entries, serial for small trees and
// otherwise with up to jobs workers. Errors are reported in entry order.
func copyFiles(src, dst string, entries []SIGEntry, jobs int) error {
	var files []int
	for i := range entries {
		if entries[i].Type == TypeFile {
			files = append(files, i)
		}
	}
	copyOne := func(idx int, buf []byte) error {
		e := &entries[idx]
		target, err := safeJoin(dst, e.Path)
		if err != nil {
			return err
		}
		return copyFileBuf(filepath.Join(src, filepath.FromSlash(e.Path)), target, fs.FileMode(parseMode(*e.Mode)), buf)
	}
	if jobs <= 1 || len(files) < parallelThreshold {
		buf := make([]byte, readChunkSize)
		for _, idx := range files {
			if err := copyOne(idx, buf); err != nil {
				return err
			}
		}
		return nil
	}
	if jobs > len(files) {
		jobs = len(files)
	}
	errAt := make([]error, len(files))
	var next atomic.Int64
	var failed atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, readChunkSize)
			for !failed.Load() {
				i := int(next.Add(1)) - 1
				if i >= len(files) {
					return
				}
				if err := copyOne(files[i], buf); err != nil {
					errAt[i] = err
					failed.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range errAt {
		if err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	return copyFileBuf(src, dst, mode, make([]byte, readChunkSize))
}

func copyFileBuf(src, dst string, mode fs.FileMode, buf []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.CopyBuffer(out, in, buf); err != nil {
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

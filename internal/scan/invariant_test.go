package scan

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

// The P0 hard promise is that a scan never modifies a scanned file. This test
// takes a complete before/after snapshot of the target tree and asserts
// equality. The only declared exception is open_as: sqlite-ro, which creates
// the sqlite -shm next to a database that already has a -wal (and therefore
// changes that directory's mtime).
//
// The tree is built from a materialized profile fixture plus extra objects
// that a profile cannot express (hardlink, sparse file, read-only file,
// 10 MiB file, symlink).

type invClock struct{}

func (invClock) Now() time.Time {
	return time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
}

// invEntry is one snapshot record. mtime is nanoseconds so a rewrite is
// visible even on coarse filesystems that report a whole-second timestamp.
type invEntry struct {
	Type       string
	Size       int64
	Alloc      int64
	MTimeNS    int64
	Perm       uint32
	LinkTarget string
	FileID     string
}

func invKind(info *fsx.Info) string {
	switch {
	case info.IsLink:
		return "symlink"
	case info.IsDir:
		return "dir"
	case info.Mode.IsRegular():
		return "file"
	default:
		return "other"
	}
}

// invSnapshot records every path below root (root included, relative slash
// spelling). filepath.WalkDir does not follow symlinks, matching fsx.Lstat.
func invSnapshot(t *testing.T, root string) map[string]invEntry {
	t.Helper()
	out := make(map[string]invEntry)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := fsx.Lstat(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = invEntry{
			Type:       invKind(info),
			Size:       info.Size,
			Alloc:      info.Alloc,
			MTimeNS:    info.ModTime.UnixNano(),
			Perm:       uint32(info.Mode.Perm()),
			LinkTarget: info.LinkTarget,
			FileID:     info.FileID,
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// invDiff returns human-readable differences. allowedAdded is the exact set of
// paths the declared side effect may create; allowedFields maps path -> fields
// ("mtime") that may change. Nothing else is tolerated.
func invDiff(before, after map[string]invEntry, allowedAdded map[string]bool, allowedFields map[string]map[string]bool) []string {
	var diffs []string
	seen := make(map[string]bool, len(before)+len(after))
	for p := range before {
		seen[p] = true
	}
	for p := range after {
		seen[p] = true
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		b, hadBefore := before[p]
		a, hasAfter := after[p]
		switch {
		case !hadBefore && hasAfter:
			if allowedAdded[p] {
				continue
			}
			diffs = append(diffs, "added   "+p)
		case hadBefore && !hasAfter:
			diffs = append(diffs, "removed "+p)
		default:
			fields := allowedFields[p]
			changed := func(name string) bool { return fields != nil && fields[name] }
			if b.Type != a.Type {
				diffs = append(diffs, "type    "+p+": "+b.Type+" -> "+a.Type)
			}
			if b.Size != a.Size {
				diffs = append(diffs, "size    "+p+": "+strconv.FormatInt(b.Size, 10)+" -> "+strconv.FormatInt(a.Size, 10))
			}
			if b.Alloc != a.Alloc && !changed("alloc") {
				diffs = append(diffs, "alloc   "+p+": "+strconv.FormatInt(b.Alloc, 10)+" -> "+strconv.FormatInt(a.Alloc, 10))
			}
			if b.MTimeNS != a.MTimeNS && !changed("mtime") {
				diffs = append(diffs, "mtime   "+p+": "+strconv.FormatInt(b.MTimeNS, 10)+" -> "+strconv.FormatInt(a.MTimeNS, 10))
			}
			if b.Perm != a.Perm {
				diffs = append(diffs, "perm    "+p+": "+strconv.FormatUint(uint64(b.Perm), 8)+" -> "+strconv.FormatUint(uint64(a.Perm), 8))
			}
			if b.LinkTarget != a.LinkTarget {
				diffs = append(diffs, "link    "+p+": "+b.LinkTarget+" -> "+a.LinkTarget)
			}
			if b.FileID != a.FileID {
				diffs = append(diffs, "fileid  "+p+": "+b.FileID+" -> "+a.FileID)
			}
		}
	}
	return diffs
}

// invariantProfile writes a minimal valid profile whose home fixture holds one
// file. The sqlite entry exercises the single declared side effect; the
// catch-all covers everything else we add to the materialized tree.
func invariantProfile(t *testing.T) (*profile.Profile, string) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "fixtures", "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".keep"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	const src = `{
  "schema_version": "2.0",
  "name": "invariant",
  "title": "scan invariant fixture",
  "applies_to": {"os": ["windows", "darwin", "linux"]},
  "roots": {"home": "/nonexistent-invariant-home"},
  "defaults": {},
  "entries": [
    {
      "id": "db",
      "selftest_exempt": "integration",
      "kind": "file",
      "root": "home",
      "path": "state.sqlite",
      "layer": "L3",
      "secret": "none",
      "extractor": "digest",
      "companions": ["-wal", "-shm"],
      "open_as": "sqlite-ro",
      "side_effects": ["shm_created"],
      "opaque_content": true,
      "signals": [{"src": "observed_behavior", "note": "sqlite fixture"}]
    },
    {
      "id": "catch-home",
      "kind": "catch-all",
      "root": "home",
      "scope": "root",
      "layer": "L2",
      "secret": "none",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_bytes_structure": 65536,
      "max_bytes_total": 1073741824,
      "signals": []
    }
  ],
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    "fixtures": {"home": "fixtures/home"},
    "budget": {"wall_ms": 20000},
    "expect": [{"entry": "catch-home", "root": "home", "match": ".keep"}]
  }
}`
	path := filepath.Join(dir, "profile.jsonc")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(path)
	if err != nil {
		t.Fatalf("load invariant profile: %v", err)
	}
	return p, dir
}

// buildInvariantTree adds the file-system shapes a profile cannot declare:
// read-only file, hardlink pair, symlink, sparse file and a 10 MiB file.
// It returns the symlink case that was skipped (if any) for the report.
func buildInvariantTree(t *testing.T, home string) (skipped []string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(home, "sub", "nested-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "empty-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeInv := func(rel string, data []byte, mode os.FileMode) string {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// sqlite database plus its -wal; scanning it must create -shm.
	writeInv("state.sqlite", []byte("SQLite format 3\x00invariant-payload"), 0o644)
	writeInv("state.sqlite-wal", []byte("wal"), 0o644)

	plain := writeInv("plain.txt", []byte("plain contents\n"), 0o644)
	writeInv("sub/nested.bin", []byte{0x00, 0x01, 0x02, 0x03}, 0o600)

	readonly := writeInv("readonly.txt", []byte("read only\n"), 0o644)
	if err := os.Chmod(readonly, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o644) })

	if err := os.Link(plain, filepath.Join(home, "hardlink.txt")); err != nil {
		// Hardlinks need no special privilege on Linux or NTFS; a failure is a
		// real environment problem worth reporting, not a reason to weaken
		// the invariant test.
		t.Fatalf("create hardlink: %v", err)
	}

	// Sparse file: apparent 8 MiB, allocated only around the written block.
	sparsePath := filepath.Join(home, "sparse.bin")
	sp, err := os.Create(sparsePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Truncate(8 << 20); err != nil {
		sp.Close()
		t.Fatal(err)
	}
	if _, err := sp.Seek(4<<20, io.SeekStart); err != nil {
		sp.Close()
		t.Fatal(err)
	}
	if _, err := sp.WriteString("hole-probe"); err != nil {
		sp.Close()
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	// 10 MiB of real bytes (not a truncate hole) so the "large file" case is
	// actually read and hashed.
	largePath := filepath.Join(home, "large.bin")
	lf, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0xA5}, 1<<20)
	for i := 0; i < 10; i++ {
		if _, err := lf.Write(chunk); err != nil {
			lf.Close()
			t.Fatal(err)
		}
	}
	if err := lf.Close(); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == "windows" {
		skipped = append(skipped, "symlink home/link-to-plain.txt: os.Symlink needs SeCreateSymbolicLinkPrivilege")
	} else {
		if err := os.Symlink("plain.txt", filepath.Join(home, "link-to-plain.txt")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
	}
	return skipped
}

func TestScanDoesNotModifyScannedTree(t *testing.T) {
	p, profileDir := invariantProfile(t)
	work := filepath.Join(profileDir, "work")
	tree := filepath.Join(work, "tree")
	if err := p.MaterializeTo(tree); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	home := filepath.Join(tree, "home")
	skipped := buildInvariantTree(t, home)
	for _, s := range skipped {
		t.Logf("SKIP platform case: %s", s)
	}

	// Output lives outside the snapshotted work tree entirely, so any write
	// here is outside the scanned tree by construction.
	out := filepath.Join(t.TempDir(), "out")

	before := invSnapshot(t, work)
	if _, ok := before["tree/home/state.sqlite-shm"]; ok {
		t.Fatal("fixture unexpectedly already contains state.sqlite-shm")
	}

	cfg := Config{
		Profile: p,
		OutDir:  out,
		Roots:   []RootBinding{{Role: "home", Path: home}},
		GOOS:    runtime.GOOS,
		Clock:   invClock{},
		Salt:    manifest.FixedSalt("00112233445566778899aabbccddeeff"),
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Complete {
		t.Fatal("scan did not complete")
	}
	if res.ReadErrors != 0 {
		t.Fatalf("scan reported %d read errors", res.ReadErrors)
	}

	after := invSnapshot(t, work)

	// The one declared exception: sqlite-ro creates <db>-shm, which updates
	// the containing directory's mtime. Both are enumerated explicitly.
	shmRel := "tree/home/state.sqlite-shm"
	allowedAdded := map[string]bool{shmRel: true}
	allowedFields := map[string]map[string]bool{"tree/home": {"mtime": true}}

	diffs := invDiff(before, after, allowedAdded, allowedFields)
	if len(diffs) > 0 {
		t.Fatalf("scan modified the scanned tree outside the declared sqlite exception:\n  %s", strings.Join(diffs, "\n  "))
	}

	// The exception must actually have happened; otherwise the allowance is
	// hiding nothing and the check above is weaker than it looks.
	if _, ok := after[shmRel]; !ok {
		t.Fatalf("declared sqlite side effect did not occur: %s missing after scan", shmRel)
	}

	// The output directory must not be part of the scanned tree.
	if fsx.Within(tree, out) {
		t.Fatalf("output directory %s is inside scanned tree %s", out, tree)
	}
}

// TestSnapshotDetectsMutation sanity-checks the snapshot/diff machinery itself
// so a hollow "no differences" result cannot pass silently.
func TestSnapshotDetectsMutation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := invSnapshot(t, dir)
	if err := os.WriteFile(p, []byte("three"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force a distinct mtime even on a coarse filesystem.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	after := invSnapshot(t, dir)
	diffs := invDiff(before, after, nil, nil)
	if len(diffs) == 0 {
		t.Fatal("diff did not detect size and mtime changes")
	}
	if !strings.Contains(strings.Join(diffs, "\n"), "size") {
		t.Fatalf("diff did not name the size change: %v", diffs)
	}
}

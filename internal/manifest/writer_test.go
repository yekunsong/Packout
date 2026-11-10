package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriterRotatesByUnits(t *testing.T) {
	hdr := newTestHeader(2)
	units := []Unit{
		fixtureUnit("e1", "/home/a/1"),
		fixtureUnit("e2", "/home/a/2"),
		fixtureUnit("e3", "/home/a/3"),
		fixtureUnit("e4", "/home/a/4"),
		fixtureUnit("e5", "/home/a/5"),
	}
	dir := writeTestManifest(t, hdr, units, nil)

	idx := readIndex(t, dir)
	if len(idx.Shards) != 3 {
		t.Fatalf("shards = %d, want 3", len(idx.Shards))
	}
	wantUnits := []int64{2, 2, 1}
	for i, s := range idx.Shards {
		if s.Units != wantUnits[i] {
			t.Fatalf("shard %d units = %d, want %d", i, s.Units, wantUnits[i])
		}
		if s.Name != "manifest.000"+string(rune('1'+i))+".jsonl" {
			t.Fatalf("shard %d name = %q", i, s.Name)
		}
	}
	if idx.Units != 5 || idx.Residual != 0 || !idx.Complete {
		t.Fatalf("index totals = %+v", idx)
	}
	// Shard 1 = header + 2 units; shard 2 = 2 units; shard 3 = unit + footer.
	if n := shardLineCount(t, dir, idx.Shards[0].Name); n != 3 {
		t.Fatalf("shard 1 lines = %d, want 3", n)
	}
	if n := shardLineCount(t, dir, idx.Shards[2].Name); n != 2 {
		t.Fatalf("shard 3 lines = %d, want 2", n)
	}

	got, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("Read returned %d units", len(got))
	}
	for i := range got {
		if got[i].Entry != units[i].Entry {
			t.Fatalf("unit order changed at %d: %s", i, got[i].Entry)
		}
	}
	if err := Validate(dir); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestWriterRotatesByBytes(t *testing.T) {
	hdr := newTestHeader(0)
	hdr.ShardBytes = 900 // header + one unit already exceed this
	units := []Unit{
		fixtureUnit("e1", "/home/a/1"),
		fixtureUnit("e2", "/home/a/2"),
		fixtureUnit("e3", "/home/a/3"),
	}
	dir := writeTestManifest(t, hdr, units, nil)
	idx := readIndex(t, dir)
	if len(idx.Shards) < 2 {
		t.Fatalf("byte threshold did not rotate: %d shards", len(idx.Shards))
	}
	for _, s := range idx.Shards {
		// A single record may exceed a tiny threshold, but no shard may hold
		// two records once it is full.
		if s.Units > 1 {
			t.Fatalf("shard %s holds %d units despite 900-byte threshold", s.Name, s.Units)
		}
	}
	if err := Validate(dir); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestAbortLeavesIncompleteProduct(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, newTestHeader(2), WithClock(fixedClock{testStart}), WithSalt(FixedSalt("s")))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []Unit{
		fixtureUnit("e1", "/home/a/1"),
		fixtureUnit("e2", "/home/a/2"),
		fixtureUnit("e3", "/home/a/3"),
	} {
		u := u
		if err := w.WriteUnit(&u); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "manifest.index.json")); !os.IsNotExist(err) {
		t.Fatalf("abort must not write an index (err=%v)", err)
	}
	issues := ValidateAll(dir)
	if !hasIssueCode(issues, "E-MAN-030") {
		t.Fatalf("aborted manifest must be E-MAN-030, got %v", issues)
	}
	if _, err := Read(dir); err == nil {
		t.Fatal("Read must reject an aborted manifest")
	}
	// A half-written .tmp is exactly the crash marker the spec expects.
	if _, err := os.Stat(filepath.Join(dir, "manifest.0002.jsonl.tmp")); err != nil {
		t.Fatalf("expected an unrenamed .tmp shard: %v", err)
	}

	// A fresh writer may retry the same directory, cleaning the stale shards.
	w2, err := NewWriter(dir, newTestHeader(0), WithClock(fixedClock{testStart}), WithSalt(FixedSalt("s")))
	if err != nil {
		t.Fatalf("retry NewWriter: %v", err)
	}
	if err := w2.WriteUnit(ptrUnit(fixtureUnit("e1", "/home/a/1"))); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir); err != nil {
		t.Fatalf("retried manifest invalid: %v", err)
	}
}

func TestAbortNeverOverwritesCompleteArtifact(t *testing.T) {
	dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/1")}, nil)
	indexPath := filepath.Join(dir, "manifest.index.json")
	before, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	shardBefore, err := os.ReadFile(filepath.Join(dir, "manifest.0001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewWriter(dir, newTestHeader(0)); err != ErrOutputExists {
		t.Fatalf("NewWriter over a complete manifest = %v, want ErrOutputExists", err)
	}

	after, err := os.ReadFile(indexPath)
	if err != nil || string(after) != string(before) {
		t.Fatal("complete index was modified")
	}
	shardAfter, err := os.ReadFile(filepath.Join(dir, "manifest.0001.jsonl"))
	if err != nil || string(shardAfter) != string(shardBefore) {
		t.Fatal("complete shard was modified")
	}
}

func TestWriterRejectsUnreleasedLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".lock"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(dir, newTestHeader(0)); err == nil {
		t.Fatal("NewWriter must refuse an unreleased .lock")
	}
}

func TestWriterWritesNotesWithoutCountingThem(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, newTestHeader(0), WithClock(fixedClock{testStart}), WithSalt(FixedSalt("s")))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteUnit(ptrUnit(fixtureUnit("e1", "/home/a/1"))); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteNote(&Note{ScanID: w.hdr.ScanID, Code: "empty_glob", Detail: "no matches"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	idx := readIndex(t, dir)
	if idx.Units != 1 {
		t.Fatalf("notes counted as units: %d", idx.Units)
	}
	m, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Notes) != 1 || m.Notes[0].Code != "empty_glob" {
		t.Fatalf("notes = %+v", m.Notes)
	}
	if m.Footer.Units != 1 || m.Footer.Shards != 1 {
		t.Fatalf("footer = %+v", m.Footer)
	}
}

func ptrUnit(u Unit) *Unit { return &u }

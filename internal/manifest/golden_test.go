package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// goldenFiles are byte-for-byte expected outputs. They exist to make any
// accidental change to field order, null handling, number/time formatting,
// shard rotation or index shape fail loudly (spec §1, §2).
var goldenFiles = []string{
	"manifest.0001.jsonl",
	"manifest.0002.jsonl",
	"manifest.index.json",
}

// goldenInputs builds a fully fixed scan: fixed ULID, fixed clock, fixed salt,
// fixed sizes and two-unit shards so rotation is covered.
func goldenInputs() (Header, []Unit, []Note, []Option) {
	hdr := newTestHeader(2)
	hdr.StartedAt = testStart
	hdr.ScanID = "01JQ8Z3K7M2V9T4R6W8X0Y2B4C"
	hdr.Host.OSVersion = "6.8.0"
	hdr.Host.PathFoldVersion = "x/text@v0.21.0 (unicode 15.0.0)"
	hdr.Host.VolumeIDs = []VolumeID{{Root: "/", Serial: "rootfs"}}
	hdr.Inputs.SecretSalt = "" // filled from the injected SaltSource
	units := []Unit{
		fixtureUnit("e1", "/home/a/one"),
		fixtureUnit("e2", "/home/a/two"),
		fixtureUnit("e3", "/home/a/three"),
	}
	notes := []Note{{
		ScanID:  hdr.ScanID,
		Code:    "empty_glob",
		Profile: "p",
		Entry:   "e1",
		Detail:  "no matches for glob",
	}}
	opts := []Option{
		WithClock(fixedClock{t: testEnd}), // Close uses this for ended_at
		WithSalt(FixedSalt("0011223344556677abcdef0011223344")),
	}
	return hdr, units, notes, opts
}

func TestGolden(t *testing.T) {
	hdr, units, notes, opts := goldenInputs()
	dir := t.TempDir()
	w, err := NewWriter(dir, hdr, opts...)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := range units {
		if err := w.WriteUnit(&units[i]); err != nil {
			t.Fatalf("WriteUnit: %v", err)
		}
		if i == 0 {
			if err := w.WriteNote(&notes[0]); err != nil {
				t.Fatalf("WriteNote: %v", err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if os.Getenv("PACKOUT_UPDATE_GOLDEN") != "" {
		outDir := filepath.Join("testdata", "golden")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range goldenFiles {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read produced %s: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(outDir, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Log("golden files updated")
		return
	}

	for _, name := range goldenFiles {
		want, err := os.ReadFile(filepath.Join("testdata", "golden", name))
		if err != nil {
			t.Fatalf("missing golden %s (run with PACKOUT_UPDATE_GOLDEN=1 on the remote): %v", name, err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read produced %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from golden\n got: %q\nwant: %q", name, got, want)
		}
	}
}

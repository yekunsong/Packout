package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixed test inputs: no wall clock, no random salt (D-022 runs on Linux).

var testStart = time.Date(2026, 11, 10, 9, 12, 3, 412345600, time.UTC)
var testEnd = time.Date(2026, 11, 10, 9, 14, 51, 9000000, time.UTC)
var testMTime = time.Date(2026, 11, 8, 12, 3, 44, 123456700, time.UTC)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func newTestHeader(shardUnits int) Header {
	if shardUnits <= 0 {
		shardUnits = DefaultShardUnits
	}
	return Header{
		ManifestVersion: Version,
		ScanID:          "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
		ScanSegment:     ScanSegment{SegmentSeq: 0, FirstShard: 1},
		StartedAt:       testStart,
		Tool:            "packout/0.1.0",
		Host: Host{
			OS:              "linux",
			OSVersion:       "6.8.0",
			Arch:            "amd64",
			CaseSensitivity: "sensitive",
			PathFoldVersion: CurrentPathFoldVersion(),
			VolumeIDs:       []VolumeID{{Root: "/", Serial: "rootfs"}},
		},
		Inputs: Inputs{
			SecretSaltMode: "random",
			Profiles:       []ProfileRef{{Name: "p", Version: "1.0", SHA256: strings.Repeat("a", 64)}},
			Options:        &InputOptions{FollowSymlinks: false},
		},
		ShardUnits: shardUnits,
		ShardBytes: DefaultShardBytes,
		Roots: []Root{{
			Name: "home", Role: "home", Instance: 1, Origin: "profile",
			Path: "/home/a", Profile: "p",
		}},
	}
}

// fixtureUnit builds a valid L3 file unit. entry and path must be unique per
// scenario; id and cid are derived from the fixed content.
func fixtureUnit(entry, path string) Unit {
	fp, err := FingerprintBytes([]byte(entry), "full")
	if err != nil {
		panic(err)
	}
	mtime := testMTime
	size := int64(1234)
	alloc := int64(4096)
	u := Unit{
		SchemaVersion: Version,
		Path:          path,
		PathKey:       strings.ToLower(path),
		Root:          "home",
		PathSemantics: SemanticsLiteral,
		DerivedFrom:   nil,
		Profile:       "p",
		Entry:         entry,
		Kind:          KindFile,
		Layer:         LayerL3,
		Confidence:    0.970,
		Signals: []Signal{{
			Src:  "profile_rule",
			Note: "profile p v1 entry " + entry + " declares L3",
			URL:  nil,
		}},
		Secret:         &Secret{Class: SecretNone, Hits: []SecretHit{}, HitCount: 0, Truncated: false},
		SizeApparent:   &size,
		SizeAlloc:      &alloc,
		MTime:          &mtime,
		FileID:         &FileID{VolumeSerial: "3A4F-9C21", Index: "0x0000000000012F3A"},
		Fingerprint:    &fp,
		ProposedAction: ActionKeep,
		RiskFlags:      []string{},
	}
	u.ID = u.ComputeID()
	u.CID = CID(u.Fingerprint)
	return u
}

func catchAllUnit(path string) Unit {
	u := fixtureUnit("home-residual", path)
	u.Kind = KindCatchAll
	u.Layer = LayerL2
	u.Confidence = 0.500
	u.ProposedAction = ActionKeep
	u.RiskFlags = []string{"low_confidence", "residual"}
	u.Signals = []Signal{{
		Src:  "filesystem_stat",
		Note: "未被任何 entry 命中，catch-all 残留",
	}}
	u.ID = u.ComputeID()
	u.CID = CID(u.Fingerprint)
	return u
}

func writeTestManifest(t *testing.T, hdr Header, units []Unit, notes []Note) string {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(dir, hdr,
		WithClock(fixedClock{t: testStart}),
		WithSalt(FixedSalt("9b2e41c7d0f3a685")))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := range units {
		if err := w.WriteUnit(&units[i]); err != nil {
			t.Fatalf("WriteUnit %d: %v", i, err)
		}
	}
	for i := range notes {
		if err := w.WriteNote(&notes[i]); err != nil {
			t.Fatalf("WriteNote %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir
}

func issueCodes(issues []Issue) map[string]bool {
	m := make(map[string]bool)
	for _, is := range issues {
		m[is.Code] = true
	}
	return m
}

func hasIssueCode(issues []Issue, code string) bool {
	return issueCodes(issues)[code]
}

func readIndex(t *testing.T, dir string) Index {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "manifest.index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatalf("parse index: %v", err)
	}
	return idx
}

func shardLineCount(t *testing.T, dir, name string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return len(strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"))
}

// rewriteShardLine replaces one line of one shard (line numbers start at 1).
func rewriteShardLine(t *testing.T, dir, name string, line int, fn func(string) string) {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if line < 1 || line > len(lines) {
		t.Fatalf("line %d out of range (%d)", line, len(lines))
	}
	lines[line-1] = fn(lines[line-1])
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func dropLastShardLine(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("empty shard")
	}
	lines = lines[:len(lines)-1]
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
)

var testTime = time.Date(2026, 11, 10, 9, 12, 3, 412345600, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return testTime }

func testHeader(root string) manifest.Header {
	return manifest.Header{
		ManifestVersion: manifest.Version,
		ScanID:          "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
		ScanSegment:     manifest.ScanSegment{SegmentSeq: 0, FirstShard: 1},
		StartedAt:       testTime,
		Tool:            "github.com/yekunsong/Packout/test",
		Host: manifest.Host{
			OS:              "linux",
			OSVersion:       "6.8.0",
			Arch:            "amd64",
			CaseSensitivity: "sensitive",
			PathFoldVersion: manifest.CurrentPathFoldVersion(),
			VolumeIDs:       []manifest.VolumeID{{Root: "/", Serial: "rootfs"}},
		},
		Inputs: manifest.Inputs{
			SecretSaltMode: "random",
			SecretSalt:     "00112233445566778899aabbccddeeff",
			Profiles:       []manifest.ProfileRef{{Name: "p", Version: "2.0", SHA256: strings.Repeat("a", 64)}},
			Options:        &manifest.InputOptions{FollowSymlinks: false},
		},
		Roots: []manifest.Root{{
			Name: "home", Role: "home", Instance: 1, Origin: "profile",
			Path: root, Profile: "p",
		}},
	}
}

// writeManifest writes a complete, valid manifest directory at dir.
func writeManifest(t *testing.T, dir string, root string, units ...manifest.Unit) {
	t.Helper()
	writeManifestOpts(t, dir, root, nil, units...)
}

// writeManifestOpts is writeManifest with a chance to adjust the header.
func writeManifestOpts(t *testing.T, dir string, root string, mutate func(*manifest.Header), units ...manifest.Unit) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hdr := testHeader(root)
	if mutate != nil {
		mutate(&hdr)
	}
	w, err := manifest.NewWriter(dir, hdr,
		manifest.WithClock(fixedClock{}),
		manifest.WithSalt(manifest.FixedSalt("00112233445566778899aabbccddeeff")))
	if err != nil {
		t.Fatal(err)
	}
	for i := range units {
		if err := w.WriteUnit(&units[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	t.Logf("manifest dir %s: %v", dir, names)
}

// fileUnit builds a minimal valid file unit for absPath.
func fileUnit(root, entry, absPath string) manifest.Unit {
	fp, _ := manifest.FingerprintBytes([]byte("content"), "full")
	u := manifest.Unit{
		SchemaVersion:  manifest.Version,
		Path:           absPath,
		PathKey:        fsx.NormKey(absPath),
		Root:           "home",
		PathSemantics:  manifest.SemanticsLiteral,
		Profile:        "p",
		Entry:          entry,
		Kind:           manifest.KindFile,
		Layer:          manifest.LayerL2,
		Confidence:     0.9,
		Signals:        []manifest.Signal{{Src: "profile_rule", Note: "test declaration"}},
		Secret:         &manifest.Secret{Class: manifest.SecretNone},
		Fingerprint:    &fp,
		ProposedAction: manifest.ActionKeep,
	}
	u.ID = u.ComputeID()
	u.CID = manifest.CID(&fp)
	return u
}

// scanFixture creates a scan output directory with a valid manifest and the
// given extra top-level files.
func scanFixture(t *testing.T, units ...manifest.Unit) (src, root string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	src = filepath.Join(base, "scan")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, filepath.Join(src, ManifestDirName), root, units...)
	return src, root
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustExport(t *testing.T, cfg Config) *Result {
	t.Helper()
	res, err := Export(cfg)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return res
}

func mustVerify(t *testing.T, dir string) *Verdict {
	t.Helper()
	v, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v (verdict %+v)", err, v)
	}
	return v
}

package restore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/pack"
	"packout/internal/profile"
)

const testToken = "sk-ant-api03-RoundTripSecretValue0123456789abcdef"

// buildPackage materialises a signed package. homeSrc is returned so tests can
// know the source layout; the package itself is independent of it.
func buildPackage(t *testing.T, withSecrets bool) (pkg, homeSrc, pub string) {
	t.Helper()
	root := t.TempDir()
	homeSrc = filepath.Join(root, "home")
	must(t, os.MkdirAll(homeSrc, 0o755))
	settings := `{
  "env": {"ANTHROPIC_API_KEY": "` + testToken + `"},
  "note": "literal missing ref: «secret:secrets.age#h_missingref»"
}
`
	must(t, os.WriteFile(filepath.Join(homeSrc, "settings.json"), []byte(settings), 0o644))
	must(t, os.WriteFile(filepath.Join(homeSrc, ".credentials.json"), []byte(`{"token":"x"}`), 0o644))

	// Manifest: one extracted L3 file, one L1 reinstall, one L5 relogin.
	mdir := filepath.Join(root, "manifest")
	w, err := manifest.NewWriter(mdir, manifest.Header{
		ManifestVersion: manifest.Version,
		ScanID:          "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
		ScanSegment:     manifest.ScanSegment{SegmentSeq: 0, FirstShard: 1},
		Tool:            "packout/0.1.0",
		Host: manifest.Host{
			OS: "linux", Arch: "amd64", CaseSensitivity: "sensitive",
			PathFoldVersion: manifest.CurrentPathFoldVersion(),
		},
		Inputs: manifest.Inputs{
			SecretSaltMode: "random",
			Profiles:       []manifest.ProfileRef{{Name: "p", Version: "1.0", SHA256: strings.Repeat("a", 64)}},
			Options:        &manifest.InputOptions{},
		},
		Roots: []manifest.Root{{Name: "home", Role: "home", Instance: 1, Origin: "cli",
			Path: homeSrc, Profile: "p"}},
	}, manifest.WithSalt(manifest.FixedSalt("00112233445566778899aabbccddeeff")))
	must(t, err)
	units := []manifest.Unit{
		testUnit(t, homeSrc, "settings", "settings.json", manifest.LayerL3, manifest.ActionKeep, 0.970),
		testUnit(t, homeSrc, "plugin", "plugins/demo.js", manifest.LayerL1, manifest.ActionReinstall, 0.950),
		reloginUnit(t, homeSrc, "oauth", ".credentials.json"),
	}
	for i := range units {
		must(t, w.WriteUnit(&units[i]))
	}
	must(t, w.Close())

	p := &profile.Profile{
		Name: "p", RootOrder: []string{"home"},
		Roots: map[string]profile.Root{"home": {Template: homeSrc}},
		Entries: []*profile.Entry{{
			ID: "settings", Kind: "file", Root: "home", Path: "settings.json",
			Layer: "L3", Secret: profile.SecretScan, Extractor: profile.ExtractorTemplate,
		}},
	}
	src := filepath.Join(root, "src")
	must(t, os.MkdirAll(src, 0o755))

	cfg := pack.Config{
		SourceDir: src, OutDir: filepath.Join(root, "pkg"),
		ManifestDir: mdir, Profile: p,
		Roots: map[string]string{"home": homeSrc},
	}
	if withSecrets {
		cfg.WithSecrets = true
		cfg.Crypt = pack.CryptOptions{Passphrase: []byte("pw")}
	}
	exp, err := pack.Export(cfg)
	must(t, err)
	pkg = exp.OutDir

	priv := filepath.Join(root, "minisign.key")
	pub = priv + ".pub"
	_, err = pack.GenerateKeyPair(priv, pub)
	must(t, err)
	_, err = pack.Sign(pkg, priv)
	must(t, err)
	return pkg, homeSrc, pub
}

func testUnit(t *testing.T, root, entry, rel, layer, action string, conf float64) manifest.Unit {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	fp, err := manifest.FingerprintBytes([]byte(p), "full")
	must(t, err)
	u := manifest.Unit{
		SchemaVersion: manifest.Version, Path: p, PathKey: fsx.NormKey(p),
		Root: "home", PathSemantics: manifest.SemanticsLiteral, Profile: "p",
		Entry: entry, Kind: manifest.KindFile, Layer: layer, Confidence: conf,
		Signals:     []manifest.Signal{{Src: "profile_rule", Note: "test"}},
		Secret:      &manifest.Secret{Class: manifest.SecretNone, Hits: []manifest.SecretHit{}, HitCount: 0},
		Fingerprint: &fp, ProposedAction: action, RiskFlags: []string{},
	}
	u.ID = u.ComputeID()
	u.CID = manifest.CID(u.Fingerprint)
	return u
}

func reloginUnit(t *testing.T, root, entry, rel string) manifest.Unit {
	t.Helper()
	u := testUnit(t, root, entry, rel, manifest.LayerL5, manifest.ActionRelogin, 0.960)
	u.Secret = &manifest.Secret{Class: manifest.SecretRelogin, Hits: []manifest.SecretHit{}, HitCount: 0}
	return u
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func optInto(pkg, into string) Options {
	return Options{PackageDir: pkg, Into: into, Crypt: pack.CryptOptions{Passphrase: []byte("pw")}}
}

func TestRoundTripReplacesSecretsAndReportsThreeSegments(t *testing.T) {
	pkg, _, pub := buildPackage(t, true)
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub
	rep, err := Run(context.Background(), opt)
	must(t, err)

	data, err := os.ReadFile(filepath.Join(into, "home", "settings.json"))
	must(t, err)
	if !strings.Contains(string(data), testToken) {
		t.Fatalf("secret not substituted: %s", data)
	}
	if strings.Contains(string(data), "«secret:secrets.age#") && !strings.Contains(string(data), "h_missingref") {
		t.Fatalf("real placeholder left behind: %s", data)
	}
	if !strings.Contains(string(data), "h_missingref") {
		t.Fatalf("missing ref should stay as a placeholder: %s", data)
	}
	foundMissing := false
	for _, p := range rep.Problems {
		if p.Code == "missing_secret" {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatal("missing_secret not reported")
	}
	if len(rep.Restored) == 0 {
		t.Fatal("restored segment is empty")
	}
	if len(rep.NeedsReinstall) != 1 || rep.NeedsReinstall[0].Layer != manifest.LayerL1 {
		t.Fatalf("needs_reinstall = %+v", rep.NeedsReinstall)
	}
	if len(rep.NeedsRelogin) != 1 || rep.NeedsRelogin[0].Layer != manifest.LayerL5 {
		t.Fatalf("needs_relogin = %+v", rep.NeedsRelogin)
	}
	if _, err := os.Stat(filepath.Join(into, "home", ".credentials.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("L5 must not be written")
	}
}

func TestUnsignedRejectedUnlessAllowed(t *testing.T) {
	pkg, _, _ := buildPackage(t, false)
	// Drop only the signature; a forced re-export is unnecessary because the
	// tree itself is unchanged.
	must(t, os.Remove(filepath.Join(pkg, pack.MinisigName)))
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)

	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("err = %v, want ErrUnverified", err)
	}
	if rep.SigConclusion != pack.ConclusionUnsigned || rep.Signed {
		t.Fatalf("report gate = %q signed=%v", rep.SigConclusion, rep.Signed)
	}
	if _, err := os.Stat(into); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nothing may be written before the gate passes")
	}

	opt.AllowUnverified = true
	rep, err = Run(context.Background(), opt)
	must(t, err)
	if !rep.AllowedUnverified {
		t.Fatal("AllowedUnverified not marked")
	}
}

func TestTamperedRejectedEvenWhenAllowed(t *testing.T) {
	pkg, _, _ := buildPackage(t, false)
	must(t, os.WriteFile(filepath.Join(pkg, "config", "home", "settings.json"), []byte("changed"), 0o644))
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.AllowUnverified = true
	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered (report %+v)", err, rep)
	}
}

func TestBadSignatureAllowedWithFlag(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	// A structurally broken .minisig is an attribution failure, not tampering.
	must(t, os.WriteFile(filepath.Join(pkg, pack.MinisigName),
		[]byte("untrusted comment: x\n"+strings.Repeat("A", 120)+"\n"), 0o644))
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub

	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("err = %v, want ErrUnverified", err)
	}
	if rep.SigConclusion != pack.ConclusionBadSignature {
		t.Fatalf("conclusion = %q", rep.SigConclusion)
	}
	if strings.Contains(err.Error(), "tampered") {
		t.Fatalf("bad-signature reported as tampering: %v", err)
	}

	opt.AllowUnverified = true
	rep, err = Run(context.Background(), opt)
	must(t, err)
	if !rep.AllowedUnverified || rep.SigConclusion != pack.ConclusionBadSignature {
		t.Fatalf("report = %+v", rep)
	}
}

func TestFailedAllowedWithFlag(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	// Removing manifest/ yields conclusion "failed" at the SIG gate.
	must(t, os.RemoveAll(filepath.Join(pkg, pack.ManifestDirName)))
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub

	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("err = %v, want ErrUnverified", err)
	}
	if rep.SigConclusion != pack.ConclusionFailed {
		t.Fatalf("conclusion = %q, want %q", rep.SigConclusion, pack.ConclusionFailed)
	}
	if strings.Contains(err.Error(), "tampered") {
		t.Fatalf("failed reported as tampering: %v", err)
	}

	// With the flag the gate opens; the missing manifest fails later as
	// corruption, which proves the gate itself allowed "failed".
	opt.AllowUnverified = true
	_, err = Run(context.Background(), opt)
	if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrUnverified) {
		t.Fatalf("gate did not allow failed: %v", err)
	}
}

func TestEmptyRefusedEvenWhenAllowed(t *testing.T) {
	pkg := t.TempDir()
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.AllowUnverified = true
	rep, err := Run(context.Background(), opt)
	if err == nil {
		t.Fatal("empty package accepted")
	}
	if errors.Is(err, ErrTampered) {
		t.Fatalf("empty reported as tampering: %v", err)
	}
	if rep == nil || rep.SigConclusion != pack.ConclusionEmpty {
		t.Fatalf("report = %+v", rep)
	}
}

func TestNonEmptyTargetNeedsInPlaceAndForce(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	into := filepath.Join(t.TempDir(), "target")
	must(t, os.MkdirAll(into, 0o755))
	untouched := filepath.Join(into, "keep.txt")
	must(t, os.WriteFile(untouched, []byte("keep"), 0o644))

	opt := optInto(pkg, into)
	opt.PubKeyPath = pub
	if _, err := Run(context.Background(), opt); !errors.Is(err, ErrDestNotEmpty) {
		t.Fatalf("err = %v, want ErrDestNotEmpty", err)
	}
	opt.InPlace = true
	if _, err := Run(context.Background(), opt); !errors.Is(err, ErrDestNotEmpty) {
		t.Fatalf("in-place without force: err = %v, want ErrDestNotEmpty", err)
	}
	opt.Force = true
	rep, err := Run(context.Background(), opt)
	must(t, err)
	if b, _ := os.ReadFile(untouched); string(b) != "keep" {
		t.Fatal("unrelated target file was touched")
	}
	if len(rep.Problems) > 0 && rep.Problems[0].Code == "restore_corrupt" {
		t.Fatalf("problems: %+v", rep.Problems)
	}
}

func TestDryRunWritesNothingButPlansSubstitutedSizes(t *testing.T) {
	pkg, _, pub := buildPackage(t, true)
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub
	opt.DryRun = true
	rep, err := Run(context.Background(), opt)
	must(t, err)
	if _, err := os.Stat(into); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry-run created the target")
	}
	var settings *PlanEntry
	for i := range rep.Plan {
		if strings.HasSuffix(rep.Plan[i].Path, "settings.json") {
			settings = &rep.Plan[i]
		}
	}
	if settings == nil || settings.Bytes == 0 {
		t.Fatalf("plan missing settings: %+v", rep.Plan)
	}
	if rep.PlannedBytes == 0 {
		t.Fatal("planned bytes not counted")
	}
}

func TestPathTraversalInSIGRejected(t *testing.T) {
	pkg, _, _ := buildPackage(t, false)
	sig, err := pack.ReadSIG(pkg)
	must(t, err)
	for i := range sig.Entries {
		if sig.Entries[i].Path == "config/home/settings.json" {
			sig.Entries[i].Path = "config/../escape.json"
		}
	}
	b, err := json.Marshal(sig)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(pkg, pack.SIGName), append(b, '\n'), 0o644))

	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrUnverified) || rep.SigConclusion != pack.ConclusionFailed {
		t.Fatalf("err = %v conclusion=%q, want an unverified refusal", err, rep.SigConclusion)
	}
	if _, err := os.Stat(into); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("traversal package must not write")
	}
	// The flag opens the gate, but the traversal SIG is rejected as corrupt
	// before anything is planned or written.
	opt.AllowUnverified = true
	if _, err := Run(context.Background(), opt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("allowed traversal: err = %v, want ErrCorrupt", err)
	}
}

func TestHashMismatchStopsAndReportsRestored(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub
	opt.AfterWrite = func(path string) {
		if strings.HasSuffix(path, "settings.json") {
			data, _ := os.ReadFile(path)
			_ = os.WriteFile(path, append(data, 'X'), 0o644)
		}
	}
	rep, err := Run(context.Background(), opt)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
	if len(rep.Restored) == 0 {
		t.Fatal("already written entries should stay in the report")
	}
	code := ""
	for _, p := range rep.Problems {
		if p.Code == "restore_corrupt" {
			code = p.Code
		}
	}
	if code != "restore_corrupt" {
		t.Fatalf("restore_corrupt not recorded: %+v", rep.Problems)
	}
}

func TestDiskBudgetRejectedBeforeWrite(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	into := filepath.Join(t.TempDir(), "target")
	opt := optInto(pkg, into)
	opt.PubKeyPath = pub
	opt.FreeBytes = func(string) (int64, error) { return 1, nil }
	if _, err := Run(context.Background(), opt); !errors.Is(err, ErrDiskBudget) {
		t.Fatalf("err = %v, want ErrDiskBudget", err)
	}
	if _, err := os.Stat(into); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("budget failure must happen before the first write")
	}
}

func TestSymlinkFlattenedWhenUnsupported(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "config", "home")
	must(t, os.MkdirAll(cfgDir, 0o755))
	must(t, os.WriteFile(filepath.Join(cfgDir, "real.txt"), []byte("real"), 0o644))
	if err := os.Symlink("real.txt", filepath.Join(cfgDir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Manifest without units is enough: symlinks are not mapped to units.
	mdir := filepath.Join(root, "manifest")
	w, err := manifest.NewWriter(mdir, manifest.Header{
		ManifestVersion: manifest.Version, ScanID: "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
		ScanSegment: manifest.ScanSegment{SegmentSeq: 0, FirstShard: 1}, Tool: "packout/0.1.0",
		Host:   manifest.Host{OS: "linux", Arch: "amd64", CaseSensitivity: "sensitive", PathFoldVersion: manifest.CurrentPathFoldVersion()},
		Inputs: manifest.Inputs{SecretSaltMode: "random", Profiles: []manifest.ProfileRef{{Name: "p", Version: "1.0", SHA256: strings.Repeat("a", 64)}}, Options: &manifest.InputOptions{}},
		Roots:  []manifest.Root{{Name: "home", Role: "home", Instance: 1, Origin: "cli", Path: cfgDir, Profile: "p"}},
	}, manifest.WithSalt(manifest.FixedSalt("00112233445566778899aabbccddeeff")))
	must(t, err)
	must(t, w.Close())
	src := filepath.Join(root, "src")
	must(t, os.MkdirAll(src, 0o755))
	exp, err := pack.Export(pack.Config{SourceDir: src, OutDir: filepath.Join(root, "pkg"), ManifestDir: mdir, ConfigDir: filepath.Join(root, "config")})
	must(t, err)
	priv := filepath.Join(root, "k")
	_, err = pack.GenerateKeyPair(priv, priv+".pub")
	must(t, err)
	_, err = pack.Sign(exp.OutDir, priv)
	must(t, err)

	into := filepath.Join(t.TempDir(), "target")
	opt := Options{PackageDir: exp.OutDir, Into: into, PubKeyPath: priv + ".pub"}
	opt.Symlink = func(string, string) error { return errors.New("no privilege") }
	rep, err := Run(context.Background(), opt)
	must(t, err)
	target := filepath.Join(into, "home", "link.txt")
	fi, err := os.Lstat(target)
	must(t, err)
	if !fi.Mode().IsRegular() {
		t.Fatalf("expected flattened regular file, got %v", fi.Mode())
	}
	found := false
	for _, p := range rep.Problems {
		if p.Code == "symlink_flattened" {
			found = true
		}
	}
	if !found {
		t.Fatal("symlink_flattened not recorded")
	}
}

func TestCanceledContext(t *testing.T) {
	pkg, _, pub := buildPackage(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opt := optInto(pkg, filepath.Join(t.TempDir(), "target"))
	opt.PubKeyPath = pub
	if _, err := Run(ctx, opt); !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v, want ErrCanceled", err)
	}
}

// TestFlattenWritesRegularFile exercises the Windows no-privilege path without
// needing a real symlink in the package.
func TestFlattenWritesRegularFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "home", "link.txt")
	fail := func(string, string) error { return errors.New("no privilege") }
	flattened, err := writeSymlink(root, target, "../real.txt", fail)
	must(t, err)
	if !flattened {
		t.Fatal("expected flatten")
	}
	fi, err := os.Lstat(target)
	must(t, err)
	if !fi.Mode().IsRegular() {
		t.Fatalf("mode = %v", fi.Mode())
	}
	data, err := os.ReadFile(target)
	must(t, err)
	if string(data) != "../real.txt" {
		t.Fatalf("content = %q", data)
	}
}

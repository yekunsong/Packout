package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packout/internal/pack"
)

// exportPkg runs scan + export and returns the package path.
func exportPkg(t *testing.T) string {
	t.Helper()
	inst := fixtureTree(t)
	work := t.TempDir()
	scanOut := filepath.Join(work, "scan")
	code, _, stderr := run(t, append([]string{"scan", "--out", scanOut, "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}
	pkg := filepath.Join(work, "pkg")
	code, _, stderr = run(t, "export", "--src", scanOut, "--out", pkg, "--quiet")
	if code != exitOK {
		t.Fatalf("export: code=%d stderr=%q", code, stderr)
	}
	return pkg
}

// isolateHome points the default key/trusted-key lookups at a temp dir.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func newKey(t *testing.T) (priv, pub string) {
	t.Helper()
	dir := t.TempDir()
	priv = filepath.Join(dir, "minisign.key")
	pub = priv + ".pub"
	if _, err := pack.GenerateKeyPair(priv, pub); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv, pub
}

func TestSignThenVerifyOK(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	priv, pub := newKey(t)

	code, stdout, stderr := run(t, "sign", pkg, "--key", priv)
	if code != exitOK {
		t.Fatalf("sign: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "SHA256:") {
		t.Errorf("sign did not read out the fingerprint: %q", stderr)
	}
	if _, err := os.Lstat(filepath.Join(pkg, pack.MinisigName)); err != nil {
		t.Fatalf("signature missing: %v", err)
	}

	code, stdout, stderr = run(t, "verify", pkg, "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("verify: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != pack.ConclusionOK {
		t.Fatalf("conclusion = %q, want ok", strings.TrimSpace(stdout))
	}
	if !strings.Contains(stderr, "TOFU") || !strings.Contains(stderr, "SHA256:") {
		t.Errorf("no TOFU fingerprint on stderr: %q", stderr)
	}

	// The same key recorded in trusted_keys verifies without --pubkey.
	home, _ := os.UserHomeDir()
	trusted := filepath.Join(home, ".config", "packout", "trusted_keys")
	if err := os.MkdirAll(filepath.Dir(trusted), 0o755); err != nil {
		t.Fatal(err)
	}
	pubText, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trusted, append([]byte("# trusted\n"), pubText...), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = run(t, "verify", pkg)
	if code != exitOK || strings.TrimSpace(stdout) != pack.ConclusionOK {
		t.Fatalf("trusted-keys verify: code=%d stdout=%q", code, stdout)
	}
}

func TestVerifyConclusionExitCodes(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	priv, pub := newKey(t)
	if code, _, stderr := run(t, "sign", pkg, "--key", priv); code != exitOK {
		t.Fatalf("sign: %d %q", code, stderr)
	}

	manifestFile := filepath.Join(pkg, pack.ManifestDirName, "manifest.index.json")
	data, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := os.WriteFile(manifestFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := run(t, "verify", pkg, "--pubkey", pub)
	if code != exitPartial || strings.TrimSpace(stdout) != pack.ConclusionTampered {
		t.Fatalf("tampered: code=%d stdout=%q", code, stdout)
	}

	// Restore content, then use the wrong key.
	if err := os.WriteFile(manifestFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Putting the flipped byte back is enough only because SIG still covers
	// the original bytes.
	orig, _ := os.ReadFile(manifestFile)
	orig[0] ^= 0xff
	if err := os.WriteFile(manifestFile, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	_, otherPub := newKey(t)
	code, stdout, _ = run(t, "verify", pkg, "--pubkey", otherPub)
	if code != exitPartial || strings.TrimSpace(stdout) != pack.ConclusionBadSignature {
		t.Fatalf("bad-signature: code=%d stdout=%q", code, stdout)
	}

	// Remove the signature: matching content is unsigned, also exit 2.
	if err := os.Remove(filepath.Join(pkg, pack.MinisigName)); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = run(t, "verify", pkg, "--pubkey", pub)
	if code != exitPartial || strings.TrimSpace(stdout) != pack.ConclusionUnsigned {
		t.Fatalf("unsigned: code=%d stdout=%q", code, stdout)
	}

	// Change content with no signature: tampered.
	orig2, _ := os.ReadFile(manifestFile)
	orig2[0] ^= 0xff
	if err := os.WriteFile(manifestFile, orig2, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = run(t, "verify", pkg, "--pubkey", pub)
	if code != exitPartial || strings.TrimSpace(stdout) != pack.ConclusionTampered {
		t.Fatalf("unsigned+changed: code=%d stdout=%q", code, stdout)
	}
}

func TestVerifyWithoutKeyIsUnverified(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	priv, _ := newKey(t)
	if code, _, stderr := run(t, "sign", pkg, "--key", priv); code != exitOK {
		t.Fatalf("sign: %d %q", code, stderr)
	}
	code, stdout, stderr := run(t, "verify", pkg)
	if code != exitOK {
		t.Fatalf("verify: code=%d", code)
	}
	if strings.TrimSpace(stdout) != pack.ConclusionHashOKUnverified {
		t.Fatalf("conclusion = %q", strings.TrimSpace(stdout))
	}
	if !strings.Contains(stderr, "--pubkey") {
		t.Fatalf("no --pubkey hint: %q", stderr)
	}
}

func TestSignMissingKeyExitsUsage(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	code, _, stderr := run(t, "sign", pkg)
	if code != exitUsage {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "--generate") {
		t.Errorf("missing-key error lacks a hint: %q", stderr)
	}
}

func TestSignGenerate(t *testing.T) {
	home := isolateHome(t)
	pkg := exportPkg(t)
	key := filepath.Join(home, "custom.key")
	code, _, stderr := run(t, "sign", pkg, "--key", key, "--generate")
	if code != exitOK {
		t.Fatalf("sign --generate: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Lstat(key + ".pub"); err != nil {
		t.Fatalf("public key not written: %v", err)
	}
	code, stdout, _ := run(t, "verify", pkg, "--pubkey", key+".pub")
	if code != exitOK || strings.TrimSpace(stdout) != pack.ConclusionOK {
		t.Fatalf("verify: code=%d stdout=%q", code, stdout)
	}
	// A second --generate refuses to overwrite.
	if code, _, _ := run(t, "sign", pkg, "--key", key, "--generate"); code != exitUsage {
		t.Fatalf("second --generate: code=%d", code)
	}
}

func TestVerifyMalformedPubkeyExitsUsage(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	priv, _ := newKey(t)
	if code, _, stderr := run(t, "sign", pkg, "--key", priv); code != exitOK {
		t.Fatalf("sign: %d %q", code, stderr)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "verify", pkg, "--pubkey", bad)
	if code != exitUsage {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, ":1:") {
		t.Errorf("line number missing: %q", stderr)
	}
	if strings.TrimSpace(stdout) != pack.ConclusionFailed {
		t.Fatalf("conclusion = %q", strings.TrimSpace(stdout))
	}
}

func TestForceExportDropsStaleSignature(t *testing.T) {
	isolateHome(t)
	pkg := exportPkg(t)
	priv, pub := newKey(t)
	if code, _, stderr := run(t, "sign", pkg, "--key", priv); code != exitOK {
		t.Fatalf("sign: %d %q", code, stderr)
	}
	// Re-export the same content into the same package.
	inst := fixtureTree(t)
	scanOut := filepath.Join(t.TempDir(), "scan")
	if code, _, stderr := run(t, append([]string{"scan", "--out", scanOut, "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("scan: %d %q", code, stderr)
	}
	if code, _, stderr := run(t, "export", "--src", scanOut, "--out", pkg, "--force", "--quiet"); code != exitOK {
		t.Fatalf("force export: %d %q", code, stderr)
	}
	if _, err := os.Lstat(filepath.Join(pkg, pack.MinisigName)); !os.IsNotExist(err) {
		t.Fatalf("stale signature survived re-export: %v", err)
	}
	code, stdout, _ := run(t, "verify", pkg, "--pubkey", pub)
	if code != exitPartial || strings.TrimSpace(stdout) != pack.ConclusionUnsigned {
		t.Fatalf("verify: code=%d stdout=%q", code, stdout)
	}
}

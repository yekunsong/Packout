package pack

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// signedFixture exports a package and signs it with a fresh key pair.
func signedFixture(t *testing.T) (pkg, priv, pub string) {
	t.Helper()
	src, _ := scanFixture(t)
	writeFile(t, filepath.Join(src, ConfigDirName, "home", "cipher.bin"), "ciphertext-ish")
	out := filepath.Join(t.TempDir(), "pkg")
	mustExport(t, Config{SourceDir: src, OutDir: out})
	keys := t.TempDir()
	priv = filepath.Join(keys, "minisign.key")
	pub = priv + ".pub"
	if _, err := GenerateKeyPair(priv, pub); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := Sign(out, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return out, priv, pub
}

func verifyWith(dir string, opt VerifyOptions) (*Verdict, error) {
	return VerifyWithOptions(dir, opt)
}

func noTrusted(t *testing.T) string {
	return filepath.Join(t.TempDir(), "trusted_keys")
}

func TestSignVerifyOK(t *testing.T) {
	pkg, _, pub := signedFixture(t)

	before, _ := scanTree(pkg, Limits{}, true, 0)
	if _, err := os.Lstat(filepath.Join(pkg, MinisigName)); err != nil {
		t.Fatalf("signature not written: %v", err)
	}
	after, _ := scanTree(pkg, Limits{}, true, 0)
	if len(before) != len(after) {
		t.Fatalf("signature changed the covered tree: %d -> %d entries", len(before), len(after))
	}
	for _, e := range after {
		if e.Path == MinisigName {
			t.Fatal(".minisig was covered by the tree")
		}
	}
	sig, err := ReadSIG(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range sig.Entries {
		if e.Path == MinisigName {
			t.Fatal(".minisig is listed in SIG.json")
		}
	}

	v, err := verifyWith(pkg, VerifyOptions{PubKeyPath: pub, TrustedKeysPath: noTrusted(t)})
	if err != nil {
		t.Fatalf("verify: %v (verdict %+v)", err, v)
	}
	if v.Conclusion != ConclusionOK {
		t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionOK)
	}
	if !v.SignaturePresent || !v.Signed || v.KeyFingerprint == "" {
		t.Fatalf("verdict does not report the signature: %+v", v)
	}
}

func TestSignatureDoesNotCoverItself(t *testing.T) {
	pkg, priv, pub := signedFixture(t)
	first, err := CoverageSHA256(pkg, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(pkg, priv); err != nil {
		t.Fatal(err)
	}
	second, err := CoverageSHA256(pkg, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("coverage changed when the signature changed: %s != %s", first, second)
	}

	// Corrupting only the signature is an attribution failure, not tampering.
	path := filepath.Join(pkg, MinisigName)
	if err := os.WriteFile(path, []byte("untrusted comment: x\n"+strings.Repeat("A", 120)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := verifyWith(pkg, VerifyOptions{PubKeyPath: pub, TrustedKeysPath: noTrusted(t)})
	if !errors.Is(err, ErrBadSignature) || v.Conclusion != ConclusionBadSignature {
		t.Fatalf("v=%+v err=%v", v, err)
	}
}

func TestTamperAfterSignIsTampered(t *testing.T) {
	cases := map[string]string{
		"ciphertext": filepath.Join(ConfigDirName, "home", "cipher.bin"),
		"manifest":   "",
	}
	for name, rel := range cases {
		t.Run(name, func(t *testing.T) {
			pkg, _, pub := signedFixture(t)
			target := rel
			if target == "" {
				target = firstManifestFile(t, pkg)
			}
			flipByte(t, filepath.Join(pkg, target))
			v, err := verifyWith(pkg, VerifyOptions{PubKeyPath: pub, TrustedKeysPath: noTrusted(t)})
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("want ErrTampered, got %v", err)
			}
			if v.Conclusion != ConclusionTampered {
				t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionTampered)
			}
		})
	}
}

func TestWrongPublicKeyIsBadSignature(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	other := t.TempDir()
	otherPriv := filepath.Join(other, "k.key")
	otherPub := otherPriv + ".pub"
	if _, err := GenerateKeyPair(otherPriv, otherPub); err != nil {
		t.Fatal(err)
	}
	v, err := verifyWith(pkg, VerifyOptions{PubKeyPath: otherPub, TrustedKeysPath: noTrusted(t)})
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
	if v.Conclusion != ConclusionBadSignature {
		t.Fatalf("conclusion = %q", v.Conclusion)
	}
}

func TestUnsignedConclusion(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	if err := os.Remove(filepath.Join(pkg, MinisigName)); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(pkg)
	if err != nil {
		t.Fatalf("unsigned matching content: %v", err)
	}
	if v.Conclusion != ConclusionUnsigned || v.SignaturePresent {
		t.Fatalf("v=%+v", v)
	}

	writeFile(t, filepath.Join(pkg, ConfigDirName, "home", "cipher.bin"), "changed")
	v, err = Verify(pkg)
	if !errors.Is(err, ErrTampered) || v.Conclusion != ConclusionTampered {
		t.Fatalf("unsigned changed content: v=%+v err=%v", v, err)
	}
}

func TestNoPublicKeyIsBadSignature(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	v, err := verifyWith(pkg, VerifyOptions{TrustedKeysPath: noTrusted(t)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// No usable key is an attribution failure; the tree matched, so this is
	// bad-signature, never failed (and never tampered).
	if v.Conclusion != ConclusionBadSignature {
		t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionBadSignature)
	}
	found := false
	for _, p := range v.Problems {
		if p.Code == "no-pubkey" && strings.Contains(p.Detail, "--pubkey") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no --pubkey hint: %+v", v.Problems)
	}
}

func TestTrustedKeysFile(t *testing.T) {
	pkg, _, pub := signedFixture(t)
	pubText, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	trusted := filepath.Join(t.TempDir(), "trusted_keys")
	content := "# my keys\n" + string(pubText) + "\n"
	if err := os.WriteFile(trusted, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var firstSeen *bool
	v, err := verifyWith(pkg, VerifyOptions{
		TrustedKeysPath: trusted,
		OnKeySeen:       func(_ string, fs bool) { firstSeen = &fs },
	})
	if err != nil || v.Conclusion != ConclusionOK {
		t.Fatalf("v=%+v err=%v", v, err)
	}
	if firstSeen == nil || *firstSeen {
		t.Fatal("key from trusted_keys must not be first-seen")
	}

	// The same key via --pubkey is known to the trusted file: no TOFU warning.
	firstSeen = nil
	v, err = verifyWith(pkg, VerifyOptions{PubKeyPath: pub, TrustedKeysPath: trusted,
		OnKeySeen: func(_ string, fs bool) { firstSeen = &fs }})
	if err != nil || v.Conclusion != ConclusionOK || firstSeen == nil || *firstSeen {
		t.Fatalf("v=%+v err=%v firstSeen=%v", v, err, firstSeen)
	}

	// An unknown --pubkey is first-seen.
	pkg2, _, pub2 := signedFixture(t)
	firstSeen = nil
	v, err = verifyWith(pkg2, VerifyOptions{PubKeyPath: pub2, TrustedKeysPath: trusted,
		OnKeySeen: func(_ string, fs bool) { firstSeen = &fs }})
	if err != nil || v.Conclusion != ConclusionOK || firstSeen == nil || !*firstSeen {
		t.Fatalf("unknown --pubkey not first-seen: v=%+v err=%v", v, err)
	}
}

func TestMalformedPublicKeyFile(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	bad := filepath.Join(t.TempDir(), "bad_keys")
	if err := os.WriteFile(bad, []byte("# comment\nnot-a-key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := verifyWith(pkg, VerifyOptions{PubKeyPath: bad})
	if !errors.Is(err, ErrInvalidPubKey) {
		t.Fatalf("want ErrInvalidPubKey, got %v", err)
	}
	if v.Conclusion != ConclusionBadSignature {
		t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionBadSignature)
	}
	if !strings.Contains(v.Problems[0].Detail, ":2:") {
		t.Fatalf("line number missing: %+v", v.Problems)
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWith(pkg, VerifyOptions{PubKeyPath: empty}); !errors.Is(err, ErrInvalidPubKey) {
		t.Fatalf("empty key file accepted: %v", err)
	}
}

func TestMissingKey(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	if _, err := Sign(pkg, filepath.Join(t.TempDir(), "nope.key")); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}

func TestKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not reflect ACL permissions")
	}
	pkg, priv, _ := signedFixture(t)
	if err := os.Chmod(priv, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(pkg, priv); !errors.Is(err, ErrKeyPermissions) {
		t.Fatalf("want ErrKeyPermissions, got %v", err)
	}
	if err := os.Chmod(priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(pkg, priv); err != nil {
		t.Fatalf("0600 key rejected: %v", err)
	}
}

func TestSignRefusesNonPackage(t *testing.T) {
	keys := t.TempDir()
	priv := filepath.Join(keys, "k.key")
	if _, err := GenerateKeyPair(priv, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(t.TempDir(), priv); err == nil {
		t.Fatal("empty directory was signed")
	}
}

func TestGenerateKeyPairRefusesOverwrite(t *testing.T) {
	priv := filepath.Join(t.TempDir(), "k.key")
	if _, err := GenerateKeyPair(priv, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKeyPair(priv, ""); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("want ErrKeyExists, got %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(priv)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode %04o, want 0600", fi.Mode().Perm())
		}
	}
}

func firstManifestFile(t *testing.T, pkg string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(filepath.Join(pkg, ManifestDirName), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		rel, _ := filepath.Rel(pkg, p)
		found = filepath.ToSlash(rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("manifest has no files")
	}
	return found
}

func flipByte(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBlankTrustedKeysIsBadSignature(t *testing.T) {
	pkg, _, _ := signedFixture(t)
	blank := filepath.Join(t.TempDir(), "trusted_keys")
	if err := os.WriteFile(blank, []byte("# no keys yet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := verifyWith(pkg, VerifyOptions{TrustedKeysPath: blank})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Conclusion != ConclusionBadSignature {
		t.Fatalf("conclusion = %q, want %q", v.Conclusion, ConclusionBadSignature)
	}
}

func TestTamperedWinsOverMissingKey(t *testing.T) {
	// Conclusion order is INV-C06: content first, attribution second. A
	// missing key must not downgrade a real content mismatch to bad-signature.
	pkg, _, _ := signedFixture(t)
	flipByte(t, filepath.Join(pkg, firstManifestFile(t, pkg)))
	v, err := verifyWith(pkg, VerifyOptions{TrustedKeysPath: noTrusted(t)})
	if !errors.Is(err, ErrTampered) || v.Conclusion != ConclusionTampered {
		t.Fatalf("v=%+v err=%v", v, err)
	}
}

func TestBrokenTrustedKeysDoesNotBlockPubkey(t *testing.T) {
	// --pubkey is the sole verification source (D-044 #4); a corrupt trust
	// store only means "unknown to the store" for the TOFU read-out.
	pkg, _, pub := signedFixture(t)
	bad := filepath.Join(t.TempDir(), "trusted_keys")
	if err := os.WriteFile(bad, []byte("not-a-key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var firstSeen *bool
	v, err := verifyWith(pkg, VerifyOptions{
		PubKeyPath:      pub,
		TrustedKeysPath: bad,
		OnKeySeen:       func(_ string, fs bool) { firstSeen = &fs },
	})
	if err != nil || v.Conclusion != ConclusionOK {
		t.Fatalf("v=%+v err=%v", v, err)
	}
	if firstSeen == nil || !*firstSeen {
		t.Fatalf("unreadable store must count as first-seen: %v", firstSeen)
	}
}

package pack

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"aead.dev/minisign"

	"packout/internal/fsx"
	"packout/internal/manifest"
)

// Signature file. It is deliberately NOT covered by SIG.json's tree and NOT
// part of the signed message, otherwise the signature would cover itself.
const MinisigName = "SIG.json.minisig"

// MaxMinisigBytes bounds the signature file.
const MaxMinisigBytes = 64 << 10

// signatureDomain separates a package coverage digest from any other message
// signed with the same key.
const signatureDomain = "packout-package-signature-v1\n"

// SignResult describes a successful Sign.
type SignResult struct {
	Path           string `json:"path"`
	KeyFingerprint string `json:"key_fingerprint"`
	CoverageSHA256 string `json:"coverage_sha256"`
}

func configDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "packout"), nil
}

// DefaultPrivateKeyPath is ~/.config/packout/minisign.key (D-043).
func DefaultPrivateKeyPath() (string, error) {
	d, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "minisign.key"), nil
}

// DefaultTrustedKeysPath is ~/.config/packout/trusted_keys. It may not exist.
func DefaultTrustedKeysPath() string {
	d, err := configDirPath()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "trusted_keys")
}

// KeyFingerprint is SHA-256 over the key's textual form, hex encoded. It is a
// read-out for TOFU comparison, not a trust anchor by itself.
func KeyFingerprint(pk *minisign.PublicKey) string {
	sum := sha256.Sum256([]byte(pk.String()))
	return hex.EncodeToString(sum[:])
}

// CoverageSHA256 hashes exactly what a signature covers: SIG.json and every
// file under manifest/. It reuses the package's canonical tree hash, with
// paths kept relative to the package root. The signature file itself is never
// included.
func CoverageSHA256(pkgDir string, limits Limits) (string, error) {
	limits = limits.withDefaults()
	if _, err := ReadSIG(pkgDir); err != nil {
		return "", err
	}
	mdir := filepath.Join(pkgDir, ManifestDirName)
	mi, err := fsx.Lstat(mdir)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoManifest, err)
	}
	if !mi.IsDir || mi.IsReparse {
		return "", fmt.Errorf("%w: %q", ErrNoManifest, mdir)
	}
	if err := manifest.Validate(mdir); err != nil {
		return "", fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}

	sigPath := filepath.Join(pkgDir, SIGName)
	si, err := fsx.Lstat(sigPath)
	if err != nil {
		return "", err
	}
	if !si.Mode.IsRegular() || si.IsLink || si.IsReparse {
		return "", fmt.Errorf("%w: SIG is not a plain regular file", ErrUnsupportedFormat)
	}
	sha, err := hashFile(sigPath, si.Size)
	if err != nil {
		return "", err
	}
	mode := modeString(si.Mode)
	size := si.Size
	entries := make([]SIGEntry, 0, 32)
	entries = append(entries, SIGEntry{Type: TypeFile, Path: SIGName, Mode: &mode, Size: &size, SHA256: &sha})

	mentries, err := scanTree(mdir, limits, false, 0)
	if err != nil {
		return "", err
	}
	for i := range mentries {
		e := mentries[i]
		e.Path = ManifestDirName + "/" + e.Path
		entries = append(entries, e)
	}
	digest, err := NewSIG(entries)
	if err != nil {
		return "", err
	}
	return digest.TreeSHA256, nil
}

// Sign signs the coverage hash of pkgDir and writes SIG.json.minisig.
// keyPath defaults to DefaultPrivateKeyPath. The package must already carry a
// valid SIG and manifest.
func Sign(pkgDir, keyPath string) (*SignResult, error) {
	if pkgDir == "" {
		return nil, fmt.Errorf("%w: empty package directory", ErrInvalidConfig)
	}
	abs, err := fsx.Abs(pkgDir)
	if err != nil {
		return nil, err
	}
	fi, err := fsx.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir || fi.IsReparse {
		return nil, fmt.Errorf("%w: %q is not a plain directory", ErrInvalidConfig, abs)
	}
	if keyPath == "" {
		if keyPath, err = DefaultPrivateKeyPath(); err != nil {
			return nil, err
		}
	}
	priv, fingerprint, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	coverage, err := CoverageSHA256(abs, Limits{})
	if err != nil {
		return nil, err
	}
	msg := []byte(signatureDomain + coverage)
	sig := minisign.SignWithComments(priv, msg,
		"packout signature over SIG.json and manifest/",
		"signature from packout key SHA256:"+fingerprint)

	// Self-check before landing: a signature we cannot verify is not written.
	pub, ok := priv.Public().(minisign.PublicKey)
	if !ok || !minisign.Verify(pub, msg, sig) {
		return nil, fmt.Errorf("pack: signing self-check failed")
	}
	path := filepath.Join(abs, MinisigName)
	if err := writeFileAtomic(path, sig, 0o644); err != nil {
		return nil, err
	}
	return &SignResult{Path: path, KeyFingerprint: fingerprint, CoverageSHA256: coverage}, nil
}

// GenerateKeyPair creates an unencrypted minisign key pair. publicPath empty
// means privatePath+".pub". Nothing is written when privatePath exists.
func GenerateKeyPair(privatePath, publicPath string) (string, error) {
	if privatePath == "" {
		return "", fmt.Errorf("%w: empty key path", ErrInvalidConfig)
	}
	if _, err := fsx.Lstat(privatePath); err == nil {
		return "", fmt.Errorf("%w: %s", ErrKeyExists, privatePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if publicPath == "" {
		publicPath = privatePath + ".pub"
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	privText, err := priv.MarshalText()
	if err != nil {
		return "", err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(privatePath, privText, 0o600); err != nil {
		return "", err
	}
	if err := writeFileAtomic(publicPath, pubText, 0o644); err != nil {
		return "", err
	}
	return KeyFingerprint(&pub), nil
}

func loadPrivateKey(path string) (minisign.PrivateKey, string, error) {
	fi, err := fsx.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return minisign.PrivateKey{}, "", fmt.Errorf("%w: %s（用 sign --generate 生成）", ErrNoKey, path)
		}
		return minisign.PrivateKey{}, "", err
	}
	if !fi.Mode.IsRegular() || fi.IsLink || fi.IsReparse {
		return minisign.PrivateKey{}, "", fmt.Errorf("%w: %s 不是普通文件", ErrNoKey, path)
	}
	// Windows mode bits are synthesized by Go and do not reflect the ACL, so
	// the check is Unix-only.
	if runtime.GOOS != "windows" && fi.Mode.Perm()&0o077 != 0 {
		return minisign.PrivateKey{}, "", fmt.Errorf("%w: %s 是 %04o，应为 0600（chmod 600 %s）",
			ErrKeyPermissions, path, fi.Mode.Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return minisign.PrivateKey{}, "", err
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(data); err != nil {
		return minisign.PrivateKey{}, "", fmt.Errorf("%w: %s: %v（加密私钥 P0 不支持）", ErrInvalidKey, path, err)
	}
	pub, ok := priv.Public().(minisign.PublicKey)
	if !ok {
		return minisign.PrivateKey{}, "", fmt.Errorf("%w: %s", ErrInvalidKey, path)
	}
	return priv, KeyFingerprint(&pub), nil
}

// LoadPublicKeys parses a trusted-keys file: one base64 minisign public key per
// line, '#' comments allowed. Full minisign .pub files are accepted too (their
// "untrusted comment:" line is skipped).
func LoadPublicKeys(path string) ([]minisign.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []minisign.PublicKey
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(line)); err != nil {
			return nil, fmt.Errorf("%w: %s:%d: %v", ErrInvalidPubKey, path, i+1, err)
		}
		keys = append(keys, pk)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s 中没有公钥", ErrInvalidPubKey, path)
	}
	return keys, nil
}

// readMinisig reads and structurally parses the signature file.
func readMinisig(pkgDir string) ([]byte, error) {
	p := filepath.Join(pkgDir, MinisigName)
	fi, err := fsx.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode.IsRegular() || fi.IsLink || fi.IsReparse {
		return nil, fmt.Errorf("%w: .minisig is not a plain regular file", ErrBadSignature)
	}
	if fi.Size > MaxMinisigBytes {
		return nil, fmt.Errorf("%w: .minisig exceeds %d bytes", ErrBadSignature, MaxMinisigBytes)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s minisign.Signature
	if err := s.UnmarshalText(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return data, nil
}

// writeFileAtomic writes via a temporary sibling and a rename.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}

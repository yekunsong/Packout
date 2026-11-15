package pack

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"

	"github.com/yekunsong/Packout/internal/fsx"
)

// SecretsName is the encrypted secrets member of a package. It is the only
// encrypted part; config/ and manifest/ stay readable without a key so that a
// package can still be inspected (and partially restored) when decryption is
// unavailable (spec-manifest §9.5).
const SecretsName = "secrets.age"

// secretsFormat identifies the plaintext index inside secrets.age. The index
// is encrypted; the format tag only helps a future reader once decrypted.
const secretsFormat = "packout-secrets"

// secretsFormatVersion is bumped when the plaintext index changes shape.
const secretsFormatVersion = 1

// maxSecretsBytes bounds secrets.age so a hostile package cannot make decrypt
// allocate without limit.
const maxSecretsBytes = 256 << 20

// CryptOptions selects exactly one encryption shape: age recipients or a
// passphrase. IdentityPath is only used for decryption (and for export
// warnings); encryption never needs it.
type CryptOptions struct {
	// Recipients are age1… or ssh-ed25519/ssh-rsa public key strings.
	Recipients []string
	// Passphrase enables scrypt mode. Empty means recipient mode.
	Passphrase []byte
	// IdentityPath is the age identity file. Empty means
	// ~/.config/packout/identity.age.
	IdentityPath string
}

func (o CryptOptions) hasPassphrase() bool { return len(o.Passphrase) > 0 }

func (o CryptOptions) validateShape() error {
	if len(o.Recipients) > 0 && o.hasPassphrase() {
		return fmt.Errorf("%w: --recipient 与 --passphrase 只能二选一", ErrInvalidConfig)
	}
	if len(o.Recipients) == 0 && !o.hasPassphrase() {
		return fmt.Errorf("%w: 需要至少一个 --recipient 或 --passphrase", ErrInvalidConfig)
	}
	return nil
}

// EncryptSecrets encrypts plaintext with opts and atomically replaces dest.
//
// The ciphertext is written to a temporary sibling first, synced and closed,
// and only then renamed over dest. A failure therefore leaves dest untouched;
// Export additionally discards its whole staging tree on error.
func EncryptSecrets(dest string, plaintext []byte, opts CryptOptions) error {
	if err := opts.validateShape(); err != nil {
		return err
	}
	abs, err := fsx.Abs(dest)
	if err != nil {
		return err
	}
	var recipients []age.Recipient
	if opts.hasPassphrase() {
		r, err := age.NewScryptRecipient(string(opts.Passphrase))
		if err != nil {
			return fmt.Errorf("pack: passphrase: %w", err)
		}
		recipients = []age.Recipient{r}
	} else {
		recipients, err = parseRecipients(opts.Recipients)
		if err != nil {
			return err
		}
	}

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(abs)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	w, err := age.Encrypt(f, recipients...)
	if err != nil {
		return fmt.Errorf("pack: encrypt %s: %w", filepath.Base(abs), err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("pack: encrypt %s: %w", filepath.Base(abs), err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("pack: encrypt %s: %w", filepath.Base(abs), err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, abs); err != nil {
		return err
	}
	tmp = ""
	return nil
}

// parseRecipients accepts only the two documented forms. age.ParseRecipients
// is still used per string so the key actually parses.
func parseRecipients(list []string) ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		switch {
		case strings.HasPrefix(s, "age1"):
		case strings.HasPrefix(s, "ssh-ed25519 "), strings.HasPrefix(s, "ssh-rsa "):
		default:
			return nil, fmt.Errorf("%w: recipient %q 不是 age1… 或 ssh-ed25519/ssh-rsa 公钥", ErrInvalidConfig, s)
		}
		rs, err := age.ParseRecipients(strings.NewReader(s + "\n"))
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %q: %v", ErrInvalidConfig, s, err)
		}
		out = append(out, rs...)
	}
	return out, nil
}

// DefaultIdentityPath returns ~/.config/packout/identity.age.
func DefaultIdentityPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "packout", "identity.age"), nil
}

// DecryptSecrets decrypts pkgDir/secrets.age with the given identity or
// passphrase. IdentityPath defaults to DefaultIdentityPath when both are
// empty.
func DecryptSecrets(pkgDir string, opts CryptOptions) ([]byte, error) {
	if len(opts.Recipients) > 0 && opts.hasPassphrase() {
		return nil, fmt.Errorf("%w: 解密时 --identity 与 --passphrase 只能二选一", ErrInvalidConfig)
	}
	dir, err := fsx.Abs(pkgDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, SecretsName)
	fi, err := fsx.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("pack: %s: %w", SecretsName, err)
	}
	if fi.IsLink || fi.IsReparse || !fi.Mode.IsRegular() {
		return nil, fmt.Errorf("pack: %s is not a plain regular file", SecretsName)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ids []age.Identity
	if opts.hasPassphrase() {
		id, err := age.NewScryptIdentity(string(opts.Passphrase))
		if err != nil {
			return nil, fmt.Errorf("pack: passphrase: %w", err)
		}
		ids = []age.Identity{id}
	} else {
		ids, err = readIdentities(opts.IdentityPath)
		if err != nil {
			return nil, err
		}
	}
	r, err := age.Decrypt(f, ids...)
	if err != nil {
		return nil, fmt.Errorf("pack: decrypt %s: %w", SecretsName, err)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSecretsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pack: decrypt %s: %w", SecretsName, err)
	}
	if len(data) > maxSecretsBytes {
		return nil, fmt.Errorf("%w: decrypted %s exceeds %d bytes", ErrLimitExceeded, SecretsName, maxSecretsBytes)
	}
	return data, nil
}

func readIdentities(path string) ([]age.Identity, error) {
	if path == "" {
		p, err := DefaultIdentityPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pack: identity: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("pack: identity %s: %w", path, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("pack: identity %s contains no keys", path)
	}
	return ids, nil
}

// identityWarnings reports identity placement and permissions. It is a
// warning-only check: neither condition stops an export.
func identityWarnings(identity, outDir string) []string {
	if identity == "" {
		return nil
	}
	abs, err := fsx.Abs(identity)
	if err != nil {
		return []string{"identity file " + identity + " is not resolvable: " + err.Error()}
	}
	var out []string
	if fsx.Within(outDir, abs) {
		out = append(out, "identity file "+abs+" will live inside the package tree")
	}
	if fi, err := os.Stat(abs); err == nil && fi.Mode().IsRegular() && runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			out = append(out, fmt.Sprintf("identity file %s has mode %04o, wider than 0600", abs, perm))
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		out = append(out, "identity file "+abs+": "+err.Error())
	}
	return out
}

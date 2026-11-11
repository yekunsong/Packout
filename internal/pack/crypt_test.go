package pack

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func writeIdentity(t *testing.T, dir string, id *age.X25519Identity) string {
	t.Helper()
	p := filepath.Join(dir, "identity.age")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEncryptDecryptRecipientRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := mustIdentity(t)
	dest := filepath.Join(dir, "secrets.age")
	plain := []byte(`{"format":"packout-secrets","entries":[{"ref":"secrets.age#h_x","value":"sk-ant-secret"}]}`)

	opts := CryptOptions{Recipients: []string{id.Recipient().String()}}
	if err := EncryptSecrets(dest, plain, opts); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets.age mode = %v, want 0600", fi.Mode().Perm())
	}
	if names, _ := filepath.Glob(filepath.Join(dir, ".secrets.age.tmp-*")); len(names) != 0 {
		t.Fatalf("temporary files left behind: %v", names)
	}

	got, err := DecryptSecrets(dir, CryptOptions{IdentityPath: writeIdentity(t, dir, id)})
	if err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip changed plaintext: %q", got)
	}
}

func TestEncryptDecryptPassphraseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plain := []byte("passphrase payload")
	opts := CryptOptions{Passphrase: []byte("correct horse battery staple")}
	if err := EncryptSecrets(filepath.Join(dir, SecretsName), plain, opts); err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}
	got, err := DecryptSecrets(dir, CryptOptions{Passphrase: opts.Passphrase})
	if err != nil {
		t.Fatalf("DecryptSecrets: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip changed plaintext: %q", got)
	}
}

func TestDecryptWrongIdentityFails(t *testing.T) {
	dir := t.TempDir()
	id := mustIdentity(t)
	if err := EncryptSecrets(filepath.Join(dir, SecretsName), []byte("x"), CryptOptions{Recipients: []string{id.Recipient().String()}}); err != nil {
		t.Fatal(err)
	}
	other := mustIdentity(t)
	if _, err := DecryptSecrets(dir, CryptOptions{IdentityPath: writeIdentity(t, dir, other)}); err == nil {
		t.Fatal("decryption with the wrong identity succeeded")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	dir := t.TempDir()
	id := mustIdentity(t)
	dest := filepath.Join(dir, SecretsName)
	if err := EncryptSecrets(dest, []byte("tamper me"), CryptOptions{Recipients: []string{id.Recipient().String()}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptSecrets(dir, CryptOptions{IdentityPath: writeIdentity(t, dir, id)}); err == nil {
		t.Fatal("tampered ciphertext decrypted cleanly")
	}
}

func TestCryptOptionsShape(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, SecretsName)
	id := mustIdentity(t)
	if err := EncryptSecrets(dest, []byte("x"), CryptOptions{}); err == nil {
		t.Fatal("no recipient and no passphrase accepted")
	}
	if err := EncryptSecrets(dest, []byte("x"), CryptOptions{
		Recipients: []string{id.Recipient().String()},
		Passphrase: []byte("p"),
	}); err == nil {
		t.Fatal("both recipient and passphrase accepted")
	}
	if err := EncryptSecrets(dest, []byte("x"), CryptOptions{Recipients: []string{"nope"}}); err == nil {
		t.Fatal("invalid recipient accepted")
	}
}

func TestEncryptFailureLeavesNoDest(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, SecretsName)
	err := EncryptSecrets(dest, []byte("x"), CryptOptions{Recipients: []string{"age1invalid"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("failed encryption left a destination file")
	}
	if names, _ := filepath.Glob(filepath.Join(dir, "."+SecretsName+".tmp-*")); len(names) != 0 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}

func TestIdentityWarnings(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "pkg")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(out, "identity.age")
	if err := os.WriteFile(inside, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := identityWarnings(inside, out)
	joined := strings.Join(w, "\n")
	if !strings.Contains(joined, "inside the package tree") {
		t.Fatalf("missing inside-package warning: %v", w)
	}

	wide := filepath.Join(dir, "wide.age")
	if err := os.WriteFile(wide, []byte("k\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		w = identityWarnings(wide, out)
	}
	if runtime.GOOS != "windows" && (len(w) != 1 || !strings.Contains(w[0], "wider than 0600")) {
		t.Fatalf("missing permission warning: %v", w)
	}
}

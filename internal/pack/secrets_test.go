package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
	"github.com/yekunsong/Packout/internal/secret"
)

const (
	apiKeyValue = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
	passwordVal = "hunter2hunter2"
)

// secretFixture builds a scan output whose single unit carries the manifest
// hits scan would have recorded for the file.
func secretFixture(t *testing.T) (src, root, out string, id *age.X25519Identity) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	src = filepath.Join(base, "scan")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"api_key":"` + apiKeyValue + `","password":"` + passwordVal + `","password_hint":"hint","theme":"dark"}`)
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(content))

	var hits []manifest.SecretHit
	pointers := jsonPointerOffsets(content)
	for _, h := range secret.DetectWithResult(secret.Options{Entropy: true, MaxHits: 32}, "settings.json", content).Hits {
		if h.Class != secret.Restore {
			continue
		}
		hits = append(hits, manifest.SecretHit{
			Kind:        "test",
			Class:       manifest.SecretRestore,
			Locator:     pointers[h.Offset],
			Prefix:      h.Prefix,
			Fingerprint: "sha256:" + secret.ValueFPWithSalt(content[h.Offset:h.End()], []byte("00112233445566778899aabbccddeeff")),
		})
	}
	if len(hits) < 2 {
		t.Fatalf("fixture detection produced %d restore hits, want >=2", len(hits))
	}
	u := fileUnit(root, "settings-global", filepath.Join(root, ".claude", "settings.json"))
	u.Confidence = 0.97
	u.Secret = &manifest.Secret{Class: manifest.SecretRestore, Hits: hits, HitCount: len(hits)}
	writeManifest(t, filepath.Join(src, ManifestDirName), root, u)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(base, "pkg")
	return src, root, out, id
}

func TestExportWithSecretsRecipient(t *testing.T) {
	src, root, out, id := secretFixture(t)
	prof, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatal(err)
	}

	res := mustExport(t, Config{
		SourceDir:   src,
		OutDir:      out,
		Profile:     prof,
		Roots:       map[string]string{"home": root},
		WithSecrets: true,
		Crypt:       CryptOptions{Recipients: []string{id.Recipient().String()}},
	})
	if res.SecretRefs < 2 {
		t.Fatalf("exported %d refs, want >=2", res.SecretRefs)
	}

	cfgPath := filepath.Join(out, ConfigDirName, "home", ".claude", "settings.json")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(cfg)
	for _, plain := range []string{apiKeyValue, passwordVal} {
		if strings.Contains(text, plain) {
			t.Fatalf("config still contains plaintext %q: %s", plain, text)
		}
	}
	if !strings.Contains(text, "«secret:"+SecretsName+"#h_") {
		t.Fatalf("config has no secret_ref placeholder: %s", text)
	}
	if !strings.Contains(text, "«REDACTED»") {
		t.Fatalf("explicit password redaction missing: %s", text)
	}
	if !json.Valid(cfg) {
		t.Fatalf("config is no longer valid JSON: %s", text)
	}

	if _, err := os.Stat(filepath.Join(out, SecretsName)); err != nil {
		t.Fatalf("secrets.age missing: %v", err)
	}
	v := mustVerify(t, out)
	if v.Conclusion != ConclusionUnsigned {
		t.Fatalf("verify conclusion = %q", v.Conclusion)
	}
	sig, err := ReadSIG(out)
	if err != nil {
		t.Fatal(err)
	}
	covered := false
	for _, e := range sig.Entries {
		if e.Path == SecretsName {
			covered = true
		}
	}
	if !covered {
		t.Fatal("SIG does not cover secrets.age")
	}

	identity := filepath.Join(t.TempDir(), "identity.age")
	if err := os.WriteFile(identity, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptSecrets(out, CryptOptions{IdentityPath: identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var doc struct {
		Entries []struct {
			Ref     string `json:"ref"`
			Value   string `json:"value"`
			Sources []struct {
				Path string `json:"path"`
			} `json:"sources"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(plain, &doc); err != nil {
		t.Fatalf("index: %v", err)
	}
	values := map[string]bool{}
	for _, e := range doc.Entries {
		values[e.Value] = true
		if len(e.Sources) == 0 || e.Sources[0].Path != "home/.claude/settings.json" {
			t.Fatalf("bad source in index entry %+v", e)
		}
	}
	if !values[apiKeyValue] || !values[passwordVal] {
		t.Fatalf("index values = %v", values)
	}
}

func TestExportWithSecretsPassphrase(t *testing.T) {
	src, root, out, _ := secretFixture(t)
	prof, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	mustExport(t, Config{
		SourceDir:   src,
		OutDir:      out,
		Profile:     prof,
		Roots:       map[string]string{"home": root},
		WithSecrets: true,
		Crypt:       CryptOptions{Passphrase: []byte("pw")},
	})
	plain, err := DecryptSecrets(out, CryptOptions{Passphrase: []byte("pw")})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !strings.Contains(string(plain), passwordVal) {
		t.Fatalf("decrypted index lacks the password: %s", plain)
	}
}

func TestExportWithSecretsRequiresShape(t *testing.T) {
	src, _ := scanFixture(t)
	if _, err := Export(Config{SourceDir: src, OutDir: filepath.Join(t.TempDir(), "p"), WithSecrets: true}); err == nil {
		t.Fatal("export with no recipients and no passphrase succeeded")
	}
	if _, err := Export(Config{
		SourceDir: src, OutDir: filepath.Join(t.TempDir(), "p"), WithSecrets: true,
		Crypt: CryptOptions{Recipients: []string{"age1x"}, Passphrase: []byte("p")},
	}); err == nil {
		t.Fatal("export with both shapes succeeded")
	}
}

func TestExportSecretsFailureLeavesNoPackage(t *testing.T) {
	src, root, out, _ := secretFixture(t)
	prof, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	// A valid-looking recipient that is actually malformed fails inside
	// age, i.e. after staging has begun.
	_, err = Export(Config{
		SourceDir: src, OutDir: out, Profile: prof,
		Roots: map[string]string{"home": root}, WithSecrets: true,
		Crypt: CryptOptions{Recipients: []string{"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}},
	})
	if err == nil {
		t.Fatal("expected encryption failure")
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("failed export left a package directory")
	}
	parent := filepath.Dir(out)
	if names, _ := filepath.Glob(filepath.Join(parent, ".pkg.stage-*")); len(names) != 0 {
		t.Fatalf("staging leftovers: %v", names)
	}
}

func TestExportIdentityInsideOutWarns(t *testing.T) {
	src, root, out, id := secretFixture(t)
	prof, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	res := mustExport(t, Config{
		SourceDir: src, OutDir: out, Profile: prof,
		Roots: map[string]string{"home": root}, WithSecrets: true,
		IdentityPath: filepath.Join(out, "identity.age"),
		Crypt:        CryptOptions{Recipients: []string{id.Recipient().String()}},
	})
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "inside the package tree") {
		t.Fatalf("no identity warning: %v", res.Warnings)
	}
}

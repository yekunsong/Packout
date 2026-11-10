package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packout/internal/manifest"
	"packout/internal/profile"
)

func TestExtractConfigDeSecretsAndKeepsStructure(t *testing.T) {
	root := t.TempDir()
	secretJSON := `{"theme":"dark","token":"sk-ant-abcdef123456","mcpServers":{"x":{"env":{"TOKEN":"plainvalue"}}}}`
	writeFile(t, filepath.Join(root, "settings.json"), secretJSON)
	writeFile(t, filepath.Join(root, "big.json"), `{"a":1,"b":{"c":2},"arr":[1,2]}`)
	writeFile(t, filepath.Join(root, "raw.txt"), "raw bytes")
	writeFile(t, filepath.Join(root, "skip.bin"), "digest only")
	writeFile(t, filepath.Join(root, "none.bin"), "never exported")

	src := filepath.Join(root, "scan")
	units := []struct{ entry, file string }{
		{"settings", "settings.json"},
		{"big", "big.json"},
		{"raw", "raw.txt"},
		{"skip", "skip.bin"},
		{"none", "none.bin"},
	}
	var us []manifest.Unit
	for _, u := range units {
		us = append(us, fileUnit(root, u.entry, filepath.Join(root, u.file)))
	}
	writeManifest(t, filepath.Join(src, ManifestDirName), root, us...)

	prof := &profile.Profile{
		Name: "p",
		Entries: []*profile.Entry{
			{ID: "settings", Kind: profile.KindFile, Root: "home", Path: "settings.json",
				Extractor: profile.ExtractorTemplate, Secret: profile.SecretRestore,
				Redact: &profile.Redact{
					KeyPattern:  []string{"(?i)token"},
					JSONPointer: []string{"/mcpServers/*/env/TOKEN"},
					Replacement: "<RED>",
				}},
			{ID: "big", Kind: profile.KindFile, Root: "home", Path: "big.json",
				Extractor: profile.ExtractorKeysOnly, Secret: profile.SecretNone},
			{ID: "raw", Kind: profile.KindFile, Root: "home", Path: "raw.txt",
				Extractor: profile.ExtractorRawRef, Secret: profile.SecretNone},
			{ID: "skip", Kind: profile.KindFile, Root: "home", Path: "skip.bin",
				Extractor: profile.ExtractorDigest, Secret: profile.SecretNone},
			{ID: "none", Kind: profile.KindFile, Root: "home", Path: "none.bin",
				Extractor: profile.ExtractorNone, Secret: profile.SecretNone},
		},
	}
	out := filepath.Join(t.TempDir(), "pkg")
	_, err := Export(Config{SourceDir: src, OutDir: out, Profile: prof, Roots: map[string]string{"home": root}})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(out, ConfigDirName, "home", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-ant-abcdef123456") || strings.Contains(string(data), "plainvalue") {
		t.Fatalf("secret survived template: %s", data)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("template is not JSON: %v: %s", err, data)
	}
	if got["theme"] != "dark" {
		t.Fatalf("structure lost: %v", got)
	}
	if got["token"] != "<RED>" {
		t.Fatalf("key pattern not applied: %v", got["token"])
	}
	mcp := got["mcpServers"].(map[string]any)["x"].(map[string]any)["env"].(map[string]any)
	if mcp["TOKEN"] != "<RED>" {
		t.Fatalf("json pointer not applied: %v", mcp)
	}

	keys, err := os.ReadFile(filepath.Join(out, ConfigDirName, "home", "big.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kv map[string]any
	if err := json.Unmarshal(keys, &kv); err != nil {
		t.Fatal(err)
	}
	if _, ok := kv["a"]; !ok {
		t.Fatalf("keys-only lost keys: %s", keys)
	}
	if kv["a"] != nil {
		t.Fatalf("keys-only kept a value: %s", keys)
	}
	if _, ok := kv["b"].(map[string]any)["c"]; !ok {
		t.Fatalf("keys-only lost nested key: %s", keys)
	}

	raw, err := os.ReadFile(filepath.Join(out, ConfigDirName, "home", "raw.txt"))
	if err != nil || string(raw) != "raw bytes" {
		t.Fatalf("raw-ref not copied: %q %v", raw, err)
	}
	if _, err := os.Lstat(filepath.Join(out, ConfigDirName, "home", "skip.bin")); !os.IsNotExist(err) {
		t.Fatal("digest entry exported")
	}
	if _, err := os.Lstat(filepath.Join(out, ConfigDirName, "home", "none.bin")); !os.IsNotExist(err) {
		t.Fatal("none entry exported")
	}

	mustVerify(t, out)
}

func TestExtractRejectsSourceOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "evil.txt"), "x")
	src := filepath.Join(root, "scan")
	u := fileUnit(root, "evil", filepath.Join(outside, "evil.txt"))
	writeManifest(t, filepath.Join(src, ManifestDirName), root, u)
	prof := &profile.Profile{Entries: []*profile.Entry{
		{ID: "evil", Kind: profile.KindFile, Root: "home", Path: "evil.txt",
			Extractor: profile.ExtractorRawRef, Secret: profile.SecretNone},
	}}
	out := filepath.Join(t.TempDir(), "pkg")
	res, err := Export(Config{SourceDir: src, OutDir: out, Profile: prof, Roots: map[string]string{"home": root}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("outside-root unit was not reported")
	}
	if _, err := os.Lstat(filepath.Join(out, ConfigDirName, "home", "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("outside-root unit exported")
	}
}

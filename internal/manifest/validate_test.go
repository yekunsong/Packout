package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptsCompleteManifest(t *testing.T) {
	dir := writeTestManifest(t, newTestHeader(2), []Unit{
		fixtureUnit("e1", "/home/a/1"),
		fixtureUnit("e2", "/home/a/2"),
		catchAllUnit("/home/a/loose.txt"),
	}, []Note{{ScanID: "01JQ8Z3K7M2V9T4R6W8X0Y2B4C", Code: "empty_glob"}})
	issues := ValidateAll(dir)
	for _, is := range issues {
		if is.Severity == SeverityError {
			t.Fatalf("unexpected error: %v", is)
		}
	}
	if err := Validate(dir); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	m, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Units) != 3 || m.Footer.Units != 3 || m.Footer.Stats.Residual != 1 {
		t.Fatalf("manifest totals: units=%d footer=%+v", len(m.Units), m.Footer)
	}
}

func TestValidateUnitCodes(t *testing.T) {
	cidPtr := func(s string) *string { return &s }
	cases := []struct {
		name   string
		code   string
		mutate func(u *Unit)
	}{
		{"bad-id", "E-MAN-006", func(u *Unit) { u.ID = "u_bad" }},
		{"signal-no-src", "E-MAN-012", func(u *Unit) { u.Signals[0].Src = "" }},
		{"docs-no-url", "E-MAN-013", func(u *Unit) {
			u.Signals[0].Src = "official_docs"
			u.Signals[0].URL = nil
		}},
		{"confidence-range", "E-MAN-014", func(u *Unit) { u.Confidence = 1.5 }},
		{"confidence-low-action", "E-MAN-015", func(u *Unit) {
			u.Confidence = 0.5
			u.ProposedAction = ActionMigrate
			u.RiskFlags = []string{"low_confidence"}
		}},
		{"restore-low-confidence", "E-MAN-016", func(u *Unit) {
			u.Secret = &Secret{Class: SecretRestore, Hits: []SecretHit{}, HitCount: 0}
			u.Confidence = 0.9
		}},
		{"plaintext-note", "E-MAN-017", func(u *Unit) {
			u.Signals[0].Note = "found token sk-ant-abcdefghijklmnop"
		}},
		{"hit-no-locator", "E-MAN-018", func(u *Unit) {
			u.Secret = &Secret{Class: SecretScan, Hits: []SecretHit{{Kind: "known_prefix", Class: SecretRestore}}, HitCount: 1}
		}},
		{"size-alloc", "E-MAN-019", func(u *Unit) {
			big := int64(10000)
			small := int64(100)
			u.SizeApparent, u.SizeAlloc = &big, &small
		}},
		{"scheme", "E-MAN-021", func(u *Unit) {
			u.Kind = KindNamedLocation
			u.Path = "ftp:thing"
			u.PathKey = "ftp:thing"
			u.Root = "os"
			u.SizeApparent, u.SizeAlloc, u.MTime, u.FileID, u.Fingerprint, u.CID = nil, nil, nil, nil, nil, nil
		}},
		{"schema-version", "E-MAN-023", func(u *Unit) { u.SchemaVersion = "1.0" }},
		{"action-layer", "E-MAN-024", func(u *Unit) {
			u.Layer = LayerL0
			u.ProposedAction = ActionReinstall
		}},
		{"duplicate-key", "E-MAN-025", func(u *Unit) { /* second identical unit below */ }},
		{"size-estimated", "E-MAN-027", func(u *Unit) { u.SizeEstimated = true }},
		{"cid", "E-MAN-028", func(u *Unit) { u.CID = cidPtr("c_0123456789ABCDEFGHJKMNPQRS") }},
		{"aggregate-count", "E-MAN-029", func(u *Unit) { u.RiskFlags = []string{"aggregated"} }},
		{"relative-path", "E-MAN-007", func(u *Unit) {
			u.Path = "relative/x"
			u.PathKey = "relative/x"
		}},
		{"trailing-sep", "E-MAN-008", func(u *Unit) {
			u.Path = "/home/a/x/"
			u.PathKey = "/home/a/x/"
		}},
		{"parent-component", "E-MAN-065", func(u *Unit) {
			u.Path = "/home/a/../x"
			u.PathKey = "/home/a/../x"
		}},
		{"path-key", "E-MAN-009", func(u *Unit) { u.PathKey = "wrong" }},
		{"secret-ref", "E-MAN-050", func(u *Unit) { u.SecretRef = "secrets.age#nope" }},
		{"owner", "E-MAN-051", func(u *Unit) { u.Owner = &Owner{Kind: "nobody", Value: "x"} }},
		{"aggregate-secret", "E-MAN-053", func(u *Unit) {
			n := int64(1)
			u.AggregateCount = &n
			u.RiskFlags = []string{"aggregated"}
			u.Secret = &Secret{Class: SecretScan, Hits: []SecretHit{{Kind: "regex", Class: SecretScan, Locator: "1:1"}}, HitCount: 1}
		}},
		{"aggregate-scope", "E-MAN-054", func(u *Unit) {
			n := int64(1)
			yes := true
			u.AggregateCount = &n
			u.ContainsSecret, u.MayContainSecret = &yes, &yes
			u.RiskFlags = []string{"aggregated"}
		}},
		{"catch-all-flags", "E-MAN-055", func(u *Unit) {
			*u = catchAllUnit("/home/a/loose.txt")
			u.RiskFlags = nil
		}},
		{"side-effect", "E-MAN-056", func(u *Unit) { u.SideEffects = []string{"bogus"} }},
		{"machine-derived", "E-MAN-058", func(u *Unit) {
			u.PathSemantics = SemanticsMachineDerived
			u.DerivedFrom = nil
		}},
		{"catch-all-residual-count", "E-MAN-059", func(u *Unit) { /* footer rewritten below */ }},
		{"root", "E-MAN-060", func(u *Unit) { u.Root = "elsewhere" }},
		{"part-alloc", "E-MAN-061", func(u *Unit) { u.PartID = "history" }},
		{"deletion-cost", "E-MAN-062", func(u *Unit) {
			u.Layer = LayerL0
			u.ProposedAction = ActionDelete
			u.NeededBy = []string{"rewind"}
		}},
		{"catch-all-confidence", "E-MAN-064", func(u *Unit) {
			*u = catchAllUnit("/home/a/loose.txt")
			u.Confidence = 0.6
		}},
		{"link-target", "E-MAN-066", func(u *Unit) { u.LinkTarget = `\\?\x` }},
		{"null-scope-value", "E-MAN-067", func(u *Unit) {
			v := "abc"
			u.Fingerprint = &Fingerprint{Algo: "sha256", Scope: "", Value: &v}
			u.CID = nil
		}},
		{"catch-all-signal", "E-MAN-068", func(u *Unit) {
			*u = catchAllUnit("/home/a/loose.txt")
			u.Signals = []Signal{{Src: "profile_rule", Note: "not injected"}}
		}},
		{"origin-literal", "E-MAN-069", func(u *Unit) {
			o, ok := "D:/Study/Chatrix", "d:/study/chatrix"
			u.Origin, u.OriginPathKey = &o, &ok
		}},
		{"open-as", "E-MAN-070", func(u *Unit) {
			u.SideEffects = []string{SideEffectShmCreate}
			u.OpenAs = OpenAsNone
		}},
		{"external-inside-root", "E-MAN-065", func(u *Unit) { u.Root = "external" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := fixtureUnit("e1", "/home/a/x")
			units := []Unit{u}
			tc.mutate(&units[0])
			if tc.name == "duplicate-key" {
				u2 := fixtureUnit("e1", "/home/a/x")
				units = append(units, u2)
			}
			dir := writeTestManifest(t, newTestHeader(0), units, nil)
			if tc.name == "catch-all-residual-count" {
				rewriteShardLine(t, dir, "manifest.0001.jsonl", shardLineCount(t, dir, "manifest.0001.jsonl"), func(s string) string {
					var f map[string]any
					_ = json.Unmarshal([]byte(s), &f)
					stats := f["stats"].(map[string]any)
					stats["residual"] = float64(9)
					b, _ := json.Marshal(f)
					return string(b)
				})
			}
			issues := ValidateAll(dir)
			if !hasIssueCode(issues, tc.code) {
				t.Fatalf("missing %s; issues:\n%s", tc.code, dumpIssues(issues))
			}
		})
	}
}

func dumpIssues(issues []Issue) string {
	var b strings.Builder
	for _, is := range issues {
		b.WriteString("  ")
		b.WriteString(is.String())
		b.WriteString("\n")
	}
	return b.String()
}

func TestValidateFileLevelCodes(t *testing.T) {
	t.Run("missing-index", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		if err := os.Remove(filepath.Join(dir, "manifest.index.json")); err != nil {
			t.Fatal(err)
		}
		if !hasIssueCode(ValidateAll(dir), "E-MAN-030") {
			t.Fatal("missing index must be E-MAN-030")
		}
	})

	t.Run("missing-footer", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		dropLastShardLine(t, dir, "manifest.0001.jsonl")
		if !hasIssueCode(ValidateAll(dir), "E-MAN-030") {
			t.Fatal("missing footer must be E-MAN-030")
		}
	})

	t.Run("footer-units", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", shardLineCount(t, dir, "manifest.0001.jsonl"), func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["units"] = float64(99) })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-041") {
			t.Fatal("footer units mismatch must be E-MAN-041")
		}
	})

	t.Run("index-units", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		mutateIndexFile(t, dir, func(m map[string]any) { m["units"] = float64(99) })
		if !hasIssueCode(ValidateAll(dir), "E-MAN-030") {
			t.Fatal("index units mismatch must be E-MAN-030")
		}
	})

	t.Run("bad-kind", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["kind"] = "mystery" })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-010") {
			t.Fatal("unknown kind must be E-MAN-010")
		}
	})

	t.Run("no-signals", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["signals"] = []any{} })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-011") {
			t.Fatal("empty signals must be E-MAN-011")
		}
	})

	t.Run("needed-by-order", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(s string) string {
			return mutateJSON(s, func(m map[string]any) {
				m["needed_by"] = []any{"mcp", "rewind"}
			})
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-057") {
			t.Fatal("out-of-order needed_by must be E-MAN-057")
		}
	})

	t.Run("unknown-type", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["type"] = "mystery" })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-004") {
			t.Fatal("unknown type must be E-MAN-004")
		}
	})

	t.Run("missing-type", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { delete(m, "type") })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-004") {
			t.Fatal("missing type must be E-MAN-004")
		}
	})

	t.Run("invalid-json", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 2, func(string) string { return "{" })
		if !hasIssueCode(ValidateAll(dir), "E-MAN-002") {
			t.Fatal("invalid JSON must be E-MAN-002")
		}
	})

	t.Run("header-not-first", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 1, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["type"] = "note" })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-001") {
			t.Fatal("header not first must be E-MAN-001")
		}
	})

	t.Run("missing-fold-version", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 1, func(s string) string {
			return mutateJSON(s, func(m map[string]any) {
				delete(m["host"].(map[string]any), "path_fold_version")
			})
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-026") {
			t.Fatal("missing path_fold_version must be E-MAN-026")
		}
	})

	t.Run("major", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 1, func(s string) string {
			return mutateJSON(s, func(m map[string]any) { m["manifest_version"] = "3.0" })
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-040") {
			t.Fatal("newer MAJOR must be E-MAN-040")
		}
	})

	t.Run("salt-mode", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 1, func(s string) string {
			return mutateJSON(s, func(m map[string]any) {
				m["inputs"].(map[string]any)["secret_salt_mode"] = "bogus"
			})
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-043") {
			t.Fatal("bad salt mode must be E-MAN-043")
		}
	})

	t.Run("segment", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		rewriteShardLine(t, dir, "manifest.0001.jsonl", 1, func(s string) string {
			return mutateJSON(s, func(m map[string]any) {
				m["scan_segment"].(map[string]any)["first_shard"] = float64(2)
			})
		})
		if !hasIssueCode(ValidateAll(dir), "E-MAN-042") {
			t.Fatal("segment mismatch must be E-MAN-042")
		}
	})

	t.Run("lock", func(t *testing.T) {
		dir := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
		if err := os.WriteFile(filepath.Join(dir, ".lock"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !hasIssueCode(ValidateAll(dir), "E-MAN-031") {
			t.Fatal("unreleased lock must be E-MAN-031")
		}
	})
}

func TestValidateWarnings(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/x")
	u.RiskFlags = []string{"future_flag"}
	u.NeededBy = []string{"future_feature"}
	dir := writeTestManifest(t, newTestHeader(0), []Unit{u}, nil)
	issues := ValidateAll(dir)
	if !hasIssueCode(issues, "W-MAN-102") {
		t.Fatalf("unknown enums must warn: %s", dumpIssues(issues))
	}
	if err := Validate(dir); err != nil {
		t.Fatalf("warnings alone must not fail Validate: %v", err)
	}

	// Unknown record fields warn W-MAN-101.
	dir2 := writeTestManifest(t, newTestHeader(0), []Unit{fixtureUnit("e1", "/home/a/x")}, nil)
	rewriteShardLine(t, dir2, "manifest.0001.jsonl", 2, func(s string) string {
		return mutateJSON(s, func(m map[string]any) { m["future_field"] = "v" })
	})
	if !hasIssueCode(ValidateAll(dir2), "W-MAN-101") {
		t.Fatal("unknown field must warn W-MAN-101")
	}
}

func mutateJSON(line string, fn func(map[string]any)) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		panic(err)
	}
	fn(m)
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func mutateIndexFile(t *testing.T, dir string, fn func(map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "manifest.index.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyManifestIsValid(t *testing.T) {
	// A scan that found nothing still has a header, footer and index; the
	// zero-unit shard must be accounted for rather than reported as missing.
	dir := writeTestManifest(t, newTestHeader(0), nil, nil)
	if err := Validate(dir); err != nil {
		t.Fatalf("empty manifest rejected: %v", err)
	}
}

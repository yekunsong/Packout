package secret

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// plain disables the entropy fallback so a positive fixture proves its own
// rule rather than the generic fallback.
func plain(name, content string) []Hit {
	return DetectWith(Options{Entropy: false, MaxHits: DefaultMaxHits}, name, []byte(content))
}

func hasRule(hits []Hit, rule string) bool {
	for _, h := range hits {
		if h.Rule == rule {
			return true
		}
	}
	return false
}

func hitFor(hits []Hit, rule string) (Hit, bool) {
	for _, h := range hits {
		if h.Rule == rule {
			return h, true
		}
	}
	return Hit{}, false
}

func TestRulePositives(t *testing.T) {
	cases := []struct {
		rule    string
		name    string
		content string
		class   Class
	}{
		{RuleAnthropicKey, "notes.txt", "key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123 here", Restore},
		{RuleOpenAIKey, "notes.txt", "key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWx here", Restore},
		{RuleGitHubPAT, "notes.txt", "x github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuv x", Restore},
		{RuleGitHubToken, "notes.txt", "x ghp_abcdefghijklmnopqrstuvwxyz0123456789 x", Restore},
		{RuleAWSAccessKey, "notes.txt", "x AKIAIOSFODNN7EXAMPLE x", Restore},
		{RuleSlackToken, "notes.txt", "x " + "xoxb-123456789012-" + "abcdefghijklmn" + " x", Restore},
		{RuleGoogleAPIKey, "notes.txt", "x AIza" + strings.Repeat("A1b2C3d4E5", 4) + " x", Restore},
		{RuleJWT, "notes.txt", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", Relogin},
		{RuleAuthBearer, "notes.txt", "Authorization: Bearer abcdefghijklmnop123456", Restore},
		{RuleEnvRef, "notes.txt", "TOKEN=${MY_TOKEN}", Reference},
		{RuleOnePassword, "notes.txt", "TOKEN=op://vault/item/field", Reference},
		{RuleMasked, "notes.txt", "TOKEN=********", None},
		{RuleMCPEnv, ".mcp.json", `{"mcpServers":{"x":{"env":{"FOO_BAR":"abcdefghijkl"}}}}`, Restore},
		{RuleJSONKey, "settings.json", `{"password": "hunter2hunter2"}`, Restore},
		{RuleTOMLKey, "config.toml", "api_key = \"abcdefghijklmno\"\n", Restore},
		{RuleDotenvKey, ".env", "API_TOKEN=supersecretvalue123\n", Restore},
		{RulePrivateKey, "id.key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", Restore},
		{RuleHighEntropy, "notes.txt", "q7Zr2Kp9Wm4Xc8Vt1Bn6Ls3Hd5Gf0JaQ2", Restore},
	}

	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			hits := Detect(tc.name, []byte(tc.content), DefaultMaxHits)
			h, ok := hitFor(hits, tc.rule)
			if !ok {
				t.Fatalf("rule %s did not fire: %+v", tc.rule, hits)
			}
			if h.Class != tc.class {
				t.Fatalf("rule %s class = %v, want %v", tc.rule, h.Class, tc.class)
			}
			if h.Offset < 0 || h.Length <= 0 || h.Offset+h.Length > len(tc.content) {
				t.Fatalf("rule %s produced invalid range %d+%d", tc.rule, h.Offset, h.Length)
			}
			if h.ValueFP == "" {
				t.Fatalf("rule %s produced empty fingerprint", tc.rule)
			}
			// The hit must cover the secret, not the surrounding syntax.
			got := tc.content[h.Offset : h.Offset+h.Length]
			if tc.rule != RulePrivateKey && strings.ContainsAny(got, "\n") {
				t.Fatalf("rule %s hit range %q includes syntax", tc.rule, got)
			}
			if strings.HasPrefix(got, `"`) {
				t.Fatalf("rule %s hit range %q includes syntax", tc.rule, got)
			}
		})
	}
}

func TestReloginKeyedSuggestions(t *testing.T) {
	hits := plain("tokens.json", `{"refresh_token": "abcdefghijklmno", "api_key": "abcdefghijklmno"}`)
	var sawRelogin, sawRestore bool
	for _, h := range hits {
		if h.Rule != RuleJSONKey {
			continue
		}
		switch h.Class {
		case Relogin:
			sawRelogin = true
		case Restore:
			sawRestore = true
		}
	}
	if !sawRelogin || !sawRestore {
		t.Fatalf("expected refresh_token relogin and api_key restore: %+v", hits)
	}
}

func TestNegatives(t *testing.T) {
	cases := []struct {
		label   string
		name    string
		content string
	}{
		{"uuid", "notes.txt", "id 123e4567-e89b-12d3-a456-426614174000 done"},
		{"version", "package.json", `{"version": "1.2.3"}`},
		{"short keyed json", "settings.json", `{"key": "value"}`},
		{"short keyed dotenv", ".env", "KEY=value\n"},
		{"package author field", "package.json", `{"author": "F. Scott Fitzgerald <scott@example.com>"}`},
		{"hockey key name", "settings.json", `{"hockey": "abcdefghijklmnop"}`},
		{"code comparison", "main.go", "if token == \"supersecretvalue123\" { return }"},
		{"base64 image", "notes.txt", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="},
		{"env reference", ".env", "PASSWORD=${DB_PASSWORD}\n"},
		{"op reference", ".env", "PASSWORD=op://vault/item/password\n"},
		{"masked value", "config.toml", `password = "********"` + "\n"},
		{"hex digest", "notes.txt", strings.Repeat("e3b0c44298fc1c149afbf4c8", 2) + strings.Repeat("a", 8)},
		{"lockfile integrity", "package-lock.json", `{"integrity": "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg=="}`},
		{"sentence with publishable prefix", "notes.txt", "the sk- prefix is public"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			hits := Detect(tc.name, []byte(tc.content), DefaultMaxHits)
			for _, h := range hits {
				if h.Class == Restore || h.Class == Relogin {
					t.Fatalf("false positive %s: %+v on %q", tc.label, h, tc.content)
				}
			}
		})
	}
}

func TestReferencesAndMaskedAreNotRedacted(t *testing.T) {
	content := "PASSWORD=${DB_PASSWORD}\nAPI_TOKEN=op://vault/item/token\nSECRET_KEY=********\n"
	hits := Detect(".env", []byte(content), DefaultMaxHits)
	for _, h := range hits {
		if h.Class == Restore || h.Class == Relogin {
			t.Fatalf("unexpected actionable hit: %+v", h)
		}
	}
	out := Redact([]byte(content), hits, nil)
	if string(out) != content {
		t.Fatalf("redaction changed a reference/masked file:\n got %q\nwant %q", out, content)
	}
}

func TestOffsetOrderAndDeterminism(t *testing.T) {
	var b strings.Builder
	b.WriteString("API_TOKEN=supersecretvalue123\n")
	b.WriteString("x AKIAIOSFODNN7EXAMPLE x\n")
	b.WriteString(`{"api_key": "abcdefghijklmno"}` + "\n")
	b.WriteString("Authorization: Bearer abcdefghijklmnop123456\n")
	b.WriteString("q7Zr2Kp9Wm4Xc8Vt1Bn6Ls3Hd5Gf0JaQ2\n")
	content := b.String()

	first := Detect("config.txt", []byte(content), DefaultMaxHits)
	second := Detect("config.txt", []byte(content), DefaultMaxHits)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Detect is not deterministic:\n%+v\n%+v", first, second)
	}
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i].Offset < first[j].Offset }) {
		t.Fatalf("hits are not in ascending offset order: %+v", first)
	}
	if len(first) < 4 {
		t.Fatalf("expected several hits, got %+v", first)
	}
}

func TestHitLimitAndTruncation(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&b, "API_TOKEN=supersecretvalue%03d\n", i)
	}
	res := DetectWithResult(Options{Entropy: true, MaxHits: 2}, ".env", []byte(b.String()))
	if len(res.Hits) != 2 {
		t.Fatalf("want 2 hits, got %d: %+v", len(res.Hits), res.Hits)
	}
	if !res.Truncated {
		t.Fatalf("result must be truncated: %+v", res)
	}
	if res.Dropped != 2 {
		t.Fatalf("Dropped = %d, want 2", res.Dropped)
	}
	below := DetectWithResult(Options{Entropy: true, MaxHits: 10}, ".env", []byte(b.String()))
	if below.Truncated || below.Dropped != 0 {
		t.Fatalf("unexpected truncation below the limit: %+v", below)
	}
}

func TestDefaultMaxHits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < DefaultMaxHits+10; i++ {
		fmt.Fprintf(&b, "API_TOKEN=supersecretvalue%03d\n", i)
	}
	res := DetectWithResult(Options{Entropy: true}, ".env", []byte(b.String()))
	if len(res.Hits) != DefaultMaxHits || !res.Truncated {
		t.Fatalf("default limit must cap hits: len=%d truncated=%v", len(res.Hits), res.Truncated)
	}
	if res.Dropped != 10 {
		t.Fatalf("Dropped = %d, want 10", res.Dropped)
	}
}

func TestLowConfidenceOnlyForEntropy(t *testing.T) {
	content := "x AKIAIOSFODNN7EXAMPLE x\nq7Zr2Kp9Wm4Xc8Vt1Bn6Ls3Hd5Gf0JaQ2\n"
	hits := Detect("notes.txt", []byte(content), DefaultMaxHits)
	aws, ok := hitFor(hits, RuleAWSAccessKey)
	if !ok {
		t.Fatalf("aws hit missing: %+v", hits)
	}
	if aws.LowConfidence {
		t.Fatalf("known-prefix hit marked low confidence: %+v", aws)
	}
	ent, ok := hitFor(hits, RuleHighEntropy)
	if !ok {
		t.Fatalf("entropy hit missing: %+v", hits)
	}
	if !ent.LowConfidence {
		t.Fatalf("entropy hit not marked low confidence: %+v", ent)
	}
}

func TestLongValueJudgedOnPrefix(t *testing.T) {
	value := strings.Repeat("a", MaxValueLen+500)
	content := "API_TOKEN=" + value + "\n"
	hits := Detect(".env", []byte(content), DefaultMaxHits)
	h, ok := hitFor(hits, RuleDotenvKey)
	if !ok {
		t.Fatalf("long value not detected: %+v", hits)
	}
	if h.Length != len(value) {
		t.Fatalf("hit covers %d bytes, want the whole %d-byte value", h.Length, len(value))
	}
	out := Redact([]byte(content), hits, nil)
	if bytes.Contains(out, []byte(value)) {
		t.Fatalf("long value survived redaction")
	}
}

func TestEmptyAndBinaryishInput(t *testing.T) {
	if hits := Detect("x", nil, DefaultMaxHits); hits != nil {
		t.Fatalf("empty input must yield nil, got %+v", hits)
	}
	bin := make([]byte, 64*1024)
	for i := range bin {
		bin[i] = byte(i)
	}
	_ = Detect("blob.bin", bin, DefaultMaxHits) // must not panic
}

// TestPerformance1MB enforces the acceptance budget on a 1 MB text file.
func TestPerformance1MB(t *testing.T) {
	block := []byte(
		"# sample configuration\n" +
			"API_TOKEN=supersecretvalue123\n" +
			"DB_PASSWORD=${DB_PASSWORD}\n" +
			`{"api_key": "abcdefghijklmno", "model": "claude-sonnet-4-5"}` + "\n" +
			"version = \"1.2.3\"\n" +
			"x AKIAIOSFODNN7EXAMPLE x\n" +
			"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==\n")
	var b bytes.Buffer
	for b.Len() < 1<<20 {
		b.Write(block)
	}
	data := b.Bytes()
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}

	Detect("large.txt", []byte("API_TOKEN=warmupvalue12345"), DefaultMaxHits) // compile regexes

	best := time.Duration(1<<62 - 1)
	for i := 0; i < 3; i++ {
		start := time.Now()
		_ = Detect("large.txt", data, DefaultMaxHits)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	if best >= 50*time.Millisecond {
		t.Fatalf("Detect on 1 MB took %v, budget 50ms", best)
	}
	t.Logf("Detect 1 MB: %v", best)
}

func BenchmarkDetect1MB(b *testing.B) {
	block := []byte("API_TOKEN=supersecretvalue123\n{\"api_key\": \"abcdefghijklmno\"}\n" +
		"# a normal comment line that is not secret\nversion = \"1.2.3\"\n")
	var buf bytes.Buffer
	for buf.Len() < 1<<20 {
		buf.Write(block)
	}
	data := buf.Bytes()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Detect("large.txt", data, DefaultMaxHits)
	}
}

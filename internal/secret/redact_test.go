package secret

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestValueFP(t *testing.T) {
	// sha256("abc") starts with ba7816bf8f01cfea.
	if got := ValueFP([]byte("abc")); got != "ba7816bf8f01cfea" {
		t.Fatalf("ValueFP(abc) = %s", got)
	}
	if ValueFP([]byte("abc")) != ValueFP([]byte("abc")) {
		t.Fatal("ValueFP is not deterministic")
	}
	if ValueFP([]byte("abc")) == ValueFP([]byte("abd")) {
		t.Fatal("ValueFP collision on adjacent values")
	}
	if len(ValueFP(nil)) != 16 {
		t.Fatal("ValueFP must be 16 hex characters")
	}
}

func TestMask(t *testing.T) {
	cases := []struct{ in, want string }{
		{"short", "*****"},
		{"12345678", "********"},
		{"123456789", "1234…6789"},
		{"sk-ant-abcdefghijklmnop", "sk-a…mnop"},
	}
	for _, tc := range cases {
		if got := string(Mask([]byte(tc.in))); got != tc.want {
			t.Fatalf("Mask(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRedactRemovesPlaintext(t *testing.T) {
	const (
		envSecret   = "supersecretvalue12345"
		jsonSecret  = "abcdefghijklmnopqrstuvwxyz"
		bearerToken = "bearer-token-value-0123456789"
	)
	content := "" +
		"API_TOKEN=" + envSecret + "\n" +
		`{"client_secret": "` + jsonSecret + `"}` + "\n" +
		"Authorization: Bearer " + bearerToken + "\n" +
		"PASSWORD=${DB_PASSWORD}\n" +
		"SESSION_TOKEN=********\n"

	b := []byte(content)
	original := append([]byte(nil), b...)
	hits := Detect(".env", b, DefaultMaxHits)
	if len(hits) < 3 {
		t.Fatalf("expected at least 3 hits, got %+v", hits)
	}

	out := Redact(b, hits, nil)
	if !bytes.Equal(b, original) {
		t.Fatal("Redact modified its input")
	}
	for _, secret := range []string{envSecret, jsonSecret, bearerToken} {
		if bytes.Contains(out, []byte(secret)) {
			t.Fatalf("plaintext %q survived redaction:\n%s", secret, out)
		}
	}
	s := string(out)
	if !strings.Contains(s, "${DB_PASSWORD}") {
		t.Fatalf("reference was redacted:\n%s", s)
	}
	if !strings.Contains(s, "SESSION_TOKEN=********") {
		t.Fatalf("already-masked value was changed:\n%s", s)
	}
	if !strings.Contains(s, "…") {
		t.Fatalf("default mask not applied:\n%s", s)
	}
}

func TestRedactDeterministicAcrossOrder(t *testing.T) {
	content := "API_TOKEN=supersecretvalue123\nSECRET_KEY=anothersecretvalue456\n"
	hits := Detect(".env", []byte(content), DefaultMaxHits)
	reversed := make([]Hit, len(hits))
	for i := range hits {
		reversed[i] = hits[len(hits)-1-i]
	}
	a := Redact([]byte(content), hits, nil)
	b := Redact([]byte(content), reversed, nil)
	if !bytes.Equal(a, b) {
		t.Fatalf("Redact depends on hit order:\n%q\n%q", a, b)
	}
}

func TestRedactIgnoresInvalidAndOverlappingHits(t *testing.T) {
	content := "abcdefghijklmnopqrstuvwxyz"
	hits := []Hit{
		{Class: Restore, Offset: 0, Length: 4},                // first
		{Class: Restore, Offset: 2, Length: 4},                // overlaps first
		{Class: Reference, Offset: 10, Length: 4},             // skipped by class
		{Class: None, Offset: 12, Length: 4},                  // skipped by class
		{Class: Restore, Offset: 24, Length: 10},              // out of range
		{Class: Restore, Offset: -1, Length: 3},               // invalid
		{Class: Restore, Offset: 20, Length: 0},               // empty
		{Class: Restore, Offset: len(content) - 2, Length: 2}, // tail
	}
	out := string(Redact([]byte(content), hits, nil))
	// Overlapping hits are masked as one union: [0,4)+[2,6) -> [0,6).
	want := "******" + content[6:24] + "**"
	if out != want {
		t.Fatalf("Redact = %q, want %q", out, want)
	}
}

func TestRedactOuterKeyedCoversInnerToken(t *testing.T) {
	const inner = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
	const value = "Bearer " + inner
	content := "API_TOKEN=" + value + "\n"

	res := DetectWithResult(Options{Entropy: true}, ".env", []byte(content))
	var outer, nested *Hit
	for i := range res.Hits {
		h := &res.Hits[i]
		if h.Rule == RuleDotenvKey {
			outer = h
		}
		if h.Rule == RuleAnthropicKey {
			nested = h
		}
	}
	if outer == nil || nested == nil {
		t.Fatalf("expected both outer keyed and inner prefix hits: %+v", res.Hits)
	}
	if outer.Offset > nested.Offset || outer.End() < nested.End() {
		t.Fatalf("outer hit %+v does not contain inner %+v", *outer, *nested)
	}

	out := string(Redact([]byte(content), res.Hits, nil))
	want := "API_TOKEN=" + string(Mask([]byte(value))) + "\n"
	if out != want {
		t.Fatalf("outer value not masked as a whole:\n got %q\nwant %q", out, want)
	}
	for _, fragment := range []string{inner, "Bearer " + inner, "Bearer", "sk-ant"} {
		if strings.Contains(out, fragment) {
			t.Fatalf("plaintext fragment %q survived: %q", fragment, out)
		}
	}
}

func TestRedactCustomRedactorAndNil(t *testing.T) {
	content := "TOKEN=supersecretvalue123"
	hits := Detect(".env", []byte(content), DefaultMaxHits)
	out := Redact([]byte(content), hits, func(v []byte) []byte { return []byte("<redacted>") })
	if string(out) != "TOKEN=<redacted>" {
		t.Fatalf("custom redactor not used: %q", out)
	}
	// A nil redactor means Mask.
	if !bytes.Equal(Redact([]byte(content), hits, nil), Redact([]byte(content), hits, Mask)) {
		t.Fatal("nil redactor differs from Mask")
	}
}

func TestRedactTruncatedHits(t *testing.T) {
	content := "TOKEN=supersecretvalue123\nTOKEN=anothersecretvalue456\n"
	res := DetectWithResult(Options{Entropy: true, MaxHits: 1}, ".env", []byte(content))
	if !res.Truncated {
		t.Fatalf("expected truncation: %+v", res)
	}
	out := Redact([]byte(content), res.Hits, nil)
	if bytes.Contains(out, []byte("supersecretvalue123")) {
		t.Fatalf("kept value survived: %q", out)
	}
}

func TestRedactEmptyHits(t *testing.T) {
	b := []byte("nothing to hide")
	out := Redact(b, nil, nil)
	if !bytes.Equal(out, b) {
		t.Fatal("Redact with no hits must return the bytes")
	}
}

func TestDetectAndRedactNoPlaintextAcrossCorpus(t *testing.T) {
	fixtures := []struct {
		name, content string
	}{
		{".env", "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789\n"},
		{"id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----\n"},
		{"settings.json", `{"env":{"ANTHROPIC_AUTH_TOKEN":"abcdefghijklmnop123456"}}`},
		{"config.toml", "[keys]\nclient_secret = \"abcdefghijklmnopqrst\"\n"},
		{"notes.txt", "git ghp_abcdefghijklmnopqrstuvwxyz0123456789 end"},
	}
	for _, f := range fixtures {
		hits := Detect(f.name, []byte(f.content), DefaultMaxHits)
		if len(hits) == 0 {
			t.Fatalf("%s: no hits found", f.name)
		}
		out := Redact([]byte(f.content), hits, nil)
		for _, h := range hits {
			if h.Class == None || h.Class == Reference {
				continue
			}
			val := f.content[h.Offset : h.Offset+h.Length]
			if len(val) > 0 && bytes.Contains(out, []byte(val)) {
				t.Fatalf("%s: value %q still present after redaction: %s", f.name, val, out)
			}
		}
	}
}

func TestClassString(t *testing.T) {
	want := map[Class]string{None: "none", Reference: "reference", Restore: "restore", Relogin: "relogin", Class(99): "unknown"}
	for c, s := range want {
		if c.String() != s {
			t.Fatalf("Class(%d).String() = %q, want %q", c, c.String(), s)
		}
	}
}

func TestHitEnd(t *testing.T) {
	h := Hit{Offset: 3, Length: 5}
	if h.End() != 8 {
		t.Fatalf("End = %d", h.End())
	}
	var zero DetectResult
	if zero.Truncated || zero.Dropped != 0 || len(zero.Hits) != 0 {
		t.Fatalf("zero DetectResult is not empty: %+v", zero)
	}
}

func TestValueFPWithSalt(t *testing.T) {
	salted := ValueFPWithSalt([]byte("abc"), []byte("salt"))
	sum := sha256.Sum256([]byte("abcsalt"))
	want := hex.EncodeToString(sum[:8])
	if salted != want {
		t.Fatalf("ValueFPWithSalt = %q, want %q", salted, want)
	}
	if ValueFP([]byte("abc")) != ValueFPWithSalt([]byte("abc"), nil) {
		t.Fatal("ValueFP must equal ValueFPWithSalt with an empty salt")
	}
	if ValueFP([]byte("abc")) == salted {
		t.Fatal("salt did not change the fingerprint")
	}
	if len(salted) != 16 {
		t.Fatalf("fingerprint length = %d, want 16 hex characters", len(salted))
	}
}

func TestDetectDoesNotAliasInput(t *testing.T) {
	b := []byte("TOKEN=supersecretvalue123")
	hits := Detect(".env", b, DefaultMaxHits)
	if !reflect.DeepEqual(b, []byte("TOKEN=supersecretvalue123")) {
		t.Fatal("Detect modified its input")
	}
	for _, h := range hits {
		if h.Offset+h.Length > len(b) {
			t.Fatalf("hit out of range: %+v", h)
		}
	}
}

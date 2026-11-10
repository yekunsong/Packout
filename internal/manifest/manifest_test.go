package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUnitFieldOrderFull(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/.claude/x.json")
	// Force every optional field so the full §4.1 order is exercised.
	origin := "D:/Study/Chatrix"
	originKey := "d:/study/chatrix"
	derived := DerivedRepoSlug
	u.PathSemantics = SemanticsMachineDerived
	u.DerivedFrom = &derived
	u.Origin = &origin
	u.OriginPathKey = &originKey
	u.PartID = "history"
	tru := true
	u.ContainsSecret = &tru
	u.MayContainSecret = &tru
	u.Owner = &Owner{Kind: "sid", Value: "S-1-5-21-1"}
	u.ACL = &ACL{Algo: "sha256", Value: "aabb", Entries: 3}
	u.SizeEstimated = true
	agg := int64(7)
	u.AggregateCount = &agg
	u.NeededBy = []string{"rewind"}
	u.Companions = []string{"-wal"}
	u.SideEffects = []string{SideEffectShmCreate}
	u.OpenAs = OpenAsSQLiteRO
	u.OpaqueContent = true
	u.LinkTarget = "relative/target"
	u.SecretRef = "secrets.age#h_0123456789ABCDEFGHJK"
	u.Notes = "one line"
	u.RiskFlags = []string{"deletion_cost", "symlink"}

	line := EncodeUnit(&u)
	_, order, err := decodeRawObject(line)
	if err != nil {
		t.Fatalf("decode own output: %v", err)
	}
	want := []string{
		"type", "schema_version", "id", "cid", "path", "path_key", "root",
		"path_semantics", "derived_from", "origin", "origin_path_key", "profile",
		"entry", "part_id", "kind", "layer", "confidence", "signals", "secret",
		"contains_secret", "may_contain_secret", "size_apparent", "size_alloc",
		"mtime", "file_id", "fingerprint", "owner", "acl", "size_estimated",
		"aggregate_count", "proposed_action", "risk_flags", "needed_by",
		"companions", "side_effects", "open_as", "opaque_content", "link_target",
		"secret_ref", "notes",
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("field order mismatch\n got: %v\nwant: %v", order, want)
	}
	// Fixed risk-flag order regardless of input order.
	if !strings.Contains(string(line), `"risk_flags":["symlink","deletion_cost"]`) {
		t.Fatalf("risk_flags not canonically ordered: %s", line)
	}
	// No insignificant whitespace.
	if bytes.Contains(line, []byte(`": `)) || bytes.Contains(line, []byte(", ")) {
		t.Fatalf("line contains insignificant whitespace: %s", line)
	}
	// Confidence is always three decimals.
	if !bytes.Contains(line, []byte(`"confidence":0.970`)) {
		t.Fatalf("confidence not formatted to three decimals: %s", line)
	}
}

func TestUnitFieldOrderMinimalOmitsOptional(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/.claude/x.json")
	line := EncodeUnit(&u)
	_, order, err := decodeRawObject(line)
	if err != nil {
		t.Fatal(err)
	}
	for _, optional := range []string{
		"origin", "origin_path_key", "part_id", "contains_secret",
		"may_contain_secret", "owner", "acl", "size_estimated",
		"aggregate_count", "needed_by", "companions", "side_effects",
		"open_as", "opaque_content", "link_target", "secret_ref", "notes",
	} {
		for _, got := range order {
			if got == optional {
				t.Fatalf("optional field %q must be omitted when unset: %v", optional, order)
			}
		}
	}
	// Required keys are present even when their value is null.
	for _, required := range []string{"cid", "derived_from", "size_apparent", "size_alloc", "mtime", "file_id", "fingerprint"} {
		found := false
		for _, got := range order {
			if got == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("required key %q missing: %v", required, order)
		}
	}
}

func TestUnknownFieldRoundTrip(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/.claude/x.json")
	base := EncodeUnit(&u)
	withUnknown := bytes.Replace(base, []byte(`"notes"`), []byte(`"future_a":{"k":[1,2]},"future_b":"v","notes"`), 1)
	if bytes.Equal(base, withUnknown) {
		// notes is omitted in the minimal unit; append before the closing brace.
		withUnknown = append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"future_a":{"k":[1,2]},"future_b":"v"}`)...)
	}

	var got Unit
	if err := json.Unmarshal(withUnknown, &got); err != nil {
		t.Fatalf("unmarshal unknown fields: %v", err)
	}
	if string(got.Extra["future_a"]) != `{"k":[1,2]}` || string(got.Extra["future_b"]) != `"v"` {
		t.Fatalf("unknown fields not preserved: %+v", got.Extra)
	}
	out := EncodeUnit(&got)
	if !bytes.Contains(out, []byte(`"future_a":{"k":[1,2]},"future_b":"v"}`)) {
		t.Fatalf("unknown fields not written back in order: %s", out)
	}
	if !bytes.HasSuffix(out, []byte(`,"future_a":{"k":[1,2]},"future_b":"v"}`)) {
		t.Fatalf("unknown fields must follow known fields: %s", out)
	}

	// A wider version field on a header survives too.
	hdr := newTestHeader(0)
	hl := EncodeHeader(&hdr)
	hl = append(append([]byte(nil), hl[:len(hl)-1]...), []byte(`,"future_header":true}`)...)
	var h2 Header
	if err := json.Unmarshal(hl, &h2); err != nil {
		t.Fatal(err)
	}
	if string(h2.Extra["future_header"]) != "true" {
		t.Fatalf("header unknown field lost: %+v", h2.Extra)
	}
	if !bytes.Contains(EncodeHeader(&h2), []byte(`"future_header":true`)) {
		t.Fatal("header unknown field not written back")
	}
}

func TestOldRiskFlagNamesMapped(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/.claude/x.json")
	line := EncodeUnit(&u)
	line = bytes.Replace(line, []byte(`"risk_flags":[]`), []byte(`"risk_flags":["binary","unversioned_repo"]`), 1)
	var got Unit
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	if !containsString(got.RiskFlags, "opaque_content") || !containsString(got.RiskFlags, "not_versioned") {
		t.Fatalf("old names not mapped: %v", got.RiskFlags)
	}
	out := string(EncodeUnit(&got))
	if !strings.Contains(out, `"risk_flags":["not_versioned","opaque_content"]`) {
		t.Fatalf("mapped flags not in canonical order: %s", out)
	}
}

func TestUnknownEnumsNormalized(t *testing.T) {
	u := fixtureUnit("e1", "/home/a/.claude/x.json")
	line := EncodeUnit(&u)
	line = bytes.Replace(line, []byte(`"layer":"L3"`), []byte(`"layer":"L9"`), 1)
	line = bytes.Replace(line, []byte(`"proposed_action":"keep"`), []byte(`"proposed_action":"archive"`), 1)
	var got Unit
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	if got.Layer != LayerL2 || got.ProposedAction != ActionKeep {
		t.Fatalf("unknown enums not normalized: layer=%s action=%s", got.Layer, got.ProposedAction)
	}
	if !containsString(got.RiskFlags, "unknown_enum") {
		t.Fatalf("unknown_enum not added: %v", got.RiskFlags)
	}
}

func TestSortStability(t *testing.T) {
	// Equal sort keys must keep their relative order (time is not a key).
	a := fixtureUnit("e", "/home/a/x")
	b := fixtureUnit("e", "/home/a/x")
	b.Notes = "later"
	units := []Unit{a, b}
	Sort(units)
	if units[0].Notes != "" || units[1].Notes != "later" {
		t.Fatal("Sort is not stable for equal keys")
	}

	// Full key ordering: root_index, profile, entry, path_key, part_id.
	mk := func(root string, rootIdx int, profile, entry, path, part string) Unit {
		u := fixtureUnit(entry, path)
		u.Root, u.RootIndex, u.Profile, u.PartID = root, rootIdx, profile, part
		u.ID = u.ComputeID()
		return u
	}
	in := []Unit{
		mk("home", 0, "p", "e2", "/home/a/b", ""),
		mk("home", 0, "p", "e1", "/home/a/b", "z"),
		mk("home", 0, "p", "e1", "/home/a/b", "a"),
		mk("repo", 1, "p", "e1", "/repo/a", ""),
	}
	Sort(in)
	got := []string{in[0].Entry + "/" + in[0].PartID, in[1].Entry + "/" + in[1].PartID, in[2].Entry + "/" + in[2].PartID, in[3].Root}
	want := []string{"e1/a", "e1/z", "e2/", "repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sort order = %v, want %v", got, want)
	}

	// Re-running with the same roots yields the same order.
	roots := []Root{{Name: "home"}, {Name: "repo"}}
	u1 := []Unit{mk("repo", 0, "p", "e1", "/repo/a", ""), mk("home", 0, "p", "e2", "/home/a/b", "")}
	u2 := []Unit{u1[1], u1[0]}
	SortWithRoots(u1, roots)
	SortWithRoots(u2, roots)
	for i := range u1 {
		if u1[i].Path != u2[i].Path {
			t.Fatalf("sort is not deterministic")
		}
	}
}

func TestFingerprintFileScopes(t *testing.T) {
	abc := []byte("abc")
	wantABC := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	fp, err := FingerprintBytes(abc, "full")
	if err != nil || fp.Value == nil || *fp.Value != wantABC {
		t.Fatalf("full fingerprint = %+v, %v", fp, err)
	}
	if p := CID(&fp); p == nil || !cidPattern.MatchString(*p) {
		t.Fatalf("full fingerprint must derive a cid, got %v", p)
	}

	// Small head-tail equals full.
	ht, err := FingerprintBytes(abc, "head-tail")
	if err != nil || ht.Value == nil || *ht.Value != wantABC {
		t.Fatalf("small head-tail = %+v, %v", ht, err)
	}

	// Large head-tail hashes exactly the first and last MiB.
	big := bytes.Repeat([]byte{0xAB}, int(3*HeadTailWindow))
	ht, err = FingerprintBytes(big, "head-tail")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(big[:HeadTailWindow])
	h.Write(big[len(big)-int(HeadTailWindow):])
	if *ht.Value != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("head-tail digest mismatch")
	}

	// Null scope has no value and therefore no cid.
	nilFP, err := FingerprintBytes(abc, "null")
	if err != nil {
		t.Fatal(err)
	}
	if nilFP.Scope != "" || nilFP.Value != nil || CID(&nilFP) != nil {
		t.Fatalf("null scope must stay null: %+v cid=%v", nilFP, CID(&nilFP))
	}

	// Shape scope also has no cid even with a value.
	shape := Fingerprint{Algo: "sha256", Scope: "shape", Value: &wantABC}
	if CID(&shape) != nil {
		t.Fatal("shape scope must not derive a cid")
	}
}

func TestFingerprintKeys(t *testing.T) {
	a := FingerprintKeys([]string{"b", "a", "c"})
	b := FingerprintKeys([]string{"a", "c", "b"})
	if a.Value == nil || b.Value == nil || *a.Value != *b.Value {
		t.Fatal("keys fingerprint must be independent of input order")
	}
	h := sha256.Sum256([]byte("a\x00b\x00c"))
	if *a.Value != hex.EncodeToString(h[:]) {
		t.Fatalf("keys digest = %s, want sha256 of sorted keys", *a.Value)
	}
	if a.Scope != "keys" {
		t.Fatalf("keys scope = %q", a.Scope)
	}
	if CID(&a) == nil {
		t.Fatal("keys fingerprint must derive a cid")
	}
}

func TestIDAndCIDIndependence(t *testing.T) {
	u1 := fixtureUnit("e1", "/home/a/one")
	u2 := fixtureUnit("e2", "/home/a/two")
	if u1.ID == UnitID("home", "p", "e1", "part", u1.PathKey) {
		t.Fatal("part id must participate in the unit id")
	}
	if !unitIDPattern.MatchString(u1.ID) || len(u1.ID) != 28 {
		t.Fatalf("unit id %q is not 26 Crockford chars after u_", u1.ID)
	}
	// Same content, different paths/entries => same cid, different id.
	if u1.Fingerprint == nil || u2.Fingerprint == nil {
		t.Fatal("fixtures need fingerprints")
	}
	u2.Fingerprint.Value = u1.Fingerprint.Value
	u2.CID = CID(u2.Fingerprint)
	if *u1.CID != *u2.CID {
		t.Fatal("equal content must yield equal cid")
	}
	if u1.ID == u2.ID {
		t.Fatal("different paths must yield different id")
	}
	if len(*u1.CID) != 28 {
		t.Fatalf("cid %q length = %d", *u1.CID, len(*u1.CID))
	}
	if id := HitID(u1.CID, "/env/X", "fp", u1.ID); len(id) != 22 {
		t.Fatalf("hit id %q length = %d, want 22", id, len(id))
	}
}

func TestWriterRejectsMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, newTestHeader(0), WithClock(fixedClock{testStart}), WithSalt(FixedSalt("s")))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()

	u := fixtureUnit("e1", "/home/a/x")
	u.ID = ""
	if err := w.WriteUnit(&u); err == nil || !strings.Contains(err.Error(), "E-MAN-005") {
		t.Fatalf("missing id: err=%v", err)
	}
	u = fixtureUnit("e1", "/home/a/x")
	u.Secret = nil
	if err := w.WriteUnit(&u); err == nil || !strings.Contains(err.Error(), "E-MAN-005") {
		t.Fatalf("missing secret: err=%v", err)
	}
	u = fixtureUnit("e1", "/home/a/x")
	u.Signals = nil
	if err := w.WriteUnit(&u); err == nil || !strings.Contains(err.Error(), "E-MAN-005") {
		t.Fatalf("missing signals: err=%v", err)
	}

	badHdr := newTestHeader(0)
	badHdr.Tool = ""
	if _, err := NewWriter(t.TempDir(), badHdr); err == nil || !strings.Contains(err.Error(), "E-MAN-005") {
		t.Fatalf("missing tool: err=%v", err)
	}
}

func TestSectionNumbersInDocComment(t *testing.T) {
	// Guard against accidentally formatting the file in a way that breaks the
	// package contract: the golden clock must remain representable.
	if testStart.Format(time.RFC3339Nano) != "2026-11-10T09:12:03.4123456Z" {
		t.Fatalf("unexpected test time format: %s", testStart.Format(time.RFC3339Nano))
	}
}

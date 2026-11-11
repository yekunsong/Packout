package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packout/internal/fsx"
	"packout/internal/manifest"
)

var (
	testStart = time.Date(2026, 11, 10, 9, 12, 3, 412345600, time.UTC)
	testEnd   = time.Date(2026, 11, 10, 9, 14, 51, 9000000, time.UTC)
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fixture is one scan output plus the source root it describes.
type fixture struct {
	out  string
	root string
	srv  *Server
}

func testHeader(root string) manifest.Header {
	return manifest.Header{
		ManifestVersion: manifest.Version,
		ScanID:          "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
		ScanSegment:     manifest.ScanSegment{SegmentSeq: 0, FirstShard: 1},
		StartedAt:       testStart,
		Tool:            "packout/test",
		Host: manifest.Host{
			OS: "linux", OSVersion: "6.8.0", Arch: "amd64",
			CaseSensitivity: "sensitive",
			PathFoldVersion: manifest.CurrentPathFoldVersion(),
			VolumeIDs:       []manifest.VolumeID{{Root: "/", Serial: "rootfs"}},
		},
		Inputs: manifest.Inputs{
			SecretSaltMode: "random",
			SecretSalt:     "00112233445566778899aabbccddeeff",
			Profiles:       []manifest.ProfileRef{{Name: "p", Version: "2.0", SHA256: strings.Repeat("a", 64)}},
			Options:        &manifest.InputOptions{},
		},
		Roots: []manifest.Root{{
			Name: "home", Role: "home", Instance: 1, Origin: "cli", Path: root, Profile: "p",
		}},
	}
}

// newFixture creates a root directory, an empty unit list and starts the
// server. Units are added with write.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "home")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "scan")
	srv, err := NewServer(Config{
		OutDir: out, Profile: "p",
		Roots:   []Root{{Name: "home", Role: "home", Instance: 1, Origin: "cli", Path: root}},
		Version: "0.1.0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return &fixture{out: out, root: root, srv: srv}
}

// write materialises the manifest with the given units. Units whose path is
// empty get one under root.
func (f *fixture) write(t *testing.T, units ...manifest.Unit) {
	t.Helper()
	mdir := filepath.Join(f.out, "manifest")
	w, err := manifest.NewWriter(mdir, testHeader(f.root),
		manifest.WithClock(fixedClock{t: testStart}),
		manifest.WithSalt(manifest.FixedSalt("00112233445566778899aabbccddeeff")))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := range units {
		if units[i].Path == "" {
			units[i].Path = filepath.Join(f.root, units[i].Entry+".txt")
			units[i].PathKey = fsx.NormKey(units[i].Path)
			units[i].ID = units[i].ComputeID()
		}
		if err := w.WriteUnit(&units[i]); err != nil {
			t.Fatalf("WriteUnit %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func unitAt(t *testing.T, path, entry, layer string) manifest.Unit {
	t.Helper()
	fp, err := manifest.FingerprintBytes([]byte(path), "full")
	if err != nil {
		t.Fatal(err)
	}
	mtime := testStart
	size := int64(42)
	alloc := int64(4096)
	u := manifest.Unit{
		SchemaVersion:  manifest.Version,
		Path:           path,
		PathKey:        fsx.NormKey(path),
		Root:           "home",
		PathSemantics:  manifest.SemanticsLiteral,
		Profile:        "p",
		Entry:          entry,
		Kind:           manifest.KindFile,
		Layer:          layer,
		Confidence:     0.9,
		Signals:        []manifest.Signal{{Src: "profile_rule", Note: "declared L" + layer}},
		Secret:         &manifest.Secret{Class: manifest.SecretNone, Hits: []manifest.SecretHit{}},
		SizeApparent:   &size,
		SizeAlloc:      &alloc,
		MTime:          &mtime,
		Fingerprint:    &fp,
		ProposedAction: manifest.ActionKeep,
		RiskFlags:      []string{},
	}
	u.ID = u.ComputeID()
	u.CID = manifest.CID(&fp)
	return u
}

func (f *fixture) file(t *testing.T, rel, content string) (string, manifest.Unit) {
	t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	u := unitAt(t, p, "entry-"+strings.ReplaceAll(rel, "/", "-"), manifest.LayerL3)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	sz := fi.Size()
	mt := fi.ModTime()
	u.SizeApparent = &sz
	u.MTime = &mt
	return p, u
}

// ---- protocol -------------------------------------------------------------

func serveOnce(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var got []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("response is not JSON: %v (%q)", err, line)
		}
		got = append(got, m)
	}
	return got
}

func TestInitializeReportsServer(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t"}}}`)
	if len(got) != 1 {
		t.Fatalf("responses = %d, want 1", len(got))
	}
	res := got[0]["result"].(map[string]any)
	if res["protocolVersion"] != ProtocolVersion {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
	info := res["serverInfo"].(map[string]any)
	if info["name"] != ServerName {
		t.Fatalf("serverInfo.name = %v", info["name"])
	}
}

func TestInitializeEchoesSupportedOldVersion(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	res := got[0]["result"].(map[string]any)
	if res["protocolVersion"] != "2024-11-05" {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
}

func TestToolsListIsExactlySix(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := got[0]["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tv := range tools {
		names = append(names, tv.(map[string]any)["name"].(string))
	}
	want := []string{"roots", "summary", "find", "explain", "verify", "restore_plan"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("tools = %v, want %v", names, want)
	}
	for _, tv := range tools {
		schema := tv.(map[string]any)["inputSchema"].(map[string]any)
		if schema["type"] != "object" {
			t.Fatalf("tool %v schema type = %v", tv.(map[string]any)["name"], schema["type"])
		}
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if len(got) != 0 {
		t.Fatalf("notification produced %d responses", len(got))
	}
}

func TestParseErrorAndUnknownMethod(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv,
		`{not json`,
		`{"jsonrpc":"2.0","id":9,"method":"nope"}`)
	if len(got) != 2 {
		t.Fatalf("responses = %d", len(got))
	}
	if got[0]["id"] != nil {
		t.Fatalf("parse error id = %v, want null", got[0]["id"])
	}
	if int(got[0]["error"].(map[string]any)["code"].(float64)) != -32700 {
		t.Fatalf("parse error code = %v", got[0]["error"])
	}
	if int(got[1]["error"].(map[string]any)["code"].(float64)) != -32601 {
		t.Fatalf("unknown method code = %v", got[1]["error"])
	}
}

// TestFullSessionStdoutStaysPure checks that stdout is a stream of valid
// JSON-RPC and nothing else, including after a parse error, and that empty
// lines are skipped. stderr is the CLI's business; Serve never writes there.
func TestFullSessionStdoutStaysPure(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a"), "a", "L3"))
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		``,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"roots","arguments":{}}}`,
		`{{{ broken`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"summary","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
	}
	var out bytes.Buffer
	if err := f.srv.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	gotLines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(gotLines) != 6 { // 8 lines minus the notification and the empty line
		t.Fatalf("responses = %d: %q", len(gotLines), gotLines)
	}
	var parsed []map[string]any
	for i, line := range gotLines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", i, err, line)
		}
		parsed = append(parsed, m)
		if m["jsonrpc"] != "2.0" {
			t.Fatalf("line %d is not JSON-RPC 2.0: %v", i, m)
		}
		if i == 3 {
			if int(m["error"].(map[string]any)["code"].(float64)) != -32700 || m["id"] != nil {
				t.Fatalf("bad JSON line = %v", m)
			}
			continue
		}
		if m["id"] == nil {
			t.Fatalf("line %d has no id: %v", i, m)
		}
	}
	// The broken line is answered -32700, and the following calls still work.
	if int(parsed[4]["id"].(float64)) != 4 || parsed[4]["result"] == nil {
		t.Fatalf("session did not continue after parse error: %v", parsed[4])
	}
	if int(parsed[5]["error"].(map[string]any)["code"].(float64)) != -32601 {
		t.Fatalf("unknown method = %v", parsed[5])
	}
}

// Newline framing only: a Content-Length header must fail as JSON.
func TestNewlineFramingOnly(t *testing.T) {
	f := newFixture(t)
	got := serveOnce(t, f.srv,
		`Content-Length: 37`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if len(got) != 2 {
		t.Fatalf("responses = %d", len(got))
	}
	if got[0]["error"] == nil {
		t.Fatalf("Content-Length line accepted as JSON: %v", got[0])
	}
	if got[1]["result"] == nil {
		t.Fatalf("ping failed: %v", got[1])
	}
}

// ---- calling helper -------------------------------------------------------

func callTool(t *testing.T, s *Server, name string, args any) *callResult {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	resp := s.call(context.Background(), json.RawMessage(`1`), params)
	if resp.Error != nil {
		t.Fatalf("%s: rpc error %+v", name, resp.Error)
	}
	res, ok := resp.Result.(*callResult)
	if !ok {
		t.Fatalf("%s: result type %T", name, resp.Result)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("%s: bad content %+v", name, res.Content)
	}
	if len(res.Content[0].Text) > MaxResultBytes {
		t.Fatalf("%s: payload %d > %d", name, len(res.Content[0].Text), MaxResultBytes)
	}
	// The text block and structuredContent must be the same document, or a
	// client that reads either one sees different data.
	sb, err := marshalNoEscape(res.StructuredContent)
	if err != nil {
		t.Fatalf("%s: marshal structured: %v", name, err)
	}
	if string(sb) != res.Content[0].Text {
		t.Fatalf("%s: content/structuredContent differ:\n%s\n%s", name, res.Content[0].Text, sb)
	}
	return res
}

func payload(t *testing.T, res *callResult) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &m); err != nil {
		t.Fatalf("structured text is not JSON: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned an error object: %v %v", m["code"], m["message"])
	}
	return m
}

func errCode(t *testing.T, res *callResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected tool error, got %s", res.Content[0].Text)
	}
	te, ok := res.StructuredContent.(*toolError)
	if !ok {
		t.Fatalf("error is not structured: %T", res.StructuredContent)
	}
	return te.Code
}

func TestUnknownToolAndBadArgs(t *testing.T) {
	f := newFixture(t)
	f.write(t)
	res := callTool(t, f.srv, "nope", map[string]any{})
	if got := errCode(t, res); got != "unknown_tool" {
		t.Fatalf("code = %s", got)
	}
	res = callTool(t, f.srv, "find", map[string]any{"limit": 0})
	if got := errCode(t, res); got != "bad_arguments" {
		t.Fatalf("code = %s", got)
	}
	res = callTool(t, f.srv, "find", map[string]any{"bogus": 1})
	if got := errCode(t, res); got != "bad_arguments" {
		t.Fatalf("unknown key code = %s", got)
	}
	res = callTool(t, f.srv, "roots", map[string]any{"x": 1})
	if got := errCode(t, res); got != "bad_arguments" {
		t.Fatalf("roots arg code = %s", got)
	}
	res = callTool(t, f.srv, "explain", map[string]any{})
	if got := errCode(t, res); got != "bad_arguments" {
		t.Fatalf("explain missing key code = %s", got)
	}
}

func TestMissingScanAndNotConfigured(t *testing.T) {
	f := newFixture(t)
	if got := errCode(t, callTool(t, f.srv, "summary", map[string]any{})); got != "no_scan" {
		t.Fatalf("summary code = %s", got)
	}
	if got := errCode(t, callTool(t, f.srv, "verify", map[string]any{})); got != "not_configured" {
		t.Fatalf("verify code = %s", got)
	}
	if got := errCode(t, callTool(t, f.srv, "restore_plan", map[string]any{})); got != "not_configured" {
		t.Fatalf("restore_plan code = %s", got)
	}
}

// Once --package/--into are configured, a model-supplied path field is still
// rejected: the schema is strict and the path comes from startup.
func TestConfiguredToolsRejectModelPath(t *testing.T) {
	f := newFixture(t)
	pkg := t.TempDir()
	into := t.TempDir()
	f.srv.pkg = pkg
	f.srv.into = into
	for _, name := range []string{"verify", "restore_plan"} {
		res := callTool(t, f.srv, name, map[string]any{"path": "/etc"})
		if got := errCode(t, res); got != "bad_arguments" {
			t.Fatalf("%s path arg code = %s", name, got)
		}
	}
	// verify itself answers (empty package → "empty" conclusion).
	res := callTool(t, f.srv, "verify", map[string]any{})
	p := payload(t, res)
	if p["package"] != pkg || p["conclusion"] != "empty" {
		t.Fatalf("verify = %v", p)
	}
	// restore_plan reaches the SIG gate and reports a structured failure.
	res = callTool(t, f.srv, "restore_plan", map[string]any{})
	if !res.IsError {
		t.Fatalf("restore_plan should fail on an empty package: %s", res.Content[0].Text)
	}
}

func TestIncompleteManifestIsScanInvalid(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.out, "manifest"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.out, "manifest", "manifest.index.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := errCode(t, callTool(t, f.srv, "summary", map[string]any{})); got != "scan_invalid" {
		t.Fatalf("code = %s", got)
	}
}

// ---- roots ----------------------------------------------------------------

func TestRootsReportsConfiguredAndScanned(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a.txt"), "a", "L3"))
	p := payload(t, callTool(t, f.srv, "roots", map[string]any{}))
	roots := p["roots"].([]any)
	r := roots[0].(map[string]any)
	if r["exists"] != true || r["is_dir"] != true {
		t.Fatalf("root stat = %v", r)
	}
	if r["path_key"] != fsx.NormKey(f.root) {
		t.Fatalf("path_key = %v", r["path_key"])
	}
	scanRoots, _ := p["scan_roots"].([]any)
	if len(scanRoots) != 1 {
		t.Fatalf("scan_roots = %v (payload %v)", p["scan_roots"], p)
	}
	if p["scan"].(map[string]any)["fingerprint"] == "" {
		t.Fatal("missing scan fingerprint")
	}
}

func TestRootsSurvivesMissingRoot(t *testing.T) {
	f := newFixture(t)
	f.srv.roots = append(f.srv.roots, Root{Name: "gone", Role: "gone", Path: filepath.Join(f.root, "nope")})
	p := payload(t, callTool(t, f.srv, "roots", map[string]any{}))
	r := p["roots"].([]any)[1].(map[string]any)
	if r["exists"] != false || r["error"] == nil {
		t.Fatalf("missing root = %v", r)
	}
}

// ---- summary --------------------------------------------------------------

func TestSummaryMatchesManifest(t *testing.T) {
	f := newFixture(t)
	f.write(t,
		unitAt(t, filepath.Join(f.root, "a"), "e1", "L2"),
		unitAt(t, filepath.Join(f.root, "b"), "e2", "L2"),
		unitAt(t, filepath.Join(f.root, "c"), "e3", "L4"),
	)
	p := payload(t, callTool(t, f.srv, "summary", map[string]any{}))
	tot := p["totals"].(map[string]any)
	if tot["units"] != float64(3) || tot["units_footer"] != float64(3) {
		t.Fatalf("totals = %v", tot)
	}
	var sum float64
	for _, lv := range p["layers"].([]any) {
		sum += lv.(map[string]any)["units"].(float64)
	}
	if sum != 3 {
		t.Fatalf("layer sum = %v", sum)
	}
	profs := p["profiles"].([]any)
	if len(profs) != 1 || profs[0].(map[string]any)["units"] != float64(3) {
		t.Fatalf("profiles = %v", profs)
	}
}

// ---- find -----------------------------------------------------------------

func TestFindFiltersAndPaginates(t *testing.T) {
	f := newFixture(t)
	f.write(t,
		unitAt(t, filepath.Join(f.root, "one", "settings.json"), "settings", "L2"),
		unitAt(t, filepath.Join(f.root, "one", "history.jsonl"), "history", "L3"),
		unitAt(t, filepath.Join(f.root, "two", "settings.json"), "settings", "L2"),
	)
	all := payload(t, callTool(t, f.srv, "find", map[string]any{}))
	if all["total_matches"] != float64(3) {
		t.Fatalf("total = %v", all["total_matches"])
	}
	first := all["units"].([]any)[0].(map[string]any)
	if first["path"] == nil || first["path_key"] == nil {
		t.Fatalf("path pair missing: %v", first)
	}

	byLayer := payload(t, callTool(t, f.srv, "find", map[string]any{"layer": "L2"}))
	if byLayer["total_matches"] != float64(2) {
		t.Fatalf("layer total = %v", byLayer["total_matches"])
	}
	byEntry := payload(t, callTool(t, f.srv, "find", map[string]any{"entry": "history"}))
	if byEntry["total_matches"] != float64(1) {
		t.Fatalf("entry total = %v", byEntry["total_matches"])
	}
	byFrag := payload(t, callTool(t, f.srv, "find", map[string]any{"path_contains": "two/settings"}))
	if byFrag["total_matches"] != float64(1) {
		t.Fatalf("fragment total = %v", byFrag["total_matches"])
	}
	upper := payload(t, callTool(t, f.srv, "find", map[string]any{"path_contains": "TWO/SETTINGS"}))
	if upper["total_matches"] != float64(1) {
		t.Fatalf("case-insensitive total = %v", upper["total_matches"])
	}

	page := payload(t, callTool(t, f.srv, "find", map[string]any{"layer": "L2", "limit": 1, "offset": 1}))
	if page["total_matches"] != float64(2) || len(page["units"].([]any)) != 1 || page["has_more"] != false {
		t.Fatalf("page = %v", page)
	}
	page2 := payload(t, callTool(t, f.srv, "find", map[string]any{"limit": 2, "offset": 0}))
	if page2["has_more"] != true || page2["next_offset"] != float64(2) {
		t.Fatalf("has_more = %v", page2)
	}
}

func TestFindRejectsBadBounds(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a"), "a", "L3"))
	for _, args := range []map[string]any{
		{"limit": 0}, {"limit": 101}, {"offset": -1}, {"layer": "L9"},
	} {
		if got := errCode(t, callTool(t, f.srv, "find", args)); got != "bad_arguments" {
			t.Fatalf("%v code = %s", args, got)
		}
	}
}

func TestFindPaginationNoOverlapNoGap(t *testing.T) {
	f := newFixture(t)
	units := make([]manifest.Unit, 0, 5)
	for i := 0; i < 5; i++ {
		units = append(units, unitAt(t, filepath.Join(f.root, "f"+string(rune('a'+i))), "e", "L3"))
	}
	f.write(t, units...)

	seen := map[string]bool{}
	for offset := 0; offset < 5; offset += 2 {
		p := payload(t, callTool(t, f.srv, "find", map[string]any{"limit": 2, "offset": offset}))
		for _, uv := range p["units"].([]any) {
			path := uv.(map[string]any)["path"].(string)
			if seen[path] {
				t.Fatalf("duplicate across pages: %s", path)
			}
			seen[path] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("pages covered %d of 5", len(seen))
	}
}

func TestFindSkipsOutsideRoot(t *testing.T) {
	f := newFixture(t)
	elsewhere := t.TempDir()
	f.write(t,
		unitAt(t, filepath.Join(f.root, "in"), "in", "L3"),
		unitAt(t, filepath.Join(elsewhere, "out"), "out", "L3"),
	)
	p := payload(t, callTool(t, f.srv, "find", map[string]any{}))
	if p["total_matches"] != float64(1) || p["outside_root_skipped"] != float64(1) {
		t.Fatalf("scope = %v", p)
	}
}

func TestFindTruncatesToResultBound(t *testing.T) {
	f := newFixture(t)
	units := make([]manifest.Unit, 0, 240)
	for i := 0; i < 240; i++ {
		name := fmt.Sprintf("%03d-%s.json", i, strings.Repeat("x", 40))
		u := unitAt(t, filepath.Join(f.root, "deep", "directory", "with", "long", "name", name), "long-entry-name", "L3")
		units = append(units, u)
	}
	f.write(t, units...)
	p := payload(t, callTool(t, f.srv, "find", map[string]any{"limit": maxFindLimit}))
	if p["truncated"] != true {
		t.Fatalf("truncated = %v (returned %v)", p["truncated"], p["returned"])
	}
	if p["source"] == nil || !strings.Contains(p["source"].(string), "manifest") {
		t.Fatalf("source = %v", p["source"])
	}
	if p["returned"].(float64) >= maxFindLimit {
		t.Fatalf("returned = %v", p["returned"])
	}
	if int(p["returned"].(float64)) != len(p["units"].([]any)) {
		t.Fatalf("returned %v != units %d", p["returned"], len(p["units"].([]any)))
	}
}

// ---- explain --------------------------------------------------------------

func TestExplainByIDAndPathKey(t *testing.T) {
	f := newFixture(t)
	content := "file body with canary CANARY-123"
	p, u := f.file(t, "settings.json", content)
	u.Secret = &manifest.Secret{Class: manifest.SecretScan, HitCount: 1, Hits: []manifest.SecretHit{{
		Kind: "anthropic-key", Class: "scan", Locator: "/env/TOKEN",
		Prefix: "sk-ant-", Fingerprint: "sha256:" + strings.Repeat("ab", 32), HitID: "h_1",
	}}}
	f.write(t, u)
	res := payload(t, callTool(t, f.srv, "explain", map[string]any{"id": u.ID}))
	unit, ok := res["unit"].(map[string]any)
	if !ok {
		t.Fatalf("explain failed: %v", res)
	}
	if unit["id"] != u.ID || unit["path"] != p {
		t.Fatalf("unit = %v", unit)
	}
	sigs := res["signals"].([]any)
	if len(sigs) != 1 || sigs[0].(map[string]any)["src"] != "profile_rule" {
		t.Fatalf("signals = %v", sigs)
	}
	if strings.Contains(res["signals"].([]any)[0].(map[string]any)["note"].(string), "CANARY") {
		t.Fatal("signal note should not carry file body")
	}
	stat, ok := res["current_stat"].(map[string]any)
	if !ok {
		t.Fatalf("current_stat missing: %v", res)
	}
	if stat["exists"] != true || stat["stale"] != false {
		t.Fatalf("stat = %v", stat)
	}
	secret := res["secret"].(map[string]any)
	if secret["class"] != "scan" || secret["hits_total"] != float64(1) {
		t.Fatalf("secret = %v", secret)
	}
	hits := res["secret_hits"].([]any)
	if hits[0].(map[string]any)["prefix"] != "sk-ant-" {
		t.Fatalf("hit = %v", hits)
	}

	byKey := payload(t, callTool(t, f.srv, "explain", map[string]any{"path_key": u.PathKey}))
	if byKey["unit"].(map[string]any)["id"] != u.ID {
		t.Fatalf("path_key lookup = %v", byKey["unit"])
	}
}

func TestExplainRestatsEachCall(t *testing.T) {
	f := newFixture(t)
	p, u := f.file(t, "grow.txt", "one")
	f.write(t, u)
	first := payload(t, callTool(t, f.srv, "explain", map[string]any{"id": u.ID}))
	if first["current_stat"].(map[string]any)["stale"] != false {
		t.Fatalf("first stat = %v", first["current_stat"])
	}
	if err := os.WriteFile(p, []byte("one and a lot more"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := payload(t, callTool(t, f.srv, "explain", map[string]any{"id": u.ID}))
	stat := second["current_stat"].(map[string]any)
	if stat["stale"] != true {
		t.Fatalf("second stat should be stale: %v", stat)
	}
	drift := stat["drift"].([]any)
	found := false
	for _, d := range drift {
		if d == "size_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("drift = %v", drift)
	}
}

func TestExplainOutsideRoot(t *testing.T) {
	f := newFixture(t)
	outside := t.TempDir()
	u := unitAt(t, filepath.Join(outside, "x"), "x", "L3")
	f.write(t, u)
	res := callTool(t, f.srv, "explain", map[string]any{"id": u.ID})
	if got := errCode(t, res); got != "outside_root" {
		t.Fatalf("code = %s", got)
	}
}

func TestExplainTruncatesManySignals(t *testing.T) {
	f := newFixture(t)
	u := unitAt(t, filepath.Join(f.root, "many"), "many", "L3")
	u.Signals = nil
	for i := 0; i < 200; i++ {
		u.Signals = append(u.Signals, manifest.Signal{
			Src: "profile_rule", Note: strings.Repeat("note ", 20) + string(rune('a'+i%26)),
		})
	}
	f.write(t, u)
	p := payload(t, callTool(t, f.srv, "explain", map[string]any{"id": u.ID}))
	if p["truncated"] != true || p["source"] == nil {
		t.Fatalf("truncated = %v source = %v", p["truncated"], p["source"])
	}
	if p["signals_returned"].(float64) >= 200 {
		t.Fatalf("signals_returned = %v", p["signals_returned"])
	}
}

func TestExplainNotFound(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a"), "a", "L3"))
	res := callTool(t, f.srv, "explain", map[string]any{"id": "u_nope"})
	if got := errCode(t, res); got != "not_found" {
		t.Fatalf("code = %s", got)
	}
}

// ---- freshness ------------------------------------------------------------

func TestFingerprintChangesWhenIndexChanges(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a"), "a", "L3"))
	first := payload(t, callTool(t, f.srv, "summary", map[string]any{}))
	fp1 := first["scan"].(map[string]any)["fingerprint"]
	idx := filepath.Join(f.out, "manifest", "manifest.index.json")
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	second := payload(t, callTool(t, f.srv, "summary", map[string]any{}))
	fp2 := second["scan"].(map[string]any)["fingerprint"]
	if fp1 == fp2 {
		t.Fatalf("fingerprint did not change: %v", fp1)
	}
}

// Same freshness check through find: no cached scan survives a call.
func TestFindFingerprintChangesWhenIndexChanges(t *testing.T) {
	f := newFixture(t)
	f.write(t, unitAt(t, filepath.Join(f.root, "a"), "a", "L3"))
	fp1 := payload(t, callTool(t, f.srv, "find", map[string]any{}))["scan"].(map[string]any)["fingerprint"]
	idx := filepath.Join(f.out, "manifest", "manifest.index.json")
	b, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, append(b, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	fp2 := payload(t, callTool(t, f.srv, "find", map[string]any{}))["scan"].(map[string]any)["fingerprint"]
	if fp1 == fp2 {
		t.Fatalf("fingerprint did not change: %v", fp1)
	}
}

// Without --root the server falls back to the scan's own header roots, which
// are only reachable through the startup --out.
func TestRootsFallBackToScannedRoots(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "home")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "scan")
	srv, err := NewServer(Config{OutDir: out, Profile: "p"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{out: out, root: root, srv: srv}
	f.write(t, unitAt(t, filepath.Join(root, "a"), "a", "L3"))

	p := payload(t, callTool(t, srv, "roots", map[string]any{}))
	if len(p["roots"].([]any)) != 0 {
		t.Fatalf("configured roots = %v", p["roots"])
	}
	if len(p["scan_roots"].([]any)) != 1 {
		t.Fatalf("scan_roots = %v", p["scan_roots"])
	}
	// find therefore still works through the scanned root.
	if payload(t, callTool(t, srv, "find", map[string]any{}))["total_matches"] != float64(1) {
		t.Fatal("fallback root did not scope find")
	}
}

func TestSummaryCountsMatchIndex(t *testing.T) {
	f := newFixture(t)
	f.write(t,
		unitAt(t, filepath.Join(f.root, "a"), "a", "L2"),
		unitAt(t, filepath.Join(f.root, "b"), "b", "L3"),
	)
	p := payload(t, callTool(t, f.srv, "summary", map[string]any{}))
	raw, err := os.ReadFile(filepath.Join(f.out, "manifest", "manifest.index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Units    int64 `json:"units"`
		Residual int64 `json:"residual"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	tot := p["totals"].(map[string]any)
	if tot["units"] != float64(idx.Units) || tot["residual"] != float64(idx.Residual) {
		t.Fatalf("summary %v vs index %+v", tot, idx)
	}
}

func TestManifestOutsideOutIsIgnored(t *testing.T) {
	f := newFixture(t)
	// A stray manifest index in a root (not in --out) must not be read.
	if err := os.WriteFile(filepath.Join(f.root, "manifest.index.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := errCode(t, callTool(t, f.srv, "summary", map[string]any{})); got != "no_scan" {
		t.Fatalf("code = %s", got)
	}
}

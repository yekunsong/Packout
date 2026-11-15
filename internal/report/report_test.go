package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yekunsong/Packout/internal/manifest"
)

var update = flag.Bool("update", false, "update golden files")

func sp(s string) *string { return &s }
func ip(n int64) *int64   { return &n }

// fixtureDoc is a fixed manifest with one of every report-relevant shape:
// L5, unversioned L3, L0/L1 volume, residual, secret hits, and hostile paths.
// Times are fixed so the rendered bytes are stable.
func fixtureDoc() *manifest.Doc {
	started := time.Date(2026, 11, 10, 9, 12, 3, 412345600, time.UTC)
	ended := started.Add(2*time.Minute + 47*time.Second)

	official := "https://code.claude.com/docs/en/setup"
	official2 := "https://code.claude.com/docs/en/memory"

	return &manifest.Doc{
		Header: manifest.Header{
			ManifestVersion: "2.0",
			ScanID:          "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
			StartedAt:       started,
			Tool:            "github.com/yekunsong/Packout/0.1.0",
			Host: manifest.Host{
				OS:              "windows",
				OSVersion:       "10.0.26100",
				Arch:            "amd64",
				CaseSensitivity: "insensitive",
			},
			Roots: []manifest.Root{{
				Name: "home", Role: "home", Instance: 1,
				Origin: "profile", Path: `C:\Users\alice`, Profile: "claude-code",
			}},
		},
		Units: []manifest.Unit{
			{
				ID: "u_1", Path: "wincred:Claude Code-credentials", PathKey: "wincred:claude code-credentials",
				Root: "os", Profile: "claude-code", Entry: "oauth-credential-store",
				Kind: manifest.KindNamedLocation, Layer: manifest.LayerL5, Confidence: 0.960,
				Signals: []manifest.Signal{
					{Src: "profile_rule", Note: "profile claude-code v2.0 entry oauth-credential-store 声明 L5/relogin"},
					{Src: "probe_result", Note: "wincred 目标存在，refresh token 绑定设备会话"},
					{Src: "official_docs", Note: "OAuth 凭据由系统凭据库保管", URL: &official},
				},
				Secret: &manifest.Secret{
					Class: manifest.SecretRelogin,
					Hits: []manifest.SecretHit{{
						Kind: "known_prefix", Class: manifest.SecretRelogin,
						Locator: "target", Prefix: "eyJhbGci", Fingerprint: "sha256:0a9b7c2d",
					}},
					HitCount: 1,
				},
				ProposedAction: manifest.ActionRelogin,
			},
			{
				ID: "u_2", Path: `C:\Users\alice\.claude\projects\D--Study-packout\4b1c.jsonl`,
				PathKey: `c:\users\alice\.claude\projects\d--study-packout\4b1c.jsonl`,
				Root:    "home", Profile: "claude-code", Entry: "projects-transcripts",
				Kind: manifest.KindFile, Layer: manifest.LayerL3, Confidence: 0.970,
				Signals: []manifest.Signal{
					{Src: "profile_rule", Note: "profile claude-code v2.0 entry projects-transcripts 声明 L3"},
					{Src: "gitignore_hit", Note: "~/.config/git/ignore 的 **/.claude/projects/ 命中，未进版本库"},
					{Src: "official_docs", Note: "transcript 记录会话内读过的全部内容，不可再生", URL: &official2},
				},
				Secret: &manifest.Secret{
					Class: manifest.SecretScan,
					Hits: []manifest.SecretHit{{
						Kind: "known_prefix", Class: manifest.SecretRestore,
						Locator: "42:17", Prefix: "sk-ant-", Fingerprint: "sha256:6c1e88f0",
					}},
					HitCount: 1,
				},
				SizeAlloc:      ip(12410880),
				ProposedAction: manifest.ActionMigrate,
				RiskFlags:      []string{"gitignored", "not_versioned"},
			},
			{
				ID: "u_3", Path: `C:\Users\alice\.claude\shell-snapshots\snapshot-1.sh`,
				PathKey: `c:\users\alice\.claude\shell-snapshots\snapshot-1.sh`,
				Root:    "home", Profile: "claude-code", Entry: "shell-snapshots",
				Kind: manifest.KindFile, Layer: manifest.LayerL0, Confidence: 0.960,
				Signals: []manifest.Signal{
					{Src: "profile_rule", Note: "profile claude-code v2.0 entry shell-snapshots 声明 L0"},
					{Src: "content_match", Note: "文件头为 shell 函数导出与环境快照，无用户内容"},
				},
				Secret:         &manifest.Secret{Class: manifest.SecretNone},
				SizeAlloc:      ip(2121728),
				ProposedAction: manifest.ActionDelete,
			},
			{
				ID: "u_4", Path: `C:\Users\alice\.claude\plugins\cache.bin`,
				PathKey: `c:\users\alice\.claude\plugins\cache.bin`,
				Root:    "home", Profile: "claude-code", Entry: "plugins-cache",
				Kind: manifest.KindFile, Layer: manifest.LayerL1, Confidence: 0.950,
				Signals: []manifest.Signal{
					{Src: "profile_rule", Note: "profile claude-code v2.0 entry plugins-cache 声明 L1"},
				},
				Secret:         &manifest.Secret{Class: manifest.SecretNone},
				SizeAlloc:      ip(4096),
				ProposedAction: manifest.ActionReinstall,
			},
			{
				ID: "u_5", Path: `C:\Users\alice\.claude\loose.txt`,
				PathKey: `c:\users\alice\.claude\loose.txt`,
				Root:    "home", Profile: "claude-code", Entry: "home-residual",
				Kind: manifest.KindCatchAll, Layer: manifest.LayerL2, Confidence: 0.500,
				Signals: []manifest.Signal{
					{Src: "filesystem_stat", Note: "未被任何 entry 命中，catch-all 残留"},
				},
				Secret:         &manifest.Secret{Class: manifest.SecretScan},
				SizeAlloc:      ip(4096),
				AggregateCount: ip(3),
				ProposedAction: manifest.ActionKeep,
				RiskFlags:      []string{"low_confidence", "residual"},
			},
			{
				ID: "u_6", Path: `<script>alert(1)</script>`,
				PathKey: `<script>alert(1)</script>`,
				Root:    "home", Profile: `"><img src=x onerror=alert(1)>`, Entry: `</style><script>alert(2)</script>`,
				Kind: manifest.KindFile, Layer: manifest.LayerL2, Confidence: 0.600,
				Signals: []manifest.Signal{
					{Src: "content_match", Note: `note with "quotes" and </style> and <script>alert(3)</script>`},
				},
				Secret:         &manifest.Secret{Class: manifest.SecretNone},
				SizeAlloc:      ip(512),
				ProposedAction: manifest.ActionKeep,
				RiskFlags:      []string{"not_versioned"},
				Notes:          `</style><img src=x onerror=alert(4)>`,
			},
		},
		Notes: []manifest.Note{
			{Code: "probe_unavailable", Profile: "claude-code", Entry: "oauth-credential-store", Detail: "wincred 探测返回 ERROR_NOT_FOUND"},
		},
		Footer: manifest.Footer{
			ScanID:   "01JQ8Z3K7M2V9T4R6W8X0Y2B4C",
			EndedAt:  ended,
			Units:    6,
			Shards:   1,
			Complete: true,
			Stats: manifest.Stats{
				L0: 1, L1: 1, L2: 2, L3: 1, L5: 1, Residual: 1,
			},
		},
	}
}

func renderString(t *testing.T, m *manifest.Doc, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, m, opts); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

func TestRenderGolden(t *testing.T) {
	opts := Options{IncludeSignals: true, Title: "固定输入报告"}
	out := renderString(t, fixtureDoc(), opts)

	// Determinism: the same inputs must produce byte-identical output.
	if again := renderString(t, fixtureDoc(), opts); again != out {
		t.Fatal("Render is not deterministic")
	}

	path := filepath.Join("testdata", "golden.html")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run: go test -run TestRenderGolden -update): %v", err)
	}
	if out != string(want) {
		t.Errorf("golden mismatch: got %d bytes, want %d bytes\n%s", len(out), len(want), firstDiff(out, string(want)))
	}
}

func firstDiff(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			lo := i - 80
			if lo < 0 {
				lo = 0
			}
			hi := i + 80
			if hi > n {
				hi = n
			}
			return "first diff at byte " + strconv.Itoa(i) + ":\n got: " + a[lo:hi] + "\nwant: " + b[lo:hi]
		}
	}
	return "one output is a prefix of the other"
}

func TestXSSEscaped(t *testing.T) {
	opts := Options{IncludeSignals: true, Title: `</title><script>alert(9)</script>`}
	out := renderString(t, fixtureDoc(), opts)

	// Hostile scan content must never appear as executable markup.
	for _, raw := range []string{
		"<script>alert(1)</script>",
		"<script>alert(2)</script>",
		"<script>alert(3)</script>",
		"<script>alert(9)</script>",
		`"><img src=x onerror=`,
		"</style><img",
	} {
		if strings.Contains(out, raw) {
			t.Errorf("raw scan content survived: %q", raw)
		}
	}
	// Escaped text may still contain the letters "onerror="; what must never
	// appear is a real tag or inline handler.
	if strings.Contains(out, "<img") {
		t.Error("raw <img tag appears in output")
	}
	if regexp.MustCompile(`(?i)<[a-z]+[^>]*\son[a-z]+\s*=`).MatchString(out) {
		t.Error("inline event handler appears in a real tag")
	}
	if strings.Contains(out, "innerHTML") {
		t.Error("output mentions innerHTML")
	}

	// Escaped forms are present instead.
	for _, esc := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;script&gt;alert(3)&lt;/script&gt;",
		"&lt;/style&gt;",
	} {
		if !strings.Contains(out, esc) {
			t.Errorf("expected escaped form %q missing", esc)
		}
	}

	// Exactly one real <title> and one real </style> (ours).
	if n := strings.Count(out, "<title>"); n != 1 {
		t.Errorf("<title> count = %d, want 1", n)
	}
	if n := strings.Count(out, "</title>"); n != 1 {
		t.Errorf("</title> count = %d, want 1", n)
	}
	if n := strings.Count(out, "</style>"); n != 1 {
		t.Errorf("</style> count = %d, want 1 (only the document stylesheet)", n)
	}
	if n := strings.Count(out, "<script"); n != 1 {
		t.Errorf("<script count = %d, want 1 (only the nonce-authorized report script)", n)
	}
}

func TestNoExternalRequests(t *testing.T) {
	doc := fixtureDoc()
	out := renderString(t, doc, Options{IncludeSignals: true, Title: "no external"})

	if !strings.Contains(out, `http-equiv="Content-Security-Policy"`) {
		t.Fatal("CSP meta missing")
	}
	if !strings.Contains(out, "default-src 'none'") {
		t.Fatal("CSP default-src 'none' missing")
	}
	if !strings.Contains(out, "script-src 'nonce-") {
		t.Fatal("CSP nonce missing")
	}

	// No external subresource of any kind.
	for _, bad := range []string{`src="http://`, `src="https://`, "<img", "<link ", "@import", "url(http"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
			t.Errorf("external subresource reference found: %q", bad)
		}
	}

	// Every http(s) href must be a source link with the required rel.
	allHref := regexp.MustCompile(`href="https?://`)
	sourceLinks := regexp.MustCompile(`<a href="https?://[^"]*" rel="noopener noreferrer" target="_blank">`)
	gotAll := len(allHref.FindAllString(out, -1))
	gotSource := len(sourceLinks.FindAllString(out, -1))
	if gotAll != gotSource {
		t.Errorf("found %d external hrefs but only %d are source links with rel=noopener noreferrer", gotAll, gotSource)
	}

	want := 0
	for _, u := range doc.Units {
		for _, s := range u.Signals {
			if s.URL != nil && (strings.HasPrefix(*s.URL, "http://") || strings.HasPrefix(*s.URL, "https://")) {
				want++
			}
		}
	}
	if gotSource != want {
		t.Errorf("source link count = %d, want %d (one per signal URL)", gotSource, want)
	}
}

func TestSecretsNeverPlaintext(t *testing.T) {
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: true})
	if !strings.Contains(out, "残留项未做内容级密检测") {
		t.Fatal("D-021 #7 residual warning missing")
	}
	// Only the non-secret prefix and the salted fingerprint are shown.
	if !strings.Contains(out, "sk-ant-…") {
		t.Error("masked prefix missing")
	}
	if !strings.Contains(out, "sha256:6c1e88f0") {
		t.Error("fingerprint missing")
	}
	// The report never receives a complete value, and must not invent one.
	if strings.Contains(out, "FOO_TOKEN=") {
		t.Error("locator with a value leaked")
	}
}

func TestRedactPaths(t *testing.T) {
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: true, RedactPaths: true})
	if strings.Contains(out, "alice") {
		t.Error("user name still present after --redact-paths")
	}
	if !strings.Contains(out, `~\.claude\projects`) {
		t.Error("root-relative ~ path missing")
	}
	if !strings.Contains(out, "路径已折叠") {
		t.Error("redaction banner missing")
	}
	// named-location URIs are not folded.
	if !strings.Contains(out, "wincred:Claude Code-credentials") {
		t.Error("named-location target was altered")
	}
}

func TestIncludeSignalsOff(t *testing.T) {
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: false})
	if regexp.MustCompile(`href="https?://`).MatchString(out) {
		t.Error("source links rendered even though IncludeSignals is false")
	}
	if strings.Contains(out, "结论与信号") {
		t.Error("signals section rendered even though IncludeSignals is false")
	}
}

func TestMobileStructure(t *testing.T) {
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: true})

	// No inline styles at all, so no inline min-width can overflow 400px.
	if strings.Contains(out, `style="`) {
		t.Error("inline style attribute found; mobile overflow cannot be structurally asserted")
	}
	re := regexp.MustCompile(`min-width\s*:\s*([0-9]+)px`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		n, _ := strconv.Atoi(m[1])
		if n > 400 {
			t.Errorf("min-width %dpx exceeds 400px", n)
		}
	}
	// Every table is horizontally contained.
	if strings.Count(out, `<div class="table-wrap">`) < strings.Count(out, "<table>") {
		t.Errorf("tables = %d, table-wrap containers = %d",
			strings.Count(out, "<table>"), strings.Count(out, `<div class="table-wrap">`))
	}
	if !strings.Contains(out, "overflow-x:auto") {
		t.Error("table overflow-x containment missing")
	}
	if !strings.Contains(out, "@media (max-width:480px)") {
		t.Error("narrow-viewport media query missing")
	}
	if !strings.Contains(out, "prefers-color-scheme: dark") {
		t.Error("dark theme variables missing")
	}
}

func TestPagination(t *testing.T) {
	old := pageSize
	pageSize = 2
	defer func() { pageSize = old }()

	// Six units aggregate to distinct paths, so the detail list paginates.
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: true})
	if n := strings.Count(out, `class="paged"`); n < 3 {
		t.Errorf("paged blocks = %d, want >= 3 with pageSize=2", n)
	}
	if !strings.Contains(out, "第 1–2 条") {
		t.Error("page range label missing")
	}
	if !strings.Contains(out, `id="expand-all"`) {
		t.Error("expand/collapse controls missing")
	}
	// The nonce-authorized script is the only script, and it never builds HTML.
	if strings.Contains(out, "innerHTML") || strings.Contains(out, "outerHTML") {
		t.Error("report script must not assign HTML")
	}
}

func TestRedactPathEdgeCases(t *testing.T) {
	m := fixtureDoc()
	cases := []struct{ in, want string }{
		{`C:\Users\alice\.claude\settings.json`, `~\.claude\settings.json`},
		{`c:\users\ALICE\.claude\x`, `~\.claude\x`},
		{`wincred:Claude Code-credentials`, `wincred:Claude Code-credentials`},
		{`D:\Users\bob\secret`, `D:\Users\…\secret`},
		{`/home/bob/secret`, `/home/…/secret`},
		{`/Users/bob/secret`, `/Users/…/secret`},
		{`D:\Study\repo\a`, `D:\Study\repo\a`},
	}
	for _, tc := range cases {
		if got := redactPath(tc.in, m); got != tc.want {
			t.Errorf("redactPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNilManifest(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, nil, Options{}); err == nil {
		t.Fatal("Render(nil) should fail")
	}
}

func TestLANBanner(t *testing.T) {
	out := renderString(t, fixtureDoc(), Options{IncludeSignals: true}.WithLAN(true))
	if !strings.Contains(out, "已暴露到局域网") {
		t.Error("LAN warning missing")
	}
}

func TestReportListsSkippedEntries(t *testing.T) {
	m := fixtureDoc()
	m.Header.Inputs.Options = &manifest.InputOptions{Selection: &manifest.Selection{
		Preset: "minimal", Include: []string{"skills"}, SessionsSince: "7d",
	}}
	m.Notes = append(m.Notes,
		manifest.Note{Code: "selection_skipped", Entry: "projects-transcripts", Category: "sessions",
			Detail: "preset minimal 未包含类别 sessions"},
		manifest.Note{Code: "selection_skipped", Entry: "projects-transcripts", Category: "sessions",
			Detail: "会话早于 --sessions-since 7d: /home/a/old.jsonl"},
	)
	html := renderString(t, m, Options{IncludeSignals: true})
	for _, want := range []string{
		`id="skipped"`, "本次未带走（1 类）", "sessions：2 条", "projects-transcripts",
		"preset minimal 未包含类别 sessions", "本次选择：preset minimal；include skills；会话仅 7d 内",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// The two skipped notes move out of the generic notes table.
	if strings.Contains(html, `>selection_skipped<`) {
		t.Error("selection_skipped still rendered in the notes table")
	}
}

func TestReportDefaultSelectionSummarisesSkipped(t *testing.T) {
	m := fixtureDoc()
	m.Notes = append(m.Notes,
		manifest.Note{Code: "selection_skipped", Entry: "projects-transcripts", Category: "sessions",
			Detail: "preset standard 未包含类别 sessions"},
	)
	html := renderString(t, m, Options{})
	for _, want := range []string{`id="skipped"`, "sessions：1 条", "--include sessions"} {
		if !strings.Contains(html, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	if strings.Contains(html, "preset standard 未包含类别 sessions") {
		t.Error("default selection expanded the skip reason rows")
	}
	if strings.Contains(html, `id="skipped"`) == false {
		t.Fatal("skipped section missing")
	}
}

func TestReportWithoutSelectionOmitsSkippedSection(t *testing.T) {
	m := fixtureDoc()
	html := renderString(t, m, Options{})
	if strings.Contains(html, `id="skipped"`) {
		t.Error("skipped section rendered without skipped notes")
	}
}

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRegistryMatchesSPEC(t *testing.T) {
	if err := validateRegistry(); err != nil {
		t.Fatal(err)
	}
	if len(allCases) != 27 {
		t.Fatalf("SPEC has 27 cases, registry has %d", len(allCases))
	}
	minimal := 0
	for _, c := range allCases {
		if c.Set == "minimal" {
			minimal++
		}
		if len(c.Paths) == 0 {
			t.Errorf("%s: no paths declared", c.ID)
		}
		hasHome := false
		for _, p := range c.Paths {
			if p == "home" || strings.HasPrefix(p, "home/") {
				hasHome = true
			}
			if filepath.IsAbs(p) || strings.Contains(p, `\`) {
				t.Errorf("%s: path %q is absolute or uses backslashes", c.ID, p)
			}
		}
		if !hasHome {
			t.Errorf("%s: home/ missing from paths", c.ID)
		}
		if len(c.Repos) > 0 {
			for _, r := range c.Repos {
				found := false
				for _, p := range c.Paths {
					if strings.HasPrefix(p, "repos/"+r+"/") || p == "repos/"+r {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: repo %q declared but no path below it", c.ID, r)
				}
			}
		}
		if strings.TrimSpace(c.Expect) == "" {
			t.Errorf("%s: empty expect.yaml", c.ID)
		}
	}
	if minimal != 10 {
		t.Errorf("minimal set must be C01-C10 (10 cases), got %d", minimal)
	}
	for i, c := range allCases {
		want := "C" + pad2(i+1) + "-"
		if !strings.HasPrefix(c.ID, want) {
			t.Errorf("case order: position %d is %s, want prefix %s", i+1, c.ID, want)
		}
	}
}

func pad2(i int) string {
	if i < 10 {
		return "0" + itoa(i)
	}
	return itoa(i)
}

func TestIndexUpToDate(t *testing.T) {
	want, err := buildIndex()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(corpusDir(), "corpus.yaml"))
	if err != nil {
		t.Fatalf("corpus.yaml missing (run: go run ./gen -index): %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("corpus.yaml drifted from registry; run: go run ./gen -index")
	}
}

func TestCanaryConsistency(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpusDir(), "canaries.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), canaryToken) {
		t.Fatal("canaryToken constant is absent from canaries.yaml")
	}
	if !strings.HasPrefix(canaryToken, "sk-ant-") || !strings.Contains(canaryToken, "C0RPUSCANARY") {
		t.Fatalf("canary %q is not obviously fake", canaryToken)
	}
}

// TestCasesBuildIdempotently builds every case twice on this host, checks the
// declared relative layout exactly, then compares the two trees.
func TestCasesBuildIdempotently(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	plat := hostPlatform()
	for _, c := range allCases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			if os.Getenv("CORPUS_SKIP_BIG") != "" && c.Big {
				t.Skip("CORPUS_SKIP_BIG")
			}
			if !supports(c, plat) {
				t.Skipf("platform %s not in %v", plat, c.Platforms)
			}
			if err := capabilityCheck(c); err != nil {
				t.Skip(err)
			}
			base, err := os.MkdirTemp("", "corpus-test-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(base)
			first, err := materialize(c, filepath.Join(base, "a"))
			if err != nil {
				if isSkip(err) {
					t.Skip(err)
				}
				t.Fatalf("build: %v", err)
			}
			second, err := materialize(c, filepath.Join(base, "b"))
			if err != nil {
				t.Fatalf("second build: %v", err)
			}
			compareTrees(t, first, second)

			expect, err := os.ReadFile(filepath.Join(first, "expect.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			checkMatchesExist(t, c, first, string(expect))
			checkContent(t, c, first, string(expect))
		})
	}
}

type entry struct {
	rel, kind, hash string
	size            int64
	mtime           int64
	link            string
}

func readTree(t *testing.T, root string) []entry {
	t.Helper()
	snaps, err := walkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []entry
	for _, s := range snaps {
		e := entry{rel: s.rel, size: s.size}
		full := filepath.Join(root, filepath.FromSlash(s.rel))
		info, err := os.Lstat(hostPath(full))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case s.isLink:
			e.kind = "link"
			target, err := os.Readlink(hostPath(full))
			if err != nil {
				// Junctions are reparse points; fall back to the recorded target.
				target = "?"
			}
			e.link = normalizeBase(target, root)
		case s.isDir:
			e.kind = "dir"
			e.mtime = info.ModTime().UnixNano()
		default:
			e.kind = "file"
			e.mtime = info.ModTime().UnixNano()
			h, err := hashFile(full, s.size)
			if err != nil {
				t.Fatal(err)
			}
			e.hash = h
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

func normalizeBase(p, root string) string {
	clean := filepath.ToSlash(p)
	base := filepath.ToSlash(filepath.Dir(root))
	return strings.ReplaceAll(clean, base, "<base>")
}

func compareTrees(t *testing.T, a, b string) {
	t.Helper()
	ta := readTree(t, a)
	tb := readTree(t, b)
	if len(ta) != len(tb) {
		t.Fatalf("tree size differs: %d vs %d", len(ta), len(tb))
	}
	for i := range ta {
		x, y := ta[i], tb[i]
		if x.rel != y.rel {
			t.Fatalf("path differs: %q vs %q", x.rel, y.rel)
		}
		if x.kind != y.kind || x.size != y.size {
			t.Errorf("%s: kind/size differs (%s/%d vs %s/%d)", x.rel, x.kind, x.size, y.kind, y.size)
			continue
		}
		if x.kind == "link" {
			if x.link != y.link {
				t.Errorf("%s: link target differs: %q vs %q", x.rel, x.link, y.link)
			}
			continue
		}
		if x.mtime != y.mtime {
			t.Errorf("%s: mtime differs: %d vs %d", x.rel, x.mtime, y.mtime)
		}
		if x.kind == "file" {
			if c := caseByID(caseIDFromPath(a)); c != nil && c.VolatileContent {
				continue
			}
			if x.hash != y.hash {
				t.Errorf("%s: content differs", x.rel)
			}
		}
	}
}

func caseIDFromPath(root string) string { return filepath.Base(root) }

var matchRE = regexp.MustCompile(`match: "([^"]+)"`)

// checkMatchesExist resolves every DSL match against the case root.
func checkMatchesExist(t *testing.T, c *Case, root, expect string) {
	t.Helper()
	all, err := walkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matchRE.FindAllStringSubmatch(expect, -1) {
		pattern := m[1]
		if filepath.IsAbs(pattern) {
			t.Errorf("%s: match %q is absolute", c.ID, pattern)
		}
		hit := false
		for _, s := range all {
			if globMatch(strings.Split(pattern, "/"), strings.Split(s.rel, "/")) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("%s: match %q hits nothing", c.ID, pattern)
		}
	}
	if strings.Contains(expect, `match: "/`) || strings.Contains(expect, `match: "C:`) {
		t.Errorf("%s: absolute path in expect.yaml", c.ID)
	}
}

// checkContent enforces the credential rules: the canary appears only in C02,
// and no fixture file embeds the absolute temp path.
func checkContent(t *testing.T, c *Case, root, expect string) {
	t.Helper()
	if strings.Contains(expect, "sk-ant-") != (c.ID == "C02-mcp-fake-token") {
		t.Errorf("%s: canary in expect.yaml out of place", c.ID)
	}
	if c.Big {
		return
	}
	snaps, err := walkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snaps {
		if s.isDir || s.isLink || s.size > 2<<20 {
			continue
		}
		raw, err := os.ReadFile(hostPath(filepath.Join(root, filepath.FromSlash(s.rel))))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		hasCanary := strings.Contains(text, "sk-ant-")
		wantCanary := c.ID == "C02-mcp-fake-token" && (s.rel == "repos/repo-a/.mcp.json" || s.rel == "expect.yaml")
		if hasCanary != wantCanary {
			t.Errorf("%s/%s: canary present=%v", c.ID, s.rel, hasCanary)
		}
		if c.ID != "C14-sqlite-wal" && strings.Contains(text, filepath.ToSlash(root)) {
			t.Errorf("%s/%s: absolute temp path leaked into content", c.ID, s.rel)
		}
	}
}

// globMatch matches path segments; "**" matches zero or more segments.
func globMatch(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(path); i++ {
			if globMatch(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	ok, err := filepath.Match(pattern[0], path[0])
	if err != nil || !ok {
		return false
	}
	return globMatch(pattern[1:], path[1:])
}

func TestListIncludesPlatforms(t *testing.T) {
	for _, c := range allCases {
		if len(c.Platforms) == 0 {
			t.Fatalf("%s: no platform requirement", c.ID)
		}
	}
	// A tiny guard against time-based nondeterminism.
	if fixedTime.Unix() != time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatal("fixed time drifted")
	}
}

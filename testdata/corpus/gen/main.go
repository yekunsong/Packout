// Command gen materialises the packout bomb corpus described by ../SPEC.md.
//
// Usage:
//
//	go run ./gen -list                 list case id, platforms and capabilities
//	go run ./gen <case_id>             build one case in a fresh temp dir, print root
//	go run ./gen -all [-skip-big=false] build every case under one temp dir
//	go run ./gen -base testdata/corpus/cases <case_id>...  build into the repo
//	go run ./gen -index                rewrite ../corpus.yaml from the registry
//
// The generator only writes below testdata/corpus/. Cases are self-contained:
// each root printed by the tool holds home/, optional repos/ and optional
// outside/, plus the case's own case.yaml and expect.yaml.
//
// Exit status: 0 when every requested case was built or legitimately skipped,
// 1 when at least one case failed. A failure always names case_id and reason.
package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	generatorVersion = "1"
	// fixedTime is written to every produced file and directory so two runs
	// compare byte-for-byte.
	fixedMoment = "2026-01-01T00:00:00Z"
)

var fixedTime = mustParseTime(fixedMoment)

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// skipError marks a case that cannot be built on this host for an expected
// reason (missing capability, foreign platform). It is not a failure.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

func skipf(format string, args ...any) error {
	return &skipError{reason: fmt.Sprintf(format, args...)}
}

func isSkip(err error) bool {
	var s *skipError
	return errors.As(err, &s)
}

// root binds a case directory to a profile role (SPEC §2 scan.roots).
type root struct {
	Role string
	Path string // case-root relative, slash separated
	Name string // manifest instance name; empty means Role
}

// Case is one corpus entry. Build writes the tree; Expect is the assertion DSL.
type Case struct {
	ID            string
	Title         string
	Set           string // minimal | full
	Platforms     []string
	Requires      []string
	Big           bool // needs the -skip-big guard / disk preflight
	BudgetWallMS  int
	BudgetRSSMiB  int
	AllowNew      []string
	AllowDirMtime []string
	Leftovers     []string
	Deferred      []string
	Repos         []string // repo names, mirrored as repos/<name> roots
	Expect        string
	// VolatileContent cases are compared on paths, kinds and sizes only
	// (sqlite pages and -shm are not byte-stable).
	VolatileContent bool
	Paths           []string // static expected paths; dynamic ones are added by Build
	Build           func(*Ctx) error
}

var (
	allCases []*Case
	idRE     = regexp.MustCompile(`^C[0-9]{2}-[a-z0-9-]+$`)
)

func register(c *Case) {
	if c.BudgetWallMS == 0 {
		c.BudgetWallMS = 10000
	}
	if c.BudgetRSSMiB == 0 {
		c.BudgetRSSMiB = 256
	}
	if c.Paths == nil {
		c.Paths = []string{}
	}
	allCases = append(allCases, c)
}

func caseByID(id string) *Case {
	for _, c := range allCases {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func hostPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "win32"
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	}
	return runtime.GOOS
}

func supports(c *Case, platform string) bool {
	for _, p := range c.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// capabilityCheck reports whether requires are satisfiable on this host.
func capabilityCheck(c *Case) error {
	for _, req := range c.Requires {
		switch req {
		case "sqlite3":
			if _, err := lookPath("sqlite3"); err != nil {
				return skipf("no_sqlite3")
			}
		case "sparse":
			if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
				return skipf("no_sparse")
			}
		case "mklink-junction", "mklink-symlink", "fsutil", "fsutil-case", "longpath":
			if runtime.GOOS != "windows" {
				return skipf("not_windows:%s", req)
			}
		case "":
		default:
			return fmt.Errorf("unknown requirement %q", req)
		}
	}
	return nil
}

func main() {
	list := flag.Bool("list", false, "list cases with platform and capability requirements")
	all := flag.Bool("all", false, "build every case into one temp directory")
	skipBig := flag.Bool("skip-big", true, "with -all, skip cases marked big (C22)")
	base := flag.String("base", "", "parent directory instead of os.MkdirTemp")
	mkIndex := flag.Bool("index", false, "rewrite ../corpus.yaml from the registry")
	flag.Parse()

	if err := validateRegistry(); err != nil {
		fatalf("%v", err)
	}
	if *list {
		printList()
		return
	}
	if *mkIndex {
		if err := writeIndex(); err != nil {
			fatalf("index: %v", err)
		}
		return
	}

	plat := hostPlatform()
	selected := flag.Args()
	if *all {
		selected = nil
		for _, c := range allCases {
			selected = append(selected, c.ID)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gen [-list] [-all] [-skip-big] [-base dir] <case_id>...")
		os.Exit(2)
	}

	parent := *base
	if parent == "" {
		p, err := os.MkdirTemp("", "packout-corpus-")
		if err != nil {
			fatalf("tempdir: %v", err)
		}
		parent = p
	} else {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			fatalf("base: %v", err)
		}
	}

	failed := 0
	built := 0
	for _, id := range selected {
		c := caseByID(id)
		if c == nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: unknown case id\n", id)
			failed++
			continue
		}
		if !supports(c, plat) {
			fmt.Printf("SKIP %s: platform %s not in %v\n", id, plat, c.Platforms)
			continue
		}
		if *all && *skipBig && c.Big {
			fmt.Printf("SKIP %s: big (use -skip-big=false)\n", id)
			continue
		}
		if err := capabilityCheck(c); err != nil {
			fmt.Printf("SKIP %s: %v\n", id, err)
			continue
		}
		if c.Big {
			if err := diskPreflight(parent, 5<<30); err != nil {
				fmt.Printf("SKIP %s: %v\n", id, err)
				continue
			}
		}
		rootPath, err := materialize(c, parent)
		if err != nil {
			if isSkip(err) {
				fmt.Printf("SKIP %s: %v\n", id, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", id, err)
			failed++
			continue
		}
		built++
		fmt.Println(rootPath)
	}
	fmt.Fprintf(os.Stderr, "built %d, failed %d, parent %s\n", built, failed, parent)
	if failed > 0 {
		os.Exit(1)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen: "+format+"\n", args...)
	os.Exit(1)
}

func printList() {
	for _, c := range allCases {
		req := "-"
		if len(c.Requires) > 0 {
			req = strings.Join(c.Requires, ",")
		}
		big := ""
		if c.Big {
			big = "\tbig"
		}
		fmt.Printf("%s\tplatforms=%s\trequires=%s\tset=%s%s\n",
			c.ID, strings.Join(c.Platforms, ","), req, c.Set, big)
	}
}

func validateRegistry() error {
	seen := map[string]bool{}
	for _, c := range allCases {
		if !idRE.MatchString(c.ID) {
			return fmt.Errorf("bad case id %q", c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Set != "minimal" && c.Set != "full" {
			return fmt.Errorf("%s: bad set %q", c.ID, c.Set)
		}
		if len(c.Platforms) == 0 {
			return fmt.Errorf("%s: empty platforms", c.ID)
		}
		for _, req := range c.Requires {
			switch req {
			case "sqlite3", "sparse", "mklink-junction", "mklink-symlink", "fsutil", "fsutil-case", "longpath":
			default:
				return fmt.Errorf("%s: unknown requirement %q", c.ID, req)
			}
		}
		if c.Build == nil {
			return fmt.Errorf("%s: nil Build", c.ID)
		}
		for _, p := range append(append([]string{}, c.Paths...), "home") {
			if filepath.IsAbs(p) || strings.Contains(p, "\\") {
				return fmt.Errorf("%s: non-relative or non-slash path %q", c.ID, p)
			}
		}
	}
	return nil
}

// materialize builds one case. A skipError from Build means the host cannot
// represent the case; everything else is a failure.
func materialize(c *Case, parent string) (rootPath string, err error) {
	rootPath = filepath.Join(parent, c.ID)
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return rootPath, err
	}
	ctx := newCtx(rootPath, c)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if err := c.Build(ctx); err != nil {
		return rootPath, err
	}
	if err := ctx.ensureHome(); err != nil {
		return rootPath, err
	}
	// Header files are part of the case and are written before the tree is
	// frozen so they get the same deterministic timestamps.
	if err := os.WriteFile(filepath.Join(rootPath, "case.yaml"), []byte(c.caseYAML()), 0o644); err != nil {
		return rootPath, err
	}
	ctx.exp["case.yaml"] = true
	if err := os.WriteFile(filepath.Join(rootPath, "expect.yaml"), []byte(c.expectedYAML()), 0o644); err != nil {
		return rootPath, err
	}
	ctx.exp["expect.yaml"] = true

	if err := freezeTimes(rootPath); err != nil {
		return rootPath, err
	}
	if err := checkTree(rootPath, ctx.exp); err != nil {
		return rootPath, err
	}
	return rootPath, nil
}

func (c *Case) caseYAML() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# generated by testdata/corpus/gen (version %s) - do not edit\n", generatorVersion)
	fmt.Fprintf(&b, "id: %s\n", c.ID)
	fmt.Fprintf(&b, "title: %q\n", c.Title)
	fmt.Fprintf(&b, "set: %s\n", c.Set)
	fmt.Fprintf(&b, "platforms: [%s]\n", strings.Join(c.Platforms, ", "))
	if len(c.Requires) == 0 {
		b.WriteString("requires: []\n")
	} else {
		fmt.Fprintf(&b, "requires: [%s]\n", strings.Join(c.Requires, ", "))
	}
	profile := "claude-code"
	if c.ID == "C26-junction-mutual-cycle-follow" {
		profile = "corpus-follow"
	}
	b.WriteString("scan:\n")
	fmt.Fprintf(&b, "  profile: %s\n", profile)
	b.WriteString("  roots:\n")
	b.WriteString("    - {role: home, path: home}\n")
	for _, r := range c.Repos {
		fmt.Fprintf(&b, "    - {role: repo, path: repos/%s, name: %s}\n", r, r)
	}
	b.WriteString("  options: {}\n")
	fmt.Fprintf(&b, "budget: {wall_ms: %d, max_rss_mib: %d}\n", c.BudgetWallMS, c.BudgetRSSMiB)
	b.WriteString(yamlList("allow_new", c.AllowNew))
	b.WriteString(yamlList("allow_dir_mtime", c.AllowDirMtime))
	b.WriteString(yamlList("leftovers", c.Leftovers))
	b.WriteString(yamlList("deferred", c.Deferred))
	if c.Big {
		b.WriteString("big: true\n")
	}
	return b.String()
}

func yamlList(key string, vals []string) string {
	if len(vals) == 0 {
		return key + ": []\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", key)
	for _, v := range vals {
		fmt.Fprintf(&b, "  - %q\n", v)
	}
	return b.String()
}

func (c *Case) expectedYAML() string {
	var b strings.Builder
	b.WriteString("# generated by testdata/corpus/gen - do not edit\n")
	b.WriteString("# match/absent are relative to the case root (SPEC §5).\n")
	b.WriteString(c.Expect)
	if !strings.HasSuffix(c.Expect, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// writeIndex regenerates ../corpus.yaml, including the canary file digest.
func writeIndex() error {
	out, err := buildIndex()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(corpusDir(), "corpus.yaml"), out, 0o644)
}

// buildIndex renders corpus.yaml (deterministic; also used by the drift test).
func buildIndex() ([]byte, error) {
	canaryPath := filepath.Join(corpusDir(), "canaries.yaml")
	raw, err := os.ReadFile(canaryPath)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# generated by testdata/corpus/gen - do not edit\n")
	b.WriteString("version: 1\n")
	fmt.Fprintf(&b, "generator_version: %s\n", generatorVersion)
	fmt.Fprintf(&b, "canaries_sha256: %x\n", sha256.Sum256(raw))
	var total int64
	type row struct {
		id  string
		set string
		est int64
	}
	rows := make([]row, 0, len(allCases))
	for _, c := range allCases {
		est := estimateBytes(c)
		total += est
		rows = append(rows, row{c.ID, c.Set, est})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	b.WriteString("cases:\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  - {id: %s, set: %s, est_bytes: %d}\n", r.id, r.set, r.est)
	}
	fmt.Fprintf(&b, "total_est_bytes: %d\n", total)
	return []byte(b.String()), nil
}

// estimateBytes is a coarse disk budget per case; only big cases matter.
func estimateBytes(c *Case) int64 {
	switch c.ID {
	case "C22-huge-jsonl-4g":
		return 4 << 30
	case "C12-sparse-file":
		return 1 << 20 // apparent 1 GiB is sparse on both platforms
	}
	return 1 << 20
}

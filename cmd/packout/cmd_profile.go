package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/profile"
)

type profileConfig struct {
	sub    string
	name   string
	roots  rootList
	strict bool
	json   bool
	quiet  bool
}

const (
	probePresent        = "present"
	probeAbsent         = "absent"
	probeNotEvaluable   = "not_evaluable"
	probeRootUnresolved = "root_unresolved"
)

type probeRow struct {
	Entry        string `json:"entry"`
	PartID       string `json:"part_id,omitempty"`
	Root         string `json:"root,omitempty"`
	ResolvedPath string `json:"resolved_path,omitempty"`
	Status       string `json:"status"`
}

type probeReport struct {
	Profile        string     `json:"profile"`
	Rows           []probeRow `json:"rows"`
	Entries        int        `json:"entries"`
	Present        int        `json:"present"`
	Absent         int        `json:"absent"`
	NotEvaluable   int        `json:"not_evaluable"`
	RootUnresolved int        `json:"root_unresolved"`
}

type profileTestSummary struct {
	Profile  string   `json:"profile"`
	Passed   bool     `json:"passed"`
	Checks   int      `json:"checks"`
	Failures []string `json:"failures,omitempty"`
}

func runProfile(ctx context.Context, cfg profileConfig, stdout, stderr io.Writer) int {
	switch cfg.sub {
	case "list":
		return runProfileList(cfg, stdout, stderr)
	case "test":
		return runProfileTest(ctx, cfg, stdout, stderr)
	case "probe":
		return runProfileProbe(ctx, cfg, stdout, stderr)
	case "":
		r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
		return r.usage("profile 需要子命令：list | probe | test")
	default:
		r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
		return r.usage("未知 profile 子命令 %q", cfg.sub)
	}
}

func runProfileList(cfg profileConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	names := profile.BuiltinNames()
	r.value(struct {
		Builtin []string `json:"builtin"`
		Schema  string   `json:"schema"`
	}{names, profile.Schema})
	for _, n := range names {
		r.info("%s（内置，schema %s）", n, profile.Schema)
	}
	return exitOK
}

func runProfileTest(ctx context.Context, cfg profileConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	if cfg.name == "" {
		return r.usage("profile test 需要 profile 名")
	}
	p, err := loadProfile(cfg.name, stderr)
	if err != nil {
		return r.usage("profile: %v", err)
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	res, err := profile.RunSelfTest(p, "")
	if err != nil {
		return r.fail(exitUsage, "profile test: %v", err)
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	sum := profileTestSummary{Profile: p.Name, Passed: res.Passed, Checks: res.Checks}
	for _, f := range res.Failures {
		sum.Failures = append(sum.Failures, f.Error())
	}
	r.value(sum)
	if !res.Passed {
		for _, f := range res.Failures {
			r.warn("packout: FAIL %v", f)
		}
		return r.fail(exitPartial, "profile %s selftest 失败：%d 项断言中 %d 项失败", p.Name, res.Checks, len(res.Failures))
	}
	r.info("profile %s selftest 通过：%d 项断言", p.Name, res.Checks)
	return exitOK
}

type probeRoot struct {
	name string
	role string
	path string
	err  error
}

// probeRoots mirrors scan's root resolution (including role#2 numbering) but
// keeps an expansion failure as a row instead of dropping the role.
func probeRoots(p *profile.Profile, list rootList) []probeRoot {
	bindings := list
	if len(bindings) == 0 {
		for _, role := range p.RootOrder {
			bindings = append(bindings, rootFlag{role: role})
		}
	}
	seen := make(map[string]int)
	var out []probeRoot
	for _, b := range bindings {
		seen[b.role]++
		name := b.role
		if seen[b.role] > 1 {
			name = b.role + "#" + itoa(seen[b.role])
		}
		pr := probeRoot{name: name, role: b.role}
		tmpl := b.path
		if tmpl == "" {
			r, ok := p.Roots[b.role]
			if !ok {
				pr.err = errString("role 未被 profile 声明")
				out = append(out, pr)
				continue
			}
			tmpl = r.ForOS(runtime.GOOS)
		}
		expanded, err := profile.ExpandTemplate(tmpl)
		if err != nil {
			pr.err = err
			out = append(out, pr)
			continue
		}
		abs, err := fsx.Abs(filepath.FromSlash(expanded))
		if err != nil {
			pr.err = err
			out = append(out, pr)
			continue
		}
		pr.path = abs
		out = append(out, pr)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

type errString string

func (e errString) Error() string { return string(e) }

// entryAppliesOS is the scan rule: an entry with os is limited to it.
func entryAppliesOS(e *profile.Entry) bool {
	if len(e.OS) == 0 {
		return true
	}
	for _, o := range e.OS {
		if o == runtime.GOOS {
			return true
		}
	}
	return false
}

// runProfileProbe is a read-only drift check: Lstat, bounded directory
// enumeration and named-location presence. It never reads file content and
// never writes the profile.
func runProfileProbe(ctx context.Context, cfg profileConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	if cfg.name == "" {
		return r.usage("profile probe 需要 profile 名")
	}
	p, err := loadProfile(cfg.name, stderr)
	if err != nil {
		return r.usage("profile: %v", err)
	}
	if _, err := cfg.roots.bindings(p); err != nil {
		return r.usage("%v", err)
	}
	roots := probeRoots(p, cfg.roots)

	rep := probeReport{Profile: p.Name}
	for _, e := range p.Entries {
		if ctx.Err() != nil {
			return exitFromCtx(r, ctx)
		}
		if !entryAppliesOS(e) {
			continue
		}
		rows := probeEntry(e, roots)
		for _, row := range rows {
			rep.Entries++
			switch row.Status {
			case probePresent:
				rep.Present++
			case probeAbsent:
				rep.Absent++
			case probeNotEvaluable:
				rep.NotEvaluable++
			case probeRootUnresolved:
				rep.RootUnresolved++
			}
			rep.Rows = append(rep.Rows, row)
			if !cfg.json {
				r.info("%s %s%s %s -> %s", row.Status, row.Entry, partSuffix(row.PartID), rootPart(row.Root), row.ResolvedPath)
			}
		}
	}
	r.value(rep)
	if !cfg.json {
		r.info("entries=%d present=%d absent=%d not_evaluable=%d root_unresolved=%d",
			rep.Entries, rep.Present, rep.Absent, rep.NotEvaluable, rep.RootUnresolved)
	}
	if rep.Absent > 0 {
		return r.fail(exitPartial, "profile probe 发现 %d 条漂移（absent）", rep.Absent)
	}
	if cfg.strict && rep.NotEvaluable > 0 {
		return r.fail(exitPartial, "profile probe 有 %d 条不可判定（--strict 视为失败）", rep.NotEvaluable)
	}
	return exitOK
}

func partSuffix(part string) string {
	if part == "" {
		return ""
	}
	return " part=" + part
}

func rootPart(root string) string {
	if root == "" {
		return ""
	}
	return " root=" + root
}

// probeEntry evaluates one entry into rows, one per part when it has parts.
func probeEntry(e *profile.Entry, roots []probeRoot) []probeRow {
	var instances []probeRoot
	switch {
	case e.Root == "":
		// Absolute declaration: one row, no root instance (scan does the same).
		instances = []probeRoot{{}}
	case len(roots) == 0:
		return []probeRow{{Entry: e.ID, Root: e.Root, Status: probeRootUnresolved}}
	default:
		for _, rt := range roots {
			if rt.role == e.Root {
				instances = append(instances, rt)
			}
		}
	}
	if len(instances) == 0 {
		return []probeRow{{Entry: e.ID, Root: e.Root, Status: probeRootUnresolved}}
	}
	var rows []probeRow
	for _, rt := range instances {
		status, path := probeOne(e, rt)
		if len(e.Parts) == 0 {
			rows = append(rows, probeRow{Entry: e.ID, Root: rt.name, ResolvedPath: path, Status: status})
			continue
		}
		for _, part := range e.Parts {
			rows = append(rows, probeRow{Entry: e.ID, PartID: part.ID, Root: rt.name, ResolvedPath: path, Status: status})
		}
	}
	return rows
}

func probeOne(e *profile.Entry, rt probeRoot) (status, path string) {
	if rt.err != nil {
		return probeRootUnresolved, ""
	}
	base := rt.path
	switch e.Kind {
	case profile.KindNamedLocation:
		return probeNamedLocation(e)
	case profile.KindCatchAll:
		if e.Under != "" {
			base = filepath.Join(base, filepath.FromSlash(e.Under))
		}
		if _, err := fsx.Lstat(base); err == nil {
			return probePresent, base
		}
		return probeAbsent, base
	case profile.KindGlobGroup:
		status = probeAbsent
		paths := e.Paths
		if len(paths) == 0 {
			paths = []string{e.Path}
		}
		for _, pat := range paths {
			expanded, err := profile.ExpandTemplate(pat)
			if err != nil {
				status = probeNotEvaluable
				continue
			}
			if filepath.IsAbs(filepath.FromSlash(expanded)) {
				abs, err := fsx.Abs(filepath.FromSlash(expanded))
				if err == nil {
					if _, err := fsx.Lstat(abs); err == nil {
						return probePresent, abs
					}
				}
				continue
			}
			ok, found, err := probeGlob(base, pat)
			if err != nil {
				status = probeNotEvaluable
				continue
			}
			if ok {
				return probePresent, found
			}
		}
		return status, ""
	case profile.KindDir:
		p, err := resolveDecl(base, rt.path, e.Path)
		if err != nil {
			return probeNotEvaluable, ""
		}
		info, err := fsx.Lstat(p)
		if err == nil && info.IsDir {
			return probePresent, p
		}
		return probeAbsent, p
	default: // file
		p, err := resolveDecl(base, rt.path, e.Path)
		if err != nil {
			return probeNotEvaluable, ""
		}
		info, err := fsx.Lstat(p)
		if err == nil {
			if e.Kind == profile.KindFile && !info.IsDir {
				return probePresent, p
			}
			if info.IsDir {
				return probePresent, p
			}
			return probeAbsent, p
		}
		return probeAbsent, p
	}
}

func resolveDecl(base, root, decl string) (string, error) {
	expanded, err := profile.ExpandTemplate(decl)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(filepath.FromSlash(expanded)) {
		return fsx.Abs(filepath.FromSlash(expanded))
	}
	return filepath.Join(root, filepath.FromSlash(expanded)), nil
}

// probeGlob expands at most probeGlobDepth levels below the static prefix and
// reports the first match.
const probeGlobDepth = 2

func probeGlob(base, pattern string) (bool, string, error) {
	expanded, err := profile.ExpandTemplate(pattern)
	if err != nil {
		return false, "", err
	}
	pattern = strings.ReplaceAll(expanded, "\\", "/")
	segs := strings.Split(strings.Trim(pattern, "/"), "/")
	prefix := make([]string, 0, len(segs))
	for _, s := range segs {
		if profile.ContainsGlob(s) {
			break
		}
		prefix = append(prefix, s)
	}
	start := base
	if len(prefix) > 0 {
		start = filepath.Join(base, filepath.FromSlash(strings.Join(prefix, "/")))
	}
	var found string
	var walk func(dir string, depth int) bool
	walk = func(dir string, depth int) bool {
		rel, err := fsx.Rel(base, dir)
		if err == nil {
			rel = filepath.ToSlash(rel)
			if rel == "." {
				rel = ""
			}
			if rel != "" && profile.MatchGlob(pattern, rel) {
				found = dir
				return true
			}
		}
		if depth >= probeGlobDepth {
			return false
		}
		names, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		for _, de := range names {
			child := filepath.Join(dir, de.Name())
			if de.IsDir() {
				if walk(child, depth+1) {
					return true
				}
				continue
			}
			crel, err := fsx.Rel(base, child)
			if err == nil && profile.MatchGlob(pattern, filepath.ToSlash(crel)) {
				found = child
				return true
			}
		}
		return false
	}
	if walk(start, 0) {
		return true, found, nil
	}
	return false, "", nil
}

func probeNamedLocation(e *profile.Entry) (string, string) {
	loc, ok := e.Locator.ForOS(runtime.GOOS)
	if !ok || loc == "" {
		return probeNotEvaluable, ""
	}
	scheme, opaque := loc, ""
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		scheme, opaque = loc[:i], loc[i+1:]
	}
	opaque = strings.Join(strings.Fields(opaque), " ")
	probe, _ := e.Probe.ForOS(runtime.GOOS)
	if probe == "" {
		switch scheme {
		case "env":
			probe = "env"
		case "file":
			probe = "file-probe"
		case "keychain", "wincred", "registry":
			probe = scheme
		}
	}
	switch probe {
	case "env":
		if _, ok := os.LookupEnv(opaque); ok {
			return probePresent, scheme + ":" + opaque
		}
		return probeNotEvaluable, scheme + ":" + opaque
	case "file-probe":
		expanded, err := profile.ExpandTemplate(opaque)
		if err != nil {
			return probeNotEvaluable, scheme + ":" + opaque
		}
		abs, err := fsx.Abs(filepath.FromSlash(expanded))
		if err != nil {
			return probeNotEvaluable, scheme + ":" + opaque
		}
		if _, err := fsx.Lstat(abs); err == nil {
			return probePresent, abs
		}
		return probeAbsent, abs
	default:
		// No P0 probe implementation for keychain/wincred/registry.
		return probeNotEvaluable, scheme + ":" + opaque
	}
}

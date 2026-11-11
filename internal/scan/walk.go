package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
)

// declarePass implements pass 1 of docs/design-scan.md: expand every
// declaration, Lstat the hit, and remember it. Nothing is written here; the
// winner selection below turns hits into Units.
func (s *scanner) declarePass(ctx context.Context) {
	matches := make(map[string]int) // entry\x00pattern -> count
	for _, e := range s.cfg.Profile.Entries {
		if !s.entryApplies(e) {
			continue
		}
		if ctx.Err() != nil {
			s.complete = false
			return
		}
		if e.Kind == profile.KindNamedLocation {
			for _, r := range s.entryRoots(e) {
				s.declareNamedLocation(e, r)
			}
			continue
		}
		for _, r := range s.entryRoots(e) {
			switch e.Kind {
			case profile.KindFile:
				p, rr, err := s.rootResolver(r, e.Path)
				if err != nil {
					continue
				}
				s.addCandidate(e, rr, p, "", "", nil, false, matches)
			case profile.KindDir:
				p, rr, err := s.rootResolver(r, e.Path)
				if err != nil {
					continue
				}
				base := p
				var relBase string
				if rr != nil {
					relBase = s.relOf(rr, base)
				}
				mx := s.cfg.Profile.EffectiveMaxDepth(e)
				seen := make(map[string]bool)
				s.walk(ctx, e, rr, base, relBase, 0, mx, seen, nil, func(path, rel string, info *fsx.Info) {
					if path == base || !s.entryOS(e) {
						return
					}
					s.addCandidate(e, rr, path, rel, "", info, false, matches)
				})
			case profile.KindGlobGroup:
				for _, pat := range e.Paths {
					absDecl, err := isAbsDecl(pat)
					if err != nil {
						continue
					}
					if absDecl {
						p, rr, err := s.rootResolver(r, pat)
						if err != nil {
							continue
						}
						s.addCandidate(e, rr, p, s.relOf(rr, p), pat, nil, false, matches)
						continue
					}
					if r == nil {
						continue
					}
					s.walkGlob(ctx, e, r, pat, matches)
				}
			}
		}
	}
	s.selectAndProduce(ctx, matches)
}

func (s *scanner) entryOS(e *profile.Entry) bool { return true }

func isAbsDecl(p string) (bool, error) {
	expanded, err := profile.ExpandTemplate(p)
	if err != nil {
		return false, err
	}
	return filepath.IsAbs(filepath.FromSlash(expanded)), nil
}

func (s *scanner) addCandidate(e *profile.Entry, root *rootInstance, path, rel, pat string, info *fsx.Info, cycle bool, matches map[string]int) {
	if len(path) > maxPathBytes {
		s.addNote(manifest.Note{Code: "path_too_long", Entry: e.ID, Detail: path})
		return
	}
	var err error
	if info == nil {
		info, err = fsx.Lstat(path)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// 声明了但不存在是常态（多数用户没有 .mcp.json），不是错误。
			s.addNote(manifest.Note{Code: "not_found", Entry: e.ID, Detail: path})
		} else {
			s.errs++
			s.addNote(manifest.Note{Code: "read_error", Entry: e.ID, Detail: err.Error()})
		}
		if pat != "" {
			matches[fmt.Sprintf("%s\x00%s", e.ID, pat)] += 0
		}
		return
	}
	key := pathKey(path)
	for _, c := range s.hits[key] {
		if c.entry == e && c.path == path {
			return
		}
	}
	s.hits[key] = append(s.hits[key], candidate{entry: e, root: root, path: path, rel: rel, info: info, cycle: cycle})
	if pat != "" {
		matches[fmt.Sprintf("%s\x00%s", e.ID, pat)]++
	}
}

// walk descends from base (inclusive) without following reparse points unless
// configured, applying excludes before descent.
func (s *scanner) walk(ctx context.Context, e *profile.Entry, root *rootInstance, base, relBase string, depth, maxDepth int, seen map[string]bool, idInfo *fsx.Info, fn func(path, rel string, info *fsx.Info)) {
	if ctx.Err() != nil {
		s.complete = false
		return
	}
	info, err := fsx.Lstat(base)
	if err != nil {
		return
	}
	if idInfo == nil {
		idInfo = info
	}
	if !enterDir(seen, idInfo) {
		return
	}
	fn(base, relBase, info)
	if !info.IsDir || info.IsReparse || depth >= maxDepth {
		return
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		s.errs++
		s.addNote(manifest.Note{Code: "permission_denied", Entry: e.ID, Detail: err.Error()})
		return
	}
	for _, de := range entries {
		name := de.Name()
		rel := joinRel(relBase, name)
		if s.excluded(e, root, rel, relEntry(relBase, name)) {
			continue
		}
		child := filepath.Join(base, name)
		ci, err := fsx.Lstat(child)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				s.errs++
				s.addNote(manifest.Note{Code: "read_error", Entry: e.ID, Detail: err.Error()})
			}
			continue
		}
		fn(child, rel, ci)
		isDir, idChild := descendable(child, ci, s.cfg.FollowSymlinks)
		if isDir && depth+1 <= maxDepth {
			s.walk(ctx, e, root, child, rel, depth+1, maxDepth, seen, idChild, fn)
		}
	}
}

// walkGlob traverses the fixed prefix of pattern and hands every match to
// addCandidate. Excludes are evaluated before descent.
func (s *scanner) walkGlob(ctx context.Context, e *profile.Entry, root *rootInstance, pattern string, matches map[string]int) {
	prefix := staticPrefix(pattern)
	relBase := strings.Trim(strings.ReplaceAll(prefix, "\\", "/"), "/")
	base := root.path
	if relBase != "" {
		base = joinRoot(root.path, relBase)
	}
	mx := s.cfg.Profile.EffectiveMaxDepth(e)
	seen := make(map[string]bool)
	var visit func(rel string, depth int)
	visit = func(rel string, depth int) {
		if ctx.Err() != nil {
			s.complete = false
			return
		}
		p := root.path
		if rel != "" {
			p = joinRoot(root.path, rel)
		}
		info, err := fsx.Lstat(p)
		if err != nil {
			if relBase != "" && errors.Is(err, fs.ErrNotExist) {
				matches[fmt.Sprintf("%s\x00%s", e.ID, pattern)] += 0
			}
			return
		}
		isDir, idInfo := descendable(p, info, s.cfg.FollowSymlinks)
		cycle := false
		if isDir && !enterDir(seen, idInfo) {
			cycle = info.IsReparse
			isDir = false
		}
		if profile.MatchGlob(pattern, rel) {
			s.addCandidate(e, root, p, rel, pattern, info, cycle, matches)
		}
		if !isDir || depth >= mx {
			return
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			s.errs++
			s.addNote(manifest.Note{Code: "permission_denied", Entry: e.ID, Detail: err.Error()})
			return
		}
		for _, de := range entries {
			name := de.Name()
			childRel := joinRel(rel, name)
			if s.excluded(e, root, childRel, name) {
				continue
			}
			visit(childRel, depth+1)
		}
	}
	_ = base
	if relBase == "" {
		visit("", 0)
		return
	}
	// Start at the fixed prefix and evaluate it too: ** may match zero
	// segments, so the prefix itself can be a hit.
	if _, err := fsx.Lstat(joinRoot(root.path, relBase)); err != nil {
		return
	}
	visit(relBase, 0)
}

// descendable reports whether the walk may enter info, and which info carries
// the identity used for cycle prevention. Reparse points are entered only when
// follow_symlinks is on; their target identity is used so a link back to an
// ancestor stops.
func descendable(path string, info *fsx.Info, follow bool) (bool, *fsx.Info) {
	if info == nil {
		return false, info
	}
	if !info.IsReparse {
		return info.IsDir, info
	}
	if !follow {
		return false, info
	}
	target := info.LinkTarget
	if target == "" {
		return false, info
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	ti, err := fsx.Lstat(target)
	if err != nil || !ti.IsDir {
		return false, info
	}
	return true, ti
}

// enterDir records a directory identity for cycle prevention. Bind mounts and
// other aliases that are not reparse points still cannot be entered twice in
// one declaration expansion.
func enterDir(seen map[string]bool, info *fsx.Info) bool {
	if info == nil || !info.IsDir || info.FileID == "" {
		return true
	}
	if seen[info.FileID] {
		return false
	}
	seen[info.FileID] = true
	return true
}

func joinRel(base, name string) string {
	if base == "" {
		return name
	}
	return base + "/" + name
}

func relEntry(relBase, name string) string {
	if relBase == "" {
		return name
	}
	rel, err := filepath.Rel(filepath.FromSlash(relBase), filepath.FromSlash(joinRel(relBase, name)))
	if err != nil {
		return name
	}
	return filepath.ToSlash(rel)
}

// staticPrefix is the literal leading path of a glob, without the glob
// segments themselves.
func staticPrefix(pattern string) string {
	segs := strings.Split(strings.ReplaceAll(pattern, "\\", "/"), "/")
	var out []string
	for _, seg := range segs {
		if profile.ContainsGlob(seg) || seg == "" {
			break
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/")
}

func (s *scanner) excluded(e *profile.Entry, root *rootInstance, rel, underEntry string) bool {
	rel = strings.Trim(rel, "/")
	underEntry = strings.Trim(underEntry, "/")
	for _, pat := range s.cfg.Profile.EffectiveExclude(e) {
		pat = strings.Trim(pat, "/")
		if pat == "" {
			continue
		}
		if profile.MatchGlobLenient(pat, rel) {
			return true
		}
		if underEntry != "" && underEntry != rel && profile.MatchGlobLenient(pat, underEntry) {
			return true
		}
	}
	return false
}

// entryRank implements spec-profile §5.2.1: priority first, then selector
// specificity.
func entryRank(e *profile.Entry) int64 {
	score := int64(e.Priority) * 1_000_000_000
	switch e.Kind {
	case profile.KindFile, profile.KindDir, profile.KindNamedLocation:
		score += 500_000_000
	}
	for _, p := range selectors(e) {
		score += int64(literalSegments(p))*1000 + int64(len(p))
	}
	return score
}

func selectors(e *profile.Entry) []string {
	switch e.Kind {
	case profile.KindFile, profile.KindDir:
		return []string{e.Path}
	case profile.KindGlobGroup:
		return e.Paths
	}
	return nil
}

func literalSegments(p string) int {
	n := 0
	for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if seg != "" && !profile.ContainsGlob(seg) {
			n++
		}
	}
	return n
}

func (s *scanner) selectAndProduce(ctx context.Context, matches map[string]int) {
	// Empty globs are a documented note, not an error.
	for _, e := range s.cfg.Profile.Entries {
		for _, pat := range e.Paths {
			if matches[fmt.Sprintf("%s\x00%s", e.ID, pat)] == 0 {
				s.addNote(manifest.Note{Code: "empty_glob", Entry: e.ID, Detail: pat})
			}
		}
	}

	// Aggregate decisions are per entry so every path of an aggregated
	// declaration is covered by the aggregate.
	agg := make(map[string]bool)
	counts := make(map[string]int)
	for _, cands := range s.hits {
		for _, c := range cands {
			counts[c.entry.ID]++
		}
	}
	for _, e := range s.cfg.Profile.Entries {
		above := profile.DefaultAggregateAbove
		if e.AggregateAbove != nil {
			above = *e.AggregateAbove
		}
		// A sessions entry under --with-sessions always goes per file: the
		// rows are the product, aggregation would lose them.
		if s.perFileSessions(e) {
			continue
		}
		if s.cfg.Profile.EffectiveExpand(e) == "aggregate" || counts[e.ID] > above {
			agg[e.ID] = true
		}
	}
	aggregated := make(map[string]bool) // entry\x00base
	for _, key := range sortedKeys(s.hits) {
		cands := s.hits[key]
		if ctx.Err() != nil {
			s.complete = false
			return
		}
		best := int64(-1 << 62)
		for _, c := range cands {
			if r := entryRank(c.entry); r > best {
				best = r
			}
		}
		winners := 0
		for _, c := range cands {
			if entryRank(c.entry) != best {
				continue
			}
			winners++
		}
		for _, c := range cands {
			if entryRank(c.entry) != best {
				s.covered[key] = true
				continue
			}
			s.covered[key] = true
			if agg[c.entry.ID] {
				base := s.aggregateBase(c)
				gk := c.entry.ID + "\x00" + base
				if aggregated[gk] {
					continue
				}
				aggregated[gk] = true
				s.produceAggregate(ctx, c, base)
				continue
			}
			s.produceFile(ctx, c)
		}
		if winners > 1 {
			for _, c := range cands {
				if entryRank(c.entry) == best {
					s.addNote(manifest.Note{
						Code: "priority_tie", Entry: c.entry.ID,
						Detail: fmt.Sprintf("路径 %s 被 %d 条同优先级同具体度 entry 命中", c.path, winners),
					})
				}
			}
		}
		delete(s.hits, key)
	}
}

// perFileSessions reports whether e must be emitted per file: it is flagged
// sessions in the profile and the scan runs with --with-sessions.
func (s *scanner) perFileSessions(e *profile.Entry) bool {
	return s.cfg.WithSessions && e.Sessions
}

func (s *scanner) aggregateBase(c candidate) string {
	e := c.entry
	switch e.Kind {
	case profile.KindDir:
		if c.root == nil {
			return filepath.Dir(c.path)
		}
		return joinRoot(c.root.path, strings.Trim(strings.ReplaceAll(e.Path, "\\", "/"), "/"))
	case profile.KindGlobGroup:
		// Recover the pattern that produced this candidate from its rel.
		for _, pat := range e.Paths {
			if profile.MatchGlob(pat, c.rel) {
				pref := staticPrefix(pat)
				if c.root == nil {
					return filepath.Dir(c.path)
				}
				if pref == "" {
					return c.root.path
				}
				return joinRoot(c.root.path, pref)
			}
		}
	}
	return c.path
}

func sortedKeys(m map[string][]candidate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

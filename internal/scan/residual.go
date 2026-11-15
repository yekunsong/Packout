package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

type residualCandidate struct {
	entry      *profile.Entry
	root       *rootInstance
	path       string
	info       *fsx.Info
	aggregate  bool
	count      int64
	sizeApp    int64
	sizeAlloc  int64
	maxMTime   time.Time
	underDepth int
}

// residualPass implements pass 2: every catch-all contributes the paths no
// declaration covered. Candidates are de-duplicated globally by path_key; the
// deepest `under` wins, then the earlier root.
func (s *scanner) residualPass(ctx context.Context) {
	best := make(map[string]*residualCandidate)
	for _, e := range s.cfg.Profile.Entries {
		if e.Kind != profile.KindCatchAll || !s.entryAppliesCatch(e) {
			continue
		}
		for _, r := range s.entryRoots(e) {
			if r == nil {
				continue
			}
			scope := e.Scope
			if scope == "" {
				scope = profile.ScopeRoot
			}
			base := r.path
			relBase := ""
			if scope == profile.ScopeSubtree {
				if e.Under == "" {
					continue
				}
				relBase = strings.Trim(strings.ReplaceAll(e.Under, "\\", "/"), "/")
				base = joinRoot(r.path, relBase)
				if info, err := fsx.Lstat(base); err != nil || !info.IsDir {
					s.addNote(manifest.Note{Code: "root_unresolved", Entry: e.ID,
						Detail: "catch-all under 不存在: " + relBase})
					continue
				}
			}
			s.collectResidual(ctx, e, r, base, relBase, scope, best)
		}
	}
	keys := make([]string, 0, len(best))
	for k := range best {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s.emitResidual(best[k])
	}
}

func (s *scanner) entryAppliesCatch(e *profile.Entry) bool {
	if len(e.OS) == 0 {
		return true
	}
	for _, o := range e.OS {
		if o == s.goos {
			return true
		}
	}
	return false
}

func (s *scanner) collectResidual(ctx context.Context, e *profile.Entry, r *rootInstance, base, relBase, scope string, best map[string]*residualCandidate) {
	mx := s.cfg.Profile.EffectiveMaxDepth(e)
	var walk func(dir, rel string, depth int) (truncated bool)
	walk = func(dir, rel string, depth int) bool {
		if ctx.Err() != nil {
			s.complete = false
			return false
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			s.errs++
			s.addNote(manifest.Note{Code: "permission_denied", Entry: e.ID, Detail: err.Error()})
			return false
		}
		truncated := false
		for _, de := range entries {
			name := de.Name()
			childRel := joinRel(rel, name)
			if s.excluded(e, r, childRel, name) {
				continue
			}
			if scope == profile.ScopeRoot && s.subtreeCatchCovers(r, childRel) {
				continue
			}
			p := filepath.Join(dir, name)
			info, err := fsx.Lstat(p)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					s.addNote(manifest.Note{Code: "not_found", Entry: e.ID, Detail: base})
				} else {
					s.errs++
					s.addNote(manifest.Note{Code: "read_error", Entry: e.ID, Detail: err.Error()})
				}
				continue
			}
			key := pathKey(p)
			covered := s.covered[key]
			if info.IsDir && !info.IsReparse {
				cand := &residualCandidate{
					entry: e, root: r, path: p, info: info, aggregate: true,
					underDepth: residualDepth(relBase),
					maxMTime:   info.ModTime,
				}
				if !covered {
					s.offerResidual(best, cand)
				}
				// Count uncovered descendants even when the directory itself
				// was covered (D-021 #4).
				var count int64
				var app, alloc int64
				var mt time.Time
				countUncovered := func(path string, inf *fsx.Info) {
					if s.covered[pathKey(path)] {
						return
					}
					count++
					app += inf.Size
					alloc += inf.Alloc
					if inf.ModTime.After(mt) {
						mt = inf.ModTime
					}
				}
				tr := walkChildren(s, e, r, p, childRel, depth+1, mx, countUncovered)
				if tr {
					truncated = true
					s.addNote(manifest.Note{Code: "depth_truncated", Entry: e.ID, Detail: childRel})
				}
				if count > 0 {
					if cand.count == 0 {
						s.offerResidual(best, cand)
					}
					cand.count += count
					cand.sizeApp += app
					cand.sizeAlloc += alloc
					if mt.After(cand.maxMTime) {
						cand.maxMTime = mt
					}
				} else if covered && cand.count == 0 {
					// Directory covered and nothing below is residual.
					if best[key] == cand {
						delete(best, key)
					}
				}
				continue
			}
			if covered {
				continue
			}
			s.offerResidual(best, &residualCandidate{
				entry: e, root: r, path: p, info: info,
				underDepth: residualDepth(relBase),
				sizeApp:    info.Size, sizeAlloc: info.Alloc, maxMTime: info.ModTime,
			})
		}
		if depth >= mx {
			truncated = true
		}
		return truncated
	}
	walk(base, relBase, 0)
}

// walkChildren is the descendant-counting walk for an aggregate residual.
func walkChildren(s *scanner, e *profile.Entry, r *rootInstance, dir, rel string, depth, mx int, fn func(string, *fsx.Info)) bool {
	if depth > mx {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	truncated := false
	for _, de := range entries {
		name := de.Name()
		childRel := joinRel(rel, name)
		if s.excluded(e, r, childRel, name) {
			continue
		}
		p := filepath.Join(dir, name)
		info, err := fsx.Lstat(p)
		if err != nil {
			continue
		}
		fn(p, info)
		if info.IsDir && !info.IsReparse {
			if depth >= mx {
				truncated = true
				continue
			}
			if walkChildren(s, e, r, p, childRel, depth+1, mx, fn) {
				truncated = true
			}
		}
	}
	return truncated
}

// subtreeCatchCovers reports whether a same-root subtree catch-all owns rel.
func (s *scanner) subtreeCatchCovers(r *rootInstance, rel string) bool {
	for _, e := range s.cfg.Profile.Entries {
		if e.Kind != profile.KindCatchAll || e.Root != r.role && e.Root != r.name {
			continue
		}
		if e.Scope == profile.ScopeSubtree && profile.PathWithinDir(strings.Trim(e.Under, "/"), rel) {
			return true
		}
	}
	return false
}

func (s *scanner) offerResidual(best map[string]*residualCandidate, cand *residualCandidate) {
	key := pathKey(cand.path)
	old := best[key]
	if old == nil {
		best[key] = cand
		return
	}
	if cand.underDepth > old.underDepth ||
		(cand.underDepth == old.underDepth && cand.root.order < old.root.order) {
		best[key] = cand
		s.addNote(manifest.Note{Code: "residual_deduplicated", Entry: cand.entry.ID,
			Detail: fmt.Sprintf("路径 %s 同时落在 %s 与 %s 的 catch-all 范围内", cand.path, old.entry.ID, cand.entry.ID)})
	}
}

func (s *scanner) emitResidual(c *residualCandidate) {
	if c == nil {
		return
	}
	if len(c.path) > maxPathBytes {
		s.addNote(manifest.Note{Code: "path_too_long", Entry: c.entry.ID, Detail: c.path})
		return
	}
	e := c.entry
	kind := manifest.KindCatchAll
	u := manifest.Unit{
		Type:          manifest.TypeUnit,
		SchemaVersion: manifest.Version,
		Path:          c.path,
		PathKey:       pathKey(c.path),
		Root:          c.root.name,
		PathSemantics: manifest.SemanticsLiteral,
		Profile:       s.cfg.Profile.Name,
		Entry:         e.ID,
		Kind:          kind,
		Layer:         manifest.LayerL2,
		Confidence:    0.5,
		Signals: []manifest.Signal{{
			Src:  "filesystem_stat",
			Note: "未被任何 entry 命中，catch-all 残留",
		}},
		Secret:         &manifest.Secret{Class: e.Secret},
		ProposedAction: manifest.ActionKeep,
		RiskFlags:      []string{"residual", "low_confidence"},
		OpenAs:         manifest.OpenAsNone,
	}
	if u.Secret.Class == "" {
		u.Secret.Class = manifest.SecretNone
	}
	u.ID = manifest.UnitID(u.Root, u.Profile, u.Entry, "", u.PathKey)
	size := c.sizeApp
	alloc := c.sizeAlloc
	u.SizeApparent = &size
	u.SizeAlloc = &alloc
	mt := c.maxMTime
	u.MTime = &mt
	u.FileID = fileID(c.info)
	if c.info != nil && c.info.IsSparse {
		u.RiskFlags = appendFlag(u.RiskFlags, "sparse")
	}
	if c.info != nil && c.info.IsReparse {
		if c.info.IsLink {
			u.RiskFlags = appendFlag(u.RiskFlags, "symlink")
		} else {
			u.RiskFlags = appendFlag(u.RiskFlags, "junction")
			u.RiskFlags = appendFlag(u.RiskFlags, "symlink")
		}
		u.LinkTarget = c.info.LinkTarget
		if s.outsideRoot(c.path, c.info.LinkTarget) {
			u.RiskFlags = appendFlag(u.RiskFlags, "outside_root")
		}
	}
	if len(c.path) > longPathMark {
		u.RiskFlags = appendFlag(u.RiskFlags, "long_path")
	}
	if c.aggregate {
		count := c.count
		u.AggregateCount = &count
		u.RiskFlags = appendFlag(u.RiskFlags, "aggregated")
		zero, may := false, e.Secret == profile.SecretScan || e.Secret == profile.SecretRestore
		u.ContainsSecret = &zero
		u.MayContainSecret = &may
		u.FileID = nil
		if alloc*2 < size {
			u.RiskFlags = appendFlag(u.RiskFlags, "sparse")
		}
		h := sha256.New()
		fmt.Fprintf(h, "%s\x00%d\x00", u.PathKey, count)
		val := hashHex(h)
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: "aggregate", Value: &val}
		u.CID = manifest.CID(u.Fingerprint)
	} else {
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: "shape"}
		u.CID = nil
	}
	s.units = append(s.units, u)
}

func residualDepth(rel string) int {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return 0
	}
	return len(strings.Split(rel, "/"))
}

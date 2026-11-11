package scan

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"packout/internal/manifest"
	"packout/internal/profile"
)

// applySessionSelection narrows the collected session candidates by mtime,
// project slug and per-project cap. It runs after the declaration pass so the
// per-project cap can compare mtimes across the whole corpus.
func (s *scanner) applySessionSelection() {
	sel := s.cfg.Selection
	if sel == nil {
		return
	}
	since := sel.SinceDuration()
	projects := sel.SessionsProjects
	maxPer := sel.SessionsMaxPerProject
	if since == 0 && len(projects) == 0 && maxPer == 0 {
		return
	}
	cutoff := time.Now().Add(-since)

	for key, cands := range s.hits {
		kept := cands[:0]
		for _, c := range cands {
			if profile.CategoryOf(c.entry) != profile.CategorySessions {
				kept = append(kept, c)
				continue
			}
			slug := projectSlug(c.rel)
			if since > 0 && c.info != nil && c.info.ModTime.Before(cutoff) {
				s.addNote(manifest.Note{
					Code: "selection_skipped", Entry: c.entry.ID,
					Category: profile.CategorySessions,
					Detail:   "会话早于 --sessions-since " + sel.SessionsSince + ": " + c.path,
				})
				continue
			}
			if len(projects) > 0 && !sessionHasProject(projects, slug) {
				s.addNote(manifest.Note{
					Code: "selection_skipped", Entry: c.entry.ID,
					Category: profile.CategorySessions,
					Detail:   "项目 " + displaySlug(slug) + " 不在 --sessions-project: " + c.path,
				})
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			delete(s.hits, key)
		} else {
			s.hits[key] = kept
		}
	}
	if maxPer <= 0 {
		return
	}

	// Group survivors by (entry, project) and keep the newest maxPer.
	type groupKey struct{ entry, slug string }
	groups := make(map[groupKey][]candidate)
	for _, cands := range s.hits {
		for _, c := range cands {
			if profile.CategoryOf(c.entry) != profile.CategorySessions {
				continue
			}
			k := groupKey{c.entry.ID, projectSlug(c.rel)}
			groups[k] = append(groups[k], c)
		}
	}
	drop := make(map[groupKey]map[string]bool)
	for k, cands := range groups {
		if len(cands) <= maxPer {
			continue
		}
		sort.SliceStable(cands, func(i, j int) bool {
			ti, tj := time.Time{}, time.Time{}
			if cands[i].info != nil {
				ti = cands[i].info.ModTime
			}
			if cands[j].info != nil {
				tj = cands[j].info.ModTime
			}
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return cands[i].path < cands[j].path
		})
		for _, c := range cands[maxPer:] {
			if drop[k] == nil {
				drop[k] = make(map[string]bool)
			}
			drop[k][c.path] = true
			s.addNote(manifest.Note{
				Code: "selection_skipped", Entry: c.entry.ID,
				Category: profile.CategorySessions,
				Detail: "项目 " + displaySlug(k.slug) + " 超过 --sessions-max-per-project=" +
					strconv.Itoa(maxPer) + "，按 mtime 保留较新者: " + c.path,
			})
		}
	}
	for key, cands := range s.hits {
		kept := cands[:0]
		for _, c := range cands {
			if profile.CategoryOf(c.entry) == profile.CategorySessions {
				if gone := drop[groupKey{c.entry.ID, projectSlug(c.rel)}]; gone[c.path] {
					continue
				}
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			delete(s.hits, key)
		} else {
			s.hits[key] = kept
		}
	}
}

// projectSlug returns the path segment right after a "projects" segment, or
// "" when the candidate does not live under a project directory.
func projectSlug(rel string) string {
	rel = strings.ReplaceAll(rel, "\\", "/")
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		if seg == "projects" && i+1 < len(segs) {
			return segs[i+1]
		}
	}
	return ""
}

func sessionHasProject(projects []string, slug string) bool {
	for _, p := range projects {
		if p == slug {
			return true
		}
	}
	return false
}

func displaySlug(slug string) string {
	if slug == "" {
		return "(无项目)"
	}
	return slug
}

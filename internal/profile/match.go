package profile

import (
	"strings"
)

// matchGlob matches a slash-separated path against a profile glob
// (spec-profile §4.2):
//
//   - `*` matches any run inside one segment, `?` one character,
//     `[a-z]` a character class;
//   - `**` matches zero or more whole segments;
//   - `*` and `**` do not match a segment that starts with "." unless the
//     pattern segment itself starts with "." (so `.*` and `**/.*` opt in).
func matchGlob(pattern, name string) bool {
	pat := splitSlash(pattern)
	segs := splitSlash(name)
	return matchSegments(pat, segs)
}

// matchGlobLenient is matchGlob without the hidden-segment restriction. It is
// used for exclude patterns (never for selectors): `**/x` must also match
// below hidden directories such as `.claude`.
func matchGlobLenient(pattern, name string) bool {
	return matchSegmentsLenient(splitSlash(pattern), splitSlash(name))
}

func matchSegmentsLenient(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		if matchSegmentsLenient(pat[1:], segs) {
			return true
		}
		if len(segs) == 0 {
			return false
		}
		return matchSegmentsLenient(pat, segs[1:])
	}
	if len(segs) == 0 {
		return false
	}
	if !matchSegment(pat[0], segs[0]) {
		return false
	}
	return matchSegmentsLenient(pat[1:], segs[1:])
}

func splitSlash(s string) []string {
	s = strings.ReplaceAll(s, "\\", "/")
	raw := strings.Split(s, "/")
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == "" {
			continue
		}
		out = append(out, seg)
	}
	return out
}

func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		if matchSegments(pat[1:], segs) {
			return true
		}
		if len(segs) == 0 {
			return false
		}
		if isHiddenSegment(segs[0]) {
			return false
		}
		return matchSegments(pat, segs[1:])
	}
	if len(segs) == 0 {
		return false
	}
	if isHiddenSegment(segs[0]) && !strings.HasPrefix(pat[0], ".") {
		return false
	}
	if !matchSegment(pat[0], segs[0]) {
		return false
	}
	return matchSegments(pat[1:], segs[1:])
}

func isHiddenSegment(s string) bool {
	return strings.HasPrefix(s, ".") && s != "." && s != ".."
}

// matchSegment matches one path segment with `*`, `?` and `[...]`.
func matchSegment(pat, s string) bool {
	pi, si := 0, 0
	star := -1
	resume := 0
	for si < len(s) {
		switch {
		case pi < len(pat) && pat[pi] == '*':
			star = pi
			resume = si
			pi++
		case pi < len(pat) && pat[pi] == '?':
			pi++
			si++
		case pi < len(pat) && pat[pi] == '[':
			end := strings.IndexByte(pat[pi:], ']')
			if end < 0 {
				return false
			}
			class := pat[pi+1 : pi+end]
			if classMatch(class, s[si]) {
				pi += end + 1
				si++
			} else if star >= 0 {
				pi = star + 1
				resume++
				si = resume
			} else {
				return false
			}
		case pi < len(pat) && pat[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			resume++
			si = resume
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

func classMatch(class string, c byte) bool {
	neg := false
	if strings.HasPrefix(class, "!") || strings.HasPrefix(class, "^") {
		neg = true
		class = class[1:]
	}
	matched := false
	for i := 0; i < len(class); i++ {
		if i+2 < len(class) && class[i+1] == '-' {
			if class[i] <= c && c <= class[i+2] {
				matched = true
			}
			i += 2
			continue
		}
		if class[i] == c {
			matched = true
		}
	}
	if neg {
		return !matched
	}
	return matched
}

// underPrefix reports whether parent and child overlap by path-segment
// prefix: equal paths or child below parent (spec-profile §5.2).
func underPrefix(parent, child string) bool {
	p := strings.Trim(strings.ReplaceAll(parent, "\\", "/"), "/")
	c := strings.Trim(strings.ReplaceAll(child, "\\", "/"), "/")
	if p == "" {
		return true
	}
	return c == p || strings.HasPrefix(c, p+"/")
}

// pathWithinDir reports whether rel is dir itself or below it.
func pathWithinDir(dir, rel string) bool {
	d := strings.Trim(strings.ReplaceAll(dir, "\\", "/"), "/")
	r := strings.Trim(strings.ReplaceAll(rel, "\\", "/"), "/")
	if d == "" {
		return true
	}
	return r == d || strings.HasPrefix(r, d+"/")
}

// splitRelPath validates a profile-relative path: non-empty, not absolute,
// no "." or ".." components. It returns the slash-separated components.
func splitRelPath(p string) ([]string, bool) {
	if p == "" {
		return nil, false
	}
	if filepathIsAbsTemplate(p) {
		return nil, false
	}
	raw := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == "" || seg == "." || seg == ".." {
			return nil, false
		}
		out = append(out, seg)
	}
	return out, true
}

// filepathIsAbsTemplate recognizes absolute paths on any platform plus
// variable-led templates.
func filepathIsAbsTemplate(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && isASCIIAlpha(p[0]) && p[1] == ':' && (p[2] == '/' || p[2] == '\\') {
		return true
	}
	return false
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func defaultExcluded(rel string) bool {
	for _, pat := range DefaultExclude {
		if matchGlobLenient(pat, rel) {
			return true
		}
	}
	return false
}

// MatchGlob exposes the profile glob matcher (spec-profile §4.2) for the scan
// engine, so entry selectors and residual checks use exactly one
// implementation. pattern and name are slash-separated.
func MatchGlob(pattern, name string) bool { return matchGlob(pattern, name) }

// MatchGlobLenient is matchGlob without the hidden-segment restriction. The
// engine uses it for exclude patterns, whose `**/x` forms must also match
// below hidden directories such as `.claude`.
func MatchGlobLenient(pattern, name string) bool { return matchGlobLenient(pattern, name) }

// ContainsGlob reports whether s contains any glob metacharacter.
func ContainsGlob(s string) bool { return containsGlob(s) }

// PathWithinDir reports whether rel is dir itself or below it, using
// segment-wise comparison. Both arguments are slash-separated.
func PathWithinDir(dir, rel string) bool { return pathWithinDir(dir, rel) }

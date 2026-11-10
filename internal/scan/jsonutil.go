package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"
)

func sha256String() hash.Hash    { return sha256.New() }
func hashHex(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

type scalarRange struct {
	start, end int
	pointer    string
}

func jsonPointerMap(data []byte) map[int]string {
	ranges := jsonScalarRanges(data)
	out := make(map[int]string, len(ranges))
	for _, r := range ranges {
		for i := r.start; i < r.end; i++ {
			out[i] = r.pointer
		}
	}
	return out
}

// jsonScalarRanges tokenizes JSON only far enough to attribute byte offsets to
// RFC 6901 pointers. Invalid JSON yields the ranges found so far.
func jsonScalarRanges(data []byte) []scalarRange {
	var out []scalarRange
	var stack []jsonFrame
	i := 0
	skipWS := func() {
		for i < len(data) {
			switch data[i] {
			case ' ', '\t', '\r', '\n':
				i++
			default:
				return
			}
		}
	}
	pointer := func() string {
		var b strings.Builder
		for _, f := range stack {
			b.WriteByte('/')
			if f.kind == 'o' {
				b.WriteString(strings.ReplaceAll(strings.ReplaceAll(f.key, "~", "~0"), "/", "~1"))
			} else {
				b.WriteString(strconv.Itoa(f.idx))
			}
		}
		return b.String()
	}
	popValue := func() {
		if len(stack) == 0 {
			return
		}
		top := &stack[len(stack)-1]
		if top.kind == 'a' {
			top.idx++
		} else {
			top.key = ""
		}
	}
	for i < len(data) {
		skipWS()
		if i >= len(data) {
			break
		}
		switch c := data[i]; {
		case c == '{':
			stack = append(stack, jsonFrame{kind: 'o'})
			i++
		case c == '[':
			stack = append(stack, jsonFrame{kind: 'a'})
			i++
		case c == '}' || c == ']':
			popValue()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
			if len(stack) > 0 {
				popValue()
			}
		case c == ',' || c == ':':
			i++
		case c == '"':
			start := i + 1
			i++
			for i < len(data) && data[i] != '"' {
				if data[i] == '\\' {
					i++
				}
				i++
			}
			end := i
			if i < len(data) {
				i++
			}
			if len(stack) > 0 && stack[len(stack)-1].kind == 'o' && stack[len(stack)-1].key == "" {
				stack[len(stack)-1].key = unquoteJSON(string(data[start:end]))
				skipWS()
				if i < len(data) && data[i] == ':' {
					i++
				}
				continue // this string was a key
			}
			out = append(out, scalarRange{start: start, end: end, pointer: pointer()})
			popValue()
		default:
			start := i
			for i < len(data) {
				c := data[i]
				if c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					break
				}
				i++
			}
			out = append(out, scalarRange{start: start, end: i, pointer: pointer()})
			popValue()
		}
	}
	return out
}

type jsonFrame struct {
	kind byte // 'o' | 'a'
	key  string
	idx  int
}

func unquoteJSON(s string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err == nil {
		return out
	}
	return s
}

// pointerJSONLocator returns the pointer covering off, if any.
func pointerJSONLocator(data []byte, off int) (string, bool) {
	for _, r := range jsonScalarRanges(data) {
		if off >= r.start && off <= r.end {
			return r.pointer, true
		}
	}
	return "", false
}

// jsonSelect follows a pointer with single-segment "*" wildcards. It also
// returns the key that the last wildcard matched.
func jsonSelect(v any, pointer string) (any, string, bool) {
	if pointer == "" || pointer == "/" {
		return v, "", true
	}
	segs := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	cur := v
	origin := ""
	for _, raw := range segs {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			if seg == "*" {
				keys := sortedAnyKeys(node)
				if len(keys) == 0 {
					return nil, "", false
				}
				first := keys[0]
				origin = first
				cur = node[first]
				continue
			}
			next, ok := node[seg]
			if !ok {
				return nil, "", false
			}
			cur = next
		case []any:
			if seg == "*" {
				if len(node) == 0 {
					return nil, "", false
				}
				cur = node[0]
				continue
			}
			n, err := strconv.Atoi(seg)
			if err != nil || n < 0 || n >= len(node) {
				return nil, "", false
			}
			cur = node[n]
		default:
			return nil, "", false
		}
	}
	return cur, origin, true
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonSelectAll returns every match of a pointer, expanding each wildcard.
func jsonSelectAll(v any, pointer string) ([][2]string, bool) {
	// result pairs: normalized JSON value, origin key
	if pointer == "" || pointer == "/" {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, false
		}
		return [][2]string{{string(b), ""}}, true
	}
	segs := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	type state struct {
		v      any
		origin string
	}
	states := []state{{v: v}}
	for _, raw := range segs {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		var next []state
		for _, st := range states {
			switch node := st.v.(type) {
			case map[string]any:
				if seg == "*" {
					for _, k := range sortedAnyKeys(node) {
						next = append(next, state{v: node[k], origin: k})
					}
					continue
				}
				if child, ok := node[seg]; ok {
					next = append(next, state{v: child, origin: st.origin})
				}
			case []any:
				if seg == "*" {
					for _, child := range node {
						next = append(next, state{v: child, origin: st.origin})
					}
					continue
				}
				n, err := strconv.Atoi(seg)
				if err == nil && n >= 0 && n < len(node) {
					next = append(next, state{v: node[n], origin: st.origin})
				}
			}
		}
		states = next
	}
	var out [][2]string
	for _, st := range states {
		b, err := json.Marshal(st.v)
		if err != nil {
			continue
		}
		out = append(out, [2]string{string(b), st.origin})
	}
	return out, len(out) > 0
}

// extractKeys returns sorted key paths for keys-only fingerprints. It handles
// JSON and a minimal TOML surface; structure bounds how many bytes are read.
func extractKeys(data []byte, structure int64) []string {
	if structure > 0 && int64(len(data)) > structure {
		data = data[:structure]
	}
	if len(data) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(data, &v) == nil {
		set := make(map[string]bool)
		collectJSONKeys(v, "", set)
		out := make([]string, 0, len(set))
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return tomlKeys(data)
}

func collectJSONKeys(v any, prefix string, set map[string]bool) {
	switch node := v.(type) {
	case map[string]any:
		for _, k := range sortedAnyKeys(node) {
			key := prefix + "/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
			set[key] = true
			collectJSONKeys(node[k], key, set)
		}
	case []any:
		for i, child := range node {
			key := prefix + "/" + strconv.Itoa(i)
			set[key] = true
			collectJSONKeys(child, key, set)
		}
	}
}

type tomlSection struct {
	name  string
	start int
	end   int
}

func tomlSections(data []byte) []tomlSection {
	var out []tomlSection
	offset := 0
	cur := tomlSection{start: 0}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\n"))
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			cur.end = offset
			out = append(out, cur)
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			cur = tomlSection{name: strings.Join(tomlSegments(name), "."), start: offset + len(line)}
		}
		offset += len(line)
	}
	cur.end = offset
	if cur.name != "" {
		out = append(out, cur)
	}
	return out
}

func tomlKeys(data []byte) []string {
	var out []string
	for _, sec := range tomlSections(data) {
		out = append(out, sec.name)
		for _, line := range strings.Split(string(data[sec.start:sec.end]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
				continue
			}
			if i := strings.IndexByte(line, '='); i > 0 {
				out = append(out, sec.name+"."+strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[:i]), ".")))
			}
		}
	}
	seen := make(map[string]bool)
	uniq := out[:0]
	for _, k := range out {
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, k)
		}
	}
	sort.Strings(uniq)
	return uniq
}

func matchSection(pattern, section string) bool {
	ps := tomlSegments(pattern)
	ss := tomlSegments(section)
	if len(ps) != len(ss) {
		return false
	}
	for i := range ps {
		if ps[i] == "*" {
			continue
		}
		if ps[i] != ss[i] {
			return false
		}
	}
	return true
}

func sectionOrigin(pattern, section string) string {
	ps := tomlSegments(pattern)
	ss := tomlSegments(section)
	for i := range ps {
		if ps[i] == "*" && i < len(ss) {
			return ss[i]
		}
	}
	return ""
}

// tomlSegments splits a dotted TOML key path, honouring quoted segments that
// may themselves contain dots.
func tomlSegments(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == '.' {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '\'' || s[i] == '"' {
			q := s[i]
			i++
			start := i
			for i < len(s) && s[i] != q {
				i++
			}
			out = append(out, s[start:i])
			if i < len(s) {
				i++
			}
			continue
		}
		start := i
		for i < len(s) && s[i] != '.' {
			i++
		}
		out = append(out, strings.TrimSpace(s[start:i]))
	}
	return out
}

func formatFloatConf(f float64) string { return fmt.Sprintf("%.3f", f) }

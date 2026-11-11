package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"packout/internal/manifest"
	"packout/internal/profile"
	"packout/internal/secret"
)

// Placeholder is what a config extract carries instead of a RESTORE value:
//
//	«secret:secrets.age#h_<20 base32 chars>»
//
// The value itself only exists inside secrets.age. A restore tool rewrites the
// reference back to bytes; without the key the file is still valid text and
// the reference is still human-readable.
const secretPlaceholderPrefix = "«secret:"

// secretSource is one occurrence of a reference.
type secretSource struct {
	Path    string `json:"path"`
	Locator string `json:"locator"`
}

// secretEntry is one reference and the plaintext behind it.
type secretEntry struct {
	Ref     string         `json:"ref"`
	Class   string         `json:"class"`
	Value   string         `json:"value"`
	Sources []secretSource `json:"sources"`
}

// secretsIndex is the plaintext document encrypted into secrets.age.
type secretsIndex struct {
	Format        string        `json:"format"`
	FormatVersion int           `json:"format_version"`
	Entries       []secretEntry `json:"entries"`
}

// secretCollector groups RESTORE values by secret_ref while extracted config
// is written. Values never reach config/.
type secretCollector struct {
	salt  []byte
	mu    sync.Mutex
	byRef map[string]*secretEntry
	used  map[*manifest.SecretHit]bool
}

func newSecretCollector(salt string) *secretCollector {
	return &secretCollector{
		salt:  []byte(salt),
		byRef: map[string]*secretEntry{},
		used:  map[*manifest.SecretHit]bool{},
	}
}

// placeholder matches one detected hit against the unit's manifest hits and,
// when it is an unexported RESTORE hit, records the value and returns the
// textual placeholder. A hit the manifest does not know about is still
// exported: the package stays self-consistent because the reference lands in
// the same index.
func (c *secretCollector) placeholder(u *manifest.Unit, value []byte, locator, source string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	fp := "sha256:" + secret.ValueFPWithSalt(value, c.salt)
	var match *manifest.SecretHit
	if u.Secret != nil {
		for i := range u.Secret.Hits {
			h := &u.Secret.Hits[i]
			if h.Class == manifest.SecretRestore && !c.used[h] && h.Fingerprint == fp && h.Locator == locator {
				match = h
				break
			}
		}
		if match == nil {
			// Locators can drift if scan and export see different bytes.
			for i := range u.Secret.Hits {
				h := &u.Secret.Hits[i]
				if h.Class == manifest.SecretRestore && !c.used[h] && h.Fingerprint == fp {
					match = h
					break
				}
			}
		}
	}
	valueFP := fp
	if match != nil {
		c.used[match] = true
		valueFP = match.Fingerprint
		locator = match.Locator
	}
	id := manifest.HitID(u.CID, locator, valueFP, u.ID)
	ref := SecretsName + "#" + id
	e := c.byRef[ref]
	if e == nil {
		e = &secretEntry{Ref: ref, Class: manifest.SecretRestore, Value: string(value)}
		c.byRef[ref] = e
	}
	for _, s := range e.Sources {
		if s.Path == source && s.Locator == locator {
			return secretPlaceholderPrefix + ref + "»"
		}
	}
	e.Sources = append(e.Sources, secretSource{Path: source, Locator: locator})
	return secretPlaceholderPrefix + ref + "»"
}

// encode produces the deterministic plaintext index. Entries and sources are
// sorted so the ciphertext is reproducible for identical input.
func (c *secretCollector) encode() ([]byte, error) {
	doc := secretsIndex{Format: secretsFormat, FormatVersion: secretsFormatVersion}
	c.mu.Lock()
	defer c.mu.Unlock()
	refs := make([]string, 0, len(c.byRef))
	for ref := range c.byRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		e := c.byRef[ref]
		sort.Slice(e.Sources, func(i, j int) bool {
			if e.Sources[i].Path != e.Sources[j].Path {
				return e.Sources[i].Path < e.Sources[j].Path
			}
			return e.Sources[i].Locator < e.Sources[j].Locator
		})
		doc.Entries = append(doc.Entries, *e)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// emptyIndex is written when --with-secrets produced no RESTORE hits, so the
// presence of secrets.age always means the user asked for secrets.
func emptyIndex() []byte {
	return []byte(`{"format":"` + secretsFormat + `","format_version":1,"entries":[]}` + "\n")
}

// renderWithSecrets is renderTemplate plus secret_ref substitution. RESTORE
// hits become placeholders, every other actionable hit keeps the ordinary
// redaction behaviour.
func renderWithSecrets(data []byte, u *manifest.Unit, e *profile.Entry, partID string, c *secretCollector, source string, p *profile.Profile) []byte {
	_, redact := extractorFor(e, partID)
	opts := secret.Options{Entropy: p.EffectiveScan(e) != "strict", MaxHits: 32}
	base := filepath.Base(u.Path)

	var pointers map[int]string
	if strings.HasSuffix(strings.ToLower(u.Path), ".json") {
		pointers = jsonPointerOffsets(data)
	}
	locatorOf := func(off int) string {
		if pointers != nil {
			if p, ok := pointers[off]; ok {
				return p
			}
		}
		return lineColumn(data, off)
	}

	type repl struct {
		start, end int
		text       string
	}
	var repls []repl
	for _, h := range secret.DetectWithResult(opts, base, data).Hits {
		if h.Class != secret.Restore {
			continue
		}
		loc := locatorOf(h.Offset)
		if u.PartID != "" {
			loc = "#" + loc
		}
		repls = append(repls, repl{h.Offset, h.End(), c.placeholder(u, data[h.Offset:h.End()], loc, source)})
	}
	if len(repls) > 0 {
		sort.Slice(repls, func(i, j int) bool { return repls[i].start > repls[j].start })
		for _, r := range repls {
			out := make([]byte, 0, len(data)-(r.end-r.start)+len(r.text))
			out = append(out, data[:r.start]...)
			out = append(out, r.text...)
			out = append(out, data[r.end:]...)
			data = out
		}
	}
	if redact != nil && (len(redact.JSONPointer) > 0 || len(redact.KeyPattern) > 0) {
		if compact, ok := redactJSON(data, redact, "«REDACTED»"); ok {
			data = compact
		}
	}
	// Anything still actionable (placeholders contain no value bytes) gets
	// the ordinary generic mask. Detection still matches keyed placeholders
	// such as api_key, so those are skipped explicitly.
	var hits []secret.Hit
	for _, h := range secret.DetectWithResult(secret.Options{}, "config", data).Hits {
		if bytes.HasPrefix(data[h.Offset:], []byte(secretPlaceholderPrefix)) {
			continue
		}
		hits = append(hits, h)
	}
	return secret.Redact(data, hits, func([]byte) []byte { return []byte("«REDACTED»") })
}

func lineColumn(data []byte, off int) string {
	line := 1 + bytes.Count(data[:off], []byte("\n"))
	col := 1 + off - (bytes.LastIndexByte(data[:off], '\n') + 1)
	return fmt.Sprintf("%d:%d", line, col)
}

// ---- JSON pointer attribution ---------------------------------------------
// Copied in spirit from internal/scan: export must derive the same locator
// scan persisted, and importing scan would pull its whole engine in.

type scalarRange struct {
	start, end int
	pointer    string
}

type jsonFrame struct {
	kind byte // 'o' | 'a'
	key  string
	idx  int
}

func jsonPointerOffsets(data []byte) map[int]string {
	ranges := jsonScalarRanges(data)
	out := make(map[int]string, len(ranges))
	for _, r := range ranges {
		for i := r.start; i < r.end; i++ {
			out[i] = r.pointer
		}
	}
	return out
}

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
				continue
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

func unquoteJSON(s string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err == nil {
		return out
	}
	return s
}

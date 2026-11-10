package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"
)

// decoder turns a hujson AST into the typed Profile projection. It never
// reformats or re-encodes the document: values are read through the AST and
// the original bytes stay available for Pack (D-019).
type decoder struct {
	src   []byte
	file  string
	errs  Errors
	warns Warnings
}

func (d *decoder) position(off int) Position {
	if off < 0 {
		off = 0
	}
	if off > len(d.src) {
		off = len(d.src)
	}
	line := 1 + bytes.Count(d.src[:off], []byte("\n"))
	col := 1 + off - (bytes.LastIndexByte(d.src[:off], '\n') + 1)
	return Position{Line: line, Column: col, Offset: off}
}

func (d *decoder) pos(v *hujson.Value) Position {
	if v == nil {
		return Position{}
	}
	return d.position(v.StartOffset)
}

func (d *decoder) errAt(code string, pos Position, subject, format string, args ...any) {
	d.errs = append(d.errs, &Error{
		Code: code, File: d.file, Pos: pos, Subject: subject,
		Message: fmt.Sprintf(format, args...),
	})
}

func (d *decoder) errf(code string, v *hujson.Value, subject, format string, args ...any) {
	d.errAt(code, d.pos(v), subject, format, args...)
}

func (d *decoder) warnAt(code string, pos Position, subject, format string, args ...any) {
	d.warns = append(d.warns, &Warning{
		Code: code, File: d.file, Pos: pos, Subject: subject,
		Message: fmt.Sprintf(format, args...),
	})
}

func (d *decoder) warnf(code string, v *hujson.Value, subject, format string, args ...any) {
	d.warnAt(code, d.pos(v), subject, format, args...)
}

// --- AST helpers -----------------------------------------------------------

func literalName(v *hujson.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	lit, ok := v.Value.(hujson.Literal)
	if !ok || lit.Kind() != '"' {
		return "", false
	}
	return lit.String(), true
}

func objectMembers(obj *hujson.Object) map[string]*hujson.Value {
	m := make(map[string]*hujson.Value, len(obj.Members))
	for i := range obj.Members {
		mem := &obj.Members[i]
		name, ok := literalName(&mem.Name)
		if !ok {
			continue
		}
		if _, exists := m[name]; !exists {
			m[name] = &mem.Value
		}
	}
	return m
}

func (d *decoder) object(v *hujson.Value, subject, code string) (*hujson.Object, bool) {
	if v == nil {
		d.errAt(code, d.pos(v), subject, "缺少对象")
		return nil, false
	}
	if obj, ok := v.Value.(*hujson.Object); ok {
		return obj, true
	}
	d.errf(code, v, subject, "期望对象")
	return nil, false
}

func (d *decoder) array(v *hujson.Value, subject, code string) (*hujson.Array, bool) {
	if v == nil {
		d.errAt(code, d.pos(v), subject, "缺少数组")
		return nil, false
	}
	if arr, ok := v.Value.(*hujson.Array); ok {
		return arr, true
	}
	d.errf(code, v, subject, "期望数组")
	return nil, false
}

func (d *decoder) str(v *hujson.Value, subject, code string) (string, bool) {
	if v == nil {
		d.errAt(code, d.pos(nil), subject, "缺少字符串")
		return "", false
	}
	lit, ok := v.Value.(hujson.Literal)
	if !ok || lit.Kind() != '"' {
		d.errf(code, v, subject, "期望字符串")
		return "", false
	}
	return lit.String(), true
}

func (d *decoder) integer(v *hujson.Value, subject, code string) (int64, bool) {
	if v == nil {
		d.errAt(code, d.pos(nil), subject, "缺少整数")
		return 0, false
	}
	lit, ok := v.Value.(hujson.Literal)
	if !ok || lit.Kind() != '0' {
		d.errf(code, v, subject, "期望整数")
		return 0, false
	}
	var n int64
	if err := json.Unmarshal([]byte(lit), &n); err != nil {
		d.errf(code, v, subject, "期望整数: %v", err)
		return 0, false
	}
	return n, true
}

func (d *decoder) number(v *hujson.Value, subject, code string) (float64, bool) {
	if v == nil {
		d.errAt(code, d.pos(nil), subject, "缺少数字")
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(v.Pack(), &f); err != nil {
		d.errf(code, v, subject, "期望数字: %v", err)
		return 0, false
	}
	return f, true
}

func (d *decoder) boolean(v *hujson.Value, subject, code string) (bool, bool) {
	if v == nil {
		d.errAt(code, d.pos(nil), subject, "缺少布尔值")
		return false, false
	}
	lit, ok := v.Value.(hujson.Literal)
	if !ok || (lit.Kind() != 't' && lit.Kind() != 'f') {
		d.errf(code, v, subject, "期望布尔值")
		return false, false
	}
	return lit.Bool(), true
}

func (d *decoder) stringList(v *hujson.Value, subject, code string) ([]string, bool) {
	arr, ok := d.array(v, subject, code)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr.Elements))
	good := true
	for i := range arr.Elements {
		s, ok := d.str(&arr.Elements[i], subject, code)
		if !ok {
			good = false
			continue
		}
		out = append(out, s)
	}
	return out, good
}

func standardizeValue(v *hujson.Value) (json.RawMessage, error) {
	// Standardize preserves line/byte offsets but leaves whitespace; Minimize
	// then gives a compact, reusable json.RawMessage. Both operate on a copy:
	// the original AST remains the write-back source (D-019).
	b := bytes.Clone(v.Pack())
	std, err := hujson.Standardize(b)
	if err != nil {
		return nil, err
	}
	min, err := hujson.Minimize(bytes.Clone(std))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(min), nil
}

// extra collects unrecognized members as standardized JSON. The original AST
// keeps the verbatim bytes, so Pack still reproduces them exactly.
func (d *decoder) extra(obj *hujson.Object, known map[string]bool, subject string) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	for i := range obj.Members {
		mem := &obj.Members[i]
		name, ok := literalName(&mem.Name)
		if !ok || known[name] {
			continue
		}
		raw, err := standardizeValue(&mem.Value)
		if err != nil {
			d.errf("E-PRF-063", &mem.Value, subject, "未知字段 %q 无法标准化: %v", name, err)
			continue
		}
		if out == nil {
			out = make(map[string]json.RawMessage)
		}
		out[name] = raw
		d.warnf("W-PRF-101", &mem.Name, subject, "未知字段 %q（已保留，不参与校验）", name)
	}
	return out
}

// checkDuplicateKeys walks the whole document; hujson accepts duplicate keys
// silently, so the loader must reject them (E-PRF-064, D-019).
func (d *decoder) checkDuplicateKeys(v *hujson.Value) {
	switch x := v.Value.(type) {
	case *hujson.Object:
		seen := make(map[string]Position, len(x.Members))
		for i := range x.Members {
			mem := &x.Members[i]
			if name, ok := literalName(&mem.Name); ok {
				if first, dup := seen[name]; dup {
					d.errAt("E-PRF-064", d.pos(&mem.Name), "profile",
						"重复键 %q（首次出现于 %s）", name, first.String())
				} else {
					seen[name] = d.pos(&mem.Name)
				}
			}
			d.checkDuplicateKeys(&mem.Value)
		}
	case *hujson.Array:
		for i := range x.Elements {
			d.checkDuplicateKeys(&x.Elements[i])
		}
	}
}

// --- parse classification --------------------------------------------------

var hujsonErrRE = regexp.MustCompile(`^hujson: line (\d+), column (\d+): (.*)$`)

func classifyParseError(msg string) (code string, pos Position, detail string) {
	code = "E-PRF-063"
	detail = msg
	if m := hujsonErrRE.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		col, _ := strconv.Atoi(m[2])
		pos = Position{Line: line, Column: col}
		detail = m[3]
	}
	switch {
	case strings.Contains(msg, "after top-level value"):
		code = "E-PRF-065"
	case strings.Contains(detail, "invalid literal:"),
		strings.Contains(detail, "invalid character '\\''"):
		code = "E-PRF-066"
	}
	if code == "E-PRF-066" {
		// The most common cause is a Windows path written with single
		// backslashes; spell the fix instead of only the symptom (D-034).
		detail += "（Windows 路径在 JSONC 中要写双反斜杠，如 C:\\\\Users\\\\a）"
	}
	return code, pos, detail
}

func dropBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

// Load parses and validates the profile at path. The file's directory is the
// base for selftest.fixtures, which must be relative to it (spec-profile §6.1).
func Load(path string) (*Profile, error) {
	src, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return load(src, path, dirOf(path), dirFS(dirOf(path)))
}

// LoadBytes parses and validates profile bytes. Selftest fixture existence
// checks are skipped because there is no base directory.
func LoadBytes(src []byte) (*Profile, error) {
	return load(src, "<bytes>", "", nil)
}

func load(src []byte, file, baseDir string, fixtureFS fs.FS) (*Profile, error) {
	src = bytes.Clone(dropBOM(src))
	d := &decoder{src: src, file: file}

	if !utf8.Valid(src) {
		off := firstInvalidUTF8(src)
		d.errAt("E-PRF-063", d.position(off), "profile", "文件不是合法 UTF-8")
		return nil, d.errs
	}

	v, err := hujson.Parse(src)
	if err != nil {
		code, pos, detail := classifyParseError(err.Error())
		d.errAt(code, pos, "profile", "%s", detail)
		return nil, d.errs
	}
	if _, ok := v.Value.(*hujson.Object); !ok {
		d.errAt("E-PRF-065", d.pos(&v), "profile", "顶层必须是单个对象")
		return nil, d.errs
	}

	d.checkDuplicateKeys(&v)
	if len(d.errs) > 0 {
		return nil, d.errs
	}

	p := &Profile{
		File:          file,
		baseDir:       baseDir,
		fixtureFS:     fixtureFS,
		ast:           v,
		src:           src,
		MaxBytesTotal: DefaultMaxBytesTotal,
	}
	decodeProfile(d, &v, p)
	if len(d.errs) > 0 {
		return nil, d.errs
	}
	p.Warnings = append(p.Warnings, d.warns...)

	if err := Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

func firstInvalidUTF8(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return 0
}

// --- profile decoding ------------------------------------------------------

var profileKnown = map[string]bool{
	"schema_version":  true,
	"name":            true,
	"title":           true,
	"vendor":          true,
	"notes":           true,
	"applies_to":      true,
	"roots":           true,
	"defaults":        true,
	"max_bytes_total": true,
	"scan":            true,
	"entries":         true,
	"selftest":        true,
}

func decodeProfile(d *decoder, root *hujson.Value, p *Profile) {
	obj := root.Value.(*hujson.Object)
	m := objectMembers(obj)
	p.Extra = d.extra(obj, profileKnown, "profile")

	if v, ok := m["schema_version"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-001"); ok {
			p.SchemaVersion = s
		}
	} else {
		d.errf("E-PRF-001", root, "profile", "缺少 schema_version")
	}

	if v, ok := m["name"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-003"); ok {
			p.Name = s
		}
	} else {
		d.errf("E-PRF-003", root, "profile", "缺少 name")
	}

	if v, ok := m["title"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-063"); ok {
			p.Title = s
		}
	} else {
		d.errf("E-PRF-063", root, "profile", "缺少 title")
	}

	if v, ok := m["vendor"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-063"); ok {
			p.Vendor = s
		}
	}
	if v, ok := m["notes"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-063"); ok {
			p.Notes = s
		}
	}

	if v, ok := m["applies_to"]; ok {
		if o, ok := d.object(v, "applies_to", "E-PRF-063"); ok {
			am := objectMembers(o)
			osv, ok := am["os"]
			if !ok {
				d.errf("E-PRF-063", v, "applies_to", "缺少 os")
			} else if list, ok := d.stringList(osv, "applies_to.os", "E-PRF-063"); ok {
				p.AppliesTo.OS = list
			}
		}
	} else {
		d.errf("E-PRF-063", root, "profile", "缺少 applies_to")
	}

	if v, ok := m["roots"]; ok {
		decodeRoots(d, v, p)
	} else {
		d.errf("E-PRF-030", root, "roots", "profile 必须至少声明一个 root")
	}

	if v, ok := m["defaults"]; ok {
		decodeDefaults(d, v, p)
	}
	if v, ok := m["max_bytes_total"]; ok {
		if n, ok := d.integer(v, "profile", "E-PRF-062"); ok {
			p.MaxBytesTotal = n
		}
	}
	if v, ok := m["scan"]; ok {
		if s, ok := d.str(v, "profile", "E-PRF-063"); ok {
			p.Scan = s
		}
	}

	if v, ok := m["entries"]; ok {
		if arr, ok := d.array(v, "entries", "E-PRF-063"); ok {
			p.Entries = make([]*Entry, 0, len(arr.Elements))
			for i := range arr.Elements {
				e := decodeEntry(d, &arr.Elements[i], i)
				p.Entries = append(p.Entries, e)
			}
		}
	} else {
		d.errf("E-PRF-063", root, "entries", "缺少 entries")
	}

	if v, ok := m["selftest"]; ok {
		p.Selftest = decodeSelfTest(d, v)
	}
}

func decodeRoots(d *decoder, v *hujson.Value, p *Profile) {
	obj, ok := d.object(v, "roots", "E-PRF-030")
	if !ok {
		return
	}
	p.Roots = make(map[string]Root, len(obj.Members))
	for i := range obj.Members {
		mem := &obj.Members[i]
		name, ok := literalName(&mem.Name)
		if !ok {
			d.errf("E-PRF-030", &mem.Name, "roots", "root 名必须是字符串")
			continue
		}
		r := Root{Pos: d.pos(&mem.Value)}
		switch x := mem.Value.Value.(type) {
		case hujson.Literal:
			if x.Kind() != '"' {
				d.errf("E-PRF-030", &mem.Value, "root "+name, "期望字符串或按 OS 的对象")
				continue
			}
			r.Template = x.String()
		case *hujson.Object:
			r.PerOS = make(map[string]string, len(x.Members))
			for j := range x.Members {
				om := &x.Members[j]
				osName, ok := literalName(&om.Name)
				if !ok {
					d.errf("E-PRF-030", &om.Name, "root "+name, "OS 名必须是字符串")
					continue
				}
				s, ok := d.str(&om.Value, "root "+name, "E-PRF-030")
				if ok {
					r.PerOS[osName] = s
				}
			}
		default:
			d.errf("E-PRF-030", &mem.Value, "root "+name, "期望字符串或按 OS 的对象")
			continue
		}
		p.Roots[name] = r
		p.RootOrder = append(p.RootOrder, name)
	}
	if len(p.Roots) == 0 {
		d.errf("E-PRF-030", v, "roots", "profile 必须至少声明一个 root")
	}
}

func decodeDefaults(d *decoder, v *hujson.Value, p *Profile) {
	obj, ok := d.object(v, "defaults", "E-PRF-063")
	if !ok {
		return
	}
	p.Defaults.Pos = d.pos(v)
	m := objectMembers(obj)
	if fv, ok := m["max_bytes_inline"]; ok {
		if n, ok := d.integer(fv, "defaults", "E-PRF-013"); ok {
			p.Defaults.MaxBytesInline = &n
		}
	}
	if fv, ok := m["max_bytes_structure"]; ok {
		if n, ok := d.integer(fv, "defaults", "E-PRF-049"); ok {
			p.Defaults.MaxBytesStructure = &n
		}
	}
	if fv, ok := m["max_bytes_total"]; ok {
		if n, ok := d.integer(fv, "defaults", "E-PRF-052"); ok {
			p.Defaults.MaxBytesTotal = &n
		}
	}
	if fv, ok := m["follow_symlinks"]; ok {
		if b, ok := d.boolean(fv, "defaults", "E-PRF-063"); ok {
			p.Defaults.FollowSymlinks = &b
		}
	}
	if fv, ok := m["expand"]; ok {
		if s, ok := d.str(fv, "defaults", "E-PRF-063"); ok {
			p.Defaults.Expand = s
		}
	}
	if fv, ok := m["max_depth"]; ok {
		if n, ok := d.integer(fv, "defaults", "E-PRF-014"); ok {
			n32 := int(n)
			p.Defaults.MaxDepth = &n32
		}
	}
	if fv, ok := m["exclude"]; ok {
		if list, ok := d.stringList(fv, "defaults", "E-PRF-063"); ok {
			p.Defaults.Exclude = list
		}
	}
	if fv, ok := m["scan"]; ok {
		if s, ok := d.str(fv, "defaults", "E-PRF-063"); ok {
			p.Defaults.Scan = s
		}
	}
}

var entryKnown = map[string]bool{
	"id": true, "kind": true, "root": true, "path": true, "paths": true,
	"locator": true, "probe": true, "os": true, "layer": true, "secret": true,
	"extractor": true, "scan": true, "signals": true, "priority": true,
	"parts": true, "parts_uncovered": true, "path_semantics": true,
	"derived_from": true, "churn": true, "needed_by": true, "companions": true,
	"side_effects": true, "open_as": true, "opaque_content": true,
	"binary": true, "max_bytes_inline": true, "max_bytes_structure": true,
	"max_bytes_total": true, "expand": true, "max_depth": true,
	"exclude": true, "follow_symlinks": true, "dedupe_targets": true,
	"case_sensitive": true, "unique_within": true, "aggregate_above": true,
	"export_group": true, "notes": true, "redact": true,
	"selftest_exempt": true, "scope": true, "under": true,
}

func entrySubject(index int, id string) string {
	if id == "" {
		return fmt.Sprintf("entries[%d]", index)
	}
	return fmt.Sprintf("entries[%d](%s)", index, id)
}

func decodeEntry(d *decoder, v *hujson.Value, index int) *Entry {
	e := &Entry{Pos: d.pos(v)}
	subj := entrySubject(index, "")
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		d.errf("E-PRF-063", v, subj, "条目必须是对象")
		return e
	}
	m := objectMembers(obj)

	if fv, ok := m["id"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			e.ID = s
		}
	} else {
		d.errf("E-PRF-063", v, subj, "缺少 id")
	}
	subj = entrySubject(index, e.ID)
	e.Extra = d.extra(obj, entryKnown, subj)

	if fv, ok := m["kind"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-005"); ok {
			e.Kind = s
		}
	} else {
		d.errf("E-PRF-005", v, subj, "缺少 kind")
	}
	if fv, ok := m["root"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-011"); ok {
			e.Root = s
		}
	}
	if fv, ok := m["path"]; ok {
		e.PathSet = true
		if s, ok := d.str(fv, subj, "E-PRF-009"); ok {
			e.Path = s
		}
	}
	if fv, ok := m["paths"]; ok {
		e.PathsSet = true
		if list, ok := d.stringList(fv, subj, "E-PRF-009"); ok {
			e.Paths = list
		}
	}
	if fv, ok := m["locator"]; ok {
		e.Locator = decodeLocator(d, fv, subj)
	}
	if fv, ok := m["probe"]; ok {
		e.Probe = decodeProbe(d, fv, subj)
	}
	if fv, ok := m["os"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-063"); ok {
			e.OS = list
		}
	}
	if fv, ok := m["layer"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-006"); ok {
			e.Layer = s
		}
	}
	if fv, ok := m["secret"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-007"); ok {
			e.Secret = s
		}
	}
	if fv, ok := m["extractor"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-008"); ok {
			e.Extractor = s
		}
	}
	if fv, ok := m["scan"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-028"); ok {
			e.Scan = s
		}
	}
	if fv, ok := m["signals"]; ok {
		e.Signals = decodeSignals(d, fv, subj)
	}
	if fv, ok := m["priority"]; ok {
		e.PrioritySet = true
		if n, ok := d.integer(fv, subj, "E-PRF-046"); ok {
			e.Priority = int(n)
		}
	}
	if fv, ok := m["parts"]; ok {
		e.PartsSet = true
		if arr, ok := d.array(fv, subj, "E-PRF-032"); ok {
			e.Parts = make([]*Part, 0, len(arr.Elements))
			for i := range arr.Elements {
				e.Parts = append(e.Parts, decodePart(d, &arr.Elements[i], subj, i))
			}
		}
	}
	if fv, ok := m["parts_uncovered"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-068"); ok {
			e.PartsUncovered = s
		}
	}
	if fv, ok := m["path_semantics"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-038"); ok {
			e.PathSemantics = s
		}
	}
	if fv, ok := m["derived_from"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-038"); ok {
			e.DerivedFrom = s
		}
	}
	if fv, ok := m["churn"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-048"); ok {
			e.Churn = s
		}
	}
	if fv, ok := m["needed_by"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-063"); ok {
			e.NeededBy = list
		}
	}
	if fv, ok := m["companions"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-045"); ok {
			e.Companions = list
		}
	}
	if fv, ok := m["side_effects"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-061"); ok {
			e.SideEffects = list
		}
	}
	if fv, ok := m["open_as"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-071"); ok {
			e.OpenAs = s
		}
	}
	if fv, ok := m["opaque_content"]; ok {
		if b, ok := d.boolean(fv, subj, "E-PRF-063"); ok {
			e.OpaqueContent = b
		}
	} else if fv, ok := m["binary"]; ok {
		// v1 alias (D-021 第 3 条 / D-024 第 6 条).
		if b, ok := d.boolean(fv, subj, "E-PRF-063"); ok {
			e.OpaqueContent = b
			d.warnf("W-PRF-101", fv, subj, "binary 是旧名，已映射为 opaque_content")
		}
	}
	if fv, ok := m["max_bytes_inline"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-013"); ok {
			e.MaxBytesInline = &n
		}
	}
	if fv, ok := m["max_bytes_structure"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-049"); ok {
			e.MaxBytesStructure = &n
		}
	}
	if fv, ok := m["max_bytes_total"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-052"); ok {
			e.MaxBytesTotal = &n
		}
	}
	if fv, ok := m["expand"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			e.Expand = s
		}
	}
	if fv, ok := m["max_depth"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-014"); ok {
			n32 := int(n)
			e.MaxDepth = &n32
		}
	}
	if fv, ok := m["exclude"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-063"); ok {
			e.Exclude = list
		}
	}
	if fv, ok := m["follow_symlinks"]; ok {
		if b, ok := d.boolean(fv, subj, "E-PRF-063"); ok {
			e.FollowSymlinks = &b
		}
	}
	if fv, ok := m["dedupe_targets"]; ok {
		if b, ok := d.boolean(fv, subj, "E-PRF-063"); ok {
			e.DedupeTargets = &b
		}
	}
	if fv, ok := m["case_sensitive"]; ok {
		if b, ok := d.boolean(fv, subj, "E-PRF-063"); ok {
			e.CaseSensitive = &b
		}
	}
	if fv, ok := m["unique_within"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-047"); ok {
			e.UniqueWithin = s
		}
	}
	if fv, ok := m["aggregate_above"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-063"); ok {
			n32 := int(n)
			e.AggregateAbove = &n32
		}
	}
	if fv, ok := m["export_group"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			e.ExportGroup = s
		}
	}
	if fv, ok := m["notes"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			e.Notes = s
		}
	}
	if fv, ok := m["redact"]; ok {
		e.Redact = decodeRedact(d, fv, subj)
	}
	if fv, ok := m["selftest_exempt"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			e.SelftestExempt = s
		}
	}
	if fv, ok := m["scope"]; ok {
		e.ScopeSet = true
		if s, ok := d.str(fv, subj, "E-PRF-070"); ok {
			e.Scope = s
		}
	}
	if fv, ok := m["under"]; ok {
		e.UnderSet = true
		if s, ok := d.str(fv, subj, "E-PRF-070"); ok {
			e.Under = s
		}
	}
	return e
}

func decodeLocator(d *decoder, v *hujson.Value, subject string) Locator {
	if lit, ok := v.Value.(hujson.Literal); ok && lit.Kind() == '"' {
		return Locator{Value: lit.String()}
	}
	if obj, ok := v.Value.(*hujson.Object); ok {
		l := Locator{PerOS: make(map[string]string, len(obj.Members))}
		for i := range obj.Members {
			mem := &obj.Members[i]
			name, ok := literalName(&mem.Name)
			if !ok {
				continue
			}
			if s, ok := d.str(&mem.Value, subject, "E-PRF-060"); ok {
				l.PerOS[name] = s
			}
		}
		return l
	}
	d.errf("E-PRF-060", v, subject, "locator 期望字符串或按 OS 的对象")
	return Locator{}
}

func decodeProbe(d *decoder, v *hujson.Value, subject string) Probe {
	if lit, ok := v.Value.(hujson.Literal); ok && lit.Kind() == '"' {
		return Probe{Value: lit.String()}
	}
	if obj, ok := v.Value.(*hujson.Object); ok {
		p := Probe{PerOS: make(map[string]string, len(obj.Members))}
		for i := range obj.Members {
			mem := &obj.Members[i]
			name, ok := literalName(&mem.Name)
			if !ok {
				continue
			}
			if s, ok := d.str(&mem.Value, subject, "E-PRF-060"); ok {
				p.PerOS[name] = s
			}
		}
		return p
	}
	d.errf("E-PRF-060", v, subject, "probe 期望字符串或按 OS 的对象")
	return Probe{}
}

func decodeSignals(d *decoder, v *hujson.Value, subject string) []Signal {
	arr, ok := d.array(v, subject, "E-PRF-015")
	if !ok {
		return nil
	}
	out := make([]Signal, 0, len(arr.Elements))
	for i := range arr.Elements {
		sv := &arr.Elements[i]
		obj, ok := d.object(sv, subject, "E-PRF-015")
		if !ok {
			continue
		}
		m := objectMembers(obj)
		sig := Signal{Pos: d.pos(sv)}
		if fv, ok := m["src"]; ok {
			if s, ok := d.str(fv, subject, "E-PRF-015"); ok {
				sig.Src = s
			}
		}
		if fv, ok := m["note"]; ok {
			if s, ok := d.str(fv, subject, "E-PRF-015"); ok {
				sig.Note = s
			}
		}
		if fv, ok := m["url"]; ok {
			if s, ok := d.str(fv, subject, "E-PRF-016"); ok {
				sig.URL = s
			}
		}
		out = append(out, sig)
	}
	return out
}

func decodeRedact(d *decoder, v *hujson.Value, subject string) *Redact {
	obj, ok := d.object(v, subject, "E-PRF-063")
	if !ok {
		return nil
	}
	m := objectMembers(obj)
	r := &Redact{Pos: d.pos(v)}
	if fv, ok := m["json_pointer"]; ok {
		if list, ok := d.stringList(fv, subject, "E-PRF-063"); ok {
			r.JSONPointer = list
		}
	}
	if fv, ok := m["key_pattern"]; ok {
		if list, ok := d.stringList(fv, subject, "E-PRF-063"); ok {
			r.KeyPattern = list
		}
	}
	if fv, ok := m["toml_section"]; ok {
		if list, ok := d.stringList(fv, subject, "E-PRF-063"); ok {
			r.TOMLSection = list
		}
	}
	if fv, ok := m["replacement"]; ok {
		if s, ok := d.str(fv, subject, "E-PRF-063"); ok {
			r.Replacement = s
		}
	}
	return r
}

var partKnown = map[string]bool{
	"id": true, "selector": true, "layer": true, "secret": true,
	"extractor": true, "signals": true, "redact": true,
	"max_bytes_inline": true, "max_bytes_structure": true,
	"needed_by": true, "notes": true, "path_semantics": true,
	"derived_from": true, "origin": true, "origin_path_key": true,
}

// partForbidden are entry-only fields that a part may not override
// (E-PRF-036). id, path_semantics, derived_from, origin and origin_path_key
// are explicitly allowed (D-024 第 3 条).
var partForbidden = map[string]bool{
	"kind": true, "path": true, "paths": true, "root": true,
	"priority": true, "churn": true, "companions": true, "os": true,
}

func decodePart(d *decoder, v *hujson.Value, entrySubj string, index int) *Part {
	p := &Part{Pos: d.pos(v)}
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		d.errf("E-PRF-033", v, entrySubj, "part 必须是对象")
		return p
	}
	m := objectMembers(obj)
	if fv, ok := m["id"]; ok {
		if s, ok := d.str(fv, entrySubj, "E-PRF-035"); ok {
			p.ID = s
		}
	}
	subj := fmt.Sprintf("%s.parts[%d](%s)", entrySubj, index, p.ID)

	// Forbidden fields are diagnosed, not silently retained.
	for i := range obj.Members {
		mem := &obj.Members[i]
		name, ok := literalName(&mem.Name)
		if ok && partForbidden[name] {
			d.errf("E-PRF-036", &mem.Value, subj, "part 不可写字段 %q", name)
		}
	}
	p.Extra = d.extra(obj, partKnown, subj)

	if fv, ok := m["selector"]; ok {
		p.Selector = decodeSelector(d, fv, subj)
	} else {
		d.errf("E-PRF-033", v, subj, "缺少 selector")
	}
	if fv, ok := m["layer"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-006"); ok {
			p.Layer = s
		}
	}
	if fv, ok := m["secret"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-007"); ok {
			p.Secret = s
		}
	}
	if fv, ok := m["extractor"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-008"); ok {
			p.Extractor = s
		}
	}
	if fv, ok := m["signals"]; ok {
		p.Signals = decodeSignals(d, fv, subj)
	}
	if fv, ok := m["redact"]; ok {
		p.Redact = decodeRedact(d, fv, subj)
	}
	if fv, ok := m["max_bytes_inline"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-013"); ok {
			p.MaxBytesInline = &n
		}
	}
	if fv, ok := m["max_bytes_structure"]; ok {
		if n, ok := d.integer(fv, subj, "E-PRF-049"); ok {
			p.MaxBytesStructure = &n
		}
	}
	if fv, ok := m["needed_by"]; ok {
		if list, ok := d.stringList(fv, subj, "E-PRF-063"); ok {
			p.NeededBy = list
		}
	}
	if fv, ok := m["notes"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-063"); ok {
			p.Notes = s
		}
	}
	if fv, ok := m["path_semantics"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-038"); ok {
			p.PathSemantics = s
		}
	}
	if fv, ok := m["derived_from"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-038"); ok {
			p.DerivedFrom = s
		}
	}
	if fv, ok := m["origin"]; ok {
		if lit, ok := fv.Value.(hujson.Literal); ok && lit.Kind() == 'n' {
			// Explicit null is allowed; Origin stays nil.
		} else if s, ok := d.str(fv, subj, "E-PRF-069"); ok {
			p.Origin = &s
		}
	}
	if fv, ok := m["origin_path_key"]; ok {
		if s, ok := d.str(fv, subj, "E-PRF-069"); ok {
			p.OriginPathKey = &s
		}
	}
	return p
}

func decodeSelector(d *decoder, v *hujson.Value, subject string) Selector {
	obj, ok := d.object(v, subject, "E-PRF-033")
	if !ok {
		return Selector{}
	}
	if len(obj.Members) != 1 {
		d.errf("E-PRF-033", v, subject, "selector 必须恰含一个键")
	}
	var sel Selector
	sel.Pos = d.pos(v)
	for i := range obj.Members {
		mem := &obj.Members[i]
		name, ok := literalName(&mem.Name)
		if !ok {
			continue
		}
		switch name {
		case "json_pointer", "line_pattern", "toml_section":
			if s, ok := d.str(&mem.Value, subject, "E-PRF-033"); ok {
				if sel.Kind != "" {
					d.errf("E-PRF-033", &mem.Name, subject, "selector 必须恰含一个键")
					continue
				}
				sel.Kind = name
				sel.Value = s
			}
		default:
			d.errf("E-PRF-033", &mem.Name, subject, "未知 selector 键 %q", name)
		}
	}
	if sel.Kind == "" {
		d.errf("E-PRF-033", v, subject, "selector 缺少 json_pointer/line_pattern/toml_section")
	}
	return sel
}

// --- selftest decoding -----------------------------------------------------

var selftestKnown = map[string]bool{
	"clock": true, "fixtures": true, "files": true, "dirs": true,
	"symlinks": true, "expect": true, "expect_absent": true, "budget": true,
}

func decodeSelfTest(d *decoder, v *hujson.Value) *SelfTest {
	obj, ok := d.object(v, "selftest", "E-PRF-017")
	if !ok {
		return nil
	}
	st := &SelfTest{Pos: d.pos(v)}
	m := objectMembers(obj)
	st.Extra = d.extra(obj, selftestKnown, "selftest")

	if fv, ok := m["clock"]; ok {
		if s, ok := d.str(fv, "selftest", "E-PRF-063"); ok {
			st.Clock = s
		}
	}
	if fv, ok := m["fixtures"]; ok {
		if o, ok := d.object(fv, "selftest.fixtures", "E-PRF-027"); ok {
			st.Fixtures = make(map[string]string, len(o.Members))
			for i := range o.Members {
				mem := &o.Members[i]
				name, ok := literalName(&mem.Name)
				if !ok {
					continue
				}
				if s, ok := d.str(&mem.Value, "selftest.fixtures", "E-PRF-027"); ok {
					st.Fixtures[name] = s
					st.FixtureOrder = append(st.FixtureOrder, name)
				}
			}
		}
	}
	if fv, ok := m["files"]; ok {
		if arr, ok := d.array(fv, "selftest.files", "E-PRF-067"); ok {
			for i := range arr.Elements {
				ev := &arr.Elements[i]
				o, ok := d.object(ev, "selftest.files", "E-PRF-067")
				if !ok {
					continue
				}
				em := objectMembers(o)
				fs := FileSpec{Pos: d.pos(ev)}
				if pv, ok := em["path"]; ok {
					if s, ok := d.str(pv, "selftest.files", "E-PRF-067"); ok {
						fs.Path = s
					}
				}
				if sv, ok := em["size"]; ok {
					if n, ok := d.integer(sv, "selftest.files", "E-PRF-067"); ok {
						fs.Size = n
					}
				}
				st.Files = append(st.Files, fs)
			}
		}
	}
	if fv, ok := m["dirs"]; ok {
		if list, ok := d.stringList(fv, "selftest.dirs", "E-PRF-067"); ok {
			st.Dirs = list
		}
	}
	if fv, ok := m["symlinks"]; ok {
		if arr, ok := d.array(fv, "selftest.symlinks", "E-PRF-067"); ok {
			for i := range arr.Elements {
				ev := &arr.Elements[i]
				o, ok := d.object(ev, "selftest.symlinks", "E-PRF-067")
				if !ok {
					continue
				}
				em := objectMembers(o)
				spec := SymlinkSpec{Pos: d.pos(ev)}
				if pv, ok := em["path"]; ok {
					if s, ok := d.str(pv, "selftest.symlinks", "E-PRF-067"); ok {
						spec.Path = s
					}
				}
				if tv, ok := em["target"]; ok {
					if s, ok := d.str(tv, "selftest.symlinks", "E-PRF-067"); ok {
						spec.Target = s
					}
				}
				st.Symlinks = append(st.Symlinks, spec)
			}
		}
	}
	if fv, ok := m["expect"]; ok {
		if arr, ok := d.array(fv, "selftest.expect", "E-PRF-017"); ok {
			for i := range arr.Elements {
				st.Expect = append(st.Expect, decodeExpect(d, &arr.Elements[i]))
			}
		}
	}
	if fv, ok := m["expect_absent"]; ok {
		if arr, ok := d.array(fv, "selftest.expect_absent", "E-PRF-017"); ok {
			for i := range arr.Elements {
				av := &arr.Elements[i]
				o, ok := d.object(av, "selftest.expect_absent", "E-PRF-017")
				if !ok {
					continue
				}
				am := objectMembers(o)
				a := Absent{Pos: d.pos(av)}
				if pv, ok := am["root"]; ok {
					if s, ok := d.str(pv, "selftest.expect_absent", "E-PRF-027"); ok {
						a.Root = s
					}
				}
				if pv, ok := am["match"]; ok {
					if s, ok := d.str(pv, "selftest.expect_absent", "E-PRF-027"); ok {
						a.Match = s
					}
				}
				st.ExpectAbsent = append(st.ExpectAbsent, a)
			}
		}
	}
	if fv, ok := m["budget"]; ok {
		if o, ok := d.object(fv, "selftest.budget", "E-PRF-050"); ok {
			b := &Budget{Pos: d.pos(fv)}
			bm := objectMembers(o)
			if wv, ok := bm["wall_ms"]; ok {
				if n, ok := d.integer(wv, "selftest.budget", "E-PRF-050"); ok {
					b.WallMS = n
				}
			}
			if rv, ok := bm["max_rss_mib"]; ok {
				if n, ok := d.integer(rv, "selftest.budget", "E-PRF-050"); ok {
					b.MaxRSSMiB = n
				}
			}
			st.Budget = b
		}
	}
	return st
}

var expectKnown = map[string]bool{
	"entry": true, "part": true, "root": true, "match": true, "os": true,
	"layer": true, "secret": true, "action": true, "risk_flags": true,
	"confidence": true,
}

func decodeExpect(d *decoder, v *hujson.Value) Expect {
	e := Expect{Pos: d.pos(v)}
	o, ok := d.object(v, "selftest.expect", "E-PRF-019")
	if !ok {
		return e
	}
	m := objectMembers(o)
	d.extra(o, expectKnown, "selftest.expect")
	if fv, ok := m["entry"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-020"); ok {
			e.Entry = s
		}
	}
	if fv, ok := m["part"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-057"); ok {
			e.Part = s
		}
	}
	if fv, ok := m["root"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-027"); ok {
			e.Root = s
		}
	}
	if fv, ok := m["match"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-019"); ok {
			e.Match = s
		}
	}
	if fv, ok := m["os"]; ok {
		if list, ok := d.stringList(fv, "selftest.expect", "E-PRF-063"); ok {
			e.OS = list
		}
	}
	if fv, ok := m["layer"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-063"); ok {
			e.Layer = s
		}
	}
	if fv, ok := m["secret"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-063"); ok {
			e.Secret = s
		}
	}
	if fv, ok := m["action"]; ok {
		if s, ok := d.str(fv, "selftest.expect", "E-PRF-063"); ok {
			e.Action = s
		}
	}
	if fv, ok := m["risk_flags"]; ok {
		if list, ok := d.stringList(fv, "selftest.expect", "E-PRF-063"); ok {
			e.RiskFlags = list
		}
	}
	if fv, ok := m["confidence"]; ok {
		if f, ok := d.number(fv, "selftest.expect", "E-PRF-063"); ok {
			e.Confidence = &f
		}
	}
	return e
}

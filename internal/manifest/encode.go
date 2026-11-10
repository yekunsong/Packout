package manifest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// jsonBuf is a small append-only JSON writer. It keeps a stack of "first
// element?" flags so consecutive fields are separated by exactly one comma and
// no insignificant whitespace is ever emitted (spec §1).
type jsonBuf struct {
	b     []byte
	first []bool
}

func (j *jsonBuf) beginObject() {
	j.b = append(j.b, '{')
	j.first = append(j.first, true)
}

func (j *jsonBuf) endObject() {
	j.b = append(j.b, '}')
	j.first = j.first[:len(j.first)-1]
}

func (j *jsonBuf) beginArray() {
	j.b = append(j.b, '[')
	j.first = append(j.first, true)
}

func (j *jsonBuf) endArray() {
	j.b = append(j.b, ']')
	j.first = j.first[:len(j.first)-1]
}

// field writes `"name":` and handles the separating comma.
func (j *jsonBuf) field(name string) {
	d := len(j.first) - 1
	if !j.first[d] {
		j.b = append(j.b, ',')
	} else {
		j.first[d] = false
	}
	j.b = appendJSONString(j.b, name)
	j.b = append(j.b, ':')
}

// elem separates array elements.
func (j *jsonBuf) elem() {
	d := len(j.first) - 1
	if !j.first[d] {
		j.b = append(j.b, ',')
	} else {
		j.first[d] = false
	}
}

func (j *jsonBuf) raw(s string) { j.b = append(j.b, s...) }

func (j *jsonBuf) null() { j.raw("null") }

func (j *jsonBuf) boolean(v bool) {
	if v {
		j.raw("true")
	} else {
		j.raw("false")
	}
}

func (j *jsonBuf) integer(v int64) { j.b = strconv.AppendInt(j.b, v, 10) }

func (j *jsonBuf) str(s string) { j.b = appendJSONString(j.b, s) }

func (j *jsonBuf) strOrNull(p *string) {
	if p == nil {
		j.null()
		return
	}
	j.str(*p)
}

func (j *jsonBuf) intOrNull(p *int64) {
	if p == nil {
		j.null()
		return
	}
	j.integer(*p)
}

func (j *jsonBuf) timeOrNull(t *time.Time) {
	if t == nil {
		j.null()
		return
	}
	j.time(*t)
}

// time writes a quoted RFC 3339 timestamp.
func (j *jsonBuf) time(t time.Time) {
	j.b = append(j.b, '"')
	j.b = append(j.b, appendRFC3339Nano(nil, t)...)
	j.b = append(j.b, '"')
}

// appendJSONString writes a JSON string with no HTML escaping (§1). Invalid
// UTF-8 is replaced rather than emitting a malformed record.
func appendJSONString(dst []byte, s string) []byte {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

// appendRFC3339Nano formats t in UTC with nanosecond precision. The 9s layout
// trims trailing zeroes, matching RFC 3339 examples such as
// "2026-11-10T09:12:03.4123456Z" (§3.1).
func appendRFC3339Nano(dst []byte, t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.999999999Z")
}

// EncodeUnit serialises u with the fixed field order of §4.1. The result does
// not contain a trailing newline. Optional fields are omitted exactly where
// the spec marks them optional; required keys are always written (with null
// where the spec allows null).
func EncodeUnit(u *Unit) []byte {
	var j jsonBuf
	j.beginObject()

	j.field("type")
	j.str(TypeUnit)
	j.field("schema_version")
	j.str(u.SchemaVersion)
	j.field("id")
	j.str(u.ID)
	j.field("cid")
	j.strOrNull(u.CID)
	j.field("path")
	j.str(u.Path)
	j.field("path_key")
	j.str(u.PathKey)
	j.field("root")
	j.str(u.Root)
	j.field("path_semantics")
	j.str(u.PathSemantics)
	j.field("derived_from")
	j.strOrNull(u.DerivedFrom)

	// origin and origin_path_key form a pair: either both are emitted or
	// neither is (§4.9). A caller that supplies only one is validated later.
	if u.Origin != nil || u.OriginPathKey != nil {
		j.field("origin")
		j.strOrNull(u.Origin)
		j.field("origin_path_key")
		j.strOrNull(u.OriginPathKey)
	}

	j.field("profile")
	j.str(u.Profile)
	j.field("entry")
	j.str(u.Entry)
	if u.PartID != "" {
		j.field("part_id")
		j.str(u.PartID)
	}
	j.field("kind")
	j.str(u.Kind)
	j.field("layer")
	j.str(u.Layer)
	j.field("confidence")
	j.raw(fmt.Sprintf("%.3f", u.Confidence))

	j.field("signals")
	writeSignals(&j, u.Signals, u.Kind == KindCatchAll)

	j.field("secret")
	writeSecret(&j, u.Secret)

	if u.ContainsSecret != nil {
		j.field("contains_secret")
		j.boolean(*u.ContainsSecret)
	}
	if u.MayContainSecret != nil {
		j.field("may_contain_secret")
		j.boolean(*u.MayContainSecret)
	}

	j.field("size_apparent")
	j.intOrNull(u.SizeApparent)
	j.field("size_alloc")
	j.intOrNull(u.SizeAlloc)
	j.field("mtime")
	j.timeOrNull(u.MTime)
	j.field("file_id")
	writeFileID(&j, u.FileID)
	j.field("fingerprint")
	writeFingerprint(&j, u.Fingerprint)

	if u.Owner != nil {
		j.field("owner")
		j.beginObject()
		j.field("kind")
		j.str(u.Owner.Kind)
		j.field("value")
		j.str(u.Owner.Value)
		writeExtra(&j, u.Owner.Extra, u.Owner.extraOrder)
		j.endObject()
	}
	if u.ACL != nil {
		j.field("acl")
		j.beginObject()
		j.field("algo")
		j.str(u.ACL.Algo)
		j.field("value")
		j.str(u.ACL.Value)
		j.field("entries")
		j.integer(int64(u.ACL.Entries))
		j.field("truncated")
		j.boolean(u.ACL.Truncated)
		writeExtra(&j, u.ACL.Extra, u.ACL.extraOrder)
		j.endObject()
	}
	if u.SizeEstimated {
		j.field("size_estimated")
		j.boolean(true)
	}
	if u.AggregateCount != nil {
		j.field("aggregate_count")
		j.integer(*u.AggregateCount)
	}
	j.field("proposed_action")
	j.str(u.ProposedAction)
	j.field("risk_flags")
	writeStringArray(&j, canonicalRiskFlags(u.RiskFlags))

	if len(u.NeededBy) > 0 {
		j.field("needed_by")
		writeStringArray(&j, canonicalNeededBy(u.NeededBy))
	}
	if len(u.Companions) > 0 {
		j.field("companions")
		writeStringArray(&j, u.Companions)
	}
	if len(u.SideEffects) > 0 {
		j.field("side_effects")
		writeStringArray(&j, canonicalSideEffects(u.SideEffects))
	}
	if u.OpenAs != "" {
		j.field("open_as")
		j.str(u.OpenAs)
	}
	if u.OpaqueContent {
		j.field("opaque_content")
		j.boolean(true)
	}
	if u.LinkTarget != "" {
		j.field("link_target")
		j.str(u.LinkTarget)
	}
	if u.SecretRef != "" {
		j.field("secret_ref")
		j.str(u.SecretRef)
	}
	if u.Notes != "" {
		j.field("notes")
		j.str(u.Notes)
	}

	writeExtra(&j, u.Extra, u.extraOrder)
	j.endObject()
	return j.b
}

func writeStringArray(j *jsonBuf, values []string) {
	j.beginArray()
	for _, v := range values {
		j.elem()
		j.str(v)
	}
	j.endArray()
}

func writeSignals(j *jsonBuf, signals []Signal, catchAll bool) {
	ordered := signals
	if !catchAll {
		ordered = canonicalSignals(signals)
	}
	j.beginArray()
	for _, s := range ordered {
		j.elem()
		j.beginObject()
		j.field("src")
		j.str(s.Src)
		j.field("note")
		j.str(s.Note)
		j.field("url")
		j.strOrNull(s.URL)
		writeExtra(j, s.Extra, s.extraOrder)
		j.endObject()
	}
	j.endArray()
}

func writeSecret(j *jsonBuf, s *Secret) {
	if s == nil {
		j.null()
		return
	}
	j.beginObject()
	j.field("class")
	j.str(s.Class)
	j.field("hits")
	j.beginArray()
	for _, h := range s.Hits {
		j.elem()
		j.beginObject()
		j.field("kind")
		j.str(h.Kind)
		j.field("class")
		j.str(h.Class)
		if h.Locator != "" {
			j.field("locator")
			j.str(h.Locator)
		}
		if h.Prefix != "" {
			j.field("prefix")
			j.str(h.Prefix)
		}
		if h.Fingerprint != "" {
			j.field("fingerprint")
			j.str(h.Fingerprint)
		}
		if h.HitID != "" {
			j.field("hit_id")
			j.str(h.HitID)
		}
		writeExtra(j, h.Extra, h.extraOrder)
		j.endObject()
	}
	j.endArray()
	j.field("hit_count")
	j.integer(int64(s.HitCount))
	j.field("truncated")
	j.boolean(s.Truncated)
	writeExtra(j, s.Extra, s.extraOrder)
	j.endObject()
}

func writeFileID(j *jsonBuf, id *FileID) {
	if id == nil {
		j.null()
		return
	}
	j.beginObject()
	j.field("volume_serial")
	j.str(id.VolumeSerial)
	j.field("index")
	j.str(id.Index)
	j.field("reparse_tag")
	if len(id.ReparseTag) == 0 {
		j.null()
	} else {
		j.b = append(j.b, id.ReparseTag...)
	}
	writeExtra(j, id.Extra, id.extraOrder)
	j.endObject()
}

func writeFingerprint(j *jsonBuf, fp *Fingerprint) {
	if fp == nil {
		j.null()
		return
	}
	j.beginObject()
	j.field("algo")
	j.str(fp.Algo)
	j.field("scope")
	if fp.Scope == "" {
		j.null()
	} else {
		j.str(fp.Scope)
	}
	j.field("value")
	j.strOrNull(fp.Value)
	writeExtra(j, fp.Extra, fp.extraOrder)
	j.endObject()
}

// writeExtra emits unknown fields after all known fields. Fields that were
// read keep their original order; keys added programmatically are emitted in
// byte order so output stays deterministic (§1, §7).
func writeExtra(j *jsonBuf, extra map[string][]byte, order []string) {
	if len(extra) == 0 {
		return
	}
	seen := make(map[string]bool, len(extra))
	for _, k := range order {
		v, ok := extra[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		j.field(k)
		j.b = append(j.b, v...)
	}
	var rest []string
	for k := range extra {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		j.field(k)
		j.b = append(j.b, extra[k]...)
	}
}

// EncodeHeader serialises h in the fixed order of §3.1.
func EncodeHeader(h *Header) []byte {
	var j jsonBuf
	j.beginObject()
	j.field("type")
	j.str(TypeHeader)
	j.field("manifest_version")
	j.str(h.ManifestVersion)
	j.field("scan_id")
	j.str(h.ScanID)

	j.field("scan_segment")
	j.beginObject()
	j.field("parent")
	j.strOrNull(h.ScanSegment.Parent)
	j.field("segment_seq")
	j.integer(int64(h.ScanSegment.SegmentSeq))
	j.field("first_shard")
	j.integer(int64(h.ScanSegment.FirstShard))
	writeExtra(&j, h.ScanSegment.Extra, h.ScanSegment.extraOrder)
	j.endObject()

	j.field("started_at")
	j.time(h.StartedAt)
	j.field("tool")
	j.str(h.Tool)

	j.field("host")
	j.beginObject()
	j.field("os")
	j.str(h.Host.OS)
	if h.Host.OSVersion != "" {
		j.field("os_version")
		j.str(h.Host.OSVersion)
	}
	j.field("arch")
	j.str(h.Host.Arch)
	j.field("case_sensitivity")
	j.str(h.Host.CaseSensitivity)
	j.field("path_fold_version")
	j.str(h.Host.PathFoldVersion)
	if len(h.Host.VolumeIDs) > 0 {
		j.field("volume_ids")
		j.beginArray()
		for _, v := range h.Host.VolumeIDs {
			j.elem()
			j.beginObject()
			j.field("root")
			j.str(v.Root)
			j.field("serial")
			j.str(v.Serial)
			writeExtra(&j, v.Extra, v.extraOrder)
			j.endObject()
		}
		j.endArray()
	}
	writeExtra(&j, h.Host.Extra, h.Host.extraOrder)
	j.endObject()

	j.field("inputs")
	j.beginObject()
	j.field("secret_salt_mode")
	j.str(h.Inputs.SecretSaltMode)
	j.field("secret_salt")
	j.str(h.Inputs.SecretSalt)
	j.field("profiles")
	j.beginArray()
	for _, p := range h.Inputs.Profiles {
		j.elem()
		j.beginObject()
		j.field("name")
		j.str(p.Name)
		j.field("version")
		j.str(p.Version)
		j.field("sha256")
		j.str(p.SHA256)
		writeExtra(&j, p.Extra, p.extraOrder)
		j.endObject()
	}
	j.endArray()
	if h.Inputs.Options != nil {
		j.field("options")
		j.beginObject()
		j.field("follow_symlinks")
		j.boolean(h.Inputs.Options.FollowSymlinks)
		writeExtra(&j, h.Inputs.Options.Extra, h.Inputs.Options.extraOrder)
		j.endObject()
	}
	writeExtra(&j, h.Inputs.Extra, h.Inputs.extraOrder)
	j.endObject()

	j.field("shard_units")
	j.integer(int64(h.ShardUnits))
	j.field("shard_bytes")
	j.integer(h.ShardBytes)
	j.field("roots")
	j.beginArray()
	for _, r := range h.Roots {
		j.elem()
		j.beginObject()
		j.field("name")
		j.str(r.Name)
		j.field("role")
		j.str(r.Role)
		j.field("instance")
		j.integer(int64(r.Instance))
		j.field("origin")
		j.str(r.Origin)
		j.field("path")
		j.str(r.Path)
		j.field("profile")
		j.str(r.Profile)
		writeExtra(&j, r.Extra, r.extraOrder)
		j.endObject()
	}
	j.endArray()

	writeExtra(&j, h.Extra, h.extraOrder)
	j.endObject()
	return j.b
}

// EncodeNote serialises n in a fixed order. Notes are not conclusions and do
// not participate in statistics (§3.2).
func EncodeNote(n *Note) []byte {
	var j jsonBuf
	j.beginObject()
	j.field("type")
	j.str(TypeNote)
	j.field("scan_id")
	j.str(n.ScanID)
	j.field("code")
	j.str(n.Code)
	if n.Profile != "" {
		j.field("profile")
		j.str(n.Profile)
	}
	if n.Entry != "" {
		j.field("entry")
		j.str(n.Entry)
	}
	if n.PartID != "" {
		j.field("part_id")
		j.str(n.PartID)
	}
	if n.Detail != "" {
		j.field("detail")
		j.str(n.Detail)
	}
	if len(n.Companions) > 0 {
		j.field("companions")
		writeStringArray(&j, n.Companions)
	}
	if len(n.SideEffects) > 0 {
		j.field("side_effects")
		writeStringArray(&j, canonicalSideEffects(n.SideEffects))
	}
	writeExtra(&j, n.Extra, n.extraOrder)
	j.endObject()
	return j.b
}

// EncodeFooter serialises f in the fixed order of §3.3.
func EncodeFooter(f *Footer) []byte {
	var j jsonBuf
	j.beginObject()
	j.field("type")
	j.str(TypeFooter)
	j.field("manifest_version")
	j.str(f.ManifestVersion)
	j.field("scan_id")
	j.str(f.ScanID)
	j.field("ended_at")
	j.time(f.EndedAt)
	j.field("units")
	j.integer(f.Units)
	j.field("shards")
	j.integer(int64(f.Shards))

	j.field("stats")
	j.beginObject()
	j.field("l0")
	j.integer(f.Stats.L0)
	j.field("l1")
	j.integer(f.Stats.L1)
	j.field("l2")
	j.integer(f.Stats.L2)
	j.field("l3")
	j.integer(f.Stats.L3)
	j.field("l4")
	j.integer(f.Stats.L4)
	j.field("l5")
	j.integer(f.Stats.L5)
	j.field("residual")
	j.integer(f.Stats.Residual)
	if len(f.Stats.SideEffects) > 0 {
		j.field("side_effects")
		j.beginObject()
		for _, k := range orderedSideEffectKeys(f.Stats.SideEffects) {
			j.field(k)
			j.integer(f.Stats.SideEffects[k])
		}
		j.endObject()
	}
	writeExtra(&j, f.Stats.Extra, f.Stats.extraOrder)
	j.endObject()

	j.field("complete")
	j.boolean(f.Complete)
	if f.Errors > 0 {
		j.field("errors")
		j.integer(f.Errors)
	}
	writeExtra(&j, f.Extra, f.extraOrder)
	j.endObject()
	return j.b
}

// canonicalSignals orders signals by the fixed source order and, within one
// source, by note byte order (§5.1).
func canonicalSignals(in []Signal) []Signal {
	if len(in) < 2 {
		return in
	}
	out := append([]Signal(nil), in...)
	sort.SliceStable(out, func(i, k int) bool {
		ri, rk := sourceRank(out[i].Src), sourceRank(out[k].Src)
		if ri != rk {
			return ri < rk
		}
		if out[i].Src != out[k].Src {
			return out[i].Src < out[k].Src
		}
		return out[i].Note < out[k].Note
	})
	return out
}

func sourceRank(src string) int {
	for i, s := range signalSourceOrder {
		if s == src {
			return i
		}
	}
	return len(signalSourceOrder)
}

// canonicalRiskFlags returns the fixed §4.6 order; unknown values are kept
// after the known ones in byte order. Duplicates collapse.
func canonicalRiskFlags(in []string) []string {
	return orderEnumValues(in, riskFlagOrder)
}

func canonicalNeededBy(in []string) []string {
	return orderEnumValues(in, neededByOrder)
}

func canonicalSideEffects(in []string) []string {
	return orderEnumValues(in, []string{SideEffectShmCreate})
}

func orderEnumValues(in []string, order []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	var known []string
	unknown := make(map[string]bool)
	for _, want := range order {
		for _, v := range in {
			if v == want && !seen[v] {
				seen[v] = true
				known = append(known, v)
			}
		}
	}
	for _, v := range in {
		if !seen[v] {
			unknown[v] = true
			seen[v] = true
		}
	}
	var rest []string
	for v := range unknown {
		rest = append(rest, v)
	}
	sort.Strings(rest)
	return append(known, rest...)
}

func orderedSideEffectKeys(m map[string]int64) []string {
	seen := make(map[string]bool, len(m))
	var out []string
	if _, ok := m[SideEffectShmCreate]; ok {
		out = append(out, SideEffectShmCreate)
		seen[SideEffectShmCreate] = true
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// containsString reports whether values contains want.
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

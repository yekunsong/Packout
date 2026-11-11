package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// decodeRawObject decodes one JSON object into a field map plus the keys in
// their original order. The order is needed to write unknown fields back in
// the order they were read (spec §1).
func decodeRawObject(b []byte) (map[string]json.RawMessage, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, fmt.Errorf("manifest: record is not a JSON object")
	}
	m := make(map[string]json.RawMessage)
	var order []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, nil, fmt.Errorf("manifest: object key is not a string")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, err
		}
		if _, seen := m[key]; !seen {
			order = append(order, key)
		}
		m[key] = append(json.RawMessage(nil), raw...)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, err
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("manifest: trailing data after object")
	}
	return m, order, nil
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func decodeString(raw json.RawMessage) (string, error) {
	if isJSONNull(raw) {
		return "", fmt.Errorf("manifest: expected string, got null")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func decodeStringPtr(raw json.RawMessage) (*string, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	s, err := decodeString(raw)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func decodeInt64(raw json.RawMessage) (int64, error) {
	if isJSONNull(raw) {
		return 0, fmt.Errorf("manifest: expected integer, got null")
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n.Int64()
}

func decodeInt(raw json.RawMessage) (int, error) {
	n, err := decodeInt64(raw)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func decodeBool(raw json.RawMessage) (bool, error) {
	if isJSONNull(raw) {
		return false, fmt.Errorf("manifest: expected boolean, got null")
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, err
	}
	return v, nil
}

// decodeTime accepts RFC 3339 with an optional fractional second and a Z zone
// (§1, E-MAN-020).
func decodeTime(raw json.RawMessage) (time.Time, error) {
	s, err := decodeString(raw)
	if err != nil {
		return time.Time{}, err
	}
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("manifest: timestamp %q is not UTC with Z", s)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func decodeStrings(raw json.RawMessage) ([]string, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func unknowns(m map[string]json.RawMessage, order []string, known map[string]bool) (map[string][]byte, []string) {
	var extra map[string][]byte
	var extraOrder []string
	for _, k := range order {
		if known[k] {
			continue
		}
		if extra == nil {
			extra = make(map[string][]byte)
		}
		if _, dup := extra[k]; dup {
			continue
		}
		extra[k] = append([]byte(nil), m[k]...)
		extraOrder = append(extraOrder, k)
	}
	return extra, extraOrder
}

// ---- nested objects -------------------------------------------------------

func decodeSignal(raw json.RawMessage) (Signal, error) {
	var s Signal
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return s, err
	}
	if v, ok := m["src"]; ok {
		if s.Src, err = decodeString(v); err != nil {
			return s, err
		}
	}
	if v, ok := m["note"]; ok {
		if s.Note, err = decodeString(v); err != nil {
			return s, err
		}
	}
	if v, ok := m["url"]; ok {
		if s.URL, err = decodeStringPtr(v); err != nil {
			return s, err
		}
	}
	s.Extra, s.extraOrder = unknowns(m, order, map[string]bool{"src": true, "note": true, "url": true})
	return s, nil
}

func decodeSecretHit(raw json.RawMessage) (SecretHit, error) {
	var h SecretHit
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return h, err
	}
	set := func(key string, dst *string) error {
		if v, ok := m[key]; ok {
			s, err := decodeString(v)
			if err != nil {
				return err
			}
			*dst = s
		}
		return nil
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"kind", &h.Kind}, {"class", &h.Class}, {"locator", &h.Locator},
		{"prefix", &h.Prefix}, {"fingerprint", &h.Fingerprint}, {"hit_id", &h.HitID},
	} {
		if err := set(f.key, f.dst); err != nil {
			return h, err
		}
	}
	h.Extra, h.extraOrder = unknowns(m, order, map[string]bool{
		"kind": true, "class": true, "locator": true, "prefix": true,
		"fingerprint": true, "hit_id": true,
	})
	return h, nil
}

func decodeSecret(raw json.RawMessage) (*Secret, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	s := &Secret{}
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := m["class"]; ok {
		if s.Class, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["hits"]; ok && !isJSONNull(v) {
		var hits []json.RawMessage
		if err := json.Unmarshal(v, &hits); err != nil {
			return nil, err
		}
		for _, hr := range hits {
			h, err := decodeSecretHit(hr)
			if err != nil {
				return nil, err
			}
			s.Hits = append(s.Hits, h)
		}
	}
	if v, ok := m["hit_count"]; ok {
		n, err := decodeInt(v)
		if err != nil {
			return nil, err
		}
		s.HitCount = n
	}
	if v, ok := m["truncated"]; ok {
		if s.Truncated, err = decodeBool(v); err != nil {
			return nil, err
		}
	}
	s.Extra, s.extraOrder = unknowns(m, order, map[string]bool{
		"class": true, "hits": true, "hit_count": true, "truncated": true,
	})
	return s, nil
}

func decodeFileID(raw json.RawMessage) (*FileID, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	id := &FileID{}
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := m["volume_serial"]; ok {
		if id.VolumeSerial, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["index"]; ok {
		if id.Index, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["reparse_tag"]; ok && !isJSONNull(v) {
		id.ReparseTag = append([]byte(nil), v...)
	}
	id.Extra, id.extraOrder = unknowns(m, order, map[string]bool{
		"volume_serial": true, "index": true, "reparse_tag": true,
	})
	return id, nil
}

func decodeFingerprint(raw json.RawMessage) (*Fingerprint, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	fp := &Fingerprint{}
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := m["algo"]; ok {
		if fp.Algo, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["scope"]; ok {
		if isJSONNull(v) {
			fp.Scope = ""
		} else if fp.Scope, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["value"]; ok {
		if fp.Value, err = decodeStringPtr(v); err != nil {
			return nil, err
		}
	}
	fp.Extra, fp.extraOrder = unknowns(m, order, map[string]bool{
		"algo": true, "scope": true, "value": true,
	})
	return fp, nil
}

func decodeOwner(raw json.RawMessage) (*Owner, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	o := &Owner{}
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := m["kind"]; ok {
		if o.Kind, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["value"]; ok {
		if o.Value, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	o.Extra, o.extraOrder = unknowns(m, order, map[string]bool{"kind": true, "value": true})
	return o, nil
}

func decodeACL(raw json.RawMessage) (*ACL, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	a := &ACL{}
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, err
	}
	if v, ok := m["algo"]; ok {
		if a.Algo, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["value"]; ok {
		if a.Value, err = decodeString(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["entries"]; ok {
		if a.Entries, err = decodeInt(v); err != nil {
			return nil, err
		}
	}
	if v, ok := m["truncated"]; ok {
		if a.Truncated, err = decodeBool(v); err != nil {
			return nil, err
		}
	}
	a.Extra, a.extraOrder = unknowns(m, order, map[string]bool{
		"algo": true, "value": true, "entries": true, "truncated": true,
	})
	return a, nil
}

func decodeScanSegment(raw json.RawMessage) (ScanSegment, error) {
	var s ScanSegment
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return s, err
	}
	s.present = make(map[string]bool, len(m))
	for k := range m {
		s.present[k] = true
	}
	if v, ok := m["parent"]; ok {
		if s.Parent, err = decodeStringPtr(v); err != nil {
			return s, err
		}
	}
	if v, ok := m["segment_seq"]; ok {
		if s.SegmentSeq, err = decodeInt(v); err != nil {
			return s, err
		}
	}
	if v, ok := m["first_shard"]; ok {
		if s.FirstShard, err = decodeInt(v); err != nil {
			return s, err
		}
	}
	s.Extra, s.extraOrder = unknowns(m, order, map[string]bool{
		"parent": true, "segment_seq": true, "first_shard": true,
	})
	return s, nil
}

func decodeHost(raw json.RawMessage) (Host, error) {
	var h Host
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return h, err
	}
	h.present = make(map[string]bool, len(m))
	for k := range m {
		h.present[k] = true
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"os", &h.OS}, {"os_version", &h.OSVersion}, {"arch", &h.Arch},
		{"case_sensitivity", &h.CaseSensitivity}, {"path_fold_version", &h.PathFoldVersion},
	} {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeString(v); err != nil {
				return h, err
			}
		}
	}
	if v, ok := m["volume_ids"]; ok && !isJSONNull(v) {
		var raws []json.RawMessage
		if err := json.Unmarshal(v, &raws); err != nil {
			return h, err
		}
		for _, vr := range raws {
			vm, vorder, err := decodeRawObject(vr)
			if err != nil {
				return h, err
			}
			var vol VolumeID
			if r, ok := vm["root"]; ok {
				if vol.Root, err = decodeString(r); err != nil {
					return h, err
				}
			}
			if r, ok := vm["serial"]; ok {
				if vol.Serial, err = decodeString(r); err != nil {
					return h, err
				}
			}
			vol.Extra, vol.extraOrder = unknowns(vm, vorder, map[string]bool{"root": true, "serial": true})
			h.VolumeIDs = append(h.VolumeIDs, vol)
		}
	}
	h.Extra, h.extraOrder = unknowns(m, order, map[string]bool{
		"os": true, "os_version": true, "arch": true, "case_sensitivity": true,
		"path_fold_version": true, "volume_ids": true,
	})
	return h, nil
}

func decodeInputs(raw json.RawMessage) (Inputs, error) {
	var in Inputs
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return in, err
	}
	in.present = make(map[string]bool, len(m))
	for k := range m {
		in.present[k] = true
	}
	if v, ok := m["secret_salt_mode"]; ok {
		if in.SecretSaltMode, err = decodeString(v); err != nil {
			return in, err
		}
	}
	if v, ok := m["secret_salt"]; ok {
		if in.SecretSalt, err = decodeString(v); err != nil {
			return in, err
		}
	}
	if v, ok := m["profiles"]; ok && !isJSONNull(v) {
		var raws []json.RawMessage
		if err := json.Unmarshal(v, &raws); err != nil {
			return in, err
		}
		for _, pr := range raws {
			pm, porder, err := decodeRawObject(pr)
			if err != nil {
				return in, err
			}
			var ref ProfileRef
			for _, f := range []struct {
				key string
				dst *string
			}{{"name", &ref.Name}, {"version", &ref.Version}, {"sha256", &ref.SHA256}} {
				if r, ok := pm[f.key]; ok {
					if *f.dst, err = decodeString(r); err != nil {
						return in, err
					}
				}
			}
			ref.Extra, ref.extraOrder = unknowns(pm, porder, map[string]bool{
				"name": true, "version": true, "sha256": true,
			})
			in.Profiles = append(in.Profiles, ref)
		}
	}
	if v, ok := m["options"]; ok && !isJSONNull(v) {
		om, oorder, err := decodeRawObject(v)
		if err != nil {
			return in, err
		}
		opt := &InputOptions{}
		if r, ok := om["follow_symlinks"]; ok {
			if opt.FollowSymlinks, err = decodeBool(r); err != nil {
				return in, err
			}
		}
		if r, ok := om["with_sessions"]; ok {
			if opt.WithSessions, err = decodeBool(r); err != nil {
				return in, fmt.Errorf("E-MAN-071: inputs.options.with_sessions must be a boolean: %w", err)
			}
		}
		if r, ok := om["selection"]; ok && !isJSONNull(r) {
			sel, serr := decodeSelection(r)
			if serr != nil {
				return in, serr
			}
			opt.Selection = sel
		}
		opt.Extra, opt.extraOrder = unknowns(om, oorder, map[string]bool{
			"follow_symlinks": true, "with_sessions": true, "selection": true,
		})
		in.Options = opt
	}
	in.Extra, in.extraOrder = unknowns(m, order, map[string]bool{
		"secret_salt_mode": true, "secret_salt": true, "profiles": true, "options": true,
	})
	return in, nil
}

// decodeSelection reads inputs.options.selection (manifest §3.1).
func decodeSelection(raw json.RawMessage) (*Selection, error) {
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return nil, fmt.Errorf("E-MAN-071: inputs.options.selection must be an object: %w", err)
	}
	sel := &Selection{}
	if r, ok := m["preset"]; ok {
		if sel.Preset, err = decodeString(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.preset: %w", err)
		}
		switch sel.Preset {
		case "minimal", "standard", "full":
		default:
			return nil, fmt.Errorf("E-MAN-071: selection.preset %q is unknown", sel.Preset)
		}
	}
	if r, ok := m["include"]; ok {
		if sel.Include, err = decodeStrings(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.include: %w", err)
		}
	}
	if r, ok := m["exclude"]; ok {
		if sel.Exclude, err = decodeStrings(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.exclude: %w", err)
		}
	}
	if r, ok := m["sessions_since"]; ok {
		if sel.SessionsSince, err = decodeString(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.sessions_since: %w", err)
		}
	}
	if r, ok := m["sessions_project"]; ok {
		if sel.SessionsProjects, err = decodeStrings(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.sessions_project: %w", err)
		}
	}
	if r, ok := m["sessions_max_per_project"]; ok {
		if sel.SessionsMaxPerProject, err = decodeInt(r); err != nil {
			return nil, fmt.Errorf("E-MAN-071: selection.sessions_max_per_project: %w", err)
		}
		if sel.SessionsMaxPerProject < 0 {
			return nil, fmt.Errorf("E-MAN-071: selection.sessions_max_per_project must be >= 0")
		}
	}
	sel.Extra, sel.extraOrder = unknowns(m, order, selectionKnownFields)
	return sel, nil
}

var selectionKnownFields = map[string]bool{
	"preset": true, "include": true, "exclude": true, "sessions_since": true,
	"sessions_project": true, "sessions_max_per_project": true,
}

func decodeRoot(raw json.RawMessage) (Root, error) {
	var r Root
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return r, err
	}
	r.present = make(map[string]bool, len(m))
	for k := range m {
		r.present[k] = true
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"name", &r.Name}, {"role", &r.Role}, {"origin", &r.Origin},
		{"path", &r.Path}, {"profile", &r.Profile},
	} {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeString(v); err != nil {
				return r, err
			}
		}
	}
	if v, ok := m["instance"]; ok {
		if r.Instance, err = decodeInt(v); err != nil {
			return r, err
		}
	}
	r.Extra, r.extraOrder = unknowns(m, order, map[string]bool{
		"name": true, "role": true, "instance": true, "origin": true,
		"path": true, "profile": true,
	})
	return r, nil
}

func decodeStats(raw json.RawMessage) (Stats, error) {
	var st Stats
	m, order, err := decodeRawObject(raw)
	if err != nil {
		return st, err
	}
	known := map[string]bool{"l0": true, "l1": true, "l2": true, "l3": true, "l4": true, "l5": true, "residual": true, "side_effects": true}
	dsts := []struct {
		key string
		dst *int64
	}{{"l0", &st.L0}, {"l1", &st.L1}, {"l2", &st.L2}, {"l3", &st.L3}, {"l4", &st.L4}, {"l5", &st.L5}, {"residual", &st.Residual}}
	for _, f := range dsts {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeInt64(v); err != nil {
				return st, err
			}
		}
	}
	if v, ok := m["side_effects"]; ok && !isJSONNull(v) {
		var se map[string]int64
		if err := json.Unmarshal(v, &se); err != nil {
			return st, err
		}
		st.SideEffects = se
	}
	st.Extra, st.extraOrder = unknowns(m, order, known)
	return st, nil
}

// ---- records --------------------------------------------------------------

// UnmarshalJSON decodes a unit leniently: missing required fields are recorded
// in present for the validator to report (E-MAN-005), while malformed values
// fail immediately (the reader maps that to E-MAN-002).
func (u *Unit) UnmarshalJSON(b []byte) error {
	m, order, err := decodeRawObject(b)
	if err != nil {
		return err
	}
	u.present = make(map[string]bool, len(m))
	for k := range m {
		u.present[k] = true
	}
	getS := func(key string, dst *string) error {
		v, ok := m[key]
		if !ok {
			return nil
		}
		s, err := decodeString(v)
		if err != nil {
			return err
		}
		*dst = s
		return nil
	}
	getSP := func(key string, dst **string) error {
		v, ok := m[key]
		if !ok {
			return nil
		}
		p, err := decodeStringPtr(v)
		if err != nil {
			return err
		}
		*dst = p
		return nil
	}
	getI64 := func(key string, dst **int64) error {
		v, ok := m[key]
		if !ok {
			return nil
		}
		if isJSONNull(v) {
			return nil
		}
		n, err := decodeInt64(v)
		if err != nil {
			return err
		}
		*dst = &n
		return nil
	}
	getBoolP := func(key string, dst **bool) error {
		v, ok := m[key]
		if !ok {
			return nil
		}
		val, err := decodeBool(v)
		if err != nil {
			return err
		}
		*dst = &val
		return nil
	}

	for _, f := range []struct {
		key string
		dst *string
	}{
		{"type", &u.Type}, {"schema_version", &u.SchemaVersion}, {"id", &u.ID},
		{"path", &u.Path}, {"path_key", &u.PathKey}, {"root", &u.Root},
		{"path_semantics", &u.PathSemantics}, {"profile", &u.Profile},
		{"entry", &u.Entry}, {"part_id", &u.PartID}, {"kind", &u.Kind},
		{"layer", &u.Layer}, {"proposed_action", &u.ProposedAction},
		{"open_as", &u.OpenAs}, {"link_target", &u.LinkTarget},
		{"secret_ref", &u.SecretRef}, {"notes", &u.Notes},
	} {
		if err := getS(f.key, f.dst); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		key string
		dst **string
	}{{"cid", &u.CID}, {"derived_from", &u.DerivedFrom}, {"origin", &u.Origin}, {"origin_path_key", &u.OriginPathKey}} {
		if err := getSP(f.key, f.dst); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		key string
		dst **int64
	}{{"size_apparent", &u.SizeApparent}, {"size_alloc", &u.SizeAlloc}, {"aggregate_count", &u.AggregateCount}} {
		if err := getI64(f.key, f.dst); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		key string
		dst **bool
	}{{"contains_secret", &u.ContainsSecret}, {"may_contain_secret", &u.MayContainSecret}} {
		if err := getBoolP(f.key, f.dst); err != nil {
			return err
		}
	}

	if v, ok := m["confidence"]; ok {
		n, err := decodeJSONNumber(v)
		if err != nil {
			return err
		}
		u.confidenceRaw = n
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return err
		}
		u.Confidence = f
	}
	if v, ok := m["size_estimated"]; ok {
		if u.SizeEstimated, err = decodeBool(v); err != nil {
			return err
		}
	}
	if v, ok := m["opaque_content"]; ok {
		if u.OpaqueContent, err = decodeBool(v); err != nil {
			return err
		}
	}
	if v, ok := m["mtime"]; ok && !isJSONNull(v) {
		t, err := decodeTime(v)
		if err != nil {
			return err
		}
		u.MTime = &t
	}
	if v, ok := m["file_id"]; ok {
		if u.FileID, err = decodeFileID(v); err != nil {
			return err
		}
	}
	if v, ok := m["fingerprint"]; ok {
		if u.Fingerprint, err = decodeFingerprint(v); err != nil {
			return err
		}
	}
	if v, ok := m["secret"]; ok {
		if u.Secret, err = decodeSecret(v); err != nil {
			return err
		}
	}
	if v, ok := m["owner"]; ok {
		if u.Owner, err = decodeOwner(v); err != nil {
			return err
		}
	}
	if v, ok := m["acl"]; ok {
		if u.ACL, err = decodeACL(v); err != nil {
			return err
		}
	}
	if v, ok := m["signals"]; ok && !isJSONNull(v) {
		var raws []json.RawMessage
		if err := json.Unmarshal(v, &raws); err != nil {
			return err
		}
		for _, sr := range raws {
			s, err := decodeSignal(sr)
			if err != nil {
				return err
			}
			u.Signals = append(u.Signals, s)
		}
	}
	for _, f := range []struct {
		key string
		dst *[]string
	}{
		{"risk_flags", &u.RiskFlags}, {"needed_by", &u.NeededBy},
		{"companions", &u.Companions}, {"side_effects", &u.SideEffects},
	} {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeStrings(v); err != nil {
				return err
			}
		}
	}

	normalizeRiskFlags(u)
	normalizeEnums(u)
	u.Extra, u.extraOrder = unknowns(m, order, unitKnownFields)
	return nil
}

// MarshalJSON makes the standard library use the canonical encoder.
func (u Unit) MarshalJSON() ([]byte, error) { return EncodeUnit(&u), nil }

var unitKnownFields = map[string]bool{
	"type": true, "schema_version": true, "id": true, "cid": true, "path": true,
	"path_key": true, "root": true, "path_semantics": true, "derived_from": true,
	"origin": true, "origin_path_key": true, "profile": true, "entry": true,
	"part_id": true, "kind": true, "layer": true, "confidence": true,
	"signals": true, "secret": true, "contains_secret": true,
	"may_contain_secret": true, "size_apparent": true, "size_alloc": true,
	"mtime": true, "file_id": true, "fingerprint": true, "owner": true,
	"acl": true, "size_estimated": true, "aggregate_count": true,
	"proposed_action": true, "risk_flags": true, "needed_by": true,
	"companions": true, "side_effects": true, "open_as": true,
	"opaque_content": true, "link_target": true, "secret_ref": true,
	"notes": true,
}

func decodeJSONNumber(raw json.RawMessage) (string, error) {
	if isJSONNull(raw) {
		return "", fmt.Errorf("manifest: expected number, got null")
	}
	s := strings.TrimSpace(string(raw))
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", err
	}
	return s, nil
}

// normalizeRiskFlags maps the two renamed flags of v1/v2 (§4.6) and keeps
// every other value, including unknown future ones.
func normalizeRiskFlags(u *Unit) {
	renames := map[string]string{
		"unversioned_repo": "not_versioned",
		"binary":           "opaque_content",
	}
	for i, f := range u.RiskFlags {
		if to, ok := renames[f]; ok {
			u.RiskFlags[i] = to
			u.aliases = append(u.aliases, f)
		}
	}
}

// normalizeEnums applies the §7 rule for unknown enum values: an unknown
// proposed_action becomes keep and an unknown layer becomes L2; both add the
// unknown_enum risk flag. The original spelling is kept in aliases for
// diagnostics.
func normalizeEnums(u *Unit) {
	if u.present["layer"] && !containsString(layerOrder, u.Layer) {
		u.aliases = append(u.aliases, "layer="+u.Layer)
		u.Layer = LayerL2
		addRiskFlag(u, "unknown_enum")
	}
	if u.present["proposed_action"] && !isKnownAction(u.ProposedAction) {
		u.aliases = append(u.aliases, "proposed_action="+u.ProposedAction)
		u.ProposedAction = ActionKeep
		addRiskFlag(u, "unknown_enum")
	}
}

func isKnownAction(a string) bool {
	switch a {
	case ActionKeep, ActionDelete, ActionReinstall, ActionTemplate, ActionMigrate, ActionRebind, ActionRelogin:
		return true
	}
	return false
}

func addRiskFlag(u *Unit, flag string) {
	if !containsString(u.RiskFlags, flag) {
		u.RiskFlags = append(u.RiskFlags, flag)
	}
}

// UnmarshalJSON decodes a header, retaining presence information for the
// required-field checks of §3.1.
func (h *Header) UnmarshalJSON(b []byte) error {
	m, order, err := decodeRawObject(b)
	if err != nil {
		return err
	}
	h.present = make(map[string]bool, len(m))
	for k := range m {
		h.present[k] = true
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"type", new(string)}, {"manifest_version", &h.ManifestVersion},
		{"scan_id", &h.ScanID}, {"tool", &h.Tool},
	} {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeString(v); err != nil {
				return err
			}
		}
	}
	if v, ok := m["started_at"]; ok {
		if h.StartedAt, err = decodeTime(v); err != nil {
			return err
		}
	}
	if v, ok := m["scan_segment"]; ok {
		if h.ScanSegment, err = decodeScanSegment(v); err != nil {
			return err
		}
	}
	if v, ok := m["host"]; ok {
		if h.Host, err = decodeHost(v); err != nil {
			return err
		}
	}
	if v, ok := m["inputs"]; ok {
		if h.Inputs, err = decodeInputs(v); err != nil {
			return err
		}
	}
	if v, ok := m["shard_units"]; ok {
		if h.ShardUnits, err = decodeInt(v); err != nil {
			return err
		}
	}
	if v, ok := m["shard_bytes"]; ok {
		if h.ShardBytes, err = decodeInt64(v); err != nil {
			return err
		}
	}
	if v, ok := m["roots"]; ok && !isJSONNull(v) {
		var raws []json.RawMessage
		if err := json.Unmarshal(v, &raws); err != nil {
			return err
		}
		for _, rr := range raws {
			r, err := decodeRoot(rr)
			if err != nil {
				return err
			}
			h.Roots = append(h.Roots, r)
		}
	}
	h.Extra, h.extraOrder = unknowns(m, order, headerKnownFields)
	return nil
}

// MarshalJSON makes the standard library use the canonical encoder.
func (h Header) MarshalJSON() ([]byte, error) { return EncodeHeader(&h), nil }

var headerKnownFields = map[string]bool{
	"type": true, "manifest_version": true, "scan_id": true, "scan_segment": true,
	"started_at": true, "tool": true, "host": true, "inputs": true,
	"shard_units": true, "shard_bytes": true, "roots": true,
}

// UnmarshalJSON decodes a note.
func (n *Note) UnmarshalJSON(b []byte) error {
	m, order, err := decodeRawObject(b)
	if err != nil {
		return err
	}
	n.present = make(map[string]bool, len(m))
	for k := range m {
		n.present[k] = true
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"type", &n.Type}, {"scan_id", &n.ScanID}, {"code", &n.Code},
		{"profile", &n.Profile}, {"entry", &n.Entry}, {"category", &n.Category},
		{"part_id", &n.PartID}, {"detail", &n.Detail},
	} {
		if v, ok := m[f.key]; ok {
			if *f.dst, err = decodeString(v); err != nil {
				return err
			}
		}
	}
	if v, ok := m["companions"]; ok {
		if n.Companions, err = decodeStrings(v); err != nil {
			return err
		}
	}
	if v, ok := m["side_effects"]; ok {
		if n.SideEffects, err = decodeStrings(v); err != nil {
			return err
		}
	}
	n.Extra, n.extraOrder = unknowns(m, order, noteKnownFields)
	return nil
}

// MarshalJSON makes the standard library use the canonical encoder.
func (n Note) MarshalJSON() ([]byte, error) { return EncodeNote(&n), nil }

var noteKnownFields = map[string]bool{
	"type": true, "scan_id": true, "code": true, "profile": true, "entry": true,
	"category": true, "part_id": true, "detail": true, "companions": true,
	"side_effects": true,
}

// UnmarshalJSON decodes a footer.
func (f *Footer) UnmarshalJSON(b []byte) error {
	m, order, err := decodeRawObject(b)
	if err != nil {
		return err
	}
	f.present = make(map[string]bool, len(m))
	for k := range m {
		f.present[k] = true
	}
	for _, x := range []struct {
		key string
		dst *string
	}{
		{"type", &f.Type}, {"manifest_version", &f.ManifestVersion}, {"scan_id", &f.ScanID},
	} {
		if v, ok := m[x.key]; ok {
			if *x.dst, err = decodeString(v); err != nil {
				return err
			}
		}
	}
	if v, ok := m["ended_at"]; ok {
		if f.EndedAt, err = decodeTime(v); err != nil {
			return err
		}
	}
	if v, ok := m["units"]; ok {
		if f.Units, err = decodeInt64(v); err != nil {
			return err
		}
	}
	if v, ok := m["shards"]; ok {
		if f.Shards, err = decodeInt(v); err != nil {
			return err
		}
	}
	if v, ok := m["stats"]; ok {
		if f.Stats, err = decodeStats(v); err != nil {
			return err
		}
	}
	if v, ok := m["complete"]; ok {
		if f.Complete, err = decodeBool(v); err != nil {
			return err
		}
	}
	if v, ok := m["errors"]; ok {
		if f.Errors, err = decodeInt64(v); err != nil {
			return err
		}
	}
	f.Extra, f.extraOrder = unknowns(m, order, footerKnownFields)
	return nil
}

// MarshalJSON makes the standard library use the canonical encoder.
func (f Footer) MarshalJSON() ([]byte, error) { return EncodeFooter(&f), nil }

var footerKnownFields = map[string]bool{
	"type": true, "manifest_version": true, "scan_id": true, "ended_at": true,
	"units": true, "shards": true, "stats": true, "complete": true, "errors": true,
}

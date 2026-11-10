package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"packout/internal/classify"
	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
)

// produceParts emits one Unit per matching part. It returns true when at least
// one part matched; the caller then omits the entry-level Unit.
func (s *scanner) produceParts(entryUnit *manifest.Unit, e *profile.Entry, data []byte, structure int64) bool {
	kind := entryUnit.Kind
	truncated := structure > 0 && int64(len(data)) >= structure
	if truncated {
		s.addNote(manifest.Note{Code: "budget_exceeded", PartID: "", Entry: e.ID,
			Detail: "max_bytes_structure 耗尽，结构可能不完整"})
		entryUnit.RiskFlags = appendFlag(entryUnit.RiskFlags, "content_partial")
	}
	var doc any
	if len(data) > 0 {
		_ = json.Unmarshal(data, &doc)
	}
	matched := false
	coveredTop := make(map[string]bool)
	usedLines := make(map[int]string)
	for _, part := range e.Parts {
		sel := s.selectPart(part, doc, data)
		if len(sel) == 0 {
			s.addNote(manifest.Note{Code: "part_missing", Entry: e.ID, PartID: part.ID})
			continue
		}
		matched = true
		if part.Selector.Kind == "json_pointer" {
			top := strings.SplitN(strings.TrimPrefix(part.Selector.Value, "/"), "/", 2)[0]
			coveredTop[strings.ReplaceAll(strings.ReplaceAll(top, "~1", "/"), "~0", "~")] = true
		}
		for _, selected := range sel {
			if selected.line > 0 {
				if owner, ok := usedLines[selected.line]; ok {
					s.addNote(manifest.Note{Code: "part_overlap", Entry: e.ID, PartID: part.ID,
						Detail: fmt.Sprintf("行 %d 已由 part %s 选中", selected.line, owner)})
					continue
				}
				usedLines[selected.line] = part.ID
			}
			pu := s.newUnit(e, s.rootByUnit(entryUnit.Root), entryUnit.Path, kind, part.ID)
			pu.FileID = entryUnit.FileID
			pu.MTime = entryUnit.MTime
			size := int64(len(selected.text))
			pu.SizeApparent = &size
			pu.SizeAlloc = nil
			if part.Layer != "" {
				pu.Layer = part.Layer
			}
			if part.Secret != "" {
				pu.Secret.Class = part.Secret
			}
			if part.Extractor != "" {
				pu.OpaqueContent = false
			}
			if len(part.NeededBy) > 0 {
				pu.NeededBy = append([]string(nil), part.NeededBy...)
			}
			pu.Signals = append(pu.Signals, convertSignals(part.Signals)...)
			pu.Signals = append(pu.Signals, manifest.Signal{
				Src:  "content_match",
				Note: "part " + part.ID + " selector " + part.Selector.Kind + " 命中",
			})
			if part.PathSemantics != "" || part.DerivedFrom != "" {
				if d := derivedFrom(part.PathSemantics, part.DerivedFrom); d != nil {
					pu.PathSemantics = manifest.SemanticsMachineDerived
					pu.DerivedFrom = d
					pu.RiskFlags = appendFlag(pu.RiskFlags, "machine_derived_path")
				}
			}
			if selected.origin != "" {
				origin := selected.origin
				key := fsx.NormKey(origin)
				pu.Origin = &origin
				pu.OriginPathKey = &key
				if pu.DerivedFrom == nil {
					d := profile.DerivedJSONPathKey
					pu.DerivedFrom = &d
					pu.PathSemantics = manifest.SemanticsMachineDerived
					pu.RiskFlags = appendFlag(pu.RiskFlags, "machine_derived_path")
				}
				pu.ID = manifest.UnitID(pu.Root, pu.Profile, pu.Entry,
					part.ID+"\x00"+key, pu.PathKey)
			}

			if part.Extractor == profile.ExtractorKeysOnly {
				fp := manifest.FingerprintKeys(extractKeys([]byte(selected.text), 0))
				pu.Fingerprint = &fp
			} else {
				fp, _ := manifest.FingerprintBytes([]byte(selected.text), "full")
				pu.Fingerprint = &fp
			}
			pu.CID = manifest.CID(pu.Fingerprint)
			if part.Secret == profile.SecretScan && len(selected.text) > 0 {
				s.scanSecret(&pu, e, entryUnit.Path, []byte(selected.text), int64(len(selected.text)))
			}
			pu.ProposedAction = classify.ActionFor(pu.Layer, pu.Secret.Class)
			s.units = append(s.units, pu)
		}
	}
	if matched {
		s.produceUncovered(e, entryUnit, doc, coveredTop)
	}
	return matched
}

type selectedBytes struct {
	text   string
	origin string
	line   int // 1-based, line_pattern only
}

type partSelection struct{ list []selectedBytes }

func selectedOrigin(sel []selectedBytes) string {
	for _, s := range sel {
		if s.origin != "" {
			return s.origin
		}
	}
	return ""
}

func (s *scanner) selectPart(part *profile.Part, doc any, data []byte) []selectedBytes {
	switch part.Selector.Kind {
	case "json_pointer":
		if doc == nil {
			return nil
		}
		all, ok := jsonSelectAll(doc, part.Selector.Value)
		if !ok {
			return nil
		}
		out := make([]selectedBytes, 0, len(all))
		for _, pair := range all {
			out = append(out, selectedBytes{text: pair[0], origin: pair[1]})
		}
		// A json_path_key part selecting an object (e.g. /projects) yields one
		// row per top-level key, each with that key as origin (D-024 #3).
		if part.DerivedFrom == profile.DerivedJSONPathKey && len(out) == 1 && out[0].origin == "" {
			var obj map[string]any
			if json.Unmarshal([]byte(out[0].text), &obj) == nil && len(obj) > 0 {
				expanded := make([]selectedBytes, 0, len(obj))
				for _, k := range sortedAnyKeys(obj) {
					b, err := json.Marshal(obj[k])
					if err != nil {
						continue
					}
					expanded = append(expanded, selectedBytes{text: string(b), origin: k})
				}
				if len(expanded) > 0 {
					return expanded
				}
			}
		}
		return out
	case "line_pattern":
		re, err := regexp.Compile(part.Selector.Value)
		if err != nil {
			return nil
		}
		var out []selectedBytes
		for _, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				out = append(out, selectedBytes{text: line + "\n"})
			}
		}
		return out
	case "toml_section":
		var out []selectedBytes
		for _, sec := range tomlSections(data) {
			if matchSection(part.Selector.Value, sec.name) {
				out = append(out, selectedBytes{
					text:   string(data[sec.start:sec.end]),
					origin: sectionOrigin(part.Selector.Value, sec.name),
				})
			}
		}
		return out
	}
	return nil
}

// produceUncovered implements parts_uncovered (D-024 #1).
func (s *scanner) produceUncovered(e *profile.Entry, entryUnit *manifest.Unit, doc any, covered map[string]bool) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return
	}
	var keys []string
	for k := range obj {
		if !covered[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Strings(keys)
	mode := e.PartsUncovered
	if mode == "" {
		mode = "note"
	}
	if mode == "note" {
		show := keys
		if len(show) > 32 {
			show = show[:32]
		}
		s.addNote(manifest.Note{
			Code: "part_uncovered", Entry: e.ID,
			Detail: strings.Join(show, ","),
		})
		return
	}
	for _, k := range keys {
		pu := s.newUnit(e, s.rootByUnit(entryUnit.Root), entryUnit.Path, entryUnit.Kind, manifest.PartUncovered)
		pu.FileID = entryUnit.FileID
		pu.MTime = entryUnit.MTime
		size := int64(len("/" + k))
		pu.SizeApparent = &size
		fp := manifest.FingerprintKeys([]string{"/" + k})
		pu.Fingerprint = &fp
		pu.CID = manifest.CID(pu.Fingerprint)
		origin := k
		key := fsx.NormKey(origin)
		pu.PathSemantics = manifest.SemanticsMachineDerived
		d := profile.DerivedJSONPathKey
		pu.DerivedFrom = &d
		pu.RiskFlags = appendFlag(pu.RiskFlags, "machine_derived_path")
		pu.Origin = &origin
		pu.OriginPathKey = &key
		// The spec id omits origin, but uncovered rows share path_key; fold
		// origin into the part component so ids stay unique.
		pu.ID = manifest.UnitID(pu.Root, pu.Profile, pu.Entry,
			manifest.PartUncovered+"\x00"+key, pu.PathKey)
		pu.Signals = append(pu.Signals, manifest.Signal{
			Src: "content_match", Note: "顶层键 /" + k + " 未被任何 part 覆盖",
		})
		if mode == "residual" {
			pu.Layer = manifest.LayerL2
			pu.Confidence = 0.5
			pu.RiskFlags = appendFlag(pu.RiskFlags, "residual")
			pu.RiskFlags = appendFlag(pu.RiskFlags, "low_confidence")
			pu.ProposedAction = manifest.ActionKeep
		} else {
			pu.ProposedAction = classify.ActionFor(pu.Layer, pu.Secret.Class)
		}
		s.units = append(s.units, pu)
	}
}

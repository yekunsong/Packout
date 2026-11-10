// Package classify implements the layer/confidence post-processing rules of
// the manifest model (spec-manifest §5, D-011 #5, D-013 M5/M7).
//
// Everything here is pure: the functions never touch the filesystem and never
// depend on internal/scan (D-005). Input and output slices have the same
// order and length; callers own both slices.
package classify

import (
	"strconv"
	"strings"

	"packout/internal/manifest"
)

// UniquenessScope parameterizes ApplyUniqueness. Mode is the only value the v2
// spec defines ("root": count per root instance and per entry). Entries names
// the entry ids that declare unique_within; units of other entries are left
// untouched.
type UniquenessScope struct {
	Mode    string
	Entries map[string]bool
}

// layerRank orders layers by conservatism. L4 and L5 are the top pair, so a
// conflict can never move a machine-bound or relogin conclusion down.
func layerRank(layer string) int {
	switch layer {
	case manifest.LayerL0:
		return 0
	case manifest.LayerL1:
		return 1
	case manifest.LayerL2:
		return 2
	case manifest.LayerL3:
		return 3
	case manifest.LayerL4:
		return 4
	case manifest.LayerL5:
		return 5
	}
	return -1
}

func moreConservative(a, b string) string {
	if a == "" {
		return b
	}
	if layerRank(a) >= layerRank(b) {
		return a
	}
	return b
}

// Resolve finds units that describe the same path (same path_key, or same
// file_id when both carry one) and gives every member the most conservative
// layer. The conflict itself becomes one content_match signal on each member
// and confidence is multiplied by 0.8 (D-011 #5, spec-manifest §5.2).
//
// Distinct profiles are not merged or removed: the manifest keeps one row per
// (profile, entry, part), exactly as §5.3 requires.
func Resolve(units []manifest.Unit) []manifest.Unit {
	out := append([]manifest.Unit(nil), units...)
	if len(out) < 2 {
		return out
	}
	groups := make(map[string][]int)
	order := make([]string, 0, len(out))
	for i := range out {
		if out[i].Kind == manifest.KindCatchAll || hasRisk(out[i].RiskFlags, "residual") {
			continue // catch-all/residual shape is fixed at L2 / 0.5
		}
		key := conflictKey(&out[i])
		if key == "" {
			continue
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	for _, key := range order {
		idxs := groups[key]
		if len(idxs) < 2 {
			continue
		}
		maxLayer := ""
		seen := make(map[string]bool)
		for _, i := range idxs {
			if !seen[out[i].Layer] {
				seen[out[i].Layer] = true
			}
			maxLayer = moreConservative(maxLayer, out[i].Layer)
		}
		if len(seen) < 2 {
			continue
		}
		for _, i := range idxs {
			u := &out[i]
			other := maxLayer
			if u.Layer == maxLayer {
				// Lowest differing layer, for a deterministic note.
				for _, l := range []string{manifest.LayerL0, manifest.LayerL1, manifest.LayerL2, manifest.LayerL3, manifest.LayerL4, manifest.LayerL5} {
					if seen[l] && l != maxLayer {
						other = l
						break
					}
				}
			}
			u.Signals = append(u.Signals, manifest.Signal{
				Src:  "content_match",
				Note: "层冲突：本行 " + u.Layer + "，同路径结论含 " + other + "；按更保守者取 " + maxLayer,
			})
			u.Layer = maxLayer
			u.Confidence *= 0.8
		}
	}
	return out
}

func conflictKey(u *manifest.Unit) string {
	if u.FileID != nil && u.FileID.VolumeSerial != "" && u.FileID.Index != "" {
		return "f\x00" + u.Root + "\x00" + u.FileID.VolumeSerial + "\x00" + u.FileID.Index
	}
	if u.PathKey != "" {
		return "p\x00" + u.PathKey
	}
	return ""
}

// ApplyUniqueness implements unique_within: root (spec-profile §5.3, D-021 #2):
// count distinct path_keys per (entry, root instance). An instance whose count
// is exactly one promotes its L2 units to L3 and gains a profile_rule signal
// naming the count and the instance.
//
// Only entries listed in scope.Entries participate. scope.Mode other than
// "root" is a no-op.
func ApplyUniqueness(units []manifest.Unit, scope UniquenessScope) []manifest.Unit {
	out := append([]manifest.Unit(nil), units...)
	if scope.Mode != "root" || len(scope.Entries) == 0 {
		return out
	}
	type group struct {
		entry string
		root  string
	}
	sets := make(map[group]map[string]bool)
	for i := range out {
		u := &out[i]
		if !scope.Entries[u.Entry] {
			continue
		}
		g := group{u.Entry, u.Root}
		if sets[g] == nil {
			sets[g] = make(map[string]bool)
		}
		sets[g][u.PathKey] = true
	}
	for i := range out {
		u := &out[i]
		if !scope.Entries[u.Entry] || u.Layer != manifest.LayerL2 {
			continue
		}
		g := group{u.Entry, u.Root}
		if len(sets[g]) != 1 {
			continue
		}
		u.Layer = manifest.LayerL3
		u.Signals = append(u.Signals, manifest.Signal{
			Src: "profile_rule",
			Note: "unique_within: root — 实例 " + u.Root + " 内 entry " + u.Entry +
				" 恰命中 1 个不同路径，运行时升 L3（计数 " + strconv.Itoa(len(sets[g])) + "）",
		})
	}
	return out
}

// EnforceConfidence applies the confidence gate of spec-manifest §5.2:
// confidence below 0.9 forces action keep and a low_confidence flag.
func EnforceConfidence(units []manifest.Unit) []manifest.Unit {
	out := append([]manifest.Unit(nil), units...)
	for i := range out {
		if out[i].Confidence < 0.9 {
			out[i].ProposedAction = manifest.ActionKeep
			out[i].RiskFlags = appendUnique(out[i].RiskFlags, "low_confidence")
		}
	}
	return out
}

// MarkDeletionCost flags L0 units that a feature consumes (D-013 M5,
// spec-manifest §4.11). The layer and action stay L0/delete.
func MarkDeletionCost(units []manifest.Unit) []manifest.Unit {
	out := append([]manifest.Unit(nil), units...)
	for i := range out {
		if out[i].Layer == manifest.LayerL0 && len(out[i].NeededBy) > 0 {
			out[i].RiskFlags = appendUnique(out[i].RiskFlags, "deletion_cost")
		}
	}
	return out
}

func hasRisk(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(values []string, v string) []string {
	for _, x := range values {
		if x == v {
			return values
		}
	}
	return append(values, v)
}

// ActionFor is the default proposed action for a resolved layer/secret pair.
// keep is always admissible; L0 delete, L1 reinstall and L5 relogin are the
// spec's δ conclusions.
func ActionFor(layer, secretClass string) string {
	if layer == manifest.LayerL5 || secretClass == manifest.SecretRelogin {
		return manifest.ActionRelogin
	}
	switch layer {
	case manifest.LayerL0:
		return manifest.ActionDelete
	case manifest.LayerL1:
		return manifest.ActionReinstall
	}
	return manifest.ActionKeep
}

// NormalizeEntry joins an entry id for signal notes without importing profile.
func NormalizeEntry(id string) string { return strings.TrimSpace(id) }

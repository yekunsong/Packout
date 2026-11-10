package classify

import (
	"testing"

	"packout/internal/manifest"
)

func unit(path, layer string) manifest.Unit {
	return manifest.Unit{PathKey: path, Path: path, Layer: layer, Confidence: 1.0}
}

func TestResolveTakesConservativeLayer(t *testing.T) {
	units := []manifest.Unit{unit("/a", manifest.LayerL0), unit("/a", manifest.LayerL3)}
	got := Resolve(units)
	for i := range got {
		if got[i].Layer != manifest.LayerL3 {
			t.Fatalf("unit %d layer = %s, want L3", i, got[i].Layer)
		}
		if got[i].Confidence != 0.8 {
			t.Fatalf("confidence = %v, want 0.8", got[i].Confidence)
		}
		found := false
		for _, s := range got[i].Signals {
			if s.Src == "content_match" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing conflict signal")
		}
	}
}

func TestResolveL4L5StayTop(t *testing.T) {
	for _, top := range []string{manifest.LayerL4, manifest.LayerL5} {
		got := Resolve([]manifest.Unit{unit("/a", manifest.LayerL0), unit("/a", top)})
		if got[0].Layer != top || got[1].Layer != top {
			t.Fatalf("conflict with %s resolved to %s/%s", top, got[0].Layer, got[1].Layer)
		}
	}
}

func TestResolveKeepsOrderAndUnrelated(t *testing.T) {
	in := []manifest.Unit{unit("/a", manifest.LayerL0), unit("/b", manifest.LayerL2), unit("/a", manifest.LayerL1)}
	got := Resolve(in)
	if len(got) != len(in) {
		t.Fatalf("len = %d, want %d", len(got), len(in))
	}
	if got[1].PathKey != "/b" || got[1].Layer != manifest.LayerL2 || got[1].Confidence != 1 {
		t.Fatal("unrelated unit changed")
	}
}

func TestApplyUniquenessPerInstanceAndEntry(t *testing.T) {
	scope := UniquenessScope{Mode: "root", Entries: map[string]bool{"e": true, "other": false}}
	units := []manifest.Unit{
		{Entry: "e", Root: "repo", PathKey: "/one", Layer: manifest.LayerL2},
		{Entry: "e", Root: "repo#2", PathKey: "/one", Layer: manifest.LayerL2},
		{Entry: "e", Root: "repo#2", PathKey: "/two", Layer: manifest.LayerL2},
		{Entry: "other", Root: "repo", PathKey: "/x", Layer: manifest.LayerL2},
	}
	got := ApplyUniqueness(units, scope)
	want := []string{manifest.LayerL3, manifest.LayerL2, manifest.LayerL2, manifest.LayerL2}
	for i, w := range want {
		if got[i].Layer != w {
			t.Fatalf("unit %d layer = %s, want %s", i, got[i].Layer, w)
		}
	}
	if len(got[0].Signals) == 0 {
		t.Fatal("promotion signal missing")
	}
}

func TestApplyUniquenessNonRootModeNoop(t *testing.T) {
	units := []manifest.Unit{{Entry: "e", Root: "r", PathKey: "/a", Layer: manifest.LayerL2}}
	got := ApplyUniqueness(units, UniquenessScope{Mode: "global", Entries: map[string]bool{"e": true}})
	if got[0].Layer != manifest.LayerL2 {
		t.Fatal("changed under unknown mode")
	}
}

func TestEnforceConfidence(t *testing.T) {
	units := []manifest.Unit{
		{Confidence: 0.89, ProposedAction: manifest.ActionDelete, Layer: manifest.LayerL0},
		{Confidence: 0.9, ProposedAction: manifest.ActionDelete, Layer: manifest.LayerL0},
	}
	got := EnforceConfidence(units)
	if got[0].ProposedAction != manifest.ActionKeep || !has(got[0].RiskFlags, "low_confidence") {
		t.Fatal("low confidence not enforced")
	}
	if got[1].ProposedAction != manifest.ActionDelete || has(got[1].RiskFlags, "low_confidence") {
		t.Fatal("0.9 must stay actionable")
	}
}

func TestMarkDeletionCost(t *testing.T) {
	units := []manifest.Unit{
		{Layer: manifest.LayerL0, NeededBy: []string{"rewind"}},
		{Layer: manifest.LayerL2, NeededBy: []string{"mcp"}},
		{Layer: manifest.LayerL0},
	}
	got := MarkDeletionCost(units)
	if !has(got[0].RiskFlags, "deletion_cost") {
		t.Fatal("L0+needed_by not flagged")
	}
	if has(got[1].RiskFlags, "deletion_cost") || has(got[2].RiskFlags, "deletion_cost") {
		t.Fatal("flag applied too broadly")
	}
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

package profile

import (
	"fmt"
	"sort"

	"github.com/yekunsong/Packout/profiles"
)

// builtinNames are the profiles shipped with the binary (spec-profile §8).
var builtinNames = []string{"claude-code", "codex"}

// BuiltinNames lists the embedded profile names in a stable order.
func BuiltinNames() []string {
	out := append([]string{}, builtinNames...)
	sort.Strings(out)
	return out
}

// Builtin loads, validates and returns the embedded profile called name.
// Built-in profiles are backed by the embedded fixtures, so RunSelfTest works
// without a source checkout.
func Builtin(name string) (*Profile, error) {
	found := false
	for _, n := range builtinNames {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("profile: unknown built-in profile %q", name)
	}
	data, err := profiles.FS.ReadFile(name + ".jsonc")
	if err != nil {
		return nil, fmt.Errorf("profile: read built-in %q: %w", name, err)
	}
	return load(data, "builtin:"+name, "", profiles.FS)
}

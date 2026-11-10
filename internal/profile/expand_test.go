package profile

import (
	"errors"
	"testing"
)

func TestExpandTemplateNestedAndDefaults(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("EMPTY", "")
	t.Setenv("SET", "value")
	t.Setenv("INDIRECT", "${HOME}/indirect")
	t.Setenv("USERPROFILE", `C:\Users\alice`)

	tests := []struct {
		name string
		in   string
		want string
	}{
		// The original D-033 bug: one pass left "$HOME/.config" literal and
		// the scan then treated it as a relative path.
		{"default recurses", "${XDG_CONFIG_HOME_UNSET:-$HOME/.config}", "/home/alice/.config"},
		{"nested defaults", "${A_UNSET:-${B_UNSET:-fallback}}", "fallback"},
		{"nested default takes set inner", "${A_UNSET:-${SET}}", "value"},
		{"bare var", "$HOME/x", "/home/alice/x"},
		{"braced var", "${HOME}/x", "/home/alice/x"},
		{"colon-dash on empty", "${EMPTY:-fallback}", "fallback"},
		{"dash on empty", "${EMPTY-fallback}", ""},
		{"colon-dash on set", "${SET:-fallback}", "value"},
		{"dash on set", "${SET-fallback}", "value"},
		{"value recurses", "${INDIRECT}", "/home/alice/indirect"},
		{"windows percent", `%USERPROFILE%\.codex`, `C:\Users\alice\.codex`},
		{"windows default recurses", "${CODEX_HOME_UNSET:-%USERPROFILE%\\.codex}", `C:\Users\alice\.codex`},
		{"no vars", `C:\Users\alice\.claude`, `C:\Users\alice\.claude`},
		{"bare percent literal", "100% done", "100% done"},
		{"malformed literal", "${}", "${}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandTemplate(tc.in)
			if err != nil {
				t.Fatalf("ExpandTemplate(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ExpandTemplate(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExpandTemplateUnresolved(t *testing.T) {
	for _, in := range []string{"$PACKOUT_NOPE_UNSET", "${PACKOUT_NOPE_UNSET}", "%PACKOUT_NOPE_UNSET%"} {
		t.Run(in, func(t *testing.T) {
			_, err := ExpandTemplate(in)
			if err == nil {
				t.Fatalf("ExpandTemplate(%q) = nil error, want unresolved", in)
			}
			var ue *UnresolvedError
			if !errors.As(err, &ue) {
				t.Fatalf("error type = %T, want *UnresolvedError", err)
			}
			if ue.Var != "PACKOUT_NOPE_UNSET" {
				t.Fatalf("UnresolvedError.Var = %q", ue.Var)
			}
			if !errors.Is(err, ErrUnresolved) {
				t.Fatal("errors.Is(err, ErrUnresolved) = false")
			}
		})
	}
	// A default makes an otherwise undefined variable fine.
	t.Setenv("PACKOUT_NOPE_UNSET", "")
	got, err := ExpandTemplate("${PACKOUT_NOPE_UNSET:-fallback}")
	if err != nil || got != "fallback" {
		t.Fatalf("default for undefined var = (%q, %v)", got, err)
	}
}

func TestExpandTemplateCycles(t *testing.T) {
	t.Run("self reference", func(t *testing.T) {
		t.Setenv("PACKOUT_SELF", "${PACKOUT_SELF}")
		_, err := ExpandTemplate("${PACKOUT_SELF}")
		var de *DepthError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v (%T), want *DepthError", err, err)
		}
		if de.Limit != maxExpandDepth {
			t.Fatalf("DepthError.Limit = %d, want %d", de.Limit, maxExpandDepth)
		}
	})
	t.Run("mutual reference", func(t *testing.T) {
		t.Setenv("PACKOUT_A", "${PACKOUT_B}")
		t.Setenv("PACKOUT_B", "${PACKOUT_A}")
		_, err := ExpandTemplate("${PACKOUT_A}")
		var de *DepthError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v (%T), want *DepthError", err, err)
		}
	})
	t.Run("depth limit", func(t *testing.T) {
		// A chain one link longer than the limit must fail, not recurse
		// forever.
		const extra = 3
		for i := 0; i <= maxExpandDepth+extra; i++ {
			t.Setenv(varName(i), "${"+varName(i+1)+"}")
		}
		t.Setenv(varName(maxExpandDepth+extra+1), "end")
		_, err := ExpandTemplate("${" + varName(0) + "}")
		var de *DepthError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DepthError", err)
		}
	})
}

func varName(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return "PACKOUT_CHAIN_" + string(digits[i])
	}
	return "PACKOUT_CHAIN_" + string(digits[i/10]) + string(digits[i%10])
}

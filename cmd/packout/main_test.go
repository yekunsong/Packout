package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain isolates every test from the real per-user config directory. A
// command test that forgets isolateConfig must never write config.json,
// state.json, keys or salt into the developer's ~/.config/packout.
// Tests that need a per-test directory still call isolateConfig, which
// overrides these values through t.Setenv.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "packout-test-config-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "packout tests: cannot create temp config dir: %v\n", err)
		os.Exit(1)
	}
	// XDG_CONFIG_HOME drives os.UserConfigDir on Linux; AppData on Windows.
	// HOME/USERPROFILE cover the fallbacks (and anything reading ~ directly).
	for _, key := range []string{"XDG_CONFIG_HOME", "AppData", "HOME", "USERPROFILE"} {
		if err := os.Setenv(key, dir); err != nil {
			fmt.Fprintf(os.Stderr, "packout tests: setenv %s: %v\n", key, err)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestDefaultConfigDirIsIsolated guards TestMain itself: without isolation a
// stray state write lands in the real user directory.
func TestDefaultConfigDirIsIsolated(t *testing.T) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = os.Getenv("AppData")
	}
	if base == "" {
		t.Skip("no config base in environment")
	}
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "packout") + string(os.PathSeparator)
	if !strings.HasPrefix(p, want) {
		t.Fatalf("configPath()=%q is not under the test config dir %q", p, base)
	}
}

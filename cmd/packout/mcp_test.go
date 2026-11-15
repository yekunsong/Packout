package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yekunsong/Packout/internal/profile"
)

func TestParseMCPRequiresOut(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := parseMCP(context.Background(), nil, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "--out") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestParseMCPRejectsMalformedRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := parseMCP(context.Background(), []string{"--out", t.TempDir(), "--root", "noequals"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stderr.String(), "role=PATH") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestParseMCPRejectsUnknownRootRole(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := parseMCP(context.Background(), []string{"--out", t.TempDir(), "--root", "nope=/tmp"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stderr.String(), "未被 profile") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestParseMCPRejectsExtraPositional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := parseMCP(context.Background(), []string{"--out", t.TempDir(), "extra"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("code = %d", code)
	}
}

func testProfile(t *testing.T) *profile.Profile {
	t.Helper()
	root := t.TempDir()
	return &profile.Profile{
		Name:      "p",
		RootOrder: []string{"home", "unsupported"},
		Roots: map[string]profile.Root{
			"home": {Template: root},
			// Deliberately has no entry for the running OS.
			"unsupported": {PerOS: map[string]string{"plan9": "/nope"}},
		},
	}
}

func TestResolveMCPRootsExpandsProfileDefaults(t *testing.T) {
	p := testProfile(t)
	roots, err := resolveMCPRoots(mcpConfig{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 {
		t.Fatalf("roots = %+v", roots)
	}
	if roots[0].Origin != "profile" || roots[0].Path == "" || roots[0].Note != "" {
		t.Fatalf("resolved root = %+v", roots[0])
	}
	if roots[1].Path != "" || roots[1].Note == "" {
		t.Fatalf("unsupported root should carry a note: %+v", roots[1])
	}
	_ = runtime.GOOS
}

func TestResolveMCPRootsNumbersDuplicates(t *testing.T) {
	p := testProfile(t)
	var rl rootList
	for _, v := range []string{"home=/a", "home=/b"} {
		if err := rl.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := resolveMCPRoots(mcpConfig{roots: rl}, p)
	if err != nil {
		t.Fatal(err)
	}
	if roots[0].Name != "home" || roots[1].Name != "home#2" {
		t.Fatalf("names = %q, %q", roots[0].Name, roots[1].Name)
	}
	if roots[1].Instance != 2 {
		t.Fatalf("instance = %d", roots[1].Instance)
	}
}

// A normal startup with no scan yet: Serve sees EOF on stdin and exits 0.
func TestRunMCPStartsAndExitsOnEOF(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scan")
	var stderr bytes.Buffer
	eof, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer eof.Close()
	old := os.Stdin
	os.Stdin = eof
	defer func() { os.Stdin = old }()

	code := parseMCP(context.Background(), []string{"--out", dir}, &bytes.Buffer{}, &stderr)
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "mcp 只读服务已启动") {
		t.Fatalf("banner missing: %q", stderr.String())
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"packout/internal/pack"
	"packout/internal/profile"
)

// run drives the real argument parser and returns code + captured streams.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := mainWithArgs(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// fixtureTree materializes the built-in claude-code fixtures and returns the
// instance paths (home, repo, appdata, localappdata).
func fixtureTree(t *testing.T) map[string]string {
	t.Helper()
	p, err := profile.Builtin("claude-code")
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	dir, err := profile.Materialize(p)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	out := map[string]string{}
	for _, inst := range []string{"home", "repo", "appdata", "localappdata"} {
		out[inst] = filepath.Join(dir, inst)
	}
	return out
}

func rootArgs(inst map[string]string) []string {
	var args []string
	for _, role := range []string{"home", "repo", "appdata", "localappdata"} {
		args = append(args, "--root", role+"="+inst[role])
	}
	return args
}

func TestMissingOutExitsUsage(t *testing.T) {
	inst := fixtureTree(t)
	scanArgs := append([]string{"scan"}, rootArgs(inst)...)
	cases := [][]string{
		scanArgs,
		{"report", "--manifest", t.TempDir()},
		{"export", "--src", t.TempDir()},
	}
	for _, args := range cases {
		code, _, stderr := run(t, args...)
		if code != exitUsage {
			t.Errorf("%v: code=%d, want %d (stderr %q)", args, code, exitUsage, stderr)
		}
		if !strings.Contains(stderr, "--out") {
			t.Errorf("%v: stderr does not mention --out: %q", args, stderr)
		}
	}
}

func TestScanWritesAndOutNotEmpty(t *testing.T) {
	inst := fixtureTree(t)
	out := filepath.Join(t.TempDir(), "scan")
	code, _, stderr := run(t, append([]string{"scan", "--out", out, "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest", "manifest.index.json")); err != nil {
		t.Fatalf("scan produced no manifest/manifest.index.json: %v", err)
	}

	// Non-empty without --force is exit 4 and must not touch the tree.
	code, _, stderr = run(t, append([]string{"scan", "--out", out}, rootArgs(inst)...)...)
	if code != exitNotEmpty {
		t.Fatalf("re-scan: code=%d, want %d (stderr %q)", code, exitNotEmpty, stderr)
	}
	// --force succeeds.
	code, _, stderr = run(t, append([]string{"scan", "--out", out, "--force", "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("forced re-scan: code=%d stderr=%q", code, stderr)
	}
}

func TestProfileTestBuiltins(t *testing.T) {
	for _, name := range profile.BuiltinNames() {
		code, stdout, stderr := run(t, "profile", "test", name)
		if code != exitOK {
			t.Fatalf("profile test %s: code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func TestProfileProbeJSONAndList(t *testing.T) {
	inst := fixtureTree(t)
	code, stdout, stderr := run(t, append([]string{"profile", "probe", "claude-code", "--json"}, rootArgs(inst)...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("probe: code=%d stderr=%q", code, stderr)
	}
	// A single JSON object with a rows array keeps stdout parseable.
	var pr struct {
		Profile string `json:"profile"`
		Rows    []struct {
			Entry  string `json:"entry"`
			Status string `json:"status"`
		} `json:"rows"`
		Entries int `json:"entries"`
	}
	if err := json.Unmarshal([]byte(stdout), &pr); err != nil {
		t.Fatalf("probe JSON: %v (%q)", err, stdout)
	}
	if pr.Profile != "claude-code" || len(pr.Rows) == 0 {
		t.Fatalf("probe report = %+v", pr)
	}

	code, stdout, stderr = run(t, "profile", "list", "--json")
	if code != exitOK {
		t.Fatalf("profile list: code=%d stderr=%q", code, stderr)
	}
	var l struct {
		Builtin []string `json:"builtin"`
	}
	if err := json.Unmarshal([]byte(stdout), &l); err != nil {
		t.Fatalf("profile list JSON: %v (%q)", err, stdout)
	}
	if len(l.Builtin) != 2 {
		t.Fatalf("builtin profiles = %v, want 2", l.Builtin)
	}
}

// TestFullFlow walks scan -> report -> export -> verify, the C24 acceptance
// path (D-015 §14), and asserts the P0 conclusion word.
func TestFullFlow(t *testing.T) {
	inst := fixtureTree(t)
	work := t.TempDir()
	scanOut := filepath.Join(work, "scan")

	code, _, stderr := run(t, append([]string{"scan", "--out", scanOut, "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}

	reportOut := filepath.Join(scanOut, "REPORT.html")
	code, stdout, stderr := run(t, "report", "--manifest", scanOut, "--out", reportOut, "--no-serve", "--quiet")
	if code != exitOK {
		t.Fatalf("report: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if fi, err := os.Stat(reportOut); err != nil || fi.Size() == 0 {
		t.Fatalf("report not written: %v", err)
	}

	pkg := filepath.Join(work, "pkg")
	code, stdout, stderr = run(t, "export", "--src", scanOut, "--out", pkg, "--quiet")
	if code != exitOK {
		t.Fatalf("export: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = run(t, "verify", pkg)
	if code != exitOK {
		t.Fatalf("verify: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != pack.ConclusionHashOKUnverified {
		t.Fatalf("verify conclusion = %q, want %q", strings.TrimSpace(stdout), pack.ConclusionHashOKUnverified)
	}

	// The same target again is exit 4; --force merges package-owned subtrees.
	code, _, stderr = run(t, "export", "--src", scanOut, "--out", pkg, "--quiet")
	if code != exitNotEmpty {
		t.Fatalf("re-export: code=%d, want %d (stderr %q)", code, exitNotEmpty, stderr)
	}
	code, stdout, stderr = run(t, "export", "--src", scanOut, "--out", pkg, "--force", "--quiet")
	if code != exitOK {
		t.Fatalf("forced re-export: code=%d stderr=%q", code, stderr)
	}
}

func TestJSONEveryCommand(t *testing.T) {
	inst := fixtureTree(t)
	work := t.TempDir()
	scanOut := filepath.Join(work, "scan")

	check := func(name string, code int, stdout string) {
		t.Helper()
		if !json.Valid(bytes.TrimSpace([]byte(stdout))) {
			t.Fatalf("%s --json produced non-JSON stdout: %q", name, stdout)
		}
	}

	code, stdout, _ := run(t, append([]string{"scan", "--out", scanOut, "--json"}, rootArgs(inst)...)...)
	check("scan", code, stdout)

	reportOut := filepath.Join(scanOut, "REPORT.html")
	code, stdout, _ = run(t, "report", "--manifest", scanOut, "--out", reportOut, "--no-serve", "--json")
	check("report", code, stdout)

	pkg := filepath.Join(work, "pkg")
	code, stdout, _ = run(t, "export", "--src", scanOut, "--out", pkg, "--json")
	check("export", code, stdout)

	code, stdout, _ = run(t, "verify", pkg, "--json")
	check("verify", code, stdout)
	var v struct {
		Conclusion string `json:"conclusion"`
	}
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("verify JSON: %v", err)
	}
	if v.Conclusion != pack.ConclusionHashOKUnverified {
		t.Fatalf("verify JSON conclusion = %q", v.Conclusion)
	}

	code, stdout, _ = run(t, "profile", "test", "claude-code", "--json")
	check("profile test", code, stdout)

	code, stdout, _ = run(t, "version", "--json")
	check("version", code, stdout)

	// Usage errors are JSON too, so a caller can always parse stdout.
	code, stdout, _ = run(t, "scan", "--json")
	if code != exitUsage {
		t.Fatalf("scan without --out: code=%d", code)
	}
	check("scan usage error", code, stdout)
}

// TestInterruptLeavesNoProduct is the exit-5 path: a cancelled context must
// not leave a directory that looks like a finished scan.
func TestInterruptLeavesNoProduct(t *testing.T) {
	inst := fixtureTree(t)
	work := t.TempDir()
	out := filepath.Join(work, "scan")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := runScan(ctx, scanConfig{
		out:   out,
		roots: rootList{{role: "home", path: inst["home"]}},
		quiet: true,
	}, &stdout, &stderr)
	if code != exitCanceled {
		t.Fatalf("runScan(cancelled) = %d, want %d (stderr %q)", code, exitCanceled, stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("cancelled scan left %s behind (err=%v)", out, err)
	}
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("staging directory left behind: %s", e.Name())
		}
	}
}

func TestScanHelpListsRoots(t *testing.T) {
	code, stdout, _ := run(t, "scan", "--help")
	if code != exitOK {
		t.Fatalf("scan --help: code=%d", code)
	}
	for _, want := range []string{"--out", "--root", "home", "appdata", "localappdata", "repo", "必填"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("scan --help missing %q:\n%s", want, stdout)
		}
	}
}

// TestReportLANWarnsOnStderr covers the --lan contract: 0.0.0.0 binding, a
// warning and the actual URL on stderr, and exit 5 on interrupt.
func TestReportLANWarnsOnStderr(t *testing.T) {
	inst := fixtureTree(t)
	work := t.TempDir()
	scanOut := filepath.Join(work, "scan")
	code, _, stderr := run(t, append([]string{"scan", "--out", scanOut, "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var stdout, stderrBuf bytes.Buffer
	code = runReport(ctx, reportConfig{
		manifest: scanOut,
		out:      filepath.Join(work, "REPORT.html"),
		lan:      true,
	}, &stdout, &stderrBuf)
	if code != exitCanceled {
		t.Fatalf("report --lan: code=%d stdout=%q stderr=%q", code, stdout.String(), stderrBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "局域网") {
		t.Errorf("no LAN warning on stderr: %q", stderrBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "http://") {
		t.Errorf("URL not on stderr: %q", stderrBuf.String())
	}
}

// TestVerifyFailedConclusion checks the exit-code table for a non-package:
// the conclusion word is printed verbatim and the code is 2.
func TestVerifyFailedConclusion(t *testing.T) {
	dir := t.TempDir()
	code, stdout, _ := run(t, "verify", dir)
	if code != exitPartial {
		t.Fatalf("verify(empty dir): code=%d, want %d", code, exitPartial)
	}
	if strings.TrimSpace(stdout) != pack.ConclusionEmpty {
		t.Fatalf("conclusion = %q, want %q", strings.TrimSpace(stdout), pack.ConclusionEmpty)
	}
}

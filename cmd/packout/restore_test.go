package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packout/internal/pack"
	"packout/internal/restore"
)

// signedPkg is exportPkg plus a signature and the matching public key.
func signedPkg(t *testing.T) (pkg, pub string) {
	t.Helper()
	pkg = exportPkg(t)
	priv, pub := newKey(t)
	if code, _, stderr := run(t, "sign", pkg, "--key", priv); code != exitOK {
		t.Fatalf("sign: code=%d stderr=%q", code, stderr)
	}
	return pkg, pub
}

func TestRestoreUsageErrors(t *testing.T) {
	if code, _, _ := run(t, "restore"); code != exitUsage {
		t.Fatalf("missing package: code=%d", code)
	}
	if code, _, _ := run(t, "restore", "somepkg"); code != exitUsage {
		t.Fatalf("missing --into: code=%d", code)
	}

}

func TestRestoreUnsignedGateAndRedWarning(t *testing.T) {
	pkg := exportPkg(t) // unsigned
	into := filepath.Join(t.TempDir(), "target")

	code, stdout, stderr := run(t, "restore", pkg, "--into", into)
	if code != exitPartial {
		t.Fatalf("unsigned default: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, pack.ConclusionUnsigned) {
		t.Errorf("SIG conclusion missing from report: %q", stdout)
	}
	if _, err := os.Stat(into); !os.IsNotExist(err) {
		t.Fatal("unsigned default must not write")
	}

	code, _, stderr = run(t, "restore", pkg, "--into", into, "--allow-unverified", "--quiet")
	if code != exitOK {
		t.Fatalf("allowed unsigned: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "\x1b[31m") {
		t.Errorf("allowed unverified must be red: %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(into, "home")); err != nil {
		t.Fatalf("restore did not write: %v", err)
	}
}

func TestRestoreNoKeyAllowedWithFlag(t *testing.T) {
	isolateHome(t)
	pkg, _ := signedPkg(t)
	into := filepath.Join(t.TempDir(), "target")

	code, stdout, stderr := run(t, "restore", pkg, "--into", into)
	if code != exitPartial {
		t.Fatalf("no-key default: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, pack.ConclusionBadSignature) || !strings.Contains(stderr, pack.ConclusionBadSignature) {
		t.Fatalf("actual conclusion not reported: stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(stderr, "tampered") || strings.Contains(stderr, "篡改") {
		t.Fatalf("no-key restore blamed tampering: %q", stderr)
	}
	if !strings.Contains(stderr, "--pubkey") && !strings.Contains(stderr, "--allow-unverified") {
		t.Fatalf("no actionable next step: %q", stderr)
	}
	if _, err := os.Stat(into); !os.IsNotExist(err) {
		t.Fatal("gate must not write")
	}

	code, _, stderr = run(t, "restore", pkg, "--into", into, "--allow-unverified", "--quiet")
	if code != exitOK {
		t.Fatalf("allowed no-key: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "[31m") {
		t.Errorf("allowed unverified must be red: %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(into, "home")); err != nil {
		t.Fatalf("restore did not write: %v", err)
	}
}

func TestRestoreTamperedExitPartial(t *testing.T) {
	pkg, pub := signedPkg(t)
	configFile := filepath.Join(pkg, "config", "home", ".claude", "settings.local.json")
	mustWrite(t, configFile, []byte("tampered"))
	code, _, stderr := run(t, "restore", pkg, "--into", filepath.Join(t.TempDir(), "t"),
		"--pubkey", pub, "--allow-unverified")
	if code != exitPartial {
		t.Fatalf("tampered: code=%d stderr=%q", code, stderr)
	}
}

func TestRestoreNonEmptyExitFourThenInPlaceForce(t *testing.T) {
	pkg, pub := signedPkg(t)
	into := t.TempDir()
	keep := filepath.Join(into, "keep.txt")
	mustWrite(t, keep, []byte("keep"))

	code, _, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub)
	if code != exitNotEmpty {
		t.Fatalf("non-empty: code=%d stderr=%q", code, stderr)
	}
	// --force alone does not enable in-place.
	code, _, stderr = run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--force")
	if code != exitNotEmpty {
		t.Fatalf("--force without --in-place: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--in-place")
	if code != exitNotEmpty {
		t.Fatalf("in-place without force: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--in-place", "--force", "--quiet")
	if code != exitOK {
		t.Fatalf("in-place force: code=%d stderr=%q", code, stderr)
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "keep" {
		t.Fatalf("unrelated file changed: %q %v", b, err)
	}
}

func TestRestoreDryRunWritesNothing(t *testing.T) {
	pkg, pub := signedPkg(t)
	into := filepath.Join(t.TempDir(), "target")
	code, stdout, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--dry-run")
	if code != exitOK {
		t.Fatalf("dry-run: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(into); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote the target")
	}
	if !strings.Contains(stdout, "干跑") {
		t.Errorf("dry-run banner missing: %q", stdout)
	}
}

func TestRestoreJSONReport(t *testing.T) {
	pkg, pub := signedPkg(t)
	into := filepath.Join(t.TempDir(), "target")
	code, stdout, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--dry-run", "--json")
	if code != exitOK {
		t.Fatalf("json dry-run: code=%d stderr=%q", code, stderr)
	}
	var rep struct {
		SigConclusion string `json:"sig_conclusion"`
		Plan          []struct {
			Path string `json:"path"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout is not one JSON value: %v (%q)", err, stdout)
	}
	if rep.SigConclusion != pack.ConclusionOK || len(rep.Plan) == 0 {
		t.Fatalf("report = %+v", rep)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreMap covers the new-machine flow: --map home=. lands home files
// directly in --into, a second role can move under a subdirectory, dry-run
// stays read-only, and unsafe mappings are refused before any write.
func TestRestoreMap(t *testing.T) {
	isolateHome(t)
	pkg, pub := signedPkg(t)
	base := t.TempDir()

	into := filepath.Join(base, "newhome")
	code, stdout, stderr := run(t, "restore", pkg, "--into", into, "--map", "home=.", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("restore --map home=.: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(into, ".claude", "settings.json")); err != nil {
		t.Fatalf("home did not land directly in --into: %v", err)
	}
	if _, err := os.Stat(filepath.Join(into, "home")); !os.IsNotExist(err) {
		t.Fatalf("home=. still created the home/ mirror: %v", err)
	}
	if !strings.Contains(stdout, "落地：home → "+into) {
		t.Fatalf("landing summary missing resolved path:\n%s", stdout)
	}

	into2 := filepath.Join(base, "mapped")
	code, stdout, stderr = run(t, "restore", pkg, "--into", into2,
		"--map", "home=work/home", "--map", "repo=work/proj2", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("restore two maps: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(into2, "work", "home", ".claude", "settings.json")); err != nil {
		t.Fatalf("mapped home missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(into2, "work", "proj2", ".mcp.json")); err != nil {
		t.Fatalf("mapped repo missing: %v", err)
	}
	if !strings.Contains(stdout, "work"+string(os.PathSeparator)+"proj2") &&
		!strings.Contains(stdout, "work/proj2") {
		t.Fatalf("landing summary does not name the repo mapping:\n%s", stdout)
	}

	dry := filepath.Join(base, "dry")
	code, _, stderr = run(t, "restore", pkg, "--into", dry, "--dry-run", "--map", "home=.", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("restore --dry-run --map: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(dry); !os.IsNotExist(err) {
		t.Fatalf("dry run with --map created the target: %v", err)
	}

	for _, m := range []string{"home=/abs/path", "home=../escape", "home=a/../../escape", "home="} {
		out := filepath.Join(base, "bad")
		code, _, stderr := run(t, "restore", pkg, "--into", out, "--map", m, "--pubkey", pub)
		if code != exitUsage {
			t.Fatalf("--map %q: code=%d, want %d (stderr %q)", m, code, exitUsage, stderr)
		}
		if !strings.Contains(stderr, "--map") {
			t.Fatalf("--map %q: error does not mention --map: %q", m, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("--map %q wrote the target", m)
		}
	}

	code, _, stderr = run(t, "restore", pkg, "--into", filepath.Join(base, "dup"),
		"--map", "home=a", "--map", "home=b", "--pubkey", pub)
	if code != exitUsage || !strings.Contains(stderr, "重复映射") {
		t.Fatalf("duplicate --map: code=%d stderr=%q", code, stderr)
	}

	// --into stays mandatory even with a mapping.
	if code, _, _ := run(t, "restore", pkg, "--map", "home=."); code != exitUsage {
		t.Fatalf("--map without --into: code=%d, want %d", code, exitUsage)
	}
}

// TestPrintLandingHonesty pins the wording branch: when every role came from
// --map, telling the user to copy subdirectories contradicts what just
// happened. Dry-run must not claim the files are already there.
func TestPrintLandingHonesty(t *testing.T) {
	render := func(rep *restore.Report) string {
		t.Helper()
		var out bytes.Buffer
		r := &reporter{stdout: &out, stderr: io.Discard}
		printLanding(r, rep)
		return out.String()
	}

	mapped := &restore.Report{Landing: []restore.Landing{
		{Role: "home", Path: "/new/home", Mapped: true},
		{Role: "repo", Path: "/new/repo", Mapped: true},
	}}
	if got := render(mapped); !strings.Contains(got, "--map 生效，已直接写到这里") ||
		strings.Contains(got, "复制到目标机器") {
		t.Fatalf("all-mapped landing still asks to copy: %q", got)
	}
	if got := render(mapped); !strings.Contains(got, "home → /new/home") ||
		!strings.Contains(got, "repo → /new/repo") {
		t.Fatalf("landing lost resolved paths: %q", got)
	}

	dry := &restore.Report{DryRun: true, Landing: []restore.Landing{
		{Role: "home", Path: "/new/home", Mapped: true},
	}}
	if got := render(dry); strings.Contains(got, "已直接写到这里") ||
		!strings.Contains(got, "干跑未写入") {
		t.Fatalf("dry-run landing claims a write: %q", got)
	}

	partial := &restore.Report{Landing: []restore.Landing{
		{Role: "home", Path: "/new/home", Mapped: true},
		{Role: "repo", Path: "/new/repo"},
	}}
	if got := render(partial); !strings.Contains(got, "复制到目标机器") ||
		strings.Contains(got, "--map 生效") {
		t.Fatalf("partial mapping dropped the copy hint: %q", got)
	}
}

// TestRestoreOverwriteNotice checks the honest overwrite line end to end:
// printed with a count when files are replaced, absent on --dry-run.
func TestRestoreOverwriteNotice(t *testing.T) {
	pkg, pub := signedPkg(t)
	into := filepath.Join(t.TempDir(), "target")
	if code, _, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--quiet"); code != exitOK {
		t.Fatalf("first restore: code=%d stderr=%q", code, stderr)
	}

	victim := ""
	if err := filepath.WalkDir(into, func(p string, d os.DirEntry, err error) error {
		if err != nil || victim != "" || !d.Type().IsRegular() {
			return nil
		}
		victim = p
		return nil
	}); err != nil {
		t.Fatalf("walk restored tree: %v", err)
	}
	if victim == "" {
		t.Fatal("no restored regular file to overwrite")
	}
	mustWrite(t, victim, []byte("changed on disk"))

	code, stdout, stderr := run(t, "restore", pkg, "--into", into,
		"--in-place", "--force", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("in-place force: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "已覆盖 1 个既有文件") || !strings.Contains(stdout, "不做备份") {
		t.Fatalf("overwrite notice missing or dishonest:\n%s", stdout)
	}

	mustWrite(t, victim, []byte("changed again"))
	code, stdout, stderr = run(t, "restore", pkg, "--into", into,
		"--in-place", "--force", "--dry-run", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("dry-run in-place force: code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stdout, "已覆盖") || strings.Contains(stdout, "不做备份") {
		t.Fatalf("dry-run claimed an overwrite:\n%s", stdout)
	}
}

// TestRestoreJSONOverwritten pins the additive JSON field.
func TestRestoreJSONOverwritten(t *testing.T) {
	pkg, pub := signedPkg(t)
	into := filepath.Join(t.TempDir(), "target")
	if code, _, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--quiet"); code != exitOK {
		t.Fatalf("first restore: code=%d stderr=%q", code, stderr)
	}
	var victim string
	if err := filepath.WalkDir(into, func(p string, d os.DirEntry, err error) error {
		if err != nil || victim != "" || !d.Type().IsRegular() {
			return nil
		}
		victim = p
		return nil
	}); err != nil {
		t.Fatalf("walk restored tree: %v", err)
	}
	mustWrite(t, victim, []byte("changed on disk"))

	code, stdout, stderr := run(t, "restore", pkg, "--into", into,
		"--in-place", "--force", "--pubkey", pub, "--json")
	if code != exitOK {
		t.Fatalf("json in-place force: code=%d stderr=%q", code, stderr)
	}
	var rep struct {
		Overwritten *int               `json:"overwritten"`
		Restored    []restore.Restored `json:"restored"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout is not one JSON value: %v (%q)", err, stdout)
	}
	if rep.Overwritten == nil || *rep.Overwritten != 1 {
		t.Fatalf("overwritten = %v, want 1 (%q)", rep.Overwritten, stdout)
	}
	if len(rep.Restored) == 0 {
		t.Fatalf("restored segment disappeared: %q", stdout)
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packout/internal/pack"
)

// --- layered help -----------------------------------------------------------

func TestHelpCommandMatchesFlagHelp(t *testing.T) {
	for _, v := range allVerbs {
		codeH, outH, errH := run(t, "help", v.name)
		codeF, outF, errF := run(t, v.name, "--help")
		if codeH != exitOK || codeF != exitOK {
			t.Errorf("%s: help code=%d, --help code=%d (stderr %q / %q)", v.name, codeH, codeF, errH, errF)
			continue
		}
		if outH != outF {
			t.Errorf("%s: `help %s` and `%s --help` differ:\n--- help\n%s\n--- --help\n%s", v.name, v.name, v.name, outH, outF)
		}
		last := ""
		for _, line := range strings.Split(strings.TrimRight(outH, "\n"), "\n") {
			if strings.TrimSpace(line) != "" {
				last = line
			}
		}
		if !strings.HasPrefix(last, "下一步：") {
			t.Errorf("%s: help does not end with a 下一步 line, last line = %q", v.name, last)
		}
	}
}

func TestHelpAllListsEveryVerb(t *testing.T) {
	code, stdout, stderr := run(t, "help", "--all")
	if code != exitOK {
		t.Fatalf("help --all: code=%d stderr=%q", code, stderr)
	}
	for _, v := range allVerbs {
		if !strings.Contains(stdout, "  "+v.name) {
			t.Errorf("help --all lacks %q:\n%s", v.name, stdout)
		}
	}
	if !strings.Contains(stdout, "下一步：") {
		t.Errorf("help --all lacks a 下一步 line")
	}
	if code, _, _ := run(t, "help", "ghost"); code != exitUsage {
		t.Errorf("help ghost: code=%d, want %d", code, exitUsage)
	}
}

// --- bare packout is a state-aware hint -------------------------------------

func TestBarePackoutUninitialized(t *testing.T) {
	cfgDir := isolateConfig(t)
	code, stdout, stderr := run(t)
	if code != exitOK {
		t.Fatalf("bare packout: code=%d, want 0 (stderr %q)", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("bare packout printed %d lines, want 3:\n%s", len(lines), stdout)
	}
	for _, want := range []string{"packout init", "packout help"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("bare packout lacks %q:\n%s", want, stdout)
		}
	}
	// It writes nothing at all.
	if _, err := os.Stat(cfgDir); !os.IsNotExist(err) {
		t.Fatalf("bare packout created %s (err=%v)", cfgDir, err)
	}
}

func TestBarePackoutConfiguredNoPackages(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1,"roots":{"home":"/tmp/home"}}`)
	code, stdout, stderr := run(t)
	if code != exitOK {
		t.Fatalf("bare packout: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "packout pack") {
		t.Errorf("bare packout does not suggest pack:\n%s", stdout)
	}
	if !strings.Contains(stdout, "还没有包记录") {
		t.Errorf("bare packout does not say there is no package yet:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "state.json")); !os.IsNotExist(err) {
		t.Errorf("bare packout wrote state.json")
	}
}

func TestBarePackoutWithPackagesPrintsStatus(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1}`)
	inst := fixtureTree(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := run(t, append([]string{"pack", pkg, "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr := run(t)
	if code != exitOK {
		t.Fatalf("bare packout: code=%d stderr=%q", code, stderr)
	}
	for _, want := range []string{"配置:", "最近的包:", pkg, "packout verify", "packout drill", "packout restore", "packout status"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("bare packout lacks %q:\n%s", want, stdout)
		}
	}
	// A second bare run must be stable (read-only).
	_, stdout2, _ := run(t)
	if stdout != stdout2 {
		t.Errorf("bare packout is not stable between runs")
	}
	_ = cfgDir
}

// --- pack positional arguments and --seal -----------------------------------

// packPackage runs pack with the fixture roots and returns the output path.
func packPackage(t *testing.T, inst map[string]string, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"pack"}, args...)
	full = append(full, "--quiet")
	full = append(full, rootArgs(inst)...)
	return run(t, full...)
}

func TestPackPositionalEqualsOut(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	work := t.TempDir()
	pkgA := filepath.Join(work, "a")
	pkgB := filepath.Join(work, "b")
	if code, _, stderr := packPackage(t, inst, pkgA); code != exitOK {
		t.Fatalf("pack positional: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := packPackage(t, inst, "--out", pkgB); code != exitOK {
		t.Fatalf("pack --out: code=%d stderr=%q", code, stderr)
	}
	namesA, _ := os.ReadDir(pkgA)
	namesB, _ := os.ReadDir(pkgB)
	if len(namesA) == 0 || len(namesA) != len(namesB) {
		t.Fatalf("pack positional and --out produced different trees: %d vs %d entries", len(namesA), len(namesB))
	}
	for i := range namesA {
		if namesA[i].Name() != namesB[i].Name() {
			t.Fatalf("tree differs at %d: %q vs %q", i, namesA[i].Name(), namesB[i].Name())
		}
	}
	if _, err := os.Stat(filepath.Join(pkgA, "SIG.json")); err != nil {
		t.Fatalf("positional pack has no SIG.json: %v", err)
	}

	// Two different spellings in one call is a usage error and writes nothing.
	other := filepath.Join(work, "other")
	code, _, stderr := run(t, append([]string{"pack", pkgA, "--out", other}, rootArgs(inst)...)...)
	if code != exitUsage {
		t.Fatalf("mismatched positional/--out: code=%d, want %d (stderr %q)", code, exitUsage, stderr)
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("usage error created %s", other)
	}
}

func TestPackSealSignsWithoutCredentials(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv)
	if code != exitOK {
		t.Fatalf("pack --seal: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(pkg, pack.MinisigName)); err != nil {
		t.Fatalf("--seal did not sign: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pkg, pack.SecretsName)); !os.IsNotExist(err) {
		t.Fatalf("pure --seal must not write secrets.age (err=%v)", err)
	}
	if code, stdout, stderr := run(t, "verify", pkg, "--pubkey", pub); code != exitOK || strings.TrimSpace(stdout) != pack.ConclusionOK {
		t.Fatalf("verify sealed pkg: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestPackSealWithCredentialEncryptsSecrets(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, _ := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	const recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv, "--recipient", recipient)
	if code != exitOK {
		t.Fatalf("pack --seal --recipient: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(pkg, pack.SecretsName)); err != nil {
		t.Fatalf("--seal with --recipient did not encrypt credentials: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pkg, pack.MinisigName)); err != nil {
		t.Fatalf("--seal with --recipient did not sign: %v", err)
	}
}

// --- state.json and status --------------------------------------------------

type testState struct {
	Version  int `json:"version"`
	LastScan *struct {
		Out   string            `json:"out"`
		Units int64             `json:"units"`
		Roots map[string]string `json:"roots"`
	} `json:"last_scan"`
	LastVerify *struct {
		Path       string `json:"path"`
		Conclusion string `json:"conclusion"`
	} `json:"last_verify"`
	LastRestore *struct {
		Path string `json:"path"`
		Into string `json:"into"`
	} `json:"last_restore"`
	Packages []struct {
		Path   string `json:"path"`
		Signed bool   `json:"signed"`
	} `json:"packages"`
}

func readState(t *testing.T, cfgDir string) testState {
	t.Helper()
	var st testState
	b, err := os.ReadFile(filepath.Join(cfgDir, "state.json"))
	if err != nil {
		t.Fatalf("state.json: %v", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("state.json parse: %v", err)
	}
	return st
}

func TestStateRecordsScanPackVerifyRestore(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1}`)
	inst := fixtureTree(t)

	scanOut := filepath.Join(t.TempDir(), "scan")
	if code, _, stderr := run(t, append([]string{"scan", "--out", scanOut, "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}
	st := readState(t, cfgDir)
	if st.Version != stateVersion || st.LastScan == nil || st.LastScan.Units == 0 {
		t.Fatalf("scan was not recorded: %+v", st)
	}
	if st.LastScan.Roots["home"] != inst["home"] {
		t.Fatalf("scan roots not recorded: %+v", st.LastScan.Roots)
	}

	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	st = readState(t, cfgDir)
	if len(st.Packages) == 0 || st.Packages[0].Path != pkg || !st.Packages[0].Signed {
		t.Fatalf("pack was not recorded: %+v", st.Packages)
	}

	if code, _, stderr := run(t, "verify", pkg, "--pubkey", pub); code != exitOK {
		t.Fatalf("verify: code=%d stderr=%q", code, stderr)
	}
	st = readState(t, cfgDir)
	if st.LastVerify == nil || st.LastVerify.Conclusion != pack.ConclusionOK || st.LastVerify.Path != pkg {
		t.Fatalf("verify was not recorded: %+v", st.LastVerify)
	}

	into := filepath.Join(t.TempDir(), "into")
	if code, _, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--quiet"); code != exitOK {
		t.Fatalf("restore: code=%d stderr=%q", code, stderr)
	}
	st = readState(t, cfgDir)
	if st.LastRestore == nil || st.LastRestore.Into != into {
		t.Fatalf("restore was not recorded: %+v", st.LastRestore)
	}

	// status is read-only and reports the facts.
	before, err := os.ReadFile(filepath.Join(cfgDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "status", "--json")
	if code != exitOK {
		t.Fatalf("status --json: code=%d stderr=%q", code, stderr)
	}
	var sum struct {
		Configured bool   `json:"configured"`
		Config     string `json:"config"`
		Next       []string
	}
	if err := json.Unmarshal([]byte(stdout), &sum); err != nil {
		t.Fatalf("status JSON: %v (%q)", err, stdout)
	}
	if !sum.Configured {
		t.Fatalf("status says not configured: %q", stdout)
	}
	after, err := os.ReadFile(filepath.Join(cfgDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("status modified state.json")
	}
	// The human view names the last package and the next commands.
	code, stdout, _ = run(t, "status")
	if code != exitOK {
		t.Fatalf("status: code=%d", code)
	}
	for _, want := range []string{"配置:", "上次 scan:", "上次 verify:", "上次 restore:", pkg} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status lacks %q:\n%s", want, stdout)
		}
	}
}

func TestStateFailureDoesNotWrite(t *testing.T) {
	cfgDir := isolateConfig(t)
	inst := fixtureTree(t)
	out := t.TempDir()
	mustWrite(t, filepath.Join(out, "keep"), []byte("x"))
	code, _, _ := run(t, append([]string{"pack", out}, rootArgs(inst)...)...)
	if code != exitNotEmpty {
		t.Fatalf("pack into non-empty: code=%d", code)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("failed pack wrote state.json")
	}
}

func TestStateBadFileOnlyWarns(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1}`)
	mustWrite(t, filepath.Join(cfgDir, "state.json"), []byte("{not json"))

	for _, args := range [][]string{{"status"}, {"status", "--json"}} {
		code, stdout, stderr := run(t, args...)
		if code != exitOK {
			t.Fatalf("%v: code=%d, want 0 (stderr %q)", args, code, stderr)
		}
		if !strings.Contains(stderr, "状态文件") {
			t.Errorf("%v: no state warning on stderr: %q", args, stderr)
		}
		if len(args) == 2 && !json.Valid([]byte(stdout)) {
			t.Errorf("status --json stdout is not JSON: %q", stdout)
		}
	}
	if code, _, stderr := run(t); code != exitOK || !strings.Contains(stderr, "状态文件") {
		t.Fatalf("bare packout with bad state: code=%d stderr=%q", code, stderr)
	}

	// A later successful command replaces the bad file with a valid one.
	inst := fixtureTree(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := run(t, append([]string{"pack", pkg, "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("pack after bad state: code=%d stderr=%q", code, stderr)
	}
	st := readState(t, cfgDir)
	if st.Version != stateVersion {
		t.Fatalf("repaired state has version %d", st.Version)
	}
}

func TestStateUnknownVersionWarns(t *testing.T) {
	cfgDir := isolateConfig(t)
	mustWrite(t, filepath.Join(cfgDir, "state.json"), []byte(`{"version":99}`))
	code, _, stderr := run(t, "status")
	if code != exitOK {
		t.Fatalf("status: code=%d", code)
	}
	if !strings.Contains(stderr, "不支持的 version") {
		t.Fatalf("no version warning: %q", stderr)
	}
}

// --- drill never touches the user target ------------------------------------

func TestDrillDryRunLeavesTargetUntouched(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}

	// --into is only a report label: it may not exist, and drill must not
	// create it (nor need it writable).
	target := filepath.Join(t.TempDir(), "no-such-dir", "deep")
	code, stdout, stderr := run(t, "drill", pkg, "--into", target, "--pubkey", pub, "--json")
	if code != exitOK {
		t.Fatalf("drill: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var sum struct {
		Package   string `json:"package"`
		TempDir   string `json:"temp_dir"`
		Kept      bool   `json:"kept"`
		DryRun    bool   `json:"dry_run"`
		Planned   int    `json:"planned"`
		Restored  int    `json:"restored"`
		IntoCheck string `json:"would_restore_into"`
	}
	if err := json.Unmarshal([]byte(stdout), &sum); err != nil {
		t.Fatalf("drill JSON: %v (%q)", err, stdout)
	}
	if !sum.DryRun || sum.Kept || sum.Planned == 0 {
		t.Fatalf("drill summary = %+v", sum)
	}
	if sum.IntoCheck != target {
		t.Fatalf("drill did not report the user target: %+v", sum)
	}
	if _, err := os.Stat(sum.TempDir); !os.IsNotExist(err) {
		t.Fatalf("drill left temp dir %s behind (err=%v)", sum.TempDir, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("drill created the report-only target %s (err=%v)", target, err)
	}

	// A read-only parent of --into must not matter either.
	parent := t.TempDir()
	roTarget := filepath.Join(parent, "target")
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	if code, _, stderr := run(t, "drill", pkg, "--into", roTarget, "--pubkey", pub, "--quiet"); code != exitOK {
		t.Fatalf("drill with read-only --into parent: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(roTarget); !os.IsNotExist(err) {
		t.Fatalf("drill created %s under a read-only parent", roTarget)
	}

	// The dry run did not create a temp dir, so it must not claim to delete
	// one either.
	code, stdout, stderr = run(t, "drill", pkg, "--into", filepath.Join(t.TempDir(), "never"), "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("drill human: code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stdout, "临时目录已删除") {
		t.Fatalf("dry run claims to have deleted a temp dir:\n%s", stdout)
	}
	if !strings.Contains(stdout, "未创建临时目录") {
		t.Fatalf("dry run does not say it created no temp dir:\n%s", stdout)
	}
}

func TestDrillWriteKeep(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}

	target := t.TempDir()
	code, stdout, stderr := run(t, "drill", pkg, "--into", target, "--write", "--keep", "--pubkey", pub, "--json")
	if code != exitOK {
		t.Fatalf("drill --write: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var sum struct {
		TempDir  string `json:"temp_dir"`
		Kept     bool   `json:"kept"`
		DryRun   bool   `json:"dry_run"`
		Restored int    `json:"restored"`
	}
	if err := json.Unmarshal([]byte(stdout), &sum); err != nil {
		t.Fatalf("drill JSON: %v (%q)", err, stdout)
	}
	t.Cleanup(func() { os.RemoveAll(sum.TempDir) })
	if !sum.Kept || sum.DryRun || sum.Restored == 0 {
		t.Fatalf("drill summary = %+v", sum)
	}
	if _, err := os.Stat(filepath.Join(sum.TempDir, "restore")); err != nil {
		t.Fatalf("--write did not land files in the temp dir: %v", err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("drill --write touched the user target: %v (err=%v)", entries, err)
	}
}

func TestDrillRefusesUnsignedWithoutFlag(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	target := t.TempDir()
	code, _, stderr := run(t, "drill", pkg, "--into", target)
	if code != exitPartial {
		t.Fatalf("drill unsigned: code=%d, want %d (stderr %q)", code, exitPartial, stderr)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("failed drill touched the user target: %v (err=%v)", entries, err)
	}
	if !strings.Contains(stderr, "下一步：") {
		t.Fatalf("drill failure lacks a next step: %q", stderr)
	}
}

// --- completion -------------------------------------------------------------

func TestCompletionScripts(t *testing.T) {
	cfgDir := isolateConfig(t)
	cases := map[string]string{
		"bash":       "complete -o bashdefault -o default -F _packout_completions packout",
		"zsh":        "compdef _packout packout",
		"fish":       "complete -c packout",
		"powershell": "Register-ArgumentCompleter -Native -CommandName packout",
	}
	for shell, marker := range cases {
		code, stdout, stderr := run(t, "completion", shell)
		if code != exitOK {
			t.Fatalf("completion %s: code=%d stderr=%q", shell, code, stderr)
		}
		if !strings.Contains(stdout, marker) {
			t.Errorf("completion %s lacks %q:\n%s", shell, marker, stdout)
		}
		for _, verb := range completionVerbNames() {
			if !strings.Contains(stdout, verb) {
				t.Errorf("completion %s lacks verb %q", shell, verb)
			}
		}
	}
	if code, _, _ := run(t, "completion", "tcsh"); code != exitUsage {
		t.Errorf("completion tcsh: code=%d, want %d", code, exitUsage)
	}
	if code, _, _ := run(t, "completion"); code != exitUsage {
		t.Errorf("completion without shell: code=%d, want %d", code, exitUsage)
	}
	// The scripts are static output; nothing is written.
	if _, err := os.Stat(cfgDir); !os.IsNotExist(err) {
		t.Fatalf("completion created %s", cfgDir)
	}
}

// --- errors carry a next step ----------------------------------------------

// assertOneJSONValue fails unless stdout holds exactly one parseable JSON value.
func assertOneJSONValue(t *testing.T, name, stdout string) {
	t.Helper()
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" || !json.Valid([]byte(trimmed)) {
		t.Fatalf("%s: stdout is not one JSON value: %q", name, stdout)
	}
	var one map[string]any
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		t.Fatalf("%s: stdout is not a single JSON object: %v (%q)", name, err, stdout)
	}
}

func TestJSONStdoutStaysOneValueWithHints(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)

	// A failed restore (non-empty target) with --json: one JSON value, hint
	// on stderr only.
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	into := t.TempDir()
	mustWrite(t, filepath.Join(into, "keep"), []byte("x"))
	code, stdout, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub, "--json")
	if code != exitNotEmpty {
		t.Fatalf("restore non-empty: code=%d stderr=%q", code, stderr)
	}
	assertOneJSONValue(t, "restore error", stdout)
	if !strings.Contains(stderr, "下一步：") {
		t.Errorf("restore error hint is not on stderr: %q", stderr)
	}

	// verify --json of an unsigned package: one JSON value, hint on stderr.
	unsignedPkg := filepath.Join(t.TempDir(), "unsigned")
	if code, _, stderr := packPackage(t, inst, unsignedPkg); code != exitOK {
		t.Fatalf("pack unsigned: code=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr = run(t, "verify", unsignedPkg, "--json")
	if code != exitPartial {
		t.Fatalf("verify unsigned: code=%d", code)
	}
	assertOneJSONValue(t, "verify", stdout)
	if !strings.Contains(stderr, "下一步：") {
		t.Errorf("verify hint is not on stderr: %q", stderr)
	}

	// drill --json failure: same contract.
	code, stdout, stderr = run(t, "drill", unsignedPkg, "--json")
	if code != exitPartial {
		t.Fatalf("drill unsigned: code=%d stderr=%q", code, stderr)
	}
	assertOneJSONValue(t, "drill", stdout)
	if !strings.Contains(stderr, "下一步：") {
		t.Errorf("drill hint is not on stderr: %q", stderr)
	}

	// --json usage errors keep the error object shape too.
	code, stdout, _ = run(t, "scan", "--json")
	if code != exitUsage {
		t.Fatalf("scan usage: code=%d", code)
	}
	assertOneJSONValue(t, "scan usage", stdout)
}

// TestOnlySuccessPathsWriteState pins the write matrix: read-only commands,
// dry runs and drills never touch state.json.
func TestOnlySuccessPathsWriteState(t *testing.T) {
	cfgDir := isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	stateFile := filepath.Join(cfgDir, "state.json")
	before, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("pack did not write state: %v", err)
	}

	check := func(name string, args ...string) {
		t.Helper()
		if code, _, stderr := run(t, args...); code != exitOK {
			t.Fatalf("%s: code=%d stderr=%q", name, code, stderr)
		}
		after, err := os.ReadFile(stateFile)
		if err != nil {
			t.Fatalf("%s: state disappeared: %v", name, err)
		}
		if string(before) != string(after) {
			t.Fatalf("%s rewrote state.json", name)
		}
	}
	check("status", "status")
	check("status --json", "status", "--json")
	check("help", "help")
	check("help --all", "help", "--all")
	check("completion", "completion", "bash")
	check("doctor", "doctor", "--quiet")
	check("mcp --help", "mcp", "--help")
	check("restore --dry-run", "restore", pkg, "--into", filepath.Join(t.TempDir(), "dry"), "--pubkey", pub, "--dry-run", "--quiet")
	check("drill", "drill", pkg, "--pubkey", pub, "--quiet")
	check("drill --write", "drill", pkg, "--pubkey", pub, "--write", "--quiet")

	// A failed command must not write either.
	out := t.TempDir()
	mustWrite(t, filepath.Join(out, "keep"), []byte("x"))
	if code, _, _ := run(t, append([]string{"pack", out}, rootArgs(inst)...)...); code != exitNotEmpty {
		t.Fatalf("pack non-empty: code=%d", code)
	}
	afterFail, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(afterFail) {
		t.Fatalf("failed pack rewrote state.json")
	}
}

func TestErrorsCarryNextStep(t *testing.T) {
	cfgDir := isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}

	// Restore into a non-empty target names the full --in-place --force command.
	into := t.TempDir()
	mustWrite(t, filepath.Join(into, "keep"), []byte("x"))
	code, _, stderr := run(t, "restore", pkg, "--into", into, "--pubkey", pub)
	if code != exitNotEmpty {
		t.Fatalf("restore non-empty: code=%d, want %d (stderr %q)", code, exitNotEmpty, stderr)
	}
	if !strings.Contains(stderr, "--in-place --force") {
		t.Fatalf("restore hint lacks --in-place --force: %q", stderr)
	}

	// verify of an unsigned package suggests signing or --allow-unverified.
	unsignedPkg := filepath.Join(t.TempDir(), "unsigned")
	if code, _, stderr := packPackage(t, inst, unsignedPkg); code != exitOK {
		t.Fatalf("pack unsigned: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run(t, "verify", unsignedPkg)
	if code != exitPartial {
		t.Fatalf("verify unsigned: code=%d", code)
	}
	if !strings.Contains(stderr, "下一步：") || (!strings.Contains(stderr, "--allow-unverified") && !strings.Contains(stderr, "packout sign")) {
		t.Fatalf("verify hint is not actionable: %q", stderr)
	}

	// A non-empty pack --out offers the forced command.
	code, _, stderr = run(t, append([]string{"pack", into}, rootArgs(inst)...)...)
	if code != exitNotEmpty {
		t.Fatalf("pack non-empty: code=%d", code)
	}
	if !strings.Contains(stderr, "packout pack "+into+" --force") {
		t.Fatalf("pack hint lacks the forced command: %q", stderr)
	}
	_ = cfgDir
}

// TestPackWithSessions pins the flag users type: it equals --preset full, is
// accepted with the same explicit preset, and contradicts any other preset.
func TestPackWithSessions(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	work := t.TempDir()

	pkg := filepath.Join(work, "pkg")
	if code, _, stderr := run(t, append([]string{"pack", pkg, "--with-sessions", "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("pack --with-sessions: code=%d stderr=%q", code, stderr)
	}
	session := filepath.Join(pkg, "config", "home", ".claude", "projects", "D--demo", "session-1.jsonl")
	if _, err := os.Stat(session); err != nil {
		t.Fatalf("--with-sessions did not carry the transcript: %v", err)
	}

	if code, _, stderr := run(t, append([]string{"pack", filepath.Join(work, "full"), "--with-sessions", "--preset", "full", "--quiet"}, rootArgs(inst)...)...); code != exitOK {
		t.Fatalf("--with-sessions with --preset full must be accepted: code=%d stderr=%q", code, stderr)
	}

	bad := filepath.Join(work, "bad")
	code, _, stderr := run(t, append([]string{"pack", bad, "--with-sessions", "--preset", "standard"}, rootArgs(inst)...)...)
	if code != exitUsage {
		t.Fatalf("--with-sessions --preset standard: code=%d, want %d (stderr %q)", code, exitUsage, stderr)
	}
	for _, want := range []string{"--with-sessions", "--preset full"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("conflict error lacks %q: %q", want, stderr)
		}
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("preset conflict wrote a package")
	}
}

// TestPackSingleSummary pins the one-line success output: no internal temp
// scan dir, no duplicate "包已写入", and duplicate-destination warnings are
// deduped by target and no longer name internal unit ids.
func TestPackSingleSummary(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	pkg := filepath.Join(t.TempDir(), "pkg")

	code, stdout, stderr := run(t, append([]string{"pack", pkg}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	if n := strings.Count(stdout, "包已写入"); n != 1 {
		t.Fatalf("pack printed %d package lines, want 1:\n%s", n, stdout)
	}
	if strings.Contains(stdout, ".packout-pack-") || strings.Contains(stdout, "清单已写入") {
		t.Fatalf("pack leaked its internal scan step:\n%s", stdout)
	}
	if !strings.Contains(stdout, "已扫描 ") || !strings.Contains(stdout, "（残留 ") {
		t.Fatalf("scan counts missing from pack output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "未签名）") && !strings.Contains(stdout, "已签名）") {
		t.Fatalf("package line lacks entry/byte/signature summary:\n%s", stdout)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	if lines > 5 {
		t.Fatalf("pack success printed %d lines, want a short summary:\n%s", lines, stdout)
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.Contains(line, "duplicate destination") {
			continue
		}
		if strings.Contains(line, "unit ") {
			t.Fatalf("duplicate warning exposes a unit id: %q", line)
		}
		if seen[line] {
			t.Fatalf("duplicate warning repeated: %q", line)
		}
		seen[line] = true
	}
}

// TestPackVerifyHintAfterInit checks that init's trust store makes the default
// verify hint sufficient; an explicit --key keeps the --pubkey hint.
func TestPackVerifyHintAfterInit(t *testing.T) {
	isolateConfig(t)
	old := initStdin
	initStdin = strings.NewReader("")
	defer func() { initStdin = old }()
	if code, _, stderr := run(t, "init", "--yes", "--quiet"); code != exitOK {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	inst := fixtureTree(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	code, stdout, stderr := run(t, append([]string{"pack", pkg, "--seal"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("pack --seal: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "校验：packout verify "+pkg+"\n") {
		t.Fatalf("default-key hint still asks for --pubkey:\n%s", stdout)
	}
	if strings.Contains(stdout, "校验：packout verify "+pkg+" --pubkey") {
		t.Fatalf("default-key hint still asks for --pubkey:\n%s", stdout)
	}

	priv, _ := newKey(t)
	pkg2 := filepath.Join(t.TempDir(), "pkg2")
	code, stdout, stderr = run(t, append([]string{"pack", pkg2, "--seal", "--key", priv}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("pack --seal --key: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "--pubkey") {
		t.Fatalf("explicit --key hint should name --pubkey:\n%s", stdout)
	}
}

// TestDrillTargetLineLabels pins the wording: a dry run says the target was
// not created; --write shows the real target.
func TestDrillTargetLineLabels(t *testing.T) {
	isolateConfig(t)
	inst := fixtureTree(t)
	priv, pub := newKey(t)
	pkg := filepath.Join(t.TempDir(), "pkg")
	if code, _, stderr := packPackage(t, inst, pkg, "--seal", "--key", priv); code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}

	code, stdout, stderr := run(t, "drill", pkg, "--into", t.TempDir(), "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("drill dry: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "演练目标（干跑未创建）: ") {
		t.Fatalf("dry-run target line not labelled:\n%s", stdout)
	}

	code, stdout, stderr = run(t, "drill", pkg, "--into", t.TempDir(), "--write", "--pubkey", pub)
	if code != exitOK {
		t.Fatalf("drill --write: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "演练目标: ") || strings.Contains(stdout, "干跑未创建）: ") {
		t.Fatalf("--write does not show the real target:\n%s", stdout)
	}
}

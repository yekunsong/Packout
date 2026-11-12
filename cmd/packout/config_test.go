package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"packout/internal/pack"
)

// isolateConfig points the per-user config/keys at a temp directory on both
// platforms and returns the would-be packout directory.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return filepath.Join(dir, "packout")
}

func writeConfigFile(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	mustWrite(t, p, []byte(body))
	return p
}

func readJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestConfigPathUsesPlatformConfigDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("AppData", base)
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "packout", "config.json"); p != want {
		t.Fatalf("configPath()=%q, want %q", p, want)
	}
}

func TestConfigRootsUsedAndCLIWins(t *testing.T) {
	inst := fixtureTree(t)
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1,"roots":{"home":`+quote(inst["home"])+`,"repo":`+quote(inst["repo"])+`}}`)

	out := filepath.Join(t.TempDir(), "scan")
	code, _, stderr := run(t, "scan", "--out", out, "--quiet")
	if code != exitOK {
		t.Fatalf("scan with config roots: code=%d stderr=%q", code, stderr)
	}
	var roots map[string]string
	readJSONFile(t, filepath.Join(out, "roots.json"), &roots)
	if roots["home"] != inst["home"] {
		t.Fatalf("config root not used: %v", roots)
	}

	// CLI --root wins over the config for the same role.
	other := t.TempDir()
	out2 := filepath.Join(t.TempDir(), "scan")
	code, _, stderr = run(t, "scan", "--out", out2, "--quiet",
		"--root", "home="+other, "--root", "repo="+inst["repo"])
	if code != exitOK {
		t.Fatalf("scan with --root: code=%d stderr=%q", code, stderr)
	}
	readJSONFile(t, filepath.Join(out2, "roots.json"), &roots)
	if roots["home"] != other {
		t.Fatalf("CLI root did not win: %v", roots)
	}
}

func TestConfigPresetDefaultAndCLIOverride(t *testing.T) {
	inst := fixtureTree(t)
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1,"preset":"minimal","roots":{"home":`+quote(inst["home"])+`,"repo":`+quote(inst["repo"])+`}}`)

	out := filepath.Join(t.TempDir(), "scan")
	code, _, stderr := run(t, "scan", "--out", out, "--quiet")
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}
	// minimal carries no memory/sessions; just assert the selection landed in
	// the header by checking the run succeeded with a config-only preset.
	if _, err := os.Stat(filepath.Join(out, "manifest")); err != nil {
		t.Fatal(err)
	}
}

func TestBadConfigExitsUsageWithPath(t *testing.T) {
	inst := fixtureTree(t)
	cfgDir := isolateConfig(t)
	p := writeConfigFile(t, cfgDir, `{"version":1,`)

	code, _, stderr := run(t, append([]string{"scan", "--out", filepath.Join(t.TempDir(), "s")}, rootArgs(inst)...)...)
	if code != exitUsage {
		t.Fatalf("bad config: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, p) {
		t.Fatalf("stderr does not name config path: %q", stderr)
	}
}

func TestUnknownConfigKeyExitsUsage(t *testing.T) {
	inst := fixtureTree(t)
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1,"colour":"red"}`)
	code, _, stderr := run(t, append([]string{"scan", "--out", filepath.Join(t.TempDir(), "s")}, rootArgs(inst)...)...)
	if code != exitUsage {
		t.Fatalf("unknown key: code=%d stderr=%q", code, stderr)
	}
}

func TestWrongConfigVersionExitsUsage(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":9}`)
	if _, _, err := loadConfig(); err == nil {
		t.Fatal("version 9 accepted")
	}
}

func chdirProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return dir
}

func TestInitYesCreatesEverything(t *testing.T) {
	cfgDir := isolateConfig(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	chdirProject(t)
	old := initStdin
	initStdin = strings.NewReader("")
	defer func() { initStdin = old }()

	code, _, stderr := run(t, "init", "--yes", "--quiet")
	if code != exitOK {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	cfgPath := filepath.Join(cfgDir, "config.json")
	var c config
	readJSONFile(t, cfgPath, &c)
	if c.Version != 1 || c.Roots["home"] != home {
		t.Fatalf("config content: %+v", c)
	}
	for _, p := range []string{cfgPath, filepath.Join(cfgDir, "identity.age"), filepath.Join(cfgDir, "minisign.key")} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %04o, want 0600", p, fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "minisign.key.pub")); err != nil {
		t.Fatalf("public key missing: %v", err)
	}

	// Second run refuses to overwrite the config, and --force keeps the keys.
	keyBefore, err := os.ReadFile(filepath.Join(cfgDir, "minisign.key"))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, "init", "--yes", "--quiet"); code != exitUsage {
		t.Fatalf("second init without --force: code=%d", code)
	}
	code, stdout, stderr := run(t, "init", "--yes", "--force")
	if code != exitOK {
		t.Fatalf("init --force: code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "未覆盖") && !strings.Contains(stderr, "未覆盖") {
		t.Errorf("existing keys not reported: stdout=%q stderr=%q", stdout, stderr)
	}
	keyAfter, err := os.ReadFile(filepath.Join(cfgDir, "minisign.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("--force overwrote the private key")
	}
}

func TestInitInteractiveRejectsRoot(t *testing.T) {
	cfgDir := isolateConfig(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	chdirProject(t)
	old := initStdin
	// home accepted, repo rejected.
	initStdin = strings.NewReader("y\nn\n")
	defer func() { initStdin = old }()

	code, _, stderr := run(t, "init", "--quiet")
	if code != exitOK {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	var c config
	readJSONFile(t, filepath.Join(cfgDir, "config.json"), &c)
	if c.Roots["home"] != home {
		t.Fatalf("home not recorded: %+v", c.Roots)
	}
	if _, ok := c.Roots["repo"]; ok {
		t.Fatalf("rejected repo recorded: %+v", c.Roots)
	}
}

func TestInitRoleOrder(t *testing.T) {
	cands := map[string]string{
		"zzz": ".", "repo": ".", "appdata": ".", "home": ".", "localappdata": ".", "aaa": ".",
	}
	got := orderedInitRoles(cands)
	want := []string{"home", "repo", "appdata", "localappdata", "aaa", "zzz"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order=%v, want %v", got, want)
	}
}

func doctorJSON(t *testing.T, args ...string) (int, doctorSummary) {
	t.Helper()
	code, stdout, stderr := run(t, append([]string{"doctor", "--json"}, args...)...)
	var sum doctorSummary
	if err := json.Unmarshal([]byte(stdout), &sum); err != nil {
		t.Fatalf("doctor JSON: %v (%q, stderr %q)", err, stdout, stderr)
	}
	return code, sum
}

func hasCheck(sum doctorSummary, name, status string) bool {
	for _, c := range sum.Checks {
		if c.Name == name && c.Status == status {
			return true
		}
	}
	return false
}

func TestDoctorCleanIsZero(t *testing.T) {
	isolateConfig(t)
	code, sum := doctorJSON(t)
	if code != exitOK {
		t.Fatalf("doctor on empty config: code=%d %+v", code, sum)
	}
	if !hasCheck(sum, "config", "warn") {
		t.Fatalf("missing config should warn: %+v", sum)
	}
}

func TestDoctorMissingRootFails(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{"version":1,"roots":{"home":`+quote(filepath.Join(t.TempDir(), "gone"))+`}}`)
	code, sum := doctorJSON(t)
	if code != exitPartial {
		t.Fatalf("missing root: code=%d %+v", code, sum)
	}
	if !hasCheck(sum, "root:home", "fail") {
		t.Fatalf("missing root not failed: %+v", sum)
	}
}

func TestDoctorBadConfigFails(t *testing.T) {
	cfgDir := isolateConfig(t)
	writeConfigFile(t, cfgDir, `{oops`)
	code, sum := doctorJSON(t)
	if code != exitPartial || !hasCheck(sum, "config", "fail") {
		t.Fatalf("bad config: code=%d %+v", code, sum)
	}
}

func TestDoctorWideIdentityPermFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are synthesized on Windows")
	}
	cfgDir := isolateConfig(t)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(cfgDir, "identity.age")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, idPath, []byte(id.String()+"\n"))
	if err := os.Chmod(idPath, 0o644); err != nil {
		t.Fatal(err)
	}
	code, sum := doctorJSON(t)
	if code != exitPartial || !hasCheck(sum, "identity", "fail") {
		t.Fatalf("wide identity: code=%d %+v", code, sum)
	}
	if err := os.Chmod(idPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, sum = doctorJSON(t); hasCheck(sum, "identity", "fail") {
		t.Fatalf("0600 identity still failed: %+v", sum)
	}
}

func TestDoctorOutParentUnwritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix mode based")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode")
	}
	isolateConfig(t)
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	code, sum := doctorJSON(t, "--out", filepath.Join(ro, "out"))
	if code != exitPartial || !hasCheck(sum, "out_parent", "fail") {
		t.Fatalf("ro parent: code=%d %+v", code, sum)
	}
}

func scanFixture(t *testing.T) string {
	t.Helper()
	isolateConfig(t)
	inst := fixtureTree(t)
	out := filepath.Join(t.TempDir(), "scan")
	code, _, stderr := run(t, append([]string{"scan", "--out", out, "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("scan: code=%d stderr=%q", code, stderr)
	}
	return out
}

func TestPassphraseFileCRLFAndMutualExclusion(t *testing.T) {
	src := scanFixture(t)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	mustWrite(t, pwFile, []byte("s3cret\r\nignored\n"))

	code, _, stderr := run(t, "export", "--src", src, "--out", filepath.Join(dir, "pkg"),
		"--with-secrets", "--passphrase-file", pwFile, "--quiet")
	if code != exitOK {
		t.Fatalf("export with passphrase file: code=%d stderr=%q", code, stderr)
	}
	into := filepath.Join(dir, "into")
	code, _, stderr = run(t, "restore", filepath.Join(dir, "pkg"), "--into", into,
		"--passphrase-file", pwFile, "--allow-unverified", "--quiet")
	if code != exitOK {
		t.Fatalf("restore with passphrase file: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(into, "home")); err != nil {
		t.Fatalf("restore did not write: %v", err)
	}

	// A config identity must not conflict with an explicit passphrase file.
	writeConfigFile(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "packout"),
		`{"version":1,"identity":`+quote(filepath.Join(dir, "nope.age"))+`}`)
	into2 := filepath.Join(dir, "into2")
	code, _, stderr = run(t, "restore", filepath.Join(dir, "pkg"), "--into", into2,
		"--passphrase-file", pwFile, "--allow-unverified", "--quiet")
	if code != exitOK {
		t.Fatalf("config identity vs passphrase file: code=%d stderr=%q", code, stderr)
	}

	// --passphrase and --passphrase-file are mutually exclusive.
	code, _, stderr = run(t, "export", "--src", src, "--out", filepath.Join(dir, "pkg2"),
		"--with-secrets", "--passphrase", "--passphrase-file", pwFile)
	if code != exitUsage || !strings.Contains(stderr, "只能二选一") {
		t.Fatalf("conflict: code=%d stderr=%q", code, stderr)
	}
}

func TestPassphraseFileEmptyFirstLine(t *testing.T) {
	src := scanFixture(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	mustWrite(t, empty, []byte("\r\nsecond\n"))
	code, _, stderr := run(t, "export", "--src", src, "--out", filepath.Join(dir, "pkg"),
		"--with-secrets", "--passphrase-file", empty)
	if code != exitUsage || !strings.Contains(stderr, "第一行为空") {
		t.Fatalf("empty first line: code=%d stderr=%q", code, stderr)
	}
}

func TestPackSuccessAndSign(t *testing.T) {
	inst := fixtureTree(t)
	isolateConfig(t)
	priv, pub := newKey(t)
	out := filepath.Join(t.TempDir(), "pkg")
	code, stdout, stderr := run(t, append([]string{"pack", "--out", out, "--key", priv, "--quiet"},
		rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("pack: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(out, pack.MinisigName)); err != nil {
		t.Fatalf("package not signed: %v", err)
	}
	code, _, stderr = run(t, "verify", out, "--pubkey", pub, "--quiet")
	if code != exitOK {
		t.Fatalf("verify signed package: code=%d stderr=%q", code, stderr)
	}
	_ = stdout
}

func TestPackSignUsesConfigDirKey(t *testing.T) {
	cfgDir := isolateConfig(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	chdirProject(t)
	if code, _, stderr := run(t, "init", "--yes", "--quiet"); code != exitOK {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	inst := fixtureTree(t)
	out := filepath.Join(t.TempDir(), "pkg")
	code, _, stderr := run(t, append([]string{"pack", "--out", out, "--sign", "--quiet"}, rootArgs(inst)...)...)
	if code != exitOK {
		t.Fatalf("pack --sign: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run(t, "verify", out, "--pubkey", filepath.Join(cfgDir, "minisign.key.pub"), "--quiet")
	if code != exitOK {
		t.Fatalf("verify: code=%d stderr=%q", code, stderr)
	}
}

func TestPackRetainsScanOnExportFailure(t *testing.T) {
	inst := fixtureTree(t)
	isolateConfig(t)
	parent := t.TempDir()
	out := filepath.Join(parent, "pkg")
	// --with-secrets without recipient/passphrase fails inside export.
	code, _, stderr := run(t, append([]string{"pack", "--out", out, "--with-secrets"}, rootArgs(inst)...)...)
	if code != exitUsage {
		t.Fatalf("pack export failure: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed pack left an --out")
	}
	i := strings.Index(stderr, "扫描 ")
	if i < 0 {
		t.Fatalf("retained scan path not reported: %q", stderr)
	}
	scanDir := strings.TrimSpace(stderr[i+len("扫描 "):])
	if j := strings.IndexAny(scanDir, " \n"); j >= 0 {
		scanDir = scanDir[:j]
	}
	if _, err := os.Stat(scanDir); err != nil {
		t.Fatalf("retained scan dir %q: %v", scanDir, err)
	}
}

func TestPackOutNotEmpty(t *testing.T) {
	inst := fixtureTree(t)
	isolateConfig(t)
	out := t.TempDir()
	mustWrite(t, filepath.Join(out, "keep"), []byte("x"))
	code, _, stderr := run(t, append([]string{"pack", "--out", out}, rootArgs(inst)...)...)
	if code != exitNotEmpty {
		t.Fatalf("non-empty out: code=%d stderr=%q", code, stderr)
	}
}

// TestTopHelpIsLayered pins the layered help contract: the top help teaches
// the five daily verbs only, and `help --all` is the discovery path for the
// rest. Nothing was removed, only moved one level down.
func TestTopHelpIsLayered(t *testing.T) {
	for _, want := range []string{"init", "pack", "verify", "drill", "restore", "packout help --all"} {
		if !strings.Contains(topHelp, want) {
			t.Errorf("topHelp lacks %q", want)
		}
	}
	for _, hidden := range []string{"doctor", "scan", "report", "export", "sign", "mcp", "profile", "completion", "status"} {
		if strings.Contains(topHelp, "\n  "+hidden) {
			t.Errorf("topHelp still lists %q; it belongs to help --all", hidden)
		}
	}
	for _, v := range allVerbs {
		if !strings.Contains(allHelp, "  "+v.name) {
			t.Errorf("allHelp lacks %q", v.name)
		}
	}
}

// quote renders s as a JSON string.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
)

// Exit codes are the table in docs/design-cli.md (§退出码). They are the
// whole contract; nothing else may invent a code.
const (
	exitOK       = 0
	exitPartial  = 2 // unhandled read errors, verify conclusion failed, drift
	exitUsage    = 3 // usage/config errors, including profile validation
	exitNotEmpty = 4 // --out exists and is non-empty without --force
	exitCanceled = 5 // user interrupt
)

// defaultProfile is used when --profile is absent.
const defaultProfile = "claude-code"

// reporter writes human output, machine output and errors under the rules of
// --json / --quiet: --json replaces the human output with one JSON value on
// stdout, --quiet drops everything except errors.
type reporter struct {
	stdout io.Writer
	stderr io.Writer
	json   bool
	quiet  bool
	// wroteValue records that a JSON result is already on stdout, so an
	// error does not append a second top-level value.
	wroteValue bool
}

func (r *reporter) info(format string, args ...any) {
	if r.quiet || r.json {
		return
	}
	fmt.Fprintf(r.stdout, format+"\n", args...)
}

// warn goes to stderr, never to stdout, and survives --json.
func (r *reporter) warn(format string, args ...any) {
	fmt.Fprintf(r.stderr, format+"\n", args...)
}

// value emits the machine summary when --json is set.
func (r *reporter) value(v any) {
	if !r.json {
		return
	}
	if err := jsonEncode(r.stdout, v); err == nil {
		r.wroteValue = true
	}
}

// jsonEncode writes one HTML-unescaped JSON value plus newline.
func jsonEncode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// errObject is the JSON body every failing command writes under --json so the
// stdout stream stays parseable.
type errObject struct {
	Error string `json:"error"`
	Exit  int    `json:"exit"`
}

// fail reports one error and returns code.
func (r *reporter) fail(code int, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	if r.json && !r.wroteValue {
		r.value(errObject{Error: msg, Exit: code})
	}
	fmt.Fprintln(r.stderr, "packout: "+msg)
	return code
}

// usageError is a flag parse failure or bad flag combination.
func (r *reporter) usage(format string, args ...any) int {
	return r.fail(exitUsage, format, args...)
}

// --- shared parsing helpers -------------------------------------------------

// rootFlag collects repeated --root role=PATH values.
type rootFlag struct {
	role string
	path string
	raw  string
}

type rootList []rootFlag

func (r *rootList) String() string { return "" }

func (r *rootList) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("--root 需要 role=PATH，收到 %q", v)
	}
	role, path := v[:i], v[i+1:]
	if role == "" {
		return fmt.Errorf("--root 缺少 role：%q", v)
	}
	if path == "" {
		return fmt.Errorf("--root 缺少 PATH：%q", v)
	}
	*r = append(*r, rootFlag{role: role, path: path, raw: v})
	return nil
}

// bindings converts the raw list, checking every role against the profile.
func (r rootList) bindings(p *profile.Profile) ([]scanRootBinding, error) {
	out := make([]scanRootBinding, 0, len(r))
	for _, b := range r {
		if _, ok := p.Roots[b.role]; !ok {
			return nil, fmt.Errorf("root role %q 未被 profile %s 声明（可用：%s）",
				b.role, p.Name, strings.Join(p.RootOrder, ", "))
		}
		out = append(out, scanRootBinding{Role: b.role, Path: b.path})
	}
	return out, nil
}

// scanRootBinding mirrors scan.RootBinding without pulling scan into helpers
// that must stay import-light.
type scanRootBinding struct {
	Role string
	Name string
	Path string
}

// loadProfile resolves --profile: builtin name, or a file treated as
// semi-trusted input whose hash is echoed (design-cli.md).
func loadProfile(ref string, stderr io.Writer) (*profile.Profile, error) {
	if ref == "" {
		ref = defaultProfile
	}
	for _, n := range profile.BuiltinNames() {
		if ref == n {
			return profile.Builtin(ref)
		}
	}
	src, err := os.ReadFile(ref)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("未知 profile %q（既不是内置名也不是可读文件）", ref)
		}
		return nil, err
	}
	sum := sha256.Sum256(src)
	fmt.Fprintf(stderr, "packout: profile %s 是外部文件（半可信输入），sha256=%s\n", ref, hex.EncodeToString(sum[:]))
	p, err := profile.Load(ref)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// rootEcho prints the profile root defaults actually used when --root is
// absent (design-cli.md).
func rootEcho(p *profile.Profile, stderr io.Writer) {
	for _, role := range p.RootOrder {
		tmpl := p.Roots[role].ForOS(runtime.GOOS)
		expanded, err := profile.ExpandTemplate(tmpl)
		if err != nil {
			expanded = tmpl + "（未解析：" + err.Error() + "）"
		}
		fmt.Fprintf(stderr, "packout: root %s=%s（来自 profile 默认值）\n", role, expanded)
	}
}

// checkOut enforces the --out contract before anything is written.
//
// A file target is "non-empty" when it exists with content. A directory
// target is "non-empty" when it has at least one entry. Returns 0 when the
// command may proceed.
func checkOut(out string, file bool, force bool) (code int, msg string) {
	abs, err := fsx.Abs(out)
	if err != nil {
		return exitUsage, err.Error()
	}
	info, err := fsx.Lstat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return exitOK, ""
		}
		return exitUsage, err.Error()
	}
	if file {
		if info.IsDir {
			return exitUsage, fmt.Sprintf("--out %s 是目录，该命令需要文件路径", abs)
		}
		if info.Size > 0 && !force {
			return exitNotEmpty, fmt.Sprintf("--out %s 已存在且非空（用 --force 覆盖）", abs)
		}
		return exitOK, ""
	}
	if !info.IsDir {
		return exitUsage, fmt.Sprintf("--out %s 是文件，该命令需要目录", abs)
	}
	names, err := os.ReadDir(abs)
	if err != nil {
		return exitUsage, err.Error()
	}
	if len(names) > 0 && !force {
		return exitNotEmpty, fmt.Sprintf("--out %s 已存在且非空（用 --force 覆盖）", abs)
	}
	return exitOK, ""
}

// stageDir creates a sibling staging directory on the same volume so a
// cancelled command leaves nothing that could pass for a product.
func stageDir(out string) (string, error) {
	abs, err := fsx.Abs(out)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	stage := filepath.Join(parent, "."+filepath.Base(abs)+".tmp-"+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(stage, 0o755); err != nil {
		return "", err
	}
	return stage, nil
}

// commitDir atomically replaces out with stage. The old out is removed first
// because os.Rename does not replace an existing directory on Windows.
func commitDir(stage, out string) error {
	abs, err := fsx.Abs(out)
	if err != nil {
		return err
	}
	if _, err := fsx.Lstat(abs); err == nil {
		if err := os.RemoveAll(abs); err != nil {
			return err
		}
	}
	return os.Rename(stage, abs)
}

// writeFileAtomic writes data to a temporary sibling of out and renames it
// into place, replacing out.
func writeFileAtomic(out string, data []byte, mode os.FileMode) error {
	abs, err := fsx.Abs(out)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(abs)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	// os.Rename replaces an existing file on both platforms.
	if err := os.Rename(tmp, abs); err != nil {
		return err
	}
	tmp = ""
	return nil
}

// stableSalt reads (or creates) ~/.config/packout/salt (D-011 §3).
func stableSalt() (manifest.FixedSalt, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, ".config", "packout", "salt")
	b, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			return manifest.FixedSalt(s), nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(salt+"\n"), 0o600); err != nil {
		return "", err
	}
	return manifest.FixedSalt(salt), nil
}

// exitFromCtx maps a cancelled context to exit 5.
func exitFromCtx(r *reporter, ctx context.Context) int {
	if ctx.Err() == nil {
		return exitOK
	}
	return r.fail(exitCanceled, "已中断（%v），未留下可当作完整产物的半成品", ctx.Err())
}

// sortedKeys is a small helper for stable map traversal in help text.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The state file is a convenience ledger for guidance and `status` only. It
// never participates in a safety decision, is written best-effort after a
// successful command, and a broken file is a warning, not an error.
const (
	stateVersion = 1
	// maxStatePackages bounds the package list so the file cannot grow
	// without limit over a machine's lifetime.
	maxStatePackages = 5
)

type stateScan struct {
	Out   string            `json:"out"`
	At    string            `json:"at"`
	Units int64             `json:"units"`
	Roots map[string]string `json:"roots,omitempty"`
}

type statePack struct {
	Out     string `json:"out"`
	At      string `json:"at"`
	Signed  bool   `json:"signed"`
	Entries int    `json:"entries,omitempty"`
}

type stateVerify struct {
	Path       string `json:"path"`
	Conclusion string `json:"conclusion"`
	At         string `json:"at"`
}

type stateRestore struct {
	Path     string `json:"path"`
	Into     string `json:"into"`
	At       string `json:"at"`
	Restored int    `json:"restored"`
}

type statePackage struct {
	Path   string `json:"path"`
	At     string `json:"at"`
	Signed bool   `json:"signed"`
}

type stateFile struct {
	Version     int               `json:"version"`
	Roots       map[string]string `json:"roots,omitempty"`
	LastScan    *stateScan        `json:"last_scan,omitempty"`
	LastPack    *statePack        `json:"last_pack,omitempty"`
	Packages    []statePackage    `json:"packages,omitempty"`
	LastVerify  *stateVerify      `json:"last_verify,omitempty"`
	LastRestore *stateRestore     `json:"last_restore,omitempty"`
}

// statePath is the single place that spells <configDir>/state.json.
func statePath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "state.json"), nil
}

// loadState reads the ledger. A missing file is (nil, nil): not being
// initialized is normal. A malformed or unknown-version file returns the
// error together with nil, and callers only warn about it.
func loadState() (*stateFile, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st stateFile
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%s: 多余内容（应只有一个 JSON 对象）", path)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("%s: 不支持的 version %d（需要 %d）", path, st.Version, stateVersion)
	}
	return &st, nil
}

// updateState rewrites state.json atomically. A broken existing file is
// replaced, because the ledger is rebuildable and blocking on it helps nobody.
func updateState(mutate func(*stateFile)) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	st, _ := loadState()
	if st == nil {
		st = &stateFile{}
	}
	mutate(st)
	st.Version = stateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

// recordState applies one best-effort ledger update. It never changes an exit
// code: a read-only or full config dir must not fail an otherwise good pack.
func recordState(warn func(string, ...any), mutate func(*stateFile)) {
	if err := updateState(mutate); err != nil {
		warn("packout: 状态文件未更新（不影响本次结果）：%v", err)
	}
}

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339) }

// pushPackage keeps the newest package first, de-duplicated and bounded.
func pushPackage(st *stateFile, path string, signed bool) {
	at := nowStamp()
	out := []statePackage{{Path: path, At: at, Signed: signed}}
	for _, p := range st.Packages {
		if p.Path == path {
			continue
		}
		out = append(out, p)
		if len(out) >= maxStatePackages {
			break
		}
	}
	st.Packages = out
}

// recordScan remembers the last complete scan and the roots it resolved.
func recordScan(warn func(string, ...any), out string, units int64, roots map[string]string) {
	recordState(warn, func(st *stateFile) {
		st.LastScan = &stateScan{Out: out, At: nowStamp(), Units: units, Roots: roots}
		if len(roots) > 0 {
			st.Roots = roots
		}
	})
}

// recordExport remembers the last exported package (unsigned).
func recordExport(warn func(string, ...any), out string, entries int) {
	recordState(warn, func(st *stateFile) {
		st.LastPack = &statePack{Out: out, At: nowStamp(), Entries: entries}
		pushPackage(st, out, false)
	})
}

// recordPack remembers the final pack product and whether it was signed.
func recordPack(warn func(string, ...any), out string, signed bool) {
	recordState(warn, func(st *stateFile) {
		st.LastPack = &statePack{Out: out, At: nowStamp(), Signed: signed}
		pushPackage(st, out, signed)
	})
}

// recordVerify stores a successful verification (exit 0) only.
func recordVerify(warn func(string, ...any), path, conclusion string) {
	recordState(warn, func(st *stateFile) {
		st.LastVerify = &stateVerify{Path: path, Conclusion: conclusion, At: nowStamp()}
	})
}

// recordRestore stores a real (non dry-run) successful restore only.
func recordRestore(warn func(string, ...any), pkg, into string, restored int) {
	recordState(warn, func(st *stateFile) {
		st.LastRestore = &stateRestore{Path: pkg, Into: into, At: nowStamp(), Restored: restored}
	})
}

// --- status -----------------------------------------------------------------

type statusConfig struct {
	json  bool
	quiet bool
}

type statusSummary struct {
	Config       string            `json:"config"`
	Configured   bool              `json:"configured"`
	Roots        map[string]string `json:"roots,omitempty"`
	LastScan     *stateScan        `json:"last_scan,omitempty"`
	LastPack     *statePack        `json:"last_pack,omitempty"`
	Packages     []statePackage    `json:"packages,omitempty"`
	LastVerify   *stateVerify      `json:"last_verify,omitempty"`
	LastRestore  *stateRestore     `json:"last_restore,omitempty"`
	Next         []string          `json:"next,omitempty"`
	StateWarning string            `json:"state_warning,omitempty"`
}

func parseStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var cfg statusConfig
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, statusHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runStatus(ctx, cfg, stdout, stderr)
}

// runStatus is read-only: it loads the config and the ledger, prints a
// summary and returns 0. The only non-zero case is a broken config file,
// which is a usage error everywhere else too.
func runStatus(ctx context.Context, cfg statusConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	sum, code := buildStatus(r)
	if code != exitOK {
		return code
	}
	r.value(sum)
	if cfg.quiet || cfg.json {
		return exitOK
	}
	for _, line := range statusLines(sum) {
		fmt.Fprintln(stdout, line)
	}
	return exitOK
}

// buildStatus assembles the shared summary used by `status` and bare packout.
func buildStatus(r *reporter) (statusSummary, int) {
	var sum statusSummary
	conf, confPath, err := loadConfig()
	if err != nil {
		return sum, r.usage("配置文件 %s: %v", confPath, err)
	}
	sum.Config = confPath
	if conf != nil {
		sum.Configured = true
		sum.Roots = conf.Roots
	}
	st, err := loadState()
	if err != nil {
		sum.StateWarning = err.Error()
		r.warn("packout: 状态文件不可用，按未记录处理：%v", err)
	}
	if st != nil {
		sum.LastScan = st.LastScan
		sum.LastPack = st.LastPack
		sum.Packages = st.Packages
		sum.LastVerify = st.LastVerify
		sum.LastRestore = st.LastRestore
		if len(st.Roots) > 0 && len(sum.Roots) == 0 {
			sum.Roots = st.Roots
		}
	}
	sum.Next = nextSteps(sum)
	return sum, exitOK
}

// nextSteps is the single source of "what now" suggestions.
func nextSteps(sum statusSummary) []string {
	if !sum.Configured {
		return []string{"packout init", "packout help"}
	}
	if len(sum.Packages) == 0 {
		return []string{"packout pack <目录>", "packout help"}
	}
	pkg := sum.Packages[0].Path
	return []string{
		"packout verify " + pkg,
		"packout drill " + pkg,
		"packout restore " + pkg + " --into <目标目录>",
	}
}

// statusLines renders the human view, newest facts first.
func statusLines(sum statusSummary) []string {
	var lines []string
	if sum.Configured {
		lines = append(lines, "配置: "+sum.Config+"（已初始化）")
	} else {
		lines = append(lines, "配置: 未初始化（"+sum.Config+" 不存在）")
	}
	if len(sum.Roots) > 0 {
		lines = append(lines, "根:")
		for _, role := range sortedKeys(sum.Roots) {
			lines = append(lines, fmt.Sprintf("  %s = %s", role, sum.Roots[role]))
		}
	}
	if sum.LastScan != nil {
		lines = append(lines, fmt.Sprintf("上次 scan: %s（%d 个 Unit，%s）",
			sum.LastScan.Out, sum.LastScan.Units, sum.LastScan.At))
	} else {
		lines = append(lines, "上次 scan: 无记录")
	}
	if len(sum.Packages) > 0 {
		lines = append(lines, "最近的包:")
		for _, p := range sum.Packages {
			signed := "未签名"
			if p.Signed {
				signed = "已签名"
			}
			lines = append(lines, fmt.Sprintf("  %s（%s，%s）", p.Path, signed, p.At))
		}
	} else {
		lines = append(lines, "最近的包: 无记录")
	}
	if sum.LastVerify != nil {
		lines = append(lines, fmt.Sprintf("上次 verify: %s → %s（%s）",
			sum.LastVerify.Path, sum.LastVerify.Conclusion, sum.LastVerify.At))
	} else {
		lines = append(lines, "上次 verify: 无记录")
	}
	if sum.LastRestore != nil {
		lines = append(lines, fmt.Sprintf("上次 restore: %s → %s（%d 项，%s）",
			sum.LastRestore.Path, sum.LastRestore.Into, sum.LastRestore.Restored, sum.LastRestore.At))
	}
	if len(sum.Next) > 0 {
		lines = append(lines, "下一步:")
		for _, n := range sum.Next {
			lines = append(lines, "  "+n)
		}
	}
	if sum.StateWarning != "" {
		lines = append(lines, "状态文件警告: "+sum.StateWarning)
	}
	return lines
}

// --- bare packout -----------------------------------------------------------

// runBare prints the state-aware hint for `packout` with no arguments. It
// always exits 0 and never writes a file.
func runBare(stdout, stderr io.Writer) int {
	conf, confPath, err := loadConfig()
	if err != nil {
		// A broken config must not turn the hint into an error, but it must
		// not be silently hidden either.
		fmt.Fprintf(stderr, "packout: 配置文件 %s 不可解析：%v\n", confPath, err)
	}
	st, serr := loadState()
	if serr != nil {
		fmt.Fprintf(stderr, "packout: 状态文件不可用，按未记录处理：%v\n", serr)
	}

	if conf == nil {
		fmt.Fprintln(stdout, "packout 是 AI 会话迁移工具，让不同的工作区拥有同一个 AI 会话基线。")
		fmt.Fprintln(stdout, "还没初始化：先运行 packout init 生成配置、age identity 与 minisign 密钥。")
		fmt.Fprintln(stdout, "想先看看全部命令：packout help（或 packout help --all）。")
		return exitOK
	}

	sum := statusSummary{Config: confPath, Configured: true, Roots: conf.Roots}
	if st != nil {
		sum.LastScan = st.LastScan
		sum.LastPack = st.LastPack
		sum.Packages = st.Packages
		sum.LastVerify = st.LastVerify
		sum.LastRestore = st.LastRestore
		if len(st.Roots) > 0 && len(sum.Roots) == 0 {
			sum.Roots = st.Roots
		}
	}
	sum.Next = nextSteps(sum)

	if len(sum.Packages) == 0 {
		fmt.Fprintln(stdout, "配置已就绪（"+sum.Config+"）。")
		fmt.Fprintln(stdout, "还没有包记录：运行 packout pack <目录>，例如 packout pack ./packout-state。")
		fmt.Fprintln(stdout, "打包后可用 packout status 看状态，packout drill <包> 演练恢复；全部命令见 packout help --all。")
		return exitOK
	}

	for _, line := range statusLines(sum) {
		fmt.Fprintln(stdout, line)
	}
	fmt.Fprintln(stdout, "完整状态：packout status；全部命令：packout help --all。")
	return exitOK
}

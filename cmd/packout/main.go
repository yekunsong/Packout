// Command packout is the CLI shell of docs/design-cli.md. It only parses
// arguments and wires packages together; every decision lives in internal/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	os.Exit(mainWithArgs(os.Args[1:], os.Stdout, os.Stderr))
}

// mainWithArgs is the testable entry point. Commands receive an injectable
// context; cancelling it is the user-interrupt path (exit 5).
func mainWithArgs(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		// Bare packout is a state-aware hint, never an error: it writes
		// nothing and always exits 0 (docs/design-cli.md).
		return runBare(stdout, stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "-help", "--help":
		return runHelp(cmd, rest, stdout, stderr)
	case "scan":
		return parseScan(ctx, rest, stdout, stderr)
	case "report":
		return parseReport(ctx, rest, stdout, stderr)
	case "export":
		return parseExport(ctx, rest, stdout, stderr)
	case "verify":
		return parseVerify(ctx, rest, stdout, stderr)
	case "sign":
		return parseSign(ctx, rest, stdout, stderr)
	case "restore":
		return parseRestore(ctx, rest, stdout, stderr)
	case "mcp":
		return parseMCP(ctx, rest, stdout, stderr)
	case "profile":
		return parseProfile(ctx, rest, stdout, stderr)
	case "init":
		return parseInit(ctx, rest, stdout, stderr)
	case "doctor":
		return parseDoctor(ctx, rest, stdout, stderr)
	case "pack":
		return parsePack(ctx, rest, stdout, stderr)
	case "status":
		return parseStatus(ctx, rest, stdout, stderr)
	case "drill":
		return parseDrill(ctx, rest, stdout, stderr)
	case "completion":
		return parseCompletion(ctx, rest, stdout, stderr)
	case "version":
		return parseVersion(ctx, rest, stdout, stderr)
	default:
		msg := fmt.Sprintf("未知命令 %q", cmd)
		if wantsJSON(rest) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		fmt.Fprint(stderr, topHelp)
		fmt.Fprint(stderr, "下一步：packout help --all 查看全部命令\n")
		return exitUsage
	}
}

// runHelp routes `packout help`, `packout help <cmd>` and `packout help --all`.
// `<cmd> -h` goes through parse() and prints the very same text, so the two
// spellings cannot drift apart.
func runHelp(invoked string, rest []string, stdout, stderr io.Writer) int {
	if invoked != "help" {
		// -h / --help always mean the top-level help, as before.
		fmt.Fprint(stdout, topHelp)
		return exitOK
	}
	if len(rest) == 0 {
		fmt.Fprint(stdout, topHelp)
		return exitOK
	}
	switch rest[0] {
	case "--all", "-all":
		fmt.Fprint(stdout, allHelp)
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, helpHelp)
		return exitOK
	}
	if len(rest) > 1 {
		fmt.Fprintf(stderr, "packout: help 只接受一个命令名，收到多余参数：%s\n\n",
			strings.Join(rest[1:], " "))
		fmt.Fprint(stderr, allHelp)
		return exitUsage
	}
	text, ok := helpFor(rest[0])
	if !ok {
		msg := fmt.Sprintf("未知命令 %q", rest[0])
		if wantsJSON(rest) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		fmt.Fprint(stderr, allHelp)
		return exitUsage
	}
	fmt.Fprint(stdout, text)
	return exitOK
}

// parse runs fs and returns the positional arguments plus -1 when the command
// should continue. Flags may appear before or after positionals: the standard
// library stops at the first positional, so remaining segments are re-parsed.
func parse(fs *flag.FlagSet, args []string, positional int, helpText string, stdout, stderr io.Writer) ([]string, int) {
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var pos []string
	rest := args
	for {
		err := fs.Parse(rest)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stdout, helpText)
				return nil, exitOK
			}
			if wantsJSON(args) {
				_ = jsonEncode(stdout, errObject{Error: err.Error(), Exit: exitUsage})
			}
			fmt.Fprint(stderr, helpText)
			return nil, exitUsage
		}
		next := fs.Args()
		if len(next) == 0 {
			break
		}
		pos = append(pos, next[0])
		rest = next[1:]
	}
	if len(pos) > positional {
		fmt.Fprintf(stderr, "packout: 多余的参数：%s\n\n", strings.Join(pos[positional:], " "))
		fmt.Fprint(stderr, helpText)
		return nil, exitUsage
	}
	return pos, -1
}

func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "-json" {
			return true
		}
	}
	return false
}

func parseScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var cfg scanConfig
	fs.StringVar(&cfg.profileRef, "profile", "", "内置 profile 名或 profile 文件路径（默认 "+defaultProfile+"）")
	fs.Var(&cfg.roots, "root", "role=PATH，可重复；同一 role 自动编号 role#2")
	fs.StringVar(&cfg.out, "out", "", "输出目录（必填，无默认值）")
	fs.BoolVar(&cfg.force, "force", false, "覆盖已存在且非空的 --out")
	fs.BoolVar(&cfg.followSymlinks, "follow-symlinks", false, "跟随符号链接/联接点")
	fs.BoolVar(&cfg.withSessions, "with-sessions", false, "逐文件导出会话 transcript/tool-results/subagents 原字节（--preset full 的别名）")
	fs.StringVar(&cfg.preset, "preset", "", "选择预设：minimal|standard|full（默认 standard=配置+记忆；full 另含会话内容）")
	fs.StringVar(&cfg.include, "include", "", "额外包含，逗号分隔：entry id / 类别 / 层（L0…L5）")
	fs.StringVar(&cfg.exclude, "exclude", "", "最后排除，逗号分隔：entry id / 类别 / 层（L0…L5）")
	fs.StringVar(&cfg.sessionsSince, "sessions-since", "", "只带最近 N 天的会话：7d|30d|all（默认 all）")
	fs.Var(&cfg.sessionsProj, "sessions-project", "只带该项目 slug 的会话（可重复）")
	fs.IntVar(&cfg.sessionsMax, "sessions-max-per-project", 0, "每个项目最多保留 N 个最新会话（默认 0=不限）")
	fs.BoolVar(&cfg.stableSalt, "stable-salt", false, "使用 ~/.config/packout/salt 的持久 salt")
	fs.IntVar(&cfg.jobs, "jobs", 0, "并行哈希的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, scanHelp(""), stdout, stderr); code >= 0 {
		return code
	}
	return runScan(ctx, cfg, stdout, stderr)
}

func parseReport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var cfg reportConfig
	fs.StringVar(&cfg.manifest, "manifest", "", "scan 的输出目录（必填）")
	fs.StringVar(&cfg.out, "out", "", "REPORT.html 路径（必填）")
	fs.BoolVar(&cfg.force, "force", false, "覆盖已存在的 --out")
	fs.BoolVar(&cfg.noSignals, "no-signals", false, "不渲染结论依据（默认 IncludeSignals=true）")
	fs.BoolVar(&cfg.redactPaths, "redact-paths", false, "把绝对路径折叠为 ~ 相对形式")
	fs.StringVar(&cfg.title, "title", "", "覆盖报告标题")
	fs.BoolVar(&cfg.lan, "lan", false, "绑定 0.0.0.0（默认只绑 127.0.0.1）")
	fs.BoolVar(&cfg.noServe, "no-serve", false, "只写 --out，不起服务")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, reportHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runReport(ctx, cfg, stdout, stderr)
}

func parseExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var cfg exportConfig
	fs.StringVar(&cfg.src, "src", "", "scan 的输出目录（必填）")
	fs.StringVar(&cfg.out, "out", "", "生成的包目录（必填）")
	fs.BoolVar(&cfg.force, "force", false, "并入已存在且非空的 --out（只碰包属子树）")
	fs.StringVar(&cfg.report, "report", "", "REPORT.html 路径（默认取 --src/REPORT.html）")
	fs.StringVar(&cfg.identity, "identity", "", "identity 路径，仅用于包内/权限警告")
	fs.BoolVar(&cfg.withSecrets, "with-secrets", false, "把 RESTORE 凭据加密写入 secrets.age，config/ 中留下 secret_ref")
	fs.Var(&cfg.recipients, "recipient", "age1… 或 ssh-ed25519/ssh-rsa 公钥，可重复")
	fs.BoolVar(&cfg.passphrase, "passphrase", false, "从终端读口令（scrypt 模式，与 --recipient 二选一）")
	fs.StringVar(&cfg.passphraseFile, "passphrase-file", "", "从文件第一行读口令（与 --passphrase 互斥）")
	fs.StringVar(&cfg.profile, "profile", "", "用于抽取配置的 profile（默认取清单头里的唯一 profile）")
	fs.Var(&cfg.roots, "root", "覆盖 roots.json 中的 role=PATH（可重复）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	fs.IntVar(&cfg.jobs, "jobs", 0, "并行哈希/复制的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）")
	if _, code := parse(fs, args, 0, exportHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runExport(ctx, cfg, stdout, stderr)
}

func parseVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var cfg verifyConfig
	fs.StringVar(&cfg.pubkey, "pubkey", "", "公钥文件（默认读 <configDir>/trusted_keys）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 结论")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	fs.IntVar(&cfg.jobs, "jobs", 0, "并行哈希的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）")
	pos, code := parse(fs, args, 1, verifyHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(pos) != 1 {
		const msg = "verify 需要一个包目录"
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		return exitUsage
	}
	cfg.dir = pos[0]
	return runVerify(ctx, cfg, stdout, stderr)
}

func parseSign(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var cfg signConfig
	fs.StringVar(&cfg.key, "key", "", "minisign 私钥路径（默认 ~/.config/packout/minisign.key）")
	fs.BoolVar(&cfg.generate, "generate", false, "密钥不存在时先生成一对（私钥 0600）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	pos, code := parse(fs, args, 1, signHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(pos) != 1 {
		const msg = "sign 需要一个包目录"
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		return exitUsage
	}
	cfg.dir = pos[0]
	return runSign(ctx, cfg, stdout, stderr)
}

func parseRestore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	var cfg restoreConfig
	fs.StringVar(&cfg.into, "into", "", "目标目录（必填）")
	fs.BoolVar(&cfg.inPlace, "in-place", false, "允许写进非空目标；先算 diff，非空时必须再给 --force")
	fs.BoolVar(&cfg.force, "force", false, "确认覆盖 --in-place 列出的差异")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "只跑验签、目标检查、解密与计划，不写盘")
	fs.BoolVar(&cfg.allowUnverified, "allow-unverified", false, "SIG 结论不是 ok 时仍继续（tampered 与 empty 除外）")
	fs.StringVar(&cfg.pubkey, "pubkey", "", "公钥文件（默认读 <configDir>/trusted_keys）")
	fs.StringVar(&cfg.identity, "identity", "", "age identity 路径（默认 ~/.config/packout/identity.age）")
	fs.BoolVar(&cfg.passphrase, "passphrase", false, "从终端读 secrets.age 口令")
	fs.StringVar(&cfg.passphraseFile, "passphrase-file", "", "从文件第一行读 secrets.age 口令（与 --passphrase 互斥）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 报告")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	pos, code := parse(fs, args, 1, restoreHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(pos) != 1 {
		const msg = "restore 需要一个包目录"
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		return exitUsage
	}
	cfg.pkg = pos[0]
	return runRestore(ctx, cfg, stdout, stderr)
}

func parseProfile(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var cfg profileConfig
	// `profile -h` must equal `help profile`; both print to stdout and exit 0.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help") {
		fmt.Fprint(stdout, profileHelp)
		return exitOK
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cfg.sub = args[0]
		args = args[1:]
	}
	if cfg.sub == "" || cfg.sub == "-h" || cfg.sub == "--help" {
		if cfg.sub == "" {
			const msg = "profile 需要子命令：list | probe | test"
			if wantsJSON(args) {
				_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
			}
			fmt.Fprintf(stderr, "packout: %s\n\n", msg)
			fmt.Fprint(stderr, profileHelp)
			return exitUsage
		}
		fmt.Fprint(stdout, profileHelp)
		return exitOK
	}
	if cfg.sub == "help" {
		fmt.Fprint(stdout, profileHelp)
		return exitOK
	}
	fs := flag.NewFlagSet("profile "+cfg.sub, flag.ContinueOnError)
	fs.Var(&cfg.roots, "root", "role=PATH，可重复（仅 probe）")
	fs.BoolVar(&cfg.strict, "strict", false, "probe：把 not_evaluable 也算失败")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	pos, code := parse(fs, args, 1, profileHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	switch cfg.sub {
	case "list", "probe", "test":
	default:
		fmt.Fprintf(stderr, "packout: 未知 profile 子命令 %q\n\n", cfg.sub)
		fmt.Fprint(stderr, profileHelp)
		return exitUsage
	}
	if len(pos) > 1 {
		msg := fmt.Sprintf("profile %s 只接受一个 profile 名", cfg.sub)
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		return exitUsage
	}
	if len(pos) == 1 {
		cfg.name = pos[0]
	}
	return runProfile(ctx, cfg, stdout, stderr)
}

func parseInit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var cfg initConfig
	fs.BoolVar(&cfg.force, "force", false, "覆盖已存在的配置（不会覆盖密钥）")
	fs.BoolVar(&cfg.yes, "yes", false, "不交互，接受全部建议的根")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, initHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runInit(ctx, cfg, stdout, stderr)
}

func parseDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var cfg doctorConfig
	fs.StringVar(&cfg.out, "out", "", "顺便检查该 --out 的父目录是否可写")
	fs.StringVar(&cfg.profile, "profile", "", "用于 selftest 的 profile（默认取配置或 "+defaultProfile+"）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 检查结果")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误与失败项")
	if _, code := parse(fs, args, 0, doctorHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runDoctor(ctx, cfg, stdout, stderr)
}

func parsePack(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	var cfg packConfig
	fs.StringVar(&cfg.out, "out", "", "包目录（必填，无默认值）")
	fs.BoolVar(&cfg.force, "force", false, "覆盖已存在且非空的 --out")
	fs.StringVar(&cfg.profileRef, "profile", "", "内置 profile 名或文件路径（默认 "+defaultProfile+"）")
	fs.Var(&cfg.roots, "root", "role=PATH，可重复；不给时用配置或 profile 默认值")
	fs.StringVar(&cfg.preset, "preset", "", "选择预设：minimal|standard|full（默认配置或 standard）")
	fs.StringVar(&cfg.include, "include", "", "额外包含，逗号分隔")
	fs.StringVar(&cfg.exclude, "exclude", "", "最后排除，逗号分隔")
	fs.StringVar(&cfg.sessionsSince, "sessions-since", "", "只带最近 N 天的会话：7d|30d|all")
	fs.Var(&cfg.sessionsProj, "sessions-project", "只带该项目 slug 的会话（可重复）")
	fs.IntVar(&cfg.sessionsMax, "sessions-max-per-project", 0, "每个项目最多保留 N 个最新会话")
	fs.BoolVar(&cfg.followSymlinks, "follow-symlinks", false, "跟随符号链接/联接点")
	fs.BoolVar(&cfg.stableSalt, "stable-salt", false, "使用持久 salt")
	fs.BoolVar(&cfg.withSecrets, "with-secrets", false, "把 RESTORE 凭据加密写入 secrets.age")
	fs.Var(&cfg.recipients, "recipient", "age1… 或 ssh 公钥，可重复")
	fs.BoolVar(&cfg.passphrase, "passphrase", false, "从终端读口令")
	fs.StringVar(&cfg.passphraseFile, "passphrase-file", "", "从文件第一行读口令（与 --passphrase 互斥）")
	fs.StringVar(&cfg.identity, "identity", "", "identity 路径（默认取配置或 ~/.config/packout/identity.age）")
	fs.BoolVar(&cfg.sign, "sign", false, "导出后签名（与 --key 一起或单独使用）")
	fs.BoolVar(&cfg.seal, "seal", false, "导出后签名；给了凭据参数时顺带加密凭据（= --with-secrets）")
	fs.StringVar(&cfg.key, "key", "", "minisign 私钥路径（给 --key 隐含 --sign）")
	fs.IntVar(&cfg.jobs, "jobs", 0, "并行 worker 数（默认 min(GOMAXPROCS,16)）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	pos, code := parse(fs, args, 1, packHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	// `pack <目录>` is sugar for `pack --out <目录>`; the old spelling stays.
	if len(pos) == 1 {
		switch {
		case cfg.out == "":
			cfg.out = pos[0]
		case filepath.Clean(cfg.out) != filepath.Clean(pos[0]):
			msg := fmt.Sprintf("位置参数 %s 与 --out %s 不一致（只给一个即可）", pos[0], cfg.out)
			if wantsJSON(args) {
				_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
			}
			fmt.Fprintf(stderr, "packout: %s\n\n%s", msg, packHelp)
			return exitUsage
		}
	}
	if cfg.seal {
		cfg.sign = true
		// --seal plus a credential shape also encrypts RESTORE credentials;
		// a bare --seal only signs.
		if len(cfg.recipients) > 0 || cfg.passphrase || cfg.passphraseFile != "" {
			cfg.withSecrets = true
		}
	}
	return runPack(ctx, cfg, stdout, stderr)
}

func parseVersion(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	var cfg versionConfig
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, versionHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runVersion(ctx, cfg, stdout, stderr)
}

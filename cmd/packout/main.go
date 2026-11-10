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
	"runtime"
	"strings"
	"syscall"

	"packout/internal/profile"
)

func main() {
	os.Exit(mainWithArgs(os.Args[1:], os.Stdout, os.Stderr))
}

// mainWithArgs is the testable entry point. Commands receive an injectable
// context; cancelling it is the user-interrupt path (exit 5).
func mainWithArgs(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, topHelp)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, topHelp)
		return exitOK
	case "scan":
		return parseScan(ctx, rest, stdout, stderr)
	case "report":
		return parseReport(ctx, rest, stdout, stderr)
	case "export":
		return parseExport(ctx, rest, stdout, stderr)
	case "verify":
		return parseVerify(ctx, rest, stdout, stderr)
	case "profile":
		return parseProfile(ctx, rest, stdout, stderr)
	case "version":
		return parseVersion(ctx, rest, stdout, stderr)
	default:
		msg := fmt.Sprintf("未知命令 %q", cmd)
		if wantsJSON(rest) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n", msg)
		fmt.Fprint(stderr, topHelp)
		return exitUsage
	}
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
	fs.BoolVar(&cfg.stableSalt, "stable-salt", false, "使用 ~/.config/packout/salt 的持久 salt")
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
	fs.StringVar(&cfg.identity, "identity", "", "identity 路径，仅用于包内警告")
	fs.StringVar(&cfg.profile, "profile", "", "用于抽取配置的 profile（默认取清单头里的唯一 profile）")
	fs.Var(&cfg.roots, "root", "覆盖 roots.json 中的 role=PATH（可重复）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	if _, code := parse(fs, args, 0, exportHelp, stdout, stderr); code >= 0 {
		return code
	}
	return runExport(ctx, cfg, stdout, stderr)
}

func parseVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var cfg verifyConfig
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 结论")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
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

func parseProfile(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var cfg profileConfig
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

// helpRoots renders every profile root default for --help (acceptance:
// `packout scan --help` lists them all).
func helpRoots(ref string) string {
	p, err := loadProfile(ref, io.Discard)
	if err != nil {
		return "  （无法加载 profile：" + err.Error() + "）\n"
	}
	var b strings.Builder
	for _, role := range p.RootOrder {
		def, err := profile.ExpandTemplate(p.Roots[role].ForOS(runtime.GOOS))
		if err != nil {
			def = "(该平台/环境未定义，需用 --root 给出)"
		}
		if def == "" {
			def = "(该平台/环境未定义，需用 --root 给出)"
		}
		fmt.Fprintf(&b, "  --root %s 默认 %s\n", role+"=PATH", def)
	}
	return b.String()
}

func scanHelp(ref string) string {
	return `用法: packout scan --out DIR [--profile NAME|FILE] [--root role=PATH]... [--force]

扫描 profile 声明的路径并写出 manifest。

  --out DIR            输出目录（必填，无默认值）
  --profile NAME|FILE  内置 profile 名或 profile 文件路径（默认 ` + defaultProfile + `）
  --root role=PATH     可重复；同一 role 多次出现自动编号 role#2
  --force              覆盖已存在且非空的 --out
  --follow-symlinks    跟随符号链接/联接点
  --stable-salt        使用 ~/.config/packout/salt 的持久 salt
  --json               stdout 输出可解析的 JSON 摘要
  --quiet              只输出错误

不给 --root 时使用 profile 的 root 默认值（并在 stderr 回显）：
` + helpRoots("") + `
退出码: 0 完成 / 2 未处理读取错误 / 3 用法或 profile 错误 / 4 --out 非空 / 5 中断
`
}

const topHelp = `用法: packout <命令> [参数]

命令:
  scan                 扫描并写 manifest 到 --out
  report               由 manifest 渲染报告（默认起本机服务）
  export               打成状态包
  verify               校验一个包（只读）
  profile list|probe|test  列内置、真机存在性探测、跑 selftest
  version              版本、commit、profile schema 版本

所有命令都支持 --json（stdout 输出可解析 JSON）与 --quiet（只留错误）。
写操作一律先落临时名再原子改名。退出码: 0/2/3/4/5，见 docs/design-cli.md。
`

const reportHelp = `用法: packout report --manifest DIR --out FILE [--no-serve] [--lan]

由 manifest 渲染自包含 HTML 报告。

  --manifest DIR   扫描输出目录或其下的 manifest/（必填）
  --out FILE       REPORT.html 路径（必填，无默认值）
  --force          覆盖已存在的 --out
  --no-signals     不渲染结论依据（默认开启：IncludeSignals=true）
  --redact-paths   把绝对路径折叠为 ~ 相对形式
  --title TEXT     覆盖报告标题
  --lan            绑定 0.0.0.0（默认只绑 127.0.0.1），并在 stderr 警示
  --no-serve       只写 --out，不起服务
  --json           stdout 输出可解析的 JSON 摘要
  --quiet          只输出错误

退出码: 0 完成 / 2 渲染或服务失败 / 3 用法错误 / 4 --out 非空 / 5 中断
`

const exportHelp = `用法: packout export --src DIR --out DIR [--force]

把扫描输出打成一个状态包（目录，不压缩）。SIG 是哈希树，P0 无签名。

  --src DIR        scan 的输出目录（必填）
  --out DIR        包目录（必填，无默认值）
  --force          并入已存在且非空的 --out；只碰包属子树（manifest/、config/、
                   reinstall/、REPORT.html），不碰无关顶层文件，因此往脏目录里
                   force 可能 verify 不干净
  --report FILE    REPORT.html 路径（默认取 --src/REPORT.html）
  --identity FILE  identity 路径，仅用于"落在包内"警告
  --profile NAME   specified 配置抽取用的 profile（默认读清单头）
  --root role=PATH 覆盖 roots.json 的根映射（可重复）
  --json           stdout 输出可解析的 JSON 摘要
  --quiet          只输出错误

退出码: 0 完成 / 2 导出失败 / 3 用法或源错误 / 4 --out 非空
`

const verifyHelp = `用法: packout verify PKG_DIR

校验一个包。结论词原样打印（P0 固定为 "hash-ok, unverified" 或 "unsigned"）。
只读，不写任何东西。

  --json   把结论与问题输出为可解析的 JSON
  --quiet  只输出错误

退出码: 0 结论通过 / 2 结论失败 / 3 用法错误
`

const profileHelp = `用法: packout profile list
       packout profile probe NAME [--root role=PATH]... [--strict]
       packout profile test NAME

  list    列出内置 profile
  probe   对真机只读检查每个 entry 的存在性，输出漂移清单
  test    在临时物化的 fixture 上跑 selftest

probe 的 root 解析与 scan 相同（同一 role 自动编号 role#2），只做 Lstat
与受限目录枚举，不读文件内容、不启动 sqlite。

退出码: 0 无漂移 / 2 有 absent（或 --strict 下有 not_evaluable）/ 3 profile 或用法错误
`

const versionHelp = `用法: packout version

打印版本、构建注入的 commit、Go 运行时与 profile schema 版本。

  --json   输出可解析的 JSON
  --quiet  只输出错误

退出码: 0
`

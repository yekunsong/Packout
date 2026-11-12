package main

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	"packout/internal/profile"
)

// The help system is layered on purpose: the top-level help teaches the five
// daily verbs only, `help --all` lists every command, and `help <cmd>` prints
// exactly what `<cmd> -h` prints. Every command help ends with one 下一步 line.

// verbHelp is one row of `packout help --all`.
type verbHelp struct {
	name string
	desc string
}

// allVerbs is the single list of commands this build accepts. Keep it in sync
// with mainWithArgs.
var allVerbs = []verbHelp{
	{"init", "生成配置、age identity 与 minisign 密钥"},
	{"pack", "scan → export →（可选）sign 一条链；可只签名/顺带加密凭据"},
	{"verify", "校验一个包（只读）"},
	{"drill", "在系统临时目录演练一次真实恢复，绝不碰用户目标目录"},
	{"restore", "把包恢复到目标目录（默认只写空目录）"},
	{"status", "只读显示配置、根、上次 scan 与包的结论"},
	{"scan", "扫描并写 manifest 到 --out"},
	{"report", "由 manifest 渲染报告（默认起本机服务）"},
	{"export", "把扫描输出打成状态包"},
	{"sign", "用 minisign 私钥给包签名"},
	{"doctor", "只读自检（配置、根、密钥、权限、磁盘）"},
	{"mcp", "stdio 上的只读 MCP 工具（roots/summary/find/explain/verify/restore_plan）"},
	{"profile", "profile list|probe|test：列内置、真机探测、跑 selftest"},
	{"completion", "把 bash|zsh|fish|powershell 补全脚本打到 stdout"},
	{"version", "版本、commit、profile schema 版本"},
}

// helpFor returns the help text a command prints for -h. `help <cmd>` reuses
// it verbatim, so the two can never drift apart.
func helpFor(cmd string) (string, bool) {
	switch cmd {
	case "help":
		return helpHelp, true
	case "init":
		return initHelp, true
	case "doctor":
		return doctorHelp, true
	case "scan":
		return scanHelp(""), true
	case "report":
		return reportHelp, true
	case "export":
		return exportHelp, true
	case "pack":
		return packHelp, true
	case "verify":
		return verifyHelp, true
	case "sign":
		return signHelp, true
	case "restore":
		return restoreHelp, true
	case "drill":
		return drillHelp, true
	case "status":
		return statusHelp, true
	case "completion":
		return completionHelp, true
	case "mcp":
		return mcpHelp, true
	case "profile":
		return profileHelp, true
	case "version":
		return versionHelp, true
	}
	return "", false
}

const topHelp = `用法: packout <命令> [参数]

packout 把一个环境（配置、记忆、技能、会话……）扫描成清单，打成可验证、
可恢复的包；恢复前可以先演练。

常用:
  init      生成配置、age identity 与 minisign 密钥
  pack      扫描 → 打包 →（可选）签名，一条链完成
  verify    校验一个包（只读）
  drill     在系统临时目录演练一次恢复，不碰任何用户目录
  restore   把包恢复到目标目录

其余：packout help --all 查看全部命令；packout help <命令> 看单个命令。
配置位于 ~/.config/packout/config.json（Windows: %APPDATA%\packout\config.json）；
CLI 参数优先。所有命令都支持 --json 与 --quiet。
写操作一律先落临时名再原子改名。退出码: 0/2/3/4/5，见 docs/design-cli.md。

下一步：packout init 生成配置与密钥，然后 packout pack <目录>
`

const allHelp = `用法: packout help [<命令> | --all]

不带参数时打印常用命令；给 <命令> 时输出与 <命令> -h 完全一致；--all 列出全部：

  init        生成配置、age identity 与 minisign 密钥
  pack        扫描 → 打包 →（可选）签名，一条链完成
  verify      校验一个包（只读）
  drill       在系统临时目录演练一次真实恢复，绝不碰用户目标目录
  restore     把包恢复到目标目录（默认只写空目录）
  status      只读显示配置、根、上次 scan 与包的结论
  scan        扫描并写 manifest 到 --out
  report      由 manifest 渲染报告（默认起本机服务）
  export      把扫描输出打成状态包
  sign        用 minisign 私钥给包签名
  doctor      只读自检（配置、根、密钥、权限、磁盘）
  mcp         stdio 上的只读 MCP 工具
  profile     list | probe | test：列内置、真机探测、跑 selftest
  completion  bash|zsh|fish|powershell 补全脚本打到 stdout
  version     版本、commit、profile schema 版本

下一步：packout help <命令> 看某个命令的全部参数与退出码
`

const helpHelp = `用法: packout help [<命令> | --all]

  packout help             常用命令（与裸 packout 不同：裸调用看当前状态给建议）
  packout help <命令>      与 <命令> -h 输出一致
  packout help --all       列出全部命令

下一步：packout help --all 查看全部命令
`

const initHelp = `用法: packout init [--force] [--yes]

交互式生成 ~/.config/packout/config.json（Windows：%APPDATA%\packout\config.json），
并生成缺失的 age identity（0600）与 minisign 密钥对（私钥 0600）。已有文件一律
不覆盖：配置已存在时需要 --force，密钥与 identity 只报告已存在。

  --force   覆盖已存在的配置（不覆盖密钥）
  --yes     不交互，接受全部建议的根
  --json    stdout 输出可解析的 JSON 摘要
  --quiet   只输出错误

检测 home；当前目录有 .git/.claude/CLAUDE.md 时建议 repo；Windows 另建议
appdata/localappdata。退出码: 0 完成 / 3 用法或生成失败

下一步：packout doctor 检查配置、根与密钥
`

const doctorHelp = `用法: packout doctor [--out DIR] [--json]

只读自检，不修任何东西。逐项输出 ok|warn|fail：
配置解析、根存在可读、identity/私钥权限（Unix 0600）、trusted_keys、--out
父目录可写、磁盘余量、profile selftest、MCP 注册提示。

  --out DIR   顺便检查该输出路径的父目录是否可写
  --profile   用于 selftest 的 profile
  --json      输出可解析的 {ok,checks[]}
  --quiet     只输出错误与失败项

有 fail 时退出 2，否则 0。

下一步：packout pack <目录> 打出第一个包
`

const packHelp = `用法: packout pack <目录> [--out DIR] [选择/加密/签名参数]

一条链完成：scan（临时目录）→ export（--out）→ 可选 sign。成功打印包路径与
verify 命令；任一失败返回该步退出码，已完成产物保留并打印路径。

  <目录>           位置参数，等价于 --out <目录>（两种写法不要同时给不同值）
  --out DIR        包目录（必填；位置参数与 --out 只能表示同一个目录）
  --seal           导出后签名；同时给了 --recipient/--passphrase-file/--passphrase
                   时顺带加密 RESTORE 凭据（等价于 --with-secrets）
  --force          覆盖已存在且非空的 --out
  --profile NAME   内置 profile 名或文件路径
  --root role=PATH 覆盖根（可重复；缺省用配置或 profile 默认值）
  --preset P       minimal|standard|full
  --include LIST / --exclude LIST / --sessions-*  同 scan
  --with-secrets / --recipient / --passphrase / --passphrase-file  同 export
  --identity FILE  identity 路径
  --sign           导出后签名（--seal 与 --key 也会打开它）
  --key FILE       minisign 私钥（给 --key 隐含 --sign）
  --jobs N         并行 worker 数
  --json / --quiet 机器输出 / 只留错误

退出码: 0 完成 / 2 步骤失败 / 3 用法或配置 / 4 --out 非空 / 5 中断

下一步：packout verify <包>；想确认能恢复就 packout drill <包>
`

const statusHelp = `用法: packout status [--json]

只读显示：配置文件路径、根、上次 scan、最近的包、上次 verify 结论与时间。
状态来自 <configDir>/state.json（版本化）；文件坏了只警告并按空状态显示。
不写任何文件，不参与任何安全判断。

  --json    stdout 输出可解析的 JSON 摘要
  --quiet   只输出错误

退出码: 0（无论是否已初始化）

下一步：packout verify <包> 或 packout drill <包> 演练恢复
`

const drillHelp = `用法: packout drill <包目录> [--into DIR] [--write] [--keep]

在系统临时目录演练一次真实恢复：先干跑打印计划，给 --write 才真正写进临时
目录；结束时删除临时目录并给出三段报告摘要。任何情况下都不写 --into 指定的
用户目标目录（它只用于在报告里说明“若正式恢复会到哪里”）。

  <包目录>         位置参数，要演练的包
  --into DIR       正式恢复时的目标，仅用于报告；drill 永不写它
  --write          真写临时目录（默认只干跑、打印计划）
  --keep           保留临时目录并打印路径（默认演练后删除）
  --allow-unverified  SIG 结论不是 ok 时仍继续（tampered 除外）
  --pubkey FILE    公钥文件（默认 ~/.config/packout/trusted_keys）
  --identity FILE  age identity（默认 ~/.config/packout/identity.age）
  --passphrase / --passphrase-file FILE  从终端/文件读 secrets.age 口令
  --json / --quiet 机器输出 / 只留错误

退出码: 同 restore（0 完成 / 2 失败 / 3 用法 / 5 中断）

下一步：packout restore <包> --into <目标目录> 正式恢复
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

下一步：packout export --src <scan 输出> --out <包目录>
`

const exportHelp = `用法: packout export --src DIR --out DIR [--force]

把扫描输出打成一个状态包（目录，不压缩）。SIG 是哈希树，P0 无签名。

  --src DIR        scan 的输出目录（必填）
  --out DIR        包目录（必填，无默认值）
  --force          并入已存在且非空的 --out；只碰包属子树（manifest/、config/、
                   reinstall/、REPORT.html），不碰无关顶层文件，因此往脏目录里
                   force 可能 verify 不干净
  --report FILE    REPORT.html 路径（默认取 --src/REPORT.html）
  --identity FILE  identity 路径，仅用于包内/权限警告
  --with-secrets   加密导出 RESTORE 凭据到 secrets.age；未给 --recipient 或
                   --passphrase 时报用法错误
  --recipient KEY  age1… 或 ssh-ed25519/ssh-rsa 公钥（可重复）
  --passphrase     从终端读口令（不回显）；口令命令行传递会泄漏，故不用参数值
  --passphrase-file FILE  从文件第一行读口令（去 CRLF；与 --passphrase 互斥）
  --profile NAME   specified 配置抽取用的 profile（默认读清单头）
  --root role=PATH 覆盖 roots.json 的根映射（可重复）
  --jobs N         并行哈希/复制的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）
  --json           stdout 输出可解析的 JSON 摘要
  --quiet          只输出错误

退出码: 0 完成 / 2 导出失败 / 3 用法或源错误 / 4 --out 非空

下一步：packout verify <包>（导出不含签名，要签名用 packout sign <包>）
`

const restoreHelp = `用法: packout restore PKG_DIR --into DIR [--allow-unverified] [--dry-run]
                   [--in-place [--force]] [--pubkey FILE] [--identity FILE | --passphrase]

按固定顺序恢复：验 SIG → 目标门 → 解密 secrets.age → 计划 → 写 → 回读复验。
默认目标必须不存在或为空；--in-place 才覆盖非空目标，并列 diff，diff 非空时必须 --force。
config/ 中的 «secret:…» 占位符会现场替换为明文；找不到引用记 missing_secret 并继续。
失败即停，已写文件保留、不回滚；L5 永不写盘，只进 needs_relogin。

  --into DIR           目标目录（必填）
  --in-place           允许非空目标；先列 diff
  --force              确认执行 --in-place 列出的覆盖
  --dry-run            只跑前四步，零写入
  --allow-unverified   SIG 结论不是 ok 时仍继续（tampered 除外；红字提示）
  --pubkey FILE        公钥文件（默认 ~/.config/packout/trusted_keys）
  --identity FILE      age identity（默认 ~/.config/packout/identity.age）
  --passphrase         从终端读口令（与 --identity 二选一）
  --passphrase-file FILE  从文件第一行读口令（与 --passphrase、--identity 互斥）
  --json               stdout 输出可解析的 JSON 报告
  --quiet              只输出错误

报告三段：restored / needs_reinstall / needs_relogin，逐条带来源 Unit id。
退出码: 0 完成 / 2 执行或校验失败（含 E-RST-*）/ 3 用法 / 4 目标非空且未 --force / 5 中断

下一步：packout doctor 自检，或 packout status 看整体状态
`

const verifyHelp = `用法: packout verify PKG_DIR [--pubkey FILE]

校验一个包。结论词原样打印：
  ok                  签名有效且内容匹配（只有它能说"可以恢复"）
  hash-ok, unverified 内容匹配但没有可用公钥
  tampered            内容与 SIG 不符（签名在也一样）
  unsigned            内容匹配但包没有签名
  bad-signature       签名在，但没有可信公钥能验证它
只读，不写任何东西。

  --pubkey FILE  公钥文件（一行一个，'#' 注释）；不给时读
                 ~/.config/packout/trusted_keys（存在才读）
  --jobs N       并行哈希的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）
  --json         把结论与问题输出为可解析的 JSON
  --quiet        只输出错误

首次用 --pubkey 见到的公钥会打印 SHA256 指纹并提示 TOFU，请用另一渠道核对。
退出码: 0 结论为 ok 或 hash-ok, unverified / 2 其余结论 / 3 用法或公钥错误

下一步：结论 ok 后 packout drill <包> 演练恢复；未签名先 packout sign <包>
`

const signHelp = `用法: packout sign PKG_DIR [--key FILE] [--generate]

对 SIG.json 与 manifest/ 的哈希树签名，写 SIG.json.minisig。签名文件本身
不参与被签名内容。包必须已有有效 SIG 与 manifest。

  --key FILE   minisign 私钥（默认 ~/.config/packout/minisign.key，须为 0600）
  --generate   密钥不存在时先生成一对，公钥写到 <key>.pub
  --json       stdout 输出可解析的 JSON 摘要
  --quiet      只输出错误

签名只证明"是谁打的包"；内容完整性仍由 SIG 的整包哈希树保证。
退出码: 0 完成 / 2 签名失败 / 3 用法或密钥错误

下一步：packout verify <包> --pubkey <key>.pub 用公钥确认签名
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

下一步：packout doctor 查看整体自检，或 packout scan --out <目录>
`

const completionHelp = `用法: packout completion bash|zsh|fish|powershell

把对应 shell 的补全脚本打到 stdout，不写任何文件。

  bash        source <(packout completion bash) 或写进 ~/.bashrc
  zsh         source <(packout completion zsh)（先 compinit）
  fish        packout completion fish | source
  powershell  packout completion powershell | Out-String | Invoke-Expression

退出码: 0 完成 / 3 用法错误（不认识的 shell）

下一步：把上面的命令写进你的 shell 启动文件
`

const versionHelp = `用法: packout version

打印版本、构建注入的 commit、Go 运行时与 profile schema 版本。

  --json   输出可解析的 JSON
  --quiet  只输出错误

退出码: 0

下一步：packout help --all 查看全部命令
`

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
  --with-sessions      会话内容逐文件出行，导出保留原字节（--preset full 的别名）
  --preset P           选择预设 minimal|standard|full（默认 standard；full 才带会话内容）
  --include LIST       逗号分隔地额外包含 entry id / 类别 / 层
  --exclude LIST       逗号分隔地在最后排除 entry id / 类别 / 层
  --sessions-since D   只带最近 7d/30d 的会话（默认 all）
  --sessions-project S 只带该项目 slug 的会话（可重复）
  --sessions-max-per-project N  每项目只保留 N 个最新会话（0=不限）
  --stable-salt        使用 ~/.config/packout/salt 的持久 salt
  --jobs N             并行哈希的 worker 数（默认 min(GOMAXPROCS,16)；1 = 串行）
  --json               stdout 输出可解析的 JSON 摘要
  --quiet              只输出错误

不给 --root 时按配置文件的 roots，再退到 profile 的 root 默认值（每一步都在
stderr 回显实际来源）：
` + helpRoots(ref) + `
退出码: 0 完成 / 2 未处理读取错误 / 3 用法或 profile 错误 / 4 --out 非空 / 5 中断

下一步：packout export --src <scan 输出> --out <包目录>
`
}

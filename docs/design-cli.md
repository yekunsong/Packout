# CLI 设计（实现前定稿）

## 产品口径

**packout 是 AI 会话迁移工具，让不同的工作区拥有同一个 AI 会话基线。**

基线 = 配置（settings、MCP、skills、agents、commands、rules、CLAUDE.md）+ 记忆（memory）+（可选）会话内容。机器绑定项与需重登项不属于基线，只进报告。场景是换机器、开新工作区、多机同一套助手习惯；不是通用备份工具，也不做清理执行（D-053）。这句话是 `README`、`packout help`、裸 `packout`、`init` 下一步与报告标题共用的唯一表述，不再写变体。

`cmd/packout` 只做参数解析与装配，业务全在 internal。**不拼 shell，全部走 argv。**

## 命令

| 命令 | 作用 | 写 |
|---|---|---|
| `init` | 交互生成配置、age identity、minisign 密钥 | 配置目录 |
| `doctor` | 只读自检（配置/根/密钥/权限/磁盘/磁盘余量/selftest） | 无（临时探测文件随删） |
| `pack` | scan → export → 可选 sign 一条链 | 只写 `--out` 与临时目录 |
| `scan` | 扫描并写 manifest 到 `--out` | 只写 `--out` |
| `report` | 由 manifest 渲染报告，默认起本机服务 | 只写 `--out` |
| `export` | 打成状态包（读 `<src>/roots.json` 与清单头里的 profile；`--profile`/`--root` 可覆盖） | 只写 `--out` |
| `verify` | 校验一个包 | 只读 |
| `profile list/probe/test` | 列内置、对真机探测存在性、跑 selftest | probe 只读 |
| `status` | 只读显示配置/根/上次 scan/包/verify 结论/时间 | 无 |
| `drill` | 在系统临时目录演练恢复（默认干跑，`--write` 真写），报告三段摘要 | 系统临时目录（`--keep` 才留） |
| `completion` | 输出 bash/zsh/fish/powershell 补全脚本 | 无（只到 stdout） |
| `version` | 版本、commit、profile schema 版本 | — |

## 分层帮助与引导（D-052）

- 裸 `packout` 是状态感知引导，**恒退出 0、不写任何文件**：无配置打印三行（这是什么 / `packout init` / `packout help`）；有配置无包记录建议 `packout pack <目录>` 并给示例；有包记录打印 `status` 摘要与 verify/drill/restore 建议。
- 主帮助只列 5 个常用动词 `init / pack / verify / drill / restore`，另给一行“其余：`packout help --all`”。`packout help --all` 列全部动词。
- `packout help <命令>` 与 `<命令> -h` 必须逐字一致（同一个常量，`profile -h` 也走帮助）。每个命令帮助末尾固定一行“下一步：…”。
- 位置参数是糖，旧旗标全部保留：`pack <目录>` = `--out <目录>`（两者不同值退出 3）；`verify <包>`、`restore <包> --into`、`drill <包>`。
- `pack --seal` = 导出后签名；同时给了 `--recipient`/`--passphrase`/`--passphrase-file` 时再加密 RESTORE 凭据（等价 `--with-secrets`），纯 `--seal` 只签名。
- 错误提示在 CLI 层补“下一步：…”一行（目标非空给 `--in-place --force` 的完整命令、未签名给 `--allow-unverified`/`sign`、未初始化给 `packout init`），**退出码不变**。

## 状态文件 state.json（D-052）

- 路径 `<configDir>/state.json`，`version: 1`，0600、原子改名；记录配置根、上次 scan（计数+根）、最近的包（最多 5 个）、上次 verify 结论、上次 restore 目标。
- scan/export/pack/verify/restore **成功**后才写；失败或中断不写；`pack` 的内层 scan/export 不写，链末记一次。
- 坏文件/未知 version 只 warn 并按空状态处理（`status` 仍退出 0）。只用于引导与展示，**不参与任何安全判断**。
- `state.json` 属于**用户配置目录**，和 config/密钥同级；测试与 CI 必须隔离 `configDir`（cmd 包的 `TestMain` 默认把 `XDG_CONFIG_HOME`/`AppData`/`HOME` 指到临时目录，个别用例再用 `isolateConfig` 覆盖），任何成功命令都不得写真实 home。

## 配置文件

- 路径：Unix `~/.config/packout/config.json`（遵循 `XDG_CONFIG_HOME`）；Windows `%APPDATA%\packout\config.json`。
- 文件 0600（Unix）、父目录 0700；严格 JSON，未知键与未知 `version` 都是退出 3 并打印路径。
- 字段：`version`（必须 1）、`profile`、`preset`、`roots`（role→绝对路径）、`identity`、`trusted_keys`。
- 优先级恒为 **CLI 参数 > 配置文件 > profile 默认值**；config 只填空缺，不覆盖任何显式参数。
- `roots` 在 scan/export/mcp 中作为 `--root` 的缺省；`preset` 给 scan/pack；`identity` 给 export/restore/mcp/pack。
- `trusted_keys` 是 verify/restore/mcp 的**可信公钥库**，经 `VerifyOptions.TrustedKeysPath` 传入，**不是** `--pubkey`：显式 `--pubkey` 永远优先且是唯一验签来源，库只用于 first-seen 判定。文件缺失/为空/损坏时无可用公钥，结论是 `bad-signature`（不是 `failed`）。`init` 会创建它并写入本机公钥（0600；已有内容只追加不覆盖）。
- 配置文件坏了是用法错误（3），消息必须带路径；缺文件不算错。

## 关键约束

- `--out` 必须由用户给，**没有默认值**；所有写操作先落到 `--out` 下的临时名再原子改名。
- `--root role=PATH` 可重复；同一 role 多次出现自动编号 `role#2`（D-015 #1）。
- 不给 `--root` 时用 profile 的 root 默认值（`home`/`codex` 等），并在 stderr 回显实际使用的根。
- `--profile` 可给内置名或文件路径；文件路径的 profile 视为半可信输入，加载时打印其哈希。
- `report` 恒传 `IncludeSignals: true`；`--no-signals` 显式关。
- `report --lan` 才绑 `0.0.0.0`，并在 stderr 打印实际 URL 与警示。
- `verify` 的结论词原样打印，不做美化。无可用公钥（trusted_keys 缺失/为空/加载失败）且树哈希匹配时是 `bad-signature`，不是 `failed`；树哈希不符仍是 `tampered`（先树后签名，INV-C06）。`hash-ok, unverified` 仅作为历史结论词保留。
- `restore`/`drill` 门禁只看结论：`tampered` 拒绝且 `--allow-unverified` 不放行；`empty`（空包/不可识别）同样不放行；`unsigned`/`bad-signature`/`failed` 在 `--allow-unverified` 下继续并红字警告，否则错误文案写实际结论与下一步，不得说“tampered”。
- `restore`/`drill` 的 `--map ROLE=PATH`（可重复）把角色落地根改到 `<into>/PATH`（PATH 相对 `--into`；绝对路径、盘符、`~`、`..` 拒绝）。未映射角色仍落 `<into>/ROLE`；`--into` 仍必填；映射不放松任何门禁，`--dry-run`/`drill` 不写盘。结束时打印解析后的绝对落地摘要。
- `pack --with-sessions` 是 `--preset full` 的别名；与 `minimal/standard` 同用是用法错误（3），`full` 同值放行。`pack` 成功的人类输出只有一次扫描计数与一行包摘要，不暴露内部临时扫描目录。
- `scan` 会在输出目录写 `roots.json`（实例名→绝对路径）。它是本机元数据，**不进包**；`export` 靠它免去重敲 `--root`。
- 所有命令支持 `--json` 输出机器可读摘要；`--quiet` 只留错误。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 完成（可含已记录的 read_error） |
| 1 | `profile probe` 有 absent、`profile test` 断言失败、verify 结论为 `empty`/不认识 |
| 2 | 有未处理的读取错误，或 verify 结论为失败 |
| 3 | 用法/配置错误（含 profile 校验失败） |
| 4 | 输出目录已存在且非空、未给 `--force` |
| 5 | 用户中断 |

`pack` 的每一步沿用同一张表：scan 失败按 scan 的码，export 失败按 export 的码，sign 失败 2/3。
`doctor` 有 fail 时用 2。

## 不做

- 不做交互式 TUI（P0）。
- `restore` 见 `design-restore.md`（P1 已实现，D-046）。
- 选择（`--preset/--include/--exclude/--sessions-*`）见 spec-profile-model §5.12 与 D-050；默认 standard，会话需 full 或显式 include。
- 不自动打开浏览器以外的任何东西；打开失败只提示路径。
- `init` 不覆盖任何已存在的文件：配置要 `--force`，密钥/identity 只报告已存在。
- `doctor` 只读不修。
- `--passphrase` 与 `--passphrase-file` 互斥；后者读第一行、去 CRLF，空行是用法错误。

## 验收

- `packout scan --help` 列出全部 root 默认值与 `--out` 必填。
- 缺 `--out` 时 exit 3 且不产生任何文件。
- 对只读目录扫描成功后，目标树快照不变。
- 全命令 `--json` 输出可被 `encoding/json` 解析。

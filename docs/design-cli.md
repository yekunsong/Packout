# CLI 设计（实现前定稿）

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
| `version` | 版本、commit、profile schema 版本 | — |

## 配置文件

- 路径：Unix `~/.config/packout/config.json`（遵循 `XDG_CONFIG_HOME`）；Windows `%APPDATA%\packout\config.json`。
- 文件 0600（Unix）、父目录 0700；严格 JSON，未知键与未知 `version` 都是退出 3 并打印路径。
- 字段：`version`（必须 1）、`profile`、`preset`、`roots`（role→绝对路径）、`identity`、`trusted_keys`。
- 优先级恒为 **CLI 参数 > 配置文件 > profile 默认值**；config 只填空缺，不覆盖任何显式参数。
- `roots` 在 scan/export/mcp 中作为 `--root` 的缺省；`preset` 给 scan/pack；`identity`/`trusted_keys` 给 export/restore/verify/mcp/pack。
- 配置文件坏了是用法错误（3），消息必须带路径；缺文件不算错。

## 关键约束

- `--out` 必须由用户给，**没有默认值**；所有写操作先落到 `--out` 下的临时名再原子改名。
- `--root role=PATH` 可重复；同一 role 多次出现自动编号 `role#2`（D-015 #1）。
- 不给 `--root` 时用 profile 的 root 默认值（`home`/`codex` 等），并在 stderr 回显实际使用的根。
- `--profile` 可给内置名或文件路径；文件路径的 profile 视为半可信输入，加载时打印其哈希。
- `report` 恒传 `IncludeSignals: true`；`--no-signals` 显式关。
- `report --lan` 才绑 `0.0.0.0`，并在 stderr 打印实际 URL 与警示。
- `verify` 的结论词原样打印，不做美化（`hash-ok, unverified` 就是 `hash-ok, unverified`）。
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

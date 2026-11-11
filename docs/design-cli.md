# CLI 设计（实现前定稿）

`cmd/packout` 只做参数解析与装配，业务全在 internal。**不拼 shell，全部走 argv。**

## 命令

| 命令 | 作用 | 写 |
|---|---|---|
| `scan` | 扫描并写 manifest 到 `--out` | 只写 `--out` |
| `report` | 由 manifest 渲染报告，默认起本机服务 | 只写 `--out` |
| `export` | 打成状态包（读 `<src>/roots.json` 与清单头里的 profile；`--profile`/`--root` 可覆盖） | 只写 `--out` |
| `verify` | 校验一个包 | 只读 |
| `profile list/probe/test` | 列内置、对真机探测存在性、跑 selftest | probe 只读 |
| `version` | 版本、commit、profile schema 版本 | — |

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

## 不做

- 不做交互式 TUI（P0）。
- `restore` 见 `design-restore.md`（P1 已实现，D-046）。
- 选择（`--preset/--include/--exclude/--sessions-*`）见 spec-profile-model §5.12 与 D-050；默认 standard，会话需 full 或显式 include。
- 不读配置文件（P0 全部走参数，避免再引入一个配置面）。
- 不自动打开浏览器以外的任何东西；打开失败只提示路径。

## 验收

- `packout scan --help` 列出全部 root 默认值与 `--out` 必填。
- 缺 `--out` 时 exit 3 且不产生任何文件。
- 对只读目录扫描成功后，目标树快照不变。
- 全命令 `--json` 输出可被 `encoding/json` 解析。

# profile 规格 v2.0（三）：校验、错误码与 CLI

状态：草案。适用于 `packout` P0。相关决策：D-010、D-013–D-017、D-024、D-028、D-030。本文是完整规格的第 9–12 章；模型与字段见 `docs/spec-profile-model.md`（§1–§7），内置 profile 见 `docs/spec-profile-builtin.md`（§8）。

---

## 9. 校验规则与错误码

校验分三级：`error` 阻止加载；`warning` 默认放行，`--strict` 下失败；`info` 只记录。所有 profile（内置、用户、迁移结果、selftest fixture）在加载时执行同一套校验，内置 profile 的 error 在构建期即失败。

| 码 | 级 | 触发条件 |
|---|---|---|
| `E-PRF-001` | error | 缺 `schema_version` |
| `E-PRF-002` | error | MAJOR 超出支持范围 |
| `E-PRF-003` | error | `name` 不合法 |
| `E-PRF-004` | error | 条目 `id` 重复 |
| `E-PRF-005` | error | 未知 `kind`，整份 profile 拒绝加载 |
| `E-PRF-006` | error | `layer` 非法 |
| `E-PRF-007` | error | `secret` 非法 |
| `E-PRF-008` | error | `extractor` 非法 |
| `E-PRF-009` | error | `glob-group` 无 `paths`，或 `file`/`dir` 无 `path` |
| `E-PRF-010` | error | `file`/`dir` 的 `path` 含 glob |
| `E-PRF-011` | error | 条目引用未声明的 root |
| `E-PRF-012` | error | 相对条目路径含 `..` 越界，或 `path`/`paths` 为空 |
| `E-PRF-013` | error | `max_bytes_inline` 越界 |
| `E-PRF-014` | error | `max_depth` 越界 |
| `E-PRF-015` | error | `signals` 为空（`catch-all` 除外，其 `residual` signal 由引擎注入）或 `note` 为空 |
| `E-PRF-016` | error | `official_docs` signal 缺 `url` |
| `E-PRF-017` | error | 缺 `selftest` 或缺 `expect` |
| `E-PRF-018` | error | entry 未被 selftest 覆盖且无 `selftest_exempt` |
| `E-PRF-019` | error | selftest `expect` 引用不存在的 fixture 路径 |
| `E-PRF-020` | error | selftest 的 `expect` 出现未知 entry |
| `E-PRF-021` | error | fixture 路径越出 fixture 根 |
| `E-PRF-022` | error | `follow_symlinks: true` 且 `max_depth` 缺失或 > 64 |
| `E-PRF-023` | error | 同一 profile 内两条 entry 的 selector 完全相同且 `priority` 相同 |
| `E-PRF-024` | error | `kind: file` 配 `expand: aggregate` |
| `E-PRF-025` | error | `redact` 用在 `raw-ref`/`none`/`digest` 上 |
| `E-PRF-026` | error | `unique_within` 用在非 L2 条目（迁移后旧字段视为未知字段，另见 `W-PRF-101`） |
| `E-PRF-027` | error | selftest `expect` 的 `root:` 未绑定或非法、`selftest.fixtures` 值非法/重复绑定，且无法兜底推断 |
| `E-PRF-028` | error | `scan` 用在 `secret != scan` 的条目 |
| `E-PRF-030` | error | root 展开后不是绝对路径 |
| `W-PRF-125` | warning | 展开后路径超 32,767 字符；记 `path_too_long`，不产出 Unit |
| `W-PRF-126` | warning | 行注释用 `#` 而非 `//` |
| `W-PRF-127` | warning | profile 扩展名不是 `.jsonc`（内容合法仍按 JSONC 解析） |
| `E-PRF-040` | error | `secret: relogin` 但 `layer != L5` |
| `E-PRF-041` | error | `secret: restore` 但 `layer != L3` |
| `E-PRF-042` | error | `secret: scan` 但 `max_bytes_inline == 0` 且 `opaque_content != true` |
| `E-PRF-043` | error | 含密条目用 `raw-ref` 且无 `redact` |
| `E-PRF-063` | error | JSONC 语法错误（未闭合字符串/注释/对象、非法转义） |
| `E-PRF-064` | error | 同一对象内重复键 |
| `E-PRF-065` | error | 顶层不是单个对象，或多个顶层值 |
| `E-PRF-066` | error | 使用单引号字符串或无引号键 |
| `E-PRF-067` | error | `selftest.fixtures`/`files`/`dirs`/`symlinks` 路径不是 profile 内相对路径或越界 |
| `E-PRF-032` | error | `parts` 为空 |
| `E-PRF-033` | error | part 缺 `selector`、`selector` 含多个键或键名未知，或同一 entry 的 parts 选择器种类不一 |
| `E-PRF-034` | error | 同一 entry 的 parts selector 可静态判定为重叠（`docs/spec-profile-model.md` §5.9） |
| `E-PRF-035` | error | part `id` 非法、entry 内重复，或使用了保留 id `uncovered` |
| `E-PRF-036` | error | part 写了不可覆盖字段（`kind`/`path`/`root`/`priority`/`churn`/`companions`/`os`）；`id`、`path_semantics`、`derived_from`、`origin`、`origin_path_key` 可写 |
| `E-PRF-037` | error | `catch-all` 缺 `root`、写 `path`/`paths`，或同一 `(profile, root 实例)` 的多条 catch-all 违反 `docs/spec-profile-model.md` §5.2 的共存条件 |
| `E-PRF-038` | error | `machine_derived` 缺 `derived_from`，或 `literal` 却给了 `derived_from` |
| `E-PRF-039` | error | `derived_from: git_worktree_of` 但路径不含 `.claude/worktrees/` |
| `E-PRF-044` | error | `companions` 用在非 `file`/`glob-group` 条目 |
| `E-PRF-045` | error | `companions` 后缀不匹配 `^-[A-Za-z0-9.]{1,15}$` 或重复 |
| `E-PRF-046` | error | `priority` 非整数或越出 -1000–1000 |
| `E-PRF-047` | error | `unique_within` 非 `root`，或 `catch-all` 使用 `unique_within` |
| `E-PRF-048` | error | `churn` 非 `high`/`low` |
| `E-PRF-049` | error | `max_bytes_structure` 越界（0–8388608） |
| `E-PRF-052` | error | `max_bytes_total` 越界，或条目值大于 profile 值 |
| `E-PRF-057` | error | part 未被 selftest 覆盖（entry 未 `selftest_exempt`）；保留 id `uncovered` 的 Unit 除外 |
| `E-PRF-058` | error | `--root` 的 role 未在 profile 声明且不是保留 root 名 |
| `E-PRF-059` | error | 绝对路径条目同时给了 `root` 但路径不在其下，或绝对路径无法展开为绝对形式 |
| `E-PRF-061` | error | `side_effects` 含未知值 |
| `E-PRF-062` | error | profile 级 `max_bytes_total` 非正或超 4 TiB |
| `E-PRF-050` | error | selftest 预算缺失或 `wall_ms` 非正 |
| `E-PRF-051` | error | selftest 使用真实绝对用户路径 |
| `E-PRF-060` | error | `probe` 与 locator scheme 不一致 |
| `W-PRF-101` | warning | 未知顶层/条目字段（保留） |
| `W-PRF-102` | warning | unknown 枚举值（降级 keep） |
| `W-PRF-103` | warning | `applies_to.os` 为空 |
| `W-PRF-104` | warning | `exclude` 里出现绝对路径 |
| `W-PRF-106` | warning | `expect.match` 用 `repo/` 前缀兜底推断 |
| `W-PRF-110` | warning | `template` 无 `redact` |
| `W-PRF-111` | warning | `max_bytes_inline` > 1 MiB |
| `W-PRF-120` | warning | 用户 profile 覆盖内置同名 profile |
| `W-PRF-121` | warning | `notes` 含 `TODO verify` |
| `W-PRF-122` | warning | 同路径多条 entry 的优先级与具体度相同（`priority_tie`） |
| `W-PRF-123` | warning | `needed_by` 含未知值（降级 `unknown_enum`） |
| `E-PRF-068` | error | `parts_uncovered` 用在无 `parts` 的条目上，或取值非 `keep`/`note`/`residual` |
| `E-PRF-069` | error | `origin` 出现在 `literal` 上，或 `origin_path_key` 与 `origin` 的折叠结果不一致 |
| `E-PRF-070` | error | `catch-all` 的 `scope`/`under` 非法（`under` 含 glob/`..`、越出 root、`scope: root` 却写 `under`，或 `scope: subtree` 缺 `under`） |
| `E-PRF-071` | error | `open_as` 值非法、`open_as: sqlite-ro` 用在非 `file`/`glob-group`，或 `side_effects: shm_created` 缺少 `open_as: sqlite-ro` |
| `E-PRF-072` | error | `parts` 用在非 `file` 条目（parts 只对 `kind: file` 合法） |
| `E-PRF-073` | error | `catch-all` 写了 `priority`（catch-all 只在残留遍求值、不参与声明遍竞争） |
| `W-PRF-124` | warning | `catch-all` 未覆盖或被 `selftest_exempt` |
| `W-PRF-131` | info | `opaque_content: true` 但 `secret: scan` 且预算为 0（仅存在性） |
| `W-PRF-130` | info | L3/L5 条目但 extractor 为 `none` |

错误输出格式：

```
E-PRF-042 entries[3](codex-thread-history): secret: scan 需要 max_bytes_inline > 0 或 opaque_content: true
```

一次加载报告全部错误后退出，不首错即停。

---

## 10. 安全边界

- profile 是**输入**，可来自用户，按不可信处理：相对路径必须落回已声明 root 内，`..` 先规范化再比较；绝对路径条目允许 root 外，但必须绝对且不含 glob。
- 扫描全程只读：不创建、不修改、不删除目标路径下的任何对象；唯一例外是 `open_as: sqlite-ro` 且 `side_effects` 已声明的 `shm_created`（sqlite 驱动行为，见 `docs/spec-profile-model.md` §5.11），selftest 物化只发生在临时目录。
- `profile probe` 同样只读：只做 `Lstat`/目录枚举与 named-location 探测，不读文件内容、不启动 sqlite。
- profile 的 `url` 只记录不请求（P0 无网络）。
- 内置 profile 走 `go:embed`，校验和进 manifest header；用户 profile 的 SHA-256 同样记录，覆盖时按新文件重新记录。
- 不得在 profile 里写任何真实密钥；示例值统一 `FIXTURE` 后缀。

---

## 11. CLI 接口

```
packout profile list                 # 列出内置与用户 profile，标出覆盖关系
packout profile show <name>          # 打印展开后（root 已解析）的 profile
packout profile validate <file>...   # 仅校验，--strict 把 warning 变失败
packout profile test <name>          # 跑 selftest；CI 用这个
packout profile probe <name> [--root role=PATH]...  # 对真机只读存在性检查
packout profile migrate <name> --to X [--dry-run] [--write]
```

`profile test` 退出码：`0` 全过，`1` 断言失败，`2` profile 校验失败，`3` 超预算。

### 11.1 profile probe

`probe` 解决 selftest 的盲区（`D-016`）：在真实机器上只读验证每个 entry 的 selector 是否存在，输出漂移清单。它不读内容，不调用扫描引擎，也不写 profile。

- root 解析与 `scan` 相同：`--root role=PATH` 可重复；未给出的 role 用 profile 模板展开。绝对路径条目直接检查。展开失败的 role 记 `root_unresolved`。
- 每条 entry/part 输出一行 JSONL：`{entry, part_id?, root, resolved_path, status}`，`status` 取 `present` / `absent` / `not_evaluable` / `root_unresolved`。`not_evaluable` 用于 glob 无法在不扫目录时判定的情况——`probe` 仍对 glob 做一层目录展开（受限 `max_depth`，默认 2），展不出任何命中记 `absent`。
- named-location 走 `docs/spec-profile-model.md` §5.5 的探测，成功 `present`、失败 `not_evaluable`（探测失败在 P0 合法，`D-010` 第 2 条）。
- 结尾输出汇总：`entries`、`present`、`absent`、`not_evaluable`、`root_unresolved`。`absent` 是漂移；`not_evaluable` 只提示。
- 退出码：`0` 无 `absent`，`1` 有 `absent`，`2` profile 校验失败。`--strict` 把 `not_evaluable` 也算失败（`1`）。
- 内置 profile 中行尾标了 `// 本机不存在` 的 entry，`probe` 仍照常检查，标签只是给人看的作者注记。

---

## 12. 未决问题

本节条目已全部由 `D-010`、`D-013`–`D-017` 裁决，保留编号作索引。

1. **YAML vs JSONC**：**已定（D-017，取代 D-010 第 1 条）**。改用 JSONC + `tailscale/hujson`，解码走 AST 并保留注释与格式，见 `docs/spec-profile-model.md` §2。
2. **named-location 探测实现**：**已定（D-010 第 2 条）**。探测失败允许，P0 只记存在性，不读凭据。
3. **凭据存储的精确名称**：**已定（D-010 第 3 条）**。发布前必须本机核实，未核实的不许进内置 profile。
4. **`l3_if_unique` 的计数范围**：**已定（D-010 第 4 条，后由 D-015 第 10 条取代）**。改为按 entry 在 root 实例内计数的 `unique_within: root`，见 `docs/spec-profile-model.md` §5.3。
5. **大小写敏感卷的判定**：**已定（D-010 第 5 条）**。由用户 profile 显式声明，报告标注"按用户声明处理"。
6. **profile 签名**：**已定（D-010 第 6 条）**。P1 再做。
7. **selftest 的多 root 断言语义**：**已定（D-010 第 7 条）**。必须显式写 `root:`，见 `docs/spec-profile-model.md` §6.2。
8. **`secret: scan` 的误报责任**：**已定（D-010 第 8 条）**。允许 `scan: strict`，见 `docs/spec-profile-model.md` §5.4。
9. **聚合阈值**：**已定（D-010 第 9 条）**。10000 为暂定值，实测后定。
10. **未知 `kind` 的处理**：**已定（D-010 第 10 条）**。整份 profile 拒绝加载，错误码 `E-PRF-005`。
11. **内置 profile 的更新通道**：**已定（D-010 第 11 条）**。带签名 profile 包放 P1，内置 profile 随二进制。
12. **模型能否覆盖真实机器**：**已定（D-013）**。接受 M1–M9，升 v2，见 `docs/spec-profile-model.md` §5.9–§5.11。
13. **残留兜底**：**已定（D-014）**。新增 `kind: catch-all`，confidence 固定 0.5，见 `docs/spec-profile-model.md` §5.2。
14. **多仓库根与 `l3_if_unique`**：**已定（D-015 第 1、10 条）**。重复 `--root repo=PATH`，实例名 `repo#2`；改 `unique_within: root` 并按 entry 计数，见 `docs/spec-profile-model.md` §4.1、§5.3。
15. **真机漂移**：**已定（D-016）**。新增 `packout profile probe`，见 §11.1。

# profile 规格 v2.0（一）：模型与字段

状态：草案。适用于 `packout` P0。相关决策：D-002（只读）、D-004（声明式 + selftest）、D-010、D-013–D-016（模型 v2：M1–M9 与语料裁决）、D-017（JSONC）、D-024、D-028。

本文是 `docs/spec-profile.md` 的第 1–7 章（模型与字段）。内置 profile 见 `docs/spec-profile-builtin.md`（§8）；校验规则、错误码与 CLI 见 `docs/spec-profile-validation.md`（§9–§12）。三份文档的章节编号连续，合计构成完整规格。

---

## 1. 术语

| 术语 | 含义 |
|---|---|
| root | profile 声明的一个命名锚点（如 `home`、`repo`、`codex`、`appdata`），条目路径相对于它；root 名是 role，可由 `--root` 产生多个实例（`repo`、`repo#2`） |
| root 实例 | role 的一次具体绑定；manifest 的 `root` 记实例名 |
| entry | 一条声明，描述一个或一组位置及其分类 |
| selector | 条目内的路径或 glob 表达式集合；part 内的 selector 还可以是文件内选择器 |
| part | entry 内对同一文件的一段结构化区域（JSON 指针、行正则、TOML 段），有独立的层/抽取/含密结论 |
| catch-all | 兜底条目，收未被任何 entry 命中的残留，confidence 固定 0.5 |
| companion | 与主文件同属一个逻辑库的伴生文件（如 sqlite 的 `-wal`、`-shm`），不单独成 Unit |
| 机器派生路径 | 由别的值转换得到、换机后必变的路径（slug、worktree 目录名、JSON 键路径） |
| Unit | 引擎由一个具体文件/位置/part 产出的清单记录（见 `docs/spec-manifest.md`） |
| 内置 profile | 随二进制通过 `go:embed` 分发、只读的 profile |
| 用户 profile | 用户放在 profile 目录里、可覆盖内置项的 profile |

---

## 2. 文件格式

### 2.1 结论：JSONC（hujson）

profile 使用 **JSONC**：标准 JSON 加行注释、块注释与尾逗号。解析器固定为 `tailscale/hujson`（`D-017`）。D-010 第 1 条的 spike 闸门已执行：`yaml.v3` 无损写回失败（16 个往返用例挂 11 个：`---` 丢失、CRLF 转 LF、折叠标量被合并、`\u` 转义被反转、注释位置漂移），因此改为 JSONC。

选择 JSONC 的理由：

1. **注释是刚需**。规格要求"路径不确定处标 `// TODO verify`"；`//` 与 `/* */` 原生支持，且 hujson 保留注释位置与空行。
2. **往返保真**。hujson 的 AST 带每个节点的前后 trivia，只改已识别值时可原样拼回；YAML 没有结束偏移，回写必然是整份重排。
3. **少歧义**。没有隐式布尔、锚点、别名、折叠标量，校验器不必实现"受限子集"。
4. **单一心智模型**。manifest 已是 JSONL，profile 用 JSONC 后工具链与评审都只需一种转义规则。

代价与对策：JSONC 没有 YAML 的多行块标量，selftest 里的多行 fixture 改为**外部样本文件**引用（§6），profile 本身不再内嵌文件内容。

**解码一律走 hujson AST，不用 struct 直解。** 加载顺序固定为：`hujson.Parse` → 在 AST 上做类型、枚举与引用校验（校验器按节点 `StartOffset` 换算行列，产出带行列号的诊断）→ 只为已识别字段投影运行期结构；未识别节点连同注释、位置一起留在 `raw` AST，回写时只改对应节点，不重排其余字节。禁止 `encoding/json` 直解后整份 `Marshal`，因为该路径丢注释与格式。

### 2.2 允许的 JSONC 子集

| 允许 | 禁止 |
|---|---|
| 行注释 `//`、块注释 `/* */`（不可嵌套） | 重复键（同一对象内后者静默覆盖的库行为不可依赖） |
| 尾逗号 | 单引号字符串、无引号键 |
| 单个顶层值（必须是对象） | 多个顶层值、`NaN` / `Infinity` |
| 标准 JSON 转义 | BOM、非 UTF-8 字节 |
| CRLF 或 LF | 注释内再出现 `/*` |

- 字符串必须双引号；转义按 RFC 8259；`\u` 序列按写法原样保留，不反转、不重排。`/` 不强制转义。
- 注释可出现在任何允许空白的位置，但不能在字符串内；注释与空行的相对位置属于需保留的格式。
- 数字按 JSON 语法（无前导 `+`、无十六进制、无前导零）。
- 所有枚举值、版本号都是字符串（如 `"layer": "L2"`、`"schema_version": "2.0"`）；布尔用 `true`/`false`。
- 文件编码 UTF-8（无 BOM），换行 LF 或 CRLF 均可并原样保留，路径分隔符一律 `/`。

文件扩展名 `.jsonc`，SHA-256 记录进 manifest header。用户手写的 `.json` 若内容是 JSONC 也接受，按扩展名之外的嗅探结果处理并在报告中标注。

### 2.3 hujson 往返要求

实现加载器之前先固定 16 个往返用例（D-017 的复现集），全部纳入 `internal/profile` 的测试：

1. 行注释在键前、值后、行尾三种位置；
2. 块注释单行与跨行；
3. CRLF 全文；
4. 尾逗号在对象与数组；
5. `\u00e9` 等转义保持原写法；
6. 空行组；
7. 顶层前后各有一段注释；
8. 只改一个已识别字段后，未改区域逐字节不变；
9. 增删一个未知键后，其余未知键顺序不变。

任一失败即回退到"只读 JSONC + 单独维护格式化"的实现，并记入 PR；不再回 YAML（D-017 已定）。

## 3. 顶层结构

```jsonc
{
  "schema_version": "2.0",
  "name": "claude-code",
  "title": "Claude Code",
  "vendor": "Anthropic",
  "notes": "自由文本，可写工具版本范围与已知坑。",
  "applies_to": { "os": ["windows", "darwin", "linux"] },
  "roots": {},
  "defaults": {},
  "max_bytes_total": 137438953472,
  "scan": "default",
  "entries": [],
  "selftest": {}
}
```

### 3.1 顶层字段

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `schema_version` | 是 | string `MAJOR.MINOR` | 见 §7 |
| `name` | 是 | string | 稳定标识，`^[a-z0-9][a-z0-9-]{0,63}$`；用户 profile 与内置同名即覆盖 |
| `title` | 是 | string | 人读名 |
| `vendor` | 否 | string | 厂商名，供报告分组 |
| `notes` | 否 | string | 审查注记；不参与匹配 |
| `applies_to.os` | 是 | `[windows\|darwin\|linux]` | 空数组合法，表示仅由 named-location 的 os 限定 |
| `roots` | 是 | object<string, string \| object<os,string>> | 至少一个；见 §4.1 |
| `defaults` | 否 | object | 条目默认值：`max_bytes_inline`、`max_bytes_structure`、`max_bytes_total`、`follow_symlinks`、`expand`、`max_depth`、`exclude`、`scan` |
| `max_bytes_total` | 否 | int | profile 级累计读取上限，默认 128 GiB（137438953472），上限 4 TiB；触发后余下条目只记元数据并记 `budget_exceeded`，见 §5.8 |
| `scan` | 否 | enum | `default` / `strict`；profile 级扫描策略，条目可覆盖，见 §5.4 |
| `entries` | 是 | sequence | 至少一条；见 §5 |
| `selftest` | 是 | object | 见 §6 |

未知顶层字段必须保留（§7.2），并按字面量原样回写。

---

## 4. 路径语义

### 4.1 roots 与 root 实例

root 名是 profile 内的稳定 role，不是某台机器的具体目录。root 的值是一个带变量展开的绝对路径模板，或按 OS 分别给出：

```jsonc
{
  "roots": {
    "home": {
      "windows": "%USERPROFILE%",
      "darwin": "$HOME",
      "linux": "$HOME"
    },
    "appdata": {
      "windows": "%APPDATA%",
      "darwin": "$HOME/Library/Application Support",
      "linux": "${XDG_CONFIG_HOME:-$HOME/.config}"
    },
    "localappdata": {
      "windows": "%LOCALAPPDATA%",
      "darwin": "$HOME/Library/Caches",
      "linux": "${XDG_CACHE_HOME:-$HOME/.cache}"
    },
    "repo": "${REPO_ROOT}",
    "codex": {
      "windows": "${CODEX_HOME:-%USERPROFILE%\\.codex}",
      "darwin": "${CODEX_HOME:-$HOME/.codex}",
      "linux": "${CODEX_HOME:-$HOME/.codex}"
    }
  }
}
```

`appdata` 与 `localappdata` 是保留 root 名：前者是配置根，后者是本机缓存/大对象根。profile 可以重新定义它们的默认模板，但不得改变语义。条目命中 `localappdata` 时默认层不因 root 名变化。

**多实例。** 一次扫描可重复给出 `--root role=PATH`（`D-015` 第 1 条）：

```
packout scan --root repo=D:\Study\Chatrix --root repo=D:\Study\Chatrix\Chatrix
```

- 首个实例名等于 role；同类后续实例自动命名 `role#2`、`role#3`，后缀从 2 起。
- 条目 `root: repo` 应用到该 role 的**全部实例**；`root: "repo#2"` 只应用到指定实例。实例名按字面匹配，不参与 glob。
- `--root role=PATH` 覆盖 profile 中该 role 的模板；role 必须已在 profile 声明，或是保留 root 名，否则 `E-PRF-058`。
- `--root` 也可带 `--root home=…` 等内置 role；未覆盖的 role 按 profile 模板展开。
- 实例名写进 manifest 的 `root`；`id` 派生与 `unique_within` 计数都按实例名区分。
- selftest 的 `selftest.roots` 可绑定任意实例名，见 §6.2。

展开规则：

- `%VAR%`（Windows）与 `$VAR` / `${VAR}`（全部平台）展开环境变量；`${VAR:-default}` 支持缺省值。
- 展开后必须是绝对路径；否则 `E-PRF-030`。
- 展开后执行与 manifest 相同的规范化（`docs/spec-manifest.md` §6），但保留原始拼写用于展示。
- 展开结果在扫描开始时固定，扫描中环境变化不生效。
- 同一 root 解析到不同 profile 的多次扫描复用同一缓存键；不同实例不复用。
- profile 必须至少声明一个 root；实际扫描至少要有一个 role 能展开，否则 `E-PRF-030`。

### 4.2 条目路径

- `path` 相对 root，使用 `/`；`kind: file` 与 `kind: dir` 禁止 glob。
- `glob-group` 的 `paths` 支持 `*`（段内任意）、`?`（段内单字符）、`[a-z]`（字符类）、`**`（跨任意段，含零段）。
- 花括号不展开；需要多模式时用 `paths: []` 列出多条。
- 以 `.` 开头的模式按段匹配隐藏项；`*` 与 `**` 默认**不**匹配以 `.` 开头的段，需显式写 `.*` 或 `**/.*`。
- `path` 可以是绝对路径模板（同样支持 §4.1 的变量展开），用于 root 之外的固定位置，如 `%LOCALAPPDATA%/Claude-3p/...`。绝对路径条目省略 `root`；若同时给出 `root`，绝对路径必须落在该 root 实例内（`E-PRF-059`）。绝对路径不得含 glob，也不得含 `..`。
- 相对 `path` / `paths` 不得含 `..` 越出 root。
- 绝对路径不落在任何已声明 root 下时，Unit 的 `root` 写 `external`，并加 `risk_flags: ["outside_root"]`。
- 条目路径大小写按 §4.4 匹配。
- `kind: catch-all` 既不写 `path` 也不写 `paths`，由 `root` 与可选的 `scope`/`under` 定义范围（§5.2）。

### 4.3 符号链接与 reparse point

- 默认**不跟随**（`follow_symlinks: false`），但仍为链接本身产出一个 Unit，带 `risk_flags: ["symlink"]` 与 `link_target`，target 不分类、不计入大小。
- `follow_symlinks: true` 时：最大深度受 `max_depth` 约束，必须维护访问过的 `(volume_id, file_id)` 集合防环；环检测命中时保留已遍历内容并加 `risk_flags: ["symlink_cycle"]`。
- `dedupe_targets: true` 时，同一 `(volume_id, file_id)` 只产出一个 Unit，后到的命中记 `target_duplicate` note；不开启时按路径各产一个。
- Windows junction / mount point / 其他 reparse tag 与符号链接同等处理，不因 tag 是 junction 就跟随。
- `dir` 条目撞上 reparse point 时，按"链接"产出而非把目标内容并入。

### 4.4 大小写

- 匹配大小写策略由**卷**决定，而非 OS：Windows NTFS 默认不敏感，macOS APFS 默认不敏感，Linux 敏感；若卷可探测为 case-sensitive（如 Windows 上的 WSL 卷），按敏感处理。
- 无法稳定探测的卷（WSL、网络重定向、部分 FUSE）**必须由用户 profile 显式声明** `case_sensitive`，不靠猜；报告对这类命中标注"按用户声明处理"（`D-010` 第 5 条）。
- profile 可用条目级 `case_sensitive: true|false` 覆盖探测结果，但必须在 `notes` 说明理由。
- 在 case-insensitive 卷上，同一 glob 命中仅大小写不同的两个路径时，两个都产出 Unit，并加 `risk_flags: ["case_collision"]`。
- 规范化键按 manifest §6.3 的全量 case folding（`x/text/cases`）生成，不做 locale 相关映射。

### 4.5 Windows 长路径

- profile 中的路径写普通形式（`C:\Users\...`），不写 `\\?\` 前缀。
- 引擎在调用 `os.Lstat` 等之前，对超过 240 字符的路径转换为 `\\?\` / `\\?\UNC\` 扩展形式；Unit 的 `path` 字段仍写普通形式。
- 长路径命中时加 `risk_flags: ["long_path"]`。
- 超过 32,767 字符的路径以 manifest §6.5 为准：记 `path_too_long` note、不产出 Unit、不计错误（`W-PRF-125`，`D-015` 第 12 条）。

### 4.6 排除

`exclude` 是相对 entry 路径（`file`/`dir`）或相对 root（`glob-group` 的负向补齐）的 glob，在下降**之前**求值。默认排除集合固定为：

```jsonc
{
  "exclude": [
    "**/node_modules/**",
    "**/.git",
    "**/.git/**"
  ]
}
```

两项 `.git` 必须并列：worktree 的 `.git` 是普通文件（内容是 `gitdir: …`），只写 `**/.git/**` 时它不被排除，会产出一个含绝对 gitdir 的 Unit（`D-013`）。`**/.git` 覆盖文件与目录本身，`**/.git/**` 覆盖目录内容。默认排除同样作用于 catch-all 的残留判定，残留 Unit 不含被默认排除的路径。

`exclude` 只能收窄，不能把 entry 范围扩到 root 之外。排除命中的文件不产出 Unit；若某个 `dir` 条目整体被排除，产出一个聚合 Unit 并加 `risk_flags: ["aggregated"]`。

---

## 5. 条目

```jsonc
{
  "entries": [
    {
      "id": "settings-local-repo",
      "kind": "file",
      "root": "repo",
      "path": ".claude/settings.local.json",
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "unique_within": "root",
      "priority": 20,
      "max_bytes_inline": 262144,
      "signals": [
        {
          "src": "official_docs",
          "note": "Claude Code 的项目级本地覆盖配置，首次写入会加入全局 gitignore",
          "url": "https://code.claude.com/docs/en/settings"
        }
      ]
    }
  ]
}
```

### 5.1 字段表

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `id` | 是 | string `^[a-z0-9][a-z0-9-]{0,63}$` | profile 内唯一 |
| `kind` | 是 | enum | `file` / `dir` / `glob-group` / `named-location` / `catch-all` |
| `root` | 视 kind | string | 引用已声明的 root role 或实例名；`named-location` 可省略；绝对路径条目省略 |
| `path` | `file`/`dir` 必填 | string | 相对 root，或绝对路径模板，见 §4.2 |
| `paths` | `glob-group` 必填 | `[string]` | 至少一条 |
| `locator` | `named-location` 必填 | string \| object<os,string> | 见 §5.5 |
| `probe` | 否 | string \| object<os,string> | 覆盖由 scheme 推导的探测方式，见 §5.5 |
| `os` | 否 | `[os]` | 条目级平台限定；缺省继承 `applies_to.os` |
| `layer` | 是 | `"L0"`…`"L5"` | 见 §5.3；`catch-all` 缺省 `L2` |
| `secret` | 是 | enum | `none` / `scan` / `reference` / `restore` / `relogin`，见 §5.4；`catch-all` 缺省 `none` |
| `extractor` | 是 | enum | `none` / `raw-ref` / `template` / `keys-only` / `digest`，见 §5.6；`catch-all` 缺省 `none` |
| `redact` | 否 | object | 模板脱敏参数，仅用于 `template` / `keys-only`，见 §5.6 |
| `selftest_exempt` | 否 | string | 豁免 selftest 覆盖的理由；仅用于确实无法覆盖的 entry，见 §6.1 |
| `scan` | 否 | enum | `default` / `strict`；覆盖 profile 级策略，仅 `secret: scan` 可用，见 §5.4 |
| `signals` | 是 | sequence | 至少一条，形如 `{src, note, url?}`，见 §5.7；**`catch-all` 可为空数组**——引擎会在其 Unit 上自动注入 `residual` signal（§5.2） |
| `priority` | 否 | int -1000–1000 | 默认 0，大者优先；仅在同一路径被多条 entry 命中时参与，catch-all 禁止写（`E-PRF-073`），见 §5.2.1 |
| `parts` | 否 | sequence | 文件内分层，仅 `kind: file`（`E-PRF-072`）；见 §5.9 |
| `parts_uncovered` | 否 | enum | `keep` / `note` / `residual`，默认 `note`；未被任何 part 覆盖的剩余键如何产出，仅用于带 `parts` 的条目；见 §5.9 |
| `path_semantics` | 否 | enum | `literal`（默认）/ `machine_derived`，见 §5.10 |
| `derived_from` | 否 | enum | `repo_slug` / `git_worktree_of` / `json_path_key`；`machine_derived` 必填 |
| `churn` | 否 | enum | `low`（默认）/ `high`；高重写频率文件不重复全量读，见 §5.8 |
| `needed_by` | 否 | `[enum]` | `rewind` / `statusline` / `resume` / `mcp` / `daemon` / `plugins`，见 §5.3.1 |
| `companions` | 否 | `[suffix]` | 伴生文件后缀，如 `-wal`、`-shm`；一个逻辑库一个 Unit，见 §5.11 |
| `side_effects` | 否 | `[enum]` | 引擎只读产生的文件系统副作用，目前仅 `shm_created`，见 §5.11 |
| `open_as` | 否 | enum | `none`（默认）/ `text` / `sqlite-ro`；引擎打开内容的方式，`shm_created` 的前提，见 §5.11 |
| `opaque_content` | 否 | bool | 声明内容按不透明字节处理（真二进制或不可解析的大文本）；`secret: scan` 可配 `max_bytes_inline: 0`，见 §5.4 |
| `max_bytes_inline` | 否 | int | 内容/值读取预算，覆盖 profile 默认；见 §5.8 |
| `max_bytes_structure` | 否 | int | 结构键读取预算，与 `max_bytes_inline` 分开；见 §5.8 |
| `max_bytes_total` | 否 | int | 该条目（含全部命中与伴生文件）的累计读取预算；见 §5.8 |
| `expand` | 否 | enum | `per-file`（默认）/ `aggregate` |
| `max_depth` | 否 | int 1–64 | 默认 32 |
| `exclude` | 否 | `[glob]` | 追加到默认排除 |
| `follow_symlinks` | 否 | bool | 默认 false |
| `dedupe_targets` | 否 | bool | 默认 false；跟随链接时按 target `(volume_id, file_id)` 去重，见 §4.3 |
| `case_sensitive` | 否 | bool | 覆盖卷探测 |
| `unique_within` | 否 | enum | 目前只接受 `root`；弃用 `l3_if_unique`，见 §5.3 |
| `aggregate_above` | 否 | int | 命中数超过该值时改为聚合 Unit，默认 10000（暂定） |
| `sessions` | 否 | bool | 默认 false；标记该 `glob-group` 属于会话内容：`scan --with-sessions` 时逐文件出行，`export` 按 `raw-ref` 保留原字节，见 §5.6。仅 `glob-group` 可用（`E-PRF-074`） |
| `export_group` | 否 | string | 导出到 `config/` 的子目录名 |
| `notes` | 否 | string | 条目说明 |

`layer`、`secret`、`extractor`、`signals` 在含 `parts` 的条目上是**默认值**：没有覆盖它们的 part 继承条目值；part 覆盖只对该 part 生效。其余条目级字段不被 part 覆盖。`catch-all` 的 `root` 必填，且 `layer` 缺省 L2、confidence 固定 0.5。

### 5.2 kind

| kind | 语义 | 产出 |
|---|---|---|
| `file` | 单个确定路径 | 0 或 1 个 Unit |
| `dir` | 目录树，受 `expand`/`max_depth`/`exclude` 约束 | 每个后代一个 Unit，或一个聚合 Unit |
| `glob-group` | 多条 glob 的合集 | 每个命中一个 Unit，共享条目分类 |
| `named-location` | 非文件系统的 OS 级位置：凭据库、keychain、环境变量、注册表键 | 0 或 1 个 Unit，`path` 写 URI 形式 |
| `catch-all` | 某个 root 内**未被任何非 catch-all entry 命中**的残留 | 每个残留顶层项一个 Unit；见 §5.2.1 |

`catch-all` 是唯一豁免"无信号不成结论"的 kind（`D-014`）：profile 可以不给 `signals`，但引擎会为每个 catch-all Unit **自动注入**一条 `residual` signal（`src: filesystem_stat`，note 写明"未被任何 entry 命中"），因此 `signals: []` 在 profile 里合法、在 manifest 里不合法为空（`D-021` 第 4 条）。Unit 的 confidence 固定为 0.5，层缺省 L2，因此按 manifest §5.2 只能 `keep`。它的用途是让漏配的路径可见，而不是替它们下结论。

catch-all 可限定范围：

| 字段 | 必填 | 说明 |
|---|---|---|
| `scope` | 否 | `root`（默认，整个 root 实例） / `subtree`（仅 `under` 之下） |
| `under` | `scope: subtree` 必填 | 相对 root 的子路径，不含 glob、不含 `..`；不得指向单个文件 |
| `unique_within` | 否 | catch-all 禁止使用（固定 L2，`E-PRF-047`） |

- `under` 必须落在 root 实例内（`E-PRF-070`）；`scope: root` 时写 `under` 也报错。
- 同一 `(profile, root 实例)` 默认只允许一条 catch-all；允许共存的条件是**除至多一条 whole-root 外全部用 `scope: subtree`，且各 `under` 两两不互为前缀**（`.claude` 与 `.claude/plugins` 算重叠）。范围重叠时取 `under` 更深者（`E-PRF-037`）。
- whole-root catch-all 跳过被任一同 root 的 subtree catch-all 覆盖的路径。
- `home` root 的 catch-all 应当限定到产品目录（如 `under: ".claude"`），否则会扫整个用户目录。

#### 5.2.1 同一路径被多条 entry 命中

重叠是常态（整目录条目与其中具体文件），因此必须确定唯一赢家。按以下顺序裁决，前一步已分出胜负即停止：

1. **`priority` 大者**。缺省 0；catch-all 禁止写 `priority`（`E-PRF-073`）。
2. **selector 具体度**：非 glob 的确定路径 > glob；glob 之间按字面段更多者、再按模式更长者。
3. 仍相等时**两条 entry 都产出 Unit**，并各记一条 `priority_tie` note（`W-PRF-122`），便于作者合并。

`catch-all` 只在残留遍求值，不参与声明遍竞争（也无 `priority` 可参与）：一条路径只要有任一非 catch-all entry 命中，就不进 catch-all。

残留判定**跨全部扫描 root 与 profile 全局进行**，按 `path_key` 去重：

- 任一 root 实例的任一非 catch-all entry 命中某路径后，该路径不再算残留，即使命中它的 root 不是 catch-all 所属实例。
- 任何 root 实例的根路径本身视为已覆盖，不产生残留 Unit；其下后代仍逐路径判定。
- 同一路径同时落在多个 catch-all 范围内时只产出一个 Unit，归属 `under` 最长者（同长取 `root_index` 小者），并各记一条 `residual_deduplicated` note。
- `named-location` 的 `file:` locator 若指向某路径，该路径也算已覆盖，不进残留。

残留按顶层未命中项产出：残留文件各成一个 catch-all Unit；残留目录本身成一个聚合 catch-all Unit，其下未被其他 entry 命中的后代计入 aggregate_count（`D-015` 第 20 条）。目录内部分被其他 entry 命中时，只把未命中的后代计入，目录本身仍作为残留项出现；`max_depth` 截断时另记 `depth_truncated` note，`aggregate_count` 只计已遍历部分。**伴生文件不参与残留判定**：主文件被命中时，其全部伴生文件视为已覆盖（§5.11）。catch-all 的默认排除沿用 §4.6。

part 是 entry **内部**的分层，不参与 entry 之间的优先级：先按本节选出 entry，再按 §5.9 在 parts 之间分配。

`named-location` 的 `probe` 字段可声明探测方式：`wincred` / `keychain` / `env` / `registry` / `file-probe`（后者用于"某文件存在即视为该 OS 存储存在"）。`probe` 可省略，缺省由 locator 的 scheme 推导；按 OS 不同的 locator 可将 `probe` 写成 map。P0 允许探测失败；失败时产出 `risk_flags: ["probe_unavailable"]` 并记入扫描统计，不产生内容 Unit。P0 即使探测成功也只记存在性，不读取凭据内容（`D-010` 第 2 条）。

### 5.3 layer

| 值 | 含义 | 典型条目 |
|---|---|---|
| `L0` | 完全可再生，不迁不备 | 缓存、日志、临时快照 |
| `L1` | 有 lockfile/清单可重装 | 插件、依赖树 |
| `L2` | 需按配置恢复 | 设置、规则 |
| `L3` | 唯一不可再生 | 会话历史、自定义 skill、密钥 |
| `L4` | 机器绑定，应重建 | 绝对路径索引、机器 ID |
| `L5` | 只能人工重登 | keychain、cookie、passkey、OAuth 凭据 |

`unique_within: root` 表示：按 **entry** 在**每个 root 实例内**分别计数不同 `path_key`；某实例内该 entry 恰命中 1 个路径时，该实例下的命中运行时升为 L3，否则保持声明层（`D-015` 第 10 条、`D-013` 的 M7）。

- 计数单位是不同路径，不是 Unit 数；同一路径被别的 entry 匹配不影响本 entry 的计数。
- 多实例各自计数：`repo` 与 `repo#2` 各命中 1 份 `settings.local.json` 时，两份都升 L3；某实例命中 2 份时只有该实例不升。
- 绝对路径条目与 named-location 属于实例名 `external` / `os`，同实例内合并计数。
- 该字段只允许用于声明层为 `L2` 的条目；非 `L2` 条目使用即 `E-PRF-026`。取值只接受 `root`；其它值，以及 `catch-all` 使用 `unique_within`，均为 `E-PRF-047`（`D-028` 第 3 条）。
- 升层后在 Unit 的 signals 里追加一条 `profile_rule`，写明计数与实例名；报告另列升层清单。
- v1 的 `l3_if_unique: true` 迁移为 `unique_within: root`，见 §7.3。

#### 5.3.1 needed_by 与删除代价

`needed_by` 列出消费该路径的功能：`rewind`（`/rewind` 检查点）、`statusline`（`statusLine.command`）、`resume`（会话回放）、`mcp`（MCP server 配置）、`daemon`（后台进程句柄）、`plugins`（插件运行时）。

`L0 + needed_by` 是合法组合，语义是"可再生，但删除会让某个功能丢状态"。此时层仍 L0、`proposed_action` 仍是 `delete`，另加 `risk_flags: ["deletion_cost"]`；报告必须把这些 Unit 单独列一节，不能混在普通 L0 删除清单里。`needed_by` 与 `layer` 不互相约束，其它层也可标注。未知值降级为 `unknown_enum` 并警告（`W-PRF-123`）。

### 5.4 secret

| 值 | 含义 | 后续动作 |
|---|---|---|
| `none` | 不含密 | 不读内容做密检测 |
| `scan` | 可能含明文凭据，需检测 | 命中后按命中类型三分，见下 |
| `reference` | 值本身是指针（环境变量名、路径、密钥环条目名） | 导出时原样保留指针 |
| `restore` | 自包含、可脱离机器恢复的密材 | 导出后进 `secrets.age` |
| `relogin` | 不迁移、只能人工重登 | 进报告 L5 清单 |

`scan` 是唯一允许"运行时再分类"的值；`reference` / `restore` / `relogin` 是确定结论。命中项的三分结果记录在 manifest 的 `secret.hits[].class`，不改变 entry 声明。

`scan: strict` 是可选的策略槽：profile 级默认 `default`，条目级可覆盖，仅对 `secret: scan` 的条目生效（`E-PRF-028`）。`strict` 下内容检测**只认已知前缀与键名，不跑熵判定**，用于误报高的条目；命中仍按三分记录。strict 不改变 `secret` 的声明值，也不豁免 `max_bytes_inline > 0`。两级都未写时按 `default`；未知取值降级为 `default` 并记 `W-PRF-102`。

`secret` 与 `layer` 的约束：

- `relogin` 必须搭配 `L5`（`E-PRF-040`）。
- `restore` 必须搭配 `L3`（`E-PRF-041`）；若条目同时含 device-bound 内容，可在 `notes` 说明并改用 `scan`。
- `scan` 必须 `max_bytes_inline > 0`，除非条目声明 `opaque_content: true`（`E-PRF-042`）。二进制的 `scan` 只记存在性与大小，不解析内容、`hits` 恒为空；Unit 加 `risk_flags: ["opaque_content", "content_partial"]`，并记 `binary_presence_only` note；声明了 `opaque_content` 且 `max_bytes_inline: 0`（一个字节都不读）时改记 `content_not_read`。若同时给了正数 `max_bytes_inline`，则只对头部做前缀/正则检测，仍不跑熵判定。
- `opaque_content: true` 表示不解析内容（真二进制、或只按流式哈希处理的大文本）；用 `template` 时按字节解码失败即退化为 `digest` 并记 note。`binary` 是 v2 冻结前的旧名，读入时映射为 `opaque_content` 并记 `W-PRF-101`（`D-021` 第 3 条）。
- `secret != none` 的条目 `extractor` 不得为 `raw-ref` 且不带脱敏（`E-PRF-043`）。
- `catch-all` 的 `secret` 缺省 `none`；要覆盖残留中的凭据必须显式写 `scan` 并给正数预算。

### 5.5 named-location

`locator` 写 URI 形式，按 OS 分列：

```jsonc
{
  "entries": [
    {
      "id": "oauth-credential-store",
      "kind": "named-location",
      "os": ["darwin", "windows"],
      "locator": {
        "darwin": "keychain:generic-password?service=Claude Code-credentials",
        "windows": "wincred:Claude Code-credentials"
      },
      "probe": {
        "darwin": "keychain",
        "windows": "wincred"
      },
      "layer": "L5",
      "secret": "relogin",
      "extractor": "digest",
      "signals": [
        { "src": "official_docs", "note": "OAuth 凭据存于系统凭据库", "url": "https://code.claude.com/docs/en/setup" }
      ]
    }
  ]
}
```

URI scheme 与探测方式的对应固定为：`keychain:`→`keychain`、`wincred:`→`wincred`、`env:`→`env`、`registry:`→`registry`、`file:`→`file-probe`。显式 `probe` 必须与 scheme 一致，否则 `E-PRF-060`。`file:` 的 locator 必须是绝对路径模板。

### 5.6 extractor

| extractor | 行为 | 适用 |
|---|---|---|
| `none` | 不导出，manifest 只有元数据 | L0 |
| `raw-ref` | 导出时不改写内容，manifest 记绝对路径 | 体积小、无密的 L3 文本 |
| `template` | 导出到 `config/` 前按脱敏规则替换敏感值，保留结构与键 | 设置、规则 |
| `keys-only` | 只导出键名/结构，不含任何值 | 大型 JSON、状态文件 |
| `digest` | 只记哈希与大小，不导出 | 大文件、二进制、命名的 OS 存储 |

`template` 的脱敏参数：

```jsonc
{
  "extractor": "template",
  "redact": {
    "json_pointer": ["/env/ANTHROPIC_AUTH_TOKEN", "/mcpServers/*/env"],
    "key_pattern": ["(?i).*(token|secret|password|api[_-]?key).*"],
    "replacement": "«REDACTED»"
  }
}
```

`sessions: true` 只标记"这是会话内容"，不改变扫描期分类：manifest 仍按条目自己的 `extractor` 记结论。它影响两个下游行为，且只在扫描以 `--with-sessions` 进行时生效（header `inputs.options.with_sessions` 为 true 时）：扫描不因 `max_bytes_total`/`aggregate_above` 聚合这些条目，逐文件出行（`max_bytes_total` 退化为行数上限）；导出把这些条目的内容按 `raw-ref` 原字节保留。未开启时行为与普通条目完全相同。

`redact` 只对 `template` / `keys-only` 生效；`digest` 天然无内容。未声明 `redact` 的 `template` 视为"原样复制但去缩进"，校验器给出警告（`W-PRF-110`）。

`redact` 的作用域按文件格式固定，三种选择器都**只匹配位置，不改写定位点本身**：

| 键 | 作用域 | 替换单位 |
|---|---|---|
| `json_pointer` | JSON 文档的 RFC 6901 指针；`*` 匹配单层全部子键 | 指针选中的整个值替换为 `replacement` |
| `key_pattern` | JSON 的**对象键名**；dotenv/`KEY=VALUE` 文本的**行首键名**（`^` 到第一个 `=` 或 `:` 之前，去首尾空白）；TOML 的**键路径**（段路径，不含值）。大小写按正则自身控制 | 该键对应的值替换为 `replacement`，键名保留 |
| `toml_section` | TOML 段路径 | 段内全部标量值替换 |

`key_pattern` 是 Go RE2 正则，按"完整键名/键路径"做全匹配，不是子串搜索；需要子串时自己写 `.*`。作用域外的同名字样不改。dotenv 行首无键的裸行不匹配。part 的 `toml_section` selector 与 `redact.toml_section` 不同：前者选层，后者选脱敏范围。多 profile 合并时脱敏规则不跨 profile 合并。

### 5.7 signals

每条 signal 说明"为什么这个条目是这个结论"，`src` 取值：

| src | 含义 |
|---|---|
| `official_docs` | 厂商文档明确描述该路径的用途 |
| `observed_behavior` | 本机复现观察（`note` 里写版本） |
| `repository_practice` | 仓库内实际用法统计 |
| `file_format` | 文件格式本身可判定（如 lockfile） |
| `vendor_policy` | 厂商声明的不迁移策略 |

`note` 必填且非空；`url` 可选但 `official_docs` 必填。`// TODO verify` 只能出现在 profile 行尾注释里，不能替代 `note`。

### 5.8 体积与展开预算

| 字段 | 默认 | 上限 | 作用 |
|---|---|---|---|
| `max_bytes_inline` | 65536 | 8388608 | 引擎最多读取多少字节做内容检测/模板化；`0` 表示不读值 |
| `max_bytes_structure` | 262144 | 8388608 | 只保留 JSON/TOML **结构键路径**、不保留值的预算；与 `max_bytes_inline` 分开。它不保证 I/O 跳过（JSON 必须顺序读字节），只保证不保留值 |
| `max_bytes_total` | profile 级默认的 1/16 | profile 级上限 | 单条目跨全部命中与伴生文件的累计读取字节 |
| `churn` | `low` | — | `high` 时同一扫描内按 `file_id` 缓存结构解析结果，不因 mtime 变化重复全量读 |
| `expand` | `per-file` | — | `aggregate` 时整棵子树一个 Unit |
| `max_depth` | 32 | 64 | 下降深度 |
| `aggregate_above` | 10000（暂定） | — | 命中数超限转聚合，防单条目爆炸；实测后定（`D-010` 第 9 条） |
| `exclude` | 默认三项 | — | 收窄范围 |

三种预算互不替代：

- `max_bytes_inline` 管"读值"；`max_bytes_structure` 管"只留键路径"（`keys-only`、`parts` 的指针解析、`churn: high` 的键集发现）。结构读取仍要过一遍字节，但不得保留值；结构预算耗尽即停止并记 `budget_exceeded`，已解析的键照常产出。
- `max_bytes_total` 是条目级总额。条目（含 glob 展开、全部伴生文件）累计读取超过它时，当前文件照常完成，其后命中转聚合 Unit 并加 `risk_flags: ["aggregated", "oversized"]`、记 `budget_exceeded`；不中止扫描。
- profile 级 `max_bytes_total` 是全局总额。耗尽后余下条目只产出元数据 Unit（`size_*` 保留，`fingerprint.scope: shape`、`content_partial`），footer `complete: false`，退出码 0。
- 超 `max_bytes_inline` 的文件仍产出 Unit，仅内容检测对前 N 字节执行，并加 `risk_flags: ["oversized", "content_partial"]`。
- 二进制文件（NUL 字节占比 > 1%）不执行模板化；声明 `opaque_content: true` 时连内容检测也跳过，除非显式给了正数预算。

#### 5.9 parts

`parts` 把**一个文件**切成互不重叠的几段，每段独立分类。只有 `kind: file` 可以带 parts（`E-PRF-072`）。

```jsonc
{
  "id": "claude-json",
  "kind": "file",
  "root": "home",
  "path": ".claude.json",
  "layer": "L2",
  "secret": "none",
  "extractor": "keys-only",
  "churn": "high",
  "max_bytes_inline": 0,
  "max_bytes_structure": 1048576,
  "max_bytes_total": 2097152,
  "priority": 30,
  "signals": [
    { "src": "observed_behavior", "note": "顶层混合状态文件，约 4–10 分钟整体重写一次；按 parts 分派层" }
  ],
  "parts_uncovered": "keep",
  "parts": [
    {
      "id": "machine-identity",
      "selector": { "json_pointer": "/machineID" },
      "layer": "L4",
      "secret": "none",
      "extractor": "digest",
      "needed_by": ["daemon"]
    },
    {
      "id": "user-identity",
      "selector": { "json_pointer": "/userID" },
      "layer": "L4",
      "secret": "none",
      "extractor": "digest"
    },
    {
      "id": "project-index",
      "selector": { "json_pointer": "/projects" },
      "layer": "L4",
      "secret": "none",
      "extractor": "keys-only",
      "path_semantics": "machine_derived",
      "derived_from": "json_path_key",
      "notes": "键为绝对路径；每个键产出一个 origin，可反查 slug"
    },
    {
      "id": "project-history",
      "selector": { "json_pointer": "/projects/*/history" },
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "max_bytes_inline": 65536
    },
    {
      "id": "mcp-servers",
      "selector": { "json_pointer": "/mcpServers" },
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "max_bytes_inline": 65536
    }
  ]
}
```

每个 part 字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `id` | 是 | `^[a-z0-9][a-z0-9-]{0,63}$`，entry 内唯一 |
| `selector` | 是 | 恰含 `json_pointer` / `line_pattern` / `toml_section` 之一；同一 entry 的 parts 必须同一种 |
| `layer` / `secret` / `extractor` / `signals` | 否 | 覆盖条目默认值；part 的 signals 与条目 signals 求并集 |
| `redact` / `max_bytes_inline` / `max_bytes_structure` / `needed_by` / `notes` | 否 | 同名字段，只作用于该 part |
| `path_semantics` / `derived_from` | 否 | part 级派生语义，覆盖并取代条目值；规则同 §5.10（`E-PRF-036` 不再禁写） |
| `origin` / `origin_path_key` | 否 | 派生来源的原始值与折叠键；可由引擎按选中键自动填充，见 §5.10 |

- `json_pointer` 是按 RFC 6901 的绝对指针，额外允许单段 `*` 匹配该层全部子键；`line_pattern` 是 Go RE2 正则，逐行匹配；`toml_section` 是 TOML 段路径，允许 `*`。
- **重叠禁止**（`D-013` 的 M1）：两个 selector 不得选中同一值。指针/段路径的包含关系算重叠，唯一例外是祖先 part 的 `extractor` 为 `keys-only`——此时它只记键名，子 part 仍可选中其下值。行正则的重叠在加载期无法判定，运行时同一行被多个 part 匹配时按 part 顺序取首个并记 `part_overlap` note；`E-PRF-034` 覆盖可静态判定的情况。
- 每个 part 产出独立 Unit，`part_id` 必填（manifest §4.1）。part Unit 的 `path` 仍是物理文件路径，`file_id` 共享；`size_apparent` 为选中值规范化后的字节数，`size_alloc` 为 null，`fingerprint` 只覆盖该段。
- entry 声明 `secret: scan` 而某 part 没有覆盖时，该 part 继承 scan 并受关联预算约束。
- 每个声明了却零命中的 part 单独记一条 `part_missing` note（带 `part_id`），不得静默消失。文件不是所声明格式、或 part 一个都没命中时，另外产出一个 entry 级 Unit，加 `risk_flags: ["content_partial"]` 并记 `part_missing` note。
- **剩余值兜底**（`D-024` 第 1 条）：指针/段路径未选中、且不在 keys-only 祖先之下的键路径称为"未覆盖剩余"。`parts_uncovered` 决定其产出：

  | 值 | 行为 |
  |---|---|
  | `note`（默认） | 每个文件记一条 `part_uncovered` note，含未覆盖键数与前 32 个键路径；不产出 Unit |
  | `keep` | 每个未覆盖的**顶层键**产出一个 part Unit，`part_id` 固定为保留值 `uncovered`，继承条目 layer/secret/extractor；值不读，结构只留键路径 |
  | `residual` | 同 `keep`，但结论同 catch-all：`layer: L2`、`confidence: 0.500`、`action: keep`，并加 `risk_flags: ["residual", "low_confidence"]` |

  `uncovered` 是保留 part id，不得在 `parts` 里声明（`E-PRF-035`）；这些 Unit 不受"part 必须被 selftest 覆盖"约束（`E-PRF-057`）。`parts_uncovered` 只能出现在带 parts 的条目上（`E-PRF-068`）。未覆盖判定依赖结构解析，预算耗尽时记 `budget_exceeded` + `content_partial`，已解析部分照常产出。
- **指纹**：part Unit 的 `fingerprint.scope` 默认为 `full`；part 的 `extractor` 为 `keys-only` 时**必须**用 `scope: keys`（键路径排序摘要），不得为满足 `full` 去读值，因此与条目 `max_bytes_inline: 0` 相容（manifest §4.5，`D-024` 第 2 条）。既无值也无键可读时 `scope` 与 `value` 均为 `null` 并加 `content_partial`。
- part 级预算耗尽只作用于该 part：记 `budget_exceeded` + `content_partial`，已解析 part 照常产出；条目级 `max_bytes_total` 耗尽后余下 part 全部转 `uncovered` 处理。

#### 5.10 path_semantics 与 derived_from

- `path_semantics: literal`（默认）：路径直接来自写入者的字面值。
- `path_semantics: machine_derived`：路径由别的值转换得到，换机后必然不同或可能碰撞。必须同时给 `derived_from`（`E-PRF-038`）：
  - `repo_slug`：仓库绝对路径经 slug 变换（`\`→`-`、`:`→`--`、`_`/`.`→`-`），如 `.claude/projects/D--Study-Chatrix`；
  - `git_worktree_of`：worktree 的注册路径，源是主 checkout 与随机 worktree 名；
  - `json_path_key`：取自 JSON 对象的绝对路径键，如 `.claude.json` 的 `projects` 键。
- 机器派生只影响结论标记与报告分组，不改变路径匹配：`path` 仍写磁盘原拼写。
- 在 `machine_derived` 条目（或 part）的 Unit 上加 `risk_flags: ["machine_derived_path"]`；当两个不同源路径折叠到同一派生表示时再加 `slug_collision`。
- part 继承条目的 `path_semantics`，也可自行覆盖。`/projects` 这类**键本身**是派生路径的 part 应写 `path_semantics: machine_derived` + `derived_from: json_path_key`；`config.toml` 的 `[projects.'d:/…']` 段同理（`toml_section: "projects.*"`）。
- **origin**（`D-024` 第 3 条）：派生 Unit 记录来源原始值。
  - `origin`：字符串，派生前的原始值，如 `D:/Study/Chatrix`；没有来源时写 `null`。
  - `origin_path_key`：`origin` 按 manifest §6.3 折叠后的比较键；`origin` 为 null 时同为 null。
  - `derived_from: json_path_key` 且 selector 含 `*` 时，每个具体匹配段的键值即 `origin`，由引擎自动填入；part 显式写的 `origin` 优先。
  - 同一 profile 内 `json_path_key` part 的 `(origin → slug)` 集合构成 slug 映射；`derived_from: repo_slug` 的 Unit 若 slug 命中映射则填 `origin`，多个 origin 折叠到同一 slug 时加 `slug_collision`。
  - `origin` 只能出现在 `machine_derived` 上，`origin_path_key` 必须与 `origin` 的折叠结果一致（`E-PRF-069`）。
- `derived_from` 不得出现在 `literal` 条目上（`E-PRF-038`）；`git_worktree_of` 只能用于路径含 `.claude/worktrees/` 的条目（`E-PRF-039`）。part 的 `git_worktree_of` 按其所属条目路径判定。

#### 5.11 companions 与 side_effects

`companions` 声明与主文件同属一个逻辑库的伴生后缀，如 sqlite 的 `-wal`、`-shm`：

```jsonc
{
  "id": "codex-thread-history",
  "kind": "file",
  "root": "codex",
  "path": "thread_history_1.sqlite",
  "companions": ["-wal", "-shm"],
  "open_as": "sqlite-ro",
  "side_effects": ["shm_created"],
  "opaque_content": true,
  "layer": "L3",
  "secret": "scan",
  "extractor": "digest",
  "max_bytes_inline": 0,
  "max_bytes_total": 1073741824,
  "signals": [
    { "src": "observed_behavior", "note": "线程历史库；只读打开仍可能生成 -shm" }
  ]
}
```

- 每个主文件及其存在的前缀匹配伴生文件合并为**一个** Unit；伴生文件不单独成 Unit。主文件或伴生文件被其他 entry 的优先级压过时，整组随主文件走。
- `size_apparent` / `size_alloc` 为全部成员之和；`fingerprint` 覆盖全部成员的 `(后缀, size, mtime, cid)`；`secret` 检在所有成员上做。
- 缺失的伴生后缀不报错，记 `companion_missing` note；没有任何伴生文件时 Unit 与普通文件相同。主文件缺失时不产出伴生 Unit（manifest `E-MAN-063`）。
- **伴生文件不参与 catch-all 残留判定**：主文件被任何 entry 命中时，其全部伴生文件视为已覆盖，不得再产出 residual Unit（`D-024` 第 5 条）。
- 后缀必须匹配 `^-[A-Za-z0-9.]{1,15}$`、互不重复（`E-PRF-045`）；`companions` 只允许用于 `file` / `glob-group`（`E-PRF-044`）。
- `open_as` 声明引擎怎样打开内容：`none`（默认，只按字节读）、`text`（按文本解码，供 `template`/`keys-only`）、`sqlite-ro`（以 SQLite `mode=ro` 打开）。`sqlite-ro` 只允许用于 `file` / `glob-group`（`E-PRF-071`）。
- `side_effects` 声明引擎只读操作**预期会改变**目标树的效果。目前只有 `shm_created`，其**前提是 `open_as: sqlite-ro`**：只按字节哈希不会建 `-shm`，声明 `shm_created` 却没有 `sqlite-ro` 即 `E-PRF-071`。扫描前记下目录项，扫描后若 `-shm` 新建且已声明，不视为不变式违例；未声明却观测到变化时记 `side_effect_unexpected` note。未知值 `E-PRF-061`。

### 5.12 选择类别

`scan` 的 `--preset` / `--include` / `--exclude` 按**类别**选择条目。类别由 entry 派生、不写进 profile：`sessions`（`sessions: true` 或 id 含 `session`）优先于其它；其次是 `memory`（id 含 `memory`、`claude-md`，或以 `-md` 结尾）；再按 id 子串取 `skill` / `agent` / `command` / `rules` / `history` / `plugin`；其余与所有 `catch-all` 为 `config`。元素匹配顺序为 entry id、类别、层（`L0`…`L5`），类别接受复数别名（`skills` 等）。

`minimal` 只含 `config`；`standard`（默认）含除会话外的全部类别（`config`、`memory`、`skill`、`agent`、`command`、`rules`、`history`、`plugin`，保持历史默认不回归）；`full` 另含 `sessions`。因此默认只需为会话内容显式开口。`--include` 在预设之上加，`--exclude` 最后减；未知 preset 或未知元素是用法错误（退出 3），必须列出可用值。

未选中的条目在扫描时不产生 Unit，但每个 entry 恰记一条 `selection_skipped` note 并带原因。会话类另受 `--sessions-since`（mtime 早者跳过）、`--sessions-project`（不在项目列表者跳过）、`--sessions-max-per-project`（每项目按 mtime 新→旧保留，其余跳过并计数）约束。选择只在扫描期生效并写进 header（仅非默认时）；`export` / `report` 只读 header，profile 不再匹配时给警告不失败。

---

## 6. selftest

每个 profile 必须自带一份可在 CI 离线运行的样本。fixture 的**文件内容放在外部样本目录**里，profile 只引用路径（`D-017`；JSONC 不是 YAML，不内嵌块标量）。

```jsonc
{
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    // root 实例名 → 外部 fixture 目录，相对本 profile 文件
    "fixtures": {
      "home": "fixtures/claude-code/home",
      "repo": "fixtures/claude-code/repo"
    },
    // 外部目录之外需要生成的对象
    "files": [
      { "path": "home/.claude/cache/blob.bin", "size": 1048576 }
    ],
    "dirs": ["home/.claude/empty"],
    "symlinks": [
      { "path": "home/.claude/link", "target": "../outside" }
    ],
    "expect": [
      { "entry": "settings-global", "root": "home", "match": ".claude/settings.json", "layer": "L2", "secret": "scan", "action": "keep" },
      { "entry": "cache", "root": "home", "match": ".claude/cache/**", "layer": "L0", "action": "delete" }
    ],
    "expect_absent": [{ "root": "home", "match": "outside/**" }],
    "budget": { "wall_ms": 5000, "max_rss_mib": 256 }
  }
}
```

### 6.1 规则

- `packout profile test <name>` 在系统临时目录物化 fixture：`selftest.fixtures` 的每个外部目录整体拷入临时目录，作为该 root 实例的内容根；再用 `files`（零填充）、`dirs`（空目录）、`symlinks` 补齐生成物。`files`/`dirs`/`symlinks` 的路径以 fixture 实例名为第一段，其余相对该实例根。
- **外部样本只读**：路径相对 profile 文件所在目录，必须是相对路径且不越出 profile 目录（`E-PRF-067`）。目录内每个文件逐字节复制，mtime 由物化器按 `selftest.clock`（若给出）统一设定；fixture 目录内不生成额外文件。
- `selftest.fixtures` 的键是 root 名或实例名（如 `repo#2`）。`expect.root` 必填，且必须是该映射的键（它只指定 fixture 绑定，named-location 的 expect 也写承载 fixture 的 root，不写 `os`）；`expect.match` 是相对该 root 所绑定 fixture 树的 glob；`expect.entry` 必填，用于覆盖率统计。`expect.os` 可选，缺省在全部平台生效。
- **隐藏段与 entry 同一套规则**：`expect.match` 与 `expect_absent[].match` 使用与 entry selector 完全相同的 glob 与隐藏段语义（§4.2）：`*` / `**` 默认不匹配以 `.` 开头的段，隐藏项必须显式写 `.*` / `**/.*`。原 `matchGlobLenient` 的宽松匹配删除，不再保留第二套语义（`D-028` 第 1 条）。
- **named-location 的匹配语义**：named-location 的 `expect` 按相对路径比较，不按 `os` 查找。把 locator / 探测结果中的 `$HOME`（Windows 为 `%USERPROFILE%`）替换为空串，去掉前导 `/`，再与 `expect.match` 比较；`root:` 仍只指定承载 fixture 的实例（`D-028` 第 4 条）。
- 断言字段：`layer`、`secret`、`action`、`risk_flags`（子集匹配）、`part`（断言 `part_id`；entry 有 parts 时必填）、`confidence`（数值精确相等）。
- `expect_absent` 的元素是 `{root, match}` 对象，`root` 语义同 `expect.root`，`match` 是相对该 fixture 树的 glob；命中任一文件即失败。用于验证默认排除（如 worktree 的 `.git` 文件）与不应出现的伴生文件。
- `catch-all` 条目也要被 `expect` 覆盖：在 fixture 里放一个不被其他 entry 命中的文件，断言其 entry、L2、`keep` 与 `confidence` 0.5。**每条 expect 都显式写 `root:`**，新老 profile 一致，不靠前缀猜。
- **不允许网络**：任何 `url` 只做记录，selftest 不请求；fixture 不得引用真实用户目录。
- **不允许时钟依赖**：`selftest.clock` 可选；给合法 RFC 3339 值时，物化器把所有 fixture 与生成物的 mtime 统一设为该值；缺失时不报错，物化器不统一改写 mtime。selftest 断言不得读取真实当前时间（`D-028` 第 5 条）。
- **必须走真实代码路径**：selftest 与生产使用完全相同的分类代码，只有 root、时钟可注入。
- **覆盖率**：profile 内每个 entry 至少被一条 `expect.entry` 覆盖（含 parts 的 entry 由其各 part 的 `expect.part` 覆盖即可，不必另有 entry 级 expect）；含 parts 的 entry 每个 part 至少被一条 `expect.part` 覆盖；无法覆盖的 entry 必须写 `selftest_exempt: <理由>`，内置 profile 的 L3/L5 entry 不得豁免（catch-all 可豁免，但内置 profile 的 catch-all 必须覆盖）。
- **预算**：超 `wall_ms` 或 `max_rss_mib` 即失败，防止 fixture 变成巨型扫描。
- selftest 必须确定性：同一 profile 连跑两次输出的 Unit 集合与字段逐字节一致（时间字段除外）。

### 6.2 多 root

`selftest.fixtures` 可同时绑定多个 root 实例，例如 `{"home": "fixtures/claude-code/home", "repo": "fixtures/claude-code/repo"}`；主 root 不是 `home` 时可写 `{"codex": "fixtures/codex/home", "repo": "fixtures/codex/repo"}`。每个外部目录拷到同一临时目录下的不同位置。`expect` 的每条断言**必须显式写 `root:`**，取值必须是映射中的键；`match` 相对该 root 的 fixture 树，不再靠 `repo/` 前缀猜是哪个根。缺 `root:` 时可按 `repo/` 前缀兜底推断并记 `W-PRF-106`；推断不出、`root:` 未绑定、或 `fixtures` 值不是合法的 profile 内相对目录，即 `E-PRF-027`（`D-010` 第 7 条）。同一外部目录不得绑定到两个 root 实例（`E-PRF-027`）。

### 6.3 selftest 与被测 profile 的边界

selftest 从 profile **自身的 entries** 与 **fixture** 生成期望，不引入外部金文件；金文件由 `expect` 在 profile 内定义。**样本内容**放外部目录只是编码方式（`D-017`），不改变"期望来自 profile"这一边界：外部目录与 profile 一起 review、一起版本化。

selftest 只证明"profile 按自己写的样子工作"，证明不了真机漂移：fixture 是照 profile 造的，路径写错时它也全绿（`D-016`）。真机存在性由 `packout profile probe` 单独负责，见 `docs/spec-profile-validation.md` §11.1；`probe` 的漂移结果不回写 profile，只输出清单。

---

## 7. schema_version 与迁移

### 7.1 格式

`schema_version` 为 `MAJOR.MINOR` 字符串。引擎内嵌支持的 MAJOR 集合。当前为 `2.0`：v2 相对 v1 的改动（含 YAML→JSONC）见 §7.3。

- **MINOR**：只新增可选字段、新增枚举值、收紧无歧义的语义。旧引擎读新 MINOR 必须成功，未知字段保留。
- **MAJOR**：删除/改名/改变既有字段语义、改变匹配语义、改变默认值。新引擎读旧 MAJOR 必须走迁移；旧引擎读新 MAJOR 必须拒绝（`E-PRF-002`）。

### 7.2 未知字段保留

- 加载时把每个对象的未识别成员原样存入 `raw` AST，迁移与回写时保留。
- `kind` 之外的未识别枚举值不报错，映射为 `unknown`，对应 Unit 强制 `proposed_action: keep` 并加 `risk_flags: ["unknown_enum"]`。
- 未识别的 `kind` **不降级**：整份 profile 拒绝加载（`E-PRF-005`），避免未知 kind 静默漏扫；错误带该键的行列号（`D-010` 第 10 条）。

### 7.3 迁移

- 每次 MAJOR 升级必须同时提交：`profiles/migrations/<name>-<from_major>-to-<to_major>.md`（变更说明+逐字段映射）与可执行迁移函数（注册在 `migrations` 表，P0 允许只做内存映射，不改磁盘）。
- `packout profile migrate <name> --to <version> [--dry-run]`；默认输出到 stdout，不覆盖源文件，除非显式 `--write`。
- 迁移必须幂等，且失败时不产生半迁移状态。
- 内置 profile 必须保持当前 MAJOR；旧 MAJOR 内置 profile 只保留一个版本用于回归。
- 迁移不改名 `id`；若必须改名，旧 `id` 进 `aliases`，manifest 的 `id` 稳定性据此保持。

v1 → v2 的字段映射（MAJOR 迁移，`profiles/migrations/claude-code-1-to-2.md` 等按此写）：

| v1 | v2 |
|---|---|
| `l3_if_unique: true` | 删除，改 `unique_within: root` |
| `kind: glob-group` + `paths: ["**"]` 作兜底 | 删除 `paths`，改 `kind: catch-all` |
| 整目录条目与具体子条目并存 | 给具体条目更高 `priority`（如 20），整目录条目降到 10 |
| `.claude.json` 单层 `L2` + `keys-only` | 顶层保持默认，新增 `parts` 按段分派层与抽取（§5.9） |
| 含 slug/worktree 的路径 | 加 `path_semantics: machine_derived` 与对应 `derived_from` |
| `binary: true` + `risk_flags: ["binary"]` | 改名 `opaque_content`（字段与风险标记同名），v1 名读入时映射（`D-021` 第 3 条） |
| 高频重写的大 JSON | 加 `churn: high`、`max_bytes_structure`，按需把 `max_bytes_inline` 降为 0 |
| `max_bytes_inline` 一项通吃 | 按读值/读结构/读总量拆到 `max_bytes_inline` / `max_bytes_structure` / `max_bytes_total` |
| 单值 `repo` root | 不改 profile，改用重复 `--root repo=PATH`（§4.1） |
| YAML `.yaml` 文件、内嵌 `content` fixture | 转 JSONC、扩展名 `.jsonc`；fixture 内容移入 `selftest.fixtures` 外部目录 |
| `# TODO verify` | 改 `// TODO verify` |

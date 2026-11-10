# 走查：用真实机器检验 profile/manifest 规格

- 走查对象：`D:\Study\packout\docs\spec-profile.md`（索引）及其子文档 `spec-profile-model.md` / `spec-profile-builtin.md` / `spec-profile-validation.md`、`docs/spec-manifest.md`，参照 `DECISIONS.md`（D-010 / D-011）。
- 方法：只读。`ls` / `find -printf` / `stat` / PowerShell `Get-ChildItem -Force` / `Get-Item`，只对 `~/.claude.json` 用 PowerShell 解析顶层键，未读取任何大文件内容。
- 观察对象：`C:\Users\27581\.claude\`、`C:\Users\27581\.claude.json`、`C:\Users\27581\.codex\`、`C:\Users\27581\AppData\Local\Claude-3p\`、`D:\Study` 下含 `.claude/` 的仓库。全程未写入被测目录。
- 结论口径：**可表达** = 现有字段能写出该条目且语义正确；**需补字段** = 现有字段能近似写，但关键语义丢失；**表达不了** = 写不出或写出来会被读成错误结论。后者给出"缺什么"和"改 spec 还是改模型"。

> 判定基准：spec 的目标是"扫描与分类"能对真实机器给出正确结论，不是一个能解析的文件格式。因此"能写进 YAML"不等于"可表达"。

---

## 1. 基线事实（本次实测）

| 路径 | 观测 |
|---|---|
| `C:\Users\27581\.claude\` | 4.9 GB；顶层 30 项（含 6 个 `settings.json.*` 备份/临时文件） |
| `C:\Users\27581\.claude\projects\` | 4.8 GB，37 个 slug 目录，1 071 个 `*.jsonl`；最大单文件 86,516,902 B |
| `C:\Users\27581\.claude\projects\D--Study-Chatrix\` | 1.5 GB |
| `C:\Users\27581\.claude\plugins\` | 57 MB，1 779 个文件 |
| `C:\Users\27581\.claude\file-history\` | 2.6 MB，268 个 `@vN` 快照 |
| `C:\Users\27581\.claude\history.jsonl` | 55,586 B |
| `C:\Users\27581\.claude\CLAUDE.md` | 2,024 B |
| `C:\Users\27581\.claude\agents\` | 3 个手写 agent（`scout.md` / `verifier.md` / `writer.md`） |
| `C:\Users\27581\.claude\plans\` | 652 KB，8 个文件 |
| `C:\Users\27581\.claude\backups\` | 5 个 `.claude.json.backup.<epoch-ms>`，各约 91 KB |
| `C:\Users\27581\.claude\sessions\` | `*.key`（各 108 B）+ `*.json` |
| `C:\Users\27581\.claude.json` | 91,666 B，`projects` 47 键，`machineID`、`userID` |
| `C:\Users\27581\.codex\` | 约 2.8 GB；`thread_history_1.sqlite` 360,218,624 B，`logs_2.sqlite` 95,399,936 B，`sessions` 1.2 GB |
| `C:\Users\27581\AppData\Local\Claude-3p\vm_bundles\` | 8.5 GB（`claudevm.bundle`、`warm`） |
| `C:\Users\27581\AppData\Local\Claude-3p\local-agent-mode-sessions\` | 629 MB |
| `D:\Study\Intern\qianniu\.claude\worktrees\optimistic-ramanujan-4d7362\` | 386 MB，`.git` 为普通文件，内容 `gitdir: D:/Study/Intern/qianniu/.git/worktrees/optimistic-ramanujan-4d7362` |

`.claude.json` 重写频率：`backups/` 中 5 份副本时间戳为 16:07:52、16:14:53、16:26:52、16:36:19、16:40:03；走查期间文件 mtime 又从 16:40:03 变到 16:49:46，体积 91,562 → 91,666 B。约 4–10 分钟一次全量重写。

---

## 2. 逐类别判定

先给总表，细节在 §2.1 起。

| # | 类别 | 代表路径 | 判定 |
|---|---|---|---|
| A | 顶层大状态 JSON | `C:\Users\27581\.claude.json` | 表达不了 |
| B | 会话 transcript 及其 slug 目录 | `.claude/projects/D--Study-Chatrix/…` | 需补字段 |
| C | project 目录内非 jsonl 附件 | `.claude/projects/…/tool-results/webfetch-…pdf` | 表达不了 |
| D | 插件安装 + 启用 + 运行时状态混层 | `.claude/plugins/` | 表达不了 |
| E | checkpoint 快照 | `.claude/file-history/<session>/<hash>@v2` | 需补字段 |
| F | git worktree | `D:\Study\Intern\qianniu\.claude\worktrees\…` | 表达不了 |
| G | 根之外的巨型缓存 | `AppData\Local\Claude-3p\vm_bundles\` | 表达不了 |
| H | sqlite 及 WAL/SHM 二进制 | `.codex/thread_history_1.sqlite{,-wal,-shm}` | 表达不了 |
| I | junction / 符号链接 | `.codex/packages/app-server-daemon/current` | 需补字段 |
| J | 跨仓库同名文件 | 3× `settings.local.json`、5× `CLAUDE.md` | 表达不了（`l3_if_unique` 语义） |
| K | `~/.claude` 顶层未覆盖项 | `agents/`、`plans/`、`backups/`、`sessions/`、`statusline.js` 等 | 表达不了 |
| L | repo 内未覆盖项与多仓库根 | `.claude/rules/*.md`、`.claude/scheduled_tasks.lock`、`D:\Study` 下 5 个独立仓库 | 表达不了 |
| M | codex 未覆盖项 | `.codex/sqlite/`、`state_5.sqlite`、`archived_sessions/`、`packages/`、`skills/`、`.env` 等 | 表达不了 |
| N | profile 声明但本机不存在的路径 | `.claude/todos/`、`.claude/skills/`、`.claude/settings.local.json`、`.mcp.json`、`statsig/`、`ide/` | 可表达，但 selftest 抓不到漂移 |
| O | 分散的凭据点 | `.claude/sessions/*.key`、`.codex/.env`、`.codex/.sandbox-secrets/sandbox_users.json` | 需补字段 |

---

### 2.1 A — `~/.claude.json`

实测结构：顶层 47 键，含 `machineID`、`userID`、`githubRepoPaths`、`projects`（47 个绝对路径键）、`mcpServers`（本机为 0 个）；每个 `projects` 项又有 `allowedTools`、`enabledMcpjsonServers`、`hasTrustDialogAccepted`、`history`。是一个**同时含 L2 配置、L3 用户输入历史、L4 机器身份与绝对路径索引**的文件，且被高频整体重写。

现有 profile 的写法：

```yaml
  - id: claude-json
    kind: file
    root: home
    path: ".claude.json"
    layer: "L2"
    secret: scan
    extractor: keys-only
```

逐项结论：

- **kind**：`file` 正确，没有别的选择。
- **extractor**：只有 `keys-only` 勉强可用；`template` 会把 91 KB 的机器状态写进 `config/`，`digest` 又丢掉全部结构。但 `keys-only` 会把 `projects` 的键名（47 条绝对路径）带进 manifest，这些是 L4；同时把 `history` 的内容（L3 用户输入）整段丢掉。
- **layer**：声明 L2 后，`machineID`/`userID`/`projects` 键全是 L4，`history` 是 L3；单一 `layer` 只能取一个。取 L2 会让 `proposed_action: template` 作用于一个含机器 ID 的文件；取 L4 又会误标。
- **读取负担**：默认 `max_bytes_inline: 65536` < 91,666 B，本机已经超限。`secret: scan` 要求读取，`fingerprint` 对 < 32 MiB 文件走 `full`，又是整读一遍。文件 ~5 分钟重写一次，因此**每次扫描都必然全量读、且每次内容都不同**。`keys-only` 解析还会被 64 KiB 截断切在 token 中间；manifest 只记 `oversized`/`content_partial`，无法表达"这份 JSON 被截断后键集不完整"。
- **随附副本**：`backups/.claude.json.backup.1794298493352` 等 5 个各 91 KB，被 `backups/**` 覆盖不到（见 K），它们同样是 L2+L4。

缺什么：文件级 `layer`/`extractor` 的**子路径切分**；`churn`（重写频率）提示；"结构性读取预算"与 `max_bytes_inline` 分离；JSON 部分解析的截断语义。
判定：**表达不了**。改**模型**（新增 `parts:`，按 JSON Pointer 给每段独立 `layer`/`extractor`/`secret`），并在 spec 增 `churn: high|low` 与 `partial_parse` 说明。

### 2.2 B — `projects/<slug>/`

slug 实测：`D--Study-Chatrix`、`C--Users-27581`、`D--Study-CST-sem7-Numerical-Methods`、`D--Study-Chatrix-Chatrix--claude-worktrees-optimistic-ramanujan-4d7362`。变换是 `:\`→`--`、`\`→`-`、`_`→`-`、`.`→`-`，最长 69 字符。

- transcript 用 `projects/**/*.jsonl` 可命中，`digest` + `max_bytes_inline: 65536` 可写。1.5 GB 目录、1 071 个文件、单文件 86 MB 都能走通（> 32 MiB 走 `head-tail`，每次 2 MiB）。
- 但 slug 是**路径派生**：`D:\Study\CST_sem7\Numerical_Methods` 与假设的 `D:\Study\CST\sem7\Numerical\Methods` 会产生同一个 `D--Study-CST-sem7-Numerical-Methods`；`-`、`_`、`.`、`\` 不可逆。规格里没有任何字段说明 slug 的生成规则，也没有"可还原到源仓库"的键。
- `l3_if_unique`、`export_group`、报告分组都只能按 slug 字符串，迁移后 slug 变了就无法与旧机同仓库的会话归并。D-011 的 `cid` 只解决内容去重，不解决"这条记录属于哪个仓库"。
- `.claude.json` 的 `projects` 键是 47 条原始绝对路径，与 37 个 slug 目录并不一一对应（包含已删除的 worktree 路径），同样是路径派生但**没有 slug 归类**。

缺什么：`path_semantics: literal | machine_derived`（或 `derived_from: <写入者/转换规则>`、`origin_key`），以及风险标记。
判定：**需补字段**。改**模型**（路径派生是数据形态问题，不是格式问题），spec 增 `path_semantics` 与 `risk_flags: ["machine_derived_path", "slug_collision"]`。

### 2.3 C — project 目录内的非 jsonl 附件

实测：`projects/D--Study/f8f18a2c-…/tool-results/webfetch-1794239872774-xfz967.pdf`（9,870,272 B）、`webfetch-…x5h4vz.pdf`（941,281 B）、`…/tool-results/b8gflw0i4.txt`（1,851,132 B）、`projects/D--Study-Chatrix/bytedesk-tree.json`（4,764,342 B）、`projects/D--Study-Chatrix/commit-groups.py`（9,984 B）、`…/12271a46-….desktop-released.json`、`projects/C--Users-27581/memory/`、18 个 `subagents/` 目录。

`projects/**/*.jsonl` 只命中 jsonl，以上全部落空。它们不是可再生缓存：transcript 里的 tool_result 引用指向这些文件，删掉后 `/resume` 回放会缺内容。
写得出条目（`projects/**/tool-results/**`、`projects/**/subagents/**/*.jsonl`、`projects/*/*.json`），但：
- 这要求相邻条目的 selector 互不重叠，而 spec 没有"重叠时谁赢"的规则（`E-PRF-023` 只管完全相同）；
- `bytedesk-tree.json` 落在 `projects/D--Study-Chatrix/` 根，与其他 slug 下同名文件无法用一个稳定 selector 区分；
- 二进制（PDF）的 `secret: scan` 命中依赖 §5.8 的 NUL 比例判定，但 `max_bytes_inline` 为 0 时 `scan` 直接非法（`E-PRF-042`），本机 PDF 必须给出非 0 值；
- `.desktop-released.json` 的用途（会话被打断后桌面端是否已释放）在当前模型里没有层语义。

判定：**表达不了**（不是写不出来，而是写出来会与 transcript 条目重叠且无优先级）。改**模型**：加 `priority` 或"更具体 selector 优先"；再加残留兜底（见 K）。

### 2.4 D — `plugins/` 三层混在同一目录

实测：

- 声明/启用：`plugins/installed_plugins.json`（`claude-hud@claude-hud`，含 `installPath`、`gitCommitSha`）、`plugins/known_marketplaces.json`，以及 `~/.claude/settings.json` 的 `enabledPlugins: {"claude-hud@claude-hud": true}`。启用状态**不在 plugins 目录里**。
- 可再生副本：`plugins/cache/claude-hud/claude-hud/0.15.1`（36 MB）、`plugins/marketplaces/claude-hud` 与 `marketplaces/claude-plugins-official`（18 MB，是带 `.git` 的完整克隆）、`plugin-directory-cache-v2.json`（2,754,173 B）。
- 用户运行时状态：`plugins/claude-hud/config.json`（显示项偏好）、`plugins/claude-hud/data/transcript-cursors/*.json`（最大 255,682 B）、`plugins/claude-hud/heartbeat.json` 与 14 个 `heartbeat.json.<pid>.tmp`、`plugins/store/transom_inline-d890fe5e4d98.json`（21,285 B）、`.last_inuse_sweep`。

现有条目是整目录 L1 + `keys-only`，只排除 `cache/**` 和 `repos/**`（本机根本没有 `repos/`，被 git 克隆叫 `marketplaces/`）。结果：

- `marketplaces/`（git 克隆）被当 L1，方向没错但每条会产出成百上千个 Unit；
- `claude-hud/config.json` 是用户偏好，标 L1 `reinstall` 意味着删了也能"重装回来"，实际会丢显示配置；
- `data/transcript-cursors` 是可再生的，却与 config 同一分类；
- `plugin-directory-cache-v2.json` 是 2.7 MB 缓存，`keys-only` 会去键扫描一个大缓存；
- `exclude: ["**/repos/**"]` 与实际目录名不符，属于 profile 写错。

要写对至少需要 5 个互斥条目（`installed_plugins.json`+`known_marketplaces.json` L2、`cache/**` 与 `marketplaces/**` L0/L1、`store/**` 与 `*/data/**` L3、`*/config.json` L2）；但整目录条目会与它们重叠，且没有优先级。另外 `enabledPlugins` 在 `settings.json` 内部，`template` 不区分具体段。
判定：**表达不了**。改**模型**（`priority` + 子键切分），并修 profile 的 `repos`→`marketplaces`。

### 2.5 E — `file-history/<session>/`

实测：`C:\Users\27581\.claude\file-history\011d0d40-4f61-4a00-b377-9d34c4c4f6de\239ed97e478ca339@v2`（41,667 B），268 个文件、2.6 MB，文件名是 `<内容哈希>@v<版本>`。

它是 `/rewind` 的检查点来源：目录名是 session id，跨会话不可重建，删掉后旧会话回不到旧版本。
可写：`dir`，`home` root，`path: ".claude/file-history"`，但层怎么定？
- 标 L0 会得到 `delete`，`/rewind` 就废了；
- 标 L3 会 `migrate`，但只有"曾经被编辑过的文件内容"，价值密度低于 transcript，多半不该整包迁移；
- 标 L2 又会 `template`（快照不是配置格式）。

模型只有 `layer` 一个维度，缺"这个路径被哪个功能消费"。同类还有 `statusline.js`（被 `settings.json` 的 `statusLine.command` 引用）、`sessions/*.key`（被 daemon 引用）。
判定：**需补字段**。改**模型**：新增 `needed_by` / `feature_impact`（如 `/rewind`、`statusLine`），让 L0 可以带"删除有功能代价"。

### 2.6 F — worktree

实测：`D:\Study\Intern\qianniu\.claude\worktrees\optimistic-ramanujan-4d7362`，386 MB，含真实源码；`.git` 是普通文件，内容 `gitdir: D:/Study/Intern/qianniu/.git/worktrees/optimistic-ramanujan-4d7362`。`D:\Study\Chatrix\Chatrix\.claude\worktrees\` 与 `D:\Study\aishow\.claude\worktrees\` 目前为空目录。对应 transcript slug 是 `D--Study-Chatrix-Chatrix--claude-worktrees-…`（8 条）。

- `.claude/worktrees/**` 可以写成条目，但默认 exclude `**/.git/**` 不排除 `.git` 这个**文件**（`**/.git/**` 要求 `.git` 之后还有段），会产出一个含绝对 gitdir 的 Unit；
- worktree 是主 checkout 的一份分支副本，含上游源码 + 未提交改动，层应接近仓库源码（通常不迁，或按 `repo` 规则），模型里没有"与主 checkout 去重/关联"的概念；
- worktree 目录名（`optimistic-ramanujan-4d7362`）是随机的，绝对父路径机器相关，又是路径派生；
- worktree 内的 `.claude/` 也可能存在并被 `repo-*` 条目命中。

判定：**表达不了**。缺 `role: worktree` / `links_to` 和路径派生标记；改**模型**。`.git` 文件本身可用 `repo/.claude/worktrees/**/.git` 补，属 spec 层面的条目补齐。

### 2.7 G — 根之外的 8.5 GB

`C:\Users\27581\AppData\Local\Claude-3p\vm_bundles\`（8.5 GB）与 `local-agent-mode-sessions\`（629 MB）**不被任何一个 root 覆盖**：`home` 下的条目全部在 `.claude/` 里，`repo`、`codex` 也够不到 `AppData`。它们既不能写 `home` 相对路径（`..\AppData\...` 越出 root 只有 named-location 允许），也不能算 root。

即便补了 `appdata` root：
- `vm_bundles` 需要 `expand: aggregate`，否则 8.5 GB 会爆 Unit 数；`aggregate` 下 `size_apparent` 求和已由 D-011 #8 定义，但**聚合 Unit 的 `fingerprint`、`secret` 扫描、`proposed_action` 都没有定义**。`vm_bundles` 里有 VM 镜像，删了要重新下载/构建，属于 L0/L1 之间，模型没有依据。
- `max_bytes_inline` 只对单文件有意义；聚合后无法再对子树做密检。
- 没有总量预算字段，`aggregate_above` 只数命中个数，不管字节。
判定：**表达不了**。改**模型**（新增 `home`/`appdata`/`localappdata` root 或 `root_relative_absolute`）与 **spec**（聚合 Unit 的 fingerprint/secret/`max_bytes_total` 语义）。

### 2.8 H — 二进制：sqlite 与 WAL/SHM

实测 `.codex/thread_history_1.sqlite` 360,218,624 B、`logs_2.sqlite` 95,399,936 B、`state_5.sqlite` 5,468,160 B，各自还有 `-wal`（`state_5` 的 WAL 4,169,472 B）与 `-shm`（32,768 B）。大量 `*.jsonl` 里的 tool-result 是 PDF/PNG 形态的大二进制，落点见 C。

- 单文件 `digest` 可写，`head-tail` 语义对 > 32 MiB 文件成立；
- 但 `*.sqlite` 与 `*.sqlite-wal` / `*.sqlite-shm` 是**一个逻辑库的三个文件**，删库留 WAL 或反之都会出问题。模型只有 `dir` 聚合能把它们放一起，代价是丢每库粒度；
- `*.sqlite-wal` 可能是 0 字节（`logs_2.sqlite-wal` 实测 0），`digest` 产出无意义指纹；
- `.codex/sqlite/`（36 KB 目录）与 `logs_2.sqlite` 等没有任何 codex 条目覆盖，属于静默漏扫；
- `secret: scan` 对 sqlite 没有意义（NUL 比例高，模板化不执行），但 `E-PRF-042` 仍要求 `max_bytes_inline > 0`。
判定：**表达不了**。缺 **伴生文件分组**（`companions: ["-wal", "-shm"]` 或 `group_key`）与"二进制跳过内容检测"的声明式开关；改**模型** + **spec**。

### 2.9 I — 符号链接 / junction

实测：
- `.claude/` 递归（全深度）**没有**符号链接；
- `.codex/packages/app-server-daemon/current` 是 `Directory, ReparsePoint`（junction），目标是同目录 `releases/` 下的版本，旁边的 `install.lock`、`auto-update-version`、`selection-history` 处于同一目录；
- `D:\Study\aishow\node_modules\*` 大量 junction（npm 行为）；
- worktree 的 `.git` 是普通文件，不是链接。

spec §4.3 的链接语义本身**可表达**（默认不跟随、记 `symlink`、target 不分类）。问题在覆盖：`packages/` 无条目；`follow_symlinks: true` 时 `current` 会与 `releases/` 下的同一份内容重复产出 Unit，spec 没有"按 target 去重"的能力。
判定：**需补字段**。链接语义不动，补条目；去重需 spec 增 `dedupe_targets: true` 或引擎按 `(volume_id, file_id)` 去重。

### 2.10 J — 跨仓库同名文件与 `l3_if_unique`

实测：`settings.local.json` 3 份（`D:\Study\Chatrix\.claude\`、`D:\Study\Chatrix\Chatrix\.claude\`、`D:\Study\Projects\Planora\.claude\`），`CLAUDE.md` 5 份（`Chatrix\Chatrix`、`Chatrix\Yanju`、`Intern`、`Intern\qianniu`、`NUFILT`）。全局 `~/.claude/settings.local.json` **不存在**。

- 全局 gitignore 首行为 `**/.claude/settings.local.json`，`D:\Study\Chatrix\Chatrix\.gitignore:44` 也再次忽略；`Chatrix/Chatrix` 与 `Intern/qianniu` 是 git 仓库，`CLAUDE.md` 均为 tracked。
- 按 D-010 #4，`l3_if_unique` 按"跨全部扫描 root 的全局路径集合"计数：扫 3 个仓库后 `settings.local.json` 计数为 3，**永远不触发升 L3**；扫 5 个仓库后 `CLAUDE.md` 计数为 5，同样不触发。这两个条目在本机全部停留在 L2。
- 语义上这里恰恰相反：每份 `settings.local.json` 的**内容**都是单仓库唯一且被 gitignore，`CLAUDE.md` 则是仓库资产（本就随仓库走，不需要迁）。`l3_if_unique` 按同名计数，无法区分"同名但内容各异"与"同名且重复"。
- 更根本的是 `repo` root 是单个 `${REPO_ROOT}`：一次只能扫一个仓库。要扫 `D:\Study` 得把 root 指到 `D:\Study`，但 `repo/CLAUDE.md` 只匹配顶层，`D:\Study\Chatrix\Chatrix\CLAUDE.md` 落空；selftest 的多 root 也要为每个仓库各写一个 root。
判定：**表达不了**。改**模型**：`l3_if_unique` 的计数作用域应为 root（`unique_within: root`），或改为按 `(basename, 内容)` 判定；并增加"多仓库发现"（`roots.repos` + `.git` 探测）。

### 2.11 K — `~/.claude` 顶层未覆盖项

以下均无条目（`~/.claude` 自身也没有 catch-all）：

- `agents/`（3 个手写 agent，12 KB）— 明显 L3，规格完全没有全局 agents 条目（`repo-commands` 只覆盖 `repo/.claude/agents/**`）；
- `plans/chatrix-service-architecture-audit/`（8 个文件、652 KB，含 `.md`/`.csv`/`.json` 手写产物）；
- `backups/.claude.json.backup.*`（5 × 91 KB，隐藏文件，`backups/**` 因 §4.2 不匹配点段而落空）；
- `sessions/*.key`（108 B）与 `sessions/*.json`；
- `session-env/<session>/`、`jobs/<id>/{state.json,timeline.jsonl}`（15 个）、`daemon/{attach-journal,dispatch,gateway-routed,control.key}`；
- `statusline.js`（8,130 B，被 `settings.json` 的 `statusLine.command` 引用）、`stats-cache.json`（13,108 B，含 `dailyActivity`）；
- `settings.json.aproo-backup`、`settings.json.bak.20261107T064009`、`settings.json.bak.autocompactfix`、`settings.json.bak.statusline`、`settings.json.tmp.33988.1792644675034246100.8`；
- `.last-cleanup`、`.last-update-result.json`、`daemon.lock`、`daemon.status.json`、`daemon.log`；
- `downloads/`、`dev-mods/`、`cache/changelog.md`（1.19 MB，被 `cache/**` 覆盖）。

这些都能逐条写出 selector（隐藏文件写 `backups/.*`、`settings.json.bak.*` 等），但：
- 没有任何"剩余项"兜底，profile 每漏一项就永久静默漏扫，selftest 也不会失败；
- `sessions/*.key` 与 `daemon/control.key` 属凭据碎片，层与 `secret` 组合没有现成答案；
- `settings.json.*` 备份与 `settings.json` 同构，但 `secret: scan` + `l3_if_unique` 会让计数更乱。
判定：**表达不了**（整体层面）。改**模型**：加 `kind: catch-all`（或 `paths: ["**"]` 的保留语义 + 未命中计数），并设"未命中项不得静默"的闸门。

### 2.12 L — repo 内未覆盖项与多仓库根

- `Chatrix/Chatrix/.claude/rules/{database,frontend,server,verification}.md`（共 5,307 B）是 **git tracked** 的规则文件，`repo-commands` 的 `.claude/commands/**`、`.claude/agents/**` 都不含 `rules/`；
- `.claude/scheduled_tasks.lock`（123 B，含 `sessionId`、`pid`）与 `repo-launch` 的 `.claude/launch.json`（705 B，tracked）并存；
- `D:\Study` 下至少 5 个独立仓库含 `CLAUDE.md`，`repo` root 单值问题见 J；
- `D:\Study` 下 `CMM`、`Encore`、`transom` 等有会话但 `.claude/` 已不存在，只留 transcript，属正常历史。

`rules/**` 与 `scheduled_tasks.lock` 用现有 `glob-group` 可以补进 profile，属 profile 遗漏。多仓库根与 tracked 判定是模型/spec 层面。
判定：条目层**需补字段**（tracked 已是 `risk_flags` 可表达，缺的是规则文件语义）；多仓库**表达不了**。改 profile + 模型。

### 2.13 M — codex 未覆盖项

现有 codex profile 只覆盖 `config.toml`、`auth.json`、`sessions/**/rollout-*.jsonl`、`history.jsonl`、`prompts/`、`rules/`、`AGENTS.md`、`log/`、`tmp/`、`models_cache.json`、`version.json`。实测落空的关键项：

- sqlite 全家族：`state_5.sqlite`(5.5 MB)+`-wal`(4.2 MB)、`thread_history_1.sqlite`(360 MB)+`-wal`(4.2 MB)、`logs_2.sqlite`(95 MB)、`goals_1.sqlite`、`queue_1.sqlite`、`memories_1.sqlite`、`sqlite/`；
- `.codex-global-state.json`(85,825 B) 与 `.codex-global-state.json.bak`、`cap_sid`(35,108 B)、`installation_id`、`.personality_migration`、`.env`(204 B)、`.sandbox-secrets/sandbox_users.json`(828 B)、`.sandbox/`、`.sandbox-bin/`、`sandbox.*.log` ×8；
- `archived_sessions/`(16 MB)、`session_index.jsonl`(34,125 B)、`memories/`、`memories_1.sqlite`；
- `packages/app-server-daemon/`(1.1 GB，含 junction)、`plugins/`(38 MB)、`cache/`(73 MB)、`skills/`(1.9 MB)、`vendor_imports/`(7.8 MB)、`node_repl/`、`pets/`、`process_manager/`、`computer-use/`、`app-server-control/`、`app-server-daemon/`、`thread-writer-locks/`、`tui-thread-reference-capabilities/`、`backup-deepseek/`、`models.json`、`cc-switch-model-catalog.json`、`mi250*`、`hooks.aproo-backup-*.json` ×16、`config.toml.usage-backup-*`、`auth.lock`、`.sqlite-maintenance.lock`。

profile 的 `rules/` 实测存在（含文件），`log/` 不存在（只有 `sandbox.*.log`、`daemon.log` 在 `.claude` 下）。`sessions/**/rollout-*.jsonl` 确实命中（636 个文件，最大 93 MB），`prompts/` 存在。整体覆盖率不到真实目录的一半。
判定：**表达不了**。条目可补齐大部分，但 sqlite/WAL 分组（H）、junction（I）、`packages` 1.1 GB 聚合、`installation_id` 属 L4，都需要模型支持。

### 2.14 N — profile 声明但本机不存在

实测不存在：`~/.claude/todos/`、`~/.claude/skills/`、`~/.claude/settings.local.json`、`~/.claude/.credentials.json`、`~/.claude/statsig/`、`~/.claude/ide/`、所有仓库的 `.mcp.json`。

这是**可表达**的：不存在就是 0 个 Unit，named-location 探测失败还有 `probe_unavailable`。但它暴露 selftest 的盲区：selftest 只跑 fixture，fixture 是照 profile 造的，profile 写错路径时 selftest 照样绿。spec §6.3 明确"不从外部金文件生成期望"，于是没有任何机制发现"profile 声明的路径在这台真机上不存在"。本机 `~/.claude/skills` 根本不存在，而 `skills` 是 L3 条目；迁移报告会以为有 skills 要迁。
判定：**可表达**（语法层）。建议 spec 增一条可选 `selftest_expect_real` 或 `packout profile probe`（对真机只读验证存在性），属 P1。

### 2.15 O — 分散的凭据点

- `~/.claude/sessions/<pid>.<sha>.key`（108 B，每会话一份）与 `~/.claude/daemon/control.key`（32 B）；
- `~/.codex/.env`（204 B）、`~/.codex/.sandbox-secrets/sandbox_users.json`（828 B）、`~/.codex/config.toml` 的 `experimental_bearer_token`、`auth.json` 的 `OPENAI_API_KEY` 与 `tokens`；
- `~/.claude/settings.json` 的 `env`（含 `ANTHROPIC_AUTH_TOKEN` 一类）。

`secret: scan` + `restore`/`relogin` 能表达单个文件，但：
- `sessions/*.key` 是**每进程再生**的，L0 与 `secret: scan` 同时成立，而 L0 的语义是"不迁不备"；
- `.env` 与 `config.toml` 是 `KEY=VALUE`，`template` 的 `redact` 只有 `json_pointer` / `key_pattern`，对 dotenv 需要按行正则，现有 `key_pattern` 作用域未定义（JSON 键名 vs 文本行首）；
- `config.toml` 的 `experimental_bearer_token` 值可能出现在 `model_providers.*` 段下，`key_pattern` 能匹配键名，但 TOML 的 locator 规格是 `段.键`，脱敏替换行为未定义。
判定：**需补字段**。spec 增 dotenv/TOML 的脱敏作用域，模型增"L0 且含密"的显式说明。

---

## 3. 专项边界逐条结论

1. **`~/.claude.json`**：`kind: file` 是唯一解；`extractor` 只有 `keys-only` 勉强可用且已超默认 `max_bytes_inline`（91,666 > 65,536）。因为 `fingerprint` 对 < 32 MiB 是 `full`、`secret: scan` 又要求读，**每次扫描都会全量读**，5–10 分钟一次重写意味着每次都不同。层是 L2+L3+L4 混合，单字段装不下。→ **表达不了**，缺子路径切分与 churn。
2. **slug 路径派生**：没有任何字段表达"这段路径是机器派生的"。`projects/**/*.jsonl` 能扫，但无法与源仓库关联，迁移后 slug 必变，`l3_if_unique`/报告分组全部失锚。→ **表达不了**，改模型（`path_semantics` / `derived_from`）。
3. **plugins 混层**：能拆成 5 个互斥条目，但整目录条目会重叠，spec 无重叠优先级；`exclude` 里的 `repos/**` 与实际 `marketplaces/` 不符；启用状态在 `settings.json`。→ **表达不了**，改模型。
4. **file-history**：能写 `dir`，层定不下来；删了破坏 `/rewind`，模型无"被谁消费"字段。→ **需补字段**（`needed_by`），属于层选择，不是扫描能力。
5. **worktrees**：能扫，但 `.git` 文件不被默认 exclude 覆盖、worktree 与主 checkout 无去重关系、随机目录名 + 绝对 gitdir 是机器派生。→ **表达不了**，改模型。
6. **1.5 GB 目录 / 8.5 GB bundle**：1.5 GB 走 per-file glob 可行（1 071 个 Unit、单文件 86 MB 有 `head-tail`）；8.5 GB 根本不在任何 root 下，且 aggregate 的 fingerprint/secret 未定义、无字节预算。→ **表达不了**，改模型 + spec。
7. **二进制**：PDF/txt tool-results 不被 `*.jsonl` 命中；sqlite 与 WAL/SHM 无分组；`secret` 与 `max_bytes_inline` 的约束对二进制组合别扭。→ **表达不了**，改模型 + spec。
8. **符号链接/junction**：`.claude` 下没有；`.codex/packages/app-server-daemon/current` 是 junction；`node_modules` 大量 junction 已被默认 exclude 挡住。§4.3 的语义**够用**，缺的是 `packages/` 条目和 follow 时的 target 去重。→ **需补字段**（条目 + `dedupe_targets`）。
9. **跨仓库同名**：3 份 `settings.local.json`、5 份 `CLAUDE.md`；`l3_if_unique` 在全局计数下永不触发；单值 `repo` root 无法覆盖嵌套仓库。→ **表达不了**，改模型（`unique_within: root` + 多仓库根）。

---

## 4. 闸门结论

**不能覆盖。** 六层模型 + 现有字段能正确处理固定路径的全局配置文件、OAuth named-location、L0 缓存、默认 exclude、junction 语义；对这台真实机器上占体积最大的四块（`projects` 4.8 GB、`vm_bundles` 8.5 GB、codex sqlite 460 MB、11 个仓库的 `.claude/`）都只能覆盖一半或完全覆盖不到，且没有"漏了什么"的兜底。

不是字段名写得不够，而是模型缺四类原语：

1. **一个文件内部可以分属不同层**（`.claude.json`、`settings.json`、`plugins/*/config.json`）；
2. **路径可以是别的东西的派生**（slug、`.claude.json` 的 `projects` 键、worktree 的 gitdir）；
3. **条目之间有覆盖与伴生关系**（整目录 vs 具体项、sqlite 的 `-wal`/`-shm`、worktree vs 主 checkout、junction vs releases）；
4. **一个路径被哪个功能消费**（file-history→/rewind、statusline.js→statusLine、plugins data→HUD），决定"删了算什么"。

### 4.1 必须改的最小集合

模型（`spec-profile-model.md` §5、`spec-manifest.md` §4）：

| # | 改动 | 用来解决 |
|---|---|---|
| M1 | entry 增加 `parts:`（`json_pointer` / 行正则 / TOML 段），每 part 独立 `layer`/`extractor`/`secret` | A、D、O |
| M2 | entry 增加 `priority`（或定义"更具体 selector 优先"）与 `kind: catch-all` 残留条目；manifest 记未命中计数 | C、D、K |
| M3 | entry 增加 `path_semantics: literal \| machine_derived` 与 `derived_from`（如 `repo_slug`、`git_worktree_of`）；`risk_flags` 增 `machine_derived_path`、`slug_collision` | B、F、A |
| M4 | entry 增加 `churn: high \| low`；spec 定义部分 JSON 解析与"结构键读取预算"（与 `max_bytes_inline` 分开） | A |
| M5 | entry 增加 `needed_by: [rewind, statusline, …]`，允许"L0 但有删除代价" | E、K、O |
| M6 | entry 增加 `companions`（`-wal`、`-shm`）或 `group_key`，一个逻辑库一个 Unit | H |
| M7 | `l3_if_unique` 改 `unique_within: root`（或按 `(basename, 内容)` 判），`repo` root 支持多值/发现（`roots.repos` + `.git` 探测） | J、L |
| M8 | roots 增 `appdata` / `localappdata`（或允许条目绝对路径命名为 root），加 `max_bytes_total` | G |
| M9 | manifest 定义聚合 Unit 的 `fingerprint`、`secret.class`、`max_bytes_total` 触发与 `risk_flags`；`follow_symlinks` 增 `dedupe_targets` | G、H、I |

spec（`spec-profile-model.md`）：

- `exclude` 的默认项与 `**/.git/**` 对 `.git` **文件**不生效，需明确 `**/.git` 与 `**/.git/**` 并列；
- §4.2 隐藏段规则要写进内置 profile 的写法示例（`backups/.*`、`settings.json.bak.*`、`.last-*`），否则作者必踩；
- `redact.key_pattern` 定义作用域（JSON 键名 / dotenv 行首 / TOML 键路径），否则 O 类脱敏无依据；
- `E-PRF-042` 对二进制（sqlite/pdf）放宽为"`scan` 允许 `max_bytes_inline` 为 0 时仅记存在性"，或新增 `secret: reference` 的二进制用法；
- §6.3 "不从金文件取期望"要补一条真机存在性检查（`packout profile probe` 或 `expect_real`），否则 N 类漂移永远发现不了。

### 4.2 如果只改 spec、不改模型

可以靠"写得足够细"再覆盖的：K 中的大部分固定文件、L 的 `rules/**`、`scheduled_tasks.lock`、M 中的固定文件、C 的 tool-results。仍会剩下的硬缺口：`.claude.json` 混层与 churn、slug 派生、plugins 重叠、file-history 层、worktree 关系、8.5 GB 根外、sqlite 分组、跨仓库 `l3_if_unique`、无兜底。即：**不改模型，这台机器上最大的几块仍然是错的或漏的。**

### 4.3 顺带发现的 profile 事实错误（已按 `D-015` 第 19 条与 `D-016` 修正）

- **home 侧条目普遍缺 `.claude/` 前缀**：`projects-transcripts`（写成 `projects/**/*.jsonl`）、`cache-debug-statsig-ide`（写成 `cache/**`、`debug/**`、`statsig/**`、`ide/**`）与真实布局不符，selftest 和 manifest §10.1 却都按 `.claude/` 写。以 `.claude/` 为准改 profile，语料不改；
- `plugins` 的 `exclude: ["**/repos/**"]` 与实际目录名不符，改为 `**/marketplaces/**`；
- `cache-debug-statsig-ide` 的 `statsig`、`ide` 段在本机不存在，行尾标 `# 本机不存在`；
- codex 的 `rules/` 存在，`log/` 不存在（日志实际是 `sandbox.*.log` 与 `daemon.log`），`log/` 行尾标 `# 本机不存在`；同目录约 95% 的 sqlite 未被覆盖；
- `todos`、`skills`、全局 `settings.local.json`、所有仓库的 `.mcp.json` 在本机均不存在，selftest 仍全绿，行尾标 `# 本机不存在`；
- `repo-launch` 的 note 原写"D 盘 11 个项目的 .claude/ 普遍只放行 launch.json"，实测为 11 个 `.claude/` 目录中 3 个含 `settings.local.json`、5 个含 `CLAUDE.md`，`launch.json` 并非普遍，note 按实测改写。

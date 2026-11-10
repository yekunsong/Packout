# 走查 v2：用真实机器复判 model v2 是否补住

> 历史说明：本文记录 2026-11-10 走查时的规格状态，保留当时的字段名（如 `binary`）作为证据；`D-024` 已按 §4.1 门禁把规格与内置 profile 改为 `opaque_content` 等新名，以 `docs/spec-profile.md`（索引）及其子文档 `docs/spec-profile-model.md` / `docs/spec-profile-builtin.md` / `docs/spec-profile-validation.md`、`docs/spec-manifest.md` 与 `profiles/*.jsonc` 为准。

- 对象：`docs/spec-profile.md` v2.0（索引）及其子文档、`docs/spec-manifest.md` v2.0，参照 `DECISIONS.md`（D-013～D-021）。
- 方法：只读重扫。PowerShell / `find` / `stat` / `du` / 只解析 `.claude.json` 的结构键与 `settings.json` 的键名；未读取任何大文件内容，未向被测目录写入任何对象。临时校验文件只落在 `%TEMP%`。
- 真实机器（2026-11-10 复测，与 v1 有变化的数字已更新）：
  - `C:\Users\27581\.claude\`：4.9 GB，3,690 个文件，顶层 30 项；`projects/` 4.8 GB、37 个 slug、1,087 个 `*.jsonl`、397 个非 jsonl 文件、11 个 `tool-results/`、19 个 `subagents/`；`file-history/` 271 个文件 / 2.7 MB；`plugins/` 57 MB / 1,800 个文件；`backups/` 5 个；`sessions/` 19 个；`agents/` 3 个；`plans/` 8 个。
  - `C:\Users\27581\.claude.json`：91,346 B，49 个顶层键，`projects` 43 键，`mcpServers` 0 项，`machineID` / `userID` 存在；**43/43 个 projects 项都没有 `history` 键**。
  - `C:\Users\27581\.codex\`：`thread_history_1.sqlite` 362,512,384 B、`logs_2.sqlite` 95,399,936 B、`state_5.sqlite` 5,521,408 B；`goals_1` / `queue_1` 各有 32,768 B 的 `-shm`、0 B 的 `-wal`；`sqlite/codex-dev.db` 36,864 B；`packages/` 1.1 GB（`app-server-daemon/current` 为 junction）；`sessions/` 645 个文件 / 1.2 GB。
  - `D:\Study`：12 个仓库含 `.claude/`；3 份 `settings.local.json`（Chatrix、Chatrix/Chatrix、Projects/Planora）；6 份 `CLAUDE.md`（其中 1 份在 `Intern/kefu/kefu`）；`rules/*.md` 存在于 Chatrix/Chatrix 与 Chatrix/Yanju；qianniu worktree 386 MB，`.git` 为普通文件。
  - 本机不存在：`~/.claude/todos/`、`skills/`、`settings.local.json`、`.credentials.json`、`statsig/`、`ide/`、`.codex/log/`，以及所有 `.mcp.json`。

## 0. 结论：**有条件通过**

模型 v2 确实补住了 v1 的多数硬缺口：15 类中 11 类（C、E、F、G、H、I、J、L、M、N、O）在模型层已可表达；**A、B、D、K 四类仍未补住**，且都是"字段/规则再加一条"能救的范围，不需要推翻 `parts` / `priority` / catch-all / 派生标记这套原语，因此判**有条件通过**，不是不通过。

但有若干项必须在实现前改，否则规格自身不自洽、内置 selftest 会直接失败：

1. `parts` 没有"未被任何 part 选中的剩余值"的兜底（A 的核心）。
2. `keys-only` part 的 `fingerprint.scope: full` 与条目 `max_bytes_inline: 0` 冲突（A）。
3. `derived_from: repo_slug` 只有标记、没有 origin，slug 与仓库无法对应；`json_path_key` 在 parts 上无合法落点（B）。
4. catch-all 不能限定子目录、与重叠 root 的关系未定义，`home` root 的 catch-all 会扫整个用户目录（D、K）。
5. D-021 的三项裁决没有落进 v2 文档：`binary`→`opaque_content`、聚合 Unit 的 `contains_secret`/`may_contain_secret`、catch-all 必须带 `residual` signal。
6. `docs/spec-profile-builtin.md` 的内置 selftest 有直接矛盾：`claude-json` 的 `machine-identity` part 声明 `secret: "none"`，selftest 却断言 `secret: "reference"`；fixture `profiles/fixtures/claude-code/home/.claude.json` 是非法 JSON（`"D:\Study\demo"` 里的 `\S` / `\d` 非法转义）。
7. `E-PRF-036` 把 `id` 列为 part 不可写字段，而 §5.9 要求 part 必须有 `id`——按现文字所有 part 都校验失败。

### 0.1 裁决落地状态（2026-11-11 更新）

本文的 P0 门禁项已由 `D-024` 逐条落实，本文留下的规格缺口另有 `D-027`、`D-028`、`D-029` 收口。下表的"现状态"只标注结论，不重写历史证据；具体文字以 `docs/spec-profile-model.md`、`docs/spec-profile-builtin.md`、`docs/spec-profile-validation.md` 与 `docs/spec-manifest.md` 为准。

- **已解决**：A、B、C、D、E、F、G、H、I、J、K、L、N、O 及 §2.1–§2.5、§3.2、§3.3、§4.1 的 P0 门禁项。
- **模型已解决、profile 仍待补全**：M（§3.1 V5 同类噪声可在实现前继续补条目）。
- **仍未单列裁决**：V10（带 parts 条目聚合时的 `E-MAN-052` 豁免口径）与 V12（catch-all 的 `priority` 是否删除）；按现规格实现时需避免依赖这两个空档。

---

## 1. A–O 逐条复判

判定口径：
- **解决**：v2 字段/规则能写出该条并得到正确结论，无关键语义丢失。
- **部分**：能写、能暴露，但有一块语义仍丢失或只能靠人工注记。
- **未解决**：写不出，或写出来会被读成错误结论。

| # | 类别 | v1 | v2 主要字段/规则 | 复判 | 现状态（2026-11-11） |
|---|---|---|---|---|---|
| A | `.claude.json` 多段混层 | 表达不了 | `parts` + `json_pointer`、`churn`、`max_bytes_structure` | **未解决（部分实现）** | **已解决**（D-024 第 1–3 条） |
| B | `projects/<slug>` 派生 | 需补字段 | `path_semantics`、`derived_from: repo_slug`、`machine_derived_path` | **未解决（只有标记）** | **已解决**（D-024 第 3 条 origin） |
| C | project 内非 jsonl 附件 | 表达不了 | `priority`、`binary: true` + `max_bytes_inline: 0`、`max_bytes_total` | **解决** | 保持（D-024 第 6 条改名） |
| D | `plugins/` 混层 | 表达不了 | `priority` + 细条目 + catch-all | **部分** | **已解决**（D-024 第 4 条拆条 + `under`） |
| E | `file-history` | 需补字段 | `needed_by: ["rewind"]`、L0 + `deletion_cost` | **解决** | 保持 |
| F | worktree | 表达不了 | `derived_from: git_worktree_of`、`**/.git` 并列排除、`expand: aggregate` | **解决** | 保持；origin 随 B 已解决 |
| G | 根外巨型缓存 | 表达不了 | `localappdata` root、`expand: aggregate`、`max_bytes_total`、manifest §4.7 聚合形态 | **解决** | **已解决**（D-024 第 6 条 + D-021 #9） |
| H | sqlite + WAL/SHM | 表达不了 | `companions`、`side_effects: ["shm_created"]`、`binary: true` | **解决（有 3 个规则缺口）** | **已解决**（D-024 第 5 条 `open_as`） |
| I | junction / 符号链接 | 需补字段 | `follow_symlinks: false`、`dedupe_targets`、`packages` 条目 | **解决** | 保持 |
| J | 跨仓库同名文件 | 表达不了 | `unique_within: root` + 重复 `--root repo=PATH` | **解决（需手工枚举）** | 保持（手工枚举取舍未变） |
| K | `~/.claude` 顶层未覆盖 | 表达不了 | `kind: catch-all` | **部分（scope 错误）** | **已解决**（D-024 第 4 条 `under`） |
| L | repo 内未覆盖 + 多仓库 | 表达不了 | `repo-rules`、`repo-scheduled-tasks-lock`、重复 `--root` | **解决（需手工枚举）** | 保持 |
| M | codex 未覆盖项 | 表达不了 | 新条目 + catch-all | **解决（模型）/ profile 未补全** | 模型保持；内置 profile 待补 |
| N | 声明但本机不存在 | 可表达 | `packout profile probe`（§11.1） | **解决** | 保持 |
| O | 分散凭据点 | 需补字段 | `key_pattern` 作用域（dotenv/TOML）、`needed_by`、E-PRF-042 放宽 | **解决** | 保持 |

### A — `.claude.json`

- 相关 entry：`claude-json`。字段：`parts[]` 的 `selector.json_pointer`、`layer`、`secret`、`extractor`、`needed_by`；条目级 `churn: high`、`max_bytes_inline: 0`、`max_bytes_structure`、`max_bytes_total`、`priority`。
- v2 已解决：`machineID`/`userID` 可固定为 L4；`/projects` 可单独 keys-only；`/projects/*/history` 可单独 L3；`churn` 与结构预算从 `max_bytes_inline` 拆开。
- 本机实测打脸三处：
  1. **part 没有"剩余值"兜底**。49 个顶层键只被 3–4 个 pointer 覆盖；`mcpServers`、`githubRepoPaths`、`cachedExperimentFeatures`、`pluginUsage` 等其余 40+ 键不会产出任何 Unit。§5.9 的"一个都没命中"兜底只处理"零个 part 命中"，不处理"部分未命中"；也没有 `part_missing` note。v1 明确关心的 L2 `mcpServers` 段在内置 profile 里甚至没有对应 part。
  2. **`max_bytes_structure` 不能做到"不读全量"**。本机文件 91,346 B < 默认 1 MiB，JSON Pointer 解析必须遍历整个文档（值可以丢弃，但字节必须读）。该字段只是上限，不是流式跳过。若把上限压到 <91 KB，`/projects` 之后的 part 会因预算耗尽而缺失，且没有 per-part 的 `budget_exceeded` 语义。
  3. **`keys-only` part 的指纹要求与 `max_bytes_inline: 0` 冲突**。manifest §4.10 规定 part Unit 的 `fingerprint` 只覆盖该段、`scope: full`；`/projects` 段值约 18 KB，做 full 指纹必须读值，与条目 `max_bytes_inline: 0`（以及"只读键路径"）矛盾。
- 另一处真实证据：本机 **0/43** 个 project 有 `history`，`project-history` part 静默零命中，既不产出 Unit 也无 note。
- `json_path_key` 不可用：`/projects` 的键本身是机器派生绝对路径，但 `path_semantics` / `derived_from` 不能写在 part 上（`E-PRF-036`），§5.10 只好说"在 notes 说明"——这不是结构化语义。
- 复判：**未解决**。已解决的只是"把大段拆开"，不是 v1 要的"混层文件被正确、完整、低代价地表达"。

### B — `projects/<slug>`

- 相关 entry：`projects-transcripts`、`projects-tool-results`、`projects-subagents`。字段：`path_semantics: machine_derived`、`derived_from: repo_slug`，manifest `risk_flags: ["machine_derived_path"]`、`slug_collision`。
- v2 已解决：slug 会被标成机器派生，报告能与普通路径区分；换机后不会把旧 slug 当稳定锚点。
- 仍未解决（直接回答任务里的重点项）：
  1. **slug → 仓库无法对应**。`derived_from` 只说明"怎么来的"，不携带源路径；slug 变换是多对一（`\`、`_`、`.`、`-` 都折叠成 `-`），不可逆。本机 37 个 slug 与 `.claude.json` 的 43 个绝对路径键也不一一对应（含已删除 worktree）。报告只能看到 `D--Study-Chatrix-Chatrix--claude-worktrees-…`，没有字段能还原成 `D:\Study\Chatrix\Chatrix\.claude\worktrees\…`。
  2. **`slug_collision` 在目录 slug 上不可探测**。扫描器只看到 slug 目录名，看不到两个源路径；要判定碰撞必须先有源路径集合（`.claude.json` 的 `projects` 键，或 `codex config.toml` 的 `[projects.'d:\…']` 段）。规格没有把这个集合与 slug 关联，因此该 flag 实际上无法产生。
  3. `json_path_key` 的合法落点缺失（见 A），使唯一可能的结构化源路径集合也用不上。
- 复判：**未解决**。需要"origin 字段 + 源路径来源"两步，见 §4。

### C — project 目录内非 jsonl 附件

- 相关 entry：`projects-tool-results`、`projects-subagents`。字段：`priority`、`binary: true`、`max_bytes_inline: 0`、`max_bytes_total`、`derived_from: repo_slug`。
- v2 已解决 v1 的两个死结：整目录/`*.jsonl` 与具体附件重叠时有 `priority` 裁决（§5.2.1）；二进制可 `binary: true` + 0 预算（`E-PRF-042` 例外）。
- 本机：11 个 `tool-results/`、19 个 `subagents/`、397 个非 jsonl，最大 PDF 9,870,272 B，最大 txt 1,851,132 B，均能落进这两条。
- 残留的只是 profile 完整度：`projects/D--Study-Chatrix/bytedesk-tree.json`（4,764,342 B）、各 slug 根的 `auto-mode-classifier-error.txt`、`.desktop-released.json` 仍会落 catch-all（L2/keep），可另加 `projects/*/*.json`、`projects/*/*.txt` 条目解决；不是模型缺口。
- 复判：**解决**。

### D — `plugins/` 三层混在同一目录

- 相关 entry：`plugins`（dir，priority 1）、`plugins-cache`（10）、`plugins-marketplaces`（10）、`plugins-enabled`（20）、`plugins-config`（20）、`plugins-store`（10）、`plugins-data`（10）。
- v2 已解决：重叠有 `priority`；`exclude` 从错误的 `repos/**` 改成 `marketplaces/**`；`installed_plugins.json` 与 `enabled*.json` 被纳入 L2；`*/config.json` L2；`store/` L3；`data/` L0。
- 本机实测仍漏：
  - `plugins/known_marketplaces.json`（528 B，配置，L2）
  - `plugins/plugin-directory-cache-v2.json`（2,754,173 B，缓存，L0）
  - `plugins/claude-hud/heartbeat.json` 与 28 个 `heartbeat.json.<pid>.tmp`、`plugins/claude-hud/stripped/`、`plugins/claude-hud/statusline.{cmd,mjs}`、`previous-statusline.txt`、`plugins/.last_inuse_sweep`
  这些路径都被宽条目 `plugins`（priority 1）命中，因此 **不会进 catch-all 残留**，而是被当作 L1 `keys-only` / `reinstall`。也就是说：优先级解决了"重"，catch-all 没有解决"漏"，因为宽条目先把它们认领了。
- 根因：catch-all 不能限定子目录；`plugins` 这种"整目录低优先级"条目会把语义未知项静默吞掉。报告里 `residual = 0` 并不代表 plugins 目录已被正确分类。
- 复判：**部分**。

### E — `file-history`

- 相关 entry：`file-history`。字段：`needed_by: ["rewind"]`、`layer: L0`、`expand: aggregate`；manifest 要求 L0 + needed_by 必带 `risk_flags: ["deletion_cost"]`（E-MAN-062），报告单列。
- 本机 271 个 `@vN` 快照、2.7 MB。v1 的"层定不下来"已被 `needed_by` 明确：层仍 L0/`delete`，但单独标删除代价。
- 复判：**解决**。

### F — worktree

- 相关 entry：`repo-worktrees`。字段：`path_semantics: machine_derived`、`derived_from: git_worktree_of`、`expand: aggregate`、`priority: 5`；默认 exclude 已把 `**/.git` 与 `**/.git/**` 并列。
- 本机 qianniu worktree 386 MB，`.git` 为普通文件，内容 `gitdir: D:/Study/Intern/qianniu/.git/worktrees/optimistic-ramanujan-4d7362`，v1 的"`.git` 文件不被排除"已修。
- 残留：`derived_from: git_worktree_of` 只做语义命名，没有字段指向主 checkout；`E-PRF-039` 只检查路径含 `.claude/worktrees/`。与 B 共用 origin 缺口。聚合后也不能区分"上游源码 / 未提交改动"。
- 复判：**解决（expressive）**，origin 缺口同 B。

### G — 根之外的 8.5 GB

- 相关 entry：`claude-vm-bundles`、`claude-agent-sessions`。字段：`localappdata` root、`expand: aggregate`、`max_bytes_total`；manifest §4.7 定义了聚合 Unit 的 `size_*` 求和、`file_id: null`、`aggregate_count`、`fingerprint.scope: aggregate`、`secret.class` 保守合成。
- 本机 `Claude-3p/vm_bundles` 8.5 GB、`local-agent-mode-sessions` 629 MB，均可覆盖。
- 残留：D-021 第 9 条要求的 `contains_secret` / `may_contain_secret` 尚未写进 manifest；聚合 Unit 的 `secret.class` 把"实际命中"与"后代声明会 scan"混在一起。
- 复判：**解决**（待 D-021 #9 落地）。

### H — sqlite + `-wal` / `-shm`

- 相关 entry：`sqlite-state`、`sqlite-logs`、`sqlite-thread-history`、`sqlite-other`。字段：`companions`、`side_effects: ["shm_created"]`、`binary: true`、`max_bytes_inline: 0`、`max_bytes_total`。
- 本机：主库与其 `-wal`/`-shm` 可并成一个 Unit；`logs_2.sqlite-wal` 0 B 合法；`goals_1`/`queue_1` 有 32,768 B 的 `-shm`，与 D-015 第 3 条一致。
- 三个未闭合点：
  1. `sqlite-other` 的 `paths: ["*.sqlite", "sqlite/*.sqlite"]` **漏掉真实的 `sqlite/codex-dev.db`（36,864 B）**；它退到 `codex-residual` L2 keys-only，既不分组也不 `digest`。这是内置 profile 的事实错误，不是模型缺口。
  2. **伴生文件与 catch-all 的关系未定义**。`goals_1.sqlite-shm` 是否算"已被非 catch-all 命中"？§5.11 说伴生不单独成 Unit，但 §5.2.1 的残留判定没提伴生；若按字面"只按主文件匹配"，`-shm` 会被 catch-all 再产出一条残留 Unit，与 `E-MAN-063` 冲突。
  3. **`side_effects` 的前提不自洽**。条目是 `binary: true` + `extractor: digest`，引擎只需按字节哈希，不需要以 sqlite 打开数据库，因而不会创建 `-shm`。manifest §8 又写"sqlite 以 `mode=ro` 打开"，但 profile 没有任何字段声明"按 sqlite 打开"；`side_effects` 只是预期副作用的声明，不是打开方式的声明。
- 复判：**解决**（需补一条伴生/残留规则与 `open_as` 或删除 `side_effects`）。

### I — junction / 符号链接

- 相关 entry：`codex-packages` 等。字段：`follow_symlinks: false`（默认）、`dedupe_targets: true`、`link_target`、`risk_flags: ["symlink"/"junction"]`。
- 本机 `packages/app-server-daemon/current` 是 junction，目标 `releases/0.167.0-x86_64-pc-windows-msvc`；不跟随即产出一个链接 Unit，不会把 releases 内容重复计入。
- 残留：`expand: aggregate` 与"链接本身产出 Unit"的先后未写清（链接是被聚合还是单独一行），属小缺口。
- 复判：**解决**。

### J — 跨仓库同名文件

- 相关 entry：`repo-settings-local`、`repo-claude-md`。字段：`unique_within: root`；CLI 重复 `--root repo=PATH`。
- 本机 3 份 `settings.local.json`，分别位于 Chatrix、Chatrix/Chatrix、Projects/Planora。只要给 3 个 `repo` 实例，每个实例内该 entry 恰命中 1 条不同 `path_key` → 3 份都升 L3。v1 的"全局计数永不触发"已解决。
- 本机 6 份 `CLAUDE.md`：同样会各自升 L3。注意 `CLAUDE.md` 是 git tracked 的仓库资产，v1 认为"本就随仓库走、不需要迁"；`unique_within` 没有 `unless git_tracked`，会把它们升 L3/`migrate`。这是策略选择，需在 D-021 口径里明确。
- 残留：没有自动仓库发现，12 个 `.claude/` 要人工逐个 `--root`；不枚举的仓库不在扫描内，catch-all 也救不了（不存在的 root 不会被扫）。
- 复判：**解决**（手工枚举）。

### K — `~/.claude` 顶层未覆盖项

- 相关 entry：`home-residual`（catch-all，`max_depth: 3`，L2，keep，confidence 0.5）。字段：`kind: catch-all`、`signals: []`。
- v2 已解决：schema 上存在"未命中残留"这一概念，漏配不再永久静默；`agents/`、`backups/.*`、`settings.json.*` 等也有具体条目。
- 但本机语义有两个硬问题：
  1. **catch-all 只能绑 root，不能绑子目录**（§4.2 / `E-PRF-037` 禁止 `path`/`paths`）。`home` root 是 `%USERPROFILE%`，本机顶层有 71 项：`AppData`、`.codex`、`.cursor`、`.gemini`、`.config`、`Documents`……`home-residual` 会扫整个用户目录（`max_depth: 3` 只限深度，不限广度）。`AppData/Local` 与 `.codex` 同时又是 `localappdata` / `codex` root，同一路径可能被两个 root 的 catch-all 各认领一次；"任一非 catch-all entry 命中"是否跨 root 全局判定没有写。
  2. **D-021 第 4 条使 `.claude` 目录本身永远是残留项**。本机 `home-residual` 至少会为 `.claude/` 产出一个聚合残留 Unit（其下未被其他条目录中的后代计入 `aggregate_count`），再加上 `.claude.json.backup`（12,792 B）、`plans/`、`daemon/`、`jobs/`、`session-env/`、`stats-cache.json` 等。`stats.residual > 0` 因此恒成立，`W-MAN-114` 失去告警意义。
- 复判：**部分**（概念解决，作用域未解决）。

### L — repo 内未覆盖项与多仓库根

- 相关 entry：`repo-rules`、`repo-scheduled-tasks-lock`、`repo-commands` 等；重复 `--root repo=`。
- 本机 Chatrix/Chatrix 有 4 份 `rules/*.md`，Chatrix/Yanju 也有；`Chatrix/Chatrix/.claude/scheduled_tasks.lock` 存在。v2 profile 已补 `rules/**` 与 `scheduled_tasks.lock`。
- 多仓库靠手工枚举 12 个 root；`D:\Study` 本身设为 root 时只能命中顶层 `.claude/`，嵌套仓库仍需单独 root。这是 D-015 的既定取舍，不是遗漏。
- 复判：**解决**。

### M — codex 未覆盖项

- 相关 entry：`sqlite-*`、`packages`、`global-state`、`installation-id`、`archived-sessions`、`sessions`、`auth`、`dotenv`、`sandbox-secrets`、`codex-residual` 等。
- 模型层已解决：大块（sqlite 460 MB、packages 1.1 GB、sessions 1.2 GB、archived 16 MB）都有字段可写。
- profile 层仍漏：`.codex-global-state.json.bak`、`cap_sid`（36,637 B）、`cc-switch-model-catalog.json`、`session_index.jsonl`、`memories/`、`skills/`、`vendor_imports/`、`node_repl/`、`pets/`、`process_manager/`、`computer-use/`、`app-server-*`、`thread-writer-locks/`、`plugins/`（38 MB）、`cache/`（73 MB）、`.sandbox*`、`backup-deepseek/`、`models.json`、`mi250*`、16 个 `hooks.aproo-backup-*.json`、`config.toml.usage-backup-*`、`auth.lock`、`sandbox.*.log`，以及 `sqlite/codex-dev.db`。这些会落到 `codex-residual`（L2/keep），可见但层不对（cache/log 应为 L0，skills/plugins 应为 L1/L3）。
- 复判：**模型解决；内置 profile 未补全**（不是 model 缺陷，但发布前要补，否则 residual 噪声很大）。

### N — profile 声明但本机不存在

- v2 新增 `packout profile probe`（§11.1）：只读检查每条 entry/part 的存在性，输出 `present` / `absent` / `not_evaluable` / `root_unresolved`，`absent` 退出码 1。
- 本机实测 absent：`~/.claude/todos/`、`skills/`、`settings.local.json`、`.credentials.json`、`statsig/`、`ide/`、`.codex/log/`，以及所有 `.mcp.json`。probe 能直接发现。
- 复判：**解决**。

### O — 分散的凭据点

- 相关 entry：`sessions`（L0 + scan + `binary: true` + `needed_by: ["daemon"]`）、`codex-config`、`auth`、`dotenv`、`sandbox-secrets`。
- v2 已解决：`redact.key_pattern` 明确定义了 JSON 键名 / dotenv 行首键名 / TOML 键路径三种作用域；`E-PRF-042` 允许 `binary: true` + `max_bytes_inline: 0`；L0 可以有 `needed_by`。
- 本机：`settings.json` 的 `env.ANTHROPIC_AUTH_TOKEN` 可被 JSON key_pattern 脱敏；`.codex/config.toml` 的 `[model_providers.custom].experimental_bearer_token` 可被 TOML key path 匹配；`.env`（实际只有 4 个 proxy 键）按 dotenv 行首处理；`.sandbox-secrets/sandbox_users.json` 828 B。
- 残留：`~/.claude/daemon/control.key`（32 B）与 `pipe.key`（16 B）没有专门条目，只落 `home-residual`（L2、scan、keys-only），不会进导出；`sessions/*.key` 因为 `max_bytes_inline: 0` 只记存在性，不产生 `secret.hits`。这是有意取舍，但报告要写清"未检测"。
- 复判：**解决**。

---

## 2. 五个重点项的正面回答

### 2.1 `.claude.json` 的 parts 能否在"不读全量"下表达？

**否。** `max_bytes_structure` 只是"最多读多少字节来解析结构"的上限；本机 91,346 B 小于默认 262,144 B / 内置 profile 的 1 MiB，解析 JSON Pointer 仍然要读完整文件（可以丢弃值，但字节必须过一遍）。JSON 不是可随机访问的索引结构。更糟的是 manifest §4.10 要求 part Unit 给出该段的 `fingerprint.scope: full`，对 `/projects` 这种段必须读值，与条目 `max_bytes_inline: 0` 冲突。要兑现"不读全量"只有两条路：
- 改规格措辞：`max_bytes_structure` 只保证"不保留值、不做内容检测"，不保证 I/O 不读；
- 或者新增 `structure_read: streaming` 语义 + 定义 `keys-only` part 的指纹为键路径摘要（新 `fingerprint.scope: "keys"` 或允许 `null`）。

另外，本机 0/43 个 project 有 `history`，内置 profile 的 `project-history` part 零命中且无 note；49 个顶层键中 40+ 个不属于任何 part——parts 只能表达"被点名的那几段"，不能表达"其余部分"。


> 状态（2026-11-11）：**已解决**。D-024 第 1、2 条新增 `parts_uncovered` 与 `fingerprint.scope: keys`，并把 `max_bytes_structure` 的措辞限定为"不保留值"，不承诺跳过 I/O。

### 2.2 `projects/<slug>` 的 `derived_from: repo_slug` 能否让报告把 slug 与仓库对应起来？

**否。** 它只回答"这是派生路径、换机会变"，不回答"派生自哪个仓库"。slug 变换不可逆；报告没有 origin 字段可用。`slug_collision` 也无法在扫描目录 slug 时被发现，因为两个源路径不会同时出现在扫描输入里。要做到对应，至少需要：
- profile/Unit 增加 `origin`（或 `origin_path_key`）字段，来源是 `.claude.json` 的 `projects` 键或 codex `config.toml` 的 `[projects.'d:\…']` 段；
- 让 `json_path_key` 能写在 part 上（或新增 `part.derived_from`），并把源路径集合与 slug 目录做一次映射；
- 映射多对一时设置 `slug_collision`。


> 状态（2026-11-11）：**已解决**。D-024 第 3 条新增 `origin` / `origin_path_key`，并允许 part 级 `path_semantics` / `derived_from`。

### 2.3 `plugins/` 的 priority + catch-all 能否既不重不漏？

> 状态（2026-11-11）：**已解决**。D-024 第 4 条给 catch-all 增加 `scope` / `under`，并删除整目录 `plugins`、改为具体条目。

- **不重：可以。** `priority` 让 `plugins/*/config.json`（20）、`data/**`（10）、`cache/**`（10）压过整目录 `plugins`（1）；同一路径只有一个赢家。
- **不漏：不可以。** 整目录 `plugins` 条目会把 `known_marketplaces.json`、`plugin-directory-cache-v2.json`、`heartbeat.json*`、`stripped/**` 全部认领为 L1，catch-all 看不到它们。catch-all 只能绑 root，不能绑 `.claude/plugins`。结果是"没有 residual"但"分类错误"，恰好是 v1 最担心的静默漏配换了个形式。
- 最小修法：删掉整目录 `plugins` 条目，让 catch-all 暴露剩余项；或允许 `catch-all` 带 `under`/`scope`，为 `.claude/plugins` 单设一条；同时补 `known_marketplaces.json` L2、`plugin-directory-cache-v2.json` L0、`heartbeat*` L0、`.last_inuse_sweep` L0。

### 2.4 codex sqlite + `-wal`/`-shm` 的 companions 与 side_effects 是否成立？

> 状态（2026-11-11）：**已解决**。D-024 第 5 条新增 `open_as: sqlite-ro` 并写死伴生文件不参与残留判定。

**基本成立，但有三处必须澄清。**
- `companions` + 合并 Unit + `fingerprint` 覆盖全部成员：成立；0 B 的 WAL 也合法。
- `side_effects: ["shm_created"]`：本机确实有 `-shm`（goals/queue 各 32,768 B），但 profile 的 `extractor: digest` + `binary: true` 只要求按字节哈希，不要求以 sqlite 打开，因而不会产生 `-shm`。规格要说明这是"若引擎以 sqlite 打开"的声明，并补一个 `open_as: sqlite-ro`（或 `reader`）字段；否则 `side_effects` 是空转，且与 manifest §8 "sqlite 以 mode=ro 打开"没有 profile 依据。
- 真实缺陷：`sqlite-other` 的 glob 漏了 `sqlite/codex-dev.db`；必须加 `sqlite/*.db` 或改为显式两条路径。
- 伴生文件与 catch-all 的归属必须写死：伴生文件视为"已随主文件命中"，不得再产 residual。

### 2.5 跨仓库 `settings.local.json` 在 `unique_within: root` 下能否正确升 L3？

> 状态（2026-11-11）：结论保持；`git_tracked` 是否参与升层仍按 D-021 第 2 条的声明层口径，未另加例外。

**能。** 规则是"按 entry、按每个 root 实例分别计数不同 `path_key`；实例内恰命中 1 个就升 L3"（D-021 #2）。本机 3 份分别在 3 个仓库实例里，各实例都命中 1 个 → 都升 L3；若某个实例内有 2 份，则只有该实例不升。这正是 v1 想要的口径。

前提是手工给出 3 个 `--root repo=…`；不枚举的仓库不会被扫。另需明确：`repo-claude-md` 这种 git tracked 的仓库资产也会因 `unique_within` 升 L3/`migrate`，是否接受要在决策里写清。

---

## 3. 主动找出的新漏洞

### 3.1 `priority` / `parts` / catch-all 的组合歧义

| # | 问题 | 证据 | 影响 | 最小修法 |
|---|---|---|---|---|
| V1 | **part 没有"剩余值"兜底** | §5.9 只定义"一个 part 都没命中"；本机 `.claude.json` 49 键只覆盖 4 段 | A 类仍漏 40+ 键；`mcpServers` 这种 L2 段在内置 profile 中无 part | 新增 `parts_uncovered: {layer,secret,extractor}` 或允许一条低优先级 `selector: {"json_pointer": "/**"}` 作为 part 兜底；每个未命中的 part 各记 `part_missing` |
| V2 | **`keys-only` 祖先 part 的指纹要求与 `max_bytes_inline: 0` 冲突** | manifest §4.10 + §4.5 `scope: full` | 无法既"只读键"又满足 manifest | 定义 `fingerprint.scope: "keys"`（键路径排序摘要）或允许 part 指纹 `null` + `content_partial` |
| V3 | **`json_path_key` 无合法落点** | `E-PRF-036` 禁止 part 写 `path_semantics`；§5.10 只能写 notes | B 类映射无法结构化 | 允许 part 级 `path_semantics`/`derived_from`，或新增 `part.key_semantics` |
| V4 | **catch-all 不能限定子目录，且与重叠 root 的关系未定义** | `E-PRF-037` 禁止 `path`；`home` = `%USERPROFILE%`，本机顶层 71 项 | home-residual 扫整个用户目录；`.codex`/`AppData` 与 codex/localappdata root 重叠；`residual` 恒 > 0 | catch-all 增加 `under`/`scope`（相对 root、无 glob）；规定"任一 root 的非 catch-all 命中即不算残留"，同路径两 catch-all 只取一个并记 note |
| V5 | **宽条目会吞掉 catch-all** | `plugins` priority 1 认领 `known_marketplaces.json` 等 | "不漏"只在 selector 未命中时成立，分类错误不暴露 | 删宽条目或给 catch-all 加子目录 scope；报告把"宽条目命中的低置信项"单列 |
| V6 | **伴生文件与 catch-all 归属未定义** | §5.11 vs §5.2.1；`E-MAN-063` | `goals_1.sqlite-shm` 可能同时是伴生与被残留 | 明确"伴生文件视为主文件命中，不参与残留判定" |
| V7 | **`side_effects` 无打开方式依据** | `extractor: digest` 不打开 sqlite；manifest §8 说以 `mode=ro` 打开 | 声明空转，或引擎越权打开 | 新增 `open_as: sqlite-ro`；或删除 digest 条目的 `side_effects` |
| V8 | **`unique_within` 与 catch-all 可同时写** | catch-all 默认 L2；`E-PRF-047` 只限制非 L2 | 若残留恰 1 项，会把 catch-all 升 L3，与 `E-MAN-055`/`E-MAN-064` 的固定 L2 冲突 | 禁止 catch-all 使用 `unique_within`（扩展 `E-PRF-047`） |
| V9 | **catch-all 的 `max_depth` 与 `aggregate_count` 口径未对齐** | §5.2.1 要求计入"未被其他 entry 命中的后代"；`max_depth: 3` 会截断 | `aggregate_count` 少计，报告以为已统计完 | 规定 `aggregate_count` 只计已遍历深度，并加 `depth_truncated` note |
| V10 | **带 parts 的 entry 聚合时与 `E-MAN-052` 冲突** | `max_bytes_total` 耗尽会"其后命中转聚合 Unit"（§5.8），但 `E-MAN-052` 要求有 parts 的 entry 必须有 `part_id` | 聚合行无 `part_id`，校验器判错 | 禁止带 parts 的 entry 聚合，或给聚合行豁免 `E-MAN-052` 并定义语义 |
| V11 | **manifest 排序键把 `part_id` 放在 `path_key` 前** | §2 排序键 `(root_index, profile, entry_id, part_id, path_key)` | 同一文件的多个 part 不相邻，聚合/报告分组别扭 | 改为 `(root_index, profile, entry_id, path_key, part_id)` |
| V12 | **catch-all 的 priority 永远不参与裁决** | §5.2.1 规定有任一非 catch-all 命中就不进 catch-all；`E-PRF-037` 又强制 priority < 0 | `priority: -100` 是死字段；普通条目也可写负数而无人约束 | 明确 catch-all 不参与优先级裁决；禁止非 catch-all 使用负 `priority`（扩展 `E-PRF-046`）或删字段 |
| V13 | **`E-PRF-036` 把 `id` 列为 part 禁写字段** | 与 §5.9 "part `id` 必填"直接矛盾 | 按字面所有 part 校验失败 | 从 `E-PRF-036` 移除 `id` |
| V14 | **manifest 字段表有一行粘连** | §4.1 `aggregate_count` 行末尾 `|| proposed_action` 把两行并成一行 | 按表生成的校验器/文档会缺字段 | 拆成两行 |
| V15 | **`parts` 与 `max_bytes_total` 中途耗尽的语义未定义** | §5.8 只说"当前文件照常完成，其后命中转聚合" | 单文件内多 part 的预算耗尽无定义 | 规定 part 级预算耗尽记 `budget_exceeded` + `content_partial`，已解析 part 照常产出 |
| V16 | **`home-residual` 使 `stats.residual > 0` 恒成立** | D-021 #4 让 `.claude` 目录本身成为残留项；本机必然如此 | `W-MAN-114` 失去意义，报告长期告警 | 区分 `residual_items` 与 `residual_roots`，或 catch-all scope 到 `.claude` |

状态（2026-11-11）：V1–V9、V11、V13–V16 已由 D-024（第 1–8 条）与 D-027 第 5 条落实；V5 由 D-024 第 4 条拆条解决。V10（带 parts 条目聚合与 `E-MAN-052`）和 V12（catch-all 的 `priority` 是否删除）尚未单列裁决，实现时按现规格避开这两个空档。

### 3.2 D-021 与 v2 文档不一致（必须在冻结 schema 前解决）

| 决策 | 决策要求 | v2 现状 | 结论 |
|---|---|---|---|
| D-021 #3 | `binary` 改名 `opaque_content` | profile / manifest / `risk_flags` / `E-PRF-042` / `E-MAN` 全部仍用 `binary`；全文无 `opaque_content` | **未落地**，字段名要全局统一 |
| D-021 #4 | catch-all 必须带 `residual` 信号 | spec-profile §5.2/§8.1 内置 profile 用 `signals: []`；manifest 允许空数组，`W-MAN-117` 反而警告非空 signals | **直接矛盾**，二选一：改决策或改规格 |
| D-021 #9 | 聚合 Unit 拆 `contains_secret` / `may_contain_secret` | manifest §4.1/§4.3/§4.7 仍只有一个 `secret.class`；两字段全文不存在 | **未落地**，聚合 Unit 会把"可能"显示成"含密" |

状态（2026-11-11）：三项均已由 D-024 第 6 条落地；`binary` 旧名读入映射，聚合 Unit 两个布尔字段已进 manifest §4.3/§4.7。

### 3.3 内置 selftest 与 fixture 的硬错误

1. `docs/spec-profile-builtin.md` 内置 `claude-json` 的 `machine-identity` part 声明 `"secret": "none"`，但 selftest（§8.1 `expect`）断言 `"secret": "reference"`。按现有文字，`packout profile test claude-code` 必然失败。
2. `profiles/fixtures/claude-code/home/.claude.json` 第 5 行是 `"D:\Study\demo": {`，`\S` / `\d` 不是合法 JSON 转义；fixture 本身无法解析，parts 的 selftest 跑不起来。改为 `"D:/Study/demo"` 或 `"D:\\Study\\demo"`。
3. 同 fixture 的 `history` 存在，而真机 0/43；selftest 会全绿，正好印证 D-016 的"fixture 照 profile 造，路径写错也全绿"。`profile probe` 是对的补法，但内置 profile 的真机核实仍需单独跑。
4. `codex` fixture 未生成 `sqlite/*.db`，无法覆盖 `sqlite-other` 的真实 `.db` 分支。
5. 内置 `codex` profile 的 `sqlite-other` 注释说覆盖 `sqlite/` 子目录，但 glob 只有 `sqlite/*.sqlite`；本机真实文件是 `sqlite/codex-dev.db`。

状态（2026-11-11）：五项均已由 D-024 第 7 条修正（`machine-identity` 期望改 `none`、fixture 改 `D:/Study/demo`、补 `mcpServers` 与剩余键样本；fixture 侧另补 `sqlite/queue_1.sqlite` 与 `sqlite/*.db` 覆盖）。

### 3.4 其他真实语料/规格缺陷

- **`home` root 的 catch-all 与 `localappdata`/`codex` root 重叠**：`%LOCALAPPDATA%` 和 `.codex` 都在 `%USERPROFILE%` 下，同一路径可能被两个 root 的 catch-all 各产出一行；需要跨 root 的"已声明"判定。
- **`CLAUDE.md` / `AGENTS.md` 被 `unique_within` 升 L3**：这些是 git tracked 的仓库资产，升 L3/`migrate` 与 v1 观察"本就随仓库走"相反；如果要避免，需要 `unique_within` 增加 `unless_git_tracked` 或改用 `(basename, content)` 口径。
- **`repo` root 默认 `${REPO_ROOT}` 未设置时**：profile 仍能靠 `home` 展开启动，但 `repo` 条目是无 note 跳过还是报错，扫描路径没有规定（probe 有 `root_unresolved`，scan 没有）。
- **`config.toml` 的 `[projects.'d:\…']` 段**同样是机器派生绝对路径键，且整文件是 L2；`json_path_key` 同样无落点。这是 B 类在 codex 侧的翻版。
- **manifest `cid` 与 part**：part Unit 的 `cid` 由该段指纹派生，同一段内容出现在不同文件会得到相同 `cid`，报告"疑似同一内容"可能误报；建议在 `cid` 说明里限定 part 的 `cid` 只用于同 part 语义。
- **`secret.class` 与 `extractor: none` 的 L3/L5**：`W-PRF-130` 只是 info；本机 `repo-worktrees` 是 L3 + `raw-ref`、`sessions` L0 + scan + 0 预算，报告需要明确"未做内容检测"。

---

## 4. 有条件通过的最小修改清单

### 4.1 实现前必须改（P0 门禁）

| # | 改哪里 | 具体字段/规则 | 解决 |
|---|---|---|---|
| P0-1 | profile §5.9 + 校验 | 新增 `parts_uncovered`（或允许低优先级 `/**` part 兜底）；未命中的每个 part 各记 `part_missing` note；`part` 缺省继承行为写清 | A、部分 D |
| P0-2 | manifest §4.5/§4.10 | 定义 `fingerprint.scope: "keys"`（键路径排序摘要）或允许 keys-only part 指纹 `null` + `content_partial`；与 `max_bytes_inline: 0` 相容 | A |
| P0-3 | profile §5.10 + `E-PRF-036` | 允许 part 写 `path_semantics`/`derived_from`，并把 `json_path_key` 与 `/projects`、`config.toml [projects]` 关联；新增 `origin`/`origin_path_key` 字段（profile 或 Unit） | A、B、F、codex 侧 |
| P0-4 | profile §4.2/§5.2 + `E-PRF-037` | catch-all 增加 `under`/`scope`（相对 root、不得 glob）；规定跨 root："任一非 catch-all 命中即不算残留"，同路径多 catch-all 只取一个并记 `priority_tie` 类 note | D、K、V4 |
| P0-5 | 内置 profile `.claude/plugins` | 删除整目录 `plugins`（或降为 `residual_only`）；补 `known_marketplaces.json` L2、`plugin-directory-cache-v2.json` L0、`heartbeat*`/`stripped/**`/`.last_inuse_sweep` L0 | D |
| P0-6 | profile §5.11 + manifest §4.12 | 明确伴生文件视为随主文件命中、不进 catch-all；`companions` 的主文件缺失时不产伴生 Unit（已有 E-MAN-063，补 profile 侧） | H、V6 |
| P0-7 | profile §5.11 + manifest §8 | 新增 `open_as: sqlite-ro`（或 `reader`）字段，`side_effects` 才有依据；或删除 digest 条目的 `side_effects` | H、V7 |
| P0-8 | 全文档 | 落实 D-021：`binary` → `opaque_content`（含 `risk_flags` 与错误码）；聚合 Unit 增 `contains_secret` / `may_contain_secret`；catch-all 的 `residual` signal 与 D-021 #4 二选一 | 全局一致性 |
| P0-9 | profile §5.3 + `E-PRF-047` | 禁止 catch-all 使用 `unique_within`；明确 `git_tracked` 是否参与升层 | J、V8 |
| P0-10 | selftest | 修 `machine-identity` 的 `secret` 期望为 `none`；修 fixture 非法 JSON 转义；codex fixture 增加 `sqlite/*.db` | 门禁 |
| P0-11 | profile `E-PRF-036` / manifest §4.1 | 从 part 禁写字段移除 `id`；拆开 `aggregate_count`/`proposed_action` 粘连行 | 规格自洽 |

状态（2026-11-11）：P0-1 至 P0-11 均已由 D-024 落实；本表保留为验收对照。

### 4.2 建议一并改（不阻塞实现，但会影响报告可读性）

- manifest §2 排序键改为 `(root_index, profile, entry_id, path_key, part_id)`。
- catch-all 的 `priority` 删除或明确不参与裁决；禁止普通条目负 priority。
- `max_bytes_structure` 的措辞从"只解析结构"改为"只保留键路径、不保留值"，不暗示 I/O 跳过。
- 聚合 Unit 与 parts entry 的预算耗尽规则（`E-MAN-052` 豁免或禁止聚合）。
- catch-all `max_depth` 截断时记 `depth_truncated`，并说明 `aggregate_count` 口径。
- 内置 codex profile 补 `sqlite/*.db` 与高频 `.codex` 项（`.codex-global-state.json.bak`、`cap_sid`、`session_index.jsonl`、`plugins/`、`cache/`、`skills/`、`.sandbox*`）。
- `repo` root 未解析时在 scan 侧记 `root_unresolved`，与 probe 对齐。
- `config.toml` 的 `[projects.*]` 段用 parts（`toml_section`）分派 L4，或至少用 `json_path_key`/origin 标注。

状态（2026-11-11）：前四条与最后一条已由 D-024 落实；内置 codex profile 的补条目仍属发布前工作。

---

## 5. 真实 entry 示例（JSONC，已用解析器自洽校验）

以下 18 条覆盖 A–O，全部使用本机真实路径/尺寸/结构。用去注释 + 去尾逗号的 JSONC 解析器解析通过（18 条、无重复 id、无 `catch-all` 正 priority、无 `machine_derived` 缺 `derived_from`、无 `unique_within` 非 L2、无 `secret: scan` 且 0 预算又非 `binary`）。注意 `machine-identity` 等 part 的 `secret` 是 `"none"`，与 selftest 现文字的 `"reference"` 不同——这正是 §3.3 要修的矛盾。

```jsonc
[
  /* A：.claude.json。本机 91,346 B、49 顶层键、43 个 projects、0/43 含 history */
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
      { "src": "observed_behavior", "note": "本机 91,346 B；49 个顶层键；约 4–10 分钟整体重写一次" }
    ],
    "parts": [
      { "id": "machine-identity", "selector": { "json_pointer": "/machineID" }, "layer": "L4", "secret": "none", "extractor": "digest", "needed_by": ["daemon"] },
      { "id": "user-identity", "selector": { "json_pointer": "/userID" }, "layer": "L4", "secret": "none", "extractor": "digest" },
      { "id": "project-index", "selector": { "json_pointer": "/projects" }, "layer": "L4", "secret": "none", "extractor": "keys-only", "notes": "43 个绝对路径键；本机 0/43 项含 history" },
      { "id": "mcp-servers", "selector": { "json_pointer": "/mcpServers" }, "layer": "L2", "secret": "scan", "extractor": "template", "max_bytes_inline": 65536 }
    ]
  },

  /* B：slug 派生。本机 37 个 slug、1,087 个 jsonl、4.8 GB */
  {
    "id": "projects-transcripts",
    "kind": "glob-group",
    "root": "home",
    "paths": [".claude/projects/**/*.jsonl"],
    "layer": "L3",
    "secret": "scan",
    "extractor": "digest",
    "binary": true,
    "max_bytes_inline": 0,
    "max_bytes_total": 2147483648,
    "path_semantics": "machine_derived",
    "derived_from": "repo_slug",
    "priority": 10,
    "signals": [
      { "src": "observed_behavior", "note": "本机 37 个 slug、1,087 个 *.jsonl、4.8 GB；最大单文件 86 MB" }
    ]
  },

  /* C：tool-results。本机 11 个目录，最大 PDF 9,870,272 B */
  {
    "id": "projects-tool-results",
    "kind": "glob-group",
    "root": "home",
    "paths": [".claude/projects/**/tool-results/**"],
    "layer": "L3",
    "secret": "scan",
    "extractor": "digest",
    "binary": true,
    "max_bytes_inline": 0,
    "max_bytes_total": 536870912,
    "path_semantics": "machine_derived",
    "derived_from": "repo_slug",
    "priority": 20,
    "signals": [
      { "src": "observed_behavior", "note": "11 个 tool-results 目录，本机最大 PDF 9,870,272 B" }
    ]
  },

  /* D：plugins 配置。本机 claude-hud/config.json；宽条目会吞掉 known_marketplaces 等 */
  {
    "id": "plugins-config",
    "kind": "glob-group",
    "root": "home",
    "paths": [".claude/plugins/*/config.json"],
    "layer": "L2",
    "secret": "scan",
    "extractor": "template",
    "priority": 20,
    "redact": { "key_pattern": ["(?i).*(token|secret|password|api[_-]?key).*"] },
    "signals": [
      { "src": "observed_behavior", "note": "本机 claude-hud/config.json 为用户偏好，重装不带回" }
    ]
  },

  /* E：file-history。本机 271 个文件、2.7 MB */
  {
    "id": "file-history",
    "kind": "dir",
    "root": "home",
    "path": ".claude/file-history",
    "layer": "L0",
    "secret": "none",
    "extractor": "none",
    "expand": "aggregate",
    "needed_by": ["rewind"],
    "signals": [
      { "src": "observed_behavior", "note": "本机 271 个 @vN 快照、2.7 MB；删后旧会话 /rewind 失效" }
    ]
  },

  /* F：worktree。本机 qianniu 386 MB，.git 为普通文件 */
  {
    "id": "repo-worktrees",
    "kind": "dir",
    "root": "repo",
    "path": ".claude/worktrees",
    "layer": "L3",
    "secret": "none",
    "extractor": "raw-ref",
    "expand": "aggregate",
    "path_semantics": "machine_derived",
    "derived_from": "git_worktree_of",
    "priority": 5,
    "signals": [
      { "src": "observed_behavior", "note": "本机 qianniu worktree 386 MB；目录名随机，.git 为普通文件" }
    ]
  },

  /* G：根外缓存。本机 8.5 GB */
  {
    "id": "claude-vm-bundles",
    "kind": "dir",
    "root": "localappdata",
    "path": "Claude-3p/vm_bundles",
    "layer": "L1",
    "secret": "none",
    "extractor": "none",
    "expand": "aggregate",
    "max_bytes_total": 137438953472,
    "priority": 10,
    "signals": [
      { "src": "observed_behavior", "note": "本机 8.5 GB VM 镜像与 warm 包，可重新下载或构建" }
    ]
  },

  /* H：sqlite + 伴生。本机 thread_history 362,512,384 B；goals/queue -shm 32,768 B、-wal 0 B */
  {
    "id": "sqlite-thread-history",
    "kind": "file",
    "root": "codex",
    "path": "thread_history_1.sqlite",
    "companions": ["-wal", "-shm"],
    "side_effects": ["shm_created"],
    "binary": true,
    "layer": "L3",
    "secret": "scan",
    "extractor": "digest",
    "max_bytes_inline": 0,
    "max_bytes_total": 4294967296,
    "priority": 20,
    "signals": [
      { "src": "observed_behavior", "note": "本机 362,512,384 B；goals_1/queue_1 的 -shm 各 32,768 B、-wal 0 B" }
    ]
  },
  {
    "id": "sqlite-other",
    "kind": "glob-group",
    "root": "codex",
    "paths": ["*.sqlite", "sqlite/*.sqlite", "sqlite/*.db"],
    "companions": ["-wal", "-shm"],
    "side_effects": ["shm_created"],
    "binary": true,
    "layer": "L3",
    "secret": "scan",
    "extractor": "digest",
    "max_bytes_inline": 0,
    "max_bytes_total": 1073741824,
    "priority": 5,
    "signals": [
      { "src": "observed_behavior", "note": "本机 sqlite/codex-dev.db 36,864 B；原 profile 的 *.sqlite 漏掉 .db" }
    ]
  },

  /* I：junction。本机 packages 1.1 GB、95 文件，current 为 junction */
  {
    "id": "codex-packages",
    "kind": "dir",
    "root": "codex",
    "path": "packages",
    "layer": "L1",
    "secret": "none",
    "extractor": "none",
    "expand": "aggregate",
    "follow_symlinks": false,
    "dedupe_targets": true,
    "max_bytes_total": 4294967296,
    "signals": [
      { "src": "observed_behavior", "note": "本机 1.1 GB、95 个文件；app-server-daemon/current 为 junction" }
    ]
  },

  /* J：跨仓库 settings.local.json。本机 3 份，分属 3 个 repo 实例 */
  {
    "id": "repo-settings-local",
    "kind": "file",
    "root": "repo",
    "path": ".claude/settings.local.json",
    "layer": "L2",
    "secret": "scan",
    "extractor": "template",
    "unique_within": "root",
    "priority": 20,
    "redact": { "key_pattern": ["(?i).*(token|secret|password|api[_-]?key).*"] },
    "signals": [
      { "src": "observed_behavior", "note": "本机 3 份，分属 Chatrix、Chatrix/Chatrix、Projects/Planora" }
    ]
  },

  /* K：catch-all。注意 home root 是 %USERPROFILE%，本机顶层 71 项，见 §3.1 V4 */
  {
    "id": "home-residual",
    "kind": "catch-all",
    "root": "home",
    "layer": "L2",
    "secret": "scan",
    "extractor": "keys-only",
    "max_bytes_inline": 65536,
    "max_depth": 3,
    "signals": []
  },

  /* L：repo rules 与锁文件。本机 Chatrix/Chatrix 4 份 rules */
  {
    "id": "repo-rules",
    "kind": "glob-group",
    "root": "repo",
    "paths": [".claude/rules/**/*.md"],
    "layer": "L3",
    "secret": "none",
    "extractor": "raw-ref",
    "signals": [
      { "src": "observed_behavior", "note": "本机 Chatrix/Chatrix 4 份、Chatrix/Yanju 多份，均 git tracked" }
    ]
  },
  {
    "id": "repo-scheduled-tasks-lock",
    "kind": "file",
    "root": "repo",
    "path": ".claude/scheduled_tasks.lock",
    "layer": "L4",
    "secret": "none",
    "extractor": "digest",
    "priority": 10,
    "signals": [
      { "src": "observed_behavior", "note": "本机 Chatrix/Chatrix 存在；含 sessionId 与 pid" }
    ]
  },

  /* M：codex 全局状态。本机 85,825 B，另有同尺寸 .bak */
  {
    "id": "codex-global-state",
    "kind": "file",
    "root": "codex",
    "path": ".codex-global-state.json",
    "layer": "L4",
    "secret": "none",
    "extractor": "keys-only",
    "churn": "high",
    "max_bytes_inline": 0,
    "max_bytes_structure": 1048576,
    "signals": [
      { "src": "observed_behavior", "note": "本机 85,825 B，另有 .bak 同尺寸" }
    ]
  },

  /* N：声明但本机不存在；由 packout profile probe 检出 absent */
  {
    "id": "todos",
    "kind": "dir",
    "root": "home",
    "path": ".claude/todos",
    "layer": "L0",
    "secret": "none",
    "extractor": "none",
    "expand": "aggregate",
    "signals": [
      { "src": "observed_behavior", "note": "本机不存在；由 packout profile probe 检出 absent" }
    ]
  },

  /* O：分散凭据点。本机 sessions/*.key 各 108 B；config.toml 有 experimental_bearer_token */
  {
    "id": "sessions",
    "kind": "glob-group",
    "root": "home",
    "paths": [".claude/sessions/**"],
    "layer": "L0",
    "secret": "scan",
    "extractor": "digest",
    "binary": true,
    "max_bytes_inline": 0,
    "needed_by": ["daemon"],
    "signals": [
      { "src": "observed_behavior", "note": "本机 19 个文件；*.key 各 108 B；每进程再生" }
    ]
  },
  {
    "id": "codex-config",
    "kind": "file",
    "root": "codex",
    "path": "config.toml",
    "layer": "L2",
    "secret": "scan",
    "extractor": "template",
    "redact": { "key_pattern": ["(?i).*(key|token|secret|password).*"] },
    "signals": [
      { "src": "observed_behavior", "note": "本机 [model_providers.custom].experimental_bearer_token；projects 段为机器绑定路径" }
    ]
  }
]
```

自洽校验结果：18 条全部通过；无重复 `id`；所有 `selector` 恰含一个键；所有 part 未写 `kind`/`path`/`root`/`priority`/`path_semantics`/`churn`/`companions`/`os`；`catch-all` 均未写 priority；`machine_derived` 均有 `derived_from`；`unique_within` 条目均为 L2；`secret: scan` 且 `max_bytes_inline: 0` 的条目均声明 `binary: true`。

> 校验器只检查本文件内的静态约束，不代替 `packout profile validate`；尤其 `E-PRF-036` 现文字含 `id` 的问题会让上面所有 part 反而不合法（见 P0-11）。

> 现状（2026-11-11）：本节的 `binary` 等旧名保留为历史证据；`E-PRF-036` 已不再禁 `id`，示例中的 parts 按新规则合法。

---

## 6. 没有覆盖到的验证（诚实标注）

- 没有真正让引擎跑这些 profile（P0 实现尚未开始），示例的自洽性是"按规格文字 + 解析器"检查，不是运行时验证。
- `.claude.json` 的"整体重写是否保持 file_id"未验证；`churn: high` 的跨扫描缓存假设（同一 `file_id`）在真实写入方式下可能不成立。本次只测到 mtime/大小在变，无法只读地区分 rename 与原地 truncate。
- sqlite 只读了目录项与大小，没有以 sqlite 打开，因此没有验证 `mode=ro` 是否真的产生 `-shm`、以及 `-shm` 的生命周期。
- `home` root 的 catch-all 评估基于目录枚举与规格推演；未实际执行"扫整个 `%USERPROFILE%`"的规模/隐私影响。
- 未验证 hujson 对本文件示例的逐字节往返（示例不是待写回的 profile 文件）；D-019 的 16 个往返用例仍需在实现前跑。

# 埋雷语料规格 v1.0

状态：草案，等待裁决（见 §14）。适用：`packout` P0（只读）。相关：`docs/spec-manifest.md`、`docs/spec-profile.md`、`docs/threat-model.md`、`DECISIONS.md` D-002/D-009、`../agent-cleanup-research/REPORT.md` §8 与 `90-verification.md` 第 18–21 条。

本文件只定义语料与断言，不生成语料、不写生成脚本。生成脚本由后续 worker 按本规格实现；本文件可被人与脚本共同作为验收依据。

---

## 0. 目的与非目标

语料是一棵**完全合成**的 home 目录树加上若干独立仓库根，每个雷点固定相对路径、唯一 `case_id`、独立根。用途是给 P0 扫描引擎做**确定性回归**：分类、路径规范化、边界、链接、体积会计、含密判定与聚合。

非目标：

- 不覆盖报告 UI、导出包、restore；只给后续 `verify` 留一组离线样本（C24）。
- 不依赖网络、真实用户目录、真实密钥、系统时区。
- 不测试“删除是否正确”，P0 不写目标目录。

**全局硬约束：一次扫描跑完，目标树的每个路径的 mtime、大小、分配大小、属性、file_id、链接目标、目录子项集合必须与扫描前逐项相等**（允许项见 §4.3）。

---

## 1. 术语

| 词 | 含义 |
|---|---|
| case | 一个 `cases/<case_id>/` 目录，自带全部输入；case 之间零共享 |
| home 根 | case 内 `home/`，映射 profile root `home` |
| repo 根 | case 内 `repos/<name>/`，映射 profile root `repo` |
| 根外 | case 内 `outside/`，只作为链接目标，永不作为扫描根 |
| unit 断言 | 对 manifest 中某相对路径 Unit 的字段断言 |
| 快照 | §4.1 定义的目标树元数据全量记录 |
| minimal / full | CI 快跑集（固定 10 个）/ nightly 全集 |

case_id 形如 `^C[0-9]{2}-[a-z0-9-]+$`，一经分配永不复用、永不改名。

---

## 2. 目录布局

生成器必须产出：

```
testdata/corpus/
  SPEC.md
  corpus.yaml                 # 索引：版本、生成器版本、全部 case_id、集合归属、总字节估算
  profiles/corpus-follow.yaml # 唯一 overlay profile（仅 C26 用）
  cases/
    C01-gitignore-unversioned/
      case.yaml
      home/...
      repos/repo-a/...
      expect.yaml
    ...
  _out/                       # 运行期产物，位于所有 case 根之外
```

`case.yaml` 字段：

```yaml
id: C01-gitignore-unversioned
title: "全局 gitignore 命中时必须仍报未版本化"
set: minimal                  # minimal | full
platforms: [win32, darwin, linux]
requires: []                  # fsutil | mklink-junction | mklink-symlink | admin | sqlite3 | git | longpath
scan:
  profile: claude-code        # 或 corpus-follow
  roots:
    - {role: home, path: home}
    - {role: repo, path: repos/repo-a, name: repo-a}
  options: {}                 # 允许的引擎开关；默认空
budget: {wall_ms: 10000, max_rss_mib: 256}
allow_new: []                 # 允许新增的文件，默认空
allow_dir_mtime: []           # 允许目录 mtime 变化的相对路径
leftovers: []                 # 期望遗留 note，例如 path_too_long
deferred: []                  # 依赖尚未实现命令的断言，例如 verify
```

`scan.roots[].role` 决定 profile 中哪个 root（`home`/`repo`）被绑定；`name` 是写进 header `roots[]` 与 Unit `root` 的实例名，缺省等于 role。多 repo 的绑定方式见 Q1。

`expect.yaml` 是 §5 的断言 DSL。一个 case 的 `home/` 即使不相关也必须存在；没有 repo 的 case 不得出现 `repos/`。

---

## 3. 运行模型

```text
corpus check                                  # 结构、case_id 唯一、无跨 case 引用、无绝对路径漏写
corpus run --set minimal|full --case C07 --case C08 [--keep] [--jobs N]
```

每个 case 独立执行：

1. 若平台不在 `platforms` 或 `requires` 不可满足（无 `mklink`、无 `fsutil` 等），记 `skip` 与原因，退出码 0；case 在 `platforms` 内且 `requires` 满足时，skip 不合法（`--fail-on-skip` 下直接失败）。
2. 新建空 out 目录 `<tmp>/<run_id>/<case_id>/out`，位于 case 根之外。
3. 全量快照（§4.1）。
4. 保持 C09、C14 需要的句柄（§7.9、§7.14）。
5. 执行 `scan`，捕获退出码、stdout/stderr、峰值 RSS、墙钟。
6. 逐条执行 `expect.yaml`；`leftovers` 与 `allow_new` 未命中即失败。
7. 第二次全量快照，逐项比较。
8. 并在 `_out/<case_id>.result.json` 写 `pass|fail|skip`、耗时、RSS、diff。失败必须保留 out 目录，通过则删除，除非 `--keep`。

`_out` 目录必须不在任何扫描根之下。`--jobs` 并行上限 4；C22/C23 串行执行。`budget.wall_ms` 只计扫描进程，不计生成与快照。

---

## 4. 全局不变式（每 case 自动执行，不可关闭）

### 4.1 快照

递归枚举 case 根，禁止跟随链接。每项记录：

```
rel_path, kind(file|dir|reparse), size_apparent, size_alloc,
mtime(100ns), attributes(hex), reparse_tag, link_target,
volume_serial, file_index, dir_child_names(sorted)
```

链接项只记录链接自身与其 target 字符串，不进入 target。快照排序后写 JSONL。比较按 rel_path 逐字段，集合差集双向为空。

### 4.2 不变条件

- 无新增、无删除、无重命名（`allow_new` 除外）。
- 所有文件 `size_apparent`/`size_alloc`/`mtime`/`attributes`/`file_id` 不变。
- 所有目录 mtime 不变（`allow_dir_mtime` 除外）。
- 所有链接 target 不变。
- 目录子项集合不变（`allow_new` 扣除后）。

### 4.3 允许项

仅 case.yaml 显式声明才生效，且必须写明理由。当前唯一候选：C14 的 `cache/state.db-shm` 与其所在目录 mtime（Q3）。

### 4.4 manifest 结构

- 分片 1 首行 `header`、末分片末行 `footer`、index 存在，`verify`（已实现时）无 error。
- `complete: true`，`leftovers` 声明的 note 除外；有 read_error 的 case 见 Q5。
- 所有 `path` 绝对、无 `\\?\`、无 `.`/`..`/重复分隔符/尾分隔符；`path_key` 等于 manifest §6.3 的折叠结果。
- `signals` 非空；`risk_flags` 按 spec 固定顺序；`confidence` 三位小数。
- 同一 `path_key` 的 unit 数不超过该 case 的预期（见 Q2）。
- 两次同参重跑，除 `started_at`/`ended_at`/`scan_id`/salt 指纹外逐行相同。

### 4.5 明文

- 扫描产出的全部文件（manifest、report、notes、日志）中不得出现 C02 的完整 canary token。
- `hits[].prefix` 长度 ≤ 7；`hits[].fingerprint` 非明文。

### 4.6 退出码与预算

- 无 read_error 的 case `exit 0`；墙钟与 RSS 不超 `budget`。
- stderr 允许日志，但不得含明文 token。

---

## 5. 断言 DSL

`expect.yaml` 只允许下列原语：

```yaml
units:
  - match: ".claude/cache/loop"          # case 根相对，glob，禁止绝对
    select: unique | all                 # 缺省 unique；多个命中时 unique 失败
    expect:
      entry: cache-debug-statsig-ide     # 精确
      kind: dir | file | glob-group | named-location
      layer: L0                          # 精确
      confidence: {min: 0.900, max: 1.000}
      secret: {class: none, hit_count: 0, hits_min: 0, hits_max: 0}
      risk_flags: {contains: [junction], excludes: [read_error], exact: false}
      link_target: {nonempty: true}
      aggregate_count: {min: 1}
      proposed_action: {in: [delete, keep]}
      signals: {contains_src: [profile_rule, filesystem_stat], note_matches: "..."}
    fields_absent: [secret_ref]
unit_count: {entry: repo-settings-local, equals: 2}
absent: [".claude/cache/loop/loop", "outside/**"]
notes: {code: path_too_long, entry: cache-debug-statsig-ide, present: true}
footer: {complete: true}
exit_code: 0
report: {guard: command_available, contains: ["sk-ant-"], not_contains: ["<canary>"]}
rerun_id_stable: true
units_any:                          # 至少一个命中满足 expect，用于“任一带某 flag”
  - {match: ".claude/cache/*", expect: {risk_flags: {contains: [symlink_cycle]}}}
either:                             # 二选一：任一分支整体成立即通过
  - {unit: {match: ".claude/cache/.../leaf.jsonl", expect: {risk_flags: {contains: [long_path]}}}}
  - {note: {code: path_too_long, present: true}}
```

`match` 相对 case 根书写，Windows 反斜杠统一写 `/`。`absent` 的 `outside/**` 指链接目标不得作为 Unit 出现。未列出的字段不约束；`contains` 是子集断言，`excludes` 是禁用值断言，`exact: true` 才逐值相等。`either` 的每个分支是以 `unit:` 或 `note:` 为唯一键的断言块（`unit:` 内含 `match`+`expect`），任一分支整体成立即通过。所有断言失败需输出实际 Unit 的脱敏 JSON。

---

## 6. 路径与命名约定

- case 内所有路径用 `/` 书写，相对 case 根。
- 生成器使用 Windows 长名接口创建（§9），但落盘名就是断言中的名。
- 不得出现真实用户名、真实盘符绝对路径（链接 target 用相对或 case 内绝对，Q7）。
- 除 C24 外，入口都由 profile 的现有 entry 覆盖；需要新 entry 时只允许 overlay profile。
- 语料一律使用真实布局 `home/.claude/…`。内置 profile 的 `projects-transcripts`（`projects/**/*.jsonl`）与 `cache-debug-statsig-ide`（`cache/**` 等）在 §8.1 里漏了 `.claude/` 前缀，而 selftest 与 manifest §10.1 都按 `.claude/` 写——生成前必须按 Q19 定稿。

---

## 7. Case 规格

每个 case 的“期望”是 manifest 的**最终结论**，不是中间判定。`conf` 一律指 `confidence` 区间。未写的 `secret` 一律 `class: none, hit_count: 0`；未写“聚合”一律断言 `risk_flags` 不含 `aggregated`。`action` 写明允许集合。所有 case 自动叠加 §4。

### C01-gitignore-unversioned  【minimal】

- 平台：全。requires：无。
- 构造：
  - `home/.config/git/ignore` 第一行 `**/.claude/settings.local.json`，第二行 `/.claude/settings.local.json`。
  - `home/.claude/settings.local.json` 内容 `{"permissions":{"allow":["Bash(ls)"]}}`。
  - `repos/repo-a/.claude/settings.local.json` 同内容；repo-a 不含 `.git/`。
  - home + repo-a 同一次扫描。
- 期望：两个 Unit 都存在，均由 `settings-local-global` / `repo-settings-local` 产生，`kind: file`，因全局唯一命中升 **L3**，conf ≥ 0.900，`risk_flags` 均含 `gitignored`；repo 侧必须含 `unversioned_repo`（Q4 决定 home 侧是否也需要）。`secret.class: scan`、`hit_count: 0`。均不聚合。action ∈ {keep, migrate}。
- 断言：`unit_count` 按 entry 各为 1；两个 `match` 的 `layer: L3`、flags 子集；`absent` 不得含这两个路径（“被 gitignore 不等于被排除”）；footer complete。
- 雷点：把全局 gitignore 当“不需要报”，或只用 ignore 规则就判 `git_tracked`。

### C02-mcp-fake-token  【minimal】

- 平台：全。requires：无。
- 构造：`repos/repo-a/.mcp.json`：

```json
{"mcpServers":{"alpha":{"command":"npx","env":{"TOKEN":"sk-ant-api03-C0RPUSCANARY0123456789abcdefXY"}},
"beta":{"command":"npx","env":{"TOKEN":"sk-ant-api03-C0RPUSCANARY0123456789abcdefXY"}}}}
```

  canary 全文只在生成器与验收脚本里出现。
- 期望：一个 Unit，entry `repo-mcp-json`，`kind: file`，**L2**，conf ≥ 0.950，`secret.class: scan`，`hit_count: 2`，两条 hit 的 `kind: known_prefix`、`class: restore`、`prefix: sk-ant-`、locator 分别为 `/mcpServers/alpha/env/TOKEN` 与 `/mcpServers/beta/env/TOKEN`，两条 `fingerprint` 相同。flags 不含 `low_confidence`。action ∈ {keep, migrate, template}。
- 断言：上述字段；`hits_max: 2`；manifest 全串不含 canary；`report.not_contains` canary、`report.contains: ["sk-ant-"]`；note 与 signal 也不含。
- 雷点：报密但明文落进 `notes`/`prefix`；相同密钥产生不同指纹；把两处合并成一条 hit。

### C03-junction-self-loop  【minimal】

- 平台：win32。requires：mklink-junction（不需管理员）。
- 构造：`home/.claude/cache/loop` 为 junction，target 指向祖先 `.claude/cache`。默认 `follow_symlinks: false`。
- 期望：恰好一个 `cache/loop` Unit，`kind: dir`，**L0**，`risk_flags` 含 `junction`（是否同时含 `symlink` 不约束），`link_target` 非空；**不得**出现 `cache/loop/loop`，`cache/loop/` 下任何后代都不产出。conf ≥ 0.900。action ∈ {delete, keep}。
- 断言：`units` 的 `match`；`absent: [".claude/cache/loop/loop", ".claude/cache/loop/**"]`；该 case Unit 总数不随循环增长（不超过 5）。
- 雷点：无 visited 集合时无限下降；把 junction 内容并入并重复计数。

### C04-symlink-outside-root  【minimal】

- 平台：win32。requires：mklink-symlink（需开发者模式或管理员；失败则 skip 原因 `symlink_privilege`）。
- 构造：`outside/secret-dir/note.txt`；`home/.claude/cache/to-outside` 为目录符号链接，target 写成相对 `../../../../outside/secret-dir`。
- 期望：一个链接 Unit，`kind: dir`，**L0**，flags 含 `symlink` 与 `outside_root`，`link_target` 非空；`outside/secret-dir/note.txt` 不作为 Unit；不递归。
- 断言：上述字段；`absent: ["outside/secret-dir/note.txt", "outside/**"]`；链接 target 字符串保留（相对形式不强制转绝对，Q7）。
- 雷点：跟随链接把根外数据带进报告且不标注；`..` 词法解析掉链接后误判在根内。

### C05-case-collision-glob  【minimal】

- 平台：全。requires：无。
- 构造：`home/.claude/projects/Demo/x.jsonl` 与 `home/.claude/projects/demo/x.jsonl`（不同目录、仅大小写不同），内容各一行 JSON。
- 期望：两个 Unit，entry `projects-transcripts`，**L3**，conf ≥ 0.900，**两者都**带 `risk_flags: [case_collision]`；`path` 保留各自磁盘拼写；`path_key` 都折叠为 `/demo/` 形式（相同）。
- 断言：`unit_count` 按 entry 为 2；两个 `match` 的 flags 子集；`path_key` 相同（Q2）；verify 不得因 E-MAN-025 失败。
- 雷点：大小写不敏感卷上只产出一个 Unit；path 被归一为同一拼写。

### C06-trailing-dot-space  【minimal】

- 平台：win32。requires：longpath（构造需要 `\\?\`）。
- 构造：`home/.claude/cache/` 下四个名：`trail.`、`trail `、`trail.txt.`、`lead.txt`。用 §9.3 的方式创建，创建后 `GetFinalPathName` 核实磁盘名未被 Win32 吃掉。
- 期望：四个 Unit 全部存在，entry `cache-debug-statsig-ide`，**L0**，均不含 `long_path`（名字本身不构成长路径，`\\?\` 只用于构造）。`path` 分别以 `trail.`、`trail `、`trail.txt.` 结尾，`path` 无 `\\?\`。四者 `path_key` 各不相同。
- 断言：四个 `match` 的 `path` 精确后缀；`unit_count` 4；不出现只有 3 个或名字被截断。
- 雷点：尾点/尾空格被剥掉；后两者折叠成同名。

### C07-long-path-over-240  【minimal】

- 平台：win32。requires：longpath。
- 构造：`home/.claude/cache/` 下 24 层单字符目录 `d0/…/d23`，再放 `deep.jsonl`，使 `path` 长度 ≥ 260 且 < 1000。创建走 `\\?\`。
- 期望：一个 Unit，**L0**，flags 含 `long_path`，conf ≥ 0.900；`path` 用普通形式且不含 `\\?\`；可读，无 `read_error`。
- 断言：`match` 该路径（`confidence` 下限、flags 含 `long_path` 且不含 `read_error`）；`path` 断言长度 ≥ 260。
- 雷点：240 字符以上未转扩展前缀导致 stat 失败；把 `\\?\` 写进 `path`。

### C08-readonly-file  【minimal】

- 平台：win32。requires：无（`attrib` 内置）。
- 构造：`home/.claude/cache/ro.jsonl`，`attrib +R`。
- 期望：正常 Unit，**L0**，conf ≥ 0.900，无 `read_error`，`secret.class: none`；扫描后只读属性仍在。
- 断言：`match`、flags `excludes: [read_error]`；全局快照覆盖属性不变。
- 雷点：把只读当不可读跳过；为读内容临时清属性（会改 attributes）。

### C09-occupied-file  【minimal】

- 平台：win32。requires：无。运行器需持有句柄到 case 结束。
- 构造：两个文件 `home/.claude/cache/shared.jsonl`、`home/.claude/cache/exclusive.jsonl`。运行器以 `FileShare.ReadWrite` 打开前者（引擎可读），以 `FileShare.None` 打开后者（引擎读内容会失败）。
- 期望：
  - `shared.jsonl`：正常 Unit，L0，`read_error` 缺席。
  - `exclusive.jsonl`：Unit 仍产出（stat 可得），L0，`risk_flags` 含 `read_error`，`fingerprint.value: null`；扫描不中止，其余 Unit 完整，footer `complete` 见 Q5；退出码见 Q5。
- 断言：两者 `match`；后者的 `fingerprint.value` 为 null；`unit_count` 不因占用而少；`footer.complete` 取裁决值。
- 雷点：整次扫描因一个 EACCES/EBUSY 中止；把占用文件静默丢弃；“处理了错误”却把 footer 报成 complete。

### C10-archived-unique-claude-md  【minimal】

- 平台：全。requires：无。
- 构造：`repos/archive-old/CLAUDE.md`（内容 `# archive rules`），repo 里无其他文件；home 无 `.claude/CLAUDE.md`；整个扫描中 CLAUDE.md 仅此一份。
- 期望：一个 Unit，entry `repo-claude-md`，**L3**（`l3_if_unique` 唯一命中），conf ≥ 0.900，无 `low_confidence`；`kind: file`，不聚合；flags 可含 `unversioned_repo`，不得含 `git_tracked`。action ∈ {keep, migrate}。signals 至少含 `profile_rule`，且其中一条 note 说明唯一命中触发升级。
- 断言：`match` 的 layer/conf/flags；`unit_count` 1；verify 通过。
- 雷点：只看声明层写 L2，把唯一副本当“配置文件可重填”；把“归档目录”当 L0。

### C11-empty-dir-empty-glob  [full]

- 平台：全。requires：无。
- 构造：`home/.claude/todos/empty/`（空目录）；`home/.claude/projects/`（存在但无文件）。
- 期望：`todos` entry 产出**一个聚合 Unit**（`kind: dir`，flags 含 `aggregated`，`aggregate_count` ≥ 1，size 求和），L0，action ∈ {delete, keep}；`projects-transcripts` entry **零** Unit，不报错。footer complete；exit 0。
- 断言：`todos` 的 aggregate 字段；`unit_count` 对 `projects-transcripts` 为 0；`absent: [".claude/projects/**"]`；footer complete。
- 雷点：空目录导致 nil 解引用/0 结果被当错误；空 glob 记成 `probe_unavailable` 或使扫描失败。

### C12-sparse-file  [full]

- 平台：win32 / lin（win 用 fsutil，Linux 用 `truncate -s 1G`，其余断言相同）。requires：sparse。
- 构造：`home/.claude/cache/sparse.bin`，`fsutil file createnew` 造 1 GiB → `fsutil sparse setflag` → `fsutil sparse setzerodata offset=0 length=1073741824`，核实 `size_alloc` ≤ 4096。
- 期望：Unit，L0，`size_apparent: 1073741824`，`size_alloc` ≤ 4096，flags 含 `sparse`；verify 不得报 E-MAN-019。
- 断言：字段精确/上限；`risk_flags` 子集；verify 无 E-MAN-019。
- 雷点：按逻辑大小估算占用；稀疏与 4 GB 大文件混淆。

### C13-binary  [full]

- 平台：全。requires：无。
- 构造：`home/.claude/cache/blob.bin`，64 KiB，含 NUL、0x00–0xFF 全字节、无换行结构。
- 期望：Unit，L0，`secret.class: none`，`fingerprint.scope: full`，`value` 非空；无 `read_error`；不套模板；flags 不含 `content_partial`。
- 断言：上述字段；`fields_absent: [secret_ref]`。
- 雷点：按 UTF-8 解码二进制失败；二进制里随机高熵被报密。

### C14-sqlite-wal  [full]

- 平台：win32 / lin。requires：sqlite3（缺失则 skip，原因 `no_sqlite3`）。
- 构造（§9.7）：`home/.claude/cache/state.db` + 未 checkpoint 的 `state.db-wal`；若可得同时留 `-shm`。用 sqlite3 建 WAL 库、`wal_autocheckpoint=0`、写 200 行、在未关闭连接时把 db/wal 拷出。
- 期望：db 与 wal 都是 Unit（entry `cache-debug-statsig-ide`，L0）；db 可读，`fingerprint.value` 非空；不出现独占锁错误；manifest 说明 wal 是持久状态的一部分（note 或 signal）。
- 断言：两个 `match`；`excludes: [read_error]`；全局快照不变（`-shm` 例外见 Q3）。
- 雷点：写模式打开 sqlite 造成 `-shm`/`-wal` 变化；把 wal 当可再生缓存漏报。

### C15-placeholder  [full]

- 平台：win32。requires：fsutil（属性模拟用）。
- 构造（§9.5）：`home/.claude/cache/placeholder.jsonl`，先做 C12 的稀疏化（1 MiB 即可），再给文件加上 `FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`。属性写入失败则 skip（原因 `attr_unsupported`），不得 fail。
- 期望：Unit，L0，flags 含 `cloud_placeholder`（`sparse` 可同存），conf ≥ 0.900；默认不水合：读前后 `size_alloc`、mtime、属性不变；`fingerprint.value: null`，flags 可含 `content_partial`（Q7）；action ∈ {keep, delete}。
- 断言：flags 子集；`allow_new: []`；快照全等；`fingerprint.value` null。
- 雷点：把占位符当普通文件读、按内容报密；“删除本地等于全设备删除”在 P0 至少要知道它没水合。

### C16-multi-repo-settings  [full]

- 平台：全。requires：无。
- 构造：`home/.config/git/ignore` 同 C01；`repos/repo-a/.claude/settings.local.json` 与 `repos/repo-b/.claude/settings.local.json` 内容不同；一次扫描三根（home + repo-a + repo-b）。
- 期望：两个 repo Unit 均为 **L2**（entry 命中数 2，`l3_if_unique` 不触发），flags 各含 `gitignored`、`unversioned_repo`；home 的全局副本为 L3（不同 entry，计数独立）。conf ≥ 0.900。
- 断言：`unit_count` per entry；两个 repo `match` 的 `layer: L2` 且 `fields_absent: [low_confidence]`；home `match` L3。
- 雷点：把 `l3_if_unique` 计成单 root；跨仓库同名互相“稀释”后仍未发现；或反过来误升 L3。

### C17-unique-promotion  [full]

- 平台：全。requires：无。
- 构造：仅 home + 单个 repo；`home/.claude/settings.local.json` 与 `repos/repo-a/.claude/settings.local.json` 各一份，内容不同，均无 `.git/`。
- 期望：两个不同 entry 各命中 1 次，**各自升 L3**，conf ≥ 0.900，无 `low_confidence`；signals 有 `profile_rule` 说明升级。flags 含 `gitignored`。
- 断言：两个 `match` 的 L3；`unit_count` 各 1。
- 雷点：C16 与 C17 结论混用；把唯一性判断写成“路径存在即升级”。

### C18-mixed-layer-plugins  [full]

- 平台：全。requires：无。
- 构造：`home/.claude/plugins/installed_plugins.json`（内容 `{"plugins":[]}`）与 `home/.claude/plugins/enabled_plugins.json`（用户手工维护的内容，无上游）。
- 期望（当前 profile 下）：两个 Unit 都产出，entry `plugins`，**L1**，conf ≥ 0.900；前者 action ∈ {reinstall, keep}；后者同样 L1 但 `notes`/signal 能看出“用户维护、可再生的证据不足”（Q8）。不聚合。
- 断言：两个 `match`；`unit_count` 2；flags 不含 `aggregated`。
- 雷点：把整个 plugins 目录一刀切 L1 而漏掉不可再生的 enabled 清单。

### C19-path-derived-slug  [full]

- 平台：全。requires：无。
- 构造：`home/.claude/projects/D--Study-packout/x.jsonl` 与 `home/.claude/projects/D--Study-packout--evil/x.jsonl`，各一行。
- 期望：两个 Unit，L3，conf ≥ 0.900，`path` 原样保留 `--`；`id` 各不相同；同参重跑 `id` 稳定。
- 断言：两个 `match`；`unit_count` 2；`rerun_id_stable: true`；路径前缀不互相吞并（`unit_count` 精确）。
- 雷点：按路径前缀而非路径段比较，`…--evil` 被并入 `…`；slug 被解码改写。

### C20-hardlink  [full]

- 平台：win32 / lin。requires：无（`mklink /H` 或 `fsutil hardlink create`；Linux `ln`）。
- 构造：`home/.claude/cache/hard-a.log` 与 `hard-b.log` 为同一文件的硬链接，写入 `hello` 后建立。
- 期望：两个 Unit，L0，`file_id` 完全相同，flags 各含 `hardlink_multi`；`size_apparent` 两者相同。
- 断言：两个 `match` 的 `file_id.index` 相等、flags 子集；`unit_count` 2。
- 雷点：硬链接被当两份大小重复计算；`link_target` 被错误用于硬链接。

### C21-ads-stream  [full]

- 平台：win32。requires：无。
- 构造（§9.7）：`home/.claude/cache/ads.jsonl`，再写同名备用数据流 `:meta`。
- 期望：至少一个基于主路径的 Unit，L0，可读，无 `read_error`；备用流是否单独出 Unit 按 Q9 裁决（默认只出主 Unit，`notes` 中提及流存在）。
- 断言：主路径 `match`；`absent: [".claude/cache/ads.jsonl:meta"]`（若裁决为独立 Unit 则改为 `match`）；verify 不报非法 path。
- 雷点：`GetFinalPathName` 把 `:meta` 当路径一部分；读取命中错流。

### C22-huge-jsonl-4g  [full，nightly，串行]

- 平台：全。requires：无；磁盘需 ≥ 5 GiB 空闲（Q11）。
- 构造（§9.8）：`home/.claude/projects/D--Study-packout/huge.jsonl`，固定短行 `{"type":"user","text":"0123456789abcdef"}\n` 重复到 4 GiB（4,294,967,296 字节，末行可截断为整行）。流式生成。
- 期望：Unit，L3，`size_apparent` ≥ 4 GiB，`fingerprint.scope: head-tail`，flags 含 `oversized`、`content_partial`；`secret.class` 为 `none`；action ∈ {keep, migrate}；预算墙钟 ≤ 300 s、RSS ≤ 268435456。
- 断言：字段、scope、flags、`budget`；峰值 RSS 由运行器测；不整读内存（无 OOM）。
- 雷点：整文件入内存；64 KiB 行上限被单行击穿；分片写出超长行。

### C23-path-over-32767  [full，nightly]

- 平台：win32。requires：longpath。
- 构造：`home/.claude/cache/` 下 130 层各 250 字符的目录名（用 `\\?\`），末端 `leaf.jsonl`；总长 ≥ 32,767。
- 期望（按 Q12）：要么不产出 Unit 且有一条 `note(code: path_too_long)`，要么产出 Unit 且 flags 含 `long_path`；两种情况都不得 `read_error`、不得中止、footer complete、exit 0。manifest 中 `path` 不超过 32,767 字符。
- 断言：`either` 二选一成立，`path` 长度上限，exit 0。
- 雷点：长路径使 Win32 API 直接失败并中止整次扫描；写超长行。

### C24-package-traversal  [full，deferred]

- 平台：全。requires：无（针对已落盘的 verify）。
- 构造：`cases/C24-package-traversal/package/entries.tsv`，制表符三列 `entry_path<TAB>A|R<TAB>normalized`，至少含：

```
../../etc/passwd            A  ../../etc/passwd
/abs/rooted                 A  /abs/rooted
C:\Windows\x                A  C:\Windows\x
C:/Users/x                  A  C:\Users\x
//server/share/file         A  \\server\share\file
a/./b//c/../d               A  a/b/d
////home/u/x                A  home/u/x
foo/                        A  foo
C:foo                       R  盘符相对，拒绝
CON                         A  CON（保留名）
NUL.txt                     A  NUL.txt
a.txt.                      A  a.txt.
"a.txt "                    A  a.txt（含尾空格）
a.txt:stream                A  a.txt:stream
~/x                         R  未展开，拒绝
..\..\x                     A  ..\..\x
a/..                        A  .
(空串)                      R
.                           R
\?\C:\x                    A  C:\x
```

- 解析：TSV 按 Go `encoding/csv` 的 Tab 模式读，含前后空白的字段用双引号包裹。
- 期望：`packout verify <pkg>` 按表对待；`A` 的规范化结果与第三列相等（第三列由脚本逐条展开），`R` 必须报错且错误信息不含完整主机路径。
- 断言：逐行比对退出码与错误码；本 case 在 `verify` 未实现时整体 skip（原因 `command_unavailable`）。
- 雷点：`filepath.Clean` 放行绝对路径（C-06）；`////` 被当绝对；尾点尾空格被剥离；`C:foo` 当绝对。

### C25-reserved-names  [full]

- 平台：win32。requires：longpath。创建失败则 skip。
- 构造：`home/.claude/cache/CON`、`NUL.txt`、`aux`、`COM1.log`。
- 期望：四个 Unit 均存在，L0，`path` 基名保留原样，无 read_error。
- 断言：四个 `match`；`unit_count` 4；不出现被解析到设备的情况。
- 雷点：`NUL.txt` 写入落空；名字被当设备。

### C26-junction-mutual-cycle-follow  [full]

- 平台：win32。requires：mklink-junction。
- 构造：`home/.claude/cache/A` junction→`B`，`B` junction→`A`；扫描 profile 用 `profiles/corpus-follow.yaml`（builtin 副本，仅 cache entry 设 `follow_symlinks: true`、`max_depth: 8`）。
- 期望：A、B 各一个链接 Unit，至少一个带 `symlink_cycle`；遍历有界（该 case Unit 数 ≤ 4）；不挂起；conf ≥ 0.900。
- 断言：两个 `match`，flags 含 `junction`；`units_any` 命中且含 `symlink_cycle`；`unit_count` 上限；`budget.wall_ms` ≤ 5000。
- 雷点：visited 集合按路径而非 `(volume,file_id)`；跟随无深度上限。

### C27-same-dir-case-collision  [full]

- 平台：win32。requires：fsutil-case（`fsutil file setCaseSensitiveInfo`）。不支持则 skip。
- 构造：`home/.claude/cache/casedir/` 开启大小写敏感后，放入 `Case.txt` 与 `case.txt`。
- 期望：两个 Unit，L0，均带 `case_collision`，`path` 保留拼写，`path_key` 相同。
- 断言：`unit_count` 2；两个 `match`；verify 通过（Q2）。
- 雷点：同目录真实大小写并存（不只是跨目录名）。

---

## 8. 平台矩阵与降级

| 能力 | Windows 造法 | 非 Windows 降级 |
|---|---|---|
| junction | `cmd /c mklink /J <link> <target>` | skip `no_junction`（C03；C26 若要跨平台需改符号链接，本期不做） |
| symlink | `cmd /c mklink /D <link> <target>`；失败 skip `symlink_privilege` | Linux/macOS 可造，但 C04 仍只标 win32 |
| 稀疏（requires: sparse） | `fsutil`（§9.1） | Linux `truncate -s 1G`，可跑 C12 |
| 占位符属性 | §9.5 | 非 win 一律 skip `attr_unsupported` |
| 长路径 | `cmd /c mkdir "\\?\…"`、`New-Item -LiteralPath '\\?\…'`、`[IO.File]::Create('\\?\…')` 三选一 | skip |
| 保留名 | `\\?\` 路径写 `CON` | skip |
| 大小写敏感目录 | `fsutil file setCaseSensitiveInfo <dir> enable` | Linux 天然敏感，C27 可跑 |
| 只读 | `attrib +R` | `chmod 444`，可跑 |
| 硬链接 | `mklink /H` 或 `fsutil hardlink create` | `ln`，可跑 |
| sqlite WAL | sqlite3 CLI | 同左；无则 skip |
| 4 GiB | 生成脚本流式写 | 同左 |

规则：

- 每个 case 的 `platforms` 之外一律 **skip，不 fail**；结果 JSON 记 `skip` + 原因。
- Windows-only case 在 CI 的 Windows job 里 `--fail-on-skip`，skip 即失败。
- `requires` 只描述能力，不描述“是否安装”；能力探测由运行器做，探测失败即 skip。
- 平台专用语义（尾点、保留名、ADS、占位符属性）必须在 case 标题或 `title` 里标明，防止被当跨平台金标准。

---

## 9. 特殊构造命令（Windows）

统一以 `\\?\D:\…` 作前缀，生成时不用真实用户目录。

### 9.1 稀疏（C12/C15）

```bat
fsutil file createnew "\\?\D:\…\sparse.bin" 1073741824
fsutil sparse setflag "\\?\D:\…\sparse.bin"
fsutil sparse setzerodata offset=0 length=1073741824 "\\?\D:\…\sparse.bin"
```

`setzerodata` 后可 `fsutil sparse queryrange` 核实。

### 9.2 junction / symlink

```bat
cmd /c mklink /J "D:\…\cache\loop" "D:\…\cache"
cmd /c mklink /D "D:\…\cache\to-outside" "..\..\..\..\outside\secret-dir"
```

junction 不需要管理员；symlink 需开发者模式或提权，失败走 skip。

### 9.3 尾点 / 尾空格 / 长路径 / 保留名

```powershell
$p = '\\?\D:\…\cache\trail. '
[IO.File]::Create($p).Dispose()
cmd /c mkdir "\\?\D:\…\d0\d1\…"
```

`New-Item -LiteralPath` 在 5.1 上对 `\\?\` 不稳定，优先 `[IO.File]::Create`。创建后用 `cmd /c dir /x` 或 `GetFinalPathName` 核实。

### 9.4 只读

```bat
attrib +R "D:\…\ro.jsonl"
```

### 9.5 占位符属性（C15）

`attrib +O` 只能置 OFFLINE。RECALL 位需 P/Invoke：

```powershell
Add-Type @"
using System.Runtime.InteropServices;
public static class CorpusAttr {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool SetFileInformationByHandle(
    Microsoft.Win32.SafeHandles.SafeFileHandle h, int cls, byte[] info, uint len);
}
"@
# FILE_BASIC_INFO: 4×FILETIME(32B) + FileAttributes(4B) + 4B 对齐 = 40B
# FileBasicInfo = 0；属性值 = 0x00001000 (OFFLINE) | 0x00400000 (RECALL_ON_DATA_ACCESS)
$fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None')
$bi = New-Object byte[] 40
[BitConverter]::GetBytes([uint32]0x00401000).CopyTo($bi, 32)
if (-not [CorpusAttr]::SetFileInformationByHandle($fs.SafeFileHandle, 0, $bi, 40)) { throw 'SetFileInformationByHandle failed' }
$fs.Dispose()
```

设置属性只改 ChangeTime，不改 mtime；快照比对不含 ChangeTime，因此安全。失败则 skip。

### 9.6 大小写敏感目录

```bat
fsutil file setCaseSensitiveInfo "D:\…\casedir" enable
```

### 9.7 硬链接 / ADS / sqlite

```bat
cmd /c mklink /H "D:\…\hard-b.log" "D:\…\hard-a.log"
```

```powershell
Set-Content -LiteralPath 'D:\…\ads.jsonl' -Value '{}'
Set-Content -LiteralPath 'D:\…\ads.jsonl' -Stream meta -Value 'x'
```

在 sqlite3 交互会话里建库，并在 `.quit` 前用 `.shell copy /b` 复制未 checkpoint 的 db/wal：

```bat
(echo PRAGMA journal_mode=WAL; ^
 echo PRAGMA wal_autocheckpoint=0; ^
 echo CREATE TABLE t^(x^); ^
 echo INSERT INTO t VALUES^(randomblob^(64^)^); ^
 echo .shell copy /b state.db out\state.db ^& copy /b state.db-wal out\state.db-wal ^& copy /b state.db-shm out\state.db-shm ^
 echo .quit) | sqlite3 state.db
```

版本不同可改为逐条 `INSERT` 循环。WAL 必须保持未 checkpoint。

### 9.8 4 GiB 生成

按 1 MiB 缓冲写固定行，循环到长度 ≥ 4,294,967,296；最后一行可整行写完，断言用 `≥` 而非 `==`。生成耗时与磁盘见 Q11。

---

## 10. 集合与运行节奏

- **minimal = 固定 10 个**：C01–C10。理由：覆盖最易错的分类与路径主线，且都不依赖 4 GiB 与 130 层路径，单 case 预算 ≤ 10 s、全集 ≤ 120 s、RSS ≤ 256 MiB。
- **full = C01–C27**，nightly，单次 ≤ 45 min，磁盘 ≤ 8 GiB。C22、C23 串行。
- minimal 不得因某平台 skip 而少于 10 个：Windows job 上 10 个全要求实跑；Linux job 允许 C03/C04/C06/C07/C08/C09 skip，另以 full 的跨平台 case 补位（Q13）。
- 两个集合的 case 内容逐字节相同，只有归属不同；从 minimal 移入 full 只需改 `set`。

---

## 11. 与产品规格的映射

| case | manifest risk_flag / 结论 | 规则来源 |
|---|---|---|
| C01/C16/C17 | gitignored、unversioned_repo、l3_if_unique | profile 4.2、5.3；REPORT §7 |
| C02 | known_prefix、restore、hit 去重 | manifest 4.3、§9 |
| C03/C04/C26/C20 | junction、symlink、symlink_cycle、outside_root、hardlink_multi | profile 4.3；manifest 4.6 |
| C05/C27/C06/C25/C21 | case_collision、实际拼写、保留名、ADS | manifest §6；threat-model A-09/C-08 |
| C07/C23 | long_path、path_too_long | profile 4.5；manifest 6.5 |
| C12/C15/C22 | sparse、cloud_placeholder、oversized、content_partial | manifest 4.5/4.6；threat-model A-03/A-04 |
| C09/C14 | read_error、WAL 一致性 | threat-model A-05/A-08 |
| C11/C18 | aggregated、同目录混层 | profile 4.6、5.2 |

---

## 12. 生成器验收（只生成，不跑扫描）

- `corpus check` 全过：case_id 唯一且合规、路径固定、无跨 case 引用、`home/` 存在、`set` 合法、`platforms` 非空。
- 生成幂等：同参数二次生成，除链接 target 的绝对部分外逐字节相同。
- 生成后自动做一次快照，确认没有任何文件在生成过程中被后续步骤改动。
- 所有 canary 只来自生成器常量文件 `canaries.yaml`，并把其哈希写入 `corpus.yaml`，防止验收脚本与 fixture 漂移。

---

## 13. 单 case 隔离检查

- 每个 case 的扫描根只指向自身目录。
- `outside/` 只被链接引用，不被任何 root 覆盖。
- 不共享 out 目录；`--jobs` 下每个 case 有自己的 tmp。
- C09 的句柄只在其进程生命周期内；C14 的 sqlite3 在生成后退出。
- 生成器不得把绝对路径写进 fixture 内容；链接 target 的相对形式优先。

---

## 14. 需要人裁决

| # | 问题 | 影响 | 建议 |
|---|---|---|---|
| Q1 | 多 repo 根：profile 只用 root 名 `repo`，一次扫描两个仓库时如何绑定？是允许重复 root 名、加 `role`，还是给扫描加 `--root repo=…` 重复参数并自动命名 `repo#2`？ | C16/C17 无法运行；影响 manifest `root` 字段与 id 稳定性 | 扫描参数支持重复 `repo=` 并自动实例名；profile 按 role 解析 |
| Q2 | `path_key` 在大小写不敏感卷上会把 `Demo`/`demo` 折叠为同键，但 E-MAN-025 按 `(profile, entry, path_key)` 判重 → 合法的两个 Unit 会报 error。 | C05/C27 的 verify 断言 | E-MAN-025 在 `file_id` 不同时放行；或把唯一键改为 `(entry, file_id)` |
| Q3 | 只读打开 sqlite 可能创建 `-shm`，意味着“目录 mtime 不变”有例外。 | C14 的全局不变式 | 允许新建 `-shm` 并允许该目录 mtime 变化；或实现改用 `immutable=1`/按字节读 WAL |
| Q4 | home 根（非仓库）里的文件是否也带 `unversioned_repo`？ | C01 断言 | home 侧也带；语义改为“不在任何版本库内” |
| Q5 | 可处理的 `read_error`（C09）时，footer `complete` 与进程退出码取什么？ | C09 断言 | `complete: true`（错误已按 Unit 记录）+ exit 0；未处理错误才 false/非零 |
| Q6 | 空目录的 `aggregate_count` 是 0 还是 1？空 glob 是否必须留 note？ | C11 | 0 与目录自身合计为 1；空 glob 无 note |
| Q7 | 根外链接的 `link_target` 是否原样保留相对形式？占位符未水合时 `fingerprint.value` 是否必须 null？ | C04/C15 | 原样保留；必须 null 且加 `content_partial` |
| Q8 | `enabled_plugins.json` 属于 L1 还是需要 profile 新增更具体 entry 升 L2/L3？ | C18 | 新增 entry（`plugins/enabled*.json` → L2 或 L3），C18 随之改为跨层断言 |
| Q9 | ADS 是独立 Unit 还是只在 note 提及？ | C21 | 只出主 Unit + note；ADS 独立寻址放 P1 |
| Q10 | `l3_if_unique` 计数范围：D-010 已定“跨全部扫描 root 的全局路径集合”，C16 按此写；需确认 home 与 repo 的“同名不同 entry”互不影响。 | C16/C17 | 确认按 entry 计，不按 basename |
| Q11 | 4 GiB 与 130 层路径是否纳入 CI 机器（磁盘/时长），还是只在本机 nightly？ | C22/C23 | 仅 nightly；CI runner 需 ≥ 10 GiB 空闲 |
| Q12 | 超 32,767 字符：manifest 说“记 note 并跳过”，profile 说 E-PRF-031 记读取错误。以哪个为准？ | C23 | 以 manifest 6.5 为准：note `path_too_long`、不产出 Unit、不算错误 |
| Q13 | 非 Windows CI 上 minimal 会因 skip 不足 10 个，如何补位？ | §10 | 允许 full 中的跨平台 case 补足；或 Linux 只跑 full 子集 |
| Q14 | C24 依赖的 `verify` 尚不存在，是现在就进 full 还是等命令落地？ | C24 | 先留在 full 标 `deferred`，命令落地后转正 |
| Q15 | 尾点/尾空格是否要求 `path` 保留磁盘拼写（与 Windows 解析行为可能冲突），需引擎/FS 确认。 | C06 | 要求保留；`GetFinalPathName` 之外的解析路径不得改写 |
| Q16 | 保留名（CON 等）是否都允许作为普通文件被扫描，还是部分入口应报 note？ | C25 | 全部按普通文件，不 special-case |
| Q17 | confidence 是断言区间还是金值？ | 全部 | 区间（本规格已用），金值只在稳定后再引入 |
| Q18 | `--explain` 若把内容送模型，canary 校验是否也要覆盖模型摘要？ | C02 全局不变式 | P0 无模型调用，暂不覆盖；P1 加 |
| Q19 | 内置 profile §8.1 的 `projects-transcripts` 与 `cache-debug-statsig-ide` 等 entry 缺 `.claude/` 前缀，与 selftest、manifest §10.1、真实布局矛盾。以哪边为准？ | 几乎全部 case 的匹配；C05/C07/C08/C09/C11–C23 | 以 `.claude/` 为准修 profile；语料已按 `.claude/` 写，不因 profile bug 改动 |
| Q20 | C11 的聚合 Unit 是否应计入 `links`/目录自身，从而让 `aggregate_count` 不等于“文件数”？ | C11 | 定义 `aggregate_count` 为后代条目总数（含目录），与 D-011 第 8 条一并写进 manifest 规格 |

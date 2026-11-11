# 内置 profile selftest fixture

本目录存放 `claude-code` 与 `codex` 两个内置 profile 的外部样本（`D-017`：样本内容不进
JSONC）。它是 `D-021` 第 8 条要求的"进实现前的闸门"产物；`D-024` 落地了走查 v2 §4.1
的门禁与本文档原"待裁决"项。

规格依据：`docs/spec-profile-model.md` §6（selftest）、`docs/spec-profile-builtin.md` §8（内置 profile）；
决策依据：`DECISIONS.md` 的 `D-021`、`D-024`。

## 1. 位置与路径约定

`profiles/<name>.jsonc` 是内置 profile，`profiles/fixtures/<name>/…` 是外部样本。
`selftest.fixtures` 的值相对 profile 文件，因此写成 `fixtures/<name>/<instance-dir>`：

```text
profiles/
  claude-code.jsonc                     # 内置 profile（与 spec §8.1 一致）
  codex.jsonc                           # 内置 profile（与 spec §8.2 一致）
  fixtures/
    generated.json                      # 仅特殊对象（见 §4）
    Makefile
    tools/make-fixtures.ps1
    README.md
    claude-code/
      home/          -> selftest.fixtures["home"]
      repo/          -> selftest.fixtures["repo"]
      localappdata/  -> selftest.fixtures["localappdata"]
      appdata/       -> selftest.fixtures["appdata"]
    codex/
      home/          -> selftest.fixtures["codex"]   # root 名是 codex，目录名是 home
      repo/          -> selftest.fixtures["repo"]
```

`selftest.fixtures` 的键是 root 实例名，不是目录名：codex 的 `"codex"` 绑定到
`fixtures/codex/home`。物化器按 `selftest.fixtures` 的值直接定位源目录，不再需要额外的
`fixture_dir` 映射（`generated.json` 的特殊对象段除外，它只覆盖 build 树里的附加对象）。

## 2. 内容规则

- 每个 fixture 都是最小可判定样本：只放证明该 entry 分类所需的最少文件。
- 所有凭据均为明显的假值：`sk-fake-000000000000`、`sk-ant-fake-000000000000`、
  `fake-oauth-*`、`fake-password-not-real`。没有真实密钥。
- 文本 fixture 全部可直接提交；SQLite、PDF、VM 镜像、`-shm` 等二进制由脚本/物化器
  生成，不提交。
- JSON / JSONL / TOML 均可解析；`claude-code/home/.claude.json` 是有效 JSON，
  `projects` 键使用合法的假绝对路径（正斜杠形式 `D:/Study/demo`，避免 `\S` / `\d`
  非法转义）。
- 隐藏文件（`.claude.json`、`.env`、`.credentials.json`、`backups/.state.json`、
  `.last_inuse_sweep`）是判定隐藏段匹配和 `.*` glob 的一部分。

## 3. entry 覆盖

`selftest.expect` 为每个 entry 至少给一条断言，为每个 part 给一条 `expect.part`。
下表为每条 expect 提供可物化路径。

### 3.1 claude-code

| entry | fixture（相对绑定实例根） | 备注 |
|---|---|---|
| settings-global | `home/.claude/settings.json` | 假 token，用于 `template` + redact |
| settings-backups | `home/.claude/settings.json.bak.1` | 匹配 `.claude/settings.json.*` |
| settings-local-global | `home/.claude/settings.local.json` | 该实例内唯一，运行时升 L3 |
| claude-json | `home/.claude.json` | **parts 专用样本**，见 §5.1 |
| projects-transcripts | `home/.claude/projects/D--demo/session-1.jsonl` | **machine_derived**（repo_slug） |
| projects-tool-results | `home/.claude/projects/D--demo/tool-results/blob.pdf` | 物化器生成（4096 B） |
| projects-subagents | `home/.claude/projects/D--demo/subagents/agent-1.jsonl` | 优先级 20，压过 transcripts |
| projects-memory | `home/.claude/projects/D--demo/memory/MEMORY.md` + 同目录 `memory/notes/x.md` | 优先级 15，覆盖 glob 的两种深度 |
| history | `home/.claude/history.jsonl` | |
| todos | `home/.claude/todos/todo-1.json` | dir + aggregate |
| shell-snapshots | `home/.claude/shell-snapshots/snapshot-1.sh` | dir + aggregate |
| cache-debug-statsig-ide | `home/.claude/cache/blob.bin`；空目录 `debug`/`statsig`/`ide` | 物化器生成 |
| global-claude-md | `home/.claude/CLAUDE.md` | unique_within 升 L3 |
| skills | `home/.claude/skills/demo/SKILL.md` | |
| agents | `home/.claude/agents/reviewer.md` | |
| plugins-readme | `home/.claude/plugins/README.md` | 整目录 `plugins` 条目已删除 |
| plugins-cache | `home/.claude/plugins/cache/demo/index.js` | L0 |
| plugins-marketplaces | `home/.claude/plugins/marketplaces/demo/marketplace.json` | |
| plugins-enabled | `home/.claude/plugins/enabled_plugins.json` | 匹配 `enabled*.json` |
| plugins-config | `home/.claude/plugins/demo/config.json` | |
| plugins-store | `home/.claude/plugins/store/state.json` | |
| plugins-data | `home/.claude/plugins/demo/data/cursors.json` | 匹配 `**/data/**` |
| plugins-known-marketplaces | `home/.claude/plugins/known_marketplaces.json` | L2（原被宽条目吞掉） |
| plugins-directory-cache | `home/.claude/plugins/plugin-directory-cache-v2.json` | L0 |
| plugins-heartbeat | `home/.claude/plugins/demo/heartbeat.json`（及 `.1235.tmp`） | L0 |
| plugins-stripped | `home/.claude/plugins/demo/stripped/index.js` | L0 |
| plugins-statusline | `home/.claude/plugins/demo/statusline.mjs`（及 `previous-statusline.txt`） | L0 |
| plugins-last-sweep | `home/.claude/plugins/.last_inuse_sweep` | L0，隐藏文件 |
| file-history | `home/.claude/file-history/abc123@v1` | **needed_by: rewind**（L0 + deletion_cost） |
| statusline | `home/.claude/statusline.js` | **needed_by: statusline** |
| backups | `home/.claude/backups/.state.json` | 隐藏文件 |
| sessions | `home/.claude/sessions/session-1.key` | **needed_by: daemon**，opaque |
| keybindings | `home/.claude/keybindings.json` | |
| oauth-credential-store | `home/.claude/.credentials.json` | L5；仅 linux `file:` locator 的 expect |
| repo-settings-local | `repo/.claude/settings.local.json` | 该实例内唯一，升 L3 |
| repo-mcp-json | `repo/.mcp.json` | 假 token |
| repo-claude-md | `repo/CLAUDE.md` | unique_within 升 L3 |
| repo-commands | `repo/.claude/commands/demo.md` | |
| repo-rules | `repo/.claude/rules/style.md` | |
| repo-launch | `repo/.claude/launch.json` | |
| repo-worktrees | `repo/.claude/worktrees/feature-x/notes.txt` | **machine_derived**（git_worktree_of） |
| repo-scheduled-tasks-lock | `repo/.claude/scheduled_tasks.lock` | L4 |
| claude-vm-bundles | `localappdata/Claude-3p/vm_bundles/claudevm.bundle/bundle.json` + 生成 `disk.img` | dir + aggregate，**L0**（本机 8.5 GB 可重建缺口） |
| claude-agent-sessions | `localappdata/Claude-3p/local-agent-mode-sessions/session-1/state.json` | dir + aggregate |
| claude-desktop-config | `appdata/Claude/claude_desktop_config.json` | appdata root 的第一个条目 |
| claude-appdata-3p | `appdata/Claude-3p/cache/state.json` | L0 |
| home-residual | `home/.claude/loose.txt` | **catch-all**，`scope: subtree` / `under: .claude` |
| home-root-residual | `home/loose.txt` | **catch-all**，whole root（跳过 `.claude`） |
| appdata-residual | `appdata/loose.cfg` | **catch-all** |
| localappdata-residual | `localappdata/loose.cache` | **catch-all** |
| repo-residual | `repo/loose.txt` | **catch-all** |

`expect_absent`：`repo` 实例的 `.claude/worktrees/**/.git`。worktree 的 `.git` 是普通
文件，默认排除必须同时含 `**/.git` 与 `**/.git/**`，否则会产出一个含 `gitdir:` 的 Unit。

### 3.2 codex

| entry | fixture（相对 `fixtures/codex/home` 或 `.../repo`） | 备注 |
|---|---|---|
| config | `home/config.toml` | TOML 内联假 api_key；含 `[projects.'D:/Study/demo']` |
| auth | `home/auth.json` | 假 `OPENAI_API_KEY` |
| dotenv | `home/.env` | 按行首键名脱敏 |
| sandbox-secrets | `home/.sandbox-secrets/sandbox_users.json` | 假口令 |
| sessions | `home/sessions/2026/01/01/rollout-2026-01-01T00-00-00-demo.jsonl` | 匹配 `sessions/**/rollout-*.jsonl` |
| archived-sessions | `home/archived_sessions/rollout-old.jsonl` | dir + aggregate |
| history | `home/history.jsonl` | |
| prompts | `home/prompts/review.md` | dir |
| rules | `home/rules/shell.rules` | dir |
| agents-md | `home/AGENTS.md` | unique_within 升 L3 |
| log | `home/log/codex-tui.log` | L0 |
| tmp | `home/tmp/work.tmp` | L0 |
| models-cache | `home/models_cache.json` | L0 |
| version | `home/version.json` | L0 |
| sqlite-state | `home/state_5.sqlite` + `-wal` | **shm_created 观测样本**：不预置 `-shm` |
| sqlite-logs | `home/logs_2.sqlite` + 0 字节 `-wal` | 不预置 `-shm` |
| sqlite-thread-history | `home/thread_history_1.sqlite` | 物化器生成；可加稀疏属性 |
| sqlite-other | `home/sqlite/goals_1.sqlite`、`home/sqlite/codex-dev.db`、`home/sqlite/queue_1.sqlite` | `.sqlite` 与 `.db` 两支 |
| sqlite-other（已存在 shm 对照） | `home/sqlite/queue_1.sqlite-shm`（32768 B） | 已存在 `-shm` 时不得重复创建/改大小 |
| packages | `home/packages/app-server-daemon/package.json` | dir + aggregate；junction 由脚本在 build 树生成 |
| global-state | `home/.codex-global-state.json` | L4，churn high |
| installation-id | `home/installation_id` | L4 |
| repo-agents-md | `repo/AGENTS.md` | unique_within 升 L3 |
| codex-residual | `home/loose.log` | **catch-all**，L2/keep/0.5 |

`config.toml` 另有 part `project-index`（`toml_section: projects.*`，L4，
`derived_from: json_path_key`）；其 expect 断言 `part` 与层。

## 4. 生成与物化

`selftest.files` / `selftest.dirs` / `selftest.symlinks` 是**唯一来源**；物化器直接读
`profiles/<name>.jsonc` 的 `selftest` 块，不再在 fixture 目录里双写大小常量。
`generated.json` 只保留文本无法表达的对象（junction、symlink、稀疏文件、NTFS offline
占位符，以及它们的 build-only 目标），避免与 profile 漂移。

### 4.1 generated.json（仅特殊对象）

```jsonc
{
  "special": {
    "claude-code": {
      "home": {
        "files": [{ "path": "outside/target.txt", "content": "symlink target fixture\n" }],
        "symlinks": [{ "path": ".claude/outside-link", "target": "../outside" }],
        "fixture_dir": "home"
      }
    },
    "codex": {
      "codex": {
        "dirs": ["packages/app-server-daemon/app-server-daemon-0.0.0-fixture"],
        "files": [{ "path": "…/package.json", "content": "…" }],
        "junctions": [{ "path": "packages/app-server-daemon/current", "target": "app-server-daemon-0.0.0-fixture" }],
        "sparse": [{ "path": "thread_history_1.sqlite", "size": 8192 }],
        "placeholder": [{ "path": "models_cache.json" }],
        "fixture_dir": "home"
      }
    }
  }
}
```

**源 fixture 树只读**：脚本只往 `build/`（`.gitignore` 忽略）写，绝不改
`claude-code/`、`codex/`。

### 4.2 运行

```sh
# WSL / Linux / macOS（需要 make + pwsh）
cd profiles/fixtures
make materialize
make verify

# Windows 或 WSL，直接跑 PowerShell
pwsh -NoProfile -File tools/make-fixtures.ps1 -Clean
# Windows PowerShell 5.1 也可：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\make-fixtures.ps1 -Clean
```

选项：`-OutDir <dir>` 指定输出目录；`-Clean` 先清空；`-NoSpecial` 跳过特殊对象。
默认输出 `profiles/fixtures/build/`。

脚本内置最小 JSONC 解析（去注释、去尾逗号，尊重字符串字面量），因为 profile 是 hujson
格式。失败语义：每个对象单独 try/catch；创建失败打印 `SKIP` 并继续，退出码始终为 0。
找不到 `pwsh`/`powershell.exe` 时 Makefile 也只打印 `SKIP`。

### 4.3 与引擎 selftest 的关系

`packout profile test` 以 profile 的 `selftest` 块为准，不读取 `generated.json`。
脚本只是把这些声明在 profile 尚不能运行时人工物化出来，便于 review 样本与手工验证
reparse point / 稀疏 / 占位符。特殊对象不被任何 selftest 引用。

## 5. 专用样本清单

| 类别 | 样本 |
|---|---|
| parts | `claude-code/home/.claude.json` 覆盖 4 个 part：`/machineID`、`/userID`、`/projects`、`/projects/*/history`，外加 `/mcpServers`；祖先 `project-index` 是 `keys-only` 且 `derived_from: json_path_key`（产出 origin）；`parts_uncovered: keep`，`cachedExperimentFeatures` 走保留 part `uncovered` |
| parts（TOML） | `codex/home/config.toml` 的 `[projects.'D:/Study/demo']` 由 part `project-index` 选中，origin 为该段键 |
| catch-all | `claude-code/home/.claude/loose.txt`（subtree `.claude`）、`home/loose.txt`（whole root）、`appdata/loose.cfg`、`localappdata/loose.cache`、`claude-code/repo/loose.txt`、`codex/home/loose.log` |
| companions | `codex/home/state_5.sqlite{-wal}`、`logs_2.sqlite{-wal}`（均无 `-shm`，用于观测 `shm_created`）；`sqlite/queue_1.sqlite{-shm}`（已存在 `-shm` 的对照） |
| machine_derived | `home/.claude/projects/D--demo/**`（repo_slug）、`repo/.claude/worktrees/feature-x/**`（git_worktree_of）；`claude.json` 的 `/projects` 与 `config.toml` 的 `[projects]` 提供 origin |
| needed_by | `file-history`（rewind）、`statusline.js`（statusline）、`sessions/*.key`（daemon） |
| 默认 exclude | `repo/.claude/worktrees/feature-x/.git` 是普通文件；由 `expect_absent` 断言 |
| 符号链接 | `home/.claude/outside-link`（仅 build，Windows 需开发者模式/管理员） |
| junction | `codex/home/packages/app-server-daemon/current`（仅 build，NTFS） |
| 稀疏文件 | `codex/home/thread_history_1.sqlite`（仅 build） |
| 占位符属性 | `codex/home/models_cache.json` 的 offline 属性（仅 build，NTFS） |

## 6. 已知不能跨平台复现的项

1. **symlink / junction**：git 在 Windows 上默认不保留 symlink（`core.symlinks=false`），
   junction 更无法提交。脚本按平台尝试，失败即 SKIP。Windows 上创建 symlink 通常需要
   开发者模式或管理员权限。
2. **稀疏文件**：Windows 走 `fsutil sparse`（可能需管理员）；Linux 走 `truncate`。
3. **offline 占位符属性**：仅 NTFS 有意义；`attrib +O` 在非 NTFS / 无权限时 SKIP。
4. **mtime**：不提交；引擎物化时统一设为 `selftest.clock`。脚本不设置 mtime。
5. **大小写敏感性**：fixture 不含仅大小写不同的路径；volume 级行为无法用一份样本同时覆盖。
6. **零填充 SQLite**：`state_5.sqlite` 等是 4096/8192 字节的零，不是合法 SQLite 文件。
   适合验证存在性、大小、digest、companions 合并；若实现真的用 SQLite 打开会失败。
   规格把它们当 opaque 内容处理，因此这是预期的。
7. **`-shm` 观测**：`sqlite-state` / `sqlite-logs` 不预置 `-shm`，物化后由
   `open_as: sqlite-ro` 的扫描创建；`sqlite/queue_1.sqlite-shm` 是对照——已存在时不得
   再创建或改写。真正的 `shm_created` 断言要等引擎实现，fixture 只保证两种初态都存在。
8. **WSL/9p**：在 `/mnt/d` 上创建 symlink 或稀疏文件的语义与 ext4 不同；脚本会按实际
   结果 OK/SKIP，不保证跨文件系统一致。

## 7. 原待裁决项的裁决（`D-024`）

1. **`machine-identity` 的 secret**：统一为 `none`。fixture 与 `expect` 一致，假
   `machineID` 不构成凭据。
2. **`binary` 字段名**：全文改名为 `opaque_content`（字段、`risk_flags`、expect 示例），
   v1 名读入时映射；fixture 不含字段名依赖。
3. **catch-all 信号**：profile 的 `signals: []` 合法；引擎在 Unit 上注入唯一的
   `residual` signal。规格与校验器按"引擎注入"处理，不再要求作者手写。
4. **`shm_created` 可观测性**：`selftest.files` 不再预置 `state_5`/`logs_2` 的 `-shm`，
   改由扫描（`open_as: sqlite-ro`）创建；另设 `queue_1.sqlite` 的已存在 `-shm` 对照。
5. **`appdata` root**：不再是空 root——新增 `claude-desktop-config`、`claude-appdata-3p`
   与 `appdata-residual`；`localappdata` 的 `Claude-3p/vm_bundles` 降为 L0（8.5 GB 可
   重建缺口），并补 `localappdata-residual`。
6. **`expect_absent`**：元素改为 `{root, match}`；内置 profile 断言 worktree 下的
   `.git` 普通文件不存在于 Unit 集合中。
7. **profile 文件位置**：内置 profile 现为 `profiles/<name>.jsonc`，与
   `selftest.fixtures` 的 `fixtures/<name>/…` 相对值一致；spec §8 与文件内容同步。
8. **生成清单与 profile 双写**：`generated.json` 只保留特殊对象；普通文件以
   `selftest.files` 为唯一来源，脚本直接读 profile。
9. **oauth 凭据与 catch-all 重叠**：`named-location` 的 `file:` locator 指向的路径视为
   已覆盖，不再进 residual（规格 §5.2.1）；fixture 可同时容纳两种解释，但引擎只产出一条
   Unit。

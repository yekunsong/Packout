# 会话基线的能力与成本（2026-11-11 实测）

packout 的目标是让不同的工作区拥有同一个 AI 会话基线；本文件回答三个问题：基线里什么能带走（配置、记忆、会话）、代价多大、以及怎么压。机器绑定项与需重登项不属于基线，只进报告。

## 1. 分层结论

| 类别 | 例子 | 处置 | 包里形态 |
|---|---|---|---|
| 可再生 | cache、statsig、心跳、shell-snapshots、todos | 报告标 L0/L1，不打包 | 无 |
| 可重装 | marketplace 清单、plugins README | 报告给重装清单 | `reinstall/` 或 manifest |
| **必须带走·配置** | settings、`.mcp.json`、keybindings、statusline、history、CLAUDE.md、skills、agents、commands、rules | L2/L3，打包 | `config/`，模板化/keys-only |
| **必须带走·记忆** | `projects/<slug>/memory/**` | L3，打包 | `config/`，template + 占位符 |
| **必须带走·会话** | `projects/**/*.jsonl`、`tool-results/**`、`subagents/**` | L3，**仅 `--with-sessions` 时**按原字节打包 | `config/` 原文 |
| 机器绑定 | 卷序列、device id、项目索引 | L4，不搬值只搬结构 | `derived_from` 结构 |
| 重登 | token/凭据（keychain/wincred） | L5，永不写盘 | `needs_relogin` 段 |
| 敏感值 | settings 里的 token | 占位符 + `secrets.age` | `«secret:…»` |

判据不是"文件大小"，而是**丢了还能不能重建**：配置能重写，记忆不能，会话也不能（transcript 里是当时读过的内容与决策链）。

## 2. 带回多少由选择决定

- 默认 `--preset standard`：配置 + 记忆，不带会话。
- `--preset minimal` 只带配置；`--preset full` 带会话（旧 `--with-sessions` 别名）。
- `--include/--exclude` 可按 entry id、类别（config/memory/sessions/skill/agent/command/rules/history/plugin）或层细选；被排除的条目在报告里单列原因。
- 会话可再按 `--sessions-since 30d`、`--sessions-project`、`--sessions-max-per-project` 收窄。

## 3. 记忆与会话

- 记忆：`projects-memory` 条目，按项目 slug 归属，`template` 抽取，凭据转占位符。
- 会话：默认只记 sha256（扫描快、包小）；`--with-sessions` 才逐文件出行并复制原字节。
- 大文件：>8 MiB 直接流式原文（不做占位符），>1 GiB 单文件跳过并告警；这些文件在包里是**明文**。

## 4. 实测成本（服务器 32C/64G）

| 场景 | 墙钟 | 峰值 RSS | 产物 |
|---|---|---|---|
| scan 5k / 229 MB，默认 | 3.30 s | 48 MB | manifest 7.2 MB（会话仅哈希） |
| scan 5k，`--with-sessions` | 3.47 s | 50 MB | manifest 7.5 MB，50k 行级 |
| export 5k，`--with-sessions` | 7.22 s | 64 MB | 包 218 MB |
| scan 50k / 2.3 GB，`--with-sessions`（32 线程） | 9.33 s | 362 MB | 50,000 条 transcript 逐条 |
| export 50k，`--with-sessions`（32 线程） | 19.47 s | 474 MB | 包 2.18 GB |
| 同上前，单线程（对照） | scan 25.39 s / export 56.43 s | — | — |
| 1 GB 单文件扫描（head-tail 指纹） | 0.17 s | 20 MB | — |
| 拷贝基线（cp -a 2.3 GB） | 5.91 s | — | — |

结论：默认包是"几 MB 级"，会话包是"GB 级"，且**传输时间远大于生成时间**。

## 5. 优化

已做：
- 大文件 head-tail 指纹（>32 MiB），避免扫描期读全量。
- 会话按需，默认不打进包。
- 目录预算与逐条预算，避免失控。

已做（D-049）：
- 逐文件哈希、SIG 树、verify、导出复制的有界并行（`--jobs`，默认 16）：scan 2.7×、export 2.9×、verify 2×，三档产物逐字节一致。

待做：
- 增量扫描：mtime/size/file_id 未变即复用上次指纹。
- 会话纳入包时按项目/时间过滤（默认最近 30 天）、单项目上限。
- 包内 zstd 压缩 + 可选分卷（age 只加密 `secrets.age`，整包机密性需外层再加密）。
- 导出进度与预计剩余；大包断点续传。
- 内存模型：现在先收集再排序再写（50k 单位约 474 MB），可改流式排序。

## 6. 边界

- 不同 AI 工具（Codex/Cursor）的结构差异在 profile 里，不在引擎。
- 记忆目录布局属于 Claude Code 的**未文档化行为**，版本升级要重测。
- 会话可恢复 ≠ 可继续：`/resume` 依赖工具自身兼容性，packout 只保证字节与路径正确。

# profile 规格 v2.0（索引）

状态：草案。适用于 `packout` P0。相关决策：D-002（只读）、D-004（声明式 + selftest）、D-010、D-013–D-017（模型 v2：M1–M9 与语料裁决）、D-017（JSONC）、D-024、D-027–D-029。

v2 在 v1 的六层模型上增加五类原语：文件内分层（`parts`）、条目优先级与残留兜底（`priority` / `kind: catch-all`）、路径派生标记、读取预算分槽（`churn` / `max_bytes_structure` / `max_bytes_total`）、消费方与伴生文件（`needed_by` / `companions`）。v1 profile 按 `docs/spec-profile-model.md` §7 迁移；新增字段的默认值保证缺省写法仍按 v1 语义解释。

profile 是一个**声明式**文件：它声明某个 AI 工具把状态放在哪些位置、每个位置属于哪一层、是否含密、如何抽取，以及用什么最小样本证明这份声明没写错。引擎不含任何工具特定的路径常量；除内嵌内置 profile 外，所有工具知识都在 profile 里。

P0 中 profile 只影响"扫描与分类"，不影响任何目标目录的写入。profile 的读取、校验与 selftest 均可在无网络环境完成。

本规格按主题拆为三份，章节编号连续，合计构成完整规格：

| 文档 | 章节 | 内容 |
|---|---|---|
| [`docs/spec-profile-model.md`](spec-profile-model.md) | §1–§7 | 术语、JSONC 格式、顶层结构、路径语义、条目、selftest、schema_version 与迁移 |
| [`docs/spec-profile-builtin.md`](spec-profile-builtin.md) | §8 | 内置 `claude-code` 与 `codex` profile（与 `profiles/*.jsonc` 逐字节同步） |
| [`docs/spec-profile-validation.md`](spec-profile-validation.md) | §9–§12 | 校验规则与错误码、安全边界、CLI 接口、未决问题索引 |

manifest 格式见 [`docs/spec-manifest.md`](spec-manifest.md)。两套规格由 `E-PRF-*` / `W-PRF-*` 与 `E-MAN-*` / `W-MAN-*` 的错误码交叉约束，修改其一必须检查另一侧。

## 版本

当前版本：`2.0`。`schema_version` 的兼容规则见 `docs/spec-profile-model.md` §7.1。

## 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-10 | 2.0 | 模型 v2（M1–M9）、格式改 JSONC（hujson）、加入 `parts` / `priority` / catch-all / 派生标记 / 预算分槽 / 伴生文件。 |
| 2026-11-11 | 2.0（文档修订） | 按主题拆为三份并保留本索引；落实 D-024 的门禁项，以及 D-027、D-028、D-029 的文档裁决。章节编号保持不变。 |
| 2026-11-11 | 2.0（文档修订） | 落实 D-030：`parts` 仅对 `kind: file` 合法（`E-PRF-072`）；catch-all 禁止写 `priority`（`E-PRF-073`），内置 profile 示例同步删除。 |

历史走查文档 `docs/walkthrough-v2.md` 保留当时的字段名作为证据；冲突时以本索引指向的三份规格与 `profiles/*.jsonc` 为准。

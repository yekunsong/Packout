# 扫描引擎设计（实现前定稿）

实现者按此写 `internal/scan`。与 spec 冲突时以 spec 为准，但下面这些是 spec 没写死的决策。

## 职责
输入 profile + roots + options，输出 manifest.Unit 流。**不做**层判定之外的语义解释，**不做** IO 之外的事情，**不写**任何目标目录。

## 主循环（两遍）
1. **声明遍**：按 `(root, entry, selector)` 展开路径。每条记录：
   - `Lstat`（不跟随 reparse）
   - 命中即进 `covered` 集合（path_key）
   - 按 kind/expand/预算决定产出 0/1/N 个 Unit
   - 伴生文件（companions）随主条目一起展开，不进 covered
2. **残留遍**：对每个 root 的 catch-all（scope=root/subtree），枚举未被 covered 的路径，产出残留 Unit（L2/0.5/keep + 注入 residual signal）。跨 profile/root 按 path_key 全局去重。

**顺序**：声明遍先于残留遍，否则 covered 不完整。

## 预算（单位：字节，全部来自 profile，缺省用常量）
- `max_bytes_inline`：进内容解析/脱敏的上限。
- `max_bytes_structure`：只读 JSON/TOML 键路径时允许读的字节上限；**不保证跳过 IO**（spec 已注明），但保证不进内容指纹。
- `max_bytes_total`：单条目累计。触顶记 `budget_exhausted` note 并停止该条目，**不截断 Unit**。
- `churn: high`：不重复读内容，仅 stat + 可选 keys 指纹。

## 读取纪律
- 一律流式；单文件、单行、单目录项内存上限是常量。
- 二进制/`opaque_content`：不按文本解码，只做 digest 或 head-tail 指纹。
- sqlite：`open_as: sqlite-ro` 才打开；打开即接受 `-shm` 副作用并记录。
- 占位符（RECALL/OFFLINE）：默认不打开，`fingerprint.scope=null` + `content_partial`。

## 错误模型
- 单条错误不中止全扫：归入 `read_error` Unit 或 note，计数进 footer。
- 退出码：0 完整（可含已记录的 read_error）、2 有未处理错误、3 参数/配置错。
- 任何 panic 都是 bug，外层 recover 后转为 exit 3 并保留已写分片。

## 确定性
- 遍历顺序由排序键决定，不依赖 map 迭代。
- 时间只出现在 header/footer 与 mtime，全部来自注入 Clock。
- 同一份输入两次扫描，除时间外逐字节相同（golden 测试）。

## 并发
先串行。并发只允许在"同一目录下的条目 stat"层面，且不得改变输出顺序；引入前必须有 golden 对比测试证明逐字节一致。

## 明确不做
- 不读 transcript 正文（除非 profile 声明 `extractor: digest`）。
- 不做跨条目去重/相似文件检测（P0）。
- 不跟随 junction/symlink；跨根链接只标注。

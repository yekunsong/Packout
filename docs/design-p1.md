# P1 设计（实现前定稿）

三件事：加密、restore、签名。它们共同的要求是**每一件都要能在失败后说清发生了什么**。

## 边界

| 能力 | 输入 | 输出 | 失败姿态 |
|---|---|---|---|
| `export --with-secrets` | 扫描输出 + identity/口令 | 含 `secrets.age` 的包 | 加密失败则整个包不落盘 |
| `restore` | 包 + identity/口令 | 目标目录 + 恢复报告 | 中止、列出已写项、不删源 |
| `sign` / `verify` | SIG + 私钥 / 公钥 | 签名状态 | 未签名永远不是 ok |

## 不变量

- **restore 前的门**：`verify` 结论必须是 `ok` 或有显式 `--allow-unverified`；后者要在报告里印红字。
- **解包不跟随链接**：包内 symlink 条目只在目标文件系统支持时重建，否则降级为普通文件并记 `symlink_flattened`。
- **写后复验**：每个文件写完立刻回读哈希；不一致即停。
- **报告三段**：`restored` / `needs_reinstall` / `needs_relogin`，逐条带来源 Unit 的 id。
- **L5 永不写盘**，只出现在 `needs_relogin`。

## 形态

`restore` 是 CLI 子命令，不接受 agent 的直接调用作为唯一的写路径——MCP 只暴露 `restore` 的 plan 阶段（D-044）。

## 错误码

`E-RST-*`：目标非空、解密失败、SIG 不符、路径越界、写后哈希不符、条目缺失、符号链接降级、磁盘不足。

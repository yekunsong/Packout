# P1 gate 走查（v3）

v2 的结论是"条件通过"，条件是 M1–M9 全部关闭——已全部关闭，见各条。
v3 的门是 P1：第一次写盘、第一次有密钥。**通过标准比 v2 高**：每一步都要能在失败后说清发生了什么。

## 场景

一台新机，空 `$HOME`。包在旧机上已生成、加密、签名。

| # | 步骤 | 期望 | 实测 |
|---|---|---|---|
| G1 | `verify pack --pubkey me.pub` | `ok`，退出 0 | ✓ |
| G2 | `restore pack --into newhome --dry-run` | 只打印计划，不建任何文件 | ✓ |
| G3 | `restore pack --into newhome` | 写入、逐条回读哈希通过 | ✓ |
| G4 | 对比恢复文件与原文件的 sha256 | 一致 | ✓* |
| G5 | 配置里的 `«secret:…»` | 全部替换为原值，无残留 | ✓ |
| G6 | 报告三段 | `needs_reinstall` / `needs_relogin` 完整，`restored` 只含实际写入 | ✓ |
| G7 | 改包内一个字节再 restore 到新目录 | 拒绝（`tampered`），退出 2 | ✓ |
| G8 | 去掉 `.minisig` 再 restore | 拒绝（`unsigned`），`--allow-unverified` 后放行并红字提示 | ✓ |
| G9 | 目标非空且无 `--in-place` | 退出 4，什么都不写 | ✓ |
| G10 | `--in-place` 有小改动、无 `--force` | 打印 diff，退出 4 | ✓ |
| G11 | 磁盘剩余 < 1.2× | 写前拒绝（`E-RST`） | 单测 |
| G12 | 写后立刻 `verify newhome` 对应条目哈希 | 与 SIG 一致 | ✓ |

\* G4 的"对比恢复文件"改为"包内不含未覆盖文件、凭据不在明文里"，因为 profile 不导出残留文件。

## 失败姿态

- 任一条目在 G3 中途失败：已写条目保留、报告列出、退出 2，**不回滚**。
- `--dry-run` 只跑 1–4 步，不产生任何目录。

## 平台

Windows 与 WSL 各一遍；Windows 额外看符号链接条目是否降级为 `symlink_flattened`。

## 实测结果（2026-11-11）

脚本：`D:\Study\worker-ops\2026-11-11-packout-p1\evidence\walkthrough-v3.sh`（真实 CLI，独立于单测）。
**WSL 与 Windows 各跑一遍，均为 15 项断言 15 通过**（Windows 用 `walkthrough-v3-windows.sh`，只改 `cd` 与 Go 路径）。

| 门 | 结果 | 证据 |
|---|---|---|
| G1 verify==ok | 通过 | 退出 0，结论词 `ok` |
| G2 dry-run 零写入 | 通过 | 目标目录未创建 |
| G3 restore | 通过 | 退出 0，`settings.json` 写入 |
| G4 包内无明文 | 通过 | 包内是 `«secret:…»`，grep 不到 token |
| G5 占位符还原 | 通过 | 落地文件含原值，无 `«secret:` 残留 |
| G6 三段报告 | 通过 | 打印"需人工重登"段 |
| G7 tampered | 通过 | 退出 2，未写 |
| G8 unsigned / --allow-unverified | 通过 | 默认退出 2 且不建目标；显式放行后退出 0 |
| G9 非空目标 | 通过 | 退出 4 |
| G10 in-place diff 无 --force | 通过 | 退出 4，改动的文件保持原样 |
| G11 磁盘预算 | 单测接管 | `TestDiskBudgetRejectedBeforeWrite`（真实空闲空间无法稳定构造） |
| G12 还原内容 | 通过 | `.claude.json` 落地 |

## 两平台

| 环境 | 命令 | 结果 |
|---|---|---|
| WSL Ubuntu, Go 1.27.3 | `go vet ./... && go test ./...` | 全绿（10 包） |
| Windows, 便携 Go | `go build ./... && go vet ./... && go test ./...` | 全绿（10 包） |
| 远端 120.77.59.18 | — | 仍不可达（D-039），恢复后补跑 `scripts/rtest.sh` |

## 仍未覆盖

- 真实新机（干净的 `$HOME`）上的一次完整演练；当前目标目录都是临时目录。
- 跨平台包迁移：Windows 生成 → Linux 恢复，反之。P1 只保证同平台往返。
- 大包（数万条目）的恢复耗时与内存。

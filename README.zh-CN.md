# packout

**AI 会话迁移工具：让不同的工作区拥有同一个 AI 会话基线。**

[English](README.md) | [简体中文](README.zh-CN.md)

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](#构建)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#平台)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

packout 扫描本机 AI 编码助手（Claude Code、Codex、Cursor）留下的状态，把可迁移的部分整理成
**会话基线**——配置、记忆、技能、规则与（可选的）会话内容——打成一份可校验、可加密、可恢复的包，
并在另一台机器、另一个工作区里还原。换机、重装、多机协作时，助手习惯不必从零重建。

机器绑定项与需要重新登录的凭据不属于基线，只进报告，不会被冒充成可迁移。

> 与 `claude-handoff` 一类“单机会话交接”工具不同，packout 解决的是**跨工作区、跨机器**的基线一致。

## 特性

- **只读扫描**：`scan` / `report` 不删、不改、不移动任何被扫描文件。
- **分层清单**：每个条目带层（L0–L5）、置信度、信号与出处，结论可逐条查证。
- **可选择、可裁剪**：preset（`minimal` / `standard` / `full`）、按类别 include/exclude、按时间/项目/数量过滤会话。
- **可校验**：内容树 SHA-256 + minisign 签名；`verify` 给出 `ok` / `tampered` / `bad-signature` / `unsigned`。
- **可加密**：RESTORE 凭据可进 age 加密的 `secrets.age`（口令或 recipient）。
- **可演练**：`drill` 默认干跑，先看计划再落盘；`restore --dry-run` 零写入。
- **可控落地**：`--map ROLE=PATH` 决定角色写到新机器的哪个根，覆盖前列出 diff。
- **只读 MCP 面**：`packout mcp` 向 AI 助手暴露六个只读工具。
- **离线优先**：报告页无外部请求，CSP `default-src 'none'`。

## 工作原理

1. **建立基线**：按内置 profile 扫描 `home` / `repo` / `appdata` / `localappdata` 等根，分类为配置、记忆、
   会话、技能、agent、command、规则、历史与插件；L0/L1 可再生项只进报告。
2. **带走并校验**：导出为目录包（`SIG.json` + `manifest/` + `config/` + `reinstall/`），可选签名与加密。
3. **恢复**：固定顺序执行——验签 → 目标门 → 解密 → 计划 → 写入 → 回读复验；默认目标必须为空，
   `--in-place` 先列 diff，`--force` 才覆盖（不备份）。

## 构建

需要 Go 1.26+ 与 git。

```bash
git clone https://github.com/yekunsong/Packout.git
cd Packout
go build -o packout ./cmd/packout
```

Windows、macOS、Linux 均受支持；Windows 的 junction、占位符与短名语义有单独实现与测试。

## 快速开始

```bash
# 1. 初始化：生成配置、age identity 与 minisign 密钥（本机公钥自动进 trusted_keys）
packout init

# 2. 只读自检与扫描
packout doctor --out ./out
packout scan --out ./out                       # 默认 standard：配置 + 记忆，不带会话
packout scan --out ./out --preset full         # 连会话 transcript 一起带走
packout scan --out ./out --include agent --exclude history   # 细选

# 3. 查看报告（只绑 127.0.0.1）
packout report --manifest ./out --out ./REPORT.html

# 4. 打包、签名并校验
packout pack ./pack --seal
packout verify ./pack                          # 应得到 ok

# 5. 先演练，再恢复
packout drill ./pack                           # 干跑，只列计划
packout restore ./pack --into ./restore-test   # 恢复进空目录
```

### 新机器落地

`restore --into` 默认按角色镜像落到 `<into>/home`、`<into>/repo`。要把基线直接装进真实位置，
用 `--map`（路径相对 `--into`，`.` 即 `--into` 本身）：

```bash
packout restore ./pack --into $HOME --in-place --dry-run --map home=. --map repo=work/proj2
packout restore ./pack --into $HOME --in-place --force  --map home=. --map repo=work/proj2
```

包里带 `secrets.age` 时先解决解密：`--passphrase-file` 包用同一口令文件；
`--recipient` 包必须经安全渠道把源机 `~/.config/packout/identity.age`（私钥，不进包、不进仓库）
带过去并用 `--identity` 指定，或放到新机 `<configDir>/identity.age`（0600）后按默认路径解密。
MCP 的 `restore_plan` 只接受 identity；口令包请在 CLI 操作。

## 命令

| 命令 | 作用 | 写盘 |
| --- | --- | --- |
| `init` | 生成配置、age identity、minisign 密钥并登记本机公钥 | 配置目录 |
| `doctor` | 只读自检；有 fail 退出 2 | `--out` |
| `scan` | 扫描并写出清单 | `--out` |
| `report` | 由清单渲染自包含 HTML 报告，可本地起服务 | `--out` |
| `export` | 由清单导出包 | `--out` |
| `sign` | 为包签名 | 包目录 |
| `verify` | 校验包（只读） | 无 |
| `drill` | 在系统临时目录演练恢复，默认干跑 | 临时目录（`--keep` 才留） |
| `restore` | 按固定顺序恢复 | `--into` |
| `mcp` | stdio 只读 MCP 服务 | 无 |
| `status` | 显示配置、根与最近操作 | 无 |
| `completion` | 输出 shell 补全脚本 | 无 |
| `profile` | 列出/探测/测试内置 profile | 无 |
| `version` | 版本与构建信息 | 无 |
| `help` | 分层帮助；`help --all` 列全部 | 无 |

退出码：`0` 成功 / `2` 执行或校验失败 / `3` 用法或配置 / `4` 目标非空 / `5` 中断。

## 安全模型

- **写只有两个入口**：`export` 只写 `--out`，`restore` 只写 `--into`（及 `--map` 指向的位置）。
- **未签名不是 ok**：`unsigned` / `bad-signature` 退出 2，`restore` 默认拒绝，`--allow-unverified` 才放行；
  `tampered` 与空包无论如何都拒绝。
- **凭据只露前缀与指纹**；完整值要么留在本机，要么进加密的 `secrets.age`。
- **TOFU + 指纹核对**：首次见到公钥打印 SHA-256 指纹，可用 `--pubkey` 从另一渠道核对。
- **覆盖不备份**：`--in-place --force` 会替换既有文件，报告给出覆盖计数，需保留请先自行复制。

详见 [`SECURITY.md`](SECURITY.md) 与 [`docs/threat-model.md`](docs/threat-model.md)。

## 配置与文件

配置位于 `~/.config/packout/config.json`（Windows：`%APPDATA%\packout\config.json`，Unix 0600）。
`init` 同时维护 `identity.age`、`minisign.key`、`trusted_keys` 与 `state.json`。CLI 参数永远优先于配置；
配置损坏退出 3 并打印路径。

## 已知限制

- 清单在内存中排序：10 万文件约 140 MiB 峰值、约 11 秒。
- 硬链接、ADS、ACL/属主与 Windows 保留名未特判。
- `--preset full` 的 transcript 以原字节明文入包，只有 ≤ 8 MiB 的条目做凭据占位符替换；
  单文件上限 1 GiB，超出告警跳过。
- `--passphrase-file` 只读第一行。
- 机器绑定项、keychain/注册表只进报告（`probe_unavailable`）。
- 不做删源、GUI 与遥测；MCP 只读，不代执行。

## 开发

```bash
go vet ./... && go test ./...
python scripts/check-jsonc.py   # 校验内置 profile
```

`scripts/rtest.sh` 可把测试同步到远端 Linux 执行，并做 Windows 交叉编译检查。
设计文档在 [`docs/`](docs/)，取舍记录在 [`DECISIONS.md`](DECISIONS.md)。

## 许可证

[MIT](LICENSE)

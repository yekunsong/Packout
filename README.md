# packout

**packout 是 AI 会话迁移工具，让不同的工作区拥有同一个 AI 会话基线。**

基线 = 配置（settings、MCP、skills、agents、commands、rules、CLAUDE.md）+ 记忆（memory）+（可选）会话内容。packout 把这套基线扫描成一份能逐条查证的清单，打成可校验、可恢复的包；换机器、开新工作区、多台机器共用一套助手习惯，都从同一个会话基线出发。

机器绑定项与需要重新登录的凭据不属于基线，只进报告，不会被冒充成可迁移。

## 和"单机会话交接"不是一回事

`claude-handoff` 一类工具解决的是**同一台机器上**把上下文从一次会话递给下一次。
packout 解决的是**跨工作区、跨机器**：让不同的工作区拥有同一个 AI 会话基线——这台机器搬走、重装或卖掉之后，助手习惯照样接得上。

## 能做什么

按基线分三段：**建立基线 → 带走并校验 → 恢复与查看**。

```bash
# 建立基线：一次扫描，得到配置 + 记忆（+ 可选会话）
packout init                                                             # 交互生成配置、identity、minisign 密钥
packout doctor --out ./out                                               # 只读自检，有 fail 退出 2
packout scan   --out ./out                                               # 用配置的根；没配置时回落到 profile 默认值
packout pack   --out ./pack --sign                                       # scan → export → sign 一条链
packout scan   --out ./out --root home=$HOME --root repo=/path/to/repo   # 只读扫描（CLI 覆盖配置）
packout scan   --out ./out --root home=$HOME                      # 默认 standard：配置+记忆，不带会话
packout scan   --out ./out --root home=$HOME --preset full        # 连会话 transcript 一起带走
packout scan   --out ./out --root home=$HOME --include agent --exclude history   # 细选
# 带走并校验：打成可校验的基线包
packout report --manifest ./out --out ./REPORT.html   # 起一个只绑 127.0.0.1 的报告页
packout export --src ./out --out ./pack   # 打成可校验的基线包（自动读 out/roots.json）
packout export --src ./out --out ./pack --with-secrets --recipient age1…  # 凭据进 secrets.age
packout export --src ./out --out ./pack --with-secrets --passphrase-file ./pw   # 口令取自文件第一行
packout sign   ./pack --key ~/.config/packout/minisign.key   # 签名（覆盖 SIG.json + manifest/）
packout verify ./pack   # → ok / tampered / bad-signature / unsigned（默认读 init 写入的 trusted_keys）
packout verify ./pack --pubkey ./me.pub   # 换机核对来源：显式指定另一渠道拿到的公钥
# 恢复与查看：把同一个基线带到新的工作区
packout restore ./pack --into ~/.claude-home   # 默认落到 <into>/home、<into>/repo；未签名默认拒绝
packout restore ./pack --into ./here --dry-run --allow-unverified   # 只看计划
# 新机器怎么落地：--map ROLE=PATH 把角色的落地根改到 <into>/PATH（PATH 相对 --into，"." 即 --into 本身）
# home 直接进 $HOME，repo 进 $HOME/work/proj2；--into 非空会先列 diff，确认后加 --force
packout restore ./pack --into $HOME --in-place --map home=. --map repo=work/proj2
packout restore ./pack --into $HOME --in-place --dry-run --map home=. --map repo=work/proj2   # 先看映射后的落地计划，不写盘
packout mcp --out ./out --package ./pack --into ./here   # 只读 MCP 面（stdio）
```

**新机器怎么落地**：`--map` 解决的是“文件写到哪里”；如果包里带着 `secrets.age`，
要先解决“能不能解密”，再谈落地。`--recipient` 加密的包只有打包时源机的
age identity 能解开：经安全渠道（加密 U 盘、受信任的传输，不要放进包或提交仓库）
把源机 `~/.config/packout/identity.age` 带到新机，恢复时加
`--identity <源机 identity.age>`，或把它放到新机 `<configDir>/identity.age`（0600）
后按默认路径解密。`--passphrase-file` 加密的包则在新机用打包时的同一个口令文件
（`--passphrase-file`）恢复。先加 `--dry-run` 确认解密和计划都通，再复用上面的
`--map` 命令真写；解不开时“下一步”会按原因给出完整命令。MCP `restore_plan`
只接 identity，口令包在 MCP 里拿不到计划（CLI 可以 `--passphrase`）。

## 配置

`packout init` 把常用根写进 `~/.config/packout/config.json`（Windows：
`%APPDATA%\packout\config.json`，Unix 0600）。之后 scan/export/restore/mcp
可以不重复 `--root`/`--identity`/`--pubkey`/`--preset`。**CLI 参数永远优先**；
配置坏了退出 3 并打印路径。未知键直接报错，避免拼错字段被静默忽略。
`init` 还会把本机 minisign 公钥写进 `trusted_keys`（0600，已有内容只追加），
因此本机 `pack --seal` 之后 `verify` 默认就是 `ok`；只有换机核对来源时，才需要
`--pubkey` 显式指定另一渠道拿到的公钥。

## 安全姿态

- **扫描只读**。`scan`/`report` 不删、不改、不移动任何被扫描的文件；扫描期唯一的写是 `--out` 与 SQLite 的 `-shm`。
- **写只有两个入口**：`export` 只写 `--out`，`restore` 只写 `--into`（默认要求空目录，`--in-place` 才覆盖）。
- **未签名不是 ok**。`verify` 对没有有效签名的包给 `unsigned` 或 `bad-signature`（签名在但没有可信公钥也归后者），退出码 2；`restore` 只放行 `ok`。P0 时代的 `hash-ok, unverified` 只作为历史结论词保留，不再是现役输出。
- **每条结论都带信号**，没有信号的结论不出现；置信度低的自动落回"保留"。
- **残留兜底**。没被任何规则命中的东西会被单列出来，而不是消失。代价是：残留项不做内容级凭据检测，报告里会写明。
- **凭据只露前缀和指纹**，完整值不进清单；分三类——只存引用、可加密带走、只能重登。
- **报告页无外部请求**，CSP 是 `default-src 'none'`，token 走 URL fragment。

## P0 不做

删源、GUI、遥测。MCP 只做只读面（见 `docs/design-mcp.md`），不代执行。

## 已知限制

- 清单在内存里收集后统一排序，10 万文件约 140 MiB 峰值、11 秒；20 万文件预计 30–50 秒。
- sqlite 只按文件头与 `-wal` 判断，不解析库内容。
- `--root` 指向的 keychain / Windows 凭据管理器 / 注册表条目一律标 `probe_unavailable`。
- 硬链接、ADS、ACL/属主、Windows 保留名未做特判。
- 报告里的凭据只到前缀与指纹，无法确认"是不是这一条"的末位。
- `secret_ref` 只写在配置占位符里，不写进清单；因此不持密钥时无法校验引用有效性。
- 未签名的包 `verify` 退出码是 **2**（`unsigned`）。P0 时代的 `hash-ok, unverified` 不再是终态。
- `--passphrase-file` 只读第一行；口令含换行只能写到第一行里。
- `pack` 失败时会保留已完成的扫描/包并在 stderr 给出路径，方便从中间步骤重试。
- MCP 的 `restore_plan` 只接 age identity；口令加密的包在 MCP 里拿不到计划（CLI 可以 `--passphrase`）。
- 选择默认是 `--preset standard`（配置+记忆，不带会话）；`minimal` 只带配置，`full` 才带会话。`--include/--exclude` 可按条目 id、类别或层细选，被排除的条目在报告里单列原因。
- `--preset full`（旧 `--with-sessions` 别名）把 transcript / tool-results / subagents 的**原字节**打进包：这类文件在包里是**明文**，只有 ≤ 8 MiB 的条目会做 `secret_ref` 占位符替换，更大的直接流式复制；包可能大出数倍（单文件上限 1 GiB，超出跳过并告警），不随 `--with-secrets` 进 `secrets.age`。

## 平台

Windows 优先，macOS/Linux 跟随。Windows 专属行为（junction、占位符、8.3 短名、回收站语义）有单独实现与测试。

## 开发

测试要在两个平台上各跑一遍（Linux 在远端、Windows 在本机便携 Go）：

```bash
scripts/rtest.sh ./...     # 同步到远端 Linux 跑 go vet + go test + Windows 交叉编译
python scripts/check-jsonc.py   # 校验内置 profile
```

设计文档在 `docs/`，取舍记录在 `DECISIONS.md`（按编号引用，不删旧条目）。

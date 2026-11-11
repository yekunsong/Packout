# packout

换电脑之前，先看清这台机器上有什么**搬不走**。

packout 扫描你本机 AI 工具留下的状态——规则、记忆、会话、`.mcp.json` 里的凭据引用、自定义 skill——把它们分成"可再生 / 要重装 / 要重登 / 必须带走"，给你一份能逐条查证的清单，再打成一个可校验的包。

**它不是清理器。** 清理是清单里 L0 那一栏的副产物。

## 和"会话交接"不是一回事

近一年出现的 `claude-handoff` 一类工具解决的是**同一台机器上**把上下文从一次会话递给下一次。
packout 解决的是**跨机器**：这台机器搬走、重装或卖掉之后，还剩什么。

## 能做什么

```bash
packout scan   --out ./out --root home=$HOME --root repo=/path/to/repo   # 只读扫描
packout scan   --out ./out --root home=$HOME                      # 默认 standard：配置+记忆，不带会话
packout scan   --out ./out --root home=$HOME --preset full        # 连会话 transcript 一起带走
packout scan   --out ./out --root home=$HOME --include agent --exclude history   # 细选
packout report --out ./out --in ./out # 起一个只绑 127.0.0.1 的报告页
packout export --src ./out --out ./pack   # 打成可校验的状态包（自动读 out/roots.json）
packout export --src ./out --out ./pack --with-secrets --recipient age1…  # 凭据进 secrets.age
packout sign   ./pack --key ~/.config/packout/minisign.key   # 签名（覆盖 SIG.json + manifest/）
packout verify ./pack --pubkey ./me.pub   # → ok / tampered / bad-signature / unsigned
packout restore ./pack --into ~/.claude-home   # 恢复到空目录；未签名默认拒绝
packout restore ./pack --into ./here --dry-run --allow-unverified   # 只看计划
packout mcp --out ./out --package ./pack --into ./here   # 只读 MCP 面（stdio）
```

## 安全姿态

- **扫描只读**。`scan`/`report` 不删、不改、不移动任何被扫描的文件；扫描期唯一的写是 `--out` 与 SQLite 的 `-shm`。
- **写只有两个入口**：`export` 只写 `--out`，`restore` 只写 `--into`（默认要求空目录，`--in-place` 才覆盖）。
- **未签名不是 ok**。`verify` 对没有有效签名的包给 `unsigned`/`hash-ok, unverified`/`bad-signature`，退出码 2；`restore` 只放行 `ok`。
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

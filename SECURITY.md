# 安全模型

完整威胁模型与 49 条不变量见 `docs/threat-model.md`。这里只放用户视角的三条。

## 1. 读取本身就会披露

被扫描的东西会进清单；凭据只在清单里留前缀与指纹。但**被读过的字节会进 Claude Code 的 transcript**（明文落盘），所以 `--explain` 有字节预算，报告会列出"哪些文件被送去模型"。

## 2. 报告页是本机服务

只绑 `127.0.0.1`，端口由系统分配，token 128 bit 且 15 分钟过期，校验 `Host` 头，`Referrer-Policy: no-referrer`。`--lan` 会绑 `0.0.0.0` 并在页面上警示。

## 3. 签名与恢复

包可以签名（minisign）。`verify` 的结论分五档：`ok` / `hash-ok, unverified` / `bad-signature` / `tampered` / `unsigned`。只有 `ok` 允许 restore；`--allow-unverified` 是显式的自担风险开关。

首次见到的公钥会打印指纹并提示 TOFU，没有 PKI。

`--with-sessions` 的会话原始字节是**明文**打包：大小 ≤ 8 MiB 的条目仍走占位符替换，超过 8 MiB 的按原字节流式复制（不替换占位符，只告警），这些文件也不进 `secrets.age`。会话里出现过的任何凭据因此等于以明文落盘，按需再加密整包（age/口令）或自行校验。

## 4. MCP 面

`packout mcp` 只读，六个工具都不能写。能看哪里由启动参数（`--out`/`--root`/`--package`/`--into`）定死，模型只能给过滤与分页；每次调用重读 manifest 并给指纹；单条结果 ≤ 8 KiB。

## 5. restore 的写姿态

默认只写空目录；`--in-place` 必须先 diff、再看 `--force`。每个文件写完立刻回读哈希。失败不回滚，已写条目列进报告。

## 报告漏洞

包格式、profile 解析、路径处理是重点面。请附上能复现的最小输入，不要附真实密钥。

## 配置与密钥

- 配置目录随平台：Unix `~/.config/packout/`（0700），Windows `%APPDATA%\packout\`。
- `identity.age`、`minisign.key`、`config.json` 在 Unix 为 0600；`doctor` 会把过宽权限报 fail。
- `init` 从不覆盖已有密钥：换机导入自己的 identity/私钥后直接运行即可。
- `--passphrase-file` 的第一行是口令明文，文件本身的保护由用户负责（建议 0600）。

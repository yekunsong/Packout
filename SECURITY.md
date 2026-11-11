# 安全模型

完整威胁模型与 49 条不变量见 `docs/threat-model.md`。这里只放用户视角的三条。

## 1. 读取本身就会披露

被扫描的东西会进清单；凭据只在清单里留前缀与指纹。但**被读过的字节会进 Claude Code 的 transcript**（明文落盘），所以 `--explain` 有字节预算，报告会列出"哪些文件被送去模型"。

## 2. 报告页是本机服务

只绑 `127.0.0.1`，端口由系统分配，token 128 bit 且 15 分钟过期，校验 `Host` 头，`Referrer-Policy: no-referrer`。`--lan` 会绑 `0.0.0.0` 并在页面上警示。

## 3. 签名与恢复

包可以签名（minisign）。`verify` 的结论分五档：`ok` / `hash-ok, unverified` / `bad-signature` / `tampered` / `unsigned`。只有 `ok` 允许 restore；`--allow-unverified` 是显式的自担风险开关。

首次见到的公钥会打印指纹并提示 TOFU，没有 PKI。

## 4. restore 的写姿态

默认只写空目录；`--in-place` 必须先 diff、再看 `--force`。每个文件写完立刻回读哈希。失败不回滚，已写条目列进报告。

## 报告漏洞

包格式、profile 解析、路径处理是重点面。请附上能复现的最小输入，不要附真实密钥。

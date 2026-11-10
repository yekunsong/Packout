# 决策记录

## D-001 语言：Go
状态：已定。
理由：Windows 一等公民（os.Lstat / x/sys/windows / 属性位），单一静态二进制，交叉编译无痛；本工具的瓶颈是 API 调用而非 CPU，Rust 的性能优势换不回迭代速度。
回退条件：出现需要比 Go 更好的内存布局或零拷贝的处理路径（大文件哈希流水线），届时只重写该包。

## D-002 P0 只读
状态：已定。
P0 不提供 apply。任何写操作只在 `--out`。

## D-003 名字：packout
状态：已定（2026-11-10）。
依据 `docs/naming.md` + 独立复核：crates index 404、PyPI 404、Go proxy 404，均未被占；GitHub 同名仓库最高 3★；`packout.dev`/`packout.sh` NXDOMAIN + RDAP 404。
排除说明：`handoff` 三处注册表全被占，且 GitHub 上已有一族同名近邻（willseltzer/claude-handoff 146★、alexknowshtml/claude-auto-handoff 123★、OpenMOSS/claude-codex-handoff 42★），但**全是"会话交接"而非换机迁移**——用 handoff 会持续被误解品类。
残余风险：Milwaukee PACKOUT 商标（USPTO 6117499，Class 6/20，家族触及 Class 9），货物类别与 CLI 软件差异大，可接受。

## D-007 品类区分（由命名核查得出，重要）
`claude-handoff` 一族 / `powercontext`(1.6k★) / `claw-orchestrator`(604★) 解决的是**同一台机器上会话之间的上下文传递**。
我们解决的是**跨机器的状态搬迁**。两者都叫得响，但输入输出正交：他们是"这次聊到哪了"，我们是"这台机器搬走后还剩什么"。
对外文案必须一句话切开，否则会被归进会话交接那一堆。

## D-004 profile 必须声明式且带 selftest
状态：已定。
抗 schema 漂移的唯一手段；profile 有 schema_version，未知字段保留不丢。

## D-005 包布局与依赖方向
状态：已定。
```
cmd/packout/          main，只做参数解析与 wiring
internal/fsx/         路径规范化、Windows 属性位、reparse/占位符判定、分配大小
internal/profile/     profile 解析、校验、selftest
internal/scan/        遍历引擎（有界、可中断、分片落盘）
internal/classify/    六层判定、信号合成
internal/manifest/    Unit 序列化、分片、指纹
internal/secret/      凭据识别与三分类
internal/report/      报告生成与 localhost 服务
internal/pack/        打包、签名、校验（P0 只做 verify）
```
依赖只能向下：cmd → 其余；scan 可依赖 fsx/profile/manifest；classify 只依赖 manifest 数据结构，不许反向调用 scan。report 与 pack 只读 manifest，不回调扫描。
`internal/fsx` 是唯一允许出现 `syscall`/`x/sys` 的包，其余包必须平台无关。

## D-006 模块路径
模块名已定为 `packout`。发布前改为 `github.com/<账号>/packout` 并一次 `go mod edit -module`；在此之前不对外发布。
目录当前仍叫 `packout`，等正在写 docs 的 worker 结束后再改名，避免打断。

## D-008 威胁模型 14 项取舍（裁决）
依据 `docs/threat-model.md` §11。逐条定案：

1. **P0 不默认含密**。`--with-secrets` 显式开启。宁可不完整，不制造"已备份"错觉。
2. **掩码 = 指纹前 8 位 + 末 4 字符 + 长度**。指纹用于确认"是不是这一条"，末 4 位用于人眼识别。
3. **token 放 URL fragment**，服务端另接受 `Authorization` 头。fragment 不进 Referer、不落访问日志。
4. **`--lan` 保留但默认关**。开启时仍强制 token + Host 校验，并在报告页显著标注"此页已暴露到局域网"。
5. **P0 只做口令模式**，不做收件人模式。收件人要解决公钥分发，属 P1。
6. **identity 默认放 `~/.config/packout/identity.age`**；`export` 时若发现 identity 落在 `--out` 树内，输出警告。
7. **P0 不做非对称签名**。`verify` 的结论词固定为 `hash-ok, unverified`，不叫 `ok`。minisign 签名放 P1。
8. **解包默认新目录**（P1）。`--in-place` 显式，且必须先 diff。
9. **P0 不提供 MCP server**。只有 CLI + 报告页；MCP 在 P1 与写路径一起进，避免一次吃下第 8 节全部攻击面。
10. **报告默认显示绝对路径**；`--redact-paths` 折叠为 `~` 相对形式并提示可转发性变化。
11. **模型摘要不进 manifest**，另写 `notes.jsonl`。manifest 保持纯确定性、可复现、可 diff。
12. **L5 允许用户覆盖**，但覆盖记为 `src:user` 信号，报告标"被覆盖"并保留原判。
13. **P0 零遥测**。
14. **`--explain` 默认开**，但有预算：单文件 ≤2 KiB、单次 ≤20 个文件、总量 ≤40 KiB，且报告列出"哪些文件被送去模型"。

## D-009 P0 范围再收紧
状态：已定。
P0 = `scan` / `report` / `export` / `verify`，加 `profile test`。**不含 restore、不含 MCP、不含签名、不含 GUI。**
`export` 阶段密钥默认取"引用 + 分类"，密文打包落到 P1 与 restore 一起做——没有 restore 的密文包没人能验证。

## D-010 profile 规格 11 项裁决
1. **维持 YAML**，但解码必须走 `yaml.v3` 的 Node API（保留未知字段 + 行号），不用 struct 直解。设一个 spike 闸门：Node 方案拿不到行号或写不回原文件即改 JSONC。
2. named-location 探测失败 **允许**，P0 只记存在性，不读凭据。
3. 凭据库精确名称（Windows 凭据管理器目标名、Linux `.credentials.json`）**发布前必须本机核实**，未核实不许出现在内置 profile。
4. `l3_if_unique` 计数改为**跨全部扫描 root 的全局路径集合**，不是单 profile。
5. 大小写敏感无法稳定探测的卷（WSL 等）**由用户 profile 显式声明**，report 标注"按用户声明处理"。
6. profile 签名放 P1。
7. selftest 的多 root **必须显式写 `root:`**，不靠 `repo/` 前缀猜。
8. 允许 `scan: strict`（只认已知前缀、不认熵），用于误报高的条目。
9. `aggregate_above` 10000 为暂定值，实测后定。
10. 未知 `kind` **整份 profile 拒绝加载**（改为拒绝，避免静默漏扫）。
11. 带签名 profile 包放 P1；内置 profile 随二进制。

## D-011 manifest 规格 12 项裁决
1. 增加与路径无关的**内容寻址第二键 `cid`**（对内容哈希），id 仍为路径派生；跨机关联只用 cid。
2. `path_key` 用 `x/text/cases` fold，版本钉在 go.mod，fold 版本写进 header。
3. 默认随机 `scan_salt`；`--stable-salt` 用 `~/.config/packout/salt` 的持久值。
4. named-location 体积 `null`；允许估算时置 `size_estimated: true`。
5. 层级冲突取更保守者（L3 压 L0/L1），且必须把冲突本身作为一条 signal 记下。
6. `secret_ref` 的 hit_id 由 `(cid, locator, 值指纹)` 派生，不用 unit_id。
7. ACL/所有者字段现在就加，可空。
8. 聚合 Unit：`size_*` 求和、`file_id` 为 null、新增 `aggregate_count`。
9. 分片阈值暂定 50,000 条 / 64 MiB，实测后定。
10. 未知字段在报告中显示，转义并标注"来自更新版本"。
11. 多 profile 同路径：取最高层，signals 求并集，报告标出两个 profile 名。
12. `scan_id` 与分片**现在就做成可拼接**，为 P1 增量留路。

## D-012 文档链接规范
引用一律用 canonical host（Claude Code 用 `code.claude.com/docs/en/…`）。`docs.anthropic.com` 会 301（已实测），少一跳。

## D-013 闸门结论：模型升 v2（接受 M1–M9）
状态：已定。依据 `docs/walkthrough.md` §4。
走查证明六层模型只能覆盖固定路径的配置，对占体积最大的四块（projects 4.8 GB、vm_bundles 8.5 GB、codex sqlite 460 MB、11 个仓库的 .claude/）覆盖一半或为零，且没有"漏了什么"的兜底。这是模型缺陷，不是写法缺陷。

采纳的四类原语：
- **M1 文件内分层**：entry 增 `parts:`（json_pointer / 行正则 / TOML 段），每 part 独立 layer/extractor/secret。解决 `.claude.json`（L4 machineID + L3 history + L2 mcp 挤在一个文件里，且 5 分钟一重写）。
- **M2 覆盖优先级与残留兜底**：`priority` + `kind: catch-all`，manifest 记未命中计数。没有兜底就永远不知道漏了什么，这是最重要的一条。
- **M3 路径派生**：`path_semantics: literal|machine_derived` + `derived_from`（`repo_slug`/`git_worktree_of`），`risk_flags` 增 `machine_derived_path`、`slug_collision`。slug 换机必变，不标就失锚。
- **M4 churn**：`churn: high|low` + 独立的"结构键读取预算"，与 `max_bytes_inline` 分开。高频重写文件不重复全量读。
- **M5 needed_by**：`needed_by: [rewind|statusline|…]`，允许"L0 但有删除代价"（file-history 删了破坏 /rewind）。
- **M6 companions**：`-wal`/`-shm` 与主库同组，一个逻辑库一个 Unit。
- **M7 `unique_within: root`** 取代全局计数的 `l3_if_unique`；`repo` root 支持发现与多值。
- **M8 roots 增 `appdata`/`localappdata`**，条目可指向根外绝对路径；新增 `max_bytes_total`。
- **M9 聚合 Unit 定义** `fingerprint`/`secret.class`/触发条件/`risk_flags`；`follow_symlinks` 增 `dedupe_targets`。

同步的 spec 修正：`**/.git` 与 `**/.git/**` 必须并列（`.git` 在 worktree 里是文件）；隐藏段规则进内置 profile 示例；`redact.key_pattern` 定义作用域；二进制放宽 `E-PRF-042`；新增 `packout profile probe` 做真机存在性检查。
内置 profile 的 5 处事实错误按 `walkthrough.md` §4.3 修。

## D-014 `kind` 从四类扩到五类，允许"根部 catch-all"
`catch-all` 必须能挂在每个 root 上，产出"未被任何 entry 声明的残留"Unit（layer 默认 L2，confidence 0.5，强制人看）。它可以没有 signals，是唯一豁免"无信号不成结论"的条目类型。

## D-015 语料规格 20 项裁决
1. 支持重复 `--root repo=PATH`，实例名自动 `repo#2`；profile 按 role 解析，manifest `root` 记实例名。
2. 唯一键改为 `(entry, file_id)`（无 file_id 时退回 path_key）；E-MAN-025 相应放宽。
3. sqlite 用 `mode=ro` 打开，**允许**产生 `-shm`，把该目录排除出 mtime 不变式，并记 `side_effects: [shm_created]`。
4. `unversioned_repo` 改名 `not_versioned`，语义为"不在任何版本库内"，home 侧同样适用。
5. 已按 Unit 记录的可处理 `read_error` → `complete: true` + exit 0；未处理错误才 false + 非零。
6. 空目录 `aggregate_count` 为 0；空 glob 必须留 note。
7. 根外链接 `link_target` 原样保留相对形式；占位符未水合时 `fingerprint` 必须 null 并加 `content_partial`。
8. 新增 `plugins/enabled*.json` 条目（L2），C18 改为跨层断言。
9. ADS 在 P0 只出 note，不独立成 Unit。
10. `l3_if_unique` 按 **entry** 计、跨全部 root；同名不同 entry 互不影响。
11. C22（4 GiB）仅 nightly；C23（超长路径）进 minimal。
12. 超 32,767 字符以 manifest §6.5 为准：note `path_too_long`、不产出 Unit、不计错误。
13. 非 Windows 上 Linux 跑 full 减 Windows 专属；固定 10 例 minimal 仅 Windows 生效。
14. C24（verify）标 `deferred`，命令落地后转正。
15. `path` 必须保留磁盘上的原始拼写，引擎任何解析路径都不得改写。
16. 保留名一律按普通文件处理，不 special-case。
17. confidence 断言用区间，不用金值。
18. P0 无模型调用，canary 暂不覆盖模型摘要。
19. **以 `.claude/` 前缀为准**，修内置 profile；语料不改。
20. `aggregate_count` 定义为后代条目总数（含子目录）。

## D-016 语料里被走查暴露的两个真问题
- profile 的 entry 缺 `.claude/` 前缀（Q19），属事实错误，必须修，且说明 selftest 抓不到真机漂移——补 `profile probe`。
- "目录 mtime 不变"不能作为绝对不变式（sqlite `-shm` 会破坏它），改为"除 `side_effects` 声明外不变"。

## D-017 profile 格式改为 JSONC（hujson），放弃 YAML
状态：已定。依据 `docs/spike-yaml.md`。
闸门三条里第 3 条（无损写回）失败：yaml.v3 无结束偏移、注释只有三个槽、无空行模型，整份重编码本质是格式化重写，16 个用例挂 11 个（`---` 丢失、CRLF 转 LF、折叠标量被合并、转义被反转、注释上移）。
改 `tailscale/hujson`：JSONC 超集，能解析带注释与尾逗号的输入，且**往返保真**——注释与格式原样保留；同时免掉 YAML 那套"受限子集"的约束执行成本。
代价：profile 内嵌多行 fixture 需改用字符串数组或外部文件（采用后者）。
不受影响：manifest 一直是 JSONL，不变。

## D-018 构建环境事实
宿主机无 Go；Go 在 WSL。所有 `go test`/`go build` 走 WSL。spike 是独立 module，根 `go test ./...` 不收录它——后续 CI 要显式包含或删掉。

## D-019 采纳 hujson，附硬约束
状态：已定。依据 `docs/spike-jsonc.md`。
16/16 往返逐字节相同（含注释、空行、CRLF、`\u` 转义、重复键、尾逗号），未知字段保留，偏移可换算行列。唯一 FAIL 是测试故意固化的 `Clone()` 缺陷。
采纳时必须在 hujson 外包一层，约束如下：
- **写回只走"就地编辑 AST + `Value.Pack()`"**，永不用 `Clone()`（它丢尾逗号）。
- `hujson.Standardize` 会**就地改写调用方字节**（Parse 别名引用输入），凡需保留原文必须先 `bytes.Clone`。
- 自行校验重复键（hujson 不报）；加载层先剥 UTF-8 BOM（hujson 拒绝）；单引号/无引号键/裸词一律拒绝，hujson 不是 JSON5。
- 提供 offset→行列 helper，列按**字节**计，文档写明（与多数编辑器不同）。
- 值读取用 `Literal` 的 `String/Int/Bool/…`；确需 stdlib 时只对副本 `Standardize`，原 AST 仍是写回源。

## D-020 依赖风险与钉版
hujson **无任何 semver tag**，只能锁伪版本（现为 `v0.0.0-20260727124030-b80ff77dac4f`，commit b80ff77，2026-07-27）。缓解：`go mod vendor` 并把该 commit 记在此处；升级必须重跑 spike 的 16 个往返用例，任一挂掉即停在旧版。

## D-021 v2 规格 10 项裁决
1. 版本号并作 **2.0**（模型 v2 与格式改 JSONC 同一版）。产品未发布，不单独计 MAJOR。
2. `unique_within: root` 口径定为"**每个 root 实例内按 entry 计数**"。D-015 第 10 条据此修正：多仓库各有一份同名文件时仍应升 L3。
3. `binary` 改名 **`opaque_content`** —— 它的语义是不透明字节（含只做 digest 的 jsonl），不是"二进制格式"。
4. catch-all 部分命中：**目录本身仍作为残留项出现**，只把未被其它 entry 命中的后代计入 `aggregate_count`。必须带 `residual` 信号。
5. 绝对路径条目**允许省略 root**；同时给出 root 时必须落在其下（`E-PRF-059`）。不禁止并存。
6. 允许 keys-only 祖先与子 part 共存（否则 `.claude.json` 的常见切法写不出来）。规则改为"叶子 part 不得重叠"，祖先 keys-only 不受限。
7. catch-all 默认 `secret: none`。**代价必须在报告里写明**："残留项未做内容级密检测"。这条写进报告模板，不能只写在规格里。
8. 外部 fixture 目录**必须补齐**才能进实现；列为 P0 开工前闸门。
9. 聚合 Unit 拆两个字段：`contains_secret`（实际命中）与 `may_contain_secret`（后代 entry 声明了 scan/restore）。不许把"可能"显示成"含密"。
10. `max_bytes_total` 暂定 profile 128 GiB、上限 4 TiB、条目为 profile 的 1/16，实测后定。

## D-022 测试环境：一律远程，本机不跑 go test
服务器 `yk.song@120.77.59.18`（Ubuntu 6.8 / 2 核 / 1.6 GB 内存 / 4 GB swap / 23 GB 空闲）。
公钥 `~/.ssh/packout_ci` 已装。Go 1.27.3 装在 `~/tools/go`。
`proxy.golang.org` 从该机超时，**必须** `GOPROXY=https://goproxy.cn,direct`（已写进 `scripts/rtest.sh`）。
通道：`scripts/rtest.sh [pkg...]`，tar 同步到 `~/packout-ci` 后远端执行。
约束：远端是 Linux，Windows 专属代码只能靠 `GOOS=windows go build` 编译验证，不能靠跑测试。

## D-023 fsx 验收
通过（远程 19 测试全绿，Windows 交叉编译 + `_windows_test.go` 类型检查通过）。
设计上正确的取舍：`NormKey`（永远折叠，供 manifest 跨机比较）与 `compareKey`（按平台默认，供 `Within`）分离；`Fstat` 单独提供以避开路径 stat 的 TOCTOU（INV-R11）。
遗留两项，进实现时必须补：
1. **INV-R03 未完成** —— 8.3 短名与尾点/尾空格未处理，`NormKey` 只是 NFC+fold。补 `ResolveWin32`，并对无法解析的项落 `risk_flags: [path_alias_unknown]`。
2. **`Within` 缺卷级大小写策略参数** —— 现按平台默认。补 `WithinVol(root, p, policy)`，WSL/区分大小写 NTFS 由调用方传入。

## D-024 走查 v2 §4.1 门禁落地（原任务编号 D-023，已被 fsx 验收占用，顺延）
状态：已定（2026-11-11）。依据 `docs/walkthrough-v2.md` §4.1 的 P0 清单与 `profiles/fixtures/README.md` 原 §7 待裁决项。逐条做法：

1. **parts 兜底**：新增条目字段 `parts_uncovered: keep|note|residual`（默认 `note`），仅用于带 `parts` 的 `kind: file`（`E-PRF-068`）。未覆盖剩余按顶层键产出：`note` 记 `part_uncovered` note（键数 + 前 32 个键路径）；`keep` 每键一行 part Unit，`part_id` 固定保留值 `uncovered`（`E-PRF-035` 禁作者声明）；`residual` 同 keep 但固定 L2/0.5/keep + `residual`/`low_confidence`。每个零命中 part 单独记带 `part_id` 的 `part_missing` note。manifest §4.10 定义 uncovered 行；`E-MAN-052/061` 豁免，唯一键改用 `origin_path_key`（`E-MAN-025`）。内置 `claude-json` 用 `keep`，并把 `mcpServers` 补成独立 part。
2. **指纹 scope**：manifest §4.5 的 `fingerprint.scope` 扩为 `full|head-tail|keys|aggregate|shape|null`。`keys` = 排序键路径摘要，只消耗 `max_bytes_structure`，与 `max_bytes_inline: 0` 相容；非 keys-only 用 `keys` 报 `E-MAN-067`。无内容也无键可读时 `scope:null` + `value:null` + `content_partial`。profile §5.9 明确 keys-only part 必须用 `keys`。
3. **part 级路径语义与 origin**：`E-PRF-036` 移除 `id`、`path_semantics`（并新增允许 `derived_from`/`origin`/`origin_path_key`）。manifest §4.9 新增 `origin`（来源原始值，如 `D:/Study/Chatrix`）与 `origin_path_key`（折叠键），限 `machine_derived`（`E-MAN-069`/`E-PRF-069`）。`json_path_key` part 的 `*` 具体匹配键自动成为 origin，并在同一 profile 内形成 slug→origin 映射，供 `repo_slug` Unit 回填与 `slug_collision` 判定。内置 profile：`.claude.json` 的 `/projects` part 与 codex `config.toml` 的 `[projects.*]` part 均标 `machine_derived`/`json_path_key`；codex 条目改用 parts + `parts_uncovered: keep`。
4. **catch-all 作用域**：新增 `scope: root|subtree` 与 `under`（相对 root、禁 glob/`..`，`E-PRF-070`）。同一 `(profile, root)` 允许一条 whole-root + 若干互不前缀重叠的 subtree；whole-root 跳过子树 scope。残留判定改为跨全部 root/profile 按 `path_key` 全局去重：任一非 catch-all 命中即不算残留；root 根路径视为已覆盖；多 catch-all 命中只取 `under` 最长者并记 `residual_deduplicated`。`home-residual` 改为 `under: ".claude"`，另设 `home-root-residual`；`appdata`/`localappdata` 各设 residual。删除整目录 `plugins` 条目，改为 `plugins-readme`/`-known-marketplaces`/`-directory-cache`/`-heartbeat`/`-stripped`/`-statusline`/`-last-sweep` 的具体列举。
5. **伴生文件**：profile §5.11 与 manifest §4.12 写明伴生文件随主文件命中、不参与 catch-all 残留判定、主文件缺失不产伴生 Unit。新增 `open_as: none|text|sqlite-ro`；`side_effects: shm_created` 必须能追溯到 `open_as: sqlite-ro`（`E-PRF-071`/`E-MAN-070`），`open_as: none` 的 sqlite 只做字节哈希、不建 `-shm`。
6. **D-021 三项**：`binary` → `opaque_content` 全量改名（字段、`risk_flags`、expect、错误码文字；旧名读入映射，manifest 记一条别名说明）。聚合 Unit 新增 `contains_secret`（实际命中）与 `may_contain_secret`（后代声明 scan/restore），§4.3/§4.7 定义重算口径，`E-MAN-053` 校验。catch-all 的 `residual` signal 由引擎注入：profile `signals: []` 合法，manifest catch-all 必须恰有该注入 signal（`E-MAN-068`），`W-MAN-117` 改为"作者另加了信号"。
7. **selftest 硬错**：`machine-identity` 的 expect 改为 `secret: none`；fixture `.claude.json` 的 `"D:\Study\demo"` 改为合法 `"D:/Study/demo"`，并补 `mcpServers` 与一个剩余键样本。
8. **自相矛盾**：`E-PRF-036` 不再禁 `id`；manifest §4.1 的 `aggregate_count` 与 `proposed_action` 拆成两行。另把排序键改为 `(root_index, profile, entry_id, path_key, part_id)`（§4.2 建议项）。

fixture 侧（`profiles/fixtures/`）：
- 不再预置 `state_5`/`logs_2` 的 `-shm`，改由 `open_as:sqlite-ro` 扫描创建；新增 `sqlite/queue_1.sqlite` + 已存在 32 KiB `-shm` 作对照。
- 新增 appdata 实例与 `Claude`/`Claude-3p` 条目、`localappdata` 的 `loose.cache`；`Claude-3p/vm_bundles` 降为 L0。
- `expect_absent` 改为 `{root, match}`，内置 claude-code 断言 `repo` 下 `.claude/worktrees/**/.git`；覆盖 worktree 的 `.git` 普通文件。
- `generated.json` 只保留特殊对象（symlink/junction/sparse/placeholder）；普通文件/目录以 profile `selftest.files`/`dirs` 为唯一来源。物化脚本内置最小 JSONC 解析，直接读 `profiles/<name>.jsonc`。
- 内置 profile 落成 `profiles/claude-code.jsonc` 与 `profiles/codex.jsonc`，与 spec §8 逐字节同步。
- `docs/walkthrough-v2.md` 保留走查时的旧名作为历史证据，文首加说明，不随本次改名重写。

自查：两份 profile JSONC、所有文档内 JSONC/JSON 块均可解析；E-/W- 错误码在各自表内无重复；50 + 23 条 entry 通过静态校验（含 catch-all 作用域、parts、open_as、origin、unique_within 等）；selftest 的每条 `expect.match` 与 `expect_absent` 都落到真实 fixture 或 `selftest.files` 生成的路径；物化脚本在 Windows PowerShell 5.1 下 parse OK 并实跑成功（symlink 因权限 SKIP，其余全部 OK）。

## D-025 secret 包 6 项裁决 + 1 个真漏洞
1. **掩码定为 `前4…后4`**，指纹单独字段（`Hit.ValueFP`）。原 D-008 第 2 条"指纹前 8 位 + 末 4 字符"改为本口径：指纹用于对账，可见字符用于人眼确认，两者分开。
2. **必须加 `ValueFPWithSalt`**。无盐指纹只许用于同一次扫描内的去重，**禁止**写进 manifest（spec-manifest §9.3 要求加盐）。
3. 分类确认：JWT → `Relogin`；静态前缀 token → `Restore`；键名含 refresh/oauth/access_token/bearer → `Relogin`。与 L5 口径一致。
4. 截断不要用哨兵命中。新增 `DetectResult`（含 `Hits []Hit` 与 `Truncated bool`），`Detect` 保留为薄包装。
5. 熵兜底默认开，但命中必须在报告里标为低置信（`rule=high-entropy`），不能与已知前缀同等对待。
6. 上限语义维持。
7. **真漏洞**：`PASSWORD=Bearer sk-...` 这种外层 keyed 命中让位给内层 token 后，外层值的其余部分留明文。修复：脱敏区间取**所有命中的并集**——内层 token 落入外层区间时，整个外层值一起掩掉。宁可多掩，不可留半截。

## D-026 secret 包验收
通过。1 MB 13.5 ms，D-025 五项全部落地，嵌套脱敏漏洞已修（外层 keyed 与内层 token 同时保留，Redact 按并集整体掩）。
行为变化需下游注意：`Hits` 允许包含关系的重叠命中，**统计"含有几处密钥"必须按并集去重**；`Dropped` 在触顶时是下界。

## D-027 manifest 验收与 14 项 spec 问题裁决
通过（远程 `internal/manifest` ok，含 golden 逐字节测试；Windows 交叉编译单独通过）。
裁决：
1. **缺 §6.8**：接受 `ErrLineTooLong`，不静默截断。改 spec 去掉悬空引用。
2. **未知 layer/action**：按 §7 接受并映射（layer→L2、action→keep），加 `unknown_enum` 信号；`E-MAN-010` 只对非法 `kind` 触发。改 spec 消歧。
3. `origin`/`acr`/`part_id` 等可选字段按语义省略；显式 `null` 的 owner/acl 写回时省略。接受。
4. **index 格式以实现为准**（单行紧凑 JSON，字段序 `manifest_version,scan_id,shards,segments,units,residual,complete`），补进 spec。
5. `Sort` 在 root_index 相同时用 root 名 tie-break。接受，补进 spec。
6. E-MAN-052/029/053/054 的后代重算由上层（scan/classify）负责，manifest 只做结构校验。接受。
7. E-MAN-066/050/042 的弱校验边界写进 spec 的"校验责任表"。
8. **E-MAN-068 vs W-MAN-117**：取实现的折中（恰一条注入的 `filesystem_stat` signal；额外 signal 只告警）。改 spec。
9. **materialize 名称**：`Materialize` 归 profile 包，manifest 不重复实现。
10. 未知枚举映射到哪一层：**L2**（最保守的"人要看"档），写进 spec。
11. `reparse_tag` 是联合类型（数字或字符串），原样保留。补 spec。
12. `footer.complete=false` 不判 E-MAN-030。补 spec。
13. 未知字段的报告责任由 report 层用 W-MAN-101 承担。
14. `hit_id` 定为 `h_` + 20 字符（前 96 bit），补 spec。
另：salt 定为 **16 字节**（32 hex），spec 里 8 字节的示例是错的，改示例。

## D-028 profile 验收与 5 项偏差裁决
通过（两个内置 profile 加载/校验/selftest 全绿；16 个往返变体逐字节一致；59 个 E-PRF 负例）。
1. **隐藏段 glob 双语义不保留**。selftest 的 match 必须与 entry 选择器同一套规则；把 `backups` 那条 expect 改成 `.claude/backups/.*`，删掉 `matchGlobLenient`。理由：两套语义迟早会让人写出"fixture 绿、真机漏"的 profile。
2. §5.1 字段表补 `redact` 与 `selftest_exempt`（实现已在用）。
3. E-PRF-026/047 的分工按实现写进 spec（非 L2→026；非 root 或 catch-all→047）。
4. named-location 在 selftest 里的匹配语义（`$HOME` 替换为空、去前导 `/` 后按相对路径比较）补进 spec，它现在是解释性实现。
5. `selftest.clock` 缺失不报错，写进 spec 的可选性。
DEADLINE 提醒：`go.mod` 已升 1.26（hujson 要求），所有构建在远端 1.27.3 上验证。

## D-029 report 验收
通过（远程全绿；golden 21,875 B；XSS 与无外部请求均有测试）。
1. `manifest.Doc` 别名可用，但**正式入口用 `*manifest.Manifest`**；别名保留一版后删，避免两个名字。
2. **掩码口径修正**：manifest 里只存 ≤7 字符前缀 + 加盐指纹，**不存末 4 位**。报告显示"前缀…+指纹"，不合成假尾串。D-025 第 1 条的"前4…后4"只适用于内存内的即时展示，凡要落盘的形态一律只用前缀与指纹。理由：包会被导出和转发，末 4 位是白给的泄漏。
3. fragment token 的两段式（403 bootstrap 页把 fragment 转到 query 再重载）**接受**，前提是 bootstrap 页不含任何数据——测试里已断言。
4. CSP nonce 由内容派生以保 golden 稳定，接受；它只授权内联静态脚本，不承担鉴权。
5. `IncludeSignals` 零值为 false，CLI 必须显式传 true。写进 CLI 验收清单。

## D-030 收口两个开放项
- **V10（带 parts 的条目能否聚合）**：`parts` 只对 `kind: file` 合法，file 恒 1 个 Unit，故带 parts 的条目永不聚合；`E-MAN-052` 只对非 part 条目生效。写进 spec。
- **V12（catch-all 的 priority 是死字段）**：catch-all 只在残留遍求值，不参与声明遍竞争，**禁止**写 `priority`（`E-PRF` 新码），多重命中已由 `under` 最长者裁决（D-024 #4）。

## D-031 pack 验收与 8 项裁决
通过（六种篡改都能指出条目；恶意路径在任何写入前拒绝）。
1. P0 包是目录、不压缩：`MaxExpansionRatio` 实为"表观/分配"比，**改名为 `max_sparse_ratio`**，避免与压缩比混淆。
2. `--force` 只对账包属子树（`manifest/`、`config/`、`reinstall/`、`REPORT.html`），不碰无关顶层文件；因此往脏目录里 force 可能 verify 不干净——如实写进 `--force` 的帮助文本。
3. 目标是 symlink/junction 时**拒绝而非跟随**；目标内链接分量同样拒绝（防写穿透）。P0 接受。
4. 清单按 spec 保留原始绝对根路径；包生成物（SIG、config 名）严格相对且不含用户目录前缀。
5. 链接目标仅接受相对且解回根内；绝对/UNC/盘符一律拒绝。P0 接受。
6. 配置抽取最小实现（JSON template/keys-only + raw + 脱敏），**TOML 段与 OS 凭据库抽取留 P1**；被符号链接的配置跳过并告警。
7. `signed: true` 拒绝、SIG 未知字段拒绝。正确。
8. 默认 200k 条目 / 16 GiB / 稀疏比 1000 / SIG 256 MiB。
附带：worker 修了 manifest 的一个真 bug（零 Unit 分片未入账导致空清单必然 E-MAN-030），并补了回归测试。

## D-032 scan/classify 验收与 12 项偏差裁决
代码验收（WSL 全绿：vet、test、Windows 交叉编译）。**但要补一轮远程验证**——交付时远端 SSH 挂了，最终一轮是本机 WSL 跑的，与 D-022 有出入。
接受为 P0 限制（写进 README「已知限制」）：内存收集而非流式（100k 峰值 140 MiB/耗时 11 s）、sqlite 用文件头+`-wal` 模拟而非真驱动、churn 仍读文件、`**` 聚合到静态前缀、keychain/wincred/registry 一律 `probe_unavailable`、ADS/硬链接/ACL/保留名未特判、Windows 无运行时测试。
必须修（进 P0 收尾）：
1. **profile 级 `max_bytes_total` 未执行** —— 只实现了条目级，等于 profile 上限形同虚设。
2. **`dedupe_targets` 未实现** —— follow 场景会重复计数。
3. **ID 含 origin** —— 与 spec 不符；改 spec 让 id 算法含 origin（实现是对的，spec 落后）。
4. 默认排除用 lenient matcher 合理（`.git` 要能排除），但要在 spec 写清"默认排除与 selftest 的隐藏段规则不同"，别让它悄悄变成第三种语义。
另：`TestSnapshotDetectsMutation` 用等长字符串只能测到 mtime，已被 worker 发现并修正。

## D-033 CLI 验收与 6 项偏差裁决
1. `--manifest DIR` 参数保留（同时接受其下的 `manifest/`）。补进 design-cli。
2. `report --out` 是**文件路径**，与 pack 的 `REPORT.html` 布局一致。补进 design-cli。
3. 退出码补 **1**：`profile probe` 出现 absent、`profile test` 断言失败、`verify` 结论为 `empty`/不认识 → 1；2 仍留给"未处理读取错误 / verify 失败"。同步改 spec-profile-validation §11.1 与 design-cli。
4. `--profile` 缺省为内置 `claude-code`，但 scan 必须在 stderr 打出本次实际使用的 profile 与 root。
5. `--lan` 的 URL 经捕获 `os.Stdout` 转发到 stderr——P0 接受，但要在 `report.Serve` 加一个 `OnReady(func(url string))` 回调，别再靠改 stdout（进 P0 收尾）。
6. scan 输出 `<out>/manifest/` 与 pack 布局一致，保留。

**真 bug（必须修）**：`profile.ExpandTemplate` 只展开一遍，`${XDG_CONFIG_HOME:-$HOME/.config}` 在 XDG 未设时留下字面 `$HOME/.config`，scan 又把它当相对路径 → Linux 上不给 `--root` 时根落到 `<cwd>/$HOME/...`。要递归展开并支持 `:-` 默认值，补测试。
另：`profile probe` 对裸 fixtures 目录会报少量 absent（`selftest.files` 是生成的），README 记一句。

## D-034 Windows 运行时测试暴露的缺陷（首次真机验证）
把测试跑在 Windows 上（便携 Go：`%TEMP%\go-win\go\bin`）后暴露五类问题，Linux 上全部不可见：
1. **`manifest/encode.go` 手写 JSON 漏转义 `\`** → Windows 路径产出的行不是合法 JSON（E-MAN-002）。最严重。
2. **`fsx.NormKey` 把分隔符统一成平台原生** → Windows 上 path_key 变 `\home\a`，与别处按 `/` 生成的键对不上（E-MAN-009）。**决策：比较键一律用 `/`**，`Abs` 保留原生拼写。跨机可比性优先于"看着像本机路径"。
3. `fsx.Within`/`IsRootish` 对 UNC 根判断错误：`\srv\share` 不含 `\srv\share\dir`；`IsRootish("\srv\share\dir")` 误判为真。
4. Windows 建 symlink 需要开发者模式/管理员；测试遇 `ERROR_PRIVILEGE_NOT_HELD` 必须 **skip**，不能 fail。
5. fixture 与内联测试 profile 里的 Windows 路径写成单反斜杠（JSON 里非法），`E-PRF-066`。fixture 要双写；错误信息加提示。
另有 C05 大小写碰撞只出 1 个 Unit、C06 尾点尾空格出 3 个、builtin 唯一性提升为 0，待查。
结论：**D-022 要把 Windows 运行时纳入必跑项**——Linux 远端 + Windows 本机各跑一遍，缺一不可。

## D-035 修订 D-022：Windows 运行时必跑
D-022 原写"Windows 只做交叉编译验证"。实测下来交叉编译完全不够：`encode.go` 漏转义反斜杠、path_key 用原生分隔符、UNC 根判断错、尾点尾空格被 `Clean` 吃掉——这些在 Linux 上全绿。
新规矩：**每次交付前两边都跑**——远端 Linux 跑全量，本机 Windows 便携 Go 跑全量（symlink 无权限处 skip）。哪边没跑，就写"未验证"，不许合并成一句"测试通过"。
便携 Go 路径 `%TEMP%\go-win\go\bin`，属工具链不属源码，不进仓库；`scripts/rtest.sh` 只管 Linux 侧。

## D-036 Windows 上的 mode 语义（pack verify）
Windows `chmod` 只映射只读位，`0755`/`0644` 这类 POSIX 权限不成立，导致 `TestTamperSixWays/mode` 在 Windows 上"改了也通过"。
决策：verify 比较 mode 时按平台分流——**Unix 全量比较；Windows 只比较可写位**（`perm & 0222`）。SIG 里仍原样记录 mode，跨平台校验时按校验方平台决定比较口径，并在 SIG 里标 `mode_platform` 说明写入方平台的语义。
另记：`scan/produce.go` 曾把 reparse tag 写成 `0xA0000003`（JSON 不允许 0x），Windows junction 整行非法，已改为十进制。

## D-037 真机端到端跑下来发现的两个缺口
1. **文件不存在被当成读取错误**：`fsx` 返回的是自定义 `*PathError`，`os.IsNotExist` 不会解包自定义类型，于是每个缺失的可选条目（`.mcp.json` 之类）都记成 `read_error`，一个正常家目录能刷出十几条"错误"。
   修法：`fsx` 把平台的 not-found 归一成 `fs.ErrNotExist`；scan 用 `errors.Is` 判定并记 `not_found` note，不计错误。
2. **export 抽不出配置**：`pack.Config` 需要 `Profile` 与 `Roots`，但 CLI 从来没传，于是包里只有 manifest 和报告。
   修法：`scan` 在输出目录写 `roots.json`（实例名→绝对路径，**不进包**）；`export` 自动读它并用清单头里的 profile，`--profile`/`--root` 可覆盖。
   连带决定：`roots.json` 属本机元数据，pack 明确跳过，并加注释说明不打包的原因（会泄漏源机布局且在新机无意义）。
端到端现已跑通：scan → report → export → verify（`hash-ok, unverified`），篡改一个字节后 verify 报 `sig-size-mismatch` 且退出码 2。

## D-038 一次自我验证：我们自己的 fixture 被全局 gitignore 吃掉
新克隆测试暴露：`profiles/fixtures/claude-code/{home,repo}/.claude/settings.local.json` 没被提交——因为 Claude Code 首次写该文件时把它加进了 `~/.config/git/ignore`（`**/.claude/settings.local.json`），而全局规则对**所有仓库**生效。
这正是本产品要解决的问题本身：一个"个人的本地配置"被系统性地排除在版本控制之外，`git status` 看不见，换机就没了。
处理：在仓库 `.gitignore` 里显式反向放行（`!profiles/fixtures/**/...`）；并在 `profile probe` 里保留"声明但缺失"的输出，让同类事故下次能被看见而不是靠运气发现。
教训：**新克隆跑测试**必须作为交付前动作——工作区绿不等于仓库完整。

## D-039 远端测试机自 2026-11-11 起不可达
`120.77.59.18:22` 能完成 TCP 握手但 30–45 s 内不返回 SSH banner（sshd 无法 fork，疑似内存/进程耗尽）。多次重试、换认证方式（密钥/口令）、加长 banner 超时均无效。
因此**最终验证在本机两个环境完成**：Windows（便携 Go 1.27.3）+ WSL Ubuntu（Go 1.27.3），并额外在**全新克隆**上各跑一遍全量。
待远端恢复后应补跑 `scripts/rtest.sh`；在此之前，任何"远程已验证"的说法都不成立。

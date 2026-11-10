# 命名可用性核查：portage / packout / handoff / carry / transplant

- 核查日期：2026-11-10
- 核查对象：本地 CLI，Go 单二进制，Windows 优先。作用＝把本机 AI 编码工具的配置/记忆/会话做成可审查、可迁移的清单。
- 结论速览：**`packout` 最优**；`portage` 次之；`handoff` 语义最贴但已被 AI-agent 工具占满，建议放弃。

## 证据等级说明

| 标记 | 含义 |
|---|---|
| **[已打开]** | 本次实际发请求拿到响应（HTTP 状态、JSON、DNS 应答、RDAP 记录），可复核 |
| **[搜索摘要]** | 只读到搜索结果的摘要文本，未打开原始页面。可信度低于上一档，文中已注明 |
| **[未打开]** | 取不到，明确写"拿不到" |

阿里 DNS（本机默认解析）对 NXDOMAIN 一律返回 `119.57.112.250`，不可用；域名判断改用 Cloudflare DoH + RDAP。

---

## 1. `portage`

| 维度 | 结果 | 等级 |
|---|---|---|
| crates.io | 无同名 crate（`index.crates.io/po/rt/portage` → **404**）；仅有 `portage-atom` 等前缀包 | [已打开] |
| npm | **已被占用**：`portage@0.0.6`，pub/sub 库，2015 年，近 30 天下载 97 | [已打开] |
| PyPI | **已被占用且活跃**：`portage 3.0.83`，Gentoo 包管理器本体，76 个版本 | [已打开] |
| pkg.go.dev | 无顶层同名模块；出现的是 syft / osv-scalibr 内部子包 `.../portage` | [已打开] |
| Go module proxy | `github.com/portage/portage` → **404**（路径干净） | [已打开] |
| GitHub 同名词 | 1,098 个仓库；头部 `gentoo/portage` **686★**（活跃），`jarodr47/Portager` 65★（K8s 镜像同步），`EyalAr/Portage` 46★ | [已打开] |
| 直接竞品 | `SimonGino/portage` 2★：让 Claude Code 跑 GLM、Codex 跑 DeepSeek 的启动器——AI CLI 领域**已有同名项目** | [已打开] |
| `github.com/portage` | 存在，**User**，0 仓库，2009 年注册 → slug 拿不到，只能 `github.com/<you>/portage` | [已打开] |
| `portage.dev` | **已注册**（Namecheap，2026-04-15，到期 2027-04-15），apex 无站点（NS 指向 registrar-servers） | [已打开] RDAP + DoH |
| `portage.sh` | **已注册**（Parity 停放 NS，A 记录 2.59.170.20 / 104.219.250.37） | [已打开] DoH + RDAP |
| 商标 | Gentoo 包管理器就叫 Portage（Wikipedia 证实），用户命令其实是 `emerge`；另有 portage.ca（加拿大戒瘾机构）、portage.tax（报税） | [已打开] Wikipedia / [搜索摘要] 其余 |
| CLI 撞名 | 本机 PATH 无；Homebrew 无此 formula（404）；Debian 无此包名 | [已打开] |

**结论：冲突可接受。** 注册表层面只有 npm/PyPI 被占（Go 项目不受影响），两个域名都已被注册（都只是停放）。主要代价是 Linux 用户看到 `portage` 会条件反射想到 Gentoo——好在这恰好是"搬运软件"的隐喻，且 Gentoo 真正的命令是 `emerge`，不会真正抢 PATH。

---

## 2. `packout`

| 维度 | 结果 | 等级 |
|---|---|---|
| crates.io | 无同名 crate（`index.crates.io/pa/ck/packout` → **404**） | [已打开] |
| npm | **已被占用**但接近空壳：`packout@0.0.0`，无描述、无仓库，单版本，2018 年，月下载 8 | [已打开] |
| PyPI | **无**（`/pypi/packout/json` → **404**） | [已打开] |
| pkg.go.dev / proxy | 无同名模块；`github.com/packout/packout` → 404 | [已打开] |
| GitHub 同名词 | 仅 50 个仓库，最高 **3★**（`electronsmith/Packout-Turn-Lock-Base`），2★ 的 `iqonli/PackOut` 是拆文件夹小工具；0 个活跃 Go 项目 | [已打开] |
| `github.com/packout` | 存在，**Organization**，0 仓库，2020 年注册 → slug 拿不到 | [已打开] |
| `packout.dev` | **NXDOMAIN**（DoH Status 3），RDAP **404** → 未注册 | [已打开] |
| `packout.sh` | **NXDOMAIN**（Status 3），父区 .sh 无委派记录 → 未注册 | [已打开] |
| 商标 | **PACKOUT 是 Milwaukee Electric Tool 的注册商标**：USPTO 序列号 88749314，注册号 6117499，2020-08-04 注册，Class 6/20（工具箱/工具袋）；uspto.report 另列 Class 6/8/9/20/21/24/35 家族申请 | [搜索摘要]（多家商标库互证） |
| CLI 撞名 | 本机 PATH 无；Homebrew 404；Debian 无 | [已打开] |

**结论：可用。** 开发者生态是五个名字里最干净的：无 crate、无 PyPI 包、Go 侧接近真空、两个域名都可能可注册。唯一实质性风险是 Milwaukee 的 PACKOUT 商标且其家族申请触及 Class 9——但货物类别（工具箱 vs CLI 软件）差异大，命名/口号避开"模块化收纳"即可。

---

## 3. `handoff`

| 维度 | 结果 | 等级 |
|---|---|---|
| crates.io | **同名 crate 已存在**：`handoff` 1.0.2，SPSC 异步通道，3,897 次下载，最后更新 2023 | [已打开] index |
| npm | **已被占用**：`handoff@1.3.2` PubSub 库，1,965 次/月 | [已打开] |
| PyPI | **已被占用**：`handoff 0.4.6`，对应产品 handoff.cloud（"serverless pipeline jobs"） | [已打开] |
| pkg.go.dev | 大量子包同名；另有 `pion/handoff` 等完整模块 | [已打开] |
| Go module proxy | `github.com/handoff/handoff` → 404（路径本身干净） | [已打开] |
| GitHub 同名词 | **5,917 个仓库**，密度最高：`hallee9000/heron-handoff` 352★（Figma 交付）、`lee-to/aif-handoff` 314★、`pion/handoff` 188★、`joshuadavidthomas/opencode-handoff` 185★、`willseltzer/claude-handoff` **146★**、`cablate/ctx-handoff-mod` 126★（Claude Code 上下文交接） | [已打开] |
| AI 领域直接竞品 | `Xsxdot/handoff` 25★（"把实现计划派发给另一个 AI 执行"的纯 CLI）、`DavidDingXu/agent-handoff` 4★（Codex↔Claude Code 会话迁移）、`alphaelements/handoff-mcp`（AI agent 跨会话记忆 MCP，crates.io 上 937 次下载）、npm `pi-handoff`、`handoff-mcp` crate | [已打开] |
| `github.com/handoff` | 存在，User（Henrik Andoff Sjölund），1 仓库 | [已打开] |
| `handoff.dev` | **已注册**（Tucows/Hover，2025-04-15），停放页，无标题 | [已打开] |
| `handoff.sh` | **已注册**（Cloudflare NS，apex 无 A，530/1016） | [已打开] |
| 商标 | Apple 2014 年申请过 HANDOFF（USPTO 86234567，Class 9/42，对应 Continuity 功能），但**已 abandonment（未获注册）** | [搜索摘要] |
| CLI 撞名 | 本机 PATH 无；Homebrew 404；Debian 无 | [已打开] |

**结论：不可用（就本产品而言）。** 最准确、最顺口，但语义已被"AI agent 会话交接"这一类工具占满——`claude-handoff`、`opencode-handoff`、`ctx-handoff-mod`、`agent-handoff`、`handoff-mcp` 全是近 12 个月内的同题竞品。搜索结果里你的项目会被淹掉，用户也会分不清。

---

## 4. `carry`

| 维度 | 结果 | 等级 |
|---|---|---|
| crates.io | 无同名 crate（`index.crates.io/ca/rr/carry` → **404**） | [已打开] |
| npm | **已被占用**，僵尸包：`carry@0.0.4`，2014 年，月下载 131 | [已打开] |
| PyPI | **已被占用**，僵尸包：`carry 0.3.1`（ETL），2018 年后无更新 | [已打开] |
| pkg.go.dev / proxy | 无同名模块；`github.com/carry/carry` → 404 | [已打开] |
| GitHub 同名词 | **7,080 个仓库**（含 `170-carry/codex-tools` 1,146★、`metametadata/carry` 148★ Clojure、`toaco/carry` 126★ Python ETL）；Go 语言同名仓库最高仅 2★ | [已打开] |
| `github.com/carry` | 存在，User，2 仓库 | [已打开] |
| `carry.dev` | **已注册**（Porkbun，2026-09-10），停放页 | [已打开] |
| `carry.sh` | **已注册**（GoDaddy NS，A 记录 3.33.130.190，停放 lander） | [已打开] |
| 商标 | 纯字典词，弱且拥挤：至少一个理财 App（usecarry.com）在 Class 9/36 使用，"carry trade" 是金融通用词 | [搜索摘要] |
| CLI 撞名 | 本机 PATH 无；Homebrew 404；Debian 无（仅有 `libmath-nocarry-perl`） | [已打开] |

**结论：冲突可接受，但性价比一般。** 技术上没有硬阻塞，可它是最泛的英文动词之一——"carry CLI" 的 SEO 基本无效，仓库名在 GitHub 检索里极易被淹没；两个域名也都已被停放注册。且 WebSearch 给出的若干 "carry CLI" 仓库链接实际是 404（`nikvdp/carry`、`yashisrani/carry`、`mgedmin/carry`、`dhruvkb/carry` 均不存在），说明这个方向的搜索信号非常嘈杂。

---

## 5. `transplant`

| 维度 | 结果 | 等级 |
|---|---|---|
| crates.io | **同名 crate 已存在**：`transplant 0.2.0`，大文件搜索替换，4,460 次下载，2019 年后无更新 | [已打开] index |
| npm | **已被占用**，空壳 `0.0.0`（2016） | [已打开] |
| PyPI | **已被占用**：`Transplant 0.8.11`，从 Python 调 Matlab，对应 112★ 仓库 | [已打开] |
| pkg.go.dev / proxy | 有 `github.com/codeactual/transplant/cmd/transplant`（Go）；`github.com/transplant/transplant` → 404 | [已打开] |
| GitHub 同名词 | 1,931 个仓库；头部 `bastibe/transplant` 112★，`mahkitah/Transplant` 71★，**`vitaliyhayda/claude-transplant` 54★（2026-11-09 活跃，迁移 Claude 会话历史）** | [已打开] |
| `github.com/transplant` | 存在，User，0 仓库 | [已打开] |
| `transplant.dev` | **NXDOMAIN**，RDAP **404** → 未注册 | [已打开] |
| `transplant.sh` | **NXDOMAIN**，RDAP 无委派 → 未注册 | [已打开] |
| 商标 | 通用医学/软件词，无著名软件商标主张 | [搜索摘要] |
| CLI 撞名 | 本机 PATH 无；Homebrew 404；Debian 无 | [已打开] |

**结论：冲突可接受。** 两个域名都可能可注册、无 CLI 撞名，crates/PyPI 的占用都在不活跃项目上。扣分项：10 个字母偏长，且 `codeactual/transplant` 恰好也是个 Go 的"把模块搬出去"的工具，`claude-transplant` 又直接做 Claude 会话迁移——语义上最近，撞车感也最强。

---

## 汇总矩阵

| | crates | npm | PyPI | Go 路径 | GitHub 头部 | `github.com/<n>` | .dev | .sh | 商标 | CLI | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| portage | 空 | 占（死） | 占（**活跃**，Gentoo） | 空 | 686★ gentoo | User 0 | **已注册** | **已注册** | Gentoo 生态名 | 无 | 冲突可接受 |
| **packout** | 空 | 占（空壳） | **空** | 空 | 3★ | Org 0 | **NXDOMAIN** | **NXDOMAIN** | Milwaukee Class 6/20(9) | 无 | **可用** |
| handoff | 占 | 占 | 占 | 空 | 5,917 仓，AI 竞品成群 | User 1 | **已注册** | **已注册** | Apple 已放弃 | 无 | **不可用** |
| carry | 空 | 占（死） | 占（死） | 空 | 7,080 仓，Go 侧 <2★ | User 2 | **已注册** | **已注册** | 弱/拥挤 | 无 | 冲突可接受 |
| transplant | 占 | 占（空壳） | 占（Matlab 库） | 有 2★ | 1,931 仓，54★ 直系 | User 0 | **NXDOMAIN** | **NXDOMAIN** | 通用词 | 无 | 冲突可接受 |

域名"可注册"仅依据 NXDOMAIN + RDAP 404，未在注册商结账页复核。

## 排序建议

1. **`packout` —— 推荐首选。** 唯一在 crates/PyPI 双空、Go 生态几近无人、两个目标域名都可能可注册的名字，GitHub 同名最高才 3★。Milwaukee 的商标在工具箱/工具袋类别，与 CLI 软件不同类，风险可控；更妙的是 "packout＝收工打包带走" 与产品动作（迁移前体检 + 打包）同构。
2. **`portage` —— 备选，如果更看重隐喻。** Go 路径干净、无 CLI 撞名，但看 Linux 的用户会先想到 Gentoo；PyPI 上 Gentoo 的 `portage` 是活跃包，且 `SimonGino/portage` 已经在做 Claude Code/Codex 启动器。两个域名都被注册（停放），点域名几乎没戏。
3. **`carry`** —— 无硬伤但太泛，搜索与心智都吃亏；两个域名也都被占。
4. **`transplant`** —— 域名可注册，但字长、且与 crates/PyPI 的既有库和 `claude-transplant` 语义重叠。
5. **`handoff` —— 建议放弃。** 语义最贴，但它是这一赛道所有既有工具的首选词，`claude-handoff`(146★)、`opencode-handoff`(185★)、`handoff-mcp`、`agent-handoff` 都在近一年内出现；命名上等于放弃辨识度。

## 关于 Go import path

五者都没有可用的 `github.com/<name>` 组织/用户 slug（全部已被注册，只是仓库为空），因此模块路径都会是 `github.com/<你的账号>/<名>`，在这个意义上起点相同。

但 **`packout` 在 Go 生态里最不容易撞 import path**：

- `github.com/packout/packout` 与 `.../packout/v2` 在 proxy 上均 404；
- pkg.go.dev 无同名顶层包，GitHub 上唯一的 Go 仓库是 2019 年的 1★ 项目；
- 对比之下 `portage` 已作为包名散落在 syft / osv-scalibr / sbom 等主流 Go 项目里（`cataloger/portage`），`carry` 会与短包名在同一文件里并置，`transplant` 已有 `codeactual/transplant/cmd/transplant`，`handoff` 在 pion 等模块中已被占用。

即便如此，任何名字都无法保证包名唯一——`import pk "github.com/<you>/packout"` 这类别名始终是兜底。

## 复核用链接

- crates 索引：https://index.crates.io/po/rt/portage ・ https://index.crates.io/pa/ck/packout ・ https://index.crates.io/ha/nd/handoff ・ https://index.crates.io/ca/rr/carry ・ https://index.crates.io/tr/an/transplant
- npm：https://www.npmjs.com/package/portage ・ https://www.npmjs.com/package/packout ・ https://www.npmjs.com/package/handoff ・ https://www.npmjs.com/package/carry ・ https://www.npmjs.com/package/transplant
- PyPI：https://pypi.org/project/portage/ ・ https://pypi.org/project/handoff/ ・ https://pypi.org/project/carry/ ・ https://pypi.org/project/transplant/（packout 无）
- pkg.go.dev：https://pkg.go.dev/search?q=portage ・ https://pkg.go.dev/search?q=packout
- GitHub：https://github.com/gentoo/portage ・ https://github.com/EyalAr/Portage ・ https://github.com/bastibe/transplant ・ https://github.com/willseltzer/claude-handoff ・ https://github.com/Xsxdot/handoff ・ https://github.com/vitaliyhayda/claude-transplant ・ https://github.com/codeactual/transplant ・ https://github.com/alphaelements/handoff-mcp
- RDAP：https://rdap.org/domain/portage.dev ・ https://rdap.org/domain/packout.dev ・ https://rdap.org/domain/handoff.dev ・ https://rdap.org/domain/carry.dev ・ https://rdap.org/domain/transplant.dev
- 商标：https://trademarks.justia.com/887/49/packout-88749314.html ・ https://alter.com/trademarks/packout-88749314 ・ https://en.wikipedia.org/wiki/Portage_(software)

# spike：`gopkg.in/yaml.v3` 能否支撑 profile 解析

状态：已完成。**结论：失败。** 需求 1、2 通过，需求 3（无损写回）不通过；按 `docs/spec-profile-model.md` §2.3 的闸门定义，profile 应改 JSONC。

本文件是一次性 spike 的记录。代码在 `internal/profile/spike/`（独立 Go module，不进入根 `packout` module 的依赖图）。

## 1. 环境与版本

| 项 | 值 |
|---|---|
| 被测库 | `gopkg.in/yaml.v3` **v3.0.1**（proxy 上最新，也是 v3 最后一个版本；原仓库 2022-05 后无发布） |
| Go | `go1.27.3 linux/amd64` |
| 运行环境 | 宿主机是 Windows 11，**未安装 Go**；Go 装在 WSL Ubuntu 内。测试全部在 Linux 下执行，样本含 CRLF 字节，结论与 OS 无关，但未在 Windows toolchain 上复跑 |
| 网络 | `proxy.golang.org` 可达（HTTP 200），`go mod tidy` 成功；`go.sum` 已随目录保存，模块已缓存后可离线运行；如需完全离线可 `go mod vendor` |
| 样本 | `internal/profile/spike/testdata/roundtrip.yaml`（手写，含注释、行尾注释、引号、块标量、空行、锚点/别名、合并键、`---`；仓库里还没有内置 `claude-code` profile 可复用） |

运行方式（在 WSL 内）：

```
cd internal/profile/spike
go test -v ./...          # 三个硬需求 + 两条实际需求；完整输出已存 test-out.txt
go run . testdata/roundtrip.yaml   # 打印每个节点的行列，再重新编码并比对
```

`go vet` 通过。测试结果为 FAIL 是预期状态，不是编译/环境故障。

## 2. 结果总表

| # | 需求 | 结果 |
|---|---|---|
| 1 | 解码成 `yaml.Node` 后保留未知字段 | **通过** |
| 2 | 每个节点都能拿到非零行列 | **通过** |
| 3 | Node 重新编码后与原文件逐字节相同 | **失败**：16 个用例 11 个失败，专用样本整体失败 |
| 附 1 | 重复键 | 行为可用但有坑：Node 保留两个键；struct/map 解码报错（带行号，无列号） |
| 附 2 | `KnownFields(false)` 下的类型错误定位 | 只有行号，没有列号；能指出值 |
| 附 3 | 列号的计数单位（非 ASCII 键） | 可用：按 rune 计 1-based 列；星平面字符与 Windows UTF-16 编辑器可能差 1 |

## 3. 证据

### 3.1 需求 1：通过

`yaml.Unmarshal` 到 `yaml.Node` 后，未知键 `future_field` 及其子树都在树里。对照实验确认 struct 直解会丢掉它（即使 `KnownFields(false)`）。

### 3.2 需求 2：通过

遍历样本的 28 个非文档节点，全部 `Line > 0 && Column > 0`；精确校验通过：

```
main_test.go:76: checked 28 nodes; all have line/column, spot check 3:1 / 3:7 ok
```

`name` 键在 3:1，其值在 3:7。列号是 1-based 的 **rune** 列（`你好: 1` 的值在第 5 列，按字节会是第 9 列），可直接用于 `文件:行:列` 诊断；注意 emoji 等星平面字符按 1 个 rune 计，而 Windows 编辑器/UTF-16 通常计 2，跨工具对齐列号时需换算。

### 3.3 需求 3：失败

用例结果（断言是逐字节相等，编码器已 `SetIndent(2)` 给出最有利条件）：

| 用例 | 结果 |
|---|---|
| 完整样本 | **失败** |
| 行尾注释前的空格宽度 | **失败** |
| `---` 文档起始符 | **失败** |
| 折叠块标量 `>-` | **失败** |
| 字面块标量带 chomping `|-` | 通过 |
| 键之间空行 | **失败** |
| 键之间普通注释 | 通过 |
| 合并键 `<<` | **失败** |
| 带引号的键 | 通过 |
| 多行 flow 序列 | **失败** |
| 序列项行尾注释 | 通过 |
| `你好` 转义 | **失败** |
| `\t` 转义 | 通过 |
| 空行隔开的独立注释 | **失败** |
| 文件末尾无换行 | **失败** |
| CRLF 换行 | **失败** |

完整样本的实际失败输出（`test-out.txt` 原文摘录）：

```
main_test.go:126: not byte-identical (orig 332 bytes, got 331):
        !  2 | orig "---"
        !    | got  "name: \"quoted name\" # trailing comment"
        !  3 | orig "name: \"quoted name\"   # trailing comment"
        !    | got  "version: 1.2.3"
...
        !  8 | orig "notes: >-"
        !    | got  "  folded line one folded line two"
        !  9 | orig "  folded line one"
...
        ! 12 | orig ""
        !    | got  "deps:"
...
        ! 17 | orig "    <<: *base"
        !    | got  "    !!merge <<: *base"
```

逐项最小复现（原文）：

```
trailing_comment_spacing: orig "a: 1   # keep my columns"  → got "a: 1 # keep my columns"
document_start_marker:    orig "---\na: 1\n"               → got "a: 1\n"
folded_block_scalar:      orig "  folded one\n  folded two" → got "  folded one folded two"
blank_line_between_keys:  orig "a: 1\n\nb: 2\n"            → got "a: 1\nb: 2\n"
merge_key:                orig "  <<: *b"                  → got "  !!merge <<: *b"
unicode_escape:           orig "a: \"\\u4f60\\u597d\""     → got "a: \"你好\""
no_trailing_newline:      orig "a: 1"（4 字节）             → got "a: 1\n"（5 字节）
crlf_line_endings:        orig "a: 1\r\nb: 2\r\n"          → got "a: 1\nb: 2\n"
comment_detached_by_blank_line: 独立注释上移到空行之前，空行丢失
```

即使把样本裁到 spec §2.2 允许的子集（无锚点、无合并键、无 `---`、flow 只一行），失败仍然成立：空行、CRLF、注释列宽、折叠标量、文件末尾无换行、转义写法都属于允许子集。

### 3.4 重复键（附加）

```
decode into map: yaml: unmarshal errors:
      line 2: mapping key "name" already defined at line 1
decode into struct, KnownFields(false): 同上
```

Node 树里两个 `name` 都在（计数 2，不报错）；一旦解码到 map/struct 就报错。错误带当前行和首次定义行，**无列号**。所以校验器要么自己在 Node 上查重，要么接受这套错误文本。

### 3.5 类型错误定位（附加）

`port: "abc"` 解到 `int`：

```
KnownFields=false: "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!str `abc` into int"
KnownFields=true:  追加 "line 3: field future not found in type main.cfg"
```

能定位到行和值，**没有列号**。由于 spec 要求校验器自己遍历 Node 产出 `文件:行:列`，这不算致命；但如果走 struct 直解就凑不齐列。

## 4. 为什么不是“调一下编码器”能修好

`yaml.Node` 和 `yaml.Encoder` 的信息量本身不足：

- `Node` 只有 `Line`、`Column`，**没有结束位置/长度**（源码注释明确 “These fields are not respected when encoding the node”）；`Value` 是已反转义、已去引号的值，原始转义和原始缩进都丢了。
- 注释只有 `HeadComment`/`LineComment`/`FootComment` 三个槽，**没有空行模型**；空行被折叠进注释归属。
- 编码器除了 `SetIndent` 没有任何开关：无 CRLF、无注释列宽、无“保留 `---`”。第一个文档永远不输出 `---`。
- flow 集合会被重排成单行；折叠标量会被重新折行；`<<` 会被物化为 `!!merge` 显式标签。

也就是说，“整份 Node 重新编码”天然是格式化重写，不是原样回写。

## 5. 结论

按 `spec-profile-model.md` §2.3：第 1 条（行列诊断）通过；第 2 条（未改区域字节/注释/空行/缩进/CRLF 完全不变）在“重新编码整份 Node”的方案下**不满足**；第 3 条只考核未知节点的顺序与内容，这两点重编码能保住，但周边格式会变，按第 2 条的硬口径同样不过。闸门失败。

两条出路：

**A. 改 JSONC（建议，符合 spec 既有约定）。** 用保留 trivia 的 JSONC AST（如 `github.com/tailscale/hujson`）解析，未触碰字节原样保留，CRLF/空行/注释/引号天然无损；未知字段和行列同样拿得到。

**B. 留在 YAML，但放弃整份重编码，改“外科手术式”回写。** 只改已识别字段的原始字节区间，其余字节不动。可行，但需要自建源文本扫描器把 `Line/Column` 扩展成区间，还要处理块标量、多行引号标量、flow、注释边界、CRLF；`Value` 的反转义意味着新值要自带序列化器。bug 面比 A 大，且是自研 YAML 词法，和“退回 JSONC 自建解析器”的维护成本接近，却保留了 YAML 的可读性优点。

若团队坚持 YAML，只能选 B；整份 `yaml.Node` 重编码不可作为写回实现。

## 6. 若退回 JSONC：工作量估计

推荐用 `tailscale/hujson`（JSONC AST，保留空白与注释，支持按路径编辑；Tailscale 自身配置读写长期使用）：

| 工作 | 估计 |
|---|---|
| 引入依赖、封装解析/编辑/写出，验证 hujson 在 CRLF、BOM、空行、注释上的字节保真 | 0.5–1 人日 |
| 在 AST 上实现 schema 遍历：未知字段保留、类型/枚举/引用校验、`文件:行:列` 诊断（hujson 提供 offset → 行列） | 1.5–2 人日 |
| 回写引擎：已识别字段值替换、增删未知条目，逐字节回归测试（含 CRLF / 末尾无换行 / 注释紧邻） | 1–2 人日 |
| selftest 多行 fixture 的表达方案（JSON 字符串需转义，是 YAML 的主要优势）：数组逐行或 `$file` 引用，需设计评审 | 1 人日 |
| v1 profile 迁移、`schema_version` MAJOR 升级、只读 YAML 适配器（用本 spike 的 Node 读取路径即可） | 1–1.5 人日 |
| **合计** | **约 4–6 人日**（含测试），风险中低 |

若不引第三方、纯手写 JSONC 词法+语法+trivia 保留：词法 1.5–2 人日、语法与 AST 2–3 人日、编辑与回写 2–3 人日、测试 2 人日，**约 7–10 人日**，另加长期维护。

不变的部分：校验规则、诊断文案、未知字段策略、条目模型都可原样迁移；只换载体和写回层。

## 7. 本 spike 未覆盖

- 未跑真实 `claude-code` profile（仓库内尚不存在），样本为手写。
- 未测 `go.yaml.in/yaml/v3`、`sigs.k8s.io/yaml` 等分支/包装；只测任务指定的 `gopkg.in/yaml.v3` v3.0.1。
- 未实现外科手术式回写原型，B 方案的成本是估算而非实测。
- 未在 Windows 原生 Go 下复跑（宿主机无 Go）。

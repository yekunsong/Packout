# spike：`github.com/tailscale/hujson` 能否支撑 profile 解析

状态：已完成。**三条硬需求的实测结论：需求 1、2、3 全部通过**（需求 3 仅在“`Parse` 后不做任何变换、直接 `Value.Pack()`”这条路径上通过），但发现两个必须在设计中吸收的缺陷/坑：

1. `Value.Clone()` 会丢掉**所有**尾逗号（空 `AfterExtra` 被 `copyBytes` 变成 nil）。凡是需要保留尾逗号的写回，不能走 Clone。
2. 包级 `hujson.Standardize(b)` 会**就地改写调用方的 `b`**（`Parse` 别名引用输入，注释字节被原地替换为空格）。需要原始字节时必须先复制。

另外 `hujson` 不是 JSON5：单引号、无引号键、裸词、UTF-8 BOM 一律拒绝（带行列报错）；注释和尾逗号接受。重复键不报错，AST 全保留。

本文件是一次性 spike 的记录。代码在 `internal/profile/spike-jsonc/`（独立 Go module，不进根 module 依赖图）。测试结构照搬 yaml 版（`internal/profile/spike/`，已 FAIL），16 个用例一一对应改写为 JSONC 语境。

## 1. 环境与版本

| 项 | 值 |
|---|---|
| 被测库 | `github.com/tailscale/hujson`，**无任何 semver tag**；`@latest` 解析为伪版本 `v0.0.0-20260727124030-b80ff77dac4f`（commit `b80ff77dac4f3b606c8bf0a28a84b33e68d07f60`，2026-07-27T12:40:30Z） |
| 库自身 go.mod | `go 1.26`；仅测试依赖 `github.com/google/go-cmp v0.7.0` |
| Go | `go1.27.3 linux/amd64`（WSL Ubuntu；宿主机无 Go，与 yaml spike 相同） |
| 网络 | `proxy.golang.org` 可达；`go.sum` 已保存。`@v/list` 返回空，确认没有可用的版本 tag |
| 样本 | `internal/profile/spike-jsonc/testdata/roundtrip.jsonc`（454 字节，含行/块注释、空行、对齐空白、未知字段及其子树、尾逗号语义的数组） |

运行方式（WSL 内）：

```
cd internal/profile/spike-jsonc
go test -v -count=1 ./...   # 完整输出在 test-out.txt；套件因 TestCloneTrailingComma 故意失败而整体 FAIL
go run . testdata/roundtrip.jsonc   # 打印偏移/行列，验证 Parse+Pack，演示 Standardize
```

`go vet` 通过，`gofmt` 干净。整体 FAIL **只**来自 `TestCloneTrailingComma`，它是为记录缺陷而故意保留的断言失败。

## 2. 结果总表

| # | 需求 | 结果 |
|---|---|---|
| 1 | 解析后保留未知字段 | **通过**：未知键与整棵未知子树都在 AST 里，`Pack()` 字节不变 |
| 2 | 每个键值可给出位置 | **通过**：`Value.StartOffset/EndOffset` 为精确字节区间，键名同样有；需自行换算行列 |
| 3 | 无损往返 | **通过（仅 Parse→Pack）**：16/16 用例逐字节相同；`Standardize`/`Format` 路径均不保真 |
| 附 1 | 重复键 | 不报错，AST 保留两个成员并保序；`Find` 返回第一个，`encoding/json` 进 map 后者覆盖前者 |
| 附 2 | 非标准 JSON | 单引号/无引号键/裸词/BOM 拒绝（错误含行列）；注释、尾逗号接受 |
| 附 3 | 列号单位 | **字节列**（1-based），非 rune/UTF-16；CJK 1 字计 3 列 |
| 附 4 | Clone 保真 | **失败**：`Clone()` 丢掉尾逗号（见 §3.6） |
| 附 5 | `Standardize` 是否改写入参 | **会就地改写调用方字节切片**（见 §3.7） |

## 3. 证据

### 3.1 需求 1：通过

`Parse` 产物是 schema 无关的 AST。`future_field` 及其 `nested` / `unknown_array` 子树原样存在，`future_field.Pack()` 为：

```
"future_field": {
    "nested": true,
    "unknown_array": [1, 2, 3]
  }
```

对照实验（`encoding/json` 解到只含 `name`/`version` 的 struct）：未知字段被静默丢弃，与 yaml spike 一致。hujson 的价值就在于校验器可以只遍历 AST，不必先转 struct。

### 3.2 需求 2：通过（附 API 说明）

类型与 API（实际签名）：

```go
func Parse(b []byte) (Value, error)                  // 注意返回 Value，不是 *Value
type Value struct {
    BeforeExtra Extra
    StartOffset int                                  // 值的首字节偏移（0-based）
    Value       ValueTrimmed                         // Literal | *Object | *Array
    EndOffset   int                                  // 值之后的下一个字节
    AfterExtra  Extra
}
type Object struct{ Members []ObjectMember; AfterExtra Extra }
type ObjectMember struct{ Name, Value Value }        // 键名本身也是 Value
func (v *Value) All() iter.Seq[*Value]               // 深度优先，含成员名和值
```

实测遍历 `{"name":"svc",...}` 的 5 个 Value（含根、2 个键名、2 个值）全部有合法偏移；`name` 键在 `2:3`、值在 `2:11`。`All()`/`Range()` **会**产出对象成员名（`allValues` 把 Name 和 Value 交错产出），键名无需自己挖 `Members`；但 `All()` 的文档只写 “all values”，容易误判，实测结果为准。

行列不在 API 里，要自己换算（约 5 行）：

```go
line = 1 + bytes.Count(src[:off], []byte("\n"))
col  = 1 + off - (bytes.LastIndexByte(src[:off], '\n') + 1)
```

这与 hujson 内部 `lineColumn` 一致。**Parse 错误已经自带 `line %d, column %d`**，所以错误定位不需要自己做；只有校验器主动产出的诊断需要基于偏移换算。

列是**字节列**：`{"你好": 1}` 中值的字节列是 12，rune 列是 8。直接拼给编辑器要注意 UTF-16/星平面字符的差异（yaml 版是 rune 列，这里不同）。

### 3.3 需求 3：通过（16/16），但路径唯一

断言是 `Parse` 后立即 `Pack` 与原文逐字节相等：

| 用例 | 结果 |
|---|---|
| 完整样本 | 通过（454 字节） |
| 行尾注释前的空格宽度 | 通过 |
| 成员间块注释 `/* */` | 通过 |
| 键之间空行 | 通过 |
| 键之间行注释 | 通过 |
| 空行隔开的独立注释 | 通过 |
| 键顺序（z/a/m） | 通过 |
| Tab 缩进 | 通过 |
| 4 空格缩进 + 对齐空白 | 通过 |
| CRLF | 通过 |
| 文件末尾无换行 | 通过 |
| `\uXXXX` 与代理对 `\ud83d\ude00` | 通过 |
| 重复键 | 通过 |
| 对象与数组尾逗号 | 通过 |
| 数组项注释 | 通过 |
| 文件末尾注释 | 通过 |

与 yaml 版的一一对应：YAML 专有语法（`---`、折叠/字面块标量、合并键、带引号键、多行 flow）在 JSONC 版中替换为 JSONC 能表达的等价维度（块注释、Tab 缩进、4 空格对齐、键顺序、数组项注释、文件末尾注释），用例总数保持 16；其余语义（行尾注释、空行、独立注释、转义、重复键、无末尾换行、CRLF、完整样本）一一对应。

关键实现事实：`Pack()` 只是把 `BeforeExtra + 值 + AfterExtra` 原样拼接，偏移字段在打包时被忽略（`pack.go`）。所以未变换时逐字节保真；任何变换都会改变 AST。

### 3.4 往返路径结论（核心）

同一份 `src = "{\r\n  // note\r\n  \"a\": [1, 2,],\r\n}\r\n"`：

| 路径 | 输出 | 与原文相同 |
|---|---|---|
| `Parse` → `Pack` | 原文 | **是** |
| `hujson.Format(src)` | `"{\n\t// note\n\t\"a\": [1, 2],\n}\n"` | 否（缩进/换行/吞尾逗号） |
| `hujson.Standardize(src)` | `"{\r\n         \r\n  \"a\": [1, 2 ] \r\n}\r\n"` | 否（注释变空格、尾逗号变空格） |
| `Parse` → `Clone` → `Standardize` → `Pack` | `"{\r\n         \r\n  \"a\": [1, 2]\r\n}\r\n"` | 否 |

结论：

- **写回路径只有 `Parse` → 就地编辑 AST → `Pack()`。** 不能先 `Standardize`/`Format`。
- `Standardize` 的用途是“喂给 `encoding/json`”：它把注释和尾逗号替换为空格，**保留行号和字节偏移**（库文档明说），所以标准化副本上的诊断位置仍对应原文。
- 读取值不必经 `encoding/json`：`Literal` 有 `String()/Int()/Uint()/Bool()/Float()`，可直接从 AST 取值。这样既不用 Standardize，也不用保留第二套字节。只有在必须用 stdlib 解码时才需要“原始字节 + 标准化副本”两套，且标准化副本必须由**拷贝**生成（见 §3.7）。

### 3.5 就地编辑可保持 trivia

不 Clone，直接改一个 `Literal` 后 `Pack`，只有该值变化；CRLF、注释、尾逗号全部原位保留。长度变化后 `UpdateOffsets()` 可把偏移修回与重新 Parse 一致。这是写回引擎可行的直接证据。

### 3.6 缺陷：`Clone()` 丢失所有尾逗号（测试失败）

尾逗号编码为“最后一个成员/元素的 `AfterExtra != nil`”，空尾逗号是零长非 nil 切片；`Clone` 内部的 `copyBytes` 是 `append([]byte(nil), b...)`，零长非 nil 会变成 nil。结果：

```
src="[1, 2,]"        clone.Pack="[1, 2]"
src="{\"a\": 1,}"    clone.Pack="{\"a\": 1}"
src="{\"a\": [1,],}" clone.Pack="{\"a\": [1]}"
```

连“逗号后有空格/注释”的情况也会丢逗号（空格被搬到容器 `AfterExtra`，标记本身仍是空切片）。`TestCloneTrailingComma` 因此失败；`Parse→Pack`（不 Clone）和就地编辑都不受影响。规避：写回时就地改原始 AST，别用 Clone；只有要“另存一份做只读变换”时才 Clone，并接受该副本丢尾逗号（`Standardize` 本来也会抹掉它们）。

### 3.7 坑：`Standardize` 就地改写调用方切片

`hujson.Standardize(b)` 内部 `Parse(b)`（别名引用 `b`）→ `ast.Standardize()`，后者对 `Extra` 逐字节执行 `(*b)[i] = ' '`。实测：

```
input slice MUTATED in place:
"{\n  // comment\n  \"a\": 1,\n}\n" ->
"{\n            \n  \"a\": 1,\n}\n"
```

因此 `src` 若既用于保留原文又传给 `Standardize`，必须先 `bytes.Clone(src)`（或对 `ast.Clone()` 做，然后接受尾逗号丢失）。库文档没有提示这一点。

### 3.8 重复键

`{"name":"first","name":"second"}`：`Parse` 无错，`Object.Members` 保留 2 项且顺序不变，`Pack` 逐字节还原；`Find("/name")` 返回第一个；`Standardize` 后 `json.Unmarshal` 进 map 得 `"second"`（后者覆盖）。hujson 不提供重复检测，校验器需自己在 `Members` 上查重（可拿到两个键名各自的偏移）。

### 3.9 非标准 JSON 的边界

拒绝（错误含 `line N, column N`）：

```
{'a': 1}       line 1, column 2: invalid character '\'' at start of value
{"a": 'b'}     line 1, column 7: invalid character '\'' at start of value
{a: 1}         line 1, column 2: invalid literal: a
{"a": yes}     line 1, column 7: invalid literal: yes
<UTF-8 BOM>{}  line 1, column 1: invalid character '\ufeff' at start of value
```

接受并逐字节还原：`{"a": 1,}`、`[1, 2,]`、行注释、块注释。BOM 需调用方先剥掉（Windows 工具容易产出 BOM，profile 加载层应显式处理）。

## 4. API 是否足够

三条需求都能满足，但有下列成本/风险，属于“够用但要包一层”：

- 位置：只有字节偏移，行列要自己算；键名不是 `All()` 文档语义，靠实测确认会被遍历到。诊断文案所需的 `文件:行:列` 需要自家 helper。
- 保真与取值是两条互斥路径：`Pack` 保真但只给字节；`Literal` 取值函数不破坏字节。若走 `encoding/json` 就必须复制后 `Standardize`，原 AST 不能再被当作写回源（除非只改克隆并接受尾逗号丢失）。
- `Parse` 别名引用输入缓冲；`Extra`/`Literal` 都指向调用方字节。调用方不能复用/改写 `src`，否则 AST 会跟着变。
- 无 semver 发布，只能锁伪版本；上游 `go.mod` 要求 Go 1.26。
- 无 BOM、无 JSON5、无重复键检查；这些都应在 profile 加载/校验层自行处理。
- `Patch`（RFC 6902）与 `UpdateOffsets` 可用，适合“改值/增删未知键”的写回实现。

## 5. 结论

hujson 在“`Parse` → 就地编辑 → `Pack`”这一条路径上同时满足未知字段保留、精确位置和逐字节无损写回，16 个覆盖注释/空行/顺序/缩进/CRLF/无末尾换行/转义/重复键/尾逗号的用例全过。yaml.v3 的失败点（trivia、CRLF、末尾换行、转义写法）在这里都不存在。

设计约束必须写进实现：

1. 写回只走 AST 原地编辑 + `Pack`；**不要** `Format`/`Standardize` 后再写回，**不要**用 `Clone` 做保真副本（尾逗号会丢）。
2. 值从 `Literal` 的访问器读；确需 stdlib 解码时，对**拷贝**调用 `Standardize`，并知道该副本已被抹掉注释/尾逗号。
3. 位置用 `StartOffset/EndOffset` + 自行换算；列是字节列，展示给 UTF-16 编辑器时按需换算。
4. 重复键、BOM、单引号/无引号键由加载层自行检查并给出明确诊断。

`TestCloneTrailingComma` 的失败是已知缺陷而非需求不通过；其余需求测试全绿。

## 6. 本 spike 未覆盖

- 未跑真实 `claude-code` profile（仓库内尚不存在），样本手写。
- 未实现读写引擎/校验器原型；写回只验证到“改单个 Literal”。
- 未测上游修复分支（无 tag，无法判断 Clone 缺陷是否已报/已修）。
- 未在 Windows 原生 Go toolchain 复跑（宿主机无 Go）；结论与 OS 无关，但 CRLF 用例在 Linux 下执行。

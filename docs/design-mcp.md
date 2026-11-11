# MCP 面设计（P1 末）

MCP 只暴露**读**与**计划**，不暴露执行。理由见 `threat-model.md` 第 8 节：模型能读到的东西最多只能影响"看什么"，不能影响"写哪里"。

## 启动

`packout mcp --out DIR [--root role=PATH]...`

根与输出目录在**启动参数**里定死，运行期不接受任意路径（INV-I03）。没给根就用 profile 默认值。

## 工具（全部只读）

| 工具 | 返回 | 说明 |
|---|---|---|
| `roots` | 已解析的根与 profile 名 | 让模型知道能看哪里 |
| `summary` | 最近一次扫描按层/按 profile 的计数与体积 | 不返回明细，避免灌爆上下文 |
| `find` | 按 layer/entry/路径片段过滤，最多 N 条 | 分页靠 offset |
| `explain` | 单个 Unit 的全部 signals 与出处 | |
| `verify` | 包的结论词 | 只读 |
| `restore_plan` | dry-run 的恢复计划 | 不写 |

## 不暴露

- `restore` 的实际写入（模型可以建议，人执行）。
- 任意 `--out`。
- 报告服务（另起进程，MCP 只给路径）。

## 传输与鉴权

stdio。工具结果限长：单次 ≤ 8 KiB，超出给路径。错误用结构化 object，不抛字符串。

## 必须遵守

- 每次工具调用都重新 stat 目标，不复用上一次的缓存（INV-I06）。
- 返回里的路径全部用 manifest 的 `path_key` 与原拼写两列，模型引用哪一列都行。
- 不返回任何明文凭据，只返回掩码与 ref。

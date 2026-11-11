# manifest 规格 v2.0

状态：草案。适用于 `packout` P0。相关决策：D-002（只读）、D-011、D-013–D-016（模型 v2）。

v2 落实 `D-013` 的 M1–M9 与 `D-015` 的语料裁决：Unit 可以属于文件的某个 `part`、新增 `catch-all` 残留结论、记录路径派生、伴生文件与只读副作用、定义聚合 Unit 的固定形态，并把唯一键放宽到 `file_id`。读取 v1 manifest 按 §7 迁移。

manifest 是扫描的唯一结论产物：一行一个 Unit，每条结论都带证据，不含任何明文密钥。它被报告、导出、verify 与后续 diff 共同消费，因此格式的稳定性优先于可读性。

本规格只定义格式与写入纪律，不定义扫描实现。

---

## 1. 序列化格式

- **JSONL**：UTF-8，一行一个完整 JSON 对象，记录间用 `\n` 分隔，行内不折行。
- 一行最大 64 KiB。超过时写入方必须返回 `ErrLineTooLong`，由调用方处置；不得静默截断或折行（`D-027` 第 1 条）。`E-MAN-002` 对已落盘的超长行判错。
- **字段顺序固定**，按本规格字段表顺序输出，便于逐行 diff；对象内无额外空白。
- 数字：大小为整数（字节），confidence 为 3 位小数，时间为 RFC 3339 带纳秒与 `Z`。
- 字符串：UTF-8，`\` 在 JSON 内转义为 `\\`；不做 HTML 转义。
- 未知字段读取方必须保留；写回时保持原顺序（P0 无写回，但 export 原样拷贝）。
- 文件扩展名 `.jsonl`，媒体类型 `application/x-ndjson`。

行内 `type` 判别记录种类，不存在无 `type` 的行。

---

## 2. 文件、分片与索引

一次扫描产物是一个目录：

```
<out>/manifest/
  manifest.0001.jsonl
  manifest.0002.jsonl
  manifest.index.json
```

- 整个 manifest 的首个分片（`segment_seq` 为 0 的 `first_shard`）第一行必须是 `header`；整个 manifest 的最后一行必须是 `footer`。续扫段不重复 header/footer。
- 分片按 `manifest.%04d.jsonl` 递增命名，四位起，超过 9999 时扩位。
- **轮转阈值（暂定）**：单分片满 50,000 条 Unit 或 64 MiB（先到者）即封片。阈值可由 `--shard-units/--shard-bytes` 调整，但必须写进 header。50,000 / 64 MiB 为暂定值，按真实 20 万文件 home 实测后定（`D-011` 第 9 条）。
- `scan_id` 与分片序号**现在就按可拼接设计**：一次逻辑扫描只有一个 `scan_id`，续扫段从父段继承同一 `scan_id`，分片序号接着父段连续递增；`manifest.index.json` 用 `segments` 记录每段的 `segment_seq`、`first_shard` 与 `shards`。按 `segment_seq` 顺序直接按字节拼接分片即得完整 manifest，P0 不跨段合并（`D-011` 第 12 条）。
- `manifest.index.json` 在 footer 落盘后写入，是实现固定的**单行紧凑 JSON**，字段顺序固定为 `manifest_version,scan_id,shards,segments,units,residual,complete`（`D-027` 第 4 条）：

```json
{"manifest_version":"2.0","scan_id":"01JQ…","shards":[{"name":"manifest.0001.jsonl","sha256":"…","units":18432,"bytes":4194304}],"segments":[{"segment_seq":0,"first_shard":1,"shards":1}],"units":18432,"residual":42,"complete":true}
```

  `shards[]` 每项含 `name`、`sha256`、`units`、`bytes`；`segments[]` 每段含 `segment_seq`、`first_shard`、`shards`；`complete` 为布尔，且与 footer 一致。
- 每个分片以 `.tmp` 写入，`fsync` 后原子 rename。缺 index 或 footer 的 manifest 一律判为不完整（`E-MAN-030`）。`footer.complete: false` 本身是完整性结论，不判 `E-MAN-030`；该码只管缺 footer、缺 index 或分片计数与 index 不符（`D-027` 第 12 条）。
- 分片顺序即扫描顺序；排序键为 `(root_index, profile, entry_id, path_key, part_id)`，`part_id` 缺省为空串，同一键内按字节序；`root_index` 相同时按 root 实例名的字节序 tie-break（`D-027` 第 5 条）。同一文件的 part 因而相邻。重跑同参数必须得到相同记录顺序（时间字段除外）。
- manifest 目录与其余产物的关系见产品定义；`manifest/` 自身不得包含别的东西。

---

## 3. 记录类型

| type | 位置 | 说明 |
|---|---|---|
| `header` | 仅分片 1 第 1 行 | 扫描元数据 |
| `unit` | 任意 | 一条结论，见 §4；含 `catch-all` 残留与 `part` 结论 |
| `note` | 任意 | 非结论性说明：跳过原因、profile 探测失败、预算触发、伴生缺失 |
| `footer` | 仅末分片末行 | 计数与完整性 |

### 3.1 header

```json
{"type":"header","manifest_version":"2.0","scan_id":"01JQ8Z3K7M2V9T4R6W8X0Y2B4C","scan_segment":{"parent":null,"segment_seq":0,"first_shard":1},"started_at":"2026-11-10T09:12:03.4123456Z","tool":"packout/0.1.0","host":{"os":"windows","os_version":"10.0.26100","arch":"amd64","case_sensitivity":"insensitive","path_fold_version":"x/text@v0.19.0 (unicode 15.0.0)","volume_ids":[{"root":"C:\\","serial":"3A4F-9C21"}]},"inputs":{"secret_salt_mode":"random","secret_salt":"9b2e41c7d0f3a6851f4a6c8e2b0d9753","profiles":[{"name":"claude-code","version":"2.0","sha256":"…"}],"options":{"follow_symlinks":false}},"shard_units":50000,"shard_bytes":67108864,"roots":[{"name":"home","role":"home","instance":1,"origin":"profile","path":"C:\\Users\\a","profile":"claude-code"}]}
```

header 必填：`manifest_version`、`scan_id`（ULID）、`scan_segment`、`started_at`、`tool`、`host.os`、`host.arch`、`host.case_sensitivity`、`host.path_fold_version`、`inputs.secret_salt_mode`、`inputs.secret_salt`、`inputs.profiles[]`、`roots[]`、`shard_units`、`shard_bytes`。
`host` 不含用户名以外的身份信息；`path_fold_version` 属于 `host`；`scan_id` 同一次逻辑扫描唯一，续扫段共享父段值。

`roots[]` 每个元素必填 `name`、`role`、`instance`、`origin`、`path`、`profile`：`name` 是实例名（`repo`、`repo#2`、`external`），`role` 是 profile 里的 root role，`instance` 从 1 起递增，`origin` 取 `profile` / `cli`（`--root` 覆盖）/ `absolute`（条目绝对路径产生的 `external` 实例）。同一 role 的多个实例 `instance` 连续递增且有稳定顺序（按 `--root` 给出顺序，再按条目出现顺序）。Unit 的 `root` 必须命中这里的 `name`（`E-MAN-060`）。
`scan_segment` 为 `{parent, segment_seq, first_shard}`：全新扫描为 `{null, 0, 1}`；续扫段的 `parent` 是父段 `scan_id`，`segment_seq` 递增，`first_shard` 必须等于父段已封分片数 + 1（`E-MAN-042`）。
`path_fold_version` 固定写 `x/text` 模块版本与 Unicode 版本（见 §6.3），用于判断 `path_key` 是否可直接比较。
`inputs.secret_salt_mode` 取 `random` / `stable`，见 §9 第 3 条。
`inputs.options` 记录影响语料的扫描选项：`follow_symlinks` 恒写；`with_sessions` 为可选布尔，仅在 `scan --with-sessions` 时以 `true` 出现。为 `true` 时，profile 中 `sessions: true` 的条目已逐文件出行，`export` 必须把它们的 `extractor` 当 `raw-ref` 处理并保留原字节；缺省按 `false`。
`inputs.options.selection` 为可选对象，记录非默认的“带什么”选择；字段 `preset`（`minimal`/`standard`/`full`，`standard` 缺省）、`include`、`exclude`（元素为 entry id、类别或 `L0`…`L5`，include 先加、exclude 最后减）、`sessions_since`（`7d`/`30d`/`all`）、`sessions_project`、`sessions_max_per_project`。仅非默认项写出；`standard` 且无 include/exclude/会话过滤时整个 `selection` 省略，既有 golden 头不变。消费方（`export`、`report`）只读 header 执行，不重新选择；header 的选择元素在当前 profile 中无匹配时给警告、不失败。

### 3.2 note

```json
{"type":"note","scan_id":"01JQ…","code":"probe_unavailable","profile":"claude-code","entry":"oauth-credential-store","detail":"wincred 探测返回 ERROR_NOT_FOUND"}
```

`note` 不是结论，不参与统计。`code` 取固定枚举：`probe_unavailable`、`permission_denied`、`budget_exceeded`、`profile_skipped`、`path_too_long`、`read_error`、`aggregated`、`part_overlap`、`part_missing`、`part_uncovered`、`binary_presence_only`、`content_not_read`、`companion_missing`、`target_duplicate`、`side_effect_unexpected`、`priority_tie`、`residual_deduplicated`、`depth_truncated`、`root_unresolved`、`empty_glob`、`ads_stream`、`selection_skipped`。`selection_skipped` 的 `detail` 给原因，可选 `category` 字段记录条目类别；每条未选中的 entry 恰一条，被会话 `since`/`project`/`max` 过滤的每个路径也各一条。

`note` 可带 `part_id`、`companions` 与 `side_effects` 等上下文字段，用于把说明挂到具体结论上；字段语义同 §4.1。另有两个固定语义：空 glob（C11）必须留 `empty_glob` note；NTFS ADS 在 P0 只留 `ads_stream` note，不独立成 Unit（`D-015` 第 6、9 条）。

### 3.3 footer

```json
{"type":"footer","manifest_version":"2.0","scan_id":"01JQ…","ended_at":"2026-11-10T09:14:51.009Z","units":18432,"shards":2,"stats":{"l0":9011,"l1":220,"l2":3110,"l3":5903,"l4":180,"l5":8,"residual":42},"complete":true}
```

`complete` 只在无未处理错误时为 true。已按 Unit 记录的可处理 `read_error` 不算未处理：`complete: true`、进程退出码 0（`D-015` 第 5 条）；未处理错误才写 `complete: false` 并附 `errors` 计数。`complete: false` 是内容结论，不是格式错误，不触发 `E-MAN-030`（`D-027` 第 12 条）。

`stats.residual` 是 `catch-all` 产出的 Unit 数（`D-013` 的 M2"未命中残留计数"）。它必须等于 `kind: catch-all` 的 Unit 行数（`E-MAN-059`）；没有 catch-all 时为 0。`residual` 同时写进 index。即使 `complete: true`，`residual > 0` 也必须在报告中单独提示：它表示"这些路径没有被任何 entry 声明"。

`stats.side_effects` 为副作用计数对象，键取 §4.1 的 `side_effects` 枚举，未发生则省略。

---

## 4. Unit

### 4.1 完整字段表

| 字段 | 必填 | 类型 | 约束 |
|---|---|---|---|
| `type` | 是 | `"unit"` | 固定 |
| `schema_version` | 是 | string | 与本行所属 header 的 `manifest_version` 相同 |
| `id` | 是 | string | `^u_[0-9A-HJKMNP-TV-Z]{26}$`，路径与 part 派生，见 §4.2 |
| `cid` | 视 kind | string \| null | 内容寻址第二键，`^c_[0-9A-HJKMNP-TV-Z]{26}$`，不可得为 `null`；见 §4.2.1 |
| `path` | 是 | string | 规范化绝对路径，或 named-location URI，见 §6 |
| `path_key` | 是 | string | 折叠后的比较键，见 §6.3 |
| `root` | 是 | string | 命中的 root 实例名；named-location 为 `os`；root 外绝对路径为 `external` |
| `path_semantics` | 是 | enum | `literal` / `machine_derived`，见 §4.9 |
| `derived_from` | 视 semantics | enum | `repo_slug` / `git_worktree_of` / `json_path_key`；`machine_derived` 必填，`literal` 为 null |
| `origin` | 否 | string \| null | 派生来源的原始值（如 `D:/Study/Chatrix`），无来源为 null；只能出现在 `machine_derived`，见 §4.9 |
| `origin_path_key` | 否 | string \| null | `origin` 的折叠比较键，见 §6.3；与 `origin` 同时为 null 或同时非 null |
| `profile` | 是 | string | profile name |
| `entry` | 是 | string | 命中的 entry id |
| `part_id` | 否 | string | 命中的 part id，仅当 entry 声明 `parts`；同一路径的 part 靠它区分，见 §4.10 |
| `kind` | 是 | enum | `file` / `dir` / `glob-group` / `named-location` / `catch-all` |
| `layer` | 是 | enum | `L0`…`L5` |
| `confidence` | 是 | number | 0.000–1.000，见 §5 |
| `signals` | 是 | array | 至少 1 条；`catch-all` 恰含引擎注入的 `residual` 一条，见 §4.1、§5.1 |
| `secret` | 是 | object | 见 §4.3 |
| `contains_secret` | 聚合必填 | bool | 后代中是否有实际命中（`hits` 非空），见 §4.7 |
| `may_contain_secret` | 聚合必填 | bool | 后代 entry 是否声明 `scan`/`restore`（可能含密），见 §4.7 |
| `size_apparent` | 视 kind | integer | 逻辑大小；不可得时为 `null` |
| `size_alloc` | 视 kind | integer | 分配大小；不可得时为 `null` |
| `mtime` | 视 kind | string | RFC 3339 纳秒；不可得时为 `null` |
| `file_id` | 视 kind | object \| null | 见 §4.4；聚合 Unit 为 `null` |
| `fingerprint` | 视 kind | object | 见 §4.5 |
| `owner` | 否 | object \| null | 所有者，见 §4.8 |
| `acl` | 否 | object \| null | ACL 摘要，见 §4.8 |
| `size_estimated` | 否 | bool | 体积为估算值；默认 false，仅 `named-location` 或聚合 Unit，见 §4.7、§6.4 |
| `aggregate_count` | 视 aggregate | integer | 聚合 Unit 的后代条目总数（含子目录），≥ 0；仅空目录为 0，见 §4.7 |
| `proposed_action` | 是 | enum | `keep` / `delete` / `reinstall` / `template` / `migrate` / `rebind` / `relogin` |
| `risk_flags` | 是 | array | 可能为空；枚举见 §4.6 |
| `needed_by` | 否 | array | 消费该路径的功能，见 §4.11 |
| `companions` | 否 | array | 已合并的伴生后缀，如 `["-wal","-shm"]`；无伴生时省略，见 §4.12 |
| `side_effects` | 否 | array | 已观测的只读副作用，目前仅 `shm_created`，见 §4.12 |
| `open_as` | 否 | enum | `none` / `text` / `sqlite-ro`；内容的打开方式，`shm_created` 的前提，见 §4.12 |
| `opaque_content` | 否 | bool | 内容未被解析，仅记录存在性；默认 false，见 §5.2 |
| `link_target` | 否 | string | 仅链接项；根外链接按磁盘上的原样保留相对形式，不绝对化（`D-015` 第 7 条） |
| `secret_ref` | 否 | string | 仅 RESTORE 项的**目标**形态；P1 尚未写出，见 §9 第 4 条、§9.2 |
| `notes` | 否 | string | 单行说明，≤ 512 字节 |

`cid`/`size_*`/`mtime`/`file_id`/`fingerprint`/`owner`/`acl` 在 named-location 上允许为 `null`；其他 kind 必填或 null（不可得），不得省略键（`owner`/`acl`/`size_estimated` 可省略，缺省即 null/false）。`path_semantics` 必填；`derived_from` 在 `literal` 上写 `null`，不得省略键。可选字段按语义省略：`part_id`、`origin`/`origin_path_key`、`companions`、`side_effects`、`open_as`、`needed_by`、`notes` 等无值时不写键；`owner`/`acl` 的显式 `null` 在写回时省略（P0 无写回，导出原样拷贝，不改写，`D-027` 第 3 条）。

`kind: catch-all` 的 Unit：`root` 是实例名，`path` 指向残留顶层项，`confidence` 恒为 `0.500`，`layer` 缺省 `L2`、`proposed_action` 恒为 `keep`，`risk_flags` 必含 `residual` 与 `low_confidence`。

`signals` 必须恰含一条引擎注入的 `residual` signal（`src: filesystem_stat`，note 形如"未被任何 entry 命中，catch-all 残留"），profile 里 `signals: []` 合法——注入由引擎负责，校验器不得因 profile 为空而拒绝（`D-021` 第 4 条）。profile 若另行写了 signals，不替代注入：注入的 `residual` 仍必须存在，额外 signal 只记 `W-MAN-117` 告警、不判错（`D-027` 第 8 条）。

`external` 根只在条目写绝对路径且不落在任何已声明 root 下时出现，同时带 `risk_flags: ["outside_root"]`。

### 4.2 id

- `id` = `"u_"` + Crockford Base32(ULID) 之外再哈希，避免顺序泄露大小：取 `sha256(root_name + "\0" + profile + "\0" + entry + "\0" + part_id_or_empty + "\0" + path_key)` 前 128 位，Crockford Base32 编码 26 字符。
- 同机、同路径、同 entry（及同 part）重扫必须得到相同 `id`；跨机不保证（绝对路径变了，`id` 变）。`id` 只作同机稳定引用。
- 内容变化**不**改变 `id`；内容指纹在 `fingerprint`。跨机关联**只用 `cid`**，不用 `id`（`D-011` 第 1 条）。
- `id` 冲突（哈希前 128 位碰撞）时保留首个，后续加 `risk_flags: ["id_collision"]`。

### 4.2.1 cid

- `cid` = `"c_"` + Crockford Base32(sha256(`fingerprint.algo` + "\0" + `fingerprint.value`) 前 128 位)，26 字符。与 `path`、`root`、`profile`、`entry` 全部无关；同内容在跨机、跨 profile 时得到相同 `cid`。
- 内容变化即 `cid` 变。`fingerprint.scope` 为 `shape`、或 `fingerprint.value` 为 `null` 时 `cid` 为 `null`；`scope` 为 `full`、`head-tail`、`keys`、`aggregate` 且 `value` 非 null 时必须给出 `cid`。
- `cid` 相等**不**自动合并 Unit；报告只并列标出"疑似同一内容，跨机可对应"。
- `cid` 与 `id` 分工固定：`id` 回答"这台机器上的这一条"，`cid` 回答"两台机器上的同一份内容"。任何用 `id` 跨机关联、或用 `cid` 替代同机引用的做法都算错。

### 4.3 secret

```json
{
"secret": {
  "class": "scan",
  "hits": [
    {"kind": "known_prefix", "class": "restore", "locator": "/env/FOO_TOKEN", "prefix": "sk-ant-", "fingerprint": "sha256:9f2c…"}
  ],
  "hit_count": 1,
  "truncated": false
}
}
```

- `class` 取 `none` / `scan` / `reference` / `restore` / `relogin`，与 profile 声明一致；`hits[].class` 是单处命中的实际三分结论。
- `hit_count` 为实际命中总数；`hits` 最多 32 条，超出设 `truncated: true`。
- `hits[].kind` 取固定枚举：`known_prefix`、`regex`、`entropy`、`key_name`、`env_ref`、`path`。
- `locator`：文本用 `行:列`，JSON 用 JSON Pointer，TOML/INI 用 `段.键`，环境变量用 `/env/KEY`。二进制用字节偏移，named-location 用 `target`。
- `prefix` 最多 7 个字符的已知非密前缀（如 `sk-ant-`），其余不落。落盘形态只存前缀 + 加盐指纹，**不存末 4 位**；报告显示为"前缀…+指纹"，不得用半截明文拼出假尾。`前4…后4` 只用于内存内即时展示（`D-025` 第 1 条由 `D-029` 第 2 条收窄）。
- `hit_id` 仅在导出 RESTORE 命中后写入，固定为 `h_` + 20 字符（前 96 bit），格式与派生见 §9 第 4 条；未导出时省略（`D-027` 第 14 条）。
- `part_id` 存在时，`locator` 是该 part 的 selector 的定位形式：JSON Pointer 加 `#/<locator>`，行号仍是文件绝对行号，TOML 仍是 `段.键`。同一文件各 part 的 locator 不共享编号。
- 聚合 Unit 的 `class` 取全部后代 `class` 的最保守者，顺序 `none < reference < scan < restore < relogin`；`hits` 为空、`hit_count` 为 0、`truncated` 为 false。需列明细时由报告回读后代 Unit，不塞进聚合行（`D-013` 的 M9）。
- 聚合 Unit 另用两个独立布尔字段表达"实际命中"与"可能命中"，不得把后者显示成前者（`D-021` 第 9 条）：
  - `contains_secret`：任一后代 `hits` 非空或 `secret.class ∈ {restore, relogin}` 时为 true；
  - `may_contain_secret`：任一后代 entry 声明 `scan`/`restore`，或后代聚合自身 `may_contain_secret` 为 true 时为 true。
  - 二者都由后代集合重算，报告优先展示 `contains_secret`；`may_contain_secret && !contains_secret` 单列"可能含密（未检测）"。
- `opaque_content: true` 且内容未解析时 `hits` 为空；若头部检测到前缀，只在 `hits` 记 `known_prefix`，`locator` 写字节偏移。
- **任何情况下不得出现完整明文**，见 §9。

### 4.4 file_id

```json
{
"file_id": {"volume_serial":"3A4F-9C21","index":"0x0000000000012F3A","reparse_tag":null}
}
```

- Windows：卷序列号 + `FILE_ID_INFO.FileIndex`（128 位）；POSIX：`dev` + `ino`，以十六进制字符串。
- `reparse_tag` 是联合类型：Windows 上为 reparse tag 数值，或实现原样保留的字符串；非 reparse 为 `null`；POSIX 符号链接记 `"symlink"`。读取方按原类型原样保留，不做数字/字符串互转（`D-027` 第 11 条）。
- 用于漂移检测与防环，不用于跨机识别。

### 4.5 fingerprint

```json
{
"fingerprint": {"algo":"sha256","scope":"full","value":"9c1d…"}
}
```

- `scope` 取 `full` / `head-tail` / `keys` / `aggregate` / `shape` / `null`：
  - `keys`：只对键路径做排序摘要（`sha256` 覆盖排序后的键路径，分隔 `\0`），用于 `extractor: keys-only` 的 Unit 与 part；只消耗 `max_bytes_structure`，不读值，因此与 `max_bytes_inline: 0` 相容（`D-024` 第 2 条）。非 keys-only 的 Unit 用 `keys` 即 `E-MAN-067`。
  - `null`：既无内容也无键路径可读（如条目两项预算都为 0、占位符、不可读）。`scope: null` 时 `algo` 仍写 `sha256`、`value` 为 `null`，并加 `content_partial`。
- 超过 `max_bytes_inline` 且 > 32 MiB 的文件用 `head-tail`；流式读取，不整文件入内存。
- 不可读时 `value: null` 并加 `risk_flags: ["read_error"]`。
- 占位符未水合（云端占位、层级未下载）时 `value` 必须为 `null`，加 `risk_flags: ["content_partial", "cloud_placeholder"]`，`cid` 随之为 `null`（`D-015` 第 7 条）。`scope` 的 `keys` 与 `value: null` 互斥（有键可读就不写 null）。

### 4.6 risk_flags

固定枚举，未知值保留：

`gitignored`、`git_tracked`、`not_versioned`、`symlink`、`symlink_cycle`、`junction`、`hardlink_multi`、`sparse`、`cloud_placeholder`、`long_path`、`case_collision`、`readonly_volume`、`encrypted_efs`、`oversized`、`content_partial`、`opaque_content`、`read_error`、`probe_unavailable`、`low_confidence`、`unknown_enum`、`id_collision`、`aggregated`、`residual`、`outside_root`、`machine_derived_path`、`slug_collision`、`deletion_cost`。

`risk_flags` 排序固定按上表顺序，保证可 diff。

`unversioned_repo` 已改名 `not_versioned`，语义为"不在任何版本库内"，home 侧同样适用；读取器接受旧名并映射（`W-MAN-116`，`D-015` 第 4 条）。`binary` 同样已改名 `opaque_content`，读取器接受旧名并映射（`W-MAN-102`，`D-021` 第 3 条）；字段名、风险标记、note 前缀三处一致改名。`machine_derived_path` 由 profile 的 `path_semantics: machine_derived` 产生；`slug_collision` 只在两个不同源路径得到同一派生表示时出现。`residual` 与 `low_confidence` 是 catch-all Unit 必带；`deletion_cost` 用于 `L0` 但被功能消费的 Unit（`D-013` 的 M5）。

### 4.7 聚合 Unit

以下任一条件触发聚合 Unit（`D-013` 的 M9）：条目的 `expand: aggregate`、命中数超过 `aggregate_above`、条目 `max_bytes_total` 耗尽、`kind: catch-all` 且残留项是目录或有多个后代。单文件残留的 catch-all 是普通 Unit，不聚合。形态固定：

- `risk_flags` 必含 `aggregated`；`aggregate_count` 必填，为后代条目总数**含子目录**（`D-015` 第 20 条）。空目录为 0，不按 1 计（`D-015` 第 6 条）。空 glob 在 `aggregate_count: 0` 之外必须留 `empty_glob` note。
- `size_apparent` / `size_alloc` 为全部后代对应字段的**求和**；某项全部不可得时写 `null`，部分不可得时只求已知部分并加 `size_estimated: true`。
- `file_id` 恒为 `null`；`mtime` 为后代 `mtime` 的最大值（全不可得为 `null`）。
- `fingerprint` 为全部后代 `(path_key, cid, size_apparent, mtime, file_id.index)` 的排序摘要，`scope` 写 `aggregate`，值非 null 时必须派生 `cid`；`keys` 与 `null` 不用于聚合（后者仅当后代全部不可得）。占位符使任一后代指纹为 null 时，聚合摘要照算已知部分并加 `content_partial`，`cid` 仍可给出；**全部**后代指纹不可得时 `value: null`、`cid: null`。
- `secret.class` 按 §4.3 的保守顺序由后代并集得出，`hits` 为空；`secret.hit_count` 为 0。`contains_secret` / `may_contain_secret` 按 §4.3 由后代重算并必填；`contains_secret: true` 时 `secret.class` 不得为 `none`。
- 聚合 Unit 的 `signals` 必须包含一条 `content_match` 或 `filesystem_stat`，写明触发条件（`aggregate` / 阈值 / 预算 / 残留）与后代计数——catch-all 的聚合除外，它沿用 catch-all 的空 signals 豁免。
- `confidence` 取后代最低者并额外 ×0.9；< 0.9 时照常 `keep` + `low_confidence`。catch-all 的 confidence 固定 0.5。
- `layer` 取后代最高层；`secret.class` 非 none 时不得低于 `L2`。catch-all 例外：confidence 0.5 使其固定 `L2`。
- 一个聚合 Unit 只对应一个 `(profile, entry, part_id, path_key)`，不再为后代单独出行（`D-011` 第 8 条）。
- 聚合的 `path` 为被聚合的目录、glob 根或 catch-all 残留顶层项；聚合不跨越 root 实例。

### 4.9 path_semantics 与 derived_from

```json
{"path_semantics":"machine_derived","derived_from":"repo_slug"}
```

- `literal`：路径来自写入者字面值。
- `machine_derived`：路径由别的值转换得到，换机必变或可碰撞。`derived_from` 必填：`repo_slug`（仓库路径的 slug 变换）、`git_worktree_of`（主 checkout + 随机 worktree 名）、`json_path_key`（JSON 对象里的绝对路径键）。
- 机器派生的 Unit 必带 `risk_flags: ["machine_derived_path"]`；两个源路径的派生表示相等时再加 `slug_collision`。派生关系只用于报告与跨机归并，`path` 仍是磁盘原拼写（`D-015` 第 15 条）。
- `origin` / `origin_path_key`：记录派生来源的原始值与折叠键（与 header `roots[].origin` 的“root 来源”语义无关，后者是 `profile`/`cli`/`absolute`）。`json_path_key` 的 Unit 写被转换的键本身（含 `*` 匹配时取该次匹配的键）；`repo_slug` 的 Unit 在能由 profile 的键映射反查时写源绝对路径，否则写 `null`；`git_worktree_of` 在能读到 `gitdir:` 目标时写主 checkout 路径，否则 `null`。
- `origin` 非 null 时 `origin_path_key` 必填且等于 `origin` 的折叠结果；两者只允许出现在 `machine_derived` 上（`E-MAN-069`）。
- 两个不同 `origin` 折叠到同一派生路径时，所有相关 Unit 加 `slug_collision`，并各记一条含两个 `origin` 的 note。

### 4.10 part 结论

- `part_id` 只在 profile entry 声明了 `parts` 时出现，取值必须是该 entry 的 part id（`E-MAN-052`）。一个文件有几个 part 命中就有几行，`path` 与 `path_key` 全部相同，靠 `part_id` 区分。
- part Unit 的 `file_id` 与主文件相同；`size_apparent` 为选中值规范化后的字节数，`size_alloc` 为 `null`（`E-MAN-061`）；`fingerprint` 只覆盖该段，`scope` 用 `full`。
- part 的 `layer`/`secret`/`extractor` 已由 profile 解析为具体值，manifest 不再引用 profile 的 part 定义。
- 每个零命中的 part 记一条带 `part_id` 的 `part_missing` note；全部 part 零命中时另产出一个无 `part_id` 的 entry 级 Unit，加 `content_partial`（`D-013` 的 M1）。
- `part_id` 保留值 `uncovered` 表示"未被任何 part 选中的剩余键"（profile `parts_uncovered`，`D-024` 第 1 条）。每个未覆盖的顶层键一行，`size_apparent` 为该子树键路径的规范化长度、`size_alloc: null`、`fingerprint.scope: keys`；`parts_uncovered: residual` 时另带 `residual`/`low_confidence` 与 `confidence 0.500`。`uncovered` 行不受 `E-MAN-052` 与 `E-MAN-061` 的"必须是已声明 part"约束，但 `path_key` 与主文件相同。

### 4.11 needed_by 与删除代价

`needed_by` 是数组，取值 `rewind` / `statusline` / `resume` / `mcp` / `daemon` / `plugins`，排序按此顺序。它说明"删了会让哪个功能丢状态"，与层无关。`layer: L0` 且 `needed_by` 非空时 `proposed_action` 仍为 `delete`，但必须带 `risk_flags: ["deletion_cost"]`（`E-MAN-062`），报告单列。未知值保留并记 `W-MAN-102`。

### 4.12 companions 与 side_effects

- `companions` 列出已合并进本 Unit 的伴生后缀（`-wal`、`-shm` 等），顺序即 profile 声明顺序。一个逻辑库只有一行，伴生文件不单独成 Unit（`E-MAN-063`）。成员大小已求和进 `size_*`，`fingerprint` 覆盖全部成员。
- 缺失后缀留 `companion_missing` note，不算错误；全部缺失时省略 `companions`。伴生文件随主文件命中，**不参与 catch-all 残留判定**，也不得再产出 residual Unit（`D-024` 第 5 条）。
- `open_as` 记录引擎实际打开内容的方式：`none`（只按字节读，默认）、`text`（按文本解码）、`sqlite-ro`（SQLite `mode=ro`）。`side_effects: ["shm_created"]` 必须伴随 `open_as: sqlite-ro`，否则声明空转（`E-MAN-070`）。
- `side_effects` 是已观测到的只读副作用，目前只有 `shm_created`（sqlite 以 `mode=ro` 打开仍可能建 `-shm`）。声明过 `side_effects` 的条目，`-shm` 新建与所在目录 mtime 变化不破坏不变式；未声明却发生的记 `side_effect_unexpected`（`D-015` 第 3 条、`D-016`）。

### 4.8 owner 与 acl

两者现在就有，可为 `null`。P0 不迁移 ACL，只作 L4"本机绑定"与权限漂移的证据（`D-011` 第 7 条）。

```json
{
"owner": {"kind":"sid","value":"S-1-5-21-1111-2222-3333-1001"},
"acl": {"algo":"sha256","value":"6b1e…","entries":12,"truncated":false}
}
```

- `owner.kind` 取 `sid`（Windows）或 `uid-gid`（POSIX，`value` 形如 `1000:1000`）。
- `acl` 对规范化后的 DACL（按 ACE 排序、稳定序列化）取哈希；`entries` 为 ACE 数，超过 256 条时只哈希前 256 条并置 `truncated: true`。
- named-location 两者均写 `null`。非 null 时格式非法即 `E-MAN-051`。

---

## 5. 结论与 confidence

### 5.1 signals

没有 `signals` 的 Unit 不允许出现（`E-MAN-011`）。`catch-all` 除外：其 `residual` signal 由引擎注入，profile 的 `signals: []` 不等于 Unit 的空 signals。每条 signal：

```json
{"src":"gitignore_hit","note":"~/.config/git/ignore 第 1 行 **/.claude/settings.local.json 命中","url":null}
```

- `src` 必填，取固定枚举：`profile_rule`、`filesystem_stat`、`git_tracked`、`gitignore_hit`、`file_format`、`content_match`、`secret_prefix`、`secret_entropy`、`link_count`、`cloud_placeholder`、`official_docs`、`user_override`、`probe_result`。
- `note` 必填、单行、≤ 512 字节、可复述（写清证据来源与判定依据，不写"看起来像"）。
- `url` 可选；`src` 为 `official_docs` 时必填。
- 每条结论的 `layer`、`secret`、`proposed_action` 都必须能由 `signals` 支撑；profile 给的层本身也要以 `profile_rule` signal 记录 entry id 与 profile 版本。
- signal 顺序固定：先 profile 规则，再文件系统事实，再版本控制事实，再内容/熵事实，最后文档。同一 `src` 内按 note 字节序。

### 5.2 confidence 与降级

- `confidence` ∈ [0, 1]。判定顺序 L3→L4→L2→L1→L0 的每一跳都产生中间置信度，最终取**最弱环节**，不取平均。
- `catch-all` 的 confidence 固定 `0.500`，不参与上述合成（`E-MAN-064`）；因 < 0.6，层固定 `L2`。
- **`confidence < 0.9` 时 `proposed_action` 必须为 `keep`**，`layer` 保留估计值，并加 `risk_flags: ["low_confidence"]`。
- `confidence < 0.6` 时 `layer` 固定写 `L2`（"不确定就先按需配置恢复"），`secret` 若不确定写 `scan`。
- 只有 `confidence ≥ 0.9` 才允许非 keep 动作；`relogin` / `restore` 类结论要求 ≥ 0.95。
- `confidence` 的来源组合必须在 `note` 可追：例如 profile 规则 0.98 × 无 reparse 0.99 × gitignore 命中 0.99 → 0.96。
- 冲突证据（如 profile 说 L3、内容显示是 lockfile）必须写入两条 signal，取**更保守者**——层号更高者；L0/L1 与 L3 冲突取 L3——且必须把冲突本身作为一条独立 signal 记下（`src` 用 `content_match` 或 `filesystem_stat`，`note` 写明双方结论），`confidence` 额外 ×0.8（`D-011` 第 5 条）。

### 5.3 多 profile 同路径

- 两个 profile 的 selector 命中同一 `path_key` 时**各自照常产出 Unit**；`E-MAN-025` 按 `(profile, entry, part_id, origin_path_key, file_id)` 判重（origin 缺省为空串；机器派生行靠它区分同一路径下的兄弟行），`file_id` 不可得时退回 `(profile, entry, part_id, origin_path_key, path_key)`，不跨 profile。大小写不敏感卷上的 `Demo`/`demo` 因 `file_id` 不同而合法；同一路径的多个 part 因 `part_id` 不同而合法（`D-015` 第 2 条）。
- 报告按 `path_key` 归并显示：`layer` 取层号更高者，`signals` 求并集去重，`risk_flags` 求并集，并同时列出两个 `profile` 名。归并结果在统计中只计一次，按归并后的层计数。
- 归并落到报告层，manifest 本身不合并两份 Unit；`W-MAN-111` 保留提示（`D-011` 第 11 条）。

---

## 6. 路径规范化

### 6.1 基本规则

1. 从扫描器拿到的原始路径先转绝对：Windows 用卷路径规则（`C:\`、`\server\share\`），POSIX 用 `/`。无法绝对化即丢弃并记 `note`。
2. 清理 `.`、折叠重复分隔符、词法解析 `..`（**不**穿透符号链接解析，因为链接本身不跟随）。
3. 盘符大写；UNC 服务器与共享名保留原大小写；POSIX 保留原大小写。
4. 除根路径（`C:\`、`/`、`\server\share\`）外不留尾分隔符。
5. 使用**磁盘上的实际拼写**作为 `path`，不做大小写归一；引擎的任何解析路径都不得改写拼写，尾点、尾空格、保留名原样保留（`D-015` 第 15 条）。保留名（`CON`、`NUL`、`COM1` 等）按普通文件处理，不 special-case（`D-015` 第 16 条）。
6. 普通形式写 `path`；调用系统接口前才加 `\\?\` 前缀。`path` 永不含 `\\?\`。
7. 路径必须是绝对路径（`E-MAN-065`）；named-location 的 URI 路径豁免，规则见 §6.4。条目绝对路径不落在任何已声明 root 下时，`root` 写 `external` 并带 `outside_root`，不改写 `path`（`D-015` 第 7 条）。

### 6.2 边界比较

- 判断 A 是否在 B 之下：比较 `path_key`，且 A 的键必须以 `B 的键 + 分隔符` 开头；根除外。
- 永远按路径段比较，不做裸字符串前缀。`C:\foo` 不包括 `C:\foobar`。
- 大小写策略按卷：默认 Windows/macOS 不敏感，Linux 敏感；卷可探测为敏感时按敏感。与 profile 的 `case_sensitive` 覆盖一致。

### 6.3 path_key

- 在 `path` 基础上做：Unicode NFC → `golang.org/x/text/cases.Fold()` 全量 case folding（不做土耳其语等 locale 规则）→ 分隔符统一（Windows 与 UNC 用 `\`，POSIX 用 `/`）。
- `x/text` 版本钉死在 `go.mod`（不允许浮动），构建时把模块版本与 Unicode 版本写入 header 的 `path_fold_version`。读 manifest 时用当前构建重算；header 版本不同只告警 `W-MAN-113`，不改写旧记录（`D-011` 第 2 条）。
- 不改变的：盘符位置、UNC 前缀、尾分隔符规则。
- `path_key` 是**比较键**，不用于展示与打开文件。
- 大小写敏感卷上 `path_key` 仍折叠（保证跨卷行为一致），敏感比较另由 §6.2 的卷策略决定；因此 `path_key` 对敏感卷只作为唯一性键，不作为相等判定。

### 6.4 named-location 的 path

- 形如 `scheme:opaque`，scheme 小写，opaque 按 scheme 规则规范化（凭据目标名去首尾空白、折叠内部连续空白；registry 键统一大写根）。
- `path_key` = 小写 scheme + `:` + 折叠后的 opaque。
- `root` 写 `os`，`size_*` / `mtime` / `file_id` / `fingerprint` / `owner` / `acl` 允许为 `null`，`fingerprint.scope` 用 `shape`。
- 体积默认 `null`。探测能给出估算时写 `size_estimated: true` 并同时写 `size_apparent`，不写 `size_alloc`；`size_estimated` 只允许出现在 named-location 或聚合 Unit（`E-MAN-027`，`D-011` 第 4 条）。

### 6.5 长度

- `path` 超过 32,000 字符写 `risk_flags: ["long_path"]`；超过 32,767 字符整条记 `note` 并跳过，不写 Unit。
- `path_key` 同样受限。

---

## 7. 版本与兼容

- `manifest_version` 为 `MAJOR.MINOR`。
- MINOR：只增可选字段、增枚举值。读取方必须忽略未知字段与未知枚举值。未知 `layer` 映射为 `L2`（最保守的"人要看"档），未知 `proposed_action` 映射为 `keep`，两者都加 `risk_flags: ["unknown_enum"]`（`D-027` 第 2、10 条）。`E-MAN-010` 只对非法 `kind` 触发；未知 `layer`/`proposed_action` 不判错。
- 未知字段读取方保留，且 `packout report` **必须显示**：按原键名列出，值做 JSON 转义（单值 ≤ 256 字节，超出截断），并标注"来自更新版本"。未知字段同样受 §11.1 的明文检测约束（`D-011` 第 10 条）。未知字段的显示责任在 report 层，以 `W-MAN-101` 记录；manifest 校验器只负责保留、不判错（`D-027` 第 13 条）。
- Go 包职责：selftest fixture 的 `Materialize` 归 `internal/profile`，manifest 包不重复实现同名能力（`D-027` 第 9 条）。正式入口类型为 `*manifest.Manifest`；`manifest.Doc` 只作兼容别名保留一个 MINOR 版本，新代码不得使用（`D-029` 第 1 条）。
- MAJOR：删字段、改语义、改规范化规则。读取方遇到更高 MAJOR 直接拒绝（`E-MAN-040`），除非 `--allow-major`。
- 每条 Unit 冗余携带 `schema_version`，使单独取出的分片仍可自校验；它必须与 header 相同（`E-MAN-041`）。
- `note` 的 `code` 与 `risk_flags` 都用固定枚举 + 保留未知值，不因新增值升 MAJOR。
- 旧 MAJOR 的 manifest 由 `packout manifest migrate` 读入内存迁移；P0 只读，不写回源。
- v1 → v2 的读取映射：`unversioned_repo` → `not_versioned`；无 `path_semantics` 补 `literal` 与 `derived_from: null`；`aggregate_count` 允许 0；唯一键补 `part_id`（空）；新增字段缺失不影响读取，只在重写时补齐。

---

## 8. 分片、流式与内存预算

大目录不能整体进内存，规则如下：

- 扫描器以事件流驱动写入，同一时刻只持有当前 Unit 与 256 KiB 写缓冲；glob 与目录下降都是流式的，不先收集全量路径。
- 哈希按 1 MiB 块流式计算；`head-tail` 只读首尾各 1 MiB。
- 三种读取预算分开记账：`max_bytes_inline`（读值）、`max_bytes_structure`（只解析键路径，不读值）、`max_bytes_total`（条目累计）。`churn: high` 的结构解析按 `file_id` 在一次扫描内缓存；文件重写但 `file_id` 不变时不重复解析。
- 条目 `max_bytes_total` 耗尽后，其后命中转聚合 Unit；profile 级总额耗尽后，余下条目只写元数据 Unit（`fingerprint.scope: shape`、`content_partial`），footer `complete: false`，进程退出码 0（`D-015` 第 5 条同口径：预算不是错误）。
- 分片索引只存计数与摘要，不存路径列表；manifest 本身不载入内存。
- 分片封片：先 `Flush`、`fsync`、rename，再开新分片。索引最后写。50,000 条 / 64 MiB 的封片阈值为暂定值，见 §2。
- 崩溃可检测：无 footer 或无 index 即不完整；已封分片可被逐行消费。
- 单次扫描的 Unit 上限默认 2,000,000，超过时 footer `complete: false` 并记 `budget_exceeded`。
- 写入顺序是单一 writer goroutine，避免锁与交错。P0 不允许多进程写同一 manifest 目录；存在 `.lock` 时拒绝（`E-MAN-031`）。
- 只有 `open_as: sqlite-ro` 的条目才以 SQLite `mode=ro` 打开，允许因此产生 `-shm`；`open_as: none` 的 sqlite 只按字节哈希，不建 `-shm`。扫描前记录目录项，扫描后把已声明的 `shm_created` 记进 Unit 与 `stats.side_effects`，不据此判不完整（`D-015` 第 3 条）。

---

## 9. 与 secrets.age 的边界

manifest 只记**位置与指纹**，`secrets.age` 只装**密文**。硬规则：

1. manifest 任何字段都不得含完整明文密钥；连 `notes` 也不行。
2. `prefix` 只允许 ≤ 7 字符且必须来自已知非密前缀表（`sk-ant-`、`sk-`、`ghp_`、`xoxb-`、`eyJ` 等）。
3. `fingerprint` = `sha256(secret_value + scan_salt)`。salt 有且只有两种模式，由 header 的 `inputs.secret_salt_mode` 标明；两次扫描模式不同或 salt 不同，指纹即不可比，报告不得合并去重（`D-011` 第 3 条）。
   - `random`（默认）：每次扫描随机 16 字节，存于 `inputs.secret_salt`（非密，32 个十六进制字符）。同一扫描内相同密钥得到相同指纹，可去重；跨扫描不可比。
   - `stable`：`--stable-salt` 打开，读 `~/.config/packout/salt`（不存在时以 0600 随机创建，此后不轮换），跨扫描可去重。salt 值仍写进 header。
4. `secret_ref` 的**目标形态**是 `secrets.age#<hit_id>`，`hit_id` = `"h_"` + Crockford Base32(sha256(`cid` + ` ` + `locator` + ` ` + 值指纹) 前 96 位) 的 20 个字符，与 `unit_id` 无关（`D-027` 第 14 条）。
   **P1 现状（`D-045` 第 1 条）**：manifest 行里**还不写** `secret_ref`；引用只出现在 `config/` 的文本占位符里，见 §9.2。字段保留，允许缺失。
5. `manifest.jsonl` 与 `config/` 必须能在没有 `secrets.age` 时单独还原；因此 `config/` 中的模板化结果也只能含脱敏占位。
6. `RELOGIN` 命中不产生 `secret_ref`，只进报告 L5 清单与 `proposed_action: relogin`。
7. 报告、日志、note 同样遵守第 1 条；调试输出若打印 Unit，只能打印脱敏后的结构。
8. 读取 sqlite 产生的 `-shm` 是唯一写副作用，内容不进 manifest，只记 `side_effects: ["shm_created"]` 与计数。

### 9.1 报告页、导出与 CLI 验收边界

- 掩码的落盘形态只有 ≤7 字符前缀 + 加盐指纹，不存末 4 位（见 §4.3、§9 第 3 条）；报告显示为"前缀…+指纹"。
- 报告页 token 可放 URL fragment，服务端另接受 `Authorization` 头。403 bootstrap 页把 fragment 转到 query 再重载的两段式接受，但 bootstrap 页不得含任何数据（Unit、计数、路径、指纹都不出现），测试必须断言（`D-029` 第 3 条）。
- CSP nonce 由内容派生以保持 golden 稳定；它只授权内联静态脚本，不承担鉴权。报告不自动请求外部子资源（`D-029` 第 4 条）。
- CLI 验收清单必须包含：`report` 的 `IncludeSignals` 零值为 false，CLI 必须显式传 `true` 才输出 signals；不得把零值当 true（`D-029` 第 5 条）。

### 9.2 占位符与加密索引（`secrets.age`）

`config/` 中被识别为 RESTORE 的值不落明文，替换为：

```
«secret:secrets.age#h_<20 个 Crockford Base32 字符>»
```

- 前缀 `«secret:`、结尾 `»` 均为固定串；`hit_id` 生成同 §9 第 4 条。
- 无密钥时文件仍是合法文本，人可直接看出"这里有一个凭据"。
- `secrets.age` 是 age 密文（收件人模式或口令模式，`D-041`），明文是一个 JSON 索引：

| 字段 | 类型 | 说明 |
|---|---|---|
| `format` | string | 恒为 `packout-secrets` |
| `format_version` | int | 当前为 1；形状变更时递增 |
| `entries[].ref` | string | `secrets.age#h_…` |
| `entries[].class` | string | 当前恒为 `restore` |
| `entries[].value` | string | 明文值（UTF-8；二进制值按原字节转字符串） |
| `entries[].sources[]` | array | `path`（包内相对路径）+ `locator`，同一值在多处出现时全部列出 |

- `entries` 与 `entries[].sources` 都按字典序排序，同样的输入得到相同明文索引（age 文件头仍随机）。
- 无 profile、无命中时仍写一个加密的空索引。
- 索引的 `ref` 集合必须与 `config/` 中出现的全部占位符一一对应；restore 缺项即 `missing_secret`。
- **已知缺口**：manifest 不记 `secret_ref`，因此 `verify` 在无密钥时无法校验占位符指向是否有效（`D-045` 第 1 条）。

---

## 10. 样例

### 10.1 完整 Unit（L3，会话 transcript）

```json
{"type":"unit","schema_version":"2.0","id":"u_7Q3ZC9K2M4P6R8T0V2X4Z6B8D0","cid":"c_7Q3ZC9K2M4P6R8T0V2X4Z6B8D0","path":"C:\\Users\\a\\.claude\\projects\\D--Study-packout\\4b1c.jsonl","path_key":"c:\\users\\a\\.claude\\projects\\d--study-packout\\4b1c.jsonl","root":"home","path_semantics":"machine_derived","derived_from":"repo_slug","profile":"claude-code","entry":"projects-transcripts","kind":"file","layer":"L3","confidence":0.970,"signals":[{"src":"profile_rule","note":"profile claude-code v2.0 entry projects-transcripts 声明 L3","url":null},{"src":"filesystem_stat","note":"普通文件，非 reparse，逻辑 12,404,871 字节","url":null},{"src":"gitignore_hit","note":"~/.config/git/ignore 的 **/.claude/projects/ 命中，未进版本库","url":null},{"src":"official_docs","note":"transcript 记录会话内读过的全部内容，不可再生","url":"https://code.claude.com/docs/en/memory"}],"secret":{"class":"scan","hits":[{"kind":"known_prefix","class":"restore","locator":"42:17","prefix":"sk-ant-","fingerprint":"sha256:6c1e88f0"}],"hit_count":1,"truncated":false},"size_apparent":12404871,"size_alloc":12410880,"mtime":"2026-11-08T12:03:44.1234567Z","file_id":{"volume_serial":"3A4F-9C21","index":"0x0000000000012F3A","reparse_tag":null},"fingerprint":{"algo":"sha256","scope":"head-tail","value":"d41d8cd98f00b204e9800998ecf8427e"},"owner":{"kind":"sid","value":"S-1-5-21-1111-2222-3333-1001"},"acl":{"algo":"sha256","value":"a1b2c3d4e5f6","entries":9,"truncated":false},"proposed_action":"migrate","risk_flags":["gitignored","oversized"]}
```

### 10.2 反例：L5（错误地当成 L3 会漏掉重登）

```json
{"type":"unit","schema_version":"2.0","id":"u_1A2B3C4D5E6F7G8H9J0K1M2N3P","cid":null,"path":"wincred:Claude Code-credentials","path_key":"wincred:claude code-credentials","root":"os","path_semantics":"literal","derived_from":null,"profile":"claude-code","entry":"oauth-credential-store","kind":"named-location","layer":"L5","confidence":0.960,"signals":[{"src":"profile_rule","note":"profile claude-code v2.0 entry oauth-credential-store 声明 L5/relogin","url":null},{"src":"probe_result","note":"wincred 目标存在，通用凭据，最近写入 2026-11-07","url":null},{"src":"official_docs","note":"OAuth 凭据由系统凭据库保管，refresh token 绑定设备会话","url":"https://code.claude.com/docs/en/setup"}],"secret":{"class":"relogin","hits":[{"kind":"known_prefix","class":"relogin","locator":"target","prefix":"sk-ant-","fingerprint":"sha256:0a9b7c2d"}],"hit_count":1,"truncated":false},"size_apparent":null,"size_alloc":null,"mtime":null,"file_id":null,"fingerprint":{"algo":"sha256","scope":"shape","value":"7f3a91c4"},"owner":null,"acl":null,"proposed_action":"relogin","risk_flags":[]}
```

反例要点：它没有可迁移的文件路径，若按普通配置文件写 L3/`migrate`，换机后会在无报错的情况下带着失效 token 起不来；`file_id`、体积都为 `null` 是合法形态。

### 10.3 反例：L0（体积大不等于要迁）

```json
{"type":"unit","schema_version":"2.0","id":"u_9K8J7H6G5F4D3S2A1Q0W9E8R7T","cid":"c_9K8J7H6G5F4D3S2A1Q0W9E8R7T","path":"C:\\Users\\a\\.claude\\shell-snapshots\\snapshot-bash-1762300000-abc.sh","path_key":"c:\\users\\a\\.claude\\shell-snapshots\\snapshot-bash-1762300000-abc.sh","root":"home","path_semantics":"literal","derived_from":null,"profile":"claude-code","entry":"shell-snapshots","kind":"file","layer":"L0","confidence":0.960,"signals":[{"src":"profile_rule","note":"profile claude-code v2.0 entry shell-snapshots 声明 L0","url":null},{"src":"filesystem_stat","note":"普通文件，逻辑 2,118,402 字节，mtime 与会话启动时间一致","url":null},{"src":"content_match","note":"文件头为 shell 函数导出与环境快照，无用户内容","url":null}],"secret":{"class":"none","hits":[],"hit_count":0,"truncated":false},"size_apparent":2118402,"size_alloc":2121728,"mtime":"2026-11-05T22:13:20.0000000Z","file_id":{"volume_serial":"3A4F-9C21","index":"0x000000000003AA11","reparse_tag":null},"fingerprint":{"algo":"sha256","scope":"full","value":"5e8c0d3b"},"owner":{"kind":"sid","value":"S-1-5-21-1111-2222-3333-1001"},"acl":{"algo":"sha256","value":"ffee0011aa22","entries":4,"truncated":false},"proposed_action":"delete","risk_flags":[]}
```

反例要点：单文件 2 MB，比很多 L3 大；判 L0 的依据是"启动时重建"而非体积。

### 10.4 同一文件的 part 与残留（catch-all）

`part_id` 让同一路径的多个结论共存；残留行只有引擎注入的 `residual` signal，confidence 固定 0.5：

```json
{"type":"unit","schema_version":"2.0","id":"u_4M5N6P7Q8R9S0T1V2W3X4Y5Z6A","cid":null,"path":"C:\\Users\\a\\.claude.json","path_key":"c:\\users\\a\\.claude.json","root":"home","path_semantics":"literal","derived_from":null,"profile":"claude-code","entry":"claude-json","part_id":"project-history","kind":"file","layer":"L3","confidence":0.940,"signals":[{"src":"profile_rule","note":"profile claude-code v2.0 entry claude-json part project-history 声明 L3","url":null}],"secret":{"class":"scan","hits":[],"hit_count":0,"truncated":false},"size_apparent":812,"size_alloc":null,"mtime":"2026-11-10T09:12:00.0000000Z","file_id":{"volume_serial":"3A4F-9C21","index":"0x0000000000003B1C","reparse_tag":null},"fingerprint":{"algo":"sha256","scope":"full","value":"b1e2…"},"proposed_action":"keep","risk_flags":["low_confidence"]}
```

```json
{"type":"unit","schema_version":"2.0","id":"u_8Z9A0B1C2D3E4F5G6H7J8K9M0N","cid":null,"path":"C:\\Users\\a\\.claude\\loose.txt","path_key":"c:\\users\\a\\.claude\\loose.txt","root":"home","path_semantics":"literal","derived_from":null,"profile":"claude-code","entry":"home-residual","kind":"catch-all","layer":"L2","confidence":0.500,"signals":[{"src":"filesystem_stat","note":"未被任何 entry 命中，catch-all 残留","url":null}],"secret":{"class":"scan","hits":[],"hit_count":0,"truncated":false},"size_apparent":14,"size_alloc":4096,"mtime":"2026-11-09T08:00:00.0000000Z","file_id":{"volume_serial":"3A4F-9C21","index":"0x00000000000044D2","reparse_tag":null},"fingerprint":{"algo":"sha256","scope":"full","value":"0f1e…"},"owner":null,"acl":null,"proposed_action":"keep","risk_flags":["low_confidence","residual"]}
```

---

## 11. 校验

`packout verify <out>` 对已落盘 manifest 做结构校验；校验器也用于跨版本回归。分三级：`error` 使 manifest 不可用于报告/导出，`warning` 记录，`--strict` 下转为失败。

| 码 | 级 | 触发条件 |
|---|---|---|
| `E-MAN-001` | error | 分片 1 第 1 行不是 `header` |
| `E-MAN-002` | error | 行不是合法 JSON 或超过 64 KiB |
| `E-MAN-003` | error | `id` 重复 |
| `E-MAN-004` | error | `type` 缺失或未知 |
| `E-MAN-005` | error | 缺必填字段 |
| `E-MAN-006` | error | `id` 不符合 `^u_[0-9A-HJKMNP-TV-Z]{26}$` |
| `E-MAN-007` | error | `path` 非绝对路径且非合法 named-location URI |
| `E-MAN-008` | error | `path` 未规范化（尾分隔符、`.`、`\\?\` 前缀） |
| `E-MAN-009` | error | `path_key` 与 `path` 的折叠结果不一致 |
| `E-MAN-010` | error | `kind` 非法或缺失；`layer`/`proposed_action` 的未知值按 §7 映射，不触发本码 |
| `E-MAN-011` | error | `signals` 为空且 `kind != catch-all` |
| `E-MAN-012` | error | signal 缺 `src` 或缺 `note` |
| `E-MAN-013` | error | `official_docs` signal 缺 `url` |
| `E-MAN-014` | error | `confidence` 越出 [0,1] 或小数位 > 3 |
| `E-MAN-015` | error | `confidence < 0.9` 但 `proposed_action != keep` |
| `E-MAN-016` | error | `secret.class` 为 `restore`/`relogin` 且 `confidence < 0.95` |
| `E-MAN-017` | error | 某字段疑似含明文凭证（见 §11.1） |
| `E-MAN-018` | error | `secret.class` 非 `none` 且 `hits` 非空时某命中缺 `locator` |
| `E-MAN-019` | error | `size_alloc` 为负，或非稀疏文件 `size_alloc < size_apparent × 0.5` |
| `E-MAN-020` | error | `mtime` 非 RFC 3339 纳秒格式 |
| `E-MAN-021` | error | named-location 的 scheme 不在允许集合 |
| `E-MAN-065` | error | `path` 非绝对路径、含 `..`/尾分隔符/`\\?\` 前缀，或 `root: external` 却落在已知 root 内 |
| `E-MAN-022` | error | `reparse_tag` 非空但 `file_id` 缺失 |
| `E-MAN-023` | error | `schema_version` 与 header 不匹配 |
| `E-MAN-024` | error | `proposed_action` 与 `layer` 不相容（见 §11.2） |
| `E-MAN-025` | error | 同一 `(profile, entry, part_id, origin_path_key, file_id)` 出现多次（origin 缺省为空串）；`file_id` 为 null 时用 `(profile, entry, part_id, origin_path_key, path_key)` |
| `E-MAN-026` | error | header 缺 `path_fold_version`，或 `path_key` 与按该版本折叠的结果不符（版本不同降为 `W-MAN-113`） |
| `E-MAN-027` | error | `size_estimated: true` 但 `size_apparent` 为 null，或用在非 named-location/非聚合 Unit |
| `E-MAN-028` | error | `cid` 格式非法，或与 `fingerprint` 重算结果不符 |
| `E-MAN-029` | error | 聚合 Unit 缺 `aggregate_count`、`aggregate_count < 0`、有后代却为 0，或 `size_*` 不是求和 |
| `E-MAN-030` | error | 缺 footer、缺 index，或分片计数与 index 不符；`footer.complete: false` 不触发 |
| `E-MAN-031` | error | 目标目录存在未释放的 `.lock` |
| `E-MAN-040` | error | `manifest_version` 的 MAJOR 高于本工具支持 |
| `E-MAN-041` | error | footer 的 `units` 与实际行数不符 |
| `E-MAN-042` | error | `scan_segment.first_shard` 与父段已封分片数不连续 |
| `E-MAN-043` | error | `inputs.secret_salt_mode` 缺失或非法 |
| `E-MAN-050` | error | `secret_ref` 格式非法或指向不存在的 hit（P1 尚无写出方，缺失不判错） |
| `E-MAN-051` | error | `owner` / `acl` 非 null 但结构或枚举非法 |
| `E-MAN-052` | error | `part_id` 不是该 entry 声明的 part，或 entry 有 parts 却缺 `part_id`（`part_missing` 的单行 entry Unit 与 `uncovered` 行除外） |
| `E-MAN-053` | error | 聚合 Unit 的 `secret.class` 与后代并集不符、`hits` 非空，或 `contains_secret`/`may_contain_secret` 缺字段或与后代重算结果不符 |
| `E-MAN-054` | error | 聚合 Unit 的 `fingerprint.scope != "aggregate"`、缺 `content_match`/`filesystem_stat` signal，或摘要与后代集合不符 |
| `E-MAN-055` | error | catch-all Unit 缺 `residual`/`low_confidence`、`proposed_action != keep`，或 `layer != L2` |
| `E-MAN-056` | error | `side_effects` 含未知值 |
| `E-MAN-057` | error | `needed_by` 中 `rewind`/`statusline`/`resume`/`mcp`/`daemon`/`plugins` 顺序错乱 |
| `E-MAN-058` | error | `path_semantics` 缺失或非法，或 `machine_derived` 缺 `derived_from` / `literal` 的 `derived_from` 非 null |
| `E-MAN-059` | error | `stats.residual` 与 catch-all Unit 行数不符，或 index 缺 `residual` |
| `E-MAN-060` | error | Unit 的 `root` 不在 header `roots[].name` 中 |
| `E-MAN-061` | error | part Unit 的 `size_alloc` 非 null、`fingerprint.scope` 既非 `full` 也非该 part 的 `keys`/`null`，或缺 `file_id` |
| `E-MAN-066` | error | 链接 Unit 的 `link_target` 被绝对化（原为相对形式） |
| `E-MAN-067` | error | `fingerprint.scope: keys` 用在非 `keys-only` 的 Unit/part 上，或 `scope: null` 时 `value` 非 null |
| `E-MAN-068` | error | catch-all Unit 缺少恰好一条引擎注入的 `residual` signal（`src` 为 `filesystem_stat` 且 note 非空），或注入了多条 |
| `E-MAN-069` | error | `origin` 出现在 `literal` Unit 上、`origin_path_key` 与 `origin` 折叠不一致，或两者一有一无 |
| `E-MAN-070` | error | `open_as` 值非法，或 `side_effects: ["shm_created"]` 而 `open_as` 不是 `sqlite-ro` |
| `E-MAN-071` | error | `inputs.options.with_sessions` 不是布尔值，或 `inputs.options.selection` 形状/取值非法 |
| `E-MAN-062` | error | `layer: L0` 且 `needed_by` 非空但缺 `deletion_cost` |
| `E-MAN-063` | error | `companions` 中的后缀也作为独立 Unit 出现，或主文件缺失却有伴生 Unit |
| `E-MAN-064` | error | catch-all Unit 的 `confidence != 0.500` |
| `W-MAN-101` | warning | 未知字段（保留；由 report 层负责显示） |
| `W-MAN-102` | warning | 未知 `risk_flags` / `needed_by` 值（保留） |
| `W-MAN-103` | warning | `signals` 被截断 |
| `W-MAN-110` | warning | `< 0.9` 但缺 `low_confidence` 标记 |
| `W-MAN-111` | warning | 同一路径被多个 profile 命中（按 §5.3 归并，不合并 manifest） |
| `W-MAN-112` | warning | 命中带 `user_override` signal |
| `W-MAN-113` | warning | header 的 `path_fold_version` 与当前构建不同 |
| `W-MAN-114` | warning | `stats.residual > 0`（有未被任何 entry 声明的路径） |
| `W-MAN-115` | warning | `path_semantics: machine_derived` 但缺 `machine_derived_path` |
| `W-MAN-116` | warning | 使用旧 `unversioned_repo`（映射为 `not_versioned`） |
| `W-MAN-117` | warning | catch-all Unit 除引擎注入的 `residual` 外还带其他 signals（允许，但应说明作者为何手写证据；只告警，不判错） |

### 11.1 明文泄漏检测

校验器对下列字段做启发式扫描，命中已知前缀或长度 ≥ 20 的高熵串即 `E-MAN-017`：

- `path`（仅 named-location 的 opaque 部分）
- `notes`
- `signals[].note`
- `hits[].prefix`（仅长度 > 7 时）
- 未知字段的值（按字符串化后）

### 11.2 动作与层相容性

| layer | 允许的 proposed_action |
|---|---|
| L0 | `delete`、`keep` |
| L1 | `reinstall`、`keep` |
| L2 | `template`、`migrate`、`keep` |
| L3 | `migrate`、`keep` |
| L4 | `rebind`、`keep` |
| L5 | `relogin`、`keep` |

`keep` 永远允许。`confidence < 0.9` 时只剩 `keep`。

### 11.3 校验责任表

部分码依赖扫描期上下文，manifest 校验器只能做结构与可重算部分的弱校验。责任划分固定如下（`D-027` 第 6、7 条）：

| 码 | 首要责任 | 校验器的边界 |
|---|---|---|
| `E-MAN-052` / `E-MAN-029` / `E-MAN-053` / `E-MAN-054` | scan / classify 在产出行时按后代集合重算 | 只校验字段存在、类型、枚举、`fingerprint.scope: aggregate` 等结构；后代集合不可得时不做语义重算 |
| `E-MAN-066` | scan 保留磁盘原样 | 只比较 `link_target` 是否仍为相对形式，不验证目标存在或可解析 |
| `E-MAN-050` | export 生成 `secret_ref` | 只校验非空 `secret_ref` 的语法与指向在 `secrets.age` 索引中存在，不解密、不校验内容；P1 无写出方，缺失不判错 |
| `E-MAN-042` | scan 续扫时计算段序号 | 只比较 `first_shard` 与父段 index 的已封分片数；父段缺失时无法判定 |
| `E-MAN-068` | 引擎注入恰一条 `residual` signal | 只校验存在且恰一条；额外 author signal 记 `W-MAN-117`，不另判错 |

---

## 12. 未决问题

本节条目已全部由 `D-011` 裁决，保留编号作索引。

1. **`id` 的稳定性边界**：**已定（D-011 第 1 条）**。新增与路径无关的 `cid` 作第二键，`id` 仍路径派生；跨机关联只用 `cid`，见 §4.2.1。
2. **`path_key` 的 Unicode 代价**：**已定（D-011 第 2 条）**。改用 `x/text/cases` fold，版本钉 `go.mod` 并写入 header，见 §6.3。
3. **scan_salt 与可比较性**：**已定（D-011 第 3 条）**。默认随机；`--stable-salt` 用 `~/.config/packout/salt` 持久值，模式进 header，见 §9 第 3 条。
4. **named-location 的 `size_apparent`**：**已定（D-011 第 4 条）**。默认 `null`，允许估算并置 `size_estimated: true`，见 §6.4。
5. **conflict 时"取更保守者"**：**已定（D-011 第 5 条）**。取层号更高者（L3 压 L0/L1），冲突本身记为独立 signal，见 §5.2。
6. **`secret_ref` 的 hit_id 生成**：**已定（D-011 第 6 条）**。改为 `(cid, locator, 值指纹)` 派生，不再用 `unit_id`，见 §9 第 4 条。
7. **manifest 是否记录 ACL/所有者**：**已定（D-011 第 7 条）**。字段现在就加，可空，见 §4.8。
8. **`aggregated` Unit 的字段形态**：**已定（D-011 第 8 条）**。`size_*` 求和、`file_id` 为 null、新增 `aggregate_count`，见 §4.7。
9. **分片阈值**：**已定（D-011 第 9 条）**。50,000 条 / 64 MiB 标为暂定，实测后定。
10. **未知字段的边界**：**已定（D-011 第 10 条）**。报告必须显示，转义并标注"来自更新版本"，见 §7。
11. **多 profile 同路径**：**已定（D-011 第 11 条）**。取最高层，signals 求并集，报告标出两个 profile 名，见 §5.3。
12. **完整性判定与增量**：**已定（D-011 第 12 条）**。`scan_id` 与分片现在就做成可拼接，见 §2 与 §3.1。
13. **文件内分层**：**已定（D-013 的 M1）**。新增 `part_id`，part Unit 共享 path、独立指纹，见 §4.10。
14. **残留兜底**：**已定（D-014）**。`kind: catch-all`，confidence 固定 0.5，footer 记 `stats.residual`，见 §3.3、§4.1。
15. **路径派生**：**已定（D-013 的 M3）**。新增 `path_semantics` / `derived_from` 与两个 `risk_flags`，见 §4.9。
16. **sqlite 的只读副作用**：**已定（D-015 第 3 条）**。允许 `-shm`，记 `side_effects`，不变式改为"除声明外不变"，见 §4.12 与 §8。
17. **唯一键与大小写碰撞**：**已定（D-015 第 2 条）**。唯一键改为 `(entry, part_id, file_id)`，E-MAN-025 放宽，见 §5.3。
18. **聚合计数口径**：**已定（D-015 第 6、20 条）**。空目录为 0，含子目录，空 glob 留 note，见 §4.7。

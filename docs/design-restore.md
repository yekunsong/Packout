# restore 设计（实现前定稿）

restore 是整个项目第一次往磁盘写用户数据。它比 export 危险，因为写错会覆盖新机上已有的东西。

## 顺序（不可调换）

1. 读 `SIG.json` → `verify`；结论不是 `ok` 且没给 `--allow-unverified` 就停在"预演"阶段。
2. 目标检查：默认必须不存在或为空；`--in-place` 才允许非空，且逐条 diff 后列给用户。
3. 解密 `secrets.age`（需要时）→ 拿到 `ref → 明文` 映射。
4. **干跑**：把每条要写的路径、大小、是新建还是覆盖、来源 Unit id 打成计划。
5. 写：逐条建目录/写文件，`config/` 里的占位符现场替换。
6. 写后复验：回读哈希，不一致即停并记为 `restore_corrupt`。比对的是**占位符已替换后**的字节哈希；SIG 里的包内哈希用于第 1 步，不参与这里（`D-046` 第 1 条）。
7. 报告三段：`restored` / `needs_reinstall` / `needs_relogin`（L5 永不写盘）。

## 不变量

- 解包路径校验复用 `internal/pack/path.go`，不新写。
- 默认不覆盖；覆盖只在 `--in-place` + diff 之后。
- 失败不回滚已写文件（回滚比留下半成品更难判对）。
- 磁盘预算：写前算总字节（按替换后大小），剩余空间 < 1.2 倍即拒绝。
- `--dry-run` 等价于只跑 1–4 步。
- 目标在源目录之内（原地重扫）要检测并提示。

## 落地与 --map

默认落地是角色镜像：`config/<role>/…` → `<into>/<role>/…`（`home` → `<into>/home`，
`repo` → `<into>/repo`，`reinstall/…` → `<into>/reinstall/…`）。`--into` 是状态根，
不是包副本；换机器时它往往不是用户想直接用的目录。

`--map ROLE=PATH`（可重复）把某个角色的落地根改到 `<into>/PATH`：`PATH` 必须是
相对 `--into` 的路径（`"."` 表示 `--into` 本身），绝对路径、盘符、`~` 与含 `..`
的路径一律拒绝。未给 `--map` 的角色仍落 `<into>/ROLE`，不传 `--map` 时行为与
之前逐字节一致。映射在 `buildPlan` 生成 `payload.target` 时完成，因此 diff
（`actionFor`）、回读校验（`verifyReadBack`）、`Within` 越界检查与
`extraTargets` 警告都自动按映射后的路径工作；写入永远发生在 `--into` 之内。

映射不改变任何门禁：目标非空仍要 `--in-place`，diff 非空仍要 `--force`；
`--dry-run` 与 `drill` 只展示映射后的计划、不写盘。结束时报告打印
`落地：home → <绝对路径>，repo → <绝对路径>`，让人知道该把哪些子目录搬到
目标机器。

新机器示例（`--into $HOME` 非空，所以先看 diff）：

```bash
packout restore ./pack --into $HOME --in-place --dry-run --map home=. --map repo=work/proj2
packout restore ./pack --into $HOME --in-place --force  --map home=. --map repo=work/proj2
```

## 报告与退出码

`E-RST-*` 全部映射到退出码 2，除了用法错误（3）与目标非空（4）。
报告必须打印"SIG 结论"与"是否签名"，`--allow-unverified` 时红字标注。

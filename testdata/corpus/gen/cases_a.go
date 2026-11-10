package main

// Registry of every case. Construction and assertions mirror SPEC §7 one to
// one; comments cite the SPEC section where a case needs interpretation.
//
// Credential material is deliberately fake. The only token shape in the whole
// corpus is C02's canary, declared in ../canaries.yaml and mirrored by
// canaryToken so the two cannot drift silently (gen_test checks both and
// corpus.yaml carries the file digest).

const canaryToken = "sk-ant-api03-C0RPUSCANARY0123456789abcdefXY"

const settingsLocal = "{\"permissions\":{\"allow\":[\"Bash(ls)\"]}}\n"
const gitIgnore = "**/.claude/settings.local.json\n/.claude/settings.local.json\n"

func init() {
	register(&Case{
		ID:        "C01-gitignore-unversioned",
		Title:     "全局 gitignore 命中时必须仍报未版本化",
		Set:       "minimal",
		Platforms: []string{"win32", "darwin", "linux"},
		Repos:     []string{"repo-a"},
		Paths: []string{
			"home/.config/git/ignore",
			"home/.claude/settings.local.json",
			"repos/repo-a/.claude/settings.local.json",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.config/git/ignore", gitIgnore); err != nil {
				return err
			}
			if err := x.Write("home/.claude/settings.local.json", settingsLocal); err != nil {
				return err
			}
			return x.Write("repos/repo-a/.claude/settings.local.json", settingsLocal)
		},
		Expect: `# D-015#4: unversioned_repo is asserted under its new name not_versioned.
units:
  - match: "home/.claude/settings.local.json"
    expect:
      entry: settings-local-global
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      secret: {class: scan, hit_count: 0}
      risk_flags: {contains: [gitignored, not_versioned], excludes: [aggregated]}
      proposed_action: {in: [keep, migrate]}
  - match: "repos/repo-a/.claude/settings.local.json"
    expect:
      entry: repo-settings-local
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      secret: {class: scan, hit_count: 0}
      risk_flags: {contains: [gitignored, not_versioned], excludes: [aggregated]}
      proposed_action: {in: [keep, migrate]}
unit_count:
  - {entry: settings-local-global, equals: 1}
  - {entry: repo-settings-local, equals: 1}
absent: ["home/.claude/cache/**"]
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C02-mcp-fake-token",
		Title:     "MCP env 明文 token：两处 hit、同指纹、明文不落盘",
		Set:       "minimal",
		Platforms: []string{"win32", "darwin", "linux"},
		Repos:     []string{"repo-a"},
		Paths:     []string{"home", "repos/repo-a/.mcp.json"},
		Build: func(x *Ctx) error {
			return x.Write("repos/repo-a/.mcp.json",
				`{"mcpServers":{"alpha":{"command":"npx","env":{"TOKEN":"`+canaryToken+`"}},`+
					`"beta":{"command":"npx","env":{"TOKEN":"`+canaryToken+`"}}}}`+"\n")
		},
		Expect: `# Two hits, both locators, identical fingerprint (SPEC §7 C02).
# locators: /mcpServers/alpha/env/TOKEN and /mcpServers/beta/env/TOKEN
units:
  - match: "repos/repo-a/.mcp.json"
    expect:
      entry: repo-mcp-json
      kind: file
      layer: L2
      confidence: {min: 0.950, max: 1.000}
      secret: {class: scan, hit_count: 2, hits_min: 2, hits_max: 2}
      risk_flags: {excludes: [low_confidence]}
      proposed_action: {in: [keep, migrate, template]}
unit_count:
  - {entry: repo-mcp-json, equals: 1}
footer: {complete: true}
exit_code: 0
report:
  guard: command_available
  contains: ["sk-ant-"]
  not_contains: ["` + canaryToken + `"]
`,
	})

	register(&Case{
		ID:        "C03-junction-self-loop",
		Title:     "junction 指回祖先：不下降、不重复计数",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Requires:  []string{"mklink-junction"},
		Repos:     nil,
		Paths:     []string{"home/.claude/cache/loop"},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/cache"); err != nil {
				return err
			}
			return x.linkDir("home/.claude/cache/loop", x.abs("home/.claude/cache"))
		},
		Expect: `# Unit total must not grow with the loop: <= 5 (SPEC §7 C03).
units:
  - match: "home/.claude/cache/loop"
    select: unique
    expect:
      entry: cache-debug-statsig-ide
      kind: dir
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [junction]}
      link_target: {nonempty: true}
      proposed_action: {in: [delete, keep]}
absent: ["home/.claude/cache/loop/loop", "home/.claude/cache/loop/**"]
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C04-symlink-outside-root",
		Title:     "符号链接指向根外：保留相对 target、不递归",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Requires:  []string{"mklink-symlink"},
		Paths: []string{
			"outside/secret-dir/note.txt",
			"home/.claude/cache/to-outside",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("outside/secret-dir/note.txt", "outside data\n"); err != nil {
				return err
			}
			if err := x.Mkdir("home/.claude/cache"); err != nil {
				return err
			}
			// Link lives at home/.claude/cache/to-outside, so three levels up
			// reach the case root (SPEC text says four; measured layout is 3).
			return x.symlinkAny("home/.claude/cache/to-outside", "../../../outside/secret-dir", true)
		},
		Expect: `# link_target must stay relative and verbatim (D-015#7).
units:
  - match: "home/.claude/cache/to-outside"
    expect:
      entry: cache-debug-statsig-ide
      kind: dir
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [symlink, outside_root]}
      link_target: {nonempty: true}
absent: ["outside/secret-dir/note.txt", "outside/**"]
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C05-case-collision-glob",
		Title:     "跨目录仅大小写不同：两个 Unit、path_key 相同",
		Set:       "minimal",
		Platforms: []string{"win32", "darwin", "linux"},
		Paths: []string{
			"home/.claude/projects/Demo/x.jsonl",
			"home/.claude/projects/demo/x.jsonl",
		},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/projects"); err != nil {
				return err
			}
			// A case-insensitive volume would fold the two directories into one,
			// so the fixture makes the parent case-sensitive (same mechanism as
			// C27). Failure is a legitimate skip.
			if err := x.caseSensitive("home/.claude/projects"); err != nil {
				return err
			}
			if err := x.Write("home/.claude/projects/Demo/x.jsonl", `{"type":"user","text":"Demo"}`+"\n"); err != nil {
				return err
			}
			return x.Write("home/.claude/projects/demo/x.jsonl", `{"type":"user","text":"demo"}`+"\n")
		},
		Expect: `# path keeps disk spelling; path_key folds both to the same value (Q2/D-015#2).
units:
  - match: "home/.claude/projects/Demo/x.jsonl"
    expect:
      entry: projects-transcripts
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [case_collision]}
  - match: "home/.claude/projects/demo/x.jsonl"
    expect:
      entry: projects-transcripts
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [case_collision]}
unit_count:
  - {entry: projects-transcripts, equals: 2}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C06-trailing-dot-space",
		Title:     "Win32 尾点 / 尾空格名必须原样保留",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Requires:  []string{"longpath"},
		Paths: []string{
			"home/.claude/cache/trail.",
			"home/.claude/cache/trail ",
			"home/.claude/cache/trail.txt.",
			"home/.claude/cache/lead.txt",
		},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/cache"); err != nil {
				return err
			}
			for _, name := range []string{"trail.", "trail ", "trail.txt."} {
				if err := x.literalFile("home/.claude/cache/"+name, []byte("{}\n"), name); err != nil {
					return err
				}
			}
			if err := x.literalFile("home/.claude/cache/lead.txt", []byte("{}\n"), "lead.txt"); err != nil {
				return err
			}
			// 8.3 alias is not itself asserted; it guards against the name being
			// resolved through a short name.
			x.bestEffortShortName("home/.claude/cache/trail.txt.", "TRAIL~1.")
			return nil
		},
		Expect: `# path must end with each literal name, no \\?\ prefix, four distinct path_keys.
units:
  - match: "home/.claude/cache/trail."
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0}
  - match: "home/.claude/cache/trail "
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0}
  - match: "home/.claude/cache/trail.txt."
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0}
  - match: "home/.claude/cache/lead.txt"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0}
unit_count:
  - {entry: cache-debug-statsig-ide, equals: 4}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C07-long-path-over-240",
		Title:     "240 字符以上路径：long_path、可读、无 \\?\\ 泄漏",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Requires:  []string{"longpath"},
		Paths:     []string{"home/.claude/cache"},
		Build: func(x *Ctx) error {
			rel := "home/.claude/cache"
			for i := 0; i < 24; i++ {
				rel += "/d" + itoa(i)
			}
			if err := x.mkdirLong(rel); err != nil {
				return err
			}
			// Pad the leaf so the absolute path stays >= 260 even under a short
			// temp base; the assertion matches the glob, not a fixed name.
			leaf := "deep-" + repeat("p", 200) + ".jsonl"
			return x.literalFile(rel+"/"+leaf, []byte(`{"type":"user","text":"deep"}`+"\n"), leaf)
		},
		Expect: `# path length >= 260 and < 1000 is checked by the runner's length rule.
units:
  - match: "home/.claude/cache/**/deep-*.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [long_path], excludes: [read_error]}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C08-readonly-file",
		Title:     "只读文件照常扫描且属性不变",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Paths:     []string{"home/.claude/cache/ro.jsonl"},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/cache/ro.jsonl", `{"type":"user","text":"ro"}`+"\n"); err != nil {
				return err
			}
			return x.readonly("home/.claude/cache/ro.jsonl")
		},
		Expect: `units:
  - match: "home/.claude/cache/ro.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      secret: {class: none, hit_count: 0}
      risk_flags: {excludes: [read_error]}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C09-occupied-file",
		Title:     "共享锁可读；独占锁记 read_error 但不中止",
		Set:       "minimal",
		Platforms: []string{"win32"},
		Paths: []string{
			"home/.claude/cache/shared.jsonl",
			"home/.claude/cache/exclusive.jsonl",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/cache/shared.jsonl", `{"type":"user","text":"shared"}`+"\n"); err != nil {
				return err
			}
			return x.Write("home/.claude/cache/exclusive.jsonl", `{"type":"user","text":"exclusive"}`+"\n")
		},
		Expect: `# Runner must hold the handles: shared with FileShare.ReadWrite,
# exclusive with FileShare.None (SPEC §7 C09). Q5/D-015#5: complete + exit 0.
units:
  - match: "home/.claude/cache/shared.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {excludes: [read_error]}
  - match: "home/.claude/cache/exclusive.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {contains: [read_error]}
      fingerprint: {value: null}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C10-archived-unique-claude-md",
		Title:     "归档仓库里唯一的 CLAUDE.md：唯一命中升 L3",
		Set:       "minimal",
		Platforms: []string{"win32", "darwin", "linux"},
		Repos:     []string{"archive-old"},
		Paths:     []string{"home", "repos/archive-old/CLAUDE.md"},
		Build: func(x *Ctx) error {
			return x.Write("repos/archive-old/CLAUDE.md", "# archive rules\n")
		},
		Expect: `units:
  - match: "repos/archive-old/CLAUDE.md"
    expect:
      entry: repo-claude-md
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [not_versioned], excludes: [low_confidence, git_tracked, aggregated]}
      signals: {contains_src: [profile_rule]}
      proposed_action: {in: [keep, migrate]}
unit_count:
  - {entry: repo-claude-md, equals: 1}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C11-empty-dir-empty-glob",
		Title:     "空目录聚合 Unit；空 glob 零 Unit 不报错",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Paths: []string{
			"home/.claude/todos",
			"home/.claude/todos/empty",
			"home/.claude/projects",
		},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/todos/empty"); err != nil {
				return err
			}
			return x.Mkdir("home/.claude/projects")
		},
		Expect: `# D-015#6: empty dir aggregate_count is 0 (SPEC §7 says >= 1); an empty
# glob must leave a note.
units:
  - match: "home/.claude/todos"
    expect:
      entry: todos
      kind: dir
      layer: L0
      risk_flags: {contains: [aggregated]}
      aggregate_count: {min: 0}
      proposed_action: {in: [delete, keep]}
unit_count:
  - {entry: projects-transcripts, equals: 0}
absent: ["home/.claude/projects/**"]
notes: {code: empty_glob, present: true}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C12-sparse-file",
		Title:     "真稀疏文件：apparent 1 GiB、alloc <= 4096、flag sparse",
		Set:       "full",
		Platforms: []string{"win32", "linux"},
		Requires:  []string{"sparse"},
		Paths:     []string{"home/.claude/cache/sparse.bin"},
		Build: func(x *Ctx) error {
			return x.sparse("home/.claude/cache/sparse.bin", 1<<30)
		},
		Expect: `units:
  - match: "home/.claude/cache/sparse.bin"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      size_apparent: {equals: 1073741824}
      size_alloc: {max: 4096}
      risk_flags: {contains: [sparse]}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C13-binary",
		Title:     "64 KiB 二进制：不按 UTF-8 失败、不误报密",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Paths:     []string{"home/.claude/cache/blob.bin"},
		Build: func(x *Ctx) error {
			b := make([]byte, 64<<10)
			for i := range b {
				b[i] = byte(i)
			}
			return x.WriteBytes("home/.claude/cache/blob.bin", b)
		},
		Expect: `# Fingerprint over the whole file; no template; fields_absent secret_ref.
units:
  - match: "home/.claude/cache/blob.bin"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      secret: {class: none, hit_count: 0}
      fingerprint: {scope: full, value: {nonempty: true}}
      risk_flags: {excludes: [read_error, content_partial]}
    fields_absent: [secret_ref]
footer: {complete: true}
exit_code: 0
`,
	})
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func init() {
	register(&Case{
		ID:        "C14-sqlite-wal",
		Title:     "未 checkpoint 的 WAL 是持久状态，db 与 wal 都是 Unit",
		Set:       "full",
		Platforms: []string{"win32", "linux"},
		Requires:  []string{"sqlite3"},
		Paths: []string{
			"home/.claude/cache/state.db",
			"home/.claude/cache/state.db-wal",
		},
		AllowNew:        []string{"home/.claude/cache/state.db-shm"},
		AllowDirMtime:   []string{"home/.claude/cache"},
		VolatileContent: true,
		Build:           buildSQLiteWAL,
		Expect: `# open_as: sqlite-ro may create -shm; that directory mtime is exempt (D-015#3).
units:
  - match: "home/.claude/cache/state.db"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {excludes: [read_error]}
      fingerprint: {value: {nonempty: true}}
  - match: "home/.claude/cache/state.db-wal"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {excludes: [read_error]}
notes: {code: wal_is_persistent_state, present: true}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C15-placeholder",
		Title:     "云占位符（OFFLINE|RECALL_ON_DATA_ACCESS）：不水合、fingerprint null",
		Set:       "full",
		Platforms: []string{"win32"},
		Requires:  []string{"fsutil"},
		Paths:     []string{"home/.claude/cache/placeholder.jsonl"},
		Build: func(x *Ctx) error {
			if err := x.sparse("home/.claude/cache/placeholder.jsonl", 1<<20); err != nil {
				return err
			}
			return x.recallAttrs("home/.claude/cache/placeholder.jsonl")
		},
		Expect: `# Q7/D-015#7: fingerprint must be null and content_partial allowed.
units:
  - match: "home/.claude/cache/placeholder.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [cloud_placeholder]}
      fingerprint: {value: null}
      proposed_action: {in: [keep, delete]}
allow_new: []
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C16-multi-repo-settings",
		Title:     "两个仓库同 entry 命中：L2 不升 L3；home 副本独立 L3",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Repos:     []string{"repo-a", "repo-b"},
		Paths: []string{
			"home/.config/git/ignore",
			"home/.claude/settings.local.json",
			"repos/repo-a/.claude/settings.local.json",
			"repos/repo-b/.claude/settings.local.json",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.config/git/ignore", gitIgnore); err != nil {
				return err
			}
			if err := x.Write("home/.claude/settings.local.json", settingsLocal); err != nil {
				return err
			}
			if err := x.Write("repos/repo-a/.claude/settings.local.json",
				"{\"permissions\":{\"allow\":[\"Bash(git status)\"]}}\n"); err != nil {
				return err
			}
			return x.Write("repos/repo-b/.claude/settings.local.json",
				"{\"permissions\":{\"allow\":[\"Bash(go test)\"]}}\n")
		},
		Expect: `# uniqueness is counted per entry across all roots (D-015#10, D-021#2).
units:
  - match: "repos/repo-a/.claude/settings.local.json"
    expect:
      entry: repo-settings-local
      kind: file
      layer: L2
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [gitignored, not_versioned]}
    fields_absent: [low_confidence]
  - match: "repos/repo-b/.claude/settings.local.json"
    expect:
      entry: repo-settings-local
      kind: file
      layer: L2
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [gitignored, not_versioned]}
    fields_absent: [low_confidence]
  - match: "home/.claude/settings.local.json"
    expect:
      entry: settings-local-global
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [gitignored, not_versioned]}
unit_count:
  - {entry: repo-settings-local, equals: 2}
  - {entry: settings-local-global, equals: 1}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C17-unique-promotion",
		Title:     "两个不同 entry 各自唯一命中，各自升 L3",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Repos:     []string{"repo-a"},
		Paths: []string{
			"home/.claude/settings.local.json",
			"repos/repo-a/.claude/settings.local.json",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/settings.local.json", settingsLocal); err != nil {
				return err
			}
			return x.Write("repos/repo-a/.claude/settings.local.json",
				"{\"permissions\":{\"allow\":[\"Bash(git log)\"]}}\n")
		},
		Expect: `# Different entries do not dilute each other's uniqueness (D-015#10).
units:
  - match: "home/.claude/settings.local.json"
    expect:
      entry: settings-local-global
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [gitignored]}
      signals: {contains_src: [profile_rule]}
    fields_absent: [low_confidence]
  - match: "repos/repo-a/.claude/settings.local.json"
    expect:
      entry: repo-settings-local
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [gitignored]}
      signals: {contains_src: [profile_rule]}
    fields_absent: [low_confidence]
unit_count:
  - {entry: settings-local-global, equals: 1}
  - {entry: repo-settings-local, equals: 1}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C18-mixed-layer-plugins",
		Title:     "插件清单同目录：installed 可再生、enabled 用户维护",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Paths: []string{
			"home/.claude/plugins/installed_plugins.json",
			"home/.claude/plugins/enabled_plugins.json",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/plugins/installed_plugins.json", "{\"plugins\":[]}\n"); err != nil {
				return err
			}
			return x.Write("home/.claude/plugins/enabled_plugins.json",
				"{\"enabledPlugins\":{\"demo@marketplace\":true}}\n")
		},
		Expect: `# D-015#8: both are L2 under the builtin entry plugins-enabled; SPEC's
# older "plugins"/L1 wording is superseded. enabled_plugins must additionally
# carry evidence that it is user-maintained (signal or note).
units:
  - match: "home/.claude/plugins/installed_plugins.json"
    expect:
      entry: plugins-enabled
      kind: file
      layer: L2
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {excludes: [aggregated]}
      proposed_action: {in: [reinstall, keep, delete]}
  - match: "home/.claude/plugins/enabled_plugins.json"
    expect:
      entry: plugins-enabled
      kind: file
      layer: L2
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {excludes: [aggregated]}
      signals: {contains_src: [profile_rule]}
unit_count:
  - {entry: plugins-enabled, equals: 2}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C19-path-derived-slug",
		Title:     "斜杠编码派生 slug：--evil 不被前缀吞并、id 稳定",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Paths: []string{
			"home/.claude/projects/D--Study-packout/x.jsonl",
			"home/.claude/projects/D--Study-packout--evil/x.jsonl",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/projects/D--Study-packout/x.jsonl",
				`{"type":"user","text":"plain"}`+"\n"); err != nil {
				return err
			}
			return x.Write("home/.claude/projects/D--Study-packout--evil/x.jsonl",
				`{"type":"user","text":"evil"}`+"\n")
		},
		Expect: `units:
  - match: "home/.claude/projects/D--Study-packout/x.jsonl"
    expect:
      entry: projects-transcripts
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
  - match: "home/.claude/projects/D--Study-packout--evil/x.jsonl"
    expect:
      entry: projects-transcripts
      kind: file
      layer: L3
      confidence: {min: 0.900, max: 1.000}
unit_count:
  - {entry: projects-transcripts, equals: 2}
rerun_id_stable: true
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C20-hardlink",
		Title:     "硬链接两份路径同一 file_id，不得重复计体积",
		Set:       "full",
		Platforms: []string{"win32", "linux"},
		Paths: []string{
			"home/.claude/cache/hard-a.log",
			"home/.claude/cache/hard-b.log",
		},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/cache/hard-a.log", "hello\n"); err != nil {
				return err
			}
			return x.hardlink("home/.claude/cache/hard-b.log", "home/.claude/cache/hard-a.log")
		},
		Expect: `# file_id.index must be equal for both units; link_target is not used
# for hard links.
units:
  - match: "home/.claude/cache/hard-a.log"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {contains: [hardlink_multi]}
      file_id: {index_equal: true}
      size_apparent: {equals: 6}
  - match: "home/.claude/cache/hard-b.log"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {contains: [hardlink_multi]}
      file_id: {index_equal: true}
      size_apparent: {equals: 6}
unit_count:
  - {entry: cache-debug-statsig-ide, equals: 2}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C21-ads-stream",
		Title:     "NTFS 备用数据流：主 Unit + note，不把 :meta 当路径",
		Set:       "full",
		Platforms: []string{"win32"},
		Paths:     []string{"home/.claude/cache/ads.jsonl"},
		Build: func(x *Ctx) error {
			if err := x.Write("home/.claude/cache/ads.jsonl", "{}\n"); err != nil {
				return err
			}
			return x.ads("home/.claude/cache/ads.jsonl", "meta", "x")
		},
		Expect: `# D-015#9: ADS is a note, never its own unit.
units:
  - match: "home/.claude/cache/ads.jsonl"
    expect:
      entry: cache-debug-statsig-ide
      kind: file
      layer: L0
      risk_flags: {excludes: [read_error]}
notes: {code: ads_stream_present, present: true}
absent: ["home/.claude/cache/ads.jsonl:meta"]
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:           "C22-huge-jsonl-4g",
		Title:        "4 GiB 单文件：head-tail 指纹、流式、不 OOM",
		Set:          "full",
		Platforms:    []string{"win32", "darwin", "linux"},
		Big:          true,
		BudgetWallMS: 300000,
		BudgetRSSMiB: 256,
		Paths:        []string{"home/.claude/projects/D--Study-packout/huge.jsonl"},
		Build:        buildHuge,
		Expect: `# size_apparent >= 4 GiB. RSS ceiling is 268435456 bytes.
units:
  - match: "home/.claude/projects/D--Study-packout/huge.jsonl"
    expect:
      entry: projects-transcripts
      kind: file
      layer: L3
      size_apparent: {min: 4294967296}
      fingerprint: {scope: head-tail}
      secret: {class: none, hit_count: 0}
      risk_flags: {contains: [oversized, content_partial]}
      proposed_action: {in: [keep, migrate]}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:           "C23-path-over-32767",
		Title:        "Win32 超长路径：note path_too_long 或 long_path Unit",
		Set:          "full",
		Platforms:    []string{"win32"},
		Requires:     []string{"longpath"},
		BudgetWallMS: 30000,
		Paths:        []string{"home/.claude/cache"},
		Build:        buildOver32767,
		Expect: `# Absolute path is padded to 32750 chars so it is at the Win32 ceiling.
either:
  - {unit: {match: "home/.claude/cache/**/leaf*.jsonl", expect: {risk_flags: {contains: [long_path], excludes: [read_error]}}}}
  - {note: {code: path_too_long, present: true}}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C24-package-traversal",
		Title:     "包内路径规范化表（verify，deferred）",
		Set:       "full",
		Platforms: []string{"win32", "darwin", "linux"},
		Deferred:  []string{"verify"},
		Paths:     []string{"home", "package/entries.tsv"},
		Build:     buildEntriesTSV,
		Expect: `# Verify lands first; every row is checked against verify exit code.
# Columns: entry_path <TAB> A|R <TAB> normalized.
deferred: [verify]
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C25-reserved-names",
		Title:     "保留名 CON / NUL.txt / aux / COM1.log 按普通文件处理",
		Set:       "full",
		Platforms: []string{"win32"},
		Requires:  []string{"longpath"},
		Paths: []string{
			"home/.claude/cache/CON",
			"home/.claude/cache/NUL.txt",
			"home/.claude/cache/aux",
			"home/.claude/cache/COM1.log",
		},
		Build: func(x *Ctx) error {
			for _, n := range []string{"CON", "NUL.txt", "aux", "COM1.log"} {
				want := []byte("name=" + n + "\n")
				if err := x.literalFile("home/.claude/cache/"+n, want, n); err != nil {
					return err
				}
				got, err := os.ReadFile(hostPath(x.P("home/.claude/cache/" + n)))
				if err != nil {
					return err
				}
				if string(got) != string(want) {
					return fmt.Errorf("read back %s: got %q want %q", n, got, want)
				}
			}
			return nil
		},
		Expect: `units:
  - match: "home/.claude/cache/CON"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {excludes: [read_error]}}
  - match: "home/.claude/cache/NUL.txt"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {excludes: [read_error]}}
  - match: "home/.claude/cache/aux"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {excludes: [read_error]}}
  - match: "home/.claude/cache/COM1.log"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {excludes: [read_error]}}
unit_count:
  - {entry: cache-debug-statsig-ide, equals: 4}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:           "C26-junction-mutual-cycle-follow",
		Title:        "junction 互相成环 + follow：有界、symlink_cycle",
		Set:          "full",
		Platforms:    []string{"win32"},
		Requires:     []string{"mklink-junction"},
		BudgetWallMS: 5000,
		Paths:        []string{"home/.claude/cache/A", "home/.claude/cache/B"},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/cache"); err != nil {
				return err
			}
			if err := x.linkDir("home/.claude/cache/A", x.abs("home/.claude/cache/B")); err != nil {
				return err
			}
			return x.linkDir("home/.claude/cache/B", x.abs("home/.claude/cache/A"))
		},
		Expect: `# Unit total <= 4 and wall <= 5000 ms; at least one unit carries
# symlink_cycle (SPEC §7 C26).
units:
  - match: "home/.claude/cache/A"
    expect:
      entry: cache-debug-statsig-ide
      kind: dir
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [junction]}
  - match: "home/.claude/cache/B"
    expect:
      entry: cache-debug-statsig-ide
      kind: dir
      layer: L0
      confidence: {min: 0.900, max: 1.000}
      risk_flags: {contains: [junction]}
units_any:
  - {match: "home/.claude/cache/*", expect: {risk_flags: {contains: [symlink_cycle]}}}
footer: {complete: true}
exit_code: 0
`,
	})

	register(&Case{
		ID:        "C27-same-dir-case-collision",
		Title:     "同一大小写敏感目录内 Case.txt 与 case.txt 并存",
		Set:       "full",
		Platforms: []string{"win32"},
		Requires:  []string{"fsutil-case"},
		Paths: []string{
			"home/.claude/cache/casedir/Case.txt",
			"home/.claude/cache/casedir/case.txt",
		},
		Build: func(x *Ctx) error {
			if err := x.Mkdir("home/.claude/cache/casedir"); err != nil {
				return err
			}
			if err := x.caseSensitive("home/.claude/cache/casedir"); err != nil {
				return err
			}
			if err := x.literalFile("home/.claude/cache/casedir/Case.txt", []byte("upper\n"), "Case.txt"); err != nil {
				return err
			}
			return x.literalFile("home/.claude/cache/casedir/case.txt", []byte("lower\n"), "case.txt")
		},
		Expect: `units:
  - match: "home/.claude/cache/casedir/Case.txt"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {contains: [case_collision]}}
  - match: "home/.claude/cache/casedir/case.txt"
    expect: {entry: cache-debug-statsig-ide, kind: file, layer: L0, risk_flags: {contains: [case_collision]}}
unit_count:
  - {entry: cache-debug-statsig-ide, equals: 2}
footer: {complete: true}
exit_code: 0
`,
	})
}

// buildSQLiteWAL writes 200 deterministic rows with autocheckpoint off and
// copies db/wal/shm out while the connection is still open (SPEC §9.7).
func buildSQLiteWAL(x *Ctx) error {
	if err := requireSQLite(); err != nil {
		return err
	}
	if err := x.Mkdir("home/.claude/cache"); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "corpus-sqlite-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	dbPath := filepath.Join(work, "state.db")
	dstDir := x.P("home/.claude/cache")

	var script strings.Builder
	script.WriteString("PRAGMA journal_mode=WAL;\nPRAGMA wal_autocheckpoint=0;\nCREATE TABLE t(x);\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&script, "INSERT INTO t VALUES('row-%03d');\n", i)
	}
	names := []string{"state.db", "state.db-wal", "state.db-shm"}
	for _, n := range names {
		dst, err := filepath.Rel(work, filepath.Join(dstDir, n))
		if err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			// sqlite .system does not survive quoted arguments here.
			fmt.Fprintf(&script, ".system cmd /c copy /b /y %s %s\n", n, dst)
		} else {
			fmt.Fprintf(&script, ".shell cp %s %s\n", n, dst)
		}
	}
	script.WriteString(".quit\n")

	cmd := exec.Command("sqlite3", dbPath)
	cmd.Dir = work
	cmd.Stdin = strings.NewReader(script.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sqlite3: %v: %s", err, strings.TrimSpace(string(out)))
	}
	wal, err := os.Stat(filepath.Join(dstDir, "state.db-wal"))
	if err != nil {
		return fmt.Errorf("wal not produced: %w", err)
	}
	if wal.Size() == 0 {
		return fmt.Errorf("wal is empty")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "state.db-shm")); err == nil {
		x.Exp("home/.claude/cache/state.db-shm")
	}
	return nil
}

func buildHuge(x *Ctx) error {
	const target = int64(4) << 30
	line := []byte(`{"type":"user","text":"0123456789abcdef"}` + "\n")
	rel := "home/.claude/projects/D--Study-packout/huge.jsonl"
	x.record(rel)
	abs := x.P(rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	f, err := os.Create(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 0, 1<<20)
	for int64(len(buf))+int64(len(line)) <= 1<<20 {
		buf = append(buf, line...)
	}
	var written int64
	for written < target {
		n := len(buf)
		if rem := target - written; int64(n) > rem {
			n = int(rem)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += int64(n)
		// Write whole lines only: trim the last partial line and resend it.
		if int64(n) < int64(len(buf)) {
			break
		}
	}
	// Finish the line if the target landed mid-line.
	for written%int64(len(line)) != 0 {
		want := int64(len(line)) - written%int64(len(line))
		if _, err := f.Write(line[:want]); err != nil {
			return err
		}
		written += want
	}
	return nil
}

func buildOver32767(x *Ctx) error {
	const target = 32750
	const levels = 130
	const compLen = 250
	if err := x.Mkdir("home/.claude/cache"); err != nil {
		return err
	}
	base := x.abs("home/.claude/cache")
	fixed := len(base) + 1 + levels*(compLen+1) + 1
	leafLen := target - fixed
	if leafLen > 255 {
		leafLen = 255
	}
	if leafLen < 12 {
		return fmt.Errorf("base path too long: %d", len(base))
	}
	leaf := "leaf" + repeat("x", leafLen-9) + ".jsonl"
	rel := "home/.claude/cache"
	for i := 0; i < levels; i++ {
		rel += "/" + fmt.Sprintf("d%03d", i) + repeat("y", compLen-4)
	}
	if err := x.mkdirLong(rel); err != nil {
		return err
	}
	full := x.abs(rel + "/" + leaf)
	if len(full) > 32767 || len(full) < target-10 {
		return fmt.Errorf("path length %d out of range", len(full))
	}
	return x.literalFile(rel+"/"+leaf, []byte(`{"type":"user","text":"deep"}`+"\n"), leaf)
}

func buildEntriesTSV(x *Ctx) error {
	rows := [][3]string{
		{"../../etc/passwd", "A", "../../etc/passwd"},
		{"/abs/rooted", "A", "/abs/rooted"},
		{`C:\Windows\x`, "A", `C:\Windows\x`},
		{"C:/Users/x", "A", `C:\Users\x`},
		{"//server/share/file", "A", `\\server\share\file`},
		{"a/./b//c/../d", "A", "a/b/d"},
		{"////home/u/x", "A", "home/u/x"},
		{"foo/", "A", "foo"},
		{"C:foo", "R", "盘符相对，拒绝"},
		{"CON", "A", "CON"},
		{"NUL.txt", "A", "NUL.txt"},
		{"a.txt.", "A", "a.txt."},
		{"a.txt ", "A", "a.txt"},
		{"a.txt:stream", "A", "a.txt:stream"},
		{"~/x", "R", "未展开，拒绝"},
		{`..\..\x`, "A", `..\..\x`},
		{"a/..", "A", "."},
		{"", "R", ""},
		{".", "R", ""},
		{`\?\C:\x`, "A", `C:\x`},
	}
	x.record("package/entries.tsv")
	if err := os.MkdirAll(x.P("package"), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(tsvField(r[0]))
		b.WriteByte('\t')
		b.WriteString(tsvField(r[1]))
		b.WriteByte('\t')
		b.WriteString(tsvField(r[2]))
		b.WriteByte('\n')
	}
	return os.WriteFile(x.P("package/entries.tsv"), []byte(b.String()), 0o644)
}

// tsvField quotes per SPEC §7 C24: fields with surrounding whitespace (or
// tabs/quotes) are double-quoted, as encoding/csv would read them back.
func tsvField(s string) string {
	need := strings.ContainsAny(s, "\t\r\n\"") ||
		strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ")
	if !need {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

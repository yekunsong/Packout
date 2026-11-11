# profile 规格 v2.0（二）：内置 profile

状态：草案。适用于 `packout` P0。相关决策：D-010、D-013–D-017、D-024、D-028。本章为完整规格的第 8 章；模型与字段见 `docs/spec-profile-model.md`（§1–§7），校验与 CLI 见 `docs/spec-profile-validation.md`（§9–§12）。

---

## 8. 内置 profile

内置 profile 用 `go:embed` 编入，运行期不可写；用户同名 profile 整体覆盖内置（不合并），覆盖时 warning `W-PRF-120`。内置清单：

| name | 状态 |
|---|---|
| `claude-code` | v2.0 |
| `codex` | v2.0 |
| `cursor` | 计划中，未随 P0 发布 |
| `continue` | 计划中，未随 P0 发布 |

内置 profile 的 `selftest.fixtures` 目录与 profile 一起分发（源码树内 `profiles/fixtures/<name>/…`，构建时与 profile 一并 `go:embed`），fixture 内容不内嵌在 JSONC 里（`D-017`）。下文 §8.1 / §8.2 的 JSONC 块即 `profiles/claude-code.jsonc` 与 `profiles/codex.jsonc` 的逐字节内容；两者必须同步修改，`profiles/fixtures/README.md` 记录对应的 fixture。`backups` 的 `expect.match` 已按 `D-028` 第 1 条在本文档改为 `.claude/backups/.*`，`profiles/claude-code.jsonc` 需同步该行。

凡路径未经本机或文档双重确认处，行尾标 `// TODO verify`。凭据库的精确名称（Windows 凭据管理器目标名、Linux `.credentials.json`）发布前必须本机核实，未核实的不许留在内置 profile（`D-010` 第 3 条）。带签名的 profile 包放 P1；P0 内置 profile 随二进制、不自带签名（`D-010` 第 6、11 条）。

### 8.1 claude-code

```jsonc
{
  "schema_version": "2.0",
  "name": "claude-code",
  "title": "Claude Code",
  "vendor": "Anthropic",
  "applies_to": {
    "os": [
      "windows",
      "darwin",
      "linux"
    ]
  },
  "roots": {
    "home": {
      "windows": "%USERPROFILE%",
      "darwin": "$HOME",
      "linux": "$HOME"
    },
    "appdata": {
      "windows": "%APPDATA%",
      "darwin": "$HOME/Library/Application Support",
      "linux": "${XDG_CONFIG_HOME:-$HOME/.config}"
    },
    "localappdata": {
      "windows": "%LOCALAPPDATA%",
      "darwin": "$HOME/Library/Caches",
      "linux": "${XDG_CACHE_HOME:-$HOME/.cache}"
    },
    "repo": "${REPO_ROOT}"
  },
  "defaults": {
    "expand": "per-file",
    "max_depth": 32
  },
  "max_bytes_total": 274877906944,
  "entries": [
    {
      "id": "settings-global",
      "kind": "file",
      "root": "home",
      "path": ".claude/settings.json",
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "official_docs",
          "note": "全局用户设置，含 env 与权限配置",
          "url": "https://code.claude.com/docs/en/settings"
        }
      ]
    },
    {
      "id": "settings-backups",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/settings.json.*"
      ],
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "settings.json 的手工备份与写入临时文件，与主文件同构"
        }
      ]
    },
    {
      "id": "settings-local-global",
      "kind": "file",
      "root": "home",
      "path": ".claude/settings.local.json",  // 本机不存在
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "unique_within": "root",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "Claude Code 首次写入时自动加入全局 gitignore；实测 ~/.config/git/ignore 首行为 **/.claude/settings.local.json"
        }
      ]
    },
    {
      "id": "claude-json",
      "kind": "file",
      "root": "home",
      "path": ".claude.json",
      "layer": "L2",
      "secret": "none",
      "extractor": "keys-only",
      "churn": "high",
      "max_bytes_inline": 0,
      "max_bytes_structure": 1048576,
      "max_bytes_total": 2097152,
      "priority": 30,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "顶层混合状态文件，约 4–10 分钟整体重写一次；按 parts 分派层；其余 40+ 键由 uncovered 兜底"
        }
      ],
      "parts_uncovered": "keep",
      "parts": [
        {
          "id": "machine-identity",
          "selector": {
            "json_pointer": "/machineID"
          },
          "layer": "L4",
          "secret": "none",
          "extractor": "digest",
          "needed_by": [
            "daemon"
          ]
        },
        {
          "id": "user-identity",
          "selector": {
            "json_pointer": "/userID"
          },
          "layer": "L4",
          "secret": "none",
          "extractor": "digest"
        },
        {
          "id": "project-index",
          "selector": {
            "json_pointer": "/projects"
          },
          "layer": "L4",
          "secret": "none",
          "extractor": "keys-only",
          "path_semantics": "machine_derived",
          "derived_from": "json_path_key",
          "notes": "43 个绝对路径键；每键产出 origin，供 slug 目录反查；本机 0/43 含 history"
        },
        {
          "id": "project-history",
          "selector": {
            "json_pointer": "/projects/*/history"
          },
          "layer": "L3",
          "secret": "scan",
          "extractor": "template",
          "max_bytes_inline": 65536,
          "redact": {
            "key_pattern": [
              "(?i).*(token|secret|password|api[_-]?key).*"
            ]
          }
        },
        {
          "id": "mcp-servers",
          "selector": {
            "json_pointer": "/mcpServers"
          },
          "layer": "L2",
          "secret": "scan",
          "extractor": "template",
          "max_bytes_inline": 65536,
          "redact": {
            "key_pattern": [
              "(?i).*(token|secret|password|api[_-]?key).*"
            ]
          }
        }
      ]
    },
    {
      "id": "projects-transcripts",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/projects/**/*.jsonl"
      ],
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "sessions": true,
      "opaque_content": true,
      "max_bytes_inline": 0,
      "max_bytes_total": 2147483648,
      "path_semantics": "machine_derived",
      "derived_from": "repo_slug",
      "priority": 10,
      "signals": [
        {
          "src": "official_docs",
          "note": "会话 transcript 以 JSONL 逐条追加，记录读过的全部内容",
          "url": "https://code.claude.com/docs/en/memory"
        },
        {
          "src": "observed_behavior",
          "note": "本机 projects 目录 4.8 GB，单文件最大 86 MB"
        }
      ]
    },
    {
      "id": "projects-tool-results",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/projects/**/tool-results/**"
      ],
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "sessions": true,
      "opaque_content": true,
      "max_bytes_inline": 0,
      "max_bytes_total": 536870912,
      "path_semantics": "machine_derived",
      "derived_from": "repo_slug",
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "webfetch/tool-result 的 PDF 与文本附件，transcript 的 tool_result 引用指向它们，删后 /resume 回放缺内容"
        }
      ]
    },
    {
      "id": "projects-subagents",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/projects/**/subagents/**/*.jsonl"
      ],
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "sessions": true,
      "max_bytes_inline": 65536,
      "path_semantics": "machine_derived",
      "derived_from": "repo_slug",
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "子代理会话记录，与主 transcript 同属会话状态"
        }
      ]
    },
    {
      "id": "projects-memory",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/projects/**/memory/**"
      ],
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "priority": 15,
      "path_semantics": "machine_derived",
      "derived_from": "repo_slug",
      "max_bytes_inline": 262144,
      "max_bytes_total": 268435456,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "Claude Code 记忆文件，按项目 slug 存放，是唯一不可再生的长期记忆"
        }
      ]
    },
    {
      "id": "history",
      "kind": "file",
      "root": "home",
      "path": ".claude/history.jsonl",
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "priority": 10,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "用户输入历史，明文"
        }
      ]
    },
    {
      "id": "todos",
      "kind": "dir",
      "root": "home",
      "path": ".claude/todos",  // 本机不存在
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "会话级待办快照，可随会话重建"
        }
      ]
    },
    {
      "id": "shell-snapshots",
      "kind": "dir",
      "root": "home",
      "path": ".claude/shell-snapshots",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "shell 快照，启动时重新生成"
        }
      ]
    },
    {
      "id": "cache-debug-statsig-ide",
      "kind": "glob-group",
      "root": "home",
      "paths": [  // statsig、ide 本机不存在
        ".claude/cache/**",
        ".claude/debug/**",
        ".claude/statsig/**",
        ".claude/ide/**"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "priority": 5,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "缓存、调试日志、特性开关缓存与 IDE 锁文件，均可再生"
        }
      ]
    },
    {
      "id": "global-claude-md",
      "kind": "file",
      "root": "home",
      "path": ".claude/CLAUDE.md",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "unique_within": "root",
      "priority": 10,
      "signals": [
        {
          "src": "official_docs",
          "note": "全局用户级记忆/规则文件",
          "url": "https://code.claude.com/docs/en/memory"
        }
      ]
    },
    {
      "id": "skills",
      "kind": "dir",
      "root": "home",
      "path": ".claude/skills",  // 本机不存在
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "official_docs",
          "note": "用户自定义 skill，多为手写且无上游",
          "url": "https://code.claude.com/docs/en/skills"
        }
      ]
    },
    {
      "id": "agents",
      "kind": "dir",
      "root": "home",
      "path": ".claude/agents",
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "用户级子代理定义，手写且无上游；本机 3 个"
        }
      ]
    },
    {
      "id": "plugins-readme",
      "kind": "file",
      "root": "home",
      "path": ".claude/plugins/README.md",
      "layer": "L1",
      "secret": "none",
      "extractor": "raw-ref",
      "priority": 1,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件目录说明；不再设整目录条目，未列出的插件文件交给 home 的 .claude catch-all"
        }
      ]
    },
    {
      "id": "plugins-known-marketplaces",
      "kind": "file",
      "root": "home",
      "path": ".claude/plugins/known_marketplaces.json",
      "layer": "L2",
      "secret": "none",
      "extractor": "keys-only",
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "已登记 marketplace 列表，528 B；重装可由清单重建但需重加来源"
        }
      ]
    },
    {
      "id": "plugins-directory-cache",
      "kind": "file",
      "root": "home",
      "path": ".claude/plugins/plugin-directory-cache-v2.json",
      "layer": "L0",
      "secret": "none",
      "extractor": "keys-only",
      "max_bytes_inline": 0,
      "max_bytes_structure": 4194304,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "marketplace 目录索引缓存，本机 2,754,173 B，可重新拉取"
        }
      ]
    },
    {
      "id": "plugins-heartbeat",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/*/heartbeat.json",
        ".claude/plugins/*/heartbeat.json.*"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "priority": 5,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件守护进程心跳；本机 28 个 heartbeat.json.<pid>.tmp"
        }
      ]
    },
    {
      "id": "plugins-stripped",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/*/stripped/**"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件代码的裁剪副本，可由插件包重建"
        }
      ]
    },
    {
      "id": "plugins-statusline",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/*/statusline.cmd",
        ".claude/plugins/*/statusline.mjs",
        ".claude/plugins/*/previous-statusline.txt"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件自带状态栏脚本与上次输出，随插件重装"
        }
      ]
    },
    {
      "id": "plugins-last-sweep",
      "kind": "file",
      "root": "home",
      "path": ".claude/plugins/.last_inuse_sweep",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件清理时间戳，隐藏文件"
        }
      ]
    },
    {
      "id": "plugins-cache",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/cache/**"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件安装副本，可凭清单重下"
        }
      ]
    },
    {
      "id": "plugins-marketplaces",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/marketplaces/**"
      ],
      "layer": "L1",
      "secret": "none",
      "extractor": "keys-only",
      "expand": "aggregate",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "marketplace 的完整 git 克隆，可重新克隆；.git 由默认 exclude 排除"
        }
      ]
    },
    {
      "id": "plugins-enabled",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/enabled*.json",
        ".claude/plugins/installed_plugins.json"
      ],
      "layer": "L2",
      "secret": "none",
      "extractor": "keys-only",
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件启用清单；启用状态同时存在于 settings.json 的 enabledPlugins，故 L2"
        }
      ]
    },
    {
      "id": "plugins-config",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/*/config.json"
      ],
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件显示项等用户偏好，重装插件不会带回"
        }
      ]
    },
    {
      "id": "plugins-store",
      "kind": "dir",
      "root": "home",
      "path": ".claude/plugins/store",
      "layer": "L3",
      "secret": "none",
      "extractor": "keys-only",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件运行时持久状态，无上游"
        }
      ]
    },
    {
      "id": "plugins-data",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/plugins/**/data/**"
      ],
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "插件游标等可重建数据，如 transcript-cursors"
        }
      ]
    },
    {
      "id": "file-history",
      "kind": "dir",
      "root": "home",
      "path": ".claude/file-history",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "needed_by": [
        "rewind"
      ],
      "signals": [
        {
          "src": "observed_behavior",
          "note": "文件编辑检查点，删后旧会话 /rewind 回不到旧版本；本机 268 个 @vN 快照"
        }
      ]
    },
    {
      "id": "statusline",
      "kind": "file",
      "root": "home",
      "path": ".claude/statusline.js",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "needed_by": [
        "statusline"
      ],
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "被 settings.json 的 statusLine.command 引用"
        }
      ]
    },
    {
      "id": "backups",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/backups/.*"
      ],
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": ".claude.json 的自动备份，隐藏文件，需显式匹配 . 段"
        }
      ]
    },
    {
      "id": "sessions",
      "kind": "glob-group",
      "root": "home",
      "paths": [
        ".claude/sessions/**"
      ],
      "layer": "L0",
      "secret": "scan",
      "extractor": "digest",
      "opaque_content": true,
      "max_bytes_inline": 0,
      "needed_by": [
        "daemon"
      ],
      "signals": [
        {
          "src": "observed_behavior",
          "note": "每进程会话密钥与状态，108 B 的 *.key 由 daemon 引用，进程重启可再生"
        }
      ]
    },
    {
      "id": "keybindings",
      "kind": "file",
      "root": "home",
      "path": ".claude/keybindings.json",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "official_docs",
          "note": "自定义键位",
          "url": "https://code.claude.com/docs/en/keybindings"
        }
      ]
    },
    {
      "id": "oauth-credential-store",
      "kind": "named-location",
      "os": [
        "darwin",
        "windows",
        "linux"
      ],
      "locator": {
        "darwin": "keychain:generic-password?service=Claude Code-credentials",
        "windows": "wincred:Claude Code-credentials",  // TODO verify 目标名
        "linux": "file:$HOME/.claude/.credentials.json"  // TODO verify
      },
      "probe": {
        "darwin": "keychain",
        "windows": "wincred",
        "linux": "file-probe"
      },
      "layer": "L5",
      "secret": "relogin",
      "extractor": "digest",
      "signals": [
        {
          "src": "official_docs",
          "note": "OAuth 凭据存于系统凭据库；换机需重新登录",
          "url": "https://code.claude.com/docs/en/setup"
        }
      ]
    },
    {
      "id": "repo-settings-local",
      "kind": "file",
      "root": "repo",
      "path": ".claude/settings.local.json",
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "unique_within": "root",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "项目本地覆盖，被 .claude/* 类 gitignore 排除，从未进版本库"
        }
      ]
    },
    {
      "id": "repo-mcp-json",
      "kind": "file",
      "root": "repo",
      "path": ".mcp.json",  // 本机不存在
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "priority": 20,
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "official_docs",
          "note": "项目级 MCP server 定义，env 中常含明文 token",
          "url": "https://code.claude.com/docs/en/mcp"
        }
      ]
    },
    {
      "id": "repo-claude-md",
      "kind": "file",
      "root": "repo",
      "path": "CLAUDE.md",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "unique_within": "root",
      "priority": 10,
      "signals": [
        {
          "src": "official_docs",
          "note": "项目级规则文件，通常伴随仓库存在但常被漏提交",
          "url": "https://code.claude.com/docs/en/memory"
        }
      ]
    },
    {
      "id": "repo-commands",
      "kind": "glob-group",
      "root": "repo",
      "paths": [
        ".claude/commands/**/*.md",
        ".claude/agents/**/*.md"
      ],
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "自定义 slash command 与子代理定义，手写且无上游"
        }
      ]
    },
    {
      "id": "repo-rules",
      "kind": "glob-group",
      "root": "repo",
      "paths": [
        ".claude/rules/**/*.md"
      ],
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "仓库级规则文件；本机为 git tracked，属仓库资产"
        }
      ]
    },
    {
      "id": "repo-launch",
      "kind": "file",
      "root": "repo",
      "path": ".claude/launch.json",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "本机实测 D 盘 11 个 .claude/ 目录中 3 个含 settings.local.json、5 个含 CLAUDE.md；launch.json 并非普遍"
        }
      ]
    },
    {
      "id": "repo-worktrees",
      "kind": "dir",
      "root": "repo",
      "path": ".claude/worktrees",
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "expand": "aggregate",
      "path_semantics": "machine_derived",
      "derived_from": "git_worktree_of",
      "priority": 5,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "worktree 是含未提交改动的分支副本，目录名随机；.git 为普通文件，由默认 exclude 排除"
        }
      ]
    },
    {
      "id": "repo-scheduled-tasks-lock",
      "kind": "file",
      "root": "repo",
      "path": ".claude/scheduled_tasks.lock",
      "layer": "L4",
      "secret": "none",
      "extractor": "digest",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "含 sessionId 与 pid 的本机锁，随会话重建"
        }
      ]
    },
    {
      "id": "claude-vm-bundles",
      "kind": "dir",
      "root": "localappdata",
      "path": "Claude-3p/vm_bundles",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "max_bytes_total": 137438953472,
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "本机 8.5 GB 的 VM 镜像与 warm 包，可重新下载/构建"
        }
      ]
    },
    {
      "id": "claude-agent-sessions",
      "kind": "dir",
      "root": "localappdata",
      "path": "Claude-3p/local-agent-mode-sessions",
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "opaque_content": true,
      "max_bytes_inline": 0,
      "expand": "aggregate",
      "max_bytes_total": 4294967296,
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "本机 629 MB 的本地 agent 会话状态，无上游"
        }
      ]
    },
    {
      "id": "claude-desktop-config",
      "kind": "dir",
      "root": "appdata",
      "path": "Claude",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_structure": 262144,
      "expand": "aggregate",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "Claude 桌面端配置目录；本机 appdata root 此前无条目"
        }
      ]
    },
    {
      "id": "claude-appdata-3p",
      "kind": "dir",
      "root": "appdata",
      "path": "Claude-3p",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "priority": 10,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "第三方组件缓存，可重新下载"
        }
      ]
    },
    {
      "id": "home-residual",
      "kind": "catch-all",
      "root": "home",
      "scope": "subtree",
      "under": ".claude",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 3,
      "signals": []
    },
    {
      "id": "home-root-residual",
      "kind": "catch-all",
      "root": "home",
      "scope": "root",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 1,
      "signals": []
    },
    {
      "id": "appdata-residual",
      "kind": "catch-all",
      "root": "appdata",
      "scope": "root",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 3,
      "signals": []
    },
    {
      "id": "localappdata-residual",
      "kind": "catch-all",
      "root": "localappdata",
      "scope": "root",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 3,
      "signals": []
    },
    {
      "id": "repo-residual",
      "kind": "catch-all",
      "root": "repo",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 3,
      "signals": []
    }
  ],
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    "fixtures": {
      "home": "fixtures/claude-code/home",
      "repo": "fixtures/claude-code/repo",
      "localappdata": "fixtures/claude-code/localappdata",
      "appdata": "fixtures/claude-code/appdata"
    },
    "files": [
      {
        "path": "home/.claude/projects/D--demo/tool-results/blob.pdf",
        "size": 4096
      },
      {
        "path": "home/.claude/cache/blob.bin",
        "size": 4096
      },
      {
        "path": "localappdata/Claude-3p/vm_bundles/claudevm.bundle/disk.img",
        "size": 4096
      }
    ],
    "dirs": [
      "home/.claude/debug",
      "home/.claude/statsig",
      "home/.claude/ide"
    ],
    "symlinks": [],
    "expect": [
      {
        "entry": "settings-global",
        "root": "home",
        "match": ".claude/settings.json",
        "layer": "L2",
        "secret": "scan"
      },
      {
        "entry": "settings-backups",
        "root": "home",
        "match": ".claude/settings.json.bak.1",
        "layer": "L2",
        "secret": "scan"
      },
      {
        "entry": "settings-local-global",
        "root": "home",
        "match": ".claude/settings.local.json",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "claude-json",
        "part": "machine-identity",
        "root": "home",
        "match": ".claude.json",
        "layer": "L4",
        "secret": "none"
      },
      {
        "entry": "claude-json",
        "part": "user-identity",
        "root": "home",
        "match": ".claude.json",
        "layer": "L4"
      },
      {
        "entry": "claude-json",
        "part": "project-index",
        "root": "home",
        "match": ".claude.json",
        "layer": "L4"
      },
      {
        "entry": "claude-json",
        "part": "project-history",
        "root": "home",
        "match": ".claude.json",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "claude-json",
        "part": "mcp-servers",
        "root": "home",
        "match": ".claude.json",
        "layer": "L2",
        "secret": "scan"
      },
      {
        "entry": "projects-transcripts",
        "root": "home",
        "match": ".claude/projects/**/*.jsonl",
        "layer": "L3",
        "action": "keep"
      },
      {
        "entry": "projects-tool-results",
        "root": "home",
        "match": ".claude/projects/**/tool-results/**",
        "layer": "L3",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "projects-subagents",
        "root": "home",
        "match": ".claude/projects/**/subagents/**/*.jsonl",
        "layer": "L3"
      },
      {
        "entry": "projects-memory",
        "root": "home",
        "match": ".claude/projects/D--demo/memory/MEMORY.md",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "history",
        "root": "home",
        "match": ".claude/history.jsonl",
        "layer": "L3"
      },
      {
        "entry": "todos",
        "root": "home",
        "match": ".claude/todos/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "shell-snapshots",
        "root": "home",
        "match": ".claude/shell-snapshots/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "cache-debug-statsig-ide",
        "root": "home",
        "match": ".claude/cache/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "global-claude-md",
        "root": "home",
        "match": ".claude/CLAUDE.md",
        "layer": "L3"
      },
      {
        "entry": "skills",
        "root": "home",
        "match": ".claude/skills/**",
        "layer": "L3"
      },
      {
        "entry": "agents",
        "root": "home",
        "match": ".claude/agents/**",
        "layer": "L3"
      },
      {
        "entry": "plugins-readme",
        "root": "home",
        "match": ".claude/plugins/README.md",
        "layer": "L1"
      },
      {
        "entry": "plugins-known-marketplaces",
        "root": "home",
        "match": ".claude/plugins/known_marketplaces.json",
        "layer": "L2"
      },
      {
        "entry": "plugins-directory-cache",
        "root": "home",
        "match": ".claude/plugins/plugin-directory-cache-v2.json",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-heartbeat",
        "root": "home",
        "match": ".claude/plugins/demo/heartbeat.json",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-stripped",
        "root": "home",
        "match": ".claude/plugins/demo/stripped/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-statusline",
        "root": "home",
        "match": ".claude/plugins/demo/statusline.mjs",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-last-sweep",
        "root": "home",
        "match": ".claude/plugins/.last_inuse_sweep",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-cache",
        "root": "home",
        "match": ".claude/plugins/cache/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "plugins-marketplaces",
        "root": "home",
        "match": ".claude/plugins/marketplaces/**",
        "layer": "L1"
      },
      {
        "entry": "plugins-enabled",
        "root": "home",
        "match": ".claude/plugins/enabled_plugins.json",
        "layer": "L2"
      },
      {
        "entry": "plugins-config",
        "root": "home",
        "match": ".claude/plugins/demo/config.json",
        "layer": "L2"
      },
      {
        "entry": "plugins-store",
        "root": "home",
        "match": ".claude/plugins/store/**",
        "layer": "L3"
      },
      {
        "entry": "plugins-data",
        "root": "home",
        "match": ".claude/plugins/demo/data/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "file-history",
        "root": "home",
        "match": ".claude/file-history/**",
        "layer": "L0",
        "action": "delete",
        "risk_flags": [
          "deletion_cost"
        ]
      },
      {
        "entry": "statusline",
        "root": "home",
        "match": ".claude/statusline.js",
        "layer": "L2"
      },
      {
        "entry": "backups",
        "root": "home",
        "match": ".claude/backups/.*",
        "layer": "L2"
      },
      {
        "entry": "sessions",
        "root": "home",
        "match": ".claude/sessions/**",
        "layer": "L0",
        "action": "delete",
        "risk_flags": [
          "deletion_cost"
        ]
      },
      {
        "entry": "keybindings",
        "root": "home",
        "match": ".claude/keybindings.json",
        "layer": "L2"
      },
      {
        "entry": "oauth-credential-store",
        "root": "home",
        "match": ".claude/.credentials.json",
        "os": [
          "linux"
        ],
        "layer": "L5",
        "secret": "relogin",
        "action": "relogin"
      },
      {
        "entry": "repo-settings-local",
        "root": "repo",
        "match": ".claude/settings.local.json",
        "layer": "L3"
      },
      {
        "entry": "repo-mcp-json",
        "root": "repo",
        "match": ".mcp.json",
        "layer": "L2",
        "secret": "scan"
      },
      {
        "entry": "repo-claude-md",
        "root": "repo",
        "match": "CLAUDE.md",
        "layer": "L3"
      },
      {
        "entry": "repo-commands",
        "root": "repo",
        "match": ".claude/commands/**",
        "layer": "L3"
      },
      {
        "entry": "repo-rules",
        "root": "repo",
        "match": ".claude/rules/**",
        "layer": "L3"
      },
      {
        "entry": "repo-launch",
        "root": "repo",
        "match": ".claude/launch.json",
        "layer": "L2"
      },
      {
        "entry": "repo-worktrees",
        "root": "repo",
        "match": ".claude/worktrees/**",
        "layer": "L3",
        "risk_flags": [
          "aggregated",
          "machine_derived_path"
        ]
      },
      {
        "entry": "repo-scheduled-tasks-lock",
        "root": "repo",
        "match": ".claude/scheduled_tasks.lock",
        "layer": "L4"
      },
      {
        "entry": "claude-vm-bundles",
        "root": "localappdata",
        "match": "Claude-3p/vm_bundles/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "claude-agent-sessions",
        "root": "localappdata",
        "match": "Claude-3p/local-agent-mode-sessions/**",
        "layer": "L3"
      },
      {
        "entry": "claude-desktop-config",
        "root": "appdata",
        "match": "Claude/**",
        "layer": "L2"
      },
      {
        "entry": "claude-appdata-3p",
        "root": "appdata",
        "match": "Claude-3p/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "appdata-residual",
        "root": "appdata",
        "match": "loose.cfg",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      },
      {
        "entry": "localappdata-residual",
        "root": "localappdata",
        "match": "loose.cache",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      },
      {
        "entry": "home-residual",
        "root": "home",
        "match": ".claude/loose.txt",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      },
      {
        "entry": "home-root-residual",
        "root": "home",
        "match": "loose.txt",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      },
      {
        "entry": "repo-residual",
        "root": "repo",
        "match": "loose.txt",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      }
    ],
    "expect_absent": [
      {
        "root": "repo",
        "match": ".claude/worktrees/**/.git"
      }
    ],
    "budget": {
      "wall_ms": 5000,
      "max_rss_mib": 256
    }
  }
}
```

### 8.2 codex

```jsonc
{
  "schema_version": "2.0",
  "name": "codex",
  "title": "Codex CLI",
  "vendor": "OpenAI",
  "applies_to": {
    "os": [
      "windows",
      "darwin",
      "linux"
    ]
  },
  "roots": {
    "codex": {
      "windows": "${CODEX_HOME:-%USERPROFILE%\\.codex}",
      "darwin": "${CODEX_HOME:-$HOME/.codex}",
      "linux": "${CODEX_HOME:-$HOME/.codex}"
    },
    "repo": "${REPO_ROOT}"
  },
  "defaults": {
    "expand": "per-file"
  },
  "max_bytes_total": 274877906944,
  "entries": [
    {
      "id": "config",
      "kind": "file",
      "root": "codex",
      "path": "config.toml",
      "layer": "L2",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(key|token|secret|password).*"
        ]
      },
      "signals": [
        {
          "src": "official_docs",
          "note": "主配置，model_providers 可以 env_key 引用密钥，也可内联，故必须扫描",
          "url": "https://github.com/openai/codex/blob/main/docs/config.md"
        }
      ],
      "parts_uncovered": "keep",
      "parts": [
        {
          "id": "project-index",
          "selector": {
            "toml_section": "projects.*"
          },
          "layer": "L4",
          "secret": "none",
          "extractor": "keys-only",
          "path_semantics": "machine_derived",
          "derived_from": "json_path_key",
          "notes": "[projects.'d:/…'] 段；段键为本机绝对路径，逐段产出 origin"
        }
      ]
    },
    {
      "id": "auth",
      "kind": "file",
      "root": "codex",
      "path": "auth.json",
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(key|token|secret).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "存 OPENAI_API_KEY 或 ChatGPT OAuth 凭据；API key 可迁，OAuth refresh token 常需重登，故用 scan 分类"  // TODO verify 字段名
        }
      ]
    },
    {
      "id": "dotenv",
      "kind": "file",
      "root": "codex",
      "path": ".env",
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(key|token|secret|password).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "dotenv 形式，按行首键名脱敏；本机 204 B"
        }
      ]
    },
    {
      "id": "sandbox-secrets",
      "kind": "file",
      "root": "codex",
      "path": ".sandbox-secrets/sandbox_users.json",
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(key|token|secret|password).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "沙箱用户口令表"
        }
      ]
    },
    {
      "id": "sessions",
      "kind": "glob-group",
      "root": "codex",
      "paths": [
        "sessions/**/rollout-*.jsonl"
      ],
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 65536,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "按日期分目录存档的会话 rollout，明文 JSONL，体积最大"  // TODO verify 文件名前缀
        }
      ]
    },
    {
      "id": "archived-sessions",
      "kind": "dir",
      "root": "codex",
      "path": "archived_sessions",
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 0,
      "opaque_content": true,
      "expand": "aggregate",
      "max_bytes_total": 4294967296,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "归档会话，16 MB，无上游"
        }
      ]
    },
    {
      "id": "history",
      "kind": "file",
      "root": "codex",
      "path": "history.jsonl",
      "layer": "L3",
      "secret": "scan",
      "extractor": "template",
      "redact": {
        "key_pattern": [
          "(?i).*(token|secret|password|api[_-]?key).*"
        ]
      },
      "signals": [
        {
          "src": "observed_behavior",
          "note": "输入历史，明文"
        }
      ]
    },
    {
      "id": "prompts",
      "kind": "dir",
      "root": "codex",
      "path": "prompts",
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "official_docs",
          "note": "自定义 prompt 模板，手写且无上游",
          "url": "https://github.com/openai/codex/blob/main/docs/prompts.md"
        }
      ]
    },
    {
      "id": "rules",
      "kind": "dir",
      "root": "codex",
      "path": "rules",
      "layer": "L3",
      "secret": "none",
      "extractor": "raw-ref",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "命令执行规则文件；本机存在"  // TODO verify 是否随版本存在
        }
      ]
    },
    {
      "id": "agents-md",
      "kind": "file",
      "root": "codex",
      "path": "AGENTS.md",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "unique_within": "root",
      "signals": [
        {
          "src": "official_docs",
          "note": "全局 agent 规则文件",
          "url": "https://github.com/openai/codex/blob/main/docs/config.md"
        }
      ]
    },
    {
      "id": "log",
      "kind": "dir",
      "root": "codex",
      "path": "log",  // 本机不存在
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "codex-tui.log 运行日志；本机无 log/，散落的 *.log 由残留条目收"
        }
      ]
    },
    {
      "id": "tmp",
      "kind": "dir",
      "root": "codex",
      "path": "tmp",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "临时工作区"  // TODO verify
        }
      ]
    },
    {
      "id": "models-cache",
      "kind": "file",
      "root": "codex",
      "path": "models_cache.json",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "模型元数据缓存，联网重新拉取"
        }
      ]
    },
    {
      "id": "version",
      "kind": "file",
      "root": "codex",
      "path": "version.json",
      "layer": "L0",
      "secret": "none",
      "extractor": "none",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "版本检查缓存"
        }
      ]
    },
    {
      "id": "sqlite-state",
      "kind": "file",
      "root": "codex",
      "path": "state_5.sqlite",
      "companions": [
        "-wal",
        "-shm"
      ],
      "open_as": "sqlite-ro",
      "side_effects": [
        "shm_created"
      ],
      "opaque_content": true,
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 0,
      "max_bytes_total": 1073741824,
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "会话状态库；只读打开仍可能生成 -shm"
        }
      ]
    },
    {
      "id": "sqlite-logs",
      "kind": "file",
      "root": "codex",
      "path": "logs_2.sqlite",
      "companions": [
        "-wal",
        "-shm"
      ],
      "open_as": "sqlite-ro",
      "side_effects": [
        "shm_created"
      ],
      "opaque_content": true,
      "layer": "L2",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 0,
      "max_bytes_total": 1073741824,
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "运行日志库，95 MB；WAL 可能为 0 字节"
        }
      ]
    },
    {
      "id": "sqlite-thread-history",
      "kind": "file",
      "root": "codex",
      "path": "thread_history_1.sqlite",
      "companions": [
        "-wal",
        "-shm"
      ],
      "open_as": "sqlite-ro",
      "side_effects": [
        "shm_created"
      ],
      "opaque_content": true,
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 0,
      "max_bytes_total": 4294967296,
      "priority": 20,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "线程历史库，360 MB，本机 codex 最大单文件"
        }
      ]
    },
    {
      "id": "sqlite-other",
      "kind": "glob-group",
      "root": "codex",
      "paths": [
        "*.sqlite",
        "sqlite/*.sqlite",
        "sqlite/*.db"
      ],
      "companions": [
        "-wal",
        "-shm"
      ],
      "open_as": "sqlite-ro",
      "side_effects": [
        "shm_created"
      ],
      "opaque_content": true,
      "layer": "L3",
      "secret": "scan",
      "extractor": "digest",
      "max_bytes_inline": 0,
      "max_bytes_total": 1073741824,
      "priority": 5,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "goals/queue/memories 等其余库与 sqlite/ 下的 *.sqlite/*.db（本机 codex-dev.db 36,864 B）"
        }
      ]
    },
    {
      "id": "packages",
      "kind": "dir",
      "root": "codex",
      "path": "packages",
      "layer": "L1",
      "secret": "none",
      "extractor": "none",
      "expand": "aggregate",
      "max_bytes_total": 4294967296,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "app-server-daemon 等可重装包，1.1 GB，含 junction"
        }
      ]
    },
    {
      "id": "global-state",
      "kind": "file",
      "root": "codex",
      "path": ".codex-global-state.json",
      "layer": "L4",
      "secret": "none",
      "extractor": "keys-only",
      "churn": "high",
      "max_bytes_inline": 0,
      "max_bytes_structure": 1048576,
      "signals": [
        {
          "src": "observed_behavior",
          "note": "全局状态，含机器绑定键；高频重写"
        }
      ]
    },
    {
      "id": "installation-id",
      "kind": "file",
      "root": "codex",
      "path": "installation_id",
      "layer": "L4",
      "secret": "none",
      "extractor": "digest",
      "signals": [
        {
          "src": "observed_behavior",
          "note": "安装标识，换机需重建"
        }
      ]
    },
    {
      "id": "repo-agents-md",
      "kind": "file",
      "root": "repo",
      "path": "AGENTS.md",
      "layer": "L2",
      "secret": "none",
      "extractor": "raw-ref",
      "unique_within": "root",
      "signals": [
        {
          "src": "official_docs",
          "note": "仓库级 agent 规则，通常应进版本库",
          "url": "https://github.com/openai/codex/blob/main/docs/config.md"
        }
      ]
    },
    {
      "id": "codex-residual",
      "kind": "catch-all",
      "root": "codex",
      "layer": "L2",
      "secret": "scan",
      "extractor": "keys-only",
      "max_bytes_inline": 65536,
      "max_depth": 3,
      "signals": []
    }
  ],
  "selftest": {
    "clock": "2026-01-01T00:00:00Z",
    "fixtures": {
      "codex": "fixtures/codex/home",
      "repo": "fixtures/codex/repo"
    },
    "files": [
      {
        "path": "codex/state_5.sqlite",
        "size": 4096
      },
      {
        "path": "codex/state_5.sqlite-wal",
        "size": 128
      },
      {
        "path": "codex/logs_2.sqlite",
        "size": 4096
      },
      {
        "path": "codex/logs_2.sqlite-wal",
        "size": 0
      },
      {
        "path": "codex/thread_history_1.sqlite",
        "size": 8192
      },
      {
        "path": "codex/sqlite/goals_1.sqlite",
        "size": 4096
      },
      {
        "path": "codex/sqlite/codex-dev.db",
        "size": 4096
      },
      {
        "path": "codex/sqlite/queue_1.sqlite",
        "size": 4096
      },
      {
        "path": "codex/sqlite/queue_1.sqlite-shm",
        "size": 32768
      }
    ],
    "dirs": [],
    "symlinks": [],
    "expect": [
      {
        "entry": "config",
        "root": "codex",
        "match": "config.toml",
        "layer": "L2",
        "secret": "scan"
      },
      {
        "entry": "config",
        "part": "project-index",
        "root": "codex",
        "match": "config.toml",
        "layer": "L4",
        "secret": "none"
      },
      {
        "entry": "auth",
        "root": "codex",
        "match": "auth.json",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "dotenv",
        "root": "codex",
        "match": ".env",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "sandbox-secrets",
        "root": "codex",
        "match": ".sandbox-secrets/sandbox_users.json",
        "layer": "L3",
        "secret": "scan"
      },
      {
        "entry": "sessions",
        "root": "codex",
        "match": "sessions/**/rollout-*.jsonl",
        "layer": "L3"
      },
      {
        "entry": "archived-sessions",
        "root": "codex",
        "match": "archived_sessions/**",
        "layer": "L3"
      },
      {
        "entry": "history",
        "root": "codex",
        "match": "history.jsonl",
        "layer": "L3"
      },
      {
        "entry": "prompts",
        "root": "codex",
        "match": "prompts/**",
        "layer": "L3"
      },
      {
        "entry": "rules",
        "root": "codex",
        "match": "rules/**",
        "layer": "L3"
      },
      {
        "entry": "agents-md",
        "root": "codex",
        "match": "AGENTS.md",
        "layer": "L3"
      },
      {
        "entry": "log",
        "root": "codex",
        "match": "log/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "tmp",
        "root": "codex",
        "match": "tmp/**",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "models-cache",
        "root": "codex",
        "match": "models_cache.json",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "version",
        "root": "codex",
        "match": "version.json",
        "layer": "L0",
        "action": "delete"
      },
      {
        "entry": "sqlite-state",
        "root": "codex",
        "match": "state_5.sqlite",
        "layer": "L3",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "sqlite-logs",
        "root": "codex",
        "match": "logs_2.sqlite",
        "layer": "L2",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "sqlite-thread-history",
        "root": "codex",
        "match": "thread_history_1.sqlite",
        "layer": "L3",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "sqlite-other",
        "root": "codex",
        "match": "sqlite/goals_1.sqlite",
        "layer": "L3",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "sqlite-other",
        "root": "codex",
        "match": "sqlite/codex-dev.db",
        "layer": "L3",
        "risk_flags": [
          "opaque_content"
        ]
      },
      {
        "entry": "sqlite-other",
        "root": "codex",
        "match": "sqlite/queue_1.sqlite",
        "layer": "L3"
      },
      {
        "entry": "packages",
        "root": "codex",
        "match": "packages/**",
        "layer": "L1",
        "action": "reinstall"
      },
      {
        "entry": "global-state",
        "root": "codex",
        "match": ".codex-global-state.json",
        "layer": "L4"
      },
      {
        "entry": "installation-id",
        "root": "codex",
        "match": "installation_id",
        "layer": "L4"
      },
      {
        "entry": "repo-agents-md",
        "root": "repo",
        "match": "AGENTS.md",
        "layer": "L3"
      },
      {
        "entry": "codex-residual",
        "root": "codex",
        "match": "loose.log",
        "layer": "L2",
        "action": "keep",
        "confidence": 0.5
      }
    ],
    "expect_absent": [],
    "budget": {
      "wall_ms": 5000,
      "max_rss_mib": 256
    }
  }
}
```

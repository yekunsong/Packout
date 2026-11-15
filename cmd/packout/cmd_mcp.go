package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/yekunsong/Packout/internal/mcp"
	"github.com/yekunsong/Packout/internal/profile"
)

// mcpConfig is the startup configuration of `packout mcp`. Everything a tool
// may read is fixed here; tools/call arguments are filters only (INV-I03).
type mcpConfig struct {
	out             string
	profileRef      string
	roots           rootList
	pkg             string
	into            string
	identity        string
	pubkey          string
	trustedKeys     string
	rootsFromConfig bool
}

// parseMCP parses the process arguments. Missing --out or an unknown --root
// role is a usage error; no scan or package needs to exist yet, because the
// server reports no_scan / not_configured per tool instead of refusing to
// start.
func parseMCP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var cfg mcpConfig
	fs := newMCPFlagSet(&cfg)
	if _, code := parse(fs, args, 0, mcpHelp, stdout, stderr); code >= 0 {
		return code
	}
	conf, confPath, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "packout: 配置文件 %s: %v\n", confPath, err)
		return exitUsage
	}
	if conf != nil {
		before := len(cfg.roots)
		applyConfigDefaults(conf, &cfg.profileRef, new(string), &cfg.identity, &cfg.pubkey, &cfg.roots)
		cfg.rootsFromConfig = before == 0 && len(cfg.roots) > 0
	}
	// config's trusted_keys is the trust store, not --pubkey. Passing it here
	// keeps the MCP verify/restore_plan tools consistent with the CLI.
	cfg.trustedKeys = trustedKeysPath(conf)
	return runMCP(ctx, cfg, stderr)
}

// newMCPFlagSet binds the mcp flags; split out so tests can exercise parsing
// without a live server.
func newMCPFlagSet(cfg *mcpConfig) *flag.FlagSet {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.StringVar(&cfg.out, "out", "", "扫描输出目录（必填；工具只读这里）")
	fs.StringVar(&cfg.profileRef, "profile", "", "内置 profile 名或文件路径（默认 "+defaultProfile+"）")
	fs.Var(&cfg.roots, "root", "role=PATH，可重复；缺省时用 profile 默认根")
	fs.StringVar(&cfg.pkg, "package", "", "verify/restore_plan 的包目录（缺省时这两个工具返回 not_configured）")
	fs.StringVar(&cfg.into, "into", "", "restore_plan 的目标目录（缺省时 restore_plan 返回 not_configured）")
	fs.StringVar(&cfg.identity, "identity", "", "restore_plan 解密 secrets.age 的 age identity（默认 ~/.config/packout/identity.age）")
	fs.StringVar(&cfg.pubkey, "pubkey", "", "verify 的公钥文件（默认读 <configDir>/trusted_keys）")
	return fs
}

func runMCP(ctx context.Context, cfg mcpConfig, stderr io.Writer) int {
	if cfg.out == "" {
		fmt.Fprintf(stderr, "packout: mcp 需要 --out <扫描输出目录>\n\n")
		return exitUsage
	}
	p, err := loadProfile(cfg.profileRef, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "packout: profile: %v\n", err)
		return exitUsage
	}
	roots, err := resolveMCPRoots(cfg, p)
	if err != nil {
		fmt.Fprintf(stderr, "packout: mcp: %v\n", err)
		return exitUsage
	}
	srv, err := mcp.NewServer(mcp.Config{
		OutDir:      cfg.out,
		Profile:     p.Name,
		Roots:       roots,
		Package:     cfg.pkg,
		Into:        cfg.into,
		Identity:    cfg.identity,
		PubKey:      cfg.pubkey,
		TrustedKeys: cfg.trustedKeys,
		Version:     version,
	})
	if err != nil {
		fmt.Fprintf(stderr, "packout: mcp: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "packout: mcp 只读服务已启动（stdio；out=%s，profile=%s）\n", srv.OutDir(), p.Name)
	if err := srv.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		if ctx.Err() != nil {
			return exitCanceled
		}
		fmt.Fprintf(stderr, "packout: mcp: %v\n", err)
		return exitPartial
	}
	return exitOK
}

// resolveMCPRoots turns --root flags (or the profile's defaults) into the
// fixed root list. Explicit roots are checked against the profile's roles;
// profile defaults are expanded per OS. Unresolvable templates are kept with a
// note so the model sees the missing role instead of a silently shorter list.
func resolveMCPRoots(cfg mcpConfig, p *profile.Profile) ([]mcp.Root, error) {
	if len(cfg.roots) > 0 {
		bindings, err := cfg.roots.bindings(p)
		if err != nil {
			return nil, err
		}
		counts := map[string]int{}
		origin := "cli"
		if cfg.rootsFromConfig {
			origin = "config"
		}
		out := make([]mcp.Root, 0, len(bindings))
		for _, b := range bindings {
			counts[b.Role]++
			name := b.Role
			if counts[b.Role] > 1 {
				name = fmt.Sprintf("%s#%d", b.Role, counts[b.Role])
			}
			out = append(out, mcp.Root{
				Name: name, Role: b.Role, Instance: counts[b.Role],
				Origin: origin, Path: b.Path,
			})
		}
		return out, nil
	}

	out := make([]mcp.Root, 0, len(p.RootOrder))
	for _, role := range p.RootOrder {
		tmpl := p.Roots[role].ForOS(runtime.GOOS)
		r := mcp.Root{Name: role, Role: role, Instance: 1, Origin: "profile"}
		if tmpl == "" {
			r.Note = "profile 未在本平台声明该 root"
			out = append(out, r)
			continue
		}
		expanded, err := profile.ExpandTemplate(tmpl)
		if err != nil || expanded == "" {
			r.Note = "profile 默认值无法解析：" + tmpl
			if err != nil {
				r.Note += "（" + err.Error() + "）"
			}
			out = append(out, r)
			continue
		}
		r.Path = expanded
		out = append(out, r)
	}
	return out, nil
}

const mcpHelp = `用法: packout mcp --out DIR [--root role=PATH]... [--package DIR] [--into DIR]

在 stdio 上提供只读 MCP 工具（JSON-RPC 2.0，换行分隔）：
  roots         已配置的根与当前扫描的根
  summary       最近一次扫描按层/按 profile 的计数与体积
  find          按 layer/entry/路径片段过滤并分页
  explain       单个 Unit 的全部 signals、出处与新鲜 stat
  verify        --package 指定包的结论词
  restore_plan  --package + --into 的干跑计划（不写任何文件）

  --out DIR        扫描输出目录（必填）。find/explain/summary 只读这里。
  --root role=PATH 覆盖 profile 默认根，可重复（同一 role 自动编号 role#2）
  --profile NAME   内置 profile 名或 profile 文件（默认 ` + defaultProfile + `）
  --package DIR    verify/restore_plan 的包目录；缺省时这两个工具返回
                   not_configured（运行期不接受模型传来的路径）
  --into DIR       restore_plan 的目标目录；缺省时 restore_plan 返回
                   not_configured
  --identity FILE  restore_plan 解密 secrets.age 用的 age identity
  --pubkey FILE    verify 的公钥文件（默认读 <configDir>/trusted_keys）

stdout 是 MCP 协议流，因此本命令不提供 --json/--quiet。
所有工具只读：每次调用都重新 stat/重读 manifest，不缓存；单次结果 ≤ 8 KiB，
超限返回 truncated 与全文所在路径；路径同时给原拼写与 path_key。
退出码: 0 正常断开 / 2 协议或运行失败 / 3 用法错误 / 5 中断

下一步：packout pack <目录> --seal 打出可 restore 的包
`

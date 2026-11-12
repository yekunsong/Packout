package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"packout/internal/manifest"
	"packout/internal/profile"
	"packout/internal/scan"
)

type scanConfig struct {
	// noState suppresses the state.json update (pack records the chain once).
	noState        bool
	profileRef     string
	roots          rootList
	out            string
	force          bool
	followSymlinks bool
	withSessions   bool
	preset         string
	include        string
	exclude        string
	sessionsSince  string
	sessionsProj   stringList
	sessionsMax    int
	stableSalt     bool
	jobs           int
	json           bool
	quiet          bool
}

type scanSummary struct {
	Out        string `json:"out"`
	Units      int64  `json:"units"`
	Residual   int64  `json:"residual"`
	ReadErrors int64  `json:"read_errors"`
	Notes      int64  `json:"notes"`
	Shards     int    `json:"shards"`
	Complete   bool   `json:"complete"`
}

// runScan is docs/design-cli.md's scan command. All writes land in a sibling
// staging directory that is only renamed onto --out after a complete scan.
func runScan(ctx context.Context, cfg scanConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.out == "" {
		return r.usage("scan 需要 --out")
	}
	conf, confPath, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s: %v", confPath, err)
	}
	fromConfig := false
	if conf != nil {
		before := len(cfg.roots)
		applyConfigDefaults(conf, &cfg.profileRef, &cfg.preset, new(string), new(string), &cfg.roots)
		fromConfig = before == 0 && len(cfg.roots) > 0
	}
	p, err := loadProfile(cfg.profileRef, stderr)
	if err != nil {
		return r.usage("profile: %v", err)
	}
	if fromConfig {
		for _, b := range cfg.roots {
			fmt.Fprintf(stderr, "packout: root %s=%s（来自配置文件）\n", b.role, b.path)
		}
	} else if len(cfg.roots) == 0 {
		rootEcho(p, stderr)
	}
	bindings, err := cfg.roots.bindings(p)
	if err != nil {
		return r.usage("%v", err)
	}
	selection, err := profile.ParseSelection(p, cfg.preset, cfg.include, cfg.exclude,
		cfg.sessionsSince, cfg.sessionsProj, cfg.sessionsMax, cfg.withSessions)
	if err != nil {
		return r.usage("%v", err)
	}
	if code, msg := checkOut(cfg.out, false, cfg.force); code != exitOK {
		return r.fail(code, "%s", withNext(msg, "packout scan --out "+cfg.out+" --force"))
	}
	salt, err := saltSource(cfg.stableSalt)
	if err != nil {
		return r.fail(exitUsage, "salt: %v", err)
	}

	stage, err := stageDir(cfg.out)
	if err != nil {
		return r.fail(exitUsage, "无法创建暂存目录: %v", err)
	}
	manifestDir := filepath.Join(stage, "manifest")
	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		return r.fail(exitUsage, "无法创建 manifest 目录: %v", err)
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(stage)
		}
	}()

	sc := scan.Config{
		Profile:        p,
		OutDir:         manifestDir,
		GOOS:           runtime.GOOS,
		Arch:           runtime.GOARCH,
		FollowSymlinks: cfg.followSymlinks,
		WithSessions:   cfg.withSessions || selection.CarriesSessions(),
		Selection:      selection,
		Jobs:           cfg.jobs,
		Tool:           "packout/" + version,
		Salt:           salt,
	}
	for _, b := range bindings {
		sc.Roots = append(sc.Roots, scan.RootBinding{Role: b.Role, Path: b.Path, Origin: "cli"})
	}

	res, err := scan.Run(ctx, sc)
	if err != nil {
		if ctx.Err() != nil {
			return exitFromCtx(r, ctx)
		}
		if errors.Is(err, scan.ErrConfig) {
			return r.usage("scan: %v", err)
		}
		return r.fail(exitPartial, "scan: %v", err)
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	if err := writeRoots(stage, res.Roots); err != nil {
		return r.fail(exitPartial, "写入 roots.json: %v", err)
	}
	if err := commitDir(stage, cfg.out); err != nil {
		return r.fail(exitPartial, "写入 --out: %v", err)
	}
	keep = true

	r.value(scanSummary{
		Out:        cfg.out,
		Units:      res.Units,
		Residual:   res.Residual,
		ReadErrors: res.ReadErrors,
		Notes:      res.Notes,
		Shards:     res.Shards,
		Complete:   res.Complete,
	})
	r.info("清单已写入 %s：%d 个 Unit（残留 %d，读取错误 %d，分片 %d）",
		cfg.out, res.Units, res.Residual, res.ReadErrors, res.Shards)
	if res.ReadErrors > 0 {
		r.warn("packout: 有 %d 条读取错误已作为 read_error 记入清单", res.ReadErrors)
	}
	if !res.Complete {
		r.warn("packout: 清单标记为不完整（footer.complete=false）")
		return exitPartial
	}
	if !cfg.noState {
		recordScan(r.warn, cfg.out, res.Units, res.Roots)
	}
	return exitOK
}

func saltSource(stable bool) (manifest.SaltSource, error) {
	if !stable {
		return nil, nil
	}
	return stableSalt()
}

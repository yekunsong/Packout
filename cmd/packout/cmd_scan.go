package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"packout/internal/manifest"
	"packout/internal/scan"
)

type scanConfig struct {
	profileRef     string
	roots          rootList
	out            string
	force          bool
	followSymlinks bool
	withSessions   bool
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
	p, err := loadProfile(cfg.profileRef, stderr)
	if err != nil {
		return r.usage("profile: %v", err)
	}
	if len(cfg.roots) == 0 {
		rootEcho(p, stderr)
	}
	bindings, err := cfg.roots.bindings(p)
	if err != nil {
		return r.usage("%v", err)
	}
	if code, msg := checkOut(cfg.out, false, cfg.force); code != exitOK {
		return r.fail(code, "%s", msg)
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
		WithSessions:   cfg.withSessions,
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
	return exitOK
}

func saltSource(stable bool) (manifest.SaltSource, error) {
	if !stable {
		return nil, nil
	}
	return stableSalt()
}

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"packout/internal/manifest"
	"packout/internal/report"
)

type reportConfig struct {
	manifest    string
	out         string
	force       bool
	noSignals   bool
	redactPaths bool
	title       string
	lan         bool
	noServe     bool
	json        bool
	quiet       bool
}

type reportSummary struct {
	Out     string `json:"out"`
	Bytes   int    `json:"bytes"`
	Served  bool   `json:"served"`
	LAN     bool   `json:"lan"`
	Signals bool   `json:"include_signals"`
}

// runReport renders the report to --out and, unless --no-serve, serves it on
// loopback. IncludeSignals is passed explicitly because report.Options' zero
// value omits signals (D-029 §5).
func runReport(ctx context.Context, cfg reportConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.out == "" {
		return r.usage("report 需要 --out")
	}
	if cfg.manifest == "" {
		return r.usage("report 需要 --manifest <扫描输出目录>")
	}
	if code, msg := checkOut(cfg.out, true, cfg.force); code != exitOK {
		return r.fail(code, "%s", msg)
	}
	dir := cfg.manifest
	if _, err := os.Stat(filepath.Join(dir, "manifest.index.json")); err != nil {
		// --manifest may name the scan output base containing manifest/.
		alt := filepath.Join(dir, "manifest")
		if _, err2 := os.Stat(filepath.Join(alt, "manifest.index.json")); err2 == nil {
			dir = alt
		}
	}
	m, err := manifest.ReadManifest(dir)
	if err != nil {
		return r.fail(exitUsage, "manifest %s 不可用: %v", dir, err)
	}

	opts := report.Options{
		IncludeSignals: !cfg.noSignals,
		RedactPaths:    cfg.redactPaths,
		Title:          cfg.title,
	}
	if cfg.lan {
		opts = opts.WithLAN(true)
	}

	var buf bytes.Buffer
	if err := report.Render(&buf, m, opts); err != nil {
		return r.fail(exitPartial, "render: %v", err)
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	if err := writeFileAtomic(cfg.out, buf.Bytes(), 0o644); err != nil {
		return r.fail(exitPartial, "写入 --out: %v", err)
	}

	served := !cfg.noServe
	r.value(reportSummary{Out: cfg.out, Bytes: buf.Len(), Served: served, LAN: cfg.lan, Signals: !cfg.noSignals})
	r.info("报告已写入 %s（%d 字节）", cfg.out, buf.Len())

	if !served {
		return exitOK
	}
	if cfg.lan {
		r.warn("packout: 警告：报告已暴露到局域网；下面的 URL 里的令牌是一次性的，勿转发。")
	}
	// Route the URL through OnReady instead of touching os.Stdout: --json
	// keeps a clean stdout and --lan puts the URL on stderr as required.
	primary := stdout
	if cfg.json {
		primary = stderr
	}
	dst := primary
	if cfg.lan {
		dst = io.MultiWriter(primary, stderr)
	}
	opts.OnReady = func(u string) {
		fmt.Fprintf(dst, "报告地址（一次性令牌在 fragment 中，勿转发）: %s\n", u)
	}
	serveErr := report.Serve(ctx, m, opts)
	if serveErr != nil {
		return r.fail(exitPartial, "报告服务: %v", serveErr)
	}
	// A normal Ctrl-C cancels ctx; report.Serve returns nil then.
	return exitFromCtx(r, ctx)
}

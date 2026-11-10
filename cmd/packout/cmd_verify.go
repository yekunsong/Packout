package main

import (
	"context"
	"fmt"
	"io"

	"packout/internal/pack"
)

type verifyConfig struct {
	dir   string
	json  bool
	quiet bool
}

// runVerify checks one package. The conclusion word is printed verbatim
// (design-cli.md): "hash-ok, unverified" stays "hash-ok, unverified".
func runVerify(ctx context.Context, cfg verifyConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.dir == "" {
		return r.usage("verify 需要一个包目录")
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	v, err := pack.Verify(cfg.dir)
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	if v == nil {
		if err != nil {
			return r.fail(exitPartial, "verify: %v", err)
		}
		return r.fail(exitPartial, "verify: 无结论")
	}
	r.value(v)
	// The word goes out before any diagnostics, and unchanged. Under --json
	// it is the "conclusion" member instead, so stdout stays one JSON value.
	if !cfg.json {
		fmt.Fprintln(stdout, v.Conclusion)
	}
	if err != nil {
		r.warn("packout: %v", err)
	}
	for _, p := range v.Problems {
		if err == nil {
			break
		}
		if p.Detail != "" {
			r.warn("packout:   %s %s: %s", p.Code, p.Path, p.Detail)
		} else {
			r.warn("packout:   %s %s", p.Code, p.Path)
		}
	}
	switch v.Conclusion {
	case pack.ConclusionHashOKUnverified, pack.ConclusionUnsigned:
		return exitOK
	default:
		return exitPartial
	}
}

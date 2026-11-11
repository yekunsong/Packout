package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"packout/internal/pack"
)

type verifyConfig struct {
	dir    string
	pubkey string
	json   bool
	quiet  bool
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
	opt := pack.VerifyOptions{PubKeyPath: cfg.pubkey}
	opt.OnKeySeen = func(fingerprint string, firstSeen bool) {
		if firstSeen {
			r.warn("packout: 首次见到公钥 SHA256:%s；已按 TOFU 信任本次，请通过另一渠道核对指纹", fingerprint)
		}
	}
	v, err := pack.VerifyWithOptions(cfg.dir, opt)
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
	// Problems are printed even without an error: "hash-ok, unverified" needs
	// its --pubkey hint, and TOFU warnings must survive --quiet.
	for _, p := range v.Problems {
		if p.Detail != "" {
			r.warn("packout:   %s %s: %s", p.Code, p.Path, p.Detail)
		} else {
			r.warn("packout:   %s %s", p.Code, p.Path)
		}
	}
	switch v.Conclusion {
	case pack.ConclusionOK, pack.ConclusionHashOKUnverified:
		return exitOK
	default:
		if errors.Is(err, pack.ErrInvalidPubKey) {
			return exitUsage
		}
		return exitPartial
	}
}

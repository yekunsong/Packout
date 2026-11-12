package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"packout/internal/pack"
)

type verifyConfig struct {
	noState bool
	dir     string
	pubkey  string
	json    bool
	quiet   bool
	jobs    int
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
	conf, confPath, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s: %v", confPath, err)
	}
	if conf != nil {
		applyConfigDefaults(conf, new(string), new(string), new(string), &cfg.pubkey, &rootList{})
	}
	opt := pack.VerifyOptions{PubKeyPath: cfg.pubkey, Jobs: cfg.jobs}
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
	// The hint is CLI wording only; the exit code stays the design table's.
	r.warn("下一步：%s", verifyNext(v.Conclusion, cfg.dir))
	switch v.Conclusion {
	case pack.ConclusionOK, pack.ConclusionHashOKUnverified:
		if !cfg.noState {
			recordVerify(r.warn, cfg.dir, v.Conclusion)
		}
		return exitOK
	default:
		if errors.Is(err, pack.ErrInvalidPubKey) {
			return exitUsage
		}
		return exitPartial
	}
}

// verifyNext maps a conclusion word to the one command worth typing next.
func verifyNext(conclusion, pkg string) string {
	switch conclusion {
	case pack.ConclusionOK:
		return "packout drill " + pkg + " 演练恢复"
	case pack.ConclusionHashOKUnverified:
		return "packout verify " + pkg + " --pubkey <公钥> 确认来源，或 packout restore " + pkg + " --into <目标目录> --allow-unverified"
	case pack.ConclusionUnsigned:
		return "packout sign " + pkg + " 签名后再 verify（或 packout restore " + pkg + " --into <目标目录> --allow-unverified）"
	case pack.ConclusionBadSignature:
		return "packout verify " + pkg + " --pubkey <你的公钥>；核对公钥指纹后再恢复"
	case pack.ConclusionTampered:
		return "内容与 SIG 不符，不要恢复；回到源机重新 packout pack <目录> --seal"
	default:
		return "确认路径指向一个包目录（应含 SIG.json 与 manifest/），再看 packout help restore"
	}
}

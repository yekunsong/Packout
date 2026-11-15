package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/yekunsong/Packout/internal/pack"
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
	trustedPath := trustedKeysPath(conf)
	opt := pack.VerifyOptions{PubKeyPath: cfg.pubkey, TrustedKeysPath: trustedPath, Jobs: cfg.jobs}
	opt.OnKeySeen = func(fingerprint string, firstSeen bool) {
		if firstSeen {
			r.warn("packout: 首次见到公钥 SHA256:%s；本次按 TOFU 信任但未持久化。用另一渠道核对指纹后，把该公钥加入 %s（或重跑 packout init）",
				fingerprint, trustedPath)
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
	r.warn("下一步：%s", verifyNext(v, cfg.dir))
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

// verifyNext maps a verdict to the one command worth typing next. The reason
// matters: "no public key" is not "wrong path" and neither is "tampered".
func verifyNext(v *pack.Verdict, pkg string) string {
	switch v.Conclusion {
	case pack.ConclusionOK:
		return "packout drill " + pkg + " 演练恢复"
	case pack.ConclusionHashOKUnverified:
		return "packout verify " + pkg + " --pubkey <公钥> 确认来源，或 packout restore " + pkg + " --into <目标目录> --allow-unverified"
	case pack.ConclusionUnsigned:
		return "packout sign " + pkg + " 签名后再 verify（或 packout restore " + pkg + " --into <目标目录> --allow-unverified）"
	case pack.ConclusionBadSignature:
		switch {
		case hasProblem(v, "no-pubkey"):
			return "没有可用公钥：packout verify " + pkg + " --pubkey <公钥> 核对来源，或运行 packout init 把本机公钥写入 trusted_keys"
		case hasProblem(v, "pubkey-invalid"):
			return "公钥文件不可用：修好 trusted_keys 或改用 packout verify " + pkg + " --pubkey <公钥>"
		default:
			return "签名与公钥不符：用 --pubkey 核对指纹，确认来源后重新 packout sign " + pkg
		}
	case pack.ConclusionTampered:
		return "内容与 SIG 不符，不要恢复；回到源机重新 packout pack <目录> --seal"
	case pack.ConclusionEmpty:
		return "确认路径指向一个包目录（应含 SIG.json 与 manifest/），再看 packout help restore"
	default:
		return "SIG 或 manifest 结构有问题：packout verify " + pkg + " --json 看 problems；仍不行就回到源机重新 packout pack"
	}
}

func hasProblem(v *pack.Verdict, code string) bool {
	for _, p := range v.Problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

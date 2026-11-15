package main

import (
	"context"
	"errors"
	"io"

	"github.com/yekunsong/Packout/internal/pack"
)

type signConfig struct {
	dir      string
	key      string
	generate bool
	json     bool
	quiet    bool
}

// runSign signs SIG.json and manifest/ with a minisign key.
func runSign(ctx context.Context, cfg signConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.dir == "" {
		return r.usage("sign 需要一个包目录")
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	keyPath := cfg.key
	if keyPath == "" {
		var err error
		if keyPath, err = pack.DefaultPrivateKeyPath(); err != nil {
			return r.usage("无法确定默认密钥路径：%v", err)
		}
	}
	if cfg.generate {
		fpr, err := pack.GenerateKeyPair(keyPath, "")
		if err != nil {
			if errors.Is(err, pack.ErrKeyExists) {
				return r.usage("%v（已有密钥直接去掉 --generate）", err)
			}
			return r.fail(exitUsage, "生成密钥：%v", err)
		}
		r.warn("packout: 已生成密钥 %s（私钥 0600），公钥 %s.pub，指纹 SHA256:%s", keyPath, keyPath, fpr)
	}
	res, err := pack.Sign(cfg.dir, keyPath)
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}
	if err != nil {
		if errors.Is(err, pack.ErrNoKey) || errors.Is(err, pack.ErrKeyPermissions) ||
			errors.Is(err, pack.ErrInvalidKey) || errors.Is(err, pack.ErrInvalidConfig) {
			return r.usage("sign: %v", err)
		}
		return r.fail(exitPartial, "sign: %v", err)
	}
	r.value(res)
	r.info("signed %s", res.Path)
	r.warn("packout: 公钥指纹 SHA256:%s；把公钥交给接收方，接收方用 verify --pubkey FILE 校验", res.KeyFingerprint)
	return exitOK
}

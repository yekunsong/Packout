package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"packout/internal/fsx"
	"packout/internal/pack"
)

type packConfig struct {
	out            string
	force          bool
	profileRef     string
	roots          rootList
	preset         string
	include        string
	exclude        string
	sessionsSince  string
	sessionsProj   stringList
	sessionsMax    int
	followSymlinks bool
	stableSalt     bool
	withSecrets    bool
	recipients     stringList
	passphrase     bool
	passphraseFile string
	identity       string
	sign           bool
	key            string
	jobs           int
	json           bool
	quiet          bool
}

type packSummary struct {
	Out         string   `json:"out"`
	ScanDir     string   `json:"scan_dir,omitempty"`
	Signed      bool     `json:"signed"`
	Fingerprint string   `json:"key_fingerprint,omitempty"`
	Verify      string   `json:"verify,omitempty"`
	Retained    []string `json:"retained,omitempty"`
}

// runPack chains scan → export → optional sign. The only thing it adds is the
// chain: each step keeps its own exit-code classification. A step failure
// leaves the earlier products on disk and names them.
func runPack(ctx context.Context, cfg packConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.out == "" {
		return r.usage("pack 需要 --out <包目录>")
	}
	if code, msg := checkOut(cfg.out, false, cfg.force); code != exitOK {
		return r.fail(code, "%s", msg)
	}
	abs, err := fsx.Abs(cfg.out)
	if err != nil {
		return r.usage("%v", err)
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return r.usage("无法创建 --out 的父目录：%v", err)
	}
	tmp, err := os.MkdirTemp(parent, ".packout-pack-")
	if err != nil {
		return r.fail(exitUsage, "无法创建扫描临时目录：%v", err)
	}
	retain := false
	defer func() {
		if !retain {
			os.RemoveAll(tmp)
		}
	}()
	scanOut := filepath.Join(tmp, "scan")
	subOut := stdout
	if cfg.json {
		subOut = io.Discard
	}
	subQuiet := cfg.quiet || cfg.json

	code := runScan(ctx, scanConfig{
		profileRef:     cfg.profileRef,
		roots:          cfg.roots,
		out:            scanOut,
		followSymlinks: cfg.followSymlinks,
		preset:         cfg.preset,
		include:        cfg.include,
		exclude:        cfg.exclude,
		sessionsSince:  cfg.sessionsSince,
		sessionsProj:   cfg.sessionsProj,
		sessionsMax:    cfg.sessionsMax,
		stableSalt:     cfg.stableSalt,
		jobs:           cfg.jobs,
		quiet:          subQuiet,
	}, subOut, stderr)
	if code != exitOK {
		return code
	}
	retain = true

	code = runExport(ctx, exportConfig{
		src:            scanOut,
		out:            cfg.out,
		force:          cfg.force,
		identity:       cfg.identity,
		withSecrets:    cfg.withSecrets,
		recipients:     cfg.recipients,
		passphrase:     cfg.passphrase,
		passphraseFile: cfg.passphraseFile,
		roots:          cfg.roots,
		jobs:           cfg.jobs,
		quiet:          subQuiet,
	}, subOut, stderr)
	if code != exitOK {
		r.warn("packout: 失败前的产物保留在：扫描 %s", scanOut)
		return code
	}

	sum := packSummary{Out: abs, ScanDir: scanOut}
	if cfg.sign || cfg.key != "" {
		keyPath := cfg.key
		if keyPath == "" {
			keyPath, err = defaultMinisignKeyPath()
			if err != nil {
				return r.usage("无法确定默认密钥路径：%v", err)
			}
		}
		signRes, serr := pack.Sign(abs, keyPath)
		if serr != nil {
			if errors.Is(serr, pack.ErrNoKey) || errors.Is(serr, pack.ErrKeyPermissions) ||
				errors.Is(serr, pack.ErrInvalidKey) || errors.Is(serr, pack.ErrInvalidConfig) {
				r.warn("packout: 产物保留在：扫描 %s，包 %s", scanOut, abs)
				return r.usage("pack sign: %v", serr)
			}
			r.warn("packout: 产物保留在：扫描 %s，包 %s", scanOut, abs)
			return r.fail(exitPartial, "pack sign: %v", serr)
		}
		sum.Signed = true
		sum.Fingerprint = signRes.KeyFingerprint
	}
	if sum.Signed {
		sum.Verify = fmt.Sprintf("packout verify %s --pubkey %s.pub", abs, cfg.keyOrDefault())
	} else {
		sum.Verify = "packout verify " + abs
	}
	r.value(sum)
	r.info("包已写入 %s", abs)
	if sum.Signed {
		r.warn("packout: 已签名，公钥指纹 SHA256:%s", sum.Fingerprint)
	} else {
		r.info("未签名；需要签名请加 --sign（或用 --key 指定私钥）")
	}
	r.info("校验：%s", sum.Verify)
	return exitOK
}

// keyOrDefault is only used to spell the verify hint.
func (cfg packConfig) keyOrDefault() string {
	if cfg.key != "" {
		return cfg.key
	}
	p, err := defaultMinisignKeyPath()
	if err != nil {
		return "~/.config/packout/minisign.key"
	}
	return p
}

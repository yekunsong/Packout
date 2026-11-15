package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/pack"
	"github.com/yekunsong/Packout/internal/profile"
)

type packConfig struct {
	out            string
	force          bool
	profileRef     string
	roots          rootList
	preset         string
	withSessions   bool
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
	seal           bool
	key            string
	noState        bool
	jobs           int
	json           bool
	quiet          bool
}

type packSummary struct {
	Out         string   `json:"out"`
	ScanDir     string   `json:"scan_dir,omitempty"`
	Entries     int      `json:"entries"`
	TotalBytes  int64    `json:"total_bytes"`
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
		return r.usage("pack 需要 <目录> 或 --out <包目录>")
	}
	// --with-sessions is the long spelling of --preset full. The same value is
	// harmless; any other preset contradicts it, so say both correct forms.
	if cfg.withSessions && cfg.preset != "" && !strings.EqualFold(strings.TrimSpace(cfg.preset), profile.PresetFull) {
		return r.usage("pack: --with-sessions 等价于 --preset full，不能与 --preset %s 同时使用；"+
			"二选一：packout pack <目录> --with-sessions 或 packout pack <目录> --preset full", cfg.preset)
	}
	if code, msg := checkOut(cfg.out, false, cfg.force); code != exitOK {
		return r.fail(code, "%s", withNext(msg, "packout pack "+cfg.out+" --force"))
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
	// The chain has one voice: inner steps stay quiet and only report counts
	// back, so the user sees one scan line and one package line, never an
	// internal temp directory or export's own "包已写入".
	var scanSum scanSummary
	var exportSum exportSummary

	code := runScan(ctx, scanConfig{
		profileRef:     cfg.profileRef,
		roots:          cfg.roots,
		out:            scanOut,
		followSymlinks: cfg.followSymlinks,
		preset:         cfg.preset,
		withSessions:   cfg.withSessions,
		include:        cfg.include,
		exclude:        cfg.exclude,
		sessionsSince:  cfg.sessionsSince,
		sessionsProj:   cfg.sessionsProj,
		sessionsMax:    cfg.sessionsMax,
		stableSalt:     cfg.stableSalt,
		jobs:           cfg.jobs,
		quiet:          true,
		noState:        true,
		onResult:       func(s scanSummary) { scanSum = s },
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
		quiet:          true,
		noState:        true,
		onResult:       func(s exportSummary) { exportSum = s },
	}, subOut, stderr)
	if code != exitOK {
		r.warn("packout: 失败前的产物保留在：扫描 %s", scanOut)
		return code
	}

	sum := packSummary{Out: abs, ScanDir: scanOut, Entries: exportSum.Entries, TotalBytes: exportSum.TotalBytes}
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
				next := "packout init 生成密钥，或给 --key <私钥>"
				if errors.Is(serr, pack.ErrKeyPermissions) {
					next = "chmod 600 <私钥> 后重试"
				}
				return r.usage("%s", withNext("pack sign: "+serr.Error(), next))
			}
			r.warn("packout: 产物保留在：扫描 %s，包 %s", scanOut, abs)
			return r.fail(exitPartial, "pack sign: %v", serr)
		}
		sum.Signed = true
		sum.Fingerprint = signRes.KeyFingerprint
	}
	if sum.Signed {
		// init writes the local public key into trusted_keys, so a package
		// signed with the default key verifies without --pubkey. Keep the
		// explicit hint only for an explicit --key or a trust store that does
		// not list this key yet.
		conf, _, _ := loadConfig()
		if cfg.key != "" || !trustedKeysHas(trustedKeysPath(conf), sum.Fingerprint) {
			sum.Verify = fmt.Sprintf("packout verify %s --pubkey %s.pub", abs, cfg.keyOrDefault())
		} else {
			sum.Verify = "packout verify " + abs
		}
	} else {
		sum.Verify = "packout verify " + abs
	}
	r.value(sum)
	if scanSum.Out != "" {
		r.info("已扫描 %d 个 Unit（残留 %d）", scanSum.Units, scanSum.Residual)
	}
	signedText := "未签名"
	if sum.Signed {
		signedText = "已签名"
	}
	r.info("包已写入 %s（%d 条目，%d 字节，%s）", abs, exportSum.Entries, exportSum.TotalBytes, signedText)
	if sum.Signed {
		r.warn("packout: 已签名，公钥指纹 SHA256:%s", sum.Fingerprint)
	} else {
		r.info("未签名；需要签名请加 --sign（或用 --key 指定私钥）")
	}
	r.info("校验：%s", sum.Verify)
	if !cfg.noState {
		recordPack(r.warn, abs, sum.Signed)
	}
	return exitOK
}

// trustedKeysHas reports whether path already lists fingerprint. A missing or
// broken store simply means "not yet".
func trustedKeysHas(path, fingerprint string) bool {
	if path == "" || fingerprint == "" {
		return false
	}
	keys, err := pack.LoadPublicKeys(path)
	if err != nil {
		return false
	}
	for i := range keys {
		if pack.KeyFingerprint(&keys[i]) == fingerprint {
			return true
		}
	}
	return false
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

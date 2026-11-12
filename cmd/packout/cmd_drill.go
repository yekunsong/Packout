package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"packout/internal/pack"
	"packout/internal/restore"
)

// drillConfig is restoreConfig narrowed to what a drill needs: a temporary
// target, an optional real write, and an optional retention of the temp dir.
type drillConfig struct {
	pkg             string
	into            string
	write           bool
	keep            bool
	allowUnverified bool
	pubkey          string
	identity        string
	passphrase      bool
	passphraseFile  string
	json            bool
	quiet           bool
}

// drillSummary is the machine-readable outcome of one drill.
type drillSummary struct {
	Package          string `json:"package"`
	TempDir          string `json:"temp_dir"`
	Created          bool   `json:"created"`
	Kept             bool   `json:"kept"`
	WouldRestoreInto string `json:"would_restore_into,omitempty"`
	DryRun           bool   `json:"dry_run"`
	SigConclusion    string `json:"sig_conclusion,omitempty"`
	Planned          int    `json:"planned"`
	PlannedBytes     int64  `json:"planned_bytes"`
	Restored         int    `json:"restored"`
	NeedsReinstall   int    `json:"needs_reinstall"`
	NeedsRelogin     int    `json:"needs_relogin"`
}

// drillTempPath picks a unique system-temp path without creating it.
func drillTempPath() string {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return filepath.Join(os.TempDir(), "packout-drill")
	}
	return filepath.Join(os.TempDir(), "packout-drill-"+hex.EncodeToString(rnd[:]))
}

func parseDrill(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("drill", flag.ContinueOnError)
	var cfg drillConfig
	fs.StringVar(&cfg.into, "into", "", "正式恢复时的目标目录（仅用于报告，drill 不写它）")
	fs.BoolVar(&cfg.write, "write", false, "真写系统临时目录（默认只干跑并打印计划）")
	fs.BoolVar(&cfg.keep, "keep", false, "保留临时目录并打印路径")
	fs.BoolVar(&cfg.allowUnverified, "allow-unverified", false, "SIG 结论不是 ok 时仍继续（tampered 与 empty 除外）")
	fs.StringVar(&cfg.pubkey, "pubkey", "", "公钥文件（默认读 <configDir>/trusted_keys）")
	fs.StringVar(&cfg.identity, "identity", "", "age identity（默认 ~/.config/packout/identity.age）")
	fs.BoolVar(&cfg.passphrase, "passphrase", false, "从终端读 secrets.age 口令")
	fs.StringVar(&cfg.passphraseFile, "passphrase-file", "", "从文件第一行读口令（与 --passphrase 互斥）")
	fs.BoolVar(&cfg.json, "json", false, "stdout 输出可解析的 JSON 摘要")
	fs.BoolVar(&cfg.quiet, "quiet", false, "只输出错误")
	pos, code := parse(fs, args, 1, drillHelp, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(pos) != 1 {
		const msg = "drill 需要一个包目录"
		if wantsJSON(args) {
			_ = jsonEncode(stdout, errObject{Error: msg, Exit: exitUsage})
		}
		fmt.Fprintf(stderr, "packout: %s\n\n%s", msg, drillHelp)
		return exitUsage
	}
	cfg.pkg = pos[0]
	return runDrill(ctx, cfg, stdout, stderr)
}

// runDrill restores a package into a fresh system temp directory. It always
// dry-runs first, only writes under --write, and never touches --into.
func runDrill(ctx context.Context, cfg drillConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.pkg == "" {
		return r.usage("drill 需要一个包目录")
	}
	conf, confPath, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s: %v", confPath, err)
	}
	if conf != nil {
		cliIdentity := cfg.identity
		applyConfigDefaults(conf, new(string), new(string), &cfg.identity, &cfg.pubkey, &rootList{})
		if cliIdentity == "" && (cfg.passphrase || cfg.passphraseFile != "") {
			cfg.identity = ""
		}
	}
	if cfg.passphrase && cfg.passphraseFile != "" {
		return r.usage("--passphrase 与 --passphrase-file 只能二选一")
	}
	if cfg.identity != "" && (cfg.passphrase || cfg.passphraseFile != "") {
		return r.usage("--identity 与 --passphrase/--passphrase-file 只能二选一")
	}
	crypt := pack.CryptOptions{IdentityPath: cfg.identity}
	if cfg.passphrase || cfg.passphraseFile != "" {
		pw, code := resolvePassphrase(r, cfg.passphrase, cfg.passphraseFile, stderr)
		if code != exitOK {
			return code
		}
		crypt.Passphrase = pw
	}

	// A dry run writes nothing, so it must not create a directory either. The
	// temp directory only exists when --write really lands files in it.
	created := cfg.write
	tmp := drillTempPath()
	if created {
		tmp, err = os.MkdirTemp("", "packout-drill-")
		if err != nil {
			return r.fail(exitUsage, "无法创建演练临时目录：%v", err)
		}
	}
	keep := cfg.keep && created
	defer func() {
		if created && !keep {
			os.RemoveAll(tmp)
		}
	}()
	target := filepath.Join(tmp, "restore")

	opt := restore.Options{
		PackageDir:      cfg.pkg,
		Into:            target,
		DryRun:          true,
		AllowUnverified: cfg.allowUnverified,
		PubKeyPath:      cfg.pubkey,
		TrustedKeysPath: trustedKeysPath(conf),
		Crypt:           crypt,
		OnKeySeen: func(fpr string, firstSeen bool) {
			if firstSeen {
				r.warn("packout: 首次见到公钥 SHA256:%s；本次按 TOFU 信任但未持久化。核对指纹后把公钥加入 %s（或重跑 packout init）",
					fpr, trustedKeysPath(conf))
			}
		},
	}
	if cfg.keep && !created {
		r.warn("packout: 干跑不创建临时目录，--keep 本次无效果；真写请加 --write")
	}

	// Step one is always a dry run: the plan is printed before anything lands.
	rep, err := restore.Run(ctx, opt)
	if ctx.Err() != nil {
		if rep != nil {
			printRestoreReport(r, rep)
		}
		return exitFromCtx(r, ctx)
	}
	if rep != nil {
		printRestoreReport(r, rep)
		if rep.AllowedUnverified {
			r.warn("\x1b[31mpackout: 警告：SIG 结论 %q —— 来源未确认，已按 --allow-unverified 继续；可用 --pubkey 核对来源\x1b[0m",
				rep.SigConclusion)
		}
	}
	sum := drillSummary{
		Package:          cfg.pkg,
		TempDir:          tmp,
		Kept:             keep,
		Created:          created,
		WouldRestoreInto: cfg.into,
		DryRun:           true,
	}
	if rep != nil {
		sum.SigConclusion = rep.SigConclusion
		sum.Planned = len(rep.Plan)
		sum.PlannedBytes = rep.PlannedBytes
	}
	if err != nil {
		r.value(sum)
		return r.fail(restoreExit(err), "%s", withNext(err.Error(), drillNext(err, cfg.pkg)))
	}

	if cfg.write {
		opt.DryRun = false
		rep, err = restore.Run(ctx, opt)
		if ctx.Err() != nil {
			if rep != nil {
				printRestoreReport(r, rep)
			}
			return exitFromCtx(r, ctx)
		}
		if rep != nil {
			printRestoreReport(r, rep)
			if rep.AllowedUnverified {
				r.warn("\x1b[31mpackout: 警告：SIG 结论 %q —— 来源未确认，已按 --allow-unverified 继续；可用 --pubkey 核对来源\x1b[0m",
					rep.SigConclusion)
			}
			sum.DryRun = false
			sum.SigConclusion = rep.SigConclusion
			sum.Restored = len(rep.Restored)
			sum.NeedsReinstall = len(rep.NeedsReinstall)
			sum.NeedsRelogin = len(rep.NeedsRelogin)
			sum.Planned = len(rep.Plan)
			sum.PlannedBytes = rep.PlannedBytes
		}
		if err != nil {
			r.value(sum)
			next := "packout restore " + cfg.pkg + " --into <目标目录> --in-place --force"
			return r.fail(restoreExit(err), "%s", withNext(err.Error(), next))
		}
	} else if rep != nil {
		sum.NeedsReinstall = len(rep.NeedsReinstall)
		sum.NeedsRelogin = len(rep.NeedsRelogin)
		sum.Restored = 0
	}

	r.value(sum)
	if !cfg.quiet && !cfg.json {
		mode := "干跑（未写入任何文件，加 --write 真写临时目录）"
		if cfg.write {
			mode = "已真实恢复到临时目录"
		}
		r.info("演练完成：%s", mode)
		if cfg.into != "" {
			r.info("若正式恢复的目标（本次未触碰）：%s", cfg.into)
		}
		switch {
		case !created:
			r.info("干跑未创建临时目录（加 --write 真写后再清理）")
		case keep:
			r.info("临时目录已保留：%s", tmp)
		default:
			r.info("临时目录已删除：%s", tmp)
		}
		r.info("摘要：计划 %d 项 / 已恢复 %d / 需重装 %d / 需人工重登 %d",
			sum.Planned, sum.Restored, sum.NeedsReinstall, sum.NeedsRelogin)
		if !cfg.write {
			r.info("正式执行：packout restore %s --into <目标目录>", cfg.pkg)
		}
	}
	return exitOK
}

// drillNext names the real next step for a gate failure instead of blaming the
// path or calling every non-ok verdict tampering.
func drillNext(err error, pkg string) string {
	switch {
	case errors.Is(err, restore.ErrTampered):
		return "不要恢复这个包；回到源机重新 packout pack <目录> --seal"
	case errors.Is(err, restore.ErrUnverified):
		return "packout verify " + pkg + " 看实际结论；确认来源后再加 --allow-unverified"
	default:
		return "packout verify " + pkg + " 看实际结论"
	}
}

package main

import (
	"context"
	"errors"
	"io"

	"packout/internal/pack"
	"packout/internal/restore"
)

type restoreConfig struct {
	pkg             string
	into            string
	inPlace         bool
	force           bool
	dryRun          bool
	allowUnverified bool
	pubkey          string
	identity        string
	passphrase      bool
	json            bool
	quiet           bool
}

// runRestore owns only presentation: the order and every safety check live in
// internal/restore.
func runRestore(ctx context.Context, cfg restoreConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.pkg == "" {
		return r.usage("restore 需要一个包目录")
	}
	if cfg.into == "" {
		return r.usage("restore 需要 --into <目标目录>")
	}
	if len(cfg.pubkey) > 0 && cfg.allowUnverified {
		// Both are legal; --allow-unverified only applies when verify fails.
	}
	if cfg.identity != "" && cfg.passphrase {
		return r.usage("--identity 与 --passphrase 只能二选一")
	}
	crypt := pack.CryptOptions{IdentityPath: cfg.identity}
	if cfg.passphrase {
		pw, perr := readPassphrase(passphraseStdin, stderr)
		if perr != nil {
			return r.usage("读取口令失败：%v", perr)
		}
		if len(pw) == 0 {
			return r.usage("口令为空")
		}
		crypt.Passphrase = pw
	}

	opt := restore.Options{
		PackageDir:      cfg.pkg,
		Into:            cfg.into,
		InPlace:         cfg.inPlace,
		Force:           cfg.force,
		DryRun:          cfg.dryRun,
		AllowUnverified: cfg.allowUnverified,
		PubKeyPath:      cfg.pubkey,
		Crypt:           crypt,
		OnKeySeen: func(fpr string, firstSeen bool) {
			if firstSeen {
				r.warn("packout: 首次见到公钥 SHA256:%s；已按 TOFU 信任本次，请通过另一渠道核对指纹", fpr)
			}
		},
	}
	rep, err := restore.Run(ctx, opt)
	if ctx.Err() != nil {
		if rep != nil {
			printRestoreReport(r, rep)
		}
		return exitFromCtx(r, ctx)
	}
	if rep != nil && rep.AllowedUnverified {
		r.warn("\x1b[31mpackout: 警告：SIG 结论 %q —— 内容完整但未确认来源，已按 --allow-unverified 继续\x1b[0m",
			rep.SigConclusion)
	}
	if rep != nil {
		if r.json && err != nil {
			r.value(map[string]any{"restore": rep, "error": err.Error(), "exit": restoreExit(err)})
			r.wroteValue = true
		} else {
			r.value(rep)
		}
		printRestoreReport(r, rep)
	}
	if err != nil {
		return r.fail(restoreExit(err), "%v", err)
	}
	return exitOK
}

func restoreExit(err error) int {
	switch {
	case errors.Is(err, restore.ErrUsage):
		return exitUsage
	case errors.Is(err, restore.ErrDestNotEmpty):
		return exitNotEmpty
	case errors.Is(err, restore.ErrCanceled):
		return exitCanceled
	default:
		return exitPartial
	}
}

func printRestoreReport(r *reporter, rep *restore.Report) {
	if rep == nil || r.quiet || r.json {
		return
	}
	signed := "未签名"
	if rep.Signed {
		signed = "已签名"
	}
	r.info("SIG 结论: %s（%s）", rep.SigConclusion, signed)
	r.info("目标: %s", rep.Target)
	if rep.DryRun {
		r.info("干跑：只跑前四步，未写入任何文件")
	}
	r.info("计划 (%d 项，%d 字节):", len(rep.Plan), rep.PlannedBytes)
	for _, p := range rep.Plan {
		action := map[string]string{"create": "新建", "overwrite": "覆盖", "same": "相同"}[p.Action]
		unit := ""
		if p.UnitID != "" {
			unit = " ← " + p.UnitID
		}
		r.info("  %s %s%s", action, p.Path, unit)
	}
	r.info("已恢复 (%d):", len(rep.Restored))
	for _, x := range rep.Restored {
		unit := ""
		if x.UnitID != "" {
			unit = " ← " + x.UnitID
		}
		r.info("  %s%s", x.Path, unit)
	}
	r.info("需重装 (%d):", len(rep.NeedsReinstall))
	for _, n := range rep.NeedsReinstall {
		r.info("  %s %s (%s)", n.UnitID, n.Path, n.Entry)
	}
	r.info("需人工重登 (%d):", len(rep.NeedsRelogin))
	for _, n := range rep.NeedsRelogin {
		r.info("  %s %s (%s)", n.UnitID, n.Path, n.Entry)
	}
	for _, p := range rep.Problems {
		r.warn("packout: %s %s: %s", p.Code, p.Path, p.Detail)
	}
	for _, w := range rep.Warnings {
		r.warn("packout: 警告：%s", w)
	}
}

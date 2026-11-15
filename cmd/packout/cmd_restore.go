package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"packout/internal/pack"
	"packout/internal/restore"
)

type restoreConfig struct {
	noState         bool
	pkg             string
	into            string
	maps            mapList
	inPlace         bool
	force           bool
	dryRun          bool
	allowUnverified bool
	pubkey          string
	identity        string
	passphrase      bool
	passphraseFile  string
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
	conf, confPath, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s: %v", confPath, err)
	}
	if conf != nil {
		cliIdentity := cfg.identity
		applyConfigDefaults(conf, new(string), new(string), &cfg.identity, &cfg.pubkey, &rootList{})
		// An explicit passphrase beats a config identity; otherwise the
		// mutual-exclusion check below would reject a CLI-only choice.
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

	opt := restore.Options{
		PackageDir:      cfg.pkg,
		Into:            cfg.into,
		Map:             cfg.maps.values(),
		InPlace:         cfg.inPlace,
		Force:           cfg.force,
		DryRun:          cfg.dryRun,
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
	rep, err := restore.Run(ctx, opt)
	if ctx.Err() != nil {
		if rep != nil {
			printRestoreReport(r, rep, "目标")
		}
		return exitFromCtx(r, ctx)
	}
	if rep != nil && rep.AllowedUnverified {
		r.warn("\x1b[31mpackout: 警告：SIG 结论 %q —— 来源未确认，已按 --allow-unverified 继续；可用 --pubkey 核对来源\x1b[0m",
			rep.SigConclusion)
	}
	if rep != nil {
		if r.json && err != nil {
			r.value(map[string]any{"restore": rep, "error": err.Error(), "exit": restoreExit(err)})
			r.wroteValue = true
		} else {
			r.value(rep)
		}
		printRestoreReport(r, rep, "目标")
	}
	if err != nil {
		return r.fail(restoreExit(err), "%s", withNext(err.Error(), restoreNext(err, cfg)))
	}
	if rep != nil {
		printLanding(r, rep)
	}
	if !cfg.dryRun && !cfg.noState && rep != nil {
		recordRestore(r.warn, cfg.pkg, cfg.into, len(rep.Restored))
	}
	return exitOK
}

// restoreNext turns the common restore failures into the next full command.
func restoreNext(err error, cfg restoreConfig) string {
	switch {
	case errors.Is(err, restore.ErrDestNotEmpty):
		return "packout restore " + cfg.pkg + " --into " + cfg.into + " --in-place --force"
	case errors.Is(err, restore.ErrUsage):
		return "packout help restore 看参数，或先 packout drill " + cfg.pkg
	case errors.Is(err, restore.ErrCanceled):
		return "packout restore " + cfg.pkg + " --into " + cfg.into + " --dry-run 先看计划"
	case errors.Is(err, restore.ErrTampered):
		return "不要恢复这个包；回到源机重新 packout pack <目录> --seal"
	case errors.Is(err, restore.ErrDecrypt):
		return decryptNext(err, cfg.pkg, cfg.into, cfg.identity,
			cfg.passphrase || cfg.passphraseFile != "", cfg.allowUnverified)
	case errors.Is(err, restore.ErrUnverified):
		return "packout verify " + cfg.pkg + " 看结论；确认来源后再加 --allow-unverified 重跑"
	default:
		return "packout verify " + cfg.pkg + " 看结论；未初始化先 packout init"
	}
}

// decryptNext explains how a secrets.age package is opened on another machine.
// A recipient-encrypted package only opens with the source machine's identity;
// a passphrase-encrypted one needs the same passphrase. Both were invisible in
// the old default next step ("verify; init first"), which is why a real user
// got stuck after moving to a new machine.
func decryptNext(err error, pkg, into, identity string, usePassphrase, allowUnverified bool) string {
	cmd := "packout restore " + pkg + " --into " + into
	if into == "" {
		cmd = "packout restore " + pkg + " --into <目标目录>"
	}
	// Carry the user's own unverified choice forward so the suggested command
	// does not bounce straight back to the signature gate. It is not an
	// endorsement: the parenthetical still says to check provenance first.
	if allowUnverified {
		cmd += " --allow-unverified"
	}
	if usePassphrase {
		return cmd + " --passphrase-file <口令文件>\n" +
			"（核对口令：--passphrase 输入或 --passphrase-file 第一行须与打包时一致；" +
			"仍失败就回源机重新 packout pack <目录> --seal --passphrase-file ./pw）"
	}
	if errors.Is(err, fs.ErrNotExist) {
		idPath := identity
		if idPath == "" {
			if p, derr := defaultIdentityPath(); derr == nil {
				idPath = p
			}
		}
		if idPath == "" {
			idPath = "<configDir>/identity.age"
		}
		note := "这个包的 secrets.age 用 recipient 加密，只有打包时源机的 age identity 能解开：" +
			"经安全渠道（如加密 U 盘或受信任的传输）把源机 identity.age 带到新机，" +
			"加 --identity <源机 identity.age>，或放到 " + idPath + "（0600）后去掉 --identity"
		if allowUnverified {
			note += "；--allow-unverified 只沿用本次选择，来源没核对过就先 packout verify 确认"
		}
		return cmd + " --identity <源机 identity.age>\n" +
			"（" + note + "；identity.age 是私钥，别放进包、别提交仓库；" +
			"若打包时用的是口令，改用 --passphrase / --passphrase-file <口令文件>）"
	}
	detail := "核对 --identity 是否指向打包时源机的 identity.age，或 --passphrase-file 的口令是否与打包时一致；" +
		"identity.age 是私钥，只经安全渠道带到新机；仍失败就回源机重新 packout pack <目录> --seal"
	if allowUnverified {
		detail += "；--allow-unverified 只沿用本次选择，来源没核对过就先 packout verify 确认"
	}
	return cmd + "\n（" + detail + "）"
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

func printRestoreReport(r *reporter, rep *restore.Report, targetLabel string) {
	if rep == nil || r.quiet || r.json {
		return
	}
	signed := "未签名"
	if rep.Signed {
		signed = "已签名"
	}
	if targetLabel == "" {
		targetLabel = "目标"
	}
	r.info("SIG 结论: %s（%s）", rep.SigConclusion, signed)
	r.info("%s: %s", targetLabel, rep.Target)
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
	// Overwrites are irreversible here: packout keeps no backup. Only say so
	// when something was actually replaced (never on --dry-run).
	if !rep.DryRun && rep.Overwritten > 0 {
		r.info("已覆盖 %d 个既有文件（packout 不做备份；需要保留请先自行复制）", rep.Overwritten)
	}
}

// printLanding names where each role actually landed (absolute paths, after
// applying --map), so a user on a new machine knows what to copy where.
// When every role came from --map the copy hint would be self-contradictory:
// the files are already at their final place.
func printLanding(r *reporter, rep *restore.Report) {
	if rep == nil || r.quiet || r.json || len(rep.Landing) == 0 {
		return
	}
	parts := make([]string, 0, len(rep.Landing))
	allMapped := true
	for _, l := range rep.Landing {
		if !l.Mapped {
			allMapped = false
		}
		parts = append(parts, fmt.Sprintf("%s → %s", l.Role, l.Path))
	}
	line := "落地：" + strings.Join(parts, "，")
	switch {
	case allMapped && rep.DryRun:
		line += "（--map 生效；干跑未写入）"
	case allMapped:
		line += "（--map 生效，已直接写到这里）"
	default:
		line += "（把需要的子目录复制到目标机器对应根，或见 --map）"
	}
	r.info("%s", line)
}

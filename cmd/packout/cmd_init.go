package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"filippo.io/age"

	"packout/internal/pack"
)

type initConfig struct {
	force bool
	yes   bool
	json  bool
	quiet bool
}

// initStdin is the interactive source; tests replace it.
var initStdin io.Reader = os.Stdin

type initKeyResult struct {
	Path        string `json:"path"`
	Created     bool   `json:"created"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type initSummary struct {
	Config           string            `json:"config"`
	Roots            map[string]string `json:"roots"`
	Identity         initKeyResult     `json:"identity"`
	Minisign         initKeyResult     `json:"minisign"`
	TrustedKeys      string            `json:"trusted_keys"`
	TrustedKeysAdded bool              `json:"trusted_keys_added"`
	Next             []string          `json:"next"`
}

// runInit writes a config after per-root confirmation and creates the missing
// age identity / minisign key pair. No existing file is ever overwritten.
func runInit(ctx context.Context, cfg initConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	path, err := configPath()
	if err != nil {
		return r.usage("无法确定配置路径：%v", err)
	}
	existing, _, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s 不可解析：%v（修好或移走后重试）", path, err)
	}
	if existing != nil && !cfg.force {
		return r.usage("配置已存在 %s（用 --force 覆盖；密钥不会被覆盖）", path)
	}

	cands := detectInitRoots()
	if len(cands) == 0 {
		return r.usage("没有可写的根（连 home 都取不到）")
	}
	// One reader for all questions: a fresh bufio.Reader per prompt would
	// swallow the remaining buffered answers on its first Read.
	answers := bufio.NewReader(initStdin)
	accepted := map[string]string{}
	for _, role := range orderedInitRoles(cands) {
		p := cands[role]
		if !cfg.yes {
			fmt.Fprintf(stderr, "packout: 把 %s 根 %s 写进配置？[Y/n] ", role, p)
			if !confirm(answers) {
				continue
			}
		}
		accepted[role] = p
	}
	if len(accepted) == 0 {
		return r.usage("没有选择任何根，未写配置")
	}

	identityPath, err := defaultIdentityPath()
	if err != nil {
		return r.usage("无法确定 identity 路径：%v", err)
	}
	keyPath, err := defaultMinisignKeyPath()
	if err != nil {
		return r.usage("无法确定密钥路径：%v", err)
	}
	trustedPath, err := defaultTrustedKeysPath()
	if err != nil {
		return r.usage("无法确定 trusted_keys 路径：%v", err)
	}
	profileRef, preset := defaultProfile, "standard"
	if existing != nil {
		// --force rewrites the config, not the identity it points at.
		if existing.Identity != "" {
			identityPath = existing.Identity
		}
		if existing.TrustedKeys != "" {
			trustedPath = existing.TrustedKeys
		}
		if existing.Profile != "" {
			profileRef = existing.Profile
		}
		if existing.Preset != "" {
			preset = existing.Preset
		}
		for role, p := range existing.Roots {
			if _, ok := accepted[role]; !ok {
				accepted[role] = p
			}
		}
	}

	res := initSummary{Config: path, Roots: accepted}
	res.Identity, err = ensureIdentity(identityPath)
	if err != nil {
		return r.fail(exitUsage, "生成 age identity：%v", err)
	}
	res.Minisign, err = ensureMinisignKey(keyPath)
	if err != nil {
		return r.fail(exitUsage, "生成 minisign 密钥：%v", err)
	}
	trusted, terr := ensureTrustedKeys(trustedPath, keyPath)
	if terr == nil {
		res.TrustedKeys = trustedPath
		res.TrustedKeysAdded = trusted.Added
	}

	c := &config{
		Version:     configVersion,
		Profile:     profileRef,
		Preset:      preset,
		Roots:       accepted,
		Identity:    identityPath,
		TrustedKeys: trustedPath,
	}
	if _, err := writeConfig(c); err != nil {
		return r.fail(exitUsage, "写配置 %s: %v", path, err)
	}

	res.Next = []string{
		"packout pack <目录> --seal     # 导出并签名",
		"packout pack <目录> --seal --passphrase-file ./pw   # 跨机器推荐：口令加密 secrets.age，新机用同一口令文件 --passphrase-file 恢复",
		"packout pack <目录> --seal --recipient <age1…>      # recipient 加密：须经安全渠道把源机 identity.age 带到新机，restore 时 --identity",
		"packout verify <包目录>        # 应得到 ok",
		"packout sign <包目录>          # 只对已导出、未签名的包",
		"packout restore <包目录> --into ./restore-test --dry-run",
		"packout restore <包目录> --into ./restore-test",
		"claude mcp add packout -- packout mcp --out ./out",
	}
	r.value(res)
	r.info("配置已写入 %s", path)
	for _, role := range sortedKeys(accepted) {
		r.info("  root %s=%s", role, accepted[role])
	}
	if res.Identity.Created {
		r.info("已生成 age identity %s（0600），公钥：%s", res.Identity.Path, res.Identity.PublicKey)
	} else {
		r.info("age identity 已存在，未覆盖：%s", res.Identity.Path)
	}
	if res.Minisign.Created {
		r.info("已生成 minisign 密钥 %s（私钥 0600），公钥 %s.pub，指纹 SHA256:%s",
			res.Minisign.Path, res.Minisign.Path, res.Minisign.Fingerprint)
	} else {
		r.info("minisign 密钥已存在，未覆盖：%s", res.Minisign.Path)
	}
	switch {
	case terr != nil:
		r.warn("packout: 无法把本机公钥写入 %s：%v（verify 需用 --pubkey）", trustedPath, terr)
	case trusted.Added:
		r.info("已把本机公钥写入 %s（0600），之后 packout verify 可直接确认本机签名的包；指纹 SHA256:%s",
			trustedPath, trusted.Fingerprint)
	case trusted.Warning != "":
		r.warn("packout: %s 已有无法解析的内容，未修改（请手动检查）：%s", trustedPath, trusted.Warning)
	default:
		r.info("trusted_keys 已包含本机公钥，未改动：%s", trustedPath)
	}
	r.info("下一步：packout pack <目录> --seal 打出一份会话基线包（或按下面顺序手动走一遍）：")
	for _, s := range res.Next {
		r.info("  %s", s)
	}
	r.info("恢复演练：restore --dry-run 只列计划；首次真恢复请先往空目录里试。")
	return exitOK
}

// detectInitRoots proposes roots. home is always offered; repo only when the
// current directory looks like a project; Windows also offers the per-user
// appdata roots when they exist.
func detectInitRoots() map[string]string {
	out := map[string]string{}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out["home"] = home
	}
	if cwd, err := os.Getwd(); err == nil {
		for _, marker := range []string{".git", ".claude", "CLAUDE.md"} {
			if _, err := os.Lstat(filepath.Join(cwd, marker)); err == nil {
				out["repo"] = cwd
				break
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, kv := range [][2]string{{"appdata", "APPDATA"}, {"localappdata", "LOCALAPPDATA"}} {
			if p := os.Getenv(kv[1]); p != "" {
				if fi, err := os.Stat(p); err == nil && fi.IsDir() {
					out[kv[0]] = p
				}
			}
		}
	}
	return out
}

// initRoleOrder fixes the prompt order across platforms so a scripted answer
// stream means the same thing on every OS. Unknown future roles are appended
// alphabetically.
var initRoleOrder = []string{"home", "repo", "appdata", "localappdata"}

func orderedInitRoles(cands map[string]string) []string {
	out := make([]string, 0, len(cands))
	for _, role := range initRoleOrder {
		if _, ok := cands[role]; ok {
			out = append(out, role)
		}
	}
	known := map[string]bool{}
	for _, role := range initRoleOrder {
		known[role] = true
	}
	extra := make([]string, 0, len(cands))
	for role := range cands {
		if !known[role] {
			extra = append(extra, role)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// confirm reads one answer line; empty or EOF means yes, matching the [Y/n]
// prompt text.
func confirm(r *bufio.Reader) bool {
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no":
		return false
	default:
		return true
	}
}

// ensureIdentity generates an age identity unless the file exists.
func ensureIdentity(path string) (initKeyResult, error) {
	res := initKeyResult{Path: path}
	if _, err := os.Lstat(path); err == nil {
		return res, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, err
	}
	if err := writeFileAtomic(path, []byte(id.String()+"\n"), 0o600); err != nil {
		return res, err
	}
	res.Created = true
	res.PublicKey = id.Recipient().String()
	return res, nil
}

// ensureMinisignKey generates a minisign pair unless the private key exists.
func ensureMinisignKey(path string) (initKeyResult, error) {
	res := initKeyResult{Path: path}
	if _, err := os.Lstat(path); err == nil {
		return res, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	fpr, err := pack.GenerateKeyPair(path, path+".pub")
	if err != nil {
		if errors.Is(err, pack.ErrKeyExists) {
			return res, nil
		}
		return res, err
	}
	res.Created = true
	res.Fingerprint = fpr
	return res, nil
}

// trustedKeysOutcome describes what init did to the trust store.
type trustedKeysOutcome struct {
	Added       bool
	Present     bool
	Fingerprint string
	// Warning is set when the existing file could not be parsed; the file is
	// then left byte-for-byte untouched.
	Warning string
}

// ensureTrustedKeys publishes the local public key in the trust store used by
// verify. A missing file is created 0600; an existing file is only appended to,
// never rewritten or truncated, and a malformed one is left alone.
func ensureTrustedKeys(path, keyPath string) (trustedKeysOutcome, error) {
	var out trustedKeysOutcome
	pubText, fpr, err := pack.PublicKeyText(keyPath)
	if err != nil {
		return out, err
	}
	out.Fingerprint = fpr
	pubLine := minisignKeyLine(pubText)
	if pubLine == "" {
		return out, errors.New("派生出的公钥为空")
	}

	existing, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		for _, raw := range strings.Split(string(existing), "\n") {
			if strings.TrimSpace(raw) == pubLine {
				out.Present = true
				return out, nil
			}
		}
		if !blankKeysData(existing) {
			if _, perr := pack.LoadPublicKeys(path); perr != nil {
				out.Warning = perr.Error()
				return out, nil
			}
		}
	case errors.Is(rerr, fs.ErrNotExist):
		// Created below.
	default:
		return out, rerr
	}

	var content []byte
	if len(existing) > 0 {
		content = append(content, existing...)
		if !strings.HasSuffix(string(content), "\n") {
			content = append(content, '\n')
		}
	} else {
		content = append(content, "# packout trusted public keys; one minisign public key per line\n"...)
	}
	content = append(content, pubText...)
	content = append(content, '\n')
	if err := writeFileAtomic(path, content, 0o600); err != nil {
		return out, err
	}
	out.Added = true
	return out, nil
}

// minisignKeyLine returns the base64 key line from a public-key text.
func minisignKeyLine(text string) string {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return line
	}
	return ""
}

// blankKeysData reports whether data holds no key lines (blank/comments only).
func blankKeysData(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return false
	}
	return true
}

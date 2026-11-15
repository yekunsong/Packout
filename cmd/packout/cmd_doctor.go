package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"filippo.io/age"

	"github.com/yekunsong/Packout/internal/pack"
	"github.com/yekunsong/Packout/internal/profile"
)

type doctorConfig struct {
	out     string
	profile string
	json    bool
	quiet   bool
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail,omitempty"`
	Path   string `json:"path,omitempty"`
}

type doctorSummary struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

// runDoctor is read-only: it inspects, never fixes. Any fail means exit 2.
func runDoctor(ctx context.Context, cfg doctorConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}
	sum := doctorSummary{OK: true}

	confPath, pathErr := configPath()
	if pathErr != nil {
		sum.add("config", "fail", pathErr.Error(), "")
	}

	var conf *config
	if pathErr == nil {
		c, _, err := loadConfig()
		switch {
		case err != nil:
			sum.add("config", "fail", err.Error(), confPath)
		case c == nil:
			sum.add("config", "warn", "未发现配置；运行 packout init 生成", confPath)
		default:
			conf = c
			sum.add("config", "ok", "配置可解析", confPath)
		}
	}

	// Roots from config; a config that names a role its profile does not
	// declare is a fail rather than silently unused.
	profRef := cfg.profile
	if profRef == "" && conf != nil {
		profRef = conf.Profile
	}
	if profRef == "" {
		profRef = defaultProfile
	}
	prof, profErr := loadProfile(profRef, io.Discard)
	if conf != nil && len(conf.Roots) > 0 {
		if profErr != nil {
			sum.add("roots", "fail", "无法加载 profile "+profRef+"："+profErr.Error(), "")
		} else {
			for _, role := range sortedKeys(conf.Roots) {
				p := conf.Roots[role]
				if _, ok := prof.Roots[role]; !ok {
					sum.add("root:"+role, "fail", "profile 未声明该 role", p)
					continue
				}
				checkReadable(&sum, "root:"+role, p)
			}
		}
	} else if conf != nil {
		sum.add("roots", "warn", "配置没有 roots；scan 将回落到 profile 默认值", "")
	}

	identity, err := defaultIdentityPath()
	if err == nil && conf != nil && conf.Identity != "" {
		identity = conf.Identity
	}
	checkSecretFile(&sum, "identity", identity, func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = age.ParseX25519Identity(string(trimLine(data)))
		return err
	})

	keyPath, err := defaultMinisignKeyPath()
	if err == nil {
		// Config has no key field; the default location is the only one.
		checkSecretFile(&sum, "signing_key", keyPath, nil)
	}

	trusted, err := defaultTrustedKeysPath()
	if err == nil && conf != nil && conf.TrustedKeys != "" {
		trusted = conf.TrustedKeys
	}
	if _, statErr := os.Lstat(trusted); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			sum.add("trusted_keys", "warn", "不存在；verify 会给出 bad-signature（用 --pubkey 或重跑 packout init）", trusted)
		} else {
			sum.add("trusted_keys", "fail", statErr.Error(), trusted)
		}
	} else if keys, kerr := pack.LoadPublicKeys(trusted); kerr != nil {
		sum.add("trusted_keys", "fail", kerr.Error(), trusted)
	} else {
		sum.add("trusted_keys", "ok", fmt.Sprintf("%d 个公钥", len(keys)), trusted)
	}

	if cfg.out == "" {
		sum.add("out_parent", "warn", "未给 --out，跳过父目录可写检查", "")
	} else {
		checkOutParent(&sum, cfg.out)
	}

	diskBase := mustHome()
	if confPath != "" {
		diskBase = confPath
	}
	checkDisk(&sum, nearestExisting(diskBase))

	checkSelftest(&sum, prof, profErr)

	if _, err := exec.LookPath("claude"); err == nil {
		sum.add("mcp_hint", "ok", "已找到 claude CLI；注册：claude mcp add packout -- packout mcp --out DIR", "")
	} else {
		sum.add("mcp_hint", "warn", "PATH 中没有 claude；可稍后手动注册 MCP", "")
	}

	for _, c := range sum.Checks {
		if c.Status == "fail" {
			sum.OK = false
		}
	}
	r.value(sum)
	if !cfg.quiet && !cfg.json {
		for _, c := range sum.Checks {
			line := fmt.Sprintf("  %-5s %s", c.Status, c.Name)
			if c.Detail != "" {
				line += "：" + c.Detail
			}
			if c.Path != "" {
				line += "（" + c.Path + "）"
			}
			r.info("%s", line)
		}
	}
	for _, c := range sum.Checks {
		if c.Status == "fail" {
			r.warn("packout: FAIL %s %s %s", c.Name, c.Detail, c.Path)
		}
	}
	if !sum.OK {
		if r.json && !r.wroteValue {
			r.value(sum)
		}
		return exitPartial
	}
	return exitOK
}

func (s *doctorSummary) add(name, status, detail, path string) {
	s.Checks = append(s.Checks, doctorCheck{Name: name, Status: status, Detail: detail, Path: path})
}

func checkReadable(s *doctorSummary, name, path string) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.add(name, "fail", "不存在", path)
		} else {
			s.add(name, "fail", err.Error(), path)
		}
		return
	}
	if !fi.IsDir() {
		s.add(name, "fail", "不是目录", path)
		return
	}
	d, err := os.Open(path)
	if err != nil {
		s.add(name, "fail", "不可读："+err.Error(), path)
		return
	}
	defer d.Close()
	if _, err := d.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		s.add(name, "fail", "不可枚举："+err.Error(), path)
		return
	}
	s.add(name, "ok", "存在且可读", path)
}

func checkSecretFile(s *doctorSummary, name, path string, validate func(string) error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.add(name, "warn", "不存在", path)
		} else {
			s.add(name, "fail", err.Error(), path)
		}
		return
	}
	if !fi.Mode().IsRegular() {
		s.add(name, "fail", "不是普通文件", path)
		return
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			s.add(name, "fail", fmt.Sprintf("权限 %04o 过宽，应为 0600", perm), path)
			return
		}
	}
	if validate != nil {
		if err := validate(path); err != nil {
			s.add(name, "fail", "无法解析："+err.Error(), path)
			return
		}
	}
	s.add(name, "ok", "存在、权限合适", path)
}

func checkOutParent(s *doctorSummary, out string) {
	abs, err := filepath.Abs(out)
	if err != nil {
		s.add("out_parent", "fail", err.Error(), out)
		return
	}
	parent := nearestExisting(filepath.Dir(abs))
	fi, err := os.Stat(parent)
	if err != nil {
		s.add("out_parent", "fail", err.Error(), parent)
		return
	}
	if !fi.IsDir() {
		s.add("out_parent", "fail", "父路径不是目录", parent)
		return
	}
	f, err := os.CreateTemp(parent, ".packout-doctor-")
	if err != nil {
		s.add("out_parent", "fail", "不可写："+err.Error(), parent)
		return
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	s.add("out_parent", "ok", "可写", parent)
}

func checkDisk(s *doctorSummary, base string) {
	free, err := freeBytes(base)
	if err != nil {
		s.add("disk", "warn", "无法读取磁盘余量："+err.Error(), base)
		return
	}
	const mib = uint64(1 << 20)
	switch {
	case free < 100*mib:
		s.add("disk", "fail", fmt.Sprintf("可用 %d MiB，低于 100 MiB", free/mib), base)
	case free < 1024*mib:
		s.add("disk", "warn", fmt.Sprintf("可用 %d MiB，低于 1 GiB", free/mib), base)
	default:
		s.add("disk", "ok", fmt.Sprintf("可用 %d MiB", free/mib), base)
	}
}

func checkSelftest(s *doctorSummary, p *profile.Profile, loadErr error) {
	if loadErr != nil || p == nil {
		s.add("profile_selftest", "fail", "profile 不可加载", "")
		return
	}
	res, err := profile.RunSelfTest(p, "")
	if err != nil {
		s.add("profile_selftest", "fail", err.Error(), "")
		return
	}
	if !res.Passed {
		s.add("profile_selftest", "fail", fmt.Sprintf("%d 项断言中 %d 项失败", res.Checks, len(res.Failures)), "")
		return
	}
	s.add("profile_selftest", "ok", fmt.Sprintf("%s：%d 项断言通过", p.Name, res.Checks), "")
}

func mustHome() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

// nearestExisting walks up until an existing path is found, so checks against
// a not-yet-created config directory still report something useful.
func nearestExisting(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p || parent == "" {
			return p
		}
		p = parent
	}
}

func trimLine(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

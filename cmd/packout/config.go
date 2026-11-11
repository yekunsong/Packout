package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// configVersion is the only config schema this build understands.
const configVersion = 1

// config is ~/.config/packout/config.json (Unix) or
// %APPDATA%\packout\config.json (Windows). Command line flags always win over
// it; it exists so init/doctor and the daily commands need one less repeated
// argument, not to become a second decision layer.
type config struct {
	Version     int               `json:"version"`
	Profile     string            `json:"profile,omitempty"`
	Preset      string            `json:"preset,omitempty"`
	Roots       map[string]string `json:"roots,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	TrustedKeys string            `json:"trusted_keys,omitempty"`
}

// configDir returns the per-user directory holding config and keys. It follows
// the platform convention (XDG on Unix, %APPDATA% on Windows) so tests can
// redirect it with XDG_CONFIG_HOME / AppData.
func configDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "packout"), nil
}

// configPath is the single place that spells the config file location.
func configPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// defaultIdentityPath is <configDir>/identity.age.
func defaultIdentityPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "identity.age"), nil
}

// defaultMinisignKeyPath is <configDir>/minisign.key.
func defaultMinisignKeyPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "minisign.key"), nil
}

// defaultTrustedKeysPath is <configDir>/trusted_keys.
func defaultTrustedKeysPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "trusted_keys"), nil
}

// loadConfig reads and strictly validates the config. A missing file returns
// (nil, path, nil). Any read or parse problem returns the path so the caller
// can name it in the exit-3 message.
func loadConfig() (*config, string, error) {
	path, err := configPath()
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, path, nil
		}
		return nil, path, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c config
	if err := dec.Decode(&c); err != nil {
		return nil, path, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, path, errors.New("多余内容（应只有一个 JSON 对象）")
	}
	if c.Version != configVersion {
		return nil, path, fmt.Errorf("不支持的 version %d（需要 %d）", c.Version, configVersion)
	}
	for role, p := range c.Roots {
		if role == "" {
			return nil, path, errors.New("roots 含空 role")
		}
		if p == "" {
			return nil, path, fmt.Errorf("roots.%s 为空路径", role)
		}
		if !filepath.IsAbs(p) {
			return nil, path, fmt.Errorf("roots.%s 不是绝对路径：%s", role, p)
		}
	}
	return &c, path, nil
}

// configRoots turns the config root map into a deterministic rootList.
func (c *config) configRoots() rootList {
	if c == nil || len(c.Roots) == 0 {
		return nil
	}
	names := make([]string, 0, len(c.Roots))
	for role := range c.Roots {
		names = append(names, role)
	}
	sort.Strings(names)
	out := make(rootList, 0, len(names))
	for _, role := range names {
		out = append(out, rootFlag{role: role, path: c.Roots[role], raw: role + "=" + c.Roots[role]})
	}
	return out
}

// applyConfigDefaults fills CLI gaps. The precedence rule is the task's:
// explicit flags always win; config only fills what the user left out.
func applyConfigDefaults(c *config, profileRef, preset, identity, pubkey *string, roots *rootList) {
	if c == nil {
		return
	}
	if *profileRef == "" {
		*profileRef = c.Profile
	}
	if *preset == "" {
		*preset = c.Preset
	}
	if *identity == "" {
		*identity = c.Identity
	}
	if *pubkey == "" {
		*pubkey = c.TrustedKeys
	}
	if len(*roots) == 0 {
		*roots = c.configRoots()
	}
}

// writeConfig lands the config atomically with 0600 on Unix. Parent dirs are
// 0700 so the directory itself never leaks more than the files.
func writeConfig(c *config) (string, error) {
	path, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return path, err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return path, err
	}
	data = append(data, '\n')
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return path, err
	}
	if runtime.GOOS != "windows" {
		// writeFileAtomic chmods the temporary file, but be explicit about the
		// final path too: a replaced file keeps the temp mode, yet a stale
		// inode from an interrupted run must not win.
		if err := os.Chmod(path, 0o600); err != nil {
			return path, err
		}
	}
	return path, nil
}

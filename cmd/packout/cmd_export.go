package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"packout/internal/manifest"
	"packout/internal/profile"

	"packout/internal/pack"
)

type exportConfig struct {
	src            string
	out            string
	force          bool
	report         string
	identity       string
	withSecrets    bool
	recipients     stringList
	passphrase     bool
	passphraseFile string
	profile        string
	roots          rootList
	json           bool
	quiet          bool
	jobs           int
}

type exportSummary struct {
	Out         string   `json:"out"`
	Entries     int      `json:"entries"`
	TotalBytes  int64    `json:"total_bytes"`
	ConfigFiles int      `json:"config_files"`
	SecretRefs  int      `json:"secret_refs,omitempty"`
	SIG         string   `json:"sig_path"`
	Method      string   `json:"method"`
	Signed      bool     `json:"signed"`
	Warnings    []string `json:"warnings,omitempty"`
	Added       int      `json:"diff_added,omitempty"`
	Modified    int      `json:"diff_modified,omitempty"`
	Removed     int      `json:"diff_removed,omitempty"`
}

// runExport builds the state package. pack.Export owns its own staging and
// diff-before-write; the CLI only classifies its sentinel errors.
func runExport(ctx context.Context, cfg exportConfig, stdout, stderr io.Writer) int {
	r := &reporter{stdout: stdout, stderr: stderr, json: cfg.json, quiet: cfg.quiet}

	if cfg.out == "" {
		return r.usage("export 需要 --out")
	}
	if cfg.src == "" {
		return r.usage("export 需要 --src <扫描输出目录>")
	}
	if code, msg := checkOut(cfg.out, false, cfg.force); code != exitOK {
		return r.fail(code, "%s", msg)
	}
	conf, confPath, err := loadConfig()
	if err != nil {
		return r.usage("配置文件 %s: %v", confPath, err)
	}
	if conf != nil {
		applyConfigDefaults(conf, &cfg.profile, new(string), &cfg.identity, new(string), &rootList{})
	}
	identity := cfg.identity
	if identity == "" {
		identity, err = defaultIdentityPath()
		if err != nil {
			identity = ""
		}
	}

	roots, err := loadExportRoots(cfg, conf)
	if err != nil {
		return r.usage("export: %v", err)
	}
	prof, err := loadExportProfile(cfg, cfg.src)
	if err != nil {
		return r.usage("export: %v", err)
	}

	if cfg.passphrase && cfg.passphraseFile != "" {
		return r.usage("--passphrase 与 --passphrase-file 只能二选一")
	}
	crypt := pack.CryptOptions{IdentityPath: identity}
	if cfg.withSecrets {
		switch {
		case len(cfg.recipients) == 0 && !cfg.passphrase && cfg.passphraseFile == "":
			return r.usage("export --with-secrets 需要 --recipient 或 --passphrase/--passphrase-file")
		case len(cfg.recipients) > 0 && (cfg.passphrase || cfg.passphraseFile != ""):
			return r.usage("--recipient 与 --passphrase/--passphrase-file 只能二选一")
		}
		crypt.Recipients = cfg.recipients
		if cfg.passphrase || cfg.passphraseFile != "" {
			pw, code := resolvePassphrase(r, cfg.passphrase, cfg.passphraseFile, stderr)
			if code != exitOK {
				return code
			}
			crypt.Passphrase = pw
		}
	} else if len(cfg.recipients) > 0 || cfg.passphrase || cfg.passphraseFile != "" {
		return r.usage("--recipient/--passphrase 需要配合 --with-secrets")
	}

	res, err := pack.Export(pack.Config{
		Profile:      prof,
		Roots:        roots,
		SourceDir:    cfg.src,
		OutDir:       cfg.out,
		ReportPath:   cfg.report,
		IdentityPath: identity,
		WithSecrets:  cfg.withSecrets,
		Crypt:        crypt,
		Force:        cfg.force,
		Jobs:         cfg.jobs,
	})
	if err != nil {
		if ctx.Err() != nil {
			return exitFromCtx(r, ctx)
		}
		switch {
		case errors.Is(err, pack.ErrDestNotEmpty):
			return r.fail(exitNotEmpty, "%v", err)
		case errors.Is(err, pack.ErrSourceOverlap), errors.Is(err, pack.ErrInvalidConfig),
			errors.Is(err, pack.ErrNoManifest), errors.Is(err, pack.ErrManifestInvalid):
			return r.fail(exitUsage, "%v", err)
		default:
			return r.fail(exitPartial, "export: %v", err)
		}
	}
	if ctx.Err() != nil {
		return exitFromCtx(r, ctx)
	}

	out := exportSummary{
		Out:         res.OutDir,
		Entries:     res.Entries,
		TotalBytes:  res.TotalBytes,
		ConfigFiles: res.ConfigFiles,
		SecretRefs:  res.SecretRefs,
		SIG:         res.SIGPath,
		Method:      res.Method,
		Signed:      res.Signed,
		Warnings:    res.Warnings,
	}
	if res.Diff != nil {
		out.Added, out.Modified, out.Removed = len(res.Diff.Added), len(res.Diff.Modified), len(res.Diff.Removed)
	}
	r.value(out)
	r.info("包已写入 %s：%d 个条目，%d 字节，SIG=%s", res.OutDir, res.Entries, res.TotalBytes, res.SIGPath)
	for _, w := range res.Warnings {
		r.warn("packout: 警告：%s", w)
	}
	return exitOK
}

// passphraseStdin is the terminal source for --passphrase; tests replace it.
var passphraseStdin io.Reader = os.Stdin

// readPassphrase reads one line without echo when stdin is a real terminal.
// When it is not (a pipe), it says so: the echo state is then out of our
// hands.
func readPassphrase(r io.Reader, stderr io.Writer) ([]byte, error) {
	if f, ok := r.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(stderr, "口令：")
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(stderr)
			return b, err
		}
	}
	fmt.Fprint(stderr, "packout: stdin 不是 TTY，口令会回显\n口令：")
	line, err := bufio.NewReader(r).ReadString('\n')
	fmt.Fprintln(stderr)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// loadExportRoots resolves what each profile root maps to on this machine.
// Order: explicit --root flags win, then <src>/roots.json written by scan.
func loadExportRoots(cfg exportConfig, conf *config) (map[string]string, error) {
	roots := map[string]string{}
	p := filepath.Join(cfg.src, "roots.json")
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &roots); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// Config roots only fill roles the scan did not record; the scan's own
	// roots.json stays the better witness.
	if conf != nil {
		for role, path := range conf.Roots {
			if _, ok := roots[role]; !ok {
				roots[role] = path
			}
		}
	}
	for _, b := range cfg.roots {
		roots[b.role] = b.path
	}
	return roots, nil
}

// loadExportProfile picks the profile used for extraction: --profile, else the
// single profile recorded in the manifest header.
func loadExportProfile(cfg exportConfig, src string) (*profile.Profile, error) {
	name := cfg.profile
	if name == "" {
		hdr, err := readHeader(filepath.Join(src, "manifest"))
		if err == nil && len(hdr.Inputs.Profiles) == 1 {
			name = hdr.Inputs.Profiles[0].Name
		} else if err == nil && len(hdr.Inputs.Profiles) > 1 {
			return nil, fmt.Errorf("清单含多个 profile，需用 --profile 指定")
		}
	}
	if name == "" {
		return nil, nil
	}
	if p, err := profile.Builtin(name); err == nil {
		return p, nil
	}
	return profile.Load(name)
}

// readHeader reads the first line of the first shard, which is the header.
func readHeader(manifestDir string) (*manifest.Header, error) {
	f, err := os.Open(filepath.Join(manifestDir, "manifest.0001.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	if !sc.Scan() {
		return nil, fmt.Errorf("清单缺少 header 行")
	}
	var h manifest.Header
	if err := json.Unmarshal(sc.Bytes(), &h); err != nil {
		return nil, err
	}
	return &h, nil
}

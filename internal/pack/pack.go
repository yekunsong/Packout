// Package pack builds and verifies the transferable state package.
//
// A package is a directory, never an archive:
//
//	manifest/      the scan's complete manifest directory (copied verbatim)
//	config/        de-secreted config extracts, path-relative
//	reinstall/     placeholder for reinstall artifacts (empty in P0)
//	REPORT.html    optional self-contained report
//	SIG.json       hash coverage of every other entry
//
// The package is a plain directory; credential values may additionally be
// encrypted into secrets.age, but the tree itself is not. SIG is a SHA-256
// tree digest. Without a signature a verify result reads "hash-ok,
// unverified"; with a valid minisign signature (D-043) it reads "ok". Verify
// itself never writes, so a malicious package cannot land anything before it
// has been checked end to end.
package pack

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aead.dev/minisign"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/profile"
)

// Top-level package names.
// rootsFileName is written by `scan` next to manifest/ and consumed by
// `export`; it never enters a package.
const rootsFileName = "roots.json"

const (
	ManifestDirName  = "manifest"
	ConfigDirName    = "config"
	ReinstallDirName = "reinstall"
	ReportName       = "REPORT.html"
)

// Config configures Export.
type Config struct {
	// SourceDir is the scan output directory. It must contain manifest/ (or
	// ManifestDir must point elsewhere); config/, reinstall/ and REPORT.html
	// are picked up from it when present and not overridden.
	SourceDir string
	// OutDir is the package directory to create.
	OutDir string

	// ManifestDir overrides SourceDir/manifest.
	ManifestDir string
	// ConfigDir supplies an already-extracted, de-secreted config tree. When
	// empty, SourceDir/config is used, and if that is absent and Profile is
	// set, extracts are produced from the units.
	ConfigDir string
	// ReinstallDir overrides SourceDir/reinstall.
	ReinstallDir string
	// ReportPath overrides SourceDir/REPORT.html. The report is optional.
	ReportPath string

	// Profile and Roots drive config extraction (extractor != none/digest).
	// Roots maps profile root names to the source machine paths.
	Profile *profile.Profile
	Roots   map[string]string

	// IdentityPath is used for the D-008 §6 warning (identity inside the
	// package) and for the 0600 permission warning.
	IdentityPath string

	// WithSecrets exports RESTORE credential values into secrets.age, leaving
	// secret_ref placeholders in config/. Crypt selects the encryption shape
	// and is required when WithSecrets is set.
	WithSecrets bool
	Crypt       CryptOptions

	// Force allows writing into a non-empty OutDir. The diff is always
	// computed before the first write (C-09).
	Force bool

	// Jobs bounds parallel hashing/copying; <= 0 takes min(GOMAXPROCS, 16).
	Jobs int

	Limits Limits
}

// Diff describes how a forced export differs from the existing destination.
type Diff struct {
	Added     []string `json:"added"`
	Modified  []string `json:"modified"`
	Removed   []string `json:"removed"`
	Unchanged []string `json:"unchanged"`
}

// Result describes a successful export.
type Result struct {
	OutDir        string   `json:"out_dir"`
	SIGPath       string   `json:"sig_path"`
	FormatVersion int      `json:"format_version"`
	Method        string   `json:"method"`
	Signed        bool     `json:"signed"`
	TreeSHA256    string   `json:"tree_sha256"`
	Entries       int      `json:"entries"`
	TotalBytes    int64    `json:"total_bytes"`
	ConfigFiles   int      `json:"config_files"`
	SecretRefs    int      `json:"secret_refs,omitempty"`
	SecretsPath   string   `json:"secrets_path,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Diff          *Diff    `json:"diff,omitempty"`
}

// Export writes a package into cfg.OutDir.
//
// All validation, path checks and content hashing happen in a staging
// directory on the same volume. OutDir is only touched once staging is
// complete; when OutDir is non-empty the diff is computed before any write.
func Export(cfg Config) (res *Result, err error) {
	cfg.Limits = cfg.Limits.withDefaults()
	if cfg.SourceDir == "" || cfg.OutDir == "" {
		return nil, fmt.Errorf("%w: SourceDir and OutDir are required", ErrInvalidConfig)
	}
	if cfg.WithSecrets {
		if err := cfg.Crypt.validateShape(); err != nil {
			return nil, err
		}
	}
	src, err := fsx.Abs(cfg.SourceDir)
	if err != nil {
		return nil, err
	}
	out, err := fsx.Abs(cfg.OutDir)
	if err != nil {
		return nil, err
	}
	if fsx.Within(src, out) || fsx.Within(out, src) {
		return nil, fmt.Errorf("%w: source %q and destination %q", ErrSourceOverlap, src, out)
	}
	si, err := fsx.Lstat(src)
	if err != nil {
		return nil, err
	}
	if !si.IsDir {
		return nil, fmt.Errorf("%w: SourceDir is not a directory", ErrInvalidConfig)
	}

	manifestDir := cfg.ManifestDir
	if manifestDir == "" {
		manifestDir = filepath.Join(src, ManifestDirName)
	}
	manifestDir, err = fsx.Abs(manifestDir)
	if err != nil {
		return nil, err
	}
	mi, err := fsx.Lstat(manifestDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoManifest, err)
	}
	if !mi.IsDir || mi.IsReparse {
		return nil, fmt.Errorf("%w: %q", ErrNoManifest, manifestDir)
	}
	// Manifest structure is a precondition: a package with an invalid
	// manifest is not worth hashing. ReadManifest validates as it parses, so
	// one load feeds both this check and the extractor below.
	m, merr := manifest.ReadManifest(manifestDir)
	if merr != nil {
		return nil, fmt.Errorf("pack: invalid manifest: %w", merr)
	}
	var secretSalt string
	if cfg.WithSecrets {
		secretSalt = m.Header.Inputs.SecretSalt
	}

	configDir, err := optionalDir(cfg.ConfigDir, filepath.Join(src, ConfigDirName))
	if err != nil {
		return nil, err
	}
	reinstallDir, err := optionalDir(cfg.ReinstallDir, filepath.Join(src, ReinstallDirName))
	if err != nil {
		return nil, err
	}
	reportPath := cfg.ReportPath
	if reportPath == "" {
		candidate := filepath.Join(src, ReportName)
		if fi, lerr := fsx.Lstat(candidate); lerr == nil && fi.Mode.IsRegular() {
			reportPath = candidate
		}
	}

	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(parent, "."+filepath.Base(out)+".stage-")
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(stage)
		}
	}()

	res = &Result{OutDir: out, FormatVersion: FormatVersion, Method: MethodSHA256Tree, Signed: false}
	if cfg.WithSecrets {
		res.Warnings = append(res.Warnings, identityWarnings(cfg.IdentityPath, out)...)
	}
	var secrets *secretCollector
	if cfg.WithSecrets {
		secrets = newSecretCollector(secretSalt)
	}
	if names, lerr := listNames(src); lerr == nil {
		for _, n := range names {
			switch n {
			case ManifestDirName, ConfigDirName, ReinstallDirName, ReportName, SIGName, SecretsName:
			case rootsFileName:
				// roots.json is local scan metadata (instance -> absolute source
				// path). It is deliberately not packaged: it would leak the
				// source machine's layout and is useless on the target.
			default:
				res.Warnings = append(res.Warnings, "source has unpackageable top-level entry "+n)
			}
		}
	}

	if _, err := copyTree(manifestDir, filepath.Join(stage, ManifestDirName), cfg.Limits, cfg.Jobs); err != nil {
		return res, err
	}
	if err := os.Mkdir(filepath.Join(stage, ConfigDirName), 0o755); err != nil {
		return res, err
	}
	if configDir != "" {
		if cfg.WithSecrets {
			res.Warnings = append(res.Warnings, "config/ 来自现成的去密目录，secrets.age 只能为空")
		}
		// copyTree requires an empty destination; use a temporary sibling.
		tmpConfig := filepath.Join(stage, ".config-copy")
		if _, err := copyTree(configDir, tmpConfig, cfg.Limits, cfg.Jobs); err != nil {
			return res, err
		}
		if err := os.Remove(filepath.Join(stage, ConfigDirName)); err != nil {
			return res, err
		}
		if err := os.Rename(tmpConfig, filepath.Join(stage, ConfigDirName)); err != nil {
			return res, err
		}
	} else if cfg.Profile != nil {
		n, werr, xerr := extractConfig(m, cfg.Profile, cfg.Roots, filepath.Join(stage, ConfigDirName), cfg.Limits, secrets, cfg.Jobs)
		res.ConfigFiles = n
		res.Warnings = append(res.Warnings, werr...)
		if xerr != nil {
			return res, xerr
		}
	} else if cfg.WithSecrets {
		res.Warnings = append(res.Warnings, "没有 profile，config/ 未抽取；secrets.age 为空")
	}
	if reinstallDir != "" {
		if _, err := copyTree(reinstallDir, filepath.Join(stage, ReinstallDirName), cfg.Limits, cfg.Jobs); err != nil {
			return res, err
		}
	} else if err := os.Mkdir(filepath.Join(stage, ReinstallDirName), 0o755); err != nil {
		return res, err
	}
	if reportPath != "" {
		ri, lerr := fsx.Lstat(reportPath)
		if lerr != nil {
			return res, fmt.Errorf("pack: report: %w", lerr)
		}
		if !ri.Mode.IsRegular() {
			return res, fmt.Errorf("pack: report is not a regular file")
		}
		if err := copyFile(reportPath, filepath.Join(stage, ReportName), ri.Mode); err != nil {
			return res, err
		}
	}

	if cfg.WithSecrets {
		plain, perr := secrets.encode()
		if perr != nil {
			return res, perr
		}
		res.SecretRefs = len(secrets.byRef)
		if res.SecretRefs == 0 {
			plain = emptyIndex()
			res.Warnings = append(res.Warnings, "未发现 RESTORE 凭据，secrets.age 为空索引")
		}
		if err := EncryptSecrets(filepath.Join(stage, SecretsName), plain, cfg.Crypt); err != nil {
			return res, err
		}
		res.SecretsPath = filepath.Join(out, SecretsName)
	}

	entries, err := scanTree(stage, cfg.Limits, true, cfg.Jobs)
	if err != nil {
		return res, err
	}
	sig, err := NewSIG(entries)
	if err != nil {
		return res, err
	}
	encoded, err := sig.Encode()
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(stage, SIGName), encoded, 0o644); err != nil {
		return res, err
	}
	res.SIGPath = filepath.Join(out, SIGName)
	res.TreeSHA256 = sig.TreeSHA256
	res.Entries = sig.EntryCount
	res.TotalBytes = sig.TotalBytes

	if err := install(stage, out, cfg.Force, cfg.Limits, cfg.Jobs, sig, res); err != nil {
		return res, err
	}
	committed = true
	return res, nil
}

func optionalDir(override, fallback string) (string, error) {
	p := override
	if p == "" {
		fi, err := fsx.Lstat(fallback)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", nil
			}
			return "", err
		}
		if !fi.IsDir {
			return "", fmt.Errorf("pack: %q is not a directory", fallback)
		}
		p = fallback
	}
	a, err := fsx.Abs(p)
	if err != nil {
		return "", err
	}
	fi, err := fsx.Lstat(a)
	if err != nil {
		return "", err
	}
	if !fi.IsDir || fi.IsReparse {
		return "", fmt.Errorf("pack: %q is not a plain directory", a)
	}
	return a, nil
}

// install moves staging to out, or diffs and merges into a non-empty out.
func install(stage, out string, force bool, limits Limits, jobs int, newSIG *SIG, res *Result) error {
	fi, err := fsx.Lstat(out)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return os.Rename(stage, out)
		}
		return err
	}
	if fi.IsReparse || fi.IsLink {
		return fmt.Errorf("pack: destination %q is a symlink or junction", out)
	}
	if !fi.IsDir {
		return fmt.Errorf("pack: destination %q is not a directory", out)
	}
	empty, err := isDirEmpty(out)
	if err != nil {
		return err
	}
	if empty {
		if err := os.Remove(out); err != nil {
			return err
		}
		return os.Rename(stage, out)
	}
	oldEntries, err := scanTree(out, limits, true, jobs)
	if err != nil {
		return fmt.Errorf("pack: existing destination: %w", err)
	}
	oldSIG, err := NewSIG(oldEntries)
	if err != nil {
		return err
	}
	diff := computeDiff(oldSIG, newSIG)
	res.Diff = &diff
	if !force {
		return fmt.Errorf("%w: %s (+%d ~%d -%d; use --force)", ErrDestNotEmpty, out,
			len(diff.Added), len(diff.Modified), len(diff.Removed))
	}
	if err := mergeStage(stage, out, newSIG, limits); err != nil {
		return err
	}
	// SIG.json is excluded from the tree walk, so merge it explicitly.
	sigDst := filepath.Join(out, SIGName)
	if err := removeIfExists(sigDst); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(stage, SIGName), sigDst, 0o644); err != nil {
		return err
	}
	// A re-export rewrites SIG, so any old signature is stale. Remove it
	// rather than leave a package that claims to be signed for old content.
	sigFile := filepath.Join(out, MinisigName)
	if _, err := fsx.Lstat(sigFile); err == nil {
		if err := removeIfExists(sigFile); err != nil {
			return err
		}
		res.Warnings = append(res.Warnings, "重新导出删除了旧签名 "+MinisigName+"，需要重新 sign")
	}
	removeManaged(out, diff.Removed)
	return os.RemoveAll(stage)
}

func computeDiff(old, new *SIG) Diff {
	var d Diff
	oldBy := make(map[string]*SIGEntry, len(old.Entries))
	for i := range old.Entries {
		oldBy[old.Entries[i].Path] = &old.Entries[i]
	}
	newBy := make(map[string]*SIGEntry, len(new.Entries))
	for i := range new.Entries {
		newBy[new.Entries[i].Path] = &new.Entries[i]
	}
	for i := range new.Entries {
		n := &new.Entries[i]
		o, ok := oldBy[n.Path]
		switch {
		case !ok:
			d.Added = append(d.Added, n.Path)
		case compareEntry(n, o) != nil:
			d.Modified = append(d.Modified, n.Path)
		default:
			d.Unchanged = append(d.Unchanged, n.Path)
		}
	}
	for i := range old.Entries {
		if _, ok := newBy[old.Entries[i].Path]; !ok {
			d.Removed = append(d.Removed, old.Entries[i].Path)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Modified)
	sort.Strings(d.Removed)
	sort.Strings(d.Unchanged)
	return d
}

// mergeStage writes staged entries into dest. Every path is re-validated and
// every destination component is checked for symlink/junction write-through.
func mergeStage(stage, dest string, sig *SIG, limits Limits) error {
	for i := range sig.Entries {
		e := &sig.Entries[i]
		dst, err := safeJoin(dest, e.Path)
		if err != nil {
			return err
		}
		src, err := safeJoin(stage, e.Path)
		if err != nil {
			return err
		}
		if e.Type == TypeDir {
			if err := ensureRealDir(dest, e.Path); err != nil {
				return err
			}
			if err := os.Chmod(dst, fs.FileMode(parseMode(*e.Mode))); err != nil {
				return err
			}
			continue
		}
		if err := ensureRealDir(dest, parentRel(e.Path)); err != nil {
			return err
		}
		if err := removeIfExists(dst); err != nil {
			return err
		}
		switch e.Type {
		case TypeFile:
			if err := copyFile(src, dst, fs.FileMode(parseMode(*e.Mode))); err != nil {
				return err
			}
		case TypeSymlink:
			if err := os.Symlink(*e.LinkTarget, dst); err != nil {
				return err
			}
		case TypeHardlink:
			primary, err := safeJoin(dest, *e.LinkTarget)
			if err != nil {
				return err
			}
			if err := os.Link(primary, dst); err != nil {
				if cerr := copyFile(src, dst, fs.FileMode(parseMode(*e.Mode))); cerr != nil {
					return cerr
				}
			}
		}
	}
	return nil
}

func parentRel(rel string) string {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return ""
}

func ensureRealDir(root, rel string) error {
	if rel == "" {
		return nil
	}
	if err := ValidateRelPath(rel); err != nil {
		return err
	}
	cur := ""
	for _, seg := range strings.Split(rel, "/") {
		if cur == "" {
			cur = seg
		} else {
			cur += "/" + seg
		}
		full, err := safeJoin(root, cur)
		if err != nil {
			return err
		}
		fi, err := fsx.Lstat(full)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.Mkdir(full, 0o755); err != nil {
				return err
			}
			continue
		}
		if fi.IsReparse || fi.IsLink {
			return fmt.Errorf("pack: destination component %q is a symlink/junction", cur)
		}
		if !fi.IsDir {
			if err := os.Remove(full); err != nil {
				return err
			}
			if err := os.Mkdir(full, 0o755); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeIfExists(p string) error {
	err := os.Remove(p)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// removeManaged deletes removed entries that live in package-owned subtrees,
// so a forced re-export cannot leave stale shards behind. Unrelated
// top-level user files are kept.
func removeManaged(dest string, removed []string) {
	tops := map[string]bool{ManifestDirName: true, ConfigDirName: true, ReinstallDirName: true}
	// Deepest first so directories empty out before their removal.
	sort.Slice(removed, func(i, j int) bool {
		di, dj := strings.Count(removed[i], "/"), strings.Count(removed[j], "/")
		if di != dj {
			return di > dj
		}
		return removed[i] > removed[j]
	})
	for _, rel := range removed {
		if rel != ReportName && rel != SecretsName && !hasTopPrefix(rel, tops) {
			continue
		}
		if p, err := safeJoin(dest, rel); err == nil {
			os.RemoveAll(p)
		}
	}
}

// Conclusion words (D-043). Only "ok" permits "可以恢复"; "hash-ok,
// unverified" proves integrity but not origin.
const (
	ConclusionOK               = "ok"
	ConclusionHashOKUnverified = "hash-ok, unverified"
	ConclusionUnsigned         = "unsigned"
	ConclusionTampered         = "tampered"
	ConclusionBadSignature     = "bad-signature"
	ConclusionFailed           = "failed"
	ConclusionEmpty            = "empty"
)

// VerifyOptions configure signature verification.
type VerifyOptions struct {
	Limits Limits
	// PubKeyPath is --pubkey. When set it is the only key source; otherwise
	// ~/.config/packout/trusted_keys is used when it exists.
	PubKeyPath string
	// Jobs bounds parallel tree hashing; <= 0 takes min(GOMAXPROCS, 16).
	Jobs int
	// TrustedKeysPath overrides the default trusted-keys file.
	TrustedKeysPath string
	// OnKeySeen is called for every public key that actually verified the
	// signature. firstSeen is true when the key came from --pubkey and was
	// not already listed in the trusted-keys file (TOFU).
	OnKeySeen func(fingerprint string, firstSeen bool)
}

// Verdict is a verify result. A failed verdict is returned together with an
// error; an unsigned but structurally sound manifest is a successful verdict.
type Verdict struct {
	Dir              string    `json:"dir"`
	Conclusion       string    `json:"conclusion"`
	Signed           bool      `json:"signed"`
	SignaturePresent bool      `json:"signature_present"`
	KeyFingerprint   string    `json:"key_fingerprint,omitempty"`
	Method           string    `json:"method,omitempty"`
	FormatVersion    int       `json:"format_version,omitempty"`
	TreeSHA256       string    `json:"tree_sha256,omitempty"`
	Entries          int       `json:"entries"`
	TotalBytes       int64     `json:"total_bytes"`
	ManifestValid    bool      `json:"manifest_valid"`
	Problems         []Problem `json:"problems,omitempty"`
}

// Verify checks a package directory with default options. It never writes.
//
// The order is deliberate (INV-C06): SIG coverage against the real tree first,
// manifest structure second, signature last. Content changed under a present
// signature is still "tampered": the signature only covers SIG.json and
// manifest/, so a changed mirror must be caught by the tree hash.
//
// A directory without SIG yields the explicit "unsigned" conclusion; an empty
// or unrecognisable one is an error.
func Verify(dir string) (*Verdict, error) {
	return VerifyWith(dir, Limits{})
}

// VerifyWith is Verify with explicit resource limits.
func VerifyWith(dir string, limits Limits) (*Verdict, error) {
	return VerifyWithOptions(dir, VerifyOptions{Limits: limits})
}

// VerifyWithOptions is Verify with explicit signature/trust options.
func VerifyWithOptions(dir string, opt VerifyOptions) (*Verdict, error) {
	limits := opt.Limits.withDefaults()
	if dir == "" {
		return nil, fmt.Errorf("%w: empty directory", ErrEmptyPackage)
	}
	abs, err := fsx.Abs(dir)
	if err != nil {
		return nil, err
	}
	v := &Verdict{Dir: abs}
	fi, err := fsx.Lstat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			v.Conclusion = ConclusionEmpty
			return v, fmt.Errorf("%w: %s", ErrEmptyPackage, abs)
		}
		return nil, err
	}
	if !fi.IsDir {
		v.Conclusion = ConclusionEmpty
		return v, fmt.Errorf("%w: not a directory", ErrEmptyPackage)
	}
	names, err := listNames(abs)
	if err != nil {
		return nil, err
	}
	var haveSIG, haveManifest, haveMinisig bool
	for _, n := range names {
		switch n {
		case SIGName:
			haveSIG = true
		case ManifestDirName:
			haveManifest = true
		case MinisigName:
			haveMinisig = true
		}
	}
	v.SignaturePresent = haveMinisig
	v.Signed = haveMinisig
	if !haveSIG && !haveManifest {
		v.Conclusion = ConclusionEmpty
		return v, fmt.Errorf("%w: %s", ErrEmptyPackage, abs)
	}
	if !haveSIG {
		v.Conclusion = ConclusionUnsigned
		entries, err := scanTree(abs, limits, true, opt.Jobs)
		if err != nil {
			v.Problems = append(v.Problems, Problem{Code: "tree-invalid", Detail: err.Error()})
			return v, err
		}
		if got, err := NewSIG(entries); err == nil {
			v.Entries = got.EntryCount
			v.TotalBytes = got.TotalBytes
		}
		v.ManifestValid = checkManifest(abs, v)
		if !v.ManifestValid {
			return v, &ProblemsError{Sentinel: ErrManifestInvalid, Problems: v.Problems}
		}
		return v, nil
	}
	if !haveManifest {
		v.Conclusion = ConclusionFailed
		v.Problems = append(v.Problems, Problem{Code: "manifest-missing", Path: ManifestDirName})
		return v, fmt.Errorf("%w: %s", ErrNoManifest, abs)
	}

	sig, err := ReadSIG(abs)
	if err != nil {
		v.Conclusion = ConclusionFailed
		v.Problems = append(v.Problems, Problem{Code: "sig-invalid", Path: SIGName, Detail: err.Error()})
		return v, err
	}
	v.Signed = haveMinisig
	v.Method = sig.Method
	v.FormatVersion = sig.FormatVersion

	entries, err := scanTree(abs, limits, true, opt.Jobs)
	if err != nil {
		v.Conclusion = ConclusionFailed
		v.Problems = append(v.Problems, Problem{Code: "tree-invalid", Detail: err.Error()})
		return v, err
	}
	got, err := NewSIG(entries)
	if err != nil {
		v.Conclusion = ConclusionFailed
		v.Problems = append(v.Problems, Problem{Code: "tree-invalid", Detail: err.Error()})
		return v, err
	}
	v.Entries = got.EntryCount
	v.TotalBytes = got.TotalBytes
	if problems := CompareSIG(sig, got); len(problems) > 0 {
		v.Conclusion = ConclusionTampered
		v.Problems = append(v.Problems, problems...)
		return v, &ProblemsError{Sentinel: ErrTampered, Problems: problems}
	}
	if sig.TreeSHA256 != got.TreeSHA256 {
		v.Conclusion = ConclusionTampered
		p := Problem{Code: "sig-tree-hash-mismatch", Detail: "canonical tree hash differs from SIG"}
		v.Problems = append(v.Problems, p)
		return v, &ProblemsError{Sentinel: ErrTampered, Problems: []Problem{p}}
	}

	v.TreeSHA256 = got.TreeSHA256
	v.ManifestValid = checkManifest(abs, v)
	if !v.ManifestValid {
		v.Conclusion = ConclusionFailed
		return v, &ProblemsError{Sentinel: ErrManifestInvalid, Problems: v.Problems}
	}
	if !haveMinisig {
		v.Conclusion = ConclusionUnsigned
		return v, nil
	}
	return verifySignature(abs, v, opt)
}

// verifySignature checks SIG.json.minisig against the coverage hash. The tree
// and manifest were already checked, so a failure here is attribution, not
// content.
func verifySignature(abs string, v *Verdict, opt VerifyOptions) (*Verdict, error) {
	trustedPath := effectiveTrustedKeysPath(opt)
	keys, err := publicKeys(opt)
	if err != nil {
		// No usable key source is an attribution problem (bad-signature), not
		// a content problem: the tree and manifest already matched above.
		v.Conclusion = ConclusionBadSignature
		v.Problems = append(v.Problems, Problem{Code: "pubkey-invalid", Detail: err.Error()})
		return v, err
	}
	if len(keys) == 0 {
		v.Conclusion = ConclusionBadSignature
		v.Problems = append(v.Problems, Problem{
			Code:   "no-pubkey",
			Detail: "签名存在，但没有可用公钥；用 --pubkey FILE 确认来源，或把这些公钥写入 " + trustedPath + "（packout init 会写入本机公钥）",
		})
		return v, nil
	}
	sig, err := readMinisig(abs)
	if err != nil {
		v.Conclusion = ConclusionBadSignature
		v.Problems = append(v.Problems, Problem{Code: "bad-signature", Path: MinisigName, Detail: err.Error()})
		return v, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	coverage, err := CoverageSHA256(abs, opt.Limits)
	if err != nil {
		v.Conclusion = ConclusionFailed
		v.Problems = append(v.Problems, Problem{Code: "coverage-invalid", Detail: err.Error()})
		return v, err
	}
	msg := []byte(signatureDomain + coverage)

	var trusted []minisign.PublicKey
	// The trusted-keys file here only answers "is this --pubkey already
	// known?" (TOFU). It is deliberately not merged into --pubkey (D-044 #4),
	// and a broken trusted store must not block an explicit --pubkey.
	if trustedPath != "" {
		trusted, _ = LoadPublicKeys(trustedPath)
	}
	for i := range keys {
		if !minisign.Verify(keys[i], msg, sig) {
			continue
		}
		fpr := KeyFingerprint(&keys[i])
		v.Conclusion = ConclusionOK
		v.KeyFingerprint = fpr
		firstSeen := opt.PubKeyPath != "" && !containsKey(trusted, &keys[i])
		if opt.OnKeySeen != nil {
			opt.OnKeySeen(fpr, firstSeen)
		}
		return v, nil
	}
	p := Problem{Code: "bad-signature", Path: MinisigName,
		Detail: "签名存在，但没有任何已知公钥能验证它"}
	v.Conclusion = ConclusionBadSignature
	v.Problems = append(v.Problems, p)
	return v, &ProblemsError{Sentinel: ErrBadSignature, Problems: []Problem{p}}
}

func containsKey(keys []minisign.PublicKey, want *minisign.PublicKey) bool {
	for i := range keys {
		if keys[i].Equal(*want) {
			return true
		}
	}
	return false
}

// effectiveTrustedKeysPath is the trust store used for first-seen reporting and
// for the no-pubkey hint.
func effectiveTrustedKeysPath(opt VerifyOptions) string {
	if opt.TrustedKeysPath != "" {
		return opt.TrustedKeysPath
	}
	return DefaultTrustedKeysPath()
}

// publicKeys resolves the key source. --pubkey wins; otherwise the trusted
// keys file is used when present. A missing or blank trusted-keys file is not
// an error: it simply yields no keys.
func publicKeys(opt VerifyOptions) ([]minisign.PublicKey, error) {
	if opt.PubKeyPath != "" {
		// An explicit --pubkey that cannot be read is a path/usage problem, not
		// "no key configured": report it so the next-step hint can say so.
		return LoadPublicKeys(opt.PubKeyPath)
	}
	path := effectiveTrustedKeysPath(opt)
	if path == "" {
		return nil, nil
	}
	keys, err := LoadPublicKeys(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || (errors.Is(err, ErrInvalidPubKey) && blankKeysFile(path)) {
			return nil, nil
		}
		return nil, err
	}
	return keys, nil
}

// blankKeysFile reports whether path holds no key lines (only blank lines and
// comments). A blank trusted-keys file means "no keys yet", not "broken file".
func blankKeysFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return false
	}
	return true
}

// checkManifest validates manifest/ and records failures on v. It returns
// false as soon as any error-severity issue exists.
func checkManifest(dir string, v *Verdict) bool {
	mdir := filepath.Join(dir, ManifestDirName)
	fi, err := fsx.Lstat(mdir)
	if err != nil || !fi.IsDir {
		v.Problems = append(v.Problems, Problem{Code: "manifest-missing", Path: ManifestDirName})
		return false
	}
	if err := manifest.Validate(mdir); err != nil {
		var ve *manifest.ValidationError
		if errors.As(err, &ve) {
			for _, is := range ve.Issues {
				v.Problems = append(v.Problems, Problem{Code: is.Code, Path: ManifestDirName, Detail: is.Message})
			}
		} else {
			v.Problems = append(v.Problems, Problem{Code: "manifest-invalid", Path: ManifestDirName, Detail: err.Error()})
		}
		return false
	}
	return true
}

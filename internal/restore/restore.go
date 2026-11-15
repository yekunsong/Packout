package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yekunsong/Packout/internal/fsx"
	"github.com/yekunsong/Packout/internal/manifest"
	"github.com/yekunsong/Packout/internal/pack"
)

// budgetFactor is the free-space multiple required before the first write
// (docs/design-restore.md).
const budgetFactor = 1.2

// Options configures Run.
type Options struct {
	PackageDir string
	Into       string
	InPlace    bool
	Force      bool
	DryRun     bool
	// AllowUnverified lets unsigned / hash-ok, unverified / bad-signature /
	// failed through. tampered and empty are always refused.
	AllowUnverified bool
	// PubKeyPath mirrors verify --pubkey.
	PubKeyPath string
	// TrustedKeysPath is verify's trust store (config trusted_keys or the
	// per-user default). --pubkey still wins inside verify.
	TrustedKeysPath string
	// Map overrides where one role lands. Values are paths relative to Into
	// ("." means Into itself); roles absent from Map keep landing at
	// Into/<role>, exactly as before. Absolute paths, drive letters, "~" and
	// ".." segments are refused.
	Map map[string]string
	// Crypt selects the decryption identity or passphrase.
	Crypt pack.CryptOptions
	// OnKeySeen forwards TOFU reporting from verify.
	OnKeySeen func(fingerprint string, firstSeen bool)
	// Limits bound the package tree scan during verify.
	Limits pack.Limits

	// Test seams. Production leaves them nil.
	FreeBytes  func(dir string) (int64, error)
	Symlink    func(oldname, newname string) error
	AfterWrite func(path string)
}

// PlanEntry is one prospective write (design step 4).
type PlanEntry struct {
	Path   string `json:"path"`   // package-relative, e.g. config/home/.claude.json
	Target string `json:"target"` // absolute destination
	UnitID string `json:"unit_id,omitempty"`
	Bytes  int64  `json:"bytes"`
	Action string `json:"action"` // create | overwrite | same
}

// Restored is one file actually written.
type Restored struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	UnitID string `json:"unit_id,omitempty"`
	Bytes  int64  `json:"bytes"`
	Action string `json:"action"`
}

// Need is one unit in needs_reinstall / needs_relogin.
type Need struct {
	UnitID string `json:"unit_id"`
	Path   string `json:"path"`
	Entry  string `json:"entry,omitempty"`
	Layer  string `json:"layer,omitempty"`
}

// Landing is one role's resolved root under the target. Path is absolute:
// either Into/<role> or the resolved --map root.
type Landing struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	Mapped bool   `json:"mapped,omitempty"`
}

// Report is the three-part result plus the SIG gate read-out.
type Report struct {
	Package           string      `json:"package"`
	Target            string      `json:"target"`
	SigConclusion     string      `json:"sig_conclusion"`
	Signed            bool        `json:"signed"`
	AllowedUnverified bool        `json:"allowed_unverified"`
	DryRun            bool        `json:"dry_run"`
	PlannedBytes      int64       `json:"planned_bytes"`
	Plan              []PlanEntry `json:"plan,omitempty"`
	Restored          []Restored  `json:"restored"`
	// Overwritten counts existing files this run actually replaced. It stays
	// 0 for --dry-run (nothing is written) and for restores into an empty
	// target. packout keeps no backup of what it overwrites.
	Overwritten    int       `json:"overwritten"`
	NeedsReinstall []Need    `json:"needs_reinstall"`
	NeedsRelogin   []Need    `json:"needs_relogin"`
	Landing        []Landing `json:"landing,omitempty"`
	Problems       []Problem `json:"problems,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
}

type payload struct {
	entry  *pack.SIGEntry
	rel    string // package-relative
	target string // absolute destination
	unitID string
	data   []byte // nil for dirs and symlinks
	hash   string // expected sha256 of the written bytes; "" when not a file
	mode   fs.FileMode
	link   string
	action string
}

type secretIndex struct {
	values map[string]string
}

var placeholderRE = regexp.MustCompile(`«secret:(secrets\.age#[^»]+)»`)

// Run performs the restore. It always returns a report (possibly partial) so
// the caller can name what was already written when a later step fails.
func Run(ctx context.Context, opt Options) (*Report, error) {
	if opt.PackageDir == "" {
		return nil, fmt.Errorf("%w: 缺少包目录", ErrUsage)
	}
	if opt.Into == "" {
		return nil, fmt.Errorf("%w: 缺少 --into", ErrUsage)
	}
	pkg, err := fsx.Abs(opt.PackageDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	into, err := fsx.Abs(opt.Into)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	mapping, err := normalizeMap(opt.Map)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	rep := &Report{Package: pkg, Target: into, DryRun: opt.DryRun,
		Restored: []Restored{}, NeedsReinstall: []Need{}, NeedsRelogin: []Need{}}

	pi, err := fsx.Lstat(pkg)
	if err != nil {
		return rep, fmt.Errorf("%w: 包目录 %s: %v", ErrUsage, pkg, err)
	}
	if !pi.IsDir || pi.IsReparse {
		return rep, fmt.Errorf("%w: %s 不是普通目录", ErrUsage, pkg)
	}
	if fsx.Within(pkg, into) {
		rep.Warnings = append(rep.Warnings, "目标位于包目录之内；写完后再 verify 这个包会看到多余文件")
	} else if fsx.Within(into, pkg) {
		rep.Warnings = append(rep.Warnings, "包目录位于目标之内；恢复产物会与其并列，注意别把包当成恢复结果")
	}

	// Step 1: SIG gate. Nothing is written before this passes.
	v, verr := pack.VerifyWithOptions(pkg, pack.VerifyOptions{
		Limits:          opt.Limits,
		PubKeyPath:      opt.PubKeyPath,
		TrustedKeysPath: opt.TrustedKeysPath,
		OnKeySeen:       opt.OnKeySeen,
	})
	if ctx.Err() != nil {
		return rep, ErrCanceled
	}
	if v == nil {
		// No verdict at all (unreadable path, I/O error): report the real
		// reason, never "tampered".
		if verr == nil {
			verr = errors.New("verify 无结论")
		}
		return rep, fmt.Errorf("%w: 无法校验这个包：%v", ErrUnverified, verr)
	}
	rep.SigConclusion = v.Conclusion
	rep.Signed = v.Signed
	switch v.Conclusion {
	case pack.ConclusionOK:
	case pack.ConclusionTampered:
		// Only content that contradicts SIG is tampering; --allow-unverified
		// never widens this.
		return rep, fmt.Errorf("%w: SIG 结论 %q（内容与 SIG 不符，--allow-unverified 也不放行）", ErrTampered, v.Conclusion)
	case pack.ConclusionEmpty:
		// An empty/unrecognisable package is a usage problem, not something a
		// user may wave through.
		return rep, fmt.Errorf("%w: SIG 结论 %q（空包或无法识别的包，--allow-unverified 不放行）", ErrUnverified, v.Conclusion)
	case pack.ConclusionHashOKUnverified, pack.ConclusionUnsigned, pack.ConclusionBadSignature, pack.ConclusionFailed:
		if !opt.AllowUnverified {
			return rep, fmt.Errorf("%w: SIG 结论 %q（来源未确认；核对后加 --allow-unverified 继续）", ErrUnverified, v.Conclusion)
		}
		rep.AllowedUnverified = true
	default:
		return rep, fmt.Errorf("%w: SIG 结论 %q（来源未确认；核对后加 --allow-unverified 继续）", ErrUnverified, v.Conclusion)
	}
	for _, p := range v.Problems {
		rep.Warnings = append(rep.Warnings, "verify: "+p.Error())
	}

	// Step 2 (first half): the target gate. A non-empty target needs
	// --in-place even before a diff exists.
	empty, exists, err := targetState(into)
	if err != nil {
		return rep, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if exists && !empty && !opt.InPlace {
		return rep, fmt.Errorf("%w: %s 已存在且非空（用 --in-place 先看 diff）", ErrDestNotEmpty, into)
	}

	// Units supply the source id for every restored path and the two
	// non-written report segments.
	m, err := manifest.ReadManifest(filepath.Join(pkg, pack.ManifestDirName))
	if err != nil {
		return rep, fmt.Errorf("%w: manifest: %v", ErrCorrupt, err)
	}
	units, reinstall, relogin := indexUnits(m)
	rep.NeedsReinstall = reinstall
	rep.NeedsRelogin = relogin

	// Step 3: decrypt secrets when the package carries them.
	secrets, derr := loadSecrets(pkg, opt.Crypt, rep)
	if derr != nil {
		return rep, derr
	}

	// Step 4: build the plan (and read every source file exactly once).
	sig, err := pack.ReadSIG(pkg)
	if err != nil {
		return rep, fmt.Errorf("%w: SIG: %v", ErrCorrupt, err)
	}
	items, planErr := buildPlan(pkg, into, mapping, sig, units, secrets, rep)
	rep.Plan = make([]PlanEntry, 0, len(items))
	var budget int64
	for i := range items {
		it := &items[i]
		rep.Plan = append(rep.Plan, PlanEntry{Path: it.rel, Target: it.target, UnitID: it.unitID,
			Bytes: int64(len(it.data)), Action: it.action})
		if it.action != "same" {
			budget += int64(len(it.data))
		}
	}
	rep.PlannedBytes = budget
	if planErr != nil {
		return rep, planErr
	}

	// The second half of step 2: a non-empty diff requires --force.
	if opt.InPlace && !opt.Force && hasChanges(items) {
		return rep, fmt.Errorf("%w: diff 非空（见上方计划），需要 --force", ErrDestNotEmpty)
	}
	if extras, xerr := extraTargets(into, items); xerr == nil {
		for _, x := range extras {
			rep.Warnings = append(rep.Warnings, "目标里未被本包涉及、将保持不动: "+x)
		}
	}
	if opt.DryRun {
		return rep, nil
	}
	if ctx.Err() != nil {
		return rep, ErrCanceled
	}

	// Disk budget before the first byte (1.2x).
	free := freeBytes
	if opt.FreeBytes != nil {
		free = opt.FreeBytes
	}
	have, ferr := free(nearestExisting(into))
	if ferr != nil {
		return rep, fmt.Errorf("%w: 无法读取剩余空间: %v", ErrDiskBudget, ferr)
	}
	if need := int64(float64(budget)*budgetFactor + 0.5); have < need {
		rep.Problems = append(rep.Problems, Problem{Code: "rst_disk_insufficient",
			Detail: fmt.Sprintf("需要 %d 字节（含 1.2 倍余量），剩余 %d", need, have)})
		return rep, fmt.Errorf("%w: 需要 %d 字节（1.2x），剩余 %d", ErrDiskBudget, need, have)
	}

	// Step 5 + 6: write and read back each file immediately.
	if err := os.MkdirAll(into, 0o755); err != nil {
		return rep, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	symlink := os.Symlink
	if opt.Symlink != nil {
		symlink = opt.Symlink
	}
	for i := range items {
		if ctx.Err() != nil {
			return rep, ErrCanceled
		}
		it := &items[i]
		switch {
		case it.entry.Type == pack.TypeDir:
			if err := writeDir(it.target); err != nil {
				return rep, failEntry(rep, it, err)
			}
			if it.action == "overwrite" {
				rep.Overwritten++
			}
		case it.entry.Type == pack.TypeSymlink:
			flattened, err := writeSymlink(into, it.target, it.link, symlink)
			if err != nil {
				return rep, failEntry(rep, it, err)
			}
			if it.action == "overwrite" {
				rep.Overwritten++
			}
			if flattened {
				it.data = []byte(it.link)
				sum := sha256.Sum256(it.data)
				it.hash = hex.EncodeToString(sum[:])
				rep.Problems = append(rep.Problems, Problem{Code: "symlink_flattened", Path: it.rel,
					UnitID: it.unitID, Detail: "目标文件系统不支持符号链接，写成了普通文件"})
			}
			rep.Restored = append(rep.Restored, Restored{Path: it.rel, Target: it.target,
				UnitID: it.unitID, Bytes: int64(len(it.data)), Action: it.action})
			if err := verifyReadBack(it, flattened); err != nil {
				rep.Problems = append(rep.Problems, Problem{Code: "restore_corrupt", Path: it.rel,
					UnitID: it.unitID, Detail: err.Error()})
				return rep, fmt.Errorf("%w: %s: %v", ErrCorrupt, it.rel, err)
			}
		case it.entry.Type == pack.TypeHardlink, it.action != "same":
			if err := writeFile(into, it); err != nil {
				return rep, failEntry(rep, it, err)
			}
			if it.action == "overwrite" {
				rep.Overwritten++
			}
			if opt.AfterWrite != nil {
				opt.AfterWrite(it.target)
			}
			rep.Restored = append(rep.Restored, Restored{Path: it.rel, Target: it.target,
				UnitID: it.unitID, Bytes: int64(len(it.data)), Action: it.action})
			if err := verifyReadBack(it, false); err != nil {
				rep.Problems = append(rep.Problems, Problem{Code: "restore_corrupt", Path: it.rel,
					UnitID: it.unitID, Detail: err.Error()})
				return rep, fmt.Errorf("%w: %s: %v", ErrCorrupt, it.rel, err)
			}
		}
	}
	return rep, nil
}

// ---- target inspection ----------------------------------------------------

func targetState(into string) (empty, exists bool, err error) {
	fi, err := fsx.Lstat(into)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, false, nil
		}
		return false, false, err
	}
	if !fi.IsDir {
		return false, true, fmt.Errorf("目标 %s 已存在但不是目录", into)
	}
	names, err := os.ReadDir(into)
	if err != nil {
		return false, true, err
	}
	return len(names) == 0, true, nil
}

// nearestExisting walks up until a directory exists, for the statfs call.
func nearestExisting(p string) string {
	for {
		if fi, err := fsx.Lstat(p); err == nil && fi.IsDir {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func extraTargets(into string, items []payload) ([]string, error) {
	fi, err := fsx.Lstat(into)
	if err != nil || !fi.IsDir {
		return nil, err
	}
	planned := make(map[string]bool, len(items))
	for i := range items {
		planned[items[i].target] = true
	}
	var out []string
	err = filepath.WalkDir(into, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || p == into || planned[p] {
			return nil
		}
		out = append(out, p)
		return nil
	})
	sort.Strings(out)
	return out, err
}

// ---- unit index -----------------------------------------------------------

func indexUnits(m *manifest.Manifest) (map[string]string, []Need, []Need) {
	roots := make(map[string]string, len(m.Header.Roots))
	for i := range m.Header.Roots {
		r := &m.Header.Roots[i]
		roots[r.Name] = r.Path
	}
	byPath := make(map[string]string, len(m.Units))
	var reinstall, relogin []Need
	for i := range m.Units {
		u := &m.Units[i]
		if key := unitConfigKey(u, roots); key != "" {
			if _, ok := byPath[key]; !ok {
				byPath[key] = u.ID
			}
		}
		n := Need{UnitID: u.ID, Path: u.Path, Entry: u.Entry, Layer: u.Layer}
		if u.ProposedAction == manifest.ActionReinstall {
			reinstall = append(reinstall, n)
		}
		if u.Layer == manifest.LayerL5 {
			relogin = append(relogin, n)
		}
	}
	sort.Slice(reinstall, func(i, j int) bool { return reinstall[i].UnitID < reinstall[j].UnitID })
	sort.Slice(relogin, func(i, j int) bool { return relogin[i].UnitID < relogin[j].UnitID })
	return byPath, reinstall, relogin
}

// unitConfigKey maps a unit onto its config/ package path.
func unitConfigKey(u *manifest.Unit, roots map[string]string) string {
	if u.Root == "" || u.Path == "" {
		return ""
	}
	rel := u.Path
	if filepath.IsAbs(u.Path) {
		rootPath := roots[u.Root]
		if rootPath == "" || !fsx.Within(rootPath, u.Path) {
			return ""
		}
		r, err := fsx.Rel(rootPath, u.Path)
		if err != nil {
			return ""
		}
		rel = r
	}
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.ReplaceAll(rel, `\`, "/"))))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return pack.ConfigDirName + "/" + u.Root + "/" + rel
}

// ---- decryption -----------------------------------------------------------

func loadSecrets(pkg string, crypt pack.CryptOptions, rep *Report) (*secretIndex, error) {
	idx := &secretIndex{values: map[string]string{}}
	path := filepath.Join(pkg, pack.SecretsName)
	fi, err := fsx.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return idx, nil
		}
		return idx, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if !fi.Mode.IsRegular() {
		return idx, fmt.Errorf("%w: %s 不是普通文件", ErrDecrypt, pack.SecretsName)
	}
	plain, err := pack.DecryptSecrets(pkg, crypt)
	if err != nil {
		rep.Problems = append(rep.Problems, Problem{Code: "rst_decrypt_failed", Detail: err.Error()})
		// Keep the cause wrapped so the CLI can tell a missing identity file
		// (fs.ErrNotExist) from a wrong identity/passphrase.
		return idx, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	var doc struct {
		Format  string `json:"format"`
		Entries []struct {
			Ref   string `json:"ref"`
			Value string `json:"value"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(plain, &doc); err != nil {
		rep.Problems = append(rep.Problems, Problem{Code: "rst_decrypt_failed", Detail: "索引不是 JSON: " + err.Error()})
		return idx, fmt.Errorf("%w: 解密后的索引无效: %v", ErrDecrypt, err)
	}
	for _, e := range doc.Entries {
		if e.Ref != "" {
			idx.values[e.Ref] = e.Value
		}
	}
	return idx, nil
}

// substitute replaces every placeholder whose ref resolves. Unresolved refs
// are recorded as missing_secret and the placeholder stays in place.
func substitute(data []byte, idx *secretIndex, rel, unit string, rep *Report) []byte {
	matches := placeholderRE.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return data
	}
	var out []byte
	last := 0
	for _, m := range matches {
		ref := string(data[m[2]:m[3]])
		out = append(out, data[last:m[0]]...)
		if v, ok := idx.values[ref]; ok {
			out = append(out, v...)
		} else {
			out = append(out, data[m[0]:m[1]]...)
			rep.Problems = append(rep.Problems, Problem{Code: "missing_secret", Path: rel,
				UnitID: unit, Detail: "secrets.age 中没有 " + ref})
		}
		last = m[1]
	}
	return append(out, data[last:]...)
}

// ---- planning -------------------------------------------------------------

func buildPlan(pkg, into string, mapping map[string]string, sig *pack.SIG, units map[string]string, secrets *secretIndex, rep *Report) ([]payload, error) {
	var items []payload
	landing := map[string]Landing{}
	for i := range sig.Entries {
		e := &sig.Entries[i]
		rel, ok := payloadRel(e.Path)
		if !ok || rel == "" {
			continue
		}
		src, err := pack.SafeJoin(pkg, e.Path)
		if err != nil {
			rep.Problems = append(rep.Problems, Problem{Code: "rst_path_escape", Path: e.Path, Detail: err.Error()})
			return items, fmt.Errorf("%w: %s: %v", ErrCorrupt, e.Path, err)
		}
		dst, err := mappedTarget(into, rel, mapping)
		if err != nil {
			rep.Problems = append(rep.Problems, Problem{Code: "rst_path_escape", Path: e.Path, Detail: err.Error()})
			return items, fmt.Errorf("%w: %s: %v", ErrCorrupt, e.Path, err)
		}
		role, _ := splitRole(rel)
		if _, ok := landing[role]; !ok {
			root, mapped, rerr := roleRoot(into, role, mapping)
			if rerr != nil {
				rep.Problems = append(rep.Problems, Problem{Code: "rst_path_escape", Path: e.Path, Detail: rerr.Error()})
				return items, fmt.Errorf("%w: %s: %v", ErrCorrupt, e.Path, rerr)
			}
			landing[role] = Landing{Role: role, Path: root, Mapped: mapped}
		}
		it := payload{entry: e, rel: e.Path, target: dst, unitID: units[e.Path]}
		switch e.Type {
		case pack.TypeDir:
			it.mode = 0o755
		case pack.TypeSymlink:
			it.link = *e.LinkTarget
			sum := sha256.Sum256([]byte(it.link))
			it.hash = hex.EncodeToString(sum[:])
			it.mode = 0o644
		case pack.TypeFile, pack.TypeHardlink:
			fi, lerr := fsx.Lstat(src)
			if lerr != nil || !fi.Mode.IsRegular() {
				rep.Problems = append(rep.Problems, Problem{Code: "rst_missing_entry", Path: e.Path,
					Detail: "包里缺少该条目"})
				return items, fmt.Errorf("%w: %s 缺失", ErrCorrupt, e.Path)
			}
			data, rerr := os.ReadFile(src)
			if rerr != nil {
				rep.Problems = append(rep.Problems, Problem{Code: "rst_missing_entry", Path: e.Path, Detail: rerr.Error()})
				return items, fmt.Errorf("%w: %s: %v", ErrCorrupt, e.Path, rerr)
			}
			if e.Type == pack.TypeFile && strings.HasPrefix(e.Path, pack.ConfigDirName+"/") {
				data = substitute(data, secrets, e.Path, it.unitID, rep)
			}
			it.data = data
			sum := sha256.Sum256(data)
			it.hash = hex.EncodeToString(sum[:])
			if e.Mode != nil {
				it.mode = pack.ParseMode(*e.Mode)
			} else {
				it.mode = 0o644
			}
			if e.Type == pack.TypeFile && e.SHA256 != nil && *e.SHA256 != it.hash &&
				!strings.HasPrefix(e.Path, pack.ConfigDirName+"/") {
				rep.Problems = append(rep.Problems, Problem{Code: "rst_missing_entry", Path: e.Path,
					Detail: "包内内容哈希与 SIG 不符"})
				return items, fmt.Errorf("%w: %s 内容与 SIG 不符", ErrCorrupt, e.Path)
			}
		default:
			continue
		}
		it.action = actionFor(dst, it)
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].rel < items[j].rel })
	roles := make([]string, 0, len(landing))
	for role := range landing {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		rep.Landing = append(rep.Landing, landing[role])
	}
	return items, nil
}

// payloadRel strips config/ and keeps the root subtree, so a restore lands at
// <into>/home/... . reinstall/ keeps its own name to avoid colliding with a
// config root of the same name.
func payloadRel(p string) (string, bool) {
	switch {
	case strings.HasPrefix(p, pack.ConfigDirName+"/"):
		return strings.TrimPrefix(p, pack.ConfigDirName+"/"), true
	case strings.HasPrefix(p, pack.ReinstallDirName+"/"):
		return p, true
	}
	return "", false
}

// splitRole separates payloadRel's leading role segment ("home", "repo",
// "reinstall", …) from the rest of the package-relative path.
func splitRole(rel string) (role, rest string) {
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return rel, ""
}

// normalizeMap validates --map values once. They must stay under Into: an
// absolute path, a drive/volume prefix, "~" or any ".." segment is a usage
// error. "." is allowed and means Into itself.
func normalizeMap(m map[string]string) (map[string]string, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(m))
	for role, raw := range m {
		if role == "" {
			return nil, fmt.Errorf("--map 缺少 ROLE")
		}
		if strings.ContainsAny(role, `/\`) || role == "." || role == ".." {
			return nil, fmt.Errorf("--map %q: ROLE 必须是单个角色名（如 home、repo）", role)
		}
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("--map %s 缺少 PATH", role)
		}
		if filepath.IsAbs(p) || filepath.VolumeName(p) != "" || strings.HasPrefix(p, "~") {
			return nil, fmt.Errorf("--map %s=%s: 映射必须是 --into 下的相对路径（不接受绝对路径、盘符或 ~）", role, raw)
		}
		clean := filepath.ToSlash(filepath.Clean(p))
		if clean == "." {
			out[role] = "."
			continue
		}
		for _, seg := range strings.Split(clean, "/") {
			if seg == ".." {
				return nil, fmt.Errorf("--map %s=%s: 映射不能包含 ..（必须留在 --into 之内）", role, raw)
			}
		}
		if err := pack.ValidateRelPath(clean); err != nil {
			return nil, fmt.Errorf("--map %s=%s: %v", role, raw, err)
		}
		out[role] = clean
	}
	return out, nil
}

// roleRoot resolves one role's landing root. Unmapped roles keep the
// historical Into/<role>; mapped roles land at Into/<map value>.
func roleRoot(into, role string, mapping map[string]string) (string, bool, error) {
	if sub, ok := mapping[role]; ok {
		if sub == "." {
			return into, true, nil
		}
		p, err := pack.SafeJoin(into, sub)
		return p, true, err
	}
	p, err := pack.SafeJoin(into, role)
	return p, false, err
}

// mappedTarget is buildPlan's destination: the role's (possibly mapped) root
// joined with the rest of the package-relative path. With no mapping it is
// exactly pack.SafeJoin(into, rel), so default restores are unchanged.
func mappedTarget(into, rel string, mapping map[string]string) (string, error) {
	role, rest := splitRole(rel)
	root, _, err := roleRoot(into, role, mapping)
	if err != nil {
		return "", err
	}
	if rest == "" {
		return root, nil
	}
	return pack.SafeJoin(root, rest)
}

func actionFor(dst string, it payload) string {
	fi, err := fsx.Lstat(dst)
	if err != nil {
		return "create"
	}
	if it.entry.Type == pack.TypeDir {
		if fi.IsDir && !fi.IsLink && !fi.IsReparse {
			return "same"
		}
		return "overwrite"
	}
	if fi.IsDir || fi.IsReparse {
		return "overwrite"
	}
	if it.entry.Type == pack.TypeSymlink {
		if fi.IsLink {
			if got, err := os.Readlink(dst); err == nil && got == it.link {
				return "same"
			}
		}
		return "overwrite"
	}
	if fi.IsLink || !fi.Mode.IsRegular() {
		return "overwrite"
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		return "overwrite"
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) == it.hash {
		return "same"
	}
	return "overwrite"
}

func hasChanges(items []payload) bool {
	for i := range items {
		if items[i].action != "same" {
			return true
		}
	}
	return false
}

// ---- writing --------------------------------------------------------------

// ensureDir makes rel (relative to root) a real directory chain.
func ensureDir(root, rel string) error {
	if rel == "" || rel == "." {
		return nil
	}
	if err := pack.ValidateRelPath(filepath.ToSlash(rel)); err != nil {
		return err
	}
	cur := ""
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if cur == "" {
			cur = seg
		} else {
			cur += "/" + seg
		}
		full, err := pack.SafeJoin(root, cur)
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
		if fi.IsLink || fi.IsReparse || !fi.IsDir {
			return fmt.Errorf("目标组件 %q 不是普通目录", cur)
		}
	}
	return nil
}

func writeDir(target string) error {
	fi, err := fsx.Lstat(target)
	if err == nil {
		if fi.IsDir && !fi.IsLink && !fi.IsReparse {
			return nil
		}
		if err := os.Remove(target); err != nil {
			return err
		}
	}
	return os.MkdirAll(target, 0o755)
}

func removeForOverwrite(target string) error {
	fi, err := fsx.Lstat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.IsDir && !fi.IsLink && !fi.IsReparse {
		return os.RemoveAll(target)
	}
	_ = os.Chmod(target, 0o644)
	return os.Remove(target)
}

// writeSymlink reports whether it had to flatten the link into a file.
func writeSymlink(root, target, link string, symlink func(string, string) error) (bool, error) {
	if err := ensureDir(root, filepath.ToSlash(parentRel(root, target))); err != nil {
		return false, err
	}
	if err := removeForOverwrite(target); err != nil {
		return false, err
	}
	if err := symlink(link, target); err == nil {
		return false, nil
	}
	it := payload{target: target, data: []byte(link), mode: 0o644,
		entry: &pack.SIGEntry{Type: pack.TypeSymlink}}
	sum := sha256.Sum256(it.data)
	it.hash = hex.EncodeToString(sum[:])
	return true, writeFile(root, &it)
}

func writeFile(root string, it *payload) error {
	if err := ensureDir(root, filepath.ToSlash(parentRel(root, it.target))); err != nil {
		return err
	}
	if err := removeForOverwrite(it.target); err != nil {
		return err
	}
	dir := filepath.Dir(it.target)
	f, err := os.CreateTemp(dir, "."+filepath.Base(it.target)+".rst-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(it.data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	mode := it.mode.Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, it.target); err != nil {
		return err
	}
	tmp = ""
	return nil
}

// parentRel returns target's directory relative to root.
func parentRel(root, target string) string {
	rel, err := fsx.Rel(root, filepath.Dir(target))
	if err != nil {
		return "."
	}
	return rel
}

func verifyReadBack(it *payload, flattened bool) error {
	if it.entry.Type == pack.TypeSymlink && !flattened {
		got, err := os.Readlink(it.target)
		if err != nil {
			return err
		}
		if got != it.link {
			return fmt.Errorf("回读链接目标 %q != 期望 %q", got, it.link)
		}
		return nil
	}
	f, err := os.Open(it.target)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != it.hash {
		return fmt.Errorf("回读哈希 %s != 期望 %s", got, it.hash)
	}
	if want := int64(len(it.data)); n != want {
		return fmt.Errorf("回读 %d 字节，期望 %d", n, want)
	}
	return nil
}

func failEntry(rep *Report, it *payload, err error) error {
	rep.Problems = append(rep.Problems, Problem{Code: "restore_corrupt", Path: it.rel,
		UnitID: it.unitID, Detail: err.Error()})
	return fmt.Errorf("%w: %s: %v", ErrCorrupt, it.rel, err)
}

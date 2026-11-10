// Package fsx owns every filesystem fact that differs between platforms:
// path canonicalization, path comparison, Windows attribute bits and
// allocation size. It is the only package allowed to import syscall or
// golang.org/x/sys (D-005); every other package stays platform independent.
//
// The package is deliberately split between path spelling and path identity:
// Abs returns the canonical, usable spelling while NormKey returns a folded
// comparison key. Callers must choose explicitly which one they need.
package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldCaser is stateless and safe for concurrent use.
var foldCaser = cases.Fold()

// caseInsensitiveDefault reports whether this platform's mainstream volumes
// are case insensitive by default. The manifest spec (§6.2) makes the volume
// policy authoritative; this is only the platform default used by Within,
// which has no volume descriptor to consult.
const caseInsensitiveDefault = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// Abs makes p absolute and cleans it. An empty p yields a *PathError wrapping
// ErrEmptyPath (INV-R01). Abs never touches the filesystem beyond reading the
// working directory and never resolves links or 8.3 short names.
//
// Abs must not hand an already absolute path to filepath.Abs: on Windows that
// goes through GetFullPathName, which strips trailing dots and spaces so a file
// stored as "trail." would come back as "trail" and could no longer be opened
// (D-034, INV-R03). filepath.Clean preserves both characters.
func Abs(p string) (string, error) {
	if p == "" {
		return "", &PathError{Op: "Abs", Path: p, Err: ErrEmptyPath}
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	if filepath.VolumeName(p) != "" {
		// Volume-relative ("C:foo") needs the OS's notion of that volume's
		// working directory. Such spellings are rare and carry no trailing
		// dot/space in practice.
		a, err := filepath.Abs(p)
		if err != nil {
			return "", &PathError{Op: "Abs", Path: p, Err: err}
		}
		return filepath.Clean(a), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", &PathError{Op: "Abs", Path: p, Err: err}
	}
	return filepath.Clean(filepath.Join(wd, p)), nil
}

// NormKey returns the comparison key for p: Unicode NFC, full case folding and
// normalization of every separator to "/". The slash is fixed, not the platform
// separator, so a key generated on Windows and one generated on Linux compare
// directly (D-034). Abs still returns the native spelling; keys are never used
// to open files. NormKey does not absolutize or clean, so the caller decides
// whether Abs is applied first. An empty p returns "".
//
// Folding is unconditional, including on case-sensitive volumes, so that the
// same manifest keys compare across machines (spec-manifest §6.3). Exact
// sensitivity on a specific volume remains the caller's policy.
func NormKey(p string) string {
	if p == "" {
		return ""
	}
	return toSlash(foldCaser.String(norm.NFC.String(p)))
}

// compareKey is like NormKey but folds only under the platform's default case
// policy. It is used for root containment (INV-R02), where the volume policy
// matters, whereas NormKey always folds.
func compareKey(p string) string {
	p = norm.NFC.String(p)
	if caseInsensitiveDefault {
		p = foldCaser.String(p)
	}
	return toSlash(p)
}

// unifySeparators rewrites "/" to the platform separator for parsing native
// spellings with filepath.
func unifySeparators(p string) string {
	if os.PathSeparator == '\\' {
		return strings.ReplaceAll(p, "/", `\`)
	}
	return p
}

// toSlash rewrites every separator to "/" for comparison keys (D-034).
func toSlash(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// Within reports whether p is root itself or lies below root. Comparison is by
// normalized path segment, never by bare string prefix (INV-R02): /data/app
// does not contain /data/application. Both arguments are absolutized first.
//
// Case is compared according to the platform default (insensitive on
// Windows/macOS, sensitive elsewhere). An empty or unusable argument yields
// false.
func Within(root, p string) bool {
	ar, err := Abs(root)
	if err != nil {
		return false
	}
	ap, err := Abs(p)
	if err != nil {
		return false
	}
	rs := compareSegments(ar)
	ps := compareSegments(ap)
	if len(rs) == 0 || len(ps) < len(rs) {
		return false
	}
	for i := range rs {
		if rs[i] != ps[i] {
			return false
		}
	}
	return true
}

func compareSegments(p string) []string {
	segs := Segments(p)
	for i := range segs {
		segs[i] = compareKey(segs[i])
	}
	return segs
}

// Segments splits p into a volume/root element followed by path components.
// The first element retains the root spelling ("/" or `C:\` or `\srv\share\`)
// so that segment-wise comparison can tell a root from a component. Empty and
// "." components are dropped; ".." is resolved by Clean. An empty p returns
// nil.
func Segments(p string) []string {
	if p == "" {
		return nil
	}
	p = filepath.Clean(unifySeparators(p))
	vol := filepath.VolumeName(p)
	rest := p[len(vol):]

	var segs []string
	if rest != "" && os.IsPathSeparator(rest[0]) {
		segs = append(segs, vol+string(os.PathSeparator))
		rest = rest[1:]
	} else if vol != "" {
		// A bare UNC volume is a share root; keep the trailing separator so it
		// never compares equal to a longer share name (\\srv\share vs
		// \\srv\share2). A bare drive letter (C:) stays as it is.
		if rest == "" && isUNCVolume(vol) {
			segs = append(segs, vol+string(os.PathSeparator))
		} else {
			segs = append(segs, vol)
		}
	}
	for _, s := range strings.Split(rest, string(os.PathSeparator)) {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// Rel returns p relative to root, using segment semantics. It requires both
// arguments to already be absolute; otherwise it returns ErrNotAbs. When the
// two paths share no volume it returns the underlying filepath.Rel error.
// Identical paths yield ".".
func Rel(root, p string) (string, error) {
	if root == "" {
		return "", &PathError{Op: "Rel", Path: root, Err: ErrEmptyPath}
	}
	if p == "" {
		return "", &PathError{Op: "Rel", Path: p, Err: ErrEmptyPath}
	}
	if !filepath.IsAbs(root) {
		return "", &PathError{Op: "Rel", Path: root, Err: ErrNotAbs}
	}
	if !filepath.IsAbs(p) {
		return "", &PathError{Op: "Rel", Path: p, Err: ErrNotAbs}
	}
	r, err := filepath.Rel(filepath.Clean(root), filepath.Clean(p))
	if err != nil {
		return "", &PathError{Op: "Rel", Path: p, Err: err}
	}
	return r, nil
}

// IsRootish reports whether deleting p would destroy an anchor that most
// machines expect to survive: a filesystem root (`/`, `C:\`), a top-level
// system directory (`/home`, `/var`, `C:\Windows`), a user profile
// (`/home/<n>`, `/Users/<n>`, `C:\Users\<n>`), or the root of a UNC share.
// Deeper paths, including anything below a UNC share root, are not rootish.
func IsRootish(p string) bool {
	if p == "" {
		return false
	}
	a, err := Abs(p)
	if err != nil {
		return false
	}
	segs := Segments(a)
	if len(segs) == 0 {
		return false
	}
	// A UNC share root (`\\srv\share`, `\\?\UNC\srv\share`) is the anchor; a
	// directory inside it is not.
	if isUNCVolume(filepath.VolumeName(a)) {
		return len(segs) == 1
	}
	switch len(segs) {
	case 1, 2:
		return true
	case 3:
		switch strings.ToLower(segs[1]) {
		case "home", "users":
			return true
		}
	}
	return false
}

// isUNCVolume reports whether vol is a UNC share (`\\srv\share`) or the UNC
// form of a verbatim path (`\\?\UNC\srv\share`). A verbatim drive path
// (`\\?\C:`) is not UNC.
func isUNCVolume(vol string) bool {
	if strings.HasPrefix(vol, `\\?\`) {
		return strings.HasPrefix(strings.ToLower(vol), `\\?\unc\`)
	}
	return strings.HasPrefix(vol, `\\`)
}

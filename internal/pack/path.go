package pack

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/yekunsong/Packout/internal/fsx"
)

// maxPathBytes mirrors the manifest's long-path ceiling (§6.5) and keeps a
// package portable to Windows without \?\ prefixes.
const maxPathBytes = 32767

// maxSegmentBytes is the NTFS component limit.
const maxSegmentBytes = 255

// reservedNames are the Win32 device names (C-08). The rule applies to the
// part before the first dot as well: "NUL.txt" is still NUL.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidateRelPath validates one package-relative entry name. It is applied to
// every SIG entry, every walked file and every extracted config path, on both
// the export and verify sides.
//
// Rejected (INV-C08, C-08):
//   - empty names and empty segments ("a//b", trailing "/")
//   - "." and ".." segments anywhere
//   - absolute POSIX paths and leading separators
//   - any backslash, which covers UNC ("\\host\share"), "\\?\\" and ".\\"
//   - drive letters and drive-relative names ("C:foo") by rejecting ":"
//   - NTFS alternate data streams ("file:stream")
//   - trailing dots and trailing spaces on any segment
//   - reserved device names, case-insensitively, with or without extension
//   - control characters, invalid UTF-8 and over-long components
//
// The accepted spelling always uses '/' as the separator and is otherwise
// unchanged; callers must not rewrite it (D-015 §15).
func ValidateRelPath(p string) error {
	if p == "" {
		return pathErr(p, "empty path")
	}
	if len(p) > maxPathBytes {
		return pathErr(p, "path exceeds 32767 bytes")
	}
	if !utf8.ValidString(p) {
		return pathErr(p, "path is not valid UTF-8")
	}
	if strings.ContainsRune(p, 0) {
		return pathErr(p, "path contains NUL")
	}
	if strings.ContainsAny(p, `\`) {
		return pathErr(p, `path contains a backslash (UNC, \?\, .\ or separator)`)
	}
	if strings.HasPrefix(p, "/") {
		return pathErr(p, "path is absolute")
	}
	if len(p) >= 2 && isASCIIAlpha(p[0]) && p[1] == ':' {
		return pathErr(p, "path starts with a drive letter")
	}
	for _, seg := range strings.Split(p, "/") {
		if err := validateSegment(seg); err != nil {
			return pathErr(p, err.Error())
		}
	}
	return nil
}

func validateSegment(seg string) error {
	if seg == "" {
		return fmt.Errorf("empty path segment")
	}
	if seg == "." || seg == ".." {
		return fmt.Errorf("dot segment %q", seg)
	}
	if len(seg) > maxSegmentBytes {
		return fmt.Errorf("segment longer than %d bytes", maxSegmentBytes)
	}
	if strings.HasSuffix(seg, ".") {
		return fmt.Errorf("segment %q ends with a dot", seg)
	}
	if strings.HasSuffix(seg, " ") {
		return fmt.Errorf("segment %q ends with a space", seg)
	}
	if strings.ContainsAny(seg, `\:*?"<>|`) {
		return fmt.Errorf("segment %q contains a Windows-forbidden character (ADS or separator)", seg)
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] < 0x20 || seg[i] == 0x7f {
			return fmt.Errorf("segment %q contains a control character", seg)
		}
	}
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if reservedNames[strings.ToUpper(base)] {
		return fmt.Errorf("segment %q is a reserved device name", seg)
	}
	return nil
}

func isASCIIAlpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ValidateLinkTarget validates a symlink target stored in the package. The
// target must be relative and must resolve, after cleaning, to a location
// inside the package root (INV-C10, C-07). Internal ".." is allowed as long as
// it does not climb out of the root.
func ValidateLinkTarget(entryPath, target string) error {
	if err := ValidateRelPath(entryPath); err != nil {
		return err
	}
	if target == "" {
		return pathErr(entryPath, "empty symlink target")
	}
	if !utf8.ValidString(target) {
		return pathErr(entryPath, "symlink target is not valid UTF-8")
	}
	if strings.ContainsRune(target, 0) {
		return pathErr(entryPath, "symlink target contains NUL")
	}
	if strings.ContainsAny(target, `\`) {
		return pathErr(entryPath, "symlink target contains a backslash")
	}
	if strings.HasPrefix(target, "/") {
		return pathErr(entryPath, "symlink target is absolute")
	}
	if len(target) >= 2 && isASCIIAlpha(target[0]) && target[1] == ':' {
		return pathErr(entryPath, "symlink target starts with a drive letter")
	}
	for _, seg := range strings.Split(target, "/") {
		if seg == "." || seg == ".." {
			continue // resolved below
		}
		if err := validateSegment(seg); err != nil {
			return pathErr(entryPath, "symlink target: "+err.Error())
		}
	}
	resolved := path.Clean(path.Join(path.Dir(entryPath), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return pathErr(entryPath, "symlink target resolves outside the package root")
	}
	return nil
}

// ValidateHardlinkTarget validates the in-package path a hardlink points at.
func ValidateHardlinkTarget(entryPath, target string) error {
	if err := ValidateRelPath(entryPath); err != nil {
		return err
	}
	if err := ValidateRelPath(target); err != nil {
		return pathErr(entryPath, "hardlink target: "+err.Error())
	}
	if entryPath == target {
		return pathErr(entryPath, "hardlink points at itself")
	}
	return nil
}

// safeJoin maps a validated package-relative path onto root and re-checks
// containment by segment (INV-R02), so a defective validator cannot become a
// write-through.
func safeJoin(root, rel string) (string, error) {
	if err := ValidateRelPath(rel); err != nil {
		return "", err
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	if !fsx.Within(root, p) {
		return "", pathErr(rel, "resolves outside root")
	}
	return p, nil
}

// SafeJoin maps a validated package-relative path onto root and re-checks
// containment by segment (INV-R02), so a defective validator cannot become a
// write-through. Restore uses it for every destination path.
func SafeJoin(root, rel string) (string, error) { return safeJoin(root, rel) }

func pathErr(p, detail string) error {
	return fmt.Errorf("%w: %q: %s", ErrInvalidPath, p, detail)
}

// modeString renders the portable permission bits deterministically.
func modeString(m fs.FileMode) string {
	return fmt.Sprintf("%04o", uint32(m.Perm()))
}

//go:build windows

package scan

import (
	"errors"

	"golang.org/x/sys/windows"
)

// symlinkNeedsPrivilege reports whether err is the Windows failure returned by
// os.Symlink when neither developer mode nor SeCreateSymbolicLinkPrivilege is
// available. Such a machine can still run the test, it just cannot create
// links, so callers skip instead of failing (D-034).
func symlinkNeedsPrivilege(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

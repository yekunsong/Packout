//go:build !windows

package pack

// symlinkNeedsPrivilege is always false off Windows; Unix either creates
// symlinks or fails for a reason worth reporting (D-034).
func symlinkNeedsPrivilege(error) bool { return false }

//go:build unix

package restore

import "syscall"

// freeBytes reports the space available to the caller on the volume holding
// dir (freeBytesAvailableToCaller semantics).
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

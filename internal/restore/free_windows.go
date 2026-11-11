//go:build windows

package restore

import "golang.org/x/sys/windows"

// freeBytes reports the space available to the caller on the volume holding
// dir.
func freeBytes(dir string) (int64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, avail uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &avail); err != nil {
		return 0, err
	}
	return int64(free), nil
}

//go:build !windows

package main

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/unix"
)

func lookPath(name string) (string, error) { return exec.LookPath(name) }

func specialScript() (string, error) {
	return "", fmt.Errorf("special.ps1: not windows")
}

func runPowerShell(args []string) (int, string, error) {
	return -1, "", fmt.Errorf("powershell unavailable")
}

func diskPreflight(path string, need uint64) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return err
	}
	avail := st.Bavail * uint64(st.Bsize)
	if avail < need {
		return skipf("disk_space (need %d MiB, have %d MiB)", need>>20, avail>>20)
	}
	return nil
}

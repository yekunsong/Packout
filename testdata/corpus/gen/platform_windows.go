//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

func lookPath(name string) (string, error) { return exec.LookPath(name) }

func specialScript() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate special.ps1")
	}
	p := filepath.Join(filepath.Dir(file), "..", "win", "special.ps1")
	return p, nil
}

func runPowerShell(args []string) (int, string, error) {
	cmd := exec.Command("powershell.exe", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), text, nil
		}
		return -1, text, err
	}
	return 0, text, nil
}

// diskPreflight requires at least need free bytes at path.
func diskPreflight(path string, need uint64) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var freeAvail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeAvail, &total, &totalFree); err != nil {
		return err
	}
	if freeAvail < need {
		return skipf("disk_space (need %d MiB, have %d MiB)", need>>20, freeAvail>>20)
	}
	return nil
}

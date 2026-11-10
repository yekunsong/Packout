//go:build !windows

package scan

import "os"

func testIsRoot() bool { return os.Geteuid() == 0 }

//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fsctlSetSparse   = 0x000900c4
	fsctlSetZeroData = 0x000980c8
)

type fileZeroDataInformation struct {
	FileOffset            int64
	BeyondFinalFileOffset int64
}

// setSparse marks the file sparse, grows it to size and punches the whole
// range to zero without allocating clusters (SPEC §9.1, but via DeviceIoControl
// so the path length does not hit the command-line limit).
func setSparse(abs string, size int64) error {
	f, err := os.Create(hostPath(abs))
	if err != nil {
		return err
	}
	f.Close()
	p, err := windows.UTF16PtrFromString(hostPath(abs))
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var ret uint32
	if err := windows.DeviceIoControl(h, fsctlSetSparse, nil, 0, nil, 0, &ret, nil); err != nil {
		return err
	}
	if _, err := windows.SetFilePointer(h, int32(size), nil, windows.FILE_BEGIN); err != nil {
		return err
	}
	if err := windows.SetEndOfFile(h); err != nil {
		return err
	}
	z := fileZeroDataInformation{FileOffset: 0, BeyondFinalFileOffset: size}
	if err := windows.DeviceIoControl(h, fsctlSetZeroData,
		(*byte)(unsafe.Pointer(&z)), uint32(unsafe.Sizeof(z)), nil, 0, &ret, nil); err != nil {
		return err
	}
	return nil
}

func isReparse(info os.FileInfo) bool {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || d == nil {
		return false
	}
	return d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

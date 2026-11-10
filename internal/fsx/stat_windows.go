//go:build windows

package fsx

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	attrReadonly         = 0x00000001
	attrDirectory        = 0x00000010
	attrSparseFile       = 0x00000200
	attrReparsePoint     = 0x00000400
	attrOffline          = 0x00001000
	attrRecallOnOpen     = 0x00040000
	attrRecallOnDataAcce = 0x00400000

	fileAttributeTagInfo = 9 // FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo
)

type fileAttributeTagInfoBuf struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// fileStandardInfo mirrors FILE_STANDARD_INFO (not exported by x/sys).
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  bool
	Directory      bool
}

// Info is the platform-neutral snapshot of one directory entry. It is filled
// by Lstat/Fstat and never follows a link by itself.
type Info struct {
	// Path is the spelling that was passed in, unchanged.
	Path string
	// Size is the apparent (logical) size in bytes (FILE_STANDARD_INFO.EndOfFile).
	Size int64
	// Alloc is the allocated size in bytes (FILE_STANDARD_INFO.AllocationSize).
	Alloc int64
	// Mode is the portable file mode.
	Mode fs.FileMode
	// ModTime is the last write time.
	ModTime time.Time
	// IsDir is true for directories.
	IsDir bool
	// IsLink is true for symbolic links. Junctions are reparse points but not
	// IsLink.
	IsLink bool
	// IsReparse is true for every reparse point, including junctions and
	// other reparse tags (INV-R04).
	IsReparse bool
	// IsSparse is true for sparse files.
	IsSparse bool
	// IsOffline is true when the entry is offline or not fully local
	// (OFFLINE / RECALL_ON_DATA_ACCESS / RECALL_ON_OPEN); reading it may
	// hydrate it (INV-R07).
	IsOffline bool
	// FileID is an opaque identity derived from volume serial and file index,
	// or "" when unavailable.
	FileID string
	// ReparseTag is the raw reparse tag when IsReparse is true, else 0.
	ReparseTag uint32
	// LinkTarget is the raw reparse target, or "".
	LinkTarget string
}

// Lstat returns information about p without following a final reparse point
// (symlink or junction). The handle is opened with FILE_FLAG_OPEN_REPARSE_POINT
// so the link itself is inspected. Errors are *PathError; an empty path wraps
// ErrEmptyPath.
func Lstat(p string) (*Info, error) {
	if p == "" {
		return nil, &PathError{Op: "Lstat", Path: p, Err: ErrEmptyPath}
	}
	full, err := preparePath(p)
	if err != nil {
		return nil, &PathError{Op: "Lstat", Path: p, Err: normalizeErr(err)}
	}
	h, err := windows.CreateFile(
		utf16Ptr(full),
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &PathError{Op: "Lstat", Path: p, Err: normalizeErr(err)}
	}
	defer windows.CloseHandle(h)

	info, err := infoFromHandle(h, p)
	if err != nil {
		return nil, &PathError{Op: "Lstat", Path: p, Err: normalizeErr(err)}
	}
	if info.IsReparse {
		if target, err := os.Readlink(full); err == nil {
			info.LinkTarget = target
		}
	}
	return info, nil
}

// Fstat returns information about an already open handle so that FileID,
// ModTime and Size can be re-verified before a read (INV-R11).
func Fstat(f *os.File) (*Info, error) {
	if f == nil {
		return nil, &PathError{Op: "Fstat", Path: "", Err: ErrUnsupported}
	}
	info, err := infoFromHandle(windows.Handle(f.Fd()), f.Name())
	if err != nil {
		return nil, &PathError{Op: "Fstat", Path: f.Name(), Err: err}
	}
	return info, nil
}

// Open opens p read-only with no write intent, following a final reparse
// point. FILE_SHARE_DELETE is always requested so an open file does not block
// deletion or rename.
func Open(p string) (*os.File, error) {
	if p == "" {
		return nil, &PathError{Op: "Open", Path: p, Err: ErrEmptyPath}
	}
	full, err := preparePath(p)
	if err != nil {
		return nil, &PathError{Op: "Open", Path: p, Err: normalizeErr(err)}
	}
	h, err := windows.CreateFile(
		utf16Ptr(full),
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, &PathError{Op: "Open", Path: p, Err: normalizeErr(err)}
	}
	return os.NewFile(uintptr(h), p), nil
}

func infoFromHandle(h windows.Handle, p string) (*Info, error) {
	var bh windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bh); err != nil {
		return nil, err
	}
	var si fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(
		h,
		windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&si)),
		uint32(unsafe.Sizeof(si)),
	); err != nil {
		return nil, err
	}
	var ti fileAttributeTagInfoBuf
	tagOK := windows.GetFileInformationByHandleEx(
		h,
		fileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&ti)),
		uint32(unsafe.Sizeof(ti)),
	) == nil

	attrs := bh.FileAttributes
	var tag uint32
	if tagOK {
		tag = ti.ReparseTag
	}
	info := &Info{
		Path:       p,
		Size:       si.EndOfFile,
		Alloc:      si.AllocationSize,
		ModTime:    time.Unix(0, bh.LastWriteTime.Nanoseconds()),
		ReparseTag: tag,
	}
	info.IsDir, info.IsLink, info.IsReparse, info.IsSparse, info.IsOffline = classify(attrs, tag)
	if attrs&attrDirectory != 0 {
		info.Mode |= fs.ModeDir
	}
	if attrs&attrReadonly == 0 {
		info.Mode |= 0o200
	}
	switch tag {
	case windows.IO_REPARSE_TAG_SYMLINK:
		info.Mode |= fs.ModeSymlink
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
		info.Mode |= fs.ModeDir | fs.ModeSymlink
	}
	info.FileID = fmt.Sprintf(
		"%04X-%04X:%016X",
		(bh.VolumeSerialNumber>>16)&0xffff,
		bh.VolumeSerialNumber&0xffff,
		uint64(bh.FileIndexHigh)<<32|uint64(bh.FileIndexLow),
	)
	return info, nil
}

// classify maps raw attributes and a reparse tag to the portable flags.
func classify(attrs, tag uint32) (isDir, isLink, isReparse, isSparse, isOffline bool) {
	isDir = attrs&attrDirectory != 0
	isReparse = attrs&attrReparsePoint != 0
	isLink = isReparse && tag == windows.IO_REPARSE_TAG_SYMLINK
	isSparse = attrs&attrSparseFile != 0
	isOffline = attrs&(attrOffline|attrRecallOnDataAcce|attrRecallOnOpen) != 0
	return
}

// preparePath absolutizes p, normalizes separators and adds the \\?\ prefix
// that disables Win32 path parsing. The prefix is always used so trailing dots
// and spaces survive: Win32 otherwise normalizes "trail." to "trail" and a
// file stored under the former could not be opened by its real name (D-034).
// Abs already cleaned the spelling, and verbatim paths perform no "."/".."
// resolution of their own (INV-R03).
func preparePath(p string) (string, error) {
	a, err := Abs(p)
	if err != nil {
		return "", err
	}
	a = strings.ReplaceAll(a, "/", `\`)
	if strings.HasPrefix(a, `\\?\`) || strings.HasPrefix(a, `\\.\`) {
		return a, nil
	}
	if strings.HasPrefix(a, `\\`) {
		return `\\?\UNC\` + a[2:], nil
	}
	return `\\?\` + a, nil
}

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		// Prepared paths are valid UTF-16 by construction.
		return nil
	}
	return p
}

// normalizeErr maps platform "not found" errors onto fs.ErrNotExist so callers
// can test with errors.Is. os.IsNotExist does not unwrap custom error types,
// which silently turned every missing optional file into a read error.
func normalizeErr(err error) error {
	if err != nil && os.IsNotExist(err) {
		return fs.ErrNotExist
	}
	return err
}

//go:build unix

package fsx

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// Info is the platform-neutral snapshot of one directory entry. It is filled
// by Lstat/Fstat and never follows a link by itself.
type Info struct {
	// Path is the spelling that was passed in, unchanged.
	Path string
	// Size is the apparent (logical) size in bytes.
	Size int64
	// Alloc is the allocated size in bytes (st_blocks * 512 on Unix,
	// FILE_STANDARD_INFO.AllocationSize on Windows).
	Alloc int64
	// Mode is the portable file mode.
	Mode fs.FileMode
	// ModTime is the last write time.
	ModTime time.Time
	// IsDir is true for directories.
	IsDir bool
	// IsLink is true for symbolic links.
	IsLink bool
	// IsReparse is true for Windows reparse points. On Unix it mirrors
	// IsLink so callers can use one predicate for "do not follow".
	IsReparse bool
	// IsSparse is true for sparse files.
	IsSparse bool
	// IsOffline is true for files marked offline or recalled on access; such
	// entries may hydrate (download) when read (INV-R07).
	IsOffline bool
	// FileID is an opaque platform file identity, or "" when unavailable.
	FileID string
	// ReparseTag is the Windows reparse tag; 0 on Unix.
	ReparseTag uint32
	// LinkTarget is the raw link target as stored on disk, or "".
	LinkTarget string
}

// Lstat returns information about p without following a final symlink. The
// error is a *PathError; an empty path wraps ErrEmptyPath.
func Lstat(p string) (*Info, error) {
	if p == "" {
		return nil, &PathError{Op: "Lstat", Path: p, Err: ErrEmptyPath}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, &PathError{Op: "Lstat", Path: p, Err: normalizeErr(err)}
	}
	info := infoFromFileInfo(p, fi)
	if info.IsLink {
		if target, err := os.Readlink(p); err == nil {
			info.LinkTarget = target
		}
	}
	return info, nil
}

// Fstat returns information about an already open handle. Callers use it to
// re-verify FileID/ModTime/Size against an earlier Lstat so that a swap between
// stat and read can be detected and marked stale (INV-R11).
func Fstat(f *os.File) (*Info, error) {
	if f == nil {
		return nil, &PathError{Op: "Fstat", Path: "", Err: ErrUnsupported}
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, &PathError{Op: "Fstat", Path: f.Name(), Err: err}
	}
	return infoFromFileInfo(f.Name(), fi), nil
}

// Open opens p read-only with no write intent. On Unix this is a plain
// O_RDONLY open and follows a final symlink.
func Open(p string) (*os.File, error) {
	if p == "" {
		return nil, &PathError{Op: "Open", Path: p, Err: ErrEmptyPath}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, &PathError{Op: "Open", Path: p, Err: normalizeErr(err)}
	}
	return f, nil
}

func infoFromFileInfo(p string, fi os.FileInfo) *Info {
	info := &Info{
		Path:    p,
		Size:    fi.Size(),
		Mode:    fi.Mode(),
		ModTime: fi.ModTime(),
		IsDir:   fi.IsDir(),
		IsLink:  fi.Mode()&fs.ModeSymlink != 0,
	}
	info.IsReparse = info.IsLink
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		info.Alloc = int64(st.Blocks) * 512
		// Heuristic: fewer allocated bytes than apparent bytes means holes.
		// Compression or dedup can make this true for dense files too.
		info.IsSparse = info.Alloc < info.Size
		info.FileID = fmt.Sprintf("%x:%x", uint64(st.Dev), uint64(st.Ino))
	}
	return info
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

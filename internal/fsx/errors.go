package fsx

import "errors"

// Sentinel errors returned by this package. Callers use errors.Is to classify
// a failure without parsing messages.
var (
	// ErrEmptyPath means a path argument was the empty string. INV-R01:
	// an empty path must abort instead of silently degrading to the root.
	ErrEmptyPath = errors.New("fsx: empty path")

	// ErrNotAbs means an operation that requires an already absolute path was
	// given a relative one.
	ErrNotAbs = errors.New("fsx: path is not absolute")

	// ErrUnsupported means the operation cannot be expressed on this platform
	// or the platform does not expose the requested information.
	ErrUnsupported = errors.New("fsx: unsupported operation")
)

// PathError carries the operation and the offending path alongside the
// underlying error. Every failure of a path-taking function is wrapped in a
// *PathError so a caller can attribute it to one entry and turn it into a
// read_error without aborting the whole scan (INV-R09).
type PathError struct {
	Op   string
	Path string
	Err  error
}

// Error implements error.
func (e *PathError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := "fsx"
	if e.Op != "" {
		msg += " " + e.Op
	}
	if e.Path != "" {
		msg += " " + quotePath(e.Path)
	} else {
		msg += " \"\""
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error for errors.Is / errors.As.
func (e *PathError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func quotePath(p string) string {
	const max = 160
	if len(p) <= max {
		return `"` + p + `"`
	}
	return `"` + p[:max] + `"…`
}

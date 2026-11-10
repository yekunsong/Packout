package pack

import "errors"

// Sentinel errors returned by this package. Callers classify failures with
// errors.Is; each mismatch also carries a *Problem with the offending entry.
var (
	// ErrDestNotEmpty is returned when OutDir exists, is non-empty and Force
	// is false (C-09). Nothing is written.
	ErrDestNotEmpty = errors.New("pack: destination directory is not empty")
	// ErrSourceOverlap means the source and destination trees overlap, which
	// would make the package include itself.
	ErrSourceOverlap = errors.New("pack: source and destination overlap")
	// ErrInvalidConfig means a required Config field is missing or unusable.
	ErrInvalidConfig = errors.New("pack: invalid config")
	// ErrPathEscape means a path leaves its allowed root.
	ErrPathEscape = errors.New("pack: path escapes root")
	// ErrInvalidPath means an entry name violates the package naming rules
	// (C-06/C-08).
	ErrInvalidPath = errors.New("pack: invalid entry path")
	// ErrUnsupportedEntry means the tree contains an entry kind the package
	// format does not model (device, FIFO, socket, junction).
	ErrUnsupportedEntry = errors.New("pack: unsupported entry kind")
	// ErrLimitExceeded means a C-10 resource limit was hit. The operation
	// aborts; nothing is truncated or partially accepted.
	ErrLimitExceeded = errors.New("pack: limit exceeded")
	// ErrEmptyPackage means the directory is neither a package nor a
	// manifest tree: it has no SIG and no manifest.
	ErrEmptyPackage = errors.New("pack: empty or unrecognised package")
	// ErrNoManifest means a SIG is present but manifest/ is missing.
	ErrNoManifest = errors.New("pack: package has no manifest")
	// ErrUnsupportedFormat means SIG declares a format, version, method or
	// signing state this build does not understand (P0 has no signatures).
	ErrUnsupportedFormat = errors.New("pack: unsupported package format")
	// ErrTampered means the actual tree does not match SIG.
	ErrTampered = errors.New("pack: package contents do not match SIG")
	// ErrManifestInvalid means manifest/ exists but does not validate.
	ErrManifestInvalid = errors.New("pack: invalid manifest")
)

// Problem is one concrete verification or export failure, always tied to the
// entry that caused it so a caller can name the file in the report.
type Problem struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Error makes Problem usable as an error value in diagnostics.
func (p Problem) Error() string {
	if p.Path != "" {
		return p.Code + " " + p.Path + ": " + p.Detail
	}
	return p.Code + ": " + p.Detail
}

// ProblemsError aggregates entry-level problems and wraps one sentinel so that
// both errors.Is and a per-entry listing are available.
type ProblemsError struct {
	Sentinel error
	Problems []Problem
}

func (e *ProblemsError) Error() string {
	msg := e.Sentinel.Error()
	if len(e.Problems) > 0 {
		msg += " (" + e.Problems[0].Error()
		if len(e.Problems) > 1 {
			msg += "; +" + itoa(len(e.Problems)-1) + " more"
		}
		msg += ")"
	}
	return msg
}

// Unwrap exposes the sentinel.
func (e *ProblemsError) Unwrap() error { return e.Sentinel }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

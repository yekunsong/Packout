// Package restore writes a verified state package onto a target directory.
//
// It is the first packout operation that writes outside --out, so the order is
// fixed (docs/design-restore.md): verify, target gate, decrypt, plan, write,
// read-back hash check, three-part report. It never deletes source data and
// never rolls back a partial write.
package restore

import "errors"

// Sentinel errors. The CLI maps every one of them to exit 2 except usage and
// a non-empty destination (exit 3/4).
var (
	// ErrUsage means a required flag is missing or contradicts another.
	ErrUsage = errors.New("restore: usage")
	// ErrUnverified means the SIG conclusion is not ok and the user did not
	// pass --allow-unverified (or the conclusion is empty, which the flag
	// never widens).
	ErrUnverified = errors.New("restore: package is not verified")
	// ErrTampered means the package contents do not match SIG, so the hashes
	// cannot be trusted even with --allow-unverified.
	ErrTampered = errors.New("restore: package is tampered")
	// ErrDestNotEmpty means the target is non-empty and --in-place was not
	// given, or --in-place found changes but --force was not given.
	ErrDestNotEmpty = errors.New("restore: destination is not empty")
	// ErrDecrypt means secrets.age exists but could not be decrypted.
	ErrDecrypt = errors.New("restore: secrets decryption failed")
	// ErrDiskBudget means free space is below 1.2x the planned bytes.
	ErrDiskBudget = errors.New("restore: not enough free space")
	// ErrCorrupt means an entry was missing, unwritable, or read back with a
	// different hash than expected.
	ErrCorrupt = errors.New("restore: restored entry failed verification")
	// ErrCanceled means the context was cancelled mid-run.
	ErrCanceled = errors.New("restore: canceled")
)

// Problem is one diagnosed item, tied to a path or a secret reference.
type Problem struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"`
	UnitID string `json:"unit_id,omitempty"`
	Detail string `json:"detail,omitempty"`
}

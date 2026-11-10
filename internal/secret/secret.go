// Package secret identifies credential material in already-read text and
// proposes a manifest secret class (spec-manifest §4.3). It never touches the
// filesystem and never keeps plaintext: callers get hit offsets, short
// non-secret affixes and a value fingerprint.
//
// The package is deterministic. Detection is a pure function of (file name,
// bytes, options): the same input yields byte-for-byte the same hits, ordered
// by ascending offset. Hits carry a stable rule name so callers can explain a
// finding without re-parsing the value.
//
// Two classes are informational only and are never redacted:
//   - Reference: the value points elsewhere (${VAR}, op://...).
//   - None: the value looks already masked (all '*'), so it is already safe.
//
// Fingerprints: ValueFP with no salt is only for de-duplication within a single
// scan. It MUST NOT be written to a manifest (spec-manifest §9.3 requires the
// scan salt). Use ValueFPWithSalt for anything persisted.
//
// Invariants from the threat model: INV-B08 (no complete plaintext in reports)
// is served by redaction; B-04 (mask too long is brute-forceable, too short is
// unusable) drove the default mask: first 4 and last 4 bytes for values longer
// than 8 bytes, a full run of '*' otherwise. Visible characters and the
// fingerprint are independent fields of Hit (D-025 §1).
package secret

import (
	"crypto/sha256"
	"encoding/hex"
)

// Class is a suggested handling class for one hit. The zero value, None, is
// also used for already-masked values.
type Class int

const (
	// None means no actionable secret at this position. Redact leaves it.
	None Class = iota
	// Reference means the value is a pointer such as ${VAR} or op://vault/...,
	// so the plaintext lives elsewhere. Redact leaves it.
	Reference
	// Restore means the plaintext can be carried to another machine as-is.
	Restore
	// Relogin means the value is short-lived or device bound and the user
	// should authenticate again on the new machine (threat-model §6).
	Relogin
)

// String returns the manifest spelling of c.
func (c Class) String() string {
	switch c {
	case None:
		return "none"
	case Reference:
		return "reference"
	case Restore:
		return "restore"
	case Relogin:
		return "relogin"
	default:
		return "unknown"
	}
}

// Hit is one detected position. Offset and Length index the input bytes and
// always describe the value as it appears in the file (quotes and key names
// excluded).
//
// ValueFP is the fingerprint of the whole matched value and is independent of
// the visible characters in Prefix/Suffix. Prefix and Suffix are short,
// non-secret affixes that belong to the value, at most 7 bytes each
// (spec-manifest §9.2); they exist for display only.
//
// LowConfidence is true exactly for high-entropy fallback hits. Reports MUST
// present them differently from known-prefix hits (D-025 §5).
type Hit struct {
	Class         Class
	Rule          string
	Offset        int
	Length        int
	ValueFP       string
	Prefix        string
	Suffix        string
	LowConfidence bool
}

// End returns the first byte after the hit.
func (h Hit) End() int { return h.Offset + h.Length }

// DetectResult is the full outcome of a detection pass. Hits never contains a
// sentinel: Truncated is a separate boolean and Dropped counts the actionable
// candidates that were known to be dropped at the hit limit (a lower bound when
// the internal candidate cap was also reached).
type DetectResult struct {
	Hits      []Hit
	Truncated bool
	Dropped   int
}

// DefaultMaxHits applies when Detect is called with maxHits <= 0.
const DefaultMaxHits = 32

// HardMaxHits is the upper bound even if the caller asks for more.
const HardMaxHits = 1024

// MaxValueLen is the longest prefix of a single value that is judged.
// Values longer than this are still redacted in full.
const MaxValueLen = 8192

// ValueFP returns the unsalted value fingerprint: the first 8 bytes of
// SHA-256, hex encoded (16 characters).
//
// The result MUST only be used to de-duplicate within one scan. It MUST NOT be
// written to a manifest; spec-manifest §9.3 requires sha256(value + scan_salt),
// which is ValueFPWithSalt.
func ValueFP(v []byte) string {
	return ValueFPWithSalt(v, nil)
}

// ValueFPWithSalt returns the salted value fingerprint required for persisted
// manifests (spec-manifest §9.3): the first 8 bytes of sha256(value || salt),
// hex encoded. salt is the non-secret scan salt from the manifest header
// (inputs.secret_salt). Callers must pass the same salt for every unit of one
// scan and must compare fingerprints only when the salt mode and value match.
func ValueFPWithSalt(v, salt []byte) string {
	h := sha256.New()
	h.Write(v)
	h.Write(salt)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// Options controls DetectWith. The zero value is valid: entropy is off and
// the default hit limit applies.
type Options struct {
	// Entropy enables the high-entropy fallback. It is the only rule that can
	// fire without a known shape, so callers on noisy corpora may disable it.
	// Entropy hits carry LowConfidence.
	Entropy bool
	// MaxHits caps real hits; 0 means DefaultMaxHits and values above
	// HardMaxHits are clamped.
	MaxHits int
}

package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

// crockford is the Crockford Base32 alphabet used by ULID-style identifiers.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// FingerprintChunk is the streaming hash chunk size (§8: 1 MiB).
const FingerprintChunk = 1 << 20

// HeadTailWindow is how many bytes are read from each end for a head-tail
// fingerprint (§4.5, §8).
const HeadTailWindow int64 = 1 << 20

// crockfordEncode encodes b as Crockford Base32, most significant bit first.
// A partial final group is zero-padded on the right, so 16 bytes always yield
// 26 characters.
func crockfordEncode(b []byte) string {
	total := len(b) * 8
	out := make([]byte, 0, (total+4)/5)
	// The leading group is partial when the bit length is not a multiple of
	// five, which is the ULID-compatible alignment (128 bits -> 3 + 25x5).
	bitAt := func(pos, n int) byte {
		var v byte
		for i := 0; i < n; i++ {
			p := pos + i
			v <<= 1
			if p < total && b[p/8]&(1<<uint(7-p%8)) != 0 {
				v |= 1
			}
		}
		return v
	}
	pos := 0
	if head := total % 5; head != 0 {
		out = append(out, crockford[bitAt(0, head)])
		pos = head
	}
	for pos < total {
		out = append(out, crockford[bitAt(pos, 5)])
		pos += 5
	}
	return string(out)
}

// UnitID derives the path-based identifier of §4.2:
//
//	"u_" + CrockfordBase32(sha256(root \0 profile \0 entry \0 part \0 path_key)[:16])
func UnitID(root, profile, entry, partID, pathKey string) string {
	h := sha256.New()
	h.Write([]byte(root))
	h.Write([]byte{0})
	h.Write([]byte(profile))
	h.Write([]byte{0})
	h.Write([]byte(entry))
	h.Write([]byte{0})
	h.Write([]byte(partID))
	h.Write([]byte{0})
	h.Write([]byte(pathKey))
	return "u_" + crockfordEncode(h.Sum(nil)[:16])
}

// ComputeID returns the value UnitID would produce for u.
func (u *Unit) ComputeID() string {
	return UnitID(u.Root, u.Profile, u.Entry, u.PartID, u.PathKey)
}

// CID derives the content-addressed second key of §4.2.1:
//
//	"c_" + CrockfordBase32(sha256(algo \0 value)[:16])
//
// It returns nil when the fingerprint has no value or uses the shape scope;
// both cases are spec-mandated nulls. CID is independent of path, root,
// profile and entry, so equal content maps to one CID across machines.
func CID(fp *Fingerprint) *string {
	if fp == nil || fp.Value == nil {
		return nil
	}
	switch fp.Scope {
	case "", "shape":
		return nil
	}
	h := sha256.New()
	h.Write([]byte(fp.Algo))
	h.Write([]byte{0})
	h.Write([]byte(*fp.Value))
	s := "c_" + crockfordEncode(h.Sum(nil)[:16])
	return &s
}

// FingerprintFile computes the content fingerprint of size bytes read from r
// (typically *os.File or bytes.Reader).
//
// scope values:
//   - "full": hash every byte in 1 MiB chunks.
//   - "head-tail": hash the first and last 1 MiB; for files of at most 2 MiB
//     this equals full, which the spec permits.
//   - "" or "null": no content is readable; the result has scope null and a
//     nil value, and callers add content_partial (§4.5).
//
// Any other scope is an error. The returned fingerprint always names sha256.
func FingerprintFile(r io.ReaderAt, size int64, scope string) (Fingerprint, error) {
	fp := Fingerprint{Algo: "sha256", Scope: scope}
	if size < 0 {
		return fp, fmt.Errorf("manifest: negative size %d", size)
	}
	h := sha256.New()
	switch scope {
	case "", "null":
		fp.Scope = ""
		return fp, nil
	case "full":
		if err := hashRange(h, r, 0, size); err != nil {
			return fp, err
		}
	case "head-tail":
		if size <= 2*HeadTailWindow {
			if err := hashRange(h, r, 0, size); err != nil {
				return fp, err
			}
		} else {
			if err := hashRange(h, r, 0, HeadTailWindow); err != nil {
				return fp, err
			}
			if err := hashRange(h, r, size-HeadTailWindow, HeadTailWindow); err != nil {
				return fp, err
			}
		}
	default:
		return fp, fmt.Errorf("manifest: unsupported fingerprint scope %q", scope)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	fp.Value = &sum
	return fp, nil
}

// FingerprintBytes is FingerprintFile over a byte slice.
func FingerprintBytes(b []byte, scope string) (Fingerprint, error) {
	return FingerprintFile(bytes.NewReader(b), int64(len(b)), scope)
}

// hashRange hashes n bytes from r starting at off using 1 MiB chunks.
func hashRange(h io.Writer, r io.ReaderAt, off, n int64) error {
	size := n
	if size > FingerprintChunk {
		size = FingerprintChunk
	}
	if size < 1 {
		size = 1
	}
	buf := make([]byte, size)
	remaining := n
	pos := off
	for remaining > 0 {
		chunk := int64(len(buf))
		if remaining < chunk {
			chunk = remaining
		}
		read, err := r.ReadAt(buf[:chunk], pos)
		if read > 0 {
			if _, werr := h.Write(buf[:read]); werr != nil {
				return werr
			}
			pos += int64(read)
			remaining -= int64(read)
		}
		if err != nil {
			if err == io.EOF && remaining == 0 {
				break
			}
			return err
		}
		if read == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// FingerprintKeys computes the keys-scope fingerprint of §4.5: sha256 over the
// sorted key paths separated by NUL. It consumes only structural reads and is
// therefore compatible with max_bytes_inline: 0. Keys are sorted by byte order
// so the digest is independent of traversal order.
func FingerprintKeys(keys []string) Fingerprint {
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	h := sha256.New()
	for i, k := range sorted {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(k))
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return Fingerprint{Algo: "sha256", Scope: "keys", Value: &sum}
}

// HitID derives a RESTORE hit identifier (§9.4):
//
//	"h_" + CrockfordBase32(sha256(cid \0 locator \0 valueFP)[:12])
//
// The spec asks for the first 96 bits, which is 12 bytes / 20 Base32 chars.
// When cid is nil, unitID is the documented fallback and the caller should
// record hit_id_fallback.
func HitID(cid *string, locator, valueFP, unitID string) string {
	key := ""
	if cid != nil {
		key = *cid
	} else {
		key = unitID
	}
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write([]byte(locator))
	h.Write([]byte{0})
	h.Write([]byte(valueFP))
	return "h_" + crockfordEncode(h.Sum(nil)[:12])
}

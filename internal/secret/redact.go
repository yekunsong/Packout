package secret

import "sort"

// Redactor maps a plaintext value to its masked replacement. Implementations
// must not retain the input slice.
type Redactor func(value []byte) []byte

// Mask is the default redactor (D-025 §1): values longer than 8 bytes keep
// their first and last 4 bytes for human confirmation, and shorter values are
// fully masked so a short secret never survives in part. Visible characters are
// independent of Hit.ValueFP.
func Mask(value []byte) []byte {
	if len(value) <= 8 {
		out := make([]byte, len(value))
		for i := range out {
			out[i] = '*'
		}
		return out
	}
	out := make([]byte, 0, 11)
	out = append(out, value[:4]...)
	out = append(out, "…"...)
	out = append(out, value[len(value)-4:]...)
	return out
}

// Redact returns a copy of b with every actionable hit replaced by mask(v).
// Reference and None hits are left untouched: a ${VAR} pointer and an
// already-masked value are not plaintext. Hits that are out of range or empty
// are ignored. The input b is never modified.
//
// Masking operates on the union of all hit ranges, not hit by hit. When a wide
// keyed hit contains a narrower prefix hit, the whole wide range is masked, so
// no fragment of the value survives around the inner token (D-025 §7). Redact
// does not depend on hit order.
func Redact(b []byte, hits []Hit, mask Redactor) []byte {
	if mask == nil {
		mask = Mask
	}

	spans := make([]span, 0, len(hits))
	for _, h := range hits {
		if h.Class == None || h.Class == Reference {
			continue
		}
		if h.Offset < 0 || h.Length <= 0 || h.Offset+h.Length > len(b) {
			continue
		}
		spans = append(spans, span{h.Offset, h.End()})
	}
	if len(spans) == 0 {
		return append([]byte(nil), b...)
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})

	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		merged = append(merged, s)
	}

	out := make([]byte, 0, len(b))
	cursor := 0
	for _, s := range merged {
		out = append(out, b[cursor:s.start]...)
		out = append(out, mask(b[s.start:s.end])...)
		cursor = s.end
	}
	out = append(out, b[cursor:]...)
	return out
}

type span struct {
	start, end int
}

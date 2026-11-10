package profile

import (
	"errors"
	"fmt"
	"strings"
)

// Position is a location inside a profile file. Line is 1-based. Column is a
// 1-based BYTE column, not a rune or UTF-16 column: a CJK character counts as
// three columns. This matches hujson's own diagnostics (spike-jsonc §3.3).
type Position struct {
	Line   int
	Column int
	Offset int // 0-based byte offset
}

// String renders the position as "line:column".
func (p Position) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Column) }

// Error is one profile diagnostic. Code is the stable E-PRF-*/W-PRF-* code
// from spec-profile §9. Subject names the offending node, e.g.
// "entries[3](codex-thread-history)".
type Error struct {
	Code    string
	File    string
	Pos     Position
	Subject string
	Message string
}

// Error implements error.
func (e *Error) Error() string {
	var b strings.Builder
	if e.File != "" {
		b.WriteString(e.File)
		b.WriteByte(':')
	}
	if e.Pos.Line > 0 {
		fmt.Fprintf(&b, "%d:%d: ", e.Pos.Line, e.Pos.Column)
	}
	b.WriteString(e.Code)
	if e.Subject != "" {
		b.WriteString(" ")
		b.WriteString(e.Subject)
	}
	b.WriteString(": ")
	b.WriteString(e.Message)
	return b.String()
}

// Errors is the complete set of diagnostics produced by one load or validate.
// Loading reports every error it can attribute instead of stopping at the
// first one (spec-profile §9).
type Errors []*Error

// Error implements error.
func (e Errors) Error() string {
	if len(e) == 0 {
		return "profile: no errors"
	}
	lines := make([]string, len(e))
	for i, err := range e {
		lines[i] = err.Error()
	}
	return strings.Join(lines, "\n")
}

// Has reports whether code is present in the set.
func (e Errors) Has(code string) bool {
	for _, err := range e {
		if err.Code == code {
			return true
		}
	}
	return false
}

// Codes returns the distinct codes in first-seen order.
func (e Errors) Codes() []string {
	seen := make(map[string]bool, len(e))
	var out []string
	for _, err := range e {
		if !seen[err.Code] {
			seen[err.Code] = true
			out = append(out, err.Code)
		}
	}
	return out
}

// Unwrap exposes the individual diagnostics to errors.Is/As.
func (e Errors) Unwrap() []error {
	out := make([]error, len(e))
	for i, err := range e {
		out[i] = err
	}
	return out
}

// Warning is a non-fatal diagnostic (W-PRF-*). Warnings are recorded on the
// Profile; Validate does not fail because of them.
type Warning struct {
	Code    string
	File    string
	Pos     Position
	Subject string
	Message string
}

// Error implements error.
func (w *Warning) Error() string {
	var b strings.Builder
	if w.File != "" {
		b.WriteString(w.File)
		b.WriteByte(':')
	}
	if w.Pos.Line > 0 {
		fmt.Fprintf(&b, "%d:%d: ", w.Pos.Line, w.Pos.Column)
	}
	b.WriteString(w.Code)
	if w.Subject != "" {
		b.WriteString(" ")
		b.WriteString(w.Subject)
	}
	b.WriteString(": ")
	b.WriteString(w.Message)
	return b.String()
}

// Warnings is a list of non-fatal diagnostics.
type Warnings []*Warning

// Error implements error.
func (w Warnings) Error() string {
	if len(w) == 0 {
		return "profile: no warnings"
	}
	lines := make([]string, len(w))
	for i, warn := range w {
		lines[i] = warn.Error()
	}
	return strings.Join(lines, "\n")
}

// ErrUnresolved is the sentinel wrapped by UnresolvedError, so callers can do
// errors.Is(err, ErrUnresolved) without naming the type.
var ErrUnresolved = errors.New("模板变量未定义")

// UnresolvedError reports a template variable that has no value and no
// default. Callers decide whether that is fatal (a root must resolve) or a
// per-item status such as root_unresolved.
type UnresolvedError struct {
	Var string
}

// Error implements error.
func (e *UnresolvedError) Error() string {
	return fmt.Sprintf("变量 %%%s%%/$%s 未定义且无默认值", e.Var, e.Var)
}

// Is makes errors.Is(err, ErrUnresolved) work.
func (e *UnresolvedError) Is(target error) bool { return target == ErrUnresolved }

// DepthError reports runaway recursive expansion (e.g. A=${B}, B=${A}).
type DepthError struct {
	Limit int
}

// Error implements error.
func (e *DepthError) Error() string {
	return fmt.Sprintf("变量展开超过最大深度 %d", e.Limit)
}

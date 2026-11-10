// Package profiles embeds the built-in profile definitions and the external
// selftest fixtures they reference. Profile JSONC files and fixture bytes are
// embedded together so that Builtin(name) can materialize a selftest without a
// source checkout (spec-profile §8).
package profiles

import "embed"

// FS holds the built-in profiles at the root (*.jsonc) and their fixtures
// under fixtures/<name>/…. The layout matches the on-disk profiles directory,
// so selftest.fixtures values (relative to the profile file) resolve unchanged.
//
//go:embed *.jsonc
//go:embed all:fixtures
var FS embed.FS

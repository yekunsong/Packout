package pack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
	"packout/internal/secret"
)

// maxExtractFile is the largest file a config extractor will read. Larger
// entries stay reference-only in the manifest (the scan's own inline budget
// normally trims them first).
const maxExtractFile = 8 << 20

// maxExtractSessionFile is the per-file ceiling for entries flagged sessions
// when the manifest says the scan ran with --with-sessions. Session
// transcripts and tool results are routinely far larger than config files.
const maxExtractSessionFile = 1 << 30

// extractConfig materialises config/ from the manifest's units.
//
// Only de-secreted extracts are written: raw-ref copies bytes unchanged,
// template redacts detected credentials (and the entry's explicit rules), and
// keys-only keeps structure without values. digest and none produce no file.
// Destinations are always relative: config/<root>/<path-within-root>, so no
// user name or home prefix is baked into the package.
func extractConfig(m *manifest.Manifest, prof *profile.Profile, roots map[string]string, dest string, limits Limits, secrets *secretCollector, jobs int) (int, []string, error) {
	jobs = normalizeJobs(jobs)
	withSessions := m.Header.Inputs.Options != nil && m.Header.Inputs.Options.WithSessions
	byID := make(map[string]*profile.Entry, len(prof.Entries))
	for _, e := range prof.Entries {
		byID[e.ID] = e
	}
	rootPaths := make(map[string]string, len(roots))
	for name, p := range roots {
		a, err := fsx.Abs(p)
		if err != nil {
			return 0, nil, err
		}
		fi, err := fsx.Lstat(a)
		if err != nil || !fi.IsDir {
			return 0, nil, fmt.Errorf("pack: root %q is not a directory: %v", name, err)
		}
		rootPaths[name] = a
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, nil, err
	}

	// Preparation stays sequential so duplicate destinations resolve by
	// manifest order; only the read/render/write half runs in parallel.
	var warnings []string
	var tasks []extractTask
	written := make(map[string]bool)
	planned := int64(0)
	for i := range m.Units {
		u := &m.Units[i]
		if u.Kind != manifest.KindFile {
			continue
		}
		entry := byID[u.Entry]
		if entry == nil {
			continue
		}
		extractor, redact := extractorFor(entry, u.PartID)
		// A --with-sessions scan promises the session bytes; digest entries
		// are exported as raw-ref regardless of their declared extractor.
		sessions := withSessions && entry.Sessions
		if sessions {
			extractor = profile.ExtractorRawRef
		}
		switch extractor {
		case profile.ExtractorNone, profile.ExtractorDigest, "":
			continue
		}
		rootName := u.Root
		root, ok := rootPaths[rootName]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("config: unit %s has unknown root %q", u.ID, rootName))
			continue
		}
		src, rel, err := resolveUnitSource(root, u.Path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("config: unit %s: %v", u.ID, err))
			continue
		}
		if err := ValidateRelPath(rootName); err != nil {
			warnings = append(warnings, fmt.Sprintf("config: root name %q: %v", rootName, err))
			continue
		}
		if err := ValidateRelPath(rel); err != nil {
			warnings = append(warnings, fmt.Sprintf("config: unit %s: %v", u.ID, err))
			continue
		}
		info, err := fsx.Lstat(src)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("config: unit %s: %v", u.ID, err))
			continue
		}
		if !info.Mode.IsRegular() {
			warnings = append(warnings, fmt.Sprintf("config: unit %s is not a regular file (symlinks are not extracted)", u.ID))
			continue
		}
		fileLimit := int64(maxExtractFile)
		if sessions {
			fileLimit = maxExtractSessionFile
		}
		if info.Size > fileLimit {
			warnings = append(warnings, fmt.Sprintf("config: unit %s exceeds %d bytes (skipped)", u.ID, fileLimit))
			continue
		}
		outRel := rootName + "/" + rel
		if err := ValidateRelPath(outRel); err != nil {
			warnings = append(warnings, fmt.Sprintf("config: unit %s: %v", u.ID, err))
			continue
		}
		if written[outRel] {
			warnings = append(warnings, fmt.Sprintf("config: duplicate destination %q (unit %s skipped)", outRel, u.ID))
			continue
		}
		target, err := safeJoin(dest, outRel)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("config: unit %s: %v", u.ID, err))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, warnings, err
		}
		written[outRel] = true
		if info.Size > maxExtractFile {
			// Large session files are streamed byte-for-byte: placeholder
			// substitution would mean parsing or buffering them whole.
			warnings = append(warnings, fmt.Sprintf(
				"config: unit %s is a session file over %d bytes; copied raw without secret placeholders", u.ID, maxExtractFile))
		}
		tasks = append(tasks, extractTask{
			u: u, entry: entry, extractor: extractor, redact: redact,
			src: src, target: target, outRel: outRel, size: info.Size,
		})
		planned += info.Size
	}
	if planned > limits.MaxTotalBytes {
		return 0, warnings, fmt.Errorf("%w: extracted config exceeds %d bytes", ErrLimitExceeded, limits.MaxTotalBytes)
	}

	count, total, errAt := runExtracts(tasks, secrets, prof, jobs)
	for _, err := range errAt {
		if err != nil {
			return count, warnings, err
		}
	}
	if total > limits.MaxTotalBytes {
		return count, warnings, fmt.Errorf("%w: extracted config exceeds %d bytes", ErrLimitExceeded, limits.MaxTotalBytes)
	}
	sort.Strings(warnings)
	return count, warnings, nil
}

type extractTask struct {
	u         *manifest.Unit
	entry     *profile.Entry
	extractor string
	redact    *profile.Redact
	src       string
	target    string
	outRel    string
	size      int64
}

// runExtracts performs the tasks, serial for small sets and otherwise with up
// to jobs workers. Failures are collected by task index and reported in that
// order; a worker stops early after the first hard failure.
func runExtracts(tasks []extractTask, secrets *secretCollector, prof *profile.Profile, jobs int) (int, int64, []error) {
	errAt := make([]error, len(tasks))
	var count, total int64
	var mu sync.Mutex
	runOne := func(i int) error {
		t := &tasks[i]
		if t.size > maxExtractFile {
			if err := copyFile(t.src, t.target, 0o644); err != nil {
				return err
			}
			mu.Lock()
			count++
			total += t.size
			mu.Unlock()
			return nil
		}
		data, err := os.ReadFile(t.src)
		if err != nil {
			return fmt.Errorf("config: unit %s: %v", t.u.ID, err)
		}
		var out []byte
		switch t.extractor {
		case profile.ExtractorRawRef:
			out = data
			if secrets != nil {
				out = renderWithSecrets(data, t.u, t.entry, t.u.PartID, secrets, t.outRel, prof)
			}
		case profile.ExtractorTemplate:
			if secrets != nil {
				out = renderWithSecrets(data, t.u, t.entry, t.u.PartID, secrets, t.outRel, prof)
			} else {
				out = renderTemplate(data, t.redact)
			}
		case profile.ExtractorKeysOnly:
			out, err = renderKeysOnly(data)
			if err != nil {
				return fmt.Errorf("config: unit %s: not JSON: %v", t.u.ID, err)
			}
		default:
			return nil
		}
		if err := os.WriteFile(t.target, out, 0o644); err != nil {
			return err
		}
		mu.Lock()
		count++
		total += int64(len(out))
		mu.Unlock()
		return nil
	}
	if jobs <= 1 || len(tasks) < parallelThreshold {
		for i := range tasks {
			if err := runOne(i); err != nil {
				errAt[i] = err
			}
		}
	} else {
		if jobs > len(tasks) {
			jobs = len(tasks)
		}
		var next atomic.Int64
		var failed atomic.Bool
		var wg sync.WaitGroup
		for w := 0; w < jobs; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !failed.Load() {
					i := int(next.Add(1)) - 1
					if i >= len(tasks) {
						return
					}
					if err := runOne(i); err != nil {
						errAt[i] = err
						failed.Store(true)
						return
					}
				}
			}()
		}
		wg.Wait()
	}
	return int(count), total, errAt
}

func extractorFor(e *profile.Entry, partID string) (string, *profile.Redact) {
	if partID != "" {
		for _, p := range e.Parts {
			if p.ID == partID {
				ex := p.Extractor
				if ex == "" {
					ex = e.Extractor
				}
				r := p.Redact
				if r == nil {
					r = e.Redact
				}
				return ex, r
			}
		}
	}
	return e.Extractor, e.Redact
}

// resolveUnitSource maps a unit path to a file inside root. Manifest paths keep
// the on-disk spelling, so absolute paths are accepted only when they land in
// the unit's root; relative paths are joined beneath it.
func resolveUnitSource(root, unitPath string) (src, rel string, err error) {
	if unitPath == "" {
		return "", "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(unitPath) {
		if !fsx.Within(root, unitPath) {
			return "", "", fmt.Errorf("%q is outside root %q", unitPath, root)
		}
		r, err := fsx.Rel(root, unitPath)
		if err != nil {
			return "", "", err
		}
		return filepath.Clean(unitPath), filepath.ToSlash(r), nil
	}
	p := filepath.FromSlash(strings.ReplaceAll(unitPath, `\`, "/"))
	p = filepath.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%q does not stay inside the root", unitPath)
	}
	full := filepath.Join(root, p)
	if !fsx.Within(root, full) {
		return "", "", fmt.Errorf("%q escapes root %q", unitPath, root)
	}
	return full, filepath.ToSlash(p), nil
}

// renderTemplate produces a compact JSON rendering with explicit and detected
// secrets removed. Non-JSON input still gets credential detection.
func renderTemplate(data []byte, r *profile.Redact) []byte {
	repl := "«REDACTED»"
	if r != nil && r.Replacement != "" {
		repl = r.Replacement
	}
	mask := func([]byte) []byte { return []byte(repl) }

	if r != nil && (len(r.JSONPointer) > 0 || len(r.KeyPattern) > 0) {
		if compact, ok := redactJSON(data, r, repl); ok {
			data = compact
		}
	}
	hits := secret.DetectWithResult(secret.Options{}, "config", data).Hits
	return secret.Redact(data, hits, mask)
}

func redactJSON(data []byte, r *profile.Redact, repl string) ([]byte, bool) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	keep := keepPlaceholder(repl)
	for _, ptr := range r.JSONPointer {
		segs := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
		applyPointer(v, segs, keep)
	}
	patterns := make([]*regexp.Regexp, 0, len(r.KeyPattern))
	for _, p := range r.KeyPattern {
		if re, err := regexp.Compile(p); err == nil {
			patterns = append(patterns, re)
		}
	}
	if len(patterns) > 0 {
		v = applyKeyPatterns(v, patterns, keep)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return out, true
}

// keepPlaceholder returns a replacement function that preserves an already
// inserted secret_ref placeholder instead of redacting it a second time.
func keepPlaceholder(repl string) func(any) any {
	return func(v any) any {
		if s, ok := v.(string); ok && strings.HasPrefix(s, secretPlaceholderPrefix) {
			return s
		}
		return repl
	}
}

func applyPointer(v any, segs []string, repl func(any) any) {
	if len(segs) == 0 {
		return
	}
	switch node := v.(type) {
	case map[string]any:
		seg := segs[0]
		if seg == "*" {
			for k, child := range node {
				if len(segs) == 1 {
					node[k] = repl(child)
				} else {
					applyPointer(child, segs[1:], repl)
				}
			}
			return
		}
		child, ok := node[seg]
		if !ok {
			return
		}
		if len(segs) == 1 {
			node[seg] = repl(child)
			return
		}
		applyPointer(child, segs[1:], repl)
	case []any:
		if len(segs) == 1 && segs[0] == "*" {
			for i := range node {
				node[i] = repl(node[i])
			}
		}
	}
}

func applyKeyPatterns(v any, patterns []*regexp.Regexp, repl func(any) any) any {
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			matched := false
			for _, re := range patterns {
				if re.MatchString(k) {
					matched = true
					break
				}
			}
			if matched {
				node[k] = repl(child)
				continue
			}
			node[k] = applyKeyPatterns(child, patterns, repl)
		}
		return node
	case []any:
		for i := range node {
			node[i] = applyKeyPatterns(node[i], patterns, repl)
		}
		return node
	default:
		return v
	}
}

// renderKeysOnly keeps objects and key names but drops every scalar value.
func renderKeysOnly(data []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	out, err := json.Marshal(keysOnly(v))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func keysOnly(v any) any {
	switch node := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(node))
		for k, child := range node {
			out[k] = keysOnly(child)
		}
		return out
	case []any:
		return []any{}
	default:
		return nil
	}
}

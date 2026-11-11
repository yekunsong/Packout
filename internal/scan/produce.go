package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"packout/internal/classify"
	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/profile"
	"packout/internal/secret"
)

const (
	maxAnalysisBytes = 8 << 20 // hard in-memory analysis cap
	longPathMark     = 240
	maxPathBytes     = 32000
	headTailLimit    = 32 << 20
)

func (s *scanner) newUnit(e *profile.Entry, root *rootInstance, path, kind, partID string) manifest.Unit {
	rootName := "external"
	if root != nil {
		rootName = root.name
	}
	key := pathKey(path)
	u := manifest.Unit{
		Type:          manifest.TypeUnit,
		SchemaVersion: manifest.Version,
		Path:          path,
		PathKey:       key,
		Root:          rootName,
		PathSemantics: manifest.SemanticsLiteral,
		Profile:       s.cfg.Profile.Name,
		Entry:         e.ID,
		PartID:        partID,
		Kind:          kind,
		Layer:         e.Layer,
		Confidence:    1.0,
		Secret:        &manifest.Secret{Class: e.Secret},
		OpenAs:        manifest.OpenAsNone,
	}
	if u.Layer == "" {
		u.Layer = manifest.LayerL2
	}
	if u.Secret.Class == "" {
		u.Secret.Class = manifest.SecretNone
	}
	u.ID = manifest.UnitID(u.Root, u.Profile, u.Entry, partID, key)
	u.DerivedFrom = derivedFrom(e.PathSemantics, e.DerivedFrom)
	if u.DerivedFrom != nil {
		u.PathSemantics = manifest.SemanticsMachineDerived
	}
	u.Signals = s.entrySignals(e)
	u.NeededBy = append([]string(nil), e.NeededBy...)
	if e.OpaqueContent {
		u.OpaqueContent = true
		u.RiskFlags = appendFlag(u.RiskFlags, "opaque_content")
	}
	if u.PathSemantics == manifest.SemanticsMachineDerived {
		u.RiskFlags = appendFlag(u.RiskFlags, "machine_derived_path")
	}
	if len(path) > longPathMark {
		u.RiskFlags = appendFlag(u.RiskFlags, "long_path")
	}
	if e.OpenAs == profile.OpenAsSQLiteRO {
		u.OpenAs = manifest.OpenAsSQLiteRO
	} else if e.OpenAs == profile.OpenAsText {
		u.OpenAs = manifest.OpenAsText
	}
	return u
}

func derivedFrom(semantics, derived string) *string {
	if semantics != profile.PathMachineDerived && derived == "" {
		return nil
	}
	if derived == "" {
		return nil
	}
	d := derived
	return &d
}

func (s *scanner) entrySignals(e *profile.Entry) []manifest.Signal {
	base, ok := s.signals[e]
	if !ok {
		base = []manifest.Signal{{
			Src:  "profile_rule",
			Note: "entry " + e.ID + " in profile " + s.cfg.Profile.Name + " " + s.profVer,
		}}
		base = append(base, convertSignals(e.Signals)...)
		s.signals[e] = base
	}
	out := make([]manifest.Signal, len(base))
	copy(out, base)
	return out
}

func convertSignals(in []profile.Signal) []manifest.Signal {
	out := make([]manifest.Signal, 0, len(in))
	for _, sig := range in {
		src := sig.Src
		switch src {
		case "official_docs":
		case "file_format":
		case "observed_behavior", "repository_practice":
			src = "filesystem_stat"
		default:
			src = "profile_rule"
		}
		var url *string
		if sig.URL != "" {
			u := sig.URL
			url = &u
		}
		out = append(out, manifest.Signal{Src: src, Note: sig.Note, URL: url})
	}
	return out
}

func (s *scanner) finishUnit(u *manifest.Unit, e *profile.Entry, info *fsx.Info) {
	u.ProposedAction = classify.ActionFor(u.Layer, u.Secret.Class)
	if info != nil {
		size := info.Size
		alloc := info.Alloc
		u.SizeApparent = &size
		u.SizeAlloc = &alloc
		mt := info.ModTime
		u.MTime = &mt
		u.FileID = fileID(info)
		if info.IsSparse {
			u.RiskFlags = appendFlag(u.RiskFlags, "sparse")
		}
		if info.IsReparse {
			if info.IsLink {
				u.RiskFlags = appendFlag(u.RiskFlags, "symlink")
			} else {
				u.RiskFlags = appendFlag(u.RiskFlags, "junction")
				u.RiskFlags = appendFlag(u.RiskFlags, "symlink")
			}
			u.LinkTarget = info.LinkTarget
			if s.outsideRoot(u.Path, info.LinkTarget) {
				u.RiskFlags = appendFlag(u.RiskFlags, "outside_root")
			}
		}
	}
}

func fileID(info *fsx.Info) *manifest.FileID {
	if info == nil || info.FileID == "" {
		return nil
	}
	vol, idx := "", info.FileID
	if i := strings.LastIndexByte(info.FileID, ':'); i >= 0 {
		vol, idx = info.FileID[:i], info.FileID[i+1:]
	}
	f := &manifest.FileID{VolumeSerial: vol, Index: idx}
	if info.IsLink {
		f.ReparseTag = []byte(`"symlink"`)
	} else if info.IsReparse {
		// JSON numbers have no 0x form, so the tag must be decimal; a raw
		// "0xA0000003" makes the whole record invalid JSON (E-MAN-002, D-034).
		tag := info.ReparseTag
		if tag == 0 {
			tag = 0xA0000003 // IO_REPARSE_TAG_MOUNT_POINT, if the query failed
		}
		f.ReparseTag = strconv.AppendUint(nil, uint64(tag), 10)
	}
	return f
}

func (s *scanner) outsideRoot(p, target string) bool {
	if target == "" {
		return false
	}
	t := target
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(p), t)
	}
	if a, err := fsx.Abs(t); err == nil {
		t = a
	}
	return s.rootContaining(t) == nil
}

// produceFile emits the Unit for one winning candidate.
func (s *scanner) produceFile(ctx context.Context, c candidate, pf *prefetchResult) {
	e, info := c.entry, c.info
	if len(c.path) > maxPathBytes {
		s.addNote(manifest.Note{Code: "path_too_long", Entry: e.ID, Detail: c.path})
		return
	}
	kind := manifest.KindFile
	if info.IsDir {
		kind = manifest.KindDir
	}
	u := s.newUnit(e, c.root, c.path, kind, "")
	if c.cycle {
		u.RiskFlags = appendFlag(u.RiskFlags, "symlink_cycle")
	}
	if c.root == nil {
		u.RiskFlags = appendFlag(u.RiskFlags, "outside_root")
	}

	if info.IsDir || info.IsReparse {
		s.finishUnit(&u, e, info)
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: "shape"}
		u.CID = manifest.CID(u.Fingerprint)
		s.addCoveredCompanions(e, c.path)
		s.units = append(s.units, u)
		return
	}

	s.finishUnit(&u, e, info)
	s.applyVCS(&u, e, c)
	s.addCoveredCompanions(e, c.path)

	if e.OpenAs == profile.OpenAsSQLiteRO {
		s.maybeShm(&u, e, c.path)
	}

	if info.IsOffline {
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: ""}
		u.CID = nil
		u.RiskFlags = appendFlag(u.RiskFlags, "cloud_placeholder")
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		s.addNote(manifest.Note{Code: "budget_exceeded", Entry: e.ID, Detail: "占位符未水合，未读取内容"})
		s.units = append(s.units, u)
		return
	}

	total := s.cfg.Profile.EffectiveMaxBytesTotal(e)
	if total > 0 && s.total[e.ID] >= total {
		if s.perFileSessions(e) {
			// Sessions mode: the budget only caps how many rows we emit, so
			// the exhausted file gets no row of its own (it stays covered).
			if !s.budgetNoted[e.ID] {
				s.budgetNoted[e.ID] = true
				s.addNote(manifest.Note{Code: "budget_exceeded", Entry: e.ID,
					Detail: "条目 max_bytes_total 已耗尽，后续会话文件不再逐条出行"})
			}
			return
		}
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: ""}
		u.RiskFlags = appendFlag(u.RiskFlags, "aggregated")
		u.RiskFlags = appendFlag(u.RiskFlags, "oversized")
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		zero := int64(0)
		u.AggregateCount = &zero
		cs, may := false, e.Secret == profile.SecretScan || e.Secret == profile.SecretRestore
		u.ContainsSecret = &cs
		u.MayContainSecret = &may
		s.addNote(manifest.Note{Code: "budget_exceeded", Entry: e.ID, Detail: "条目 max_bytes_total 已耗尽"})
		s.units = append(s.units, u)
		return
	}

	files := []companionFile{{suffix: "", path: c.path, info: info}}
	for _, suffix := range e.Companions {
		cp := c.path + suffix
		ci, err := fsx.Lstat(cp)
		if err != nil {
			s.addNote(manifest.Note{Code: "companion_missing", Entry: e.ID, Detail: suffix})
			continue
		}
		files = append(files, companionFile{suffix: suffix, path: cp, info: ci})
		u.Companions = append(u.Companions, suffix)
		s.covered[pathKey(cp)] = true
		s.total[e.ID] += ci.Size
	}
	u.SizeApparent = nil
	u.SizeAlloc = nil
	var sumApp, sumAlloc int64
	var maxMTime time.Time
	for _, f := range files {
		sumApp += f.info.Size
		sumAlloc += f.info.Alloc
		if f.info.ModTime.After(maxMTime) {
			maxMTime = f.info.ModTime
		}
	}
	u.SizeApparent = &sumApp
	u.SizeAlloc = &sumAlloc
	if sumAlloc*2 < sumApp {
		u.RiskFlags = appendFlag(u.RiskFlags, "sparse")
	}
	if !maxMTime.IsZero() {
		u.MTime = &maxMTime
	}

	// Analysis read: inline for secret/parts, structure for keys. Both are
	// capped; the fingerprint hashes the whole member independently.
	inline, structure, need, scope := s.readPlan(e, info)
	var data []byte
	var readErr error
	if pf != nil {
		// The parallel prefetch already did this read and counted the bytes.
		data, readErr = pf.data, pf.readErr
		if readErr == nil {
			s.total[e.ID] += int64(len(data))
		}
	} else if need > 0 {
		limit := need
		if info.Size < limit {
			limit = info.Size
		}
		if limit > 0 {
			data, readErr = readPrefix(c.path, limit)
			s.total[e.ID] += int64(len(data))
		}
	}
	if readErr != nil {
		s.readFailure(&u, e, readErr)
		s.units = append(s.units, u)
		return
	}
	if inline > 0 && info.Size > inline {
		u.RiskFlags = appendFlag(u.RiskFlags, "oversized")
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
	}
	if looksBinary(data) {
		u.OpaqueContent = true
		u.RiskFlags = appendFlag(u.RiskFlags, "opaque_content")
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		s.addNote(manifest.Note{Code: "binary_presence_only", Entry: e.ID, Detail: c.path})
	}

	// Fingerprint first; a read error here is a handled read_error.
	var fp manifest.Fingerprint
	var err error
	if pf != nil {
		fp, err = pf.fp, pf.fpErr
	} else if len(files) > 1 {
		fp, err = combinedFingerprint(files, scope)
	} else {
		fp, err = fingerprintFile(c.path, info.Size, scope)
	}
	if err != nil {
		s.readFailure(&u, e, err)
		s.units = append(s.units, u)
		return
	}
	u.Fingerprint = &fp
	u.CID = manifest.CID(u.Fingerprint)
	s.total[e.ID] += info.Size

	if len(e.Parts) > 0 {
		if s.produceParts(&u, e, data, structure) {
			return
		}
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		s.units = append(s.units, u)
		return
	}

	// opaque_content with max_bytes_inline 0 reads no bytes at all: say so
	// accurately instead of calling every such file binary (text transcripts
	// are flagged opaque too). Real NUL detection already noted above.
	if u.OpaqueContent && e.Secret == profile.SecretScan && len(data) == 0 {
		s.addNote(manifest.Note{Code: "content_not_read", Entry: e.ID, Detail: c.path})
	}
	if s.shouldScanSecret(e, u.OpaqueContent) {
		s.scanSecret(&u, e, c.path, data, inline)
	}
	s.applyKeysFingerprint(&u, e, data, structure)
	s.units = append(s.units, u)
}

// prefetchBatchKeys and prefetchBatchBytes bound how much read data one
// batch may hold in memory before produceKeys drains it.
const (
	prefetchBatchKeys  = 2048
	prefetchBatchBytes = 64 << 20
)

// prefetchThreshold below which the pool is skipped (task card: < 32 items).
const prefetchThreshold = 32

type candRef struct {
	key string
	idx int
}

type prefetchTask struct {
	ref  candRef
	e    *profile.Entry
	path string
	info *fsx.Info
}

type prefetchResult struct {
	data    []byte
	readErr error
	fp      manifest.Fingerprint
	fpErr   error
}

// readPlan mirrors the read decisions of produceFile so the prefetch pass can
// run ahead without changing what produceFile would do.
func (s *scanner) readPlan(e *profile.Entry, info *fsx.Info) (inline, structure, need int64, scope string) {
	inline = s.cfg.Profile.EffectiveMaxBytesInline(e, nil)
	if len(e.Parts) > 0 || e.Extractor == profile.ExtractorKeysOnly || e.Churn == "high" {
		structure = s.cfg.Profile.EffectiveMaxBytesStructure(e, nil)
	}
	need = inline
	if structure > need {
		need = structure
	}
	scope = "full"
	if info.Size > headTailLimit && info.Size > inline {
		scope = "head-tail"
	}
	return inline, structure, need, scope
}

// prefetchTasks runs the read+hash half of produceFile for a batch, bounded
// by s.jobs. Results are keyed so produceKeys can consume them in input order.
func (s *scanner) prefetchTasks(ctx context.Context, tasks []prefetchTask) map[candRef]*prefetchResult {
	res := make(map[candRef]*prefetchResult, len(tasks))
	if len(tasks) == 0 {
		return res
	}
	if s.jobs <= 1 || len(tasks) < prefetchThreshold {
		for i := range tasks {
			res[tasks[i].ref] = s.runPrefetch(tasks[i])
		}
		return res
	}
	ch := make(chan prefetchTask)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < s.jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				r := s.runPrefetch(t)
				mu.Lock()
				res[t.ref] = r
				mu.Unlock()
			}
		}()
	}
	for _, t := range tasks {
		select {
		case ch <- t:
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return res
		}
	}
	close(ch)
	wg.Wait()
	return res
}

// runPrefetch performs exactly the analysis read and fingerprint produceFile
// would perform, including companion discovery.
func (s *scanner) runPrefetch(t prefetchTask) *prefetchResult {
	r := &prefetchResult{}
	files := []companionFile{{suffix: "", path: t.path, info: t.info}}
	for _, suffix := range t.e.Companions {
		cp := t.path + suffix
		ci, err := fsx.Lstat(cp)
		if err != nil {
			continue
		}
		files = append(files, companionFile{suffix: suffix, path: cp, info: ci})
	}
	_, _, need, scope := s.readPlan(t.e, t.info)
	limit := need
	if t.info.Size < limit {
		limit = t.info.Size
	}
	if limit > 0 {
		r.data, r.readErr = readPrefix(t.path, limit)
	}
	if r.readErr != nil {
		return r
	}
	if len(files) > 1 {
		r.fp, r.fpErr = combinedFingerprint(files, scope)
	} else {
		r.fp, r.fpErr = fingerprintFile(t.path, t.info.Size, scope)
	}
	return r
}

type companionFile struct {
	suffix string
	path   string
	info   *fsx.Info
}

func (s *scanner) readFailure(u *manifest.Unit, e *profile.Entry, err error) {
	s.errs++
	u.RiskFlags = appendFlag(u.RiskFlags, "read_error")
	u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: ""}
	u.CID = nil
	s.addNote(manifest.Note{Code: "read_error", Entry: e.ID, Detail: err.Error()})
}

func (s *scanner) shouldScanSecret(e *profile.Entry, opaque bool) bool {
	if e.Secret == profile.SecretNone || e.Secret == "" || opaque {
		return false
	}
	return s.cfg.Profile.EffectiveMaxBytesInline(e, nil) > 0
}

func readPrefix(path string, limit int64) ([]byte, error) {
	f, err := fsx.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit > maxAnalysisBytes {
		limit = maxAnalysisBytes
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(f, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		err = nil
	}
	return buf[:n], err
}

func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	nul := 0
	for _, b := range data {
		if b == 0 {
			nul++
		}
	}
	return nul*100 > len(data)
}

// combinedFingerprint hashes the logical pair (suffix, size, mtime, digest)
// of every member (§4.12).
func combinedFingerprint(files []companionFile, scope string) (manifest.Fingerprint, error) {
	h := sha256.New()
	for _, f := range files {
		mfp, err := fingerprintFile(f.path, f.info.Size, scope)
		if err != nil {
			return manifest.Fingerprint{}, err
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00", f.suffix, f.info.Size, f.info.ModTime.UnixNano())
		if mfp.Value != nil {
			h.Write([]byte(*mfp.Value))
		}
		h.Write([]byte{0})
	}
	val := hashHex(h)
	return manifest.Fingerprint{Algo: "sha256", Scope: scope, Value: &val}, nil
}

func fingerprintFile(path string, size int64, scope string) (manifest.Fingerprint, error) {
	f, err := fsx.Open(path)
	if err != nil {
		return manifest.Fingerprint{}, err
	}
	defer f.Close()
	return fingerprintAt(f, size, scope)
}

// fpBufSize is the shared hash buffer size: one fixed 64 KiB block per worker.
const fpBufSize = 64 << 10

var fpBufPool = sync.Pool{New: func() any {
	b := make([]byte, fpBufSize)
	return &b
}}

// fingerprintAt is manifest.FingerprintFile with a pooled buffer instead of a
// fresh allocation per file. The byte stream (and therefore the digest) is
// identical: full hashes everything, head-tail hashes the first and last
// HeadTailWindow bytes, and both read in fpBufSize chunks.
func fingerprintAt(r io.ReaderAt, size int64, scope string) (manifest.Fingerprint, error) {
	fp := manifest.Fingerprint{Algo: "sha256", Scope: scope}
	if size < 0 {
		return fp, fmt.Errorf("manifest: negative size %d", size)
	}
	h := sha256.New()
	switch scope {
	case "", "null":
		fp.Scope = ""
		return fp, nil
	case "full":
		if err := hashRangeAt(h, r, 0, size); err != nil {
			return fp, err
		}
	case "head-tail":
		if size <= 2*manifest.HeadTailWindow {
			if err := hashRangeAt(h, r, 0, size); err != nil {
				return fp, err
			}
		} else {
			if err := hashRangeAt(h, r, 0, manifest.HeadTailWindow); err != nil {
				return fp, err
			}
			if err := hashRangeAt(h, r, size-manifest.HeadTailWindow, manifest.HeadTailWindow); err != nil {
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

func hashRangeAt(h io.Writer, r io.ReaderAt, off, n int64) error {
	bp := fpBufPool.Get().(*[]byte)
	buf := *bp
	defer fpBufPool.Put(bp)
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

func (s *scanner) scanSecret(u *manifest.Unit, e *profile.Entry, path string, data []byte, inline int64) {
	if inline < int64(len(data)) && inline > 0 {
		data = data[:inline]
	}
	opts := secret.Options{Entropy: s.cfg.Profile.EffectiveScan(e) != "strict", MaxHits: 32}
	res := secret.DetectWithResult(opts, filepath.Base(path), data)
	if len(res.Hits) == 0 {
		return
	}
	isJSON := strings.HasSuffix(strings.ToLower(path), ".json")
	var pointers map[int]string
	if isJSON {
		pointers = jsonPointerMap(data)
	}
	for _, h := range res.Hits {
		if h.Class == secret.None {
			continue
		}
		loc := lineColumn(data, h.Offset)
		if pointers != nil {
			if p, ok := pointers[h.Offset]; ok {
				loc = p
			}
		}
		if u.PartID != "" {
			loc = "#" + loc
		}
		val := data[h.Offset:h.End()]
		prefix := h.Prefix
		if prefix == "" {
			prefix = knownPrefix(val)
		}
		u.Secret.Hits = append(u.Secret.Hits, manifest.SecretHit{
			Kind:        secretKind(h.Rule),
			Class:       h.Class.String(),
			Locator:     loc,
			Prefix:      prefix,
			Fingerprint: "sha256:" + secret.ValueFPWithSalt(val, s.salt),
		})
	}
	u.Secret.HitCount += len(res.Hits) + res.Dropped
	u.Secret.Truncated = res.Truncated
	if u.Secret.Class == profile.SecretNone {
		u.Secret.Class = profile.SecretScan
	}
	src := "secret_prefix"
	if res.Truncated {
		src = "secret_entropy"
	}
	u.Signals = append(u.Signals, manifest.Signal{
		Src:  src,
		Note: fmt.Sprintf("内容检测命中 %d 处（条目声明 secret: %s）", len(res.Hits), e.Secret),
	})
}

func knownPrefix(val []byte) string {
	for _, p := range []string{"sk-ant-", "github_pat_", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA", "AIza", "op://", "sk-"} {
		if bytes.HasPrefix(val, []byte(p)) {
			if len(p) > 7 {
				return p[:7]
			}
			return p
		}
	}
	return ""
}

func secretKind(rule string) string {
	switch rule {
	case secret.RuleEnvRef, secret.RuleOnePassword:
		return "env_ref"
	case secret.RuleHighEntropy:
		return "entropy"
	case secret.RuleJSONKey, secret.RuleTOMLKey, secret.RuleDotenvKey:
		return "key_name"
	case secret.RuleAnthropicKey, secret.RuleOpenAIKey, secret.RuleGitHubPAT,
		secret.RuleGitHubToken, secret.RuleAWSAccessKey, secret.RuleSlackToken,
		secret.RuleGoogleAPIKey, secret.RulePrivateKey, secret.RuleAuthBearer, secret.RuleMCPEnv:
		return "known_prefix"
	}
	return "regex"
}

func lineColumn(data []byte, off int) string {
	line := 1 + bytes.Count(data[:off], []byte("\n"))
	col := 1 + off - (bytes.LastIndexByte(data[:off], '\n') + 1)
	return fmt.Sprintf("%d:%d", line, col)
}

// applyVCS adds gitignore / not_versioned evidence. It is deliberately
// lexical and never invokes git.
func (s *scanner) applyVCS(u *manifest.Unit, e *profile.Entry, c candidate) {
	if c.root == nil {
		return
	}
	rel := c.rel
	if rel == "" {
		rel = s.relOf(c.root, c.path)
	}
	if pat, ok := s.gitignored(c.root, rel); ok {
		u.RiskFlags = appendFlag(u.RiskFlags, "gitignored")
		u.Signals = append(u.Signals, manifest.Signal{
			Src:  "gitignore_hit",
			Note: "全局 gitignore 规则 " + pat + " 命中",
		})
	}
	if c.root.role == "repo" && !s.hasGit(c.root.path) {
		u.RiskFlags = appendFlag(u.RiskFlags, "not_versioned")
		u.Signals = append(u.Signals, manifest.Signal{
			Src:  "filesystem_stat",
			Note: "root " + c.root.name + " 内没有 .git，路径不在任何版本库内",
		})
	}
}

func (s *scanner) hasGit(root string) bool {
	if v, ok := s.gitSeen[root]; ok {
		return v
	}
	_, err := os.Lstat(filepath.Join(root, ".git"))
	v := err == nil
	s.gitSeen[root] = v
	return v
}

type gitRule struct {
	pattern string
	negate  bool
}

// gitignored checks the root's .gitignore and the per-user global ignore file.
// Parsed rule sets are cached per root.
func (s *scanner) gitignored(root *rootInstance, rel string) (string, bool) {
	rel = strings.Trim(rel, "/")
	rules, ok := s.ignore[root.path]
	if !ok {
		candidates := []string{filepath.Join(root.path, ".gitignore")}
		if home := s.homeDir(root); home != "" {
			candidates = append(candidates, filepath.Join(home, ".config", "git", "ignore"))
		}
		for _, file := range candidates {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				pat := strings.TrimSpace(line)
				if pat == "" || strings.HasPrefix(pat, "#") {
					continue
				}
				neg := strings.HasPrefix(pat, "!")
				if neg {
					pat = pat[1:]
				}
				rules = append(rules, gitRule{pattern: pat, negate: neg})
			}
		}
		s.ignore[root.path] = rules
	}
	for _, rule := range rules {
		if patternMatches(rule.pattern, rel) {
			return rule.pattern, !rule.negate
		}
	}
	return "", false
}

func (s *scanner) homeDir(root *rootInstance) string {
	if root.role == "home" {
		return root.path
	}
	for i := range s.roots {
		if s.roots[i].role == "home" {
			return s.roots[i].path
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

func patternMatches(pattern, rel string) bool {
	p := strings.Trim(pattern, "/")
	if p == "" {
		return false
	}
	if !strings.Contains(p, "/") {
		// basename pattern
		base := rel
		if i := strings.LastIndexByte(rel, '/'); i >= 0 {
			base = rel[i+1:]
		}
		if profile.MatchGlob(p, base) {
			return true
		}
	}
	return profile.MatchGlob(p, rel) || profile.MatchGlob("**/"+p, rel)
}

func (s *scanner) applyKeysFingerprint(u *manifest.Unit, e *profile.Entry, data []byte, structure int64) {
	keysOnly := e.Extractor == profile.ExtractorKeysOnly
	if !keysOnly {
		return
	}
	cacheKey := ""
	if e.Churn == "high" && u.FileID != nil {
		cacheKey = u.FileID.VolumeSerial + ":" + u.FileID.Index
		if fp, ok := s.churn[cacheKey]; ok {
			u.Fingerprint = &fp
			u.CID = manifest.CID(u.Fingerprint)
			return
		}
	}
	if structure > 0 && int64(len(data)) >= structure {
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		s.addNote(manifest.Note{Code: "budget_exceeded", Entry: e.ID, Detail: "max_bytes_structure 耗尽"})
	}
	keys := extractKeys(data, structure)
	if len(keys) == 0 {
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: ""}
		u.CID = nil
		u.RiskFlags = appendFlag(u.RiskFlags, "content_partial")
		return
	}
	fp := manifest.FingerprintKeys(keys)
	u.Fingerprint = &fp
	u.CID = manifest.CID(u.Fingerprint)
	if cacheKey != "" {
		s.churn[cacheKey] = fp
	}
}

// produceAggregate emits the single aggregated Unit for one base path.
func (s *scanner) produceAggregate(ctx context.Context, c candidate, base string) {
	var members []candidate
	for _, cands := range s.hits {
		for _, x := range cands {
			if x.path == base {
				continue
			}
			if x.entry == c.entry && x.root == c.root && profile.PathWithinDir(base, x.path) {
				members = append(members, x)
			}
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].path < members[j].path })
	baseInfo, _ := fsx.Lstat(base)
	kind := manifest.KindDir
	if baseInfo != nil && !baseInfo.IsDir {
		kind = manifest.KindFile
	}
	u := s.newUnit(c.entry, c.root, base, kind, "")
	u.RiskFlags = appendFlag(u.RiskFlags, "aggregated")
	u.Confidence = 0.9
	if u.Secret.Class == profile.SecretRestore || u.Secret.Class == profile.SecretRelogin {
		u.Confidence = 0.95
	}
	count := int64(len(members))
	u.AggregateCount = &count
	cs, ms := false, c.entry.Secret == profile.SecretScan || c.entry.Secret == profile.SecretRestore
	u.ContainsSecret = &cs
	u.MayContainSecret = &ms
	var app, alloc int64
	var mt time.Time
	for _, m := range members {
		if m.info == nil {
			continue
		}
		app += m.info.Size
		alloc += m.info.Alloc
		if m.info.ModTime.After(mt) {
			mt = m.info.ModTime
		}
	}
	u.SizeApparent = &app
	u.SizeAlloc = &alloc
	if !mt.IsZero() {
		u.MTime = &mt
	}
	u.FileID = nil
	if alloc*2 < app {
		u.RiskFlags = appendFlag(u.RiskFlags, "sparse")
	}
	if count > 0 {
		fp := aggregateFingerprint(members, s.salt)
		u.Fingerprint = &fp
		u.CID = manifest.CID(u.Fingerprint)
	} else {
		u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: "aggregate"}
		u.CID = nil
	}
	display := base
	if c.root != nil {
		display = s.relOf(c.root, base)
	}
	u.Signals = append(u.Signals, manifest.Signal{
		Src:  "filesystem_stat",
		Note: fmt.Sprintf("聚合：%s 下 %d 个命中（expand/aggregate_above）", display, count),
	})
	if info := baseInfo; info != nil {
		u.SizeEstimated = false
	}
	if u.Layer == manifest.LayerL0 {
		u.ProposedAction = manifest.ActionDelete
	} else {
		u.ProposedAction = classify.ActionFor(u.Layer, u.Secret.Class)
	}
	s.units = append(s.units, u)
}

func aggregateFingerprint(members []candidate, salt []byte) manifest.Fingerprint {
	h := sha256String()
	for _, m := range members {
		fmt.Fprintf(h, "%s\x00", pathKey(m.path))
		if m.info != nil {
			fmt.Fprintf(h, "%d\x00%d\x00", m.info.Size, m.info.ModTime.UnixNano())
		}
	}
	val := hashHex(h)
	return manifest.Fingerprint{Algo: "sha256", Scope: "aggregate", Value: &val}
}

func (s *scanner) addCoveredCompanions(e *profile.Entry, path string) {
	for _, suffix := range e.Companions {
		s.covered[pathKey(path+suffix)] = true
	}
}

func (s *scanner) maybeShm(u *manifest.Unit, e *profile.Entry, path string) {
	f, err := fsx.Open(path)
	if err != nil {
		return
	}
	head := make([]byte, 16)
	_, _ = io.ReadFull(f, head)
	f.Close()
	if !bytes.HasPrefix(head, []byte("SQLite format 3\x00")) {
		return
	}
	wal := path + "-wal"
	shm := path + "-shm"
	if _, err := os.Lstat(wal); err != nil {
		return
	}
	if _, err := os.Lstat(shm); err == nil {
		return
	}
	if !containsPath(e.SideEffects, "shm_created") {
		return
	}
	fh, err := os.OpenFile(shm, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return
	}
	fh.Close()
	u.SideEffects = append(u.SideEffects, "shm_created")
	u.OpenAs = manifest.OpenAsSQLiteRO
}

func (s *scanner) partMatchedFlag() {}

// declareNamedLocation emits 0/1 unit for a named-location entry. P0 records
// presence only and never reads the credential.
func (s *scanner) declareNamedLocation(e *profile.Entry, root *rootInstance) {
	loc, ok := e.Locator.ForOS(s.goos)
	if !ok || loc == "" {
		return
	}
	scheme := "env"
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		scheme = loc[:i]
	}
	opaque := loc
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		opaque = loc[i+1:]
	}
	opaque = strings.Join(strings.Fields(opaque), " ")
	path := scheme + ":" + opaque
	key := strings.ToLower(scheme) + ":" + pathKey(opaque)

	probe, _ := e.Probe.ForOS(s.goos)
	if probe == "" {
		switch scheme {
		case "keychain":
			probe = "keychain"
		case "wincred":
			probe = "wincred"
		case "registry":
			probe = "registry"
		case "env":
			probe = "env"
		case "file":
			probe = "file-probe"
		}
	}
	present := true
	if probe == "env" {
		_, present = os.LookupEnv(opaque)
	} else if probe == "keychain" || probe == "wincred" || probe == "registry" {
		present = false // P0 has no native probe for these stores
	} else if probe == "file-probe" {
		if p, err := absPath(opaque); err == nil {
			if _, err := os.Lstat(p); err == nil {
				s.covered[pathKey(p)] = true
			} else {
				present = false
			}
		}
	}

	u := manifest.Unit{
		Type:          manifest.TypeUnit,
		SchemaVersion: manifest.Version,
		Path:          path,
		PathKey:       key,
		Root:          "os",
		PathSemantics: manifest.SemanticsLiteral,
		Profile:       s.cfg.Profile.Name,
		Entry:         e.ID,
		Kind:          manifest.KindNamedLocation,
		Layer:         e.Layer,
		Confidence:    1.0,
		Secret:        &manifest.Secret{Class: e.Secret},
		OpenAs:        manifest.OpenAsNone,
		Signals:       s.entrySignals(e),
		NeededBy:      append([]string(nil), e.NeededBy...),
	}
	u.ID = manifest.UnitID(u.Root, u.Profile, u.Entry, "", key)
	if u.Secret.Class == "" {
		u.Secret.Class = manifest.SecretNone
	}
	u.Fingerprint = &manifest.Fingerprint{Algo: "sha256", Scope: "shape"}
	u.ProposedAction = classify.ActionFor(u.Layer, u.Secret.Class)
	if !present {
		u.RiskFlags = appendFlag(u.RiskFlags, "probe_unavailable")
		u.Signals = append(u.Signals, manifest.Signal{
			Src: "probe_result", Note: "探测不可用或目标不存在（P0 只记存在性）",
		})
		s.addNote(manifest.Note{Code: "probe_unavailable", Entry: e.ID, Detail: path})
	} else {
		u.Signals = append(u.Signals, manifest.Signal{
			Src: "probe_result", Note: "存在性探测成功；P0 不读取凭据内容",
		})
	}
	s.units = append(s.units, u)
}

var _ = json.Marshal
var _ = regexp.MustCompile
var _ = context.Background

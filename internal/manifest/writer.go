package manifest

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Clock supplies timestamps. Injecting a Clock makes golden output stable.
type Clock interface {
	Now() time.Time
}

// SaltSource supplies the scan salt when the header does not carry one.
// Injecting it makes golden output stable (§9.3).
type SaltSource interface {
	Salt() (string, error)
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// randomSalt produces the default 16-byte random scan salt, hex encoded.
type randomSalt struct{}

func (randomSalt) Salt() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Option configures a Writer.
type Option func(*writerConfig)

type writerConfig struct {
	clock Clock
	salt  SaltSource
}

// WithClock injects a deterministic clock (tests, golden output).
func WithClock(c Clock) Option {
	return func(cfg *writerConfig) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// WithSalt injects a deterministic salt source (tests, --stable-salt).
func WithSalt(s SaltSource) Option {
	return func(cfg *writerConfig) {
		if s != nil {
			cfg.salt = s
		}
	}
}

// FixedSalt is a SaltSource that always returns one value.
type FixedSalt string

// Salt implements SaltSource.
func (s FixedSalt) Salt() (string, error) { return string(s), nil }

// shardWriter is one open shard. Data is buffered, hashed on the way out, and
// the .tmp file is only renamed after a successful Flush+Sync (§2, §8).
type shardWriter struct {
	name  string
	file  *os.File
	bw    *bufio.Writer
	hash  hash.Hash
	bytes int64
	units int64
	notes int64
}

func (s *shardWriter) writeLine(line []byte) error {
	if _, err := s.bw.Write(line); err != nil {
		return err
	}
	if err := s.bw.WriteByte('\n'); err != nil {
		return err
	}
	s.hash.Write(line)
	s.hash.Write([]byte{'\n'})
	s.bytes += int64(len(line)) + 1
	return nil
}

// Writer streams one manifest segment into dir. A Writer is not safe for
// concurrent use; the spec requires a single writer goroutine (§8).
type Writer struct {
	dir   string
	hdr   Header
	clock Clock

	shard *shardWriter
	// shards holds sealed shard metadata in order.
	shards []IndexShard

	totalUnits int64
	stats      Stats

	complete bool
	errCount int64

	state writerState
}

type writerState int

const (
	writerOpen writerState = iota
	writerClosed
	writerAborted
)

var shardNamePattern = regexp.MustCompile(`^manifest\.[0-9]{4,}\.jsonl(\.tmp)?$`)

// NewWriter creates dir if needed and opens the first shard, writing the
// header as its first line. The header's shard_units/shard_bytes override the
// package defaults; a missing salt, ULID, path_fold_version and start time are
// filled from the injected Clock/SaltSource.
//
// NewWriter refuses to run on top of an existing manifest.index.json
// (ErrOutputExists) so an incomplete rerun can never destroy a complete
// artifact. Stale shards from a previous aborted attempt are removed only when
// no index exists.
func NewWriter(dir string, hdr Header, opts ...Option) (*Writer, error) {
	cfg := writerConfig{clock: systemClock{}, salt: randomSalt{}}
	for _, o := range opts {
		o(&cfg)
	}

	if err := prepareHeader(&hdr, cfg); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("manifest: output %q is not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, ".lock")); err == nil {
		return nil, fmt.Errorf("%w: E-MAN-031 unreleased .lock in %s", ErrIncomplete, dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.index.json")); err == nil {
		return nil, ErrOutputExists
	}
	if err := removeStaleShards(dir); err != nil {
		return nil, err
	}

	w := &Writer{dir: dir, hdr: hdr, clock: cfg.clock, complete: true}
	if err := w.startShard(); err != nil {
		return nil, err
	}
	headerLine := EncodeHeader(&w.hdr)
	if len(headerLine)+1 > MaxLineBytes {
		w.Abort()
		return nil, ErrLineTooLong
	}
	if err := w.shard.writeLine(headerLine); err != nil {
		w.Abort()
		return nil, err
	}
	return w, nil
}

// prepareHeader fills defaults and validates required header fields (§3.1).
func prepareHeader(h *Header, cfg writerConfig) error {
	if h.ManifestVersion == "" {
		h.ManifestVersion = Version
	}
	if h.ScanID == "" {
		id, err := newULID(cfg.clock)
		if err != nil {
			return err
		}
		h.ScanID = id
	}
	if h.StartedAt.IsZero() {
		h.StartedAt = cfg.clock.Now().UTC()
	} else {
		h.StartedAt = h.StartedAt.UTC()
	}
	if h.ScanSegment.FirstShard == 0 {
		if h.ScanSegment.SegmentSeq > 0 {
			return fmt.Errorf("manifest: E-MAN-005 scan_segment.first_shard is required for a continuation segment")
		}
		h.ScanSegment.FirstShard = 1
	}
	if h.ScanSegment.SegmentSeq > 0 && h.ScanSegment.Parent == nil {
		return fmt.Errorf("manifest: E-MAN-005 scan_segment.parent is required for segment_seq > 0")
	}
	if h.Host.PathFoldVersion == "" {
		h.Host.PathFoldVersion = CurrentPathFoldVersion()
	}
	if h.Inputs.SecretSaltMode == "" {
		h.Inputs.SecretSaltMode = "random"
	}
	switch h.Inputs.SecretSaltMode {
	case "random", "stable":
	default:
		return fmt.Errorf("manifest: E-MAN-043 invalid secret_salt_mode %q", h.Inputs.SecretSaltMode)
	}
	if h.Inputs.SecretSalt == "" {
		salt, err := cfg.salt.Salt()
		if err != nil {
			return err
		}
		h.Inputs.SecretSalt = salt
	}
	if h.ShardUnits <= 0 {
		h.ShardUnits = DefaultShardUnits
	}
	if h.ShardBytes <= 0 {
		h.ShardBytes = DefaultShardBytes
	}
	issues := checkHeaderRequired(h)
	for _, is := range issues {
		if is.Severity == SeverityError {
			return fmt.Errorf("%w: %s %s", ErrIncomplete, is.Code, is.Message)
		}
	}
	return nil
}

func newULID(clock Clock) (string, error) {
	var b [16]byte
	ms := uint64(clock.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	return crockfordEncode(b[:]), nil
}

func removeStaleShards(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if shardNamePattern.MatchString(e.Name()) || e.Name() == "manifest.index.json.tmp" {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *Writer) startShard() error {
	seq := len(w.shards) + 1
	name := fmt.Sprintf("manifest.%04d.jsonl", seq)
	tmp := filepath.Join(w.dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w.shard = &shardWriter{
		name: name,
		file: f,
		bw:   bufio.NewWriterSize(f, 256<<10),
		hash: sha256.New(),
	}
	return nil
}

// WriteUnit appends one unit. Required fields must already be set; the writer
// never invents conclusions. Rotation (50,000 units / 64 MiB by default) is
// checked before the line is written, so a sealed shard stays under the byte
// limit whenever the next record can still fit on a fresh shard.
func (w *Writer) WriteUnit(u *Unit) error {
	if err := w.writeState(); err != nil {
		return err
	}
	if err := checkUnitRequired(u); err != nil {
		return err
	}
	line := EncodeUnit(u)
	if len(line)+1 > MaxLineBytes {
		return ErrLineTooLong
	}
	if w.shard.units > 0 &&
		(w.shard.units >= int64(w.hdr.ShardUnits) ||
			w.shard.bytes+int64(len(line))+1 > w.hdr.ShardBytes) {
		if err := w.sealShard(); err != nil {
			return err
		}
		if err := w.startShard(); err != nil {
			return err
		}
	}
	if err := w.shard.writeLine(line); err != nil {
		return err
	}
	w.shard.units++
	w.totalUnits++
	recordUnitStats(&w.stats, u)
	return nil
}

// WriteNote appends one note. Notes do not count toward units or statistics,
// but their bytes count toward the shard size (§2, §3.2).
func (w *Writer) WriteNote(n *Note) error {
	if err := w.writeState(); err != nil {
		return err
	}
	if n.ScanID == "" || n.Code == "" {
		return fmt.Errorf("manifest: E-MAN-005 note requires scan_id and code")
	}
	if n.Type == "" {
		n.Type = TypeNote
	}
	line := EncodeNote(n)
	if len(line)+1 > MaxLineBytes {
		return ErrLineTooLong
	}
	if (w.shard.units > 0 || w.shard.notes > 0) &&
		w.shard.bytes+int64(len(line))+1 > w.hdr.ShardBytes {
		if err := w.sealShard(); err != nil {
			return err
		}
		if err := w.startShard(); err != nil {
			return err
		}
	}
	if err := w.shard.writeLine(line); err != nil {
		return err
	}
	w.shard.notes++
	return nil
}

func recordUnitStats(st *Stats, u *Unit) {
	switch u.Layer {
	case LayerL0:
		st.L0++
	case LayerL1:
		st.L1++
	case LayerL2:
		st.L2++
	case LayerL3:
		st.L3++
	case LayerL4:
		st.L4++
	case LayerL5:
		st.L5++
	}
	if u.Kind == KindCatchAll {
		st.Residual++
	}
	for _, se := range u.SideEffects {
		if st.SideEffects == nil {
			st.SideEffects = make(map[string]int64)
		}
		st.SideEffects[se]++
	}
}

// SetComplete records whether the scan had unhandled errors (§3.3). The
// default is complete=true; errCount > 0 forces complete=false.
func (w *Writer) SetComplete(complete bool, errCount int64) {
	if errCount > 0 {
		complete = false
	}
	w.complete = complete
	w.errCount = errCount
}

// Close writes the footer, seals the final shard, then writes
// manifest.index.json atomically. It is idempotent.
func (w *Writer) Close() error {
	switch w.state {
	case writerClosed:
		return nil
	case writerAborted:
		return ErrAborted
	}
	footer := Footer{
		Type:            TypeFooter,
		ManifestVersion: w.hdr.ManifestVersion,
		ScanID:          w.hdr.ScanID,
		EndedAt:         w.clock.Now().UTC(),
		Units:           w.totalUnits,
		Shards:          len(w.shards) + 1,
		Stats:           w.stats,
		Complete:        w.complete,
		Errors:          w.errCount,
	}
	line := EncodeFooter(&footer)
	if len(line)+1 > MaxLineBytes {
		return ErrLineTooLong
	}
	if err := w.shard.writeLine(line); err != nil {
		return err
	}
	if err := w.sealShard(); err != nil {
		return err
	}
	if err := w.writeIndex(&footer); err != nil {
		return err
	}
	w.state = writerClosed
	return nil
}

// Abort stops the writer without producing a complete manifest. The currently
// open shard is flushed and closed but never renamed, and no footer or index
// is written, so E-MAN-030 detects the result as incomplete (§2, §8). Shards
// that were already sealed remain byte-consumable for diagnostics.
func (w *Writer) Abort() error {
	if w.state == writerClosed || w.state == writerAborted {
		return nil
	}
	w.state = writerAborted
	if w.shard != nil {
		w.shard.bw.Flush()
		w.shard.file.Close()
		w.shard = nil
	}
	return nil
}

// Units reports how many unit records have been written.
func (w *Writer) Units() int64 { return w.totalUnits }

// Shards reports how many shards have been sealed. The currently open shard
// is not counted.
func (w *Writer) Shards() int { return len(w.shards) }

func (w *Writer) writeState() error {
	switch w.state {
	case writerClosed:
		return ErrClosed
	case writerAborted:
		return ErrAborted
	}
	return nil
}

func (w *Writer) sealShard() error {
	s := w.shard
	if s == nil {
		return nil
	}
	w.shard = nil
	if err := s.bw.Flush(); err != nil {
		s.file.Close()
		return err
	}
	if err := s.file.Sync(); err != nil {
		s.file.Close()
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	final := filepath.Join(w.dir, s.name)
	if err := os.Rename(s.file.Name(), final); err != nil {
		return err
	}
	w.shards = append(w.shards, IndexShard{
		Name:   s.name,
		SHA256: hex.EncodeToString(s.hash.Sum(nil)),
		Units:  s.units,
		Bytes:  s.bytes,
	})
	return syncDir(w.dir)
}

// Index* are the manifest.index.json structures (§2). Field order is fixed by
// declaration order, which encoding/json honours for structs.
type Index struct {
	ManifestVersion string         `json:"manifest_version"`
	ScanID          string         `json:"scan_id"`
	Shards          []IndexShard   `json:"shards"`
	Segments        []IndexSegment `json:"segments"`
	Units           int64          `json:"units"`
	Residual        int64          `json:"residual"`
	Complete        bool           `json:"complete"`
}

// IndexShard describes one shard file.
type IndexShard struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Units  int64  `json:"units"`
	Bytes  int64  `json:"bytes"`
}

// IndexSegment describes one scan segment for later byte-splicing (§2).
type IndexSegment struct {
	Parent     *string  `json:"parent"`
	SegmentSeq int      `json:"segment_seq"`
	FirstShard int      `json:"first_shard"`
	Shards     []string `json:"shards"`
}

func (w *Writer) writeIndex(footer *Footer) error {
	names := make([]string, len(w.shards))
	for i, s := range w.shards {
		names[i] = s.Name
	}
	idx := Index{
		ManifestVersion: w.hdr.ManifestVersion,
		ScanID:          w.hdr.ScanID,
		Shards:          w.shards,
		Segments: []IndexSegment{{
			Parent:     w.hdr.ScanSegment.Parent,
			SegmentSeq: w.hdr.ScanSegment.SegmentSeq,
			FirstShard: w.hdr.ScanSegment.FirstShard,
			Shards:     names,
		}},
		Units:    footer.Units,
		Residual: footer.Stats.Residual,
		Complete: footer.Complete,
	}
	data, err := json.Marshal(&idx)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := filepath.Join(w.dir, "manifest.index.json.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(w.dir, "manifest.index.json")); err != nil {
		return err
	}
	return syncDir(w.dir)
}

// syncDir flushes directory metadata after a rename. Windows does not support
// fsync on directories; the error is intentionally ignored there and on
// filesystems that reject it.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	_ = f.Sync()
	return nil
}

// ScanID returns the scan identifier written into the header. The value is
// final once NewWriter returns.
func (w *Writer) ScanID() string { return w.hdr.ScanID }

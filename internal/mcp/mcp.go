// Package mcp implements the read-only MCP surface of docs/design-mcp.md.
//
// The server speaks hand-written JSON-RPC 2.0 over stdio (newline-delimited
// messages): initialize, ping, tools/list and tools/call. There are exactly
// six tools — roots, summary, find, explain, verify, restore_plan — and none of
// them writes a file. Every root, the scan output directory and the package
// directory are fixed by the process arguments; a tool call can only add
// filters and pagination (INV-I03, D-05).
//
// Freshness: no tool caches a scan. Each call re-reads manifest.index.json,
// hashes it, re-reads and re-validates the manifest, and re-stats the paths it
// reports (INV-I06). The hash is returned as scan.fingerprint so a caller can
// tell two observations apart.
//
// Results are summarised and bounded to MaxResultBytes. When a list does not
// fit, the caller gets the leading items plus truncated=true and source, the
// path of the manifest or package that holds the full data (INV-I05).
package mcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"packout/internal/fsx"
	"packout/internal/manifest"
)

// Protocol and framing constants.
const (
	// ProtocolVersion is the newest MCP revision this server implements.
	ProtocolVersion = "2025-06-18"
	// ServerName is reported in initialize.
	ServerName = "packout"
	// MaxResultBytes bounds one tools/call payload (design-mcp.md: 8 KiB).
	MaxResultBytes = 8 << 10
	// MaxMessageBytes bounds one incoming JSON-RPC line. Tool arguments are
	// filters and pagination, so this is generous.
	MaxMessageBytes = 1 << 20
)

// supportedProtocols are the revisions the server can answer. The client's
// requested revision is echoed when it is one of these, else ProtocolVersion.
var supportedProtocols = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// Root is one root the operator allowed at startup. Path is empty when the
// profile template could not be resolved on this host; such a root is still
// reported, with Note, so the model does not silently lose a role.
type Root struct {
	Name     string
	Role     string
	Instance int
	Origin   string // cli | profile
	Path     string
	PathKey  string
	Note     string
}

// Config is the startup configuration. Only the process arguments fill it; a
// tool call can never change it.
type Config struct {
	OutDir   string
	Profile  string
	Roots    []Root
	Package  string // optional; verify and restore_plan need it
	Into     string // optional; restore_plan needs it
	Identity string // optional; age identity for restore_plan's dry run
	PubKey   string // optional; verify --pubkey
	Version  string
}

// Server is one stdio MCP session.
type Server struct {
	out      string
	profile  string
	roots    []Root
	pkg      string
	into     string
	identity string
	pubkey   string
	version  string
}

// NewServer validates and absolutizes the startup configuration. Missing
// optional directories are not an error: the tools that need them answer
// not_configured, and tools that read the scan answer no_scan until one
// exists. Nothing is read here.
func NewServer(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.OutDir) == "" {
		return nil, errors.New("mcp: 缺少扫描输出目录（--out）")
	}
	out, err := fsx.Abs(cfg.OutDir)
	if err != nil {
		return nil, fmt.Errorf("mcp: --out: %w", err)
	}
	s := &Server{
		out:      out,
		profile:  cfg.Profile,
		identity: cfg.Identity,
		pubkey:   cfg.PubKey,
		version:  cfg.Version,
	}
	for _, r := range cfg.Roots {
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = r.Role
		}
		if r.Path == "" {
			if r.Note == "" {
				r.Note = "profile 默认值在本机无法解析"
			}
			s.roots = append(s.roots, r)
			continue
		}
		abs, err := fsx.Abs(r.Path)
		if err != nil {
			r.Note = "路径无法绝对化：" + err.Error()
			s.roots = append(s.roots, r)
			continue
		}
		r.Path = abs
		r.PathKey = fsx.NormKey(abs)
		s.roots = append(s.roots, r)
	}
	if cfg.Package != "" {
		if s.pkg, err = fsx.Abs(cfg.Package); err != nil {
			return nil, fmt.Errorf("mcp: --package: %w", err)
		}
	}
	if cfg.Into != "" {
		if s.into, err = fsx.Abs(cfg.Into); err != nil {
			return nil, fmt.Errorf("mcp: --into: %w", err)
		}
	}
	return s, nil
}

// OutDir reports the absolutized scan output directory.
func (s *Server) OutDir() string { return s.out }

// Serve reads newline-delimited JSON-RPC messages until EOF or ctx is done.
// A clean EOF is a normal client disconnect and returns nil.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), MaxMessageBytes)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		resp := s.handle(ctx, line)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("mcp: 读取 stdio 消息: %w", err)
	}
	return nil
}

// ---- JSON-RPC 2.0 ---------------------------------------------------------

type request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func okResponse(id json.RawMessage, result any) *response {
	if id == nil {
		id = json.RawMessage("null")
	}
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func errResponse(id json.RawMessage, code int, msg string) *response {
	if id == nil {
		id = json.RawMessage("null")
	}
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// handle dispatches one message. A nil return means "notification, no reply".
func (s *Server) handle(ctx context.Context, line []byte) *response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return errResponse(nil, -32700, "parse error")
	}
	if req.Method == "" || (req.JSONRPC != "" && req.JSONRPC != "2.0") {
		return errResponse(idOrNil(req.ID), -32600, "invalid request")
	}
	if req.ID == nil {
		// Notifications (notifications/initialized, notifications/cancelled,
		// …) must never be answered.
		return nil
	}
	switch req.Method {
	case "initialize":
		return okResponse(*req.ID, s.initialize(req.Params))
	case "ping":
		return okResponse(*req.ID, map[string]any{})
	case "tools/list":
		return okResponse(*req.ID, map[string]any{"tools": toolSpecs()})
	case "tools/call":
		return s.call(ctx, *req.ID, req.Params)
	default:
		return errResponse(*req.ID, -32601, "method not found: "+req.Method)
	}
}

func idOrNil(id *json.RawMessage) json.RawMessage {
	if id == nil {
		return nil
	}
	return *id
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p) // a malformed initialize still gets a usable answer
	}
	ver := ProtocolVersion
	if p.ProtocolVersion != "" && supportedProtocols[p.ProtocolVersion] {
		ver = p.ProtocolVersion
	}
	info := map[string]any{"name": ServerName, "title": "packout 只读工具"}
	if s.version != "" {
		info["version"] = s.version
	}
	return map[string]any{
		"protocolVersion": ver,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": info,
		"instructions": "只读：roots/summary/find/explain/verify/restore_plan。" +
			"允许的根、扫描输出目录与包目录由启动参数固定，工具参数只能给过滤条件与分页。",
	}
}

// ---- tools/call -----------------------------------------------------------

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	Content           []content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

func (s *Server) call(ctx context.Context, id json.RawMessage, params json.RawMessage) *response {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) == 0 {
		return errResponse(id, -32602, "tools/call 缺少 params")
	}
	if err := json.Unmarshal(params, &p); err != nil || strings.TrimSpace(p.Name) == "" {
		return errResponse(id, -32602, "tools/call 需要 name 与 arguments")
	}
	args := p.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}

	var (
		val  any
		terr *toolError
	)
	switch p.Name {
	case "roots":
		val, terr = s.toolRoots(ctx, args)
	case "summary":
		val, terr = s.toolSummary(ctx, args)
	case "find":
		val, terr = s.toolFind(ctx, args)
	case "explain":
		val, terr = s.toolExplain(ctx, args)
	case "verify":
		val, terr = s.toolVerify(ctx, args)
	case "restore_plan":
		val, terr = s.toolRestorePlan(ctx, args)
	default:
		terr = &toolError{Code: "unknown_tool", Message: "未知工具：" + p.Name}
	}
	if terr != nil {
		return okResponse(id, errorResult(terr))
	}
	res, err := makeCallResult(val)
	if err != nil {
		return okResponse(id, errorResult(&toolError{Code: "internal", Message: err.Error()}))
	}
	return okResponse(id, res)
}

// makeCallResult renders a tool payload once and mirrors it into the MCP
// content block. A payload that somehow exceeds the bound is replaced by a
// structured result_too_large error rather than silently cut.
func makeCallResult(v any) (*callResult, error) {
	b, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxResultBytes {
		te := &toolError{Code: "result_too_large",
			Message: fmt.Sprintf("工具结果 %d 字节，超过 %d 字节上限", len(b), MaxResultBytes)}
		return &callResult{
			Content:           []content{{Type: "text", Text: string(mustMarshal(errorResult(te).StructuredContent))}},
			StructuredContent: errorResult(te).StructuredContent,
			IsError:           true,
		}, nil
	}
	return &callResult{
		Content:           []content{{Type: "text", Text: string(b)}},
		StructuredContent: v,
	}, nil
}

func mustMarshal(v any) []byte {
	b, err := marshalNoEscape(v)
	if err != nil {
		return []byte(`{"code":"internal","message":"encode failed"}`)
	}
	return b
}

// toolError is the structured error object every failing tool returns. It is
// a JSON object, never a bare string.
type toolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Source  string `json:"source,omitempty"`
}

func (e *toolError) Error() string { return e.Code + ": " + e.Message }

func errorResult(e *toolError) *callResult {
	b := mustMarshal(e)
	return &callResult{
		Content:           []content{{Type: "text", Text: string(b)}},
		StructuredContent: e,
		IsError:           true,
	}
}

// ---- scan I/O (never cached) ---------------------------------------------

type scanMeta struct {
	ScanID        string `json:"scan_id"`
	Fingerprint   string `json:"fingerprint"` // sha256 of manifest.index.json
	Units         int64  `json:"units"`
	Residual      int64  `json:"residual"`
	Complete      bool   `json:"complete"`
	Manifest      string `json:"manifest"`
	ManifestMTime string `json:"manifest_mtime,omitempty"`
	IndexBytes    int64  `json:"index_bytes"`
}

// scanDir locates the manifest directory under the configured --out, accepting
// either "<out>/manifest" (scan layout) or an --out that is the manifest
// directory itself, matching `report --manifest`.
func (s *Server) scanDir() (string, *toolError) {
	fi, err := fsx.Lstat(s.out)
	if err != nil {
		return "", &toolError{Code: "no_scan", Message: "还没有可读的扫描输出：" + s.out,
			Detail: err.Error(), Source: s.out}
	}
	if !fi.IsDir {
		return "", &toolError{Code: "no_scan", Message: "--out 不是目录：" + s.out, Source: s.out}
	}
	candidates := []string{filepath.Join(s.out, "manifest"), s.out}
	for _, dir := range candidates {
		if _, err := fsx.Lstat(filepath.Join(dir, "manifest.index.json")); err == nil {
			return dir, nil
		}
	}
	return "", &toolError{Code: "no_scan",
		Message: "扫描输出里没有完整的 manifest.index.json；先跑 packout scan --out " + s.out,
		Source:  s.out}
}

// openScan re-reads and re-hashes the scan for one tool call. Nothing is
// cached between calls (INV-I06): the index hash changes when the scan is
// replaced, and a caller can compare fingerprints.
func (s *Server) openScan() (*manifest.Manifest, scanMeta, *toolError) {
	dir, terr := s.scanDir()
	if terr != nil {
		return nil, scanMeta{}, terr
	}
	idxPath := filepath.Join(dir, "manifest.index.json")
	idx, err := osReadFile(idxPath)
	if err != nil {
		return nil, scanMeta{}, &toolError{Code: "scan_invalid",
			Message: "读不到 manifest.index.json", Detail: err.Error(), Source: dir}
	}
	sum := sha256.Sum256(idx)
	m, err := manifest.ReadManifest(dir)
	if err != nil {
		return nil, scanMeta{}, &toolError{Code: "scan_invalid",
			Message: "manifest 不可用（不完整或结构错误）", Detail: err.Error(), Source: dir}
	}
	meta := scanMeta{
		ScanID:      m.Header.ScanID,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		Units:       m.Footer.Units,
		Residual:    m.Footer.Stats.Residual,
		Complete:    m.Footer.Complete,
		Manifest:    dir,
		IndexBytes:  int64(len(idx)),
	}
	if st, err := fsx.Lstat(dir); err == nil {
		meta.ManifestMTime = st.ModTime.UTC().Format(timeFormat)
	}
	return m, meta, nil
}

// allowedRoots decides which paths this session may inspect. Explicit --root
// values win; otherwise the roots recorded by the scan itself (the manifest is
// only reachable through the startup --out) are used. Either way the model
// cannot add a root (INV-I03).
func (s *Server) allowedRoots(m *manifest.Manifest) []string {
	var out []string
	for _, r := range s.roots {
		if r.Path != "" {
			out = append(out, r.Path)
		}
	}
	if len(out) > 0 {
		return out
	}
	if m != nil {
		for _, r := range m.Header.Roots {
			if r.Path != "" {
				out = append(out, r.Path)
			}
		}
	}
	return out
}

func withinAny(roots []string, p string) bool {
	if p == "" {
		return false
	}
	for _, r := range roots {
		if fsx.Within(r, p) {
			return true
		}
	}
	return false
}

// inScope reports whether a manifest unit may be shown and re-stat'ed.
// named-location units carry no filesystem path and are always in scope.
func inScope(u *manifest.Unit, roots []string) bool {
	if u.Root == "os" && !filepath.IsAbs(u.Path) {
		return true
	}
	return withinAny(roots, u.Path)
}

// ---- small shared helpers -------------------------------------------------

// marshalNoEscape encodes v without HTML escaping and without a trailing
// newline, so the byte count is the payload size.
func marshalNoEscape(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// fitPrefix returns how many leading items fit in budget. itemLen must give
// the encoded length of item i. reserve is subtracted from budget for the
// fields that explain the truncation.
func fitPrefix(baseLen int, itemLen func(int) int, n, budget, reserve int) int {
	used := baseLen + reserve
	for i := 0; i < n; i++ {
		l := itemLen(i) + 1 // comma
		if used+l > budget {
			return i
		}
		used += l
	}
	return n
}

// decodeArgs enforces a strict argument object: unknown keys are rejected so
// an injected payload cannot smuggle parameters past the schema.
func decodeArgs(raw json.RawMessage, dst any) *toolError {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return &toolError{Code: "bad_arguments", Message: "参数不符合工具 schema", Detail: err.Error()}
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return &toolError{Code: "bad_arguments", Message: "参数对象之后还有多余内容"}
	}
	return nil
}

// noArgs is used by tools whose schema accepts nothing.
func noArgs(raw json.RawMessage) *toolError {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 0 {
		return &toolError{Code: "bad_arguments", Message: "该工具不接受参数"}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

// osReadFile is a variable so tests can observe (and count) re-reads.
var osReadFile = func(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<20))
}

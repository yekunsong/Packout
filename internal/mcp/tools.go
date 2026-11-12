package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"packout/internal/fsx"
	"packout/internal/manifest"
	"packout/internal/pack"
	"packout/internal/restore"
)

// toolSpecs returns the fixed tool list of docs/design-mcp.md. It is exactly
// six read-only tools; adding one is a design change, not an implementation
// detail.
func toolSpecs() []map[string]any {
	empty := func() map[string]any {
		return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	}
	return []map[string]any{
		{
			"name":        "roots",
			"title":       "已配置的根",
			"description": "Returns the roots this session may look at, the profile name and the current scan's roots. Read-only; no paths can be added at runtime.",
			"inputSchema": empty(),
		},
		{
			"name":        "summary",
			"title":       "扫描汇总",
			"description": "Counts and sizes of the latest complete scan, grouped by layer and by profile. No individual paths.",
			"inputSchema": empty(),
		},
		{
			"name":        "find",
			"title":       "过滤条目",
			"description": "Filters the latest scan by layer, entry or path fragment. Returns at most `limit` entries after skipping `offset`; paths carry both the original spelling and the manifest path_key.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"layer": map[string]any{
						"type": "string", "enum": []string{"L0", "L1", "L2", "L3", "L4", "L5"},
						"description": "只保留该层的条目",
					},
					"entry": map[string]any{"type": "string", "description": "只保留该 entry id 的条目"},
					"path_contains": map[string]any{
						"type": "string", "description": "路径片段（大小写不敏感，按 path_key 匹配）",
					},
					"limit": map[string]any{
						"type": "integer", "minimum": 1, "maximum": 100, "default": 25,
						"description": "本次最多返回几条",
					},
					"offset": map[string]any{
						"type": "integer", "minimum": 0, "default": 0,
						"description": "分页起点",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			"name":        "explain",
			"title":       "解释一个 Unit",
			"description": "Returns one unit's full signals and provenance, its secret summary (masked, never plaintext) and a fresh stat of the recorded path. Identify it by id, path or path_key — exactly one.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":       map[string]any{"type": "string", "description": "Unit id（u_…）"},
					"path":     map[string]any{"type": "string", "description": "manifest 里的原始路径拼写"},
					"path_key": map[string]any{"type": "string", "description": "manifest 里的 path_key"},
				},
				"additionalProperties": false,
			},
		},
		{
			"name":        "verify",
			"title":       "校验包",
			"description": "Verifies the package fixed by the --package startup argument and returns its conclusion word. Returns not_configured when --package was not given. Read-only.",
			"inputSchema": empty(),
		},
		{
			"name":        "restore_plan",
			"title":       "恢复计划（干跑）",
			"description": "Runs restore's dry-run against the package from --package and the target from --into. Builds the plan only; writes nothing. Returns not_configured when either startup argument is missing.",
			"inputSchema": empty(),
		},
	}
}

// ---- roots ----------------------------------------------------------------

type rootOut struct {
	Name       string `json:"name"`
	Role       string `json:"role,omitempty"`
	Instance   int    `json:"instance,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Path       string `json:"path,omitempty"`
	PathKey    string `json:"path_key,omitempty"`
	Configured bool   `json:"configured"`
	Exists     bool   `json:"exists"`
	IsDir      bool   `json:"is_dir,omitempty"`
	IsLink     bool   `json:"is_link,omitempty"`
	IsOffline  bool   `json:"is_offline,omitempty"`
	Error      string `json:"error,omitempty"`
	Note       string `json:"note,omitempty"`
}

type scanRootOut struct {
	Name     string `json:"name"`
	Role     string `json:"role,omitempty"`
	Instance int    `json:"instance,omitempty"`
	Origin   string `json:"origin,omitempty"`
	Path     string `json:"path,omitempty"`
	PathKey  string `json:"path_key,omitempty"`
	Profile  string `json:"profile,omitempty"`
}

func (s *Server) toolRoots(_ context.Context, raw json.RawMessage) (any, *toolError) {
	if terr := noArgs(raw); terr != nil {
		return nil, terr
	}
	items := make([]any, 0, len(s.roots))
	for _, r := range s.roots {
		o := rootOut{Name: r.Name, Role: r.Role, Instance: r.Instance, Origin: r.Origin,
			Path: r.Path, PathKey: r.PathKey, Note: r.Note}
		if r.Path != "" {
			o.Configured = true
			// Re-stat on every call: a root can appear or vanish at any time.
			fi, err := fsx.Lstat(r.Path)
			if err != nil {
				o.Error = err.Error()
			} else {
				o.Exists = true
				o.IsDir = fi.IsDir
				o.IsLink = fi.IsLink
				o.IsOffline = fi.IsOffline
			}
		}
		items = append(items, o)
	}

	res := map[string]any{
		"profile": s.profile,
		"out":     s.out,
		"roots":   items,
	}
	var scanItems []any
	m, meta, terr := s.openScan()
	if terr == nil {
		res["scan"] = meta
		for _, r := range m.Header.Roots {
			scanItems = append(scanItems, scanRootOut{
				Name: r.Name, Role: r.Role, Instance: r.Instance, Origin: r.Origin,
				Path: r.Path, PathKey: fsx.NormKey(r.Path), Profile: r.Profile,
			})
		}
		res["scan_roots"] = scanItems
	} else {
		note := terr.Message
		if terr.Detail != "" {
			note += "：" + terr.Detail
		}
		res["scan_note"] = note
	}
	res["scope"] = "roots 由启动参数固定；工具参数不能新增根"

	// Keep the whole answer inside the bound; roots are few in practice.
	fitList(res, "roots", items, 128, func(n int, truncated bool) {
		res["roots_truncated"] = truncated
	})
	if scanItems != nil {
		fitList(res, "scan_roots", scanItems, 128, func(n int, truncated bool) {
			res["scan_roots_truncated"] = truncated
		})
		enforceBound(res, "scan_roots", scanItems, s.out)
	}
	enforceBound(res, "roots", items, s.out)
	return res, nil
}

// ---- summary --------------------------------------------------------------

type layerCount struct {
	Layer         string `json:"layer"`
	Units         int64  `json:"units"`
	BytesApparent int64  `json:"bytes_apparent"`
	BytesAlloc    int64  `json:"bytes_alloc"`
}

type profileCount struct {
	Profile       string `json:"profile"`
	Units         int64  `json:"units"`
	BytesApparent int64  `json:"bytes_apparent"`
}

func (s *Server) toolSummary(_ context.Context, raw json.RawMessage) (any, *toolError) {
	if terr := noArgs(raw); terr != nil {
		return nil, terr
	}
	m, meta, terr := s.openScan()
	if terr != nil {
		return nil, terr
	}

	byLayer := map[string]*layerCount{}
	for _, l := range []string{"L0", "L1", "L2", "L3", "L4", "L5"} {
		byLayer[l] = &layerCount{Layer: l}
	}
	layers := make([]any, 0, 7)
	profiles := map[string]*profileCount{}
	var totalApparent, totalAlloc int64

	for i := range m.Units {
		u := &m.Units[i]
		lc := byLayer[u.Layer]
		if lc == nil {
			// Unknown layer (newer minor): counted under its own bucket.
			lc = &layerCount{Layer: u.Layer}
			byLayer[u.Layer] = lc
		}
		lc.Units++
		if u.SizeApparent != nil {
			lc.BytesApparent += *u.SizeApparent
			totalApparent += *u.SizeApparent
		}
		if u.SizeAlloc != nil {
			lc.BytesAlloc += *u.SizeAlloc
			totalAlloc += *u.SizeAlloc
		}
		pc := profiles[u.Profile]
		if pc == nil {
			pc = &profileCount{Profile: u.Profile}
			profiles[u.Profile] = pc
		}
		pc.Units++
		if u.SizeApparent != nil {
			pc.BytesApparent += *u.SizeApparent
		}
	}

	keys := []string{"L0", "L1", "L2", "L3", "L4", "L5"}
	for k := range byLayer {
		if k != "L0" && k != "L1" && k != "L2" && k != "L3" && k != "L4" && k != "L5" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys[6:])
	for _, k := range keys {
		layers = append(layers, *byLayer[k])
	}
	profileItems := make([]any, 0, len(profiles))
	for _, name := range sortedKeys(profiles) {
		profileItems = append(profileItems, *profiles[name])
	}

	res := map[string]any{
		"scan":   meta,
		"layers": layers,
		"totals": map[string]any{
			"units":          int64(len(m.Units)),
			"units_footer":   m.Footer.Units,
			"residual":       m.Footer.Stats.Residual,
			"notes":          int64(len(m.Notes)),
			"complete":       m.Footer.Complete,
			"bytes_apparent": totalApparent,
			"bytes_alloc":    totalAlloc,
			"profiles":       int64(len(profiles)),
		},
	}
	fitList(res, "profiles", profileItems, 128, func(n int, truncated bool) {
		res["profiles_truncated"] = truncated
	})
	enforceBound(res, "profiles", profileItems, meta.Manifest)
	return res, nil
}

// ---- find -----------------------------------------------------------------

type findArgs struct {
	Layer        *string `json:"layer"`
	Entry        *string `json:"entry"`
	PathContains *string `json:"path_contains"`
	Limit        *int    `json:"limit"`
	Offset       *int    `json:"offset"`
}

type findUnit struct {
	ID             string   `json:"id"`
	Path           string   `json:"path"`
	PathKey        string   `json:"path_key"`
	Root           string   `json:"root"`
	Layer          string   `json:"layer"`
	Entry          string   `json:"entry"`
	PartID         string   `json:"part_id,omitempty"`
	Kind           string   `json:"kind"`
	Confidence     float64  `json:"confidence"`
	ProposedAction string   `json:"proposed_action"`
	SecretClass    string   `json:"secret_class,omitempty"`
	SizeApparent   *int64   `json:"size_apparent"`
	RiskFlags      []string `json:"risk_flags,omitempty"`
}

const (
	defaultFindLimit = 25
	maxFindLimit     = 100
)

func (s *Server) toolFind(_ context.Context, raw json.RawMessage) (any, *toolError) {
	var a findArgs
	if terr := decodeArgs(raw, &a); terr != nil {
		return nil, terr
	}
	if a.Layer != nil {
		switch *a.Layer {
		case "L0", "L1", "L2", "L3", "L4", "L5":
		default:
			return nil, &toolError{Code: "bad_arguments", Message: "layer 必须是 L0…L5"}
		}
	}
	limit := defaultFindLimit
	if a.Limit != nil {
		limit = *a.Limit
		if limit < 1 || limit > maxFindLimit {
			return nil, &toolError{Code: "bad_arguments", Message: fmt.Sprintf("limit 必须在 1…%d", maxFindLimit)}
		}
	}
	offset := 0
	if a.Offset != nil {
		offset = *a.Offset
		if offset < 0 {
			return nil, &toolError{Code: "bad_arguments", Message: "offset 不能为负"}
		}
	}
	var needle string
	if a.PathContains != nil {
		needle = fsx.NormKey(strings.TrimSpace(*a.PathContains))
	}

	m, meta, terr := s.openScan()
	if terr != nil {
		return nil, terr
	}
	roots := s.allowedRoots(m)

	total, outside := 0, 0
	page := make([]any, 0, limit)
	for i := range m.Units {
		u := &m.Units[i]
		if !inScope(u, roots) {
			outside++
			continue
		}
		if a.Layer != nil && u.Layer != *a.Layer {
			continue
		}
		if a.Entry != nil && u.Entry != *a.Entry {
			continue
		}
		if needle != "" && !strings.Contains(u.PathKey, needle) {
			continue
		}
		if total < offset {
			total++
			continue
		}
		if len(page) < limit {
			secretClass := ""
			if u.Secret != nil {
				secretClass = u.Secret.Class
			}
			page = append(page, findUnit{
				ID: u.ID, Path: u.Path, PathKey: u.PathKey, Root: u.Root,
				Layer: u.Layer, Entry: u.Entry, PartID: u.PartID, Kind: u.Kind,
				Confidence: u.Confidence, ProposedAction: u.ProposedAction,
				SecretClass: secretClass, SizeApparent: u.SizeApparent,
				RiskFlags: u.RiskFlags,
			})
		}
		total++
	}

	filter := map[string]any{
		"layer": a.Layer, "entry": a.Entry, "path_contains": a.PathContains,
	}
	res := map[string]any{
		"scan":                 meta,
		"filter":               filter,
		"total_matches":        total,
		"offset":               offset,
		"limit":                limit,
		"outside_root_skipped": outside,
	}
	kept := fitList(res, "units", page, 160, func(n int, truncated bool) {
		res["returned"] = n
		res["truncated"] = truncated
		res["source"] = sourceFor(meta, truncated)
	})
	_ = kept
	enforceBound(res, "units", page, meta.Manifest)
	kept = 0
	if v, ok := res["units"].([]any); ok {
		kept = len(v)
	} else {
		res["units"] = []any{}
	}
	res["returned"] = kept
	res["truncated"] = kept < len(page)
	res["source"] = sourceFor(meta, kept < len(page))
	res["next_offset"] = offset + kept
	res["has_more"] = offset+kept < total
	return res, nil
}

func sourceFor(meta scanMeta, truncated bool) any {
	if !truncated {
		return nil
	}
	return meta.Manifest
}

// ---- explain --------------------------------------------------------------

type explainArgs struct {
	ID      *string `json:"id"`
	Path    *string `json:"path"`
	PathKey *string `json:"path_key"`
}

type signalOut struct {
	Src  string  `json:"src"`
	Note string  `json:"note"`
	URL  *string `json:"url,omitempty"`
}

type hitOut struct {
	Kind        string `json:"kind"`
	Class       string `json:"class,omitempty"`
	Locator     string `json:"locator,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	HitID       string `json:"hit_id,omitempty"`
}

type unitOut struct {
	ID             string         `json:"id"`
	CID            *string        `json:"cid"`
	Path           string         `json:"path"`
	PathKey        string         `json:"path_key"`
	Root           string         `json:"root"`
	Profile        string         `json:"profile"`
	Entry          string         `json:"entry"`
	PartID         string         `json:"part_id,omitempty"`
	Kind           string         `json:"kind"`
	Layer          string         `json:"layer"`
	Confidence     float64        `json:"confidence"`
	PathSemantics  string         `json:"path_semantics"`
	DerivedFrom    *string        `json:"derived_from"`
	Origin         *string        `json:"origin,omitempty"`
	OriginPathKey  *string        `json:"origin_path_key,omitempty"`
	ProposedAction string         `json:"proposed_action"`
	RiskFlags      []string       `json:"risk_flags,omitempty"`
	NeededBy       []string       `json:"needed_by,omitempty"`
	Companions     []string       `json:"companions,omitempty"`
	SideEffects    []string       `json:"side_effects,omitempty"`
	OpenAs         string         `json:"open_as,omitempty"`
	OpaqueContent  bool           `json:"opaque_content,omitempty"`
	LinkTarget     string         `json:"link_target,omitempty"`
	SecretRef      string         `json:"secret_ref,omitempty"`
	Notes          string         `json:"notes,omitempty"`
	SizeApparent   *int64         `json:"size_apparent"`
	SizeAlloc      *int64         `json:"size_alloc"`
	SizeEstimated  bool           `json:"size_estimated,omitempty"`
	AggregateCount *int64         `json:"aggregate_count,omitempty"`
	MTime          *string        `json:"mtime"`
	FileID         map[string]any `json:"file_id,omitempty"`
	Fingerprint    map[string]any `json:"fingerprint,omitempty"`
}

type statOut struct {
	Path       string   `json:"path"`
	PathKey    string   `json:"path_key"`
	Exists     bool     `json:"exists"`
	IsDir      bool     `json:"is_dir,omitempty"`
	IsLink     bool     `json:"is_link,omitempty"`
	IsSparse   bool     `json:"is_sparse,omitempty"`
	IsOffline  bool     `json:"is_offline,omitempty"`
	Size       int64    `json:"size,omitempty"`
	Alloc      int64    `json:"alloc,omitempty"`
	MTime      string   `json:"mtime,omitempty"`
	FileID     string   `json:"file_id,omitempty"`
	LinkTarget string   `json:"link_target,omitempty"`
	Stale      bool     `json:"stale"`
	Drift      []string `json:"drift,omitempty"`
	Skipped    string   `json:"skipped,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func (s *Server) toolExplain(_ context.Context, raw json.RawMessage) (any, *toolError) {
	var a explainArgs
	if terr := decodeArgs(raw, &a); terr != nil {
		return nil, terr
	}
	nonEmpty := 0
	for _, v := range []*string{a.ID, a.Path, a.PathKey} {
		if v != nil && strings.TrimSpace(*v) != "" {
			nonEmpty++
		}
	}
	if nonEmpty != 1 {
		return nil, &toolError{Code: "bad_arguments",
			Message: "explain 需要 id、path、path_key 中恰好一个"}
	}

	m, meta, terr := s.openScan()
	if terr != nil {
		return nil, terr
	}
	u := lookupUnit(m, a)
	if u == nil {
		return nil, &toolError{Code: "not_found", Message: "manifest 里没有匹配的 Unit",
			Source: meta.Manifest}
	}
	roots := s.allowedRoots(m)
	if !inScope(u, roots) {
		return nil, &toolError{Code: "outside_root",
			Message: "该 Unit 不在本会话允许的根内；根只由启动参数决定", Source: meta.Manifest}
	}

	var mtime *string
	if u.MTime != nil {
		t := u.MTime.UTC().Format(timeFormat)
		mtime = &t
	}
	unit := unitOut{
		ID: u.ID, CID: u.CID, Path: u.Path, PathKey: u.PathKey, Root: u.Root,
		Profile: u.Profile, Entry: u.Entry, PartID: u.PartID, Kind: u.Kind,
		Layer: u.Layer, Confidence: u.Confidence, PathSemantics: u.PathSemantics,
		DerivedFrom: u.DerivedFrom, Origin: u.Origin, OriginPathKey: u.OriginPathKey,
		ProposedAction: u.ProposedAction, RiskFlags: u.RiskFlags, NeededBy: u.NeededBy,
		Companions: u.Companions, SideEffects: u.SideEffects, OpenAs: u.OpenAs,
		OpaqueContent: u.OpaqueContent, LinkTarget: u.LinkTarget, SecretRef: u.SecretRef,
		Notes: u.Notes, SizeApparent: u.SizeApparent, SizeAlloc: u.SizeAlloc,
		SizeEstimated: u.SizeEstimated, AggregateCount: u.AggregateCount,
		MTime: mtime, FileID: fileIDOut(u.FileID), Fingerprint: fingerprintOut(u.Fingerprint),
	}

	signals := make([]any, 0, len(u.Signals))
	for _, sg := range u.Signals {
		signals = append(signals, signalOut{Src: sg.Src, Note: sg.Note, URL: sg.URL})
	}
	secret := map[string]any{"class": manifest.SecretNone}
	hits := []any{}
	if u.Secret != nil {
		secret["class"] = u.Secret.Class
		secret["hit_count"] = u.Secret.HitCount
		secret["truncated"] = u.Secret.Truncated
		for _, h := range u.Secret.Hits {
			hits = append(hits, hitOut{Kind: h.Kind, Class: h.Class, Locator: h.Locator,
				Prefix: h.Prefix, Fingerprint: h.Fingerprint, HitID: h.HitID})
		}
	}
	secret["hits_total"] = len(hits)

	res := map[string]any{
		"scan":          meta,
		"unit":          unit,
		"secret":        secret,
		"signals_total": len(signals),
	}
	fitList(res, "signals", signals, 220, func(n int, truncated bool) {
		res["signals_returned"] = n
		res["truncated"] = truncated
		res["source"] = sourceFor(meta, truncated)
	})
	fitList(res, "secret_hits", hits, 220, func(n int, truncated bool) {
		res["secret_hits_returned"] = n
		if truncated {
			res["truncated"] = true
			res["source"] = meta.Manifest
		}
	})
	enforceBound(res, "secret_hits", hits, meta.Manifest)
	enforceBound(res, "signals", signals, meta.Manifest)
	res["current_stat"] = s.statUnit(u, roots)
	if b, err := marshalNoEscape(res); err == nil && len(b) > MaxResultBytes {
		delete(res, "current_stat")
		res["truncated"] = true
		res["source"] = meta.Manifest
	}
	enforceBound(res, "signals", signals, meta.Manifest)
	return res, nil
}

func fileIDOut(f *manifest.FileID) map[string]any {
	if f == nil {
		return nil
	}
	out := map[string]any{"volume_serial": f.VolumeSerial, "index": f.Index}
	if len(f.ReparseTag) > 0 {
		var tag any
		if json.Unmarshal(f.ReparseTag, &tag) == nil {
			out["reparse_tag"] = tag
		} else {
			out["reparse_tag"] = string(f.ReparseTag)
		}
	}
	return out
}

func fingerprintOut(f *manifest.Fingerprint) map[string]any {
	if f == nil {
		return nil
	}
	out := map[string]any{"algo": f.Algo, "scope": f.Scope}
	if f.Value != nil {
		out["value"] = *f.Value
	}
	return out
}

func lookupUnit(m *manifest.Manifest, a explainArgs) *manifest.Unit {
	if a.ID != nil && strings.TrimSpace(*a.ID) != "" {
		for i := range m.Units {
			if m.Units[i].ID == *a.ID {
				return &m.Units[i]
			}
		}
		return nil
	}
	if a.PathKey != nil && strings.TrimSpace(*a.PathKey) != "" {
		key := fsx.NormKey(*a.PathKey)
		for i := range m.Units {
			if m.Units[i].PathKey == key || fsx.NormKey(m.Units[i].PathKey) == key {
				return &m.Units[i]
			}
		}
		return nil
	}
	if a.Path != nil && strings.TrimSpace(*a.Path) != "" {
		raw := *a.Path
		key := fsx.NormKey(raw)
		var found *manifest.Unit
		for i := range m.Units {
			if m.Units[i].Path == raw || m.Units[i].PathKey == key {
				if found != nil {
					return nil // ambiguous: path matches several part units
				}
				found = &m.Units[i]
			}
		}
		return found
	}
	return nil
}

// statUnit re-stats the unit's recorded path. It never reads contents, and it
// only touches paths inside the allowed roots. The comparison with the
// manifest fields is the freshness signal (INV-I06).
func (s *Server) statUnit(u *manifest.Unit, roots []string) statOut {
	out := statOut{Path: u.Path, PathKey: u.PathKey}
	switch {
	case u.Path == "" || !filepath.IsAbs(u.Path):
		out.Skipped = "non_path"
		return out
	case !withinAny(roots, u.Path):
		out.Skipped = "outside_root"
		return out
	}
	fi, err := fsx.Lstat(u.Path)
	if err != nil {
		out.Stale = true
		out.Drift = []string{"missing"}
		out.Error = err.Error()
		return out
	}
	out.Exists = true
	out.IsDir = fi.IsDir
	out.IsLink = fi.IsLink
	out.IsSparse = fi.IsSparse
	out.IsOffline = fi.IsOffline
	out.Size = fi.Size
	out.Alloc = fi.Alloc
	out.MTime = fi.ModTime.UTC().Format(timeFormat)
	out.FileID = fi.FileID
	out.LinkTarget = fi.LinkTarget
	if u.SizeApparent != nil && *u.SizeApparent != fi.Size {
		out.Drift = append(out.Drift, "size_changed")
	}
	if u.MTime != nil && !fi.ModTime.Equal(*u.MTime) {
		out.Drift = append(out.Drift, "mtime_changed")
	}
	out.Stale = len(out.Drift) > 0
	return out
}

// ---- verify ---------------------------------------------------------------

func (s *Server) toolVerify(_ context.Context, raw json.RawMessage) (any, *toolError) {
	if terr := noArgs(raw); terr != nil {
		return nil, terr
	}
	if s.pkg == "" {
		return nil, &toolError{Code: "not_configured",
			Message: "verify 未配置包目录；启动时加 --package DIR（运行期不接受路径）"}
	}
	// Fresh stat every call; the package may have been replaced.
	if _, err := fsx.Lstat(s.pkg); err != nil {
		return nil, &toolError{Code: "package_missing", Message: "包目录不可读", Detail: err.Error(), Source: s.pkg}
	}
	v, verr := pack.VerifyWithOptions(s.pkg, pack.VerifyOptions{
		PubKeyPath:      s.pubkey,
		TrustedKeysPath: s.trustedKeys,
	})
	if v == nil {
		detail := ""
		if verr != nil {
			detail = verr.Error()
		}
		return nil, &toolError{Code: "verify_failed", Message: "verify 没有给出结论", Detail: detail, Source: s.pkg}
	}

	res := map[string]any{
		"package":           s.pkg,
		"package_key":       fsx.NormKey(s.pkg),
		"conclusion":        v.Conclusion,
		"signed":            v.Signed,
		"signature_present": v.SignaturePresent,
		"manifest_valid":    v.ManifestValid,
		"entries":           v.Entries,
		"total_bytes":       v.TotalBytes,
		"tree_sha256":       v.TreeSHA256,
		"fingerprint":       v.TreeSHA256,
	}
	if v.KeyFingerprint != "" {
		res["key_fingerprint"] = v.KeyFingerprint
	}
	if v.Method != "" {
		res["method"] = v.Method
	}
	if verr != nil {
		res["error"] = verr.Error()
	}
	problems := make([]any, 0, len(v.Problems))
	for _, p := range v.Problems {
		problems = append(problems, p)
	}
	res["problems_total"] = len(problems)
	fitList(res, "problems", problems, 128, func(n int, truncated bool) {
		res["problems_returned"] = n
		if truncated {
			res["truncated"] = true
			res["source"] = s.pkg
		}
	})
	enforceBound(res, "problems", problems, s.pkg)
	return res, nil
}

// ---- restore_plan ---------------------------------------------------------

func (s *Server) toolRestorePlan(ctx context.Context, raw json.RawMessage) (any, *toolError) {
	if terr := noArgs(raw); terr != nil {
		return nil, terr
	}
	var missing []string
	if s.pkg == "" {
		missing = append(missing, "--package")
	}
	if s.into == "" {
		missing = append(missing, "--into")
	}
	if len(missing) > 0 {
		return nil, &toolError{Code: "not_configured",
			Message: "restore_plan 缺少启动参数：" + strings.Join(missing, "、") + "（运行期不接受路径）"}
	}

	// Reuse restore's own dry-run: verify → target gate → decrypt → plan.
	// InPlace/Force make the plan a diff against an existing target; DryRun
	// guarantees no write. AllowUnverified only widens the read-only plan (the
	// CLI's real write still requires an explicit human flag); every result
	// names the SIG conclusion and allowed_unverified.
	rep, err := restore.Run(ctx, restore.Options{
		PackageDir:      s.pkg,
		Into:            s.into,
		InPlace:         true,
		Force:           true,
		DryRun:          true,
		AllowUnverified: true,
		PubKeyPath:      s.pubkey,
		TrustedKeysPath: s.trustedKeys,
		Crypt:           pack.CryptOptions{IdentityPath: s.identity},
	})
	if rep == nil {
		return nil, &toolError{Code: "restore_plan_failed", Message: "restore 干跑没有给出报告",
			Detail: errString(err), Source: s.pkg}
	}
	if err != nil {
		return nil, &toolError{Code: restorePlanCode(err), Message: "restore 干跑中止",
			Detail: errString(err), Source: s.pkg}
	}

	plan := make([]any, 0, len(rep.Plan))
	for _, p := range rep.Plan {
		plan = append(plan, map[string]any{
			"path":       p.Path,
			"path_key":   fsx.NormKey(p.Path),
			"target":     p.Target,
			"target_key": fsx.NormKey(p.Target),
			"unit_id":    p.UnitID,
			"bytes":      p.Bytes,
			"action":     p.Action,
		})
	}
	reinstall := make([]any, 0, len(rep.NeedsReinstall))
	for _, n := range rep.NeedsReinstall {
		reinstall = append(reinstall, map[string]any{
			"unit_id": n.UnitID, "path": n.Path, "path_key": fsx.NormKey(n.Path),
			"entry": n.Entry, "layer": n.Layer,
		})
	}
	relogin := make([]any, 0, len(rep.NeedsRelogin))
	for _, n := range rep.NeedsRelogin {
		relogin = append(relogin, map[string]any{
			"unit_id": n.UnitID, "path": n.Path, "path_key": fsx.NormKey(n.Path),
			"entry": n.Entry, "layer": n.Layer,
		})
	}
	problems := make([]any, 0, len(rep.Problems))
	for _, p := range rep.Problems {
		problems = append(problems, p)
	}

	res := map[string]any{
		"package":               s.pkg,
		"package_key":           fsx.NormKey(s.pkg),
		"target":                s.into,
		"target_key":            fsx.NormKey(s.into),
		"dry_run":               true,
		"wrote":                 false,
		"sig_conclusion":        rep.SigConclusion,
		"signed":                rep.Signed,
		"allowed_unverified":    rep.AllowedUnverified,
		"planned_bytes":         rep.PlannedBytes,
		"plan_total":            len(plan),
		"needs_reinstall_total": len(reinstall),
		"needs_relogin_total":   len(relogin),
		"problems":              problems,
		"warnings":              rep.Warnings,
	}
	fitList(res, "plan", plan, 200, func(n int, truncated bool) {
		res["plan_returned"] = n
		res["truncated"] = truncated
		res["source"] = sourceFor(scanMeta{Manifest: s.pkg}, truncated)
	})
	if len(reinstall) > 0 || len(relogin) > 0 {
		fitList(res, "needs_reinstall", reinstall, 200, func(n int, truncated bool) {
			res["needs_reinstall_returned"] = n
			if truncated {
				res["truncated"] = true
				res["source"] = s.pkg
			}
		})
		fitList(res, "needs_relogin", relogin, 200, func(n int, truncated bool) {
			res["needs_relogin_returned"] = n
			if truncated {
				res["truncated"] = true
				res["source"] = s.pkg
			}
		})
		enforceBound(res, "needs_relogin", relogin, s.pkg)
		enforceBound(res, "needs_reinstall", reinstall, s.pkg)
	}
	enforceBound(res, "plan", plan, s.pkg)
	return res, nil
}

func restorePlanCode(err error) string {
	switch {
	case errors.Is(err, restore.ErrUnverified):
		return "package_unverified"
	case errors.Is(err, restore.ErrTampered):
		return "package_tampered"
	case errors.Is(err, restore.ErrDecrypt):
		return "decrypt_failed"
	case errors.Is(err, restore.ErrDestNotEmpty):
		return "target_not_empty"
	case errors.Is(err, restore.ErrUsage):
		return "bad_target"
	case errors.Is(err, restore.ErrCanceled):
		return "canceled"
	default:
		return "restore_plan_failed"
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fitList stores the longest prefix of items that keeps res within
// MaxResultBytes. fn is invoked for every candidate so flags such as
// truncated/source/next_offset are part of the measurement. It returns the
// number of items kept.
func fitList(res map[string]any, key string, items []any, reserve int, fn func(n int, truncated bool)) int {
	sizes := make([]int, len(items))
	for i := range items {
		b, err := marshalNoEscape(items[i])
		if err != nil {
			sizes[i] = MaxResultBytes
			continue
		}
		sizes[i] = len(b)
	}
	measure := func(n int) bool {
		res[key] = items[:n]
		fn(n, n < len(items))
		b, err := marshalNoEscape(res)
		if err != nil {
			return false
		}
		return len(b) <= MaxResultBytes-reserve
	}
	// Exponential probe, then binary search, so a huge list costs O(log n)
	// measurements rather than O(n).
	lo, hi := 0, len(items)
	best := 0
	for lo <= hi {
		mid := (lo + hi) / 2
		if measure(mid) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	measure(best)
	return best
}

// enforceBound is the last line of defence after fitList: if the result is
// still too large (base fields alone were expensive), the list is halved and,
// in the worst case, dropped entirely. Tools call it right before returning so
// makeCallResult's result_too_large fallback is never reached in practice.
func enforceBound(res map[string]any, key string, full []any, source string) {
	n := 0
	if kept, ok := res[key].([]any); ok {
		n = len(kept)
	}
	tooBig := func() bool {
		b, err := marshalNoEscape(res)
		return err == nil && len(b) > MaxResultBytes
	}
	for n > 0 && tooBig() {
		n /= 2
		res[key] = full[:n]
		res["truncated"] = true
		res["source"] = source
	}
	if tooBig() {
		delete(res, key)
		res["truncated"] = true
		res["source"] = source
	}
}

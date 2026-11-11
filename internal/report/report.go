// Package report renders a manifest into a self-contained, offline HTML
// report and serves it on loopback for the P0 trust UI.
//
// Security invariants implemented here (threat model B, INV-B01..B11):
//   - the HTML is a single file: inline CSS and JS, no external subresources;
//   - the CSP meta is `default-src 'none'; style-src 'unsafe-inline';
//     script-src 'nonce-…'`; the only anchors are official-docs links from
//     signals and they carry rel="noopener noreferrer";
//   - every string that came from a scan is escaped by html/template in its
//     own context; report JS never uses innerHTML;
//   - a secret is only ever shown as its non-secret prefix and fingerprint,
//     never as a complete value (the manifest does not contain one);
//   - the residual message required by D-021 §7 is always rendered.
//
// The package only reads a manifest (D-005): it never imports scan or pack.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"packout/internal/manifest"
)

// Options controls rendering. The zero value is a safe, quiet report with
// signals omitted; callers normally set IncludeSignals.
type Options struct {
	// RedactPaths folds absolute paths under a declared root to `~`-relative
	// form and scrubs user-home segments outside roots (D-008 §10).
	RedactPaths bool
	// IncludeSignals renders every conclusion's evidence and source links.
	IncludeSignals bool
	// Title overrides the document title.
	Title string
	// OnReady, when non-nil, is called by Serve with the one-time URL as soon
	// as the listener is bound. It replaces the default stdout printing, so
	// the caller controls where the URL goes (D-033 §5).
	OnReady func(url string)

	// lan is set through WithLAN. It is unexported so the public shape stays
	// exactly {RedactPaths, IncludeSignals, Title} while Serve can still bind
	// 0.0.0.0 and render the "exposed to LAN" warning.
	lan bool
}

// WithLAN returns a copy of o that makes Serve bind 0.0.0.0 and makes Render
// put a prominent warning at the top of the page (D-008 §4).
func (o Options) WithLAN(v bool) Options {
	o.lan = v
	return o
}

// LAN reports whether the LAN warning/binding is enabled.
func (o Options) LAN() bool { return o.lan }

// pageSize bounds one collapsible page of a long list. It is a variable so
// tests can exercise pagination cheaply.
var pageSize = 200

// reportTmpl is parsed once; a parse failure is a programmer error.
var reportTmpl = template.Must(template.New("report").Parse(reportHTML))

// Render writes a complete single-file HTML report for m to w.
//
// The output is a pure function of (m, opts): no clock other than the
// manifest's own timestamps and no randomness are used, so the same inputs
// produce byte-identical output. The CSP nonce is derived from the manifest,
// not from a CSPRNG, precisely to keep that property; the nonce only has to
// authorize our own static script and carries no authority.
func Render(w io.Writer, m *manifest.Doc, opts Options) error {
	b, err := renderBytes(m, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// renderBytes is Render's implementation, reused by Serve so it renders once.
func renderBytes(m *manifest.Doc, opts Options) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("report: nil manifest")
	}
	v := buildView(m, opts)
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("report: render: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- view model -----------------------------------------------------------

type view struct {
	Title    string
	Nonce    string
	LAN      bool
	Redacted bool

	ScanID     string
	Generated  string
	StartedAt  string
	EndedAt    string
	Machine    string
	Tool       string
	Duration   string
	Complete   string
	ErrorCount int64

	TotalUnits     int64
	Residuals      int64
	DeleteCount    int
	ReclaimBytes   int64
	ReclaimText    string
	L0Count        int
	L0Bytes        int64
	L0Text         string
	L1Count        int
	L1Bytes        int64
	L1Text         string
	Unversioned    int
	L5Count        int
	SecretHits     int
	MayOnlySecrets int

	ContainsSecrets bool
	ContainsText    string

	L5                 []l5Row
	UnversionedRows    []basicRow
	Secrets            []secretRow
	SecretPages        []secretPage
	SecretTruncated    bool
	ResidualRows       []basicRow
	ResidualPages      []basicPage
	DetailPages        []detailPage
	Notes              []noteRow
	Skipped            []skipRow
	SkippedPages       []skipPage
	HasSkipped         bool
	ShowSkippedDetails bool
	SkippedSummary     []skipCount
	SelectionText      string
	HasDetails         bool
}

type signalView struct {
	Src  string
	Note string
	URL  string
	Link bool
}

type l5Row struct {
	Path        string
	Entry       string
	Profiles    string
	Official    string
	OfficialURL string
	Prereq      string
	Confidence  string
	Secret      string
}

type basicRow struct {
	Path       string
	Layer      string
	Action     string
	Entry      string
	Profiles   string
	SizeText   string
	CountText  string
	Confidence string
	Flags      string
	Note       string
}

type secretRow struct {
	Path        string
	Locator     string
	Kind        string
	Class       string
	Mask        string
	Fingerprint string
	Note        string
}

type detailRow struct {
	Path        string
	Layer       string
	Action      string
	Confidence  string
	Entry       string
	Profiles    string
	Flags       string
	SecretClass string
	Signals     []signalView
}

type noteRow struct {
	Code    string
	Profile string
	Entry   string
	Detail  string
}

// skipRow is one entry the scan deliberately left out ("本次未带走").
type skipRow struct {
	Entry    string
	Category string
	Reason   string
}

type skipPage struct {
	Label string
	Open  bool
	Rows  []skipRow
}

// skipCount is one category line of the skipped summary.
type skipCount struct {
	Category string
	Count    int
}

type basicPage struct {
	Label string
	Open  bool
	Rows  []basicRow
}

type secretPage struct {
	Label string
	Open  bool
	Rows  []secretRow
}

type detailPage struct {
	Label string
	Open  bool
	Rows  []detailRow
}

// ---- aggregation (spec §5.3: the report merges by path_key) ---------------

type aggUnit struct {
	u        manifest.Unit
	profiles []string
	seenSig  map[string]bool
	seenFlag map[string]bool
}

func sigKey(s manifest.Signal) string {
	u := ""
	if s.URL != nil {
		u = *s.URL
	}
	return s.Src + "\x00" + s.Note + "\x00" + u
}

func (a *aggUnit) merge(u manifest.Unit) {
	if u.Profile != "" && !contains(a.profiles, u.Profile) {
		a.profiles = append(a.profiles, u.Profile)
	}
	for _, s := range u.Signals {
		k := sigKey(s)
		if !a.seenSig[k] {
			a.seenSig[k] = true
			a.u.Signals = append(a.u.Signals, s)
		}
	}
	for _, f := range u.RiskFlags {
		if !a.seenFlag[f] {
			a.seenFlag[f] = true
			a.u.RiskFlags = append(a.u.RiskFlags, f)
		}
	}
	a.u.Secret = mergeSecret(a.u.Secret, u.Secret)
	a.u.ContainsSecret = orBool(a.u.ContainsSecret, u.ContainsSecret)
	a.u.MayContainSecret = orBool(a.u.MayContainSecret, u.MayContainSecret)
	a.u.AggregateCount = maxInt64(a.u.AggregateCount, u.AggregateCount)
	a.u.SizeAlloc = maxInt64(a.u.SizeAlloc, u.SizeAlloc)
	a.u.SizeApparent = maxInt64(a.u.SizeApparent, u.SizeApparent)
	if layerRank(u.Layer) > layerRank(a.u.Layer) {
		a.u.Layer = u.Layer
		a.u.ProposedAction = u.ProposedAction
		a.u.Confidence = u.Confidence
		a.u.Entry = u.Entry
		a.u.Kind = u.Kind
		a.u.SecretRef = u.SecretRef
	}
}

func orBool(a, b *bool) *bool {
	if a != nil && *a {
		return a
	}
	if b != nil && *b {
		return b
	}
	if a != nil {
		return a
	}
	return b
}

func maxInt64(a, b *int64) *int64 {
	if a == nil {
		return b
	}
	if b == nil || *a >= *b {
		return a
	}
	return b
}

func mergeSecret(dst, src *manifest.Secret) *manifest.Secret {
	if src == nil {
		return dst
	}
	if dst == nil {
		cp := *src
		cp.Hits = append([]manifest.SecretHit(nil), src.Hits...)
		return &cp
	}
	seen := make(map[string]bool, len(dst.Hits))
	for _, h := range dst.Hits {
		seen[secretKey(h)] = true
	}
	for _, h := range src.Hits {
		if !seen[secretKey(h)] {
			seen[secretKey(h)] = true
			dst.Hits = append(dst.Hits, h)
		}
	}
	dst.HitCount = len(dst.Hits)
	dst.Truncated = dst.Truncated || src.Truncated
	if secretRank(src.Class) > secretRank(dst.Class) {
		dst.Class = src.Class
	}
	return dst
}

func secretKey(h manifest.SecretHit) string {
	return h.Kind + "\x00" + h.Class + "\x00" + h.Locator + "\x00" + h.Prefix + "\x00" + h.Fingerprint
}

func secretRank(c string) int {
	switch c {
	case manifest.SecretNone:
		return 0
	case manifest.SecretReference:
		return 1
	case manifest.SecretScan:
		return 2
	case manifest.SecretRestore:
		return 3
	case manifest.SecretRelogin:
		return 4
	}
	return 0
}

func layerRank(l string) int {
	switch l {
	case manifest.LayerL0:
		return 0
	case manifest.LayerL1:
		return 1
	case manifest.LayerL2:
		return 2
	case manifest.LayerL3:
		return 3
	case manifest.LayerL4:
		return 4
	case manifest.LayerL5:
		return 5
	}
	return 2 // unknown layers are read as L2 (D-027 §2)
}

func aggregateUnits(units []manifest.Unit) []*aggUnit {
	byKey := make(map[string]*aggUnit, len(units))
	out := make([]*aggUnit, 0, len(units))
	for i := range units {
		u := units[i]
		key := u.PathKey
		if key == "" {
			key = u.Path
		}
		if key == "" {
			key = u.ID
		}
		if a, ok := byKey[key]; ok {
			a.merge(u)
			continue
		}
		a := &aggUnit{
			u:        u,
			profiles: []string{u.Profile},
			seenSig:  make(map[string]bool, len(u.Signals)),
			seenFlag: make(map[string]bool, len(u.RiskFlags)),
		}
		for _, s := range u.Signals {
			a.seenSig[sigKey(s)] = true
		}
		for _, f := range u.RiskFlags {
			a.seenFlag[f] = true
		}
		byKey[key] = a
		out = append(out, a)
	}
	return out
}

// ---- view construction ----------------------------------------------------

func buildView(m *manifest.Doc, opts Options) *view {
	aggs := aggregateUnits(m.Units)
	v := &view{
		Title:     opts.Title,
		Nonce:     deriveNonce(m, opts),
		LAN:       opts.lan,
		Redacted:  opts.RedactPaths,
		ScanID:    m.Header.ScanID,
		Tool:      m.Header.Tool,
		Machine:   machineString(m.Header.Host),
		StartedAt: fmtTime(m.Header.StartedAt),
		EndedAt:   fmtTime(m.Footer.EndedAt),
	}
	if v.Title == "" {
		v.Title = "packout 扫描报告"
	}
	if !m.Header.StartedAt.IsZero() && !m.Footer.EndedAt.IsZero() {
		d := m.Footer.EndedAt.Sub(m.Header.StartedAt)
		if d < 0 {
			d = 0
		}
		v.Duration = d.Round(time.Second).String()
	} else {
		v.Duration = "—"
	}
	v.Generated = v.EndedAt
	if v.Generated == "—" {
		v.Generated = v.StartedAt
	}
	v.Complete = "是"
	if !m.Footer.Complete {
		v.Complete = "否（扫描有未处理错误）"
	}
	v.ErrorCount = m.Footer.Errors

	v.TotalUnits = m.Footer.Units
	if v.TotalUnits == 0 {
		v.TotalUnits = int64(len(m.Units))
	}
	v.Residuals = m.Footer.Stats.Residual
	// The footer is authoritative, but a hand-built document may omit stats.
	if v.Residuals == 0 {
		for _, a := range aggs {
			if a.u.Kind == manifest.KindCatchAll {
				v.Residuals++
			}
		}
	}

	for _, a := range aggs {
		u := &a.u
		path := displayPath(u.Path, m, opts)
		flags := strings.Join(u.RiskFlags, ", ")
		conf := fmtConfidence(u.Confidence)
		profiles := strings.Join(a.profiles, ", ")

		// Volume accounting uses allocation size, never apparent size.
		if u.SizeAlloc != nil {
			switch u.Layer {
			case manifest.LayerL0:
				v.L0Count++
				v.L0Bytes += *u.SizeAlloc
			case manifest.LayerL1:
				v.L1Count++
				v.L1Bytes += *u.SizeAlloc
			}
			if u.ProposedAction == manifest.ActionDelete {
				v.DeleteCount++
				v.ReclaimBytes += *u.SizeAlloc
			}
		}

		if hasSecret(u) {
			v.SecretHits += len(u.Secret.Hits)
		}
		if u.MayContainSecret != nil && *u.MayContainSecret &&
			!(u.ContainsSecret != nil && *u.ContainsSecret) && !hasSecret(u) {
			v.MayOnlySecrets++
		}

		// L5: items that need a manual re-login on the new machine.
		if u.Layer == manifest.LayerL5 || u.ProposedAction == manifest.ActionRelogin {
			v.L5 = append(v.L5, l5Row{
				Path:        path,
				Entry:       u.Entry,
				Profiles:    profiles,
				Official:    officialText(u.Signals),
				OfficialURL: officialURL(u.Signals),
				Prereq:      prereqText(u.Signals),
				Confidence:  conf,
				Secret:      secretClass(u),
			})
			v.L5Count++
		}

		// Core finding: unversioned L2/L3.
		if (u.Layer == manifest.LayerL2 || u.Layer == manifest.LayerL3) &&
			!hasFlag(u, "git_tracked") &&
			(hasFlag(u, "not_versioned") || hasFlag(u, "gitignored")) {
			v.UnversionedRows = append(v.UnversionedRows, basicRow{
				Path: path, Layer: u.Layer, Action: u.ProposedAction, Entry: u.Entry,
				Profiles: profiles, SizeText: allocText(u.SizeAlloc), Confidence: conf,
				Flags: flags, Note: u.Notes,
			})
			v.Unversioned++
		}

		// Credential locations: mask and fingerprint only.
		if hasSecret(u) {
			for _, h := range u.Secret.Hits {
				n := ""
				if h.Kind == "entropy" {
					n = "低置信（熵兜底）"
				}
				if u.Secret.Truncated {
					if n != "" {
						n += "；"
					}
					n += "命中已截断"
				}
				class := h.Class
				if class == "" {
					class = u.Secret.Class
				}
				v.Secrets = append(v.Secrets, secretRow{
					Path: path, Locator: h.Locator, Kind: h.Kind, Class: class,
					Mask: maskOf(h.Prefix), Fingerprint: h.Fingerprint, Note: n,
				})
			}
			if u.Secret.Truncated {
				v.SecretTruncated = true
			}
		}

		// Residual (catch-all) detail.
		if u.Kind == manifest.KindCatchAll {
			count := "—"
			if u.AggregateCount != nil {
				count = strconv.FormatInt(*u.AggregateCount, 10) + " 个后代"
			}
			v.ResidualRows = append(v.ResidualRows, basicRow{
				Path: path, Layer: u.Layer, Action: u.ProposedAction, Entry: u.Entry,
				Profiles: profiles, SizeText: allocText(u.SizeAlloc), CountText: count,
				Confidence: conf, Flags: flags, Note: u.Notes,
			})
		}
	}

	// One detail row per conclusion, carrying every signal and source link.
	if opts.IncludeSignals {
		var rows []detailRow
		for _, a := range aggs {
			u := &a.u
			sigs := make([]signalView, 0, len(u.Signals))
			for _, s := range u.Signals {
				sigs = append(sigs, signalView{
					Src: s.Src, Note: s.Note, URL: urlText(s.URL), Link: linkable(s.URL),
				})
			}
			rows = append(rows, detailRow{
				Path: displayPath(u.Path, m, opts), Layer: u.Layer, Action: u.ProposedAction,
				Confidence: fmtConfidence(u.Confidence), Entry: u.Entry,
				Profiles: strings.Join(a.profiles, ", "), Flags: strings.Join(u.RiskFlags, ", "),
				SecretClass: secretClass(u), Signals: sigs,
			})
		}
		v.DetailPages = paginateDetails(rows)
		v.HasDetails = true
	}

	v.ReclaimText = humanBytes(v.ReclaimBytes)
	v.L0Text = humanBytes(v.L0Bytes)
	v.L1Text = humanBytes(v.L1Bytes)

	v.ContainsSecrets = v.SecretHits > 0
	if v.ContainsSecrets {
		v.ContainsText = "是（仅显示掩码与位置，不含完整值）"
	} else {
		v.ContainsText = "未发现（仍不排除残留项未做内容级检测）"
	}

	v.SecretPages = paginateSecrets(v.Secrets)
	v.ResidualPages = paginateBasic(v.ResidualRows)

	for _, n := range m.Notes {
		if n.Code == "selection_skipped" {
			v.Skipped = append(v.Skipped, skipRow{
				Entry: n.Entry, Category: n.Category, Reason: n.Detail,
			})
			continue
		}
		v.Notes = append(v.Notes, noteRow{
			Code: n.Code, Profile: n.Profile, Entry: n.Entry, Detail: n.Detail,
		})
	}
	v.HasSkipped = len(v.Skipped) > 0
	v.SelectionText = selectionText(m)
	v.ShowSkippedDetails = m.Header.Inputs.Options != nil && m.Header.Inputs.Options.Selection != nil
	byCat := make(map[string]int)
	for _, r := range v.Skipped {
		byCat[r.Category]++
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		v.SkippedSummary = append(v.SkippedSummary, skipCount{Category: c, Count: byCat[c]})
	}
	if v.ShowSkippedDetails {
		v.SkippedPages = paginateSkips(v.Skipped)
	} else {
		// The default selection skips every session path; a count per
		// category beats thousands of rows.
		v.Skipped = nil
	}
	return v
}

// selectionText summarises inputs.options.selection for the report banner.
func selectionText(m *manifest.Doc) string {
	if m.Header.Inputs.Options == nil || m.Header.Inputs.Options.Selection == nil {
		return "standard（配置 + 记忆）"
	}
	s := m.Header.Inputs.Options.Selection
	preset := s.Preset
	if preset == "" {
		preset = "standard"
	}
	out := "preset " + preset
	if len(s.Include) > 0 {
		out += "；include " + strings.Join(s.Include, ", ")
	}
	if len(s.Exclude) > 0 {
		out += "；exclude " + strings.Join(s.Exclude, ", ")
	}
	if s.SessionsSince != "" && s.SessionsSince != "all" {
		out += "；会话仅 " + s.SessionsSince + " 内"
	}
	if len(s.SessionsProjects) > 0 {
		out += "；项目 " + strings.Join(s.SessionsProjects, ", ")
	}
	if s.SessionsMaxPerProject > 0 {
		out += "；每项目最多 " + strconv.Itoa(s.SessionsMaxPerProject) + " 个"
	}
	return out
}

func hasSecret(u *manifest.Unit) bool {
	return u.Secret != nil && len(u.Secret.Hits) > 0
}

func secretClass(u *manifest.Unit) string {
	if u.Secret == nil || u.Secret.Class == "" {
		return "none"
	}
	return u.Secret.Class
}

func hasFlag(u *manifest.Unit, f string) bool {
	for _, x := range u.RiskFlags {
		if x == f {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func officialText(sigs []manifest.Signal) string {
	var out []string
	for _, s := range sigs {
		if s.Src == "official_docs" {
			out = append(out, s.Note)
		}
	}
	if len(out) == 0 {
		return "—"
	}
	return strings.Join(out, "；")
}

func officialURL(sigs []manifest.Signal) string {
	for _, s := range sigs {
		if s.Src == "official_docs" && s.URL != nil {
			return *s.URL
		}
	}
	return ""
}

func prereqText(sigs []manifest.Signal) string {
	var out []string
	for _, s := range sigs {
		switch s.Src {
		case "probe_result", "filesystem_stat", "content_match":
			out = append(out, s.Note)
		}
	}
	if len(out) == 0 {
		return "—"
	}
	return strings.Join(out, "；")
}

func displayPath(p string, m *manifest.Doc, opts Options) string {
	if !opts.RedactPaths {
		return p
	}
	return redactPath(p, m)
}

// ---- redaction ------------------------------------------------------------

var (
	reWinUsers = regexp.MustCompile(`(?i)^([A-Za-z]:\\Users\\)[^\\]+`)
	reMacUsers = regexp.MustCompile(`^(/Users/)[^/]+`)
	reHome     = regexp.MustCompile(`^(/home/)[^/]+`)
)

// redactPath folds a path under its declared root to `~`-relative form and
// scrubs user-home segments that are outside every root. It is best-effort:
// redaction lowers recognisability, it does not make the report shareable.
func redactPath(p string, m *manifest.Doc) string {
	if p == "" {
		return p
	}
	// named-location URIs such as wincred:Target are not filesystem paths.
	// A Windows drive path ("C:\..." or "c:/...") is the one colon-before-
	// separator shape that is not a URI.
	if i := strings.IndexByte(p, ':'); i > 0 && !strings.ContainsAny(p[:i], `\/`) {
		drive := i == 1 && isASCIILetter(p[0]) && len(p) > 2 && (p[2] == '\\' || p[2] == '/')
		if !drive {
			return p
		}
	}
	roots := append([]manifest.Root(nil), m.Header.Roots...)
	sort.SliceStable(roots, func(i, j int) bool { return len(roots[i].Path) > len(roots[j].Path) })
	insensitive := strings.EqualFold(m.Header.Host.CaseSensitivity, "insensitive")
	for _, r := range roots {
		rp := strings.TrimRight(r.Path, `\/`)
		if rp == "" || len(p) < len(rp) {
			continue
		}
		if !prefixFold(p[:len(rp)], rp, insensitive) {
			continue
		}
		rest := p[len(rp):]
		if rest != "" && rest[0] != '\\' && rest[0] != '/' {
			continue
		}
		label := "~"
		if !strings.EqualFold(r.Role, "home") {
			label = "[" + r.Name + "]"
		}
		return label + rest
	}
	if loc := reWinUsers.FindStringSubmatchIndex(p); loc != nil {
		return p[:loc[3]] + "…" + p[loc[1]:]
	}
	if loc := reMacUsers.FindStringSubmatchIndex(p); loc != nil {
		return p[:loc[3]] + "…" + p[loc[1]:]
	}
	if loc := reHome.FindStringSubmatchIndex(p); loc != nil {
		return p[:loc[3]] + "…" + p[loc[1]:]
	}
	return p
}

func prefixFold(s, prefix string, insensitive bool) bool {
	if len(s) != len(prefix) {
		return false
	}
	if insensitive {
		return strings.EqualFold(s, prefix)
	}
	return s == prefix
}

func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// ---- formatting -----------------------------------------------------------

func humanBytes(n int64) string {
	if n < 0 {
		return "不可得"
	}
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
}

func allocText(p *int64) string {
	if p == nil {
		return "—"
	}
	return humanBytes(*p)
}

func fmtConfidence(c float64) string {
	return strconv.FormatFloat(c, 'f', 3, 64)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func machineString(h manifest.Host) string {
	parts := make([]string, 0, 3)
	if h.OS != "" {
		parts = append(parts, h.OS)
	}
	if h.Arch != "" {
		parts = append(parts, h.Arch)
	}
	m := strings.Join(parts, "/")
	if h.OSVersion != "" {
		if m != "" {
			m += " "
		}
		m += "(" + h.OSVersion + ")"
	}
	if m == "" {
		m = "未声明"
	}
	return m
}

// maskOf renders the only secret material a manifest retains: the known
// non-secret prefix (<=7 chars) and, separately, the salted fingerprint.
// D-025 §1 masks as 前4…后4; the manifest stores no suffix (spec §9.2), so the
// report shows the prefix followed by an ellipsis and never invents a tail.
func maskOf(prefix string) string {
	if prefix == "" {
		return "…"
	}
	r := []rune(prefix)
	if len(r) > 7 {
		r = r[:7]
	}
	return string(r) + "…"
}

func urlText(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// linkable reports whether a signal URL may be rendered as an anchor. Only
// http(s) URLs qualify; every other scheme stays text.
func linkable(p *string) bool {
	if p == nil {
		return false
	}
	u, err := url.Parse(*p)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

// ---- pagination -----------------------------------------------------------

func paginateDetails(rows []detailRow) []detailPage {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) <= pageSize {
		return []detailPage{{Open: true, Rows: rows}}
	}
	var out []detailPage
	for start := 0; start < len(rows); start += pageSize {
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}
		out = append(out, detailPage{
			Label: fmt.Sprintf("第 %d–%d 条（共 %d 条）", start+1, end, len(rows)),
			Open:  start == 0,
			Rows:  rows[start:end],
		})
	}
	return out
}

func paginateBasic(rows []basicRow) []basicPage {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) <= pageSize {
		return []basicPage{{Open: true, Rows: rows}}
	}
	var out []basicPage
	for start := 0; start < len(rows); start += pageSize {
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}
		out = append(out, basicPage{
			Label: fmt.Sprintf("第 %d–%d 条（共 %d 条）", start+1, end, len(rows)),
			Open:  start == 0,
			Rows:  rows[start:end],
		})
	}
	return out
}

func paginateSkips(rows []skipRow) []skipPage {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) <= pageSize {
		return []skipPage{{Open: true, Rows: rows}}
	}
	var out []skipPage
	for start := 0; start < len(rows); start += pageSize {
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}
		out = append(out, skipPage{
			Label: fmt.Sprintf("第 %d–%d 条（共 %d 条）", start+1, end, len(rows)),
			Open:  start == 0,
			Rows:  rows[start:end],
		})
	}
	return out
}

func paginateSecrets(rows []secretRow) []secretPage {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) <= pageSize {
		return []secretPage{{Open: true, Rows: rows}}
	}
	var out []secretPage
	for start := 0; start < len(rows); start += pageSize {
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}
		out = append(out, secretPage{
			Label: fmt.Sprintf("第 %d–%d 条（共 %d 条）", start+1, end, len(rows)),
			Open:  start == 0,
			Rows:  rows[start:end],
		})
	}
	return out
}

// deriveNonce produces a stable nonce for the inline script. Determinism is a
// deliberate trade-off: a golden report must be byte-stable, and the nonce
// authorizes only this package's static script, not caller data.
func deriveNonce(m *manifest.Doc, opts Options) string {
	h := sha256.New()
	io.WriteString(h, "packout-report\x00")
	io.WriteString(h, m.Header.ScanID)
	h.Write([]byte{0})
	io.WriteString(h, m.Header.StartedAt.UTC().Format(time.RFC3339Nano))
	h.Write([]byte{0})
	io.WriteString(h, m.Footer.EndedAt.UTC().Format(time.RFC3339Nano))
	h.Write([]byte{0})
	io.WriteString(h, opts.Title)
	if opts.lan {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

package secret

import (
	"bytes"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Rule names are stable identifiers. They appear in Hit.Rule and are meant to
// be logged as evidence; do not rename without a migration note.
const (
	RulePrivateKey   = "pem-private-key"
	RuleAnthropicKey = "anthropic-key"
	RuleOpenAIKey    = "openai-key"
	RuleGitHubPAT    = "github-pat"
	RuleGitHubToken  = "github-token"
	RuleAWSAccessKey = "aws-access-key"
	RuleSlackToken   = "slack-token"
	RuleGoogleAPIKey = "google-api-key"
	RuleJWT          = "jwt"
	RuleAuthBearer   = "auth-bearer"
	RuleEnvRef       = "env-ref"
	RuleOnePassword  = "op-ref"
	RuleMasked       = "masked-value"
	RuleMCPEnv       = "mcp-env"
	RuleJSONKey      = "json-key"
	RuleTOMLKey      = "toml-key"
	RuleDotenvKey    = "dotenv-key"
	RuleHighEntropy  = "high-entropy"
)

// Priority ordering is fixed: a higher priority candidate wins an overlap.
// Reference-like rules sit above keyed rules so that a value which is only a
// pointer is never mistaken for plaintext and redacted.
const (
	prioPrivateKey  = 100
	prioAnthropic   = 98
	prioGitHubPAT   = 97
	prioGitHub      = 96
	prioAWS         = 95
	prioSlack       = 94
	prioGoogle      = 93
	prioJWT         = 90
	prioBearer      = 88
	prioOnePassword = 86
	prioEnvRef      = 85
	prioMasked      = 84
	prioMCPEnv      = 70
	prioJSONKey     = 60
	prioTOMLKey     = 58
	prioDotenvKey   = 56
	prioEntropy     = 10
)

const (
	minKeyedValue = 12 // shorter keyed values are the "key: value" false-positive class
	minMCPValue   = 8
	entropyMinLen = 24
	maxCandidates = 4096
)

// Detect scans b for credentials and returns hits ordered by ascending
// offset. name is a file name hint (base name, either separator) used only for
// ".mcp.json"; it never affects the byte ranges otherwise. b is not modified.
//
// The entropy fallback is on in Detect; use DetectWith to turn it off, or
// DetectWithResult when the caller needs the truncation state.
func Detect(name string, b []byte, maxHits int) []Hit {
	return DetectWith(Options{Entropy: true, MaxHits: maxHits}, name, b)
}

// DetectWith is Detect with explicit options.
func DetectWith(opts Options, name string, b []byte) []Hit {
	return DetectWithResult(opts, name, b).Hits
}

// DetectWithResult is the full detection entry point. Detect and DetectWith
// are thin wrappers over it.
func DetectWithResult(opts Options, name string, b []byte) DetectResult {
	max := opts.MaxHits
	if max <= 0 {
		max = DefaultMaxHits
	}
	if max > HardMaxHits {
		max = HardMaxHits
	}
	if len(b) == 0 {
		return DetectResult{}
	}

	c := &collector{b: b}
	base := strings.ToLower(baseName(name))

	detectPrefixRules(c)
	detectPEM(c)
	detectInlineValues(c)
	detectJSONKeys(c)
	detectKeyedLines(c)
	if base == ".mcp.json" {
		detectMCPEnv(c)
	}
	if opts.Entropy {
		detectEntropy(c)
	}

	return c.finish(max)
}

// ---------------------------------------------------------------------------
// candidate collection and overlap resolution

type candidate struct {
	Hit
	prio int
}

type collector struct {
	b     []byte
	cands []candidate
}

func (c *collector) add(prio int, rule string, class Class, off, length int, prefix, suffix string) {
	if off < 0 || length <= 0 || off+length > len(c.b) {
		return
	}
	if len(c.cands) >= maxCandidates {
		return
	}
	if len(prefix) > 7 {
		prefix = prefix[:7]
	}
	if len(suffix) > 7 {
		suffix = suffix[:7]
	}
	c.cands = append(c.cands, candidate{
		Hit: Hit{
			Class:   class,
			Rule:    rule,
			Offset:  off,
			Length:  length,
			ValueFP: ValueFP(c.b[off : off+length]),
			Prefix:  prefix,
			Suffix:  suffix,
		},
		prio: prio,
	})
}

// addLow adds a hit and marks it as a low-confidence entropy finding.
func (c *collector) addLow(prio int, rule string, class Class, off, length int) {
	n := len(c.cands)
	c.add(prio, rule, class, off, length, "", "")
	if len(c.cands) > n {
		c.cands[len(c.cands)-1].LowConfidence = true
	}
}

// finish resolves overlaps, sorts by offset and applies the hit limit.
//
// A candidate is dropped when it partially overlaps an accepted hit, or when it
// is equal to or inside one. A candidate that strictly contains an accepted hit
// is accepted too: Redact masks the union of ranges, so keeping the wider range
// is what prevents a keyed value from leaving plaintext around an inner token
// (D-025 §7). Redact is the authority on masking; duplicates only widen the
// union, never narrow it.
func (c *collector) finish(max int) DetectResult {
	cands := c.cands
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].prio != cands[j].prio {
			return cands[i].prio > cands[j].prio
		}
		if cands[i].Offset != cands[j].Offset {
			return cands[i].Offset < cands[j].Offset
		}
		if cands[i].Length != cands[j].Length {
			return cands[i].Length > cands[j].Length
		}
		return cands[i].Rule < cands[j].Rule
	})

	accepted := make([]Hit, 0, minInt(len(cands), max))
	dropped := 0
	for i := range cands {
		cand := cands[i].Hit
		overlaps, containsAll := false, true
		for _, a := range accepted {
			if !intersects(cand, a) {
				continue
			}
			overlaps = true
			if !strictlyContains(cand, a) {
				containsAll = false
				break
			}
		}
		if overlaps && !containsAll {
			continue
		}
		if len(accepted) >= max {
			dropped++
			continue
		}
		accepted = append(accepted, cand)
	}

	sort.SliceStable(accepted, func(i, j int) bool {
		if accepted[i].Offset != accepted[j].Offset {
			return accepted[i].Offset < accepted[j].Offset
		}
		if accepted[i].Length != accepted[j].Length {
			return accepted[i].Length > accepted[j].Length
		}
		return accepted[i].Rule < accepted[j].Rule
	})

	return DetectResult{
		Hits:      accepted,
		Truncated: dropped > 0 || len(c.cands) >= maxCandidates,
		Dropped:   dropped,
	}
}

func intersects(a, b Hit) bool {
	return a.Offset < b.End() && b.Offset < a.End()
}

// strictlyContains reports outer contains inner and is not the same range.
func strictlyContains(outer, inner Hit) bool {
	return outer.Offset <= inner.Offset && outer.End() >= inner.End() &&
		(outer.Offset < inner.Offset || outer.End() > inner.End())
}

func baseName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// byte predicates

func isAlnum(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func isKeyChar(ch byte) bool { // [A-Za-z0-9_-]
	return isAlnum(ch) || ch == '_' || ch == '-'
}

func isTokenChar(ch byte) bool { // [A-Za-z0-9_]
	return isAlnum(ch) || ch == '_'
}

func isB64URL(ch byte) bool {
	return isAlnum(ch) || ch == '-' || ch == '_'
}

func isWordByte(ch byte) bool { return isAlnum(ch) || ch == '_' }

func wordStart(b []byte, i int) bool { return i == 0 || !isWordByte(b[i-1]) }

func foldEqualAt(b []byte, i int, lit string) bool {
	if i+len(lit) > len(b) {
		return false
	}
	for j := 0; j < len(lit); j++ {
		ch := b[i+j]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != lit[j] {
			return false
		}
	}
	return true
}

func runWhile(b []byte, i int, pred func(byte) bool) int {
	for i < len(b) && pred(b[i]) {
		i++
	}
	return i
}

// ---------------------------------------------------------------------------
// known-prefix rules

// detectPrefixRules does one literal prefilter pass per known prefix and then
// validates the run by hand. Regexp scanning over whole files is the dominant
// cost otherwise, and these shapes are simple enough to validate directly.
func detectPrefixRules(c *collector) {
	b := c.b
	for i := 0; ; {
		rel := bytes.Index(b[i:], []byte("sk-ant-"))
		if rel < 0 {
			break
		}
		at := i + rel
		if wordStart(b, at) {
			end := runWhile(b, at+7, isKeyChar)
			if end-(at+7) >= 20 {
				c.add(prioAnthropic, RuleAnthropicKey, Restore, at, end-at, "sk-ant-", "")
			}
		}
		i = at + 7
	}
	for i := 0; ; {
		rel := bytes.Index(b[i:], []byte("sk-"))
		if rel < 0 {
			break
		}
		at := i + rel
		i = at + 3
		if !wordStart(b, at) {
			continue
		}
		j := at + 3
		for _, opt := range []string{"proj-", "svcacct-"} {
			if j+len(opt) <= len(b) && string(b[j:j+len(opt)]) == opt {
				j += len(opt)
				break
			}
		}
		end := runWhile(b, j, isKeyChar)
		if end-j >= 20 {
			c.add(prioAnthropic-1, RuleOpenAIKey, Restore, at, end-at, "sk-", "")
		}
	}
	for i := 0; ; {
		rel := bytes.Index(b[i:], []byte("github_pat_"))
		if rel < 0 {
			break
		}
		at := i + rel
		if wordStart(b, at) {
			end := runWhile(b, at+11, isTokenChar)
			if end-(at+11) >= 22 {
				c.add(prioGitHubPAT, RuleGitHubPAT, Restore, at, end-at, "github_", "")
			}
		}
		i = at + 11
	}
	for _, lit := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		for i := 0; ; {
			rel := bytes.Index(b[i:], []byte(lit))
			if rel < 0 {
				break
			}
			at := i + rel
			i = at + len(lit)
			if !wordStart(b, at) {
				continue
			}
			end := runWhile(b, at+len(lit), isAlnum)
			if end-(at+len(lit)) >= 20 {
				c.add(prioGitHub, RuleGitHubToken, Restore, at, end-at, lit, "")
			}
		}
	}
	for _, lit := range []string{"AKIA", "ASIA"} {
		for i := 0; ; {
			rel := bytes.Index(b[i:], []byte(lit))
			if rel < 0 {
				break
			}
			at := i + rel
			i = at + 4
			if !wordStart(b, at) || at+20 > len(b) {
				continue
			}
			ok := true
			for j := at + 4; j < at+20; j++ {
				ch := b[j]
				if !(ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z') {
					ok = false
					break
				}
			}
			if ok && (at+20 == len(b) || !isWordByte(b[at+20])) {
				c.add(prioAWS, RuleAWSAccessKey, Restore, at, 20, lit, "")
			}
		}
	}
	for _, lit := range []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"} {
		for i := 0; ; {
			rel := bytes.Index(b[i:], []byte(lit))
			if rel < 0 {
				break
			}
			at := i + rel
			i = at + len(lit)
			if !wordStart(b, at) {
				continue
			}
			end := runWhile(b, at+len(lit), isKeyChar)
			if end-(at+len(lit)) >= 10 {
				c.add(prioSlack, RuleSlackToken, Restore, at, end-at, lit, "")
			}
		}
	}
	for i := 0; ; {
		rel := bytes.Index(b[i:], []byte("AIza"))
		if rel < 0 {
			break
		}
		at := i + rel
		i = at + 4
		if !wordStart(b, at) || at+4+35 > len(b) {
			continue
		}
		ok := true
		for j := at + 4; j < at+4+35; j++ {
			if !isKeyChar(b[j]) {
				ok = false
				break
			}
		}
		if ok {
			c.add(prioGoogle, RuleGoogleAPIKey, Restore, at, 39, "AIza", "")
		}
	}
	// JWT: eyJ <seg>.<seg>.<seg>, all base64url. "eyJ" is the base64url of "{"
	// and is the known non-secret prefix from the manifest spec.
	for i := 0; ; {
		rel := bytes.Index(b[i:], []byte("eyJ"))
		if rel < 0 {
			break
		}
		at := i + rel
		i = at + 3
		if !wordStart(b, at) {
			continue
		}
		j := runWhile(b, at+3, isB64URL)
		if j-(at+3) < 10 || j >= len(b) || b[j] != '.' {
			continue
		}
		j2 := runWhile(b, j+1, isB64URL)
		if j2-(j+1) < 4 || j2 >= len(b) || b[j2] != '.' {
			continue
		}
		j3 := runWhile(b, j2+1, isB64URL)
		if j3-(j2+1) < 4 {
			continue
		}
		c.add(prioJWT, RuleJWT, Relogin, at, j3-at, "eyJ", "")
	}
}

var (
	pemBegin = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
	pemEnd   = regexp.MustCompile(`-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
)

func detectPEM(c *collector) {
	if !bytes.Contains(c.b, []byte("PRIVATE KEY-----")) {
		return
	}
	for _, loc := range pemBegin.FindAllIndex(c.b, -1) {
		end := len(c.b)
		if m := pemEnd.FindIndex(c.b[loc[1]:]); m != nil {
			end = loc[1] + m[1]
			for end < len(c.b) && c.b[end] != '\n' && c.b[end] != '\r' {
				end++
			}
		}
		c.add(prioPrivateKey, RulePrivateKey, Restore, loc[0], end-loc[0], "-----", "")
	}
}

// ---------------------------------------------------------------------------
// references, masked values and Authorization: Bearer, in one byte pass

func detectInlineValues(c *collector) {
	b := c.b
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '$':
			if i+2 < len(b) && b[i+1] == '{' {
				j := i + 2
				if isAlpha(b[j]) || b[j] == '_' {
					j = runWhile(b, j+1, isTokenChar)
					if j < len(b) && b[j] == '}' {
						c.add(prioEnvRef, RuleEnvRef, Reference, i, j+1-i, "", "")
					}
				}
			}
		case 'o':
			if i+5 < len(b) && string(b[i:i+5]) == "op://" {
				j := runWhile(b, i+5, isRefChar)
				if j-(i+5) >= 3 {
					c.add(prioOnePassword, RuleOnePassword, Reference, i, j-i, "op://", "")
				}
			}
		case '*':
			j := runWhile(b, i, isStar)
			if j-i >= 8 {
				c.add(prioMasked, RuleMasked, None, i, j-i, "", "")
			}
			i = j - 1
		case 0xE2:
			if i+2 < len(b) && b[i+1] == 0x80 && b[i+2] == 0xA2 {
				j := i
				for j+2 < len(b) && b[j] == 0xE2 && b[j+1] == 0x80 && b[j+2] == 0xA2 {
					j += 3
				}
				if (j-i)/3 >= 8 {
					c.add(prioMasked, RuleMasked, None, i, j-i, "", "")
				}
				i = j - 1
			}
		case 'A', 'a':
			if end, ok := matchBearer(b, i); ok {
				c.add(prioBearer, RuleAuthBearer, Restore, i+end[0], end[1]-end[0], "Bearer ", "")
			}
		}
	}
}

func isAlpha(ch byte) bool { return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' }

func isStar(ch byte) bool { return ch == '*' }

func isRefChar(ch byte) bool {
	return isAlnum(ch) || ch == '_' || ch == '.' || ch == '@' || ch == '/' || ch == '-'
}

// matchBearer parses "Authorization: Bearer <token>" case-insensitively at i
// and returns the token's range relative to i.
func matchBearer(b []byte, i int) ([2]int, bool) {
	if !foldEqualAt(b, i, "authorization") {
		return [2]int{}, false
	}
	j := runWhile(b, i+13, isSpaceTab)
	if j >= len(b) || b[j] != ':' {
		return [2]int{}, false
	}
	j = runWhile(b, j+1, isSpaceTab)
	if !foldEqualAt(b, j, "bearer") {
		return [2]int{}, false
	}
	j += 6
	if j >= len(b) || !(b[j] == ' ' || b[j] == '\t') {
		return [2]int{}, false
	}
	j = runWhile(b, j, isSpaceTab)
	start := j
	j = runWhile(b, j, isBearerTokenChar)
	for j > start && b[j-1] == '=' {
		j--
	}
	if j-start < 8 {
		return [2]int{}, false
	}
	return [2]int{start - i, j - i}, true
}

func isSpaceTab(ch byte) bool { return ch == ' ' || ch == '\t' }

func isBearerTokenChar(ch byte) bool {
	return isAlnum(ch) || ch == '.' || ch == '_' || ch == '~' || ch == '+' || ch == '/' || ch == '-' || ch == '='
}

// ---------------------------------------------------------------------------
// keyed rules (JSON, TOML, dotenv, .mcp.json)

func detectJSONKeys(c *collector) {
	b := c.b
	for i := 0; ; {
		rel := bytes.IndexByte(b[i:], '"')
		if rel < 0 {
			return
		}
		i += rel
		kend := skipString(b, i)
		if kend < 0 {
			i++
			continue
		}
		j := skipSpace(b, kend)
		if j >= len(b) || b[j] != ':' {
			i = kend
			continue
		}
		vpos := skipSpace(b, j+1)
		if vpos >= len(b) || b[vpos] != '"' {
			i = j + 1
			continue
		}
		vend := skipString(b, vpos)
		if vend < 0 {
			i = vpos + 1
			continue
		}
		key := string(b[i+1 : kend-1])
		if isSensitiveKey(key) {
			if class, ok := classifyValue(key, b[vpos+1:vend-1]); ok {
				c.add(prioJSONKey, RuleJSONKey, class, vpos+1, vend-1-(vpos+1), "", "")
			}
		}
		i = vend
	}
}

// detectKeyedLines handles dotenv and TOML-style lines in a single pass over
// the file. Both shapes share "key = value"; they differ only in quoting and
// in which rules apply.
func detectKeyedLines(c *collector) {
	b := c.b
	for start := 0; start < len(b); {
		rel := bytes.IndexByte(b[start:], '\n')
		end := len(b)
		if rel >= 0 {
			end = start + rel
		}
		line := b[start:end]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		detectKeyedLine(c, line, start)
		start = end + 1
	}
}

func detectKeyedLine(c *collector, line []byte, lineStart int) {
	eq := bytes.IndexByte(line, '=')
	if eq <= 0 {
		return
	}
	key := strings.TrimSpace(string(line[:eq]))
	if strings.HasPrefix(key, "export ") {
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
	}
	if key == "" || len(key) > 64 || !isTOMLKey(key) || !isSensitiveKey(key) {
		return
	}
	rest := line[eq+1:]
	val := bytes.TrimSpace(rest)
	valOff := eq + 1 + len(rest) - len(bytes.TrimLeft(rest, " \t"))
	quoted := false
	if len(val) >= 2 {
		q := val[0]
		if (q == '"' || q == '\'') && val[len(val)-1] == q {
			val = val[1 : len(val)-1]
			valOff++
			quoted = true
		}
	}
	if len(val) == 0 {
		return
	}
	class, ok := classifyValue(key, val)
	if !ok {
		return
	}
	// A quoted value is both dotenv-style and TOML-style; both rules describe
	// the same range and the TOML priority wins, which keeps the rule name
	// honest for .toml files without losing quoted .env values.
	c.add(prioDotenvKey, RuleDotenvKey, class, lineStart+valOff, len(val), "", "")
	if quoted && isTOMLKey(key) {
		c.add(prioTOMLKey, RuleTOMLKey, class, lineStart+valOff, len(val), "", "")
	}
}

// isTOMLKey reports whether key is a bare or dotted TOML key.
func isTOMLKey(key string) bool {
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// detectMCPEnv treats every string value directly under .mcp.json "env" or
// "headers" as credential material, regardless of its key name. This is the
// structure-level rule the keyed rules cannot express.
func detectMCPEnv(c *collector) {
	for pos := 0; pos < len(c.b); {
		best := -1
		bestLit := ""
		for _, lit := range []string{`"env"`, `"headers"`} {
			rel := bytes.Index(c.b[pos:], []byte(lit))
			if rel < 0 {
				continue
			}
			if best < 0 || pos+rel < best {
				best = pos + rel
				bestLit = lit
			}
		}
		if best < 0 {
			return
		}
		j := skipSpace(c.b, best+len(bestLit))
		if j < len(c.b) && c.b[j] == ':' {
			j = skipSpace(c.b, j+1)
			if j < len(c.b) && c.b[j] == '{' {
				scanMCPObject(c, j+1)
			}
		}
		pos = best + len(bestLit)
	}
}

func scanMCPObject(c *collector, pos int) {
	for pos < len(c.b) {
		pos = skipSpace(c.b, pos)
		if pos >= len(c.b) {
			return
		}
		switch c.b[pos] {
		case '}':
			return
		case ',':
			pos++
			continue
		case '"':
			end := skipString(c.b, pos)
			if end < 0 {
				return
			}
			after := skipSpace(c.b, end)
			if after >= len(c.b) || c.b[after] != ':' {
				pos = end
				continue
			}
			vpos := skipSpace(c.b, after+1)
			if vpos >= len(c.b) || c.b[vpos] != '"' {
				pos = after + 1
				continue
			}
			vend := skipString(c.b, vpos)
			if vend < 0 {
				return
			}
			key := string(c.b[pos+1 : end-1])
			val := c.b[vpos+1 : vend-1]
			if len(val) >= minMCPValue {
				if class, ok := classifyValue(key, val); ok {
					c.add(prioMCPEnv, RuleMCPEnv, class, vpos+1, len(val), "", "")
				}
			}
			pos = vend
		default:
			if c.b[pos] == '{' || c.b[pos] == '[' {
				next := skipNested(c.b, pos)
				if next < 0 {
					return
				}
				pos = next
				continue
			}
			pos++
		}
	}
}

// skipString returns the index just after the closing quote of the JSON string
// starting at i, or -1.
func skipString(b []byte, i int) int {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		case '\n':
			return -1
		}
	}
	return -1
}

// skipNested returns the index just after the balanced close of b[i], or -1.
func skipNested(b []byte, i int) int {
	depth := 0
	for j := i; j < len(b); j++ {
		switch b[j] {
		case '"':
			end := skipString(b, j)
			if end < 0 {
				return -1
			}
			j = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return -1
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	return i
}

// classifyValue decides the class of a keyed value and reports whether it is
// worth emitting at all. Values longer than MaxValueLen are judged on their
// prefix only; the hit and its redaction still cover the whole value.
func classifyValue(key string, val []byte) (Class, bool) {
	judged := val
	if len(judged) > MaxValueLen {
		judged = judged[:MaxValueLen]
	}
	if len(bytes.TrimSpace(judged)) < minKeyedValue {
		return None, false
	}
	if isReference(judged) {
		return Reference, true
	}
	if isMasked(judged) {
		return None, true
	}
	if isReloginKey(key) {
		return Relogin, true
	}
	return Restore, true
}

func isReference(v []byte) bool {
	t := bytes.TrimSpace(v)
	if len(t) >= 3 && t[0] == '$' && t[1] == '{' && t[len(t)-1] == '}' {
		name := t[2 : len(t)-1]
		if len(name) > 0 && len(name) <= 128 && (isAlpha(name[0]) || name[0] == '_') {
			for _, ch := range name[1:] {
				if !isTokenChar(ch) {
					return false
				}
			}
			return true
		}
	}
	if len(t) >= 8 && bytes.HasPrefix(t, []byte("op://")) {
		return true
	}
	return false
}

func isMasked(v []byte) bool {
	t := bytes.TrimSpace(v)
	if len(t) < 8 {
		return false
	}
	for i := 0; i < len(t); {
		if t[i] == '*' {
			i++
			continue
		}
		if i+2 < len(t) && t[i] == 0xE2 && t[i+1] == 0x80 && t[i+2] == 0xA2 {
			i += 3
			continue
		}
		return false
	}
	return true
}

// isSensitiveKey reports whether a key name/path suggests secret material.
// The check is manual because it runs once per line and a regexp here is the
// single hottest operation on large configuration files. "auth" is matched as
// a path component or an auth_* compound rather than as a substring, so that
// package.json "author" fields do not become false positives.
func isSensitiveKey(key string) bool {
	if len(key) == 0 {
		return false
	}
	if len(key) > 128 {
		key = key[:128]
	}
	lk := strings.ToLower(key)
	for _, s := range []string{
		"token", "secret", "passw", "pwd", "credential", "cookie", "apikey",
		"authorization", "bearer",
		"auth_token", "auth-token", "authtoken", "auth_key", "auth-key", "authkey",
	} {
		if strings.Contains(lk, s) {
			return true
		}
	}
	// A "key"/"auth" path component, e.g. key, api_key, ssh-key, auth, auth.key.
	start := 0
	for i := 0; i <= len(lk); i++ {
		if i == len(lk) || !isAlnum(lk[i]) {
			seg := lk[start:i]
			if seg == "key" || seg == "keys" || seg == "auth" {
				return true
			}
			start = i + 1
		}
	}
	// camelCase forms such as accessKey / privateKey / signingKey.
	if len(lk) > 3 && strings.HasSuffix(lk, "key") {
		base := lk[:len(lk)-3]
		for _, q := range []string{
			"api", "access", "private", "public", "secret", "session", "signing",
			"encryption", "client", "app", "master", "service", "account", "token",
			"auth", "license", "ssh", "gpg", "kms", "deploy", "webhook",
		} {
			if base == q || strings.HasSuffix(base, q) {
				return true
			}
		}
	}
	return false
}

func isReloginKey(key string) bool {
	lk := strings.ToLower(key)
	if len(lk) > 128 {
		lk = lk[:128]
	}
	for _, s := range []string{
		"refresh", "oauth", "access_token", "access-token", "access token",
		"session_token", "session-token", "bearer",
	} {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// high-entropy fallback

func detectEntropy(c *collector) {
	b := c.b
	for i := 0; i < len(b); {
		if !entropyByte(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && entropyByte(b[j]) {
			j++
		}
		if j-i >= entropyMinLen && !entropyContextExcluded(b, i) && entropyWorth(b[i:j]) {
			c.addLow(prioEntropy, RuleHighEntropy, Restore, i, j-i)
		}
		i = j
	}
}

func entropyByte(ch byte) bool {
	return isAlnum(ch) || ch == '+' || ch == '/' || ch == '_' || ch == '-'
}

// entropyWorth applies tiered thresholds: longer runs need less entropy per
// character because length itself is evidence, but every run must look like a
// mixed token rather than an identifier, a UUID, a version string or a digest.
func entropyWorth(v []byte) bool {
	if len(v) > 4096 {
		// Long unbroken runs are base64 payloads, not single credentials.
		v = v[:4096]
	}
	// Lockfile integrity values (sha512-<base64>) are hashes, not secrets.
	for _, p := range []string{"sha1-", "sha256-", "sha384-", "sha512-", "md5-", "blake3-"} {
		if foldEqualAt(v, 0, p) {
			return false
		}
	}
	var hasDigit, hasLetter bool
	var seen [256]bool
	distinct := 0
	for _, ch := range v {
		switch {
		case ch >= '0' && ch <= '9':
			hasDigit = true
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
			hasLetter = true
		}
		if !seen[ch] {
			seen[ch] = true
			distinct++
		}
	}
	if !hasDigit || !hasLetter {
		return false
	}
	if isHexRun(v) || isUUID(v) {
		return false
	}
	if distinct < 12 {
		return false
	}
	minEnt := 4.5
	switch {
	case len(v) >= 64:
		minEnt = 3.6
	case len(v) >= 40:
		minEnt = 3.9
	case len(v) >= 28:
		minEnt = 4.2
	}
	return shannon(v) >= minEnt
}

// entropyContextExcluded suppresses base64 payloads such as
// "data:image/png;base64,iVBOR..." which are long and high entropy but are not
// credentials.
func entropyContextExcluded(b []byte, i int) bool {
	lo := i - 16
	if lo < 0 {
		lo = 0
	}
	return bytes.Contains(bytes.ToLower(b[lo:i]), []byte("base64,"))
}

func isHexRun(v []byte) bool {
	for _, ch := range v {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
			return false
		}
	}
	return true
}

func isUUID(v []byte) bool {
	if len(v) != 36 {
		return false
	}
	for i, ch := range v {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
				return false
			}
		}
	}
	return true
}

func shannon(v []byte) float64 {
	if len(v) == 0 {
		return 0
	}
	var counts [256]int
	for _, ch := range v {
		counts[ch]++
	}
	n := float64(len(v))
	var h float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

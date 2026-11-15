package report

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yekunsong/Packout/internal/manifest"
)

// idleTimeout is the no-request lifetime of the report server (INV-B10,
// D-008 §3). It is a variable so tests can shorten it.
var idleTimeout = 15 * time.Minute

// Serve renders the report and serves it until ctx is cancelled or the server
// is idle for idleTimeout.
//
// It binds 127.0.0.1:0 (the OS picks the port) unless opts was built with
// WithLAN, in which case it binds 0.0.0.0:0 and the page carries a warning.
// The one-time token is passed as part of the URL fragment:
//
//	http://127.0.0.1:<port>/#<token>
//
// When opts.OnReady is set it receives that URL once the listener is bound;
// otherwise the URL is printed to stdout. The host in the URL is the bind
// host (127.0.0.1, or a LAN IPv4 with WithLAN; 0.0.0.0 only if none found).
//
// The server never writes a request log; the token is accepted from the URL
// query (?t=), an Authorization: Bearer header, or the fragment bootstrap
// redirect described in bootstrapHTML. No CORS header is ever emitted.
func Serve(ctx context.Context, m *manifest.Doc, opts Options) error {
	ready := opts.OnReady
	if ready == nil {
		ready = func(u string) {
			fmt.Fprintf(os.Stdout, "报告地址（一次性令牌在 fragment 中，勿转发）: %s\n", u)
		}
	}
	return serve(ctx, m, opts, ready)
}

// serve is the testable core. ready receives the one-time URL once the
// listener is bound.
func serve(ctx context.Context, m *manifest.Doc, opts Options, ready func(string)) error {
	page, err := renderBytes(m, opts)
	if err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return fmt.Errorf("report: token: %w", err)
	}

	bind := "127.0.0.1"
	if opts.lan {
		bind = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		return fmt.Errorf("report: listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	adv := bind
	if opts.lan {
		// 0.0.0.0 只是绑定地址，手机连不上；换成一个真实的非回环 IPv4。
		if ip := preferredLANIP(); ip != "" {
			adv = ip
		}
	}

	h := &handler{
		page:  page,
		token: token,
		port:  port,
		nonce: deriveNonce(m, opts),
	}
	h.last.Store(time.Now().UnixNano())

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		// IdleTimeout bounds an idle keep-alive connection; the watcher below
		// bounds an idle server even if a connection is held open.
		IdleTimeout: idleTimeout,
		ErrorLog:    log.New(io.Discard, "", 0),
	}

	stop := make(chan struct{})
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(c)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-stop:
		}
	}()
	go idleWatch(&h.last, idleTimeout, shutdown, stop)

	ready(fmt.Sprintf("http://%s:%d/#%s", adv, port, token))

	err = srv.Serve(ln)
	close(stop)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// newToken returns a 256-bit URL-safe token (INV-B03 requires >=128 bits).
func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// idleWatch shuts the server down after timeout without any request.
func idleWatch(last *atomic.Int64, timeout time.Duration, shutdown func(), stop <-chan struct{}) {
	tick := timeout / 4
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	if tick > time.Minute {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if now.Sub(time.Unix(0, last.Load())) >= timeout {
				shutdown()
				return
			}
		}
	}
}

// handler implements the whole P0 HTTP surface: GET / only.
type handler struct {
	page  []byte
	token string
	port  int
	nonce string
	last  atomic.Int64
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.last.Store(time.Now().UnixNano())
	setSecurityHeaders(w, h.nonce)

	// Host validation defeats DNS rebinding (B-06/INV-B05): only localhost or
	// IP literals on the bound port are accepted.
	if !hostAllowed(r.Host, h.port) {
		http.Error(w, "forbidden: host not allowed", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tok := tokenFrom(r)
	if tok == "" {
		// No credential at all: return a data-free bootstrap page whose only
		// job is to move a fragment token into the query (fragments are not
		// sent to servers, so this is the one hop that must happen in the
		// browser). The page carries no manifest data.
		if r.URL.RawQuery == "" && r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusForbidden)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(bootstrapPage(h.nonce)))
			}
			return
		}
		http.Error(w, "forbidden: token required", http.StatusForbidden)
		return
	}
	if !sameToken(tok, h.token) {
		http.Error(w, "forbidden: bad token", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(h.page)
	}
}

func tokenFrom(r *http.Request) string {
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "Bearer ") {
		return strings.TrimSpace(a[7:])
	}
	q := r.URL.Query()
	for _, k := range []string{"t", "token"} {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// hostAllowed accepts localhost and IP literals only, and requires the
// listener's port when a port is present. A DNS name such as evil.test is
// always rejected, which is what defeats DNS rebinding.
func hostAllowed(hostport string, port int) bool {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
		p = ""
	}
	if p != "" && p != strconv.Itoa(port) {
		return false
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	return net.ParseIP(h) != nil
}

func setSecurityHeaders(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// Deliberately no Access-Control-Allow-Origin (INV-B05).
}

// bootstrapPage is served with 403 and contains no report data. Its only
// action is to read the fragment token and reload with it as a query
// parameter, which the server can validate. It uses textContent, never
// innerHTML, and is authorized by the same CSP nonce.
const bootstrapHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-NONCE'">
<meta name="referrer" content="no-referrer">
<title>packout 报告 · 需要令牌</title>
<style>
body{font:14px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:24px;background:#f7f8fa;color:#1b1f24}
@media (prefers-color-scheme: dark){body{background:#11151a;color:#e6e9ee}}
main{max-width:640px;margin:40px auto;border:1px solid #d8dde5;border-radius:10px;padding:20px;background:#fff}
@media (prefers-color-scheme: dark){main{background:#181e25;border-color:#2b3542}}
code{font-family:ui-monospace,Consolas,monospace}
</style>
</head>
<body>
<main>
<h1>需要一次性访问令牌</h1>
<p id="msg">正在校验 URL fragment 中的令牌……</p>
<p>请使用 packout 输出的完整链接打开本页。令牌只存在于 URL fragment 中，不会发送到服务器日志。</p>
</main>
<script nonce="NONCE">
(function(){
  "use strict";
  var raw = location.hash ? location.hash.slice(1) : "";
  var msg = document.getElementById("msg");
  if (!raw) {
    if (msg) { msg.textContent = "缺少访问令牌。请使用 packout 输出的完整链接。"; }
    return;
  }
  location.replace("/?t=" + encodeURIComponent(raw) + "#" + encodeURIComponent(raw));
})();
</script>
</body>
</html>
`

func bootstrapPage(nonce string) string {
	return strings.ReplaceAll(bootstrapHTML, "NONCE", nonce)
}

// preferredLANIP returns a non-loopback, non-link-local IPv4 to advertise when
// the listener is bound to 0.0.0.0. Binding address and reachable address are
// not the same thing; printing 0.0.0.0 gives a URL no phone can open.
func preferredLANIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		if v4 := n.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

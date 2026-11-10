package report

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func doRequest(h *handler, method, target, host, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if host != "" {
		req.Host = host
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerAuthAndHost(t *testing.T) {
	h := &handler{
		page:  []byte("<!DOCTYPE html><html><body>REPORT PAGE</body></html>"),
		token: "good-token-value",
		port:  8080,
		nonce: "testnonce",
	}

	tests := []struct {
		name    string
		method  string
		target  string
		host    string
		auth    string
		status  int
		hasPage bool
	}{
		{"no token", http.MethodGet, "/", "127.0.0.1:8080", "", 403, false},
		{"good query token", http.MethodGet, "/?t=good-token-value", "127.0.0.1:8080", "", 200, true},
		{"good token alias", http.MethodGet, "/?token=good-token-value", "localhost:8080", "", 200, true},
		{"good bearer", http.MethodGet, "/", "127.0.0.1:8080", "Bearer good-token-value", 200, true},
		{"bad token", http.MethodGet, "/?t=wrong", "127.0.0.1:8080", "", 403, false},
		{"forged host", http.MethodGet, "/?t=good-token-value", "evil.test:8080", "", 403, false},
		{"wrong port", http.MethodGet, "/?t=good-token-value", "127.0.0.1:9999", "", 403, false},
		{"ipv6 loopback", http.MethodGet, "/?t=good-token-value", "[::1]:8080", "", 200, true},
		{"other path", http.MethodGet, "/foo?t=good-token-value", "127.0.0.1:8080", "", 404, false},
		{"post", http.MethodPost, "/?t=good-token-value", "127.0.0.1:8080", "", 405, false},
		{"head", http.MethodHead, "/?t=good-token-value", "127.0.0.1:8080", "", 200, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(h, tc.method, tc.target, tc.host, tc.auth)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.status, rec.Body.String())
			}
			gotPage := strings.Contains(rec.Body.String(), "REPORT PAGE")
			if gotPage != tc.hasPage {
				t.Fatalf("report body present = %v, want %v", gotPage, tc.hasPage)
			}
			if rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Error("Referrer-Policy: no-referrer missing")
			}
			if rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Error("CORS header must not be present")
			}
			if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Error("CSP header missing default-src 'none'")
			}
		})
	}
}

func TestBootstrapHasNoData(t *testing.T) {
	h := &handler{page: []byte("SECRET REPORT DATA"), token: "tok", port: 8080, nonce: "abc123"}
	rec := doRequest(h, http.MethodGet, "/", "127.0.0.1:8080", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "SECRET REPORT DATA") {
		t.Fatal("unauthenticated response leaked report data")
	}
	if !strings.Contains(body, `script-src 'nonce-abc123'`) {
		t.Fatal("bootstrap page lacks nonce CSP")
	}
	if strings.Contains(body, "innerHTML") {
		t.Fatal("bootstrap page must not use innerHTML")
	}
}

func TestNewToken(t *testing.T) {
	a, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("tokens are not unique")
	}
	// 32 random bytes -> 43 base64url characters, well above 128 bits.
	if len(a) < 22 {
		t.Fatalf("token too short: %q", a)
	}
}

func TestServeLifecycle(t *testing.T) {
	old := idleTimeout
	idleTimeout = 10 * time.Second
	defer func() { idleTimeout = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, fixtureDoc(), Options{IncludeSignals: true}, func(u string) { ready <- u })
	}()

	var raw string
	select {
	case raw = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not become ready")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad ready URL %q: %v", raw, err)
	}
	token := u.Fragment
	if token == "" {
		t.Fatal("token missing from fragment")
	}
	if u.Hostname() != "127.0.0.1" {
		t.Fatalf("default bind host = %q, want 127.0.0.1", u.Hostname())
	}
	base := "http://" + u.Host
	client := &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// No token: 403.
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-token status = %d, want 403", resp.StatusCode)
	}

	// Token: 200 and the rendered report.
	resp, err = client.Get(base + "/?t=" + url.QueryEscape(token))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "固定输入报告") && !strings.Contains(string(body), "packout 扫描报告") {
		t.Fatal("report title missing from authenticated response")
	}

	// Forged Host with a valid token still fails (DNS rebinding).
	req, _ := http.NewRequest(http.MethodGet, base+"/?t="+url.QueryEscape(token), nil)
	req.Host = "evil.test"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged-Host status = %d, want 403", resp.StatusCode)
	}

	// Cancelling ctx closes the listener.
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(base + "/?t=" + url.QueryEscape(token))
		if err != nil {
			break
		}
		resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("server still accepting requests after ctx cancellation")
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after cancellation")
	}
}

func TestServeIdleTimeout(t *testing.T) {
	old := idleTimeout
	idleTimeout = 300 * time.Millisecond
	defer func() { idleTimeout = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, fixtureDoc(), Options{}, func(u string) { ready <- u })
	}()
	var raw string
	select {
	case raw = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not become ready")
	}
	u, _ := url.Parse(raw)
	base := "http://" + u.Host
	client := &http.Client{Timeout: time.Second}

	time.Sleep(1200 * time.Millisecond)
	if resp, err := client.Get(base + "/?t=" + url.QueryEscape(u.Fragment)); err == nil {
		resp.Body.Close()
		t.Fatal("server still alive after idle timeout")
	}
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return after idle timeout")
	}
}

// TestServeOnReady checks the D-033 §5 callback: it fires only after the
// listener is bound, with the real port, and Serve no longer needs os.Stdout.
func TestServeOnReady(t *testing.T) {
	old := idleTimeout
	idleTimeout = 10 * time.Second
	defer func() { idleTimeout = old }()

	tests := []struct {
		name     string
		lan      bool
		wantHost string
	}{
		{"loopback", false, "127.0.0.1"},
		// LAN 打印的是可达地址，不是绑定地址；没有非回环网卡时退回 0.0.0.0。
		{"lan", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			got := make(chan string, 1)
			errCh := make(chan error, 1)
			opts := reportOptionsForTest()
			opts = opts.WithLAN(tc.lan)
			opts.OnReady = func(u string) { got <- u }
			go func() { errCh <- Serve(ctx, fixtureDoc(), opts) }()

			var raw string
			select {
			case raw = <-got:
			case <-time.After(10 * time.Second):
				t.Fatal("OnReady was not called")
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("bad ready URL %q: %v", raw, err)
			}
			if u.Fragment == "" {
				t.Fatal("token missing from callback URL")
			}
			if u.Port() == "" || u.Port() == "0" {
				t.Fatalf("callback URL port = %q, want a real ephemeral port", u.Port())
			}
			if tc.wantHost == "" {
				if h := u.Hostname(); h == "127.0.0.1" || h == "::1" {
					t.Fatalf("lan callback host = %q, want a reachable address", h)
				}
			} else if u.Hostname() != tc.wantHost {
				t.Fatalf("callback host = %q, want %q", u.Hostname(), tc.wantHost)
			}

			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("Serve returned %v after cancellation, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return after cancellation")
			}
		})
	}
}

func reportOptionsForTest() Options { return Options{IncludeSignals: true} }

package webui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func serve(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHandlerServesConsoleWithSecurityHeaders(t *testing.T) {
	h := Handler()
	rec := serve(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: HTTP %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Evidence Console") || !strings.Contains(body, `src="/app.js"`) {
		t.Fatalf("index.html not served correctly: %q", body[:min(len(body), 200)])
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("weak CSP: %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("nosniff missing: %q", got)
	}
}

func TestHandlerServesAssets(t *testing.T) {
	h := Handler()
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/app.js", "javascript"},
		{"/styles.css", "text/css"},
		{"/theme.js", "javascript"},
		{"/favicon.svg", "image/svg+xml"},
	} {
		rec := serve(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", tc.path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.Contains(got, tc.want) {
			t.Fatalf("%s: Content-Type %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestHandlerHidesIndexForUnknownPath(t *testing.T) {
	rec := serve(t, Handler(), "/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: HTTP %d, want 404", rec.Code)
	}
}

// TestNextHandlerServesConsole covers the migration route: the built React
// bundle when present, otherwise the "not built" page. It also pins the CSP
// invariant that the app ships no inline scripts.
func TestNextHandlerServesConsole(t *testing.T) {
	h := NextHandler()
	rec := serve(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /next/: HTTP %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") {
		t.Fatalf("weak CSP: %q", got)
	}
	body := rec.Body.String()
	if strings.Contains(body, "has not been built") {
		if !strings.Contains(body, "make web-build") {
			t.Fatalf("placeholder page does not explain the build step: %q", body)
		}
		return // front-end bundle not built in this checkout
	}
	if !strings.Contains(body, `type="module"`) || !strings.Contains(body, "/next/assets/") {
		t.Fatalf("built index.html not served correctly: %q", body[:min(len(body), 300)])
	}
	if inline := firstInlineScript(body); inline != "" {
		t.Fatalf("index.html contains an inline script (blocked by CSP): %q", inline)
	}
	for path, want := range map[string]string{
		"/theme.js":    "javascript",
		"/favicon.svg": "image/svg+xml",
	} {
		rec := serve(t, h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); !strings.Contains(got, want) {
			t.Fatalf("%s: Content-Type %q, want %q", path, got, want)
		}
	}
}

// firstInlineScript returns the first <script> tag without a src attribute
// (CSP script-src 'self' forbids inline scripts). Go's regexp has no
// lookahead, so scan the tags instead.
func firstInlineScript(body string) string {
	for _, tag := range scriptTag.FindAllString(body, -1) {
		if !strings.Contains(strings.ToLower(tag), "src=") {
			return tag
		}
	}
	return ""
}

var scriptTag = regexp.MustCompile(`(?is)<script\b[^>]*>`)

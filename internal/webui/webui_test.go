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

// built reports whether this checkout contains a built bundle; without one
// the handler serves the "not built" page and asset assertions do not apply.
func built(t *testing.T, h http.Handler) bool {
	t.Helper()
	body := serve(t, h, "/").Body.String()
	return !strings.Contains(body, "has not been built")
}

func TestHandlerServesConsole(t *testing.T) {
	h := Handler()
	rec := serve(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: HTTP %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "has not been built") {
		if !strings.Contains(body, "make web-build") {
			t.Fatalf("placeholder page does not explain the build step: %q", body[:min(len(body), 200)])
		}
		return
	}
	if !strings.Contains(body, `type="module"`) || !strings.Contains(body, "/assets/") {
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

func TestHandlerHardensResponses(t *testing.T) {
	rec := serve(t, Handler(), "/")
	headers := rec.Header()
	if got := headers.Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("weak CSP: %q", got)
	}
	for name, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-cache",
	} {
		if got := headers.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestHandlerHidesUnknownPaths(t *testing.T) {
	h := Handler()
	if !built(t, h) {
		t.Skip("front-end bundle not built in this checkout")
	}
	if rec := serve(t, h, "/does-not-exist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: HTTP %d, want 404", rec.Code)
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

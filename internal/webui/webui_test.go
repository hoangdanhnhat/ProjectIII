package webui

import (
	"net/http"
	"net/http/httptest"
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

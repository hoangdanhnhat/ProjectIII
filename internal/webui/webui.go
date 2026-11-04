// Package webui serves the embedded operator console (React build in dist/).
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'; " +
	"form-action 'self'"

// notBuiltPage explains the one missing build step instead of returning a
// bare 404 when the front-end bundle was never built.
const notBuiltPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Console not built</title>
<style>body{font:14px system-ui;margin:48px auto;max-width:560px;line-height:1.6;color:#17181a}
code{background:#f2f4f6;padding:2px 5px;border-radius:4px}</style></head>
<body><h1>Front-end has not been built</h1>
<p>This server was compiled without the React console bundle.</p>
<p>Build it with <code>make web-build</code> (or <code>npm ci &amp;&amp; npm run build</code> in
<code>web/</code>) and rebuild the server.</p>
</body></html>`

func init() {
	// Go's built-in MIME table predates some web font types; register the
	// extensions the bundle can emit so they are served correctly.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".woff", "font/woff")
	_ = mime.AddExtensionType(".map", "application/json")
}

// Handler serves the built console with hardened response headers.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(notBuiltPage))
		}))
	}
	return withSecurityHeaders(http.FileServerFS(sub))
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

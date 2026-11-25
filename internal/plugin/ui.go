package plugin

import (
	_ "embed"
	"net/http"
)

//go:embed web/ui.html
var uiHTML []byte

// The page is served without authentication by CLIProxyAPI's resource route,
// so it contains no data or secrets: it asks for the management key and calls
// the authenticated management API from the browser.
func uiResponse() ManagementResponse {
	return ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":           {"text/html; charset=utf-8"},
			"Cache-Control":          {"no-store"},
			"Referrer-Policy":        {"no-referrer"},
			"X-Content-Type-Options": {"nosniff"},
			"Content-Security-Policy": {"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
				"connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"},
		},
		Body: uiHTML,
	}
}

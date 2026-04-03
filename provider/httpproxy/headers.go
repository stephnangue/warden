package httpproxy

// BaseHeadersToRemove is the standard set of headers stripped from all proxied requests.
// Provider specs can add extra headers via ExtraHeadersToRemove.
var BaseHeadersToRemove = []string{
	// Security headers (replaced with provider credentials)
	"Authorization",
	"X-Warden-Token",
	"X-Warden-Role",
	// Hop-by-hop headers
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	// Proxy headers
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-Ip",
	"Forwarded",
}

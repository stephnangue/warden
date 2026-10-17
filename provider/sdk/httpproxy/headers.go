package httpproxy

import (
	"net/http"
	"strings"
)

// BaseHeadersToRemove is the standard set of headers stripped from all proxied requests.
// Provider specs can add extra headers via ExtraHeadersToRemove.
var BaseHeadersToRemove = []string{
	// Security headers (replaced with provider credentials)
	"Authorization",
	"X-Warden-Token",
	"X-Warden-Agent-Token",
	// Retired in 0.20: the user credential now rides Authorization. Still
	// stripped so a client that keeps sending the old header cannot leak the
	// credential to the upstream.
	"X-Warden-User-Token",
	"X-Warden-Role",
	"X-Warden-Provider",
	"X-Warden-Namespace",
	"X-Warden-Subject-Token",
	"X-Warden-Actor-Token",
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

// StripInboundHeaders removes from h every inbound header that must not reach the
// upstream: BaseHeadersToRemove, the spec's ExtraHeadersToRemove and
// ExtraHeaderPrefixesToRemove, and the headers the request's Connection header
// names as hop-by-hop — read before Connection itself is removed.
func (s *ProviderSpec) StripInboundHeaders(h http.Header) {
	conn := h.Get("Connection")

	for _, name := range BaseHeadersToRemove {
		h.Del(name)
	}
	for _, name := range s.ExtraHeadersToRemove {
		h.Del(name)
	}
	if len(s.ExtraHeaderPrefixesToRemove) > 0 {
		removeHeaderPrefixes(h, s.ExtraHeaderPrefixesToRemove)
	}

	if conn != "" {
		for _, name := range strings.Split(conn, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
}

// removeHeaderPrefixes deletes every header whose name begins with one of
// prefixes, ignoring case. Deleting from a map while ranging over it is safe in Go.
func removeHeaderPrefixes(h http.Header, prefixes []string) {
	for name := range h {
		for _, p := range prefixes {
			if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
				delete(h, name)
				break
			}
		}
	}
}

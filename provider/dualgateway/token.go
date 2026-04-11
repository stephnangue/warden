package dualgateway

import (
	"net/http"
	"strings"

	"github.com/stephnangue/warden/provider/sigv4"
)

// extractToken extracts the client token from the request.
// Handles three modes:
//   - Standard: X-Warden-Token or Authorization: Bearer
//   - S3 JWT transparent: JWT (eyJ prefix) in SigV4 Credential access_key_id
//   - S3 Cert transparent: role name from SigV4 Credential access_key_id
func extractToken(r *http.Request) string {
	// Standard Warden token
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}

	// Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}

	// S3 transparent: extract access_key_id from SigV4 header
	if sigv4.IsSigV4Request(r) {
		accessKeyID := sigv4.ExtractAccessKeyID(authHeader)
		if accessKeyID != "" {
			return accessKeyID
		}
	}

	return ""
}

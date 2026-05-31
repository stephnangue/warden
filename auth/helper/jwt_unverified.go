package helper

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ParseJWTClaimsUnverified decodes a JWT's payload segment and returns its
// claims as a map. **No signature verification.** Intended for cheap
// shape-sniffing on incoming requests — e.g. distinguishing a Kubernetes
// SA token (sub starts with "system:serviceaccount:") from a generic JWT,
// or pre-filtering by issuer claim before doing a full validator round-trip.
//
// Callers must NOT use the returned claims for authorization decisions;
// they have not been cryptographically validated. Use a full validator
// (JWKS, TokenReview, etc.) for any security-relevant check.
//
// Returns an error if the token is not a well-formed JWT (three segments)
// or the payload is not valid base64url JSON.
func ParseJWTClaimsUnverified(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT: expected three dot-separated segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("JWT payload is not valid base64url")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("JWT payload is not valid JSON")
	}
	return claims, nil
}

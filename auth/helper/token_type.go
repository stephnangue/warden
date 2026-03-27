package helper

// BackendJWT and BackendCert identify the auth backend type for token type resolution.
const (
	BackendJWT  = "jwt"
	BackendCert = "cert"
)

// DefaultTokenType returns the default token type for the given auth backend.
func DefaultTokenType(backend string) string {
	if backend == BackendCert {
		return "cert_role"
	}
	return "jwt_role"
}

// DisplayTokenType maps an internal token type name to its user-facing alias.
// Unknown values pass through unchanged.
func DisplayTokenType(internal string) string {
	switch internal {
	case "jwt_role", "cert_role":
		return "transparent"
	default:
		return internal
	}
}

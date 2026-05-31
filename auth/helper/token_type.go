package helper

// BackendJWT, BackendCert, BackendKubernetes identify the auth backend type
// for token type resolution.
const (
	BackendJWT        = "jwt"
	BackendCert       = "cert"
	BackendKubernetes = "kubernetes"
)

// DefaultTokenType returns the default token type for the given auth backend.
func DefaultTokenType(backend string) string {
	switch backend {
	case BackendCert:
		return "cert_role"
	case BackendKubernetes:
		return "kubernetes_role"
	default:
		return "jwt_role"
	}
}

// DisplayTokenType maps an internal token type name to its user-facing alias.
// Pass isTransparent=true (as reported by the TokenStore registry) to alias
// transparent-family token types to "transparent". This keeps auth/helper
// decoupled from the core token registry: callers consult the registry once
// and hand the boolean here.
func DisplayTokenType(internal string, isTransparent bool) string {
	if isTransparent {
		return "transparent"
	}
	return internal
}

package helper

// BackendJWT and BackendCert identify the auth backend type for token type resolution.
const (
	BackendJWT  = "jwt"
	BackendCert = "cert"
)

// UserTokenTypes is the ordered list of user-facing token type aliases.
var UserTokenTypes = []string{"aws", "warden", "transparent"}

// ResolveTokenType maps a user-facing token type alias to the internal name used in storage.
// The backend parameter ("jwt" or "cert") determines what "transparent" resolves to:
//   - jwt backend: "transparent" → "jwt_role"
//   - cert backend: "transparent" → "cert_role"
//
// Unknown values pass through unchanged to allow internal names in tests.
func ResolveTokenType(backend, alias string) string {
	switch alias {
	case "aws":
		return "aws_access_keys"
	case "warden":
		return "warden_token"
	case "transparent":
		if backend == BackendCert {
			return "cert_role"
		}
		return "jwt_role"
	default:
		return alias
	}
}

// DisplayTokenType maps an internal token type name to its user-facing alias.
// Unknown values pass through unchanged.
func DisplayTokenType(internal string) string {
	switch internal {
	case "aws_access_keys":
		return "aws"
	case "warden_token":
		return "warden"
	case "jwt_role", "cert_role":
		return "transparent"
	default:
		return internal
	}
}

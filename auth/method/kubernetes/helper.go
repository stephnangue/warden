package kubernetes

import (
	"fmt"
	"strings"
)

// errAuthFailed is the generic error returned for all authentication
// failures to prevent information leakage about which specific check
// failed (bound SA mismatch vs. expired token vs. issuer mismatch, etc.).
// Mirrors the same pattern used by the JWT auth method.
var errAuthFailed = fmt.Errorf("authentication failed")

// serviceAccountUsernamePrefix is the mandatory prefix Kubernetes uses
// for ServiceAccount-issued tokens in TokenReview.Status.User.Username.
// Format: "system:serviceaccount:<namespace>:<sa-name>".
const serviceAccountUsernamePrefix = "system:serviceaccount:"

// parseSAUsername splits a TokenReview status.user.username into the
// namespace and service account name, as the API server splits its own
// service-account usernames: after the mandatory prefix, exactly two
// ":"-separated parts, the namespace a DNS-1123 label and the name a DNS-1123
// subdomain. Anything else is not a service account and returns false (e.g.
// system:anonymous, system:node:..., an OIDC user, or ns:name:extra).
func parseSAUsername(username string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(username, serviceAccountUsernamePrefix)
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, ":")
	if !found || strings.Contains(name, ":") {
		return "", "", false
	}
	if !isDNS1123Label(namespace) || !isDNS1123Subdomain(name) {
		return "", "", false
	}
	return namespace, name, true
}

// isDNS1123Label reports whether s is a DNS-1123 label: 1 to 63 characters of
// lowercase letters, digits and '-', starting and ending with a letter or
// digit.
func isDNS1123Label(s string) bool {
	return len(s) <= 63 && isLabelText(s)
}

// isDNS1123Subdomain reports whether s is a DNS-1123 subdomain: at most 253
// characters of DNS-1123 labels joined by '.'. As in the API server, only the
// whole is bounded; a label is not held to 63 characters here.
func isDNS1123Subdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if !isLabelText(label) {
			return false
		}
	}
	return true
}

// isLabelText reports whether s is one or more lowercase letters, digits and
// '-', starting and ending with a letter or digit, of any length.
func isLabelText(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

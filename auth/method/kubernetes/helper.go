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
// namespace and service account name. Returns false if the username
// doesn't start with the mandatory prefix or is otherwise malformed
// (e.g. system:anonymous, system:node:..., or an OIDC user).
func parseSAUsername(username string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(username, serviceAccountUsernamePrefix)
	if !found {
		return "", "", false
	}
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// matchBoundList returns true if want is in the bound list, or if the
// list contains "*" (wildcard). Empty bound list rejects everything —
// the caller is responsible for refusing role configs with both
// bound_service_account_names and bound_service_account_namespaces empty.
func matchBoundList(bound []string, want string) bool {
	for _, b := range bound {
		if b == "*" || b == want {
			return true
		}
	}
	return false
}

// matchRoleBindings returns nil if the (namespace, name) pair satisfies
// the role's bound_service_account_namespaces and bound_service_account_names.
// Returns a descriptive error for server-side logging; callers should
// return errAuthFailed to clients.
func matchRoleBindings(role *KubernetesRole, namespace, name string) error {
	if !matchBoundList(role.BoundServiceAccountNamespaces, namespace) {
		return fmt.Errorf("service account namespace %q not in role's bound list", namespace)
	}
	if !matchBoundList(role.BoundServiceAccountNames, name) {
		return fmt.Errorf("service account name %q not in role's bound list", name)
	}
	return nil
}

// audienceMatches returns true if want is empty (role declared no
// audience requirement) or want appears in the TokenReview's returned
// status.audiences slice.
func audienceMatches(want string, got []string) bool {
	if want == "" {
		return true
	}
	for _, a := range got {
		if a == want {
			return true
		}
	}
	return false
}

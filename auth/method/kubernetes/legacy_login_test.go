package kubernetes

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// legacyRoleAdmits is the role login logins ran before they became
// admissions, frozen as the oracle the equivalence tests compare converted
// rules against: the issuer pre-filter and a TokenReview with the role's
// audience (none: the API server's), the role's service-account bindings, and
// the role's max_age against an iat that parses as a number (an absent one
// passed). It reports whether that login would have admitted token under the
// stored role roleName. It goes with the role matchers it calls.
func legacyRoleAdmits(t testing.TB, b *kubernetesAuthBackend, token, roleName string) bool {
	t.Helper()
	ctx := context.Background()
	b.configMu.RLock()
	cfg := b.config
	b.configMu.RUnlock()
	require.NotNil(t, cfg)

	role, err := b.getRole(ctx, roleName)
	require.NoError(t, err)
	require.NotNil(t, role, "role %q", roleName)

	var audiences []string
	if role.Audience != "" {
		audiences = []string{role.Audience}
	}
	rv, err := reviewWorkload(ctx, cfg, token, audiences)
	if err != nil {
		return false
	}
	if err := matchRoleBindings(role, rv.namespace, rv.name); err != nil {
		return false
	}
	if role.MaxAge != "" && rv.claims != nil {
		maxAge, err := role.ParseMaxAge()
		if err == nil && maxAge > 0 {
			if iat, ok := rv.claims["iat"].(float64); ok && time.Since(time.Unix(int64(iat), 0)) > maxAge {
				return false
			}
		}
	}
	return true
}

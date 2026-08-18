package alicloud

import (
	"crypto/x509"
	"net/http"

	"github.com/stephnangue/warden/listener"
)

// extractToken adapts the two-principal extractor to the single-return shape
// the pre-0.20 tests were written against. Every assertion made through it is a
// byte-identity regression test: with userLeg false the agent must resolve
// exactly as it did before the user leg existed, and no user may be produced.
func extractToken(r *http.Request) string {
	agent, user := extractTokens(r, false)
	if user != "" {
		panic("extractTokens returned a user credential with userLeg=false")
	}
	return agent
}

// withClientCert returns r carrying a trusted client certificate, the way the
// API listener's middleware presents one. Tests must use this rather than
// setting X-SSL-Client-Cert / X-Forwarded-Client-Cert: the middleware strips
// those headers on every request before a provider ever runs, so a raw header
// proves nothing about production behaviour.
func withClientCert(r *http.Request) *http.Request {
	return r.WithContext(listener.WithForwardedClientCert(r.Context(), &x509.Certificate{}))
}

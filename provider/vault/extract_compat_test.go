package vault

import "net/http"

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

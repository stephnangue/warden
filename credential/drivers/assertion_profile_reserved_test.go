package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExchangeGrantsAreReservedProfileNames is the drift guard for the exchange
// grant values. It lives here rather than in package credential because the grant
// constants are unexported in THIS package — and drivers imports credential, not
// the reverse, so the reserved list over there cannot be derived from them.
//
// It iterates tokenExchangeGrants, the same slice the source-config OneOf validator
// uses, so a grant added to the validator is automatically in this loop and fails
// it until it is also reserved. (Iterating a hardcoded copy here would pass a new
// grant straight through, which is the failure this test exists to prevent.)
//
// id_jag is the reason this matters most: it already means the shipped two-leg
// Cross-App Access exchange, so an assertion_profile=id_jag would be two unrelated
// features spelled identically.
func TestExchangeGrantsAreReservedProfileNames(t *testing.T) {
	require.NotEmpty(t, tokenExchangeGrants, "the grant list must not be empty, or this test asserts nothing")

	for _, grant := range tokenExchangeGrants {
		assert.True(t, credential.IsReservedAssertionProfileName(grant),
			"exchange grant %q is not a reserved assertion profile name: reserve it, or it can be registered as a profile and mean two different things", grant)
	}
}

// Deliberately NOT guarded: the RFC 8693 token-type URNs (tokenTypeIDJAG and
// friends). The reserved list holds SHORT names an operator could plausibly type as
// a profile — access_token, jwt, at_jwt — because those are the ones that
// read like a profile name. A full urn:ietf:params:oauth:token-type:... is not a
// snake_case single token, so it can never be a valid profile name by convention and
// reserving it would protect nothing.

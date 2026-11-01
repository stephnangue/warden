package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logical"
)

func TestFactsProvider(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(map[string]any{"alias_name_source": nil})
	assert.Equal(t, logical.EntityKindHuman, e.b.EntityKind())
	// The names core checks a group rule against (ruleWarnings): a mapped fact
	// and a built-in raise no warning, a fact the mount does not publish does.
	assert.Subset(t, e.b.FactNames(), []string{"sub", "iss", "aud", "oid", "roles", "country"})
	assert.NotContains(t, e.b.FactNames(), "department")
	assert.NotContains(t, e.b.FactNames(), "email", "an unmapped claim is not a fact")
	assert.Same(t, e.b.mountFacts, e.b.MountFacts())
	from, to := e.b.AliasChange(map[string]any{"alias_name_source": "oid"})
	assert.Equal(t, `kind human, fact "sub"`, from)
	assert.Equal(t, `kind human, fact "oid"`, to)
}

// The claims kept are the top-level claim each built-in and mapped source
// reads, once each; nothing else, and nothing the token lacks.
func TestKeptClaims(t *testing.T) {
	c := helper.FactsConfig{EntityKind: logical.EntityKindHuman, Facts: map[string]string{
		"/address/country": "country",
		"/address/city":    "city",
		"roles":            "roles",
		"absent":           "absent",
	}}
	c.Compile(builtinFacts(), aliasPolicy)
	require.NoError(t, c.Err())

	claims := map[string]any{
		"sub": "s", "iss": "i", "aud": "a",
		"address": map[string]any{"country": "CM", "city": "Douala", "street": "x"},
		"roles":   []any{"r"},
		"email":   "ada@example.com",
		"nonce":   "n",
	}
	kept := keptClaims(claims, c.Naming())
	assert.ElementsMatch(t, []string{"sub", "iss", "aud", "address", "roles"}, keys(kept))
	assert.Equal(t, claims["address"], kept["address"], "a pointer keeps its whole top-level claim")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

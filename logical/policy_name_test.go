package logical

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCanonicalPolicyName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"admin", "admin", true},
		{"Admin", "admin", true},
		{"  deploy ", "deploy", true},
		{"group-team.a_1", "group-team.a_1", true},
		{"_x_", "_x_", true},
		{"a", "a", true},
		{"a..b", "a..b", true},

		{"", "", false},
		{"   ", "", false},
		{"..", "", false},
		{".", "", false},
		{"../../00000000-0000-0000-0000-000000000000/cbp/admin", "", false},
		{"x/../admin", "", false},
		{"a/b", "", false},
		{"-a", "", false},
		{"a-", "", false},
		{".a", "", false},
		{"a.", "", false},
		{"a b", "", false},
		{"a\tb", "", false},
		{"a%2fb", "", false},
		{"a\\b", "", false},
		{"é", "", false},
		// Unicode folding would map these onto ASCII names; they are refused.
		{"ADMİN", "", false},    // "İ" lowers to "i"
		{"\u212Aey", "", false}, // the Kelvin sign lowers to "k"
	}
	for _, tc := range cases {
		got, ok := CanonicalPolicyName(tc.in)
		assert.Equal(t, tc.ok, ok, "ok for %q", tc.in)
		if tc.ok {
			assert.Equal(t, tc.want, got, "canonical form of %q", tc.in)
		}
	}
}

// TestCanonicalPolicyName_NoAllocWhenCanonical pins the hot path: every policy
// of every request goes through it.
func TestCanonicalPolicyName_NoAllocWhenCanonical(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = CanonicalPolicyName("group-team.a_1")
	})
	assert.Zero(t, allocs)
}

func TestValidateAssignablePolicies_CanonicalForm(t *testing.T) {
	assert.NoError(t, ValidateAssignablePolicies([]string{"deploy", "Deploy"}))
	assert.Error(t, ValidateAssignablePolicies([]string{"../../00000000-0000-0000-0000-000000000000/cbp/admin"}))
	assert.Error(t, ValidateAssignablePolicies([]string{"x/../admin"}))
	// Compared in canonical form, so no spelling of root gets past.
	assert.Error(t, ValidateAssignablePolicies([]string{"root"}))
	assert.Error(t, ValidateAssignablePolicies([]string{" ROOT "}))
}

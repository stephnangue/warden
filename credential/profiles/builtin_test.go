package profiles

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterBuiltinProfiles_ExactSet pins the full builtin roster in one place, so a
// new profile updates this list rather than a sibling profile's tests. Names are
// permanent: a name dropping out of this list is a breaking change, not a cleanup.
func TestRegisterBuiltinProfiles_ExactSet(t *testing.T) {
	reg := credential.NewAssertionProfileRegistry()
	require.NoError(t, RegisterBuiltinProfiles(reg))
	assert.Equal(t, []string{"aws", "default", "minimal"}, reg.ListProfiles())
}

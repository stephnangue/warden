package credential

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wardenIdentityConfig builds a minimal warden_identity spec config with the given
// extra keys layered on.
func wardenIdentityConfig(extra map[string]string) Config {
	m := map[string]string{
		ConfigSubjectTokenSource: SourceWardenIdentity,
		ConfigAssertionAudience:  "sts.amazonaws.com",
	}
	for k, v := range extra {
		m[k] = v
	}
	return NewConfig(m)
}

// A nil registry passes: a test or bootstrap without registries can persist a spec,
// and mint-time resolution still fails closed on a name this build lacks.
func TestValidateAssertionProfileConfig_NilRegistry(t *testing.T) {
	assert.NoError(t, ValidateAssertionProfileConfig(nil,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: "anything_at_all"}), SourceTypeAWS))
}

func TestValidateAssertionProfileConfig_UnsetIsDefault(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	require.NoError(t, reg.Register(fakeProfile{name: DefaultAssertionProfileName}))

	// Unset resolves to the default profile, which is registered, so this passes.
	assert.NoError(t, ValidateAssertionProfileConfig(reg, wardenIdentityConfig(nil), SourceTypeAWS))
	// Explicitly naming the default is the same thing.
	assert.NoError(t, ValidateAssertionProfileConfig(reg,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: DefaultAssertionProfileName}), SourceTypeAWS))
}

func TestValidateAssertionProfileConfig_UnknownName(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	require.NoError(t, reg.Register(fakeProfile{name: DefaultAssertionProfileName}))

	err := ValidateAssertionProfileConfig(reg,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: "nope"}), SourceTypeAWS)
	require.Error(t, err)
	// Names the offending key, like every sibling assertion_* rejection, and lists
	// the sorted available profiles so the message is stable as more are added.
	assert.EqualError(t, err,
		"field 'assertion_profile': unknown assertion profile: nope (available profiles: [default])")
}

// The pin is ONE-DIRECTIONAL: a pinned profile requires one of its source types, but
// a source of that type never requires the profile.
func TestValidateAssertionProfileConfig_SourcePin(t *testing.T) {
	// A pin listing AWS accepts an AWS source and rejects anything else.
	reg := NewAssertionProfileRegistry()
	pinned := pinnedFakeProfile{fakeProfile: fakeProfile{name: "aws_shape"}}
	pinned.sourceTypes = []string{SourceTypeAWS}
	require.NoError(t, reg.Register(pinned))

	assert.NoError(t, ValidateAssertionProfileConfig(reg,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: "aws_shape"}), SourceTypeAWS))

	err := ValidateAssertionProfileConfig(reg,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: "aws_shape"}), SourceTypeVault)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a source of type")
	assert.Contains(t, err.Error(), SourceTypeVault)

	// One-directional: an AWS source with no profile key is fine.
	regDefault := NewAssertionProfileRegistry()
	require.NoError(t, regDefault.Register(fakeProfile{name: DefaultAssertionProfileName}))
	assert.NoError(t, ValidateAssertionProfileConfig(regDefault, wardenIdentityConfig(nil), SourceTypeAWS))
}

// An unpinned profile (like default) works with every source type.
func TestValidateAssertionProfileConfig_UnpinnedWorksAnywhere(t *testing.T) {
	reg := NewAssertionProfileRegistry()
	require.NoError(t, reg.Register(fakeProfile{name: DefaultAssertionProfileName}))

	for _, st := range []string{SourceTypeAWS, SourceTypeVault, SourceTypeGCP, SourceTypeTokenExchange} {
		assert.NoError(t, ValidateAssertionProfileConfig(reg, wardenIdentityConfig(nil), st),
			"the default profile must be usable on a %s source", st)
	}
}

// The profile's own ValidateSpec runs last and its error surfaces.
func TestValidateAssertionProfileConfig_ProfileValidateSpecRuns(t *testing.T) {
	sentinel := errors.New("this profile emits no warden_resource")
	reg := NewAssertionProfileRegistry()
	require.NoError(t, reg.Register(fakeProfile{name: "picky_shape", specErr: sentinel}))

	err := ValidateAssertionProfileConfig(reg,
		wardenIdentityConfig(map[string]string{ConfigAssertionProfile: "picky_shape"}), SourceTypeAWS)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

// TestValidateExchangeSpecConfig_AssertionProfileGate pins the registry-free half:
// the key is meaningless without a Warden-minted assertion, and that check sits with
// its four siblings in the source-agnostic structural validator.
func TestValidateExchangeSpecConfig_AssertionProfileGate(t *testing.T) {
	// No warden_identity anywhere → rejected.
	err := ValidateExchangeSpecConfig(NewConfig(map[string]string{
		ConfigAssertionProfile: DefaultAssertionProfileName,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), ConfigAssertionProfile)
	assert.Contains(t, err.Error(), SourceWardenIdentity)

	// A non-warden subject is still rejected.
	err = ValidateExchangeSpecConfig(NewConfig(map[string]string{
		ConfigSubjectTokenSource: SourceAgentIdentity,
		ConfigAssertionProfile:   DefaultAssertionProfileName,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), ConfigAssertionProfile)

	// warden_identity as the SUBJECT → accepted.
	assert.NoError(t, ValidateExchangeSpecConfig(NewConfig(map[string]string{
		ConfigSubjectTokenSource: SourceWardenIdentity,
		ConfigAssertionProfile:   DefaultAssertionProfileName,
	})))

	// warden_identity as the ACTOR (the delegation shape) → also accepted, since the
	// assertion_* keys apply to whichever slot mints.
	assert.NoError(t, ValidateExchangeSpecConfig(NewConfig(map[string]string{
		ConfigSubjectTokenSource: SourceUserIdentity,
		ConfigActorTokenSource:   SourceWardenIdentity,
		ConfigAssertionProfile:   DefaultAssertionProfileName,
	})))

	// Unset is always fine.
	assert.NoError(t, ValidateExchangeSpecConfig(NewConfig(map[string]string{
		ConfigSubjectTokenSource: SourceAgentIdentity,
	})))
}

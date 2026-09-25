package profiles

import (
	"github.com/stephnangue/warden/credential"
)

// MinimalProfileName is the minimal profile's name. Permanent, like every profile name.
const MinimalProfileName = "minimal"

// MinimalProfile shapes the assertion for a verifier that binds only the registered
// claims: iss, sub and aud, exactly, with nothing else read.
//
// Entra ID workload identity federation is the verifier this shape exists for. A
// federated identity credential matches the token's issuer, subject and audience by
// exact comparison and evaluates no other claim, so every warden_* claim the default
// profile emits is unreadable there — it only discloses the principal, role,
// namespace, metadata and user identity to a party that cannot use any of it.
// Nothing about the shape is specific to Entra, which is why it is named after what
// it is and not pinned to a source: any verifier that binds only iss/sub/aud fits.
//
// sub stays the composite "wid:{nsID}:{mountAccessor}:{principalID}", identical to
// the default profile's, so a trust written against a default-profile subject still
// matches when a spec moves to this profile.
//
// The rule is the aws profile's: emit only what the verifier can bind. So
// warden_resource is dropped with the rest, and an explicit assertion_resource is
// rejected at spec-create — its sole effect is output this profile never renders.
//
// THIS SHAPE IS FROZEN once shipped, like every profile's: trusts bind to it. A
// different shape ships as a new profile name.
type MinimalProfile struct{}

var _ credential.AssertionProfile = (*MinimalProfile)(nil)

// Name returns the profile name an operator writes in assertion_profile.
func (MinimalProfile) Name() string { return MinimalProfileName }

// Typ returns the JOSE typ header.
func (MinimalProfile) Typ() string { return "JWT" }

// ValidateSpec rejects an explicit assertion_resource other than "none": that key's
// sole effect is the warden_resource claim, which this profile never emits. Unset is
// accepted — it means "derive", which is invisible to a config-only check, and the
// profile simply ignores the derived value.
//
// It never rejects assertion_user_claims or assertion_metadata_claims: this profile
// renders neither warden_user nor warden_metadata, but both keys also drive
// {{user.<claim>}} / {{agent.<claim>}} request templating.
func (MinimalProfile) ValidateSpec(config credential.Config) error {
	return rejectExplicitResource(MinimalProfileName, config)
}

// Claims renders the registered claims and nothing else. req.Metadata,
// req.UserClaims and req.Resource are deliberately not read, and a role-less identity
// (a root token) needs no special case since the role is not rendered.
func (MinimalProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	return map[string]any{
		"iss": req.Issuer,
		"sub": req.Identity.WardenSubject(),
		"aud": req.Audience,
		"iat": req.IssuedAt.Unix(),
		"nbf": req.NotBefore.Unix(),
		"exp": req.ExpiresAt.Unix(),
		"jti": req.JTI,
	}, nil
}

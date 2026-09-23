// Package profiles holds the built-in assertion profiles — the claim shapes a
// warden_identity assertion can be minted in. It mirrors credential/types/:
// one file per profile, plus a builtin.go that registers them all.
package profiles

import (
	"github.com/stephnangue/warden/credential"
)

// DefaultProfile is the historical claim shape: a composite `sub`, the raw
// principal and its role/namespace/mount alongside it as warden_* claims, and three
// opt-in claims (warden_metadata, warden_user, warden_resource).
//
// It honors all five assertion_* config keys, so ValidateSpec has nothing to reject,
// and it is usable with every source type — no source pin.
//
// THIS SHAPE IS FROZEN. An unset assertion_profile means default, forever, and
// operators have written upstream trust policies against these exact claims — an
// AWS role binding `sub`, a JWT-auth verifier binding warden_role. Changing what this
// profile emits would silently break every one of them on upgrade, with nothing in
// any spec config having changed. A new claim shape needs a new profile name. The
// unmodified pre-existing mint tests and TestDefaultProfile_Claims_* enforce the
// bytes; this comment is why they must never be "updated to match".
type DefaultProfile struct{}

// Compile-time assertion that the profile satisfies the interface.
var _ credential.AssertionProfile = (*DefaultProfile)(nil)

// Name returns the profile name an operator writes in assertion_profile.
func (DefaultProfile) Name() string { return credential.DefaultAssertionProfileName }

// Typ returns the JOSE typ header.
func (DefaultProfile) Typ() string { return "JWT" }

// ValidateSpec accepts every spec: this profile renders all five assertion_* keys,
// so none of them is silently dropped.
func (DefaultProfile) ValidateSpec(config credential.Config) error { return nil }

// Claims renders the default claim set.
//
// The three conditional claims stay conditional: an absent warden_metadata is not
// the same as an empty one, and emitting the empty forms would change the assertion
// bytes for every spec that does not opt in.
func (DefaultProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	claims := map[string]any{
		"iss": req.Issuer,
		// sub is the composite Warden subject "wid:{ns_id}:{mount_accessor}:{principal_id}"; warden_sub below
		// carries the raw principal id on its own, so a verifier can bind the principal
		// directly without having to parse the composite sub.
		"sub":               req.Identity.WardenSubject(),
		"aud":               req.Audience,
		"iat":               req.IssuedAt.Unix(),
		"nbf":               req.NotBefore.Unix(),
		"exp":               req.ExpiresAt.Unix(),
		"jti":               req.JTI,
		"warden_sub":        req.Identity.PrincipalID,
		"warden_role":       req.Identity.RoleName,
		"warden_namespace":  req.Identity.NamespacePath,
		"warden_auth_mount": req.Identity.MountAccessor,
	}
	if len(req.Metadata) > 0 {
		claims["warden_metadata"] = req.Metadata
	}
	if len(req.UserClaims) > 0 {
		claims["warden_user"] = req.UserClaims
	}
	if req.Resource != "" {
		claims["warden_resource"] = req.Resource
	}
	return claims, nil
}

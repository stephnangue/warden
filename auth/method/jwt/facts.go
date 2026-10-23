package jwt

import (
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// jwtBuiltinFacts returns the claims every jwt mount publishes under their own
// names: the ones the validator checks against the mount's expectations
// (issuer, subject, audiences). Every other claim is invisible until mapped.
// The slice is fresh on each call.
func jwtBuiltinFacts() []string { return []string{"sub", "iss", "aud"} }

var _ logical.FactsProvider = (*jwtAuthBackend)(nil)

// FactNames implements logical.FactsProvider (see helper.FactNames).
func (b *jwtAuthBackend) FactNames() []string { return helper.FactNames(b.mountFacts) }

// newAdmission returns what the login verified about token, whose validated
// claims are claims. The admission adopts claims without copying: the caller
// must not read or modify them afterwards, and nothing else may hold them.
// mount is the backend's live naming, so a later mapping edit reaches this
// admission.
func newAdmission(claims map[string]any, token string, mount *logical.MountFacts) *logical.Admission {
	return &logical.Admission{
		Facts:    selector.NewClaims(claims),
		Mount:    mount,
		IssuedAt: helper.IssuedAt(claims),
		Bytes:    helper.JWTPayloadBytes(token),
	}
}

package profiles

import (
	"errors"
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// ActorProfileName is the actor profile's name. Permanent, like every profile name.
const ActorProfileName = "actor"

// ActorProfile shapes the assertion as an RFC 8693 delegation token: the USER is the
// subject and the AGENT is the current actor, in an "act" claim.
//
// Every other profile names the agent as sub and, at most, describes the user in
// warden_user. A verifier that expects the RFC 8693 form (whose authority is used in
// sub, who is exercising it in act) could only get that from a real token exchange.
// Warden already authenticates both principals on one request, so this profile lets
// its own assertion carry the delegation directly. The name follows the IETF Actor
// Profile draft (draft-mcguinness-oauth-actor-profile), which specifies this act
// structure.
//
//   - sub is the USER's composite "wid:{nsID}:{mountAccessor}:{principalID}".
//     Composite, not the raw principal, because the user can log in through a
//     different auth mount than the agent: a raw id is unique only within its mount,
//     and an issuer's sub must be unique within the issuer. The composite also gives a
//     verifier a mount-pinnable prefix.
//   - act.sub is the AGENT's composite, and act.iss is Warden's issuer URL — the
//     context act.sub is interpreted in. RFC 8693 permits the member; the Actor
//     Profile draft requires it.
//   - When the user's own token carried a verified act chain, that chain is nested
//     under the agent as PRIOR actors, oldest innermost (RFC 8693 §4.1). Each layer is
//     re-emitted as the IdP attested it at login — sub, plus iss only when that layer
//     had one — never rewritten or filled in. These subs are the IdP's own ids, not
//     Warden composites. Per RFC 8693, a verifier applies access control only to the
//     top-level claims and the current actor; nested actors are informational.
//   - warden_role (the agent's role), warden_namespace, and the opt-in
//     warden_metadata (the agent's) and warden_resource render as in default.
//     warden_user renders the projected user claims WITHOUT sub (sub is now the
//     top-level claim) and is omitted when sub was the only key listed.
//   - Dropped relative to default: warden_sub (it is inside act.sub) and
//     warden_auth_mount (each subject already carries its own mount, and one claim
//     would be ambiguous about whose mount it names).
//
// Two refusals, in CheckIdentities, which the core runs while it resolves the
// request's assertion — before any cache lookup:
//   - an agent whose OWN token carries an act chain. RFC 8693 would make that
//     chain's head the current actor, so naming the agent in act.sub would misstate
//     who acts. Refused rather than rendered, which keeps rendering it later
//     additive: it would only change a case that errors today.
//   - no user principal: the shape has no subject without one. In practice the
//     core refuses this first — ValidateSpec makes assertion_user_claims mandatory,
//     and that opt-in already requires a user — so this check is the backstop for
//     a caller that bypassed that gate.
//
// The deepest act this renders is 1 + the login-time chain bound (4).
//
// THIS SHAPE IS FROZEN once shipped, like every profile's: verifiers bind to it. A
// different delegation shape ships as a new profile name.
type ActorProfile struct{}

var (
	_ credential.AssertionProfile                = (*ActorProfile)(nil)
	_ credential.AssertionProfileIdentityChecker = (*ActorProfile)(nil)
)

// Name returns the profile name an operator writes in assertion_profile.
func (ActorProfile) Name() string { return ActorProfileName }

// Typ returns the JOSE typ header.
func (ActorProfile) Typ() string { return "JWT" }

// ValidateSpec requires the single-token shape with a disclosed user:
//
//   - the assertion must fill the SUBJECT slot. actor_token_source=warden_identity
//     already means "Warden's assertion is the actor token" in the two-token shape,
//     where the upstream STS writes act itself; this profile would there assert the
//     user as the actor, which is backwards.
//   - assertion_user_claims must be non-empty. It is the opt-in that discloses the
//     user to the assertion at all, and this shape names the user as sub.
//
// It rejects nothing else: metadata and resource both render.
func (ActorProfile) ValidateSpec(config credential.Config) error {
	actor := config.Get(credential.ConfigActorTokenSource)
	if (actor != "" && actor != credential.SourceNone) ||
		config.Get(credential.ConfigSubjectTokenSource) != credential.SourceWardenIdentity {
		return fmt.Errorf("field '%s': profile '%s' mints the subject token; set %s=%s and remove %s (in the two-token shape the upstream STS writes act itself)",
			credential.ConfigAssertionProfile, ActorProfileName,
			credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity,
			credential.ConfigActorTokenSource)
	}
	if len(credential.AssertionUserClaimKeys(config)) == 0 {
		return fmt.Errorf("field '%s': profile '%s' names the user as sub; list at least 'sub' in %s",
			credential.ConfigAssertionProfile, ActorProfileName, credential.ConfigAssertionUserClaims)
	}
	return nil
}

// errAgentActChain is the refusal for an agent whose own token carries an act chain.
var errAgentActChain = errors.New("the agent token carries an RFC 8693 act chain; the actor profile would name the agent as the current actor and misstate who acts")

// CheckIdentities refuses a missing user and an agent that is itself being acted for.
func (ActorProfile) CheckIdentities(agent credential.AssertionIdentity, user *credential.AssertionIdentity) error {
	if user == nil {
		return fmt.Errorf("profile '%s' names the user as sub: %w", ActorProfileName, credential.ErrUserRequired)
	}
	if len(agent.Actors) > 0 {
		return errAgentActChain
	}
	return nil
}

// Claims renders the delegation shape. It re-runs CheckIdentities, as defence in
// depth for a caller that skipped the setup-time check. Every map it returns is
// fresh, nested act layers included, and it never writes to req.Metadata,
// req.UserClaims or either identity's Actors.
func (p ActorProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	if err := p.CheckIdentities(req.Identity, req.User); err != nil {
		return nil, err
	}

	claims := map[string]any{
		"iss":              req.Issuer,
		"sub":              req.User.WardenSubject(),
		"aud":              req.Audience,
		"iat":              req.IssuedAt.Unix(),
		"nbf":              req.NotBefore.Unix(),
		"exp":              req.ExpiresAt.Unix(),
		"jti":              req.JTI,
		"act":              actClaim(req.Issuer, req.Identity, req.User.Actors),
		"warden_role":      req.Identity.RoleName,
		"warden_namespace": req.Identity.NamespacePath,
	}
	if len(req.Metadata) > 0 {
		claims["warden_metadata"] = req.Metadata
	}
	if user := userClaimsWithoutSub(req.UserClaims); len(user) > 0 {
		claims["warden_user"] = user
	}
	if req.Resource != "" {
		claims["warden_resource"] = req.Resource
	}
	return claims, nil
}

// actClaim builds the act claim: the agent as current actor, with the user token's
// chain nested beneath it as prior actors. prior is outermost-first, so the nesting
// is built innermost-out.
func actClaim(issuer string, agent credential.AssertionIdentity, prior []credential.AssertionActor) map[string]any {
	var inner map[string]any
	for i := len(prior) - 1; i >= 0; i-- {
		layer := map[string]any{"sub": prior[i].Subject}
		if prior[i].Issuer != "" {
			layer["iss"] = prior[i].Issuer
		}
		if inner != nil {
			layer["act"] = inner
		}
		inner = layer
	}

	act := map[string]any{
		"sub": agent.WardenSubject(),
		"iss": issuer,
	}
	if inner != nil {
		act["act"] = inner
	}
	return act
}

// userClaimsWithoutSub copies the projected user claims minus "sub", which this
// profile renders as the top-level subject instead. Nil when nothing else is left.
func userClaimsWithoutSub(in map[string]string) map[string]string {
	var out map[string]string
	for k, v := range in {
		if k == "sub" {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(in))
		}
		out[k] = v
	}
	return out
}

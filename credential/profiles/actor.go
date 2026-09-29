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
// Warden already authenticates both principals on one request — the agent's own
// credential, and the user token the agent presents, validated by the mount's user
// auth method — so this profile lets its own assertion carry the delegation
// directly. The name follows the IETF Actor Profile draft
// (draft-mcguinness-oauth-actor-profile), which specifies this act structure.
//
// Both principals are named by their RAW ids, never by Warden's composite
// "wid:{nsID}:{mountAccessor}:{principalID}". Neither is an identity Warden issues:
// each presented a credential its own IdP or trust root issued, and a Warden auth
// mount validated it. Which auth mount did the validating is Warden's own wiring, of
// no concern to the upstream, which knows each party by the id its IdP issued.
// Within a namespace, an id is unique only as far as its operator makes it: an
// audience reachable by principals validated against different IdPs needs a claim
// unique across them (the auth role's user_claim), or the audiences kept apart.
// Cache keys are unaffected: they are built from the composite, which is finer than
// what is rendered.
//
// ACROSS namespaces the raw ids are not a boundary at all; the namespace claims are.
// Every namespace mints under the one global issuer, and a namespace admin can mount
// an auth method that asserts any principal id and aim a spec at any audience — so
// "alice" minted in one namespace is indistinguishable by sub alone from "alice"
// minted in another. Each id is therefore paired with the namespace whose auth mount
// vouched for it, and the two can differ: an agent token from a parent namespace is
// valid in its children, while the user must belong to the request's namespace. A
// verifier MUST bind warden_namespace together with sub, and act.warden_namespace
// together with act.sub. Both are namespace paths, matched exactly: the root
// namespace's path is the empty string, which is a value to bind, not an absent
// claim.
//
//   - sub is the USER's principal: the id the user's IdP asserted in the token the
//     agent presented, as the auth role's user_claim selects it — the same value
//     {{user.sub}} templates.
//   - warden_namespace is the USER's namespace — the request's — which qualifies sub.
//   - warden_role is the USER's role: the auth role the presented user token was
//     validated under (the mount's user auth role). It is not an authorization role
//     — the user grants the request no permissions — but it names which population
//     of users the id belongs to, which an upstream may bind.
//   - warden_metadata is the USER's projected claims (assertion_user_claims) WITHOUT
//     sub, which would repeat the top-level sub; omitted when sub was the only key
//     listed. The name is the one the agent's metadata carries in act: each level of
//     the token describes its own principal with the same claims — sub,
//     warden_namespace, warden_role, warden_metadata — so the top level is the user
//     and act is the agent. (In default, where the agent is the subject, the user's claims are
//     warden_user instead.)
//   - act.sub is the AGENT's principal, act.warden_namespace the agent's namespace,
//     which qualifies it, and act.iss is Warden's issuer URL: the context both ids
//     are vouched for in, as the top-level iss is for sub. act.warden_role is the
//     role the agent was admitted under — the authorization context an upstream may
//     bind — and it sits in act because it is the agent's. A
//     role-less agent (a root token) renders it empty, as default does.
//     act.warden_metadata is the agent's projected login metadata, opt-in as in
//     default — in act for the same reason. RFC 8693 permits identity members such
//     as these in act; the Actor Profile draft requires act.iss.
//   - When the user token carried a verified act chain, that chain is nested under
//     the agent as PRIOR actors, oldest innermost (RFC 8693 §4.1). Each layer is
//     re-emitted as the IdP attested it — sub, plus iss only when that layer had one
//     — never rewritten or filled in. Per RFC 8693, a verifier applies access control
//     only to the top-level claims and the current actor; nested actors are
//     informational.
//   - The opt-in warden_resource renders as in default.
//   - Dropped relative to default: warden_sub (it is act.sub), warden_user (it is the
//     top-level warden_metadata) and warden_auth_mount (Warden wiring the raw ids
//     leave out).
//
// The delegation act asserts is established by the POLICY LAYER, not by this
// profile: the agent's policies are evaluated before the assertion is minted, and a
// CEL condition there is what binds the agent to the user (IdP-attested, via a
// mapped act.sub on the user token, or operator-decided). This profile renders the
// pair that policy admitted; without a binding condition, any agent the policy
// authorizes may pair with any valid user token.
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
// The deepest act this renders is 1 + the chain bound applied when a token is
// authenticated (4).
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
		"sub":              req.User.PrincipalID,
		"aud":              req.Audience,
		"iat":              req.IssuedAt.Unix(),
		"nbf":              req.NotBefore.Unix(),
		"exp":              req.ExpiresAt.Unix(),
		"jti":              req.JTI,
		"act":              actClaim(req.Issuer, req.Identity, req.Metadata, req.User.Actors),
		"warden_namespace": req.User.NamespacePath,
		"warden_role":      req.User.RoleName,
	}
	if user := userClaimsWithoutSub(req.UserClaims); len(user) > 0 {
		claims["warden_metadata"] = user
	}
	if req.Resource != "" {
		claims["warden_resource"] = req.Resource
	}
	return claims, nil
}

// actClaim builds the act claim: the agent as current actor, with its own namespace,
// role and projected metadata, and the user token's chain nested beneath it as prior
// actors — those layers are the IdP's, so they get no Warden claims. prior is
// outermost-first, so the nesting is built innermost-out. metadata is read-only: it
// is embedded as-is, never written to, exactly as the default profile embeds it.
func actClaim(issuer string, agent credential.AssertionIdentity, metadata map[string]string, prior []credential.AssertionActor) map[string]any {
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
		"sub":              agent.PrincipalID,
		"iss":              issuer,
		"warden_namespace": agent.NamespacePath,
		"warden_role":      agent.RoleName,
	}
	if len(metadata) > 0 {
		act["warden_metadata"] = metadata
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

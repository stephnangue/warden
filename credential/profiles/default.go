// Package profiles holds the built-in assertion profiles — the claim shapes a
// warden_identity assertion can be minted in. It mirrors credential/types/:
// one file per profile, plus a builtin.go that registers them all.
package profiles

import (
	"errors"

	"github.com/stephnangue/warden/credential"
)

// DefaultProfile is the shape an unset assertion_profile selects. It names the
// agent, and — when a user is disclosed — the user the agent acts for:
//
//   - With NO user disclosed, the top level is the AGENT and there is no act.
//   - With a user disclosed, the token is an RFC 8693 delegation token: the top
//     level is the USER, whose authority is used, and act is the AGENT exercising
//     it. When the user token carried a verified act chain, that chain is nested
//     under the agent as PRIOR actors, oldest innermost (RFC 8693 §4.1), each layer
//     re-emitted as the IdP attested it — sub, plus iss only when that layer had one
//     — never rewritten or filled in. Per RFC 8693, a verifier applies access
//     control only to the top-level claims and the current actor; nested actors are
//     informational.
//
// The core decides whether a user is disclosed (req.User), not the spec alone: only
// when the spec lists assertion_user_claims, the assertion fills the SUBJECT slot
// (the actor token of a two-token exchange describes the agent — the token service
// builds act from its sub and learns the user from the subject token), and the
// source's verifier can bind claims beyond iss, sub and aud. So the profile
// branches on req.User, never on req.UserClaims, which the core also passes when it
// withholds the user, for request templating.
//
// The two principals are named differently, by what each is to Warden:
//
//   - The AGENT is named by Warden's composite
//     "wid:{nsID}:{mountAccessor}:{principalID}" — top-level sub, or act.sub. One
//     issuer signs for every namespace, and a namespace admin can mount an auth
//     method that asserts any principal id; the composite carries the Warden-
//     generated namespace and mount, which no namespace can forge, so it is a tenant
//     boundary even for a verifier that binds sub alone (AWS, Entra, Alibaba RAM).
//     The agent level therefore carries no warden_namespace.
//   - The USER is named by its raw id: the id the user's IdP asserted in the token
//     the agent presented, as the auth role's user_claim selects it — the same
//     value {{user.sub}} templates. The user is an identity Warden relays, and the
//     upstream knows it by that id. A raw id is not a tenant boundary, so the user
//     level carries warden_namespace, and a verifier MUST bind it together with
//     sub. It is the namespace path, matched exactly; the root namespace renders
//     "root" (credential.RootNamespaceClaim), which no child path can equal. Within
//     a namespace, a user id is unique only as far as its operator makes it: users
//     validated against different IdPs need a user_claim unique across them.
//
// The claims at each level:
//   - sub: as above.
//   - warden_namespace: the user level only.
//   - warden_role: for the agent, the role it was admitted under — the
//     authorization context an upstream may bind; a role-less agent (a root token)
//     renders it empty. For the user, the auth role its token was validated under
//     (the mount's user auth role): not an authorization role, since the user grants
//     the request no permissions, but the population of users the id belongs to.
//   - warden_metadata: for the agent, its projected login metadata
//     (assertion_metadata_claims); for the user, its projected claims
//     (assertion_user_claims) WITHOUT sub, which would repeat the top-level sub.
//     Opt-in, and absent rather than empty.
//   - act.iss (delegation only): Warden's issuer URL, the context act.sub is
//     vouched for in. RFC 8693 permits identity members such as these in act; the
//     IETF Actor Profile draft (draft-mcguinness-oauth-actor-profile) requires it.
//   - warden_resource (top level): the opt-in single downstream resource.
//
// The delegation act asserts is established by the POLICY LAYER, not by this
// profile: the agent's policies are evaluated before the assertion is minted, and a
// CEL condition there is what binds the agent to the user (IdP-attested, via a
// mapped act.sub on the user token, or operator-decided). This profile renders the
// pair that policy admitted; without a binding condition, any agent the policy
// authorizes may pair with any valid user token.
//
// One refusal, in CheckIdentities, which the core runs while it resolves the
// request's assertion — before any cache lookup: a user is disclosed and the agent's
// OWN token carries an act chain. RFC 8693 would make that chain's head the current
// actor, so naming the agent in act.sub would misstate who acts. With no user the
// agent's chain is simply not rendered — the token makes no delegation claim to
// misstate — and it stays in the audit log.
//
// The deepest act this renders is 1 + the chain bound applied when a token is
// authenticated (4).
//
// THIS SHAPE IS FROZEN from the release that introduced it: an unset
// assertion_profile means default, and verifiers bind to these claims. It replaced,
// deliberately and once, an earlier shape that carried warden_sub,
// warden_auth_mount, warden_namespace and a nested warden_user beside the agent's
// composite sub — whose agent-only sub it keeps byte for byte. A different claim
// shape ships as a new profile name.
type DefaultProfile struct{}

var (
	_ credential.AssertionProfile                = (*DefaultProfile)(nil)
	_ credential.AssertionProfileIdentityChecker = (*DefaultProfile)(nil)
)

// Name returns the profile name an operator writes in assertion_profile.
func (DefaultProfile) Name() string { return credential.DefaultAssertionProfileName }

// Typ returns the JOSE typ header.
func (DefaultProfile) Typ() string { return "JWT" }

// ValidateSpec accepts every spec: the profile renders every assertion_* key, and
// which principal is the subject is decided per request (by the slot, the source
// and whether a user is disclosed), not by the spec.
func (DefaultProfile) ValidateSpec(config credential.Config) error { return nil }

// errAgentActChain is the refusal for a delegation whose agent token carries its own
// act chain.
var errAgentActChain = errors.New("the agent token carries an RFC 8693 act chain; a delegation token would name the agent as the current actor and misstate who acts")

// CheckIdentities refuses a delegation whose agent is itself being acted for. A nil
// user — no user disclosed — is always accepted.
func (DefaultProfile) CheckIdentities(agent credential.AssertionIdentity, user *credential.AssertionIdentity) error {
	if user != nil && len(agent.Actors) > 0 {
		return errAgentActChain
	}
	return nil
}

// Claims renders the claim set: the agent at the top level when no user is
// disclosed, else the user at the top level and the agent in act. It re-runs
// CheckIdentities, as defence in depth for a caller that skipped the setup-time
// check. Every map it builds is fresh, nested act layers included, and it never
// writes to req.Metadata, req.UserClaims or either identity's Actors.
func (p DefaultProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	if err := p.CheckIdentities(req.Identity, req.User); err != nil {
		return nil, err
	}

	claims := map[string]any{
		"iss": req.Issuer,
		"aud": req.Audience,
		"iat": req.IssuedAt.Unix(),
		"nbf": req.NotBefore.Unix(),
		"exp": req.ExpiresAt.Unix(),
		"jti": req.JTI,
	}
	if req.User == nil {
		agentClaims(claims, req.Identity, req.Metadata)
	} else {
		userClaims(claims, *req.User, userClaimsWithoutSub(req.UserClaims))
		claims["act"] = actClaim(req.Issuer, req.Identity, req.Metadata, req.User.Actors)
	}
	if req.Resource != "" {
		claims["warden_resource"] = req.Resource
	}
	return claims, nil
}

// agentClaims writes the agent's identity claims into m: its composite subject, its
// role, and its metadata when there is any. metadata is embedded as-is and never
// written to.
func agentClaims(m map[string]any, agent credential.AssertionIdentity, metadata map[string]string) {
	m["sub"] = agent.WardenSubject()
	m["warden_role"] = agent.RoleName
	if len(metadata) > 0 {
		m["warden_metadata"] = metadata
	}
}

// userClaims writes the user's identity claims into m: its raw id qualified by its
// namespace, its role, and its metadata when there is any.
func userClaims(m map[string]any, user credential.AssertionIdentity, metadata map[string]string) {
	m["sub"] = user.PrincipalID
	m["warden_namespace"] = credential.NamespaceClaim(user.NamespacePath)
	m["warden_role"] = user.RoleName
	if len(metadata) > 0 {
		m["warden_metadata"] = metadata
	}
}

// actClaim builds the act claim: the agent as current actor with its identity
// claims and Warden's iss, and the user token's chain nested beneath it as prior
// actors — those layers are the IdP's, so they get no Warden claims. prior is
// outermost-first, so the nesting is built innermost-out.
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

	act := map[string]any{"iss": issuer}
	agentClaims(act, agent, metadata)
	if inner != nil {
		act["act"] = inner
	}
	return act
}

// userClaimsWithoutSub copies the projected user claims minus "sub", which is
// rendered as the top-level subject instead. Nil when nothing else is left.
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

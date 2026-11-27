package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	capoidc "github.com/hashicorp/cap/oidc"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// signInRequest is what a login asks the identity provider for, so that the
// sign-in meets mfa_options: the floor's values, and a fresh sign-in. It is a
// request only, which the identity provider may ignore; the callback checks
// what the ID token says (checkSignIn). Built once per configuration.
type signInRequest struct {
	// acrValues are the floor's values for a fact read from the acr claim,
	// sent as acr_values in the order listed (an order of preference).
	acrValues []string

	// claims is the claims request parameter (OpenID Connect Core §5.5): the
	// floor's other claims, each essential with the values listed, and
	// auth_time when maxAge is set. Nil when the floor names no such claim:
	// max_age alone already makes auth_time required. It is sent whether or
	// not discovery advertises claims_parameter_supported (Entra does not,
	// yet honours it), since an authorization server must ignore a parameter
	// it does not recognise (RFC 6749 §3.1).
	claims []byte

	// maxAge is mfa_options.reauthenticate_after, sent as max_age with
	// prompt=login; 0 when unset.
	maxAge time.Duration
}

// newSignInRequest derives what a login asks for from o under mapping m, which
// o was compiled against. Checked but never asked for: a floor value that is a
// pattern, or holds whitespace where it would go in acr_values (a list split
// on spaces); a fact read through a JSON pointer; and the built-in claims
// (sub, iss, aud), which the identity provider issues anyway. Nil when o is
// nil.
func newSignInRequest(o *helper.MFAOptions, m *selector.Mapping) *signInRequest {
	if o == nil {
		return nil
	}
	r := &signInRequest{maxAge: o.ReauthenticateAfter}
	idToken := map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(o.Require)) {
		key, ok := m.Resolve(name)
		if !ok || key.IsPointer() || slices.Contains(builtinFacts(), key.Name) {
			continue
		}
		values := askable(o.Require[name])
		if key.Name == "acr" {
			values = slices.DeleteFunc(values, func(v string) bool { return strings.ContainsFunc(v, unicode.IsSpace) })
		}
		switch {
		case len(values) == 0:
			continue
		case key.Name == "acr":
			r.acrValues = values
		case len(values) == 1:
			idToken[key.Name] = map[string]any{"essential": true, "value": values[0]}
		default:
			idToken[key.Name] = map[string]any{"essential": true, "values": values}
		}
	}
	if len(idToken) > 0 {
		if r.maxAge > 0 {
			idToken["auth_time"] = map[string]any{"essential": true}
		}
		// Maps of strings, booleans and string slices always encode.
		r.claims, _ = json.Marshal(map[string]any{"id_token": idToken})
	}
	return r
}

// askable returns the exact values among values, unescaped, in the order
// listed and each once: what a request can name. Patterns are left out.
func askable(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if selector.IsPattern(v) {
			continue
		}
		lit, err := selector.Unescape(v)
		if err != nil || slices.Contains(out, lit) {
			continue
		}
		out = append(out, lit)
	}
	return out
}

// options returns the authorization request options r asks for: acr_values,
// the claims parameter, and max_age with prompt=login. Nil for a nil r.
func (r *signInRequest) options() []capoidc.Option {
	if r == nil {
		return nil
	}
	var opts []capoidc.Option
	if len(r.acrValues) > 0 {
		opts = append(opts, capoidc.WithACRValues(r.acrValues...))
	}
	if r.claims != nil {
		opts = append(opts, capoidc.WithClaims(r.claims))
	}
	if r.maxAge > 0 {
		opts = append(opts, capoidc.WithMaxAge(uint(r.maxAge/time.Second)), capoidc.WithPrompts(capoidc.Login))
	}
	return opts
}

// Bounds on the auth_time of a sign-in that mfa_options.reauthenticate_after
// applies to.
const (
	// minFreshness is the least a sign-in must have left before
	// reauthenticate_after to be issued a session: one that would expire on
	// arrival is refused here, with its reason.
	minFreshness = time.Minute

	// maxAuthTimeSkew is how far ahead of Warden's clock an auth_time may be:
	// it is then taken as now. Further ahead, it is refused.
	maxAuthTimeSkew = time.Minute
)

var errNoAuthTime = errors.New("the ID token carries no auth_time, which mfa_options.reauthenticate_after needs: " +
	"have the identity provider put auth_time in the ID token")

// checkSignIn returns why the sign-in admitted as adm, under naming n (built
// from the configuration whose mfa_options are o), may not be issued a session
// at now, or nil. These are the only checks of what the login asked for (cap
// checks auth_time only when its own request carries max_age, which exchange's
// does not, and checks acr never), and they apply no leeway beyond taking an
// auth_time up to maxAuthTimeSkew ahead as now, which it sets on adm, so the
// session's freshness is never stretched by the identity provider's clock.
func checkSignIn(adm *logical.Admission, n *logical.MountNaming, o *helper.MFAOptions, now time.Time) error {
	var r *logical.MFARequirement
	if n != nil {
		r = n.MFA
	}
	if adm.AuthTime.After(now) {
		if ahead := adm.AuthTime.Sub(now); r != nil && r.ReauthenticateAfter > 0 && ahead > maxAuthTimeSkew {
			return fmt.Errorf("the ID token's auth_time is %s ahead of this server's clock: "+
				"the identity provider's clock is off", ahead.Truncate(time.Second))
		}
		adm.AuthTime = now
	}
	if r == nil {
		return nil
	}
	if r.Invalid != nil {
		return errConfigInvalid
	}
	if r.ReauthenticateAfter > 0 {
		if adm.AuthTime.IsZero() {
			return errNoAuthTime
		}
		age := now.Sub(adm.AuthTime).Truncate(time.Second)
		switch left := adm.AuthTime.Add(r.ReauthenticateAfter).Sub(now); {
		case left <= 0:
			return fmt.Errorf("the identity provider reports a sign-in %s ago, older than mfa_options."+
				"reauthenticate_after (%s): it kept an earlier sign-in rather than asking for a new one",
				age, r.ReauthenticateAfter)
		case left < minFreshness:
			return fmt.Errorf("the identity provider reports a sign-in %s ago, within a minute of mfa_options."+
				"reauthenticate_after (%s): it kept an earlier sign-in rather than asking for a new one",
				age, r.ReauthenticateAfter)
		}
	}
	// The floor, as core checks it on every request; Unmet names what failed.
	err := adm.CheckMFA(n, now)
	if !errors.Is(err, logical.ErrMFARequireNotMet) {
		return err
	}
	name := r.Rule.Unmet(adm.Source(n))
	claim := name
	if key, ok := n.Mapping.Resolve(name); ok {
		claim = key.Name
	}
	var values []string
	if o != nil {
		values = o.Require[name]
	}
	return fmt.Errorf("the sign-in does not meet mfa_options.require: fact %q (claim %q) holds none of: %s",
		name, claim, strings.Join(values, ", "))
}

// sessionTTL returns the lifetime of the session a sign-in at adm.AuthTime is
// issued at now: base, the mount's session_ttl, cut to end when the sign-in
// grows older than n's reauthenticate_after. checkSignIn has made sure at
// least minFreshness is left.
func sessionTTL(base time.Duration, adm *logical.Admission, n *logical.MountNaming, now time.Time) time.Duration {
	if n == nil || n.MFA == nil || n.MFA.ReauthenticateAfter <= 0 || adm.AuthTime.IsZero() {
		return base
	}
	return min(base, adm.AuthTime.Add(n.MFA.ReauthenticateAfter).Sub(now))
}

package drivers

import (
	"fmt"
	"regexp"
	"strings"
)

// Claim templating lets a spec select what it fetches from the verified claims of
// the principals on the request, so one spec can serve many callers and each
// reaches only its own material. It is shared by every driver whose fetch
// coordinate is a string the operator writes — a secret path, a stored-secret id,
// a signing key name — and the rules below are the same wherever it is used.

// claimTemplate matches a {{user.<claim>}} or {{agent.<claim>}} token in a request
// coordinate. The claim name is a conservative identifier (letters, digits, '_',
// '.', '-').
//
// One expression rather than one per principal: every rule that follows a
// substitution — the value allow-list, the traversal check, the leftover-fragment
// check — is the same whichever principal supplied the value, and a single pass makes
// a coordinate mixing both namespaces order-independent.
var claimTemplate = regexp.MustCompile(`\{\{(user|agent)\.([A-Za-z0-9_.-]+)\}\}`)

// claimTemplatePrefixes are the literal openings claimTemplate can match. Both the
// fast path and the leftover check scan for them, so a malformed token (a missing
// brace, an empty claim name) is refused rather than sent as literal bytes.
var claimTemplatePrefixes = []string{"{{user.", "{{agent."}

// claimValuePattern is the strict allow-list a substituted claim value must
// match before it can be placed into a request coordinate. It excludes '/' (which
// would let one value span segments) and every other separator. '.' is allowed
// (e.g. first.last), so a value or adjacent values could still compose a "."/".."
// segment — that is caught after substitution by the segment check below, not here.
var claimValuePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)

// containsClaimTemplate reports whether raw opens either namespace's token.
func containsClaimTemplate(raw string) bool {
	for _, prefix := range claimTemplatePrefixes {
		if strings.Contains(raw, prefix) {
			return true
		}
	}
	return false
}

// resolveClaimTemplate substitutes any {{user.<claim>}} or {{agent.<claim>}} token in
// raw from the projected claims of the principal each names. A value with no such
// token is returned verbatim (byte-identical to the pre-templating behaviour). It FAILS
// CLOSED when a referenced claim is absent, when a value is empty or not in the strict
// allow-list, or when the RESOLVED value contains a "." / ".." segment or a leftover
// template fragment.
//
// The last check is the real boundary. A coordinate is frequently a path, and a
// client that cleans one before sending it would resolve a claim value of "."
// (which collapses its segment) or two adjacent tokens composing ".." into a
// different, likely shared or parent, target — so a per-principal value that could
// compose one must deny instead. field names the config key for error messages.
func resolveClaimTemplate(raw string, userClaims, agentClaims map[string]string, field string) (string, error) {
	if !containsClaimTemplate(raw) {
		return raw, nil
	}
	// Deliberately NOT an ErrUserRequired case, however tempting: an empty claim
	// map does not mean the request lacked a principal. Claims are projected only
	// when the spec opts in, and when it does, core has already rejected a
	// principal-less request before the driver runs — and a present principal
	// always yields at least "sub". So reaching here with no claims means the
	// spec structurally cannot project any, which no amount of authenticating
	// will change. Returning a 401 challenge would send the caller into an OAuth
	// loop it cannot escape while hiding the real fix from the operator. That
	// holds doubly for the agent, which is present on every request.
	var subErr error
	resolved := claimTemplate.ReplaceAllStringFunc(raw, func(match string) string {
		groups := claimTemplate.FindStringSubmatch(match)
		principal, claim := groups[1], groups[2]

		claims, fix := userClaims, "list it in assertion_user_claims, which requires subject_token_source=warden_identity"
		if principal == "agent" {
			claims = agentClaims
			switch {
			case len(agentClaims) == 0:
				// Nothing was projected at all, so the subject source is the fault,
				// not the list — and for "sub", which needs no listing, it is the
				// only possible fault. Sending an operator to the allow-list here
				// would have them add an entry that changes nothing.
				fix = "the agent's claims are projected only when subject_token_source is agent_identity or warden_identity"
			case claim == "sub":
				// Projection ran and still produced no sub. It is written
				// unconditionally from the principal, so this is unreachable
				// short of a construction bug — say that rather than blame config.
				fix = "the agent's principal is always projected, so this indicates an internal error rather than a configuration one"
			default:
				// Projection ran without this claim. Listing it is necessary but
				// may not be sufficient: an absent metadata key is skipped rather
				// than rejected, so the login may simply not carry it.
				fix = "list it in assertion_metadata_claims, and check the agent's login provides it"
			}
		}

		v, ok := claims[claim]
		if !ok {
			// The principal IS present; this claim was simply never projected. For
			// the user, note that assertion_user_claims only applies to a
			// warden_identity subject — pairing {{user.…}} with
			// subject_token_source=user_identity cannot populate claims at all,
			// which is the likelier mistake.
			subErr = fmt.Errorf("%s references {{%s.%s}} but that claim is absent from the %s's projected claims (%s)",
				field, principal, claim, principal, fix)
			return ""
		}
		// The value becomes request bytes: a single non-empty allow-listed token
		// that cannot span segments (no '/'). Dot-only / traversal segments it might
		// compose are rejected after substitution.
		if v == "" || !claimValuePattern.MatchString(v) {
			subErr = fmt.Errorf("%s claim %q has a value rejected by the allow-list", field, claim)
			return ""
		}
		return v
	})
	if subErr != nil {
		return "", subErr
	}
	// A leftover fragment means a malformed token (e.g. a missing brace or an empty
	// claim name) — fail closed rather than use a literal "{{user.…" value.
	if containsClaimTemplate(resolved) {
		return "", fmt.Errorf("%s has an unresolved template fragment after substitution", field)
	}
	// Reject any "." or ".." segment the substituted value(s) may have composed —
	// a client that cleans the coordinate would otherwise resolve it into a
	// different target.
	for _, seg := range strings.Split(resolved, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("%s resolves to a %q path segment (traversal)", field, seg)
		}
	}
	return resolved, nil
}

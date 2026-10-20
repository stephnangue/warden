package jwt

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// jwtBuiltinFacts are the claims every jwt mount publishes under their own
// names: the ones the validator checks against the mount's expectations
// (issuer, subject, audiences). Every other claim is invisible until mapped.
var jwtBuiltinFacts = []string{"sub", "iss", "aud"}

var _ logical.FactsProvider = (*jwtAuthBackend)(nil)

// compileNaming compiles a mount's entity kind and fact mapping into the naming
// its admissions are read through. Errors name the config key at fault.
func compileNaming(kind string, facts map[string]string) (*logical.MountNaming, error) {
	mapping, err := selector.CompileMapping(jwtBuiltinFacts, facts)
	if err != nil {
		return nil, fmt.Errorf("facts: %w", err)
	}
	naming, err := logical.NewMountNaming(mapping, kind)
	if err != nil {
		return nil, fmt.Errorf("entity_kind: %w", err)
	}
	return naming, nil
}

// factsFromField converts the facts field of a config write: every fact name
// must be a string. An empty map clears the mapping.
func factsFromField(raw map[string]any) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	facts := make(map[string]string, len(raw))
	for source, v := range raw {
		name, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("facts: the fact name for source %q must be a string, got %T", source, v)
		}
		facts[source] = name
	}
	return facts, nil
}

// FactNames implements logical.FactsProvider: every fact name the mount
// answers under its current configuration, built-in and mapped, sorted. It is
// empty when the mount has no configuration or its facts do not compile, since
// such a mount answers nothing. It loads the naming without a lock.
func (b *jwtAuthBackend) FactNames() []string {
	n := b.mountFacts.Load()
	if n == nil {
		return nil
	}
	return slices.Clone(n.Mapping.Names())
}

// newAdmission returns what the login verified about token, whose validated
// claims are claims. The admission adopts claims without copying: the caller
// must not read or modify them afterwards, and nothing else may hold them.
// mount is the backend's live naming, so a later mapping edit reaches this
// admission.
func newAdmission(claims map[string]any, token string, mount *logical.MountFacts) *logical.Admission {
	return &logical.Admission{
		Facts:    selector.NewClaims(claims),
		Mount:    mount,
		IssuedAt: issuedAt(claims),
		Bytes:    payloadBytes(token),
	}
}

// issuedAt returns the token's iat as a time, or zero when the claim is absent,
// not a number, or not after the epoch.
func issuedAt(claims map[string]any) time.Time {
	v, ok := claims["iat"]
	if !ok {
		return time.Time{}
	}
	iat, ok := parseNumericClaim(v)
	if !ok || iat <= 0 {
		return time.Time{}
	}
	return time.Unix(iat, 0)
}

// payloadBytes estimates the memory the decoded claims retain as the size of
// the token's JSON payload: the decoded length of its middle segment. The
// decoded map is larger than its text by a roughly constant factor, so this
// ranks cached admissions correctly; it is 0 for a token without three
// segments, which validation has already refused.
func payloadBytes(token string) int64 {
	_, rest, ok := strings.Cut(token, ".")
	if !ok {
		return 0
	}
	payload, _, ok := strings.Cut(rest, ".")
	if !ok {
		return 0
	}
	return int64(base64.RawURLEncoding.DecodedLen(len(payload)))
}

package credential

import (
	"context"
	"strings"
	"testing"
)

// stubResolve is a no-op lazy subject-token provider for tests.
func stubResolve(context.Context) (string, error) { return "lazy-token", nil }

func TestExchangeInputs_Validate(t *testing.T) {
	tests := []struct {
		name    string
		inputs  *ExchangeInputs
		wantErr bool
	}{
		{
			name: "valid subject only",
			inputs: &ExchangeInputs{
				SubjectToken:     "eyJ.sub",
				SubjectTokenType: TokenTypeJWT,
			},
		},
		{
			name: "valid subject and actor",
			inputs: &ExchangeInputs{
				SubjectToken:     "eyJ.sub",
				SubjectTokenType: TokenTypeJWT,
				ActorToken:       "eyJ.act",
				ActorTokenType:   TokenTypeJWT,
			},
		},
		{
			name: "missing subject token",
			inputs: &ExchangeInputs{
				SubjectTokenType: TokenTypeJWT,
			},
			wantErr: true,
		},
		{
			name: "lazy subject with cache identity",
			inputs: &ExchangeInputs{
				// SubjectToken empty on purpose: resolved lazily on a cache miss.
				SubjectTokenType:     TokenTypeJWT,
				SubjectCacheIdentity: "wid:ns:mount:alice\x00aud",
				ResolveSubjectToken:  stubResolve,
			},
		},
		{
			name: "lazy subject without cache identity",
			inputs: &ExchangeInputs{
				SubjectTokenType:    TokenTypeJWT,
				ResolveSubjectToken: stubResolve,
			},
			wantErr: true,
		},
		{
			name: "missing subject token type",
			inputs: &ExchangeInputs{
				SubjectToken: "eyJ.sub",
			},
			wantErr: true,
		},
		{
			name: "actor token without type",
			inputs: &ExchangeInputs{
				SubjectToken:     "eyJ.sub",
				SubjectTokenType: TokenTypeJWT,
				ActorToken:       "eyJ.act",
			},
			wantErr: true,
		},
		{
			name: "actor type without token",
			inputs: &ExchangeInputs{
				SubjectToken:     "eyJ.sub",
				SubjectTokenType: TokenTypeJWT,
				ActorTokenType:   TokenTypeJWT,
			},
			wantErr: true,
		},
		{
			name: "lazy actor with cache identity",
			inputs: &ExchangeInputs{
				// Eager user_identity subject paired with a lazy warden_identity actor:
				// ActorToken empty on purpose, resolved on a cache miss.
				SubjectToken:       "eyJ.user",
				SubjectTokenType:   TokenTypeJWT,
				ActorTokenType:     TokenTypeJWT,
				ActorCacheIdentity: "wid:ns:mount:agent\x00aud",
				ResolveActorToken:  stubResolve,
			},
		},
		{
			name: "lazy actor without cache identity",
			inputs: &ExchangeInputs{
				SubjectToken:      "eyJ.user",
				SubjectTokenType:  TokenTypeJWT,
				ActorTokenType:    TokenTypeJWT,
				ResolveActorToken: stubResolve,
			},
			wantErr: true,
		},
		{
			name: "lazy actor without token type",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.user",
				SubjectTokenType:   TokenTypeJWT,
				ActorCacheIdentity: "wid:ns:mount:agent\x00aud",
				ResolveActorToken:  stubResolve,
			},
			wantErr: true,
		},
		{
			name: "oversized subject token",
			inputs: &ExchangeInputs{
				SubjectToken:     string(make([]byte, maxExchangeTokenBytes+1)),
				SubjectTokenType: TokenTypeJWT,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inputs.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExchangeInputs_Validate_Nil(t *testing.T) {
	var e *ExchangeInputs
	if err := e.Validate(); err == nil {
		t.Fatal("expected error validating nil inputs")
	}
}

func TestExchangeInputs_Fingerprint_Deterministic(t *testing.T) {
	a := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}
	b := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("identical inputs must fingerprint identically")
	}
}

func TestExchangeInputs_Fingerprint_Distinct(t *testing.T) {
	base := ExchangeInputs{
		SubjectToken:     "sub",
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       "act",
		ActorTokenType:   TokenTypeJWT,
	}
	variants := map[string]ExchangeInputs{
		"different subject":       {SubjectToken: "sub2", SubjectTokenType: TokenTypeJWT, ActorToken: "act", ActorTokenType: TokenTypeJWT},
		"different actor":         {SubjectToken: "sub", SubjectTokenType: TokenTypeJWT, ActorToken: "act2", ActorTokenType: TokenTypeJWT},
		"different subject type":  {SubjectToken: "sub", SubjectTokenType: TokenTypeAccessToken, ActorToken: "act", ActorTokenType: TokenTypeJWT},
		"swapped subject / actor": {SubjectToken: "act", SubjectTokenType: TokenTypeJWT, ActorToken: "sub", ActorTokenType: TokenTypeJWT},
	}
	baseFP := base.Fingerprint()
	for name, v := range variants {
		if v.Fingerprint() == baseFP {
			t.Errorf("%s: fingerprint collided with base", name)
		}
	}
}

// TestExchangeInputs_Fingerprint_NoConcatAmbiguity guards the length-prefixing:
// moving a byte across a field boundary must change the fingerprint.
func TestExchangeInputs_Fingerprint_NoConcatAmbiguity(t *testing.T) {
	x := &ExchangeInputs{SubjectToken: "ab", SubjectTokenType: TokenTypeJWT, ActorToken: "c", ActorTokenType: TokenTypeJWT}
	y := &ExchangeInputs{SubjectToken: "a", SubjectTokenType: TokenTypeJWT, ActorToken: "bc", ActorTokenType: TokenTypeJWT}
	if x.Fingerprint() == y.Fingerprint() {
		t.Fatal("length-prefixing must prevent concatenation ambiguity")
	}
}

// TestExchangeInputs_Fingerprint_SubjectCacheIdentity covers the Warden-minted-subject
// caching contract: the fingerprint keys on SubjectCacheIdentity (stable) rather than
// the volatile SubjectToken, so re-mints of the same identity share a cache
// entry while distinct identities stay isolated and cannot collide with the
// raw-subject path.
func TestExchangeInputs_Fingerprint_SubjectCacheIdentity(t *testing.T) {
	// Same identity, different (freshly minted) subject bytes -> same fingerprint.
	a := &ExchangeInputs{SubjectToken: "assertion-mint-1", SubjectTokenType: TokenTypeJWT, SubjectCacheIdentity: "wid:ns:mount:alice|aud"}
	b := &ExchangeInputs{SubjectToken: "assertion-mint-2", SubjectTokenType: TokenTypeJWT, SubjectCacheIdentity: "wid:ns:mount:alice|aud"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("same SubjectCacheIdentity must fingerprint identically despite different subject bytes")
	}

	// Different identity -> different fingerprint.
	c := &ExchangeInputs{SubjectToken: "assertion-mint-1", SubjectTokenType: TokenTypeJWT, SubjectCacheIdentity: "wid:ns:mount:bob|aud"}
	if c.Fingerprint() == a.Fingerprint() {
		t.Fatal("distinct SubjectCacheIdentity must fingerprint differently")
	}

	// Domain separation: SubjectCacheIdentity="X" must not collide with SubjectToken="X".
	viaIdentity := &ExchangeInputs{SubjectToken: "assertion", SubjectTokenType: TokenTypeJWT, SubjectCacheIdentity: "X"}
	viaSubject := &ExchangeInputs{SubjectToken: "X", SubjectTokenType: TokenTypeJWT}
	if viaIdentity.Fingerprint() == viaSubject.Fingerprint() {
		t.Fatal("SubjectCacheIdentity path must be domain-separated from the raw-subject path")
	}

	// Setting SubjectCacheIdentity must change the fingerprint vs. keying on the subject.
	withID := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, SubjectCacheIdentity: "id"}
	withoutID := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}
	if withID.Fingerprint() == withoutID.Fingerprint() {
		t.Fatal("SubjectCacheIdentity must be folded into the fingerprint")
	}
}

// TestExchangeInputs_Fingerprint_IgnoresResolveClosure proves the lazy provider
// does not enter the cache key: a leader (closure set, subject not yet minted)
// and a would-be follower must key identically so they share one cache entry.
func TestExchangeInputs_Fingerprint_IgnoresResolveClosure(t *testing.T) {
	base := ExchangeInputs{
		SubjectTokenType:     TokenTypeJWT,
		SubjectCacheIdentity: "wid:ns:mount:alice\x00aud",
	}
	withClosure := base
	withClosure.ResolveSubjectToken = stubResolve

	if base.Fingerprint() != withClosure.Fingerprint() {
		t.Fatal("ResolveSubjectToken must not affect the fingerprint")
	}

	// And a later-populated SubjectToken must also not change the key (the closure
	// path keys on SubjectCacheIdentity, not the minted bytes).
	populated := withClosure
	populated.SubjectToken = "freshly-minted-assertion"
	if populated.Fingerprint() != base.Fingerprint() {
		t.Fatal("a lazily-populated SubjectToken must not change the SubjectCacheIdentity-keyed fingerprint")
	}
}

// TestExchangeInputs_Fingerprint_ActorCacheIdentity mirrors the subject
// cache-identity contract for a lazily-minted actor (warden_identity delegation):
// the fingerprint keys on ActorCacheIdentity (stable), the closure and any
// later-populated ActorToken bytes never enter the key, and the ActorCacheIdentity
// path is domain-separated from a raw ActorToken of the same value.
func TestExchangeInputs_Fingerprint_ActorCacheIdentity(t *testing.T) {
	base := ExchangeInputs{
		SubjectToken:       "eyJ.user",
		SubjectTokenType:   TokenTypeJWT,
		ActorTokenType:     TokenTypeJWT,
		ActorCacheIdentity: "wid:ns:mount:agent\x00aud",
	}
	withClosure := base
	withClosure.ResolveActorToken = stubResolve
	if base.Fingerprint() != withClosure.Fingerprint() {
		t.Fatal("ResolveActorToken must not affect the fingerprint")
	}
	populated := withClosure
	populated.ActorToken = "freshly-minted-actor-assertion"
	if populated.Fingerprint() != base.Fingerprint() {
		t.Fatal("a lazily-populated ActorToken must not change the ActorCacheIdentity-keyed fingerprint")
	}

	// Distinct actor identity -> distinct fingerprint.
	other := base
	other.ActorCacheIdentity = "wid:ns:mount:other-agent\x00aud"
	if other.Fingerprint() == base.Fingerprint() {
		t.Fatal("distinct ActorCacheIdentity must fingerprint differently")
	}

	// Domain separation: ActorCacheIdentity="X" must not collide with ActorToken="X".
	viaIdentity := ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, ActorTokenType: TokenTypeJWT, ActorCacheIdentity: "X"}
	viaToken := ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, ActorTokenType: TokenTypeJWT, ActorToken: "X"}
	if viaIdentity.Fingerprint() == viaToken.Fingerprint() {
		t.Fatal("ActorCacheIdentity path must be domain-separated from the raw-actor path")
	}
}

func TestSpecRequestsExchange(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		want   bool
	}{
		{"absent", map[string]string{}, false},
		{"none", map[string]string{ConfigSubjectTokenSource: SourceNone}, false},
		{"agent_identity", map[string]string{ConfigSubjectTokenSource: SourceAgentIdentity}, true},
		{"user_identity", map[string]string{ConfigSubjectTokenSource: SourceUserIdentity}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SpecRequestsExchange(tt.config); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateExchangeSpecConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{"empty is valid", map[string]string{}, false},
		{"subject agent_identity", map[string]string{ConfigSubjectTokenSource: SourceAgentIdentity}, false},
		{"subject user_identity", map[string]string{ConfigSubjectTokenSource: SourceUserIdentity}, false},
		{
			// The retired "header" source is no longer accepted by the OneOf.
			name:    "subject header rejected",
			config:  map[string]string{ConfigSubjectTokenSource: "header"},
			wantErr: true,
		},
		{
			// The retired "auth_token" literal is no longer accepted by the OneOf.
			name:    "subject auth_token literal rejected",
			config:  map[string]string{ConfigSubjectTokenSource: "auth_token"},
			wantErr: true,
		},
		{
			name:    "invalid subject source",
			config:  map[string]string{ConfigSubjectTokenSource: "bogus"},
			wantErr: true,
		},
		{
			name:    "invalid actor source",
			config:  map[string]string{ConfigSubjectTokenSource: SourceUserIdentity, ConfigActorTokenSource: "bogus"},
			wantErr: true,
		},
		{
			name:    "actor without subject",
			config:  map[string]string{ConfigActorTokenSource: SourceAgentIdentity},
			wantErr: true,
		},
		{
			// The valid delegation shape: a user subject with the agent as actor.
			name:   "subject user_identity + actor agent_identity",
			config: map[string]string{ConfigSubjectTokenSource: SourceUserIdentity, ConfigActorTokenSource: SourceAgentIdentity},
		},
		{
			// An actor is only meaningful in the delegation shape (subject=user_identity),
			// so agent_identity subject + any actor is rejected.
			name:    "subject agent_identity + actor agent_identity rejected",
			config:  map[string]string{ConfigSubjectTokenSource: SourceAgentIdentity, ConfigActorTokenSource: SourceAgentIdentity},
			wantErr: true,
		},
		{
			// The audience-required rule is now source-aware and enforced one layer
			// up (in the core config store), since some source types derive the
			// audience from their own config. This structural validator no longer
			// rejects a missing audience on its own.
			name:    "warden_identity without assertion_audience (structural: allowed)",
			config:  map[string]string{ConfigSubjectTokenSource: SourceWardenIdentity},
			wantErr: false,
		},
		{
			name:   "warden_identity with assertion_audience",
			config: map[string]string{ConfigSubjectTokenSource: SourceWardenIdentity, ConfigAssertionAudience: "https://sts.example/aud"},
		},
		{
			name: "assertion_metadata_claims with warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource:      SourceWardenIdentity,
				ConfigAssertionAudience:       "https://sts.example/aud",
				ConfigAssertionMetadataClaims: "team,env",
			},
		},
		{
			// agent_identity mints no assertion, so nothing is projected into one —
			// but the same list names what {{agent.<claim>}} may template, and that
			// works on a forwarded agent token too.
			name: "assertion_metadata_claims with agent_identity",
			config: map[string]string{
				ConfigSubjectTokenSource:      SourceAgentIdentity,
				ConfigAssertionMetadataClaims: "team",
			},
		},
		{
			// user_identity carries neither job: no assertion is minted, and the
			// agent's claims are not what a user-subject spec templates on.
			name: "assertion_metadata_claims with user_identity",
			config: map[string]string{
				ConfigSubjectTokenSource:      SourceUserIdentity,
				ConfigAssertionMetadataClaims: "team",
			},
			wantErr: true,
		},
		{
			name: "assertion_algorithm ES256 with warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
				ConfigAssertionAlgorithm: AssertionAlgES256,
			},
		},
		{
			name: "assertion_algorithm unknown value",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
				ConfigAssertionAlgorithm: "EdDSA",
			},
			wantErr: true,
		},
		{
			name: "assertion_algorithm without warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceAgentIdentity,
				ConfigAssertionAlgorithm: AssertionAlgES256,
			},
			wantErr: true,
		},
		{
			name: "assertion_resource with warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
				ConfigAssertionResource:  "aws-secretsmanager:prod/db",
			},
			wantErr: false,
		},
		{
			name: "assertion_resource=none with warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
				ConfigAssertionResource:  AssertionResourceNone,
			},
			wantErr: false,
		},
		{
			name: "assertion_resource without warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceAgentIdentity,
				ConfigAssertionResource:  "aws-secretsmanager:prod/db",
			},
			wantErr: true,
		},
		{
			// The valid delegation shape with a Warden-minted actor assertion.
			name: "actor warden_identity with user_identity subject",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceUserIdentity,
				ConfigActorTokenSource:   SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
			},
		},
		{
			name: "actor warden_identity rejects agent_identity subject",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceAgentIdentity,
				ConfigActorTokenSource:   SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
			},
			wantErr: true,
		},
		{
			name: "actor warden_identity rejects warden_identity subject",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceWardenIdentity,
				ConfigActorTokenSource:   SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
			},
			wantErr: true,
		},
		{
			name: "assertion_algorithm valid when actor is warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource: SourceUserIdentity,
				ConfigActorTokenSource:   SourceWardenIdentity,
				ConfigAssertionAudience:  "https://sts.example/aud",
				ConfigAssertionAlgorithm: AssertionAlgES256,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExchangeSpecConfig(tt.config)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAssertionMetadataKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"unset", "", nil},
		{"single", "team", []string{"team"}},
		{"multiple with spaces", " team , env ", []string{"team", "env"}},
		{"blanks skipped", "team,,env,", []string{"team", "env"}},
		{"dedup preserves order", "team,env,team", []string{"team", "env"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssertionMetadataKeys(map[string]string{ConfigAssertionMetadataClaims: tt.raw})
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestAssertionUserClaimKeys(t *testing.T) {
	if got := AssertionUserClaimKeys(map[string]string{}); got != nil {
		t.Errorf("empty config: got %v, want nil", got)
	}
	// Trimmed, de-duplicated, order-preserving.
	got := AssertionUserClaimKeys(map[string]string{ConfigAssertionUserClaims: " username , email , username "})
	want := []string{"username", "email"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestValidateExchangeSpecConfig_AssertionUserClaimsGate(t *testing.T) {
	// Valid: a warden_identity subject mints the assertion the claims ride in.
	if err := ValidateExchangeSpecConfig(map[string]string{
		ConfigSubjectTokenSource:  SourceWardenIdentity,
		ConfigAssertionUserClaims: "username",
	}); err != nil {
		t.Fatalf("warden_identity + assertion_user_claims should be valid: %v", err)
	}
	// "sub" alone is valid — the identity-only opt-in.
	if err := ValidateExchangeSpecConfig(map[string]string{
		ConfigSubjectTokenSource:  SourceWardenIdentity,
		ConfigAssertionUserClaims: "sub",
	}); err != nil {
		t.Fatalf("assertion_user_claims=sub should be valid: %v", err)
	}
	// A set-but-empty value (parses to zero keys) is rejected.
	if err := ValidateExchangeSpecConfig(map[string]string{
		ConfigSubjectTokenSource:  SourceWardenIdentity,
		ConfigAssertionUserClaims: " , ",
	}); err == nil {
		t.Fatal("whitespace-only assertion_user_claims must be rejected")
	}
	// Rejected: a non-minting subject cannot carry warden_user.
	err := ValidateExchangeSpecConfig(map[string]string{
		ConfigSubjectTokenSource:  SourceAgentIdentity,
		ConfigAssertionUserClaims: "username",
	})
	if err == nil {
		t.Fatal("assertion_user_claims without a warden_identity subject/actor must be rejected")
	}
	if !strings.Contains(err.Error(), ConfigAssertionUserClaims) {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

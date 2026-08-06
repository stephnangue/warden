package credential

import (
	"context"
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
				SubjectToken:       "eyJ.sub",
				SubjectTokenType:   TokenTypeJWT,
				SubjectTokenOrigin: ExchangeOriginVerified,
			},
		},
		{
			name: "valid subject and actor",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.sub",
				SubjectTokenType:   TokenTypeJWT,
				ActorToken:         "eyJ.act",
				ActorTokenType:     TokenTypeJWT,
				SubjectTokenOrigin: ExchangeOriginUnverified,
			},
		},
		{
			name: "missing subject token",
			inputs: &ExchangeInputs{
				SubjectTokenType:   TokenTypeJWT,
				SubjectTokenOrigin: ExchangeOriginVerified,
			},
			wantErr: true,
		},
		{
			name: "lazy subject with cache identity",
			inputs: &ExchangeInputs{
				// SubjectToken empty on purpose: resolved lazily on a cache miss.
				SubjectTokenType:    TokenTypeJWT,
				SubjectTokenOrigin:  ExchangeOriginVerified,
				CacheIdentity:       "wid:ns:mount:alice\x00aud",
				ResolveSubjectToken: stubResolve,
			},
		},
		{
			name: "lazy subject without cache identity",
			inputs: &ExchangeInputs{
				SubjectTokenType:    TokenTypeJWT,
				SubjectTokenOrigin:  ExchangeOriginVerified,
				ResolveSubjectToken: stubResolve,
			},
			wantErr: true,
		},
		{
			name: "missing subject token type",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.sub",
				SubjectTokenOrigin: ExchangeOriginVerified,
			},
			wantErr: true,
		},
		{
			name: "actor token without type",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.sub",
				SubjectTokenType:   TokenTypeJWT,
				ActorToken:         "eyJ.act",
				SubjectTokenOrigin: ExchangeOriginVerified,
			},
			wantErr: true,
		},
		{
			name: "actor type without token",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.sub",
				SubjectTokenType:   TokenTypeJWT,
				ActorTokenType:     TokenTypeJWT,
				SubjectTokenOrigin: ExchangeOriginVerified,
			},
			wantErr: true,
		},
		{
			name: "unknown origin",
			inputs: &ExchangeInputs{
				SubjectToken:       "eyJ.sub",
				SubjectTokenType:   TokenTypeJWT,
				SubjectTokenOrigin: "made-up",
			},
			wantErr: true,
		},
		{
			name: "oversized subject token",
			inputs: &ExchangeInputs{
				SubjectToken:       string(make([]byte, maxExchangeTokenBytes+1)),
				SubjectTokenType:   TokenTypeJWT,
				SubjectTokenOrigin: ExchangeOriginVerified,
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
	a := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified}
	b := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("identical inputs must fingerprint identically")
	}
}

func TestExchangeInputs_Fingerprint_Distinct(t *testing.T) {
	base := ExchangeInputs{
		SubjectToken:       "sub",
		SubjectTokenType:   TokenTypeJWT,
		ActorToken:         "act",
		ActorTokenType:     TokenTypeJWT,
		SubjectTokenOrigin: ExchangeOriginVerified,
	}
	variants := map[string]ExchangeInputs{
		"different subject":       {SubjectToken: "sub2", SubjectTokenType: TokenTypeJWT, ActorToken: "act", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified},
		"different actor":         {SubjectToken: "sub", SubjectTokenType: TokenTypeJWT, ActorToken: "act2", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified},
		"different subject type":  {SubjectToken: "sub", SubjectTokenType: TokenTypeAccessToken, ActorToken: "act", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified},
		"different origin":        {SubjectToken: "sub", SubjectTokenType: TokenTypeJWT, ActorToken: "act", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginUnverified},
		"swapped subject / actor": {SubjectToken: "act", SubjectTokenType: TokenTypeJWT, ActorToken: "sub", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified},
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
	x := &ExchangeInputs{SubjectToken: "ab", SubjectTokenType: TokenTypeJWT, ActorToken: "c", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified}
	y := &ExchangeInputs{SubjectToken: "a", SubjectTokenType: TokenTypeJWT, ActorToken: "bc", ActorTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified}
	if x.Fingerprint() == y.Fingerprint() {
		t.Fatal("length-prefixing must prevent concatenation ambiguity")
	}
}

// TestExchangeInputs_Fingerprint_CacheIdentity covers the Warden-minted-subject
// caching contract: the fingerprint keys on CacheIdentity (stable) rather than
// the volatile SubjectToken, so re-mints of the same identity share a cache
// entry while distinct identities stay isolated and cannot collide with the
// raw-subject path.
func TestExchangeInputs_Fingerprint_CacheIdentity(t *testing.T) {
	// Same identity, different (freshly minted) subject bytes -> same fingerprint.
	a := &ExchangeInputs{SubjectToken: "assertion-mint-1", SubjectTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified, CacheIdentity: "wid:ns:mount:alice|aud"}
	b := &ExchangeInputs{SubjectToken: "assertion-mint-2", SubjectTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified, CacheIdentity: "wid:ns:mount:alice|aud"}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("same CacheIdentity must fingerprint identically despite different subject bytes")
	}

	// Different identity -> different fingerprint.
	c := &ExchangeInputs{SubjectToken: "assertion-mint-1", SubjectTokenType: TokenTypeJWT, SubjectTokenOrigin: ExchangeOriginVerified, CacheIdentity: "wid:ns:mount:bob|aud"}
	if c.Fingerprint() == a.Fingerprint() {
		t.Fatal("distinct CacheIdentity must fingerprint differently")
	}

	// Domain separation: CacheIdentity="X" must not collide with SubjectToken="X".
	viaIdentity := &ExchangeInputs{SubjectToken: "assertion", SubjectTokenType: TokenTypeJWT, CacheIdentity: "X"}
	viaSubject := &ExchangeInputs{SubjectToken: "X", SubjectTokenType: TokenTypeJWT}
	if viaIdentity.Fingerprint() == viaSubject.Fingerprint() {
		t.Fatal("CacheIdentity path must be domain-separated from the raw-subject path")
	}

	// Setting CacheIdentity must change the fingerprint vs. keying on the subject.
	withID := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT, CacheIdentity: "id"}
	withoutID := &ExchangeInputs{SubjectToken: "s", SubjectTokenType: TokenTypeJWT}
	if withID.Fingerprint() == withoutID.Fingerprint() {
		t.Fatal("CacheIdentity must be folded into the fingerprint")
	}
}

// TestExchangeInputs_Fingerprint_IgnoresResolveClosure proves the lazy provider
// does not enter the cache key: a leader (closure set, subject not yet minted)
// and a would-be follower must key identically so they share one cache entry.
func TestExchangeInputs_Fingerprint_IgnoresResolveClosure(t *testing.T) {
	base := ExchangeInputs{
		SubjectTokenType:   TokenTypeJWT,
		SubjectTokenOrigin: ExchangeOriginVerified,
		CacheIdentity:      "wid:ns:mount:alice\x00aud",
	}
	withClosure := base
	withClosure.ResolveSubjectToken = stubResolve

	if base.Fingerprint() != withClosure.Fingerprint() {
		t.Fatal("ResolveSubjectToken must not affect the fingerprint")
	}

	// And a later-populated SubjectToken must also not change the key (the closure
	// path keys on CacheIdentity, not the minted bytes).
	populated := withClosure
	populated.SubjectToken = "freshly-minted-assertion"
	if populated.Fingerprint() != base.Fingerprint() {
		t.Fatal("a lazily-populated SubjectToken must not change the CacheIdentity-keyed fingerprint")
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
		{"auth_token", map[string]string{ConfigSubjectTokenSource: SourceAuthToken}, true},
		{"header", map[string]string{ConfigSubjectTokenSource: SourceHeader}, true},
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
		{"subject auth_token", map[string]string{ConfigSubjectTokenSource: SourceAuthToken}, false},
		{"subject header", map[string]string{ConfigSubjectTokenSource: SourceHeader}, false},
		{
			name:   "subject + actor header",
			config: map[string]string{ConfigSubjectTokenSource: SourceHeader, ConfigActorTokenSource: SourceHeader},
		},
		{
			name:    "invalid subject source",
			config:  map[string]string{ConfigSubjectTokenSource: "bogus"},
			wantErr: true,
		},
		{
			name:    "invalid actor source",
			config:  map[string]string{ConfigSubjectTokenSource: SourceHeader, ConfigActorTokenSource: "bogus"},
			wantErr: true,
		},
		{
			name:    "actor without subject",
			config:  map[string]string{ConfigActorTokenSource: SourceHeader},
			wantErr: true,
		},
		{
			name:   "subject header + actor auth_token",
			config: map[string]string{ConfigSubjectTokenSource: SourceHeader, ConfigActorTokenSource: SourceAuthToken},
		},
		{
			name:    "subject and actor both auth_token (mutually exclusive)",
			config:  map[string]string{ConfigSubjectTokenSource: SourceAuthToken, ConfigActorTokenSource: SourceAuthToken},
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
			name: "assertion_metadata_claims without warden_identity",
			config: map[string]string{
				ConfigSubjectTokenSource:      SourceHeader,
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
				ConfigSubjectTokenSource: SourceHeader,
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
				ConfigSubjectTokenSource: SourceHeader,
				ConfigAssertionResource:  "aws-secretsmanager:prod/db",
			},
			wantErr: true,
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

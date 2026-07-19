package credential

import "testing"

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

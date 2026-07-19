package credential

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// RFC 8693 §3 token-type identifiers. These label the format of a subject or
// actor token in a token-exchange request so the downstream STS knows how to
// interpret it. Operators set them per credential spec; callers never choose
// them, so an arbitrary blob cannot be relabelled as, say, an access token.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

// Subject/actor token origins record how Warden obtained a token, which is the
// only trust signal the plumbing carries. A driver that consumes exchange
// inputs uses this to decide whether it may forward the token as-is or must
// validate it first.
const (
	// ExchangeOriginVerified marks a token Warden already verified during
	// inbound authentication (a transparent-auth JWT reused as the subject).
	ExchangeOriginVerified = "verified"
	// ExchangeOriginUnverified marks a token the caller supplied on the
	// request that Warden has NOT verified.
	ExchangeOriginUnverified = "unverified"
)

// Spec-config keys that opt a credential spec into token exchange and describe
// where the subject and actor tokens come from.
const (
	// ConfigSubjectTokenSource selects the subject-token source:
	// "auth_token" reuses the verified inbound JWT, "header" reads a
	// caller-supplied header, "none" (or absent) disables exchange.
	ConfigSubjectTokenSource = "subject_token_source"
	// ConfigSubjectTokenType overrides the subject token's RFC 8693 type
	// (default TokenTypeJWT).
	ConfigSubjectTokenType = "subject_token_type"
	// ConfigActorTokenSource selects the actor-token source: "header" or
	// "none" (or absent).
	ConfigActorTokenSource = "actor_token_source"
	// ConfigActorTokenType overrides the actor token's RFC 8693 type
	// (default TokenTypeJWT).
	ConfigActorTokenType = "actor_token_type"
)

// Accepted values for the *_source config keys.
const (
	SourceAuthToken = "auth_token"
	SourceHeader    = "header"
	SourceNone      = "none"
)

// maxExchangeTokenBytes bounds a single subject or actor token. Real JWTs and
// access tokens are far smaller; the cap guards against a caller pushing an
// oversized blob through the exchange plumbing.
const maxExchangeTokenBytes = 256 * 1024

// ExchangeInputs carries caller-derived RFC 8693 token-exchange inputs from an
// inbound request down to a credential driver at mint time. The values are
// bearer secrets: the plumbing never logs them, never persists them, and never
// places them in a credential's data map. Only a driver that implements
// ExchangeMinter receives them.
type ExchangeInputs struct {
	// SubjectToken is the RFC 8693 §2.1 subject_token — the identity being
	// exchanged.
	SubjectToken string
	// SubjectTokenType is the RFC 8693 §2.1 subject_token_type.
	SubjectTokenType string
	// ActorToken is the optional RFC 8693 §2.1 actor_token — the party acting
	// on behalf of the subject (delegation).
	ActorToken string
	// ActorTokenType is the RFC 8693 §2.1 actor_token_type. Required when
	// ActorToken is set, empty otherwise.
	ActorTokenType string
	// SubjectTokenOrigin is one of ExchangeOriginVerified or
	// ExchangeOriginUnverified.
	SubjectTokenOrigin string
	// ActorTokenOrigin records how the actor token was obtained, mirroring
	// SubjectTokenOrigin: ExchangeOriginVerified when it is the caller's inbound
	// JWT (actor_token_source=auth_token), ExchangeOriginUnverified when supplied
	// on a header. Empty when no actor token is present. A driver consuming an
	// unverified actor must validate it before forwarding, exactly as for a subject.
	ActorTokenOrigin string
}

// Validate performs structural checks only. It does not verify token contents
// (signature, audience, expiry) — that is a driver's responsibility, since the
// meaning of a token depends on the exchange being performed.
func (e *ExchangeInputs) Validate() error {
	if e == nil {
		return fmt.Errorf("exchange inputs are nil")
	}
	if e.SubjectToken == "" {
		return fmt.Errorf("subject_token is required")
	}
	if e.SubjectTokenType == "" {
		return fmt.Errorf("subject_token_type is required")
	}
	if len(e.SubjectToken) > maxExchangeTokenBytes {
		return fmt.Errorf("subject_token exceeds %d bytes", maxExchangeTokenBytes)
	}
	// RFC 8693 §2.1: actor_token_type is required when actor_token is present,
	// and meaningless without it.
	if e.ActorToken != "" && e.ActorTokenType == "" {
		return fmt.Errorf("actor_token_type is required when actor_token is set")
	}
	if e.ActorToken == "" && e.ActorTokenType != "" {
		return fmt.Errorf("actor_token_type set without actor_token")
	}
	if len(e.ActorToken) > maxExchangeTokenBytes {
		return fmt.Errorf("actor_token exceeds %d bytes", maxExchangeTokenBytes)
	}
	if e.ActorToken == "" && e.ActorTokenOrigin != "" {
		return fmt.Errorf("actor_token_origin set without actor_token")
	}
	if e.ActorTokenOrigin != "" {
		switch e.ActorTokenOrigin {
		case ExchangeOriginVerified, ExchangeOriginUnverified:
		default:
			return fmt.Errorf("invalid actor_token_origin %q", e.ActorTokenOrigin)
		}
	}
	switch e.SubjectTokenOrigin {
	case ExchangeOriginVerified, ExchangeOriginUnverified:
	default:
		return fmt.Errorf("invalid subject_token_origin %q", e.SubjectTokenOrigin)
	}
	return nil
}

// Fingerprint returns a hex-encoded SHA-256 over the inputs, used solely to
// key cached credentials per distinct exchange input. It is never logged.
//
// Each field is length-prefixed before hashing so that no two distinct field
// combinations can collide by concatenation (e.g. subject "ab"/actor "c" must
// not hash the same as subject "a"/actor "bc").
func (e *ExchangeInputs) Fingerprint() string {
	h := sha256.New()
	writeField := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeField(e.SubjectTokenType)
	writeField(e.SubjectToken)
	writeField(e.ActorTokenType)
	writeField(e.ActorToken)
	writeField(e.SubjectTokenOrigin)
	writeField(e.ActorTokenOrigin)
	return hex.EncodeToString(h.Sum(nil))
}

// SpecRequestsExchange reports whether a spec's config opts into token
// exchange, i.e. subject_token_source is set to something other than "none".
func SpecRequestsExchange(config map[string]string) bool {
	src := config[ConfigSubjectTokenSource]
	return src != "" && src != SourceNone
}

// ValidateExchangeSpecConfig performs structural validation of the
// exchange-related keys in a spec config. It does not check that any driver
// supports exchange — an exchange spec bound to a non-exchange source fails
// closed at mint time instead.
func ValidateExchangeSpecConfig(config map[string]string) error {
	if err := ValidateSchema(config,
		StringField(ConfigSubjectTokenSource).OneOf(SourceAuthToken, SourceHeader, SourceNone),
		StringField(ConfigActorTokenSource).OneOf(SourceAuthToken, SourceHeader, SourceNone),
	); err != nil {
		return err
	}
	// An actor token only has meaning alongside a subject token (RFC 8693 §2.1),
	// so reject an actor source without a subject source.
	actorSrc := config[ConfigActorTokenSource]
	if actorSrc != "" && actorSrc != SourceNone && !SpecRequestsExchange(config) {
		return fmt.Errorf("field '%s': requires '%s' to be set", ConfigActorTokenSource, ConfigSubjectTokenSource)
	}
	// A single inbound token cannot be both the subject and the actor.
	if config[ConfigSubjectTokenSource] == SourceAuthToken && actorSrc == SourceAuthToken {
		return fmt.Errorf("field '%s': cannot be '%s' when '%s' is also '%s' (one inbound token cannot be both subject and actor)",
			ConfigActorTokenSource, SourceAuthToken, ConfigSubjectTokenSource, SourceAuthToken)
	}
	return nil
}

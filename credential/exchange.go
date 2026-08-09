package credential

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/textproto"
	"strings"
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
	// ConfigSubjectTokenHeader names the request header the "header" subject
	// source reads. Absent/empty defaults to DefaultSubjectTokenHeader. Set it to
	// "Authorization" (the Bearer scheme is stripped) to carry the subject token in
	// the standard header when that header is otherwise free (e.g. a cert/SPIFFE-
	// authenticated agent). Valid only with subject_token_source=header.
	ConfigSubjectTokenHeader = "subject_token_header"
	// ConfigActorTokenHeader names the request header the "header" actor source
	// reads. Absent/empty defaults to DefaultActorTokenHeader. Valid only with
	// actor_token_source=header.
	ConfigActorTokenHeader = "actor_token_header"
)

// Default header names for the "header" token source. These preserve the
// historical behaviour exactly: a spec that does not set a *_token_header reads
// the same Warden header it always did, so this configurability adds no migration.
const (
	DefaultSubjectTokenHeader = "X-Warden-Subject-Token"
	DefaultActorTokenHeader   = "X-Warden-Actor-Token"
)

// internalTokenHeaders lists request headers that carry Warden's own auth and so
// must never be reused to carry an exchange token: pointing a *_token_header at
// one would either leak the caller's own auth into the exchange or let a caller
// smuggle a token past validation. Compared canonicalized.
var internalTokenHeaders = map[string]struct{}{
	textproto.CanonicalMIMEHeaderKey("X-Warden-Token"): {},
}

// SubjectTokenHeaderName returns the canonicalized header name the "header"
// subject source reads for this spec, defaulting to DefaultSubjectTokenHeader.
func SubjectTokenHeaderName(config map[string]string) string {
	return canonicalTokenHeader(config[ConfigSubjectTokenHeader], DefaultSubjectTokenHeader)
}

// ActorTokenHeaderName returns the canonicalized header name the "header" actor
// source reads for this spec, defaulting to DefaultActorTokenHeader.
func ActorTokenHeaderName(config map[string]string) string {
	return canonicalTokenHeader(config[ConfigActorTokenHeader], DefaultActorTokenHeader)
}

// canonicalTokenHeader canonicalizes a configured header name (falling back to
// def when unset) so name comparisons and lookups are case-insensitive and
// consistent with net/http's own header canonicalization.
func canonicalTokenHeader(v, def string) string {
	if v == "" {
		v = def
	}
	return textproto.CanonicalMIMEHeaderKey(v)
}

// Accepted values for the *_source config keys.
const (
	SourceAuthToken = "auth_token"
	// SourceHeader reads a caller-supplied token from a request header named by
	// ConfigSubjectTokenHeader/ConfigActorTokenHeader (default the X-Warden-*-Token
	// headers). The token is unverified — the driver validates it against the
	// source's configured trust.
	SourceHeader = "header"
	SourceNone   = "none"
	// SourceWardenIdentity mints a fresh Warden-signed identity assertion (via
	// the OIDC issuer) as the subject token. Used for Workload Identity
	// Federation: Warden re-issues the resolved agent identity so an upstream
	// federates Warden's issuer once, regardless of how the agent authenticated.
	// Valid only for the subject source.
	SourceWardenIdentity = "warden_identity"
)

// ConfigAssertionAudience is the spec-config key naming the `aud` of a
// warden_identity assertion — the upstream the assertion is minted for. Required
// and non-empty whenever subject_token_source=warden_identity: it is the control
// that stops an assertion for one upstream being replayed at another.
const ConfigAssertionAudience = "assertion_audience"

// ConfigAssertionMetadataClaims is the spec-config key naming which of the
// caller's login-derived metadata keys to project into a warden_identity
// assertion (comma-separated). Absent/empty projects nothing — the assertion
// crosses a trust boundary to a third-party upstream, so disclosure is opt-in and
// operator-chosen, never the whole metadata map. Valid only when
// subject_token_source=warden_identity.
const ConfigAssertionMetadataClaims = "assertion_metadata_claims"

// AssertionMetadataKeys parses the comma-separated ConfigAssertionMetadataClaims
// value into a de-duplicated, order-preserving list of metadata key names,
// ignoring blank entries and surrounding whitespace. Returns nil when unset.
func AssertionMetadataKeys(config map[string]string) []string {
	raw := config[ConfigAssertionMetadataClaims]
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var keys []string
	for _, part := range strings.Split(raw, ",") {
		k := strings.TrimSpace(part)
		if k == "" {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	return keys
}

// Assertion signing algorithms selectable per warden_identity spec via
// ConfigAssertionAlgorithm. RS256 (the default) is the universal OIDC verifier
// default and the algorithm AWS IAM OIDC providers accept; ES256 (ECDSA P-256) is
// the smaller/faster alternative some upstreams (e.g. GCP WIF) prefer. The issuer
// publishes a JWKS key for each, so a spec can pick either. The string values must
// match the issuer's supported algs.
const (
	AssertionAlgRS256   = "RS256"
	AssertionAlgES256   = "ES256"
	DefaultAssertionAlg = AssertionAlgRS256
)

// ConfigAssertionAlgorithm is the spec-config key selecting the JWS algorithm a
// warden_identity assertion is signed with. Absent/empty defaults to RS256. Valid
// only when subject_token_source=warden_identity.
const ConfigAssertionAlgorithm = "assertion_algorithm"

// AssertionAlgorithm returns the spec's configured assertion signing algorithm,
// defaulting to RS256 when unset.
func AssertionAlgorithm(config map[string]string) string {
	if a := config[ConfigAssertionAlgorithm]; a != "" {
		return a
	}
	return DefaultAssertionAlg
}

// ConfigAssertionResource is the spec-config key that names the single
// downstream resource a warden_identity assertion targets, emitted as the
// `warden_resource` claim so a verifier evaluating arbitrary bound claims can
// pin the assertion to one resource. Three modes: unset derives the resource
// from the source/spec config; AssertionResourceNone suppresses the claim; any
// other value is emitted verbatim. Valid only when
// subject_token_source=warden_identity.
const ConfigAssertionResource = "assertion_resource"

// AssertionResourceNone is the ConfigAssertionResource value that suppresses the
// warden_resource claim entirely (opt-out), for deployments that do not want a
// resource name disclosed into the cross-boundary assertion.
const AssertionResourceNone = "none"

// maxExchangeTokenBytes bounds a single subject or actor token. Real JWTs and
// access tokens are far smaller; the cap guards against a caller pushing an
// oversized blob through the exchange plumbing.
const maxExchangeTokenBytes = 256 * 1024

// ExchangeInputs carries the RFC 8693 token-exchange inputs for one request from
// the request handler down to a credential driver at mint time. The subject and
// actor tokens are either derived from the inbound request (a reused auth JWT or a
// caller-supplied header) or minted by Warden itself — a signed identity assertion
// for Workload Identity Federation, produced lazily via ResolveSubjectToken. The
// token values are bearer secrets: the plumbing never logs them, never persists
// them, and never places them in a credential's data map. Only a driver that
// implements ExchangeMinter receives them.
type ExchangeInputs struct {
	// SubjectToken is the RFC 8693 §2.1 subject_token — the identity being
	// exchanged. It may be empty until the Manager populates it when
	// ResolveSubjectToken is set (a subject minted lazily on a cache miss).
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

	// CacheIdentity, when non-empty, is the value Fingerprint() keys the
	// credential cache on IN PLACE OF SubjectToken. It exists for subjects whose
	// SubjectToken is freshly minted on every request (a Warden-signed identity
	// assertion carries a new jti/iat/exp each time), which would otherwise make
	// the fingerprint unique per request and defeat the cache. Set it to a stable
	// identity tuple (e.g. subject + audience) so distinct identities stay
	// isolated while one identity reuses its cached upstream credential.
	//
	// It MUST be set only by core (resolveExchangeInputs), never derived from a
	// caller-supplied value, and it does not travel to drivers as a token. It is
	// mandatory whenever ResolveSubjectToken is set (enforced by Validate).
	CacheIdentity string

	// ResolveSubjectToken, when non-nil, produces SubjectToken lazily. It is
	// invoked by the credential Manager only on a real cache MISS (inside the
	// singleflight leader), so a per-request-expensive subject token — e.g. a
	// Warden-signed RS256 identity assertion — is never minted just to be
	// discarded on a cache hit. When set, SubjectToken may be empty until the
	// Manager populates it, and CacheIdentity MUST be set so Fingerprint() is
	// stable without the token bytes.
	//
	// Set only by core (resolveExchangeInputs), never from caller input. It is
	// not hashed by Fingerprint, never logged, and never persisted.
	ResolveSubjectToken func(ctx context.Context) (string, error)
}

// Validate performs structural checks only. It does not verify token contents
// (signature, audience, expiry) — that is a driver's responsibility, since the
// meaning of a token depends on the exchange being performed.
func (e *ExchangeInputs) Validate() error {
	if e == nil {
		return fmt.Errorf("exchange inputs are nil")
	}
	if e.ResolveSubjectToken != nil {
		// Lazy subject: the token is produced on a cache miss, so it may be empty
		// here — but the fingerprint must not then hash an empty SubjectToken and
		// collide across identities, so CacheIdentity is mandatory.
		if e.CacheIdentity == "" {
			return fmt.Errorf("cache_identity is required when the subject token is resolved lazily")
		}
	} else if e.SubjectToken == "" {
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
//
// When CacheIdentity is set, it is hashed in place of SubjectToken (so a
// per-request-volatile assertion does not defeat the cache), under a distinct
// domain tag so the CacheIdentity path and the raw-subject path can never
// collide. Every other field — token type, actor, origins — is always folded
// in, so a Warden-minted subject and a raw subject that happen to share a value
// still key differently, and delegation/provenance never share a cache entry.
//
// ResolveSubjectToken is intentionally NOT hashed: a lazily-minted subject sets
// CacheIdentity (mandatory per Validate), which stands in for the token here.
func (e *ExchangeInputs) Fingerprint() string {
	h := sha256.New()
	writeField := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeField(e.SubjectTokenType)
	if e.CacheIdentity != "" {
		writeField("cache-identity")
		writeField(e.CacheIdentity)
	} else {
		writeField("subject-token")
		writeField(e.SubjectToken)
	}
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
		StringField(ConfigSubjectTokenSource).OneOf(SourceAuthToken, SourceHeader, SourceNone, SourceWardenIdentity),
		StringField(ConfigActorTokenSource).OneOf(SourceAuthToken, SourceHeader, SourceNone),
		StringField(ConfigAssertionAlgorithm).OneOf(AssertionAlgRS256, AssertionAlgES256),
	); err != nil {
		return err
	}
	// A Warden-minted subject must declare the audience it is minted for — an
	// empty/absent aud is replayable at any upstream whose trust policy does not pin
	// aud. That check is source-aware (some source types derive the audience from
	// their own config) and needs the source, so it runs one layer up in the core
	// config store, not in this source-agnostic structural validator. It is enforced
	// again at mint time, defence in depth.
	// Projecting metadata into the assertion only makes sense when Warden mints it;
	// on a reused/caller-supplied subject Warden does not control the claims.
	if config[ConfigAssertionMetadataClaims] != "" && config[ConfigSubjectTokenSource] != SourceWardenIdentity {
		return fmt.Errorf("field '%s': is valid only when '%s' is '%s'",
			ConfigAssertionMetadataClaims, ConfigSubjectTokenSource, SourceWardenIdentity)
	}
	// The assertion algorithm only applies to a Warden-minted subject.
	if config[ConfigAssertionAlgorithm] != "" && config[ConfigSubjectTokenSource] != SourceWardenIdentity {
		return fmt.Errorf("field '%s': is valid only when '%s' is '%s'",
			ConfigAssertionAlgorithm, ConfigSubjectTokenSource, SourceWardenIdentity)
	}
	// Naming a resource in the assertion only makes sense when Warden mints it.
	if config[ConfigAssertionResource] != "" && config[ConfigSubjectTokenSource] != SourceWardenIdentity {
		return fmt.Errorf("field '%s': is valid only when '%s' is '%s'",
			ConfigAssertionResource, ConfigSubjectTokenSource, SourceWardenIdentity)
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
	// A configured header name is meaningful only for the matching header source,
	// and must not name an internal auth header.
	if err := validateTokenHeaderKey(config, ConfigSubjectTokenHeader, ConfigSubjectTokenSource); err != nil {
		return err
	}
	if err := validateTokenHeaderKey(config, ConfigActorTokenHeader, ConfigActorTokenSource); err != nil {
		return err
	}
	// One header cannot carry both the subject and the actor token.
	if config[ConfigSubjectTokenSource] == SourceHeader && actorSrc == SourceHeader &&
		SubjectTokenHeaderName(config) == ActorTokenHeaderName(config) {
		return fmt.Errorf("field '%s': subject and actor cannot read the same header %q",
			ConfigActorTokenHeader, SubjectTokenHeaderName(config))
	}
	return nil
}

// validateTokenHeaderKey checks a *_token_header config key: it is valid only
// when the matching *_token_source is "header", and must not name an internal
// auth header (compared canonicalized).
func validateTokenHeaderKey(config map[string]string, headerKey, sourceKey string) error {
	raw := config[headerKey]
	if raw == "" {
		return nil
	}
	if config[sourceKey] != SourceHeader {
		return fmt.Errorf("field '%s': is valid only when '%s' is '%s'", headerKey, sourceKey, SourceHeader)
	}
	if _, bad := internalTokenHeaders[textproto.CanonicalMIMEHeaderKey(raw)]; bad {
		return fmt.Errorf("field '%s': %q is an internal header and cannot carry an exchange token", headerKey, raw)
	}
	return nil
}

package drivers

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/internal/remotesign"
	"github.com/stephnangue/warden/logger"
)

// Exchange grants selected by the source's `grant` config.
const (
	tokenExchangeGrantRFC8693   = "rfc8693"
	tokenExchangeGrantJWTBearer = "jwt_bearer"
	tokenExchangeGrantIDJAG     = "id_jag"
)

// tokenExchangeGrants is every accepted `grant` value. It is the single source of
// truth for both the source-config OneOf check and the assertion-profile
// reserved-name drift test, so a new grant cannot become a registrable profile name
// without failing that test. Unexported so it cannot be widened at runtime.
var tokenExchangeGrants = []string{tokenExchangeGrantRFC8693, tokenExchangeGrantJWTBearer, tokenExchangeGrantIDJAG}

// tokenTypeIDJAG is the requested_token_type for an ID-JAG assertion (leg 1 of
// the cross-app-access flow).
const tokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

// idJAGPinnedParams are the leg-1 fields of an id_jag exchange that token_param.* may
// not set, each with what to do instead. Together they say what the request asks for
// and which resource authorization server the ID-JAG is for; overriding either turns it
// into a different request. The order is the order a stored source's refusal names
// them in.
var idJAGPinnedParams = []struct{ key, instead string }{
	{"requested_token_type", "Warden always asks for an ID-JAG"},
	{"audience", "set audience instead, which names the resource authorization server"},
}

// idJAGPinned reports whether key is one of idJAGPinnedParams.
func idJAGPinned(key string) bool {
	return slices.ContainsFunc(idJAGPinnedParams, func(p struct{ key, instead string }) bool { return p.key == key })
}

// idJAGFirstClassParams maps a leg-1 form field to the config key that sets it.
// token_param.* may not set these fields on a write. A stored source may still carry
// one; it is sent only when the config key left the field empty, so it never replaces a
// narrower value a spec sets.
var idJAGFirstClassParams = map[string]string{"scope": "scope", "resource": "resources"}

// TokenExchangeSupportsActor reports whether a token_exchange source's grant has
// an RFC 8693 actor slot. jwt_bearer (an assertion grant) has none — the driver
// rejects any actor there at mint time (see MintCredentialWithExchange) — while
// rfc8693 and id_jag both carry the actor. It lets the config store reject an
// actor spec bound to a jwt_bearer source at create time (single source of truth
// for the grant string, mirroring DeriveAssertionAudience living here).
func TokenExchangeSupportsActor(sourceCfg credential.Config) bool {
	return credential.GetString(sourceCfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantJWTBearer
}

// grantTypeTokenExchange is the RFC 8693 grant_type URN sent in the token
// request; the jwt-bearer one, grantTypeJWTBearer, lives with the other
// assertion-grant pieces in signed_assertion.go.
const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// Compile-time interface assertions.
var _ credential.SourceDriver = (*TokenExchangeDriver)(nil)
var _ credential.ExchangeMinter = (*TokenExchangeDriver)(nil)
var _ credential.ChainedExchangeMinter = (*TokenExchangeDriver)(nil)

// TokenExchangeDriver exchanges a caller-derived identity (a subject token, and
// optionally an actor token) for a scoped downstream bearer at an RFC 8693 / RFC
// 7523 token endpoint. It is exchange-only: it never mints from static source
// config, so plain MintCredential is a defensive error and all issuance flows
// through MintCredentialWithExchange.
type TokenExchangeDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
	// capSigners signs with fetched signing capabilities over pooled connections.
	capSigners *remotesign.CapabilitySigners
	// refusal, when set, is why this source cannot mint at all. It is decided once,
	// when the driver is built, and returned before a mint sends or signs anything.
	refusal error
	// inline are the clients the source's own config names, resolved once when the
	// driver is built. A chained source resolves its clients per mint instead.
	inline tokenClients
}

// TokenExchangeDriverFactory creates TokenExchangeDriver instances.
type TokenExchangeDriverFactory struct{}

// Type returns the driver type identifier.
func (f *TokenExchangeDriverFactory) Type() string {
	return credential.SourceTypeTokenExchange
}

// ValidateConfig validates source configuration. VerifySpec never runs for
// exchange specs, so the factory is the place strict validation lives.
func (f *TokenExchangeDriverFactory) ValidateConfig(config credential.Config) error {
	skip := credential.GetBool(config, "tls_skip_verify", false)
	if err := credential.ValidateSchema(config,
		credential.StringField("token_url").
			Required().
			Custom(func(v string) error { return validateOAuth2SafeURL(v, "token_url", skip) }).
			Describe("Token endpoint (HTTPS) of the STS/IdP performing the exchange").
			Example("https://idp.example.com/oauth2/v1/token"),

		defaultTokenTTLField(),

		credential.StringField("grant").
			OneOf(tokenExchangeGrants...).
			Describe("Exchange grant: rfc8693 (token-exchange), jwt_bearer (assertion; Entra OBO), or id_jag (cross-app access)").
			Example("rfc8693"),

		credential.StringField("resource_token_url").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateOAuth2SafeURL(v, "resource_token_url", skip)
			}).
			Describe("Resource authorization-server token endpoint (HTTPS) for id_jag leg 2").
			Example("https://auth.resourceapp.example.com/oauth2/token"),

		credential.StringField("client_auth").
			OneOf(clientAuthSecretBasic, clientAuthSecretPost, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT, clientAuthNone).
			Describe("How Warden authenticates to the token endpoint; kms_private_key_jwt signs the same assertion with a key held in a KMS, reached through secret_spec; none presents no client credential (a public client identified by its subject token; not with grant=id_jag)").
			Example("client_secret_post"),

		credential.StringField("client_id").
			Describe("OAuth2 client ID Warden presents to the token endpoint (inline only; omit when secret_spec is set)").
			Example("warden-gateway"),

		credential.StringField("client_secret").
			Describe("OAuth2 client secret (masked on read; for client_secret_* auth; omit when secret_spec is set)").
			Example("****"),

		credential.StringField("private_key").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				_, err := parseRSAPrivateKey(v)
				return err
			}).
			Describe("PEM RSA private key for private_key_jwt client authentication (masked on read; omit when secret_spec is set)").
			Example("-----BEGIN PRIVATE KEY----- ..."),

		credential.StringField("client_assertion_alg").
			OneOf("RS256").
			Describe("Signing algorithm for the private_key_jwt client assertion (RS256)").
			Example("RS256"),

		credential.StringField("client_assertion_kid").
			Describe("Optional key id (kid) header for the client assertion (inline only; when secret_spec is set it travels in the referenced payload beside the key, under 'client_assertion_kid' or 'kid')").
			Example("key-1"),

		credential.StringField("client_assertion_aud").
			OneOf(clientAssertionAudTokenURL, clientAssertionAudIssuer).
			Describe("Audience of the client assertion: token_url (default) names each endpoint the assertion is sent to; issuer names the server's issuer identifier, which an authorization server enforcing RFC 7523bis requires (needs issuer, and resource_issuer for grant=id_jag)").
			Example("token_url"),

		credential.StringField("issuer").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateIssuerIdentifier(v, "issuer", skip)
			}).
			Describe("Issuer identifier of the authorization server behind token_url, named as the client assertion's audience when client_assertion_aud=issuer").
			Example("https://idp.example.com"),

		credential.StringField("resource_issuer").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				return validateIssuerIdentifier(v, "resource_issuer", skip)
			}).
			Describe("Issuer identifier of the resource authorization server behind resource_token_url (id_jag leg 2), named as that leg's client assertion audience when it names the issuer: resource_client_assertion_aud=issuer, or client_assertion_aud=issuer without a resource client").
			Example("https://auth.resourceapp.example.com"),

		credential.StringField("resource_client_auth").
			OneOf(clientAuthSecretBasic, clientAuthSecretPost, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT).
			Describe("How id_jag's leg 2 authenticates at the resource authorization server, as the client registered there, which the ID-JAG's client_id names; omit to authenticate as the IdP client, which only an assertion-based client_auth may").
			Example("client_secret_post"),

		credential.StringField("resource_client_id").
			Describe("Client ID at the resource authorization server (inline only; omit when secret_spec is set, whose payload carries it as 'resource_client_id')").
			Example("warden-at-resource"),

		credential.StringField("resource_client_secret").
			Describe("Client secret at the resource authorization server (masked on read; omit when secret_spec is set, whose payload carries it as 'resource_client_secret')").
			Example("****"),

		credential.StringField("resource_private_key").
			Custom(func(v string) error {
				if v == "" {
					return nil
				}
				_, err := parseRSAPrivateKey(v)
				return err
			}).
			Describe("PEM RSA private key the resource client signs its assertions with (masked on read; omit when secret_spec is set, whose payload carries it as 'resource_private_key')").
			Example("-----BEGIN PRIVATE KEY----- ..."),

		credential.StringField("resource_client_assertion_kid").
			Describe("Optional key id (kid) header for the resource client's assertion (inline only; with secret_spec it travels in the payload beside the key, as 'resource_client_assertion_kid' or 'resource_kid'; with kms_private_key_jwt both clients sign with one key under its kid)").
			Example("key-1"),

		credential.StringField("resource_client_assertion_aud").
			OneOf(clientAssertionAudTokenURL, clientAssertionAudIssuer).
			Describe("Audience of the resource client's assertion: token_url (default) names resource_token_url; issuer names resource_issuer").
			Example("token_url"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),

		credential.StringField("secret_spec").
			Describe("Source the whole client credential from another cred spec via credential chaining instead of storing it inline (client_id and client_secret / private_key then omitted; the referenced payload supplies both, and the resource client's too when resource_client_auth is set)").
			Example("idp-client-secret"),

		credential.StringField("secret_field").
			Describe("Which field of the referenced secret_spec's credential holds the client secret (when its payload has multiple keys); the client id travels beside it under 'client_id'. It selects the IdP client's secret only; a resource client's is read by its field names").
			Example("client_secret"),

		credential.StringField("secret_cache_ttl").
			Describe("Cache the chained client secret source-wide for this duration (e.g. 30m); omit to fetch it on every mint").
			Example("30m"),
	); err != nil {
		return err
	}

	// id_jag needs a second (resource authorization-server) endpoint for leg 2.
	idJAG := credential.GetString(config, "grant", tokenExchangeGrantRFC8693) == tokenExchangeGrantIDJAG
	if idJAG {
		if credential.GetString(config, "resource_token_url", "") == "" {
			return fmt.Errorf("resource_token_url is required for grant=id_jag")
		}
		if err := idJAGClientAuthError(config); err != nil {
			return err
		}
	}

	// The resource client is id_jag's alone, and is configured whole or not at all: a
	// partial one would leave leg 2 to make up the rest from the IdP client, presenting
	// one server's credential under another's name.
	idpMethod := idpClientKeys.method(config)
	resourceMethod := resourceClientKeys.method(config)
	hasResource := resourceMethod != ""
	if !hasResource {
		for _, key := range []string{"resource_client_id", "resource_client_secret", "resource_private_key", "resource_client_assertion_kid", "resource_client_assertion_aud"} {
			if credential.GetString(config, key, "") != "" {
				return fmt.Errorf("%s needs resource_client_auth: the resource client is configured whole or not at all", key)
			}
		}
	}
	if hasResource && !idJAG {
		return fmt.Errorf("resource_client_auth applies only to grant=id_jag, whose leg 2 authenticates at the resource authorization server")
	}
	// Without a resource client, leg 2 authenticates as the IdP client. An assertion is
	// bound to the server it names, but a client secret is not: leg 2 would hand the
	// IdP's secret to another authorization server.
	if idJAG && !hasResource && isClientSecretMethod(idpMethod) {
		return fmt.Errorf("with grant=id_jag and client_auth=%s, set resource_client_auth and the resource client's credential: leg 2 would otherwise send the IdP's client secret to the resource authorization server", idpMethod)
	}

	// The audience each client's assertion names. Only an assertion has one, and naming
	// an issuer needs the issuer of the server it is sent to. Anything that would never
	// be read is refused rather than stored, so the config says what is sent.
	if !isClientAssertionMethod(idpMethod) && credential.GetString(config, "client_assertion_aud", "") != "" {
		return fmt.Errorf("client_assertion_aud must be omitted for client_auth=%s; it applies to client_auth=%s or %s",
			idpMethod, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT)
	}
	if hasResource && !isClientAssertionMethod(resourceMethod) && credential.GetString(config, "resource_client_assertion_aud", "") != "" {
		return fmt.Errorf("resource_client_assertion_aud must be omitted for resource_client_auth=%s; it applies to resource_client_auth=%s or %s",
			resourceMethod, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT)
	}
	idpIssuer := credential.GetString(config, "client_assertion_aud", "") == clientAssertionAudIssuer
	// Leg 2's assertion names the resource authorization server's issuer when the client
	// it authenticates as asks for the issuer.
	leg2Issuer := idJAG && idpIssuer && !hasResource ||
		hasResource && credential.GetString(config, "resource_client_assertion_aud", "") == clientAssertionAudIssuer
	if idpIssuer {
		if credential.GetString(config, "issuer", "") == "" {
			return fmt.Errorf("client_assertion_aud=%s requires issuer, the issuer identifier of the server behind token_url", clientAssertionAudIssuer)
		}
	} else if credential.GetString(config, "issuer", "") != "" {
		// Unlike an oauth2 source's, issuer names nothing but an assertion's audience.
		return fmt.Errorf("issuer is read only when client_assertion_aud=%s; set that, or omit issuer", clientAssertionAudIssuer)
	}
	switch resourceIssuer := credential.GetString(config, "resource_issuer", ""); {
	case !idJAG && resourceIssuer != "":
		return fmt.Errorf("resource_issuer applies only to grant=id_jag, whose leg 2 authenticates to the resource authorization server")
	case leg2Issuer && resourceIssuer == "" && hasResource:
		return fmt.Errorf("resource_client_assertion_aud=%s requires resource_issuer, the issuer identifier of the server behind resource_token_url", clientAssertionAudIssuer)
	case leg2Issuer && resourceIssuer == "":
		return fmt.Errorf("resource_issuer is required for grant=id_jag when client_assertion_aud=%s: leg 2 authenticates to the resource authorization server, which has an issuer of its own", clientAssertionAudIssuer)
	case !leg2Issuer && resourceIssuer != "":
		return fmt.Errorf("resource_issuer is read only when leg 2's client assertion names the issuer: resource_client_assertion_aud=%s, or client_assertion_aud=%s without a resource client; set that, or omit resource_issuer",
			clientAssertionAudIssuer, clientAssertionAudIssuer)
	}

	// Each client's method determines which of its credentials are required.
	chained := credential.GetString(config, credential.ConfigSecretSpec, "") != ""
	if hasResource {
		// The two clients share one referenced payload, which is either a signing
		// capability or a stored credential, never both.
		if (idpMethod == clientAuthKMSPrivateKeyJWT) != (resourceMethod == clientAuthKMSPrivateKeyJWT) {
			return fmt.Errorf("client_auth and resource_client_auth must both be %s or neither: the clients share one referenced payload, which is either a signing capability or a stored credential", clientAuthKMSPrivateKeyJWT)
		}
		// The field selector picks the IdP client's secret; pointed at the resource
		// client's, leg 1 would present that secret to the IdP.
		if field := credential.GetString(config, credential.ConfigSecretField, ""); fieldOfResourceClient(field) {
			return fmt.Errorf("secret_field %q names the resource client's credential; it selects the IdP client's secret only", field)
		}
	}
	if err := validateClientCredential(config, idpClientKeys, idpMethod, chained); err != nil {
		return err
	}
	if hasResource {
		if err := validateClientCredential(config, resourceClientKeys, resourceMethod, chained); err != nil {
			return err
		}
	}
	if idpMethod == clientAuthNone {
		// A public client has no credential to store or to fetch. Anything that would
		// supply one is refused rather than ignored: a secret left here would still be
		// stored, and still be reported as stored, while never being sent.
		for _, key := range []string{"client_secret", "private_key", "client_assertion_alg", "client_assertion_kid",
			credential.ConfigSecretSpec, credential.ConfigSecretField, "secret_cache_ttl"} {
			if credential.GetString(config, key, "") != "" {
				return fmt.Errorf("%s must be omitted for client_auth=%s; a public client presents no client credential", key, clientAuthNone)
			}
		}
	}

	// token_param.* must not override core token-exchange form fields.
	protected := map[string]bool{
		"grant_type": true, "client_id": true, "client_secret": true,
		"client_assertion": true, "client_assertion_type": true,
		"subject_token": true, "subject_token_type": true,
		"actor_token": true, "actor_token_type": true, "assertion": true,
	}
	for key := range credential.GetPrefixed(config, "token_param.") {
		if protected[key] {
			return fmt.Errorf("token_param.%s cannot override a core token-exchange field", key)
		}
		if !idJAG {
			continue
		}
		if err := idJAGPinnedParamError(key); err != nil {
			return err
		}
		if own, ok := idJAGFirstClassParams[key]; ok {
			return fmt.Errorf("token_param.%s is not used with grant=id_jag: set %s instead, which is sent to the IdP in the ID-JAG request", key, own)
		}
	}
	return nil
}

// idJAGSubjectTokenTypes are the subject token types an ID-JAG request may carry
// (draft-ietf-oauth-identity-assertion-authz-grant §4.3): an identity assertion, as an
// ID token or a SAML 2.0 assertion, or a refresh token where the IdP accepts one. The
// subject sources Warden has today supply JWTs, so only an ID token reaches an IdP as
// itself; the other two are named for a subject source that can supply them.
var idJAGSubjectTokenTypes = []string{credential.TokenTypeIDToken, credential.TokenTypeSAML2, credential.TokenTypeRefreshToken}

// IDJAGSpecError checks a spec against its source when the source asks for ID-JAGs, and
// is nil for any other source. It is applied when the spec is written, when the source
// changes, and at mint. Pure: reads the two configs only.
func IDJAGSpecError(specCfg, sourceCfg credential.Config) error {
	if credential.GetString(sourceCfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG {
		return nil
	}
	_, err := idJAGSubjectTokenType(specCfg)
	return err
}

// idJAGSubjectTokenType is the subject_token_type URN an id_jag spec sends, or why the
// spec cannot be the subject of an ID-JAG request. That subject is an identity
// assertion the IdP issued, so the spec may not have Warden sign one, and its type is
// one of idJAGSubjectTokenTypes, named by short name or URN; id_token when none is named.
func idJAGSubjectTokenType(specCfg credential.Config) (string, error) {
	if specCfg.Get(credential.ConfigSubjectTokenSource) == credential.SourceWardenIdentity {
		return "", fmt.Errorf("%s=%s cannot be used with grant=id_jag: the subject of an ID-JAG request is an identity assertion the IdP issued, not one Warden signs; use %s or %s",
			credential.ConfigSubjectTokenSource, credential.SourceWardenIdentity, credential.SourceUserIdentity, credential.SourceAgentIdentity)
	}
	name := specCfg.Get(credential.ConfigSubjectTokenType)
	if name == "" {
		return credential.TokenTypeIDToken, nil
	}
	if urn, ok := credential.TokenTypeURN(name); ok && slices.Contains(idJAGSubjectTokenTypes, urn) {
		return urn, nil
	}
	return "", fmt.Errorf("%s %q cannot be used with grant=id_jag: use id_token (the default), saml2 or refresh_token",
		credential.ConfigSubjectTokenType, name)
}

// idTokenShapeError refuses a subject that cannot be the ID token it is sent as: one
// that is not a JWT, signed (three segments) or encrypted (five), or one whose header
// says it is an access token or an ID-JAG. The IdP must refuse either
// (draft-ietf-oauth-identity-assertion-authz-grant §4.3.3); refusing it here saves the
// round trip and says what the caller must present instead. It reads the header only
// and verifies nothing.
func idTokenShapeError(token string) error {
	const want = "the caller must present an ID token issued to this source's client"
	segments := strings.Split(token, ".")
	if len(segments) != 3 && len(segments) != 5 {
		return fmt.Errorf("id_jag: the subject is not a JWT; %s", want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return fmt.Errorf("id_jag: the subject's JWT header cannot be read; %s", want)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("id_jag: the subject's JWT header cannot be read; %s", want)
	}
	// A typ is a media type, matched without case or parameters, with or without
	// "application/" (RFC 7515 §4.1.9).
	typ, _ := header["typ"].(string)
	media, _, _ := strings.Cut(typ, ";")
	switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(media)), "application/") {
	case "at+jwt", "oauth-id-jag+jwt":
		return fmt.Errorf("id_jag: the subject is a JWT of type %q, not an ID token; %s", typ, want)
	}
	return nil
}

// idJAGClientAuthError refuses an id_jag source that would not authenticate its client.
// The IdP must authenticate the client that asks it for an ID-JAG, and refuse a request
// that does not (draft-ietf-oauth-identity-assertion-authz-grant §4.3.3): the ID-JAG
// names that client, and the resource authorization server redeems it only for that
// client. A public client is therefore never an ID-JAG client.
func idJAGClientAuthError(config credential.Config) error {
	if idpClientKeys.method(config) != clientAuthNone {
		return nil
	}
	return fmt.Errorf("client_auth=%s cannot be used with grant=id_jag: the IdP must authenticate the client that asks for an ID-JAG; use %s, %s, %s or %s",
		clientAuthNone, clientAuthSecretBasic, clientAuthSecretPost, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT)
}

// idJAGPinnedParamError refuses token_param.<key> on an id_jag source when key is one of
// the fields that make the request an ID-JAG request, saying what to do instead.
func idJAGPinnedParamError(key string) error {
	for _, p := range idJAGPinnedParams {
		if p.key == key {
			return fmt.Errorf("token_param.%s cannot override the ID-JAG request with grant=id_jag: %s", key, p.instead)
		}
	}
	return nil
}

// validateIssuerIdentifier checks an RFC 8414 issuer identifier: an https URL with a host
// and no query or fragment. It is only ever named as an assertion's audience, never
// called, so it needs no SSRF guard — but a server compares it exactly, so a value with
// a query or fragment could never match and is refused here instead of at every mint.
func validateIssuerIdentifier(rawURL, fieldName string, tlsSkipVerify bool) error {
	if err := validateOAuth2HTTPSURL(rawURL, fieldName, tlsSkipVerify); err != nil {
		return err
	}
	parsed, _ := url.Parse(rawURL) // already parsed cleanly above
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an issuer identifier, which has no query or fragment", fieldName)
	}
	return nil
}

// rejectInlineClientCredential refuses anything naming a client left in the config of a
// source that fetches its client credential per mint. keys are whatever the chosen
// client_auth calls for; client_id is always checked, since none of the rest are
// meaningful apart from the client they belong to.
func rejectInlineClientCredential(config credential.Config, keys ...string) error {
	return rejectInlineClient(config, "client_id", keys...)
}

// rejectInlineClient is rejectInlineClientCredential for a client whose id is under
// idKey.
func rejectInlineClient(config credential.Config, idKey string, keys ...string) error {
	for _, key := range append(keys, idKey) {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s must be omitted when secret_spec is set; the referenced spec supplies the whole client credential", key)
		}
	}
	return nil
}

// isClientSecretMethod reports whether a client_auth value presents a client secret,
// which is good at any server that accepts it, unlike an assertion naming one server.
func isClientSecretMethod(method string) bool {
	return method == clientAuthSecretPost || method == clientAuthSecretBasic
}

// isClientAssertionMethod reports whether a client_auth value presents an RFC 7523
// client assertion, the one form of client authentication that names an audience.
func isClientAssertionMethod(method string) bool {
	return method == clientAuthPrivateKeyJWT || method == clientAuthKMSPrivateKeyJWT
}

// validateClientCredential checks that the client keys names carries what its method
// needs. A source in chaining mode (secret_spec set) holds no part of a client: the
// secret is excluded because a source that reads as keyless must not still store the
// very secret chaining exists to remove, and the id follows it because the two
// authenticate as a pair. An id kept here beside a secret fetched from the chain would
// name one client while presenting another's, which the token endpoint answers with
// invalid_client, and which the chained path then reads as a rejected secret and
// retries pointlessly.
//
// Requiring everything from the payload also lets one source and one spec serve many
// clients, since the pair is resolved per mint rather than pinned to the source.
func validateClientCredential(config credential.Config, keys clientKeys, method string, chained bool) error {
	rejectInline := func(names ...string) error { return rejectInlineClient(config, keys.id, names...) }
	switch method {
	case clientAuthSecretBasic, clientAuthSecretPost:
		if chained {
			return rejectInline(keys.secret)
		}
		if credential.GetString(config, keys.id, "") == "" {
			return fmt.Errorf("%s is required for a secret-based %s", keys.id, keys.auth)
		}
		if credential.GetString(config, keys.secret, "") == "" {
			return fmt.Errorf("%s (or secret_spec) is required for a secret-based %s", keys.secret, keys.auth)
		}
	case clientAuthPrivateKeyJWT:
		if chained {
			// The key id goes with the key. A kid identifies one key among the several an
			// authorization server may hold for a client, so it is only true of the key it
			// was stored beside — kept here, it would stamp assertions signed by every
			// agent's key with one agent's kid, and an AS that selects its verification key
			// by kid would refuse all but that one.
			return rejectInline(keys.privateKey, keys.kid)
		}
		if credential.GetString(config, keys.id, "") == "" {
			return fmt.Errorf("%s is required for %s=%s", keys.id, keys.auth, clientAuthPrivateKeyJWT)
		}
		if credential.GetString(config, keys.privateKey, "") == "" {
			return fmt.Errorf("%s (or secret_spec) is required for %s=%s", keys.privateKey, keys.auth, clientAuthPrivateKeyJWT)
		}
	case clientAuthKMSPrivateKeyJWT:
		// The signing capability IS the referenced material, so there is no inline form
		// of this method: without secret_spec there is nothing to sign with.
		if !chained {
			return fmt.Errorf("%s=%s requires secret_spec naming the spec that mints the signing capability", keys.auth, clientAuthKMSPrivateKeyJWT)
		}
		// Same rule as private_key_jwt, and for the same reason: everything naming the
		// client travels with the key it belongs to.
		if err := rejectInline(keys.privateKey, keys.kid); err != nil {
			return err
		}
		// The payload is read by fixed field names, so a field selector would either be
		// ignored or point at one coordinate as though it were the secret.
		if credential.GetString(config, credential.ConfigSecretField, "") != "" {
			return fmt.Errorf("secret_field must be omitted for %s=%s; the referenced payload is read by its own field names", keys.auth, clientAuthKMSPrivateKeyJWT)
		}
		// The algorithm is a property of the key, checked against it when the capability
		// is minted. Naming it again here could only ever disagree.
		if credential.GetString(config, "client_assertion_alg", "") != "" {
			return fmt.Errorf("client_assertion_alg must be omitted for %s=%s; the algorithm travels with the key in the referenced payload", keys.auth, clientAuthKMSPrivateKeyJWT)
		}
	}
	return nil
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *TokenExchangeDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "private_key", "resource_client_secret", "resource_private_key", "ca_data"}
}

// StoredSecrets reports the secret config keys this source holds.
func (f *TokenExchangeDriverFactory) StoredSecrets(config credential.Config) []string {
	return config.Present("client_secret", "private_key", "resource_client_secret", "resource_private_key")
}

// InferCredentialType returns the credential type for token_exchange sources.
func (f *TokenExchangeDriverFactory) InferCredentialType(_ credential.Config) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new TokenExchangeDriver.
func (f *TokenExchangeDriverFactory) Create(config credential.Config, log *logger.GatedLogger) (credential.SourceDriver, error) {
	client, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	return newTokenExchangeDriver(config, client, log.WithSubsystem(credential.SourceTypeTokenExchange)), nil
}

// newTokenExchangeDriver assembles a driver for a source's config. It is the one place a
// driver is built, and it is rebuilt whenever its source changes, so what a stored
// source's config decides once, rather than on every mint, is decided here.
func newTokenExchangeDriver(config credential.Config, client *http.Client, log *logger.GatedLogger) *TokenExchangeDriver {
	d := &TokenExchangeDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeTokenExchange, Config: config},
		logger:     log,
		httpClient: client,
		// The source's TLS settings describe its token endpoint, not the signing
		// store, so they are not handed to the signers.
		capSigners: remotesign.NewCapabilitySigners(log, remotesign.CapabilityOptions{}),
		refusal:    storedIDJAGRefusal(config),
		inline:     tokenClients{idp: inlineClient(config, idpClientKeys), resource: inlineClient(config, resourceClientKeys)},
	}
	d.warnStoredIDJAG()
	return d
}

// storedIDJAGRefusal is why an id_jag source stored before today's write checks cannot
// mint, or nil. A write refuses both shapes now; a stored source reaches the driver
// without one, so the same rules hold here, before anything is sent or signed.
//
// A public client is refused because the IdP must authenticate the client it issues an
// ID-JAG to. A pinned token_param.* field is refused because dropping it would change
// what the IdP is sent without a word, and sending it would make the request something
// other than an ID-JAG request; the first in idJAGPinnedParams order is named.
func storedIDJAGRefusal(cfg credential.Config) error {
	if credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG {
		return nil
	}
	if err := idJAGClientAuthError(cfg); err != nil {
		return fmt.Errorf("this id_jag source cannot mint until it is updated: %w", err)
	}
	params := credential.GetPrefixed(cfg, "token_param.")
	for _, p := range idJAGPinnedParams {
		if _, ok := params[p.key]; ok {
			return fmt.Errorf("this id_jag source cannot mint until it is updated: %w", idJAGPinnedParamError(p.key))
		}
	}
	return nil
}

// warnStoredIDJAG logs, each time the driver is built, what a stored id_jag source
// carries that a write would now refuse: why it cannot mint at all, if it cannot; a
// client secret leg 2 would present to the resource authorization server; and each
// token_param.* field sent only when its config key is empty. Otherwise an operator
// would learn of these only from a failed or changed request, or not at all. The
// endpoints identify the source, whose name the driver is not given.
func (d *TokenExchangeDriver) warnStoredIDJAG() {
	cfg := d.credSource.Config
	if d.logger == nil || credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG {
		return
	}
	source := []logger.TypedField{
		logger.String("token_url", credential.GetString(cfg, "token_url", "")),
		logger.String("resource_token_url", credential.GetString(cfg, "resource_token_url", "")),
	}
	if d.refusal != nil {
		d.logger.Warn("id_jag source cannot mint until it is updated", append(source, logger.Err(d.refusal))...)
	}
	// A write now refuses this shape; a stored source keeps minting, and keeps handing
	// the IdP's client secret to the resource authorization server until it is fixed.
	if isClientSecretMethod(idpClientKeys.method(cfg)) && resourceClientKeys.method(cfg) == "" {
		d.logger.Warn("id_jag source sends the IdP's client secret to the resource authorization server; set resource_client_auth and the resource client's credential", source...)
	}
	params := credential.GetPrefixed(cfg, "token_param.")
	for _, key := range slices.Sorted(maps.Keys(params)) {
		if own, ok := idJAGFirstClassParams[key]; ok {
			d.logger.Warn("id_jag source carries a token_param that is sent only when its config key is empty; set the config key instead",
				append(source, logger.String("token_param", key), logger.String("config_key", own))...)
		}
	}
}

// Type returns the driver type.
func (d *TokenExchangeDriver) Type() string {
	return credential.SourceTypeTokenExchange
}

// MintCredential is a defensive error: this driver is exchange-only. Reaching it
// means a spec without a subject source slipped past validation; never forward
// without caller identity.
func (d *TokenExchangeDriver) MintCredential(_ context.Context, _ *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return nil, nil, 0, "", fmt.Errorf("token_exchange requires caller exchange inputs; set %s=%s|%s|%s on the spec",
		credential.ConfigSubjectTokenSource, credential.SourceAgentIdentity, credential.SourceUserIdentity, credential.SourceWardenIdentity)
}

// MintCredentialWithExchange exchanges the caller-derived subject for a scoped
// downstream bearer token, authenticating as the clients the source configures.
func (d *TokenExchangeDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return d.mintExchange(ctx, spec, inputs, d.inline)
}

// MintCredentialWithExchangeFromSecret performs the same exchange as
// MintCredentialWithExchange, but its client credentials come from credential-chaining
// material (secret_spec) instead of source config. A chained source stores no part of
// them, so each client's id and secret or key are read together from the one fetched
// payload.
func (d *TokenExchangeDriver) MintCredentialWithExchangeFromSecret(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	clients, err := chainedClients(d.credSource.Config, material)
	if err != nil {
		return nil, nil, 0, "", err
	}
	return d.mintExchange(ctx, spec, inputs, clients)
}

// tokenClients are the clients one mint authenticates as: idp at token_url, and
// resource, when the source names one, at resource_token_url for id_jag's leg 2.
type tokenClients struct{ idp, resource *tokenClient }

// redeemer is the client id_jag's leg 2 authenticates as: the resource client when the
// source names one, else the IdP client.
func (c tokenClients) redeemer() *tokenClient {
	if c.resource != nil {
		return c.resource
	}
	return c.idp
}

// chainedClients reads both clients out of fetched secret material, for the methods the
// source configures. The reading is shared with every driver that chains a client
// credential (chainedClientAuthFromPayload); this names the driver, and the client, in
// what it reports.
func chainedClients(cfg credential.Config, material credential.SecretMaterial) (tokenClients, error) {
	idp, err := chainedClient(cfg, idpClientKeys, material)
	if err != nil {
		return tokenClients{}, fmt.Errorf("token_exchange: %w", err)
	}
	if credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG || resourceClientKeys.method(cfg) == "" {
		return tokenClients{idp: idp}, nil
	}
	// The field selector picks the IdP client's secret. Pointed at the resource
	// client's, it would have leg 1 present that secret to the IdP; a spec's own
	// secret_field can override the source's, so this holds at mint as well as at
	// write. No refetch would change it.
	if fieldOfResourceClient(material.Field) {
		return tokenClients{}, fmt.Errorf("token_exchange: secret_field %q names the resource client's credential, and selects the IdP client's secret only", material.Field)
	}
	resource, err := chainedClient(cfg, resourceClientKeys, material)
	if err != nil {
		return tokenClients{}, fmt.Errorf("token_exchange: resource client: %w", err)
	}
	return tokenClients{idp: idp, resource: resource}, nil
}

// fieldOfResourceClient reports whether a payload field is one the resource client's
// credential travels under.
func fieldOfResourceClient(field string) bool {
	p := resourceClientKeys.payload
	return field != "" && (field == p.id || field == p.secret || field == p.key || slices.Contains(p.kids, field))
}

// mintExchange runs the exchange for the configured grant, authenticating as clients.
func (d *TokenExchangeDriver) mintExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, clients tokenClients) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if d.refusal != nil {
		return nil, nil, 0, "", d.refusal
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: no subject token in exchange inputs")
	}

	// Every subject/actor Warden forwards is trusted at the source — a Warden-minted
	// assertion, the agent's verified inbound JWT, or the user's auth-method-validated
	// credential — so the driver forwards it to the STS as-is.

	// Actor delegation (RFC 8693). jwt-bearer has no actor slot, so reject an actor
	// there.
	if inputs.ActorToken != "" {
		if credential.GetString(d.credSource.Config, "grant", tokenExchangeGrantRFC8693) == tokenExchangeGrantJWTBearer {
			return nil, nil, 0, "", fmt.Errorf("token_exchange: actor tokens are not supported with grant=jwt_bearer (no actor slot)")
		}
	}

	var (
		resp *oauth2TokenResponse
		err  error
	)
	if credential.GetString(d.credSource.Config, "grant", tokenExchangeGrantRFC8693) == tokenExchangeGrantIDJAG {
		resp, err = d.mintIDJAG(ctx, spec, inputs, clients)
	} else {
		resp, err = d.exchangeOnce(ctx, spec, inputs, clients.idp)
	}
	if err != nil {
		return nil, nil, 0, "", err
	}
	if resp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: token response missing access_token")
	}

	return accessTokenRawData(resp), d.subjectMetadata(resp, inputs, clients), exchangedTokenLease(resp.ExpiresIn, d.credSource.Config, spec), "", nil
}

// exchangeOnce performs a single-hop exchange (rfc8693 or jwt_bearer), authenticating
// as client.
func (d *TokenExchangeDriver) exchangeOnce(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, client *tokenClient) (*oauth2TokenResponse, error) {
	form, err := d.buildExchangeForm(spec, inputs)
	if err != nil {
		return nil, err
	}
	cfg := d.credSource.Config
	return d.postWithClientAuth(ctx, tokenCall{
		endpoint: credential.GetString(cfg, "token_url", ""),
		issuer:   credential.GetString(cfg, "issuer", ""),
		readable: tokenEndpointReadableStatuses,
		attempts: oauth2MaxRetryAttempts,
		classify: classifyExchangeError,
		rejected: "token_exchange: client authentication rejected",
	}, sameForm(form), client)
}

// tokenCall is how one request to a token endpoint is made, and how its refusals read.
type tokenCall struct {
	// endpoint is where the request is sent. issuer is the issuer identifier of the
	// server behind it, which a client assertion names as its audience when the source
	// asks for it (client_assertion_aud=issuer); the assertion otherwise names endpoint.
	endpoint, issuer string
	// readable lists the statuses whose body is read as an OAuth2 answer.
	readable []int
	// attempts is how many times the request is tried before a retryable failure is
	// given up on.
	attempts int
	// classify renders a failure the endpoint answered with, or a transport failure.
	classify func(error) error
	// rejected opens the error for a chained client credential the endpoint refused.
	rejected string
}

// sameForm builds the same form for every attempt, each a copy of form, so the
// client authentication an attempt adds never reaches the next one.
func sameForm(form url.Values) func() (url.Values, error) {
	return func() (url.Values, error) { return maps.Clone(form), nil }
}

// postWithClientAuth sends the form build makes to call.endpoint, authenticated as
// client. The client's assertion names call.endpoint, or call.issuer when the client
// asks for the issuer.
//
// build runs once per attempt, and the client authentication is applied afresh to what
// it returns, so a retry presents a new client assertion rather than replaying one: a
// server enforcing single use refuses a repeated jti as invalid_client, and a request it
// received but whose answer was lost would otherwise turn a blip into a failed mint.
//
// A failure before sending is returned as it is: a key that will not parse, a capability
// found spent, or whatever build itself failed on. Nothing was sent, so it is not this
// endpoint's error to classify. When the endpoint rejects a client credential that came
// from credential chaining, the error wraps credential.ErrChainedSecretRejected, so the
// minting layer evicts the cached secret and retries once with a fresh fetch;
// invalid_client does not say which half was refused and need not, since the refetch
// replaces both. Any other failure is rendered by call.classify.
func (d *TokenExchangeDriver) postWithClientAuth(ctx context.Context, call tokenCall, build func() (url.Values, error), client *tokenClient) (*oauth2TokenResponse, error) {
	aud := clientAssertionAudience(client.audMode, call.endpoint, call.issuer)
	var buildErr error
	resp, err := postOAuthTokenFormFuncReading(ctx, d.httpClient, call.endpoint, func() (url.Values, error) {
		form, err := build()
		if err == nil {
			err = d.applyClientAuth(ctx, form, aud, client)
		}
		if err != nil {
			buildErr = err
			return nil, err
		}
		return form, nil
	}, clientAuthHeaders(client), call.readable, call.attempts)
	if buildErr != nil {
		return nil, buildErr
	}
	if err != nil {
		// The rejection test is shared with the oauth2 driver: client_secret_post's 400,
		// client_secret_basic's 401, and a rejected assertion under either private_key_jwt
		// method. For a KMS-held key that last case is how an authorization server holding
		// only the previous public key recovers: the eviction re-mints the capability,
		// which resolves the current key version. It runs before call.classify, whose
		// reading of a 400 or 401 would otherwise hide it.
		if client.chained && isChainedClientAuthRejection(err) {
			return nil, fmt.Errorf("%s: %w (%w)", call.rejected, credential.ErrChainedSecretRejected, err)
		}
		return nil, call.classify(err)
	}
	return resp, nil
}

// mintIDJAG runs the two-leg ID-JAG cross-app-access flow inside one mint:
//
//	leg 1 → token_url (home IdP): RFC 8693 token-exchange with
//	        requested_token_type=id-jag, the audience, scope and resource
//	        indicators → an ID-JAG assertion bound to the resource AS, carrying what
//	        the IdP granted
//	leg 2 → resource_token_url (resource AS): RFC 7523 jwt-bearer with the ID-JAG
//	        as the assertion, and the scope the IdP granted → the downstream access
//	        token
//
// The draft has the resource authorization server read scope and resources from the
// ID-JAG. Resources are left there, but the scope is named again: a server that
// issues only the scope a redemption asks for, as the xaa.dev reference
// implementation does, would otherwise issue a token with none. It is the scope the
// IdP granted — its answer's scope, or the one asked for when the answer leaves it
// out, which says they are the same (§4.3.4) — so it is never more than the ID-JAG
// carries, and cannot be refused for asking more. Leg 1 authenticates as the IdP
// client; leg 2 as the resource client the source names, which is the client the
// ID-JAG's client_id names (§3.1, §4.4.1), else as the IdP client. Each assertion
// names its own endpoint or issuer. Only the final access token is returned.
//
// Each attempt at leg 2 sends an ID-JAG no attempt has sent before, with the scope
// granted for it. A resource authorization server may accept each ID-JAG only once,
// by its jti, and one whose answer was lost may already have spent it; so a retried
// leg 2 asks the IdP for a new one first. That request is tried once: leg 2's own
// retries already cover a failing IdP, and trying it again inside each of them would
// multiply the calls. A retry the resource authorization server asked for with a 429
// costs a new ID-JAG too, since an attempt cannot tell that answer from a lost one.
func (d *TokenExchangeDriver) mintIDJAG(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, clients tokenClients) (*oauth2TokenResponse, error) {
	cfg := d.credSource.Config
	// A client that cannot authenticate at all fails the mint before an ID-JAG is asked
	// for, rather than after one is issued and wasted.
	for _, c := range []*tokenClient{clients.idp, clients.redeemer()} {
		if err := c.unusable(); err != nil {
			return nil, err
		}
	}
	leg1, err := d.idJAGRequestForm(spec, inputs)
	if err != nil {
		return nil, err
	}
	// A refused subject asks the user to sign in again only when the user's token is the
	// one thing the request could be refused for: a request that also carries an actor
	// token or extras of the source's own can be refused for those, which a new user
	// token would not fix and the user would be sent round in circles.
	challenge := spec != nil && spec.Config.Get(credential.ConfigSubjectTokenSource) == credential.SourceUserIdentity &&
		!leg1.Has("actor_token") && len(credential.GetPrefixed(cfg, "token_param.")) == 0
	jag, scope, err := d.requestIDJAG(ctx, leg1, challenge, clients.idp, oauth2MaxRetryAttempts)
	if err != nil {
		return nil, err
	}

	// Leg 2: redeem the ID-JAG at the resource authorization server, for the scope the
	// IdP granted. The ID-JAG an attempt sends is cleared once it is in the form; a
	// later attempt finds none and requests its own.
	redeem := tokenCall{
		endpoint: credential.GetString(cfg, "resource_token_url", ""),
		issuer:   credential.GetString(cfg, "resource_issuer", ""),
		readable: jwtBearerReadableStatuses,
		attempts: oauth2MaxRetryAttempts,
		classify: classifyIDJAGRedeemError,
		rejected: "id_jag: the resource authorization server rejected the chained client credential",
	}
	return d.postWithClientAuth(ctx, redeem, func() (url.Values, error) {
		if jag == "" {
			if d.logger != nil {
				d.logger.Debug("requesting a new ID-JAG for a retried redemption",
					logger.String("resource_token_url", redeem.endpoint))
			}
			fresh, freshScope, err := d.requestIDJAG(ctx, leg1, challenge, clients.idp, 1)
			if err != nil {
				// The mint fails with the IdP's answer; what made the redemption retry is
				// only in this record.
				if d.logger != nil {
					d.logger.Warn("a retried ID-JAG redemption could not get a new ID-JAG",
						logger.String("resource_token_url", redeem.endpoint), logger.Err(err))
				}
				return nil, err
			}
			jag, scope = fresh, freshScope
		}
		form := url.Values{"grant_type": {grantTypeJWTBearer}, "assertion": {jag}}
		if scope != "" {
			form.Set("scope", scope)
		}
		jag = ""
		return form, nil
	}, clients.redeemer())
}

// requestIDJAG asks the IdP for an ID-JAG (leg 1) with form, as client, trying at most
// attempts times, and returns it with the scope the IdP granted for it. challenge
// makes a refused subject ask the user to authenticate again.
func (d *TokenExchangeDriver) requestIDJAG(ctx context.Context, form url.Values, challenge bool, client *tokenClient, attempts int) (string, string, error) {
	cfg := d.credSource.Config
	resp, err := d.postWithClientAuth(ctx, tokenCall{
		endpoint: credential.GetString(cfg, "token_url", ""),
		issuer:   credential.GetString(cfg, "issuer", ""),
		readable: tokenEndpointReadableStatuses,
		attempts: attempts,
		classify: classifyIDJAGRequestError(challenge),
		rejected: "id_jag: the IdP rejected the chained client credential",
	}, sameForm(form), client)
	if err != nil {
		return "", "", err
	}
	if resp.AccessToken == "" {
		return "", "", fmt.Errorf("id_jag: the IdP returned no ID-JAG")
	}
	// The response must say what it issued (draft-ietf-oauth-identity-assertion-authz-grant
	// §4.3.4), so nothing else is ever redeemed as an ID-JAG.
	if resp.IssuedTokenType != tokenTypeIDJAG {
		return "", "", fmt.Errorf("id_jag: the IdP returned issued_token_type %q, expected %q", resp.IssuedTokenType, tokenTypeIDJAG)
	}
	return resp.AccessToken, grantedScope(resp, form), nil
}

// idJAGRequestForm builds the ID-JAG request (leg 1) for one mint, without client
// authentication, which each attempt adds to its own copy.
func (d *TokenExchangeDriver) idJAGRequestForm(spec *credential.CredSpec, inputs *credential.ExchangeInputs) (url.Values, error) {
	// The ID-JAG must be bound to the resource authorization server via audience.
	audience := d.resolve(spec, "audience")
	if audience == "" {
		return nil, fmt.Errorf("id_jag: audience (the resource authorization server) is required")
	}
	// The subject's type comes from the spec, whatever the request path defaulted it
	// to: a spec stored before the write check existed meets the same rules here.
	var specCfg credential.Config
	if spec != nil {
		specCfg = spec.Config
	}
	subjectType, err := idJAGSubjectTokenType(specCfg)
	if err != nil {
		return nil, err
	}
	if subjectType == credential.TokenTypeIDToken {
		if err := idTokenShapeError(inputs.SubjectToken); err != nil {
			return nil, err
		}
	}
	leg1 := url.Values{}
	leg1.Set("grant_type", grantTypeTokenExchange)
	leg1.Set("subject_token", inputs.SubjectToken)
	leg1.Set("subject_token_type", subjectType)
	leg1.Set("requested_token_type", tokenTypeIDJAG)
	leg1.Set("audience", audience)
	if inputs.ActorToken != "" {
		leg1.Set("actor_token", inputs.ActorToken)
		leg1.Set("actor_token_type", actorTokenType(inputs))
	}
	// The IdP decides on scope and resource indicators and writes what it grants into
	// the ID-JAG.
	if scope := d.resolve(spec, "scope"); scope != "" {
		leg1.Set("scope", scope)
	}
	d.addResources(leg1, spec)
	// Vendor-specific extras apply to the exchange (leg 1) at the home IdP.
	addIDJAGExtras(leg1, d.credSource.Config)
	return leg1, nil
}

// grantedScope is the scope the IdP granted an ID-JAG request: its answer's scope, or
// the scope asked for when the answer leaves it out, which says the two are the same
// (draft-ietf-oauth-identity-assertion-authz-grant §4.3.4).
func grantedScope(answer *oauth2TokenResponse, request url.Values) string {
	if answer.Scope != "" {
		return answer.Scope
	}
	return request.Get("scope")
}

// addIDJAGExtras adds a source's token_param.* extras to an ID-JAG request (leg 1).
//
// A pinned field is never added: a source that carries one is refused before any
// request is built (storedIDJAGRefusal). A first-class field is added only when its
// config key left it empty, so it never replaces a narrower value a spec sets nor
// collapses repeated resource indicators. A resource fallback is split like resources,
// one indicator per value.
func addIDJAGExtras(form url.Values, cfg credential.Config) {
	for k, v := range credential.GetPrefixed(cfg, "token_param.") {
		_, firstClass := idJAGFirstClassParams[k]
		switch {
		case idJAGPinned(k), firstClass && form.Has(k):
			// Not sent: refused when the driver was built, or set by its config key.
		case k == "resource":
			for _, r := range strings.Fields(v) {
				form.Add(k, r)
			}
		default:
			form.Set(k, v)
		}
	}
}

// buildExchangeForm assembles the token-endpoint form for the configured grant.
func (d *TokenExchangeDriver) buildExchangeForm(spec *credential.CredSpec, inputs *credential.ExchangeInputs) (url.Values, error) {
	cfg := d.credSource.Config
	form := url.Values{}

	switch credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) {
	case tokenExchangeGrantRFC8693, "":
		form.Set("grant_type", grantTypeTokenExchange)
		form.Set("subject_token", inputs.SubjectToken)
		form.Set("subject_token_type", subjectTokenType(inputs))
		if aud := d.resolve(spec, "audience"); aud != "" {
			form.Set("audience", aud)
		}
		if inputs.ActorToken != "" {
			form.Set("actor_token", inputs.ActorToken)
			form.Set("actor_token_type", actorTokenType(inputs))
		}
	case tokenExchangeGrantJWTBearer:
		// audience is an RFC 8693 token-exchange parameter; jwt-bearer has no slot
		// for it (it targets via scope). Reject rather than silently drop an
		// operator-set value — if a specific IdP needs it, send token_param.audience.
		// (RFC 8707 resources are grant-agnostic and handled below.)
		if aud := d.resolve(spec, "audience"); aud != "" {
			return nil, fmt.Errorf("token_exchange: 'audience' is not sent with grant=jwt_bearer; target via 'scope'/'resources', or set 'token_param.audience' if your IdP requires it")
		}
		form.Set("grant_type", grantTypeJWTBearer)
		form.Set("assertion", inputs.SubjectToken)
	default:
		return nil, fmt.Errorf("token_exchange: unsupported grant %q", credential.GetString(cfg, "grant", ""))
	}

	if scope := d.resolve(spec, "scope"); scope != "" {
		form.Set("scope", scope)
	}
	// RFC 8707 resource indicators (grant-agnostic).
	d.addResources(form, spec)
	// Vendor-specific extras (e.g. Entra's requested_token_use=on_behalf_of).
	for k, v := range credential.GetPrefixed(cfg, "token_param.") {
		form.Set(k, v)
	}
	return form, nil
}

// clientKeys names where one client of a token_exchange source is configured: its
// config keys, and its fields in a chained payload. A source authenticates as its IdP
// client; an id_jag source may also authenticate at the resource authorization server
// as a client registered there.
type clientKeys struct {
	// auth, id, secret, privateKey, kid and assertionAud are the client's config keys.
	auth, id, secret, privateKey, kid, assertionAud string
	// defaultAuth is the method when auth is unset; empty means the client is absent.
	defaultAuth string
	// payload names the client's fields in a chained payload.
	payload payloadFields
}

// method is the client's method in cfg: its auth key's value, or defaultAuth when the
// key is unset or empty, since an empty value is how an update clears a field. Every
// reader of a client's method goes through here, so a cleared one never reads as a
// method of its own.
func (k clientKeys) method(cfg credential.Config) string {
	if v := cfg.Get(k.auth); v != "" {
		return v
	}
	return k.defaultAuth
}

var (
	// idpClientKeys configure the client at token_url.
	idpClientKeys = clientKeys{
		auth: "client_auth", id: "client_id", secret: "client_secret", privateKey: "private_key",
		kid: "client_assertion_kid", assertionAud: "client_assertion_aud",
		defaultAuth: clientAuthSecretPost,
		payload:     clientPayloadFields,
	}
	// resourceClientKeys configure id_jag's client at resource_token_url, which leg 2
	// authenticates as when it is set.
	resourceClientKeys = clientKeys{
		auth: "resource_client_auth", id: "resource_client_id", secret: "resource_client_secret", privateKey: "resource_private_key",
		kid: "resource_client_assertion_kid", assertionAud: "resource_client_assertion_aud",
		payload: payloadFields{
			id: "resource_client_id", secret: "resource_client_secret", key: "resource_private_key",
			kids: []string{"resource_client_assertion_kid", "resource_kid"},
		},
	}
)

// tokenClient is one client resolved for a mint: how it authenticates, its id, what it
// presents, and the audience its assertions name. A client from the source's own
// config is resolved once, when the driver is built; one from credential chaining once
// per mint. Neither changes after it is resolved, so concurrent mints share one safely.
type tokenClient struct {
	method      string // a client_auth value
	methodField string // the config field method was read from, named in what it reports
	audMode     string // a client_assertion_aud value
	id          string
	secret      string // the client secret, for the secret methods
	kid         string
	key         *rsa.PrivateKey        // private_key_jwt's key, parsed once
	keyErr      error                  // why private_key_jwt has no key to sign with
	kms         *remotesign.Capability // kms_private_key_jwt's signing capability
	chained     bool                   // fetched through credential chaining
}

// inlineClient resolves the client keys names from the source's own config, or returns
// nil when the source configures none. A private key that does not parse is kept as the
// reason the client cannot sign, reported when it is needed, so a stored source with a
// bad key still builds and fails only the mints that use it.
func inlineClient(cfg credential.Config, keys clientKeys) *tokenClient {
	method := keys.method(cfg)
	if method == "" {
		return nil
	}
	c := &tokenClient{
		method:      method,
		methodField: keys.auth,
		audMode:     credential.GetString(cfg, keys.assertionAud, ""),
		id:          credential.GetString(cfg, keys.id, ""),
	}
	switch method {
	case clientAuthSecretPost, clientAuthSecretBasic:
		c.secret = credential.GetString(cfg, keys.secret, "")
	case clientAuthPrivateKeyJWT:
		c.kid = credential.GetString(cfg, keys.kid, "")
		if c.key, c.keyErr = parseRSAPrivateKey(credential.GetString(cfg, keys.privateKey, "")); c.keyErr != nil {
			c.keyErr = fmt.Errorf("invalid %s: %w", keys.privateKey, c.keyErr)
		}
	}
	return c
}

// chainedClient resolves the client keys names from a fetched chained payload, or
// returns nil when the source configures none. Its method and audience mode stay the
// source's; everything naming the client comes from the payload.
func chainedClient(cfg credential.Config, keys clientKeys, material credential.SecretMaterial) (*tokenClient, error) {
	method := keys.method(cfg)
	if method == "" {
		return nil, nil
	}
	auth, err := chainedClientAuthFromPayload(method, material, keys.payload)
	if err != nil {
		return nil, err
	}
	c := &tokenClient{
		method:      method,
		methodField: keys.auth,
		audMode:     credential.GetString(cfg, keys.assertionAud, ""),
		id:          auth.clientID,
		kid:         auth.kid,
		kms:         auth.kms,
		chained:     true,
	}
	switch method {
	case clientAuthSecretPost, clientAuthSecretBasic:
		c.secret = auth.secret
	case clientAuthPrivateKeyJWT:
		if c.key, c.keyErr = parseRSAPrivateKey(auth.secret); c.keyErr != nil {
			c.keyErr = fmt.Errorf("invalid %s: %w", keys.payload.key, c.keyErr)
		}
	}
	return c, nil
}

// clientAuthHeaders returns the headers c's client authentication sends:
// client_secret_basic's Authorization header, and nothing for the other methods. They
// are the same on every attempt, so they are settled once rather than per attempt.
func clientAuthHeaders(c *tokenClient) map[string]string {
	if c.method != clientAuthSecretBasic {
		return nil
	}
	return map[string]string{"Authorization": basicClientAuthHeader(c.id, c.secret)}
}

// applyClientAuth decorates the form with c's client authentication. aud is the
// audience for a client assertion (each ID-JAG leg authenticates against its own
// server). It runs once per attempt, so an assertion is never sent twice;
// client_secret_basic travels in a header instead (see clientAuthHeaders).
func (d *TokenExchangeDriver) applyClientAuth(ctx context.Context, form url.Values, aud string, c *tokenClient) error {
	switch c.method {
	case clientAuthSecretPost:
		form.Set("client_id", c.id)
		form.Set("client_secret", c.secret)
	case clientAuthSecretBasic:
		// Sent in the Authorization header; nothing goes in the body.
	case clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT:
		// One case for both: the assertion, and everything the endpoint sees, is
		// identical. Only where the signature comes from differs.
		assertion, err := d.buildClientAssertion(ctx, c, aud)
		if err != nil {
			return err
		}
		form.Set("client_id", c.id)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case clientAuthNone:
		// RFC 6749 §2.3: a public client identifies itself with client_id alone, and only
		// when the endpoint knows it by one.
		if c.id != "" {
			form.Set("client_id", c.id)
		}
	default:
		return fmt.Errorf("token_exchange: unsupported %s %q", c.methodField, c.method)
	}
	return nil
}

// unusable is why c cannot authenticate at all, found before anything is sent: a key
// that does not parse, or a capability method with no capability. Nil when c can try.
func (c *tokenClient) unusable() error {
	switch {
	case c.method == clientAuthPrivateKeyJWT && c.keyErr != nil:
		return fmt.Errorf("token_exchange: %w", c.keyErr)
	case c.method == clientAuthKMSPrivateKeyJWT && c.kms == nil:
		return fmt.Errorf("token_exchange: %s=%s signs with a capability from secret_spec, and none was fetched", c.methodField, clientAuthKMSPrivateKeyJWT)
	}
	return nil
}

// buildClientAssertion builds and signs an RFC 7523 client-assertion JWT for c: a
// short-lived JWT with iss=sub=c's id and the given aud, signed with c's key under the
// key id stored beside it, or by its signing capability.
func (d *TokenExchangeDriver) buildClientAssertion(ctx context.Context, c *tokenClient, aud string) (string, error) {
	claims, err := clientAssertionClaims(c.id, aud)
	if err != nil {
		return "", err
	}

	// A signing capability signs the very same claims elsewhere. Built here rather than
	// in the remote path so the two methods cannot drift into producing different
	// assertions.
	if c.kms != nil {
		return d.signAssertionWithCapability(ctx, c.kms, claims)
	}
	if err := c.unusable(); err != nil {
		return "", err
	}
	assertion, err := signClientAssertionLocal(c.key, c.kid, claims)
	if err != nil {
		return "", fmt.Errorf("token_exchange: %w", err)
	}
	return assertion, nil
}

// signAssertionWithCapability signs the client assertion with a key the capability
// names but Warden cannot read. The signing and its error mapping are shared with every
// driver that authenticates with a capability (signClientAssertionWithCapability); this
// names the driver in what it reports.
func (d *TokenExchangeDriver) signAssertionWithCapability(ctx context.Context, c *remotesign.Capability, claims map[string]interface{}) (string, error) {
	assertion, err := signClientAssertionWithCapability(ctx, d.capSigners, c, claims)
	if err != nil {
		return "", fmt.Errorf("token_exchange: %w", err)
	}
	return assertion, nil
}

// addResources appends the source/spec's RFC 8707 resource indicators as repeated
// `resource` form parameters. `resources` is a space-separated list of absolute
// URIs; RFC 8707 §2 allows the parameter to appear multiple times. It is
// grant-agnostic, so it applies to rfc8693, jwt_bearer, and leg 1 of id_jag alike.
func (d *TokenExchangeDriver) addResources(form url.Values, spec *credential.CredSpec) {
	for _, r := range strings.Fields(d.resolve(spec, "resources")) {
		form.Add("resource", r)
	}
}

// tokenExchangeAssertionResource reports the single RFC 8707 resource a
// token-exchange spec targets, for the warden_resource assertion claim. Pure:
// reads config maps only. It reproduces resolve()'s spec-then-source fallback for
// the `resources` key (which is why the resource can vary with source config, not
// just spec — see the SubjectCacheIdentity note). Only a lone resource is named; zero or
// several yield no claim, since a scalar claim can't express a set.
func tokenExchangeAssertionResource(sourceCfg, specCfg credential.Config) (string, bool) {
	raw := credential.GetString(specCfg, "resources", "")
	if raw == "" {
		raw = credential.GetString(sourceCfg, "resources", "")
	}
	fields := strings.Fields(raw)
	if len(fields) != 1 {
		return "", false
	}
	return "oauth-resource:" + fields[0], true
}

// resolve returns spec.Config.Get(key) when set, else the source config value.
func (d *TokenExchangeDriver) resolve(spec *credential.CredSpec, key string) string {
	if spec != nil {
		if v := credential.GetString(spec.Config, key, ""); v != "" {
			return v
		}
	}
	return credential.GetString(d.credSource.Config, key, "")
}

// subjectMetadata derives the non-secret, audit-logged identity of the exchanged
// token: the subject (from the minted token's sub claim, falling back to the
// subject token's) and — when the exchange carried an actor (delegation) — the
// actor's sub, so agent-on-behalf-of delegation is attributable in the credential's
// audit metadata. The actor sub is read from the actor token's own claims (for an
// actor_token_source=warden_identity actor that is the Warden-minted wid:… sub);
// like the subject it is a claim read, never a raw token byte, so no secret is
// recorded. An id_jag exchange also records the client each leg authenticated as —
// client_id at the IdP, resource_client_id at the resource authorization server —
// since the ID-JAG names the latter and a mismatch is the first thing to look for.
func (d *TokenExchangeDriver) subjectMetadata(resp *oauth2TokenResponse, inputs *credential.ExchangeInputs, clients tokenClients) map[string]interface{} {
	meta := map[string]interface{}{}
	if credential.GetString(d.credSource.Config, "grant", tokenExchangeGrantRFC8693) == tokenExchangeGrantIDJAG {
		meta["client_id"] = clients.idp.id
		meta["resource_client_id"] = clients.redeemer().id
	}
	claims := unverifiedJWTClaims(resp.AccessToken)
	if claims == nil {
		claims = unverifiedJWTClaims(inputs.SubjectToken)
	}
	if claims != nil {
		if sub, ok := scalarClaim(claims["sub"]); ok && sub != "" {
			meta["subject"] = sub
		}
	}
	if inputs.ActorToken != "" {
		if actorClaims := unverifiedJWTClaims(inputs.ActorToken); actorClaims != nil {
			if sub, ok := scalarClaim(actorClaims["sub"]); ok && sub != "" {
				meta["actor"] = sub
			}
		}
	}
	return meta
}

// Revoke is a no-op — exchanged bearer tokens expire naturally.
func (d *TokenExchangeDriver) Revoke(_ context.Context, _ string) error {
	return nil
}

// Cleanup releases resources.
func (d *TokenExchangeDriver) Cleanup(_ context.Context) error {
	d.httpClient.CloseIdleConnections()
	d.capSigners.Close()
	return nil
}

// subjectTokenType returns the RFC 8693 subject_token_type, defaulting to jwt.
func subjectTokenType(inputs *credential.ExchangeInputs) string {
	return tokenTypeOnTheWire(inputs.SubjectTokenType)
}

// actorTokenType returns the RFC 8693 actor_token_type, defaulting to jwt.
func actorTokenType(inputs *credential.ExchangeInputs) string {
	return tokenTypeOnTheWire(inputs.ActorTokenType)
}

// tokenTypeOnTheWire is the token-type URN a request carries for a type a spec names:
// the URN of a short name, a URN as it is, jwt when none is named. A value that names
// no type Warden knows is sent as written, for an STS that defines its own.
func tokenTypeOnTheWire(named string) string {
	if named == "" {
		return credential.TokenTypeJWT
	}
	if urn, ok := credential.TokenTypeURN(named); ok {
		return urn
	}
	return named
}

// unverifiedJWTClaims decodes a JWT's claims without verifying its signature,
// for identity extraction only. Returns nil for opaque (non-JWT) tokens.
func unverifiedJWTClaims(token string) map[string]interface{} {
	claims, err := helper.ParseJWTClaimsUnverified(token)
	if err != nil {
		return nil
	}
	return claims
}

// classifyExchangeError renders a token-endpoint failure into a legible error,
// distinguishing a rejected grant (the caller should re-authenticate) from a
// transport/server failure.
func classifyExchangeError(err error) error {
	var tee *tokenEndpointError
	if errors.As(err, &tee) && (tee.code == "invalid_grant" || tee.status == http.StatusBadRequest || tee.status == http.StatusUnauthorized) {
		return fmt.Errorf("token_exchange rejected by the IdP (the subject token may be expired or unacceptable; re-authenticate): %w", err)
	}
	return fmt.Errorf("token_exchange failed: %w", err)
}

// classifyIDJAGRequestError renders a failed ID-JAG request (leg 1), by the error codes
// draft-ietf-oauth-identity-assertion-authz-grant §4.3.4.3 profiles for it, so an
// operator can tell what would fix it.
//
// challenge marks a request whose only token of the user's is the subject, and nothing
// else of the source's own that could be refused: an invalid_request then asks the user
// to authenticate again, since a new token from them is what resolves it. It can still
// be a request the IdP will not take at all, which the user cannot fix; the cause stays
// in the error for the logs. invalid_grant, which some IdPs answer a refused subject
// with in place of the code the draft profiles, reads the same but asks nothing of the
// user, until an IdP shows that it means the user's token.
func classifyIDJAGRequestError(challenge bool) func(error) error {
	return func(err error) error {
		var tee *tokenEndpointError
		if !errors.As(err, &tee) {
			return fmt.Errorf("id_jag: requesting the ID-JAG from the IdP failed: %w", err)
		}
		switch tee.code {
		case "invalid_request", "invalid_grant":
			refused := fmt.Errorf("id_jag: the IdP refused the subject token (expired, malformed, or issued to another client); a new subject token may resolve it: %w", err)
			if challenge && tee.code == "invalid_request" {
				return &credential.UserChallengeError{Code: credential.UserChallengeInvalidToken, Cause: refused}
			}
			return refused
		case "access_denied":
			return fmt.Errorf("id_jag: the IdP does not allow this client or user an ID-JAG for that resource authorization server; a new subject token will not resolve it: %w", err)
		case "invalid_target":
			return fmt.Errorf("id_jag: the IdP has no trust relationship with the audience, or a resource is not governed by it; check audience and resources: %w", err)
		case "invalid_client":
			return fmt.Errorf("id_jag: the IdP rejected Warden's client authentication: %w", err)
		}
		return fmt.Errorf("id_jag: requesting the ID-JAG from the IdP failed: %w", err)
	}
}

// classifyIDJAGRedeemError renders a failed ID-JAG redemption (leg 2), by the error
// codes draft-ietf-oauth-identity-assertion-authz-grant §4.4.3 profiles for it. Every
// attempt redeems an ID-JAG never sent before, so an invalid_grant points at what the
// ID-JAG says or how it was signed, not at its reuse.
func classifyIDJAGRedeemError(err error) error {
	var tee *tokenEndpointError
	if !errors.As(err, &tee) {
		return fmt.Errorf("id_jag: redeeming the ID-JAG at the resource authorization server failed: %w", err)
	}
	switch tee.code {
	case "invalid_grant":
		return fmt.Errorf("id_jag: the resource authorization server refused the ID-JAG: check that its audience is that server and its client_id the client redeeming it, and its signature, type and lifetime: %w", err)
	case "access_denied":
		return fmt.Errorf("id_jag: the resource authorization server does not allow this user or client; a new ID-JAG will not resolve it: %w", err)
	case "invalid_client":
		return fmt.Errorf("id_jag: the resource authorization server rejected Warden's client authentication: %w", err)
	}
	return fmt.Errorf("id_jag: redeeming the ID-JAG at the resource authorization server failed: %w", err)
}

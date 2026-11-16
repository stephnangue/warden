package drivers

import (
	"context"
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
			Describe("How Warden authenticates to the token endpoint; kms_private_key_jwt signs the same assertion with a key held in a KMS, reached through secret_spec; none presents no client credential (a public client identified by its subject token)").
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
			Describe("Issuer identifier of the resource authorization server behind resource_token_url (id_jag leg 2), named as that leg's client assertion audience when client_assertion_aud=issuer").
			Example("https://auth.resourceapp.example.com"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example("LS0tLS1CRUdJTi..."),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),

		credential.StringField("secret_spec").
			Describe("Source the whole client credential from another cred spec via credential chaining instead of storing it inline (client_id and client_secret / private_key then omitted; the referenced payload supplies both)").
			Example("idp-client-secret"),

		credential.StringField("secret_field").
			Describe("Which field of the referenced secret_spec's credential holds the client secret (when its payload has multiple keys); the client id travels beside it under 'client_id'").
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
	}

	// The audience a client assertion names. Only an assertion has one, and naming the
	// issuer needs the issuer of every server an assertion is sent to: id_jag
	// authenticates to two. Anything that would never be read is refused rather than
	// stored, so the config says what is sent.
	switch clientAuth := credential.GetString(config, "client_auth", clientAuthSecretPost); clientAuth {
	case clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT:
	default:
		if credential.GetString(config, "client_assertion_aud", "") != "" {
			return fmt.Errorf("client_assertion_aud must be omitted for client_auth=%s; it applies to client_auth=%s or %s",
				clientAuth, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT)
		}
	}
	if credential.GetString(config, "client_assertion_aud", "") != clientAssertionAudIssuer {
		// Unlike an oauth2 source's, these name nothing but an assertion's audience.
		for _, key := range []string{"issuer", "resource_issuer"} {
			if credential.GetString(config, key, "") != "" {
				return fmt.Errorf("%s is read only when client_assertion_aud=%s; set that, or omit %s", key, clientAssertionAudIssuer, key)
			}
		}
	} else {
		if credential.GetString(config, "issuer", "") == "" {
			return fmt.Errorf("client_assertion_aud=%s requires issuer, the issuer identifier of the server behind token_url", clientAssertionAudIssuer)
		}
		if idJAG && credential.GetString(config, "resource_issuer", "") == "" {
			return fmt.Errorf("resource_issuer is required for grant=id_jag when client_assertion_aud=%s: leg 2 authenticates to the resource authorization server, which has an issuer of its own", clientAssertionAudIssuer)
		}
	}
	if !idJAG && credential.GetString(config, "resource_issuer", "") != "" {
		return fmt.Errorf("resource_issuer applies only to grant=id_jag, whose leg 2 authenticates to the resource authorization server")
	}

	// Client-auth method determines which credentials are required. A source in
	// chaining mode (secret_spec set) holds NEITHER half of the client credential: the
	// secret is excluded because a source that reads as keyless must not still store the
	// very secret chaining exists to remove, and the id follows it because the two
	// authenticate as a pair. An id kept here beside a secret fetched from the chain
	// would name one client while presenting another's, which the token endpoint answers
	// with invalid_client, and which the chained path then reads as a rejected secret and
	// retries pointlessly.
	//
	// Requiring both from the payload also lets one source and one spec serve many
	// clients, since the pair is resolved per mint rather than pinned to the source.
	chained := credential.GetString(config, credential.ConfigSecretSpec, "") != ""
	switch credential.GetString(config, "client_auth", clientAuthSecretPost) {
	case clientAuthSecretBasic, clientAuthSecretPost, "":
		if chained {
			if err := rejectInlineClientCredential(config, "client_secret"); err != nil {
				return err
			}
			break
		}
		if credential.GetString(config, "client_id", "") == "" {
			return fmt.Errorf("client_id is required for a secret-based client_auth")
		}
		if credential.GetString(config, "client_secret", "") == "" {
			return fmt.Errorf("client_secret (or secret_spec) is required for a secret-based client_auth")
		}
	case clientAuthPrivateKeyJWT:
		if chained {
			// The key id goes with the key. A kid identifies one key among the several
			// an authorization server may hold for a client, so it is only true of the
			// key it was stored beside — kept here, it would stamp assertions signed by
			// every agent's key with one agent's kid, and an AS that selects its
			// verification key by kid would refuse all but that one.
			if err := rejectInlineClientCredential(config, "private_key", "client_assertion_kid"); err != nil {
				return err
			}
			break
		}
		if credential.GetString(config, "client_id", "") == "" {
			return fmt.Errorf("client_id is required for client_auth=private_key_jwt")
		}
		if credential.GetString(config, "private_key", "") == "" {
			return fmt.Errorf("private_key (or secret_spec) is required for client_auth=private_key_jwt")
		}
	case clientAuthKMSPrivateKeyJWT:
		// The signing capability IS the referenced material, so there is no inline
		// form of this method: without secret_spec there is nothing to sign with.
		if !chained {
			return fmt.Errorf("client_auth=%s requires secret_spec naming the spec that mints the signing capability", clientAuthKMSPrivateKeyJWT)
		}
		// Same rule as private_key_jwt, and for the same reason: everything naming the
		// client travels with the key it belongs to.
		if err := rejectInlineClientCredential(config, "private_key", "client_assertion_kid"); err != nil {
			return err
		}
		// The payload is read by fixed field names, so a field selector would either be
		// ignored or point at one coordinate as though it were the secret.
		if credential.GetString(config, credential.ConfigSecretField, "") != "" {
			return fmt.Errorf("secret_field must be omitted for client_auth=%s; the referenced payload is read by its own field names", clientAuthKMSPrivateKeyJWT)
		}
		// The algorithm is a property of the key, checked against it when the capability
		// is minted. Naming it again here could only ever disagree.
		if credential.GetString(config, "client_assertion_alg", "") != "" {
			return fmt.Errorf("client_assertion_alg must be omitted for client_auth=%s; the algorithm travels with the key in the referenced payload", clientAuthKMSPrivateKeyJWT)
		}
	case clientAuthNone:
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
	for _, key := range append(keys, "client_id") {
		if credential.GetString(config, key, "") != "" {
			return fmt.Errorf("%s must be omitted when secret_spec is set; the referenced spec supplies the whole client credential", key)
		}
	}
	return nil
}

// SensitiveConfigFields returns source config keys that should be masked.
func (f *TokenExchangeDriverFactory) SensitiveConfigFields() []string {
	return []string{"client_secret", "private_key", "ca_data"}
}

// StoredSecrets reports the secret config keys this source holds.
func (f *TokenExchangeDriverFactory) StoredSecrets(config credential.Config) []string {
	return config.Present("client_secret", "private_key")
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
		refusal:    storedIDJAGParamRefusal(config),
	}
	d.warnStoredIDJAGParams()
	return d
}

// storedIDJAGParamRefusal is why an id_jag source cannot mint when it carries a pinned
// token_param.* field, or nil. Only a source stored before the write check existed can
// carry one. Dropping it would change what the IdP is sent without a word, and sending
// it would make the request something other than an ID-JAG request, so the source is
// refused until it is fixed. The first pinned field in idJAGPinnedParams order is named.
func storedIDJAGParamRefusal(cfg credential.Config) error {
	if credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG {
		return nil
	}
	params := credential.GetPrefixed(cfg, "token_param.")
	for _, p := range idJAGPinnedParams {
		if _, ok := params[p.key]; ok {
			return fmt.Errorf("id_jag: %w; remove it from the source", idJAGPinnedParamError(p.key))
		}
	}
	return nil
}

// warnStoredIDJAGParams logs the token_param.* fields a stored id_jag source carries that
// a write would now refuse, each time the driver is built: a pinned one stops every
// mint, and a first-class one is sent only when its config key is empty. The endpoints
// identify the source, whose name the driver is not given.
func (d *TokenExchangeDriver) warnStoredIDJAGParams() {
	cfg := d.credSource.Config
	if d.logger == nil || credential.GetString(cfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantIDJAG {
		return
	}
	params := credential.GetPrefixed(cfg, "token_param.")
	keys := slices.Sorted(maps.Keys(params))
	for _, key := range keys {
		source := []logger.TypedField{
			logger.String("token_param", key),
			logger.String("token_url", credential.GetString(cfg, "token_url", "")),
			logger.String("resource_token_url", credential.GetString(cfg, "resource_token_url", "")),
		}
		if idJAGPinned(key) {
			d.logger.Warn("id_jag source cannot mint: a token_param overrides the ID-JAG request; remove it from the source", source...)
		} else if own, ok := idJAGFirstClassParams[key]; ok {
			d.logger.Warn("id_jag source carries a token_param that is sent only when its config key is empty; set the config key instead",
				append(source, logger.String("config_key", own))...)
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
// downstream bearer token.
func (d *TokenExchangeDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// Client auth comes from source config (client_secret / private_key).
	return d.mintExchange(ctx, spec, inputs, nil)
}

// MintCredentialWithExchangeFromSecret performs the same exchange as
// MintCredentialWithExchange, but its client credential — both halves — comes from
// credential-chaining material (secret_spec) instead of source config. A chained
// source stores neither half, so the id and the secret are read together from the
// fetched payload.
func (d *TokenExchangeDriver) MintCredentialWithExchangeFromSecret(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, material credential.SecretMaterial) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	chained, err := tokenExchangeChainedAuthFromMaterial(d.credSource.Config, material)
	if err != nil {
		return nil, nil, 0, "", err
	}
	return d.mintExchange(ctx, spec, inputs, chained)
}

// tokenExchangeChainedAuthFromMaterial reads a whole client credential out of fetched
// secret material, for the client_auth the source configures. The reading is shared
// with every driver that chains a client credential (chainedClientAuthFromMaterial);
// this names the driver in what it reports.
func tokenExchangeChainedAuthFromMaterial(cfg credential.Config, material credential.SecretMaterial) (*chainedClientAuth, error) {
	auth, err := chainedClientAuthFromMaterial(credential.GetString(cfg, "client_auth", ""), material)
	if err != nil {
		return nil, fmt.Errorf("token_exchange: %w", err)
	}
	return auth, nil
}

// mintExchange runs the exchange for the configured grant. chained, when non-nil,
// supplies the client credential (from credential chaining) in place of source config.
func (d *TokenExchangeDriver) mintExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *chainedClientAuth) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
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
		resp, err = d.mintIDJAG(ctx, spec, inputs, chained)
	} else {
		resp, err = d.exchangeOnce(ctx, spec, inputs, chained)
	}
	if err != nil {
		return nil, nil, 0, "", err
	}
	if resp.AccessToken == "" {
		return nil, nil, 0, "", fmt.Errorf("token_exchange: token response missing access_token")
	}

	return accessTokenRawData(resp), d.subjectMetadata(resp, inputs), exchangedTokenLease(resp.ExpiresIn, d.credSource.Config, spec), "", nil
}

// exchangeOnce performs a single-hop exchange (rfc8693 or jwt_bearer). chained,
// when non-nil, supplies the client credential from credential chaining.
func (d *TokenExchangeDriver) exchangeOnce(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *chainedClientAuth) (*oauth2TokenResponse, error) {
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
	}, sameForm(form), chained)
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

// postWithClientAuth sends the form build makes to call.endpoint, authenticated as the
// client.
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
func (d *TokenExchangeDriver) postWithClientAuth(ctx context.Context, call tokenCall, build func() (url.Values, error), chained *chainedClientAuth) (*oauth2TokenResponse, error) {
	aud := clientAssertionAudience(credential.GetString(d.credSource.Config, "client_assertion_aud", ""), call.endpoint, call.issuer)
	var buildErr error
	resp, err := postOAuthTokenFormFuncReading(ctx, d.httpClient, call.endpoint, func() (url.Values, error) {
		form, err := build()
		if err == nil {
			err = d.applyClientAuth(ctx, form, aud, chained)
		}
		if err != nil {
			buildErr = err
			return nil, err
		}
		return form, nil
	}, d.clientAuthHeaders(chained), call.readable, call.attempts)
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
		if chained != nil && isChainedClientAuthRejection(err) {
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
// carries, and cannot be refused for asking more. Client auth runs on both legs
// (each with its own endpoint as the assertion audience). Only the final access
// token is returned.
//
// Each attempt at leg 2 sends an ID-JAG no attempt has sent before, with the scope
// granted for it. A resource authorization server may accept each ID-JAG only once,
// by its jti, and one whose answer was lost may already have spent it; so a retried
// leg 2 asks the IdP for a new one first. That request is tried once: leg 2's own
// retries already cover a failing IdP, and trying it again inside each of them would
// multiply the calls. A retry the resource authorization server asked for with a 429
// costs a new ID-JAG too, since an attempt cannot tell that answer from a lost one.
func (d *TokenExchangeDriver) mintIDJAG(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *chainedClientAuth) (*oauth2TokenResponse, error) {
	cfg := d.credSource.Config
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
	jag, scope, err := d.requestIDJAG(ctx, leg1, challenge, chained, oauth2MaxRetryAttempts)
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
			fresh, freshScope, err := d.requestIDJAG(ctx, leg1, challenge, chained, 1)
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
	}, chained)
}

// requestIDJAG asks the IdP for an ID-JAG (leg 1) with form, trying at most attempts
// times, and returns it with the scope the IdP granted for it. challenge makes a
// refused subject ask the user to authenticate again.
func (d *TokenExchangeDriver) requestIDJAG(ctx context.Context, form url.Values, challenge bool, chained *chainedClientAuth, attempts int) (string, string, error) {
	cfg := d.credSource.Config
	resp, err := d.postWithClientAuth(ctx, tokenCall{
		endpoint: credential.GetString(cfg, "token_url", ""),
		issuer:   credential.GetString(cfg, "issuer", ""),
		readable: tokenEndpointReadableStatuses,
		attempts: attempts,
		classify: classifyIDJAGRequestError(challenge),
		rejected: "id_jag: the IdP rejected the chained client credential",
	}, sameForm(form), chained)
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
	leg1 := url.Values{}
	leg1.Set("grant_type", grantTypeTokenExchange)
	leg1.Set("subject_token", inputs.SubjectToken)
	leg1.Set("subject_token_type", subjectTokenType(inputs))
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
// request is built (storedIDJAGParamRefusal). A first-class field is added only when its
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

// clientCredential returns the client id and secret this mint authenticates with.
// chained, when non-nil, supplies both from credential chaining in place of config.
//
// Both halves move together: an id from config beside a secret from the chain would
// name one client while presenting another's, which the token endpoint answers with
// invalid_client.
func (d *TokenExchangeDriver) clientCredential(chained *chainedClientAuth) (clientID, clientSecret string) {
	if chained != nil {
		return chained.clientID, chained.secret
	}
	return credential.GetString(d.credSource.Config, "client_id", ""),
		credential.GetString(d.credSource.Config, "client_secret", "")
}

// clientAuthHeaders returns the headers the configured client authentication sends:
// client_secret_basic's Authorization header, and nothing for the other methods. They
// are the same on every attempt, so they are settled once rather than per attempt.
func (d *TokenExchangeDriver) clientAuthHeaders(chained *chainedClientAuth) map[string]string {
	if credential.GetString(d.credSource.Config, "client_auth", clientAuthSecretPost) != clientAuthSecretBasic {
		return nil
	}
	return map[string]string{"Authorization": basicClientAuthHeader(d.clientCredential(chained))}
}

// applyClientAuth decorates the form with the configured client authentication. aud is
// the audience for a private_key_jwt assertion (each ID-JAG leg authenticates against
// its own server). It runs once per attempt, so an assertion is never sent twice;
// client_secret_basic travels in a header instead (see clientAuthHeaders).
func (d *TokenExchangeDriver) applyClientAuth(ctx context.Context, form url.Values, aud string, chained *chainedClientAuth) error {
	cfg := d.credSource.Config
	clientID, clientSecret := d.clientCredential(chained)

	switch credential.GetString(cfg, "client_auth", clientAuthSecretPost) {
	case clientAuthSecretPost, "":
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	case clientAuthSecretBasic:
		// Sent in the Authorization header; nothing goes in the body.
	case clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT:
		// One case for both: the assertion, and everything the endpoint sees, is
		// identical. Only where the signature comes from differs.
		assertion, err := d.buildClientAssertion(ctx, clientID, aud, chained)
		if err != nil {
			return err
		}
		form.Set("client_id", clientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	case clientAuthNone:
		// RFC 6749 §2.3: a public client identifies itself with client_id alone, and only
		// when the endpoint knows it by one.
		if clientID != "" {
			form.Set("client_id", clientID)
		}
	default:
		return fmt.Errorf("token_exchange: unsupported client_auth %q", credential.GetString(cfg, "client_auth", ""))
	}
	return nil
}

// buildClientAssertion builds and signs an RFC 7523 client-assertion JWT: a
// short-lived JWT with iss=sub=client_id and the given aud, signed with the RSA private
// key. chained, when non-nil, supplies the PEM key and its key id from credential
// chaining in place of the source-configured ones; clientID is then the chained id its
// caller already substituted, so the assertion names the client whose key signs it,
// under the key id that key was stored beside.
func (d *TokenExchangeDriver) buildClientAssertion(ctx context.Context, clientID, aud string, chained *chainedClientAuth) (string, error) {
	claims, err := clientAssertionClaims(clientID, aud)
	if err != nil {
		return "", err
	}

	// A chained signing capability signs the very same claims elsewhere. Built here
	// rather than in the remote path so the two methods cannot drift into producing
	// different assertions.
	if chained != nil && chained.kms != nil {
		return d.signAssertionWithCapability(ctx, chained.kms, claims)
	}

	pemKey := credential.GetString(d.credSource.Config, "private_key", "")
	kid := credential.GetString(d.credSource.Config, "client_assertion_kid", "")
	if chained != nil {
		pemKey, kid = chained.secret, chained.kid
	}
	key, err := parseRSAPrivateKey(pemKey)
	if err != nil {
		return "", fmt.Errorf("token_exchange: invalid private_key: %w", err)
	}
	assertion, err := signClientAssertionLocal(key, kid, claims)
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
// recorded.
func (d *TokenExchangeDriver) subjectMetadata(resp *oauth2TokenResponse, inputs *credential.ExchangeInputs) map[string]interface{} {
	meta := map[string]interface{}{}
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
	if inputs.SubjectTokenType != "" {
		return inputs.SubjectTokenType
	}
	return credential.TokenTypeJWT
}

// actorTokenType returns the RFC 8693 actor_token_type, defaulting to jwt.
func actorTokenType(inputs *credential.ExchangeInputs) string {
	if inputs.ActorTokenType != "" {
		return inputs.ActorTokenType
	}
	return credential.TokenTypeJWT
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

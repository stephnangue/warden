package drivers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

// tokenTypeIDJAG is the requested_token_type for an ID-JAG assertion (leg 1 of
// the cross-app-access flow).
const tokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

// TokenExchangeSupportsActor reports whether a token_exchange source's grant has
// an RFC 8693 actor slot. jwt_bearer (an assertion grant) has none — the driver
// rejects any actor there at mint time (see MintCredentialWithExchange) — while
// rfc8693 and id_jag both carry the actor. It lets the config store reject an
// actor spec bound to a jwt_bearer source at create time (single source of truth
// for the grant string, mirroring DeriveAssertionAudience living here).
func TokenExchangeSupportsActor(sourceCfg map[string]string) bool {
	return credential.GetString(sourceCfg, "grant", tokenExchangeGrantRFC8693) != tokenExchangeGrantJWTBearer
}

// Client-authentication methods selected by the source's `client_auth` config.
//
// kms_private_key_jwt puts the same assertion on the wire as private_key_jwt — the
// authorization server cannot tell them apart — but the key is held in a KMS and Warden
// never sees it. It is a separate method rather than a modifier because the two are
// configured from opposite ends: one takes a key, the other takes a reference to a
// capability, and nothing an operator sets for one is meaningful for the other.
const (
	clientAuthSecretBasic      = "client_secret_basic"
	clientAuthSecretPost       = "client_secret_post"
	clientAuthPrivateKeyJWT    = "private_key_jwt"
	clientAuthKMSPrivateKeyJWT = "kms_private_key_jwt"
)

// clientAssertionType is the RFC 7523 client-assertion type for private_key_jwt.
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionTTL bounds the lifetime of a signed client assertion.
const clientAssertionTTL = 5 * time.Minute

// grant_type URNs sent in the token request.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Compile-time interface assertions.
var _ credential.SourceDriver = (*TokenExchangeDriver)(nil)
var _ credential.ExchangeMinter = (*TokenExchangeDriver)(nil)
var _ credential.ChainedExchangeMinter = (*TokenExchangeDriver)(nil)

// tokenExchangeChainedAuth carries the client credential a single mint fetched
// through credential chaining. A nil pointer means the inline source config.
//
// secret is whichever half client_auth calls for: the client secret for
// client_secret_post/basic, or the PEM private key for private_key_jwt. kid is the
// optional key id naming that private key, and is empty for the secret methods. It
// holds fetched values only — never the mode — and is threaded by parameter rather than
// stored on the driver, so concurrent mints resolving different pairs cannot cross.
type tokenExchangeChainedAuth struct {
	clientID string
	secret   string
	kid      string
	// kms is set instead of secret when the referenced spec minted a signing
	// capability rather than a key. The two are mutually exclusive: one carries the
	// key, the other carries permission to use a key it will never see.
	kms *kmsSignerMaterial
}

// kmsSignerMaterial is a signing capability fetched through chaining: which key, which
// version, where it lives, and a token that may sign with it. It holds no key material —
// that absence is the entire point of the method.
type kmsSignerMaterial struct {
	backend    string
	token      string
	address    string
	namespace  string
	mount      string
	keyName    string
	keyVersion int
	alg        string
	kid        string
	// expiresAt is the capability token's expiry, when the producer reported one. It
	// lets a spent capability be recognised without spending a round trip discovering
	// it, and told apart from a broken one.
	expiresAt time.Time
}

// TokenExchangeDriver exchanges a caller-derived identity (a subject token, and
// optionally an actor token) for a scoped downstream bearer at an RFC 8693 / RFC
// 7523 token endpoint. It is exchange-only: it never mints from static source
// config, so plain MintCredential is a defensive error and all issuance flows
// through MintCredentialWithExchange.
type TokenExchangeDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger
	httpClient *http.Client
	// kmsClients pools one token-less base client per signing backend address, cloned
	// per assertion so the capability token never touches a shared client. In practice
	// it holds a single entry.
	kmsClients sync.Map
}

// TokenExchangeDriverFactory creates TokenExchangeDriver instances.
type TokenExchangeDriverFactory struct{}

// Type returns the driver type identifier.
func (f *TokenExchangeDriverFactory) Type() string {
	return credential.SourceTypeTokenExchange
}

// ValidateConfig validates source configuration. VerifySpec never runs for
// exchange specs, so the factory is the place strict validation lives.
func (f *TokenExchangeDriverFactory) ValidateConfig(config map[string]string) error {
	skip := credential.GetBool(config, "tls_skip_verify", false)
	if err := credential.ValidateSchema(config,
		credential.StringField("token_url").
			Required().
			Custom(func(v string) error { return validateOAuth2SafeURL(v, "token_url", skip) }).
			Describe("Token endpoint (HTTPS) of the STS/IdP performing the exchange").
			Example("https://idp.example.com/oauth2/v1/token"),

		credential.StringField("grant").
			OneOf(tokenExchangeGrantRFC8693, tokenExchangeGrantJWTBearer, tokenExchangeGrantIDJAG).
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
			OneOf(clientAuthSecretBasic, clientAuthSecretPost, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT).
			Describe("How Warden authenticates to the token endpoint; kms_private_key_jwt signs the same assertion with a key held in a KMS, reached through secret_spec").
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
	if credential.GetString(config, "grant", tokenExchangeGrantRFC8693) == tokenExchangeGrantIDJAG {
		if credential.GetString(config, "resource_token_url", "") == "" {
			return fmt.Errorf("resource_token_url is required for grant=id_jag")
		}
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
	}
	return nil
}

// rejectInlineClientCredential refuses anything naming a client left in the config of a
// source that fetches its client credential per mint. keys are whatever the chosen
// client_auth calls for; client_id is always checked, since none of the rest are
// meaningful apart from the client they belong to.
func rejectInlineClientCredential(config map[string]string, keys ...string) error {
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

// InferCredentialType returns the credential type for token_exchange sources.
func (f *TokenExchangeDriverFactory) InferCredentialType(_ map[string]string) (string, error) {
	return credential.TypeOAuthBearerToken, nil
}

// Create instantiates a new TokenExchangeDriver.
func (f *TokenExchangeDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	client, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}
	return &TokenExchangeDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeTokenExchange, Config: config},
		logger:     log.WithSubsystem(credential.SourceTypeTokenExchange),
		httpClient: client,
	}, nil
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
// secret material. client_auth decides which half the secret is — a client secret or a
// PEM private key — and so which conventional key names apply.
//
// secret_field names the secret alone, so a field that resolved to nothing is a
// misconfigured source rather than an invitation to look elsewhere: the conventional
// keys are consulted only when no field was resolved at all. The id is read by
// convention for the same reason, and has nowhere to fall back to — a source in
// chaining mode holds no client_id — so its absence is an error raised here, before any
// request is sent.
//
// Every "the payload lacks what I need" error carries ErrChainedSecretIncomplete, so a
// cached payload that predates a key it now has to hold is refetched once rather than
// failing for the rest of its secret_cache_ttl.
func tokenExchangeChainedAuthFromMaterial(cfg map[string]string, material credential.SecretMaterial) (*tokenExchangeChainedAuth, error) {
	// The id is never the secret. A payload holding nothing but an id resolves that
	// lone key as the secret field — the single-key shortcut has no way to know
	// better — and without this the same value would be spent as both halves of the
	// pair, which the endpoint answers with invalid_client and the chained path then
	// misreads as a rotated secret.
	if material.Field == "client_id" {
		return nil, fmt.Errorf("token_exchange: the fetched secret material holds a client id but no secret: %w", credential.ErrChainedSecretIncomplete)
	}

	secret := material.Secret()
	var kid string
	var kms *kmsSignerMaterial

	switch credential.GetString(cfg, "client_auth", clientAuthSecretPost) {
	case clientAuthKMSPrivateKeyJWT:
		// Nothing secret is selected here: the payload is a set of coordinates read by
		// name, so material.Field plays no part. Clear whatever the generic selector
		// picked out — leaving a coordinate sitting in the secret slot would present it
		// as key material to anything that later reads the struct.
		secret = ""
		var err error
		if kms, err = kmsSignerFromMaterial(material); err != nil {
			return nil, err
		}
	case clientAuthSecretPost, clientAuthSecretBasic, "":
		if secret == "" && material.Field == "" {
			secret = material.Data["client_secret"]
		}
		if secret == "" {
			if material.Field != "" {
				return nil, fmt.Errorf("token_exchange: secret_field %q is empty or absent in the fetched secret material: %w", material.Field, credential.ErrChainedSecretIncomplete)
			}
			return nil, fmt.Errorf("token_exchange: no client secret in fetched secret material (set secret_field, or store it under 'client_secret'): %w", credential.ErrChainedSecretIncomplete)
		}
	case clientAuthPrivateKeyJWT:
		if secret == "" && material.Field == "" {
			secret = material.Data["private_key"]
		}
		if secret == "" {
			if material.Field != "" {
				return nil, fmt.Errorf("token_exchange: secret_field %q is empty or absent in the fetched secret material: %w", material.Field, credential.ErrChainedSecretIncomplete)
			}
			return nil, fmt.Errorf("token_exchange: no private key in fetched secret material (set secret_field, or store it under 'private_key'): %w", credential.ErrChainedSecretIncomplete)
		}
		// Optional, and read by convention like the id: an authorization server that
		// resolves the key from the client id alone needs none. When it is present it
		// has to be the one stored beside this key, which is why a chained source is
		// refused an inline client_assertion_kid rather than falling back to it.
		kid = material.Data["client_assertion_kid"]
		if kid == "" {
			kid = material.Data["kid"]
		}
	default:
		// A source-config error, not a payload one: refetching cannot change the answer,
		// so this must not carry the sentinel that asks the manager to try again.
		return nil, fmt.Errorf("token_exchange: credential chaining supports client_auth=%s, %s, %s or %s, got %q",
			clientAuthSecretPost, clientAuthSecretBasic, clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT,
			credential.GetString(cfg, "client_auth", ""))
	}

	clientID := material.Data["client_id"]
	if clientID == "" {
		return nil, fmt.Errorf("token_exchange: no client id in fetched secret material (store it under 'client_id' alongside the secret): %w", credential.ErrChainedSecretIncomplete)
	}

	return &tokenExchangeChainedAuth{clientID: clientID, secret: secret, kid: kid, kms: kms}, nil
}

// kmsSignerFromMaterial reads a signing capability out of the referenced payload. Every
// coordinate is required and read by its own name — the producer writes them all
// together, so any one missing means a payload written by something else, or by an
// older version of the producer.
//
// Those failures carry ErrChainedSecretIncomplete so a cached payload predating a field
// is refetched once, rather than failing every mint for the rest of its cache window.
func kmsSignerFromMaterial(material credential.SecretMaterial) (*kmsSignerMaterial, error) {
	need := func(key string) (string, error) {
		if v := material.Data[key]; v != "" {
			return v, nil
		}
		return "", fmt.Errorf("token_exchange: the fetched signing capability has no %q: %w", key, credential.ErrChainedSecretIncomplete)
	}

	backend, err := need("kms_backend")
	if err != nil {
		return nil, err
	}
	if backend != remotesign.BackendTypeTransit {
		// A backend this build cannot drive. Not a payload-freshness problem — refetching
		// yields the same answer — so it must not ask the manager to retry.
		return nil, fmt.Errorf("token_exchange: unsupported signing backend %q in the fetched capability", backend)
	}

	m := &kmsSignerMaterial{backend: backend, namespace: material.Data["vault_namespace"], kid: material.Data["kid"]}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"vault_token", &m.token},
		{"vault_address", &m.address},
		{"transit_mount", &m.mount},
		{"transit_key", &m.keyName},
		{"signing_alg", &m.alg},
	} {
		if *f.dst, err = need(f.key); err != nil {
			return nil, err
		}
	}

	rawVersion, err := need("transit_key_version")
	if err != nil {
		return nil, err
	}
	// The producer always writes a concrete version, so an unusable one means a stale or
	// foreign payload — something a refetch can fix.
	if m.keyVersion, err = strconv.Atoi(rawVersion); err != nil || m.keyVersion < 1 {
		return nil, fmt.Errorf("token_exchange: the fetched signing capability has an unusable key version %q: %w", rawVersion, credential.ErrChainedSecretIncomplete)
	}

	// Optional: without it the expiry preflight is simply skipped, and a spent
	// capability is discovered by the store refusing to sign with it instead.
	if raw := material.Data["token_expires_at"]; raw != "" {
		if ts, perr := time.Parse(time.RFC3339, raw); perr == nil {
			m.expiresAt = ts
		}
	}
	return m, nil
}

// mintExchange runs the exchange for the configured grant. chained, when non-nil,
// supplies the client credential (from credential chaining) in place of source config.
func (d *TokenExchangeDriver) mintExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *tokenExchangeChainedAuth) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
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

	return accessTokenRawData(resp), d.subjectMetadata(resp, inputs), ttlFromExpiresIn(resp.ExpiresIn), "", nil
}

// exchangeOnce performs a single-hop exchange (rfc8693 or jwt_bearer). chained,
// when non-nil, supplies the client credential from credential chaining.
func (d *TokenExchangeDriver) exchangeOnce(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *tokenExchangeChainedAuth) (*oauth2TokenResponse, error) {
	form, err := d.buildExchangeForm(spec, inputs)
	if err != nil {
		return nil, err
	}
	tokenURL := credential.GetString(d.credSource.Config, "token_url", "")
	headers := map[string]string{}
	if err := d.applyClientAuth(ctx, form, headers, tokenURL, chained); err != nil {
		return nil, err
	}
	resp, err := postOAuthTokenForm(ctx, d.httpClient, tokenURL, form, headers)
	if err != nil {
		return nil, chainedClientAuthError(err, chained != nil)
	}
	return resp, nil
}

// mintIDJAG runs the two-leg ID-JAG cross-app-access flow inside one mint:
//
//	leg 1 → token_url (home IdP): RFC 8693 token-exchange with
//	        requested_token_type=id-jag → an ID-JAG assertion bound to the resource AS
//	leg 2 → resource_token_url (resource AS): RFC 7523 jwt-bearer with the ID-JAG
//	        as the assertion → the downstream access token
//
// Client auth runs on both legs (each with its own endpoint as the assertion
// audience). Only the final access token is returned; the ID-JAG is single-use.
func (d *TokenExchangeDriver) mintIDJAG(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs, chained *tokenExchangeChainedAuth) (*oauth2TokenResponse, error) {
	cfg := d.credSource.Config

	// Leg 1: exchange the subject for an ID-JAG at the home IdP. The ID-JAG must be
	// bound to the resource authorization server via audience.
	idpURL := credential.GetString(cfg, "token_url", "")
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
	// Vendor-specific extras apply to the exchange (leg 1) at the home IdP.
	for k, v := range credential.GetPrefixed(cfg, "token_param.") {
		leg1.Set(k, v)
	}
	h1 := map[string]string{}
	if err := d.applyClientAuth(ctx, leg1, h1, idpURL, chained); err != nil {
		return nil, err
	}
	jag, err := postOAuthTokenForm(ctx, d.httpClient, idpURL, leg1, h1)
	if err != nil {
		return nil, chainedClientAuthError(err, chained != nil)
	}
	if jag.AccessToken == "" {
		return nil, fmt.Errorf("id_jag: leg 1 returned no ID-JAG assertion")
	}
	// If the IdP labels the issued token, confirm it is an ID-JAG before redeeming it.
	if jag.IssuedTokenType != "" && jag.IssuedTokenType != tokenTypeIDJAG {
		return nil, fmt.Errorf("id_jag: leg 1 returned issued_token_type %q, expected %q", jag.IssuedTokenType, tokenTypeIDJAG)
	}

	// Leg 2: redeem the ID-JAG at the resource authorization server.
	resURL := credential.GetString(cfg, "resource_token_url", "")
	leg2 := url.Values{}
	leg2.Set("grant_type", grantTypeJWTBearer)
	leg2.Set("assertion", jag.AccessToken)
	if scope := d.resolve(spec, "scope"); scope != "" {
		leg2.Set("scope", scope)
	}
	// RFC 8707 resource indicators scope the final access token, so they belong on
	// leg 2 (the resource-AS redemption), not leg 1 (which mints the ID-JAG).
	d.addResources(leg2, spec)
	h2 := map[string]string{}
	if err := d.applyClientAuth(ctx, leg2, h2, resURL, chained); err != nil {
		return nil, err
	}
	final, err := postOAuthTokenForm(ctx, d.httpClient, resURL, leg2, h2)
	if err != nil {
		return nil, chainedClientAuthError(err, chained != nil)
	}
	return final, nil
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

// applyClientAuth decorates the request with the configured client
// authentication. tokenEndpoint is the audience for a private_key_jwt assertion
// (each ID-JAG leg authenticates against its own endpoint). chained, when non-nil,
// supplies the whole client credential from credential chaining in place of config.
//
// Both halves move together: an id from config beside a secret from the chain would
// name one client while presenting another's, which the token endpoint answers with
// invalid_client.
func (d *TokenExchangeDriver) applyClientAuth(ctx context.Context, form url.Values, headers map[string]string, tokenEndpoint string, chained *tokenExchangeChainedAuth) error {
	cfg := d.credSource.Config
	clientID := credential.GetString(cfg, "client_id", "")
	clientSecret := credential.GetString(cfg, "client_secret", "")
	if chained != nil {
		clientID = chained.clientID
		clientSecret = chained.secret
	}

	switch credential.GetString(cfg, "client_auth", clientAuthSecretPost) {
	case clientAuthSecretPost, "":
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	case clientAuthSecretBasic:
		// RFC 6749 §2.3.1: client id/secret are form-urlencoded, then Basic-encoded.
		creds := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	case clientAuthPrivateKeyJWT, clientAuthKMSPrivateKeyJWT:
		// One case for both: the assertion, and everything the endpoint sees, is
		// identical. Only where the signature comes from differs.
		assertion, err := d.buildClientAssertion(ctx, clientID, tokenEndpoint, chained)
		if err != nil {
			return err
		}
		form.Set("client_id", clientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	default:
		return fmt.Errorf("token_exchange: unsupported client_auth %q", credential.GetString(cfg, "client_auth", ""))
	}
	return nil
}

// buildClientAssertion builds and signs an RFC 7523 client-assertion JWT: a
// short-lived JWT with iss=sub=client_id and aud=tokenEndpoint, signed with the RSA
// private key. chained, when non-nil, supplies the PEM key and its key id from
// credential chaining in place of the source-configured ones; clientID is then the
// chained id its caller already substituted, so the assertion names the client whose key
// signs it, under the key id that key was stored beside.
func (d *TokenExchangeDriver) buildClientAssertion(ctx context.Context, clientID, tokenEndpoint string, chained *tokenExchangeChainedAuth) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(clientAssertionTTL).Unix(),
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
	header := map[string]string{}
	if kid != "" {
		header["kid"] = kid
	}
	assertion, err := signRS256JWT(key, header, claims)
	if err != nil {
		return "", fmt.Errorf("token_exchange: failed to sign client assertion: %w", err)
	}
	return assertion, nil
}

// addResources appends the source/spec's RFC 8707 resource indicators as repeated
// `resource` form parameters. `resources` is a space-separated list of absolute
// URIs; RFC 8707 §2 allows the parameter to appear multiple times. It is
// grant-agnostic, so it applies to rfc8693, jwt_bearer, and the id_jag legs alike.
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
func tokenExchangeAssertionResource(sourceCfg, specCfg map[string]string) (string, bool) {
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

// resolve returns spec.Config[key] when set, else the source config value.
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

// chainedClientAuthError classifies a token-endpoint failure, but when the client
// credential came from credential chaining (chained) and the endpoint rejected the client
// authentication (invalid_client — 400 for client_secret_post, 401 for
// client_secret_basic, or a rejected private_key_jwt assertion), it wraps
// credential.ErrChainedSecretRejected so the minting layer evicts the cached secret and
// retries once with a fresh fetch. This must run BEFORE classifyExchangeError, whose
// broad 400/401 branch would otherwise mask invalid_client as a subject-token problem.
//
// invalid_client does not say which half was refused, and it does not need to: the
// eviction refetches the payload, so the id and the secret are replaced together.
func chainedClientAuthError(err error, chained bool) error {
	// The rejection test itself is shared with the oauth2 driver
	// (isChainedClientAuthRejection); here it covers client_secret_post's 400,
	// client_secret_basic's 401, and a rejected assertion under either private_key_jwt
	// method. For a KMS-held key that last case is how an authorization server holding
	// only the previous public key recovers: the eviction re-mints the capability, which
	// resolves the current key version. Keep the underlying error (the IdP's code /
	// description) in the chain alongside the sentinel for legible diagnostics.
	if chained && isChainedClientAuthRejection(err) {
		return fmt.Errorf("token_exchange: client authentication rejected: %w (%w)", credential.ErrChainedSecretRejected, err)
	}
	return classifyExchangeError(err)
}

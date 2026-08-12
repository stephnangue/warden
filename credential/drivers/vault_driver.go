package drivers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// vaultAuthMethodApprole and vaultAuthMethodOIDCFederation select how the source
// authenticates to the upstream Vault/OpenBao. approle holds a long-lived secret_id
// (rotatable); oidc_federation holds no secret and authenticates per request by
// exchanging a caller-presented Warden identity assertion at Vault's JWT auth method.
// An empty auth_method means a pre-set/environment token.
const (
	vaultAuthMethodApprole        = "approle"
	vaultAuthMethodOIDCFederation = "oidc_federation"

	// defaultVaultJWTMount is the conventional Vault JWT/OIDC auth mount path used
	// when a federation source does not set jwt_mount.
	defaultVaultJWTMount = "jwt"
)

// Compile-time interface assertions
var _ credential.SourceDriver = (*VaultDriver)(nil)
var _ credential.Rotatable = (*VaultDriver)(nil)
var _ credential.ExchangeMinter = (*VaultDriver)(nil)

// VaultDriver fetches credentials from HashiCorp Vault
// Supports: KV, AWS engine, GCP engine, IBM engine, OAuth2 engine, Vault tokens
type VaultDriver struct {
	vault         *api.Client
	credSource    *credential.CredSource
	logger        *logger.GatedLogger
	httpClient    *http.Client // HTTP client for external API calls (e.g., IBM IAM token exchange)
	tokenExpireAt time.Time    // Tracks when the current token expires
	authMu        sync.Mutex   // Protects tokenExpireAt and authentication
}

// VaultDriverFactory creates VaultDriver instances
type VaultDriverFactory struct{}

// Type returns the driver type
func (f *VaultDriverFactory) Type() string {
	return credential.SourceTypeVault
}

// Create instantiates a new VaultDriver
func (f *VaultDriverFactory) Create(config map[string]string, logger *logger.GatedLogger) (credential.SourceDriver, error) {
	// Parse config values
	vaultAddress := credential.GetString(config, "vault_address", "")
	vaultNamespace := credential.GetString(config, "vault_namespace", "")
	authMethod := credential.GetString(config, "auth_method", "")

	apiCfg := api.DefaultConfig()
	apiCfg.Address = vaultAddress

	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set namespace if provided
	if vaultNamespace != "" {
		apiClient.SetNamespace(vaultNamespace)
	}

	// Authenticate if auth_method is provided
	credSource := &credential.CredSource{
		Type:   credential.SourceTypeVault,
		Config: config,
	}

	// HTTP client for external API calls (e.g., IBM IAM token exchange for dynamic_ibm).
	// Honors ca_data/tls_skip_verify from the source config so custom CAs work.
	httpClient, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	driver := &VaultDriver{
		vault:      apiClient,
		credSource: credSource,
		logger:     logger.WithSubsystem(credential.SourceTypeVault),
		httpClient: httpClient,
	}

	// Perform initial authentication
	if authMethod != "" {
		if err := driver.authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("Vault authentication failed: %w", err)
		}
	}

	// Verify the AppRole role exists in Vault
	if authMethod == "approle" {
		roleName := credential.GetString(config, "role_name", "")
		approleMount := credential.GetString(config, "approle_mount", "")
		if roleName != "" && approleMount != "" {
			rolePath := fmt.Sprintf("auth/%s/role/%s", approleMount, roleName)
			secret, err := apiClient.Logical().ReadWithContext(context.Background(), rolePath)
			if err != nil {
				return nil, fmt.Errorf("failed to verify AppRole role '%s': %w", roleName, err)
			}
			if secret == nil || secret.Data == nil {
				return nil, fmt.Errorf("AppRole role '%s' does not exist at path '%s'", roleName, rolePath)
			}
		}
	}

	return driver, nil
}

// ValidateConfig validates Vault driver configuration using declarative schema
func (f *VaultDriverFactory) ValidateConfig(config map[string]string) error {
	// Validate vault_address with custom URL validation
	if err := credential.ValidateSchema(config,
		credential.StringField("vault_address").
			Required().
			Custom(validateVaultAddress).
			Describe("Vault server address").
			Example("https://vault.example.com"),
	); err != nil {
		return err
	}

	// Validate auth_method if provided
	authMethod := credential.GetString(config, "auth_method", "")
	if authMethod != "" {
		if err := credential.ValidateSchema(config,
			credential.StringField("auth_method").
				OneOf(vaultAuthMethodApprole, vaultAuthMethodOIDCFederation).
				Describe("Authentication method: 'approle' (secret_id) or 'oidc_federation' (keyless JWT auth)").
				Example(vaultAuthMethodApprole),
		); err != nil {
			return err
		}

		switch authMethod {
		case vaultAuthMethodApprole:
			// AppRole requires the login + rotation fields.
			if err := credential.ValidateSchema(config,
				credential.StringField("role_id").
					Required().
					Describe("AppRole role ID").
					Example("role-id-uuid"),

				credential.StringField("secret_id").
					Required().
					Describe("AppRole secret ID").
					Example("secret-id-uuid"),

				credential.StringField("approle_mount").
					Required().
					Describe("AppRole auth mount path").
					Example("approle"),

				credential.StringField("role_name").
					Required().
					Describe("AppRole role name for rotation").
					Example("warden-source-role"),
			); err != nil {
				return err
			}
			// Reject keyless-federation config on an approle source so a
			// misconfiguration cannot silently mix modes.
			for _, k := range []string{"jwt_role", "jwt_mount", "audience"} {
				if config[k] != "" {
					return fmt.Errorf("field '%s' is only valid for auth_method=%s", k, vaultAuthMethodOIDCFederation)
				}
			}

		case vaultAuthMethodOIDCFederation:
			// Keyless: the source holds no secret and authenticates per request by
			// exchanging a Warden identity assertion at Vault's JWT auth method.
			if err := credential.ValidateSchema(config,
				credential.StringField("jwt_role").
					Required().
					Describe("Vault JWT-auth role name the assertion logs in as").
					Example("warden-agents"),

				credential.StringField("jwt_mount").
					Describe("Vault JWT/OIDC auth mount path (default 'jwt')").
					Example("jwt"),

				credential.StringField("audience").
					Describe("Assertion audience; must equal the Vault role's bound_audiences").
					Example("https://vault.example.com/warden"),
			); err != nil {
				return err
			}
			// Reject approle/token secrets on a keyless source (symmetric guard).
			for _, k := range []string{"role_id", "secret_id", "secret_id_accessor", "approle_mount", "role_name", "token"} {
				if config[k] != "" {
					return fmt.Errorf("field '%s' must not be set for auth_method=%s", k, vaultAuthMethodOIDCFederation)
				}
			}
		}
	}

	return nil
}

// validateVaultAddress validates that the vault_address is a well-formed URL
func validateVaultAddress(addr string) error {
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid vault_address: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("vault_address must use http:// or https:// scheme, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("vault_address must include a host")
	}

	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *VaultDriverFactory) SensitiveConfigFields() []string {
	return []string{"token", "secret_id", "secret_id_accessor"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *VaultDriverFactory) InferCredentialType(specConfig map[string]string) (string, error) {
	mintMethod := specConfig["mint_method"]
	switch mintMethod {
	case "static_aws", "dynamic_aws":
		return credential.TypeAWSAccessKeys, nil
	case "static_apikey":
		return credential.TypeAPIKey, nil
	case "kv2_read":
		return credential.TypeKeyValue, nil
	case "dynamic_gcp":
		return credential.TypeGCPAccessToken, nil
	case "dynamic_ibm":
		return credential.TypeIBMCloudKeys, nil
	case "oauth2":
		return credential.TypeOAuthBearerToken, nil
	case "vault_token", "":
		return credential.TypeVaultToken, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// getAuthMethod returns the source's configured auth_method ("" for a pre-set token).
func (d *VaultDriver) getAuthMethod() string {
	return credential.GetString(d.credSource.Config, "auth_method", "")
}

// authenticate performs Vault authentication only if needed (thread-safe)
func (d *VaultDriver) authenticate(ctx context.Context) error {
	switch d.getAuthMethod() {
	case vaultAuthMethodApprole:
		d.authMu.Lock()
		defer d.authMu.Unlock()

		// Check if token is still valid (not expired and actually works)
		if time.Now().Add(30 * time.Second).Before(d.tokenExpireAt) {
			// Token not expired, but verify it's still valid with Vault
			if d.isTokenValid(ctx) {
				return nil
			}
		}
		return d.loginViaApprole(ctx)
	case vaultAuthMethodOIDCFederation:
		// Keyless: there is no shared source session to establish. Each request
		// logs in with its own caller assertion via MintCredentialWithExchange, so
		// the driver-level authenticate is a no-op.
		return nil
	case "":
		// No auth method, assume token is already set
		return nil
	default:
		return fmt.Errorf("unsupported auth method: %s", d.getAuthMethod())
	}
}

// isTokenValid checks if the current token is still valid with Vault
func (d *VaultDriver) isTokenValid(ctx context.Context) bool {
	// Use token lookup-self as a lightweight validation
	_, err := d.vault.Auth().Token().LookupSelfWithContext(ctx)
	return err == nil
}

// loginViaApprole authenticates to Vault using AppRole
func (d *VaultDriver) loginViaApprole(ctx context.Context) error {
	roleID := credential.GetString(d.credSource.Config, "role_id", "")
	secretID := credential.GetString(d.credSource.Config, "secret_id", "")
	approleMount := credential.GetString(d.credSource.Config, "approle_mount", "")

	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	path := fmt.Sprintf("auth/%s/login", approleMount)

	secret, err := d.vault.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return fmt.Errorf("AppRole login failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no auth info returned from AppRole login")
	}

	d.vault.SetToken(secret.Auth.ClientToken)

	// Track token expiration time
	if secret.Auth.LeaseDuration > 0 {
		d.tokenExpireAt = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	} else {
		// If no lease duration, assume 1 hour default
		d.tokenExpireAt = time.Now().Add(1 * time.Hour)
	}

	if d.logger != nil {
		d.logger.Trace("authenticated to Vault via AppRole",
			logger.String("approle_mount", approleMount),
			logger.String("token_expires_at", d.tokenExpireAt.Format(time.RFC3339)),
		)
	}

	return nil
}

// MintCredential mints credential using Hashicorp Vault based on mint_method
func (d *VaultDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	// A keyless federation source has no shared session and mints only by exchanging
	// a caller assertion — fail closed here (before authenticate) so it surfaces the
	// real reason rather than a generic "unsupported auth method".
	if d.getAuthMethod() == vaultAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("vault: source uses auth_method=%s; the spec must set subject_token_source (e.g. %s or auth_token) to mint over the exchange path", vaultAuthMethodOIDCFederation, credential.SourceWardenIdentity)
	}

	// Re-authenticate if needed
	if err := d.authenticate(ctx); err != nil {
		return nil, nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "static_aws", "static_apikey", "kv2_read":
		// Non-federation path carries no user context; a templated secret_path here
		// fails closed in resolveSecretPath (no claims to satisfy {{user.…}}).
		return d.fetchStaticKVSecret(ctx, d.vault, spec, nil)
	case "dynamic_aws":
		return d.fetchDynamicAWSCreds(ctx, d.vault, spec)
	case "dynamic_gcp":
		return d.fetchDynamicGCPCreds(ctx, d.vault, spec)
	case "dynamic_ibm":
		return d.fetchDynamicIBMCreds(ctx, d.vault, spec)
	case "vault_token":
		return d.fetchDynamicVaultToken(ctx, d.vault, spec)
	case "oauth2":
		return d.fetchOAuth2Creds(ctx, d.vault, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for Vault driver; supported: 'static_aws', 'static_apikey', 'kv2_read', 'dynamic_aws', 'dynamic_gcp', 'dynamic_ibm', 'vault_token', 'oauth2'", mintMethod)
	}
}

// MintCredentialWithExchange mints a credential over Workload Identity Federation by
// exchanging the caller's verified Warden identity assertion at Vault's JWT auth
// method for a per-request, per-identity Vault token, then vending either that token
// (mint_method=vault_token) or a downstream secret brokered with it.
//
// Every path returns an EMPTY leaseID: a keyless source holds no session with
// authority over the login token's leases, so credentials expire by TTL, and a
// dynamic lease — a child of the login token — is revoked by Vault when that token
// expires. For dynamic engines the vended TTL is therefore capped to the login
// token's remaining lifetime.
//
// Batch and service login tokens are both supported: a batch token cannot be revoked
// but Vault constrains any lease it creates to expire no later than the token itself,
// so the TTL cap still bounds the credential; the static-path login-token cleanup is
// simply skipped for a batch token (see revokeLoginToken).
func (d *VaultDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if d.getAuthMethod() != vaultAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("vault: workload identity federation requires auth_method=%s on the source", vaultAuthMethodOIDCFederation)
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("vault: no subject token in exchange inputs")
	}
	if inputs.SubjectTokenOrigin != credential.ExchangeOriginVerified {
		return nil, nil, 0, "", fmt.Errorf("vault: workload identity federation requires a verified subject (subject_token_source=%s or auth_token); a caller-supplied, unverified subject is rejected", credential.SourceWardenIdentity)
	}

	// Exchange the assertion for a per-request Vault token on an isolated client.
	client, loginAuth, err := d.loginViaJWT(ctx, spec, inputs.SubjectToken)
	if err != nil {
		return nil, nil, 0, "", err
	}
	loginTTL := time.Duration(loginAuth.LeaseDuration) * time.Second

	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	// The JWT-login token itself is the credential — never revoke it here.
	if mintMethod == "vault_token" {
		if loginTTL <= 0 {
			// A role that issues a no-expiry token: give the cache/lease layer a
			// positive lifetime rather than a zero (which would read as "static").
			loginTTL = 1 * time.Hour
		}
		// The token's real validity is fixed by the Vault role, but the lease/cache
		// lifetime must not exceed the spec's MaxTTL (mirrors the GCP federated path).
		if spec.MaxTTL > 0 && loginTTL > spec.MaxTTL {
			loginTTL = spec.MaxTTL
		}
		rawData := map[string]interface{}{
			"token":        loginAuth.ClientToken,
			"client_token": loginAuth.ClientToken,
			"accessor":     loginAuth.Accessor,
			"policies":     loginAuth.Policies,
			"renewable":    loginAuth.Renewable,
		}
		metadata := map[string]interface{}{"role": d.effectiveJWTRole(spec)}
		if loginAuth.EntityID != "" {
			metadata["subject"] = loginAuth.EntityID
		}
		if d.logger != nil {
			d.logger.Debug("minted federated Vault token",
				logger.String("spec", spec.Name),
				logger.String("jwt_role", d.effectiveJWTRole(spec)),
				logger.String("accessor", loginAuth.Accessor),
				logger.String("ttl", loginTTL.String()),
			)
		}
		return rawData, metadata, loginTTL, "", nil
	}

	// Downstream engines: broker with the per-request login token.
	var (
		rawData  map[string]interface{}
		metadata map[string]interface{}
		leaseTTL time.Duration
	)
	switch mintMethod {
	case "static_aws", "static_apikey", "kv2_read":
		rawData, metadata, leaseTTL, _, err = d.fetchStaticKVSecret(ctx, client, spec, inputs.UserClaims)
		// A static read holds no lease that depends on the login token — best-effort
		// revoke it so a transient session is not left behind.
		defer d.revokeLoginToken(loginAuth.Accessor, client)
	case "dynamic_aws":
		rawData, metadata, leaseTTL, _, err = d.fetchDynamicAWSCreds(ctx, client, spec)
	case "dynamic_gcp":
		rawData, metadata, leaseTTL, _, err = d.fetchDynamicGCPCreds(ctx, client, spec)
	case "dynamic_ibm":
		rawData, metadata, leaseTTL, _, err = d.fetchDynamicIBMCreds(ctx, client, spec)
	case "oauth2":
		rawData, metadata, leaseTTL, _, err = d.fetchOAuth2Creds(ctx, client, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("vault: mint_method %q is not supported over auth_method=%s (supported: vault_token, static_aws, static_apikey, kv2_read, dynamic_aws, dynamic_gcp, dynamic_ibm, oauth2)", mintMethod, vaultAuthMethodOIDCFederation)
	}
	if err != nil {
		return nil, nil, 0, "", err
	}

	// Cap a dynamic lease to the login token's remaining lifetime (a child lease
	// cannot outlive its parent). A static read returns leaseTTL=0 (no lease); leave
	// it untouched so the fetched secret is not turned into a short-lived one.
	if leaseTTL > 0 && loginTTL > 0 && loginTTL < leaseTTL {
		leaseTTL = loginTTL
	}
	// Never serve a credential (or cache entry) beyond the spec's MaxTTL.
	if leaseTTL > 0 && spec.MaxTTL > 0 && leaseTTL > spec.MaxTTL {
		leaseTTL = spec.MaxTTL
	}
	return rawData, metadata, leaseTTL, "", nil
}

// effectiveJWTRole returns the JWT-auth role for this mint: a per-spec jwt_role
// override falls back to the source's jwt_role.
func (d *VaultDriver) effectiveJWTRole(spec *credential.CredSpec) string {
	if r := credential.GetString(spec.Config, "jwt_role", ""); r != "" {
		return r
	}
	return credential.GetString(d.credSource.Config, "jwt_role", "")
}

// loginViaJWT builds a per-request, token-isolated Vault client and logs in at the
// source's JWT auth mount with the caller assertion, returning the client (with the
// login token set) and the login auth info.
func (d *VaultDriver) loginViaJWT(ctx context.Context, spec *credential.CredSpec, assertion string) (*api.Client, *api.SecretAuth, error) {
	// CloneWithHeaders reuses the shared transport (connection pooling) and copies the
	// namespace header, but gives an independent token field so the per-request
	// identity never mutates d.vault. SetToken("") drops any env-inherited VAULT_TOKEN
	// so it is not sent on the login request.
	client, err := d.vault.CloneWithHeaders()
	if err != nil {
		return nil, nil, fmt.Errorf("vault: failed to clone client for JWT login: %w", err)
	}
	client.SetToken("")

	jwtRole := d.effectiveJWTRole(spec)
	if jwtRole == "" {
		return nil, nil, fmt.Errorf("vault: jwt_role is required for auth_method=%s", vaultAuthMethodOIDCFederation)
	}
	jwtMount := credential.GetString(d.credSource.Config, "jwt_mount", defaultVaultJWTMount)

	path := fmt.Sprintf("auth/%s/login", jwtMount)
	secret, err := client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role": jwtRole,
		"jwt":  assertion,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("vault: JWT login failed at mount %q role %q: %w", jwtMount, jwtRole, err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, nil, fmt.Errorf("vault: no auth info returned from JWT login at mount %q", jwtMount)
	}
	client.SetToken(secret.Auth.ClientToken)
	return client, secret.Auth, nil
}

// isBatchToken reports whether a Vault token is a batch token (by prefix). Batch
// tokens cannot be revoked (Vault rejects it) and expire on their own; any lease they
// create is constrained by Vault to expire no later than the token itself. So there is
// nothing to revoke and no cleanup to attempt.
func isBatchToken(token string) bool {
	return strings.HasPrefix(token, consts.BatchTokenPrefix) ||
		strings.HasPrefix(token, consts.LegacyBatchTokenPrefix)
}

// revokeLoginToken best-effort revokes the per-request JWT-login token that `client`
// holds, used after a static read that created no lease depending on it. It uses
// revoke-self (which the default policy always grants — revoke-accessor would need an
// extra grant the login token normally lacks) on its own short timeout and a fresh
// context so it fires even if the caller's context is done; failures are logged only.
// accessor is passed for logging only.
func (d *VaultDriver) revokeLoginToken(accessor string, client *api.Client) {
	// A batch-token login cannot be revoked (Vault would reject it) and self-expires,
	// so skip the guaranteed-failing call rather than log a warning on every read.
	if isBatchToken(client.Token()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil && d.logger != nil {
		d.logger.Warn("failed to revoke federated JWT-login token after static read",
			logger.String("accessor", truncateID(accessor, 8)),
			logger.Err(err),
		)
	}
}

// userClaimTemplate matches a {{user.<claim>}} token in secret_path. The claim
// name is a conservative identifier (letters, digits, '_', '.', '-').
var userClaimTemplate = regexp.MustCompile(`\{\{user\.([A-Za-z0-9_.-]+)\}\}`)

// userClaimValuePattern is the strict allow-list a substituted claim value must
// match before it can be placed into a KV path segment. It excludes '/' (which
// would let one value span segments) and every other separator. '.' is allowed
// (e.g. first.last), so a value or adjacent values could still compose a "."/".."
// segment — that is caught after substitution by the segment check below, not here.
var userClaimValuePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)

// resolveSecretPath returns the KV secret path for a kv2_read, substituting any
// {{user.<claim>}} token from the projected per-user claims. A path with no such
// token is returned verbatim (byte-identical to the pre-templating behaviour). It
// FAILS CLOSED when a referenced claim is absent (project it via
// assertion_user_claims), when a value is empty or not in the strict allow-list,
// or when the RESOLVED path contains a "." / ".." segment or a leftover template
// fragment. The last check is the real boundary: the Vault API client runs
// path.Clean on the request path, so a claim value of "." (which collapses its
// segment) or two adjacent tokens composing ".." would otherwise silently retarget
// the read at a shared/parent path — the per-user secret_path must deny instead.
func resolveSecretPath(rawPath string, userClaims map[string]string) (string, error) {
	if !strings.Contains(rawPath, "{{user.") {
		return rawPath, nil
	}
	var subErr error
	resolved := userClaimTemplate.ReplaceAllStringFunc(rawPath, func(match string) string {
		claim := userClaimTemplate.FindStringSubmatch(match)[1]
		v, ok := userClaims[claim]
		if !ok {
			subErr = fmt.Errorf("secret_path references {{user.%s}} but that claim is absent (project it via assertion_user_claims)", claim)
			return ""
		}
		// The value becomes path bytes: a single non-empty allow-listed token that
		// cannot span segments (no '/'). Dot-only / traversal segments it might
		// compose are rejected after substitution.
		if v == "" || !userClaimValuePattern.MatchString(v) {
			subErr = fmt.Errorf("secret_path claim %q has a value rejected by the path allow-list", claim)
			return ""
		}
		return v
	})
	if subErr != nil {
		return "", subErr
	}
	// A leftover fragment means a malformed token (e.g. a missing brace or an empty
	// claim name) — fail closed rather than read a literal "{{user.…" path.
	if strings.Contains(resolved, "{{user.") {
		return "", fmt.Errorf("secret_path has an unresolved template fragment after substitution")
	}
	// Reject any "." or ".." segment the substituted value(s) may have composed —
	// path.Clean would otherwise resolve it into a different (shared/parent) path.
	for _, seg := range strings.Split(resolved, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("secret_path resolves to a %q path segment (traversal)", seg)
		}
	}
	return resolved, nil
}

// fetchStaticKVSecret fetches static secrets from Vault KV v2. userClaims, when
// non-nil (a per-user chained mint), supplies the values for any {{user.<claim>}}
// token in secret_path so the read is scoped to one user's secret.
func (d *VaultDriver) fetchStaticKVSecret(ctx context.Context, client *api.Client, spec *credential.CredSpec, userClaims map[string]string) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	kv2Mount := credential.GetString(spec.Config, "kv2_mount", "")
	rawPath := credential.GetString(spec.Config, "secret_path", "")

	if kv2Mount == "" || rawPath == "" {
		return nil, nil, 0, "", fmt.Errorf("kv2_mount and secret_path are required for static KV credentials")
	}

	secretPath, err := resolveSecretPath(rawPath, userClaims)
	if err != nil {
		return nil, nil, 0, "", err
	}

	secret, err := client.KVv2(kv2Mount).Get(ctx, secretPath)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to read KV secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, 0, "", fmt.Errorf("no secret found at path '%s' on mount '%s'", secretPath, kv2Mount)
	}

	if d.logger != nil {
		d.logger.Trace("fetched static secret from Vault KV",
			logger.String("spec", spec.Name),
			logger.String("mount", kv2Mount),
			logger.String("path", secretPath),
		)
	}

	// Return raw data (static, no lease)
	return secret.Data, nil, 0, "", nil
}

// fetchDynamicAWSCreds fetches dynamic AWS credentials from Vault AWS engine
func (d *VaultDriver) fetchDynamicAWSCreds(ctx context.Context, client *api.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	awsMount := credential.GetString(spec.Config, "aws_mount", "")
	roleName := credential.GetString(spec.Config, "role_name", "")

	if awsMount == "" || roleName == "" {
		return nil, nil, 0, "", fmt.Errorf("aws_mount and role_name are required for dynamic AWS credentials")
	}

	// Build request path and data
	path := fmt.Sprintf("%s/creds/%s", awsMount, roleName)
	data := make(map[string]interface{})

	// Add optional parameters
	roleArn := credential.GetString(spec.Config, "role_arn", "")
	if roleArn != "" {
		data["role_arn"] = roleArn
	}
	roleSessionName := credential.GetString(spec.Config, "role_session_name", "")
	if roleSessionName != "" {
		data["role_session_name"] = roleSessionName
	}
	ttl := credential.GetString(spec.Config, "ttl", "")
	if ttl != "" {
		// Parse and validate TTL against min/max bounds
		parsedTTL, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}

		// Validate TTL against spec bounds
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", parsedTTL, spec.MinTTL)
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", parsedTTL, spec.MaxTTL)
		}

		data["ttl"] = parsedTTL.String()
	}

	var secret *api.Secret
	var err error

	if len(data) > 0 {
		// POST request with parameters
		secret, err = client.Logical().WriteWithContext(ctx, path, data)
	} else {
		// GET request without parameters
		secret, err = client.Logical().ReadWithContext(ctx, path)
	}

	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to generate AWS credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, 0, "", fmt.Errorf("no credentials returned for role '%s' on mount '%s'", roleName, awsMount)
	}

	leaseTTL := time.Duration(secret.LeaseDuration) * time.Second

	// Validate lease TTL is positive
	if leaseTTL <= 0 {
		return nil, nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for AWS credentials on mount '%s'", awsMount)
	}

	// Add credential source
	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}
	rawData["cred_source"] = client.Address()

	if d.logger != nil {
		d.logger.Debug("generated dynamic AWS credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", awsMount),
			logger.String("vault_role", roleName),
			logger.String("lease_id", secret.LeaseID),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, nil, leaseTTL, secret.LeaseID, nil
}

// fetchDynamicGCPCreds fetches dynamic GCP credentials from Vault GCP secret engine
func (d *VaultDriver) fetchDynamicGCPCreds(ctx context.Context, client *api.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	gcpMount := credential.GetString(spec.Config, "gcp_mount", "")
	roleName := credential.GetString(spec.Config, "role_name", "")

	if gcpMount == "" || roleName == "" {
		return nil, nil, 0, "", fmt.Errorf("gcp_mount and role_name are required for dynamic GCP credentials")
	}

	// Build path based on role_type (roleset or static-account)
	roleType := credential.GetString(spec.Config, "role_type", "roleset")
	var path string
	switch roleType {
	case "roleset":
		path = fmt.Sprintf("%s/roleset/%s/token", gcpMount, roleName)
	case "static-account":
		path = fmt.Sprintf("%s/static-account/%s/token", gcpMount, roleName)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported role_type '%s'; use 'roleset' or 'static-account'", roleType)
	}

	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to generate GCP credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, 0, "", fmt.Errorf("no credentials returned for role '%s' on mount '%s'", roleName, gcpMount)
	}

	leaseTTL := time.Duration(secret.LeaseDuration) * time.Second

	// GCP tokens may have zero lease duration; use token_ttl from response if available
	if leaseTTL <= 0 {
		if ttlStr, ok := secret.Data["token_ttl"].(string); ok && ttlStr != "" {
			if parsed, err := time.ParseDuration(ttlStr); err == nil {
				leaseTTL = parsed
			}
		}
		// Default to 1 hour if still zero (GCP access tokens expire in ~1h)
		if leaseTTL <= 0 {
			leaseTTL = 1 * time.Hour
		}
	}

	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}

	if d.logger != nil {
		d.logger.Debug("generated dynamic GCP credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", gcpMount),
			logger.String("vault_role", roleName),
			logger.String("role_type", roleType),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, nil, leaseTTL, secret.LeaseID, nil
}

// fetchOAuth2Creds fetches OAuth2 credentials from an OpenBao/Vault OAuth2 secret engine
// (compatible with openbao-plugin-secrets-oauthapp)
func (d *VaultDriver) fetchOAuth2Creds(ctx context.Context, client *api.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	oauth2Mount := credential.GetString(spec.Config, "oauth2_mount", "")
	credentialName := credential.GetString(spec.Config, "credential_name", "")

	if oauth2Mount == "" || credentialName == "" {
		return nil, nil, 0, "", fmt.Errorf("oauth2_mount and credential_name are required for oauth2 credentials")
	}

	path := fmt.Sprintf("%s/creds/%s", oauth2Mount, credentialName)
	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to fetch OAuth2 credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, 0, "", fmt.Errorf("no credentials returned for '%s' on mount '%s'", credentialName, oauth2Mount)
	}

	// Compute TTL from expire_time if available (RFC3339 timestamp from oauthapp plugin)
	leaseTTL := time.Duration(secret.LeaseDuration) * time.Second
	if expireTime, ok := secret.Data["expire_time"].(string); ok && expireTime != "" {
		if parsed, err := time.Parse(time.RFC3339, expireTime); err == nil {
			remaining := time.Until(parsed)
			if remaining > 0 {
				leaseTTL = remaining
			}
		}
	}

	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}

	if d.logger != nil {
		d.logger.Debug("fetched OAuth2 credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", oauth2Mount),
			logger.String("credential_name", credentialName),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, nil, leaseTTL, secret.LeaseID, nil
}

// fetchDynamicIBMCreds fetches dynamic IBM Cloud credentials from Vault IBM secrets engine,
// exchanges the API key for an IAM bearer token, and optionally includes COS HMAC keys.
func (d *VaultDriver) fetchDynamicIBMCreds(ctx context.Context, client *api.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	ibmMount := credential.GetString(spec.Config, "ibm_mount", "")
	roleName := credential.GetString(spec.Config, "role_name", "")

	if ibmMount == "" || roleName == "" {
		return nil, nil, 0, "", fmt.Errorf("ibm_mount and role_name are required for dynamic IBM credentials")
	}

	// Step 1: Fetch dynamic API key from Vault IBM secrets engine
	path := fmt.Sprintf("%s/creds/%s", ibmMount, roleName)

	data := make(map[string]interface{})
	ttl := credential.GetString(spec.Config, "ttl", "")
	if ttl != "" {
		parsedTTL, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", parsedTTL, spec.MinTTL)
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", parsedTTL, spec.MaxTTL)
		}
		data["ttl"] = parsedTTL.String()
	}

	var secret *api.Secret
	var err error
	if len(data) > 0 {
		secret, err = client.Logical().WriteWithContext(ctx, path, data)
	} else {
		secret, err = client.Logical().ReadWithContext(ctx, path)
	}
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to generate IBM credentials from Vault: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil, 0, "", fmt.Errorf("no credentials returned for role '%s' on mount '%s'", roleName, ibmMount)
	}

	// Extract API key from Vault response
	apiKey, _ := secret.Data["api_key"].(string)
	if apiKey == "" {
		return nil, nil, 0, "", fmt.Errorf("Vault IBM engine did not return an api_key for role '%s'", roleName)
	}

	vaultLeaseTTL := time.Duration(secret.LeaseDuration) * time.Second

	// Step 2: Exchange API key for IAM bearer token.
	// If this fails, revoke the Vault lease to avoid leaking a dynamic API key
	// that Warden can't use. Use a fresh context for revocation so it still fires
	// if the caller's context is already canceled.
	iamEndpoint := credential.GetString(spec.Config, "iam_endpoint", defaultIBMIAMEndpoint)
	accessToken, tokenExpiry, err := exchangeIBMAPIKeyForIAMToken(ctx, d.httpClient, apiKey, iamEndpoint)
	if err != nil {
		if secret.LeaseID != "" {
			revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if revokeErr := client.Sys().RevokeWithContext(revokeCtx, secret.LeaseID); revokeErr != nil && d.logger != nil {
				d.logger.Warn("failed to revoke orphaned Vault lease after IAM token exchange failure",
					logger.String("lease_id", secret.LeaseID),
					logger.Err(revokeErr),
				)
			}
			cancel()
		}
		return nil, nil, 0, "", fmt.Errorf("failed to exchange IBM API key for IAM token: %w", err)
	}

	// Step 3: Build result with IAM token
	rawData := map[string]interface{}{
		"access_token": accessToken,
	}

	// Add optional COS HMAC keys from spec config
	accessKeyID := credential.GetString(spec.Config, "access_key_id", "")
	secretAccessKey := credential.GetString(spec.Config, "secret_access_key", "")
	if accessKeyID != "" && secretAccessKey != "" {
		rawData["access_key_id"] = accessKeyID
		rawData["secret_access_key"] = secretAccessKey
	}

	// Step 4: Compute TTL as min(vault_lease, iam_token_expiry)
	iamTTL := time.Until(tokenExpiry)
	leaseTTL := vaultLeaseTTL
	if leaseTTL <= 0 || (iamTTL > 0 && iamTTL < leaseTTL) {
		leaseTTL = iamTTL
	}
	if leaseTTL <= 0 {
		return nil, nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for IBM credentials on mount '%s'", ibmMount)
	}

	if d.logger != nil {
		hasCOS := accessKeyID != "" && secretAccessKey != ""
		d.logger.Debug("generated dynamic IBM credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", ibmMount),
			logger.String("vault_role", roleName),
			logger.String("lease_id", secret.LeaseID),
			logger.String("lease_ttl", leaseTTL.String()),
			logger.Bool("has_cos", hasCOS),
		)
	}

	return rawData, nil, leaseTTL, secret.LeaseID, nil
}

// fetchDynamicVaultToken generates a Vault token via auth/token/create/{role}
func (d *VaultDriver) fetchDynamicVaultToken(ctx context.Context, client *api.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	tokenRole := credential.GetString(spec.Config, "token_role", "")

	if tokenRole == "" {
		return nil, nil, 0, "", fmt.Errorf("token_role is required for dynamic Vault token generation")
	}

	// Build request path
	path := fmt.Sprintf("auth/token/create/%s", tokenRole)

	// Build request data with optional parameters
	data := make(map[string]interface{})

	// Add optional TTL
	ttl := credential.GetString(spec.Config, "ttl", "")
	if ttl != "" {
		parsedTTL, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}

		// Validate TTL against spec bounds
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", parsedTTL, spec.MinTTL)
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			return nil, nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", parsedTTL, spec.MaxTTL)
		}

		data["ttl"] = parsedTTL.String()
	}

	// Add optional display name
	displayName := credential.GetString(spec.Config, "display_name", "")
	if displayName != "" {
		data["display_name"] = displayName
	}

	// Add optional metadata
	meta := credential.GetString(spec.Config, "meta", "")
	if meta != "" {
		data["meta"] = meta
	}

	// Create the token
	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to create Vault token: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, nil, 0, "", fmt.Errorf("no token returned for role '%s'", tokenRole)
	}

	// Extract token TTL from auth response
	leaseTTL := time.Duration(secret.Auth.LeaseDuration) * time.Second

	// Validate lease TTL is positive
	if leaseTTL <= 0 {
		return nil, nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for token role '%s'", tokenRole)
	}

	// Build raw data with token
	rawData := map[string]interface{}{
		"token":        secret.Auth.ClientToken,
		"client_token": secret.Auth.ClientToken, // Alternative field name
		"accessor":     secret.Auth.Accessor,
		"policies":     secret.Auth.Policies,
		"renewable":    secret.Auth.Renewable,
	}

	// Non-secret subject identity for clear audit logging: the token role it was
	// minted from and the Vault entity it resolves to. The token itself stays in
	// the HMAC-salted rawData.
	metadata := map[string]interface{}{
		"role": tokenRole,
	}
	// EntityID is empty for tokens not tied to an entity; include it only when present.
	if secret.Auth.EntityID != "" {
		metadata["subject"] = secret.Auth.EntityID
	}

	if d.logger != nil {
		d.logger.Debug("generated dynamic Vault token",
			logger.String("spec", spec.Name),
			logger.String("token_role", tokenRole),
			logger.String("accessor", secret.Auth.Accessor),
			logger.String("lease_ttl", leaseTTL.String()),
			logger.Bool("renewable", secret.Auth.Renewable),
		)
	}

	// Vault tokens don't have a lease ID in the traditional sense
	// The token itself is the credential; revocation is done via token/revoke
	return rawData, metadata, leaseTTL, secret.Auth.Accessor, nil
}

// Revoke revokes a Vault lease or token accessor
func (d *VaultDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil // Nothing to revoke
	}

	// A keyless federation source holds no session with authority over the
	// per-request login token's leases, so it cannot revoke on demand. Its mint
	// paths return an empty leaseID (credentials expire by TTL, and dynamic leases
	// are revoked when their parent login token expires), so a non-empty leaseID
	// here is unexpected — treat it as a no-op rather than erroring on authenticate.
	if d.getAuthMethod() == vaultAuthMethodOIDCFederation {
		return nil
	}

	if err := d.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed before revocation: %w", err)
	}

	// Check if this is a token accessor (Vault tokens use accessor for revocation)
	// Token accessors are typically shorter and don't contain slashes like lease IDs
	if !containsSlash(leaseID) {
		// Try to revoke as token accessor
		err := d.vault.Auth().Token().RevokeAccessorWithContext(ctx, leaseID)
		if err != nil {
			return fmt.Errorf("failed to revoke token accessor %s: %w", leaseID, err)
		}

		if d.logger != nil {
			d.logger.Debug("revoked Vault token via accessor",
				logger.String("accessor", leaseID),
			)
		}
		return nil
	}

	// Revoke as standard lease
	err := d.vault.Sys().RevokeWithContext(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("failed to revoke lease %s: %w", leaseID, err)
	}

	if d.logger != nil {
		d.logger.Debug("revoked Vault lease",
			logger.String("lease_id", leaseID),
		)
	}

	return nil
}

// containsSlash checks if a string contains a forward slash
func containsSlash(s string) bool {
	return strings.Contains(s, "/")
}

// Type returns the driver type
func (d *VaultDriver) Type() string {
	return credential.SourceTypeVault
}

// Cleanup releases resources
func (d *VaultDriver) Cleanup(ctx context.Context) error {
	// Vault client doesn't need explicit cleanup
	return nil
}

// SupportsRotation returns true if this driver instance can rotate its credentials.
// Currently only AppRole authentication supports rotation.
func (d *VaultDriver) SupportsRotation() bool {
	authMethod := credential.GetString(d.credSource.Config, "auth_method", "")
	if authMethod != "approle" {
		return false
	}

	// AppRole rotation requires role_name to generate new secret_id
	roleName := credential.GetString(d.credSource.Config, "role_name", "")
	return roleName != ""
}

// PrepareRotation generates a new AppRole secret_id WITHOUT destroying the old one.
// Both old and new secret_ids remain valid during the overlap period.
// Returns activateAfter=0 since Vault has immediate consistency.
func (d *VaultDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	authMethod := credential.GetString(d.credSource.Config, "auth_method", "")
	if authMethod != "approle" {
		return nil, nil, 0, fmt.Errorf("rotation only supported for approle auth method, got: %s", authMethod)
	}

	approleMount := credential.GetString(d.credSource.Config, "approle_mount", "")
	roleName := credential.GetString(d.credSource.Config, "role_name", "")
	oldAccessor := credential.GetString(d.credSource.Config, "secret_id_accessor", "")

	if roleName == "" {
		return nil, nil, 0, fmt.Errorf("role_name is required for AppRole rotation")
	}

	// Generate new secret_id (old one still valid - no disruption)
	generatePath := fmt.Sprintf("auth/%s/role/%s/secret-id", approleMount, roleName)
	secret, err := d.vault.Logical().WriteWithContext(ctx, generatePath, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to generate new secret_id: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, 0, fmt.Errorf("no data returned when generating new secret_id")
	}

	newSecretID, ok := secret.Data["secret_id"].(string)
	if !ok || newSecretID == "" {
		return nil, nil, 0, fmt.Errorf("secret_id not found in response")
	}

	newAccessor, ok := secret.Data["secret_id_accessor"].(string)
	if !ok || newAccessor == "" {
		return nil, nil, 0, fmt.Errorf("secret_id_accessor not found in response")
	}

	// Build new config (both old and new are valid at this point)
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
		newConfig[k] = v
	}
	newConfig["secret_id"] = newSecretID
	newConfig["secret_id_accessor"] = newAccessor

	// Build cleanup config with data needed to destroy old credentials
	cleanupConfig := map[string]string{
		"secret_id_accessor": oldAccessor,
		"approle_mount":      approleMount,
		"role_name":          roleName,
	}

	if d.logger != nil {
		d.logger.Debug("prepared new secret_id for rotation",
			logger.String("role_name", roleName),
			logger.String("new_accessor", truncateID(newAccessor, 8)),
		)
	}

	// Vault has immediate consistency — no propagation delay needed
	return newConfig, cleanupConfig, 0, nil
}

// CommitRotation activates the new credentials in driver state.
//
// Thread-safety: authMu protects credSource.Config writes and loginViaApprole reads.
// The rotated fields (secret_id, secret_id_accessor) are ONLY read inside loginViaApprole
// which always runs under authMu. Other config fields (vault_address, database_mount, etc.)
// are never modified by rotation, so concurrent reads by MintCredential are safe.
func (d *VaultDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Update internal state (safe: rotated fields only read under authMu)
	d.credSource.Config = newConfig

	// Re-authenticate with new credentials
	if err := d.loginViaApprole(ctx); err != nil {
		return fmt.Errorf("failed to authenticate with new secret_id: %w", err)
	}

	roleName := credential.GetString(newConfig, "role_name", "")
	newAccessor := credential.GetString(newConfig, "secret_id_accessor", "")

	if d.logger != nil {
		d.logger.Debug("committed rotated AppRole secret_id",
			logger.String("role_name", roleName),
			logger.String("new_accessor", truncateID(newAccessor, 8)),
		)
	}

	return nil
}

// CleanupRotation destroys the old secret_id using the accessor from cleanupConfig.
// Returns error if cleanup fails (will be retried by RotationManager).
func (d *VaultDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAccessor := cleanupConfig["secret_id_accessor"]
	if oldAccessor == "" {
		return nil // No old accessor to clean up
	}

	d.authMu.Lock()
	defer d.authMu.Unlock()

	approleMount := cleanupConfig["approle_mount"]
	roleName := cleanupConfig["role_name"]

	destroyPath := fmt.Sprintf("auth/%s/role/%s/secret-id-accessor/destroy", approleMount, roleName)
	_, err := d.vault.Logical().WriteWithContext(ctx, destroyPath, map[string]interface{}{
		"secret_id_accessor": oldAccessor,
	})
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("failed to destroy old secret_id during cleanup",
				logger.Err(err),
				logger.String("accessor", truncateID(oldAccessor, 8)),
			)
		}
		return fmt.Errorf("failed to destroy old secret_id: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("destroyed old secret_id",
			logger.String("accessor", truncateID(oldAccessor, 8)),
		)
	}
	return nil
}

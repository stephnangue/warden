package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// DefaultAWSActivationDelay is the default wait period for AWS IAM key propagation.
// AWS IAM has eventual consistency across regions; new access keys may take several
// minutes before they are recognized by all AWS services (STS, IAM, etc.).
const DefaultAWSActivationDelay = 5 * time.Minute

// Compile-time interface assertions
var _ credential.SourceDriver = (*AWSDriver)(nil)
var _ credential.Rotatable = (*AWSDriver)(nil)
var _ credential.ExchangeMinter = (*AWSDriver)(nil)

// AWSDriver fetches credentials from AWS (STS AssumeRole, Secrets Manager)
type AWSDriver struct {
	credSource *credential.CredSource
	logger     *logger.GatedLogger

	// Base credentials (long-lived IAM keys from source config)
	baseCreds aws.CredentialsProvider

	// Elevated session (from assume_role_arn in source config)
	// Protected by authMu
	elevatedCreds  *aws.Credentials
	elevatedExpiry time.Time
	authMu         sync.Mutex

	// clients is the current generation of service clients, rebuilt on auth
	// changes. Written and read only under authMu; a mint takes one reference and
	// uses it without the lock. See awsClients.
	clients *awsClients

	region string

	// baseCredsVerified records that the base key was proven usable by a live
	// call. It says nothing about whether the current elevated session is fresh —
	// only elevatedExpiry answers that, and conflating the two would let an
	// assume-role source serve an expired session indefinitely.
	baseCredsVerified bool

	// httpClient bounds every request the SDK makes and carries any custom CA the
	// source configured. Immutable after Create.
	httpClient *http.Client

	// anonSTSClient calls sts:AssumeRoleWithWebIdentity, which is unsigned — it
	// takes no AWS credentials, only the web identity token. Built once in Create
	// so a keyless federation (auth_method=oidc_federation) source needs no IAM keys.
	anonSTSClient *sts.Client

	// smBaseEndpoint and stsEndpoint, when non-empty, override where the Secrets
	// Manager and STS calls are sent. Resolved once in Create from the source's
	// secretsmanager_endpoint / sts_endpoint; empty leaves the SDK to resolve the
	// real regional endpoint. Every client of either service is built through
	// smOptions/stsOptions so an override applies to all of them, including the
	// ones used to validate the source at write time.
	smBaseEndpoint string
	stsEndpoint    string

	// iamTestEndpoint redirects the IAM calls rotation makes. Set only by tests in
	// this package: unlike the STS and Secrets Manager overrides there is
	// deliberately no source-config key, because rotation acts on the real account
	// whatever else a source is pointed at.
	iamTestEndpoint string
}

// awsAuthMethodStatic and awsAuthMethodOIDCFederation select how the source
// authenticates. static (default) uses long-lived IAM keys; oidc_federation holds
// no key and mints only via sts:AssumeRoleWithWebIdentity from a caller-presented
// identity assertion.
const (
	awsAuthMethodStatic         = "static"
	awsAuthMethodOIDCFederation = "oidc_federation"
)

// federatedFetchSessionDuration is the lifetime requested for the temporary credentials
// backing a single federated Secrets Manager read. They are used once and discarded, so
// this is the AWS minimum for AssumeRoleWithWebIdentity (15m) rather than the secret's TTL.
const federatedFetchSessionDuration = 15 * time.Minute

// awsRequestTimeout bounds a single HTTP attempt to any AWS service. The SDK's
// default retryer may make up to three, so the worst case is a small multiple of
// this rather than the unbounded wait a missing timeout would allow.
const awsRequestTimeout = 30 * time.Second

// awsCreateProbeTimeout bounds the credential probe run when a source is written.
// A var, not a const, so tests can shrink it — an endpoint that accepts the
// connection and never answers would otherwise hold the write open for the full
// request timeout.
var awsCreateProbeTimeout = 30 * time.Second

// awsClients is one coherent generation of service clients, together with the
// base credentials they were built from. It is built under authMu and then used
// without it: a mint takes the whole snapshot up front, so every call it makes
// signs with a single generation even if a rotation commit swaps the driver
// underneath it mid-request.
type awsClients struct {
	baseCreds  aws.CredentialsProvider
	sts        *sts.Client
	sm         *secretsmanager.Client
	redshift   *redshift.Client
	redshiftSL *redshiftserverless.Client
}

// AWSDriverFactory creates AWSDriver instances
type AWSDriverFactory struct{}

// Type returns the driver type
func (f *AWSDriverFactory) Type() string {
	return credential.SourceTypeAWS
}

// ValidateConfig validates AWS driver configuration using declarative schema
func (f *AWSDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateSchema(config,
		credential.StringField("auth_method").
			OneOf(awsAuthMethodStatic, awsAuthMethodOIDCFederation).
			Describe("How the source authenticates: static (IAM keys) or oidc_federation (Workload Identity Federation, keyless)").
			Example("static"),

		credential.StringField("access_key_id").
			Describe("AWS IAM access key ID (required for auth_method=static)").
			Example("AKIAIOSFODNN7EXAMPLE"),

		credential.StringField("secret_access_key").
			Describe("AWS IAM secret access key (required for auth_method=static)").
			Example("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),

		credential.StringField("region").
			Required().
			Describe("AWS region for API calls").
			Example("us-east-1"),

		credential.StringField("assume_role_arn").
			Describe("Optional IAM role ARN to assume for elevated permissions (static only)").
			Example("arn:aws:iam::123456789012:role/WardenSourceRole"),

		credential.StringField("session_name").
			Describe("Session name for AssumeRole operations").
			Example("warden-source-session"),

		credential.DurationField("session_duration").
			Describe("Duration for AssumeRole sessions").
			Example("1h"),

		credential.StringField("external_id").
			Describe("Optional external ID for AssumeRole operations").
			Example("unique-external-id"),

		credential.StringField("audience").
			Describe("Audience minted into a warden_identity assertion for this source (oidc_federation only; default sts.amazonaws.com)").
			Example("sts.amazonaws.com"),

		credential.StringField("sts_endpoint").
			Custom(validateAWSEndpoint).
			Describe("Override where STS calls are sent, including the credential probe run when this source is written (default: the SDK's regional endpoint). Does not apply to the IAM, Redshift or RDS clients").
			Example("https://sts.us-east-1.amazonaws.com"),

		credential.StringField("secretsmanager_endpoint").
			Custom(validateAWSEndpoint).
			Describe("Override where Secrets Manager calls are sent (default: the SDK's regional endpoint)").
			Example("https://secretsmanager.us-east-1.amazonaws.com"),

		credential.DurationField("activation_delay").
			Describe("Wait between creating a new IAM key and activating it, for propagation (default: 5m)").
			Example("5m"),

		credential.StringField("ca_data").
			Custom(ValidateCAData).
			Describe("Base64-encoded PEM CA certificate for custom/self-signed CAs").
			Example(""),

		credential.BoolField("tls_skip_verify").
			Describe("Skip TLS certificate verification (development only)").
			Example("false"),
	); err != nil {
		return err
	}

	// Cross-field rules per auth_method.
	switch credential.GetString(config, "auth_method", awsAuthMethodStatic) {
	case awsAuthMethodStatic:
		if credential.GetString(config, "access_key_id", "") == "" || credential.GetString(config, "secret_access_key", "") == "" {
			return fmt.Errorf("access_key_id and secret_access_key are required for auth_method=static")
		}
		// audience seeds only the warden_identity federation assertion; on a static
		// source it would be silently ignored, so reject it rather than mislead.
		if credential.GetString(config, "audience", "") != "" {
			return fmt.Errorf("audience is only valid for auth_method=oidc_federation")
		}
	case awsAuthMethodOIDCFederation:
		// A federation source holds no static secret. Reject leftover static config
		// so a misconfiguration cannot silently mix modes.
		if credential.GetString(config, "access_key_id", "") != "" || credential.GetString(config, "secret_access_key", "") != "" {
			return fmt.Errorf("access_key_id/secret_access_key must not be set for auth_method=oidc_federation")
		}
		if credential.GetString(config, "assume_role_arn", "") != "" {
			return fmt.Errorf("assume_role_arn is not supported for auth_method=oidc_federation")
		}
	}
	return nil
}

// validateAWSEndpoint checks an endpoint override is a URL the SDK can actually
// send to. A keyless source runs no probe when it is written, so without this a
// typo surfaces only on the first request that needs it.
func validateAWSEndpoint(v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("endpoint is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint must use http or https scheme, got: %s", v)
	}
	if u.Host == "" {
		return fmt.Errorf("endpoint has no host: %s", v)
	}
	return nil
}

// ValidateRotationConfig refuses a rotation period on a source whose STS calls are
// redirected. Rotation acts on the real account through IAM, which deliberately has
// no override, so a source pointed at a stand-in would mint and verify against it
// while trying to rotate keys that only exist somewhere else — failing on a loop
// with no indication of why.
func (f *AWSDriverFactory) ValidateRotationConfig(config map[string]string) error {
	if credential.GetString(config, "sts_endpoint", "") == "" &&
		credential.GetString(config, "secretsmanager_endpoint", "") == "" {
		return nil
	}
	return fmt.Errorf("rotation_period cannot be set on a source that overrides sts_endpoint or " +
		"secretsmanager_endpoint: rotation manages IAM keys in the real account, which those " +
		"overrides do not redirect")
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AWSDriverFactory) SensitiveConfigFields() []string {
	return []string{"secret_access_key", "ca_data"}
}

// InferCredentialType infers the credential type from the spec's mint_method.
func (f *AWSDriverFactory) InferCredentialType(specConfig map[string]string) (string, error) {
	mintMethod := specConfig["mint_method"]
	// credential_type selects the stored-secret shape and is meaningful only for
	// secrets_manager; reject it elsewhere rather than silently ignoring it.
	if specConfig["credential_type"] != "" && mintMethod != "secrets_manager" {
		return "", fmt.Errorf("credential_type is only valid with mint_method=secrets_manager (got mint_method=%q)", mintMethod)
	}
	switch mintMethod {
	case "rds_iam_token", "redshift_iam_token":
		return credential.TypeDBAuthToken, nil
	case "secrets_manager":
		// A stored secret can hold different credential shapes; the spec selects one
		// via credential_type (default: AWS access keys). This mirrors how a Vault
		// source vends multiple shapes — the transport is one thing, the shape another.
		return inferSecretsManagerType(specConfig["credential_type"])
	case "sts_assume_role", "":
		return credential.TypeAWSAccessKeys, nil
	default:
		return "", fmt.Errorf("cannot infer credential type for mint_method %q", mintMethod)
	}
}

// inferSecretsManagerType maps the operator-selected credential_type to a supported
// stored-secret shape. Empty defaults to AWS access keys for back-compat. Extend the
// allowlist to admit another storable type once its ValidateConfig accepts an AWS source.
func inferSecretsManagerType(credType string) (string, error) {
	switch credType {
	case "", credential.TypeAWSAccessKeys:
		return credential.TypeAWSAccessKeys, nil
	case credential.TypeAPIKey:
		return credential.TypeAPIKey, nil
	default:
		return "", fmt.Errorf("unsupported credential_type %q for mint_method=secrets_manager (supported: %s, %s)", credType, credential.TypeAWSAccessKeys, credential.TypeAPIKey)
	}
}

// Create instantiates a new AWSDriver
func (f *AWSDriverFactory) Create(config map[string]string, log *logger.GatedLogger) (credential.SourceDriver, error) {
	accessKeyID := credential.GetString(config, "access_key_id", "")
	secretAccessKey := credential.GetString(config, "secret_access_key", "")
	region := credential.GetString(config, "region", "us-east-1")

	baseCreds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")

	httpClient, err := BuildHTTPClient(config, awsRequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP client: %w", err)
	}

	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: config,
		},
		logger:         log.WithSubsystem(credential.SourceTypeAWS),
		baseCreds:      baseCreds,
		region:         region,
		stsEndpoint:    credential.GetString(config, "sts_endpoint", ""),
		smBaseEndpoint: credential.GetString(config, "secretsmanager_endpoint", ""),
		httpClient:     httpClient,
	}

	// AssumeRoleWithWebIdentity is unsigned: anonymous credentials skip SigV4.
	// Built after the literal so it picks up the resolved endpoint override.
	driver.anonSTSClient = sts.NewFromConfig(
		driver.awsConfig(aws.AnonymousCredentials{}), driver.stsOptions())

	// A federation source holds no IAM keys: skip the eager credential probe. All
	// authentication happens per-request from the caller's identity assertion.
	if credential.GetString(config, "auth_method", awsAuthMethodStatic) == awsAuthMethodOIDCFederation {
		return driver, nil
	}

	// Perform initial authentication. Bounded: a source write must not hang on an
	// endpoint that accepts the connection and never answers.
	probeCtx, cancel := context.WithTimeout(context.Background(), awsCreateProbeTimeout)
	defer cancel()
	if _, err := driver.authenticate(probeCtx); err != nil {
		return nil, fmt.Errorf("AWS authentication failed: %w", err)
	}

	return driver, nil
}

// authenticate refreshes the session if needed and returns the client generation
// to use. Thread-safe. The returned snapshot is the caller's for the rest of its
// request: it must not re-read driver fields afterwards, or it risks mixing two
// credential generations across a rotation.
func (d *AWSDriver) authenticate(ctx context.Context) (*awsClients, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authenticateLocked(ctx)
}

// authenticateLocked performs authentication without acquiring authMu.
// Caller must hold authMu.
func (d *AWSDriver) authenticateLocked(ctx context.Context) (*awsClients, error) {
	assumeRoleArn := credential.GetString(d.credSource.Config, "assume_role_arn", "")
	if assumeRoleArn == "" {
		// Base credentials do not expire, so a verified generation stays good until
		// a rotation drops it. The assumeRoleArn guard is what keeps this branch
		// from answering for an elevated session, whose expiry it cannot see.
		if d.clients != nil && d.baseCredsVerified {
			return d.clients, nil
		}

		// Verify base credentials are valid once with a lightweight API call
		if !d.baseCredsVerified {
			baseSTS := sts.NewFromConfig(d.awsConfig(d.baseCreds), d.stsOptions())
			if _, err := baseSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
				return nil, fmt.Errorf("invalid AWS credentials: %w", err)
			}
			d.baseCredsVerified = true
		}

		return d.buildClientsLocked(d.baseCreds), nil
	}

	// Check if elevated session is still valid (30-second buffer)
	if d.clients != nil && d.elevatedCreds != nil && time.Now().Add(30*time.Second).Before(d.elevatedExpiry) {
		return d.clients, nil
	}

	// Call STS AssumeRole using base credentials
	sessionName := credential.GetString(d.credSource.Config, "session_name", "warden-source-session")
	sessionDuration := credential.GetDuration(d.credSource.Config, "session_duration", 1*time.Hour)
	externalID := credential.GetString(d.credSource.Config, "external_id", "")

	durationSeconds, err := awsSessionSeconds(sessionDuration, "session_duration")
	if err != nil {
		return nil, err
	}

	baseSTS := sts.NewFromConfig(d.awsConfig(d.baseCreds), d.stsOptions())

	input := &sts.AssumeRoleInput{
		RoleArn:         &assumeRoleArn,
		RoleSessionName: &sessionName,
		DurationSeconds: aws.Int32(durationSeconds),
	}
	if externalID != "" {
		input.ExternalId = &externalID
	}

	result, err := baseSTS.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role %s: %w", assumeRoleArn, err)
	}
	if err := validSTSCredentials(result.Credentials, "STS AssumeRole for "+assumeRoleArn); err != nil {
		return nil, err
	}

	d.elevatedCreds = &aws.Credentials{
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
	}
	d.elevatedExpiry = *result.Credentials.Expiration

	elevatedProvider := credentials.NewStaticCredentialsProvider(
		d.elevatedCreds.AccessKeyID,
		d.elevatedCreds.SecretAccessKey,
		d.elevatedCreds.SessionToken,
	)
	clients := d.buildClientsLocked(elevatedProvider)

	if d.logger != nil {
		d.logger.Trace("authenticated to AWS via AssumeRole",
			logger.String("role_arn", assumeRoleArn),
			logger.String("expires_at", d.elevatedExpiry.Format(time.RFC3339)),
		)
	}

	return clients, nil
}

// stsOptions applies the source's STS endpoint override, if it set one. Every STS
// client goes through here: an override that reached only the minting clients would
// leave the source validated against the real service and minted against another.
func (d *AWSDriver) stsOptions() func(*sts.Options) {
	return func(o *sts.Options) {
		if d.stsEndpoint != "" {
			o.BaseEndpoint = aws.String(d.stsEndpoint)
		}
	}
}

// smOptions applies the source's Secrets Manager endpoint override, if it set one.
func (d *AWSDriver) smOptions() func(*secretsmanager.Options) {
	return func(o *secretsmanager.Options) {
		if d.smBaseEndpoint != "" {
			o.BaseEndpoint = aws.String(d.smBaseEndpoint)
		}
	}
}

// buildClientsLocked creates a new client generation from the given credentials
// and publishes it. Caller must hold authMu.
//
// The Redshift clients keep their resolved endpoints — the endpoint overrides
// cover only the mint and source-validation paths.
func (d *AWSDriver) buildClientsLocked(creds aws.CredentialsProvider) *awsClients {
	cfg := d.awsConfig(creds)
	d.clients = &awsClients{
		baseCreds:  d.baseCreds,
		sts:        sts.NewFromConfig(cfg, d.stsOptions()),
		sm:         secretsmanager.NewFromConfig(cfg, d.smOptions()),
		redshift:   redshift.NewFromConfig(cfg),
		redshiftSL: redshiftserverless.NewFromConfig(cfg),
	}
	return d.clients
}

// validSTSCredentials rejects a structurally incomplete credentials block. A
// malformed 200 — an intercepting proxy, an endpoint override pointed at
// something that only half speaks the protocol — yields a response whose missing
// fields the SDK leaves nil, and every consumer here dereferences them. op names
// the call for the error, which names the first field that is absent.
//
// The fields are checked in a fixed order rather than by map iteration so the
// error a given response produces is always the same one.
func validSTSCredentials(creds *ststypes.Credentials, op string) error {
	if creds == nil {
		return fmt.Errorf("%s returned no credentials block", op)
	}
	for _, f := range []struct {
		name  string
		value *string
	}{
		{"AccessKeyId", creds.AccessKeyId},
		{"SecretAccessKey", creds.SecretAccessKey},
		{"SessionToken", creds.SessionToken},
	} {
		if f.value == nil {
			return fmt.Errorf("%s returned credentials with no %s", op, f.name)
		}
	}
	if creds.Expiration == nil {
		return fmt.Errorf("%s returned credentials with no Expiration", op)
	}
	return nil
}

// validNewIAMAccessKey rejects a CreateAccessKey response that does not carry the
// key material a rotation is about to persist as the source's only credential.
func validNewIAMAccessKey(key *iamtypes.AccessKey) error {
	if key == nil {
		return fmt.Errorf("IAM CreateAccessKey returned no access key")
	}
	if key.AccessKeyId == nil {
		return fmt.Errorf("IAM CreateAccessKey returned a key with no AccessKeyId")
	}
	if key.SecretAccessKey == nil {
		return fmt.Errorf("IAM CreateAccessKey returned a key with no SecretAccessKey")
	}
	return nil
}

// awsConfig builds the SDK config every client in this driver is constructed
// from. HTTPClient is set only when one was actually built: aws.Config takes an
// interface, and a nil *http.Client stored in it reads as non-nil to the SDK,
// which then panics on the first request instead of using its own default.
func (d *AWSDriver) awsConfig(creds aws.CredentialsProvider) aws.Config {
	cfg := aws.Config{
		Region:      d.region,
		Credentials: creds,
	}
	if d.httpClient != nil {
		cfg.HTTPClient = d.httpClient
	}
	return cfg
}

// newIAMClient builds the IAM client rotation uses, from the base credentials —
// an elevated session acts as the role principal and cannot manage the user's own
// access keys.
func (d *AWSDriver) newIAMClient(creds aws.CredentialsProvider) *iam.Client {
	cfg := d.awsConfig(creds)
	if d.iamTestEndpoint != "" {
		return iam.NewFromConfig(cfg, func(o *iam.Options) {
			o.BaseEndpoint = aws.String(d.iamTestEndpoint)
		})
	}
	return iam.NewFromConfig(cfg)
}

// sourceConfig returns the current source config for callers that need it before
// (or without) authenticating. The map is never written in place, so the pointer
// is a stable snapshot; a rotation swaps in a whole new map instead.
func (d *AWSDriver) sourceConfig() map[string]string {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.credSource.Config
}

// MintCredential mints credentials using AWS based on credential spec
func (d *AWSDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	authMethod := credential.GetString(d.sourceConfig(), "auth_method", awsAuthMethodStatic)

	// A federation source holds no static credentials: it authenticates per-request
	// by federating a caller assertion, which flows through MintCredentialWithExchange.
	// Reaching the non-exchange path means the spec lacks subject_token_source. Fail
	// clearly rather than falling into authenticate() with empty keys and a misleading
	// "invalid AWS credentials" error.
	if authMethod == awsAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("auth_method=oidc_federation requires subject_token_source on the spec (warden_identity or agent_identity); federated minting runs through the token-exchange path")
	}

	// Re-authenticate if needed. The returned generation is this mint's for the
	// rest of the call; a concurrent rotation swaps the driver's, not this one.
	c, err := d.authenticate(ctx)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	switch mintMethod {
	case "sts_assume_role":
		return d.mintViaSTSAssumeRole(ctx, c, spec)
	case "secrets_manager":
		return d.mintViaSecretsManager(ctx, c, spec)
	case "rds_iam_token":
		return d.mintViaRDSIAMToken(ctx, c, spec)
	case "redshift_iam_token":
		return d.mintViaRedshiftIAMToken(ctx, c, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for AWS driver; use 'sts_assume_role', 'secrets_manager', 'rds_iam_token', or 'redshift_iam_token'", mintMethod)
	}
}

// mintViaSTSAssumeRole mints temporary credentials via STS AssumeRole
func (d *AWSDriver) mintViaSTSAssumeRole(ctx context.Context, c *awsClients, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	roleArn, err := credential.GetStringRequired(spec.Config, "role_arn")
	if err != nil {
		return nil, nil, 0, "", err
	}

	sessionName, err := awsSessionName(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}

	ttlStr := credential.GetString(spec.Config, "ttl", "1h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("invalid ttl '%s': %w", ttlStr, err)
	}

	// Validate TTL against spec bounds
	if spec.MinTTL > 0 && ttl < spec.MinTTL {
		return nil, nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", ttl, spec.MinTTL)
	}
	if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
		return nil, nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", ttl, spec.MaxTTL)
	}

	durationSeconds, err := awsSessionSeconds(ttl, "ttl")
	if err != nil {
		return nil, nil, 0, "", err
	}

	input := &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &sessionName,
		DurationSeconds: aws.Int32(durationSeconds),
	}

	if extID := credential.GetString(spec.Config, "external_id", ""); extID != "" {
		input.ExternalId = &extID
	}
	if policy := credential.GetString(spec.Config, "policy", ""); policy != "" {
		input.Policy = &policy
	}

	result, err := c.sts.AssumeRole(ctx, input)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("STS AssumeRole failed for %s: %w", roleArn, err)
	}
	if err := validSTSCredentials(result.Credentials, "STS AssumeRole for "+roleArn); err != nil {
		return nil, nil, 0, "", err
	}

	creds := result.Credentials
	leaseTTL := time.Until(*creds.Expiration)

	// Validate lease TTL is positive (guards against clock skew or cached responses)
	if leaseTTL <= 0 {
		return nil, nil, 0, "", fmt.Errorf("STS credentials already expired or have invalid expiration time")
	}

	// Synthetic lease ID for tracking (STS creds can't be revoked)
	leaseID := fmt.Sprintf("sts:%s", *creds.AccessKeyId)

	rawData := map[string]interface{}{
		"access_key_id":     *creds.AccessKeyId,
		"secret_access_key": *creds.SecretAccessKey,
		"session_token":     *creds.SessionToken,
		"security_token":    *creds.SessionToken,
		"cred_source":       "aws_sts",
	}

	// Non-secret, descriptive attributes for clear audit logging. The secret
	// material stays in rawData; only the principal identity goes here.
	metadata := map[string]interface{}{
		"subject":      roleArn, // the role the caller asked to assume
		"session_name": sessionName,
		"expiration":   creds.Expiration.UTC().Format(time.RFC3339),
	}
	if result.AssumedRoleUser != nil {
		if arn := aws.ToString(result.AssumedRoleUser.Arn); arn != "" {
			metadata["assumed_role_arn"] = arn
			if acct := accountIDFromARN(arn); acct != "" {
				metadata["account_id"] = acct
			}
		}
		if id := aws.ToString(result.AssumedRoleUser.AssumedRoleId); id != "" {
			metadata["assumed_role_id"] = id
		}
	}

	if d.logger != nil {
		d.logger.Debug("generated STS temporary credentials",
			logger.String("spec", spec.Name),
			logger.String("role_arn", roleArn),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, metadata, leaseTTL, leaseID, nil
}

// MintCredentialWithExchange federates a caller-derived identity into AWS via
// sts:AssumeRoleWithWebIdentity (Workload Identity Federation), then produces the
// outcome the spec's mint_method asks for. It requires a keyless source
// (auth_method=oidc_federation) and a verified subject, of which there are two shapes:
//   - subject_token_source=warden_identity: Warden mints a fresh assertion and AWS
//     validates its signature against Warden's published JWKS (federate Warden once).
//   - subject_token_source=agent_identity: Warden forwards the agent's verified
//     inbound JWT untouched, and AWS validates it against the origin IdP's JWKS
//     (the role must federate that IdP directly, and its trust policy must accept the
//     token's audience — Warden pins nothing here since it did not mint the token).
//
// Either way the subject is trusted at the source; there is no caller-supplied,
// unverified subject token.
//
// Supported mint methods over federation:
//   - sts_assume_role: the federated role credentials are themselves the issued credential.
//   - secrets_manager: the federated credentials read one secret and are then discarded.
func (d *AWSDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if credential.GetString(d.sourceConfig(), "auth_method", awsAuthMethodStatic) != awsAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("aws: web-identity federation requires auth_method=oidc_federation on the source")
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("aws: no subject token in exchange inputs")
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	switch mintMethod {
	case "sts_assume_role":
		// The assumed-role credentials are the issued credential, so their lifetime is
		// the spec's TTL (validated against its bounds).
		ttl, err := federatedSessionTTL(spec)
		if err != nil {
			return nil, nil, 0, "", err
		}
		out, err := d.assumeRoleWithWebIdentity(ctx, spec, inputs.SubjectToken, ttl)
		if err != nil {
			return nil, nil, 0, "", err
		}
		return d.credsFromWebIdentity(spec, out)
	case "secrets_manager":
		// These credentials serve a single GetSecretValue and are then discarded, so
		// request a short fixed session — the spec's TTL bounds govern the returned
		// static secret, not this transient assume-role.
		out, err := d.assumeRoleWithWebIdentity(ctx, spec, inputs.SubjectToken, federatedFetchSessionDuration)
		if err != nil {
			return nil, nil, 0, "", err
		}
		creds := out.Credentials
		provider := credentials.NewStaticCredentialsProvider(
			aws.ToString(creds.AccessKeyId),
			aws.ToString(creds.SecretAccessKey),
			aws.ToString(creds.SessionToken),
		)
		return d.fetchSecret(ctx, d.newSecretsManagerClient(provider), spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("aws: mint_method %q is not supported over auth_method=oidc_federation (supported: sts_assume_role, secrets_manager)", mintMethod)
	}
}

// awsAssertionResource reports the canonical downstream resource an AWS
// federation spec targets, for the warden_resource assertion claim. Pure: reads
// spec config only, no network or driver state. Mirrors the federated mint_method
// dispatch in MintCredentialWithExchange so the named resource is the one the
// exchange actually reaches. The provider prefix is human-readable sugar on an
// opaque value — never parse it back (a secret id / ARN can itself contain ':').
// defaultAWSFederationAudience is the conventional `aud` for IAM OIDC federation:
// AWS STS AssumeRoleWithWebIdentity accepts sts.amazonaws.com unless the OIDC
// provider is configured with different client IDs.
const defaultAWSFederationAudience = "sts.amazonaws.com"

// awsAssertionAudience derives the warden_identity assertion audience for an AWS
// federation source: the source's explicit `audience`, else the conventional
// default. Only a keyless (oidc_federation) source federates, so a static source
// supplies no derived audience — a warden_identity spec on it must set one
// explicitly (and would fail closed at mint anyway).
func awsAssertionAudience(sourceCfg map[string]string) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", awsAuthMethodStatic) != awsAuthMethodOIDCFederation {
		return "", false
	}
	return credential.GetString(sourceCfg, "audience", defaultAWSFederationAudience), true
}

func awsAssertionResource(specCfg map[string]string) (string, bool) {
	switch credential.GetString(specCfg, "mint_method", "") {
	case "secrets_manager":
		if id := credential.GetString(specCfg, "secret_id", ""); id != "" {
			return "aws-secretsmanager:" + id, true
		}
	case "sts_assume_role":
		if arn := credential.GetString(specCfg, "role_arn", ""); arn != "" {
			return "aws-iam:" + arn, true
		}
	}
	return "", false
}

// federatedSessionTTL resolves the assume-role session duration from the spec's ttl
// (default 1h), validated against the spec's TTL bounds.
func federatedSessionTTL(spec *credential.CredSpec) (time.Duration, error) {
	ttlStr := credential.GetString(spec.Config, "ttl", "1h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl '%s': %w", ttlStr, err)
	}
	if spec.MinTTL > 0 && ttl < spec.MinTTL {
		return 0, fmt.Errorf("requested TTL %s is below minimum %s", ttl, spec.MinTTL)
	}
	if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
		return 0, fmt.Errorf("requested TTL %s exceeds maximum %s", ttl, spec.MaxTTL)
	}
	return ttl, nil
}

// assumeRoleWithWebIdentity exchanges webIdentityToken for temporary AWS credentials via
// the unsigned anonSTSClient, so an oidc_federation source needs no IAM keys. The session
// duration is supplied by the caller, since a role-assumption outcome and a transient
// secret fetch want different lifetimes.
func (d *AWSDriver) assumeRoleWithWebIdentity(ctx context.Context, spec *credential.CredSpec, webIdentityToken string, dur time.Duration) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	roleArn, err := credential.GetStringRequired(spec.Config, "role_arn")
	if err != nil {
		return nil, err
	}
	sessionName, err := awsSessionName(spec)
	if err != nil {
		return nil, err
	}
	durationSeconds, err := awsSessionSeconds(dur, "ttl")
	if err != nil {
		return nil, err
	}

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleArn,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &webIdentityToken,
		DurationSeconds:  aws.Int32(durationSeconds),
	}
	if policy := credential.GetString(spec.Config, "policy", ""); policy != "" {
		input.Policy = &policy
	}

	result, err := d.anonSTSClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("STS AssumeRoleWithWebIdentity failed for %s: %w", roleArn, err)
	}
	// The single choke point for both consumers: the shaping in credsFromWebIdentity
	// and the credential provider the federated secret fetch is built from. Checking
	// the whole block here means neither has to.
	if err := validSTSCredentials(result.Credentials, "STS AssumeRoleWithWebIdentity for "+roleArn); err != nil {
		return nil, err
	}
	return result, nil
}

// credsFromWebIdentity shapes the temporary credentials from a web-identity assume-role
// into the mint tuple, for when the assumed-role credentials are themselves the issued
// credential (mint_method=sts_assume_role over oidc_federation).
func (d *AWSDriver) credsFromWebIdentity(spec *credential.CredSpec, result *sts.AssumeRoleWithWebIdentityOutput) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	roleArn := credential.GetString(spec.Config, "role_arn", "")
	// Already validated by assumeRoleWithWebIdentity, which had to send it.
	sessionName, err := awsSessionName(spec)
	if err != nil {
		return nil, nil, 0, "", err
	}

	creds := result.Credentials
	leaseTTL := time.Until(*creds.Expiration)
	if leaseTTL <= 0 {
		return nil, nil, 0, "", fmt.Errorf("STS credentials already expired or have invalid expiration time")
	}
	leaseID := fmt.Sprintf("sts:%s", *creds.AccessKeyId)

	rawData := map[string]interface{}{
		"access_key_id":     *creds.AccessKeyId,
		"secret_access_key": *creds.SecretAccessKey,
		"session_token":     *creds.SessionToken,
		"security_token":    *creds.SessionToken,
		"cred_source":       "aws_sts_web_identity",
	}

	metadata := map[string]interface{}{
		"subject":      roleArn,
		"session_name": sessionName,
		"expiration":   creds.Expiration.UTC().Format(time.RFC3339),
	}
	if result.AssumedRoleUser != nil {
		if arn := aws.ToString(result.AssumedRoleUser.Arn); arn != "" {
			metadata["assumed_role_arn"] = arn
			if acct := accountIDFromARN(arn); acct != "" {
				metadata["account_id"] = acct
			}
		}
	}

	if d.logger != nil {
		d.logger.Debug("generated STS temporary credentials via web identity",
			logger.String("spec", spec.Name),
			logger.String("role_arn", roleArn),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, metadata, leaseTTL, leaseID, nil
}

// newSecretsManagerClient builds a Secrets Manager client bound to the given credentials
// (e.g. freshly federated temporary credentials), honouring the source's endpoint
// override when it set one.
func (d *AWSDriver) newSecretsManagerClient(creds aws.CredentialsProvider) *secretsmanager.Client {
	return secretsmanager.NewFromConfig(d.awsConfig(creds), d.smOptions())
}

// mintViaSecretsManager fetches a secret using the source's authenticated client (static
// auth). The keyless (federation) path fetches with a temp-credential client instead.
func (d *AWSDriver) mintViaSecretsManager(ctx context.Context, c *awsClients, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return d.fetchSecret(ctx, c.sm, spec)
}

// fetchSecret reads and parses a Secrets Manager secret with the given client. The client
// may be the source's own (static auth) or one bound to freshly federated credentials.
func (d *AWSDriver) fetchSecret(ctx context.Context, sm *secretsmanager.Client, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	secretID, err := credential.GetStringRequired(spec.Config, "secret_id")
	if err != nil {
		return nil, nil, 0, "", err
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	}
	if vs := credential.GetString(spec.Config, "version_stage", ""); vs != "" {
		input.VersionStage = &vs
	}
	if vid := credential.GetString(spec.Config, "version_id", ""); vid != "" {
		input.VersionId = &vid
	}

	result, err := sm.GetSecretValue(ctx, input)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to get secret '%s': %w", secretID, err)
	}

	if result.SecretString == nil {
		return nil, nil, 0, "", fmt.Errorf("secret '%s' has no string value (binary secrets not supported)", secretID)
	}

	var secretData map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secretData); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	// Project through the spec's field selection, when it declares one.
	secretData = credential.ApplyKeyMap(secretData, credential.GetString(spec.Config, "json_key_map", ""))

	if d.logger != nil {
		d.logger.Debug("fetched secret from AWS Secrets Manager",
			logger.String("spec", spec.Name),
			logger.String("secret_id", secretID),
		)
	}

	// Secrets Manager secrets are static (no lease TTL)
	return secretData, nil, 0, "", nil
}

// accountIDFromARN extracts the account-id segment from an ARN
// (arn:partition:service:region:account-id:resource), or "" if malformed.
func accountIDFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// mintViaRDSIAMToken generates a short-lived IAM authentication token for RDS.
// The token is a pre-signed STS GetCallerIdentity URL that RDS accepts as a password.
// This is a local SigV4 signing operation — no network call to RDS.
//
// The token is a signature, not credential material, so its lifetime is bounded by
// the signing key rather than by the fifteen minutes reported below: RDS validates
// the signature at connection time, and cleanup deleting (or deactivating) the key
// invalidates every token still signed by it. Cleanup runs right after a commit, so
// a token minted moments earlier can be reported valid for fifteen minutes and be
// unusable seconds later. Nothing here can see cleanup's schedule; closing the
// window means delaying source-key cleanup by at least this lifetime, which is the
// rotation manager's to arrange.
func (d *AWSDriver) mintViaRDSIAMToken(ctx context.Context, c *awsClients, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	dbEndpoint, err := credential.GetStringRequired(spec.Config, "db_endpoint")
	if err != nil {
		return nil, nil, 0, "", err
	}
	dbUser, err := credential.GetStringRequired(spec.Config, "db_user")
	if err != nil {
		return nil, nil, 0, "", err
	}

	dbEngine := credential.GetString(spec.Config, "db_engine", "postgres")
	dbPort := credential.GetString(spec.Config, "db_port", defaultPortForEngine(dbEngine))
	region := credential.GetString(spec.Config, "region", d.region)

	endpoint := fmt.Sprintf("%s:%s", dbEndpoint, dbPort)

	token, err := rdsauth.BuildAuthToken(ctx, endpoint, region, dbUser, c.baseCreds)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to build RDS IAM auth token: %w", err)
	}

	rawData := map[string]interface{}{
		"auth_token": token,
		"db_host":    dbEndpoint,
		"db_port":    dbPort,
		"db_user":    dbUser,
		"db_engine":  dbEngine,
		"region":     region,
		"token_type": "rds_iam",
	}

	if d.logger != nil {
		d.logger.Debug("generated RDS IAM auth token",
			logger.String("spec", spec.Name),
			logger.String("endpoint", endpoint),
			logger.String("db_user", dbUser),
			logger.String("region", region),
		)
	}

	// RDS IAM tokens are valid for 15 minutes
	return rawData, nil, 15 * time.Minute, "", nil
}

// mintViaRedshiftIAMToken generates a short-lived IAM authentication token for
// Amazon Redshift. Unlike RDS IAM (local SigV4 signing), Redshift requires an
// AWS API call:
//   - cluster_identifier set → redshift:GetClusterCredentialsWithIAM (provisioned)
//   - workgroup_name set     → redshift-serverless:GetCredentials  (serverless)
//
// Both APIs return a database user (mapped 1:1 to the source IAM identity for
// provisioned, workgroup-scoped for serverless) and a temporary password.
func (d *AWSDriver) mintViaRedshiftIAMToken(ctx context.Context, c *awsClients, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	dbEndpoint, err := credential.GetStringRequired(spec.Config, "db_endpoint")
	if err != nil {
		return nil, nil, 0, "", err
	}

	clusterID := credential.GetString(spec.Config, "cluster_identifier", "")
	workgroup := credential.GetString(spec.Config, "workgroup_name", "")
	if clusterID == "" && workgroup == "" {
		return nil, nil, 0, "", fmt.Errorf("redshift_iam_token requires either 'cluster_identifier' (provisioned) or 'workgroup_name' (serverless)")
	}
	if clusterID != "" && workgroup != "" {
		return nil, nil, 0, "", fmt.Errorf("redshift_iam_token requires exactly one of 'cluster_identifier' or 'workgroup_name', not both")
	}

	dbName := credential.GetString(spec.Config, "db_name", "")
	dbPort := credential.GetString(spec.Config, "db_port", "5439")
	region := credential.GetString(spec.Config, "region", d.region)

	durationSeconds := credential.GetInt(spec.Config, "duration_seconds", 900)
	if durationSeconds < 900 || durationSeconds > 3600 {
		return nil, nil, 0, "", fmt.Errorf("duration_seconds must be between 900 and 3600 (got %d)", durationSeconds)
	}

	var (
		dbUser     string
		dbPassword string
		expiration *time.Time
		deployment string
	)

	if clusterID != "" {
		input := &redshift.GetClusterCredentialsWithIAMInput{
			ClusterIdentifier: aws.String(clusterID),
			DurationSeconds:   aws.Int32(int32(durationSeconds)),
		}
		if dbName != "" {
			input.DbName = aws.String(dbName)
		}
		out, err := c.redshift.GetClusterCredentialsWithIAM(ctx, input)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("Redshift GetClusterCredentialsWithIAM failed for cluster %s: %w", clusterID, err)
		}
		if out.DbUser == nil || out.DbPassword == nil {
			return nil, nil, 0, "", fmt.Errorf("Redshift GetClusterCredentialsWithIAM returned empty credentials for cluster %s", clusterID)
		}
		dbUser = *out.DbUser
		dbPassword = *out.DbPassword
		expiration = out.Expiration
		deployment = "provisioned"
	} else {
		input := &redshiftserverless.GetCredentialsInput{
			WorkgroupName:   aws.String(workgroup),
			DurationSeconds: aws.Int32(int32(durationSeconds)),
		}
		if dbName != "" {
			input.DbName = aws.String(dbName)
		}
		out, err := c.redshiftSL.GetCredentials(ctx, input)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("Redshift Serverless GetCredentials failed for workgroup %s: %w", workgroup, err)
		}
		if out.DbUser == nil || out.DbPassword == nil {
			return nil, nil, 0, "", fmt.Errorf("Redshift Serverless GetCredentials returned empty credentials for workgroup %s", workgroup)
		}
		dbUser = *out.DbUser
		dbPassword = *out.DbPassword
		expiration = out.Expiration
		deployment = "serverless"
	}

	leaseTTL, err := redshiftLeaseTTL(durationSeconds, expiration)
	if err != nil {
		return nil, nil, 0, "", err
	}

	rawData := map[string]interface{}{
		"auth_token": dbPassword,
		"db_user":    dbUser,
		"db_host":    dbEndpoint,
		"db_port":    dbPort,
		"region":     region,
		"deployment": deployment,
		"token_type": "redshift_iam",
	}

	if d.logger != nil {
		d.logger.Debug("generated Redshift IAM auth token",
			logger.String("spec", spec.Name),
			logger.String("deployment", deployment),
			logger.String("endpoint", dbEndpoint),
			logger.String("db_user", dbUser),
			logger.String("region", region),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, nil, leaseTTL, "", nil
}

// Revoke attempts to revoke a credential (best-effort)
// STS temporary credentials cannot be revoked via AWS API — they expire naturally.
func (d *AWSDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}

	// STS credentials expire naturally; nothing to revoke
	if strings.HasPrefix(leaseID, "sts:") {
		if d.logger != nil {
			d.logger.Debug("STS credentials expire naturally, skipping revocation",
				logger.String("lease_id", leaseID),
			)
		}
		return nil
	}

	// Secrets Manager secrets are static; nothing to revoke
	return nil
}

// Type returns the driver type
func (d *AWSDriver) Type() string {
	return credential.SourceTypeAWS
}

// Cleanup releases resources
func (d *AWSDriver) Cleanup(ctx context.Context) error {
	return nil
}

// SupportsRotation returns true if this driver can rotate its own IAM keys.
// Only permanent IAM keys (AKIA prefix) support rotation.
func (d *AWSDriver) SupportsRotation() bool {
	accessKeyID := credential.GetString(d.sourceConfig(), "access_key_id", "")
	return strings.HasPrefix(accessKeyID, "AKIA")
}

// STS accepts a session duration between 15 minutes and 12 hours. A role's own
// maximum may be lower, which stays AWS's error to raise — this only rejects what
// no role could accept.
const (
	minSTSSessionDuration = 15 * time.Minute
	maxSTSSessionDuration = 12 * time.Hour
)

// awsSessionSeconds converts a session duration for an STS DurationSeconds field.
// Rejecting out-of-range values here turns an opaque service-side ValidationError
// into one naming the config key, and stops an absurd duration from wrapping the
// int32 conversion into a negative number the service would read as something else
// entirely.
func awsSessionSeconds(dur time.Duration, field string) (int32, error) {
	if dur < minSTSSessionDuration {
		return 0, fmt.Errorf("'%s' must be at least %s (the AWS STS minimum), got %s", field, minSTSSessionDuration, dur)
	}
	if dur > maxSTSSessionDuration {
		return 0, fmt.Errorf("'%s' must be at most %s (the AWS STS maximum), got %s", field, maxSTSSessionDuration, dur)
	}
	return int32(dur.Seconds()), nil
}

// awsSessionNamePattern is the character set and length AWS accepts for a
// RoleSessionName.
var awsSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// awsSessionName resolves the session name for an assume-role and checks it
// against what AWS will accept. The default is derived from the spec's name, so a
// spec named in a way AWS rejects would otherwise fail every mint with a service
// error that never mentions the spec. Validated rather than sanitised: a silently
// rewritten session name is what shows up in the audit trail on the other side.
func awsSessionName(spec *credential.CredSpec) (string, error) {
	name := credential.GetString(spec.Config, "session_name", fmt.Sprintf("warden-%s", spec.Name))
	if !awsSessionNamePattern.MatchString(name) {
		return "", fmt.Errorf(
			"session name %q is not accepted by AWS (2-64 characters of [A-Za-z0-9_+=,.@-]); "+
				"set 'session_name' on the spec to override the default derived from its name", name)
	}
	return name, nil
}

// redshiftLeaseTTL derives the lease from what Redshift reported. An expiration
// already in the past means the credentials are dead on arrival — clock skew, or a
// cached response — and reporting the full requested duration for them would hand
// out a lease that was never valid. Mirrors the assume-role path, which rejects a
// non-positive TTL rather than substituting one.
func redshiftLeaseTTL(durationSeconds int, expiration *time.Time) (time.Duration, error) {
	if expiration == nil {
		return time.Duration(durationSeconds) * time.Second, nil
	}
	remaining := time.Until(*expiration)
	if remaining <= 0 {
		return 0, fmt.Errorf("Redshift credentials expired at %s, before they could be issued",
			expiration.UTC().Format(time.RFC3339))
	}
	return remaining, nil
}

// isIAMNoSuchEntity reports whether an error means the key is already gone, which
// for cleanup is success rather than failure — it is retried on a schedule, and a
// key deleted out of band should not keep it retrying forever.
func isIAMNoSuchEntity(err error) bool {
	var notFound *iamtypes.NoSuchEntityException
	return errors.As(err, &notFound)
}

// maxIAMKeysPerUser is the hard cap IAM places on an user's access keys, which is
// why a rotation has to free a slot before it can mint one.
const maxIAMKeysPerUser = 2

// makeRoomForNewKey frees a slot so CreateAccessKey can succeed, without
// destroying a key it cannot attribute to this source's own rotation.
//
// It acts only at the cap, touches at most one key per attempt, and deletes only
// a key that is already Inactive — the state an interrupted cleanup leaves
// behind, since CleanupRotation now deactivates before it deletes. An Active key
// that is not the current one is deactivated instead and the attempt stops with
// an error; the retry finds it Inactive and reclaims the slot. A failed prepare
// is retried on a backoff starting around twenty seconds, so that detour costs
// one short retry rather than a rotation period.
//
// The alternative — refusing to touch an Active key at all — would wedge rotation
// permanently, because two paths leave an Active key of this source's own behind:
// a crash between CreateAccessKey and the staged persist, and a staged activation
// exhausting its attempts, after which the manager resets to idle and prepares
// afresh. Deactivating someone else's key is disruptive but reversible; deleting
// it is not, and that is the trade being made.
func (d *AWSDriver) makeRoomForNewKey(ctx context.Context, iamClient *iam.Client,
	currentKeyID string, keys []iamtypes.AccessKeyMetadata) error {

	if len(keys) < maxIAMKeysPerUser {
		return nil
	}

	// The current key must be among the ones listed. If it is not, the source's
	// credentials belong to a different IAM user than the one being listed, so
	// every key here belongs to someone else — touch none of them and say why.
	var candidate *iamtypes.AccessKeyMetadata
	currentFound := false
	for i := range keys {
		keyID := aws.ToString(keys[i].AccessKeyId)
		if keyID == "" {
			continue
		}
		switch {
		case keyID == currentKeyID:
			currentFound = true
		case candidate == nil:
			candidate = &keys[i]
		}
	}
	if !currentFound {
		return fmt.Errorf(
			"IAM user holds %d access keys, none of them the configured access_key_id %s: "+
				"refusing to remove a key this source does not own",
			len(keys), truncateID(currentKeyID, 8))
	}
	if candidate == nil {
		return nil
	}
	candidateID := aws.ToString(candidate.AccessKeyId)

	if candidate.Status == iamtypes.StatusTypeInactive {
		if d.logger != nil {
			d.logger.Warn("deleting inactive orphaned IAM access key from an interrupted rotation",
				logger.String("orphaned_key_id", truncateID(candidateID, 8)),
			)
		}
		if _, err := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			AccessKeyId: candidate.AccessKeyId,
		}); err != nil {
			return fmt.Errorf("failed to delete orphaned IAM access key %s: %w", truncateID(candidateID, 8), err)
		}
		return nil
	}

	if d.logger != nil {
		d.logger.Warn("deactivating an active non-current IAM access key to free a rotation slot; "+
			"it will be deleted on the next rotation attempt",
			logger.String("key_id", truncateID(candidateID, 8)),
		)
	}
	if _, err := iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: candidate.AccessKeyId,
		Status:      iamtypes.StatusTypeInactive,
	}); err != nil {
		return fmt.Errorf("failed to deactivate non-current IAM access key %s: %w", truncateID(candidateID, 8), err)
	}

	return fmt.Errorf(
		"IAM user is at the %d-key limit and the non-current key %s was still active; "+
			"it has been deactivated and will be removed on the next rotation attempt. "+
			"If it is not this source's, reactivate it and give the source a dedicated IAM user",
		maxIAMKeysPerUser, truncateID(candidateID, 8))
}

// PrepareRotation creates a new IAM access key without destroying the old one.
// Both old and new keys remain valid during the overlap period.
// Returns activateAfter to allow time for AWS IAM eventual consistency propagation.
func (d *AWSDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	// Snapshot what the IAM calls need, then release: preparing must not modify
	// driver state, and holding the lock across this call would block every mint
	// on the source for as long as IAM takes to answer.
	d.authMu.Lock()
	cfg, baseCreds := d.credSource.Config, d.baseCreds
	d.authMu.Unlock()

	oldAccessKeyID := credential.GetString(cfg, "access_key_id", "")

	// Use base credentials (not elevated) for IAM operations on the user's own keys
	iamClient := d.newIAMClient(baseCreds)

	listResult, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to list IAM access keys: %w", err)
	}
	if err := d.makeRoomForNewKey(ctx, iamClient, oldAccessKeyID, listResult.AccessKeyMetadata); err != nil {
		return nil, nil, 0, err
	}

	// Create new access key
	result, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new IAM access key: %w", err)
	}

	if err := validNewIAMAccessKey(result.AccessKey); err != nil {
		return nil, nil, 0, err
	}
	newKey := result.AccessKey

	// Build new config (copy all, replace key fields). Copied from the snapshot,
	// not the live field: a commit landing mid-prepare would otherwise derive the
	// new config from one generation while cleanup names another generation's key.
	newConfig := make(map[string]string)
	for k, v := range cfg {
		newConfig[k] = v
	}
	newConfig["access_key_id"] = *newKey.AccessKeyId
	newConfig["secret_access_key"] = *newKey.SecretAccessKey

	// Cleanup config: the old key ID to delete later
	cleanupConfig := map[string]string{
		"access_key_id": oldAccessKeyID,
	}

	// Return activateAfter to let the rotation manager schedule activation
	// after AWS IAM eventual consistency has propagated the new key.
	activateAfter := credential.GetDuration(cfg, "activation_delay", DefaultAWSActivationDelay)

	if d.logger != nil {
		d.logger.Debug("prepared new IAM access key for rotation",
			logger.String("new_key_id", truncateID(*newKey.AccessKeyId, 8)),
			logger.String("activate_after", activateAfter.String()),
		)
	}

	return newConfig, cleanupConfig, activateAfter, nil
}

// CommitRotation activates the new IAM keys in driver state.
// Called after the new config has been persisted to storage.
func (d *AWSDriver) CommitRotation(ctx context.Context, newConfig map[string]string) error {
	newAccessKeyID := credential.GetString(newConfig, "access_key_id", "")
	newSecretAccessKey := credential.GetString(newConfig, "secret_access_key", "")
	newCreds := credentials.NewStaticCredentialsProvider(newAccessKeyID, newSecretAccessKey, "")

	// Verify before touching any driver state, and outside the lock so minting
	// keeps flowing while IAM answers. On failure this instance is left whole:
	// in-flight mints holding a generation finish on the credentials they started
	// with, rather than on a driver switched half-way to a key that does not work.
	//
	// That is the whole of what this buys, and it is worth being exact about:
	// the manager persists the new config before calling here and closes the
	// driver when it does, so a later request is served by a fresh instance built
	// from the persisted key whatever this call concludes. Durable state is the
	// manager's ordering to fix, not this driver's.
	probe := sts.NewFromConfig(d.awsConfig(newCreds), d.stsOptions())
	if _, err := probe.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return fmt.Errorf("failed to authenticate with new IAM keys: %w", err)
	}

	d.authMu.Lock()
	defer d.authMu.Unlock()

	d.credSource.Config = newConfig
	d.baseCreds = newCreds
	d.baseCredsVerified = true

	// Drop the elevated session and the client generation built from the old key.
	// The next mint rebuilds both; for an assume-role source that re-establishes
	// the session lazily, exactly as it does after an expiry.
	d.elevatedCreds = nil
	d.elevatedExpiry = time.Time{}
	d.clients = nil

	if d.logger != nil {
		d.logger.Debug("committed rotated IAM access key",
			logger.String("new_key_id", truncateID(newAccessKeyID, 8)),
		)
	}

	return nil
}

// CleanupRotation destroys the old IAM access key.
// Returns error if cleanup fails (will be retried by RotationManager).
func (d *AWSDriver) CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error {
	oldAccessKeyID := cleanupConfig["access_key_id"]
	if oldAccessKeyID == "" {
		return nil
	}

	// Snapshot and release, as PrepareRotation does — cleanup runs on a retry
	// schedule and must not hold minting up while IAM answers.
	d.authMu.Lock()
	baseCreds := d.baseCreds
	d.authMu.Unlock()

	// Matches PrepareRotation: the user's own keys, from the base credentials.
	iamClient := d.newIAMClient(baseCreds)

	// Deactivate before deleting, so an interrupted cleanup leaves the key in a
	// state the next prepare can attribute to this source. A key found Active is
	// indistinguishable from a stranger's, and prepare will not delete it.
	if _, err := iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: &oldAccessKeyID,
		Status:      iamtypes.StatusTypeInactive,
	}); err != nil && !isIAMNoSuchEntity(err) {
		return fmt.Errorf("failed to deactivate old IAM access key %s: %w", truncateID(oldAccessKeyID, 8), err)
	}

	_, err := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		AccessKeyId: &oldAccessKeyID,
	})
	if err != nil {
		// Already gone is the outcome cleanup wanted.
		if isIAMNoSuchEntity(err) {
			return nil
		}
		if d.logger != nil {
			d.logger.Warn("failed to delete old IAM access key during cleanup",
				logger.Err(err),
				logger.String("key_id", truncateID(oldAccessKeyID, 8)),
			)
		}
		return fmt.Errorf("failed to delete old IAM access key %s: %w", truncateID(oldAccessKeyID, 8), err)
	}

	if d.logger != nil {
		d.logger.Debug("destroyed old IAM access key",
			logger.String("key_id", truncateID(oldAccessKeyID, 8)),
		)
	}
	return nil
}

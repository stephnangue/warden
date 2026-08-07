package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	// AWS clients (rebuilt on auth changes)
	stsClient                *sts.Client
	secretsManagerClient     *secretsmanager.Client
	iamClient                *iam.Client
	redshiftClient           *redshift.Client
	redshiftServerlessClient *redshiftserverless.Client
	region                   string
	baseCredsVerified        bool

	// anonSTSClient calls sts:AssumeRoleWithWebIdentity, which is unsigned — it
	// takes no AWS credentials, only the web identity token. Built once in Create
	// so a keyless federation (auth_method=oidc_federation) source needs no IAM keys.
	anonSTSClient *sts.Client

	// smBaseEndpoint, when non-empty, overrides the Secrets Manager endpoint for
	// clients built from freshly federated credentials. Test-only: production leaves
	// it empty so the SDK resolves the real regional endpoint.
	smBaseEndpoint string
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

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AWSDriverFactory) SensitiveConfigFields() []string {
	return []string{"secret_access_key"}
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

	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: config,
		},
		logger:    log.WithSubsystem(credential.SourceTypeAWS),
		baseCreds: baseCreds,
		region:    region,
		// AssumeRoleWithWebIdentity is unsigned: anonymous credentials skip SigV4.
		anonSTSClient: sts.NewFromConfig(aws.Config{
			Region:      region,
			Credentials: aws.AnonymousCredentials{},
		}),
	}

	// A federation source holds no IAM keys: skip the eager credential probe. All
	// authentication happens per-request from the caller's identity assertion.
	if credential.GetString(config, "auth_method", awsAuthMethodStatic) == awsAuthMethodOIDCFederation {
		return driver, nil
	}

	// Perform initial authentication
	if err := driver.authenticate(context.Background()); err != nil {
		return nil, fmt.Errorf("AWS authentication failed: %w", err)
	}

	return driver, nil
}

// authenticate refreshes the elevated session if needed (thread-safe)
func (d *AWSDriver) authenticate(ctx context.Context) error {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	return d.authenticateLocked(ctx)
}

// authenticateLocked performs authentication without acquiring authMu.
// Caller must hold authMu.
func (d *AWSDriver) authenticateLocked(ctx context.Context) error {
	assumeRoleArn := credential.GetString(d.credSource.Config, "assume_role_arn", "")
	if assumeRoleArn == "" {
		// No role chaining; use base creds directly
		d.buildClients(d.baseCreds)

		// Verify base credentials are valid once with a lightweight API call
		if !d.baseCredsVerified {
			baseSTS := sts.NewFromConfig(aws.Config{
				Region:      d.region,
				Credentials: d.baseCreds,
			})
			if _, err := baseSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
				return fmt.Errorf("invalid AWS credentials: %w", err)
			}
			d.baseCredsVerified = true
		}

		return nil
	}

	// Check if elevated session is still valid (30-second buffer)
	if d.elevatedCreds != nil && time.Now().Add(30*time.Second).Before(d.elevatedExpiry) {
		return nil
	}

	// Call STS AssumeRole using base credentials
	sessionName := credential.GetString(d.credSource.Config, "session_name", "warden-source-session")
	sessionDuration := credential.GetDuration(d.credSource.Config, "session_duration", 1*time.Hour)
	externalID := credential.GetString(d.credSource.Config, "external_id", "")

	baseSTS := sts.NewFromConfig(aws.Config{
		Region:      d.region,
		Credentials: d.baseCreds,
	})

	input := &sts.AssumeRoleInput{
		RoleArn:         &assumeRoleArn,
		RoleSessionName: &sessionName,
		DurationSeconds: aws.Int32(int32(sessionDuration.Seconds())),
	}
	if externalID != "" {
		input.ExternalId = &externalID
	}

	result, err := baseSTS.AssumeRole(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to assume role %s: %w", assumeRoleArn, err)
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
	d.buildClients(elevatedProvider)

	if d.logger != nil {
		d.logger.Trace("authenticated to AWS via AssumeRole",
			logger.String("role_arn", assumeRoleArn),
			logger.String("expires_at", d.elevatedExpiry.Format(time.RFC3339)),
		)
	}

	return nil
}

// buildClients creates AWS service clients from the given credentials provider
func (d *AWSDriver) buildClients(creds aws.CredentialsProvider) {
	cfg := aws.Config{
		Region:      d.region,
		Credentials: creds,
	}
	d.stsClient = sts.NewFromConfig(cfg)
	d.secretsManagerClient = secretsmanager.NewFromConfig(cfg)
	d.iamClient = iam.NewFromConfig(cfg)
	d.redshiftClient = redshift.NewFromConfig(cfg)
	d.redshiftServerlessClient = redshiftserverless.NewFromConfig(cfg)
}

// MintCredential mints credentials using AWS based on credential spec
func (d *AWSDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	mintMethod := credential.GetString(spec.Config, "mint_method", "")
	authMethod := credential.GetString(d.credSource.Config, "auth_method", awsAuthMethodStatic)

	// A federation source holds no static credentials: it authenticates per-request
	// by federating a caller assertion, which flows through MintCredentialWithExchange.
	// Reaching the non-exchange path means the spec lacks subject_token_source. Fail
	// clearly rather than falling into authenticate() with empty keys and a misleading
	// "invalid AWS credentials" error.
	if authMethod == awsAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("auth_method=oidc_federation requires subject_token_source on the spec (warden_identity or auth_token); federated minting runs through the token-exchange path")
	}

	// Re-authenticate if needed
	if err := d.authenticate(ctx); err != nil {
		return nil, nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	switch mintMethod {
	case "sts_assume_role":
		return d.mintViaSTSAssumeRole(ctx, spec)
	case "secrets_manager":
		return d.mintViaSecretsManager(ctx, spec)
	case "rds_iam_token":
		return d.mintViaRDSIAMToken(ctx, spec)
	case "redshift_iam_token":
		return d.mintViaRedshiftIAMToken(ctx, spec)
	default:
		return nil, nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for AWS driver; use 'sts_assume_role', 'secrets_manager', 'rds_iam_token', or 'redshift_iam_token'", mintMethod)
	}
}

// mintViaSTSAssumeRole mints temporary credentials via STS AssumeRole
func (d *AWSDriver) mintViaSTSAssumeRole(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	roleArn, err := credential.GetStringRequired(spec.Config, "role_arn")
	if err != nil {
		return nil, nil, 0, "", err
	}

	sessionName := credential.GetString(spec.Config, "session_name", fmt.Sprintf("warden-%s", spec.Name))

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

	input := &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &sessionName,
		DurationSeconds: aws.Int32(int32(ttl.Seconds())),
	}

	if extID := credential.GetString(spec.Config, "external_id", ""); extID != "" {
		input.ExternalId = &extID
	}
	if policy := credential.GetString(spec.Config, "policy", ""); policy != "" {
		input.Policy = &policy
	}

	result, err := d.stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("STS AssumeRole failed for %s: %w", roleArn, err)
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
//   - subject_token_source=auth_token: Warden forwards the caller's origin-verified
//     inbound JWT untouched, and AWS validates it against the origin IdP's JWKS
//     (the role must federate that IdP directly, and its trust policy must accept the
//     token's audience — Warden pins nothing here since it did not mint the token).
//
// Either way the subject is one Warden verified inbound; an unverified caller token
// (subject_token_source=header) is never forwarded on Warden's authority.
//
// Supported mint methods over federation:
//   - sts_assume_role: the federated role credentials are themselves the issued credential.
//   - secrets_manager: the federated credentials read one secret and are then discarded.
func (d *AWSDriver) MintCredentialWithExchange(ctx context.Context, spec *credential.CredSpec, inputs *credential.ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	if credential.GetString(d.credSource.Config, "auth_method", awsAuthMethodStatic) != awsAuthMethodOIDCFederation {
		return nil, nil, 0, "", fmt.Errorf("aws: web-identity federation requires auth_method=oidc_federation on the source")
	}
	if inputs == nil || inputs.SubjectToken == "" {
		return nil, nil, 0, "", fmt.Errorf("aws: no subject token in exchange inputs")
	}
	if inputs.SubjectTokenOrigin != credential.ExchangeOriginVerified {
		return nil, nil, 0, "", fmt.Errorf("aws: web-identity federation requires a verified subject (subject_token_source=warden_identity or auth_token); a caller-supplied, unverified subject is rejected")
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
	sessionName := credential.GetString(spec.Config, "session_name", fmt.Sprintf("warden-%s", spec.Name))

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &roleArn,
		RoleSessionName:  &sessionName,
		WebIdentityToken: &webIdentityToken,
		DurationSeconds:  aws.Int32(int32(dur.Seconds())),
	}
	if policy := credential.GetString(spec.Config, "policy", ""); policy != "" {
		input.Policy = &policy
	}

	result, err := d.anonSTSClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("STS AssumeRoleWithWebIdentity failed for %s: %w", roleArn, err)
	}
	// A malformed 200 (e.g. an intercepting proxy) can omit the credentials block;
	// guard here so both consumers dereference a non-nil struct.
	if result.Credentials == nil {
		return nil, fmt.Errorf("STS AssumeRoleWithWebIdentity for %s returned no credentials", roleArn)
	}
	return result, nil
}

// credsFromWebIdentity shapes the temporary credentials from a web-identity assume-role
// into the mint tuple, for when the assumed-role credentials are themselves the issued
// credential (mint_method=sts_assume_role over oidc_federation).
func (d *AWSDriver) credsFromWebIdentity(spec *credential.CredSpec, result *sts.AssumeRoleWithWebIdentityOutput) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	roleArn := credential.GetString(spec.Config, "role_arn", "")
	sessionName := credential.GetString(spec.Config, "session_name", fmt.Sprintf("warden-%s", spec.Name))

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
// (e.g. freshly federated temporary credentials). smBaseEndpoint, when set, overrides the
// endpoint for tests.
func (d *AWSDriver) newSecretsManagerClient(creds aws.CredentialsProvider) *secretsmanager.Client {
	cfg := aws.Config{Region: d.region, Credentials: creds}
	if d.smBaseEndpoint != "" {
		return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
			o.BaseEndpoint = aws.String(d.smBaseEndpoint)
		})
	}
	return secretsmanager.NewFromConfig(cfg)
}

// mintViaSecretsManager fetches a secret using the source's authenticated client (static
// auth). The keyless (federation) path fetches with a temp-credential client instead.
func (d *AWSDriver) mintViaSecretsManager(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	return d.fetchSecret(ctx, d.secretsManagerClient, spec)
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

	// Apply json_key_map if provided (remap keys)
	jsonKeyMap := credential.GetString(spec.Config, "json_key_map", "")
	if jsonKeyMap != "" {
		secretData = applyKeyMap(secretData, jsonKeyMap)
	}

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

// applyKeyMap remaps keys in data according to a comma-separated "srcKey=destKey" map
func applyKeyMap(data map[string]interface{}, keyMapStr string) map[string]interface{} {
	result := make(map[string]interface{})
	pairs := strings.Split(keyMapStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			srcKey := strings.TrimSpace(parts[0])
			destKey := strings.TrimSpace(parts[1])
			if val, ok := data[srcKey]; ok {
				result[destKey] = val
			}
		}
	}
	return result
}

// mintViaRDSIAMToken generates a short-lived IAM authentication token for RDS.
// The token is a pre-signed STS GetCallerIdentity URL that RDS accepts as a password.
// This is a local SigV4 signing operation — no network call to RDS.
func (d *AWSDriver) mintViaRDSIAMToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
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

	token, err := rdsauth.BuildAuthToken(ctx, endpoint, region, dbUser, d.baseCreds)
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
func (d *AWSDriver) mintViaRedshiftIAMToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
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
		out, err := d.redshiftClient.GetClusterCredentialsWithIAM(ctx, input)
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
		out, err := d.redshiftServerlessClient.GetCredentials(ctx, input)
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

	leaseTTL := time.Duration(durationSeconds) * time.Second
	if expiration != nil {
		if remaining := time.Until(*expiration); remaining > 0 {
			leaseTTL = remaining
		}
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
	accessKeyID := credential.GetString(d.credSource.Config, "access_key_id", "")
	return strings.HasPrefix(accessKeyID, "AKIA")
}

// PrepareRotation creates a new IAM access key without destroying the old one.
// Both old and new keys remain valid during the overlap period.
// Returns activateAfter to allow time for AWS IAM eventual consistency propagation.
func (d *AWSDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, time.Duration, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	oldAccessKeyID := credential.GetString(d.credSource.Config, "access_key_id", "")

	// Use base credentials (not elevated) for IAM operations on the user's own keys
	baseCfg := aws.Config{
		Region:      d.region,
		Credentials: d.baseCreds,
	}
	iamClient := iam.NewFromConfig(baseCfg)

	// IAM users can have max 2 keys. If there are already 2 (e.g., from a
	// previously failed rotation), delete the orphaned key before creating a new one.
	listResult, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to list IAM access keys: %w", err)
	}
	if len(listResult.AccessKeyMetadata) >= 2 {
		for _, key := range listResult.AccessKeyMetadata {
			if *key.AccessKeyId != oldAccessKeyID {
				if d.logger != nil {
					d.logger.Warn("deleting orphaned IAM access key from previous failed rotation",
						logger.String("orphaned_key_id", truncateID(*key.AccessKeyId, 8)),
					)
				}
				_, err := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
					AccessKeyId: key.AccessKeyId,
				})
				if err != nil {
					return nil, nil, 0, fmt.Errorf("failed to delete orphaned IAM access key: %w", err)
				}
				break
			}
		}
	}

	// Create new access key
	result, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create new IAM access key: %w", err)
	}

	newKey := result.AccessKey

	// Build new config (copy all, replace key fields)
	newConfig := make(map[string]string)
	for k, v := range d.credSource.Config {
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
	activateAfter := credential.GetDuration(d.credSource.Config, "activation_delay", DefaultAWSActivationDelay)

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
	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Update internal config
	d.credSource.Config = newConfig

	// Rebuild base credentials provider
	newAccessKeyID := credential.GetString(newConfig, "access_key_id", "")
	newSecretAccessKey := credential.GetString(newConfig, "secret_access_key", "")
	d.baseCreds = credentials.NewStaticCredentialsProvider(newAccessKeyID, newSecretAccessKey, "")

	// Invalidate elevated session and base-creds flag to force full re-authentication
	d.elevatedCreds = nil
	d.elevatedExpiry = time.Time{}
	d.baseCredsVerified = false

	// Re-authenticate (we already hold authMu, so use locked variant)
	if err := d.authenticateLocked(ctx); err != nil {
		return fmt.Errorf("failed to authenticate with new IAM keys: %w", err)
	}

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

	d.authMu.Lock()
	defer d.authMu.Unlock()

	// Use base credentials (not elevated) for IAM operations on the user's own keys,
	// matching PrepareRotation. Elevated/assumed-role creds operate as the role
	// principal and cannot delete the IAM user's access keys.
	baseCfg := aws.Config{
		Region:      d.region,
		Credentials: d.baseCreds,
	}
	iamClient := iam.NewFromConfig(baseCfg)

	_, err := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		AccessKeyId: &oldAccessKeyID,
	})
	if err != nil {
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

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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

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
	stsClient            *sts.Client
	secretsManagerClient *secretsmanager.Client
	iamClient            *iam.Client
	region               string
	baseCredsVerified    bool
}

// AWSDriverFactory creates AWSDriver instances
type AWSDriverFactory struct{}

// Type returns the driver type
func (f *AWSDriverFactory) Type() string {
	return credential.SourceTypeAWS
}

// ValidateConfig validates AWS driver configuration
func (f *AWSDriverFactory) ValidateConfig(config map[string]string) error {
	if err := credential.ValidateRequired(config, "access_key_id", "secret_access_key", "region"); err != nil {
		return err
	}

	// Validate session_duration if provided
	if sd := credential.GetString(config, "session_duration", ""); sd != "" {
		if _, err := time.ParseDuration(sd); err != nil {
			return fmt.Errorf("invalid session_duration '%s': %w", sd, err)
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *AWSDriverFactory) SensitiveConfigFields() []string {
	return []string{"secret_access_key"}
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
}

// MintCredential mints credentials using AWS based on credential spec
func (d *AWSDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Re-authenticate if needed
	if err := d.authenticate(ctx); err != nil {
		return nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "sts_assume_role":
		return d.mintViaSTSAssumeRole(ctx, spec)
	case "secrets_manager":
		return d.mintViaSecretsManager(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for AWS driver; use 'sts_assume_role' or 'secrets_manager'", mintMethod)
	}
}

// mintViaSTSAssumeRole mints temporary credentials via STS AssumeRole
func (d *AWSDriver) mintViaSTSAssumeRole(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	roleArn, err := credential.GetStringRequired(spec.Config, "role_arn")
	if err != nil {
		return nil, 0, "", err
	}

	sessionName := credential.GetString(spec.Config, "session_name", fmt.Sprintf("warden-%s", spec.Name))

	ttlStr := credential.GetString(spec.Config, "ttl", "1h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid ttl '%s': %w", ttlStr, err)
	}

	// Validate TTL against spec bounds
	if spec.MinTTL > 0 && ttl < spec.MinTTL {
		return nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", ttl, spec.MinTTL)
	}
	if spec.MaxTTL > 0 && ttl > spec.MaxTTL {
		return nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", ttl, spec.MaxTTL)
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
		return nil, 0, "", fmt.Errorf("STS AssumeRole failed for %s: %w", roleArn, err)
	}

	creds := result.Credentials
	leaseTTL := time.Until(*creds.Expiration)

	// Validate lease TTL is positive (guards against clock skew or cached responses)
	if leaseTTL <= 0 {
		return nil, 0, "", fmt.Errorf("STS credentials already expired or have invalid expiration time")
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

	if d.logger != nil {
		d.logger.Debug("generated STS temporary credentials",
			logger.String("spec", spec.Name),
			logger.String("role_arn", roleArn),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, leaseTTL, leaseID, nil
}

// mintViaSecretsManager fetches a secret from AWS Secrets Manager
func (d *AWSDriver) mintViaSecretsManager(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	secretID, err := credential.GetStringRequired(spec.Config, "secret_id")
	if err != nil {
		return nil, 0, "", err
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

	result, err := d.secretsManagerClient.GetSecretValue(ctx, input)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to get secret '%s': %w", secretID, err)
	}

	if result.SecretString == nil {
		return nil, 0, "", fmt.Errorf("secret '%s' has no string value (binary secrets not supported)", secretID)
	}

	var secretData map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secretData); err != nil {
		return nil, 0, "", fmt.Errorf("failed to parse secret JSON: %w", err)
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
	return secretData, 0, "", nil
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
func (d *AWSDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, error) {
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
		return nil, nil, fmt.Errorf("failed to list IAM access keys: %w", err)
	}
	if len(listResult.AccessKeyMetadata) >= 2 {
		for _, key := range listResult.AccessKeyMetadata {
			if *key.AccessKeyId != oldAccessKeyID {
				if d.logger != nil {
					d.logger.Warn("deleting orphaned IAM access key from previous failed rotation",
						logger.String("orphaned_key_id", (*key.AccessKeyId)[:8]+"..."),
					)
				}
				_, err := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
					AccessKeyId: key.AccessKeyId,
				})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to delete orphaned IAM access key: %w", err)
				}
				break
			}
		}
	}

	// Create new access key
	result, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new IAM access key: %w", err)
	}

	newKey := result.AccessKey

	// Wait for the new credentials to fully propagate at AWS (eventual consistency).
	// AWS IAM has two levels of consistency:
	// 1. STS recognition (GetCallerIdentity works) - usually fast
	// 2. IAM permission propagation (can perform IAM operations) - can take longer
	// We must verify BOTH before considering the key ready, otherwise operations
	// like MintCredential or CleanupRotation may fail after CommitRotation.
	newCreds := credentials.NewStaticCredentialsProvider(*newKey.AccessKeyId, *newKey.SecretAccessKey, "")
	newCfg := aws.Config{
		Region:      d.region,
		Credentials: newCreds,
	}
	newSTS := sts.NewFromConfig(newCfg)
	newIAM := iam.NewFromConfig(newCfg)

	propagated := false
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(4 * time.Second)

		// Check 1: STS recognizes the new credentials
		if _, err := newSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
			if d.logger != nil {
				d.logger.Trace("waiting for new IAM key to propagate (STS)",
					logger.String("new_key_id", (*newKey.AccessKeyId)[:8]+"..."),
					logger.Int("attempt", attempt+1),
				)
			}
			continue
		}

		// Check 2: IAM permissions are active (can list own keys)
		if _, err := newIAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{}); err != nil {
			if d.logger != nil {
				d.logger.Trace("waiting for new IAM key to propagate (IAM)",
					logger.String("new_key_id", (*newKey.AccessKeyId)[:8]+"..."),
					logger.Int("attempt", attempt+1),
				)
			}
			continue
		}

		propagated = true
		break
	}
	if !propagated {
		return nil, nil, fmt.Errorf("new IAM access key %s did not fully propagate within 120s", (*newKey.AccessKeyId)[:8]+"...")
	}

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

	if d.logger != nil {
		d.logger.Debug("prepared new IAM access key for rotation",
			logger.String("new_key_id", (*newKey.AccessKeyId)[:8]+"..."),
		)
	}

	return newConfig, cleanupConfig, nil
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

	// Invalidate elevated session to force re-authentication with new keys
	d.elevatedCreds = nil
	d.elevatedExpiry = time.Time{}

	// Re-authenticate (we already hold authMu, so use locked variant)
	if err := d.authenticateLocked(ctx); err != nil {
		return fmt.Errorf("failed to authenticate with new IAM keys: %w", err)
	}

	if d.logger != nil {
		d.logger.Info("committed rotated IAM access key",
			logger.String("new_key_id", newAccessKeyID[:8]+"..."),
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

	// Use current (new) base credentials to delete the old key
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
				logger.String("key_id", oldAccessKeyID[:8]+"..."),
			)
		}
		return fmt.Errorf("failed to delete old IAM access key %s: %w", oldAccessKeyID[:8]+"...", err)
	}

	if d.logger != nil {
		d.logger.Debug("destroyed old IAM access key",
			logger.String("key_id", oldAccessKeyID[:8]+"..."),
		)
	}
	return nil
}

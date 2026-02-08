package drivers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// VaultDriver fetches credentials from HashiCorp Vault
// Supports: KV, AWS engine, Azure engine, GCP engine
type VaultDriver struct {
	vault         *api.Client
	credSource    *credential.CredSource
	logger        *logger.GatedLogger
	tokenExpireAt time.Time  // Tracks when the current token expires
	authMu        sync.Mutex // Protects tokenExpireAt and authentication
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

	driver := &VaultDriver{
		vault:      apiClient,
		credSource: credSource,
		logger:     logger.WithSubsystem(credential.SourceTypeVault),
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

// ValidateConfig validates Vault driver configuration
func (f *VaultDriverFactory) ValidateConfig(config map[string]string) error {
	// Validate required fields
	if _, err := credential.GetStringRequired(config, "vault_address"); err != nil {
		return err
	}

	authMethod := credential.GetString(config, "auth_method", "")
	if authMethod != "" && authMethod != "approle" {
		return fmt.Errorf("unsupported auth_method: %s (only 'approle' is currently supported)", authMethod)
	}

	if authMethod == "approle" {
		// Validate required approle fields
		if err := credential.ValidateRequired(config, "role_id", "secret_id", "approle_mount", "role_name"); err != nil {
			return err
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of config keys that should be masked in output
func (f *VaultDriverFactory) SensitiveConfigFields() []string {
	return []string{"token", "secret_id", "secret_id_accessor"}
}

// authenticate performs Vault authentication only if needed (thread-safe)
func (d *VaultDriver) authenticate(ctx context.Context) error {
	authMethod := credential.GetString(d.credSource.Config, "auth_method", "")

	switch authMethod {
	case "approle":
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
	case "":
		// No auth method, assume token is already set
		return nil
	default:
		return fmt.Errorf("unsupported auth method: %s", authMethod)
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
func (d *VaultDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Re-authenticate if needed
	if err := d.authenticate(ctx); err != nil {
		return nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	mintMethod := credential.GetString(spec.Config, "mint_method", "")

	switch mintMethod {
	case "kv2_static":
		return d.fetchStaticKVSecret(ctx, spec)
	case "dynamic_database":
		return d.fetchDynamicDatabaseCreds(ctx, spec)
	case "dynamic_aws":
		return d.fetchDynamicAWSCreds(ctx, spec)
	case "vault_token":
		return d.fetchDynamicVaultToken(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported mint_method '%s' for Vault driver; use 'kv2_static', 'dynamic_database', 'dynamic_aws', or 'vault_token'", mintMethod)
	}
}

// fetchStaticKVSecret fetches static secrets from Vault KV v2
func (d *VaultDriver) fetchStaticKVSecret(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	kv2Mount := credential.GetString(spec.Config, "kv2_mount", "")
	secretPath := credential.GetString(spec.Config, "secret_path", "")

	if kv2Mount == "" || secretPath == "" {
		return nil, 0, "", fmt.Errorf("kv2_mount and secret_path are required for static KV credentials")
	}

	secret, err := d.vault.KVv2(kv2Mount).Get(ctx, secretPath)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to read KV secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, 0, "", fmt.Errorf("no secret found at path '%s' on mount '%s'", secretPath, kv2Mount)
	}

	if d.logger != nil {
		d.logger.Trace("fetched static secret from Vault KV",
			logger.String("spec", spec.Name),
			logger.String("mount", kv2Mount),
			logger.String("path", secretPath),
		)
	}

	// Return raw data (static, no lease)
	return secret.Data, 0, "", nil
}

// fetchDynamicDatabaseCreds fetches dynamic database credentials from Vault database engine
func (d *VaultDriver) fetchDynamicDatabaseCreds(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	dbMount := credential.GetString(spec.Config, "database_mount", "")
	roleName := credential.GetString(spec.Config, "role_name", "")

	if dbMount == "" || roleName == "" {
		return nil, 0, "", fmt.Errorf("database_mount and role_name are required for dynamic database credentials")
	}

	// Read credentials
	path := fmt.Sprintf("%s/creds/%s", dbMount, roleName)
	secret, err := d.vault.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to generate database credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, 0, "", fmt.Errorf("no credentials returned for role '%s' on mount '%s'", roleName, dbMount)
	}

	leaseTTL := time.Duration(secret.LeaseDuration) * time.Second

	// Validate lease TTL is positive
	if leaseTTL <= 0 {
		return nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for database credentials on mount '%s'", dbMount)
	}

	// Add optional database name if provided in config
	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}
	database := credential.GetString(spec.Config, "database", "")
	if database != "" {
		rawData["database"] = database
	}

	if d.logger != nil {
		d.logger.Trace("generated dynamic database credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", dbMount),
			logger.String("vault_role", roleName),
			logger.String("lease_id", secret.LeaseID),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, leaseTTL, secret.LeaseID, nil
}

// fetchDynamicAWSCreds fetches dynamic AWS credentials from Vault AWS engine
func (d *VaultDriver) fetchDynamicAWSCreds(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	awsMount := credential.GetString(spec.Config, "aws_mount", "")
	roleName := credential.GetString(spec.Config, "role_name", "")

	if awsMount == "" || roleName == "" {
		return nil, 0, "", fmt.Errorf("aws_mount and role_name are required for dynamic AWS credentials")
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
			return nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}

		// Validate TTL against spec bounds
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			return nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", parsedTTL, spec.MinTTL)
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			return nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", parsedTTL, spec.MaxTTL)
		}

		data["ttl"] = parsedTTL.String()
	}

	var secret *api.Secret
	var err error

	if len(data) > 0 {
		// POST request with parameters
		secret, err = d.vault.Logical().WriteWithContext(ctx, path, data)
	} else {
		// GET request without parameters
		secret, err = d.vault.Logical().ReadWithContext(ctx, path)
	}

	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to generate AWS credentials: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, 0, "", fmt.Errorf("no credentials returned for role '%s' on mount '%s'", roleName, awsMount)
	}

	leaseTTL := time.Duration(secret.LeaseDuration) * time.Second

	// Validate lease TTL is positive
	if leaseTTL <= 0 {
		return nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for AWS credentials on mount '%s'", awsMount)
	}

	// Add credential source
	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}
	rawData["cred_source"] = d.vault.Address()

	if d.logger != nil {
		d.logger.Debug("generated dynamic AWS credentials from Vault",
			logger.String("spec", spec.Name),
			logger.String("mount", awsMount),
			logger.String("vault_role", roleName),
			logger.String("lease_id", secret.LeaseID),
			logger.String("lease_ttl", leaseTTL.String()),
		)
	}

	return rawData, leaseTTL, secret.LeaseID, nil
}

// fetchDynamicVaultToken generates a Vault token via auth/token/create/{role}
func (d *VaultDriver) fetchDynamicVaultToken(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	tokenRole := credential.GetString(spec.Config, "token_role", "")

	if tokenRole == "" {
		return nil, 0, "", fmt.Errorf("token_role is required for dynamic Vault token generation")
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
			return nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}

		// Validate TTL against spec bounds
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			return nil, 0, "", fmt.Errorf("requested TTL %s is below minimum %s", parsedTTL, spec.MinTTL)
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			return nil, 0, "", fmt.Errorf("requested TTL %s exceeds maximum %s", parsedTTL, spec.MaxTTL)
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
	secret, err := d.vault.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create Vault token: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, 0, "", fmt.Errorf("no token returned for role '%s'", tokenRole)
	}

	// Extract token TTL from auth response
	leaseTTL := time.Duration(secret.Auth.LeaseDuration) * time.Second

	// Validate lease TTL is positive
	if leaseTTL <= 0 {
		return nil, 0, "", fmt.Errorf("Vault returned invalid lease duration for token role '%s'", tokenRole)
	}

	// Build raw data with token
	rawData := map[string]interface{}{
		"token":        secret.Auth.ClientToken,
		"client_token": secret.Auth.ClientToken, // Alternative field name
		"accessor":     secret.Auth.Accessor,
		"policies":     secret.Auth.Policies,
		"renewable":    secret.Auth.Renewable,
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
	return rawData, leaseTTL, secret.Auth.Accessor, nil
}

// Revoke revokes a Vault lease or token accessor
func (d *VaultDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil // Nothing to revoke
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
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

// Type returns the driver type
func (d *VaultDriver) Type() string {
	return "vault"
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
func (d *VaultDriver) PrepareRotation(ctx context.Context) (map[string]string, map[string]string, error) {
	d.authMu.Lock()
	defer d.authMu.Unlock()

	authMethod := credential.GetString(d.credSource.Config, "auth_method", "")
	if authMethod != "approle" {
		return nil, nil, fmt.Errorf("rotation only supported for approle auth method, got: %s", authMethod)
	}

	approleMount := credential.GetString(d.credSource.Config, "approle_mount", "")
	roleName := credential.GetString(d.credSource.Config, "role_name", "")
	oldAccessor := credential.GetString(d.credSource.Config, "secret_id_accessor", "")

	if roleName == "" {
		return nil, nil, fmt.Errorf("role_name is required for AppRole rotation")
	}

	// Generate new secret_id (old one still valid - no disruption)
	generatePath := fmt.Sprintf("auth/%s/role/%s/secret-id", approleMount, roleName)
	secret, err := d.vault.Logical().WriteWithContext(ctx, generatePath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new secret_id: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil, fmt.Errorf("no data returned when generating new secret_id")
	}

	newSecretID, ok := secret.Data["secret_id"].(string)
	if !ok || newSecretID == "" {
		return nil, nil, fmt.Errorf("secret_id not found in response")
	}

	newAccessor, ok := secret.Data["secret_id_accessor"].(string)
	if !ok || newAccessor == "" {
		return nil, nil, fmt.Errorf("secret_id_accessor not found in response")
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
			logger.String("new_accessor", newAccessor[:8]+"..."),
		)
	}

	return newConfig, cleanupConfig, nil
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
		d.logger.Info("committed rotated AppRole secret_id",
			logger.String("role_name", roleName),
			logger.String("new_accessor", newAccessor[:8]+"..."),
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
				logger.String("accessor", oldAccessor[:8]+"..."),
			)
		}
		return fmt.Errorf("failed to destroy old secret_id: %w", err)
	}

	if d.logger != nil {
		d.logger.Debug("destroyed old secret_id",
			logger.String("accessor", oldAccessor[:8]+"..."),
		)
	}
	return nil
}

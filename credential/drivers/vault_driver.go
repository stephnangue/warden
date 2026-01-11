package drivers

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// VaultDriver fetches credentials from HashiCorp Vault
// Supports: KV v2, Database engine, AWS engine, Azure engine, GCP engine
type VaultDriver struct {
	vault      *api.Client
	credSource *credential.CredSource
	logger     *logger.GatedLogger
}

// VaultDriverFactory creates VaultDriver instances
type VaultDriverFactory struct{}

// Type returns the driver type
func (f *VaultDriverFactory) Type() string {
	return "hashicorp_vault"
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
		Type:   "hashicorp_vault",
		Config: config,
	}

	driver := &VaultDriver{
		vault:      apiClient,
		credSource: credSource,
		logger:     logger,
	}

	// Perform initial authentication
	if authMethod != "" {
		if err := driver.authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("Vault authentication failed: %w", err)
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
		if err := credential.ValidateRequired(config, "role_id", "secret_id", "approle_mount"); err != nil {
			return err
		}
	}

	return nil
}

// authenticate performs Vault authentication
func (d *VaultDriver) authenticate(ctx context.Context) error {
	authMethod := credential.GetString(d.credSource.Config, "auth_method", "")

	switch authMethod {
	case "approle":
		return d.loginViaApprole(ctx)
	case "":
		// No auth method, assume token is already set
		return nil
	default:
		return fmt.Errorf("unsupported auth method: %s", authMethod)
	}
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

	if d.logger != nil {
		d.logger.Debug("authenticated to Vault via AppRole",
			logger.String("approle_mount", approleMount),
		)
	}

	return nil
}

// MintCredential mints credential using Hashicorp Vault based on credential spec type
func (d *VaultDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Re-authenticate if needed
	if err := d.authenticate(ctx); err != nil {
		return nil, 0, "", fmt.Errorf("authentication failed: %w", err)
	}

	// Route based on credential type
	switch spec.Type {
	case credential.TypeDatabaseUserPass, "static_database_userpass", "dynamic_database_userpass":
		// Determine if static or dynamic based on presence of database_mount
		databaseMount := credential.GetString(spec.SourceParams, "database_mount", "")
		if databaseMount != "" {
			return d.fetchDynamicDatabaseCreds(ctx, spec)
		}
		return d.fetchStaticKVSecret(ctx, spec)
	case credential.TypeAWSAccessKeys, "static_aws_access_keys", "dynamic_aws_access_keys":
		// Determine if static or dynamic based on presence of aws_mount
		awsMount := credential.GetString(spec.SourceParams, "aws_mount", "")
		if awsMount != "" {
			return d.fetchDynamicAWSCreds(ctx, spec)
		}
		return d.fetchStaticKVSecret(ctx, spec)
	default:
		return nil, 0, "", fmt.Errorf("unsupported credential type for Vault: %s", spec.Type)
	}
}

// fetchStaticKVSecret fetches static secrets from Vault KV v2
func (d *VaultDriver) fetchStaticKVSecret(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	kv2Mount := credential.GetString(spec.SourceParams, "kv2_mount", "")
	secretPath := credential.GetString(spec.SourceParams, "secret_path", "")

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
		d.logger.Debug("fetched static secret from Vault KV",
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
	dbMount := credential.GetString(spec.SourceParams, "database_mount", "")
	roleName := credential.GetString(spec.SourceParams, "role_name", "")

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

	// Add optional database name if provided in config
	rawData := make(map[string]interface{})
	for k, v := range secret.Data {
		rawData[k] = v
	}
	database := credential.GetString(spec.SourceParams, "database", "")
	if database != "" {
		rawData["database"] = database
	}

	if d.logger != nil {
		d.logger.Debug("generated dynamic database credentials from Vault",
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
	awsMount := credential.GetString(spec.SourceParams, "aws_mount", "")
	roleName := credential.GetString(spec.SourceParams, "role_name", "")

	if awsMount == "" || roleName == "" {
		return nil, 0, "", fmt.Errorf("aws_mount and role_name are required for dynamic AWS credentials")
	}

	// Build request path and data
	path := fmt.Sprintf("%s/creds/%s", awsMount, roleName)
	data := make(map[string]interface{})

	// Add optional parameters
	roleArn := credential.GetString(spec.SourceParams, "role_arn", "")
	if roleArn != "" {
		data["role_arn"] = roleArn
	}
	roleSessionName := credential.GetString(spec.SourceParams, "role_session_name", "")
	if roleSessionName != "" {
		data["role_session_name"] = roleSessionName
	}
	ttl := credential.GetString(spec.SourceParams, "ttl", "")
	if ttl != "" {
		// Parse and validate TTL against min/max bounds
		parsedTTL, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, 0, "", fmt.Errorf("invalid ttl format '%s': %w", ttl, err)
		}

		// Clamp TTL to min/max bounds if they are set
		if spec.MinTTL > 0 && parsedTTL < spec.MinTTL {
			parsedTTL = spec.MinTTL
			if d.logger != nil {
				d.logger.Debug("TTL adjusted to minimum",
					logger.String("requested", ttl),
					logger.String("adjusted", parsedTTL.String()),
				)
			}
		}
		if spec.MaxTTL > 0 && parsedTTL > spec.MaxTTL {
			parsedTTL = spec.MaxTTL
			if d.logger != nil {
				d.logger.Debug("TTL adjusted to maximum",
					logger.String("requested", ttl),
					logger.String("adjusted", parsedTTL.String()),
				)
			}
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

// Revoke revokes a Vault lease
func (d *VaultDriver) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil // Nothing to revoke
	}

	if err := d.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed before revocation: %w", err)
	}

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

// Type returns the driver type
func (d *VaultDriver) Type() string {
	return "vault"
}

// Cleanup releases resources
func (d *VaultDriver) Cleanup(ctx context.Context) error {
	// Vault client doesn't need explicit cleanup
	return nil
}

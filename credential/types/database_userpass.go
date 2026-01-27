package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// DatabaseUserPassCredType handles database username/password credentials
type DatabaseUserPassCredType struct{}

// Metadata returns the type's metadata
func (t *DatabaseUserPassCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeDatabaseUserPass,
		Category:    credential.CategoryDatabase,
		Description: "Database username and password credentials for MySQL, PostgreSQL, Oracle, etc.",
		DefaultTTL:  1 * time.Hour,
	}
}

// ValidateConfig validates the Config for a database credential spec
// sourceType determines the validation rules:
// - "local": only username, password, and optional database are allowed
// - "vault": requires database_mount/role_name (dynamic) or kv2_mount/secret_path (static KV)
func (t *DatabaseUserPassCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeLocal:
		return t.validateLocalConfig(config)
	case credential.SourceTypeVault:
		return t.validateVaultConfig(config)
	default:
		return fmt.Errorf("unsupported source type '%s' for database credentials", sourceType)
	}
}

// validateLocalConfig validates config for local source
// Only username, password, and optional database are accepted
func (t *DatabaseUserPassCredType) validateLocalConfig(config map[string]string) error {
	// Define allowed fields
	allowedFields := map[string]bool{
		"username": true,
		"password": true,
		"database": true,
	}

	// Check for invalid fields first and provide helpful error
	var invalidFields []string
	for key := range config {
		if !allowedFields[key] {
			invalidFields = append(invalidFields, key)
		}
	}
	if len(invalidFields) > 0 {
		return fmt.Errorf("invalid config field(s) %v; expected: username, password (optional: database)", invalidFields)
	}

	// Validate required fields
	if err := credential.ValidateRequired(config, "username", "password"); err != nil {
		return err
	}

	return nil
}

// validateVaultConfig validates config for Vault source
// Requires either database_mount (dynamic) or kv2_mount (static KV)
func (t *DatabaseUserPassCredType) validateVaultConfig(config map[string]string) error {
	databaseMount := credential.GetString(config, "database_mount", "")
	kv2Mount := credential.GetString(config, "kv2_mount", "")

	// Must specify either database_mount (dynamic) or kv2_mount (static)
	if databaseMount == "" && kv2Mount == "" {
		return fmt.Errorf("either 'database_mount' (for dynamic credentials) or 'kv2_mount' (for static credentials) must be specified")
	}

	// Can't specify both
	if databaseMount != "" && kv2Mount != "" {
		return fmt.Errorf("cannot specify both 'database_mount' and 'kv2_mount' - choose dynamic or static")
	}

	// Dynamic database credentials validation
	if databaseMount != "" {
		if err := credential.ValidateRequired(config, "database_mount", "role_name"); err != nil {
			return fmt.Errorf("dynamic database credentials require: %w", err)
		}
	}

	// Static KV credentials validation
	if kv2Mount != "" {
		if err := credential.ValidateRequired(config, "kv2_mount", "secret_path"); err != nil {
			return fmt.Errorf("static KV credentials require: %w", err)
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *DatabaseUserPassCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract username
	username, ok := rawData["username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("%w: missing or invalid username", credential.ErrInvalidCredential)
	}

	// Extract password
	password, ok := rawData["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("%w: missing or invalid password", credential.ErrInvalidCredential)
	}

	// Extract optional database name
	database, _ := rawData["database"].(string)

	cred := &credential.Credential{
		Type:      credential.TypeDatabaseUserPass,
		Category:  credential.CategoryDatabase,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0, // Dynamic credentials are revocable
		Data: map[string]string{
			"username": username,
			"password": password,
		},
	}

	// Add database if provided
	if database != "" {
		cred.Data["database"] = database
	}

	// Add lease info for dynamic credentials
	if leaseTTL > 0 {
		cred.Data["lease_ttl"] = fmt.Sprintf("%d", int(leaseTTL.Seconds()))
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *DatabaseUserPassCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeDatabaseUserPass {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeDatabaseUserPass, cred.Type)
	}

	// Validate required fields
	username, ok := cred.Data["username"]
	if !ok || username == "" {
		return fmt.Errorf("%w: missing username", credential.ErrInvalidCredential)
	}

	password, ok := cred.Data["password"]
	if !ok || password == "" {
		return fmt.Errorf("%w: missing password", credential.ErrInvalidCredential)
	}

	// Validate username format (basic check)
	if len(username) > 255 {
		return fmt.Errorf("%w: username too long (max 255 characters)", credential.ErrInvalidCredential)
	}

	// Validate password format (basic check)
	if len(password) < 1 {
		return fmt.Errorf("%w: password cannot be empty", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort)
func (t *DatabaseUserPassCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	// Only dynamic credentials with a lease can be revoked
	if cred.LeaseID == "" {
		return nil // Static credentials cannot be revoked
	}

	// Attempt revocation through the driver
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}

	return nil
}

// CanRotate indicates if this type supports proactive rotation
func (t *DatabaseUserPassCredType) CanRotate() bool {
	return true // Database credentials support rotation
}

// FieldSchemas returns metadata about the credential's data fields
func (t *DatabaseUserPassCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"username": {
			Description: "Database username",
			Sensitive:   false,
		},
		"password": {
			Description: "Database password",
			Sensitive:   true,
		},
		"database": {
			Description: "Database name",
			Sensitive:   false,
		},
		"lease_ttl": {
			Description: "Lease time-to-live in seconds",
			Sensitive:   false,
		},
	}
}

package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
)

// AWSIAMAccessKeysCredType handles AWS IAM access keys (static and STS temporary)
type AWSIAMAccessKeysCredType struct{}

// Metadata returns the type's metadata
func (t *AWSIAMAccessKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeAWSAccessKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "AWS IAM access keys (static and STS temporary credentials)",
		DefaultTTL:  12 * time.Hour,
	}
}

// ValidateSourceParams validates the SourceParams for an AWS credential spec
func (t *AWSIAMAccessKeysCredType) ValidateSourceParams(params map[string]string, sourceName string) error {
	// Check if it's dynamic or static based on presence of aws_mount
	awsMount := credential.GetString(params, "aws_mount", "")
	kv2Mount := credential.GetString(params, "kv2_mount", "")

	// Must specify either aws_mount (dynamic) or kv2_mount (static)
	if awsMount == "" && kv2Mount == "" {
		return fmt.Errorf("either 'aws_mount' (for dynamic credentials) or 'kv2_mount' (for static credentials) must be specified")
	}

	// Can't specify both
	if awsMount != "" && kv2Mount != "" {
		return fmt.Errorf("cannot specify both 'aws_mount' and 'kv2_mount' - choose dynamic or static")
	}

	// Dynamic AWS credentials validation
	if awsMount != "" {
		if err := credential.ValidateRequired(params, "aws_mount", "role_name"); err != nil {
			return fmt.Errorf("dynamic AWS credentials require: %w", err)
		}
	}

	// Static KV credentials validation
	if kv2Mount != "" {
		if err := credential.ValidateRequired(params, "kv2_mount", "secret_path"); err != nil {
			return fmt.Errorf("static KV credentials require: %w", err)
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *AWSIAMAccessKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract access_key_id (may be named "access_key" from Vault AWS engine)
	accessKeyID, ok := rawData["access_key_id"].(string)
	if !ok || accessKeyID == "" {
		// Try alternative field name used by Vault AWS engine
		accessKeyID, ok = rawData["access_key"].(string)
		if !ok || accessKeyID == "" {
			return nil, fmt.Errorf("%w: missing or invalid access_key_id", credential.ErrInvalidCredential)
		}
	}

	// Extract secret_access_key (may be named "secret_key" from Vault AWS engine)
	secretAccessKey, ok := rawData["secret_access_key"].(string)
	if !ok || secretAccessKey == "" {
		// Try alternative field name used by Vault AWS engine
		secretAccessKey, ok = rawData["secret_key"].(string)
		if !ok || secretAccessKey == "" {
			return nil, fmt.Errorf("%w: missing or invalid secret_access_key", credential.ErrInvalidCredential)
		}
	}

	cred := &credential.Credential{
		Type:       credential.TypeAWSAccessKeys,
		Category:   credential.CategoryCloudIAM,
		LeaseTTL:   leaseTTL,
		LeaseID:    leaseID,
		IssuedAt:   time.Now(),
		Revocable:  leaseTTL > 0, // STS temporary credentials are revocable
		Data: map[string]string{
			"access_key_id":     accessKeyID,
			"secret_access_key": secretAccessKey,
		},
	}

	// Extract optional session token (for STS temporary credentials)
	if sessionToken, ok := rawData["session_token"].(string); ok && sessionToken != "" {
		cred.Data["session_token"] = sessionToken
	}

	// Extract optional security token (alternative name for session_token)
	if securityToken, ok := rawData["security_token"].(string); ok && securityToken != "" {
		cred.Data["security_token"] = securityToken
	}

	// Extract optional credential source
	if credSource, ok := rawData["cred_source"].(string); ok && credSource != "" {
		cred.SourceType = credSource
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *AWSIAMAccessKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeAWSAccessKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeAWSAccessKeys, cred.Type)
	}

	// Validate access_key_id
	accessKeyID, ok := cred.Data["access_key_id"]
	if !ok || accessKeyID == "" {
		return fmt.Errorf("%w: missing access_key_id", credential.ErrInvalidCredential)
	}

	// AWS access key IDs start with "AKIA" (IAM user) or "ASIA" (STS temporary)
	if !strings.HasPrefix(accessKeyID, "AKIA") && !strings.HasPrefix(accessKeyID, "ASIA") {
		return fmt.Errorf("%w: invalid access_key_id format (must start with AKIA or ASIA)", credential.ErrInvalidCredential)
	}

	// Validate secret_access_key
	secretAccessKey, ok := cred.Data["secret_access_key"]
	if !ok || secretAccessKey == "" {
		return fmt.Errorf("%w: missing secret_access_key", credential.ErrInvalidCredential)
	}

	// Secret access keys are 40 characters long
	if len(secretAccessKey) != 40 {
		return fmt.Errorf("%w: invalid secret_access_key length (must be 40 characters)", credential.ErrInvalidCredential)
	}

	// If this is an STS temporary credential (ASIA prefix), validate session token
	if strings.HasPrefix(accessKeyID, "ASIA") {
		sessionToken, hasSession := cred.Data["session_token"]
		securityToken, hasSecurity := cred.Data["security_token"]

		if (!hasSession || sessionToken == "") && (!hasSecurity || securityToken == "") {
			return fmt.Errorf("%w: STS temporary credentials require session_token or security_token", credential.ErrInvalidCredential)
		}
	}

	return nil
}

// Revoke releases the credential (best-effort)
func (t *AWSIAMAccessKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	// Only STS temporary credentials with a lease can be revoked
	if cred.LeaseID == "" {
		return nil // Static IAM credentials cannot be revoked
	}

	// Attempt revocation through the driver
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}

	return nil
}

// CanRotate indicates if this type supports proactive rotation
func (t *AWSIAMAccessKeysCredType) CanRotate() bool {
	return true // AWS credentials support rotation
}

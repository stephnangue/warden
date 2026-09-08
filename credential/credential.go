package credential

import (
	"time"
)

// Credential type constants
const (
	TypeAWSAccessKeys     = "aws_access_keys"
	TypeVaultToken        = "vault_token"
	TypeAzureBearerToken  = "azure_bearer_token"
	TypeGCPAccessToken    = "gcp_access_token"
	TypeGitLabAccessToken = "gitlab_access_token"
	TypeGitHubToken       = "github_token"
	TypeAPIKey            = "api_key"
	TypeDBAuthToken       = "db_auth_token"
	TypeOAuthBearerToken  = "oauth_bearer_token"
	TypeKubernetesToken   = "kubernetes_token"
	TypeScalewayKeys      = "scaleway_keys"
	TypeOVHKeys           = "ovh_keys"
	TypeCloudflareKeys    = "cloudflare_keys"
	TypeIBMCloudKeys      = "ibmcloud_keys"
	TypeAlicloudKeys      = "alicloud_keys"
	TypeKeyValue          = "key_value"
)

// Source type constants
const (
	SourceTypeLocal         = "local"
	SourceTypeVault         = "hvault"
	SourceTypeAWS           = "aws"
	SourceTypeAzure         = "azure"
	SourceTypeGCP           = "gcp"
	SourceTypeGitLab        = "gitlab"
	SourceTypeGitHub        = "github"
	SourceTypeAPIKey        = "apikey"
	SourceTypeOAuth2        = "oauth2"
	SourceTypeIBM           = "ibm"
	SourceTypeElastic       = "elastic"
	SourceTypeKubernetes    = "kubernetes"
	SourceTypeScaleway      = "scaleway"
	SourceTypeOVH           = "ovh"
	SourceTypeGrafana       = "grafana"
	SourceTypeAlicloud      = "alicloud"
	SourceTypeTokenExchange = "token_exchange"
)

// Category constants for credential categorization
const (
	CategoryDatabase = "database"
	CategoryCloudIAM = "cloud_iam"
	CategoryOAuth    = "oauth"
	CategoryPKI      = "pki"
	CategoryK8s      = "kubernetes"
	CategoryAPI      = "api"
)

// Credential represents a minted credential instance returned to gateway requests.
// It is the output of the Manager.IssueCredential pipeline: a SourceDriver produces
// raw data, a credential Type parses it, and the result is stored here with full
// lifecycle metadata.
//
// Provider gateway handlers read Data to inject authentication into proxied requests
// (e.g., Data["access_token"] for Azure/GCP Bearer injection, Data["access_key_id"]
// and Data["secret_access_key"] for AWS SigV4 re-signing).
//
// Each instance is bound to a session token (TokenID) and cached in the Manager.
// Dynamic credentials (LeaseTTL > 0) are tracked by the expiration manager for
// automatic revocation when the token expires.
type Credential struct {
	// Identity
	// CredentialID is the unique identifier for this credential instance.
	// Always a UUID, generated when the credential is minted.
	// This is separate from LeaseID which is the source's revocation handle.
	CredentialID string // UUID - unique identifier for this credential instance

	// Type information
	Type     string // Credential type name (e.g., "aws_access_keys", "vault_token")
	Category string // Category for routing/organization

	// Lifecycle
	LeaseTTL time.Duration // TTL for dynamic credentials (0 for static)
	LeaseID  string        // Lease ID for revocation at source (empty for static)
	TokenID  string        // Session token this credential is bound to
	IssuedAt time.Time     // When the credential was issued

	// The secret part of the credential
	Data map[string]string // Type-specific credential data

	// Metadata
	SourceName string // Name of the credential source (for driver lookup during revocation)
	SourceType string // Type of the driver that issued this credential
	Revocable  bool   // Whether this credential can be revoked
	SpecName   string // Which spec created this credential (for tracking/audit)

	// Metadata holds non-secret, descriptive attributes about the credential
	// (e.g. "subject", "actor") that audit logs in clear. Never put secret material
	// here — that belongs in Data, which audit HMAC-salts.
	Metadata map[string]string
}

// IsExpired checks if the credential has expired
func (c *Credential) IsExpired() bool {
	if c.LeaseTTL == 0 {
		return false // Static credentials don't expire
	}
	return time.Since(c.IssuedAt) >= c.LeaseTTL
}

// RemainingTTL returns the remaining time until expiration
func (c *Credential) RemainingTTL() time.Duration {
	if c.LeaseTTL == 0 {
		return 0 // Static credentials have no TTL
	}
	remaining := c.LeaseTTL - time.Since(c.IssuedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ShouldRotate checks if the credential should be rotated based on a threshold
// threshold is a percentage (0.0 to 1.0) of TTL remaining
func (c *Credential) ShouldRotate(threshold float64) bool {
	if c.LeaseTTL == 0 || !c.Revocable {
		return false // Static or non-revocable credentials don't rotate
	}
	remaining := c.RemainingTTL()
	return float64(remaining) <= float64(c.LeaseTTL)*threshold
}

type CredSource struct {
	Name           string
	Type           string // local, hvault, aws, azure_key_vault, gcp_secret_manager
	Config         Config
	RotationPeriod time.Duration // 0 means no rotation
}

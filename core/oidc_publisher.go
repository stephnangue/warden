package core

import (
	"context"
	"fmt"
	"time"
)

// The OIDC issuer's public documents are published under these object paths, so
// their layout matches the served endpoints: an upstream fetching
// <issuer_url>/.well-known/openid-configuration and <issuer_url>/oidc/jwks works
// whether Warden serves them itself or they are pushed to a bucket/CDN.
const (
	oidcDiscoveryObjectPath = ".well-known/openid-configuration"
	oidcJWKSObjectPath      = "oidc/jwks"
)

// minPublisherRotationPeriod is the floor for the publisher-credential rotation cadence,
// enforced on the config-write path so automatic rotation cannot hammer the provider API.
const minPublisherRotationPeriod = 24 * time.Hour

// publisherConfig selects and configures where the public discovery + JWKS
// documents are pushed. Only public material is ever published; the private
// signing key never leaves Warden.
type publisherConfig struct {
	// Type is "", "none" (serve only from Warden's own endpoint), "local_file",
	// "http_put", "s3", "azure_blob", or "gcs".
	Type string `json:"type,omitempty"`

	// local_file: an external process (with its own credentials) syncs the
	// directory to the bucket/CDN, so Warden holds no bucket write-credential.
	Dir string `json:"dir,omitempty"`

	// http_put: Warden PUTs each document under this origin (e.g. a Cloudflare
	// Worker/R2 endpoint). AuthValue is the write credential — an unauthenticated
	// origin would let anyone overwrite the JWKS (the trust root), so it should
	// always be set unless the origin is protected another way (mTLS/network).
	BaseURL   string `json:"base_url,omitempty"`
	Autheader string `json:"auth_header,omitempty"` // header name; default Authorization
	AuthValue string `json:"auth_value,omitempty"`  // e.g. "Bearer <token>" (masked)

	// s3: stored static IAM access key (secret masked); Warden can self-rotate it.
	Bucket          string `json:"bucket,omitempty"`
	Region          string `json:"region,omitempty"`
	Prefix          string `json:"prefix,omitempty"` // shared with azure_blob (in-container blob-name prefix)
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`

	// azure_blob: writes to an Azure Storage container authenticated by a service
	// principal's OAuth token (Entra ID data-plane auth). Warden self-rotates the SP's
	// ClientSecret via Microsoft Graph (see RotatablePublisher): on the configured
	// cadence it adds a fresh secret to the app registration, verifies it, swaps it in,
	// and removes the old one — which requires the SP to hold Storage Blob Data
	// Contributor on the container and Graph rights to manage its own app registration
	// (Application.ReadWrite.OwnedBy as an owner of its app, or Application.ReadWrite.All).
	// ClientSecret is masked; SecretID is the Graph password-credential id (keyId) of the
	// current secret, used to remove it on rotation. Prefix above is reused as the
	// blob-name prefix; Endpoint overrides the blob service URL (private endpoint or a
	// test/emulator), empty defaults to the public-cloud host. Sovereign clouds are not yet
	// supported: the OAuth authority and Graph host are the public-cloud endpoints.
	AccountName  string `json:"account_name,omitempty"`
	Container    string `json:"container,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	SecretID     string `json:"secret_id,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"` // shared with gcs (API endpoint override)

	// gcs: writes to a Google Cloud Storage bucket authenticated by a stored
	// static service-account JSON key. CredentialsJSON is a stored static secret
	// (masked); like the s3/azure_blob keys it is an infra-scoped write credential.
	// Warden can self-rotate it (see RotatablePublisher): on the configured cadence
	// it mints a fresh key via the IAM API, verifies it, swaps it in, and deletes the
	// old one — which requires the service account to hold
	// iam.serviceAccountKeys.create/delete on itself. Bucket above is reused; Prefix
	// is reused as the object-name prefix; Endpoint overrides the storage API endpoint
	// (for a private endpoint or a test/emulator).
	CredentialsJSON string `json:"credentials_json,omitempty"`

	// RotationPeriod, when > 0, enables automatic rotation of the credential-bearing
	// publisher's write key on that cadence (gcs and s3). Empty/0 disables it.
	// A duration string ("720h"); validated and floored server-side.
	RotationPeriod string `json:"rotation_period,omitempty"`
}

// rotationPeriod parses the configured publisher-credential rotation cadence; 0
// (empty or unparseable) disables automatic rotation. The write path parses and
// bounds the value strictly before it is stored, so a stored value is well-formed.
func (c *publisherConfig) rotationPeriod() time.Duration {
	if c.RotationPeriod == "" {
		return 0
	}
	d, err := time.ParseDuration(c.RotationPeriod)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// JWKSPublisher pushes the issuer's public discovery + JWKS documents to an
// external surface (bucket/CDN) so the issuer URL need not be Warden's own
// address. Implementations are selected by publisherConfig.Type.
type JWKSPublisher interface {
	Publish(ctx context.Context, discovery, jwks []byte) error
	Type() string
}

// RotatablePublisher is an optional interface a publisher implements when Warden can
// self-rotate its stored write credential. The rotation loop discovers it by type
// assertion, so a publisher that cannot rotate simply does not implement it.
//
// Rotation is single-stage with verify-before-swap (the credential is off the request
// hot path, and the built-in endpoint always serves, so no timed propagation overlap is
// needed):
//  1. PrepareRotation mints a NEW credential and verifies it works, leaving the old one
//     untouched. It returns the config fields to persist and an opaque handle for
//     deleting the old credential.
//  2. [the loop persists newFields into the publisher config]
//  3. CommitRotation swaps the live in-memory credential to the just-persisted new one.
//  4. CleanupRotation destroys the old credential (best-effort).
type RotatablePublisher interface {
	// SupportsRotation reports whether this publisher instance can rotate its credential.
	SupportsRotation() bool

	// PrepareRotation mints and verifies a new credential without touching the old one.
	//   - newFields:  publisher-config keys to persist (e.g. {"credentials_json": …}).
	//   - prevFields: the current value of each key newFields replaces, for a
	//     compare-and-swap on persist — if the stored config no longer matches, an
	//     operator changed the credential concurrently and the rotation is abandoned.
	//   - cleanup:    the handle CleanupRotation needs to destroy the superseded credential.
	PrepareRotation(ctx context.Context) (newFields, prevFields, cleanup map[string]string, err error)

	// CommitRotation swaps the live in-memory credential to newFields (already persisted).
	CommitRotation(newFields map[string]string) error

	// CleanupRotation destroys the superseded credential (best-effort).
	CleanupRotation(ctx context.Context, cleanup map[string]string) error

	// RollbackRotation destroys a credential that PrepareRotation minted but that was
	// never persisted or committed (e.g. persistence failed), so a failed rotation does
	// not leak a live-but-unreferenced credential. Best-effort.
	RollbackRotation(ctx context.Context, newFields map[string]string) error
}

// newJWKSPublisher builds the configured publisher, or (nil, nil) when none is
// configured (the built-in HTTP endpoint remains the surface). cacheControl is
// the Cache-Control header value Warden derives from the JWKS cache TTL and sends
// on uploads, so a verifier refreshes the JWKS before a newly published key signs.
func newJWKSPublisher(cfg publisherConfig, cacheControl string) (JWKSPublisher, error) {
	switch cfg.Type {
	case "", "none":
		return nil, nil
	case "local_file":
		if cfg.Dir == "" {
			return nil, fmt.Errorf("oidc publisher: local_file requires 'dir'")
		}
		return &localFilePublisher{dir: cfg.Dir}, nil
	case "http_put":
		return newHTTPPutPublisher(cfg, cacheControl)
	case "s3":
		return newS3Publisher(cfg, cacheControl)
	case "azure_blob":
		return newAzureBlobPublisher(cfg, cacheControl)
	case "gcs":
		return newGCSPublisher(cfg, cacheControl)
	default:
		return nil, fmt.Errorf("oidc publisher: unsupported type %q", cfg.Type)
	}
}

// retryWithBackoff calls fn until it succeeds or ctx is done, backing off exponentially
// (1s→8s cap). Returns the last error on ctx expiry. Shared by the rotation retry paths.
func retryWithBackoff(ctx context.Context, fn func() error) error {
	backoff := time.Second
	for {
		err := fn()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
}
